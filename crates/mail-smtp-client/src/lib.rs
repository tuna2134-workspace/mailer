use std::{io, net::SocketAddr, time::Duration};

use mail_dns::{MailHost, MailRoute};
use mail_storage::{MailRepository, QueueLease, StorageError};
use thiserror::Error;
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::TcpStream,
    time::timeout,
};

const REPLY_LIMIT: usize = 8 * 1024;
const MESSAGE_CHUNK: u32 = 64 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SendResult {
    Delivered,
    Deferred {
        code: Option<String>,
        diagnostic: String,
    },
    Failed {
        code: Option<String>,
        diagnostic: String,
    },
}

#[derive(Debug, Error)]
pub enum ClientError {
    #[error("message storage failed: {0}")]
    Storage(#[from] StorageError),
}

#[derive(Clone, Debug)]
pub struct SmtpClient {
    hostname: String,
    connect_timeout: Duration,
    command_timeout: Duration,
}

impl SmtpClient {
    #[must_use]
    pub fn new(hostname: String) -> Self {
        Self {
            hostname,
            connect_timeout: Duration::from_secs(30),
            command_timeout: Duration::from_secs(60),
        }
    }

    pub async fn send<R: MailRepository>(
        &self,
        repository: &R,
        lease: &QueueLease,
        route: &MailRoute,
    ) -> Result<SendResult, ClientError> {
        if matches!(route, MailRoute::NullMx) {
            return Ok(SendResult::Failed {
                code: Some("5.1.2".into()),
                diagnostic: "destination publishes null MX".into(),
            });
        }
        if has_line_break(&lease.envelope_sender) || has_line_break(&lease.recipient) {
            return Ok(SendResult::Failed {
                code: Some("5.6.0".into()),
                diagnostic: "invalid envelope address".into(),
            });
        }
        let MailRoute::Hosts(hosts) = route else {
            unreachable!()
        };
        let mut last = "no reachable mail exchanger".to_owned();
        for host in hosts {
            for address in &host.addresses {
                match self
                    .send_to(repository, lease, host, SocketAddr::new(*address, 25))
                    .await?
                {
                    SendResult::Deferred { diagnostic, .. } => last = diagnostic,
                    result => return Ok(result),
                }
            }
        }
        Ok(SendResult::Deferred {
            code: Some("4.4.1".into()),
            diagnostic: last,
        })
    }

    #[allow(clippy::too_many_lines)] // Keeping the SMTP exchange in wire order makes state auditing safer.
    async fn send_to<R: MailRepository>(
        &self,
        repository: &R,
        lease: &QueueLease,
        host: &MailHost,
        address: SocketAddr,
    ) -> Result<SendResult, ClientError> {
        let stream = match timeout(self.connect_timeout, TcpStream::connect(address)).await {
            Ok(Ok(stream)) => stream,
            Ok(Err(error)) => return Ok(deferred_io(host, &error)),
            Err(_) => {
                return Ok(SendResult::Deferred {
                    code: Some("4.4.1".into()),
                    diagnostic: format!("connection to {} timed out", host.name),
                });
            }
        };
        let (read, mut write) = stream.into_split();
        let mut read = BufReader::new(read);
        let greeting = self.reply(&mut read).await;
        if let Some(result) = classify_reply(greeting, "greeting", &[220]) {
            return Ok(result);
        }

        if let Err(error) = self
            .write(&mut write, format!("EHLO {}\r\n", self.hostname).as_bytes())
            .await
        {
            return Ok(deferred_io(host, &error));
        }
        let ehlo = self.reply(&mut read).await;
        if matches!(ehlo, Ok((500..=599, _))) {
            if let Err(error) = self
                .write(&mut write, format!("HELO {}\r\n", self.hostname).as_bytes())
                .await
            {
                return Ok(deferred_io(host, &error));
            }
            if let Some(result) = classify_reply(self.reply(&mut read).await, "HELO", &[250]) {
                return Ok(result);
            }
        } else if let Some(result) = classify_reply(ehlo, "EHLO", &[250]) {
            return Ok(result);
        }
        let reverse_path = if lease.envelope_sender.is_empty() {
            "<>".to_owned()
        } else {
            format!("<{}>", lease.envelope_sender)
        };
        if let Err(error) = self
            .write(
                &mut write,
                format!("MAIL FROM:{reverse_path}\r\n").as_bytes(),
            )
            .await
        {
            return Ok(deferred_io(host, &error));
        }
        if let Some(result) = classify_reply(self.reply(&mut read).await, "MAIL FROM", &[250]) {
            return Ok(result);
        }
        if let Err(error) = self
            .write(
                &mut write,
                format!("RCPT TO:<{}>\r\n", lease.recipient).as_bytes(),
            )
            .await
        {
            return Ok(deferred_io(host, &error));
        }
        if let Some(result) =
            classify_reply(self.reply(&mut read).await, "RCPT TO", &[250, 251, 252])
        {
            return Ok(result);
        }
        if let Err(error) = self.write(&mut write, b"DATA\r\n").await {
            return Ok(deferred_io(host, &error));
        }
        if let Some(result) = classify_reply(self.reply(&mut read).await, "DATA", &[354]) {
            return Ok(result);
        }

        let mut offset = 0_u64;
        let mut line_start = true;
        let mut tail = [0_u8; 2];
        loop {
            let chunk = repository
                .read_message_chunk(lease.message_id, offset, MESSAGE_CHUNK)
                .await?;
            if chunk.is_empty() {
                break;
            }
            let stuffed = dot_stuff(&chunk, &mut line_start);
            if let Err(error) = self.write(&mut write, &stuffed).await {
                return Ok(deferred_io(host, &error));
            }
            for byte in chunk.iter().copied() {
                tail = [tail[1], byte];
            }
            offset = offset.saturating_add(chunk.len() as u64);
            if chunk.len() < MESSAGE_CHUNK as usize {
                break;
            }
        }
        if tail != *b"\r\n" {
            if let Err(error) = self.write(&mut write, b"\r\n").await {
                return Ok(deferred_io(host, &error));
            }
        }
        if let Err(error) = self.write(&mut write, b".\r\n").await {
            return Ok(deferred_io(host, &error));
        }
        if let Some(result) = classify_reply(self.reply(&mut read).await, "message body", &[250]) {
            return Ok(result);
        }
        let _ = write.write_all(b"QUIT\r\n").await;
        Ok(SendResult::Delivered)
    }

    async fn reply<R: tokio::io::AsyncBufRead + Unpin>(
        &self,
        read: &mut R,
    ) -> io::Result<(u16, String)> {
        timeout(self.command_timeout, read_reply(read))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "SMTP reply timeout"))?
    }

    async fn write<W: tokio::io::AsyncWrite + Unpin>(
        &self,
        write: &mut W,
        value: &[u8],
    ) -> io::Result<()> {
        timeout(self.command_timeout, write.write_all(value))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "SMTP write timeout"))?
    }
}

fn has_line_break(value: &str) -> bool {
    value.contains(['\r', '\n'])
}

fn deferred_io(host: &MailHost, error: &io::Error) -> SendResult {
    SendResult::Deferred {
        code: Some("4.4.1".into()),
        diagnostic: format!("connection to {} failed: {error}", host.name),
    }
}

fn classify_reply(
    reply: io::Result<(u16, String)>,
    stage: &str,
    accepted: &[u16],
) -> Option<SendResult> {
    match reply {
        Ok((code, _)) if accepted.contains(&code) => None,
        Ok((code, text)) if (400..500).contains(&code) => Some(SendResult::Deferred {
            code: enhanced(&text),
            diagnostic: format!("{stage}: {code} {text}"),
        }),
        Ok((code, text)) => Some(SendResult::Failed {
            code: enhanced(&text),
            diagnostic: format!("{stage}: {code} {text}"),
        }),
        Err(error) => Some(SendResult::Deferred {
            code: Some("4.4.2".into()),
            diagnostic: format!("{stage}: {error}"),
        }),
    }
}

fn enhanced(text: &str) -> Option<String> {
    text.split_ascii_whitespace()
        .find(|part| {
            let mut pieces = part.split('.');
            matches!(pieces.next(), Some("2" | "4" | "5"))
                && pieces
                    .next()
                    .is_some_and(|p| p.bytes().all(|b| b.is_ascii_digit()))
                && pieces
                    .next()
                    .is_some_and(|p| p.bytes().all(|b| b.is_ascii_digit()))
                && pieces.next().is_none()
        })
        .map(str::to_owned)
}

async fn read_reply<R: tokio::io::AsyncBufRead + Unpin>(read: &mut R) -> io::Result<(u16, String)> {
    let mut total = 0;
    let mut expected = None;
    let mut text = String::new();
    loop {
        let mut line = String::new();
        let bytes = read.read_line(&mut line).await?;
        total += bytes;
        if bytes == 0 || total > REPLY_LIMIT || !line.ends_with("\r\n") || line.len() < 5 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid SMTP reply",
            ));
        }
        let code = line[..3]
            .parse::<u16>()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid SMTP reply code"))?;
        if expected.replace(code).is_some_and(|first| first != code) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "inconsistent SMTP multiline reply",
            ));
        }
        if !text.is_empty() {
            text.push(' ');
        }
        text.push_str(line[4..].trim_end());
        match line.as_bytes()[3] {
            b'-' => {}
            b' ' => return Ok((code, text)),
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid SMTP reply separator",
                ));
            }
        }
    }
}

fn dot_stuff(input: &[u8], line_start: &mut bool) -> Vec<u8> {
    let mut output = Vec::with_capacity(input.len());
    for byte in input.iter().copied() {
        if *line_start && byte == b'.' {
            output.push(b'.');
        }
        output.push(byte);
        *line_start = byte == b'\n';
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dot_stuffing_survives_chunk_boundaries() {
        let mut start = true;
        assert_eq!(dot_stuff(b".one\r\n", &mut start), b"..one\r\n");
        assert_eq!(dot_stuff(b".two", &mut start), b"..two");
    }

    #[test]
    fn enhanced_status_is_strict() {
        assert_eq!(enhanced("5.1.1 no such user"), Some("5.1.1".into()));
        assert_eq!(enhanced("5.1.x invalid"), None);
    }
}
