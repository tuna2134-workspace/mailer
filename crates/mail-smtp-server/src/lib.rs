#![forbid(unsafe_code)]

use mail_smtp_proto::{
    Action, Command, DataError, ParseError, Reply, Session, parse_command, unstuff_data_line,
};
use mail_storage::{LocalRecipient, SmtpRepository, StorageError};
use std::{collections::HashMap, net::SocketAddr, sync::Arc, time::Duration};
use thiserror::Error;
use time::{OffsetDateTime, format_description::well_known::Rfc2822};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::Semaphore,
    time::timeout,
};

const DATA_LINE_LIMIT: usize = 1000;
const CHUNK_SIZE: usize = 64 * 1024;

#[derive(Clone, Debug)]
pub struct SmtpConfig {
    pub hostname: String,
    pub max_message_size: u64,
    pub max_recipients: usize,
    pub max_connections: usize,
    pub command_timeout: Duration,
    pub data_timeout: Duration,
    pub allow_bare_lf: bool,
}

impl Default for SmtpConfig {
    fn default() -> Self {
        Self {
            hostname: "localhost".into(),
            max_message_size: 25 * 1024 * 1024,
            max_recipients: 100,
            max_connections: 1024,
            command_timeout: Duration::from_secs(300),
            data_timeout: Duration::from_secs(600),
            allow_bare_lf: false,
        }
    }
}

#[derive(Debug, Error)]
pub enum SmtpError {
    #[error("I/O failure: {0}")]
    Io(String),
    #[error("session timed out")]
    Timeout,
    #[error("storage unavailable")]
    Storage,
    #[error("message rejected: {0}")]
    Data(#[from] DataError),
}

pub async fn serve<R: SmtpRepository + 'static>(
    listener: TcpListener,
    repository: Arc<R>,
    config: SmtpConfig,
) -> Result<(), SmtpError> {
    let permits = Arc::new(Semaphore::new(config.max_connections));
    loop {
        let (stream, peer) = listener.accept().await.map_err(io)?;
        let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else {
            reject_busy(stream).await;
            continue;
        };
        let repository = Arc::clone(&repository);
        let config = config.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let _ = run_session(stream, peer, repository.as_ref(), &config).await;
        });
    }
}

async fn reject_busy(mut stream: TcpStream) {
    let _ = stream.write_all(b"421 4.3.2 Service busy\r\n").await;
    let _ = stream.shutdown().await;
}

#[allow(clippy::too_many_lines, clippy::semicolon_if_nothing_returned)]
pub async fn run_session<S, R>(
    mut stream: S,
    peer: SocketAddr,
    repository: &R,
    config: &SmtpConfig,
) -> Result<(), SmtpError>
where
    S: AsyncRead + AsyncWrite + Unpin,
    R: SmtpRepository,
{
    write_reply(
        &mut stream,
        &Reply {
            code: 220,
            enhanced: Some("2.0.0"),
            text: "Service ready",
        },
    )
    .await?;
    let mut session = Session::new(config.max_recipients);
    let mut resolved = HashMap::<String, LocalRecipient>::new();
    loop {
        let line = timeout(
            config.command_timeout,
            read_line_bounded(&mut stream, mail_smtp_proto::MAX_COMMAND_LINE),
        )
        .await
        .map_err(|_| SmtpError::Timeout)??;
        let Some(line) = line else {
            return Ok(());
        };
        let command = match parse_command(&line, config.allow_bare_lf) {
            Ok(command) => command,
            Err(error) => {
                write_reply(&mut stream, &parse_reply(error)).await?;
                continue;
            }
        };
        if matches!(
            command,
            Command::Ehlo(_) | Command::Helo(_) | Command::Mail { .. } | Command::Rset
        ) {
            resolved.clear();
        }
        let action = session.command(command);
        match action {
            Action::Reply(reply) => write_reply(&mut stream, &reply).await?,
            Action::Quit(reply) => {
                write_reply(&mut stream, &reply).await?;
                return Ok(());
            }
            Action::Recipient(address) => {
                if resolved.contains_key(&address) {
                    session.accept_recipient(address);
                    write_reply(
                        &mut stream,
                        &Reply {
                            code: 250,
                            enhanced: Some("2.1.5"),
                            text: "Recipient OK",
                        },
                    )
                    .await?;
                    continue;
                }
                match repository.resolve_local_recipient(&address).await {
                    Ok(Some(recipient)) => {
                        resolved.insert(address.clone(), recipient);
                        session.accept_recipient(address);
                        write_reply(
                            &mut stream,
                            &Reply {
                                code: 250,
                                enhanced: Some("2.1.5"),
                                text: "Recipient OK",
                            },
                        )
                        .await?;
                    }
                    Ok(None) => {
                        write_reply(
                            &mut stream,
                            &Reply {
                                code: 550,
                                enhanced: Some("5.1.1"),
                                text: "No such local recipient; relaying denied",
                            },
                        )
                        .await?
                    }
                    Err(_) => {
                        write_reply(
                            &mut stream,
                            &Reply {
                                code: 451,
                                enhanced: Some("4.3.0"),
                                text: "Temporary local lookup failure",
                            },
                        )
                        .await?
                    }
                }
            }
            Action::BeginData(transaction) => {
                write_reply(
                    &mut stream,
                    &Reply {
                        code: 354,
                        enhanced: None,
                        text: "End data with <CRLF>.<CRLF>",
                    },
                )
                .await?;
                let recipients: Vec<LocalRecipient> = transaction
                    .recipients
                    .iter()
                    .filter_map(|address| resolved.get(address).cloned())
                    .collect();
                let result = timeout(
                    config.data_timeout,
                    receive_data(
                        &mut stream,
                        repository,
                        config,
                        peer,
                        session.peer_name.as_deref(),
                        &transaction.reverse_path,
                        &recipients,
                    ),
                )
                .await;
                session.finish_data();
                resolved.clear();
                match result {
                    Err(_) => return Err(SmtpError::Timeout),
                    Ok(Ok(())) => {
                        write_reply(
                            &mut stream,
                            &Reply {
                                code: 250,
                                enhanced: Some("2.0.0"),
                                text: "Message accepted for delivery",
                            },
                        )
                        .await?
                    }
                    Ok(Err(SmtpError::Data(DataError::TooLarge))) => {
                        write_reply(
                            &mut stream,
                            &Reply {
                                code: 552,
                                enhanced: Some("5.3.4"),
                                text: "Message size exceeds fixed maximum",
                            },
                        )
                        .await?
                    }
                    Ok(Err(SmtpError::Data(DataError::BareLf))) => {
                        write_reply(
                            &mut stream,
                            &Reply {
                                code: 554,
                                enhanced: Some("5.6.0"),
                                text: "Bare LF not accepted",
                            },
                        )
                        .await?
                    }
                    Ok(Err(SmtpError::Data(DataError::LineTooLong))) => {
                        write_reply(
                            &mut stream,
                            &Reply {
                                code: 554,
                                enhanced: Some("5.6.0"),
                                text: "DATA line too long",
                            },
                        )
                        .await?
                    }
                    Ok(Err(SmtpError::Storage)) => {
                        write_reply(
                            &mut stream,
                            &Reply {
                                code: 451,
                                enhanced: Some("4.3.0"),
                                text: "Temporary local storage failure",
                            },
                        )
                        .await?
                    }
                    Ok(Err(error)) => return Err(error),
                }
            }
        }
    }
}

async fn receive_data<S: AsyncRead + AsyncWrite + Unpin, R: SmtpRepository>(
    stream: &mut S,
    repository: &R,
    config: &SmtpConfig,
    peer: SocketAddr,
    helo: Option<&str>,
    reverse_path: &str,
    recipients: &[LocalRecipient],
) -> Result<(), SmtpError> {
    let ingestion = repository.begin_smtp_ingestion().await.map_err(storage)?;
    let result = receive_data_inner(stream, repository, config, ingestion).await;
    if let Err(error) = result {
        repository
            .abort_smtp_ingestion(ingestion)
            .await
            .map_err(storage)?;
        return Err(error);
    }
    let received = received_header(&config.hostname, peer, helo);
    repository
        .commit_smtp_ingestion(ingestion, reverse_path, recipients, received.as_bytes())
        .await
        .map_err(storage)?;
    Ok(())
}

async fn receive_data_inner<S: AsyncRead + Unpin, R: SmtpRepository>(
    stream: &mut S,
    repository: &R,
    config: &SmtpConfig,
    ingestion: uuid::Uuid,
) -> Result<(), SmtpError> {
    let mut chunk = Vec::with_capacity(CHUNK_SIZE);
    let mut position = 0_u32;
    let mut size = 0_u64;
    loop {
        let line = read_line_bounded(stream, DATA_LINE_LIMIT)
            .await?
            .ok_or_else(|| {
                io(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "EOF during DATA",
                ))
            })?;
        if line.len() > DATA_LINE_LIMIT {
            drain_data(stream, config.allow_bare_lf).await?;
            return Err(DataError::LineTooLong.into());
        }
        let Some(content) = unstuff_data_line(&line, config.allow_bare_lf)? else {
            break;
        };
        size = size.saturating_add(content.len() as u64);
        if size > config.max_message_size {
            drain_data(stream, config.allow_bare_lf).await?;
            return Err(DataError::TooLarge.into());
        }
        chunk.extend_from_slice(content);
        if chunk.len() >= CHUNK_SIZE {
            repository
                .append_smtp_chunk(ingestion, position, &chunk)
                .await
                .map_err(storage)?;
            position = position.checked_add(1).ok_or(SmtpError::Storage)?;
            chunk.clear();
        }
    }
    repository
        .append_smtp_chunk(ingestion, position, &chunk)
        .await
        .map_err(storage)?;
    Ok(())
}

async fn drain_data<S: AsyncRead + Unpin>(
    stream: &mut S,
    allow_bare_lf: bool,
) -> Result<(), SmtpError> {
    loop {
        let Some(line) = read_line_bounded(stream, DATA_LINE_LIMIT).await? else {
            return Ok(());
        };
        if line == b".\r\n" || (allow_bare_lf && line == b".\n") {
            return Ok(());
        }
    }
}

async fn read_line_bounded<S: AsyncRead + Unpin>(
    stream: &mut S,
    limit: usize,
) -> Result<Option<Vec<u8>>, SmtpError> {
    let mut line = Vec::with_capacity(limit.min(1024));
    let mut byte = [0_u8; 1];
    loop {
        let read = stream.read(&mut byte).await.map_err(io)?;
        if read == 0 {
            return if line.is_empty() {
                Ok(None)
            } else {
                Ok(Some(line))
            };
        }
        if line.len() < limit + 1 {
            line.push(byte[0]);
        }
        if byte[0] == b'\n' {
            return Ok(Some(line));
        }
        if line.len() > limit {
            while stream.read(&mut byte).await.map_err(io)? != 0 && byte[0] != b'\n' {}
            return Ok(Some(line));
        }
    }
}

fn received_header(hostname: &str, peer: SocketAddr, helo: Option<&str>) -> String {
    let date = OffsetDateTime::now_utc()
        .format(&Rfc2822)
        .unwrap_or_else(|_| "Thu, 01 Jan 1970 00:00:00 +0000".into());
    format!(
        "Received: from {} ([{}]) by {} with SMTP; {}\r\n",
        helo.unwrap_or("unknown"),
        peer.ip(),
        hostname,
        date
    )
}

async fn write_reply<S: AsyncWrite + Unpin>(
    stream: &mut S,
    reply: &Reply,
) -> Result<(), SmtpError> {
    stream.write_all(reply.line().as_bytes()).await.map_err(io)
}

fn parse_reply(error: ParseError) -> Reply {
    match error {
        ParseError::LineTooLong => Reply {
            code: 500,
            enhanced: Some("5.5.2"),
            text: "Command line too long",
        },
        ParseError::BareLf => Reply {
            code: 500,
            enhanced: Some("5.5.2"),
            text: "Bare LF not accepted",
        },
        ParseError::InvalidEncoding | ParseError::InvalidSyntax => Reply {
            code: 501,
            enhanced: Some("5.5.2"),
            text: "Syntax error in parameters",
        },
    }
}

#[allow(clippy::needless_pass_by_value)] // Result::map_err supplies an owned error.
fn io(error: std::io::Error) -> SmtpError {
    SmtpError::Io(error.to_string())
}
fn storage(_: StorageError) -> SmtpError {
    SmtpError::Storage
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use mail_domain::{MailboxId, TenantId};
    use mail_storage::StoredMessage;
    use std::sync::Mutex;
    use tokio::io::{AsyncBufRead, AsyncBufReadExt, BufReader, duplex};
    use uuid::Uuid;

    #[derive(Default)]
    struct Repository {
        chunks: Mutex<Vec<u8>>,
        committed: Mutex<bool>,
    }

    #[async_trait]
    impl SmtpRepository for Repository {
        async fn recover_smtp_ingestions(&self) -> Result<u64, StorageError> {
            Ok(0)
        }

        async fn resolve_local_recipient(
            &self,
            address: &str,
        ) -> Result<Option<LocalRecipient>, StorageError> {
            Ok((address == "alice@example.test").then(|| LocalRecipient {
                address: address.into(),
                tenant_id: TenantId::new(Uuid::nil()),
                mailbox_id: MailboxId::new(Uuid::nil()),
            }))
        }

        async fn begin_smtp_ingestion(&self) -> Result<Uuid, StorageError> {
            Ok(Uuid::nil())
        }

        async fn append_smtp_chunk(
            &self,
            _: Uuid,
            _: u32,
            bytes: &[u8],
        ) -> Result<(), StorageError> {
            self.chunks
                .lock()
                .map_err(|_| StorageError::Unavailable("lock".into()))?
                .extend_from_slice(bytes);
            Ok(())
        }

        async fn commit_smtp_ingestion(
            &self,
            _: Uuid,
            _: &str,
            recipients: &[LocalRecipient],
            received: &[u8],
        ) -> Result<StoredMessage, StorageError> {
            if recipients.len() != 1 || !received.starts_with(b"Received:") {
                return Err(StorageError::Conflict);
            }
            *self
                .committed
                .lock()
                .map_err(|_| StorageError::Unavailable("lock".into()))? = true;
            Ok(StoredMessage {
                message_ids: vec![Uuid::nil()],
                octets: 0,
            })
        }

        async fn abort_smtp_ingestion(&self, _: Uuid) -> Result<(), StorageError> {
            Ok(())
        }
    }

    async fn response<R: AsyncBufRead + Unpin>(reader: &mut R) -> Result<String, std::io::Error> {
        let mut line = String::new();
        reader.read_line(&mut line).await?;
        Ok(line)
    }

    #[tokio::test]
    async fn local_delivery_transcript_and_relay_denial() -> Result<(), Box<dyn std::error::Error>>
    {
        let (client, server) = duplex(16 * 1024);
        let repository = Arc::new(Repository::default());
        let task_repository = Arc::clone(&repository);
        let peer: SocketAddr = "192.0.2.1:2525".parse()?;
        let task = tokio::spawn(async move {
            run_session(
                server,
                peer,
                task_repository.as_ref(),
                &SmtpConfig::default(),
            )
            .await
        });
        let (read, mut write) = tokio::io::split(client);
        let mut reader = BufReader::new(read);
        assert!(response(&mut reader).await?.starts_with("220 "));
        for (command, code) in [
            ("EHLO client.example\r\n", "250"),
            ("MAIL FROM:<sender@example.net>\r\n", "250"),
            ("RCPT TO:<outside@example.net>\r\n", "550"),
            ("RCPT TO:<alice@example.test>\r\n", "250"),
            ("DATA\r\n", "354"),
        ] {
            write.write_all(command.as_bytes()).await?;
            assert!(response(&mut reader).await?.starts_with(code));
        }
        write
            .write_all(b"Subject: test\r\n\r\n..dot\r\n.\r\n")
            .await?;
        assert!(response(&mut reader).await?.starts_with("250"));
        write.write_all(b"QUIT\r\n").await?;
        assert!(response(&mut reader).await?.starts_with("221"));
        task.await??;
        assert_eq!(
            *repository.chunks.lock().map_err(|_| "lock")?,
            b"Subject: test\r\n\r\n.dot\r\n"
        );
        assert!(*repository.committed.lock().map_err(|_| "lock")?);
        Ok(())
    }

    #[tokio::test]
    async fn idle_command_timeout_terminates_session() -> Result<(), Box<dyn std::error::Error>> {
        let (mut client, server) = duplex(1024);
        let repository = Repository::default();
        let peer: SocketAddr = "192.0.2.2:2525".parse()?;
        let config = SmtpConfig {
            command_timeout: Duration::from_millis(10),
            ..SmtpConfig::default()
        };
        let task =
            tokio::spawn(async move { run_session(server, peer, &repository, &config).await });
        let mut greeting = [0_u8; 128];
        let count = client.read(&mut greeting).await?;
        assert!(greeting[..count].starts_with(b"220 "));
        assert!(matches!(task.await?, Err(SmtpError::Timeout)));
        Ok(())
    }
}
