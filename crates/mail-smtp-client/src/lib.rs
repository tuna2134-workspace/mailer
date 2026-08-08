mod transport_security;
pub use transport_security::{TlsFailureAction, TransportSecurityPolicy};

use std::{
    io,
    net::SocketAddr,
    time::{Duration, SystemTime},
};

use mail_arc::{ArcSealConfig, ChainStatus, seal as seal_arc};
use mail_dkim::{BodyHasher, Canonicalization, SigningKey, sign_headers};
use mail_dns::{MailHost, MailRoute};
use mail_storage::{AuthenticationResultsTrust, MailRepository, QueueLease, StorageError};
use rustls_platform_verifier::BuilderVerifierExt;
use thiserror::Error;
use tokio::{
    io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader},
    net::TcpStream,
    time::timeout,
};

trait ClientIo: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> ClientIo for T {}

const REPLY_LIMIT: usize = 8 * 1024;
const MESSAGE_CHUNK: u32 = 64 * 1024;
const MAX_SIGNED_HEADERS: usize = 256 * 1024;

#[derive(Clone, Debug)]
pub struct DkimSigningConfig {
    pub domain: String,
    pub selector: String,
    pub key: SigningKey,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SendResult {
    Delivered,
    Ambiguous {
        diagnostic: String,
    },
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
    dkim: Option<DkimSigningConfig>,
    transport_security: TransportSecurityPolicy,
}

impl SmtpClient {
    #[must_use]
    pub fn new(hostname: String) -> Self {
        Self {
            hostname,
            connect_timeout: Duration::from_secs(30),
            command_timeout: Duration::from_secs(60),
            dkim: None,
            transport_security: TransportSecurityPolicy::Opportunistic,
        }
    }

    #[must_use]
    pub fn with_dkim(mut self, config: DkimSigningConfig) -> Self {
        self.dkim = Some(config);
        self
    }

    #[must_use]
    pub const fn with_transport_security(mut self, policy: TransportSecurityPolicy) -> Self {
        self.transport_security = policy;
        self
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
        if [
            &lease.dsn_ret,
            &lease.envelope_id,
            &lease.dsn_notify,
            &lease.original_recipient,
        ]
        .into_iter()
        .flatten()
        .any(|value| has_line_break(value) || value.contains(' '))
        {
            return Ok(SendResult::Failed {
                code: Some("5.6.0".into()),
                diagnostic: "invalid DSN envelope option".into(),
            });
        }
        let MailRoute::Hosts(hosts) = route else {
            unreachable!()
        };
        let policy = if lease.require_tls {
            TransportSecurityPolicy::RequireTls
        } else {
            self.transport_security
        };
        if policy == TransportSecurityPolicy::Dane {
            return Ok(SendResult::Deferred {
                code: Some("4.7.5".into()),
                diagnostic: "DANE TLSA verifier is not configured".into(),
            });
        }
        let mut last = "no reachable mail exchanger".to_owned();
        for host in hosts {
            for address in &host.addresses {
                match self
                    .send_to(
                        repository,
                        lease,
                        host,
                        SocketAddr::new(*address, 25),
                        policy,
                        true,
                    )
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
        policy: TransportSecurityPolicy,
        attempt_tls: bool,
    ) -> Result<SendResult, ClientError> {
        let dkim_header = match &self.dkim {
            Some(config) => match prepare_dkim(repository, lease, config).await? {
                Ok(header) => Some(header),
                Err(diagnostic) => {
                    return Ok(SendResult::Deferred {
                        code: Some("4.7.5".into()),
                        diagnostic,
                    });
                }
            },
            None => None,
        };
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
        let mut connection = BufReader::new(Box::new(stream) as Box<dyn ClientIo>);
        let greeting = self.reply(&mut connection).await;
        if let Some(result) = classify_reply(greeting, "greeting", &[220]) {
            return Ok(result);
        }

        if let Err(error) = self
            .write(
                connection.get_mut(),
                format!("EHLO {}\r\n", self.hostname).as_bytes(),
            )
            .await
        {
            return Ok(deferred_io(host, &error));
        }
        let ehlo = self.reply(&mut connection).await;
        let mut tls_active = false;
        let mut requiretls_supported = false;
        let mut smtp_utf8_supported = false;
        let mut dsn_supported = false;
        let mut deliver_by_supported = false;
        if matches!(ehlo, Ok((500..=599, _))) {
            if let Err(error) = self
                .write(
                    connection.get_mut(),
                    format!("HELO {}\r\n", self.hostname).as_bytes(),
                )
                .await
            {
                return Ok(deferred_io(host, &error));
            }
            if let Some(result) = classify_reply(self.reply(&mut connection).await, "HELO", &[250])
            {
                return Ok(result);
            }
        } else {
            let starttls = matches!(&ehlo, Ok((250, text)) if has_capability(text, "STARTTLS"));
            requiretls_supported =
                matches!(&ehlo, Ok((250, text)) if has_capability(text, "REQUIRETLS"));
            smtp_utf8_supported =
                matches!(&ehlo, Ok((250, text)) if has_capability(text, "SMTPUTF8"));
            dsn_supported = matches!(&ehlo, Ok((250, text)) if has_capability(text, "DSN"));
            deliver_by_supported =
                matches!(&ehlo, Ok((250, text)) if has_capability(text, "DELIVERBY"));
            if let Some(result) = classify_reply(ehlo, "EHLO", &[250]) {
                return Ok(result);
            }
            if starttls && attempt_tls {
                if let Err(error) = self.write(connection.get_mut(), b"STARTTLS\r\n").await {
                    if policy.on_tls_failure() == TlsFailureAction::RetryPlaintext {
                        return Box::pin(
                            self.send_to(repository, lease, host, address, policy, false),
                        )
                        .await;
                    }
                    return Ok(deferred_io(host, &error));
                }
                let starttls_reply = self.reply(&mut connection).await;
                if !matches!(starttls_reply, Ok((220, _))) {
                    if policy.on_tls_failure() == TlsFailureAction::RetryPlaintext {
                        return Box::pin(
                            self.send_to(repository, lease, host, address, policy, false),
                        )
                        .await;
                    }
                    return Ok(SendResult::Deferred {
                        code: Some("4.7.5".into()),
                        diagnostic: match starttls_reply {
                            Ok((code, text)) => format!("STARTTLS: {code} {text}"),
                            Err(error) => format!("STARTTLS: {error}"),
                        },
                    });
                }
                let tls = match rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(
                    rustls::crypto::ring::default_provider(),
                ))
                .with_safe_default_protocol_versions()
                .and_then(BuilderVerifierExt::with_platform_verifier)
                .map(no_client_auth)
                {
                    Ok(config) => config,
                    Err(error) => {
                        if policy.on_tls_failure() == TlsFailureAction::RetryPlaintext {
                            return Box::pin(
                                self.send_to(repository, lease, host, address, policy, false),
                            )
                            .await;
                        }
                        return Ok(SendResult::Deferred {
                            code: Some("4.7.5".into()),
                            diagnostic: format!("TLS verifier unavailable: {error}"),
                        });
                    }
                };
                let server_name = match rustls::pki_types::ServerName::try_from(host.name.clone()) {
                    Ok(name) => name,
                    Err(error) => {
                        if policy.on_tls_failure() == TlsFailureAction::RetryPlaintext {
                            return Box::pin(
                                self.send_to(repository, lease, host, address, policy, false),
                            )
                            .await;
                        }
                        return Ok(SendResult::Deferred {
                            code: Some("4.7.5".into()),
                            diagnostic: format!("invalid TLS server name: {error}"),
                        });
                    }
                };
                let secured = match timeout(
                    self.command_timeout,
                    tokio_rustls::TlsConnector::from(std::sync::Arc::new(tls))
                        .connect(server_name, connection.into_inner()),
                )
                .await
                {
                    Ok(Ok(stream)) => stream,
                    Ok(Err(error)) => {
                        if policy.on_tls_failure() == TlsFailureAction::RetryPlaintext {
                            return Box::pin(
                                self.send_to(repository, lease, host, address, policy, false),
                            )
                            .await;
                        }
                        return Ok(SendResult::Deferred {
                            code: Some("4.7.5".into()),
                            diagnostic: format!("TLS handshake failed: {error}"),
                        });
                    }
                    Err(_) => {
                        if policy.on_tls_failure() == TlsFailureAction::RetryPlaintext {
                            return Box::pin(
                                self.send_to(repository, lease, host, address, policy, false),
                            )
                            .await;
                        }
                        return Ok(SendResult::Deferred {
                            code: Some("4.7.5".into()),
                            diagnostic: "TLS handshake timed out".into(),
                        });
                    }
                };
                connection = BufReader::new(Box::new(secured));
                tls_active = true;
                if let Err(error) = self
                    .write(
                        connection.get_mut(),
                        format!("EHLO {}\r\n", self.hostname).as_bytes(),
                    )
                    .await
                {
                    return Ok(deferred_io(host, &error));
                }
                let ehlo = self.reply(&mut connection).await;
                requiretls_supported =
                    matches!(&ehlo, Ok((250, text)) if has_capability(text, "REQUIRETLS"));
                smtp_utf8_supported =
                    matches!(&ehlo, Ok((250, text)) if has_capability(text, "SMTPUTF8"));
                dsn_supported = matches!(&ehlo, Ok((250, text)) if has_capability(text, "DSN"));
                deliver_by_supported =
                    matches!(&ehlo, Ok((250, text)) if has_capability(text, "DELIVERBY"));
                if let Some(result) = classify_reply(ehlo, "EHLO after TLS", &[250]) {
                    return Ok(result);
                }
            }
        }
        if policy.requires_tls()
            && (!tls_active || policy.requires_requiretls() && !requiretls_supported)
        {
            return Ok(SendResult::Deferred {
                code: Some("4.7.5".into()),
                diagnostic: "REQUIRETLS cannot be satisfied by destination".into(),
            });
        }
        if lease.smtp_utf8 && !smtp_utf8_supported {
            return Ok(SendResult::Failed {
                code: Some("5.6.7".into()),
                diagnostic: "destination does not support SMTPUTF8".into(),
            });
        }
        if !dsn_supported
            && (lease.dsn_ret.is_some()
                || lease.envelope_id.is_some()
                || lease.dsn_notify.is_some()
                || lease.original_recipient.is_some())
        {
            return Ok(SendResult::Deferred {
                code: Some("4.5.1".into()),
                diagnostic: "destination does not support requested DSN options".into(),
            });
        }
        if lease.deliver_by_mode.as_deref() == Some("R") && !deliver_by_supported {
            return Ok(SendResult::Deferred {
                code: Some("4.5.1".into()),
                diagnostic: "destination does not support required DELIVERBY return mode".into(),
            });
        }
        let deliver_by = if deliver_by_supported {
            lease
                .deliver_by_at
                .and_then(|deadline| {
                    deadline
                        .duration_since(SystemTime::now())
                        .ok()
                        .map(|remaining| {
                            format!(
                                " BY={};{}{}",
                                remaining.as_secs().clamp(1, 999_999_999),
                                lease.deliver_by_mode.as_deref().unwrap_or("N"),
                                if lease.deliver_by_trace { ";T" } else { "" }
                            )
                        })
                })
                .unwrap_or_default()
        } else {
            String::new()
        };
        let reverse_path = if lease.envelope_sender.is_empty() {
            "<>".to_owned()
        } else {
            format!("<{}>", lease.envelope_sender)
        };
        if let Err(error) = self
            .write(
                connection.get_mut(),
                format!(
                    "MAIL FROM:{reverse_path}{}{}{}{}{}\r\n",
                    if lease.require_tls { " REQUIRETLS" } else { "" },
                    if lease.smtp_utf8 { " SMTPUTF8" } else { "" },
                    lease
                        .dsn_ret
                        .as_ref()
                        .map_or_else(String::new, |value| format!(" RET={value}")),
                    lease
                        .envelope_id
                        .as_ref()
                        .map_or_else(String::new, |value| format!(" ENVID={value}")),
                    deliver_by
                )
                .as_bytes(),
            )
            .await
        {
            return Ok(deferred_io(host, &error));
        }
        if let Some(result) = classify_reply(self.reply(&mut connection).await, "MAIL FROM", &[250])
        {
            return Ok(result);
        }
        if let Err(error) = self
            .write(
                connection.get_mut(),
                format!(
                    "RCPT TO:<{}>{}{}\r\n",
                    lease.recipient,
                    lease
                        .dsn_notify
                        .as_ref()
                        .map_or_else(String::new, |value| format!(" NOTIFY={value}")),
                    lease
                        .original_recipient
                        .as_ref()
                        .map_or_else(String::new, |value| format!(" ORCPT={value}")),
                )
                .as_bytes(),
            )
            .await
        {
            return Ok(deferred_io(host, &error));
        }
        if let Some(result) = classify_reply(
            self.reply(&mut connection).await,
            "RCPT TO",
            &[250, 251, 252],
        ) {
            return Ok(result);
        }
        if let Err(error) = self.write(connection.get_mut(), b"DATA\r\n").await {
            return Ok(deferred_io(host, &error));
        }
        if let Some(result) = classify_reply(self.reply(&mut connection).await, "DATA", &[354]) {
            return Ok(result);
        }

        let mut offset = 0_u64;
        let mut line_start = true;
        let mut tail = [0_u8; 2];
        if let Some(header) = &dkim_header {
            let stuffed = dot_stuff(header, &mut line_start);
            if let Err(error) = self.write(connection.get_mut(), &stuffed).await {
                return Ok(deferred_io(host, &error));
            }
            for byte in header.iter().copied() {
                tail = [tail[1], byte];
            }
        }
        loop {
            let chunk = repository
                .read_message_chunk(lease.message_id, offset, MESSAGE_CHUNK)
                .await?;
            if chunk.is_empty() {
                break;
            }
            let stuffed = dot_stuff(&chunk, &mut line_start);
            if let Err(error) = self.write(connection.get_mut(), &stuffed).await {
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
        if tail != *b"\r\n"
            && let Err(error) = self.write(connection.get_mut(), b"\r\n").await
        {
            return Ok(deferred_io(host, &error));
        }
        if let Err(error) = self.write(connection.get_mut(), b".\r\n").await {
            return Ok(deferred_io(host, &error));
        }
        if let Some(result) = classify_final_reply(self.reply(&mut connection).await) {
            return Ok(result);
        }
        let _ = connection.get_mut().write_all(b"QUIT\r\n").await;
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

async fn prepare_dkim<R: MailRepository>(
    repository: &R,
    lease: &QueueLease,
    config: &DkimSigningConfig,
) -> Result<Result<Vec<u8>, String>, StorageError> {
    if has_line_break(&config.domain)
        || has_line_break(&config.selector)
        || config.domain.is_empty()
        || config.selector.is_empty()
    {
        return Ok(Err("invalid DKIM signing identity".into()));
    }
    let mut offset = 0_u64;
    let mut headers = Vec::new();
    let mut body = BodyHasher::new(Canonicalization::Relaxed);
    let mut in_headers = true;
    let mut boundary = Vec::with_capacity(3);
    loop {
        let chunk = repository
            .read_message_chunk(lease.message_id, offset, MESSAGE_CHUNK)
            .await?;
        if chunk.is_empty() {
            break;
        }
        for byte in chunk.iter().copied() {
            if in_headers {
                headers.push(byte);
                if headers.len() > MAX_SIGNED_HEADERS {
                    return Ok(Err("message headers exceed DKIM signing limit".into()));
                }
                boundary.push(byte);
                if boundary.len() > 4 {
                    boundary.remove(0);
                }
                if boundary == b"\r\n\r\n" {
                    headers.truncate(headers.len() - 2);
                    in_headers = false;
                }
            } else {
                body.update(&[byte]);
            }
        }
        offset = offset.saturating_add(chunk.len() as u64);
        if chunk.len() < MESSAGE_CHUNK as usize {
            break;
        }
    }
    if in_headers {
        return Ok(Err("message has no RFC 5322 header/body separator".into()));
    }
    let hash = body.finish();
    let dkim = match sign_headers(
        &headers,
        &hash,
        &config.domain,
        &config.selector,
        config.key.clone(),
        &["From", "To", "Cc", "Subject", "Date", "Message-ID"],
        Canonicalization::Relaxed,
        Canonicalization::Relaxed,
    ) {
        Ok(header) => header,
        Err(error) => return Ok(Err(format!("DKIM signing failed: {error}"))),
    };
    Ok(add_arc(
        &headers,
        &hash,
        config,
        dkim,
        lease.authentication_results_trust == AuthenticationResultsTrust::LocallyGenerated,
    ))
}

fn add_arc(
    headers: &[u8],
    hash: &str,
    config: &DkimSigningConfig,
    dkim: Vec<u8>,
    trusted_authentication_results: bool,
) -> Result<Vec<u8>, String> {
    if !trusted_authentication_results {
        return Ok(dkim);
    }
    let text = String::from_utf8_lossy(headers);
    let authentication_results = text
        .lines()
        .find_map(|line| line.strip_prefix("Authentication-Results:"))
        .map(str::trim);
    let Some(authentication_results) = authentication_results else {
        return Ok(dkim);
    };
    let chain_status = if authentication_results.contains("arc=pass") {
        ChainStatus::Pass
    } else if authentication_results.contains("arc=fail") {
        ChainStatus::Fail
    } else {
        ChainStatus::None
    };
    let owned = text
        .lines()
        .filter_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.starts_with("ARC-")
                .then(|| (name.to_owned(), value.trim().to_owned()))
        })
        .collect::<Vec<_>>();
    let existing = owned
        .iter()
        .map(|(name, value)| (name.as_str(), value.as_str()))
        .collect::<Vec<_>>();
    let arc = match seal_arc(
        headers,
        hash,
        authentication_results,
        &existing,
        chain_status,
        &ArcSealConfig {
            domain: config.domain.clone(),
            selector: config.selector.clone(),
            key: config.key.clone(),
        },
    ) {
        Ok(header) => header,
        Err(error) => return Err(format!("ARC sealing failed: {error}")),
    };
    Ok([arc, dkim].concat())
}

fn has_line_break(value: &str) -> bool {
    value.contains(['\r', '\n'])
}

fn no_client_auth(
    builder: rustls::ConfigBuilder<rustls::ClientConfig, rustls::client::WantsClientCert>,
) -> rustls::ClientConfig {
    builder.with_no_client_auth()
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

fn classify_final_reply(reply: io::Result<(u16, String)>) -> Option<SendResult> {
    match reply {
        Err(error) => Some(SendResult::Ambiguous {
            diagnostic: format!("final delivery status is unknown: {error}"),
        }),
        reply => classify_reply(reply, "message body", &[250]),
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

fn has_capability(reply_text: &str, name: &str) -> bool {
    reply_text.lines().any(|line| {
        line.split_ascii_whitespace()
            .next()
            .is_some_and(|keyword| keyword.eq_ignore_ascii_case(name))
    })
}

async fn read_reply<R: tokio::io::AsyncBufRead + Unpin>(read: &mut R) -> io::Result<(u16, String)> {
    let mut total = 0;
    let mut expected = None;
    let mut text = String::new();
    loop {
        let mut line = Vec::new();
        let remaining = REPLY_LIMIT.saturating_sub(total).saturating_add(1) as u64;
        let bytes = read.take(remaining).read_until(b'\n', &mut line).await?;
        total += bytes;
        if bytes == 0 || total > REPLY_LIMIT {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "SMTP reply too large or incomplete",
            ));
        }
        let (code, continued) = parse_reply_line(&line)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid SMTP reply"))?;
        if expected.replace(code).is_some_and(|first| first != code) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "inconsistent SMTP multiline reply",
            ));
        }
        if !text.is_empty() {
            text.push('\n');
        }
        text.push_str(&String::from_utf8_lossy(&line[4..line.len() - 2]));
        if !continued {
            return Ok((code, text));
        }
    }
}

/// Parses one complete, CRLF-terminated SMTP reply line.
#[must_use]
pub fn parse_reply_line(line: &[u8]) -> Option<(u16, bool)> {
    if line.len() < 5 || !line.ends_with(b"\r\n") || !line[..3].iter().all(u8::is_ascii_digit) {
        return None;
    }
    let code = u16::from(line[0] - b'0') * 100
        + u16::from(line[1] - b'0') * 10
        + u16::from(line[2] - b'0');
    match line[3] {
        b'-' => Some((code, true)),
        b' ' => Some((code, false)),
        _ => None,
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

    #[test]
    fn reply_line_requires_crlf_and_valid_separator() {
        assert_eq!(parse_reply_line(b"250-ok\r\n"), Some((250, true)));
        assert_eq!(parse_reply_line(b"250 ok\r\n"), Some((250, false)));
        assert_eq!(parse_reply_line(b"250?bad\r\n"), None);
        assert_eq!(parse_reply_line(b"250 bare\n"), None);
    }

    #[test]
    fn final_reply_loss_is_delivery_ambiguity() {
        assert!(matches!(
            classify_final_reply(Err(io::Error::new(io::ErrorKind::UnexpectedEof, "lost")),),
            Some(SendResult::Ambiguous { .. })
        ));
    }

    #[test]
    fn ehlo_capabilities_are_recognized_only_at_line_start() {
        assert!(has_capability("mx.example\nSTARTTLS\nSIZE 100", "STARTTLS"));
        assert!(!has_capability("mx.example says no STARTTLS", "STARTTLS"));
        assert!(!has_capability("XSTARTTLS", "STARTTLS"));
    }

    #[test]
    fn untrusted_authentication_results_cannot_trigger_arc_sealing() {
        let dkim = b"DKIM-Signature: test\r\n".to_vec();
        let config = DkimSigningConfig {
            domain: "example.test".into(),
            selector: "selector".into(),
            key: mail_dkim::SigningKey::Ed25519Pkcs8(vec![0; 32]),
        };
        assert_eq!(
            add_arc(
                b"Authentication-Results: attacker.example; arc=pass\r\n",
                "hash",
                &config,
                dkim.clone(),
                false,
            ),
            Ok(dkim)
        );
    }
}
