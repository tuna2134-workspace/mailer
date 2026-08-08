#![forbid(unsafe_code)]

mod arc_validation;
mod auth;
mod authentication;

pub use authentication::InboundAuthenticator;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use mail_message::{MessageLimits, MessageParser, ParseProgress};
use mail_smtp_proto::{
    Action, Command, DataError, ParseError, Reply, Session, SessionExtensions, Transaction,
    parse_command, unstuff_data_line,
};
use mail_storage::{
    LocalRecipient, SmtpMailOptions, SmtpRepository, StorageError, SubmissionRecipient,
};
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

trait SmtpIo: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> SmtpIo for T {}

struct BdatIngestion {
    id: uuid::Uuid,
    position: u32,
    size: u64,
    transaction: Transaction,
    recipients: Vec<LocalRecipient>,
    submission_recipients: Vec<SubmissionRecipient>,
}

#[derive(Clone)]
#[allow(clippy::struct_excessive_bools)]
pub struct SmtpConfig {
    pub hostname: String,
    pub max_message_size: u64,
    pub max_recipients: usize,
    pub max_connections: usize,
    pub command_timeout: Duration,
    pub data_timeout: Duration,
    pub allow_bare_lf: bool,
    pub tls: Option<Arc<rustls::ServerConfig>>,
    pub auth_plain: bool,
    pub auth_scram: bool,
    pub chunking: bool,
    pub dsn: bool,
    pub smtp_utf8: bool,
    pub require_tls: bool,
    pub require_auth: bool,
    pub authenticated_relay: bool,
    pub implicit_tls: bool,
    pub deliver_by_min_seconds: Option<u32>,
    pub future_release_max_seconds: Option<u32>,
    pub inbound_authentication: Option<Arc<InboundAuthenticator>>,
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
            tls: None,
            auth_plain: false,
            auth_scram: false,
            chunking: false,
            dsn: false,
            smtp_utf8: false,
            require_tls: false,
            require_auth: false,
            authenticated_relay: false,
            implicit_tls: false,
            deliver_by_min_seconds: None,
            future_release_max_seconds: None,
            inbound_authentication: None,
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
    #[error("authentication exchange failed")]
    Auth,
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

async fn accept_tls(
    stream: Box<dyn SmtpIo>,
    config: Arc<rustls::ServerConfig>,
    handshake_timeout: Duration,
) -> Result<(Box<dyn SmtpIo>, [u8; 32]), SmtpError> {
    let secured = timeout(
        handshake_timeout,
        tokio_rustls::TlsAcceptor::from(config).accept(stream),
    )
    .await
    .map_err(|_| SmtpError::Timeout)?
    .map_err(io)?;
    let mut exporter = [0_u8; 32];
    secured
        .get_ref()
        .1
        .export_keying_material(&mut exporter, b"EXPORTER-Channel-Binding", None)
        .map_err(|_| SmtpError::Auth)?;
    Ok((Box::new(secured), exporter))
}

#[allow(clippy::too_many_lines, clippy::semicolon_if_nothing_returned)]
pub async fn run_session<S, R>(
    stream: S,
    peer: SocketAddr,
    repository: &R,
    config: &SmtpConfig,
) -> Result<(), SmtpError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    R: SmtpRepository,
{
    let stream: Box<dyn SmtpIo> = Box::new(stream);
    let (mut stream, initial_exporter) = if config.implicit_tls {
        let tls = config.tls.clone().ok_or(SmtpError::Storage)?;
        let (stream, exporter) = accept_tls(stream, tls, config.command_timeout).await?;
        (stream, Some(exporter))
    } else {
        (stream, None)
    };
    write_reply(
        &mut stream,
        &Reply {
            code: 220,
            enhanced: Some("2.0.0"),
            text: "Service ready",
        },
    )
    .await?;
    let mut session = Session::with_extensions(
        config.max_recipients,
        SessionExtensions {
            hostname: config.hostname.clone(),
            max_message_size: config.max_message_size,
            starttls: config.tls.is_some(),
            auth_plain: config.auth_plain,
            auth_scram: config.auth_scram,
            dsn: config.dsn,
            chunking: config.chunking,
            smtp_utf8: config.smtp_utf8,
            require_tls: config.require_tls,
            deliver_by_min_seconds: config.deliver_by_min_seconds,
            future_release_max_seconds: config.future_release_max_seconds,
        },
    );
    if config.implicit_tls {
        session.reset_after_tls();
    }
    let mut resolved = HashMap::<String, LocalRecipient>::new();
    let mut auth_attempts = 0_u8;
    let mut tls_exporter = initial_exporter;
    let mut authenticated_user = None;
    let mut relay = HashMap::<String, SubmissionRecipient>::new();
    let mut bdat: Option<BdatIngestion> = None;
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
        if let Command::Mail { reverse_path, .. } = &command
            && config.require_auth
        {
            let Some(user_id) = authenticated_user else {
                write_reply(
                    &mut stream,
                    &Reply {
                        code: 530,
                        enhanced: Some("5.7.0"),
                        text: "Authentication required",
                    },
                )
                .await?;
                continue;
            };
            if !repository
                .authorize_smtp_sender(user_id, reverse_path)
                .await
                .map_err(storage)?
            {
                write_reply(
                    &mut stream,
                    &Reply {
                        code: 553,
                        enhanced: Some("5.7.1"),
                        text: "Sender address is not authorized",
                    },
                )
                .await?;
                continue;
            }
        }
        if bdat.is_some()
            && !matches!(
                command,
                Command::Bdat { .. } | Command::Rset | Command::Quit
            )
        {
            write_reply(
                &mut stream,
                &Reply {
                    code: 503,
                    enhanced: Some("5.5.1"),
                    text: "BDAT transaction in progress",
                },
            )
            .await?;
            continue;
        }
        if matches!(
            command,
            Command::Ehlo(_)
                | Command::Helo(_)
                | Command::Mail { .. }
                | Command::Rset
                | Command::Quit
        ) {
            if let Some(ingestion) = bdat.take() {
                repository
                    .abort_smtp_ingestion(ingestion.id)
                    .await
                    .map_err(storage)?;
            }
            resolved.clear();
            relay.clear();
        }
        let action = session.command(command);
        match action {
            Action::Reply(reply) => write_reply(&mut stream, &reply).await?,
            Action::Ehlo {
                greeting,
                capabilities,
            } => write_ehlo(&mut stream, &greeting, &capabilities).await?,
            Action::StartTls(reply) => {
                write_reply(&mut stream, &reply).await?;
                let tls = config.tls.clone().ok_or(SmtpError::Storage)?;
                let (secured, exporter) = accept_tls(stream, tls, config.command_timeout).await?;
                tls_exporter = Some(exporter);
                stream = secured;
                session.reset_after_tls();
                authenticated_user = None;
                resolved.clear();
            }
            Action::Authenticate {
                mechanism,
                initial_response,
            } => {
                auth_attempts = auth_attempts.saturating_add(1);
                if auth_attempts > 3 {
                    write_reply(&mut stream, &auth_failed()).await?;
                    continue;
                }
                let response =
                    read_auth_response(&mut stream, initial_response, config.command_timeout, true)
                        .await?;
                if response == "*" {
                    write_reply(
                        &mut stream,
                        &Reply {
                            code: 501,
                            enhanced: Some("5.7.0"),
                            text: "Authentication cancelled",
                        },
                    )
                    .await?;
                } else if mechanism == "PLAIN" {
                    let authenticated = auth::authenticate(repository, &response).await?;
                    let Some(user_id) = authenticated else {
                        write_reply(&mut stream, &auth_failed()).await?;
                        continue;
                    };
                    authenticated_user = Some(user_id);
                    session.authentication_succeeded();
                    write_reply(
                        &mut stream,
                        &Reply {
                            code: 235,
                            enhanced: Some("2.7.0"),
                            text: "Authentication successful",
                        },
                    )
                    .await?;
                } else if matches!(mechanism.as_str(), "SCRAM-SHA-256" | "SCRAM-SHA-256-PLUS") {
                    let mechanism = if mechanism == "SCRAM-SHA-256-PLUS" {
                        mail_sasl::ScramMechanism::Sha256Plus
                    } else {
                        mail_sasl::ScramMechanism::Sha256
                    };
                    let client_first = STANDARD
                        .decode(&response)
                        .ok()
                        .and_then(|value| String::from_utf8(value).ok());
                    let Some(client_first) = client_first else {
                        write_reply(&mut stream, &auth_failed()).await?;
                        continue;
                    };
                    let Ok((server_first, exchange)) = auth::begin_scram(
                        repository,
                        mechanism,
                        &client_first,
                        tls_exporter.as_ref().map(<[u8; 32]>::as_slice),
                    )
                    .await
                    else {
                        write_reply(&mut stream, &auth_failed()).await?;
                        continue;
                    };
                    stream
                        .write_all(format!("334 {}\r\n", STANDARD.encode(server_first)).as_bytes())
                        .await
                        .map_err(io)?;
                    let client_final =
                        read_auth_response(&mut stream, None, config.command_timeout, false)
                            .await?;
                    let client_final = STANDARD
                        .decode(client_final)
                        .ok()
                        .and_then(|value| String::from_utf8(value).ok());
                    let result = match client_final {
                        Some(value) => auth::finish_scram(repository, exchange, &value).await?,
                        None => None,
                    };
                    if let Some((user_id, server_final)) = result {
                        authenticated_user = Some(user_id);
                        session.authentication_succeeded();
                        stream
                            .write_all(
                                format!("235 2.7.0 {}\r\n", STANDARD.encode(server_final))
                                    .as_bytes(),
                            )
                            .await
                            .map_err(io)?;
                    } else {
                        write_reply(&mut stream, &auth_failed()).await?;
                    }
                } else {
                    write_reply(&mut stream, &auth_failed()).await?;
                }
            }
            Action::BeginBdat {
                transaction,
                size,
                last,
            } => {
                if bdat.is_none() {
                    let recipients = transaction
                        .recipients
                        .iter()
                        .filter_map(|address| resolved.get(address).cloned())
                        .collect();
                    let submission_recipients =
                        submission_recipients(&transaction, &resolved, &relay);
                    bdat = Some(BdatIngestion {
                        id: repository.begin_smtp_ingestion().await.map_err(storage)?,
                        position: 0,
                        size: 0,
                        transaction,
                        recipients,
                        submission_recipients,
                    });
                }
                let ingestion = bdat.as_mut().ok_or(SmtpError::Storage)?;
                let Ok(result) = timeout(
                    config.data_timeout,
                    receive_bdat_piece(&mut stream, repository, config, ingestion, size),
                )
                .await
                else {
                    let ingestion = bdat.take().ok_or(SmtpError::Storage)?;
                    repository
                        .abort_smtp_ingestion(ingestion.id)
                        .await
                        .map_err(storage)?;
                    return Err(SmtpError::Timeout);
                };
                if let Err(error) = result {
                    let ingestion = bdat.take().ok_or(SmtpError::Storage)?;
                    repository
                        .abort_smtp_ingestion(ingestion.id)
                        .await
                        .map_err(storage)?;
                    session.finish_data();
                    resolved.clear();
                    relay.clear();
                    write_reply(&mut stream, &data_failure_reply(&error)).await?;
                    continue;
                }
                if last {
                    let ingestion = bdat.take().ok_or(SmtpError::Storage)?;
                    let received =
                        received_header(&config.hostname, peer, session.peer_name.as_deref());
                    let authentication = authentication_headers(
                        config,
                        repository,
                        ingestion.id,
                        peer,
                        &ingestion.transaction.reverse_path,
                        session.peer_name.as_deref(),
                    )
                    .await?;
                    let prefix = [received.as_bytes(), authentication.as_slice()].concat();
                    if config.authenticated_relay {
                        repository
                            .commit_submission_ingestion(
                                ingestion.id,
                                authenticated_user.ok_or(SmtpError::Auth)?,
                                &ingestion.transaction.reverse_path,
                                &ingestion.submission_recipients,
                                &prefix,
                                &mail_options(&ingestion.transaction),
                            )
                            .await
                            .map_err(storage)?;
                    } else {
                        repository
                            .commit_smtp_ingestion(
                                ingestion.id,
                                &ingestion.transaction.reverse_path,
                                &ingestion.recipients,
                                &prefix,
                                &mail_options(&ingestion.transaction),
                            )
                            .await
                            .map_err(storage)?;
                    }
                    session.finish_data();
                    resolved.clear();
                }
                write_reply(
                    &mut stream,
                    &Reply {
                        code: 250,
                        enhanced: Some("2.0.0"),
                        text: if last {
                            "Message accepted for delivery"
                        } else {
                            "BDAT chunk accepted"
                        },
                    },
                )
                .await?;
            }
            Action::Quit(reply) => {
                write_reply(&mut stream, &reply).await?;
                return Ok(());
            }
            Action::Recipient {
                address,
                parameters,
            } => {
                if resolved.contains_key(&address) {
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
                        let recipient = LocalRecipient {
                            dsn_notify: parameters.notify,
                            original_recipient: parameters.orcpt.or(recipient.original_recipient),
                            ..recipient
                        };
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
                        if config.authenticated_relay && authenticated_user.is_some() {
                            relay.insert(
                                address.clone(),
                                SubmissionRecipient {
                                    address: address.clone(),
                                    dsn_notify: parameters.notify,
                                    original_recipient: parameters.orcpt,
                                },
                            );
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
                        } else {
                            write_reply(
                                &mut stream,
                                &Reply {
                                    code: 550,
                                    enhanced: Some("5.1.1"),
                                    text: "No such local recipient; relaying denied",
                                },
                            )
                            .await?;
                        }
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
                let submission_recipients = submission_recipients(&transaction, &resolved, &relay);
                let result = timeout(
                    config.data_timeout,
                    receive_data(
                        &mut stream,
                        repository,
                        config,
                        peer,
                        session.peer_name.as_deref(),
                        &transaction,
                        &recipients,
                        authenticated_user,
                        &submission_recipients,
                    ),
                )
                .await;
                session.finish_data();
                resolved.clear();
                relay.clear();
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
                    Ok(Err(SmtpError::Data(
                        DataError::InvalidLineEnding | DataError::InvalidMessage,
                    ))) => {
                        write_reply(
                            &mut stream,
                            &Reply {
                                code: 554,
                                enhanced: Some("5.6.0"),
                                text: "Malformed message data",
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

#[allow(clippy::too_many_arguments)]
async fn receive_data<S: AsyncRead + AsyncWrite + Unpin, R: SmtpRepository>(
    stream: &mut S,
    repository: &R,
    config: &SmtpConfig,
    peer: SocketAddr,
    helo: Option<&str>,
    transaction: &Transaction,
    recipients: &[LocalRecipient],
    authenticated_user: Option<uuid::Uuid>,
    submission_recipients: &[SubmissionRecipient],
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
    let authentication = authentication_headers(
        config,
        repository,
        ingestion,
        peer,
        &transaction.reverse_path,
        helo,
    )
    .await?;
    let prefix = [received.as_bytes(), authentication.as_slice()].concat();
    if config.authenticated_relay {
        repository
            .commit_submission_ingestion(
                ingestion,
                authenticated_user.ok_or(SmtpError::Auth)?,
                &transaction.reverse_path,
                submission_recipients,
                &prefix,
                &mail_options(transaction),
            )
            .await
            .map_err(storage)?;
    } else {
        repository
            .commit_smtp_ingestion(
                ingestion,
                &transaction.reverse_path,
                recipients,
                &prefix,
                &mail_options(transaction),
            )
            .await
            .map_err(storage)?;
    }
    Ok(())
}

async fn authentication_headers<R: SmtpRepository>(
    config: &SmtpConfig,
    repository: &R,
    ingestion_id: uuid::Uuid,
    peer: SocketAddr,
    sender: &str,
    helo: Option<&str>,
) -> Result<Vec<u8>, SmtpError> {
    if config.authenticated_relay {
        return Ok(Vec::new());
    }
    let Some(authenticator) = &config.inbound_authentication else {
        return Ok(Vec::new());
    };
    authenticator
        .headers(
            repository,
            ingestion_id,
            peer.ip(),
            sender,
            helo.unwrap_or("unknown"),
        )
        .await
        .map_err(storage)
}

fn mail_options(transaction: &Transaction) -> SmtpMailOptions {
    let now = std::time::SystemTime::now();
    let deliver_by_at = transaction.parameters.deliver_by.map(|request| {
        if request.seconds >= 0 {
            now + Duration::from_secs(u64::from(request.seconds.unsigned_abs()))
        } else {
            now - Duration::from_secs(u64::from(request.seconds.unsigned_abs()))
        }
    });
    let release_at = transaction
        .parameters
        .future_release
        .map(|request| match request {
            mail_smtp_proto::FutureRelease::HoldFor(seconds) => {
                now + Duration::from_secs(u64::from(seconds))
            }
            mail_smtp_proto::FutureRelease::HoldUntil(until) => until,
        });
    SmtpMailOptions {
        smtp_utf8: transaction.parameters.smtp_utf8,
        require_tls: transaction.parameters.require_tls,
        dsn_ret: transaction.parameters.ret.clone(),
        envelope_id: transaction.parameters.envid.clone(),
        deliver_by_at,
        deliver_by_mode: transaction
            .parameters
            .deliver_by
            .map(|request| match request.mode {
                mail_smtp_proto::DeliverByMode::Notify => "N".into(),
                mail_smtp_proto::DeliverByMode::Return => "R".into(),
            }),
        deliver_by_trace: transaction
            .parameters
            .deliver_by
            .is_some_and(|request| request.trace),
        release_at,
    }
}

fn submission_recipients(
    transaction: &Transaction,
    local: &HashMap<String, LocalRecipient>,
    relay: &HashMap<String, SubmissionRecipient>,
) -> Vec<SubmissionRecipient> {
    transaction
        .recipients
        .iter()
        .filter_map(|address| {
            relay.get(address).cloned().or_else(|| {
                local.get(address).map(|recipient| SubmissionRecipient {
                    address: address.clone(),
                    dsn_notify: recipient.dsn_notify.clone(),
                    original_recipient: recipient.original_recipient.clone(),
                })
            })
        })
        .collect()
}

async fn receive_bdat_piece<S: AsyncRead + Unpin, R: SmtpRepository>(
    stream: &mut S,
    repository: &R,
    config: &SmtpConfig,
    ingestion: &mut BdatIngestion,
    octets: u64,
) -> Result<(), SmtpError> {
    let too_large = ingestion.size.saturating_add(octets) > config.max_message_size;
    if octets == 0 && ingestion.position == 0 {
        repository
            .append_smtp_chunk(ingestion.id, 0, &[])
            .await
            .map_err(storage)?;
        ingestion.position = 1;
    }
    let mut remaining = octets;
    let mut buffer = vec![0_u8; CHUNK_SIZE];
    while remaining != 0 {
        let length =
            usize::try_from(remaining.min(CHUNK_SIZE as u64)).map_err(|_| DataError::TooLarge)?;
        stream.read_exact(&mut buffer[..length]).await.map_err(io)?;
        if !too_large {
            repository
                .append_smtp_chunk(ingestion.id, ingestion.position, &buffer[..length])
                .await
                .map_err(storage)?;
            ingestion.position = ingestion
                .position
                .checked_add(1)
                .ok_or(SmtpError::Storage)?;
        }
        remaining -= length as u64;
    }
    if too_large {
        return Err(DataError::TooLarge.into());
    }
    ingestion.size += octets;
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
    let mut message = MessageParser::new(MessageLimits::default());
    let mut headers_complete = false;
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
        if !headers_complete {
            match message.push(content) {
                Ok(ParseProgress::Complete { .. }) => headers_complete = true,
                Ok(ParseProgress::NeedMore) => {}
                Err(_) => {
                    drain_data(stream, config.allow_bare_lf).await?;
                    return Err(DataError::InvalidMessage.into());
                }
            }
        }
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
    if !headers_complete && message.finish().is_err() {
        return Err(DataError::InvalidMessage.into());
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

async fn read_auth_response<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    initial: Option<String>,
    command_timeout: Duration,
    send_empty_challenge: bool,
) -> Result<String, SmtpError> {
    if let Some(value) = initial.filter(|value| value != "=") {
        return Ok(value);
    }
    if send_empty_challenge {
        stream.write_all(b"334 \r\n").await.map_err(io)?;
    }
    let Some(line) = timeout(command_timeout, read_line_bounded(stream, 4096))
        .await
        .map_err(|_| SmtpError::Timeout)??
    else {
        return Err(SmtpError::Io("EOF during AUTH".into()));
    };
    String::from_utf8(line)
        .map(|value| value.trim_end_matches(['\r', '\n']).to_owned())
        .map_err(|_| SmtpError::Auth)
}

async fn write_ehlo<S: AsyncWrite + Unpin>(
    stream: &mut S,
    greeting: &Reply,
    capabilities: &[String],
) -> Result<(), SmtpError> {
    stream
        .write_all(format!("{}-{}\r\n", greeting.code, greeting.text).as_bytes())
        .await
        .map_err(io)?;
    for (index, capability) in capabilities.iter().enumerate() {
        let separator = if index + 1 == capabilities.len() {
            ' '
        } else {
            '-'
        };
        stream
            .write_all(format!("{}{separator}{capability}\r\n", greeting.code).as_bytes())
            .await
            .map_err(io)?;
    }
    Ok(())
}

const fn auth_failed() -> Reply {
    Reply {
        code: 535,
        enhanced: Some("5.7.8"),
        text: "Authentication credentials invalid",
    }
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

fn data_failure_reply(error: &SmtpError) -> Reply {
    match error {
        SmtpError::Data(DataError::TooLarge) => Reply {
            code: 552,
            enhanced: Some("5.3.4"),
            text: "Message size exceeds fixed maximum",
        },
        SmtpError::Storage => Reply {
            code: 451,
            enhanced: Some("4.3.0"),
            text: "Temporary local storage failure",
        },
        _ => Reply {
            code: 554,
            enhanced: Some("5.6.0"),
            text: "BDAT rejected",
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
        auth_hash: Mutex<Option<String>>,
        scram: Mutex<Option<mail_storage::SmtpScramCredential>>,
        submitted: Mutex<Vec<String>>,
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
                mailbox_id: Some(MailboxId::new(Uuid::nil())),
                dsn_notify: None,
                original_recipient: None,
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
            _: &SmtpMailOptions,
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

        async fn smtp_auth_account(
            &self,
            identity: &str,
        ) -> Result<Option<mail_storage::SmtpAuthAccount>, StorageError> {
            let hash = self
                .auth_hash
                .lock()
                .map_err(|_| StorageError::Unavailable("lock".into()))?
                .clone();
            let scram = self
                .scram
                .lock()
                .map_err(|_| StorageError::Unavailable("lock".into()))?
                .clone();
            Ok(
                (identity == "alice@example.test").then(|| mail_storage::SmtpAuthAccount {
                    user_id: Uuid::nil(),
                    password_hashes: hash.into_iter().collect(),
                    scram,
                }),
            )
        }

        async fn record_smtp_auth(&self, _: Uuid, _: bool) -> Result<(), StorageError> {
            Ok(())
        }

        async fn authorize_smtp_sender(
            &self,
            user_id: Uuid,
            sender: &str,
        ) -> Result<bool, StorageError> {
            Ok(user_id == Uuid::nil() && sender == "alice@example.test")
        }

        async fn commit_submission_ingestion(
            &self,
            _: Uuid,
            _: Uuid,
            _: &str,
            recipients: &[SubmissionRecipient],
            _: &[u8],
            _: &SmtpMailOptions,
        ) -> Result<StoredMessage, StorageError> {
            self.submitted
                .lock()
                .map_err(|_| StorageError::Unavailable("lock".into()))?
                .extend(recipients.iter().map(|value| value.address.clone()));
            Ok(StoredMessage {
                message_ids: vec![Uuid::nil()],
                octets: 0,
            })
        }
    }

    async fn response<R: AsyncBufRead + Unpin>(reader: &mut R) -> Result<String, std::io::Error> {
        let mut line = String::new();
        reader.read_line(&mut line).await?;
        if line.starts_with("250-") {
            loop {
                let mut continuation = String::new();
                reader.read_line(&mut continuation).await?;
                if continuation.starts_with("250 ") {
                    break;
                }
            }
        }
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
    async fn tcp_listener_receives_a_real_smtp_message() -> Result<(), Box<dyn std::error::Error>> {
        let repository = Arc::new(Repository::default());
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let task_repository = Arc::clone(&repository);
        let server =
            tokio::spawn(
                async move { serve(listener, task_repository, SmtpConfig::default()).await },
            );
        let client = TcpStream::connect(address).await?;
        let (read, mut write) = tokio::io::split(client);
        let mut reader = BufReader::new(read);
        assert!(response(&mut reader).await?.starts_with("220 "));
        for (command, code) in [
            ("EHLO sender.example\r\n", "250"),
            ("MAIL FROM:<sender@example.net>\r\n", "250"),
            ("RCPT TO:<alice@example.test>\r\n", "250"),
            ("DATA\r\n", "354"),
        ] {
            write.write_all(command.as_bytes()).await?;
            assert!(response(&mut reader).await?.starts_with(code));
        }
        write
            .write_all(b"Subject: docker e2e\r\n\r\nreal body\r\n.\r\n")
            .await?;
        assert!(response(&mut reader).await?.starts_with("250"));
        write.write_all(b"QUIT\r\n").await?;
        assert!(response(&mut reader).await?.starts_with("221"));
        assert!(*repository.committed.lock().map_err(|_| "lock")?);
        assert!(
            repository
                .chunks
                .lock()
                .map_err(|_| "lock")?
                .ends_with(b"real body\r\n")
        );
        server.abort();
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

    #[tokio::test]
    async fn rejects_orphan_header_continuation_without_committing() {
        let repository = Repository::default();
        let mut input = &b" injected: value\r\nSubject: safe\r\n\r\nbody\r\n.\r\n"[..];
        let result =
            receive_data_inner(&mut input, &repository, &SmtpConfig::default(), Uuid::nil()).await;
        assert!(matches!(
            result,
            Err(SmtpError::Data(DataError::InvalidMessage))
        ));
        assert!(
            repository
                .chunks
                .lock()
                .is_ok_and(|chunks| chunks.is_empty())
        );
    }

    #[tokio::test]
    async fn enforces_data_line_limit_at_exact_boundary() {
        let repository = Repository::default();
        let mut boundary = b"X: ".to_vec();
        boundary.resize(DATA_LINE_LIMIT - 2, b'a');
        boundary.extend_from_slice(b"\r\n\r\n.\r\n");
        let mut input = boundary.as_slice();
        assert!(
            receive_data_inner(&mut input, &repository, &SmtpConfig::default(), Uuid::nil(),)
                .await
                .is_ok()
        );

        let repository = Repository::default();
        boundary.insert(DATA_LINE_LIMIT - 2, b'a');
        let mut input = boundary.as_slice();
        assert!(matches!(
            receive_data_inner(&mut input, &repository, &SmtpConfig::default(), Uuid::nil(),).await,
            Err(SmtpError::Data(DataError::LineTooLong))
        ));
    }

    #[tokio::test]
    async fn rejects_incomplete_dot_terminator_without_committing() {
        let repository = Repository::default();
        let mut input = &b"Subject: safe\r\n\r\nbody\r\n.\r"[..];
        let result =
            receive_data_inner(&mut input, &repository, &SmtpConfig::default(), Uuid::nil()).await;
        assert!(matches!(
            result,
            Err(SmtpError::Data(DataError::InvalidLineEnding))
        ));
        assert!(
            repository
                .chunks
                .lock()
                .is_ok_and(|chunks| chunks.is_empty())
        );
    }

    #[tokio::test]
    async fn submission_rejects_unauthenticated_mail() -> Result<(), Box<dyn std::error::Error>> {
        let (client, server) = duplex(4096);
        let peer: SocketAddr = "192.0.2.5:2525".parse()?;
        let config = SmtpConfig {
            require_auth: true,
            authenticated_relay: true,
            ..SmtpConfig::default()
        };
        let task = tokio::spawn(async move {
            run_session(server, peer, &Repository::default(), &config).await
        });
        let (read, mut write) = tokio::io::split(client);
        let mut reader = BufReader::new(read);
        assert!(response(&mut reader).await?.starts_with("220 "));
        write.write_all(b"EHLO client.example\r\n").await?;
        assert!(response(&mut reader).await?.starts_with("250-"));
        write
            .write_all(b"MAIL FROM:<sender@example.test>\r\n")
            .await?;
        assert!(response(&mut reader).await?.starts_with("530 "));
        write.write_all(b"QUIT\r\n").await?;
        assert!(response(&mut reader).await?.starts_with("221 "));
        task.await??;
        Ok(())
    }

    #[tokio::test]
    async fn bdat_streams_exact_octets() -> Result<(), Box<dyn std::error::Error>> {
        let (client, server) = duplex(16 * 1024);
        let repository = Arc::new(Repository::default());
        let task_repository = Arc::clone(&repository);
        let peer: SocketAddr = "192.0.2.3:2525".parse()?;
        let config = SmtpConfig {
            chunking: true,
            ..SmtpConfig::default()
        };
        let task = tokio::spawn(async move {
            run_session(server, peer, task_repository.as_ref(), &config).await
        });
        let (read, mut write) = tokio::io::split(client);
        let mut reader = BufReader::new(read);
        assert!(response(&mut reader).await?.starts_with("220 "));
        for command in [
            "EHLO client.example\r\n",
            "MAIL FROM:<sender@example.net> BODY=BINARYMIME\r\n",
            "RCPT TO:<alice@example.test>\r\n",
        ] {
            write.write_all(command.as_bytes()).await?;
            assert!(response(&mut reader).await?.starts_with("250"));
        }
        write.write_all(b"BDAT 3\r\nabc").await?;
        assert!(response(&mut reader).await?.starts_with("250"));
        write.write_all(b"BDAT 3 LAST\r\ndef").await?;
        assert!(response(&mut reader).await?.starts_with("250"));
        write.write_all(b"QUIT\r\n").await?;
        assert!(response(&mut reader).await?.starts_with("221"));
        task.await??;
        assert_eq!(*repository.chunks.lock().map_err(|_| "lock")?, b"abcdef");
        Ok(())
    }

    #[tokio::test]
    async fn starttls_authenticates_and_submits_without_open_relay()
    -> Result<(), Box<dyn std::error::Error>> {
        use argon2::{Argon2, PasswordHasher as _, password_hash::SaltString};
        use rustls::{
            ClientConfig, RootCertStore, ServerConfig,
            pki_types::{PrivatePkcs8KeyDer, ServerName},
        };

        let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new())?;
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params
            .key_usages
            .push(rcgen::KeyUsagePurpose::KeyCertSign);
        let ca_key = rcgen::KeyPair::generate()?;
        let ca_certificate = ca_params.self_signed(&ca_key)?;
        let issuer = rcgen::Issuer::new(ca_params, ca_key);
        let leaf_key = rcgen::KeyPair::generate()?;
        let certificate = rcgen::CertificateParams::new(vec!["localhost".into()])?
            .signed_by(&leaf_key, &issuer)?;
        let server_tls =
            ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()?
                .with_no_client_auth()
                .with_single_cert(
                    vec![certificate.der().clone()],
                    PrivatePkcs8KeyDer::from(leaf_key.serialize_der()).into(),
                )?;
        let mut roots = RootCertStore::empty();
        roots.add(ca_certificate.der().clone())?;
        let client_tls =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()?
                .with_root_certificates(roots)
                .with_no_client_auth();

        let (client, server) = duplex(16 * 1024);
        let password_hash = Argon2::default()
            .hash_password(
                b"secret",
                &SaltString::encode_b64(b"0123456789abcdef").map_err(|_| "salt")?,
            )
            .map_err(|_| "password hash")?
            .to_string();
        let repository = Arc::new(Repository {
            auth_hash: Mutex::new(Some(password_hash)),
            ..Repository::default()
        });
        let task_repository = Arc::clone(&repository);
        let peer: SocketAddr = "192.0.2.4:2525".parse()?;
        let config = SmtpConfig {
            tls: Some(Arc::new(server_tls)),
            auth_plain: true,
            require_auth: true,
            authenticated_relay: true,
            ..SmtpConfig::default()
        };
        let task = tokio::spawn(async move {
            run_session(server, peer, task_repository.as_ref(), &config).await
        });
        let mut client = BufReader::new(client);
        assert!(response(&mut client).await?.starts_with("220 "));
        client.get_mut().write_all(b"EHLO localhost\r\n").await?;
        assert!(response(&mut client).await?.starts_with("250-"));
        client.get_mut().write_all(b"STARTTLS\r\n").await?;
        assert!(response(&mut client).await?.starts_with("220 "));

        let client = tokio_rustls::TlsConnector::from(Arc::new(client_tls))
            .connect(ServerName::try_from("localhost")?, client.into_inner())
            .await?;
        let mut client = BufReader::new(client);
        client
            .get_mut()
            .write_all(b"AUTH PLAIN AGFsaWNlQGV4YW1wbGUudGVzdABzZWNyZXQ=\r\n")
            .await?;
        assert!(response(&mut client).await?.starts_with("503 "));
        client.get_mut().write_all(b"EHLO localhost\r\n").await?;
        assert!(response(&mut client).await?.starts_with("250-"));
        client
            .get_mut()
            .write_all(b"AUTH PLAIN AGFsaWNlQGV4YW1wbGUudGVzdABzZWNyZXQ=\r\n")
            .await?;
        assert!(response(&mut client).await?.starts_with("235 "));
        for (command, expected) in [
            ("MAIL FROM:<alice@example.test>\r\n", "250 "),
            ("RCPT TO:<bob@remote.test>\r\n", "250 "),
            ("DATA\r\n", "354 "),
        ] {
            client.get_mut().write_all(command.as_bytes()).await?;
            assert!(response(&mut client).await?.starts_with(expected));
        }
        client
            .get_mut()
            .write_all(b"Subject: submitted\r\n\r\nbody\r\n.\r\n")
            .await?;
        assert!(response(&mut client).await?.starts_with("250 "));
        client.get_mut().write_all(b"QUIT\r\n").await?;
        assert!(response(&mut client).await?.starts_with("221 "));
        task.await??;
        assert_eq!(
            *repository.submitted.lock().map_err(|_| "lock")?,
            ["bob@remote.test"]
        );
        Ok(())
    }

    #[tokio::test]
    async fn scram_sha_256_plus_uses_tls_exporter() -> Result<(), Box<dyn std::error::Error>> {
        use rustls::{
            ClientConfig, RootCertStore, ServerConfig,
            pki_types::{PrivatePkcs8KeyDer, ServerName},
        };

        let identity = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
        let certificate = identity.cert.der().clone();
        let server_tls =
            ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()?
                .with_no_client_auth()
                .with_single_cert(
                    vec![certificate.clone()],
                    PrivatePkcs8KeyDer::from(identity.signing_key.serialize_der()).into(),
                )?;
        let mut roots = RootCertStore::empty();
        roots.add(certificate)?;
        let client_tls =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()?
                .with_root_certificates(roots)
                .with_no_client_auth();
        let salt = b"0123456789abcdef";
        let credential = mail_sasl::derive_credential(
            b"secret",
            salt,
            std::num::NonZeroU32::new(4096).ok_or("iterations")?,
        );
        let repository = Arc::new(Repository {
            scram: Mutex::new(Some(mail_storage::SmtpScramCredential {
                salt: credential.salt,
                iterations: credential.iterations.get(),
                stored_key: credential.stored_key.to_vec(),
                server_key: credential.server_key.to_vec(),
            })),
            ..Repository::default()
        });
        let task_repository = Arc::clone(&repository);
        let (client, server) = duplex(16 * 1024);
        let peer: SocketAddr = "192.0.2.6:2525".parse()?;
        let config = SmtpConfig {
            tls: Some(Arc::new(server_tls)),
            auth_scram: true,
            ..SmtpConfig::default()
        };
        let task = tokio::spawn(async move {
            run_session(server, peer, task_repository.as_ref(), &config).await
        });
        let mut client = BufReader::new(client);
        assert!(response(&mut client).await?.starts_with("220 "));
        client.get_mut().write_all(b"EHLO localhost\r\n").await?;
        let _ = response(&mut client).await?;
        client.get_mut().write_all(b"STARTTLS\r\n").await?;
        assert!(response(&mut client).await?.starts_with("220 "));
        let client = tokio_rustls::TlsConnector::from(Arc::new(client_tls))
            .connect(ServerName::try_from("localhost")?, client.into_inner())
            .await?;
        let mut exporter = [0_u8; 32];
        client.get_ref().1.export_keying_material(
            &mut exporter,
            b"EXPORTER-Channel-Binding",
            None,
        )?;
        let mut client = BufReader::new(client);
        client.get_mut().write_all(b"EHLO localhost\r\n").await?;
        let _ = response(&mut client).await?;
        let first_bare = "n=alice@example.test,r=clientnonce123";
        let first = format!("p=tls-exporter,,{first_bare}");
        client
            .get_mut()
            .write_all(format!("AUTH SCRAM-SHA-256-PLUS {}\r\n", STANDARD.encode(first)).as_bytes())
            .await?;
        let challenge = response(&mut client).await?;
        let server_first = String::from_utf8(
            STANDARD.decode(
                challenge
                    .strip_prefix("334 ")
                    .ok_or("SCRAM challenge")?
                    .trim_end(),
            )?,
        )?;
        let final_message =
            scram_client_final(b"secret", salt, 4096, first_bare, &server_first, &exporter)?;
        client
            .get_mut()
            .write_all(format!("{}\r\n", STANDARD.encode(final_message)).as_bytes())
            .await?;
        assert!(response(&mut client).await?.starts_with("235 "));
        client.get_mut().write_all(b"QUIT\r\n").await?;
        let _ = response(&mut client).await?;
        task.await??;
        Ok(())
    }

    fn scram_client_final(
        password: &[u8],
        salt: &[u8],
        iterations: u32,
        first_bare: &str,
        server_first: &str,
        exporter: &[u8],
    ) -> Result<String, Box<dyn std::error::Error>> {
        use ring::{digest, hmac, pbkdf2};
        let nonce = server_first
            .split(',')
            .find_map(|value| value.strip_prefix("r="))
            .ok_or("server nonce")?;
        let mut binding = b"p=tls-exporter,,".to_vec();
        binding.extend_from_slice(exporter);
        let without_proof = format!("c={},r={nonce}", STANDARD.encode(binding));
        let auth_message = format!("{first_bare},{server_first},{without_proof}");
        let mut salted = [0_u8; 32];
        pbkdf2::derive(
            pbkdf2::PBKDF2_HMAC_SHA256,
            std::num::NonZeroU32::new(iterations).ok_or("iterations")?,
            salt,
            password,
            &mut salted,
        );
        let client_key = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, &salted), b"Client Key");
        let stored_key = digest::digest(&digest::SHA256, client_key.as_ref());
        let signature = hmac::sign(
            &hmac::Key::new(hmac::HMAC_SHA256, stored_key.as_ref()),
            auth_message.as_bytes(),
        );
        let proof: Vec<u8> = client_key
            .as_ref()
            .iter()
            .zip(signature.as_ref())
            .map(|(left, right)| left ^ right)
            .collect();
        Ok(format!("{without_proof},p={}", STANDARD.encode(proof)))
    }
}
