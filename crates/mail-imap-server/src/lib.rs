#![forbid(unsafe_code)]

mod auth;
mod commands;
mod frame;

use mail_imap_proto::{Action, Session, Status, greeting, parse_command, tagged};
use mail_storage::ImapRepository;
use std::{io, net::SocketAddr, sync::Arc, time::Duration};
use thiserror::Error;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpListener,
    sync::Semaphore,
    time::timeout,
};
use uuid::Uuid;

trait ImapIo: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> ImapIo for T {}

#[derive(Clone)]
pub struct ImapConfig {
    pub max_connections: usize,
    pub max_literal_size: usize,
    pub command_timeout: Duration,
    pub tls: Option<Arc<rustls::ServerConfig>>,
    pub implicit_tls: bool,
}

impl Default for ImapConfig {
    fn default() -> Self {
        Self {
            max_connections: 1024,
            max_literal_size: 50 * 1024 * 1024,
            command_timeout: Duration::from_secs(300),
            tls: None,
            implicit_tls: false,
        }
    }
}

#[derive(Debug, Error)]
pub enum ImapError {
    #[error("I/O failure: {0}")]
    Io(String),
    #[error("session timed out")]
    Timeout,
    #[error("command line is too long")]
    LineTooLong,
    #[error("literal is too large")]
    LiteralTooLarge,
    #[error("invalid line ending")]
    BadLineEnding,
    #[error("authentication storage unavailable")]
    Storage,
    #[error("TLS configuration unavailable")]
    Tls,
}

impl From<io::Error> for ImapError {
    fn from(value: io::Error) -> Self {
        Self::Io(value.to_string())
    }
}

pub async fn serve<R: ImapRepository + 'static>(
    listener: TcpListener,
    repository: Arc<R>,
    config: ImapConfig,
) -> Result<(), ImapError> {
    let permits = Arc::new(Semaphore::new(config.max_connections));
    loop {
        let (stream, peer) = listener.accept().await?;
        let permit = Arc::clone(&permits)
            .acquire_owned()
            .await
            .map_err(|_| ImapError::Storage)?;
        let repository = Arc::clone(&repository);
        let config = config.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let _ = run_session(stream, peer, repository.as_ref(), &config).await;
        });
    }
}

#[allow(clippy::too_many_lines)] // Keeping one command exchange in wire order makes protocol auditing safer.
pub async fn run_session<S, R>(
    stream: S,
    _peer: SocketAddr,
    repository: &R,
    config: &ImapConfig,
) -> Result<(), ImapError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    R: ImapRepository,
{
    let stream: Box<dyn ImapIo> = Box::new(stream);
    let mut stream = if config.implicit_tls {
        accept_tls(stream, config).await?
    } else {
        stream
    };
    let mut session = Session::new(config.implicit_tls, config.tls.is_some());
    let mut auth_failures = 0_u8;
    let mut authenticated_user = None;
    let mut selected = None;
    stream
        .write_all(greeting(&session.capabilities()).as_bytes())
        .await?;
    loop {
        let frame = match timeout(
            config.command_timeout,
            frame::read_frame(&mut stream, config),
        )
        .await
        {
            Ok(Ok(frame)) => frame,
            Ok(Err(ImapError::LiteralTooLarge)) => {
                stream
                    .write_all(b"* BYE [TOOBIG] literal exceeds configured limit\r\n")
                    .await?;
                return Ok(());
            }
            Ok(Err(error)) => return Err(error),
            Err(_) => {
                stream.write_all(b"* BYE idle timeout\r\n").await?;
                return Err(ImapError::Timeout);
            }
        };
        let Some(frame) = frame else { return Ok(()) };
        if let (Some(user), Some(mailbox)) = (authenticated_user, selected.as_mut()) {
            write_sync_updates(&mut stream, repository, user, mailbox).await?;
        }
        let Ok(command) = parse_command(&frame.line, &frame.literals) else {
            let tag = frame
                .line
                .split(|byte| *byte == b' ')
                .next()
                .filter(|tag| valid_recovery_tag(tag))
                .and_then(|tag| std::str::from_utf8(tag).ok());
            if let Some(tag) = tag {
                stream
                    .write_all(tagged(tag, Status::Bad, "invalid command syntax").as_bytes())
                    .await?;
            } else {
                stream
                    .write_all(b"* BAD invalid command syntax\r\n")
                    .await?;
            }
            continue;
        };
        match session.command(command) {
            Action::Responses(responses) => write_responses(&mut stream, &responses).await?,
            Action::Close(responses) => {
                write_responses(&mut stream, &responses).await?;
                return Ok(());
            }
            Action::StartTls { tag } => {
                stream
                    .write_all(tagged(&tag, Status::Ok, "Begin TLS negotiation").as_bytes())
                    .await?;
                stream = accept_tls(stream, config).await?;
                session.tls_started();
            }
            Action::Idle { tag } => {
                let (Some(user), Some(mailbox)) = (authenticated_user, selected.as_mut()) else {
                    stream
                        .write_all(tagged(&tag, Status::Bad, "no mailbox selected").as_bytes())
                        .await?;
                    continue;
                };
                run_idle(
                    &mut stream,
                    repository,
                    user,
                    mailbox,
                    &tag,
                    config.command_timeout,
                )
                .await?;
            }
            Action::Login {
                tag,
                username,
                password,
            } => {
                let identity = String::from_utf8(username).ok();
                if let Some(user) = finish_auth(
                    &mut stream,
                    &mut session,
                    repository,
                    tag,
                    identity.zip(Some(password)),
                )
                .await?
                {
                    authenticated_user = Some(user);
                } else {
                    auth_failures += 1;
                }
            }
            Action::Authenticate {
                tag,
                mechanism,
                initial_response,
            } => {
                if mechanism != "PLAIN" {
                    stream
                        .write_all(
                            tagged(&tag, Status::No, "unsupported authentication mechanism")
                                .as_bytes(),
                        )
                        .await?;
                    continue;
                }
                let response = if let Some(response) = initial_response {
                    response
                } else {
                    stream.write_all(b"+ \r\n").await?;
                    let line = timeout(
                        config.command_timeout,
                        frame::read_line(&mut stream, mail_imap_proto::MAX_COMMAND_LINE),
                    )
                    .await
                    .map_err(|_| ImapError::Timeout)??
                    .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "SASL response"))?;
                    String::from_utf8(line[..line.len() - 2].to_vec()).unwrap_or_default()
                };
                let credentials = if response == "*" {
                    None
                } else if response == "=" {
                    auth::decode_plain("")
                } else {
                    auth::decode_plain(&response)
                };
                if let Some(user) =
                    finish_auth(&mut stream, &mut session, repository, tag, credentials).await?
                {
                    authenticated_user = Some(user);
                } else {
                    auth_failures += 1;
                }
            }
            Action::Execute { tag, command } => {
                let Some(user) = authenticated_user else {
                    stream
                        .write_all(tagged(&tag, Status::No, "authentication required").as_bytes())
                        .await?;
                    continue;
                };
                let outcome = commands::execute(
                    repository,
                    user,
                    selected.as_ref(),
                    command,
                    frame.spooled_append.as_ref(),
                    session.qresync_enabled(),
                    session.condstore_enabled(),
                )
                .await;
                match outcome {
                    Ok(result) => {
                        for response in result.responses {
                            stream.write_all(&response).await?;
                        }
                        if result.select.is_some() {
                            selected = result.select;
                            session.mailbox_selected();
                        }
                        if result.unselect {
                            selected = None;
                            session.mailbox_unselected();
                        }
                        if let Some(mailbox) = selected.as_mut() {
                            write_sync_updates(&mut stream, repository, user, mailbox).await?;
                        }
                        stream
                            .write_all(tagged(&tag, Status::Ok, &result.completion).as_bytes())
                            .await?;
                    }
                    Err(commands::CommandError::Bad(message)) => {
                        stream
                            .write_all(tagged(&tag, Status::Bad, message).as_bytes())
                            .await?;
                    }
                    Err(commands::CommandError::No(message)) => {
                        stream
                            .write_all(tagged(&tag, Status::No, message).as_bytes())
                            .await?;
                    }
                }
            }
        }
        if auth_failures >= 3 {
            stream
                .write_all(b"* BYE too many authentication failures\r\n")
                .await?;
            return Ok(());
        }
    }
}

async fn write_sync_updates<S: AsyncWrite + Unpin, R: ImapRepository>(
    stream: &mut S,
    repository: &R,
    user: Uuid,
    selected: &mut commands::Selected,
) -> Result<(), ImapError> {
    let changes = repository
        .imap_changes(user, selected.mailbox.id, selected.observed_modseq)
        .await
        .map_err(|_| ImapError::Storage)?;
    if changes.highest_modseq == selected.observed_modseq {
        return Ok(());
    }
    if !changes.vanished.is_empty() {
        if selected.qresync {
            stream
                .write_all(format!("* VANISHED {}\r\n", join_uids(&changes.vanished)).as_bytes())
                .await?;
        } else {
            let mut sequences = changes
                .vanished
                .iter()
                .filter_map(|uid| {
                    selected
                        .known_uids
                        .iter()
                        .position(|known| known == uid)
                        .map(|position| u32::try_from(position + 1).unwrap_or(u32::MAX))
                })
                .collect::<Vec<_>>();
            sequences.sort_unstable_by(|left, right| right.cmp(left));
            for sequence in sequences {
                stream
                    .write_all(format!("* {sequence} EXPUNGE\r\n").as_bytes())
                    .await?;
            }
        }
        selected
            .known_uids
            .retain(|uid| !changes.vanished.contains(uid));
    }
    let new_message = changes
        .changed
        .iter()
        .any(|change| !selected.known_uids.contains(&change.uid));
    for change in &changes.changed {
        if !selected.known_uids.contains(&change.uid) {
            selected.known_uids.push(change.uid);
        }
    }
    selected.known_uids.sort_unstable();
    if new_message || changes.message_count != selected.mailbox.message_count {
        stream
            .write_all(format!("* {} EXISTS\r\n", changes.message_count).as_bytes())
            .await?;
    }
    for response in commands::change_responses(&changes.changed, selected.condstore) {
        stream.write_all(&response).await?;
    }
    selected.observed_modseq = changes.highest_modseq;
    selected.mailbox.highest_modseq = changes.highest_modseq;
    selected.mailbox.message_count = changes.message_count;
    Ok(())
}

async fn run_idle<S: AsyncRead + AsyncWrite + Unpin, R: ImapRepository>(
    stream: &mut S,
    repository: &R,
    user: Uuid,
    selected: &mut commands::Selected,
    tag: &str,
    idle_timeout: Duration,
) -> Result<(), ImapError> {
    stream.write_all(b"+ idling\r\n").await?;
    stream.flush().await?;
    let deadline = tokio::time::sleep(idle_timeout);
    tokio::pin!(deadline);
    let mut interval = tokio::time::interval(Duration::from_secs(1));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut line = Vec::with_capacity(8);
    loop {
        let mut byte = [0_u8; 1];
        tokio::select! {
            () = &mut deadline => {
                stream.write_all(b"* BYE IDLE timeout\r\n").await?;
                return Err(ImapError::Timeout);
            }
            _ = interval.tick() => write_sync_updates(stream, repository, user, selected).await?,
            read = stream.read(&mut byte) => {
                if read? == 0 { return Ok(()); }
                line.push(byte[0]);
                if line.len() > 6 || (line.ends_with(b"\n") && !line.ends_with(b"\r\n")) {
                    stream.write_all(tagged(tag, Status::Bad, "invalid IDLE continuation").as_bytes()).await?;
                    return Ok(());
                }
                if line.ends_with(b"\r\n") {
                    write_sync_updates(stream, repository, user, selected).await?;
                    let status = if line.eq_ignore_ascii_case(b"DONE\r\n") { Status::Ok } else { Status::Bad };
                    let message = if status == Status::Ok { "IDLE completed" } else { "invalid IDLE continuation" };
                    stream.write_all(tagged(tag, status, message).as_bytes()).await?;
                    return Ok(());
                }
            }
        }
    }
}

fn join_uids(values: &[u32]) -> String {
    values
        .iter()
        .map(u32::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

fn valid_recovery_tag(tag: &[u8]) -> bool {
    !tag.is_empty()
        && tag.len() <= mail_imap_proto::MAX_TAG_BYTES
        && tag.iter().all(|byte| {
            (0x21..=0x7e).contains(byte)
                && !matches!(
                    byte,
                    b'(' | b')' | b'{' | b' ' | b'%' | b'*' | b'"' | b'\\' | b']'
                )
        })
}

async fn finish_auth<S: AsyncWrite + Unpin, R: ImapRepository>(
    stream: &mut S,
    session: &mut Session,
    repository: &R,
    tag: String,
    credentials: Option<(String, Vec<u8>)>,
) -> Result<Option<Uuid>, ImapError> {
    let authenticated = match credentials {
        Some((identity, password)) => auth::authenticate(repository, identity, password).await?,
        None => None,
    };
    if authenticated.is_some() {
        session.authentication_succeeded();
        stream
            .write_all(tagged(&tag, Status::Ok, "authentication completed").as_bytes())
            .await?;
    } else {
        stream
            .write_all(tagged(&tag, Status::No, "authentication failed").as_bytes())
            .await?;
    }
    Ok(authenticated)
}

async fn accept_tls(
    stream: Box<dyn ImapIo>,
    config: &ImapConfig,
) -> Result<Box<dyn ImapIo>, ImapError> {
    let tls = config.tls.clone().ok_or(ImapError::Tls)?;
    timeout(
        config.command_timeout,
        tokio_rustls::TlsAcceptor::from(tls).accept(stream),
    )
    .await
    .map_err(|_| ImapError::Timeout)?
    .map(|stream| Box::new(stream) as Box<dyn ImapIo>)
    .map_err(|_| ImapError::Tls)
}

async fn write_responses<S: AsyncWrite + Unpin>(
    stream: &mut S,
    responses: &[String],
) -> Result<(), ImapError> {
    for response in responses {
        stream.write_all(response.as_bytes()).await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use argon2::PasswordHasher as _;
    use async_trait::async_trait;
    use mail_domain::MailboxId;
    use mail_storage::{ImapChange, ImapChanges, ImapMailbox, SmtpAuthAccount, StorageError};
    use std::sync::atomic::{AtomicBool, Ordering};
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader, duplex};
    use uuid::Uuid;

    struct Repository {
        hash: Option<String>,
    }

    struct SyncRepository(AtomicBool);

    #[async_trait]
    impl ImapRepository for SyncRepository {
        async fn imap_auth_account(
            &self,
            _identity: &str,
        ) -> Result<Option<SmtpAuthAccount>, StorageError> {
            Ok(None)
        }

        async fn record_imap_auth(
            &self,
            _user_id: Uuid,
            _success: bool,
        ) -> Result<(), StorageError> {
            Ok(())
        }

        async fn imap_changes(
            &self,
            _user_id: Uuid,
            _mailbox_id: MailboxId,
            since_modseq: u64,
        ) -> Result<ImapChanges, StorageError> {
            if since_modseq == 1 && !self.0.swap(true, Ordering::SeqCst) {
                return Ok(ImapChanges {
                    highest_modseq: 2,
                    message_count: 1,
                    changed: vec![ImapChange {
                        sequence: Some(1),
                        uid: 1,
                        modseq: 2,
                        flags: vec!["\\Seen".into()],
                    }],
                    vanished: Vec::new(),
                });
            }
            Ok(ImapChanges {
                highest_modseq: 2,
                message_count: 1,
                changed: Vec::new(),
                vanished: Vec::new(),
            })
        }
    }

    #[async_trait]
    impl ImapRepository for Repository {
        async fn imap_auth_account(
            &self,
            _identity: &str,
        ) -> Result<Option<SmtpAuthAccount>, StorageError> {
            Ok(self.hash.as_ref().map(|hash| SmtpAuthAccount {
                user_id: Uuid::nil(),
                password_hashes: vec![hash.clone()],
                scram: None,
            }))
        }

        async fn record_imap_auth(
            &self,
            _user_id: Uuid,
            _success: bool,
        ) -> Result<(), StorageError> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn capability_noop_literal_and_logout_transcript()
    -> Result<(), Box<dyn std::error::Error>> {
        let (client, server) = duplex(4096);
        let peer: SocketAddr = "192.0.2.1:143".parse()?;
        let task = tokio::spawn(async move {
            run_session(
                server,
                peer,
                &Repository { hash: None },
                &ImapConfig::default(),
            )
            .await
        });
        let (read, mut write) = tokio::io::split(client);
        let mut reader = BufReader::new(read);
        let mut line = String::new();
        reader.read_line(&mut line).await?;
        assert!(line.starts_with("* OK [CAPABILITY IMAP4rev2"));
        write
            .write_all(b"A1 CAPABILITY\r\nA2 NOOP\r\nA3 LOGOUT\r\n")
            .await?;
        let mut output = String::new();
        reader.read_to_string(&mut output).await?;
        assert!(output.contains("* CAPABILITY IMAP4rev2"));
        assert!(output.contains("A2 OK NOOP completed"));
        assert!(output.contains("* BYE logging out\r\nA3 OK LOGOUT completed"));
        task.await??;
        Ok(())
    }

    #[tokio::test]
    async fn split_literals_are_streamed_with_continuations()
    -> Result<(), Box<dyn std::error::Error>> {
        let (client, server) = duplex(4096);
        let peer: SocketAddr = "192.0.2.1:143".parse()?;
        let task = tokio::spawn(async move {
            run_session(
                server,
                peer,
                &Repository { hash: None },
                &ImapConfig::default(),
            )
            .await
        });
        let (read, mut write) = tokio::io::split(client);
        let mut reader = BufReader::new(read);
        let mut line = String::new();
        reader.read_line(&mut line).await?;
        write.write_all(b"A1 LOGIN {5}\r\n").await?;
        line.clear();
        reader.read_line(&mut line).await?;
        assert!(line.starts_with('+'));
        write.write_all(b"alice {6}\r\n").await?;
        line.clear();
        reader.read_line(&mut line).await?;
        assert!(line.starts_with('+'));
        write.write_all(b"secret\r\nA2 LOGOUT\r\n").await?;
        line.clear();
        reader.read_line(&mut line).await?;
        assert!(line.starts_with("A1 BAD"), "unexpected response: {line:?}");
        write.shutdown().await?;
        task.await??;
        Ok(())
    }

    #[tokio::test]
    async fn oversized_literal_is_rejected_before_allocation()
    -> Result<(), Box<dyn std::error::Error>> {
        let (client, server) = duplex(1024);
        let peer: SocketAddr = "192.0.2.1:143".parse()?;
        let config = ImapConfig {
            max_literal_size: 4,
            ..ImapConfig::default()
        };
        let task = tokio::spawn(async move {
            run_session(server, peer, &Repository { hash: None }, &config).await
        });
        let (read, mut write) = tokio::io::split(client);
        let mut reader = BufReader::new(read);
        let mut line = String::new();
        reader.read_line(&mut line).await?;
        write.write_all(b"A1 LOGIN {5}\r\n").await?;
        line.clear();
        reader.read_line(&mut line).await?;
        assert_eq!(line, "* BYE [TOOBIG] literal exceeds configured limit\r\n");
        task.await??;
        Ok(())
    }

    #[tokio::test]
    async fn idle_pushes_cross_session_changes_and_accepts_done()
    -> Result<(), Box<dyn std::error::Error>> {
        let (mut client, mut server) = duplex(4096);
        let repository = SyncRepository(AtomicBool::new(false));
        let task = tokio::spawn(async move {
            let mut selected = commands::Selected {
                mailbox: ImapMailbox {
                    id: MailboxId::new(Uuid::new_v4()),
                    name: "INBOX".into(),
                    uid_validity: 1,
                    uid_next: 1,
                    highest_modseq: 1,
                    message_count: 0,
                    unseen_count: 0,
                    subscribed: false,
                },
                read_only: false,
                observed_modseq: 1,
                qresync: true,
                condstore: true,
                known_uids: Vec::new(),
            };
            run_idle(
                &mut server,
                &repository,
                Uuid::nil(),
                &mut selected,
                "A1",
                Duration::from_secs(5),
            )
            .await
        });
        let mut buffer = vec![0; 256];
        let count = timeout(Duration::from_secs(3), client.read(&mut buffer)).await??;
        let mut output = buffer[..count].to_vec();
        assert!(String::from_utf8_lossy(&output).contains("+ idling"));
        client.write_all(b"DONE\r\n").await?;
        while !String::from_utf8_lossy(&output).contains("A1 OK IDLE completed") {
            let count = timeout(Duration::from_secs(3), client.read(&mut buffer)).await??;
            output.extend_from_slice(&buffer[..count]);
        }
        let output = String::from_utf8_lossy(&output);
        assert!(output.contains("* 1 EXISTS"));
        assert!(output.contains("MODSEQ (2)"));
        task.await??;
        Ok(())
    }

    #[tokio::test]
    async fn starttls_performs_real_handshake_and_resets_capabilities()
    -> Result<(), Box<dyn std::error::Error>> {
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
        let (client, server) = duplex(16 * 1024);
        let peer: SocketAddr = "192.0.2.1:143".parse()?;
        let config = ImapConfig {
            tls: Some(Arc::new(server_tls)),
            ..ImapConfig::default()
        };
        let hash = argon2::Argon2::default()
            .hash_password(
                b"secret",
                &argon2::password_hash::SaltString::encode_b64(b"0123456789abcdef")
                    .map_err(|_| "salt")?,
            )
            .map_err(|_| "hash")?
            .to_string();
        let task = tokio::spawn(async move {
            run_session(server, peer, &Repository { hash: Some(hash) }, &config).await
        });
        let mut client = BufReader::new(client);
        let mut line = String::new();
        client.read_line(&mut line).await?;
        assert!(line.contains("STARTTLS"));
        client.get_mut().write_all(b"A1 STARTTLS\r\n").await?;
        line.clear();
        client.read_line(&mut line).await?;
        assert!(line.starts_with("A1 OK"));
        let client = tokio_rustls::TlsConnector::from(Arc::new(client_tls))
            .connect(ServerName::try_from("localhost")?, client.into_inner())
            .await?;
        let mut client = BufReader::new(client);
        client
            .get_mut()
            .write_all(
                b"A2 CAPABILITY\r\nA3 LOGIN alice@example.test secret\r\nA4 ENABLE UNKNOWN\r\nA5 LOGOUT\r\n",
            )
            .await?;
        let mut output = String::new();
        for _ in 0..7 {
            let mut response = String::new();
            client.read_line(&mut response).await?;
            output.push_str(&response);
        }
        assert!(output.contains("AUTH=PLAIN"));
        assert!(!output.contains("STARTTLS"));
        assert!(output.contains("A3 OK authentication completed"));
        assert!(output.contains("* ENABLED\r\n"));
        task.await??;
        Ok(())
    }
}
