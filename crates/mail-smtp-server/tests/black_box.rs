#![forbid(unsafe_code)]

use async_trait::async_trait;
use mail_domain::{MailboxId, TenantId};
use mail_smtp_server::{SmtpConfig, serve};
use mail_storage::{LocalRecipient, SmtpMailOptions, SmtpRepository, StorageError, StoredMessage};
use std::sync::{Arc, Mutex};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
};
use uuid::Uuid;

#[derive(Default)]
struct Repository {
    body: Mutex<Vec<u8>>,
    aborted: Mutex<usize>,
    committed_recipients: Mutex<usize>,
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
        Ok(address.ends_with("@example.test").then(|| LocalRecipient {
            address: address.into(),
            tenant_id: TenantId::new(Uuid::nil()),
            mailbox_id: Some(MailboxId::new(Uuid::nil())),
            dsn_notify: None,
            original_recipient: None,
        }))
    }

    async fn begin_smtp_ingestion(&self) -> Result<Uuid, StorageError> {
        Ok(Uuid::new_v4())
    }

    async fn append_smtp_chunk(
        &self,
        _ingestion_id: Uuid,
        _position: u32,
        bytes: &[u8],
    ) -> Result<(), StorageError> {
        self.body
            .lock()
            .map_err(|error| StorageError::Unavailable(error.to_string()))?
            .extend_from_slice(bytes);
        Ok(())
    }

    async fn commit_smtp_ingestion(
        &self,
        _ingestion_id: Uuid,
        _envelope_sender: &str,
        recipients: &[LocalRecipient],
        _received_header: &[u8],
        _options: &SmtpMailOptions,
    ) -> Result<StoredMessage, StorageError> {
        *self
            .committed_recipients
            .lock()
            .map_err(|error| StorageError::Unavailable(error.to_string()))? = recipients.len();
        Ok(StoredMessage {
            message_ids: vec![Uuid::new_v4()],
            octets: 0,
        })
    }

    async fn abort_smtp_ingestion(&self, _ingestion_id: Uuid) -> Result<(), StorageError> {
        let mut aborted = self
            .aborted
            .lock()
            .map_err(|error| StorageError::Unavailable(error.to_string()))?;
        *aborted = aborted.saturating_add(1);
        Ok(())
    }
}

struct Server {
    address: std::net::SocketAddr,
    repository: Arc<Repository>,
    task: tokio::task::JoinHandle<Result<(), mail_smtp_server::SmtpError>>,
}

impl Server {
    async fn start(config: SmtpConfig) -> Result<Self, Box<dyn std::error::Error>> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let repository = Arc::new(Repository::default());
        let task_repository = Arc::clone(&repository);
        let task = tokio::spawn(async move { serve(listener, task_repository, config).await });
        Ok(Self {
            address,
            repository,
            task,
        })
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn reply(reader: &mut BufReader<TcpStream>) -> Result<Vec<String>, std::io::Error> {
    let mut lines = Vec::new();
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).await?;
        let final_line = line.as_bytes().get(3) != Some(&b'-');
        lines.push(line);
        if final_line {
            return Ok(lines);
        }
    }
}

async fn command(
    client: &mut BufReader<TcpStream>,
    wire: &[u8],
) -> Result<Vec<String>, std::io::Error> {
    client.get_mut().write_all(wire).await?;
    reply(client).await
}

fn code(lines: &[String]) -> &str {
    lines
        .last()
        .and_then(|line| line.get(..3))
        .unwrap_or_default()
}

#[tokio::test]
async fn command_errors_do_not_desynchronize_the_tcp_session()
-> Result<(), Box<dyn std::error::Error>> {
    let server = Server::start(SmtpConfig {
        max_recipients: 1,
        max_message_size: 128,
        chunking: true,
        dsn: true,
        smtp_utf8: true,
        ..SmtpConfig::default()
    })
    .await?;
    let mut client = BufReader::new(TcpStream::connect(server.address).await?);
    assert_eq!(code(&reply(&mut client).await?), "220");

    client
        .get_mut()
        .write_all(b"DATA\r\nBOGUS\r\nNOOP\r\nVRFY hidden@example.test\r\n")
        .await?;
    for expected in ["503", "500", "250", "252"] {
        assert_eq!(code(&reply(&mut client).await?), expected);
    }

    let mut overlong = vec![b'X'; mail_smtp_proto::MAX_COMMAND_LINE];
    overlong.extend_from_slice(b"\r\nNOOP\r\n");
    client.get_mut().write_all(&overlong).await?;
    assert_eq!(code(&reply(&mut client).await?), "500");
    assert_eq!(code(&reply(&mut client).await?), "250");

    client.get_mut().write_all(b"NOOP\nNOOP\r\n").await?;
    assert_eq!(code(&reply(&mut client).await?), "500");
    assert_eq!(code(&reply(&mut client).await?), "250");

    assert_eq!(
        code(&command(&mut client, b"EHLO client.example\r\n").await?),
        "250"
    );
    assert_eq!(
        code(&command(&mut client, b"MAIL FROM:<sender@example.net> SIZE=129\r\n").await?),
        "555"
    );
    assert_eq!(
        code(&command(&mut client, b"MAIL FROM:<sender@example.net>\r\n").await?),
        "250"
    );
    assert_eq!(
        code(
            &command(
                &mut client,
                b"RCPT TO:<first@example.test> NOTIFY=FAILURE\r\n"
            )
            .await?
        ),
        "250"
    );
    assert_eq!(
        code(&command(&mut client, b"RCPT TO:<second@example.test>\r\n").await?),
        "452"
    );
    assert_eq!(code(&command(&mut client, b"RSET\r\n").await?), "250");
    assert_eq!(code(&command(&mut client, b"NOOP\r\n").await?), "250");
    assert_eq!(code(&command(&mut client, b"QUIT\r\n").await?), "221");
    Ok(())
}

#[tokio::test]
async fn data_limits_dot_transparency_and_pipeline_work_over_tcp()
-> Result<(), Box<dyn std::error::Error>> {
    let server = Server::start(SmtpConfig {
        max_message_size: 2_048,
        ..SmtpConfig::default()
    })
    .await?;
    let mut client = BufReader::new(TcpStream::connect(server.address).await?);
    let _ = reply(&mut client).await?;
    client
        .get_mut()
        .write_all(
            b"HELO client.example\r\nMAIL FROM:<sender@example.net>\r\nRCPT TO:<first@example.test>\r\nRCPT TO:<second@example.test>\r\nDATA\r\n",
        )
        .await?;
    for expected in ["250", "250", "250", "250", "354"] {
        assert_eq!(code(&reply(&mut client).await?), expected);
    }
    client
        .get_mut()
        .write_all(b"Subject: test\r\n\r\n..leading dot\r\n.\r\nNOOP\r\n")
        .await?;
    assert_eq!(code(&reply(&mut client).await?), "250");
    assert_eq!(code(&reply(&mut client).await?), "250");
    assert_eq!(
        server
            .repository
            .body
            .lock()
            .map_err(|error| error.to_string())?
            .as_slice(),
        b"Subject: test\r\n\r\n.leading dot\r\n"
    );
    assert_eq!(
        *server
            .repository
            .committed_recipients
            .lock()
            .map_err(|error| error.to_string())?,
        2
    );

    client
        .get_mut()
        .write_all(b"MAIL FROM:<sender@example.net>\r\nRCPT TO:<first@example.test>\r\nDATA\r\n")
        .await?;
    for expected in ["250", "250", "354"] {
        assert_eq!(code(&reply(&mut client).await?), expected);
    }
    let mut long_data = vec![b'a'; 999];
    long_data.extend_from_slice(b"\r\n.\r\nNOOP\r\n");
    client.get_mut().write_all(&long_data).await?;
    assert_eq!(code(&reply(&mut client).await?), "554");
    assert_eq!(code(&reply(&mut client).await?), "250");
    Ok(())
}

#[tokio::test]
async fn interrupted_bdat_is_aborted_without_acceptance() -> Result<(), Box<dyn std::error::Error>>
{
    let server = Server::start(SmtpConfig {
        chunking: true,
        ..SmtpConfig::default()
    })
    .await?;
    let mut client = BufReader::new(TcpStream::connect(server.address).await?);
    let _ = reply(&mut client).await?;
    assert_eq!(
        code(&command(&mut client, b"EHLO client.example\r\n").await?),
        "250"
    );
    assert_eq!(
        code(
            &command(
                &mut client,
                b"MAIL FROM:<sender@example.net> BODY=BINARYMIME\r\n"
            )
            .await?
        ),
        "250"
    );
    assert_eq!(
        code(&command(&mut client, b"RCPT TO:<first@example.test>\r\n").await?),
        "250"
    );
    client.get_mut().write_all(b"BDAT 8 LAST\r\nabc").await?;
    client.get_mut().shutdown().await?;
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert_eq!(
        *server
            .repository
            .committed_recipients
            .lock()
            .map_err(|error| error.to_string())?,
        0
    );
    assert_eq!(
        *server
            .repository
            .aborted
            .lock()
            .map_err(|error| error.to_string())?,
        1
    );
    Ok(())
}
