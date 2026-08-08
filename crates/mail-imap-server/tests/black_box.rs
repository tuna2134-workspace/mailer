#![forbid(unsafe_code)]

use async_trait::async_trait;
use mail_imap_server::{ImapConfig, serve};
use mail_storage::{ImapRepository, SmtpAuthAccount, StorageError};
use std::sync::Arc;
use tokio::{
    io::{AsyncBufRead, AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
};
use uuid::Uuid;

struct Repository;

#[async_trait]
impl ImapRepository for Repository {
    async fn imap_auth_account(
        &self,
        _identity: &str,
    ) -> Result<Option<SmtpAuthAccount>, StorageError> {
        Ok(None)
    }

    async fn record_imap_auth(&self, _user_id: Uuid, _success: bool) -> Result<(), StorageError> {
        Ok(())
    }
}

struct Server {
    address: std::net::SocketAddr,
    task: tokio::task::JoinHandle<Result<(), mail_imap_server::ImapError>>,
}

impl Server {
    async fn start(config: ImapConfig) -> Result<Self, Box<dyn std::error::Error>> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let task = tokio::spawn(async move { serve(listener, Arc::new(Repository), config).await });
        Ok(Self { address, task })
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn line<R: AsyncBufRead + Unpin>(reader: &mut R) -> Result<String, std::io::Error> {
    let mut output = String::new();
    reader.read_line(&mut output).await?;
    Ok(output)
}

#[tokio::test]
async fn plaintext_fragmentation_pipeline_and_recovery_work_over_tcp()
-> Result<(), Box<dyn std::error::Error>> {
    let server = Server::start(ImapConfig::default()).await?;
    let mut client = BufReader::new(TcpStream::connect(server.address).await?);
    let greeting = line(&mut client).await?;
    assert!(greeting.starts_with("* OK [CAPABILITY IMAP4rev2"));
    assert!(greeting.contains("LOGINDISABLED"));
    assert!(!greeting.contains("STARTTLS"));

    for fragment in [b"A1 NO".as_slice(), b"OP\r".as_slice(), b"\n".as_slice()] {
        client.get_mut().write_all(fragment).await?;
    }
    assert_eq!(line(&mut client).await?, "A1 OK NOOP completed\r\n");

    client
        .get_mut()
        .write_all(b"A2 LOGIN alice secret\r\nA3 BROKEN (\r\nA4 CAPABILITY\r\nA5 LOGOUT\r\n")
        .await?;
    assert_eq!(
        line(&mut client).await?,
        "A2 NO LOGIN disabled until TLS is active\r\n"
    );
    assert_eq!(line(&mut client).await?, "A3 BAD unknown command\r\n");
    assert!(line(&mut client).await?.starts_with("* CAPABILITY "));
    assert_eq!(line(&mut client).await?, "A4 OK CAPABILITY completed\r\n");
    assert_eq!(line(&mut client).await?, "* BYE logging out\r\n");
    assert_eq!(line(&mut client).await?, "A5 OK LOGOUT completed\r\n");
    Ok(())
}

#[tokio::test]
async fn oversized_literal_is_rejected_before_payload_over_tcp()
-> Result<(), Box<dyn std::error::Error>> {
    let server = Server::start(ImapConfig {
        max_literal_size: 16,
        ..ImapConfig::default()
    })
    .await?;
    let mut client = BufReader::new(TcpStream::connect(server.address).await?);
    let _ = line(&mut client).await?;
    client.get_mut().write_all(b"A1 LOGIN {17}\r\n").await?;
    assert_eq!(
        line(&mut client).await?,
        "* BYE [TOOBIG] literal exceeds configured limit\r\n"
    );
    Ok(())
}

#[tokio::test]
async fn starttls_over_tcp_resets_capabilities() -> Result<(), Box<dyn std::error::Error>> {
    use rustls::{
        ClientConfig, RootCertStore, ServerConfig,
        pki_types::{PrivatePkcs8KeyDer, ServerName},
    };

    let identity = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    let certificate = identity.cert.der().clone();
    let tls =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()?
            .with_no_client_auth()
            .with_single_cert(
                vec![certificate.clone()],
                PrivatePkcs8KeyDer::from(identity.signing_key.serialize_der()).into(),
            )?;
    let server = Server::start(ImapConfig {
        tls: Some(Arc::new(tls)),
        ..ImapConfig::default()
    })
    .await?;
    let mut client = BufReader::new(TcpStream::connect(server.address).await?);
    let greeting = line(&mut client).await?;
    assert!(greeting.contains("STARTTLS"));
    assert!(greeting.contains("LOGINDISABLED"));
    client.get_mut().write_all(b"A1 STARTTLS\r\n").await?;
    assert_eq!(line(&mut client).await?, "A1 OK Begin TLS negotiation\r\n");

    let mut roots = RootCertStore::empty();
    roots.add(certificate)?;
    let tls =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()?
            .with_root_certificates(roots)
            .with_no_client_auth();
    let secured = tokio_rustls::TlsConnector::from(Arc::new(tls))
        .connect(ServerName::try_from("localhost")?, client.into_inner())
        .await?;
    let mut client = BufReader::new(secured);
    client
        .get_mut()
        .write_all(b"A2 CAPABILITY\r\nA3 LOGOUT\r\n")
        .await?;
    let capabilities = line(&mut client).await?;
    assert!(capabilities.contains("AUTH=PLAIN"));
    assert!(!capabilities.contains("STARTTLS"));
    assert!(!capabilities.contains("LOGINDISABLED"));
    assert_eq!(line(&mut client).await?, "A2 OK CAPABILITY completed\r\n");
    assert_eq!(line(&mut client).await?, "* BYE logging out\r\n");
    assert_eq!(line(&mut client).await?, "A3 OK LOGOUT completed\r\n");
    Ok(())
}
