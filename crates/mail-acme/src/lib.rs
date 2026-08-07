#![forbid(unsafe_code)]

use async_trait::async_trait;
use futures::StreamExt;
use ring::{
    aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey},
    digest::{SHA256, digest},
    rand::{SecureRandom, SystemRandom},
};
use sqlx::{Connection, PgConnection, PgPool};
use std::sync::Arc;
use thiserror::Error;
use tokio::{
    net::{TcpListener, TcpStream},
    sync::mpsc,
};
use tokio_rustls_acme::{
    AccountCache, AcmeConfig, AcmeState, CertCache, EventError, EventOk,
    tokio_rustls::{TlsStream, rustls::ServerConfig},
};

const NONCE_LEN: usize = 12;

#[derive(Debug, Error)]
pub enum AcmeError {
    #[error("ACME cache encryption key must contain exactly 32 bytes")]
    InvalidEncryptionKey,
    #[error("ACME cache encryption failed")]
    Encrypt,
    #[error("ACME cache authentication failed")]
    Decrypt,
    #[error("ACME cache value is truncated")]
    Truncated,
    #[error("PostgreSQL operation failed: {0}")]
    Postgres(String),
    #[error("listener operation failed: {0}")]
    Io(String),
    #[error("another node owns the ACME renewal lock")]
    LockBusy,
}

#[derive(Clone)]
pub struct PostgresAcmeCache {
    pool: PgPool,
    key: LessSafeKey,
}

impl PostgresAcmeCache {
    pub fn new(pool: PgPool, encryption_key: &[u8]) -> Result<Self, AcmeError> {
        let key = UnboundKey::new(&AES_256_GCM, encryption_key)
            .map_err(|_| AcmeError::InvalidEncryptionKey)?;
        Ok(Self {
            pool,
            key: LessSafeKey::new(key),
        })
    }

    async fn load(&self, kind: &str, cache_key: &[u8]) -> Result<Option<Vec<u8>>, AcmeError> {
        let value: Option<Vec<u8>> = sqlx::query_scalar(
            "SELECT ciphertext FROM acme_cache_entries WHERE kind=$1 AND cache_key=$2",
        )
        .bind(kind)
        .bind(cache_key)
        .fetch_optional(&self.pool)
        .await
        .map_err(pg)?;
        value
            .map(|ciphertext| self.decrypt(&ciphertext))
            .transpose()
    }

    async fn store(&self, kind: &str, cache_key: &[u8], value: &[u8]) -> Result<(), AcmeError> {
        let ciphertext = self.encrypt(value)?;
        sqlx::query("INSERT INTO acme_cache_entries(kind,cache_key,ciphertext) VALUES($1,$2,$3) ON CONFLICT(kind,cache_key) DO UPDATE SET ciphertext=EXCLUDED.ciphertext,updated_at=clock_timestamp()")
            .bind(kind).bind(cache_key).bind(ciphertext).execute(&self.pool).await.map_err(pg)?;
        Ok(())
    }

    fn encrypt(&self, value: &[u8]) -> Result<Vec<u8>, AcmeError> {
        let mut nonce_bytes = [0_u8; NONCE_LEN];
        SystemRandom::new()
            .fill(&mut nonce_bytes)
            .map_err(|_| AcmeError::Encrypt)?;
        let mut output = value.to_vec();
        self.key
            .seal_in_place_append_tag(
                Nonce::assume_unique_for_key(nonce_bytes),
                Aad::empty(),
                &mut output,
            )
            .map_err(|_| AcmeError::Encrypt)?;
        let mut envelope = nonce_bytes.to_vec();
        envelope.extend_from_slice(&output);
        Ok(envelope)
    }

    fn decrypt(&self, envelope: &[u8]) -> Result<Vec<u8>, AcmeError> {
        let (nonce, ciphertext) = envelope
            .split_at_checked(NONCE_LEN)
            .ok_or(AcmeError::Truncated)?;
        let nonce: [u8; NONCE_LEN] = nonce.try_into().map_err(|_| AcmeError::Truncated)?;
        let mut plaintext = ciphertext.to_vec();
        let opened = self
            .key
            .open_in_place(
                Nonce::assume_unique_for_key(nonce),
                Aad::empty(),
                &mut plaintext,
            )
            .map_err(|_| AcmeError::Decrypt)?;
        Ok(opened.to_vec())
    }
}

#[async_trait]
impl CertCache for PostgresAcmeCache {
    type EC = AcmeError;

    async fn load_cert(
        &self,
        domains: &[String],
        directory_url: &str,
    ) -> Result<Option<Vec<u8>>, Self::EC> {
        self.load("certificate", &cache_key(domains, directory_url))
            .await
    }

    async fn store_cert(
        &self,
        domains: &[String],
        directory_url: &str,
        cert: &[u8],
    ) -> Result<(), Self::EC> {
        self.store("certificate", &cache_key(domains, directory_url), cert)
            .await
    }
}

#[async_trait]
impl AccountCache for PostgresAcmeCache {
    type EA = AcmeError;

    async fn load_account(
        &self,
        contact: &[String],
        directory_url: &str,
    ) -> Result<Option<Vec<u8>>, Self::EA> {
        self.load("account", &cache_key(contact, directory_url))
            .await
    }

    async fn store_account(
        &self,
        contact: &[String],
        directory_url: &str,
        account: &[u8],
    ) -> Result<(), Self::EA> {
        self.store("account", &cache_key(contact, directory_url), account)
            .await
    }
}

fn cache_key(values: &[String], directory_url: &str) -> Vec<u8> {
    let mut material = directory_url.as_bytes().to_vec();
    for value in values {
        material.push(0);
        material.extend_from_slice(value.as_bytes());
    }
    digest(&SHA256, &material).as_ref().to_vec()
}

#[allow(clippy::needless_pass_by_value)] // Result::map_err supplies owned errors.
fn pg(error: sqlx::Error) -> AcmeError {
    AcmeError::Postgres(error.to_string())
}

pub struct RenewalLock {
    connection: PgConnection,
}

impl RenewalLock {
    pub async fn acquire(database_url: &str, lock_id: i64) -> Result<Self, AcmeError> {
        let mut connection = PgConnection::connect(database_url).await.map_err(pg)?;
        let acquired: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock($1)")
            .bind(lock_id)
            .fetch_one(&mut connection)
            .await
            .map_err(pg)?;
        if !acquired {
            return Err(AcmeError::LockBusy);
        }
        Ok(Self { connection })
    }

    pub async fn release(mut self, lock_id: i64) -> Result<(), AcmeError> {
        let released: bool = sqlx::query_scalar("SELECT pg_advisory_unlock($1)")
            .bind(lock_id)
            .fetch_one(&mut self.connection)
            .await
            .map_err(pg)?;
        if !released {
            return Err(AcmeError::LockBusy);
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct AcmeSettings {
    pub domains: Vec<String>,
    pub contacts: Vec<String>,
    pub production: bool,
}

#[must_use]
pub fn state(settings: &AcmeSettings, cache: PostgresAcmeCache) -> AcmeState<AcmeError> {
    AcmeConfig::new(&settings.domains)
        .contact(&settings.contacts)
        .directory_lets_encrypt(settings.production)
        .cache(cache)
        .state()
}

pub async fn run_tls_alpn_listener(
    mut state: AcmeState<AcmeError>,
    listener: TcpListener,
    accepted: mpsc::Sender<TlsStream<TcpStream>>,
    pool: PgPool,
    settings: AcmeSettings,
) -> Result<(), AcmeError> {
    let acceptor = state.acceptor();
    let server_config = Arc::new(
        ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(state.resolver()),
    );
    loop {
        tokio::select! {
            event = state.next() => {
                let Some(event) = event else { return Ok(()); };
                record_event(&pool, &settings, &event).await?;
            }
            connection = listener.accept() => {
                let (tcp, _) = connection.map_err(|error| AcmeError::Io(error.to_string()))?;
                let acceptor = acceptor.clone();
                let config = Arc::clone(&server_config);
                let accepted = accepted.clone();
                tokio::spawn(async move {
                    let Ok(Some(handshake)) = acceptor.accept(tcp).await else { return; };
                    let Ok(stream) = handshake.into_stream(config).await else { return; };
                    let _ = accepted.send(TlsStream::Server(stream)).await;
                });
            }
        }
    }
}

async fn record_event(
    pool: &PgPool,
    settings: &AcmeSettings,
    event: &Result<EventOk, EventError<AcmeError, AcmeError>>,
) -> Result<(), AcmeError> {
    let (event_type, detail) = match event {
        Ok(EventOk::DeployedCachedCert) => ("deployed_cached_certificate", None),
        Ok(EventOk::DeployedNewCert) => ("deployed_new_certificate", None),
        Ok(EventOk::CertCacheStore) => ("stored_certificate_cache", None),
        Ok(EventOk::AccountCacheStore) => ("stored_account_cache", None),
        Err(_) => (
            "renewal_failure",
            Some("ACME operation failed; inspect restricted service logs"),
        ),
    };
    let directory = if settings.production {
        "letsencrypt-production"
    } else {
        "letsencrypt-staging"
    };
    sqlx::query("INSERT INTO certificate_events(event_type,directory_url,domains,detail) VALUES($1,$2,$3,$4)")
        .bind(event_type).bind(directory).bind(&settings.domains).bind(detail).execute(pool).await.map_err(pg)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn encryption_round_trip_and_tamper_detection() -> Result<(), AcmeError> {
        let pool = PgPool::connect_lazy("postgresql://localhost/unused").map_err(pg)?;
        let cache = PostgresAcmeCache::new(pool, &[7; 32])?;
        let encrypted = cache.encrypt(b"private material")?;
        assert_ne!(encrypted, b"private material");
        assert_eq!(cache.decrypt(&encrypted)?, b"private material");
        let mut tampered = encrypted;
        if let Some(last) = tampered.last_mut() {
            *last ^= 1;
        }
        assert!(matches!(cache.decrypt(&tampered), Err(AcmeError::Decrypt)));
        Ok(())
    }
}
