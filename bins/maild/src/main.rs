#![forbid(unsafe_code)]

use anyhow::{Context, Result, bail};
use axum_server::tls_rustls::RustlsConfig;
use mail_acme::{AcmeSettings, PostgresAcmeCache, RenewalLock, run_tls_alpn_listener, state};
use mail_postgres::PostgresRepository;
use mail_storage::SmtpRepository;
use rustls::ServerConfig;
use sqlx::postgres::PgPoolOptions;
use std::{net::SocketAddr, sync::Arc};
use tokio::{net::TcpListener, sync::mpsc};

const RENEWAL_LOCK_ID: i64 = 0x4d41_494c_4143_4d45;

#[tokio::main]
async fn main() -> Result<()> {
    let database_url = required("MAIL_DATABASE_URL")?;
    let domains = csv("MAIL_ACME_DOMAINS")?;
    let contacts = csv("MAIL_ACME_CONTACTS")?;
    let cache_key = decode_hex(&required("MAIL_ACME_CACHE_KEY_HEX")?)?;
    let production = std::env::var("MAIL_ACME_PRODUCTION").is_ok_and(|value| value == "true");
    let acme_addr = address("MAIL_ACME_LISTEN", "0.0.0.0:443")?;
    let admin_addr = address("MAIL_ADMIN_LISTEN", "127.0.0.1:8443")?;
    let smtp_addr = address("MAIL_SMTP_LISTEN", "0.0.0.0:25")?;
    let hostname = match std::env::var("MAIL_HOSTNAME") {
        Ok(value) => value,
        Err(_) => domains
            .first()
            .cloned()
            .context("ACME domain list is empty")?,
    };
    if !valid_hostname(&hostname) {
        bail!("MAIL_HOSTNAME must be a valid ASCII DNS hostname");
    }

    let pool = PgPoolOptions::new()
        .max_connections(20)
        .connect(&database_url)
        .await
        .context("connect to PostgreSQL")?;
    check_migrations(&pool).await?;
    let _renewal_lock = RenewalLock::acquire(&database_url, RENEWAL_LOCK_ID)
        .await
        .context("acquire distributed ACME renewal lock")?;
    let settings = AcmeSettings {
        domains,
        contacts,
        production,
    };
    let cache = PostgresAcmeCache::new(pool.clone(), &cache_key)?;
    let acme_state = state(&settings, cache);
    let resolver = acme_state.resolver();
    let mut admin_tls = ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    admin_tls.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    let listener = TcpListener::bind(acme_addr)
        .await
        .with_context(|| format!("bind ACME TLS-ALPN-01 listener {acme_addr}"))?;
    let (accepted_tx, mut accepted_rx) = mpsc::channel(32);
    let acme_pool = pool.clone();
    let acme_task = tokio::spawn(async move {
        run_tls_alpn_listener(acme_state, listener, accepted_tx, acme_pool, settings).await
    });
    tokio::spawn(async move {
        while let Some(mut connection) = accepted_rx.recv().await {
            let _ = tokio::io::AsyncWriteExt::shutdown(&mut connection).await;
        }
    });

    let repository = PostgresRepository::new(pool);
    repository
        .recover_smtp_ingestions()
        .await
        .context("recover expired SMTP ingestions")?;
    let smtp_listener = TcpListener::bind(smtp_addr)
        .await
        .with_context(|| format!("bind SMTP listener {smtp_addr}"))?;
    let smtp_repository = Arc::new(repository.clone());
    let smtp_task = tokio::spawn(async move {
        mail_smtp_server::serve(
            smtp_listener,
            smtp_repository,
            mail_smtp_server::SmtpConfig {
                hostname,
                ..mail_smtp_server::SmtpConfig::default()
            },
        )
        .await
    });
    let app = mail_admin_api::router(repository);
    let tls = RustlsConfig::from_config(Arc::new(admin_tls));
    let admin = axum_server::bind_rustls(admin_addr, tls).serve(app.into_make_service());
    tokio::pin!(admin);
    tokio::select! {
        result = &mut admin => {
            result.with_context(|| format!("serve administration HTTPS on {admin_addr}"))?;
        }
        result = acme_task => {
            result.context("ACME listener task stopped")??;
            bail!("ACME listener stopped unexpectedly");
        }
        result = smtp_task => {
            result.context("SMTP listener task stopped")??;
            bail!("SMTP listener stopped unexpectedly");
        }
        result = shutdown_signal() => {
            result.context("install shutdown signal handler")?;
        }
    }
    Ok(())
}

#[cfg(unix)]
async fn shutdown_signal() -> std::io::Result<()> {
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::select! {
        result = tokio::signal::ctrl_c() => result,
        _ = terminate.recv() => Ok(()),
    }
}

#[cfg(not(unix))]
async fn shutdown_signal() -> std::io::Result<()> {
    tokio::signal::ctrl_c().await
}

fn required(name: &str) -> Result<String> {
    std::env::var(name).with_context(|| format!("{name} is required"))
}

fn csv(name: &str) -> Result<Vec<String>> {
    let values: Vec<String> = required(name)?
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .collect();
    if values.is_empty() {
        bail!("{name} must contain at least one value");
    }
    Ok(values)
}

fn address(name: &str, default: &str) -> Result<SocketAddr> {
    std::env::var(name)
        .unwrap_or_else(|_| default.to_owned())
        .parse()
        .with_context(|| format!("{name} must be a socket address"))
}

fn decode_hex(value: &str) -> Result<Vec<u8>> {
    if value.len() != 64 || !value.is_ascii() {
        bail!("MAIL_ACME_CACHE_KEY_HEX must be 64 hexadecimal characters");
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair).context("cache key is not ASCII")?;
            u8::from_str_radix(text, 16).context("cache key contains non-hexadecimal characters")
        })
        .collect()
}

fn valid_hostname(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}

async fn check_migrations(pool: &sqlx::PgPool) -> Result<()> {
    let applied: Option<i64> =
        sqlx::query_scalar("SELECT max(version) FROM _sqlx_migrations WHERE success = true")
            .fetch_optional(pool)
            .await
            .context("read migration version; run mail-migrate up first")?
            .flatten();
    let expected = mail_migrations::MIGRATOR
        .iter()
        .map(|migration| migration.version)
        .max();
    if applied != expected {
        bail!("schema mismatch: applied={applied:?}, expected={expected:?}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_key_requires_exact_hex() -> Result<()> {
        assert_eq!(decode_hex(&"ab".repeat(32))?, vec![0xab; 32]);
        assert!(decode_hex("not-a-key").is_err());
        Ok(())
    }
}
