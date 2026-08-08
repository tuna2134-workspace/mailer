#![forbid(unsafe_code)]

use std::time::Duration;

use anyhow::{Context, Result};
use mail_delivery::DeliveryWorker;
use mail_dkim::SigningKey;
use mail_dns::MailResolver;
use mail_postgres::PostgresRepository;
use mail_smtp_client::DkimSigningConfig;
use sqlx::postgres::PgPoolOptions;

#[tokio::main]
async fn main() -> Result<()> {
    let database_url =
        std::env::var("MAIL_DATABASE_URL").context("MAIL_DATABASE_URL is required")?;
    let hostname = std::env::var("MAIL_HOSTNAME").context("MAIL_HOSTNAME is required")?;
    let pool = PgPoolOptions::new()
        .max_connections(10)
        .connect(&database_url)
        .await
        .context("connect to PostgreSQL")?;
    let resolver = MailResolver::system().context("initialize system DNS resolver")?;
    let mut worker = DeliveryWorker::new(PostgresRepository::new(pool), resolver, hostname);
    if let Some(config) = dkim_config()? {
        worker = worker.with_dkim(config);
    }

    loop {
        tokio::select! {
            result = worker.run_once(50) => {
                if result.context("process delivery queue")? == 0 {
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
            signal = tokio::signal::ctrl_c() => {
                signal.context("wait for shutdown signal")?;
                break;
            }
        }
    }
    Ok(())
}

fn dkim_config() -> Result<Option<DkimSigningConfig>> {
    let domain = std::env::var("MAIL_DKIM_DOMAIN").ok();
    let selector = std::env::var("MAIL_DKIM_SELECTOR").ok();
    let key_file = std::env::var("MAIL_DKIM_KEY_FILE").ok();
    match (domain, selector, key_file) {
        (None, None, None) => Ok(None),
        (Some(domain), Some(selector), Some(path)) => {
            let der = std::fs::read(&path).with_context(|| format!("read DKIM key {path}"))?;
            let key = match std::env::var("MAIL_DKIM_ALGORITHM").as_deref() {
                Ok("rsa-sha256") => SigningKey::RsaPkcs8(der),
                Ok("ed25519-sha256") | Err(_) => SigningKey::Ed25519Pkcs8(der),
                Ok(value) => anyhow::bail!("unsupported MAIL_DKIM_ALGORITHM: {value}"),
            };
            Ok(Some(DkimSigningConfig {
                domain,
                selector,
                key,
            }))
        }
        _ => anyhow::bail!(
            "MAIL_DKIM_DOMAIN, MAIL_DKIM_SELECTOR, and MAIL_DKIM_KEY_FILE must be set together"
        ),
    }
}
