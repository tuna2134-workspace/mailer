#![forbid(unsafe_code)]

use anyhow::{Context, Result, bail};
use axum_server::tls_rustls::RustlsConfig;
use clap::Parser;
use mail_acme::{AcmeSettings, PostgresAcmeCache, RenewalLock, run_tls_alpn_listener, state};
use mail_config::{MaildConfig, ManualTlsConfig};
use mail_dns::MailResolver;
use mail_postgres::PostgresRepository;
use mail_storage::SmtpRepository;
use mail_tls::PemIdentity;
use rustls::ServerConfig;
use sqlx::postgres::PgPoolOptions;
use std::{path::PathBuf, sync::Arc};
use tokio::{net::TcpListener, sync::mpsc};

const RENEWAL_LOCK_ID: i64 = 0x4d41_494c_4143_4d45;

#[derive(Debug, Parser)]
#[command(about = "Internet mail server")]
struct Args {
    /// TOML configuration file. Overrides `MAIL_CONFIG_FILE`.
    #[arg(long)]
    config: Option<PathBuf>,
}

#[tokio::main]
#[allow(clippy::too_many_lines)]
async fn main() -> Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("install rustls ring crypto provider"))?;
    let MaildConfig {
        database_url,
        hostname,
        admin_listen: admin_addr,
        smtp_listen: smtp_addr,
        submission_listen: submission_addr,
        submissions_listen: implicit_submission_addr,
        imap_listen: imap_addr,
        imaps_listen: implicit_imap_addr,
        manual_tls,
        acme,
    } = MaildConfig::load(Args::parse().config).context("load maild configuration")?;
    let manual_identity = manual_identity(&hostname, manual_tls.as_ref()).await?;

    let pool = PgPoolOptions::new()
        .max_connections(20)
        .connect(&database_url)
        .await
        .context("connect to PostgreSQL")?;
    check_migrations(&pool).await?;
    let mut renewal_lock = None;
    let (resolver, acme_task): (_, tokio::task::JoinHandle<Result<()>>) =
        if let Some(identity) = manual_identity {
            (
                mail_tls::sni_resolver(&[identity]).context("load manual TLS identity")?,
                tokio::spawn(std::future::pending()),
            )
        } else {
            let acme = acme.context("ACME configuration is required without manual TLS")?;
            let cache_key = decode_hex(&acme.cache_key_hex)?;
            renewal_lock = Some(
                RenewalLock::acquire(&database_url, RENEWAL_LOCK_ID)
                    .await
                    .context("acquire distributed ACME renewal lock")?,
            );
            let settings = AcmeSettings {
                domains: acme.domains,
                contacts: acme.contacts,
                production: acme.production,
            };
            let cache = PostgresAcmeCache::new(pool.clone(), &cache_key)?;
            let acme_state = state(&settings, cache);
            let resolver = acme_state.resolver();
            let listener = TcpListener::bind(acme.listen)
                .await
                .with_context(|| format!("bind ACME TLS-ALPN-01 listener {}", acme.listen))?;
            let (accepted_tx, mut accepted_rx) = mpsc::channel(32);
            let acme_pool = pool.clone();
            let acme_task = tokio::spawn(async move {
                run_tls_alpn_listener(acme_state, listener, accepted_tx, acme_pool, settings)
                    .await
                    .map_err(anyhow::Error::from)
            });
            tokio::spawn(async move {
                while let Some(mut connection) = accepted_rx.recv().await {
                    let _ = tokio::io::AsyncWriteExt::shutdown(&mut connection).await;
                }
            });
            (resolver, acme_task)
        };
    let smtp_resolver: Arc<dyn rustls::server::ResolvesServerCert> = Arc::clone(&resolver);
    let smtp_tls = Arc::new(
        ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(smtp_resolver),
    );
    let mut admin_tls = ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(Arc::clone(&resolver));
    admin_tls.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    // Keep the PostgreSQL advisory-lock connection alive for the ACME task.
    let _renewal_lock = renewal_lock;

    let repository = PostgresRepository::new(pool);
    repository
        .recover_smtp_ingestions()
        .await
        .context("recover expired SMTP ingestions")?;
    let smtp_listener = TcpListener::bind(smtp_addr)
        .await
        .with_context(|| format!("bind SMTP listener {smtp_addr}"))?;
    let smtp_repository = Arc::new(repository.clone());
    let inbound_authenticator = Arc::new(mail_smtp_server::InboundAuthenticator::new(
        MailResolver::system().context("initialize authentication DNS resolver")?,
        hostname.clone(),
    ));
    let submission_listener = TcpListener::bind(submission_addr)
        .await
        .with_context(|| format!("bind Submission listener {submission_addr}"))?;
    let submission_repository = Arc::clone(&smtp_repository);
    let submission_tls = Arc::clone(&smtp_tls);
    let submission_hostname = hostname.clone();
    let submission_task = tokio::spawn(async move {
        mail_smtp_server::serve(
            submission_listener,
            submission_repository,
            mail_smtp_server::SmtpConfig {
                hostname: submission_hostname,
                tls: Some(submission_tls),
                auth_plain: true,
                auth_scram: true,
                chunking: true,
                dsn: true,
                smtp_utf8: true,
                require_tls: true,
                require_auth: true,
                authenticated_relay: true,
                deliver_by_min_seconds: Some(0),
                future_release_max_seconds: Some(30 * 24 * 60 * 60),
                ..mail_smtp_server::SmtpConfig::default()
            },
        )
        .await
    });
    let implicit_submission_listener = TcpListener::bind(implicit_submission_addr)
        .await
        .with_context(|| {
            format!("bind implicit TLS Submission listener {implicit_submission_addr}")
        })?;
    let implicit_repository = Arc::clone(&smtp_repository);
    let implicit_tls = Arc::clone(&smtp_tls);
    let implicit_hostname = hostname.clone();
    let implicit_submission_task = tokio::spawn(async move {
        mail_smtp_server::serve(
            implicit_submission_listener,
            implicit_repository,
            mail_smtp_server::SmtpConfig {
                hostname: implicit_hostname,
                tls: Some(implicit_tls),
                auth_plain: true,
                auth_scram: true,
                chunking: true,
                dsn: true,
                smtp_utf8: true,
                require_tls: true,
                require_auth: true,
                authenticated_relay: true,
                implicit_tls: true,
                deliver_by_min_seconds: Some(0),
                future_release_max_seconds: Some(30 * 24 * 60 * 60),
                ..mail_smtp_server::SmtpConfig::default()
            },
        )
        .await
    });
    let imap_tls = Arc::clone(&smtp_tls);
    let implicit_imap_tls = Arc::clone(&smtp_tls);
    let smtp_task = tokio::spawn(async move {
        mail_smtp_server::serve(
            smtp_listener,
            smtp_repository,
            mail_smtp_server::SmtpConfig {
                hostname,
                inbound_authentication: Some(inbound_authenticator),
                tls: Some(smtp_tls),
                auth_plain: true,
                auth_scram: true,
                chunking: true,
                dsn: true,
                smtp_utf8: true,
                require_tls: true,
                deliver_by_min_seconds: Some(0),
                ..mail_smtp_server::SmtpConfig::default()
            },
        )
        .await
    });
    let imap_listener = TcpListener::bind(imap_addr)
        .await
        .with_context(|| format!("bind IMAP listener {imap_addr}"))?;
    let imap_repository = Arc::new(repository.clone());
    let imap_task = tokio::spawn(async move {
        mail_imap_server::serve(
            imap_listener,
            imap_repository,
            mail_imap_server::ImapConfig {
                tls: Some(imap_tls),
                ..mail_imap_server::ImapConfig::default()
            },
        )
        .await
    });
    let implicit_imap_listener = TcpListener::bind(implicit_imap_addr)
        .await
        .with_context(|| format!("bind IMAPS listener {implicit_imap_addr}"))?;
    let implicit_imap_repository = Arc::new(repository.clone());
    let implicit_imap_task = tokio::spawn(async move {
        mail_imap_server::serve(
            implicit_imap_listener,
            implicit_imap_repository,
            mail_imap_server::ImapConfig {
                tls: Some(implicit_imap_tls),
                implicit_tls: true,
                ..mail_imap_server::ImapConfig::default()
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
        result = submission_task => {
            result.context("Submission listener task stopped")??;
            bail!("Submission listener stopped unexpectedly");
        }
        result = implicit_submission_task => {
            result.context("implicit TLS Submission listener task stopped")??;
            bail!("implicit TLS Submission listener stopped unexpectedly");
        }
        result = imap_task => {
            result.context("IMAP listener task stopped")??;
            bail!("IMAP listener stopped unexpectedly");
        }
        result = implicit_imap_task => {
            result.context("IMAPS listener task stopped")??;
            bail!("IMAPS listener stopped unexpectedly");
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

async fn manual_identity(
    hostname: &str,
    config: Option<&ManualTlsConfig>,
) -> Result<Option<PemIdentity>> {
    match config {
        None => Ok(None),
        Some(config) => Ok(Some(PemIdentity {
            names: vec![hostname.to_owned()],
            certificate_chain: tokio::fs::read(&config.certificate_file)
                .await
                .with_context(|| {
                    format!("read TLS certificate {}", config.certificate_file.display())
                })?,
            private_key: tokio::fs::read(&config.private_key_file)
                .await
                .with_context(|| {
                    format!("read TLS private key {}", config.private_key_file.display())
                })?,
        })),
    }
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
