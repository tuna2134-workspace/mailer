#![forbid(unsafe_code)]

use std::time::Duration;

use anyhow::{Context, Result};
use mail_delivery::DeliveryWorker;
use mail_dns::MailResolver;
use mail_postgres::PostgresRepository;
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
    let worker = DeliveryWorker::new(PostgresRepository::new(pool), resolver, hostname);

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
