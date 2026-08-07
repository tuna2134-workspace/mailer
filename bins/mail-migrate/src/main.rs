#![forbid(unsafe_code)]

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use sqlx::postgres::PgPoolOptions;

#[derive(Parser)]
#[command(about = "Explicit PostgreSQL migration operator")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Up,
    Check,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let database_url = std::env::var("MAIL_DATABASE_URL")
        .context("MAIL_DATABASE_URL must be supplied through a secret-capable environment")?;
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&database_url)
        .await
        .context("connect to PostgreSQL")?;

    match cli.command {
        Command::Up => mail_migrations::run(&pool)
            .await
            .context("run migrations")?,
        Command::Check => {
            let applied: Option<i64> = sqlx::query_scalar(
                "SELECT max(version) FROM _sqlx_migrations WHERE success = true",
            )
            .fetch_one(&pool)
            .await
            .context("read migration version")?;
            let expected = mail_migrations::MIGRATOR
                .iter()
                .map(|migration| migration.version)
                .max();
            if applied != expected {
                bail!("schema mismatch: applied={applied:?}, expected={expected:?}");
            }
        }
    }
    Ok(())
}
