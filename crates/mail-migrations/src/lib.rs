#![forbid(unsafe_code)]

use sqlx::{PgPool, migrate::Migrator};

// Keep this embedding point rebuilt whenever the migration set changes (Phase 10 IMAP state).
pub static MIGRATOR: Migrator = sqlx::migrate!("../../migrations");

pub async fn run(pool: &PgPool) -> Result<(), sqlx::migrate::MigrateError> {
    MIGRATOR.run(pool).await
}
