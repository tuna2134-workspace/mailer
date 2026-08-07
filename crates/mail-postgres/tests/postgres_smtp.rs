use mail_domain::{
    Domain, DomainId, DomainName, EntityStatus, LocalPart, Mailbox, MailboxId, QuotaBytes, Tenant,
    TenantId, User, UserId,
};
use mail_postgres::PostgresRepository;
use mail_storage::{MailRepository, SmtpRepository};
use sqlx::{Row, postgres::PgPoolOptions};
use uuid::Uuid;

#[tokio::test]
#[allow(clippy::too_many_lines)] // End-to-end schema and delivery contract fixture.
async fn streaming_ingestion_and_atomic_local_delivery() -> Result<(), Box<dyn std::error::Error>> {
    let Ok(url) = std::env::var("MAIL_TEST_DATABASE_URL") else {
        return Ok(());
    };
    let pool = PgPoolOptions::new()
        .max_connections(8)
        .connect(&url)
        .await?;
    mail_migrations::run(&pool).await?;
    let repository = PostgresRepository::new(pool.clone());
    let tenant = TenantId::new(Uuid::new_v4());
    let domain = DomainId::new(Uuid::new_v4());
    let user = UserId::new(Uuid::new_v4());
    let mailbox = MailboxId::new(Uuid::new_v4());
    repository
        .create_tenant(&Tenant {
            id: tenant,
            name: "smtp-contract".into(),
            status: EntityStatus::Active,
        })
        .await?;
    sqlx::query("UPDATE tenants SET quota_bytes=$2 WHERE id=$1")
        .bind(tenant.into_uuid())
        .bind(1_000_000_i64)
        .execute(&pool)
        .await?;
    repository
        .create_domain(&Domain {
            id: domain,
            tenant_id: tenant,
            name: DomainName::parse("example.test")?,
            status: EntityStatus::Active,
        })
        .await?;
    repository
        .create_user(&User {
            id: user,
            tenant_id: tenant,
            domain_id: domain,
            local_part: LocalPart::parse("alice")?,
            display_name: "Alice".into(),
            quota: QuotaBytes::new(1_000_000)?,
            status: EntityStatus::Active,
        })
        .await?;
    repository
        .create_mailbox(&Mailbox {
            id: mailbox,
            tenant_id: tenant,
            user_id: user,
            name: "INBOX".into(),
            uid_validity: 1,
            uid_next: 1,
            highest_modseq: 1,
        })
        .await?;

    let recipient = repository
        .resolve_local_recipient("alice@example.test")
        .await?
        .ok_or("recipient missing")?;
    assert!(
        repository
            .resolve_local_recipient("alice@remote.test")
            .await?
            .is_none()
    );
    let ingestion = repository.begin_smtp_ingestion().await?;
    repository
        .append_smtp_chunk(ingestion, 0, b"Subject: stored\r\n")
        .await?;
    repository
        .append_smtp_chunk(ingestion, 1, b"\r\nbody\r\n")
        .await?;
    let stored = repository
        .commit_smtp_ingestion(
            ingestion,
            "sender@example.net",
            &[recipient],
            b"Received: from test by mx.example.test; Thu, 01 Jan 1970 00:00:00 +0000\r\n",
        )
        .await?;
    assert_eq!(stored.message_ids.len(), 1);
    let row = sqlx::query("SELECT raw_message,message_size FROM messages WHERE id=$1")
        .bind(stored.message_ids[0])
        .fetch_one(&pool)
        .await?;
    let raw: Vec<u8> = row.try_get("raw_message")?;
    assert!(raw.starts_with(b"Return-Path: <sender@example.net>\r\nReceived:"));
    assert!(raw.ends_with(b"Subject: stored\r\n\r\nbody\r\n"));
    assert_eq!(
        i64::try_from(raw.len())?,
        row.try_get::<i64, _>("message_size")?
    );
    let counters = sqlx::query(
        "SELECT uid_next,highest_modseq,message_count,unseen_count FROM mailboxes WHERE id=$1",
    )
    .bind(mailbox.into_uuid())
    .fetch_one(&pool)
    .await?;
    assert_eq!(counters.try_get::<i64, _>("uid_next")?, 2);
    assert_eq!(counters.try_get::<i64, _>("highest_modseq")?, 2);
    assert_eq!(counters.try_get::<i64, _>("message_count")?, 1);
    assert_eq!(counters.try_get::<i64, _>("unseen_count")?, 1);
    let expired = Uuid::new_v4();
    sqlx::query("INSERT INTO smtp_ingestions(id,state,expires_at) VALUES($1,'receiving',clock_timestamp()-interval '1 minute')")
        .bind(expired).execute(&pool).await?;
    sqlx::query("INSERT INTO smtp_ingestion_chunks(ingestion_id,position,content) VALUES($1,0,$2)")
        .bind(expired)
        .bind(b"orphan".as_slice())
        .execute(&pool)
        .await?;
    assert_eq!(repository.recover_smtp_ingestions().await?, 1);
    let recovered: String = sqlx::query_scalar("SELECT state FROM smtp_ingestions WHERE id=$1")
        .bind(expired)
        .fetch_one(&pool)
        .await?;
    assert_eq!(recovered, "abandoned");
    let chunks: i64 =
        sqlx::query_scalar("SELECT count(*) FROM smtp_ingestion_chunks WHERE ingestion_id=$1")
            .bind(expired)
            .fetch_one(&pool)
            .await?;
    assert_eq!(chunks, 0);
    Ok(())
}
