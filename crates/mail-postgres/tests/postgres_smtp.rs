use mail_domain::{
    Domain, DomainId, DomainName, EntityStatus, LocalPart, Mailbox, MailboxId, QuotaBytes, Tenant,
    TenantId, User, UserId,
};
use mail_mailbox::{FlagSet, StoreMode, SystemFlag};
use mail_postgres::PostgresRepository;
use mail_storage::{
    MailRepository, MailboxRepository, SmtpMailOptions, SmtpRepository, StorageError, StoreFlags,
};
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
    let hosted_domain = format!("smtp-{}.test", tenant.into_uuid());
    let identity = format!("alice@{hosted_domain}");
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
            name: DomainName::parse(&hosted_domain)?,
            status: EntityStatus::Active,
        })
        .await?;
    repository
        .create_user_with_password(
            &User {
                id: user,
                tenant_id: tenant,
                domain_id: domain,
                local_part: LocalPart::parse("alice")?,
                display_name: "Alice".into(),
                quota: QuotaBytes::new(1_000_000)?,
                status: EntityStatus::Active,
            },
            &mail_storage::PasswordCredential::argon2_only("$argon2id$test-fixture"),
        )
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
    let archive = MailboxId::new(Uuid::new_v4());
    repository
        .create_mailbox(&Mailbox {
            id: archive,
            tenant_id: tenant,
            user_id: user,
            name: "Archive".into(),
            uid_validity: 1,
            uid_next: 1,
            highest_modseq: 1,
        })
        .await?;
    let validities: Vec<i64> = sqlx::query_scalar(
        "SELECT uid_validity FROM mailboxes WHERE id=ANY($1) ORDER BY uid_validity",
    )
    .bind(vec![mailbox.into_uuid(), archive.into_uuid()])
    .fetch_all(&pool)
    .await?;
    assert_eq!(validities.len(), 2);
    assert_ne!(validities[0], validities[1]);

    let recipient = repository
        .resolve_local_recipient(&identity)
        .await?
        .ok_or("recipient missing")?;
    let account = repository
        .smtp_auth_account(&identity.to_ascii_uppercase())
        .await?
        .ok_or("authentication account missing")?;
    assert_eq!(account.user_id, user.into_uuid());
    assert_eq!(account.password_hashes, ["$argon2id$test-fixture"]);
    for _ in 0..5 {
        repository.record_smtp_auth(account.user_id, false).await?;
    }
    assert!(repository.smtp_auth_account(&identity).await?.is_none());
    repository.record_smtp_auth(account.user_id, true).await?;
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
    assert_eq!(
        repository.read_smtp_chunk(ingestion, 0).await?,
        b"Subject: stored\r\n"
    );
    assert_eq!(
        repository.read_smtp_chunk(ingestion, 1).await?,
        b"\r\nbody\r\n"
    );
    assert!(repository.read_smtp_chunk(ingestion, 2).await?.is_empty());
    let stored = repository
        .commit_smtp_ingestion(
            ingestion,
            "sender@example.net",
            &[recipient],
            b"Received: from test by mx.example.test; Thu, 01 Jan 1970 00:00:00 +0000\r\n",
            &SmtpMailOptions::default(),
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
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT used_bytes FROM tenants WHERE id=$1")
            .bind(tenant.into_uuid())
            .fetch_one(&pool)
            .await?,
        i64::try_from(raw.len())?
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
    let seen = repository
        .store_flags(
            tenant,
            mailbox,
            1,
            &StoreFlags {
                mode: StoreMode::Add,
                values: FlagSet::new([SystemFlag::Seen], ["important".to_owned()])?,
                unchanged_since: Some(2),
            },
        )
        .await?;
    assert_eq!(seen.modseq, 3);
    assert!(seen.flags.system.contains(&SystemFlag::Seen));
    assert!(matches!(
        repository
            .store_flags(
                tenant,
                mailbox,
                1,
                &StoreFlags {
                    mode: StoreMode::Remove,
                    values: FlagSet::new([SystemFlag::Seen], [])?,
                    unchanged_since: Some(2),
                },
            )
            .await,
        Err(StorageError::Conflict)
    ));
    let fetched = repository
        .mailbox_message_by_uid(tenant, mailbox, 1)
        .await?;
    assert_eq!(fetched.modseq, 3);
    let first = repository.clone();
    let second = repository.clone();
    let update_one = StoreFlags {
        mode: StoreMode::Add,
        values: FlagSet::new([SystemFlag::Deleted], ["concurrent-a".to_owned()])?,
        unchanged_since: None,
    };
    let update_two = StoreFlags {
        mode: StoreMode::Add,
        values: FlagSet::new([], ["concurrent-b".to_owned()])?,
        unchanged_since: None,
    };
    let (one, two) = tokio::join!(
        first.store_flags(tenant, mailbox, 1, &update_one),
        second.store_flags(tenant, mailbox, 1, &update_two)
    );
    one?;
    two?;
    let concurrent = repository
        .mailbox_message_by_uid(tenant, mailbox, 1)
        .await?;
    assert_eq!(concurrent.modseq, 5);
    assert!(concurrent.flags.keywords.contains("concurrent-a"));
    assert!(concurrent.flags.keywords.contains("concurrent-b"));
    assert_eq!(repository.expunge_uid(tenant, mailbox, 1).await?, 6);
    let expunged = repository
        .mailbox_message_by_uid(tenant, mailbox, 1)
        .await?;
    assert!(expunged.expunged);
    let counters = sqlx::query(
        "SELECT uid_next,highest_modseq,message_count,unseen_count FROM mailboxes WHERE id=$1",
    )
    .bind(mailbox.into_uuid())
    .fetch_one(&pool)
    .await?;
    assert_eq!(counters.try_get::<i64, _>("uid_next")?, 2);
    assert_eq!(counters.try_get::<i64, _>("highest_modseq")?, 6);
    assert_eq!(counters.try_get::<i64, _>("message_count")?, 0);
    assert_eq!(counters.try_get::<i64, _>("unseen_count")?, 0);
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
