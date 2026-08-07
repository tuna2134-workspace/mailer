use mail_domain::{
    Domain, DomainId, DomainName, EntityStatus, LocalPart, QuotaBytes, Tenant, TenantId, User,
    UserId,
};
use mail_mailbox::{FlagSet, StoreMode, SystemFlag};
use mail_postgres::PostgresRepository;
use mail_storage::{ImapRepository, MailRepository, StoreFlags};
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

#[tokio::test]
#[allow(clippy::too_many_lines)] // One isolated end-to-end PostgreSQL contract fixture.
async fn phase10_mailbox_message_and_uid_contract() -> Result<(), Box<dyn std::error::Error>> {
    let Ok(database_url) = std::env::var("MAIL_TEST_DATABASE_URL") else {
        return Ok(());
    };
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&database_url)
        .await?;
    mail_migrations::run(&pool).await?;
    let repository = PostgresRepository::new(pool);
    let tenant_id = TenantId::new(Uuid::new_v4());
    repository
        .create_tenant(&Tenant {
            id: tenant_id,
            name: format!("imap-{}", Uuid::new_v4()),
            status: EntityStatus::Active,
        })
        .await?;
    sqlx::query("UPDATE tenants SET quota_bytes=1000000 WHERE id=$1")
        .bind(tenant_id.into_uuid())
        .execute(repository.pool())
        .await?;
    let domain_id = DomainId::new(Uuid::new_v4());
    repository
        .create_domain(&Domain {
            id: domain_id,
            tenant_id,
            name: DomainName::parse(&format!("{}.test", Uuid::new_v4()))?,
            status: EntityStatus::Active,
        })
        .await?;
    let user_id = UserId::new(Uuid::new_v4());
    repository
        .create_user(&User {
            id: user_id,
            tenant_id,
            domain_id,
            local_part: LocalPart::parse("alice")?,
            display_name: "Alice".into(),
            quota: QuotaBytes::new(1_000_000)?,
            status: EntityStatus::Active,
        })
        .await?;

    let inbox = repository
        .imap_create_mailbox(user_id.into_uuid(), "INBOX")
        .await?;
    let archive = repository
        .imap_create_mailbox(user_id.into_uuid(), "Archive")
        .await?;
    repository
        .imap_subscribe(user_id.into_uuid(), "Archive", true)
        .await?;
    let (validity, uid) = repository
        .imap_append(user_id.into_uuid(), "INBOX", b"Subject: test\r\n\r\nbody")
        .await?;
    assert_eq!(validity, inbox.uid_validity);
    assert_eq!(uid, 1);
    assert_eq!(
        repository
            .imap_messages(user_id.into_uuid(), inbox.id)
            .await?
            .len(),
        1
    );

    let seen = StoreFlags {
        mode: StoreMode::Add,
        values: FlagSet::new([SystemFlag::Seen], [])?,
        unchanged_since: None,
    };
    repository
        .imap_store_flags(user_id.into_uuid(), inbox.id, &[uid], &seen)
        .await?;
    let copied = repository
        .imap_copy(user_id.into_uuid(), inbox.id, &[uid], "Archive", false)
        .await?;
    assert_eq!(copied, [1]);
    assert_eq!(
        repository
            .imap_messages(user_id.into_uuid(), archive.id)
            .await?
            .len(),
        1
    );

    let deleted = StoreFlags {
        mode: StoreMode::Add,
        values: FlagSet::new([SystemFlag::Deleted], [])?,
        unchanged_since: None,
    };
    repository
        .imap_store_flags(user_id.into_uuid(), inbox.id, &[uid], &deleted)
        .await?;
    assert_eq!(
        repository
            .imap_expunge(user_id.into_uuid(), inbox.id, None)
            .await?,
        [uid]
    );
    assert!(
        repository
            .imap_messages(user_id.into_uuid(), inbox.id)
            .await?
            .is_empty()
    );
    assert!(
        repository
            .imap_mailboxes(user_id.into_uuid())
            .await?
            .iter()
            .any(|mailbox| mailbox.name == "Archive" && mailbox.subscribed)
    );
    Ok(())
}
