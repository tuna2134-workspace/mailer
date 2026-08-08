use mail_domain::{
    Domain, DomainId, DomainName, EntityStatus, LocalPart, QuotaBytes, Tenant, TenantId, User,
    UserId,
};
use mail_mailbox::{FlagSet, StoreMode, SystemFlag};
use mail_postgres::PostgresRepository;
use mail_storage::{ImapAppend, ImapRepository, MailRepository, StoreFlags};
use sqlx::postgres::PgPoolOptions;
use std::{
    io::Write,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;

#[tokio::test]
#[allow(clippy::too_many_lines)] // One isolated end-to-end PostgreSQL contract fixture.
async fn phase10_and_phase11_mailbox_sync_contract() -> Result<(), Box<dyn std::error::Error>> {
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
    let append_flags = FlagSet::new([SystemFlag::Seen], [])?;
    let append_date = UNIX_EPOCH + Duration::from_secs(1_786_104_000);
    let (validity, uid) = repository
        .imap_append(
            user_id.into_uuid(),
            "INBOX",
            &ImapAppend {
                raw: b"Subject: test\r\n\r\nbody",
                flags: &append_flags,
                internal_date: append_date,
            },
        )
        .await?;
    assert_eq!(validity, inbox.uid_validity);
    assert_eq!(uid, 1);
    let appended = repository
        .imap_messages(user_id.into_uuid(), inbox.id)
        .await?;
    assert_eq!(appended.len(), 1);
    assert!(appended[0].flags.iter().any(|flag| flag == "\\Seen"));
    assert_eq!(appended[0].internal_date, append_date);

    let (_, second_uid) = repository
        .imap_append(
            user_id.into_uuid(),
            "INBOX",
            &ImapAppend {
                raw: b"Subject: second\r\n\r\nbody",
                flags: &FlagSet::default(),
                internal_date: SystemTime::now(),
            },
        )
        .await?;
    let large = vec![b'x'; 70 * 1024];
    let mut spool = tempfile::NamedTempFile::new()?;
    spool.write_all(&large)?;
    spool.as_file().sync_data()?;
    let (_, large_uid) = repository
        .imap_append_file(
            user_id.into_uuid(),
            "INBOX",
            spool.as_file(),
            &FlagSet::default(),
            SystemTime::now(),
        )
        .await?;
    assert_eq!(
        repository
            .imap_messages(user_id.into_uuid(), inbox.id)
            .await?
            .into_iter()
            .find(|message| message.uid == large_uid)
            .ok_or("large APPEND")?
            .raw,
        large
    );
    let flagged = StoreFlags {
        mode: StoreMode::Add,
        values: FlagSet::new([SystemFlag::Flagged], [])?,
        unchanged_since: None,
    };
    assert!(
        repository
            .imap_store_flags(user_id.into_uuid(), inbox.id, &[uid, 999], &flagged)
            .await
            .is_err()
    );
    assert!(
        !repository
            .imap_messages(user_id.into_uuid(), inbox.id)
            .await?[0]
            .flags
            .iter()
            .any(|flag| flag == "\\Flagged")
    );

    let seen = StoreFlags {
        mode: StoreMode::Add,
        values: FlagSet::new([SystemFlag::Seen], [])?,
        unchanged_since: None,
    };
    repository
        .imap_store_flags(user_id.into_uuid(), inbox.id, &[uid], &seen)
        .await?;
    let conditional = StoreFlags {
        mode: StoreMode::Add,
        values: FlagSet::new([SystemFlag::Flagged], [])?,
        unchanged_since: Some(3),
    };
    let conditional_result = repository
        .imap_store_flags_conditional(
            user_id.into_uuid(),
            inbox.id,
            &[uid, second_uid],
            &conditional,
        )
        .await?;
    assert_eq!(conditional_result.modified, [uid]);
    assert_eq!(conditional_result.updated.len(), 1);
    assert_eq!(conditional_result.updated[0].uid, second_uid);
    let synchronization = repository
        .imap_changes(user_id.into_uuid(), inbox.id, 3)
        .await?;
    assert!(synchronization.highest_modseq > 3);
    assert!(
        synchronization
            .changed
            .iter()
            .any(|change| change.uid == uid)
    );
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
    let expunge_changes = repository
        .imap_changes(user_id.into_uuid(), inbox.id, 0)
        .await?;
    assert!(expunge_changes.vanished.contains(&uid));
    assert!(
        !repository
            .imap_messages(user_id.into_uuid(), inbox.id)
            .await?
            .is_empty()
    );
    repository
        .imap_store_flags(
            user_id.into_uuid(),
            inbox.id,
            &[second_uid, large_uid],
            &deleted,
        )
        .await?;
    repository
        .imap_expunge(user_id.into_uuid(), inbox.id, None)
        .await?;
    assert!(
        repository
            .imap_messages(user_id.into_uuid(), inbox.id)
            .await?
            .is_empty()
    );
    repository
        .imap_append(
            user_id.into_uuid(),
            "INBOX",
            &ImapAppend {
                raw: b"Subject: rename\r\n\r\nbody",
                flags: &FlagSet::default(),
                internal_date: SystemTime::now(),
            },
        )
        .await?;
    repository
        .imap_rename_mailbox(user_id.into_uuid(), "INBOX", "Renamed")
        .await?;
    let mailboxes = repository.imap_mailboxes(user_id.into_uuid()).await?;
    let renamed = mailboxes
        .iter()
        .find(|mailbox| mailbox.name == "Renamed")
        .ok_or("renamed mailbox")?;
    assert_eq!(renamed.message_count, 1);
    assert_eq!(
        mailboxes
            .iter()
            .find(|mailbox| mailbox.name == "INBOX")
            .ok_or("INBOX")?
            .message_count,
        0
    );
    assert!(
        repository
            .imap_mailboxes(user_id.into_uuid())
            .await?
            .iter()
            .any(|mailbox| mailbox.name == "Archive" && mailbox.subscribed)
    );
    let inbox = repository
        .imap_mailboxes(user_id.into_uuid())
        .await?
        .into_iter()
        .find(|mailbox| mailbox.name == "INBOX")
        .ok_or("INBOX")?;
    let destination = repository
        .imap_create_mailbox(user_id.into_uuid(), "MoveTarget")
        .await?;
    let (_, move_uid) = repository
        .imap_append(
            user_id.into_uuid(),
            "INBOX",
            &ImapAppend {
                raw: b"Subject: concurrent move\r\n\r\nbody",
                flags: &FlagSet::default(),
                internal_date: SystemTime::now(),
            },
        )
        .await?;
    let first = repository.clone();
    let second = repository.clone();
    let user = user_id.into_uuid();
    let source = inbox.id;
    let move_uids = [move_uid];
    let (left, right) = tokio::join!(
        first.imap_copy(user, source, &move_uids, "MoveTarget", true),
        second.imap_copy(user, source, &move_uids, "MoveTarget", true),
    );
    assert_eq!(usize::from(left.is_ok()) + usize::from(right.is_ok()), 1);
    assert!(
        repository
            .imap_messages(user, source)
            .await?
            .iter()
            .all(|message| message.uid != move_uid)
    );
    assert_eq!(
        repository.imap_messages(user, destination.id).await?.len(),
        1
    );
    Ok(())
}
