use mail_domain::{
    Alias, AliasId, AliasKind, Domain, DomainId, DomainName, EntityStatus, LocalPart, MailboxId,
    QuotaBytes, Tenant, TenantId, User, UserId,
};
use mail_postgres::PostgresRepository;
use mail_storage::{AdminRepository, ApiTokenInfo, AuditEvent, MailRepository, StorageError};
use sqlx::postgres::PgPoolOptions;
use std::time::Duration;
use uuid::Uuid;

#[tokio::test]
#[allow(clippy::too_many_lines)] // One end-to-end transaction/constraint contract fixture.
async fn constraints_counters_quota_and_leases() -> Result<(), Box<dyn std::error::Error>> {
    let Ok(database_url) = std::env::var("MAIL_TEST_DATABASE_URL") else {
        return Ok(());
    };
    let pool = PgPoolOptions::new()
        .max_connections(8)
        .connect(&database_url)
        .await?;
    mail_migrations::run(&pool).await?;
    let repository = PostgresRepository::new(pool.clone());

    let tenant_id = TenantId::new(Uuid::new_v4());
    repository
        .create_tenant(&Tenant {
            id: tenant_id,
            name: "contract".into(),
            status: EntityStatus::Active,
        })
        .await?;
    let token_id = Uuid::new_v4();
    sqlx::query("INSERT INTO api_tokens (id,tenant_id,display_name,token_hash,scopes) VALUES ($1,$2,'contract',$3,ARRAY['tenants:read'])")
        .bind(token_id).bind(tenant_id.into_uuid()).bind(b"token-hash".as_slice()).execute(&pool).await?;
    let principal = repository.authenticate_api_token(b"token-hash").await?;
    assert_eq!(principal.token_id, token_id);
    assert_eq!(principal.tenant_id, Some(tenant_id));
    assert_eq!(
        repository
            .list_tenants(principal.tenant_id, 50, 0)
            .await?
            .len(),
        1
    );
    let mut tenant = repository.get_tenant(tenant_id).await?.value;
    tenant.name = "contract-updated".into();
    assert_eq!(repository.update_tenant(&tenant, 1).await?, 2);
    assert!(matches!(
        repository.update_tenant(&tenant, 1).await,
        Err(StorageError::Conflict)
    ));
    repository
        .write_audit(&AuditEvent {
            tenant_id: Some(tenant_id),
            actor_id: token_id,
            request_id: Uuid::new_v4(),
            action: "contract.test".into(),
            resource_type: "tenant".into(),
            resource_id: Some(tenant_id.into_uuid()),
        })
        .await?;
    sqlx::query("UPDATE tenants SET quota_bytes=10 WHERE id=$1")
        .bind(tenant_id.into_uuid())
        .execute(&pool)
        .await?;
    repository.consume_quota(tenant_id, 7).await?;
    assert!(matches!(
        repository.consume_quota(tenant_id, 4).await,
        Err(StorageError::QuotaExceeded)
    ));

    let domain_id = DomainId::new(Uuid::new_v4());
    repository
        .create_domain(&Domain {
            id: domain_id,
            tenant_id,
            name: DomainName::parse("example.test")?,
            status: EntityStatus::Active,
        })
        .await?;
    let mut domain = repository.get_domain(tenant_id, domain_id).await?.value;
    domain.status = EntityStatus::Disabled;
    assert_eq!(repository.update_domain(&domain, 1).await?, 2);
    let user_id = UserId::new(Uuid::new_v4());
    repository
        .create_user_with_password(
            &User {
                id: user_id,
                tenant_id,
                domain_id,
                local_part: LocalPart::parse("alice")?,
                display_name: "Alice".into(),
                quota: QuotaBytes::new(10)?,
                status: EntityStatus::Active,
            },
            "$argon2id$initial",
        )
        .await?;
    let mut stored_user = repository.get_user(tenant_id, user_id).await?.value;
    stored_user.display_name = "Updated".into();
    assert_eq!(repository.update_user(&stored_user, 1).await?, 2);
    repository
        .set_user_password(tenant_id, user_id, "$argon2id$test")
        .await?;
    repository.unlock_user(tenant_id, user_id).await?;

    let alias_id = AliasId::new(Uuid::new_v4());
    let mut alias = Alias {
        id: alias_id,
        tenant_id,
        source: "sales@example.test".into(),
        kind: AliasKind::Forwarding,
        targets: vec!["alice@example.test".into()],
    };
    repository.create_alias(&alias).await?;
    assert_eq!(
        repository.get_alias(tenant_id, alias_id).await?.value,
        alias
    );
    alias.targets.push("archive@example.test".into());
    assert_eq!(repository.update_alias(&alias, 1).await?, 2);
    repository.delete_alias(tenant_id, alias_id, 2).await?;

    let app_id = Uuid::new_v4();
    repository
        .create_application_password(tenant_id, user_id, app_id, "phone", "hash")
        .await?;
    assert_eq!(
        repository
            .list_application_passwords(tenant_id, user_id)
            .await?
            .len(),
        1
    );
    repository
        .revoke_application_password(tenant_id, user_id, app_id)
        .await?;

    let extra_token = ApiTokenInfo {
        id: Uuid::new_v4(),
        tenant_id: Some(tenant_id),
        display_name: "extra".into(),
        scopes: vec!["users:read".into()],
        revoked: false,
    };
    repository
        .create_api_token(&extra_token, b"extra-hash", token_id, None, &[])
        .await?;
    assert!(
        repository
            .list_api_tokens(Some(tenant_id), 50)
            .await?
            .iter()
            .any(|t| t.id == extra_token.id)
    );
    repository
        .revoke_api_token(Some(tenant_id), extra_token.id)
        .await?;

    repository
        .idempotency_begin(tenant_id, "contract-key-0001", "/users", b"request")
        .await?;
    assert_eq!(
        repository
            .idempotency_get(tenant_id, "contract-key-0001", "/users")
            .await?
            .map(|r| r.request_hash),
        Some(b"request".to_vec())
    );
    repository
        .idempotency_finish(
            tenant_id,
            "contract-key-0001",
            "/users",
            201,
            r#"{"id":"ok"}"#,
        )
        .await?;

    let mailbox_id = MailboxId::new(Uuid::new_v4());
    sqlx::query("INSERT INTO mailboxes (id,tenant_id,user_id,name,uid_validity) VALUES ($1,$2,$3,'INBOX',1)")
        .bind(mailbox_id.into_uuid()).bind(tenant_id.into_uuid()).bind(user_id.into_uuid()).execute(&pool).await?;
    assert_eq!(
        repository
            .list_mailboxes(tenant_id, user_id, 50)
            .await?
            .len(),
        1
    );
    assert_eq!(
        repository
            .get_mailbox(tenant_id, user_id, mailbox_id)
            .await?
            .mailbox
            .name,
        "INBOX"
    );
    assert_eq!(
        repository
            .update_mailbox_name(tenant_id, user_id, mailbox_id, "Archive", 1)
            .await?,
        2
    );
    assert_eq!(repository.allocate_mailbox_item(mailbox_id).await?.uid, 1);
    assert_eq!(
        repository.allocate_mailbox_item(mailbox_id).await?.modseq,
        3
    );
    let mut allocations = tokio::task::JoinSet::new();
    for _ in 0..8 {
        let repository = repository.clone();
        allocations.spawn(async move { repository.allocate_mailbox_item(mailbox_id).await });
    }
    let mut uids = Vec::new();
    let mut modseqs = Vec::new();
    while let Some(result) = allocations.join_next().await {
        let allocation = result??;
        uids.push(allocation.uid);
        modseqs.push(allocation.modseq);
    }
    uids.sort_unstable();
    modseqs.sort_unstable();
    assert_eq!(uids, (3..=10).collect::<Vec<_>>());
    assert_eq!(modseqs, (4..=11).collect::<Vec<_>>());

    let message_id = Uuid::new_v4();
    sqlx::query("INSERT INTO messages (id,tenant_id,raw_message,envelope_sender,received_at,message_size,content_hash,storage_state) VALUES ($1,$2,$3,'',clock_timestamp(),3,$4,'committed')")
        .bind(message_id).bind(tenant_id.into_uuid()).bind(b"abc".as_slice()).bind(b"hash".as_slice()).execute(&pool).await?;
    let queue_id = Uuid::new_v4();
    sqlx::query("INSERT INTO queue_recipients (id,tenant_id,message_id,recipient,destination_domain,state,next_attempt_at,expires_at) VALUES ($1,$2,$3,'bob@example.net','example.net','pending',clock_timestamp(),clock_timestamp()+interval '1 day')")
        .bind(queue_id).bind(tenant_id.into_uuid()).bind(message_id).execute(&pool).await?;
    let first = repository
        .lease_queue(Uuid::new_v4(), 1, Duration::from_secs(30))
        .await?;
    let second = repository
        .lease_queue(Uuid::new_v4(), 1, Duration::from_secs(30))
        .await?;
    assert_eq!(first.len(), 1);
    assert!(second.is_empty());
    assert_eq!(first[0].queue_id.into_uuid(), queue_id);
    Ok(())
}
