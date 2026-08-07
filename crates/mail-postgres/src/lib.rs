#![forbid(unsafe_code)]

use async_trait::async_trait;
use mail_domain::{
    Alias, AliasId, AliasKind, Domain, DomainId, DomainName, EntityStatus, LocalPart, Mailbox,
    MailboxId, QuotaBytes, Tenant, TenantId, User, UserId,
};
use mail_storage::{
    AdminRepository, ApiCredential, ApiTokenInfo, ApplicationPasswordInfo, AuditEvent, AuditRecord,
    DeliveryOutcome, IdempotencyRecord, LocalRecipient, MailRepository, MailboxAllocation,
    MailboxInfo, QueueLease, SmtpRepository, StorageError, StoredMessage, Versioned,
};
use sqlx::{PgPool, Row};
use std::{
    collections::HashMap,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;

#[derive(Clone)]
pub struct PostgresRepository {
    pool: PgPool,
}

impl PostgresRepository {
    #[must_use]
    pub const fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    #[must_use]
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }
}

fn status(value: EntityStatus) -> &'static str {
    match value {
        EntityStatus::Active => "active",
        EntityStatus::Disabled => "disabled",
        EntityStatus::PendingDeletion => "pending_deletion",
    }
}

fn alias_kind(value: AliasKind) -> &'static str {
    match value {
        AliasKind::User => "user",
        AliasKind::Domain => "domain",
        AliasKind::Forwarding => "forwarding",
        AliasKind::Distribution => "distribution",
        AliasKind::CatchAll => "catch_all",
        AliasKind::Blackhole => "blackhole",
        AliasKind::Reject => "reject",
    }
}

fn parse_status(value: &str) -> Result<EntityStatus, StorageError> {
    match value {
        "active" => Ok(EntityStatus::Active),
        "disabled" => Ok(EntityStatus::Disabled),
        "pending_deletion" => Ok(EntityStatus::PendingDeletion),
        _ => Err(StorageError::Unavailable("invalid stored status".into())),
    }
}

fn parse_alias_kind(value: &str) -> Result<AliasKind, StorageError> {
    match value {
        "user" => Ok(AliasKind::User),
        "domain" => Ok(AliasKind::Domain),
        "forwarding" => Ok(AliasKind::Forwarding),
        "distribution" => Ok(AliasKind::Distribution),
        "catch_all" => Ok(AliasKind::CatchAll),
        "blackhole" => Ok(AliasKind::Blackhole),
        "reject" => Ok(AliasKind::Reject),
        _ => Err(StorageError::Unavailable(
            "invalid stored alias kind".into(),
        )),
    }
}

#[allow(clippy::needless_pass_by_value)] // `Result::map_err` supplies the owned error.
fn map_sqlx(error: sqlx::Error) -> StorageError {
    if let sqlx::Error::Database(database) = &error {
        return match database.code().as_deref() {
            Some("23505" | "23503" | "23514") => StorageError::Conflict,
            _ => StorageError::Unavailable(database.message().to_owned()),
        };
    }
    StorageError::Unavailable(error.to_string())
}

#[async_trait]
impl MailRepository for PostgresRepository {
    async fn authenticate_api_token(
        &self,
        token_hash: &[u8],
    ) -> Result<ApiCredential, StorageError> {
        let row = sqlx::query("UPDATE api_tokens SET last_used_at=clock_timestamp() WHERE token_hash=$1 AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > clock_timestamp()) RETURNING id,tenant_id,scopes")
            .bind(token_hash).fetch_optional(&self.pool).await.map_err(map_sqlx)?.ok_or(StorageError::NotFound)?;
        Ok(ApiCredential {
            token_id: row.try_get("id").map_err(map_sqlx)?,
            tenant_id: row
                .try_get::<Option<Uuid>, _>("tenant_id")
                .map_err(map_sqlx)?
                .map(TenantId::new),
            scopes: row.try_get("scopes").map_err(map_sqlx)?,
        })
    }

    async fn write_audit(&self, event: &AuditEvent) -> Result<(), StorageError> {
        sqlx::query("INSERT INTO audit_events (tenant_id,actor_id,request_id,action,resource_type,resource_id) VALUES ($1,$2,$3,$4,$5,$6)")
            .bind(event.tenant_id.map(TenantId::into_uuid)).bind(event.actor_id).bind(event.request_id)
            .bind(&event.action).bind(&event.resource_type).bind(event.resource_id)
            .execute(&self.pool).await.map_err(map_sqlx)?;
        Ok(())
    }

    async fn create_tenant(&self, tenant: &Tenant) -> Result<(), StorageError> {
        sqlx::query("INSERT INTO tenants (id, name, status) VALUES ($1, $2, $3)")
            .bind(tenant.id.into_uuid())
            .bind(&tenant.name)
            .bind(status(tenant.status))
            .execute(&self.pool)
            .await
            .map_err(map_sqlx)?;
        Ok(())
    }

    async fn list_tenants(
        &self,
        tenant_id: Option<TenantId>,
        limit: u16,
        offset: u32,
    ) -> Result<Vec<Tenant>, StorageError> {
        let rows = sqlx::query("SELECT id,name,status FROM tenants WHERE ($1::uuid IS NULL OR id=$1) ORDER BY id LIMIT $2 OFFSET $3")
            .bind(tenant_id.map(TenantId::into_uuid)).bind(i64::from(limit)).bind(i64::from(offset)).fetch_all(&self.pool).await.map_err(map_sqlx)?;
        rows.into_iter()
            .map(|row| {
                Ok(Tenant {
                    id: TenantId::new(row.try_get("id").map_err(map_sqlx)?),
                    name: row.try_get("name").map_err(map_sqlx)?,
                    status: parse_status(row.try_get("status").map_err(map_sqlx)?)?,
                })
            })
            .collect()
    }

    async fn create_domain(&self, domain: &Domain) -> Result<(), StorageError> {
        sqlx::query("INSERT INTO domains (id, tenant_id, name, status) VALUES ($1, $2, $3, $4)")
            .bind(domain.id.into_uuid())
            .bind(domain.tenant_id.into_uuid())
            .bind(domain.name.as_str())
            .bind(status(domain.status))
            .execute(&self.pool)
            .await
            .map_err(map_sqlx)?;
        Ok(())
    }

    async fn list_domains(
        &self,
        tenant_id: TenantId,
        limit: u16,
        offset: u32,
    ) -> Result<Vec<Domain>, StorageError> {
        let rows = sqlx::query(
            "SELECT id,name,status FROM domains WHERE tenant_id=$1 ORDER BY id LIMIT $2 OFFSET $3",
        )
        .bind(tenant_id.into_uuid())
        .bind(i64::from(limit))
        .bind(i64::from(offset))
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx)?;
        rows.into_iter()
            .map(|row| {
                Ok(Domain {
                    id: DomainId::new(row.try_get("id").map_err(map_sqlx)?),
                    tenant_id,
                    name: DomainName::parse(row.try_get("name").map_err(map_sqlx)?)
                        .map_err(|error| StorageError::Unavailable(error.to_string()))?,
                    status: parse_status(row.try_get("status").map_err(map_sqlx)?)?,
                })
            })
            .collect()
    }

    async fn create_user(&self, user: &User) -> Result<(), StorageError> {
        sqlx::query("INSERT INTO users (id, tenant_id, domain_id, local_part, display_name, status, quota_bytes) VALUES ($1,$2,$3,$4,$5,$6,$7)")
            .bind(user.id.into_uuid()).bind(user.tenant_id.into_uuid()).bind(user.domain_id.into_uuid())
            .bind(user.local_part.as_str()).bind(&user.display_name).bind(status(user.status))
            .bind(user.quota.as_i64()).execute(&self.pool).await.map_err(map_sqlx)?;
        Ok(())
    }

    async fn create_user_with_password(
        &self,
        user: &User,
        password_hash: &str,
    ) -> Result<(), StorageError> {
        let mut transaction = self.pool.begin().await.map_err(map_sqlx)?;
        sqlx::query("INSERT INTO users (id,tenant_id,domain_id,local_part,display_name,status,quota_bytes,password_changed_at) VALUES ($1,$2,$3,$4,$5,$6,$7,clock_timestamp())")
            .bind(user.id.into_uuid()).bind(user.tenant_id.into_uuid()).bind(user.domain_id.into_uuid())
            .bind(user.local_part.as_str()).bind(&user.display_name).bind(status(user.status)).bind(user.quota.as_i64())
            .execute(&mut *transaction).await.map_err(map_sqlx)?;
        sqlx::query("INSERT INTO password_credentials (user_id,password_hash) VALUES ($1,$2)")
            .bind(user.id.into_uuid())
            .bind(password_hash)
            .execute(&mut *transaction)
            .await
            .map_err(map_sqlx)?;
        transaction.commit().await.map_err(map_sqlx)
    }

    async fn list_users(
        &self,
        tenant_id: TenantId,
        limit: u16,
        offset: u32,
    ) -> Result<Vec<User>, StorageError> {
        let rows = sqlx::query("SELECT id,domain_id,local_part,display_name,status,quota_bytes FROM users WHERE tenant_id=$1 ORDER BY id LIMIT $2 OFFSET $3")
            .bind(tenant_id.into_uuid()).bind(i64::from(limit)).bind(i64::from(offset)).fetch_all(&self.pool).await.map_err(map_sqlx)?;
        rows.into_iter()
            .map(|row| {
                let quota: i64 = row.try_get("quota_bytes").map_err(map_sqlx)?;
                Ok(User {
                    id: UserId::new(row.try_get("id").map_err(map_sqlx)?),
                    tenant_id,
                    domain_id: DomainId::new(row.try_get("domain_id").map_err(map_sqlx)?),
                    local_part: LocalPart::parse(row.try_get("local_part").map_err(map_sqlx)?)
                        .map_err(|error| StorageError::Unavailable(error.to_string()))?,
                    display_name: row.try_get("display_name").map_err(map_sqlx)?,
                    quota: QuotaBytes::new(
                        u64::try_from(quota)
                            .map_err(|_| StorageError::Unavailable("invalid quota".into()))?,
                    )
                    .map_err(|error| StorageError::Unavailable(error.to_string()))?,
                    status: parse_status(row.try_get("status").map_err(map_sqlx)?)?,
                })
            })
            .collect()
    }

    async fn create_alias(&self, alias: &Alias) -> Result<(), StorageError> {
        let mut transaction = self.pool.begin().await.map_err(map_sqlx)?;
        sqlx::query("INSERT INTO aliases (id, tenant_id, source, kind) VALUES ($1,$2,$3,$4)")
            .bind(alias.id.into_uuid())
            .bind(alias.tenant_id.into_uuid())
            .bind(&alias.source)
            .bind(alias_kind(alias.kind))
            .execute(&mut *transaction)
            .await
            .map_err(map_sqlx)?;
        for (position, target) in alias.targets.iter().enumerate() {
            let position = i32::try_from(position).map_err(|_| StorageError::Conflict)?;
            sqlx::query("INSERT INTO alias_targets (alias_id, position, target) VALUES ($1,$2,$3)")
                .bind(alias.id.into_uuid())
                .bind(position)
                .bind(target)
                .execute(&mut *transaction)
                .await
                .map_err(map_sqlx)?;
        }
        transaction.commit().await.map_err(map_sqlx)
    }

    async fn list_aliases(
        &self,
        tenant_id: TenantId,
        limit: u16,
        offset: u32,
    ) -> Result<Vec<Alias>, StorageError> {
        let rows = sqlx::query(
            "SELECT id,source,kind FROM aliases WHERE tenant_id=$1 ORDER BY id LIMIT $2 OFFSET $3",
        )
        .bind(tenant_id.into_uuid())
        .bind(i64::from(limit))
        .bind(i64::from(offset))
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx)?;
        let mut aliases = Vec::with_capacity(rows.len());
        for row in rows {
            let id: Uuid = row.try_get("id").map_err(map_sqlx)?;
            let targets = sqlx::query_scalar(
                "SELECT target FROM alias_targets WHERE alias_id=$1 ORDER BY position",
            )
            .bind(id)
            .fetch_all(&self.pool)
            .await
            .map_err(map_sqlx)?;
            aliases.push(Alias {
                id: AliasId::new(id),
                tenant_id,
                source: row.try_get("source").map_err(map_sqlx)?,
                kind: parse_alias_kind(row.try_get("kind").map_err(map_sqlx)?)?,
                targets,
            });
        }
        Ok(aliases)
    }

    async fn create_mailbox(&self, mailbox: &Mailbox) -> Result<(), StorageError> {
        let highest_modseq =
            i64::try_from(mailbox.highest_modseq).map_err(|_| StorageError::CounterExhausted)?;
        sqlx::query("INSERT INTO mailboxes (id,tenant_id,user_id,name,uid_validity,uid_next,highest_modseq) VALUES ($1,$2,$3,$4,$5,$6,$7)")
            .bind(mailbox.id.into_uuid()).bind(mailbox.tenant_id.into_uuid()).bind(mailbox.user_id.into_uuid())
            .bind(&mailbox.name).bind(i64::from(mailbox.uid_validity)).bind(i64::from(mailbox.uid_next))
            .bind(highest_modseq).execute(&self.pool).await.map_err(map_sqlx)?;
        Ok(())
    }

    async fn allocate_mailbox_item(
        &self,
        mailbox_id: MailboxId,
    ) -> Result<MailboxAllocation, StorageError> {
        let row = sqlx::query(
            "UPDATE mailboxes SET uid_next = uid_next + 1, highest_modseq = highest_modseq + 1, version = version + 1 \
             WHERE id = $1 AND uid_next < 4294967295 AND highest_modseq < 9223372036854775807 \
             RETURNING uid_next - 1 AS uid, highest_modseq AS modseq",
        ).bind(mailbox_id.into_uuid()).fetch_optional(&self.pool).await.map_err(map_sqlx)?;
        let row = row.ok_or(StorageError::CounterExhausted)?;
        let uid: i64 = row.try_get("uid").map_err(map_sqlx)?;
        let modseq: i64 = row.try_get("modseq").map_err(map_sqlx)?;
        Ok(MailboxAllocation {
            uid: u32::try_from(uid).map_err(|_| StorageError::CounterExhausted)?,
            modseq: u64::try_from(modseq).map_err(|_| StorageError::CounterExhausted)?,
        })
    }

    async fn consume_quota(&self, tenant_id: TenantId, bytes: u64) -> Result<(), StorageError> {
        let bytes = i64::try_from(bytes).map_err(|_| StorageError::QuotaExceeded)?;
        let result = sqlx::query(
            "UPDATE tenants SET used_bytes = used_bytes + $2, version = version + 1, updated_at = clock_timestamp() \
             WHERE id = $1 AND used_bytes <= quota_bytes - $2",
        ).bind(tenant_id.into_uuid()).bind(bytes).execute(&self.pool).await.map_err(map_sqlx)?;
        if result.rows_affected() == 1 {
            Ok(())
        } else {
            Err(StorageError::QuotaExceeded)
        }
    }

    async fn lease_queue(
        &self,
        worker: Uuid,
        limit: u32,
        duration: Duration,
    ) -> Result<Vec<QueueLease>, StorageError> {
        let lease_seconds = i32::try_from(duration.as_secs().clamp(1, i32::MAX as u64))
            .map_err(|_| StorageError::Conflict)?;
        let limit = i64::from(limit.min(1_000));
        let rows = sqlx::query(
            "WITH candidates AS ( \
                SELECT id FROM queue_recipients \
                WHERE ((state IN ('pending','deferred') AND next_attempt_at <= clock_timestamp()) \
                    OR (state = 'leased' AND lease_expires_at <= clock_timestamp())) \
                  OR (state IN ('pending','deferred','leased') AND expires_at <= clock_timestamp()) \
                ORDER BY next_attempt_at, id FOR UPDATE SKIP LOCKED LIMIT $1 \
             ) UPDATE queue_recipients q SET state='leased', lease_owner=$2, lease_token=gen_random_uuid(), \
                 lease_expires_at=clock_timestamp() + make_interval(secs => $3::int) \
             FROM candidates c WHERE q.id=c.id \
             RETURNING q.id, q.lease_token, q.message_id, q.recipient, q.destination_domain, q.attempt_count, \
                 (SELECT envelope_sender FROM messages WHERE id=q.message_id) AS envelope_sender, \
                 extract(epoch FROM q.expires_at)::bigint AS expiry",
        ).bind(limit).bind(worker).bind(lease_seconds).fetch_all(&self.pool).await.map_err(map_sqlx)?;

        rows.into_iter()
            .map(|row| {
                let expiry: i64 = row.try_get("expiry").map_err(map_sqlx)?;
                let expiry = u64::try_from(expiry).map_err(|_| StorageError::Conflict)?;
                Ok(QueueLease {
                    queue_id: mail_domain::QueueId::new(row.try_get("id").map_err(map_sqlx)?),
                    lease_token: row.try_get("lease_token").map_err(map_sqlx)?,
                    message_id: row.try_get("message_id").map_err(map_sqlx)?,
                    recipient: row.try_get("recipient").map_err(map_sqlx)?,
                    destination_domain: row.try_get("destination_domain").map_err(map_sqlx)?,
                    envelope_sender: row.try_get("envelope_sender").map_err(map_sqlx)?,
                    attempt_count: row
                        .try_get::<i32, _>("attempt_count")
                        .map_err(map_sqlx)?
                        .try_into()
                        .map_err(|_| StorageError::Conflict)?,
                    expires_at: UNIX_EPOCH
                        .checked_add(Duration::from_secs(expiry))
                        .ok_or(StorageError::Conflict)?,
                })
            })
            .collect()
    }

    async fn read_message_chunk(
        &self,
        message_id: Uuid,
        offset: u64,
        limit: u32,
    ) -> Result<Vec<u8>, StorageError> {
        let start = i32::try_from(offset.saturating_add(1)).map_err(|_| StorageError::Conflict)?;
        let limit = i32::try_from(limit.clamp(1, 1_048_576)).map_err(|_| StorageError::Conflict)?;
        sqlx::query_scalar("SELECT substring(raw_message FROM $2 FOR $3) FROM messages WHERE id=$1")
            .bind(message_id)
            .bind(start)
            .bind(limit)
            .fetch_optional(&self.pool)
            .await
            .map_err(map_sqlx)?
            .ok_or(StorageError::NotFound)
    }

    async fn finish_delivery(
        &self,
        queue_id: mail_domain::QueueId,
        lease_token: Uuid,
        outcome: &DeliveryOutcome,
    ) -> Result<(), StorageError> {
        let mut tx = self.pool.begin().await.map_err(map_sqlx)?;
        let (state, next_attempt, code, diagnostic) = match outcome {
            DeliveryOutcome::Delivered => ("delivered", None, None, None),
            DeliveryOutcome::Deferred {
                next_attempt_at,
                enhanced_status_code,
                diagnostic,
            } => (
                "deferred",
                Some(*next_attempt_at),
                enhanced_status_code.as_deref(),
                Some(diagnostic.as_str()),
            ),
            DeliveryOutcome::Failed {
                enhanced_status_code,
                diagnostic,
            } => (
                "failed",
                None,
                enhanced_status_code.as_deref(),
                Some(diagnostic.as_str()),
            ),
        };
        let next_attempt = next_attempt
            .map(|value| value.duration_since(UNIX_EPOCH))
            .transpose()
            .map_err(|_| StorageError::Conflict)?
            .map(|duration| i64::try_from(duration.as_secs()))
            .transpose()
            .map_err(|_| StorageError::Conflict)?;
        let updated = sqlx::query(
            "UPDATE queue_recipients SET state=$3, next_attempt_at=COALESCE(to_timestamp($4),next_attempt_at), \
             attempt_count=attempt_count+1, enhanced_status_code=$5, failure_reason=$6, \
             lease_owner=NULL, lease_token=NULL, lease_expires_at=NULL \
             WHERE id=$1 AND state='leased' AND lease_token=$2",
        )
        .bind(queue_id.into_uuid())
        .bind(lease_token)
        .bind(state)
        .bind(next_attempt)
        .bind(code)
        .bind(diagnostic)
        .execute(&mut *tx)
        .await
        .map_err(map_sqlx)?;
        if updated.rows_affected() != 1 {
            return Err(StorageError::Conflict);
        }
        sqlx::query("INSERT INTO delivery_attempts(queue_id,result,enhanced_status_code,diagnostic) VALUES($1,$2,$3,$4)")
            .bind(queue_id.into_uuid()).bind(state).bind(code).bind(diagnostic)
            .execute(&mut *tx).await.map_err(map_sqlx)?;
        if let DeliveryOutcome::Failed { diagnostic, .. } = outcome {
            let original: Option<(Uuid, String)> = sqlx::query_as(
                "SELECT m.tenant_id,m.envelope_sender FROM queue_recipients q JOIN messages m ON m.id=q.message_id WHERE q.id=$1")
                .bind(queue_id.into_uuid()).fetch_optional(&mut *tx).await.map_err(map_sqlx)?;
            if let Some((tenant_id, sender)) = original {
                if let Some(domain) = sender
                    .rsplit_once('@')
                    .map(|(_, domain)| domain)
                    .filter(|domain| !domain.is_empty())
                {
                    let message_id = Uuid::new_v4();
                    let bounce = format!(
                        "From: Mail Delivery System <MAILER-DAEMON@localhost>\r\nTo: <{sender}>\r\nSubject: Delivery Status Notification (Failure)\r\nAuto-Submitted: auto-generated\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nDelivery failed permanently.\r\n\r\n{}\r\n",
                        diagnostic.chars().take(2_000).collect::<String>()
                    ).into_bytes();
                    sqlx::query("INSERT INTO messages(id,tenant_id,raw_message,envelope_sender,envelope_recipients,received_at,message_size,content_hash,storage_state) VALUES($1,$2,$3,'',ARRAY[$4],clock_timestamp(),octet_length($3),digest($3,'sha256'),'committed')")
                        .bind(message_id).bind(tenant_id).bind(&bounce).bind(&sender)
                        .execute(&mut *tx).await.map_err(map_sqlx)?;
                    sqlx::query("INSERT INTO queue_recipients(id,tenant_id,message_id,recipient,destination_domain,state,next_attempt_at,expires_at) VALUES($1,$2,$3,$4,$5,'pending',clock_timestamp(),clock_timestamp()+interval '5 days')")
                        .bind(Uuid::new_v4()).bind(tenant_id).bind(message_id).bind(&sender).bind(domain)
                        .execute(&mut *tx).await.map_err(map_sqlx)?;
                }
            }
        }
        tx.commit().await.map_err(map_sqlx)
    }
}

pub async fn check(pool: &PgPool) -> Result<(), StorageError> {
    sqlx::query("SELECT 1")
        .execute(pool)
        .await
        .map_err(map_sqlx)?;
    Ok(())
}

#[async_trait]
impl AdminRepository for PostgresRepository {
    async fn get_tenant(&self, id: TenantId) -> Result<Versioned<Tenant>, StorageError> {
        let row = sqlx::query("SELECT name,status,version FROM tenants WHERE id=$1")
            .bind(id.into_uuid())
            .fetch_optional(&self.pool)
            .await
            .map_err(map_sqlx)?
            .ok_or(StorageError::NotFound)?;
        Ok(Versioned {
            value: Tenant {
                id,
                name: row.try_get("name").map_err(map_sqlx)?,
                status: parse_status(row.try_get("status").map_err(map_sqlx)?)?,
            },
            version: row.try_get("version").map_err(map_sqlx)?,
        })
    }
    async fn update_tenant(&self, tenant: &Tenant, expected: i64) -> Result<i64, StorageError> {
        sqlx::query_scalar("UPDATE tenants SET name=$2,status=$3,version=version+1,updated_at=clock_timestamp() WHERE id=$1 AND version=$4 RETURNING version")
            .bind(tenant.id.into_uuid()).bind(&tenant.name).bind(status(tenant.status)).bind(expected).fetch_optional(&self.pool).await.map_err(map_sqlx)?.ok_or(StorageError::Conflict)
    }
    async fn get_domain(
        &self,
        tenant: TenantId,
        id: DomainId,
    ) -> Result<Versioned<Domain>, StorageError> {
        let row =
            sqlx::query("SELECT name,status,version FROM domains WHERE tenant_id=$1 AND id=$2")
                .bind(tenant.into_uuid())
                .bind(id.into_uuid())
                .fetch_optional(&self.pool)
                .await
                .map_err(map_sqlx)?
                .ok_or(StorageError::NotFound)?;
        Ok(Versioned {
            value: Domain {
                id,
                tenant_id: tenant,
                name: DomainName::parse(row.try_get("name").map_err(map_sqlx)?)
                    .map_err(|e| StorageError::Unavailable(e.to_string()))?,
                status: parse_status(row.try_get("status").map_err(map_sqlx)?)?,
            },
            version: row.try_get("version").map_err(map_sqlx)?,
        })
    }
    async fn update_domain(&self, domain: &Domain, expected: i64) -> Result<i64, StorageError> {
        sqlx::query_scalar("UPDATE domains SET name=$3,status=$4,version=version+1 WHERE tenant_id=$1 AND id=$2 AND version=$5 RETURNING version")
            .bind(domain.tenant_id.into_uuid()).bind(domain.id.into_uuid()).bind(domain.name.as_str()).bind(status(domain.status)).bind(expected).fetch_optional(&self.pool).await.map_err(map_sqlx)?.ok_or(StorageError::Conflict)
    }
    async fn get_user(
        &self,
        tenant: TenantId,
        id: UserId,
    ) -> Result<Versioned<User>, StorageError> {
        let row=sqlx::query("SELECT domain_id,local_part,display_name,status,quota_bytes,version FROM users WHERE tenant_id=$1 AND id=$2").bind(tenant.into_uuid()).bind(id.into_uuid()).fetch_optional(&self.pool).await.map_err(map_sqlx)?.ok_or(StorageError::NotFound)?;
        let quota: i64 = row.try_get("quota_bytes").map_err(map_sqlx)?;
        Ok(Versioned {
            value: User {
                id,
                tenant_id: tenant,
                domain_id: DomainId::new(row.try_get("domain_id").map_err(map_sqlx)?),
                local_part: LocalPart::parse(row.try_get("local_part").map_err(map_sqlx)?)
                    .map_err(|e| StorageError::Unavailable(e.to_string()))?,
                display_name: row.try_get("display_name").map_err(map_sqlx)?,
                quota: QuotaBytes::new(u64::try_from(quota).map_err(|_| StorageError::Conflict)?)
                    .map_err(|e| StorageError::Unavailable(e.to_string()))?,
                status: parse_status(row.try_get("status").map_err(map_sqlx)?)?,
            },
            version: row.try_get("version").map_err(map_sqlx)?,
        })
    }
    async fn update_user(&self, user: &User, expected: i64) -> Result<i64, StorageError> {
        sqlx::query_scalar("UPDATE users SET domain_id=$3,local_part=$4,display_name=$5,status=$6,quota_bytes=$7,version=version+1 WHERE tenant_id=$1 AND id=$2 AND version=$8 AND used_bytes <= $7 RETURNING version")
            .bind(user.tenant_id.into_uuid()).bind(user.id.into_uuid()).bind(user.domain_id.into_uuid()).bind(user.local_part.as_str()).bind(&user.display_name).bind(status(user.status)).bind(user.quota.as_i64()).bind(expected).fetch_optional(&self.pool).await.map_err(map_sqlx)?.ok_or(StorageError::Conflict)
    }
    async fn set_user_password(
        &self,
        tenant: TenantId,
        user: UserId,
        hash: &str,
    ) -> Result<(), StorageError> {
        let result=sqlx::query("UPDATE password_credentials p SET password_hash=$3,created_at=clock_timestamp() FROM users u WHERE p.user_id=u.id AND u.tenant_id=$1 AND u.id=$2")
            .bind(tenant.into_uuid()).bind(user.into_uuid()).bind(hash).execute(&self.pool).await.map_err(map_sqlx)?;
        if result.rows_affected() == 1 {
            Ok(())
        } else {
            Err(StorageError::NotFound)
        }
    }
    async fn unlock_user(&self, tenant: TenantId, user: UserId) -> Result<(), StorageError> {
        let result=sqlx::query("UPDATE users SET failed_login_count=0,locked_until=NULL,version=version+1 WHERE tenant_id=$1 AND id=$2").bind(tenant.into_uuid()).bind(user.into_uuid()).execute(&self.pool).await.map_err(map_sqlx)?;
        if result.rows_affected() == 1 {
            Ok(())
        } else {
            Err(StorageError::NotFound)
        }
    }
    async fn get_alias(
        &self,
        tenant: TenantId,
        id: AliasId,
    ) -> Result<Versioned<Alias>, StorageError> {
        let row =
            sqlx::query("SELECT source,kind,version FROM aliases WHERE tenant_id=$1 AND id=$2")
                .bind(tenant.into_uuid())
                .bind(id.into_uuid())
                .fetch_optional(&self.pool)
                .await
                .map_err(map_sqlx)?
                .ok_or(StorageError::NotFound)?;
        let targets = sqlx::query_scalar(
            "SELECT target FROM alias_targets WHERE alias_id=$1 ORDER BY position",
        )
        .bind(id.into_uuid())
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(Versioned {
            value: Alias {
                id,
                tenant_id: tenant,
                source: row.try_get("source").map_err(map_sqlx)?,
                kind: parse_alias_kind(row.try_get("kind").map_err(map_sqlx)?)?,
                targets,
            },
            version: row.try_get("version").map_err(map_sqlx)?,
        })
    }
    async fn update_alias(&self, alias: &Alias, expected: i64) -> Result<i64, StorageError> {
        let mut tx = self.pool.begin().await.map_err(map_sqlx)?;
        let version:Option<i64>=sqlx::query_scalar("UPDATE aliases SET source=$3,kind=$4,version=version+1 WHERE tenant_id=$1 AND id=$2 AND version=$5 RETURNING version")
            .bind(alias.tenant_id.into_uuid()).bind(alias.id.into_uuid()).bind(&alias.source).bind(alias_kind(alias.kind)).bind(expected).fetch_optional(&mut *tx).await.map_err(map_sqlx)?;
        let version = version.ok_or(StorageError::Conflict)?;
        sqlx::query("DELETE FROM alias_targets WHERE alias_id=$1")
            .bind(alias.id.into_uuid())
            .execute(&mut *tx)
            .await
            .map_err(map_sqlx)?;
        for (position, target) in alias.targets.iter().enumerate() {
            sqlx::query("INSERT INTO alias_targets(alias_id,position,target)VALUES($1,$2,$3)")
                .bind(alias.id.into_uuid())
                .bind(i32::try_from(position).map_err(|_| StorageError::Conflict)?)
                .bind(target)
                .execute(&mut *tx)
                .await
                .map_err(map_sqlx)?;
        }
        tx.commit().await.map_err(map_sqlx)?;
        Ok(version)
    }
    async fn delete_alias(
        &self,
        tenant: TenantId,
        id: AliasId,
        expected: i64,
    ) -> Result<(), StorageError> {
        let result = sqlx::query("DELETE FROM aliases WHERE tenant_id=$1 AND id=$2 AND version=$3")
            .bind(tenant.into_uuid())
            .bind(id.into_uuid())
            .bind(expected)
            .execute(&self.pool)
            .await
            .map_err(map_sqlx)?;
        if result.rows_affected() == 1 {
            Ok(())
        } else {
            Err(StorageError::Conflict)
        }
    }
    async fn list_mailboxes(
        &self,
        tenant: TenantId,
        user: UserId,
        limit: u16,
    ) -> Result<Vec<MailboxInfo>, StorageError> {
        let rows=sqlx::query("SELECT id,name,uid_validity,uid_next,highest_modseq,version,message_count,unseen_count FROM mailboxes WHERE tenant_id=$1 AND user_id=$2 ORDER BY id LIMIT $3").bind(tenant.into_uuid()).bind(user.into_uuid()).bind(i64::from(limit)).fetch_all(&self.pool).await.map_err(map_sqlx)?;
        rows.into_iter()
            .map(|r| mailbox_info(tenant, user, &r))
            .collect()
    }
    async fn get_mailbox(
        &self,
        tenant: TenantId,
        user: UserId,
        id: MailboxId,
    ) -> Result<MailboxInfo, StorageError> {
        let row=sqlx::query("SELECT id,name,uid_validity,uid_next,highest_modseq,version,message_count,unseen_count FROM mailboxes WHERE tenant_id=$1 AND user_id=$2 AND id=$3").bind(tenant.into_uuid()).bind(user.into_uuid()).bind(id.into_uuid()).fetch_optional(&self.pool).await.map_err(map_sqlx)?.ok_or(StorageError::NotFound)?;
        mailbox_info(tenant, user, &row)
    }
    async fn update_mailbox_name(
        &self,
        tenant: TenantId,
        user: UserId,
        id: MailboxId,
        name: &str,
        expected: i64,
    ) -> Result<i64, StorageError> {
        sqlx::query_scalar("UPDATE mailboxes SET name=$4,version=version+1 WHERE tenant_id=$1 AND user_id=$2 AND id=$3 AND version=$5 RETURNING version").bind(tenant.into_uuid()).bind(user.into_uuid()).bind(id.into_uuid()).bind(name).bind(expected).fetch_optional(&self.pool).await.map_err(map_sqlx)?.ok_or(StorageError::Conflict)
    }
    async fn delete_mailbox(
        &self,
        tenant: TenantId,
        user: UserId,
        id: MailboxId,
        expected: i64,
    ) -> Result<(), StorageError> {
        let r=sqlx::query("DELETE FROM mailboxes WHERE tenant_id=$1 AND user_id=$2 AND id=$3 AND version=$4 AND message_count=0").bind(tenant.into_uuid()).bind(user.into_uuid()).bind(id.into_uuid()).bind(expected).execute(&self.pool).await.map_err(map_sqlx)?;
        if r.rows_affected() == 1 {
            Ok(())
        } else {
            Err(StorageError::Conflict)
        }
    }
    async fn create_application_password(
        &self,
        tenant: TenantId,
        user: UserId,
        id: Uuid,
        name: &str,
        hash: &str,
    ) -> Result<ApplicationPasswordInfo, StorageError> {
        sqlx::query("INSERT INTO application_passwords(id,tenant_id,user_id,display_name,secret_hash)VALUES($1,$2,$3,$4,$5)").bind(id).bind(tenant.into_uuid()).bind(user.into_uuid()).bind(name).bind(hash).execute(&self.pool).await.map_err(map_sqlx)?;
        Ok(ApplicationPasswordInfo {
            id,
            display_name: name.into(),
            revoked: false,
        })
    }
    async fn list_application_passwords(
        &self,
        tenant: TenantId,
        user: UserId,
    ) -> Result<Vec<ApplicationPasswordInfo>, StorageError> {
        let rows=sqlx::query("SELECT id,display_name,revoked_at IS NOT NULL AS revoked FROM application_passwords WHERE tenant_id=$1 AND user_id=$2 ORDER BY created_at,id").bind(tenant.into_uuid()).bind(user.into_uuid()).fetch_all(&self.pool).await.map_err(map_sqlx)?;
        rows.into_iter()
            .map(|r| {
                Ok(ApplicationPasswordInfo {
                    id: r.try_get("id").map_err(map_sqlx)?,
                    display_name: r.try_get("display_name").map_err(map_sqlx)?,
                    revoked: r.try_get("revoked").map_err(map_sqlx)?,
                })
            })
            .collect()
    }
    async fn revoke_application_password(
        &self,
        tenant: TenantId,
        user: UserId,
        id: Uuid,
    ) -> Result<(), StorageError> {
        let r=sqlx::query("UPDATE application_passwords SET revoked_at=COALESCE(revoked_at,clock_timestamp()) WHERE tenant_id=$1 AND user_id=$2 AND id=$3").bind(tenant.into_uuid()).bind(user.into_uuid()).bind(id).execute(&self.pool).await.map_err(map_sqlx)?;
        if r.rows_affected() == 1 {
            Ok(())
        } else {
            Err(StorageError::NotFound)
        }
    }
    async fn create_api_token(
        &self,
        info: &ApiTokenInfo,
        hash: &[u8],
        creator: Uuid,
        expires_at: Option<&str>,
        networks: &[String],
    ) -> Result<(), StorageError> {
        sqlx::query("INSERT INTO api_tokens(id,tenant_id,display_name,token_hash,scopes,created_by,expires_at,allowed_source_networks)VALUES($1,$2,$3,$4,$5,$6,$7::timestamptz,$8::cidr[])").bind(info.id).bind(info.tenant_id.map(TenantId::into_uuid)).bind(&info.display_name).bind(hash).bind(&info.scopes).bind(creator).bind(expires_at).bind(networks).execute(&self.pool).await.map_err(map_sqlx)?;
        Ok(())
    }
    async fn list_api_tokens(
        &self,
        tenant: Option<TenantId>,
        limit: u16,
    ) -> Result<Vec<ApiTokenInfo>, StorageError> {
        let rows=sqlx::query("SELECT id,tenant_id,display_name,scopes,revoked_at IS NOT NULL AS revoked FROM api_tokens WHERE ($1::uuid IS NULL OR tenant_id=$1) ORDER BY created_at,id LIMIT $2").bind(tenant.map(TenantId::into_uuid)).bind(i64::from(limit)).fetch_all(&self.pool).await.map_err(map_sqlx)?;
        rows.into_iter()
            .map(|r| {
                Ok(ApiTokenInfo {
                    id: r.try_get("id").map_err(map_sqlx)?,
                    tenant_id: r
                        .try_get::<Option<Uuid>, _>("tenant_id")
                        .map_err(map_sqlx)?
                        .map(TenantId::new),
                    display_name: r.try_get("display_name").map_err(map_sqlx)?,
                    scopes: r.try_get("scopes").map_err(map_sqlx)?,
                    revoked: r.try_get("revoked").map_err(map_sqlx)?,
                })
            })
            .collect()
    }
    async fn revoke_api_token(
        &self,
        tenant: Option<TenantId>,
        id: Uuid,
    ) -> Result<(), StorageError> {
        let r=sqlx::query("UPDATE api_tokens SET revoked_at=COALESCE(revoked_at,clock_timestamp()) WHERE id=$2 AND ($1::uuid IS NULL OR tenant_id=$1)").bind(tenant.map(TenantId::into_uuid)).bind(id).execute(&self.pool).await.map_err(map_sqlx)?;
        if r.rows_affected() == 1 {
            Ok(())
        } else {
            Err(StorageError::NotFound)
        }
    }
    async fn list_audit(
        &self,
        tenant: Option<TenantId>,
        limit: u16,
    ) -> Result<Vec<AuditRecord>, StorageError> {
        let rows=sqlx::query("SELECT id,action,resource_type,resource_id FROM audit_events WHERE ($1::uuid IS NULL OR tenant_id=$1) ORDER BY occurred_at DESC,id DESC LIMIT $2").bind(tenant.map(TenantId::into_uuid)).bind(i64::from(limit)).fetch_all(&self.pool).await.map_err(map_sqlx)?;
        rows.into_iter()
            .map(|r| {
                Ok(AuditRecord {
                    id: r.try_get("id").map_err(map_sqlx)?,
                    action: r.try_get("action").map_err(map_sqlx)?,
                    resource_type: r.try_get("resource_type").map_err(map_sqlx)?,
                    resource_id: r.try_get("resource_id").map_err(map_sqlx)?,
                })
            })
            .collect()
    }
    async fn idempotency_get(
        &self,
        tenant: TenantId,
        key: &str,
        operation: &str,
    ) -> Result<Option<IdempotencyRecord>, StorageError> {
        let row=sqlx::query("SELECT request_hash,response_status,response_body::text AS body FROM idempotency_keys WHERE tenant_id=$1 AND key=$2 AND operation=$3 AND expires_at>clock_timestamp()").bind(tenant.into_uuid()).bind(key).bind(operation).fetch_optional(&self.pool).await.map_err(map_sqlx)?;
        row.map(|r| {
            Ok(IdempotencyRecord {
                request_hash: r.try_get("request_hash").map_err(map_sqlx)?,
                response_status: r
                    .try_get::<Option<i32>, _>("response_status")
                    .map_err(map_sqlx)?
                    .and_then(|v| u16::try_from(v).ok()),
                response_body: r.try_get("body").map_err(map_sqlx)?,
            })
        })
        .transpose()
    }
    async fn idempotency_begin(
        &self,
        tenant: TenantId,
        key: &str,
        operation: &str,
        request_hash: &[u8],
    ) -> Result<(), StorageError> {
        sqlx::query("INSERT INTO idempotency_keys(tenant_id,key,operation,request_hash,expires_at)VALUES($1,$2,$3,$4,clock_timestamp()+interval '24 hours')").bind(tenant.into_uuid()).bind(key).bind(operation).bind(request_hash).execute(&self.pool).await.map_err(map_sqlx)?;
        Ok(())
    }
    async fn idempotency_finish(
        &self,
        tenant: TenantId,
        key: &str,
        operation: &str,
        status: u16,
        body: &str,
    ) -> Result<(), StorageError> {
        sqlx::query("UPDATE idempotency_keys SET response_status=$4,response_body=$5::jsonb WHERE tenant_id=$1 AND key=$2 AND operation=$3").bind(tenant.into_uuid()).bind(key).bind(operation).bind(i32::from(status)).bind(body).execute(&self.pool).await.map_err(map_sqlx)?;
        Ok(())
    }
}

#[async_trait]
impl SmtpRepository for PostgresRepository {
    async fn recover_smtp_ingestions(&self) -> Result<u64, StorageError> {
        let result = sqlx::query("WITH abandoned AS (UPDATE smtp_ingestions SET state='abandoned' WHERE state='receiving' AND expires_at<clock_timestamp() RETURNING id) DELETE FROM smtp_ingestion_chunks c USING abandoned a WHERE c.ingestion_id=a.id")
            .execute(&self.pool).await.map_err(map_sqlx)?;
        Ok(result.rows_affected())
    }

    async fn resolve_local_recipient(
        &self,
        address: &str,
    ) -> Result<Option<LocalRecipient>, StorageError> {
        let row = sqlx::query(
            "SELECT u.tenant_id,m.id AS mailbox_id FROM users u JOIN domains d ON d.id=u.domain_id JOIN mailboxes m ON m.user_id=u.id AND m.tenant_id=u.tenant_id AND m.name='INBOX' WHERE u.local_part || '@' || d.name=$1 AND u.status='active' AND d.status='active'",
        )
        .bind(address)
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx)?;
        row.map(|row| {
            Ok(LocalRecipient {
                address: address.to_owned(),
                tenant_id: TenantId::new(row.try_get("tenant_id").map_err(map_sqlx)?),
                mailbox_id: MailboxId::new(row.try_get("mailbox_id").map_err(map_sqlx)?),
            })
        })
        .transpose()
    }

    async fn begin_smtp_ingestion(&self) -> Result<Uuid, StorageError> {
        let id = Uuid::new_v4();
        sqlx::query("INSERT INTO smtp_ingestions(id,state) VALUES($1,'receiving')")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(map_sqlx)?;
        Ok(id)
    }

    async fn append_smtp_chunk(
        &self,
        ingestion_id: Uuid,
        position: u32,
        bytes: &[u8],
    ) -> Result<(), StorageError> {
        let result = sqlx::query("WITH inserted AS (INSERT INTO smtp_ingestion_chunks(ingestion_id,position,content) SELECT id,$2,$3 FROM smtp_ingestions WHERE id=$1 AND state='receiving' RETURNING octet_length(content) AS size) UPDATE smtp_ingestions SET byte_count=byte_count+(SELECT size FROM inserted) WHERE id=$1 AND EXISTS(SELECT 1 FROM inserted)")
            .bind(ingestion_id).bind(i32::try_from(position).map_err(|_| StorageError::Conflict)?).bind(bytes).execute(&self.pool).await.map_err(map_sqlx)?;
        if result.rows_affected() != 1 {
            return Err(StorageError::NotFound);
        }
        Ok(())
    }

    async fn commit_smtp_ingestion(
        &self,
        ingestion_id: Uuid,
        envelope_sender: &str,
        recipients: &[LocalRecipient],
        received_header: &[u8],
    ) -> Result<StoredMessage, StorageError> {
        if recipients.is_empty() {
            return Err(StorageError::Conflict);
        }
        let mut transaction = self.pool.begin().await.map_err(map_sqlx)?;
        let state: Option<String> =
            sqlx::query_scalar("SELECT state FROM smtp_ingestions WHERE id=$1 FOR UPDATE")
                .bind(ingestion_id)
                .fetch_optional(&mut *transaction)
                .await
                .map_err(map_sqlx)?;
        if state.as_deref() != Some("receiving") {
            return Err(StorageError::Conflict);
        }
        let return_path = format!("Return-Path: <{envelope_sender}>\r\n");
        let prefix = [return_path.as_bytes(), received_header].concat();
        let mut by_tenant: HashMap<TenantId, Vec<&LocalRecipient>> = HashMap::new();
        for recipient in recipients {
            by_tenant
                .entry(recipient.tenant_id)
                .or_default()
                .push(recipient);
        }
        let mut message_ids = Vec::with_capacity(by_tenant.len());
        let mut octets = 0_u64;
        for (tenant_id, tenant_recipients) in by_tenant {
            let message_id = Uuid::new_v4();
            let addresses: Vec<&str> = tenant_recipients
                .iter()
                .map(|recipient| recipient.address.as_str())
                .collect();
            let size: i64 = sqlx::query_scalar("INSERT INTO messages(id,tenant_id,raw_message,envelope_sender,envelope_recipients,received_at,message_size,content_hash,storage_state) SELECT $1,$2,$3::bytea || mail_bytea_concat(content),$4,$5,clock_timestamp(),octet_length($3::bytea || mail_bytea_concat(content)),digest($3::bytea || mail_bytea_concat(content),'sha256'),'committed' FROM smtp_ingestion_chunks WHERE ingestion_id=$6 RETURNING message_size")
                .bind(message_id).bind(tenant_id.into_uuid()).bind(&prefix).bind(envelope_sender).bind(addresses).bind(ingestion_id)
                .fetch_one(&mut *transaction).await.map_err(map_sqlx)?;
            for recipient in tenant_recipients {
                let quota = sqlx::query("UPDATE users u SET used_bytes=used_bytes+$1 WHERE u.tenant_id=$2 AND u.id=(SELECT user_id FROM mailboxes WHERE id=$3 AND tenant_id=$2) AND u.status='active' AND used_bytes+$1<=quota_bytes")
                    .bind(size).bind(tenant_id.into_uuid()).bind(recipient.mailbox_id.into_uuid()).execute(&mut *transaction).await.map_err(map_sqlx)?;
                if quota.rows_affected() != 1 {
                    return Err(StorageError::QuotaExceeded);
                }
                let allocation = sqlx::query("UPDATE mailboxes SET uid_next=uid_next+1,highest_modseq=highest_modseq+1,message_count=message_count+1,unseen_count=unseen_count+1 WHERE id=$1 AND tenant_id=$2 AND uid_next<4294967295 RETURNING uid_next-1 AS uid,highest_modseq")
                    .bind(recipient.mailbox_id.into_uuid()).bind(tenant_id.into_uuid()).fetch_optional(&mut *transaction).await.map_err(map_sqlx)?.ok_or(StorageError::Conflict)?;
                let uid: i64 = allocation.try_get("uid").map_err(map_sqlx)?;
                let modseq: i64 = allocation.try_get("highest_modseq").map_err(map_sqlx)?;
                sqlx::query("INSERT INTO mailbox_messages(mailbox_id,message_id,uid,modseq,internal_date,object_id) VALUES($1,$2,$3,$4,clock_timestamp(),$5)")
                    .bind(recipient.mailbox_id.into_uuid()).bind(message_id).bind(uid).bind(modseq).bind(Uuid::new_v4()).execute(&mut *transaction).await.map_err(map_sqlx)?;
            }
            octets = u64::try_from(size).map_err(|_| StorageError::Conflict)?;
            message_ids.push(message_id);
        }
        sqlx::query("DELETE FROM smtp_ingestion_chunks WHERE ingestion_id=$1")
            .bind(ingestion_id)
            .execute(&mut *transaction)
            .await
            .map_err(map_sqlx)?;
        sqlx::query("UPDATE smtp_ingestions SET state='committed' WHERE id=$1")
            .bind(ingestion_id)
            .execute(&mut *transaction)
            .await
            .map_err(map_sqlx)?;
        transaction.commit().await.map_err(map_sqlx)?;
        Ok(StoredMessage {
            message_ids,
            octets,
        })
    }

    async fn abort_smtp_ingestion(&self, ingestion_id: Uuid) -> Result<(), StorageError> {
        sqlx::query(
            "UPDATE smtp_ingestions SET state='abandoned' WHERE id=$1 AND state='receiving'",
        )
        .bind(ingestion_id)
        .execute(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(())
    }
}

fn mailbox_info(
    tenant: TenantId,
    user: UserId,
    row: &sqlx::postgres::PgRow,
) -> Result<MailboxInfo, StorageError> {
    let uv: i64 = row.try_get("uid_validity").map_err(map_sqlx)?;
    let un: i64 = row.try_get("uid_next").map_err(map_sqlx)?;
    let ms: i64 = row.try_get("highest_modseq").map_err(map_sqlx)?;
    let count: i64 = row.try_get("message_count").map_err(map_sqlx)?;
    let unseen: i64 = row.try_get("unseen_count").map_err(map_sqlx)?;
    Ok(MailboxInfo {
        mailbox: Mailbox {
            id: MailboxId::new(row.try_get("id").map_err(map_sqlx)?),
            tenant_id: tenant,
            user_id: user,
            name: row.try_get("name").map_err(map_sqlx)?,
            uid_validity: u32::try_from(uv).map_err(|_| StorageError::Conflict)?,
            uid_next: u32::try_from(un).map_err(|_| StorageError::Conflict)?,
            highest_modseq: u64::try_from(ms).map_err(|_| StorageError::Conflict)?,
        },
        version: row.try_get("version").map_err(map_sqlx)?,
        message_count: u64::try_from(count).map_err(|_| StorageError::Conflict)?,
        unseen_count: u64::try_from(unseen).map_err(|_| StorageError::Conflict)?,
    })
}

#[allow(dead_code)]
fn _system_time_is_send(_: SystemTime) {}
