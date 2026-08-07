#![forbid(unsafe_code)]

use async_trait::async_trait;
use mail_domain::{Alias, Domain, Mailbox, MailboxId, QueueId, Tenant, TenantId, User};
use mail_storage::{
    AdminRepository, ApiCredential, AuditEvent, IdempotencyRecord, MailRepository,
    PasswordCredential, QueueLease, StorageError, Versioned,
};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::Duration,
};
use uuid::Uuid;

#[derive(Default)]
struct State {
    tenants: HashMap<TenantId, (Tenant, u64, u64)>,
    domains: HashMap<mail_domain::DomainId, Domain>,
    users: HashMap<mail_domain::UserId, User>,
    aliases: HashMap<mail_domain::AliasId, Alias>,
    mailboxes: HashMap<MailboxId, (u32, u64)>,
    credentials: HashMap<Vec<u8>, ApiCredential>,
    password_hashes: HashMap<mail_domain::UserId, String>,
    audits: Vec<AuditEvent>,
    idempotency: HashMap<(TenantId, String, String), IdempotencyRecord>,
}

#[async_trait]
impl AdminRepository for InMemoryRepository {
    async fn get_tenant(&self, id: TenantId) -> Result<Versioned<Tenant>, StorageError> {
        let state = self
            .state
            .lock()
            .map_err(|e| StorageError::Unavailable(e.to_string()))?;
        let (tenant, _, _) = state.tenants.get(&id).ok_or(StorageError::NotFound)?;
        Ok(Versioned {
            value: tenant.clone(),
            version: 1,
        })
    }
    async fn idempotency_get(
        &self,
        tenant: TenantId,
        key: &str,
        operation: &str,
    ) -> Result<Option<IdempotencyRecord>, StorageError> {
        Ok(self
            .state
            .lock()
            .map_err(|e| StorageError::Unavailable(e.to_string()))?
            .idempotency
            .get(&(tenant, key.into(), operation.into()))
            .cloned())
    }
    async fn idempotency_begin(
        &self,
        tenant: TenantId,
        key: &str,
        operation: &str,
        hash: &[u8],
    ) -> Result<(), StorageError> {
        let old = self
            .state
            .lock()
            .map_err(|e| StorageError::Unavailable(e.to_string()))?
            .idempotency
            .insert(
                (tenant, key.into(), operation.into()),
                IdempotencyRecord {
                    request_hash: hash.into(),
                    response_status: None,
                    response_body: None,
                },
            );
        if old.is_some() {
            Err(StorageError::Conflict)
        } else {
            Ok(())
        }
    }
    async fn idempotency_finish(
        &self,
        tenant: TenantId,
        key: &str,
        operation: &str,
        status: u16,
        body: &str,
    ) -> Result<(), StorageError> {
        let mut state = self
            .state
            .lock()
            .map_err(|e| StorageError::Unavailable(e.to_string()))?;
        let record = state
            .idempotency
            .get_mut(&(tenant, key.into(), operation.into()))
            .ok_or(StorageError::NotFound)?;
        record.response_status = Some(status);
        record.response_body = Some(body.into());
        Ok(())
    }
}

#[derive(Clone, Default)]
pub struct InMemoryRepository {
    state: Arc<Mutex<State>>,
}

impl InMemoryRepository {
    pub fn add_api_credential(
        &self,
        hash: Vec<u8>,
        credential: ApiCredential,
    ) -> Result<(), StorageError> {
        self.state
            .lock()
            .map_err(|error| StorageError::Unavailable(error.to_string()))?
            .credentials
            .insert(hash, credential);
        Ok(())
    }

    pub fn add_mailbox(
        &self,
        id: MailboxId,
        uid_next: u32,
        highest_modseq: u64,
    ) -> Result<(), StorageError> {
        let mut state = self
            .state
            .lock()
            .map_err(|error| StorageError::Unavailable(error.to_string()))?;
        state.mailboxes.insert(id, (uid_next, highest_modseq));
        Ok(())
    }

    pub fn set_tenant_quota(&self, id: TenantId, quota: u64) -> Result<(), StorageError> {
        let mut state = self
            .state
            .lock()
            .map_err(|error| StorageError::Unavailable(error.to_string()))?;
        let entry = state.tenants.get_mut(&id).ok_or(StorageError::NotFound)?;
        entry.1 = quota;
        Ok(())
    }
}

#[async_trait]
impl MailRepository for InMemoryRepository {
    async fn authenticate_api_token(
        &self,
        token_hash: &[u8],
    ) -> Result<ApiCredential, StorageError> {
        self.state
            .lock()
            .map_err(|error| StorageError::Unavailable(error.to_string()))?
            .credentials
            .get(token_hash)
            .cloned()
            .ok_or(StorageError::NotFound)
    }

    async fn write_audit(&self, event: &AuditEvent) -> Result<(), StorageError> {
        self.state
            .lock()
            .map_err(|error| StorageError::Unavailable(error.to_string()))?
            .audits
            .push(event.clone());
        Ok(())
    }

    async fn create_tenant(&self, tenant: &Tenant) -> Result<(), StorageError> {
        let mut state = self
            .state
            .lock()
            .map_err(|error| StorageError::Unavailable(error.to_string()))?;
        if state
            .tenants
            .insert(tenant.id, (tenant.clone(), 0, 0))
            .is_some()
        {
            return Err(StorageError::Conflict);
        }
        Ok(())
    }

    async fn list_tenants(
        &self,
        tenant_id: Option<TenantId>,
        limit: u16,
        offset: u32,
    ) -> Result<Vec<Tenant>, StorageError> {
        let state = self
            .state
            .lock()
            .map_err(|error| StorageError::Unavailable(error.to_string()))?;
        Ok(state
            .tenants
            .values()
            .filter(|(tenant, _, _)| tenant_id.is_none_or(|id| tenant.id == id))
            .skip(offset as usize)
            .take(usize::from(limit))
            .map(|(tenant, _, _)| tenant.clone())
            .collect())
    }

    async fn create_domain(&self, domain: &Domain) -> Result<(), StorageError> {
        let mut state = self
            .state
            .lock()
            .map_err(|error| StorageError::Unavailable(error.to_string()))?;
        if !state.tenants.contains_key(&domain.tenant_id) {
            return Err(StorageError::Conflict);
        }
        if state
            .domains
            .values()
            .any(|stored| stored.tenant_id == domain.tenant_id && stored.name == domain.name)
            || state.domains.insert(domain.id, domain.clone()).is_some()
        {
            return Err(StorageError::Conflict);
        }
        Ok(())
    }

    async fn list_domains(
        &self,
        tenant_id: TenantId,
        limit: u16,
        offset: u32,
    ) -> Result<Vec<Domain>, StorageError> {
        let state = self
            .state
            .lock()
            .map_err(|error| StorageError::Unavailable(error.to_string()))?;
        Ok(state
            .domains
            .values()
            .filter(|domain| domain.tenant_id == tenant_id)
            .skip(offset as usize)
            .take(usize::from(limit))
            .cloned()
            .collect())
    }

    async fn create_user(&self, user: &User) -> Result<(), StorageError> {
        let mut state = self
            .state
            .lock()
            .map_err(|error| StorageError::Unavailable(error.to_string()))?;
        let domain_ok = state
            .domains
            .get(&user.domain_id)
            .is_some_and(|domain| domain.tenant_id == user.tenant_id);
        if !domain_ok
            || state.users.values().any(|stored| {
                stored.tenant_id == user.tenant_id
                    && stored.domain_id == user.domain_id
                    && stored.local_part == user.local_part
            })
            || state.users.insert(user.id, user.clone()).is_some()
        {
            return Err(StorageError::Conflict);
        }
        Ok(())
    }

    async fn create_user_with_password(
        &self,
        user: &User,
        credential: &PasswordCredential,
    ) -> Result<(), StorageError> {
        self.create_user(user).await?;
        self.state
            .lock()
            .map_err(|error| StorageError::Unavailable(error.to_string()))?
            .password_hashes
            .insert(user.id, credential.argon2_hash.clone());
        Ok(())
    }

    async fn list_users(
        &self,
        tenant_id: TenantId,
        limit: u16,
        offset: u32,
    ) -> Result<Vec<User>, StorageError> {
        let state = self
            .state
            .lock()
            .map_err(|error| StorageError::Unavailable(error.to_string()))?;
        Ok(state
            .users
            .values()
            .filter(|user| user.tenant_id == tenant_id)
            .skip(offset as usize)
            .take(usize::from(limit))
            .cloned()
            .collect())
    }

    async fn create_alias(&self, alias: &Alias) -> Result<(), StorageError> {
        let mut state = self
            .state
            .lock()
            .map_err(|error| StorageError::Unavailable(error.to_string()))?;
        if !state.tenants.contains_key(&alias.tenant_id)
            || state
                .aliases
                .values()
                .any(|stored| stored.tenant_id == alias.tenant_id && stored.source == alias.source)
            || state.aliases.insert(alias.id, alias.clone()).is_some()
        {
            return Err(StorageError::Conflict);
        }
        Ok(())
    }

    async fn list_aliases(
        &self,
        tenant_id: TenantId,
        limit: u16,
        offset: u32,
    ) -> Result<Vec<Alias>, StorageError> {
        let state = self
            .state
            .lock()
            .map_err(|error| StorageError::Unavailable(error.to_string()))?;
        Ok(state
            .aliases
            .values()
            .filter(|alias| alias.tenant_id == tenant_id)
            .skip(offset as usize)
            .take(usize::from(limit))
            .cloned()
            .collect())
    }

    async fn create_mailbox(&self, mailbox: &Mailbox) -> Result<(), StorageError> {
        let mut state = self
            .state
            .lock()
            .map_err(|error| StorageError::Unavailable(error.to_string()))?;
        if !state
            .users
            .get(&mailbox.user_id)
            .is_some_and(|user| user.tenant_id == mailbox.tenant_id)
            || state
                .mailboxes
                .insert(mailbox.id, (mailbox.uid_next, mailbox.highest_modseq))
                .is_some()
        {
            return Err(StorageError::Conflict);
        }
        Ok(())
    }

    async fn consume_quota(&self, tenant_id: TenantId, bytes: u64) -> Result<(), StorageError> {
        let mut state = self
            .state
            .lock()
            .map_err(|error| StorageError::Unavailable(error.to_string()))?;
        let (_, quota, used) = state
            .tenants
            .get_mut(&tenant_id)
            .ok_or(StorageError::NotFound)?;
        let next = used.checked_add(bytes).ok_or(StorageError::QuotaExceeded)?;
        if next > *quota {
            return Err(StorageError::QuotaExceeded);
        }
        *used = next;
        Ok(())
    }

    async fn lease_queue(
        &self,
        _worker: Uuid,
        _limit: u32,
        _duration: Duration,
    ) -> Result<Vec<QueueLease>, StorageError> {
        let _ = QueueId::new(Uuid::nil());
        Ok(Vec::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mail_domain::EntityStatus;

    #[tokio::test]
    async fn uid_modseq_and_quota_are_monotonic_and_bounded() -> Result<(), StorageError> {
        let repository = InMemoryRepository::default();
        let tenant_id = TenantId::new(Uuid::new_v4());
        repository
            .create_tenant(&Tenant {
                id: tenant_id,
                name: "test".into(),
                status: EntityStatus::Active,
            })
            .await?;
        repository.set_tenant_quota(tenant_id, 10)?;
        repository.consume_quota(tenant_id, 7).await?;
        assert!(matches!(
            repository.consume_quota(tenant_id, 4).await,
            Err(StorageError::QuotaExceeded)
        ));

        Ok(())
    }
}
