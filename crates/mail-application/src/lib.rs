#![forbid(unsafe_code)]

use mail_domain::{Alias, Domain, Mailbox, Tenant, TenantId, User};
use mail_storage::{
    AdminRepository, ApiTokenInfo, ApplicationPasswordInfo, AuditRecord, IdempotencyRecord,
    MailboxInfo, Versioned,
};
use mail_storage::{ApiCredential, AuditEvent, MailRepository, StorageError};
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum ApplicationError {
    #[error("operation conflicts with existing state")]
    Conflict,
    #[error("resource not found")]
    NotFound,
    #[error("quota exceeded")]
    QuotaExceeded,
    #[error("service unavailable")]
    Unavailable,
    #[error("authentication required")]
    Unauthorized,
    #[error("operation is not permitted")]
    Forbidden,
}

impl From<StorageError> for ApplicationError {
    fn from(value: StorageError) -> Self {
        match value {
            StorageError::Conflict => Self::Conflict,
            StorageError::NotFound => Self::NotFound,
            StorageError::QuotaExceeded => Self::QuotaExceeded,
            StorageError::CounterExhausted | StorageError::Unavailable(_) => Self::Unavailable,
        }
    }
}

pub struct AdministrationService<R> {
    repository: R,
}

impl<R: MailRepository> AdministrationService<R> {
    #[must_use]
    pub const fn new(repository: R) -> Self {
        Self { repository }
    }

    pub async fn create_tenant(&self, tenant: &Tenant) -> Result<(), ApplicationError> {
        self.repository
            .create_tenant(tenant)
            .await
            .map_err(Into::into)
    }

    pub async fn create_domain(&self, domain: &Domain) -> Result<(), ApplicationError> {
        self.repository
            .create_domain(domain)
            .await
            .map_err(Into::into)
    }

    pub async fn create_user(&self, user: &User) -> Result<(), ApplicationError> {
        self.repository.create_user(user).await.map_err(Into::into)
    }

    pub async fn create_user_with_password(
        &self,
        user: &User,
        password_hash: &str,
    ) -> Result<(), ApplicationError> {
        self.repository
            .create_user_with_password(user, password_hash)
            .await
            .map_err(Into::into)
    }

    pub async fn create_alias(&self, alias: &Alias) -> Result<(), ApplicationError> {
        self.repository
            .create_alias(alias)
            .await
            .map_err(Into::into)
    }

    pub async fn create_mailbox(&self, mailbox: &Mailbox) -> Result<(), ApplicationError> {
        self.repository
            .create_mailbox(mailbox)
            .await
            .map_err(Into::into)
    }

    pub async fn authenticate(&self, hash: &[u8]) -> Result<ApiCredential, ApplicationError> {
        self.repository
            .authenticate_api_token(hash)
            .await
            .map_err(|error| match error {
                StorageError::NotFound => ApplicationError::Unauthorized,
                other => other.into(),
            })
    }

    pub async fn audit(&self, event: &AuditEvent) -> Result<(), ApplicationError> {
        self.repository.write_audit(event).await.map_err(Into::into)
    }

    pub async fn list_tenants(
        &self,
        principal: &ApiCredential,
        limit: u16,
        offset: u32,
    ) -> Result<Vec<Tenant>, ApplicationError> {
        authorize(principal, "tenants:read", principal.tenant_id)?;
        self.repository
            .list_tenants(principal.tenant_id, limit.min(201), offset)
            .await
            .map_err(Into::into)
    }

    pub async fn list_domains(
        &self,
        principal: &ApiCredential,
        tenant_id: TenantId,
        limit: u16,
        offset: u32,
    ) -> Result<Vec<Domain>, ApplicationError> {
        authorize(principal, "domains:read", Some(tenant_id))?;
        self.repository
            .list_domains(tenant_id, limit.min(201), offset)
            .await
            .map_err(Into::into)
    }

    pub async fn list_users(
        &self,
        principal: &ApiCredential,
        tenant_id: TenantId,
        limit: u16,
        offset: u32,
    ) -> Result<Vec<User>, ApplicationError> {
        authorize(principal, "users:read", Some(tenant_id))?;
        self.repository
            .list_users(tenant_id, limit.min(201), offset)
            .await
            .map_err(Into::into)
    }

    pub async fn list_aliases(
        &self,
        principal: &ApiCredential,
        tenant_id: TenantId,
        limit: u16,
        offset: u32,
    ) -> Result<Vec<Alias>, ApplicationError> {
        authorize(principal, "aliases:read", Some(tenant_id))?;
        self.repository
            .list_aliases(tenant_id, limit.min(201), offset)
            .await
            .map_err(Into::into)
    }
}

pub fn authorize(
    principal: &ApiCredential,
    scope: &str,
    tenant_id: Option<TenantId>,
) -> Result<(), ApplicationError> {
    if !principal.scopes.iter().any(|candidate| candidate == scope) {
        return Err(ApplicationError::Forbidden);
    }
    if let (Some(allowed), Some(requested)) = (principal.tenant_id, tenant_id)
        && allowed != requested
    {
        return Err(ApplicationError::NotFound);
    }
    Ok(())
}

pub fn validate_alias_graph(candidate: &Alias, existing: &[Alias]) -> Result<(), ApplicationError> {
    use std::collections::{HashMap, HashSet};
    let mut graph: HashMap<&str, Vec<&str>> = existing
        .iter()
        .map(|a| {
            (
                a.source.as_str(),
                a.targets.iter().map(String::as_str).collect(),
            )
        })
        .collect();
    graph.insert(
        candidate.source.as_str(),
        candidate.targets.iter().map(String::as_str).collect(),
    );
    let mut stack = vec![candidate.source.as_str()];
    let mut seen = HashSet::new();
    while let Some(node) = stack.pop() {
        if !seen.insert(node) {
            return Err(ApplicationError::Conflict);
        }
        if seen.len() > 100 {
            return Err(ApplicationError::Conflict);
        }
        if let Some(next) = graph.get(node) {
            stack.extend(
                next.iter()
                    .copied()
                    .filter(|target| graph.contains_key(target)),
            );
        }
    }
    Ok(())
}

#[must_use]
pub fn audit_event(
    principal: &ApiCredential,
    request_id: Uuid,
    action: &str,
    resource_type: &str,
    resource_id: Option<Uuid>,
) -> AuditEvent {
    AuditEvent {
        tenant_id: principal.tenant_id,
        actor_id: principal.token_id,
        request_id,
        action: action.into(),
        resource_type: resource_type.into(),
        resource_id,
    }
}

impl<R: AdminRepository> AdministrationService<R> {
    pub async fn get_tenant(&self, id: TenantId) -> Result<Versioned<Tenant>, ApplicationError> {
        self.repository.get_tenant(id).await.map_err(Into::into)
    }
    pub async fn update_tenant(
        &self,
        value: &Tenant,
        version: i64,
    ) -> Result<i64, ApplicationError> {
        self.repository
            .update_tenant(value, version)
            .await
            .map_err(Into::into)
    }
    pub async fn get_domain(
        &self,
        tenant: TenantId,
        id: mail_domain::DomainId,
    ) -> Result<Versioned<Domain>, ApplicationError> {
        self.repository
            .get_domain(tenant, id)
            .await
            .map_err(Into::into)
    }
    pub async fn update_domain(
        &self,
        value: &Domain,
        version: i64,
    ) -> Result<i64, ApplicationError> {
        self.repository
            .update_domain(value, version)
            .await
            .map_err(Into::into)
    }
    pub async fn get_user(
        &self,
        tenant: TenantId,
        id: mail_domain::UserId,
    ) -> Result<Versioned<User>, ApplicationError> {
        self.repository
            .get_user(tenant, id)
            .await
            .map_err(Into::into)
    }
    pub async fn update_user(&self, value: &User, version: i64) -> Result<i64, ApplicationError> {
        self.repository
            .update_user(value, version)
            .await
            .map_err(Into::into)
    }
    pub async fn set_user_password(
        &self,
        tenant: TenantId,
        user: mail_domain::UserId,
        hash: &str,
    ) -> Result<(), ApplicationError> {
        self.repository
            .set_user_password(tenant, user, hash)
            .await
            .map_err(Into::into)
    }
    pub async fn unlock_user(
        &self,
        tenant: TenantId,
        user: mail_domain::UserId,
    ) -> Result<(), ApplicationError> {
        self.repository
            .unlock_user(tenant, user)
            .await
            .map_err(Into::into)
    }
    pub async fn get_alias(
        &self,
        tenant: TenantId,
        id: mail_domain::AliasId,
    ) -> Result<Versioned<Alias>, ApplicationError> {
        self.repository
            .get_alias(tenant, id)
            .await
            .map_err(Into::into)
    }
    pub async fn update_alias(&self, value: &Alias, version: i64) -> Result<i64, ApplicationError> {
        self.repository
            .update_alias(value, version)
            .await
            .map_err(Into::into)
    }
    pub async fn delete_alias(
        &self,
        tenant: TenantId,
        id: mail_domain::AliasId,
        version: i64,
    ) -> Result<(), ApplicationError> {
        self.repository
            .delete_alias(tenant, id, version)
            .await
            .map_err(Into::into)
    }
    pub async fn list_mailboxes(
        &self,
        tenant: TenantId,
        user: mail_domain::UserId,
        limit: u16,
    ) -> Result<Vec<MailboxInfo>, ApplicationError> {
        self.repository
            .list_mailboxes(tenant, user, limit.min(200))
            .await
            .map_err(Into::into)
    }
    pub async fn get_mailbox(
        &self,
        tenant: TenantId,
        user: mail_domain::UserId,
        id: mail_domain::MailboxId,
    ) -> Result<MailboxInfo, ApplicationError> {
        self.repository
            .get_mailbox(tenant, user, id)
            .await
            .map_err(Into::into)
    }
    pub async fn update_mailbox_name(
        &self,
        tenant: TenantId,
        user: mail_domain::UserId,
        id: mail_domain::MailboxId,
        name: &str,
        version: i64,
    ) -> Result<i64, ApplicationError> {
        self.repository
            .update_mailbox_name(tenant, user, id, name, version)
            .await
            .map_err(Into::into)
    }
    pub async fn delete_mailbox(
        &self,
        tenant: TenantId,
        user: mail_domain::UserId,
        id: mail_domain::MailboxId,
        version: i64,
    ) -> Result<(), ApplicationError> {
        self.repository
            .delete_mailbox(tenant, user, id, version)
            .await
            .map_err(Into::into)
    }
    pub async fn create_application_password(
        &self,
        tenant: TenantId,
        user: mail_domain::UserId,
        id: Uuid,
        name: &str,
        hash: &str,
    ) -> Result<ApplicationPasswordInfo, ApplicationError> {
        self.repository
            .create_application_password(tenant, user, id, name, hash)
            .await
            .map_err(Into::into)
    }
    pub async fn list_application_passwords(
        &self,
        tenant: TenantId,
        user: mail_domain::UserId,
    ) -> Result<Vec<ApplicationPasswordInfo>, ApplicationError> {
        self.repository
            .list_application_passwords(tenant, user)
            .await
            .map_err(Into::into)
    }
    pub async fn revoke_application_password(
        &self,
        tenant: TenantId,
        user: mail_domain::UserId,
        id: Uuid,
    ) -> Result<(), ApplicationError> {
        self.repository
            .revoke_application_password(tenant, user, id)
            .await
            .map_err(Into::into)
    }
    pub async fn create_api_token(
        &self,
        info: &ApiTokenInfo,
        hash: &[u8],
        creator: Uuid,
        expires_at: Option<&str>,
        networks: &[String],
    ) -> Result<(), ApplicationError> {
        self.repository
            .create_api_token(info, hash, creator, expires_at, networks)
            .await
            .map_err(Into::into)
    }
    pub async fn list_api_tokens(
        &self,
        tenant: Option<TenantId>,
        limit: u16,
    ) -> Result<Vec<ApiTokenInfo>, ApplicationError> {
        self.repository
            .list_api_tokens(tenant, limit.min(200))
            .await
            .map_err(Into::into)
    }
    pub async fn revoke_api_token(
        &self,
        tenant: Option<TenantId>,
        id: Uuid,
    ) -> Result<(), ApplicationError> {
        self.repository
            .revoke_api_token(tenant, id)
            .await
            .map_err(Into::into)
    }
    pub async fn list_audit(
        &self,
        tenant: Option<TenantId>,
        limit: u16,
    ) -> Result<Vec<AuditRecord>, ApplicationError> {
        self.repository
            .list_audit(tenant, limit.min(200))
            .await
            .map_err(Into::into)
    }
    pub async fn idempotency_get(
        &self,
        tenant: TenantId,
        key: &str,
        operation: &str,
    ) -> Result<Option<IdempotencyRecord>, ApplicationError> {
        self.repository
            .idempotency_get(tenant, key, operation)
            .await
            .map_err(Into::into)
    }
    pub async fn idempotency_begin(
        &self,
        tenant: TenantId,
        key: &str,
        operation: &str,
        hash: &[u8],
    ) -> Result<(), ApplicationError> {
        self.repository
            .idempotency_begin(tenant, key, operation, hash)
            .await
            .map_err(Into::into)
    }
    pub async fn idempotency_finish(
        &self,
        tenant: TenantId,
        key: &str,
        operation: &str,
        status: u16,
        body: &str,
    ) -> Result<(), ApplicationError> {
        self.repository
            .idempotency_finish(tenant, key, operation, status, body)
            .await
            .map_err(Into::into)
    }
}
