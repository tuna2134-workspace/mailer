#![forbid(unsafe_code)]

use async_trait::async_trait;
use mail_domain::{Alias, Domain, Mailbox, MailboxId, QueueId, Tenant, TenantId, User};
use mail_mailbox::{FlagSet, StoreMode};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::time::{Duration, SystemTime};
use thiserror::Error;
use uuid::Uuid;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Versioned<T> {
    pub value: T,
    pub version: i64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ApplicationPasswordInfo {
    pub id: Uuid,
    pub display_name: String,
    pub revoked: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ApiTokenInfo {
    pub id: Uuid,
    pub tenant_id: Option<TenantId>,
    pub display_name: String,
    pub scopes: Vec<String>,
    pub revoked: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MailboxInfo {
    pub mailbox: Mailbox,
    pub version: i64,
    pub message_count: u64,
    pub unseen_count: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AuditRecord {
    pub id: i64,
    pub action: String,
    pub resource_type: String,
    pub resource_id: Option<Uuid>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IdempotencyRecord {
    pub request_hash: Vec<u8>,
    pub response_status: Option<u16>,
    pub response_body: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApiCredential {
    pub token_id: Uuid,
    pub tenant_id: Option<TenantId>,
    pub scopes: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditEvent {
    pub tenant_id: Option<TenantId>,
    pub actor_id: Uuid,
    pub request_id: Uuid,
    pub action: String,
    pub resource_type: String,
    pub resource_id: Option<Uuid>,
}

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("resource not found")]
    NotFound,
    #[error("resource conflict")]
    Conflict,
    #[error("quota exceeded")]
    QuotaExceeded,
    #[error("counter exhausted")]
    CounterExhausted,
    #[error("storage unavailable: {0}")]
    Unavailable(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MailboxMessageState {
    pub message_id: Uuid,
    pub uid: u32,
    pub modseq: u64,
    pub flags: FlagSet,
    pub internal_date: SystemTime,
    pub saved_date: Option<SystemTime>,
    pub object_id: Uuid,
    pub expunged: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImapMailbox {
    pub id: MailboxId,
    pub name: String,
    pub uid_validity: u32,
    pub uid_next: u32,
    pub highest_modseq: u64,
    pub message_count: u64,
    pub unseen_count: u64,
    pub subscribed: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImapMessage {
    pub sequence: u32,
    pub uid: u32,
    pub modseq: u64,
    pub flags: Vec<String>,
    pub internal_date: SystemTime,
    pub raw: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImapChange {
    pub sequence: Option<u32>,
    pub uid: u32,
    pub modseq: u64,
    pub flags: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImapChanges {
    pub highest_modseq: u64,
    pub message_count: u64,
    pub changed: Vec<ImapChange>,
    pub vanished: Vec<u32>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImapAppend<'a> {
    pub raw: &'a [u8],
    pub flags: &'a FlagSet,
    pub internal_date: SystemTime,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoreFlags {
    pub mode: StoreMode,
    pub values: FlagSet,
    pub unchanged_since: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConditionalStoreResult {
    pub updated: Vec<MailboxMessageState>,
    pub modified: Vec<u32>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QueueLease {
    pub queue_id: QueueId,
    pub lease_token: Uuid,
    pub message_id: Uuid,
    pub recipient: String,
    pub destination_domain: String,
    pub envelope_sender: String,
    pub require_tls: bool,
    pub smtp_utf8: bool,
    pub dsn_ret: Option<String>,
    pub envelope_id: Option<String>,
    pub dsn_notify: Option<String>,
    pub original_recipient: Option<String>,
    pub deliver_by_at: Option<SystemTime>,
    pub deliver_by_mode: Option<String>,
    pub deliver_by_trace: bool,
    pub attempt_count: u32,
    pub expires_at: SystemTime,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DeliveryOutcome {
    Delivered,
    Deferred {
        next_attempt_at: SystemTime,
        enhanced_status_code: Option<String>,
        diagnostic: String,
    },
    Failed {
        enhanced_status_code: Option<String>,
        diagnostic: String,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalRecipient {
    pub address: String,
    pub tenant_id: TenantId,
    pub mailbox_id: MailboxId,
    pub dsn_notify: Option<String>,
    pub original_recipient: Option<String>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SmtpMailOptions {
    pub smtp_utf8: bool,
    pub require_tls: bool,
    pub dsn_ret: Option<String>,
    pub envelope_id: Option<String>,
    pub deliver_by_at: Option<SystemTime>,
    pub deliver_by_mode: Option<String>,
    pub deliver_by_trace: bool,
    pub release_at: Option<SystemTime>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubmissionRecipient {
    pub address: String,
    pub dsn_notify: Option<String>,
    pub original_recipient: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredMessage {
    pub message_ids: Vec<Uuid>,
    pub octets: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SmtpAuthAccount {
    pub user_id: Uuid,
    pub password_hashes: Vec<String>,
    pub scram: Option<SmtpScramCredential>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SmtpScramCredential {
    pub salt: Vec<u8>,
    pub iterations: u32,
    pub stored_key: Vec<u8>,
    pub server_key: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PasswordCredential {
    pub argon2_hash: String,
    pub scram: Option<SmtpScramCredential>,
}

impl PasswordCredential {
    #[must_use]
    pub fn argon2_only(hash: impl Into<String>) -> Self {
        Self {
            argon2_hash: hash.into(),
            scram: None,
        }
    }
}

#[async_trait]
pub trait MailRepository: Send + Sync {
    async fn authenticate_api_token(
        &self,
        token_hash: &[u8],
    ) -> Result<ApiCredential, StorageError>;
    async fn write_audit(&self, event: &AuditEvent) -> Result<(), StorageError>;
    async fn create_tenant(&self, tenant: &Tenant) -> Result<(), StorageError>;
    async fn list_tenants(
        &self,
        tenant_id: Option<TenantId>,
        limit: u16,
        offset: u32,
    ) -> Result<Vec<Tenant>, StorageError>;
    async fn create_domain(&self, domain: &Domain) -> Result<(), StorageError>;
    async fn list_domains(
        &self,
        tenant_id: TenantId,
        limit: u16,
        offset: u32,
    ) -> Result<Vec<Domain>, StorageError>;
    async fn create_user(&self, user: &User) -> Result<(), StorageError>;
    async fn create_user_with_password(
        &self,
        user: &User,
        credential: &PasswordCredential,
    ) -> Result<(), StorageError>;
    async fn list_users(
        &self,
        tenant_id: TenantId,
        limit: u16,
        offset: u32,
    ) -> Result<Vec<User>, StorageError>;
    async fn create_alias(&self, alias: &Alias) -> Result<(), StorageError>;
    async fn list_aliases(
        &self,
        tenant_id: TenantId,
        limit: u16,
        offset: u32,
    ) -> Result<Vec<Alias>, StorageError>;
    async fn create_mailbox(&self, mailbox: &Mailbox) -> Result<(), StorageError>;
    async fn consume_quota(&self, tenant_id: TenantId, bytes: u64) -> Result<(), StorageError>;
    async fn lease_queue(
        &self,
        worker: Uuid,
        limit: u32,
        duration: Duration,
    ) -> Result<Vec<QueueLease>, StorageError>;

    async fn read_message_chunk(
        &self,
        _message_id: Uuid,
        _offset: u64,
        _limit: u32,
    ) -> Result<Vec<u8>, StorageError> {
        Err(StorageError::Unavailable(
            "message streaming is unsupported".into(),
        ))
    }

    async fn finish_delivery(
        &self,
        _queue_id: QueueId,
        _lease_token: Uuid,
        _outcome: &DeliveryOutcome,
    ) -> Result<(), StorageError> {
        Err(StorageError::Unavailable(
            "delivery completion is unsupported".into(),
        ))
    }
}

#[async_trait]
pub trait AdminRepository: MailRepository {
    async fn get_tenant(&self, _id: TenantId) -> Result<Versioned<Tenant>, StorageError> {
        Err(StorageError::NotFound)
    }
    async fn update_tenant(&self, _tenant: &Tenant, _expected: i64) -> Result<i64, StorageError> {
        Err(StorageError::NotFound)
    }
    async fn get_domain(
        &self,
        _tenant: TenantId,
        _id: mail_domain::DomainId,
    ) -> Result<Versioned<Domain>, StorageError> {
        Err(StorageError::NotFound)
    }
    async fn update_domain(&self, _domain: &Domain, _expected: i64) -> Result<i64, StorageError> {
        Err(StorageError::NotFound)
    }
    async fn get_user(
        &self,
        _tenant: TenantId,
        _id: mail_domain::UserId,
    ) -> Result<Versioned<User>, StorageError> {
        Err(StorageError::NotFound)
    }
    async fn update_user(&self, _user: &User, _expected: i64) -> Result<i64, StorageError> {
        Err(StorageError::NotFound)
    }
    async fn set_user_password(
        &self,
        _tenant: TenantId,
        _user: mail_domain::UserId,
        _credential: &PasswordCredential,
    ) -> Result<(), StorageError> {
        Err(StorageError::NotFound)
    }
    async fn unlock_user(
        &self,
        _tenant: TenantId,
        _user: mail_domain::UserId,
    ) -> Result<(), StorageError> {
        Err(StorageError::NotFound)
    }
    async fn get_alias(
        &self,
        _tenant: TenantId,
        _id: mail_domain::AliasId,
    ) -> Result<Versioned<Alias>, StorageError> {
        Err(StorageError::NotFound)
    }
    async fn update_alias(&self, _alias: &Alias, _expected: i64) -> Result<i64, StorageError> {
        Err(StorageError::NotFound)
    }
    async fn delete_alias(
        &self,
        _tenant: TenantId,
        _id: mail_domain::AliasId,
        _expected: i64,
    ) -> Result<(), StorageError> {
        Err(StorageError::NotFound)
    }
    async fn list_mailboxes(
        &self,
        _tenant: TenantId,
        _user: mail_domain::UserId,
        _limit: u16,
    ) -> Result<Vec<MailboxInfo>, StorageError> {
        Ok(Vec::new())
    }
    async fn get_mailbox(
        &self,
        _tenant: TenantId,
        _user: mail_domain::UserId,
        _id: MailboxId,
    ) -> Result<MailboxInfo, StorageError> {
        Err(StorageError::NotFound)
    }
    async fn update_mailbox_name(
        &self,
        _tenant: TenantId,
        _user: mail_domain::UserId,
        _id: MailboxId,
        _name: &str,
        _expected: i64,
    ) -> Result<i64, StorageError> {
        Err(StorageError::NotFound)
    }
    async fn delete_mailbox(
        &self,
        _tenant: TenantId,
        _user: mail_domain::UserId,
        _id: MailboxId,
        _expected: i64,
    ) -> Result<(), StorageError> {
        Err(StorageError::NotFound)
    }
    async fn create_application_password(
        &self,
        _tenant: TenantId,
        _user: mail_domain::UserId,
        _id: Uuid,
        _name: &str,
        _credential: &PasswordCredential,
    ) -> Result<ApplicationPasswordInfo, StorageError> {
        Err(StorageError::NotFound)
    }
    async fn list_application_passwords(
        &self,
        _tenant: TenantId,
        _user: mail_domain::UserId,
    ) -> Result<Vec<ApplicationPasswordInfo>, StorageError> {
        Ok(Vec::new())
    }
    async fn revoke_application_password(
        &self,
        _tenant: TenantId,
        _user: mail_domain::UserId,
        _id: Uuid,
    ) -> Result<(), StorageError> {
        Err(StorageError::NotFound)
    }
    async fn create_api_token(
        &self,
        _info: &ApiTokenInfo,
        _hash: &[u8],
        _creator: Uuid,
        _expires_at: Option<&str>,
        _networks: &[String],
    ) -> Result<(), StorageError> {
        Err(StorageError::NotFound)
    }
    async fn list_api_tokens(
        &self,
        _tenant: Option<TenantId>,
        _limit: u16,
    ) -> Result<Vec<ApiTokenInfo>, StorageError> {
        Ok(Vec::new())
    }
    async fn revoke_api_token(
        &self,
        _tenant: Option<TenantId>,
        _id: Uuid,
    ) -> Result<(), StorageError> {
        Err(StorageError::NotFound)
    }
    async fn list_audit(
        &self,
        _tenant: Option<TenantId>,
        _limit: u16,
    ) -> Result<Vec<AuditRecord>, StorageError> {
        Ok(Vec::new())
    }
    async fn idempotency_get(
        &self,
        _tenant: TenantId,
        _key: &str,
        _operation: &str,
    ) -> Result<Option<IdempotencyRecord>, StorageError> {
        Ok(None)
    }
    async fn idempotency_begin(
        &self,
        _tenant: TenantId,
        _key: &str,
        _operation: &str,
        _request_hash: &[u8],
    ) -> Result<(), StorageError> {
        Ok(())
    }
    async fn idempotency_finish(
        &self,
        _tenant: TenantId,
        _key: &str,
        _operation: &str,
        _status: u16,
        _body: &str,
    ) -> Result<(), StorageError> {
        Ok(())
    }
}

#[async_trait]
pub trait SmtpRepository: Send + Sync {
    async fn recover_smtp_ingestions(&self) -> Result<u64, StorageError>;
    async fn resolve_local_recipient(
        &self,
        address: &str,
    ) -> Result<Option<LocalRecipient>, StorageError>;
    async fn begin_smtp_ingestion(&self) -> Result<Uuid, StorageError>;
    async fn append_smtp_chunk(
        &self,
        ingestion_id: Uuid,
        position: u32,
        bytes: &[u8],
    ) -> Result<(), StorageError>;
    async fn read_smtp_chunk(
        &self,
        _ingestion_id: Uuid,
        _position: u32,
    ) -> Result<Vec<u8>, StorageError> {
        Err(StorageError::Unavailable(
            "SMTP ingestion reads are unsupported".into(),
        ))
    }
    async fn commit_smtp_ingestion(
        &self,
        ingestion_id: Uuid,
        envelope_sender: &str,
        recipients: &[LocalRecipient],
        received_header: &[u8],
        options: &SmtpMailOptions,
    ) -> Result<StoredMessage, StorageError>;
    async fn abort_smtp_ingestion(&self, ingestion_id: Uuid) -> Result<(), StorageError>;

    async fn smtp_auth_account(
        &self,
        _identity: &str,
    ) -> Result<Option<SmtpAuthAccount>, StorageError> {
        Ok(None)
    }

    async fn record_smtp_auth(&self, _user_id: Uuid, _success: bool) -> Result<(), StorageError> {
        Ok(())
    }

    async fn authorize_smtp_sender(
        &self,
        _user_id: Uuid,
        _sender: &str,
    ) -> Result<bool, StorageError> {
        Ok(false)
    }

    async fn commit_submission_ingestion(
        &self,
        _ingestion_id: Uuid,
        _user_id: Uuid,
        _envelope_sender: &str,
        _recipients: &[SubmissionRecipient],
        _received_header: &[u8],
        _options: &SmtpMailOptions,
    ) -> Result<StoredMessage, StorageError> {
        Err(StorageError::Unavailable(
            "message submission is unsupported".into(),
        ))
    }
}

#[async_trait]
pub trait MailboxRepository: Send + Sync {
    async fn mailbox_message_by_uid(
        &self,
        tenant_id: TenantId,
        mailbox_id: MailboxId,
        uid: u32,
    ) -> Result<MailboxMessageState, StorageError>;

    async fn store_flags(
        &self,
        tenant_id: TenantId,
        mailbox_id: MailboxId,
        uid: u32,
        update: &StoreFlags,
    ) -> Result<MailboxMessageState, StorageError>;

    async fn expunge_uid(
        &self,
        tenant_id: TenantId,
        mailbox_id: MailboxId,
        uid: u32,
    ) -> Result<u64, StorageError>;
}

#[async_trait]
pub trait ImapRepository: Send + Sync {
    async fn imap_auth_account(
        &self,
        identity: &str,
    ) -> Result<Option<SmtpAuthAccount>, StorageError>;

    async fn record_imap_auth(&self, user_id: Uuid, success: bool) -> Result<(), StorageError>;

    async fn imap_mailboxes(&self, _user_id: Uuid) -> Result<Vec<ImapMailbox>, StorageError> {
        Err(StorageError::Unavailable(
            "IMAP mailbox operations are unsupported".into(),
        ))
    }

    async fn imap_create_mailbox(
        &self,
        _user_id: Uuid,
        _name: &str,
    ) -> Result<ImapMailbox, StorageError> {
        Err(StorageError::Unavailable(
            "IMAP mailbox operations are unsupported".into(),
        ))
    }

    async fn imap_rename_mailbox(
        &self,
        _user_id: Uuid,
        _from: &str,
        _to: &str,
    ) -> Result<(), StorageError> {
        Err(StorageError::Unavailable(
            "IMAP mailbox operations are unsupported".into(),
        ))
    }

    async fn imap_delete_mailbox(&self, _user_id: Uuid, _name: &str) -> Result<(), StorageError> {
        Err(StorageError::Unavailable(
            "IMAP mailbox operations are unsupported".into(),
        ))
    }

    async fn imap_subscribe(
        &self,
        _user_id: Uuid,
        _name: &str,
        _subscribe: bool,
    ) -> Result<(), StorageError> {
        Err(StorageError::Unavailable(
            "IMAP mailbox operations are unsupported".into(),
        ))
    }

    async fn imap_messages(
        &self,
        _user_id: Uuid,
        _mailbox_id: MailboxId,
    ) -> Result<Vec<ImapMessage>, StorageError> {
        Err(StorageError::Unavailable(
            "IMAP message operations are unsupported".into(),
        ))
    }

    async fn imap_changes(
        &self,
        _user_id: Uuid,
        _mailbox_id: MailboxId,
        _since_modseq: u64,
    ) -> Result<ImapChanges, StorageError> {
        Err(StorageError::Unavailable(
            "IMAP synchronization is unsupported".into(),
        ))
    }

    async fn imap_append(
        &self,
        _user_id: Uuid,
        _mailbox: &str,
        _append: &ImapAppend<'_>,
    ) -> Result<(u32, u32), StorageError> {
        Err(StorageError::Unavailable(
            "IMAP APPEND is unsupported".into(),
        ))
    }

    async fn imap_append_file(
        &self,
        _user_id: Uuid,
        _mailbox: &str,
        _file: &File,
        _flags: &FlagSet,
        _internal_date: SystemTime,
    ) -> Result<(u32, u32), StorageError> {
        Err(StorageError::Unavailable(
            "streaming IMAP APPEND is unsupported".into(),
        ))
    }

    async fn imap_copy(
        &self,
        _user_id: Uuid,
        _source: MailboxId,
        _uids: &[u32],
        _destination: &str,
        _move_messages: bool,
    ) -> Result<Vec<u32>, StorageError> {
        Err(StorageError::Unavailable("IMAP COPY is unsupported".into()))
    }

    async fn imap_store_flags(
        &self,
        _user_id: Uuid,
        _mailbox: MailboxId,
        _uids: &[u32],
        _update: &StoreFlags,
    ) -> Result<Vec<MailboxMessageState>, StorageError> {
        Err(StorageError::Unavailable(
            "IMAP STORE is unsupported".into(),
        ))
    }

    async fn imap_store_flags_conditional(
        &self,
        user_id: Uuid,
        mailbox: MailboxId,
        uids: &[u32],
        update: &StoreFlags,
    ) -> Result<ConditionalStoreResult, StorageError> {
        self.imap_store_flags(user_id, mailbox, uids, update)
            .await
            .map(|updated| ConditionalStoreResult {
                updated,
                modified: Vec::new(),
            })
    }

    async fn imap_expunge(
        &self,
        _user_id: Uuid,
        _mailbox: MailboxId,
        _uids: Option<&[u32]>,
    ) -> Result<Vec<u32>, StorageError> {
        Err(StorageError::Unavailable(
            "IMAP EXPUNGE is unsupported".into(),
        ))
    }
}
