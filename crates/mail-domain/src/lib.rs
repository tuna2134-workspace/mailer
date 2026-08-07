#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;
use uuid::Uuid;

macro_rules! id {
    ($name:ident) => {
        #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
        pub struct $name(Uuid);

        impl $name {
            #[must_use]
            pub const fn new(value: Uuid) -> Self {
                Self(value)
            }

            #[must_use]
            pub const fn into_uuid(self) -> Uuid {
                self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(f)
            }
        }
    };
}

id!(TenantId);
id!(DomainId);
id!(UserId);
id!(AliasId);
id!(MailboxId);
id!(MessageId);
id!(QueueId);

#[derive(Debug, Error, Eq, PartialEq)]
pub enum ValidationError {
    #[error("value is empty")]
    Empty,
    #[error("value exceeds {max} bytes")]
    TooLong { max: usize },
    #[error("domain name is invalid")]
    InvalidDomain,
    #[error("local part is invalid")]
    InvalidLocalPart,
    #[error("quota exceeds signed PostgreSQL range")]
    QuotaOutOfRange,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DomainName(String);

impl DomainName {
    pub fn parse(value: &str) -> Result<Self, ValidationError> {
        if value.is_empty() || value.len() > 253 {
            return Err(if value.is_empty() {
                ValidationError::Empty
            } else {
                ValidationError::TooLong { max: 253 }
            });
        }
        let normalized = value.trim_end_matches('.').to_ascii_lowercase();
        if normalized.is_empty()
            || normalized.split('.').any(|label| {
                label.is_empty()
                    || label.len() > 63
                    || label.starts_with('-')
                    || label.ends_with('-')
                    || !label
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            })
        {
            return Err(ValidationError::InvalidDomain);
        }
        Ok(Self(normalized))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct LocalPart(String);

impl LocalPart {
    pub fn parse(value: &str) -> Result<Self, ValidationError> {
        if value.is_empty() {
            return Err(ValidationError::Empty);
        }
        if value.len() > 64 {
            return Err(ValidationError::TooLong { max: 64 });
        }
        if value.bytes().any(|b| b <= 0x20 || b == 0x7f || b == b'@') {
            return Err(ValidationError::InvalidLocalPart);
        }
        Ok(Self(value.to_owned()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct QuotaBytes(i64);

impl QuotaBytes {
    pub fn new(value: u64) -> Result<Self, ValidationError> {
        i64::try_from(value)
            .map(Self)
            .map_err(|_| ValidationError::QuotaOutOfRange)
    }

    #[must_use]
    pub const fn as_i64(self) -> i64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntityStatus {
    Active,
    Disabled,
    PendingDeletion,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Tenant {
    pub id: TenantId,
    pub name: String,
    pub status: EntityStatus,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Domain {
    pub id: DomainId,
    pub tenant_id: TenantId,
    pub name: DomainName,
    pub status: EntityStatus,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct User {
    pub id: UserId,
    pub tenant_id: TenantId,
    pub domain_id: DomainId,
    pub local_part: LocalPart,
    pub display_name: String,
    pub quota: QuotaBytes,
    pub status: EntityStatus,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AliasKind {
    User,
    Domain,
    Forwarding,
    Distribution,
    CatchAll,
    Blackhole,
    Reject,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Alias {
    pub id: AliasId,
    pub tenant_id: TenantId,
    pub source: String,
    pub kind: AliasKind,
    pub targets: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Mailbox {
    pub id: MailboxId,
    pub tenant_id: TenantId,
    pub user_id: UserId,
    pub name: String,
    pub uid_validity: u32,
    pub uid_next: u32,
    pub highest_modseq: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QueueState {
    Pending,
    Leased,
    Deferred,
    Delivered,
    Failed,
    Cancelled,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct QueueItem {
    pub id: QueueId,
    pub tenant_id: TenantId,
    pub message_id: MessageId,
    pub recipient: String,
    pub destination_domain: DomainName,
    pub state: QueueState,
    pub attempt_count: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_normalizes_and_rejects_bad_labels() {
        assert_eq!(
            DomainName::parse("Mail.Example.").map(|v| v.0),
            Ok("mail.example".into())
        );
        assert_eq!(
            DomainName::parse("-bad.example"),
            Err(ValidationError::InvalidDomain)
        );
    }

    #[test]
    fn local_part_is_bounded() {
        assert!(LocalPart::parse("alice").is_ok());
        assert_eq!(
            LocalPart::parse("a@b"),
            Err(ValidationError::InvalidLocalPart)
        );
    }
}
