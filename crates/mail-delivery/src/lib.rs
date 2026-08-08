use std::time::{Duration, SystemTime};

use mail_dns::{DnsError, MailResolver};
use mail_smtp_client::{ClientError, DkimSigningConfig, SendResult, SmtpClient};
use mail_storage::{DeliveryOutcome, MailRepository, QueueLease, StorageError};
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum DeliveryError {
    #[error(transparent)]
    Storage(#[from] StorageError),
    #[error(transparent)]
    Client(#[from] ClientError),
}

pub struct DeliveryWorker<R> {
    repository: R,
    resolver: MailResolver,
    client: SmtpClient,
    worker_id: Uuid,
}

impl<R: MailRepository> DeliveryWorker<R> {
    #[must_use]
    pub fn new(repository: R, resolver: MailResolver, hostname: String) -> Self {
        Self {
            repository,
            resolver,
            client: SmtpClient::new(hostname),
            worker_id: Uuid::new_v4(),
        }
    }

    #[must_use]
    pub fn with_dkim(mut self, config: DkimSigningConfig) -> Self {
        self.client = self.client.with_dkim(config);
        self
    }

    pub async fn run_once(&self, limit: u32) -> Result<usize, DeliveryError> {
        let leases = self
            .repository
            .lease_queue(self.worker_id, limit, Duration::from_secs(120))
            .await?;
        let count = leases.len();
        for lease in leases {
            let outcome = self.deliver(&lease).await?;
            self.repository
                .finish_delivery(lease.queue_id, lease.lease_token, &outcome)
                .await?;
        }
        Ok(count)
    }

    async fn deliver(&self, lease: &QueueLease) -> Result<DeliveryOutcome, DeliveryError> {
        if lease.expires_at <= SystemTime::now() {
            return Ok(DeliveryOutcome::Failed {
                enhanced_status_code: Some("5.4.7".into()),
                diagnostic: "delivery time expired".into(),
            });
        }
        let route = match self.resolver.route(&lease.destination_domain).await {
            Ok(route) => route,
            Err(DnsError::Permanent) => {
                return Ok(DeliveryOutcome::Failed {
                    enhanced_status_code: Some("5.4.4".into()),
                    diagnostic: "mail route does not exist".into(),
                });
            }
            Err(DnsError::Temporary(error)) => {
                return Ok(defer(lease, Some("4.4.3".into()), error));
            }
        };
        Ok(
            match self.client.send(&self.repository, lease, &route).await? {
                SendResult::Delivered => DeliveryOutcome::Delivered,
                SendResult::Deferred { code, diagnostic } => defer(lease, code, diagnostic),
                SendResult::Failed { code, diagnostic } => DeliveryOutcome::Failed {
                    enhanced_status_code: code,
                    diagnostic,
                },
            },
        )
    }
}

fn defer(lease: &QueueLease, code: Option<String>, diagnostic: String) -> DeliveryOutcome {
    let delay = retry_delay(lease.queue_id.into_uuid(), lease.attempt_count);
    let next = SystemTime::now()
        .checked_add(delay)
        .unwrap_or(lease.expires_at)
        .min(lease.expires_at);
    DeliveryOutcome::Deferred {
        next_attempt_at: next,
        enhanced_status_code: code,
        diagnostic,
    }
}

#[must_use]
pub fn retry_delay(queue_id: Uuid, attempt: u32) -> Duration {
    let exponent = attempt.min(7);
    let base = 300_u64.saturating_mul(1_u64 << exponent).min(28_800);
    let jitter = u64::from(queue_id.as_bytes()[0]) * base / 2_550;
    Duration::from_secs(base + jitter)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retry_is_bounded_and_deterministic() {
        let id = Uuid::from_u128(1);
        assert_eq!(retry_delay(id, 0), retry_delay(id, 0));
        assert!(retry_delay(id, 100) <= Duration::from_secs(31_680));
    }
}
