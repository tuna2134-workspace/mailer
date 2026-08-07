use std::time::{Duration, SystemTime};

use mail_domain::{EntityStatus, Tenant, TenantId};
use mail_postgres::PostgresRepository;
use mail_storage::{DeliveryOutcome, MailRepository, StorageError};
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

#[tokio::test]
async fn queue_lease_stream_result_and_bounce_are_atomic() -> Result<(), Box<dyn std::error::Error>>
{
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
    repository
        .create_tenant(&Tenant {
            id: tenant,
            name: "delivery-contract".into(),
            status: EntityStatus::Active,
        })
        .await?;
    let message = Uuid::new_v4();
    let raw = b"Subject: test\r\n\r\nbody\r\n";
    sqlx::query("INSERT INTO messages(id,tenant_id,raw_message,envelope_sender,envelope_recipients,received_at,message_size,content_hash,storage_state) VALUES($1,$2,$3,'alice@example.test',ARRAY['bob@example.net'],clock_timestamp(),octet_length($3),digest($3,'sha256'),'committed')")
        .bind(message).bind(tenant.into_uuid()).bind(raw.as_slice()).execute(&pool).await?;
    let queue = Uuid::new_v4();
    sqlx::query("INSERT INTO queue_recipients(id,tenant_id,message_id,recipient,destination_domain,state,next_attempt_at,expires_at) VALUES($1,$2,$3,'bob@example.net','example.net','pending',clock_timestamp(),clock_timestamp()+interval '1 day')")
        .bind(queue).bind(tenant.into_uuid()).bind(message).execute(&pool).await?;

    let lease = repository
        .lease_queue(Uuid::new_v4(), 1, Duration::from_secs(30))
        .await?
        .remove(0);
    assert_eq!(
        repository.read_message_chunk(message, 0, 8).await?,
        &raw[..8]
    );
    assert!(matches!(
        repository
            .finish_delivery(lease.queue_id, Uuid::new_v4(), &DeliveryOutcome::Delivered)
            .await,
        Err(StorageError::Conflict)
    ));
    repository
        .finish_delivery(
            lease.queue_id,
            lease.lease_token,
            &DeliveryOutcome::Deferred {
                next_attempt_at: SystemTime::now() + Duration::from_secs(60),
                enhanced_status_code: Some("4.4.1".into()),
                diagnostic: "temporary".into(),
            },
        )
        .await?;
    let state: String = sqlx::query_scalar("SELECT state FROM queue_recipients WHERE id=$1")
        .bind(queue)
        .fetch_one(&pool)
        .await?;
    assert_eq!(state, "deferred");

    sqlx::query("UPDATE queue_recipients SET next_attempt_at=clock_timestamp() WHERE id=$1")
        .bind(queue)
        .execute(&pool)
        .await?;
    let lease = repository
        .lease_queue(Uuid::new_v4(), 1, Duration::from_secs(30))
        .await?
        .remove(0);
    repository
        .finish_delivery(
            lease.queue_id,
            lease.lease_token,
            &DeliveryOutcome::Failed {
                enhanced_status_code: Some("5.1.1".into()),
                diagnostic: "recipient rejected".into(),
            },
        )
        .await?;
    let bounce: (String, String) = sqlx::query_as("SELECT m.envelope_sender,q.recipient FROM messages m JOIN queue_recipients q ON q.message_id=m.id WHERE m.envelope_sender='' AND q.recipient='alice@example.test'")
        .fetch_one(&pool).await?;
    assert_eq!(bounce, (String::new(), "alice@example.test".into()));
    Ok(())
}
