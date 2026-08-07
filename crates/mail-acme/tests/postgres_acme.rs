use mail_acme::{AcmeError, PostgresAcmeCache, RenewalLock};
use sqlx::postgres::PgPoolOptions;
use tokio_rustls_acme::{AccountCache, CertCache};

#[tokio::test]
async fn encrypted_cache_and_distributed_lock() -> Result<(), Box<dyn std::error::Error>> {
    let Ok(url) = std::env::var("MAIL_TEST_DATABASE_URL") else {
        return Ok(());
    };
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&url)
        .await?;
    mail_migrations::run(&pool).await?;
    let cache = PostgresAcmeCache::new(pool.clone(), &[9; 32])?;
    let domains = vec!["mail.example.test".to_owned()];
    let contacts = vec!["mailto:admin@example.test".to_owned()];
    let directory = "https://acme-staging-v02.api.letsencrypt.org/directory";

    cache
        .store_cert(&domains, directory, b"certificate-private-key-pem")
        .await?;
    cache
        .store_account(&contacts, directory, b"account-private-key")
        .await?;
    assert_eq!(
        cache.load_cert(&domains, directory).await?,
        Some(b"certificate-private-key-pem".to_vec())
    );
    assert_eq!(
        cache.load_account(&contacts, directory).await?,
        Some(b"account-private-key".to_vec())
    );
    let stored: Vec<Vec<u8>> = sqlx::query_scalar("SELECT ciphertext FROM acme_cache_entries")
        .fetch_all(&pool)
        .await?;
    assert!(stored.iter().all(|value| {
        !value
            .windows(b"private-key".len())
            .any(|window| window == b"private-key")
    }));

    let lock_id = 7_300_003;
    let first = RenewalLock::acquire(&url, lock_id).await?;
    assert!(matches!(
        RenewalLock::acquire(&url, lock_id).await,
        Err(AcmeError::LockBusy)
    ));
    first.release(lock_id).await?;
    let second = RenewalLock::acquire(&url, lock_id).await?;
    second.release(lock_id).await?;
    Ok(())
}
