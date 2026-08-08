use mail_admin_api::router;
use mail_storage::ApiCredential;
use mail_testkit::InMemoryRepository;
use sha2::{Digest, Sha256};
use std::process::Command;
use tokio::net::TcpListener;
use uuid::Uuid;

#[tokio::test(flavor = "multi_thread")]
async fn database_and_migration_commands_call_admin_api() -> Result<(), Box<dyn std::error::Error>>
{
    let repository = InMemoryRepository::default();
    repository.add_api_credential(
        Sha256::digest(b"system-token").to_vec(),
        ApiCredential {
            token_id: Uuid::new_v4(),
            tenant_id: None,
            scopes: vec!["metrics:read".into()],
        },
    )?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let base_url = format!("http://{}", listener.local_addr()?);
    let server = tokio::spawn(async move { axum::serve(listener, router(repository)).await });

    let database = mailctl(&base_url, &["database", "check"])?;
    assert_eq!(database["status"], "ok");

    let migrations = mailctl(&base_url, &["migration", "status"])?;
    assert_eq!(migrations["status"], "current");

    server.abort();
    Ok(())
}

fn mailctl(
    base_url: &str,
    arguments: &[&str],
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let output = Command::new(env!("CARGO_BIN_EXE_mailctl"))
        .arg("--api-url")
        .arg(base_url)
        .args(arguments)
        .env("MAIL_API_TOKEN", "system-token")
        .output()?;
    assert!(
        output.status.success(),
        "mailctl failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(serde_json::from_slice(&output.stdout)?)
}
