use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use mail_admin_api::router;
use mail_postgres::PostgresRepository;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::postgres::PgPoolOptions;
use tower::ServiceExt;
use uuid::Uuid;

#[tokio::test]
async fn postgres_crud_occ_and_idempotency() -> Result<(), Box<dyn std::error::Error>> {
    let Ok(url) = std::env::var("MAIL_TEST_DATABASE_URL") else {
        return Ok(());
    };
    let pool = PgPoolOptions::new()
        .max_connections(8)
        .connect(&url)
        .await?;
    mail_migrations::run(&pool).await?;
    let secret = format!("system-{}", Uuid::new_v4());
    let hash = Sha256::digest(secret.as_bytes());
    sqlx::query(
        "INSERT INTO api_tokens(id,display_name,token_hash,scopes)VALUES($1,'system',$2,$3)",
    )
    .bind(Uuid::new_v4())
    .bind(hash.as_slice())
    .bind(vec![
        "tenants:read",
        "tenants:write",
        "domains:read",
        "domains:write",
        "users:read",
        "users:write",
        "aliases:read",
        "aliases:write",
        "mailboxes:read",
        "mailboxes:write",
        "audit:read",
    ])
    .execute(&pool)
    .await?;
    let app = router(PostgresRepository::new(pool));
    let key = Uuid::new_v4().to_string();
    let make = || {
        Request::builder()
            .method("POST")
            .uri("/api/v1/tenants")
            .header("authorization", format!("Bearer {secret}"))
            .header("idempotency-key", &key)
            .header("content-type", "application/json")
            .body(Body::from(r#"{"name":"API Tenant"}"#))
    };
    let first = app.clone().oneshot(make()?).await?;
    assert_eq!(first.status(), StatusCode::CREATED);
    let first_body = to_bytes(first.into_body(), 65536).await?;
    let tenant: Value = serde_json::from_slice(&first_body)?;
    let tenant_id = tenant["id"].as_str().ok_or("missing tenant id")?;
    let replay = app.clone().oneshot(make()?).await?;
    assert_eq!(replay.status(), StatusCode::CREATED);
    assert_eq!(
        replay
            .headers()
            .get("x-idempotent-replay")
            .and_then(|v| v.to_str().ok()),
        Some("true")
    );
    let domain_body = json!({"tenant_id":tenant_id,"name":"api.example"}).to_string();
    let domain = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/domains")
                .header("authorization", format!("Bearer {secret}"))
                .header("idempotency-key", Uuid::new_v4().to_string())
                .header("content-type", "application/json")
                .body(Body::from(domain_body))?,
        )
        .await?;
    assert_eq!(domain.status(), StatusCode::CREATED);
    let value: Value = serde_json::from_slice(&to_bytes(domain.into_body(), 65536).await?)?;
    let domain_id = value["id"].as_str().ok_or("missing domain id")?;
    let get = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/domains/{domain_id}?tenant_id={tenant_id}"))
                .header("authorization", format!("Bearer {secret}"))
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(get.status(), StatusCode::OK);
    assert_eq!(
        get.headers().get("etag").and_then(|v| v.to_str().ok()),
        Some("\"1\"")
    );
    let patch = || {
        Request::builder()
            .method("PATCH")
            .uri(format!("/api/v1/domains/{domain_id}?tenant_id={tenant_id}"))
            .header("authorization", format!("Bearer {secret}"))
            .header("if-match", "1")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"enabled":false}"#))
    };
    assert_eq!(
        app.clone().oneshot(patch()?).await?.status(),
        StatusCode::OK
    );
    assert_eq!(app.oneshot(patch()?).await?.status(), StatusCode::CONFLICT);
    Ok(())
}
