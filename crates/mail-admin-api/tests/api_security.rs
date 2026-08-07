use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use mail_admin_api::router;
use mail_domain::{EntityStatus, Tenant, TenantId};
use mail_storage::{ApiCredential, MailRepository};
use mail_testkit::InMemoryRepository;
use serde_json::Value;
use sha2::{Digest, Sha256};
use tower::ServiceExt;
use uuid::Uuid;

#[tokio::test]
async fn authentication_scope_and_tenant_isolation() -> Result<(), Box<dyn std::error::Error>> {
    let repository = InMemoryRepository::default();
    let tenant_a = TenantId::new(Uuid::new_v4());
    let tenant_b = TenantId::new(Uuid::new_v4());
    repository
        .create_tenant(&Tenant {
            id: tenant_a,
            name: "A".into(),
            status: EntityStatus::Active,
        })
        .await?;
    repository
        .create_tenant(&Tenant {
            id: tenant_b,
            name: "B".into(),
            status: EntityStatus::Active,
        })
        .await?;
    repository.add_api_credential(
        Sha256::digest(b"tenant-token").to_vec(),
        ApiCredential {
            token_id: Uuid::new_v4(),
            tenant_id: Some(tenant_a),
            scopes: vec!["tenants:read".into(), "domains:write".into()],
        },
    )?;
    let app = router(repository);

    let unauthorized = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/tenants")
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);
    assert!(unauthorized.headers().contains_key("x-request-id"));
    assert_eq!(
        unauthorized
            .headers()
            .get("content-type")
            .and_then(|value| value.to_str().ok()),
        Some("application/problem+json")
    );

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/tenants")
                .header("authorization", "Bearer tenant-token")
                .header("idempotency-key", "test-key-00000001")
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let value: Value = serde_json::from_slice(&to_bytes(response.into_body(), 64 * 1024).await?)?;
    assert_eq!(value["items"].as_array().map(Vec::len), Some(1));
    assert_eq!(value["items"][0]["id"], tenant_a.into_uuid().to_string());

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/domains")
                .header("authorization", "Bearer tenant-token")
                .header("content-type", "application/json")
                .header("idempotency-key", "test-key-00000001")
                .body(Body::from(format!(
                    r#"{{"tenant_id":"{}","name":"escape.test"}}"#,
                    tenant_b.into_uuid()
                )))?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    Ok(())
}

#[tokio::test]
async fn idempotency_replays_completed_response() -> Result<(), Box<dyn std::error::Error>> {
    let repository = InMemoryRepository::default();
    repository
        .create_tenant(&Tenant {
            id: TenantId::new(Uuid::new_v4()),
            name: "Existing".into(),
            status: EntityStatus::Active,
        })
        .await?;
    repository.add_api_credential(
        Sha256::digest(b"system-token").to_vec(),
        ApiCredential {
            token_id: Uuid::new_v4(),
            tenant_id: None,
            scopes: vec!["tenants:read".into(), "tenants:write".into()],
        },
    )?;
    let app = router(repository);
    let request = || {
        Request::builder()
            .method("POST")
            .uri("/api/v1/tenants")
            .header("authorization", "Bearer system-token")
            .header("idempotency-key", "same-request-0001")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"name":"One"}"#))
    };
    let first = app.clone().oneshot(request()?).await?;
    assert_eq!(first.status(), StatusCode::CREATED);
    let second = app.clone().oneshot(request()?).await?;
    assert_eq!(second.status(), StatusCode::CREATED);
    assert_eq!(
        second
            .headers()
            .get("x-idempotent-replay")
            .and_then(|v| v.to_str().ok()),
        Some("true")
    );
    let page = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/tenants?limit=1")
                .header("authorization", "Bearer system-token")
                .body(Body::empty())?,
        )
        .await?;
    let value: Value = serde_json::from_slice(&to_bytes(page.into_body(), 64 * 1024).await?)?;
    assert_eq!(value["items"].as_array().map(Vec::len), Some(1));
    assert_eq!(value["next_cursor"], "1");
    Ok(())
}
