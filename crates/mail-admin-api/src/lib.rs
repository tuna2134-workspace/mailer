#![forbid(unsafe_code)]

use argon2::{Argon2, PasswordHasher, password_hash::SaltString};
use axum::{
    Json, Router,
    body::{Body, to_bytes},
    extract::{DefaultBodyLimit, Path, Query, State},
    http::{HeaderMap, Method, Request, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::get,
};
use mail_application::{
    AdministrationService, ApplicationError, audit_event, authorize, validate_alias_graph,
};
use mail_domain::{
    Alias, AliasId, AliasKind, Domain, DomainId, DomainName, EntityStatus, LocalPart, QuotaBytes,
    Tenant, TenantId, User, UserId,
};
use mail_storage::{
    AdminRepository, ApiCredential, ApiTokenInfo, DatabaseStatus, MailRepository, MigrationStatus,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tower::limit::ConcurrencyLimitLayer;
use tower_http::sensitive_headers::SetSensitiveRequestHeadersLayer;
use tower_http::{set_header::SetResponseHeaderLayer, timeout::TimeoutLayer};
use uuid::Uuid;

struct AppState<R> {
    service: Arc<AdministrationService<R>>,
    rate: RateState,
}
type RateState = Arc<Mutex<HashMap<Vec<u8>, (Instant, u32)>>>;

impl<R> Clone for AppState<R> {
    fn clone(&self) -> Self {
        Self {
            service: Arc::clone(&self.service),
            rate: Arc::clone(&self.rate),
        }
    }
}

#[allow(clippy::too_many_lines)] // Route inventory stays visible in one place.
pub fn router<R: AdminRepository + 'static>(repository: R) -> Router {
    let state = AppState {
        service: Arc::new(AdministrationService::new(repository)),
        rate: Arc::new(Mutex::new(HashMap::new())),
    };
    Router::new()
        .route(
            "/api/v1/tenants",
            get(list_tenants::<R>).post(create_tenant::<R>),
        )
        .route(
            "/api/v1/domains",
            get(list_domains::<R>).post(create_domain::<R>),
        )
        .route("/api/v1/users", get(list_users::<R>).post(create_user::<R>))
        .route(
            "/api/v1/aliases",
            get(list_aliases::<R>).post(create_alias::<R>),
        )
        .route(
            "/api/v1/tenants/{id}",
            get(get_tenant::<R>)
                .patch(patch_tenant::<R>)
                .delete(delete_tenant::<R>),
        )
        .route(
            "/api/v1/domains/{id}",
            get(get_domain::<R>)
                .patch(patch_domain::<R>)
                .delete(delete_domain::<R>),
        )
        .route(
            "/api/v1/domains/{id}/enable",
            axum::routing::post(enable_domain::<R>),
        )
        .route(
            "/api/v1/domains/{id}/disable",
            axum::routing::post(disable_domain::<R>),
        )
        .route("/api/v1/domains/{id}/dns-records", get(domain_dns::<R>))
        .route(
            "/api/v1/domains/{id}/verify",
            axum::routing::post(verify_domain::<R>),
        )
        .route(
            "/api/v1/users/{id}",
            get(get_user::<R>)
                .patch(patch_user::<R>)
                .delete(delete_user::<R>),
        )
        .route(
            "/api/v1/users/{id}/enable",
            axum::routing::post(enable_user::<R>),
        )
        .route(
            "/api/v1/users/{id}/disable",
            axum::routing::post(disable_user::<R>),
        )
        .route(
            "/api/v1/users/{id}/unlock",
            axum::routing::post(unlock_user::<R>),
        )
        .route(
            "/api/v1/users/{id}/password",
            axum::routing::post(set_password::<R>),
        )
        .route(
            "/api/v1/users/{id}/quota",
            get(get_quota::<R>).patch(patch_quota::<R>),
        )
        .route(
            "/api/v1/users/{id}/application-passwords",
            get(list_app_passwords::<R>).post(create_app_password::<R>),
        )
        .route(
            "/api/v1/users/{id}/application-passwords/{password_id}",
            axum::routing::delete(delete_app_password::<R>),
        )
        .route("/api/v1/users/{id}/mailboxes", get(list_mailboxes::<R>))
        .route(
            "/api/v1/users/{user_id}/mailboxes/{id}",
            get(get_mailbox::<R>)
                .patch(patch_mailbox::<R>)
                .delete(delete_mailbox::<R>),
        )
        .route(
            "/api/v1/aliases/{id}",
            get(get_alias::<R>)
                .patch(patch_alias::<R>)
                .delete(delete_alias::<R>),
        )
        .route(
            "/api/v1/api-tokens",
            get(list_tokens::<R>).post(create_token::<R>),
        )
        .route(
            "/api/v1/api-tokens/{id}",
            axum::routing::delete(revoke_token::<R>),
        )
        .route("/api/v1/audit", get(list_audit::<R>))
        .route("/api/v1/database/check", get(database_check::<R>))
        .route("/api/v1/migrations/status", get(migration_status::<R>))
        .route("/health", get(|| async { StatusCode::NO_CONTENT }))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            idempotency::<R>,
        ))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            audit_mutation::<R>,
        ))
        .layer(DefaultBodyLimit::max(64 * 1024))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            Duration::from_secs(30),
        ))
        .layer(ConcurrencyLimitLayer::new(256))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::CACHE_CONTROL,
            header::HeaderValue::from_static("no-store"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::HeaderName::from_static("x-content-type-options"),
            header::HeaderValue::from_static("nosniff"),
        ))
        .layer(SetSensitiveRequestHeadersLayer::new(std::iter::once(
            header::AUTHORIZATION,
        )))
        .layer(middleware::from_fn(request_ids))
        .with_state(state)
}

async fn request_ids(mut request: Request<Body>, next: Next) -> Response {
    let id = request_id(request.headers());
    if let Ok(value) = header::HeaderValue::from_str(&id.to_string()) {
        request.headers_mut().insert("x-request-id", value.clone());
        let mut response = next.run(request).await;
        response.headers_mut().insert("x-request-id", value);
        response
    } else {
        next.run(request).await
    }
}

async fn audit_mutation<R: AdminRepository>(
    State(state): State<AppState<R>>,
    request: Request<Body>,
    next: Next,
) -> Response {
    if !matches!(
        *request.method(),
        Method::POST | Method::PATCH | Method::DELETE
    ) || !request.uri().path().starts_with("/api/v1/")
    {
        return next.run(request).await;
    }
    let req = request_id(request.headers());
    let actor = match authenticate_no_rate(request.headers(), &state, req).await {
        Ok(v) => v,
        Err(e) => return e.into_response(),
    };
    let path = request.uri().path();
    let resource_id = path
        .split('/')
        .rev()
        .find_map(|part| Uuid::parse_str(part).ok());
    let event = audit_event(
        &actor,
        req,
        &format!("{}.attempt", request.method().as_str().to_ascii_lowercase()),
        path,
        resource_id,
    );
    if let Err(e) = state.service.audit(&event).await {
        return application_error(e, req).into_response();
    }
    next.run(request).await
}

async fn idempotency<R: AdminRepository>(
    State(state): State<AppState<R>>,
    request: Request<Body>,
    next: Next,
) -> Response {
    if request.method() != Method::POST || !request.uri().path().starts_with("/api/v1/") {
        return next.run(request).await;
    }
    let req_id = request_id(request.headers());
    let key = match request
        .headers()
        .get("idempotency-key")
        .and_then(|v| v.to_str().ok())
        .filter(|v| (16..=200).contains(&v.len()))
    {
        Some(v) => v.to_owned(),
        None => {
            return invalid(
                req_id,
                "idempotency_key_required",
                "A valid Idempotency-Key is required.",
            )
            .into_response();
        }
    };
    let actor = match authenticate_no_rate(request.headers(), &state, req_id).await {
        Ok(v) => v,
        Err(e) => return e.into_response(),
    };
    let operation = request.uri().path().to_owned();
    let (parts, body) = request.into_parts();
    let Ok(bytes) = to_bytes(body, 64 * 1024).await else {
        return invalid(req_id, "invalid_body", "Request body is invalid.").into_response();
    };
    let body_json: serde_json::Value =
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    let tenant = body_json
        .get("tenant_id")
        .and_then(|v| v.as_str())
        .and_then(|v| Uuid::parse_str(v).ok())
        .map(TenantId::new)
        .or(actor.tenant_id)
        .unwrap_or_else(|| TenantId::new(Uuid::nil()));
    let hash = Sha256::digest(&bytes);
    match state
        .service
        .idempotency_get(tenant, &key, &operation)
        .await
    {
        Ok(Some(record)) if record.request_hash != hash.as_slice() => {
            return application_error(ApplicationError::Conflict, req_id).into_response();
        }
        Ok(Some(record)) => {
            if let (Some(status), Some(body)) = (record.response_status, record.response_body) {
                let status = StatusCode::from_u16(status).unwrap_or(StatusCode::OK);
                return Response::builder()
                    .status(status)
                    .header("x-idempotent-replay", "true")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body))
                    .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response());
            }
            return application_error(ApplicationError::Conflict, req_id).into_response();
        }
        Ok(None) => {}
        Err(error) => return application_error(error, req_id).into_response(),
    }
    if let Err(error) = state
        .service
        .idempotency_begin(tenant, &key, &operation, hash.as_slice())
        .await
    {
        return application_error(error, req_id).into_response();
    }
    let response = next
        .run(Request::from_parts(parts, Body::from(bytes)))
        .await;
    let status = response.status();
    let (parts, body) = response.into_parts();
    let Ok(bytes) = to_bytes(body, 64 * 1024).await else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    let body = String::from_utf8_lossy(&bytes);
    if state
        .service
        .idempotency_finish(tenant, &key, &operation, status.as_u16(), &body)
        .await
        .is_err()
    {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    Response::from_parts(parts, Body::from(bytes))
}

#[derive(Debug, Serialize)]
pub struct Problem {
    r#type: &'static str,
    title: &'static str,
    status: u16,
    code: &'static str,
    detail: &'static str,
    request_id: Uuid,
}

struct ApiError {
    status: StatusCode,
    code: &'static str,
    title: &'static str,
    detail: &'static str,
    request_id: Uuid,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = Problem {
            r#type: "about:blank",
            title: self.title,
            status: self.status.as_u16(),
            code: self.code,
            detail: self.detail,
            request_id: self.request_id,
        };
        (
            self.status,
            [(header::CONTENT_TYPE, "application/problem+json")],
            Json(body),
        )
            .into_response()
    }
}

#[allow(clippy::needless_pass_by_value)] // Async error adapters supply owned values.
fn application_error(error: ApplicationError, request_id: Uuid) -> ApiError {
    match error {
        ApplicationError::Unauthorized => ApiError {
            status: StatusCode::UNAUTHORIZED,
            code: "invalid_token",
            title: "Authentication required",
            detail: "The bearer token is missing or invalid.",
            request_id,
        },
        ApplicationError::Forbidden => ApiError {
            status: StatusCode::FORBIDDEN,
            code: "insufficient_scope",
            title: "Forbidden",
            detail: "The token does not grant this operation.",
            request_id,
        },
        ApplicationError::NotFound => ApiError {
            status: StatusCode::NOT_FOUND,
            code: "not_found",
            title: "Not found",
            detail: "The resource was not found.",
            request_id,
        },
        ApplicationError::Conflict => ApiError {
            status: StatusCode::CONFLICT,
            code: "resource_conflict",
            title: "Resource conflict",
            detail: "The resource conflicts with existing state.",
            request_id,
        },
        ApplicationError::QuotaExceeded => ApiError {
            status: StatusCode::CONFLICT,
            code: "quota_exceeded",
            title: "Quota exceeded",
            detail: "The quota would be exceeded.",
            request_id,
        },
        ApplicationError::Unavailable => ApiError {
            status: StatusCode::SERVICE_UNAVAILABLE,
            code: "service_unavailable",
            title: "Service unavailable",
            detail: "The operation is temporarily unavailable.",
            request_id,
        },
    }
}

async fn principal<R: MailRepository>(
    headers: &HeaderMap,
    state: &AppState<R>,
    request_id: Uuid,
) -> Result<ApiCredential, ApiError> {
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .filter(|value| !value.is_empty())
        .ok_or_else(|| application_error(ApplicationError::Unauthorized, request_id))?;
    let hash = Sha256::digest(token.as_bytes());
    {
        let mut rates = state
            .rate
            .lock()
            .map_err(|_| application_error(ApplicationError::Unavailable, request_id))?;
        let entry = rates.entry(hash.to_vec()).or_insert((Instant::now(), 0));
        if entry.0.elapsed() >= Duration::from_secs(60) {
            *entry = (Instant::now(), 0);
        }
        if entry.1 >= 120 {
            return Err(ApiError {
                status: StatusCode::TOO_MANY_REQUESTS,
                code: "rate_limited",
                title: "Too many requests",
                detail: "The token request rate was exceeded.",
                request_id,
            });
        }
        entry.1 += 1;
    }
    state
        .service
        .authenticate(hash.as_slice())
        .await
        .map_err(|error| application_error(error, request_id))
}

async fn authenticate_no_rate<R: MailRepository>(
    headers: &HeaderMap,
    state: &AppState<R>,
    request_id: Uuid,
) -> Result<ApiCredential, ApiError> {
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .filter(|v| !v.is_empty())
        .ok_or_else(|| application_error(ApplicationError::Unauthorized, request_id))?;
    let hash = Sha256::digest(token.as_bytes());
    state
        .service
        .authenticate(hash.as_slice())
        .await
        .map_err(|e| application_error(e, request_id))
}

fn request_id(headers: &HeaderMap) -> Uuid {
    headers
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| Uuid::parse_str(value).ok())
        .unwrap_or_else(Uuid::new_v4)
}

#[derive(Deserialize)]
struct ListQuery {
    tenant_id: Option<Uuid>,
    limit: Option<u16>,
    cursor: Option<u32>,
}

#[derive(Serialize)]
struct Page<T> {
    items: Vec<T>,
    next_cursor: Option<String>,
}

fn page<T>(mut items: Vec<T>, limit: u16, offset: u32) -> Page<T> {
    let has_more = items.len() > usize::from(limit);
    items.truncate(usize::from(limit));
    Page {
        items,
        next_cursor: has_more.then(|| offset.saturating_add(u32::from(limit)).to_string()),
    }
}

async fn list_tenants<R: MailRepository>(
    State(state): State<AppState<R>>,
    headers: HeaderMap,
    Query(query): Query<ListQuery>,
) -> Result<Json<Page<Tenant>>, ApiError> {
    let id = request_id(&headers);
    let actor = principal(&headers, &state, id).await?;
    let limit = query.limit.unwrap_or(50).clamp(1, 200);
    let offset = query.cursor.unwrap_or(0);
    let items = state
        .service
        .list_tenants(&actor, limit.saturating_add(1), offset)
        .await
        .map_err(|error| application_error(error, id))?;
    Ok(Json(page(items, limit, offset)))
}

async fn list_domains<R: MailRepository>(
    State(state): State<AppState<R>>,
    headers: HeaderMap,
    Query(query): Query<ListQuery>,
) -> Result<Json<Page<Domain>>, ApiError> {
    let id = request_id(&headers);
    let actor = principal(&headers, &state, id).await?;
    let tenant_id = query
        .tenant_id
        .map(TenantId::new)
        .or(actor.tenant_id)
        .ok_or_else(|| application_error(ApplicationError::Forbidden, id))?;
    let limit = query.limit.unwrap_or(50).clamp(1, 200);
    let offset = query.cursor.unwrap_or(0);
    let items = state
        .service
        .list_domains(&actor, tenant_id, limit.saturating_add(1), offset)
        .await
        .map_err(|error| application_error(error, id))?;
    Ok(Json(page(items, limit, offset)))
}

async fn list_users<R: MailRepository>(
    State(state): State<AppState<R>>,
    headers: HeaderMap,
    Query(query): Query<ListQuery>,
) -> Result<Json<Page<User>>, ApiError> {
    let id = request_id(&headers);
    let actor = principal(&headers, &state, id).await?;
    let tenant_id = query
        .tenant_id
        .map(TenantId::new)
        .or(actor.tenant_id)
        .ok_or_else(|| application_error(ApplicationError::Forbidden, id))?;
    let limit = query.limit.unwrap_or(50).clamp(1, 200);
    let offset = query.cursor.unwrap_or(0);
    let items = state
        .service
        .list_users(&actor, tenant_id, limit.saturating_add(1), offset)
        .await
        .map_err(|error| application_error(error, id))?;
    Ok(Json(page(items, limit, offset)))
}

async fn list_aliases<R: MailRepository>(
    State(state): State<AppState<R>>,
    headers: HeaderMap,
    Query(query): Query<ListQuery>,
) -> Result<Json<Page<Alias>>, ApiError> {
    let id = request_id(&headers);
    let actor = principal(&headers, &state, id).await?;
    let tenant_id = query
        .tenant_id
        .map(TenantId::new)
        .or(actor.tenant_id)
        .ok_or_else(|| application_error(ApplicationError::Forbidden, id))?;
    let limit = query.limit.unwrap_or(50).clamp(1, 200);
    let offset = query.cursor.unwrap_or(0);
    let items = state
        .service
        .list_aliases(&actor, tenant_id, limit.saturating_add(1), offset)
        .await
        .map_err(|error| application_error(error, id))?;
    Ok(Json(page(items, limit, offset)))
}

async fn database_check<R: AdminRepository>(
    State(state): State<AppState<R>>,
    headers: HeaderMap,
) -> Result<Json<DatabaseStatus>, ApiError> {
    let (id, actor) = authz(&headers, &state, "metrics:read", None).await?;
    if actor.tenant_id.is_some() {
        return Err(application_error(ApplicationError::NotFound, id));
    }
    state
        .service
        .database_status()
        .await
        .map(Json)
        .map_err(|error| application_error(error, id))
}

async fn migration_status<R: AdminRepository>(
    State(state): State<AppState<R>>,
    headers: HeaderMap,
) -> Result<Json<MigrationStatus>, ApiError> {
    let (id, actor) = authz(&headers, &state, "metrics:read", None).await?;
    if actor.tenant_id.is_some() {
        return Err(application_error(ApplicationError::NotFound, id));
    }
    state
        .service
        .migration_status()
        .await
        .map(Json)
        .map_err(|error| application_error(error, id))
}

#[derive(Deserialize)]
struct CreateTenant {
    name: String,
}
async fn create_tenant<R: MailRepository>(
    State(state): State<AppState<R>>,
    headers: HeaderMap,
    Json(input): Json<CreateTenant>,
) -> Result<(StatusCode, Json<Tenant>), ApiError> {
    let id = request_id(&headers);
    let actor = principal(&headers, &state, id).await?;
    if actor.tenant_id.is_some() {
        return Err(application_error(ApplicationError::NotFound, id));
    }
    authorize(&actor, "tenants:write", None).map_err(|error| application_error(error, id))?;
    let tenant = Tenant {
        id: TenantId::new(Uuid::new_v4()),
        name: input.name,
        status: EntityStatus::Active,
    };
    state
        .service
        .create_tenant(&tenant)
        .await
        .map_err(|error| application_error(error, id))?;
    state
        .service
        .audit(&audit_event(
            &actor,
            id,
            "tenant.create",
            "tenant",
            Some(tenant.id.into_uuid()),
        ))
        .await
        .map_err(|error| application_error(error, id))?;
    Ok((StatusCode::CREATED, Json(tenant)))
}

#[derive(Deserialize)]
struct CreateDomain {
    tenant_id: Uuid,
    name: String,
}
async fn create_domain<R: MailRepository>(
    State(state): State<AppState<R>>,
    headers: HeaderMap,
    Json(input): Json<CreateDomain>,
) -> Result<(StatusCode, Json<Domain>), ApiError> {
    let id = request_id(&headers);
    let actor = principal(&headers, &state, id).await?;
    let tenant_id = TenantId::new(input.tenant_id);
    authorize(&actor, "domains:write", Some(tenant_id))
        .map_err(|error| application_error(error, id))?;
    let domain = Domain {
        id: DomainId::new(Uuid::new_v4()),
        tenant_id,
        name: DomainName::parse(&input.name).map_err(|_| ApiError {
            status: StatusCode::UNPROCESSABLE_ENTITY,
            code: "invalid_domain",
            title: "Invalid request",
            detail: "The domain name is invalid.",
            request_id: id,
        })?,
        status: EntityStatus::Active,
    };
    state
        .service
        .create_domain(&domain)
        .await
        .map_err(|error| application_error(error, id))?;
    state
        .service
        .audit(&audit_event(
            &actor,
            id,
            "domain.create",
            "domain",
            Some(domain.id.into_uuid()),
        ))
        .await
        .map_err(|error| application_error(error, id))?;
    Ok((StatusCode::CREATED, Json(domain)))
}

#[derive(Deserialize)]
struct CreateUser {
    tenant_id: Uuid,
    domain_id: Uuid,
    local_part: String,
    display_name: Option<String>,
    password: String,
    quota_bytes: u64,
    enabled: Option<bool>,
}
async fn create_user<R: MailRepository + 'static>(
    State(state): State<AppState<R>>,
    headers: HeaderMap,
    Json(input): Json<CreateUser>,
) -> Result<(StatusCode, Json<User>), ApiError> {
    let id = request_id(&headers);
    let actor = principal(&headers, &state, id).await?;
    let tenant_id = TenantId::new(input.tenant_id);
    authorize(&actor, "users:write", Some(tenant_id))
        .map_err(|error| application_error(error, id))?;
    if input.password.len() < 12 || input.password.len() > 1024 {
        return Err(ApiError {
            status: StatusCode::UNPROCESSABLE_ENTITY,
            code: "invalid_password",
            title: "Invalid request",
            detail: "Password length is outside policy.",
            request_id: id,
        });
    }
    let credential = hash_password(input.password, id).await?;
    let user = User {
        id: UserId::new(Uuid::new_v4()),
        tenant_id,
        domain_id: DomainId::new(input.domain_id),
        local_part: LocalPart::parse(&input.local_part).map_err(|_| ApiError {
            status: StatusCode::UNPROCESSABLE_ENTITY,
            code: "invalid_local_part",
            title: "Invalid request",
            detail: "The local part is invalid.",
            request_id: id,
        })?,
        display_name: input.display_name.unwrap_or_default(),
        quota: QuotaBytes::new(input.quota_bytes)
            .map_err(|_| application_error(ApplicationError::Conflict, id))?,
        status: if input.enabled.unwrap_or(true) {
            EntityStatus::Active
        } else {
            EntityStatus::Disabled
        },
    };
    state
        .service
        .create_user_with_password(&user, &credential)
        .await
        .map_err(|error| application_error(error, id))?;
    state
        .service
        .audit(&audit_event(
            &actor,
            id,
            "user.create",
            "user",
            Some(user.id.into_uuid()),
        ))
        .await
        .map_err(|error| application_error(error, id))?;
    Ok((StatusCode::CREATED, Json(user)))
}

#[derive(Deserialize)]
struct CreateAlias {
    tenant_id: Uuid,
    source: String,
    kind: AliasKind,
    targets: Vec<String>,
}
async fn create_alias<R: MailRepository>(
    State(state): State<AppState<R>>,
    headers: HeaderMap,
    Json(input): Json<CreateAlias>,
) -> Result<(StatusCode, Json<Alias>), ApiError> {
    let id = request_id(&headers);
    let actor = principal(&headers, &state, id).await?;
    let tenant_id = TenantId::new(input.tenant_id);
    authorize(&actor, "aliases:write", Some(tenant_id))
        .map_err(|error| application_error(error, id))?;
    if input.source.is_empty() || input.source.len() > 320 || input.targets.len() > 100 {
        return Err(ApiError {
            status: StatusCode::UNPROCESSABLE_ENTITY,
            code: "invalid_alias",
            title: "Invalid request",
            detail: "Alias input exceeds configured limits.",
            request_id: id,
        });
    }
    let alias = Alias {
        id: AliasId::new(Uuid::new_v4()),
        tenant_id,
        source: input.source,
        kind: input.kind,
        targets: input.targets,
    };
    let existing = state
        .service
        .list_aliases(&actor, tenant_id, 200, 0)
        .await
        .map_err(|e| application_error(e, id))?;
    validate_alias_graph(&alias, &existing).map_err(|e| application_error(e, id))?;
    state
        .service
        .create_alias(&alias)
        .await
        .map_err(|error| application_error(error, id))?;
    state
        .service
        .audit(&audit_event(
            &actor,
            id,
            "alias.create",
            "alias",
            Some(alias.id.into_uuid()),
        ))
        .await
        .map_err(|error| application_error(error, id))?;
    Ok((StatusCode::CREATED, Json(alias)))
}

fn expected_version(headers: &HeaderMap, id: Uuid) -> Result<i64, ApiError> {
    headers
        .get(header::IF_MATCH)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.trim_matches('"'))
        .and_then(|v| v.parse().ok())
        .filter(|v| *v > 0)
        .ok_or(ApiError {
            status: StatusCode::PRECONDITION_REQUIRED,
            code: "if_match_required",
            title: "Precondition required",
            detail: "A valid If-Match version is required.",
            request_id: id,
        })
}

fn tenant_for(
    actor: &ApiCredential,
    requested: Option<Uuid>,
    id: Uuid,
) -> Result<TenantId, ApiError> {
    requested
        .map(TenantId::new)
        .or(actor.tenant_id)
        .ok_or_else(|| application_error(ApplicationError::Forbidden, id))
}

async fn authz<R: MailRepository>(
    headers: &HeaderMap,
    state: &AppState<R>,
    scope: &str,
    tenant: Option<TenantId>,
) -> Result<(Uuid, ApiCredential), ApiError> {
    let id = request_id(headers);
    let actor = principal(headers, state, id).await?;
    authorize(&actor, scope, tenant).map_err(|e| application_error(e, id))?;
    Ok((id, actor))
}

#[derive(Deserialize)]
struct TenantQuery {
    tenant_id: Option<Uuid>,
}
#[derive(Deserialize)]
struct PatchTenant {
    name: Option<String>,
    enabled: Option<bool>,
}
async fn get_tenant<R: AdminRepository>(
    State(state): State<AppState<R>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, ApiError> {
    let tenant = TenantId::new(id);
    let (_, actor) = authz(&headers, &state, "tenants:read", Some(tenant)).await?;
    let found = state
        .service
        .get_tenant(actor.tenant_id.unwrap_or(tenant))
        .await
        .map_err(|e| application_error(e, request_id(&headers)))?;
    Ok((
        [(header::ETAG, format!("\"{}\"", found.version))],
        Json(found),
    ))
}
async fn patch_tenant<R: AdminRepository>(
    State(state): State<AppState<R>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(input): Json<PatchTenant>,
) -> Result<impl IntoResponse, ApiError> {
    let tenant_id = TenantId::new(id);
    let (req, actor) = authz(&headers, &state, "tenants:write", Some(tenant_id)).await?;
    let expected = expected_version(&headers, req)?;
    let mut current = state
        .service
        .get_tenant(tenant_id)
        .await
        .map_err(|e| application_error(e, req))?
        .value;
    if let Some(name) = input.name {
        if name.is_empty() || name.len() > 200 {
            return Err(invalid(req, "invalid_name", "Tenant name is invalid."));
        }
        current.name = name;
    }
    if let Some(enabled) = input.enabled {
        current.status = if enabled {
            EntityStatus::Active
        } else {
            EntityStatus::Disabled
        };
    }
    let version = state
        .service
        .update_tenant(&current, expected)
        .await
        .map_err(|e| application_error(e, req))?;
    state
        .service
        .audit(&audit_event(
            &actor,
            req,
            "tenant.update",
            "tenant",
            Some(id),
        ))
        .await
        .map_err(|e| application_error(e, req))?;
    Ok(([(header::ETAG, format!("\"{version}\""))], Json(current)))
}
async fn delete_tenant<R: AdminRepository>(
    State(state): State<AppState<R>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    let tenant = TenantId::new(id);
    let (req, actor) = authz(&headers, &state, "tenants:write", Some(tenant)).await?;
    let expected = expected_version(&headers, req)?;
    let mut value = state
        .service
        .get_tenant(tenant)
        .await
        .map_err(|e| application_error(e, req))?
        .value;
    value.status = EntityStatus::PendingDeletion;
    state
        .service
        .update_tenant(&value, expected)
        .await
        .map_err(|e| application_error(e, req))?;
    state
        .service
        .audit(&audit_event(
            &actor,
            req,
            "tenant.delete.schedule",
            "tenant",
            Some(id),
        ))
        .await
        .map_err(|e| application_error(e, req))?;
    Ok(StatusCode::ACCEPTED)
}

#[derive(Deserialize)]
struct PatchDomain {
    name: Option<String>,
    enabled: Option<bool>,
}
async fn get_domain<R: AdminRepository>(
    State(state): State<AppState<R>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Query(q): Query<TenantQuery>,
) -> Result<impl IntoResponse, ApiError> {
    let req = request_id(&headers);
    let actor = principal(&headers, &state, req).await?;
    let tenant = tenant_for(&actor, q.tenant_id, req)?;
    authorize(&actor, "domains:read", Some(tenant)).map_err(|e| application_error(e, req))?;
    let found = state
        .service
        .get_domain(tenant, DomainId::new(id))
        .await
        .map_err(|e| application_error(e, req))?;
    Ok((
        [(header::ETAG, format!("\"{}\"", found.version))],
        Json(found),
    ))
}
async fn patch_domain<R: AdminRepository>(
    State(state): State<AppState<R>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Query(q): Query<TenantQuery>,
    Json(input): Json<PatchDomain>,
) -> Result<impl IntoResponse, ApiError> {
    let req = request_id(&headers);
    let actor = principal(&headers, &state, req).await?;
    let tenant = tenant_for(&actor, q.tenant_id, req)?;
    authorize(&actor, "domains:write", Some(tenant)).map_err(|e| application_error(e, req))?;
    let expected = expected_version(&headers, req)?;
    let mut value = state
        .service
        .get_domain(tenant, DomainId::new(id))
        .await
        .map_err(|e| application_error(e, req))?
        .value;
    if let Some(name) = input.name {
        value.name = DomainName::parse(&name)
            .map_err(|_| invalid(req, "invalid_domain", "Domain name is invalid."))?;
    }
    if let Some(enabled) = input.enabled {
        value.status = if enabled {
            EntityStatus::Active
        } else {
            EntityStatus::Disabled
        };
    }
    let version = state
        .service
        .update_domain(&value, expected)
        .await
        .map_err(|e| application_error(e, req))?;
    state
        .service
        .audit(&audit_event(
            &actor,
            req,
            "domain.update",
            "domain",
            Some(id),
        ))
        .await
        .map_err(|e| application_error(e, req))?;
    Ok(([(header::ETAG, format!("\"{version}\""))], Json(value)))
}
async fn set_domain_state<R: AdminRepository>(
    state: AppState<R>,
    headers: HeaderMap,
    id: Uuid,
    q: TenantQuery,
    status_value: EntityStatus,
) -> Result<StatusCode, ApiError> {
    let req = request_id(&headers);
    let actor = principal(&headers, &state, req).await?;
    let tenant = tenant_for(&actor, q.tenant_id, req)?;
    authorize(&actor, "domains:write", Some(tenant)).map_err(|e| application_error(e, req))?;
    let expected = expected_version(&headers, req)?;
    let mut value = state
        .service
        .get_domain(tenant, DomainId::new(id))
        .await
        .map_err(|e| application_error(e, req))?
        .value;
    value.status = status_value;
    state
        .service
        .update_domain(&value, expected)
        .await
        .map_err(|e| application_error(e, req))?;
    Ok(StatusCode::NO_CONTENT)
}
async fn enable_domain<R: AdminRepository>(
    State(s): State<AppState<R>>,
    h: HeaderMap,
    Path(id): Path<Uuid>,
    Query(q): Query<TenantQuery>,
) -> Result<StatusCode, ApiError> {
    set_domain_state(s, h, id, q, EntityStatus::Active).await
}
async fn disable_domain<R: AdminRepository>(
    State(s): State<AppState<R>>,
    h: HeaderMap,
    Path(id): Path<Uuid>,
    Query(q): Query<TenantQuery>,
) -> Result<StatusCode, ApiError> {
    set_domain_state(s, h, id, q, EntityStatus::Disabled).await
}
async fn delete_domain<R: AdminRepository>(
    State(s): State<AppState<R>>,
    h: HeaderMap,
    Path(id): Path<Uuid>,
    Query(q): Query<TenantQuery>,
) -> Result<StatusCode, ApiError> {
    set_domain_state(s, h, id, q, EntityStatus::PendingDeletion)
        .await
        .map(|_| StatusCode::ACCEPTED)
}

#[derive(Serialize)]
struct DnsRecord {
    kind: &'static str,
    name: String,
    value: String,
}
async fn domain_dns<R: AdminRepository>(
    State(state): State<AppState<R>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Query(q): Query<TenantQuery>,
) -> Result<Json<Vec<DnsRecord>>, ApiError> {
    let req = request_id(&headers);
    let actor = principal(&headers, &state, req).await?;
    let tenant = tenant_for(&actor, q.tenant_id, req)?;
    authorize(&actor, "domains:read", Some(tenant)).map_err(|e| application_error(e, req))?;
    let domain = state
        .service
        .get_domain(tenant, DomainId::new(id))
        .await
        .map_err(|e| application_error(e, req))?
        .value;
    let d = domain.name.as_str();
    Ok(Json(vec![
        DnsRecord {
            kind: "MX",
            name: d.into(),
            value: format!("10 mail.{d}."),
        },
        DnsRecord {
            kind: "TXT",
            name: d.into(),
            value: "v=spf1 mx -all".into(),
        },
        DnsRecord {
            kind: "TXT",
            name: format!("_dmarc.{d}"),
            value: "v=DMARC1; p=reject".into(),
        },
        DnsRecord {
            kind: "TXT",
            name: format!("_smtp._tls.{d}"),
            value: format!("v=TLSRPTv1; rua=mailto:tlsrpt@{d}"),
        },
    ]))
}
async fn verify_domain<R: AdminRepository>(
    State(state): State<AppState<R>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Query(q): Query<TenantQuery>,
) -> Result<StatusCode, ApiError> {
    let req = request_id(&headers);
    let actor = principal(&headers, &state, req).await?;
    let tenant = tenant_for(&actor, q.tenant_id, req)?;
    authorize(&actor, "domains:write", Some(tenant)).map_err(|e| application_error(e, req))?;
    state
        .service
        .get_domain(tenant, DomainId::new(id))
        .await
        .map_err(|e| application_error(e, req))?;
    Ok(StatusCode::ACCEPTED)
}

fn invalid(request_id: Uuid, code: &'static str, detail: &'static str) -> ApiError {
    ApiError {
        status: StatusCode::UNPROCESSABLE_ENTITY,
        code,
        title: "Invalid request",
        detail,
        request_id,
    }
}

#[derive(Deserialize)]
struct PatchUser {
    display_name: Option<String>,
    quota_bytes: Option<u64>,
    enabled: Option<bool>,
}
async fn get_user<R: AdminRepository>(
    State(state): State<AppState<R>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Query(q): Query<TenantQuery>,
) -> Result<impl IntoResponse, ApiError> {
    let req = request_id(&headers);
    let actor = principal(&headers, &state, req).await?;
    let tenant = tenant_for(&actor, q.tenant_id, req)?;
    authorize(&actor, "users:read", Some(tenant)).map_err(|e| application_error(e, req))?;
    let found = state
        .service
        .get_user(tenant, UserId::new(id))
        .await
        .map_err(|e| application_error(e, req))?;
    Ok((
        [(header::ETAG, format!("\"{}\"", found.version))],
        Json(found),
    ))
}
async fn patch_user<R: AdminRepository>(
    State(state): State<AppState<R>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Query(q): Query<TenantQuery>,
    Json(input): Json<PatchUser>,
) -> Result<impl IntoResponse, ApiError> {
    let req = request_id(&headers);
    let actor = principal(&headers, &state, req).await?;
    let tenant = tenant_for(&actor, q.tenant_id, req)?;
    authorize(&actor, "users:write", Some(tenant)).map_err(|e| application_error(e, req))?;
    let expected = expected_version(&headers, req)?;
    let mut value = state
        .service
        .get_user(tenant, UserId::new(id))
        .await
        .map_err(|e| application_error(e, req))?
        .value;
    if let Some(name) = input.display_name {
        if name.len() > 256 {
            return Err(invalid(
                req,
                "invalid_display_name",
                "Display name is too long.",
            ));
        }
        value.display_name = name;
    }
    if let Some(quota) = input.quota_bytes {
        value.quota = QuotaBytes::new(quota)
            .map_err(|_| invalid(req, "invalid_quota", "Quota is invalid."))?;
    }
    if let Some(enabled) = input.enabled {
        value.status = if enabled {
            EntityStatus::Active
        } else {
            EntityStatus::Disabled
        };
    }
    let version = state
        .service
        .update_user(&value, expected)
        .await
        .map_err(|e| application_error(e, req))?;
    state
        .service
        .audit(&audit_event(&actor, req, "user.update", "user", Some(id)))
        .await
        .map_err(|e| application_error(e, req))?;
    Ok(([(header::ETAG, format!("\"{version}\""))], Json(value)))
}
async fn set_user_state<R: AdminRepository>(
    state: AppState<R>,
    headers: HeaderMap,
    id: Uuid,
    q: TenantQuery,
    status_value: EntityStatus,
) -> Result<StatusCode, ApiError> {
    let req = request_id(&headers);
    let actor = principal(&headers, &state, req).await?;
    let tenant = tenant_for(&actor, q.tenant_id, req)?;
    authorize(&actor, "users:write", Some(tenant)).map_err(|e| application_error(e, req))?;
    let expected = expected_version(&headers, req)?;
    let mut value = state
        .service
        .get_user(tenant, UserId::new(id))
        .await
        .map_err(|e| application_error(e, req))?
        .value;
    value.status = status_value;
    state
        .service
        .update_user(&value, expected)
        .await
        .map_err(|e| application_error(e, req))?;
    Ok(StatusCode::NO_CONTENT)
}
async fn enable_user<R: AdminRepository>(
    State(s): State<AppState<R>>,
    h: HeaderMap,
    Path(id): Path<Uuid>,
    Query(q): Query<TenantQuery>,
) -> Result<StatusCode, ApiError> {
    set_user_state(s, h, id, q, EntityStatus::Active).await
}
async fn disable_user<R: AdminRepository>(
    State(s): State<AppState<R>>,
    h: HeaderMap,
    Path(id): Path<Uuid>,
    Query(q): Query<TenantQuery>,
) -> Result<StatusCode, ApiError> {
    set_user_state(s, h, id, q, EntityStatus::Disabled).await
}
async fn delete_user<R: AdminRepository>(
    State(s): State<AppState<R>>,
    h: HeaderMap,
    Path(id): Path<Uuid>,
    Query(q): Query<TenantQuery>,
) -> Result<StatusCode, ApiError> {
    set_user_state(s, h, id, q, EntityStatus::PendingDeletion)
        .await
        .map(|_| StatusCode::ACCEPTED)
}
async fn unlock_user<R: AdminRepository>(
    State(state): State<AppState<R>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Query(q): Query<TenantQuery>,
) -> Result<StatusCode, ApiError> {
    let req = request_id(&headers);
    let actor = principal(&headers, &state, req).await?;
    let tenant = tenant_for(&actor, q.tenant_id, req)?;
    authorize(&actor, "users:write", Some(tenant)).map_err(|e| application_error(e, req))?;
    state
        .service
        .unlock_user(tenant, UserId::new(id))
        .await
        .map_err(|e| application_error(e, req))?;
    Ok(StatusCode::NO_CONTENT)
}
#[derive(Deserialize)]
struct PasswordInput {
    password: String,
}
async fn hash_password(
    password: String,
    req: Uuid,
) -> Result<mail_storage::PasswordCredential, ApiError> {
    if password.len() < 12 || password.len() > 1024 {
        return Err(invalid(
            req,
            "invalid_password",
            "Password length is outside policy.",
        ));
    }
    tokio::task::spawn_blocking(move || {
        use ring::rand::{SecureRandom as _, SystemRandom};
        let mut salts = [0_u8; 32];
        SystemRandom::new().fill(&mut salts).map_err(|_| ())?;
        let argon2_salt = SaltString::encode_b64(&salts[..16]).map_err(|_| ())?;
        let argon2_hash = Argon2::default()
            .hash_password(password.as_bytes(), &argon2_salt)
            .map(|v| v.to_string())
            .map_err(|_| ())?;
        let iterations = std::num::NonZeroU32::new(4096).ok_or(())?;
        let scram = mail_sasl::derive_credential(password.as_bytes(), &salts[16..], iterations);
        Ok::<_, ()>(mail_storage::PasswordCredential {
            argon2_hash,
            scram: Some(mail_storage::SmtpScramCredential {
                salt: scram.salt,
                iterations: scram.iterations.get(),
                stored_key: scram.stored_key.to_vec(),
                server_key: scram.server_key.to_vec(),
            }),
        })
    })
    .await
    .map_err(|_| application_error(ApplicationError::Unavailable, req))?
    .map_err(|()| application_error(ApplicationError::Unavailable, req))
}
async fn set_password<R: AdminRepository>(
    State(state): State<AppState<R>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Query(q): Query<TenantQuery>,
    Json(input): Json<PasswordInput>,
) -> Result<StatusCode, ApiError> {
    let req = request_id(&headers);
    let actor = principal(&headers, &state, req).await?;
    let tenant = tenant_for(&actor, q.tenant_id, req)?;
    authorize(&actor, "users:write", Some(tenant)).map_err(|e| application_error(e, req))?;
    let credential = hash_password(input.password, req).await?;
    state
        .service
        .set_user_password(tenant, UserId::new(id), &credential)
        .await
        .map_err(|e| application_error(e, req))?;
    Ok(StatusCode::NO_CONTENT)
}
#[derive(Serialize)]
struct QuotaResponse {
    quota_bytes: u64,
}
async fn get_quota<R: AdminRepository>(
    State(state): State<AppState<R>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Query(q): Query<TenantQuery>,
) -> Result<Json<QuotaResponse>, ApiError> {
    let req = request_id(&headers);
    let actor = principal(&headers, &state, req).await?;
    let tenant = tenant_for(&actor, q.tenant_id, req)?;
    authorize(&actor, "users:read", Some(tenant)).map_err(|e| application_error(e, req))?;
    let user = state
        .service
        .get_user(tenant, UserId::new(id))
        .await
        .map_err(|e| application_error(e, req))?
        .value;
    Ok(Json(QuotaResponse {
        quota_bytes: u64::try_from(user.quota.as_i64())
            .map_err(|_| application_error(ApplicationError::Unavailable, req))?,
    }))
}
#[derive(Deserialize)]
struct QuotaInput {
    quota_bytes: u64,
}
async fn patch_quota<R: AdminRepository>(
    State(state): State<AppState<R>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Query(q): Query<TenantQuery>,
    Json(input): Json<QuotaInput>,
) -> Result<StatusCode, ApiError> {
    let req = request_id(&headers);
    let actor = principal(&headers, &state, req).await?;
    let tenant = tenant_for(&actor, q.tenant_id, req)?;
    authorize(&actor, "users:write", Some(tenant)).map_err(|e| application_error(e, req))?;
    let expected = expected_version(&headers, req)?;
    let mut user = state
        .service
        .get_user(tenant, UserId::new(id))
        .await
        .map_err(|e| application_error(e, req))?
        .value;
    user.quota = QuotaBytes::new(input.quota_bytes)
        .map_err(|_| invalid(req, "invalid_quota", "Quota is invalid."))?;
    state
        .service
        .update_user(&user, expected)
        .await
        .map_err(|e| application_error(e, req))?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
struct AppPasswordInput {
    display_name: String,
}
#[derive(Serialize)]
struct CreatedSecret<T> {
    resource: T,
    secret: String,
}
async fn create_app_password<R: AdminRepository>(
    State(state): State<AppState<R>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Query(q): Query<TenantQuery>,
    Json(input): Json<AppPasswordInput>,
) -> Result<
    (
        StatusCode,
        Json<CreatedSecret<mail_storage::ApplicationPasswordInfo>>,
    ),
    ApiError,
> {
    let req = request_id(&headers);
    let actor = principal(&headers, &state, req).await?;
    let tenant = tenant_for(&actor, q.tenant_id, req)?;
    authorize(&actor, "users:write", Some(tenant)).map_err(|e| application_error(e, req))?;
    if input.display_name.is_empty() || input.display_name.len() > 200 {
        return Err(invalid(req, "invalid_name", "Display name is invalid."));
    }
    let secret = format!(
        "mailapp_{}{}",
        Uuid::new_v4().simple(),
        Uuid::new_v4().simple()
    );
    let credential = hash_password(secret.clone(), req).await?;
    let info = state
        .service
        .create_application_password(
            tenant,
            UserId::new(id),
            Uuid::new_v4(),
            &input.display_name,
            &credential,
        )
        .await
        .map_err(|e| application_error(e, req))?;
    Ok((
        StatusCode::CREATED,
        Json(CreatedSecret {
            resource: info,
            secret,
        }),
    ))
}
async fn list_app_passwords<R: AdminRepository>(
    State(state): State<AppState<R>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Query(q): Query<TenantQuery>,
) -> Result<Json<Vec<mail_storage::ApplicationPasswordInfo>>, ApiError> {
    let req = request_id(&headers);
    let actor = principal(&headers, &state, req).await?;
    let tenant = tenant_for(&actor, q.tenant_id, req)?;
    authorize(&actor, "users:read", Some(tenant)).map_err(|e| application_error(e, req))?;
    Ok(Json(
        state
            .service
            .list_application_passwords(tenant, UserId::new(id))
            .await
            .map_err(|e| application_error(e, req))?,
    ))
}
async fn delete_app_password<R: AdminRepository>(
    State(state): State<AppState<R>>,
    headers: HeaderMap,
    Path((id, password_id)): Path<(Uuid, Uuid)>,
    Query(q): Query<TenantQuery>,
) -> Result<StatusCode, ApiError> {
    let req = request_id(&headers);
    let actor = principal(&headers, &state, req).await?;
    let tenant = tenant_for(&actor, q.tenant_id, req)?;
    authorize(&actor, "users:write", Some(tenant)).map_err(|e| application_error(e, req))?;
    state
        .service
        .revoke_application_password(tenant, UserId::new(id), password_id)
        .await
        .map_err(|e| application_error(e, req))?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
struct PatchAlias {
    source: Option<String>,
    kind: Option<AliasKind>,
    targets: Option<Vec<String>>,
}
async fn get_alias<R: AdminRepository>(
    State(state): State<AppState<R>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Query(q): Query<TenantQuery>,
) -> Result<impl IntoResponse, ApiError> {
    let req = request_id(&headers);
    let actor = principal(&headers, &state, req).await?;
    let tenant = tenant_for(&actor, q.tenant_id, req)?;
    authorize(&actor, "aliases:read", Some(tenant)).map_err(|e| application_error(e, req))?;
    let found = state
        .service
        .get_alias(tenant, AliasId::new(id))
        .await
        .map_err(|e| application_error(e, req))?;
    Ok((
        [(header::ETAG, format!("\"{}\"", found.version))],
        Json(found),
    ))
}
async fn patch_alias<R: AdminRepository>(
    State(state): State<AppState<R>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Query(q): Query<TenantQuery>,
    Json(input): Json<PatchAlias>,
) -> Result<impl IntoResponse, ApiError> {
    let req = request_id(&headers);
    let actor = principal(&headers, &state, req).await?;
    let tenant = tenant_for(&actor, q.tenant_id, req)?;
    authorize(&actor, "aliases:write", Some(tenant)).map_err(|e| application_error(e, req))?;
    let expected = expected_version(&headers, req)?;
    let mut value = state
        .service
        .get_alias(tenant, AliasId::new(id))
        .await
        .map_err(|e| application_error(e, req))?
        .value;
    if let Some(source) = input.source {
        value.source = source;
    }
    if let Some(kind) = input.kind {
        value.kind = kind;
    }
    if let Some(targets) = input.targets {
        if targets.len() > 100 {
            return Err(invalid(req, "invalid_alias", "Too many alias targets."));
        }
        value.targets = targets;
    }
    let existing = state
        .service
        .list_aliases(&actor, tenant, 200, 0)
        .await
        .map_err(|e| application_error(e, req))?;
    validate_alias_graph(&value, &existing).map_err(|e| application_error(e, req))?;
    let version = state
        .service
        .update_alias(&value, expected)
        .await
        .map_err(|e| application_error(e, req))?;
    Ok(([(header::ETAG, format!("\"{version}\""))], Json(value)))
}
async fn delete_alias<R: AdminRepository>(
    State(state): State<AppState<R>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Query(q): Query<TenantQuery>,
) -> Result<StatusCode, ApiError> {
    let req = request_id(&headers);
    let actor = principal(&headers, &state, req).await?;
    let tenant = tenant_for(&actor, q.tenant_id, req)?;
    authorize(&actor, "aliases:write", Some(tenant)).map_err(|e| application_error(e, req))?;
    state
        .service
        .delete_alias(tenant, AliasId::new(id), expected_version(&headers, req)?)
        .await
        .map_err(|e| application_error(e, req))?;
    Ok(StatusCode::NO_CONTENT)
}

async fn list_mailboxes<R: AdminRepository>(
    State(state): State<AppState<R>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Query(q): Query<ListQuery>,
) -> Result<Json<Vec<mail_storage::MailboxInfo>>, ApiError> {
    let req = request_id(&headers);
    let actor = principal(&headers, &state, req).await?;
    let tenant = tenant_for(&actor, q.tenant_id, req)?;
    authorize(&actor, "mailboxes:read", Some(tenant)).map_err(|e| application_error(e, req))?;
    Ok(Json(
        state
            .service
            .list_mailboxes(tenant, UserId::new(id), q.limit.unwrap_or(50))
            .await
            .map_err(|e| application_error(e, req))?,
    ))
}
async fn get_mailbox<R: AdminRepository>(
    State(state): State<AppState<R>>,
    headers: HeaderMap,
    Path((user, id)): Path<(Uuid, Uuid)>,
    Query(q): Query<TenantQuery>,
) -> Result<Json<mail_storage::MailboxInfo>, ApiError> {
    let req = request_id(&headers);
    let actor = principal(&headers, &state, req).await?;
    let tenant = tenant_for(&actor, q.tenant_id, req)?;
    authorize(&actor, "mailboxes:read", Some(tenant)).map_err(|e| application_error(e, req))?;
    Ok(Json(
        state
            .service
            .get_mailbox(tenant, UserId::new(user), mail_domain::MailboxId::new(id))
            .await
            .map_err(|e| application_error(e, req))?,
    ))
}
#[derive(Deserialize)]
struct MailboxPatch {
    name: String,
}
async fn patch_mailbox<R: AdminRepository>(
    State(state): State<AppState<R>>,
    headers: HeaderMap,
    Path((user, id)): Path<(Uuid, Uuid)>,
    Query(q): Query<TenantQuery>,
    Json(input): Json<MailboxPatch>,
) -> Result<StatusCode, ApiError> {
    let req = request_id(&headers);
    let actor = principal(&headers, &state, req).await?;
    let tenant = tenant_for(&actor, q.tenant_id, req)?;
    authorize(&actor, "mailboxes:write", Some(tenant)).map_err(|e| application_error(e, req))?;
    if input.name.is_empty() || input.name.len() > 255 {
        return Err(invalid(
            req,
            "invalid_mailbox_name",
            "Mailbox name is invalid.",
        ));
    }
    state
        .service
        .update_mailbox_name(
            tenant,
            UserId::new(user),
            mail_domain::MailboxId::new(id),
            &input.name,
            expected_version(&headers, req)?,
        )
        .await
        .map_err(|e| application_error(e, req))?;
    Ok(StatusCode::NO_CONTENT)
}
async fn delete_mailbox<R: AdminRepository>(
    State(state): State<AppState<R>>,
    headers: HeaderMap,
    Path((user, id)): Path<(Uuid, Uuid)>,
    Query(q): Query<TenantQuery>,
) -> Result<StatusCode, ApiError> {
    let req = request_id(&headers);
    let actor = principal(&headers, &state, req).await?;
    let tenant = tenant_for(&actor, q.tenant_id, req)?;
    authorize(&actor, "mailboxes:write", Some(tenant)).map_err(|e| application_error(e, req))?;
    state
        .service
        .delete_mailbox(
            tenant,
            UserId::new(user),
            mail_domain::MailboxId::new(id),
            expected_version(&headers, req)?,
        )
        .await
        .map_err(|e| application_error(e, req))?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
struct TokenInput {
    tenant_id: Option<Uuid>,
    display_name: String,
    scopes: Vec<String>,
    expires_at: Option<String>,
    #[serde(default)]
    allowed_source_networks: Vec<String>,
}
#[derive(Serialize)]
struct TokenSecret {
    token: ApiTokenInfo,
    secret: String,
}
async fn create_token<R: AdminRepository>(
    State(state): State<AppState<R>>,
    headers: HeaderMap,
    Json(input): Json<TokenInput>,
) -> Result<(StatusCode, Json<TokenSecret>), ApiError> {
    let req = request_id(&headers);
    let actor = principal(&headers, &state, req).await?;
    let tenant = input.tenant_id.map(TenantId::new).or(actor.tenant_id);
    authorize(&actor, "users:write", tenant).map_err(|e| application_error(e, req))?;
    if input.display_name.is_empty()
        || input.scopes.is_empty()
        || input.scopes.len() > 64
        || input.allowed_source_networks.len() > 64
    {
        return Err(invalid(
            req,
            "invalid_token",
            "Token definition is invalid.",
        ));
    }
    let secret = format!(
        "mailtok_{}{}",
        Uuid::new_v4().simple(),
        Uuid::new_v4().simple()
    );
    let hash = Sha256::digest(secret.as_bytes());
    let token = ApiTokenInfo {
        id: Uuid::new_v4(),
        tenant_id: tenant,
        display_name: input.display_name,
        scopes: input.scopes,
        revoked: false,
    };
    state
        .service
        .create_api_token(
            &token,
            hash.as_slice(),
            actor.token_id,
            input.expires_at.as_deref(),
            &input.allowed_source_networks,
        )
        .await
        .map_err(|e| application_error(e, req))?;
    Ok((StatusCode::CREATED, Json(TokenSecret { token, secret })))
}
async fn list_tokens<R: AdminRepository>(
    State(state): State<AppState<R>>,
    headers: HeaderMap,
    Query(q): Query<ListQuery>,
) -> Result<Json<Vec<ApiTokenInfo>>, ApiError> {
    let req = request_id(&headers);
    let actor = principal(&headers, &state, req).await?;
    let tenant = q.tenant_id.map(TenantId::new).or(actor.tenant_id);
    authorize(&actor, "users:read", tenant).map_err(|e| application_error(e, req))?;
    Ok(Json(
        state
            .service
            .list_api_tokens(tenant, q.limit.unwrap_or(50))
            .await
            .map_err(|e| application_error(e, req))?,
    ))
}
async fn revoke_token<R: AdminRepository>(
    State(state): State<AppState<R>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Query(q): Query<TenantQuery>,
) -> Result<StatusCode, ApiError> {
    let req = request_id(&headers);
    let actor = principal(&headers, &state, req).await?;
    let tenant = q.tenant_id.map(TenantId::new).or(actor.tenant_id);
    authorize(&actor, "users:write", tenant).map_err(|e| application_error(e, req))?;
    state
        .service
        .revoke_api_token(tenant, id)
        .await
        .map_err(|e| application_error(e, req))?;
    Ok(StatusCode::NO_CONTENT)
}
async fn list_audit<R: AdminRepository>(
    State(state): State<AppState<R>>,
    headers: HeaderMap,
    Query(q): Query<ListQuery>,
) -> Result<Json<Vec<mail_storage::AuditRecord>>, ApiError> {
    let req = request_id(&headers);
    let actor = principal(&headers, &state, req).await?;
    let tenant = q.tenant_id.map(TenantId::new).or(actor.tenant_id);
    authorize(&actor, "audit:read", tenant).map_err(|e| application_error(e, req))?;
    Ok(Json(
        state
            .service
            .list_audit(tenant, q.limit.unwrap_or(50))
            .await
            .map_err(|e| application_error(e, req))?,
    ))
}
