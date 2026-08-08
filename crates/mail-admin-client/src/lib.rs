#![forbid(unsafe_code)]

use reqwest::{Client as HttpClient, Method, StatusCode};
use serde_json::Value;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ClientError {
    #[error("invalid API base URL")]
    InvalidBaseUrl,
    #[error("HTTP transport failed: {0}")]
    Transport(#[from] reqwest::Error),
    #[error("API returned HTTP {status}: {problem}")]
    Api { status: StatusCode, problem: Value },
}

pub struct Client {
    http: HttpClient,
    base_url: String,
    token: String,
}

impl Client {
    pub fn new(base_url: &str, token: String) -> Result<Self, ClientError> {
        let base_url = base_url.trim_end_matches('/');
        if !base_url.starts_with("https://")
            && !base_url.starts_with("http://127.0.0.1")
            && !base_url.starts_with("http://[::1]")
        {
            return Err(ClientError::InvalidBaseUrl);
        }
        Ok(Self {
            http: HttpClient::new(),
            base_url: base_url.to_owned(),
            token,
        })
    }

    pub async fn list(
        &self,
        resource: &str,
        tenant_id: Option<&str>,
    ) -> Result<Value, ClientError> {
        let mut request = self
            .http
            .request(Method::GET, format!("{}/api/v1/{resource}", self.base_url))
            .bearer_auth(&self.token);
        if let Some(tenant_id) = tenant_id {
            request = request.query(&[("tenant_id", tenant_id)]);
        }
        self.send(request).await
    }

    pub async fn create(&self, resource: &str, body: &Value) -> Result<Value, ClientError> {
        let request = self
            .http
            .request(Method::POST, format!("{}/api/v1/{resource}", self.base_url))
            .bearer_auth(&self.token)
            .header("Idempotency-Key", uuid::Uuid::new_v4().to_string())
            .json(body);
        self.send(request).await
    }

    pub async fn get(&self, path: &str, tenant_id: Option<&str>) -> Result<Value, ClientError> {
        self.request(Method::GET, path, tenant_id, None, None, false)
            .await
    }

    pub async fn database_check(&self) -> Result<Value, ClientError> {
        self.get("/api/v1/database/check", None).await
    }

    pub async fn migration_status(&self) -> Result<Value, ClientError> {
        self.get("/api/v1/migrations/status", None).await
    }
    pub async fn patch(
        &self,
        path: &str,
        tenant_id: Option<&str>,
        version: &str,
        body: &Value,
    ) -> Result<Value, ClientError> {
        self.request(
            Method::PATCH,
            path,
            tenant_id,
            Some(body),
            Some(version),
            false,
        )
        .await
    }
    pub async fn delete(
        &self,
        path: &str,
        tenant_id: Option<&str>,
        version: Option<&str>,
    ) -> Result<Value, ClientError> {
        self.request(Method::DELETE, path, tenant_id, None, version, false)
            .await
    }
    pub async fn action(
        &self,
        path: &str,
        tenant_id: Option<&str>,
        version: Option<&str>,
        body: Option<&Value>,
    ) -> Result<Value, ClientError> {
        self.request(Method::POST, path, tenant_id, body, version, true)
            .await
    }

    async fn request(
        &self,
        method: Method,
        path: &str,
        tenant_id: Option<&str>,
        body: Option<&Value>,
        version: Option<&str>,
        idempotent: bool,
    ) -> Result<Value, ClientError> {
        let mut request = self
            .http
            .request(method, format!("{}{}", self.base_url, path))
            .bearer_auth(&self.token);
        if let Some(tenant_id) = tenant_id {
            request = request.query(&[("tenant_id", tenant_id)]);
        }
        if let Some(body) = body {
            request = request.json(body);
        }
        if let Some(version) = version {
            request = request.header("If-Match", version);
        }
        if idempotent {
            request = request.header("Idempotency-Key", uuid::Uuid::new_v4().to_string());
        }
        self.send(request).await
    }

    async fn send(&self, request: reqwest::RequestBuilder) -> Result<Value, ClientError> {
        let response = request.send().await?;
        let status = response.status();
        let bytes = response.bytes().await?;
        let body = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes)
                .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()))
        };
        if status.is_success() {
            Ok(body)
        } else {
            Err(ClientError::Api {
                status,
                problem: body,
            })
        }
    }
}
