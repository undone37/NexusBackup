//! `nexus-web-api`: REST API + embedded SPA (docs/control-plane.md, plan §11).
//!
//! The web-api only writes *intent* into the catalog (config rows, job
//! requests, quorum decisions); the scheduler executes jobs.

use axum::extract::rejection::{JsonRejection, QueryRejection};
use axum::extract::{FromRequest, FromRequestParts, Request};
use axum::http::{header, HeaderValue, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use catalog::Catalog;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};

pub mod auth;
pub mod jobs;
pub mod ops;
pub mod quorum;
pub mod resources;
pub mod spa;
pub mod validate;

/// Runtime configuration. Defaults are the appliance paths; every value can be
/// overridden through an environment variable (used by tests and the lab).
#[derive(Clone, Debug)]
pub struct Config {
    pub listen: std::net::SocketAddr,
    pub catalog: PathBuf,
    pub tls_cert: PathBuf,
    pub tls_key: PathBuf,
    pub setup_done: PathBuf,
    pub metrics_token: PathBuf,
    pub downloads: PathBuf,
}

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        let p = |k: &str, d: &str| PathBuf::from(std::env::var_os(k).unwrap_or_else(|| d.into()));
        Ok(Config {
            listen: std::env::var("NEXUS_WEBAPI_LISTEN")
                .unwrap_or_else(|_| "[::]:8443".into())
                .parse()?,
            catalog: p("NEXUS_CATALOG", "/var/lib/nexus/catalog/catalog.db"),
            tls_cert: p("NEXUS_TLS_CERT", "/etc/nexus/tls/cert.pem"),
            tls_key: p("NEXUS_TLS_KEY", "/etc/nexus/tls/key.pem"),
            setup_done: p("NEXUS_SETUP_DONE", "/var/lib/nexus/setup-done"),
            metrics_token: p("NEXUS_METRICS_TOKEN", "/etc/nexus/metrics-token"),
            downloads: p("NEXUS_DOWNLOADS", "/var/lib/nexus/downloads"),
        })
    }
}

pub struct AppState {
    pub cat: Catalog,
    /// `None` disables `/metrics` (no token file).
    pub metrics_token: Option<String>,
    pub downloads: PathBuf,
    pub limiter: Mutex<auth::Limiter>,
    pub failed_logins: AtomicU64,
}

impl AppState {
    pub fn new(cat: Catalog, metrics_token: Option<String>, downloads: PathBuf) -> Arc<Self> {
        Arc::new(AppState {
            cat,
            metrics_token,
            downloads,
            limiter: Mutex::new(auth::Limiter::default()),
            failed_logins: AtomicU64::new(0),
        })
    }

    /// Appends an audit entry. Must not be called while holding `cat.conn()`.
    pub fn audit(&self, actor: &str, action: &str, target: &str, details: serde_json::Value) -> Result<(), ApiError> {
        self.cat.audit(actor, action, target, &details)?;
        Ok(())
    }
}

pub type St = Arc<AppState>;

// ---------------------------------------------------------------- errors

#[derive(Debug)]
pub struct ApiError(pub StatusCode, pub String);

pub type ApiResult<T> = Result<T, ApiError>;

impl ApiError {
    pub fn bad(m: impl Into<String>) -> Self {
        ApiError(StatusCode::BAD_REQUEST, m.into())
    }
    pub fn unauthorized() -> Self {
        ApiError(StatusCode::UNAUTHORIZED, "not logged in".into())
    }
    pub fn forbidden() -> Self {
        ApiError(StatusCode::FORBIDDEN, "forbidden".into())
    }
    pub fn not_found() -> Self {
        ApiError(StatusCode::NOT_FOUND, "not found".into())
    }
    pub fn conflict(m: impl Into<String>) -> Self {
        ApiError(StatusCode::CONFLICT, m.into())
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(json!({ "error": self.1 }))).into_response()
    }
}

impl From<catalog::rusqlite::Error> for ApiError {
    fn from(e: catalog::rusqlite::Error) -> Self {
        use catalog::rusqlite::{Error, ErrorCode};
        match &e {
            Error::SqliteFailure(f, _) if f.code == ErrorCode::ConstraintViolation => {
                ApiError::conflict("conflicts with existing data (duplicate name or still referenced)")
            }
            Error::QueryReturnedNoRows => ApiError::not_found(),
            _ => {
                eprintln!("<3>web-api: database error: {e}");
                ApiError(StatusCode::INTERNAL_SERVER_ERROR, "internal error".into())
            }
        }
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(e: anyhow::Error) -> Self {
        eprintln!("<3>web-api: {e:#}");
        ApiError(StatusCode::INTERNAL_SERVER_ERROR, "internal error".into())
    }
}

// ---------------------------------------------------------------- extractors

/// `Json` with `{error}` bodies on rejection (wrong content type, unknown
/// fields, bad types …). Requiring `application/json` also keeps HTML forms
/// from posting cross-site.
pub struct J<T>(pub T);

impl<S: Send + Sync, T: serde::de::DeserializeOwned> FromRequest<S> for J<T> {
    type Rejection = ApiError;
    async fn from_request(req: Request, state: &S) -> Result<Self, ApiError> {
        match Json::<T>::from_request(req, state).await {
            Ok(Json(v)) => Ok(J(v)),
            Err(e @ JsonRejection::MissingJsonContentType(_)) => {
                Err(ApiError(StatusCode::UNSUPPORTED_MEDIA_TYPE, e.body_text()))
            }
            Err(e) => Err(ApiError::bad(e.body_text())),
        }
    }
}

pub struct Q<T>(pub T);

impl<S: Send + Sync, T: serde::de::DeserializeOwned> FromRequestParts<S> for Q<T> {
    type Rejection = ApiError;
    async fn from_request_parts(parts: &mut axum::http::request::Parts, state: &S) -> Result<Self, ApiError> {
        axum::extract::Query::<T>::from_request_parts(parts, state)
            .await
            .map(|q| Q(q.0))
            .map_err(|e: QueryRejection| ApiError::bad(e.body_text()))
    }
}

// ---------------------------------------------------------------- helpers

pub fn sha256_hex(b: &[u8]) -> String {
    Sha256::digest(b).iter().map(|b| format!("{b:02x}")).collect()
}

/// 256 bit from the OS CSPRNG, hex encoded.
pub fn random_hex() -> String {
    rand::random::<[u8; 32]>().iter().map(|b| format!("{b:02x}")).collect()
}

pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

// ---------------------------------------------------------------- router

pub const CSP: &str = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'";

async fn security_headers(req: Request, next: Next) -> Response {
    let api = req.uri().path().starts_with("/api/");
    let mut res = next.run(req).await;
    let h = res.headers_mut();
    h.insert(header::CONTENT_SECURITY_POLICY, HeaderValue::from_static(CSP));
    h.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    h.insert(header::REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    h.insert(
        header::STRICT_TRANSPORT_SECURITY,
        HeaderValue::from_static("max-age=31536000"),
    );
    h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    if api || !h.contains_key(header::CACHE_CONTROL) {
        h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    }
    res
}

async fn api_not_found() -> ApiError {
    ApiError::not_found()
}

pub fn router(st: St) -> Router {
    use auth::*;
    use jobs::*;
    use ops::*;
    use quorum::*;
    use resources::*;
    let api = Router::new()
        .route("/health", get(health))
        .route("/metrics", get(metrics))
        .route("/auth/login", post(login))
        .route("/auth/logout", post(logout))
        .route("/auth/me", get(me))
        .route("/tenants", get(list_tenants).post(create_tenant))
        .route("/tenants/{name}", put(update_tenant).delete(delete_tenant))
        .route("/sources", get(list_sources).post(create_source))
        .route("/sources/{id}", put(update_source).delete(delete_source))
        .route("/policies", get(list_policies).post(create_policy))
        .route("/policies/{id}", put(update_policy).delete(delete_policy))
        .route("/groups", get(list_groups).post(create_group))
        .route("/groups/{id}", put(update_group).delete(delete_group))
        .route("/users", get(list_users).post(create_user))
        .route("/users/{id}", put(update_user))
        .route("/snapshots", get(list_snapshots))
        .route("/jobs", get(list_jobs).post(create_job))
        .route("/jobs/{id}", get(get_job))
        .route("/jobs/{id}/cancel", post(cancel_job))
        .route("/downloads/{token}", get(download))
        .route("/quorum", get(list_quorum))
        .route("/quorum/{id}/approve", post(approve))
        .route("/quorum/{id}/reject", post(reject))
        .route("/audit", get(list_audit))
        .route("/audit/verify", get(verify_audit))
        .route("/alerts", get(list_alerts))
        .route("/alerts/{id}/ack", post(ack_alert))
        .fallback(api_not_found);
    Router::new()
        .nest("/api/v1", api)
        .route("/health", get(health))
        .route("/metrics", get(metrics))
        .fallback(spa::serve)
        .layer(axum::extract::DefaultBodyLimit::max(1 << 20))
        .layer(middleware::from_fn(security_headers))
        .with_state(st)
}
