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
use catalog::secret::{SealKey, TotpKey};
use catalog::Catalog;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};

pub mod access;
pub mod activation;
pub mod agents;
pub mod alerts;
pub mod approvals;
pub mod auth;
pub mod certs;
pub mod changes;
pub mod config_backup;
pub mod console;
pub mod dashboard;
pub mod diag;
pub mod endpoint;
pub mod firewall;
pub mod fleet;
pub mod forwarding;
pub mod hardware;
pub mod holds;
pub mod impersonate;
pub mod incident;
pub mod inventory;
pub mod jobs;
pub mod offsite;
pub mod oidc;
pub mod ops;
pub mod passkeys;
pub mod plugins;
pub mod quorum;
pub mod recovery;
pub mod replication;
pub mod reports;
pub mod rescue;
pub mod resources;
pub mod restores;
pub mod runctl;
pub mod search;
pub mod selection;
pub mod settings;
pub mod spa;
pub mod storage;
pub mod tenancy;
pub mod tenant_key;
pub mod tenants;
pub mod tls;
pub mod tokens;
pub mod validate;
pub mod vault;

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
    /// web-api-only key for TOTP seeds (0600 nexus-webapi)
    pub totp_key: PathBuf,
    /// scheduler public key: source/offsite secrets are sealed to it
    pub secrets_pub: PathBuf,
    /// nexus-replicad: socket, replication CA certificate, sealing public key
    /// (docs/replication.md)
    pub replicad_socket: PathBuf,
    pub replication_ca: PathBuf,
    pub replicad_pub: PathBuf,
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
            totp_key: p("NEXUS_TOTP_KEY", "/var/lib/nexus/webapi/totp.key"),
            secrets_pub: p("NEXUS_SECRETS_PUB", "/var/lib/nexus/catalog/secrets.pub"),
            replicad_socket: p("NEXUS_REPLICAD_SOCKET", "/run/nexus-replicad/replicad.sock"),
            replication_ca: p("NEXUS_REPLICATION_CA", "/run/nexus-replicad/ca.pem"),
            replicad_pub: p("NEXUS_REPLICAD_PUB", "/run/nexus-replicad/seal.pub"),
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
    /// encrypts / decrypts `users.totp_secret`
    pub totp: TotpKey,
    /// published scheduler public key; read on every secret write (the
    /// scheduler may start after the web-api). `None` = secret writes refused.
    pub secrets_pub: Option<PathBuf>,
    /// replication: replicad paths, per-peer limits and sessions
    pub repl: crate::replication::ReplState,
    /// plugin staging / project keys / install dir (default: env or appliance paths)
    pub plugins: std::sync::OnceLock<crate::plugins::PluginPaths>,
    /// OS update control dir (default: env `NEXUS_UPDATE_DIR` or /var/lib/nexus/update)
    pub update_dir: std::sync::OnceLock<PathBuf>,
    /// diagnostics control dir (default: env `NEXUS_DIAG_DIR` or /var/lib/nexus/diag)
    pub diag_dir: std::sync::OnceLock<PathBuf>,
    /// nexus-config-backup control dir (default: env `NEXUS_CONFIG_BACKUP_DIR` or /var/lib/nexus/config-backup)
    pub config_backup_dir: std::sync::OnceLock<PathBuf>,
    /// console unlock codes (default: env `NEXUS_CONSOLE_UNLOCK_DIR` or /var/lib/nexus/console-unlock)
    pub console_dir: std::sync::OnceLock<PathBuf>,
    /// nexus-disks control dir (default: env `NEXUS_DISKS_DIR` or /var/lib/nexus/disks)
    pub disks_dir: std::sync::OnceLock<PathBuf>,
    /// nexus-nft-sync status file (default: env `NEXUS_NFT_STATUS` or /run/nexus-nft-status/status.json)
    pub nft_status: std::sync::OnceLock<PathBuf>,
    /// `GET /dashboard` answers, ≤ 60 s old
    pub dashboard: crate::dashboard::Cache,
    /// OIDC discovery/JWKS cache and pending logins
    pub oidc: crate::oidc::OidcState,
    /// web certificate files and the nexus-tls request dir (default: appliance paths)
    pub tls: std::sync::OnceLock<webtls::Paths>,
}

impl AppState {
    /// Production / integration tests: everything including replication serving.
    pub fn with_replication(
        cat: Catalog,
        metrics_token: Option<String>,
        downloads: PathBuf,
        totp: TotpKey,
        secrets_pub: Option<PathBuf>,
        repl: crate::replication::ReplPaths,
    ) -> Arc<Self> {
        Arc::new(AppState {
            cat,
            metrics_token,
            downloads,
            limiter: Mutex::new(auth::Limiter::default()),
            failed_logins: AtomicU64::new(0),
            totp,
            secrets_pub,
            repl: crate::replication::ReplState::new(repl),
            plugins: std::sync::OnceLock::new(),
            update_dir: std::sync::OnceLock::new(),
            diag_dir: std::sync::OnceLock::new(),
            config_backup_dir: std::sync::OnceLock::new(),
            console_dir: std::sync::OnceLock::new(),
            disks_dir: std::sync::OnceLock::new(),
            nft_status: std::sync::OnceLock::new(),
            dashboard: Default::default(),
            oidc: Default::default(),
            tls: std::sync::OnceLock::new(),
        })
    }

    /// Tests / fuzzing: ephemeral TOTP key, no scheduler public key.
    pub fn new(cat: Catalog, metrics_token: Option<String>, downloads: PathBuf) -> Arc<Self> {
        Self::with_keys(cat, metrics_token, downloads, TotpKey::generate(), None)
    }

    pub fn with_keys(
        cat: Catalog,
        metrics_token: Option<String>,
        downloads: PathBuf,
        totp: TotpKey,
        secrets_pub: Option<PathBuf>,
    ) -> Arc<Self> {
        Self::with_replication(
            cat,
            metrics_token,
            downloads,
            totp,
            secrets_pub,
            crate::replication::ReplPaths::default(),
        )
    }

    /// The scheduler's public key, or 503 if it has not been published yet.
    pub fn seal_key(&self) -> ApiResult<SealKey> {
        let unavailable = |why: String| {
            eprintln!("<4>web-api: {why}");
            ApiError(
                StatusCode::SERVICE_UNAVAILABLE,
                "cannot store secrets: the scheduler has not published its public key yet (start nexus-scheduler and retry)"
                    .into(),
            )
        };
        let p = self
            .secrets_pub
            .as_ref()
            .ok_or_else(|| unavailable("no scheduler public key configured".into()))?;
        SealKey::load(p).map_err(|e| unavailable(format!("{e:#}")))
    }

    pub fn plugin_paths(&self) -> crate::plugins::PluginPaths {
        self.plugins.get_or_init(Default::default).clone()
    }

    /// Appends an audit entry. Must not be called while holding `cat.conn()`.
    /// During an API token request the token's user is recorded as
    /// `<user> via token <name>`.
    pub fn audit(&self, actor: &str, action: &str, target: &str, details: serde_json::Value) -> Result<(), ApiError> {
        let actor = crate::tokens::audit_actor(actor);
        self.cat
            .audit(&crate::impersonate::audit_actor(&actor), action, target, &details)?;
        Ok(())
    }
}

pub type St = Arc<AppState>;

/// Re-encrypts legacy plaintext TOTP seeds (users and pending `user.update`
/// quorum params) with the web-api key; one audit entry per changed row.
pub fn migrate_totp_seeds(st: &AppState) -> anyhow::Result<usize> {
    use catalog::rusqlite::params;
    use catalog::secret::is_encrypted_totp;
    let users: Vec<(i64, String, String)> = {
        let c = st.cat.conn();
        let mut q = c.prepare("SELECT id, name, totp_secret FROM users")?;
        let r = q.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
        r.collect::<Result<_, _>>()?
    };
    let mut n = 0;
    // an empty seed belongs to an account pending activation (no authenticator yet)
    for (id, name, seed) in users
        .into_iter()
        .filter(|u| !u.2.is_empty() && !is_encrypted_totp(&u.2))
    {
        let enc = st.totp.encrypt(&name, &seed)?;
        let changed = st.cat.conn().execute(
            "UPDATE users SET totp_secret = ?1 WHERE id = ?2 AND totp_secret = ?3",
            params![enc, id, seed],
        )?;
        if changed == 1 {
            st.cat.audit(
                "web-api",
                "secret.migrate",
                &format!("user/{name}"),
                &json!({"encrypted": ["totp_secret"]}),
            )?;
            n += 1;
        }
    }
    let pending: Vec<(i64, String)> = {
        let c = st.cat.conn();
        let mut q = c.prepare("SELECT id, params FROM quorum WHERE state = 'pending' AND action = 'user.update'")?;
        let r = q.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?;
        r.collect::<Result<_, _>>()?
    };
    for (id, raw) in pending {
        let Ok(mut p) = serde_json::from_str::<serde_json::Value>(&raw) else {
            continue;
        };
        let (Some(seed), Some(name)) = (p["totp_secret"].as_str(), p["name"].as_str()) else {
            continue;
        };
        if is_encrypted_totp(seed) {
            continue;
        }
        p["totp_secret"] = json!(st.totp.encrypt(name, seed)?);
        let changed = st.cat.conn().execute(
            "UPDATE quorum SET params = ?1 WHERE id = ?2 AND params = ?3 AND state = 'pending'",
            params![p.to_string(), id, raw],
        )?;
        if changed == 1 {
            st.cat.audit(
                "web-api",
                "secret.migrate",
                &format!("quorum/{id}"),
                &json!({"encrypted": ["totp_secret"]}),
            )?;
            n += 1;
        }
    }
    Ok(n)
}

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

/// Replication connections (client certificate / enrollment ALPN) reach only
/// `/replication/v1/*`; ordinary connections never reach it (docs/replication.md §3).
async fn connection_scope(req: Request, next: Next) -> Response {
    let repl = req.uri().path().starts_with("/replication/v1/");
    match (req.extensions().get::<tls::ReplConn>().is_some(), repl) {
        (true, false) => ApiError::not_found().into_response(),
        (false, true) => ApiError(
            StatusCode::FORBIDDEN,
            "replication requests need the replication protocol and a client certificate".into(),
        )
        .into_response(),
        _ => next.run(req).await,
    }
}

pub fn router(st: St) -> Router {
    use crate::replication as repl;
    use agents::*;
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
        .route("/auth/activate/begin", post(activation::begin))
        .route("/auth/activate/complete", post(activation::complete))
        .route("/auth/activate/passkey", post(activation::passkey_options))
        .route("/auth/tokens", get(tokens::list).post(tokens::create))
        .route("/auth/tokens/{id}", axum::routing::delete(tokens::revoke))
        .route("/certificate", get(certs::get_status))
        .route("/certificate/csr", post(certs::csr))
        .route("/certificate/install", post(certs::install))
        .route("/certificate/revert", post(certs::revert))
        .route("/auth/oidc", get(oidc::info))
        .route("/auth/oidc/start", get(oidc::start))
        .route("/auth/oidc/callback", get(oidc::callback))
        .route("/dashboard", get(dashboard::dashboard))
        .route("/storage", get(storage::storage))
        .route("/reports/{file}", get(reports::export))
        .route(
            "/settings/reports",
            get(reports::get_scheduled).put(reports::put_scheduled),
        )
        .route("/settings/reports/{name}/send", post(reports::send_now))
        .route("/tenants/{name}/quota", put(storage::put_quota))
        .route(
            "/tenants/{tenant}/recovery-key",
            get(tenant_key::get).post(tenant_key::request_key),
        )
        .route("/tenants/{tenant}/recovery-key/{id}/show", post(tenant_key::show))
        .route("/settings/anomaly", get(storage::get_anomaly).put(storage::put_anomaly))
        .route("/settings/oidc", get(oidc::get_settings).put(oidc::put_settings))
        .route("/settings/oidc/test", post(oidc::test_settings))
        .route("/settings/alerts", get(settings::get_alerts).put(settings::put_alerts))
        .route("/settings/alerts/test", post(settings::test_alerts))
        .route("/ssh-keys", get(settings::list_ssh_keys))
        .route("/ssh-keys/{name}/rotate", post(settings::rotate_ssh_key))
        .route("/ssh-keys/{name}/retire", post(settings::retire_ssh_key))
        .route("/updates", get(settings::get_updates))
        .route("/updates/check", post(settings::check_updates))
        .route("/updates/apply", post(settings::apply_update))
        .route(
            "/updates/registry",
            get(settings::get_registry_auth)
                .put(settings::put_registry_auth)
                .delete(settings::delete_registry_auth),
        )
        .route("/settings/config-backup", get(config_backup::get))
        .route("/settings/config-backup/run", post(config_backup::run))
        .route("/settings/config-backup/download", get(config_backup::download))
        .route("/diagnostics", get(diag::list))
        .route("/diagnostics/checks", post(diag::run_checks))
        .route("/diagnostics/bundle", post(diag::create_bundle))
        .route("/diagnostics/{id}", get(diag::get_one))
        .route("/diagnostics/{id}/download", get(diag::download))
        .route(
            "/settings/approvals",
            get(approvals::get_approvals).put(approvals::set_approvals),
        )
        .route("/gc/pending", get(approvals::gc_pending))
        .route("/gc/approve-large", post(approvals::gc_approve_large))
        .route("/tenants", get(list_tenants).post(create_tenant))
        .route("/tenants/attach", post(offsite::request_attach))
        .route("/tenants/attach/{id}/run", post(offsite::run_attach))
        .route("/tenants/{name}", put(update_tenant).delete(delete_tenant))
        .route("/sources", get(list_sources).post(create_source))
        .route("/sources/{id}", put(update_source).delete(delete_source))
        .route("/sources/{id}/inventory", get(inventory::list))
        .route("/policies", get(list_policies).post(create_policy))
        .route("/policies/{id}", put(update_policy).delete(delete_policy))
        .route("/groups", get(list_groups).post(create_group))
        .route("/groups/{id}", put(update_group).delete(delete_group))
        .route("/groups/{id}/pause", post(runctl::pause_group))
        .route("/groups/{id}/index-files", put(search::put_index_files))
        .route("/search", post(search::search))
        .route("/groups/{id}/resume", post(runctl::resume_group))
        .route("/sources/{id}/maintenance", post(runctl::start_maintenance))
        .route("/sources/{id}/maintenance/end", post(runctl::end_maintenance))
        .route("/users", get(list_users).post(create_user))
        .route("/users/{id}", put(update_user))
        .route("/agents", get(list_agents).post(create_agent))
        .route("/agents/{id}", axum::routing::delete(delete_agent))
        .route("/agents/{id}/token", post(new_agent_token))
        .route("/agents/{id}/enroll", post(enroll_agent))
        // Phase 19a: bare-metal recovery / P2V (rescue.rs)
        .route("/agents/{id}/rescue", post(crate::rescue::create))
        .route("/agents/{id}/p2v", post(crate::rescue::p2v))
        .route("/rescue", get(crate::rescue::list))
        .route("/rescue/checkin", post(crate::rescue::checkin))
        .route("/rescue/{id}", get(crate::rescue::get))
        .route("/rescue/{id}/start", post(crate::rescue::start))
        .route("/rescue/{id}/cancel", post(crate::rescue::cancel))
        .route("/agents/{id}/limits", axum::routing::put(selection::set_agent_limits))
        .route("/agents/bulk", post(fleet::bulk_agents))
        .route("/fleets", get(fleet::list_fleets).post(fleet::create_fleet))
        .route("/fleets/{id}", axum::routing::delete(fleet::revoke_fleet))
        .route("/fleets/{id}/scan", post(fleet::scan_fleet))
        .route("/fleet/candidates", get(fleet::list_candidates))
        .route("/fleet/candidates/{id}/accept", post(fleet::accept_candidate))
        .route("/fleet/candidates/{id}/reject", post(fleet::reject_candidate))
        .route("/agents/{id}/ui-policy", axum::routing::put(endpoint::set_ui_policy))
        .route("/agents/{id}/laptop", axum::routing::put(endpoint::set_laptop))
        .route("/agents/{id}/sessions", get(endpoint::agent_sessions))
        .route("/snapshots", get(list_snapshots))
        .route("/snapshots/diff", post(changes::diff))
        .route(
            "/snapshots/{tenant}/{source}/{time}/anomaly/clear",
            post(changes::clear),
        )
        .route("/stats/trends", get(changes::trends))
        .route("/restore-tests", get(recovery::list_tests))
        .route("/restore-tests/schedules", get(recovery::list_schedules))
        .route(
            "/restore-tests/schedules/{group_id}",
            put(recovery::put_schedule).delete(recovery::delete_schedule),
        )
        .route("/recovery-plans", get(recovery::list_plans).post(recovery::create_plan))
        .route(
            "/recovery-plans/{id}",
            put(recovery::update_plan).delete(recovery::delete_plan),
        )
        .route("/recovery-plans/{id}/readiness", post(recovery::readiness))
        .route("/recovery-plans/{id}/test", post(recovery::test_run))
        .route("/recovery-plans/{id}/execute", post(recovery::execute))
        .route("/recovery-plans/{id}/runs", get(recovery::runs))
        .route("/recovery-runs/{id}/report", get(recovery::report))
        .route(
            "/snapshots/{tenant}/{source}/{time}",
            axum::routing::delete(delete_snapshot),
        )
        .route("/jobs", get(list_jobs).post(create_job))
        .route("/restores", post(restores::restore_many))
        .route("/jobs/{id}", get(get_job))
        .route("/jobs/{id}/cancel", post(cancel_job))
        .route("/downloads/{token}", get(download))
        .route("/quorum", get(list_quorum))
        .route("/console/unlock", get(console::list).post(console::request_unlock))
        .route("/console/unlock/{id}", axum::routing::delete(console::revoke))
        .route("/console/unlock/{id}/code", post(console::fetch_code))
        .route("/quorum/{id}/approve", post(approve))
        .route("/quorum/{id}/reject", post(reject))
        .route("/audit", get(list_audit))
        .route("/audit/verify", get(verify_audit))
        .route("/audit.csv", get(export_audit))
        .route("/audit/forwarding", get(forwarding::status))
        .route(
            "/settings/forwarding",
            get(forwarding::get_settings).put(forwarding::put_settings),
        )
        .route("/settings/forwarding/test", post(forwarding::test))
        .route("/alerts", get(alerts::list_alerts))
        .route("/alerts/{id}/ack", post(alerts::ack_alert))
        .route("/alerts/{id}/resolve", post(alerts::resolve_alert))
        .route(
            "/plugins",
            get(plugins::list_plugins)
                .post(plugins::upload_plugin)
                .layer(axum::extract::DefaultBodyLimit::max(plugins::MAX_UPLOAD)),
        )
        .route("/plugins/{id}", axum::routing::delete(plugins::delete_plugin))
        .route("/plugins/{id}/enable", post(plugins::enable_plugin))
        .route("/plugins/{id}/disable", post(plugins::disable_plugin))
        .route("/plugins/{id}/activate", post(plugins::activate_plugin))
        .route("/plugin-keys", get(plugins::list_keys).post(plugins::add_key))
        .route("/plugin-keys/{fp}", axum::routing::delete(plugins::delete_key))
        .route("/replication/peers", get(repl::list_peers).post(repl::create_peer))
        .route("/replication/peers/{id}", axum::routing::delete(repl::delete_peer))
        .route("/replication/peers/{id}/export-keys", post(repl::export_keys))
        .route(
            "/replication/sources",
            get(repl::list_sources).post(repl::create_source),
        )
        .route(
            "/replication/sources/{id}",
            put(repl::update_source).delete(repl::delete_source),
        )
        .route("/replication/sources/{id}/enroll", post(repl::enroll_source))
        .route("/replication/sources/{id}/sync", post(repl::sync_source))
        .route("/replication/sources/{id}/close", post(repl::close_source))
        .route("/replication/sources/{id}/reopen", post(repl::reopen_source))
        .merge(access::routes())
        .merge(passkeys::routes())
        .merge(firewall::routes())
        .merge(holds::routes())
        .merge(hardware::routes())
        .merge(tenants::routes())
        .merge(tenancy::routes())
        .merge(vault::routes())
        .merge(incident::routes())
        .fallback(api_not_found);
    // peer API: only on replication TLS connections (see `connection_scope`)
    let peer = Router::new()
        .route("/enroll", post(repl::enroll))
        .route("/peer", get(repl::peer_info))
        .route("/session", post(repl::session_start))
        .route("/session/{id}/end", post(repl::session_end))
        .route("/tenants/{tenant}/keys", get(repl::tenant_keys))
        .route("/tenants/{tenant}/snapshots", get(repl::list_remote_snapshots))
        .route("/tenants/{tenant}/holds", get(repl::remote_holds))
        .route(
            "/tenants/{tenant}/snapshots/{source}/{time}/{file}",
            get(repl::snapshot_file),
        )
        .route("/tenants/{tenant}/chunks", post(repl::chunks))
        .fallback(api_not_found);
    Router::new()
        .nest("/api/v1", api)
        .nest(repl_proto::PREFIX, peer)
        .route("/health", get(health))
        .route("/metrics", get(metrics))
        .fallback(spa::serve)
        .layer(axum::extract::DefaultBodyLimit::max(1 << 20))
        .layer(middleware::from_fn_with_state(st.clone(), tokens::layer))
        .layer(middleware::from_fn(impersonate::layer))
        .layer(middleware::from_fn(connection_scope))
        .layer(middleware::from_fn(security_headers))
        .with_state(st)
}
