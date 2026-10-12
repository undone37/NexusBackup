//! API tokens (docs/control-plane.md "API tokens", catalog v15).
//!
//! `Authorization: Bearer nxt_<prefix>_<secret>` instead of the session cookie,
//! for scripts and monitoring. No CSRF header: browsers never send this header
//! on their own. A token
//! - belongs to a user and stops working when the user is disabled, pending
//!   activation or deleted, and when it expires (mandatory, at most 365 days);
//! - has a scope: `read` (GET only) or `operator` (also start and cancel jobs,
//!   pause/resume groups, maintenance, acknowledge alerts, sync replication).
//!   The effective role is the lower of the user's role and the scope: an admin's
//!   operator token acts as operator, a security officer's tokens are read-only;
//! - reaches only the endpoints on [`allowed`]: an allow-list, so a new
//!   endpoint is closed to tokens until it is added here. Never on the list:
//!   approvals, settings, users, tokens, plugins, certificates, downloads,
//!   replication keys; job kinds that hand out data ([`DENIED_KINDS`]) are refused.
//!
//! Only SHA-256 of the 256-bit secret is stored: the secret is random and long,
//! so a fast hash is enough (no password KDF). It is shown once, at creation.
//! Audit entries written during a token request name the actor
//! `<user> via token <name>` ([`audit_actor`]).

use crate::auth::{reauth, ClientIp, Ctx, User, USER_COLS};
use crate::{ct_eq, random_hex, sha256_hex, validate, ApiError, ApiResult, St, J, Q};
use axum::extract::{Path, Request, State};
use axum::http::{header, Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use catalog::rusqlite::{params, OptionalExtension};
use serde::Deserialize;
use serde_json::{json, Value};
use std::borrow::Cow;
use std::net::SocketAddr;

pub const PREFIX: &str = "nxt_";
pub const MAX_DAYS: i64 = 365;
pub const MAX_PER_USER: i64 = 20;
/// `last_used` / `last_ip` are written at most this often per token
const TOUCH_SECS: i64 = 60;
/// OIDC accounts cannot re-authenticate here: their session must be this fresh
const OIDC_FRESH_SECS: i64 = 15 * 60;
/// job kinds that hand data out of the appliance: never through a token
pub const DENIED_KINDS: &[&str] = &["files_get", "plugin_mount"];

/// The token of a token-authenticated request (`Ctx::token`).
#[derive(Clone, Debug)]
pub struct TokenRef {
    pub id: i64,
    pub name: String,
    pub scope: String,
}

/// Request extension set by [`layer`]: the authenticated (role-capped) user.
#[derive(Clone)]
pub struct TokenAuth {
    pub user: User,
    pub token: TokenRef,
}

tokio::task_local! {
    /// (user name, token name) while a token request runs
    static VIA: (String, String);
}

/// The audit actor: `alice via token ci` for the token's user during a token request.
pub fn audit_actor(actor: &str) -> Cow<'_, str> {
    VIA.try_with(|(user, token)| (actor == user).then(|| format!("{user} via token {token}")))
        .ok()
        .flatten()
        .map_or(Cow::Borrowed(actor), Cow::Owned)
}

const READ: &[&str] = &[
    "/auth/me",
    "/dashboard",
    "/storage",
    "/hardware",
    "/tenants",
    "/sources",
    "/sources/*/inventory",
    "/policies",
    "/groups",
    "/agents",
    "/snapshots",
    "/holds",
    "/jobs",
    "/jobs/*",
    "/alerts",
    "/quorum",
    "/audit",
    "/audit/verify",
    "/replication/peers",
    "/replication/sources",
    "/plugins",
];

const OPERATE: &[&str] = &[
    "/jobs",
    "/jobs/*/cancel",
    "/groups/*/pause",
    "/groups/*/resume",
    "/sources/*/maintenance",
    "/sources/*/maintenance/end",
    "/alerts/*/ack",
    "/replication/sources/*/sync",
];

fn matches(pattern: &str, path: &str) -> bool {
    let (mut p, mut q) = (pattern.split('/'), path.split('/'));
    loop {
        match (p.next(), q.next()) {
            (None, None) => return true,
            (Some("*"), Some(s)) if !s.is_empty() => {}
            (Some(a), Some(b)) if a == b => {}
            _ => return false,
        }
    }
}

/// Whether a token with `writes` (operator scope and role) may call `method path`
/// (`path` below `/api/v1`).
pub fn allowed(writes: bool, method: &Method, path: &str) -> bool {
    match *method {
        Method::GET | Method::HEAD => READ.iter().any(|p| matches(p, path)),
        Method::POST if writes => OPERATE.iter().any(|p| matches(p, path)),
        _ => false,
    }
}

/// (effective role, may write) for a scope and the user's role.
fn effective(scope: &str, role: &str) -> (String, bool) {
    match (scope, role) {
        ("operator", "admin" | "operator") => ("operator".into(), true),
        ("operator", "tenant_user") => (role.into(), true),
        _ => (role.into(), false),
    }
}

fn denied(code: StatusCode, m: &str) -> Response {
    ApiError(code, m.into()).into_response()
}

/// Middleware: authenticates `Bearer nxt_…` requests, enforces the allow-list
/// and runs the handler with [`TokenAuth`] in the extensions. Other requests
/// (cookies, the metrics bearer token) pass untouched.
pub async fn layer(State(st): State<St>, mut req: Request, next: Next) -> Response {
    let Some(token) = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|t| t.starts_with(PREFIX))
        .map(str::to_owned)
    else {
        return next.run(req).await;
    };
    let ip = req
        .extensions()
        .get::<axum::extract::ConnectInfo<SocketAddr>>()
        .map(|c| c.0.ip().to_canonical().to_string())
        .unwrap_or_else(|| "unknown".into());
    let auth = match authenticate(&st, &token, &ip) {
        Ok(Some(a)) => a,
        Ok(None) => return denied(StatusCode::UNAUTHORIZED, "invalid or expired API token"),
        Err(e) => return e.into_response(),
    };
    let path = req.uri().path().strip_prefix("/api/v1").unwrap_or("-");
    let (_, writes) = effective(&auth.token.scope, &auth.user.role);
    if !allowed(writes, req.method(), path) {
        return denied(
            StatusCode::FORBIDDEN,
            "API tokens cannot use this endpoint (or not with this scope)",
        );
    }
    let via = (auth.user.name.clone(), auth.token.name.clone());
    req.extensions_mut().insert(auth);
    VIA.scope(via, next.run(req)).await
}

/// The token's user (role capped) or `None` (unknown, wrong secret, expired, user disabled
/// (also as dormant) or expired).
fn authenticate(st: &St, token: &str, ip: &str) -> ApiResult<Option<TokenAuth>> {
    let Some((prefix, secret)) = token[PREFIX.len()..].split_once('_') else {
        return Ok(None);
    };
    if prefix.len() != 8 || !prefix.bytes().all(|b| b.is_ascii_hexdigit()) || secret.len() > 128 {
        return Ok(None);
    }
    let now = catalog::now();
    let c = st.cat.conn();
    let cols = USER_COLS
        .split(", ")
        .map(|c| format!("u.{c}"))
        .collect::<Vec<_>>()
        .join(", ");
    let row = c
        .query_row(
            &format!(
                "SELECT t.id, t.name, t.scope, t.hash, t.expires, t.last_used, {cols} FROM api_tokens t
                 JOIN users u ON u.id = t.user_id WHERE t.prefix = ?1 AND u.activation_hash IS NULL"
            ),
            [prefix],
            |r| {
                Ok((
                    TokenRef {
                        id: r.get(0)?,
                        name: r.get(1)?,
                        scope: r.get(2)?,
                    },
                    r.get::<_, String>(3)?,
                    r.get::<_, i64>(4)?,
                    r.get::<_, Option<i64>>(5)?,
                    User::from_row(r, 6)?,
                ))
            },
        )
        .optional()?;
    let Some((tok, hash, expires, last_used, mut user)) = row else {
        return Ok(None);
    };
    if !ct_eq(sha256_hex(secret.as_bytes()).as_bytes(), hash.as_bytes())
        || expires <= now
        || user.disabled
        || user.expired(now)
        || crate::tenants::blocked(&c, &user)?
    {
        return Ok(None);
    }
    if last_used.is_none_or(|t| now - t >= TOUCH_SECS) {
        c.execute(
            "UPDATE api_tokens SET last_used = ?2, last_ip = ?3 WHERE id = ?1",
            params![tok.id, now, ip],
        )?;
    }
    user.role = effective(&tok.scope, &user.role).0;
    // tokens never download (not on the allow-list either), whatever the account's privilege
    user.can_download = false;
    Ok(Some(TokenAuth { user, token: tok }))
}

// ---------------------------------------------------------------- endpoints (sessions only)

fn row_json(r: &catalog::rusqlite::Row) -> catalog::rusqlite::Result<Value> {
    Ok(json!({
        "id": r.get::<_, i64>(0)?, "user": r.get::<_, String>(1)?, "name": r.get::<_, String>(2)?,
        "prefix": r.get::<_, String>(3)?, "scope": r.get::<_, String>(4)?, "expires": r.get::<_, i64>(5)?,
        "created": r.get::<_, i64>(6)?, "last_used": r.get::<_, Option<i64>>(7)?,
        "last_ip": r.get::<_, Option<String>>(8)?,
    }))
}

const COLS: &str =
    "t.id, u.name, t.name, t.prefix, t.scope, t.expires, t.created, t.last_used, t.last_ip FROM api_tokens t JOIN users u ON u.id = t.user_id";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListQ {
    /// admins: every user's tokens
    #[serde(default)]
    all: bool,
}

/// Own tokens; `?all=true` (admin): everyone's. Never the hash.
pub async fn list(State(st): State<St>, ctx: Ctx, Q(q): Q<ListQ>) -> ApiResult<Json<Value>> {
    if q.all {
        ctx.require(&["admin"])?;
    }
    let c = st.cat.conn();
    let rows = c
        .prepare(&format!(
            "SELECT {COLS} WHERE ?1 OR t.user_id = ?2 ORDER BY u.name, t.name"
        ))?
        .query_map(params![q.all, ctx.user.id], row_json)?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Json(json!(rows)))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateReq {
    name: String,
    scope: String,
    /// lifetime in days, 1..=365
    days: i64,
    #[serde(default)]
    current_password: Option<String>,
    #[serde(default)]
    current_totp: Option<String>,
}

/// A new token for the signed-in user; the secret is in the answer only.
/// Local accounts re-authenticate (password + TOTP): a stolen session must not
/// turn into a credential that outlives it. OIDC accounts need a session that
/// is at most 15 minutes old instead.
pub async fn create(State(st): State<St>, ctx: Ctx, ClientIp(ip): ClientIp, J(r): J<CreateReq>) -> ApiResult<Response> {
    validate::name(&r.name, "name")?;
    if !(1..=MAX_DAYS).contains(&r.days) {
        return Err(ApiError::bad(format!("days: 1..={MAX_DAYS}")));
    }
    match r.scope.as_str() {
        "read" => {}
        "operator" if effective("operator", &ctx.user.role).1 => {}
        "operator" => {
            return Err(ApiError::bad(
                "scope: operator tokens need the admin, operator or tenant user role",
            ))
        }
        _ => return Err(ApiError::bad("scope: read or operator")),
    }
    let n: i64 = st.cat.conn().query_row(
        "SELECT COUNT(*) FROM api_tokens WHERE user_id = ?1",
        [ctx.user.id],
        |r| r.get(0),
    )?;
    if n >= MAX_PER_USER {
        return Err(ApiError::conflict(format!(
            "at most {MAX_PER_USER} tokens per user: revoke one first"
        )));
    }
    if ctx.user.auth == "local" {
        reauth(&st, &ctx, &ip, r.current_password, r.current_totp, "token.create").await?;
    } else {
        let created: i64 =
            st.cat
                .conn()
                .query_row("SELECT created FROM sessions WHERE id_hash = ?1", [&ctx.sid], |r| {
                    r.get(0)
                })?;
        if catalog::now() - created > OIDC_FRESH_SECS {
            return Err(ApiError(
                StatusCode::FORBIDDEN,
                "sign in again (single sign-on) and create the token within 15 minutes".into(),
            ));
        }
    }
    let (prefix, secret) = (random_hex()[..8].to_owned(), random_hex());
    let now = catalog::now();
    let expires = now + r.days * 86400;
    let id = {
        let c = st.cat.conn();
        c.execute(
            "INSERT INTO api_tokens (user_id, name, prefix, hash, scope, expires, created) VALUES (?1,?2,?3,?4,?5,?6,?7)",
            params![ctx.user.id, r.name, prefix, sha256_hex(secret.as_bytes()), r.scope, expires, now],
        )?;
        c.last_insert_rowid()
    };
    st.audit(
        ctx.name(),
        "token.create",
        &format!("token/{}/{}", ctx.name(), r.name),
        json!({"id": id, "prefix": prefix, "scope": r.scope, "expires": expires, "ip": ip}),
    )?;
    let row = st
        .cat
        .conn()
        .query_row(&format!("SELECT {COLS} WHERE t.id = ?1"), [id], row_json)?;
    let mut body = row;
    body["token"] = json!(format!("{PREFIX}{prefix}_{secret}"));
    Ok((StatusCode::CREATED, Json(body)).into_response())
}

/// Revokes (deletes) a token: own ones, admins any.
pub async fn revoke(State(st): State<St>, ctx: Ctx, Path(id): Path<i64>) -> ApiResult<Json<Value>> {
    let row: Option<(i64, String, String)> = st
        .cat
        .conn()
        .query_row(
            "SELECT t.user_id, u.name, t.name FROM api_tokens t JOIN users u ON u.id = t.user_id WHERE t.id = ?1",
            [id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()?;
    let Some((owner, user, name)) = row else {
        return Err(ApiError::not_found());
    };
    if owner != ctx.user.id {
        ctx.require(&["admin"]).map_err(|_| ApiError::not_found())?;
    }
    st.cat.conn().execute("DELETE FROM api_tokens WHERE id = ?1", [id])?;
    st.audit(
        ctx.name(),
        "token.revoke",
        &format!("token/{user}/{name}"),
        json!({"id": id}),
    )?;
    Ok(Json(json!({"ok": true})))
}
