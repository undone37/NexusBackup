//! Login (argon2id + TOTP via `catalog::auth`), cookie sessions, CSRF, RBAC
//! context and the login rate limiter.

use crate::{ct_eq, random_hex, sha256_hex, validate, ApiError, ApiResult, St, J};
use axum::extract::{ConnectInfo, FromRequestParts, State};
use axum::http::request::Parts;
use axum::http::{header, HeaderValue, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use catalog::rusqlite::{params, Connection, OptionalExtension, Row};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::OnceLock;

pub const COOKIE: &str = "nx_session";
pub const IDLE_SECS: i64 = 30 * 60;
pub const ABSOLUTE_SECS: i64 = 12 * 3600;
pub const MAX_FAILURES: usize = 5;
pub const WINDOW_SECS: i64 = 15 * 60;
pub const LOCKOUT_SECS: i64 = 15 * 60;

// ---------------------------------------------------------------- users

#[derive(Serialize, Clone, Debug)]
pub struct User {
    pub id: i64,
    pub name: String,
    pub role: String,
    /// `None` = all tenants
    pub tenant: Option<String>,
    pub disabled: bool,
    pub created: i64,
}

pub const USER_COLS: &str = "id, name, role, tenant, disabled, created";

impl User {
    pub fn from_row(r: &Row, off: usize) -> catalog::rusqlite::Result<Self> {
        Ok(User {
            id: r.get(off)?,
            name: r.get(off + 1)?,
            role: r.get(off + 2)?,
            tenant: r.get(off + 3)?,
            disabled: r.get::<_, i64>(off + 4)? != 0,
            created: r.get(off + 5)?,
        })
    }

    pub fn load(c: &Connection, id: i64) -> ApiResult<User> {
        Ok(
            c.query_row(&format!("SELECT {USER_COLS} FROM users WHERE id=?1"), [id], |r| {
                User::from_row(r, 0)
            })?,
        )
    }
}

// ---------------------------------------------------------------- request context

/// An authenticated request. Extracting it validates the session cookie,
/// enforces idle/absolute expiry, refreshes `last_seen` and — for every
/// method other than GET/HEAD — checks the `X-CSRF-Token` header.
pub struct Ctx {
    pub user: User,
    pub sid: String,
    pub csrf: String,
}

impl Ctx {
    pub fn require(&self, roles: &[&str]) -> ApiResult<()> {
        if roles.contains(&self.user.role.as_str()) {
            Ok(())
        } else {
            Err(ApiError::forbidden())
        }
    }
    /// Tenant the user is restricted to (always set for tenant_user).
    pub fn scope(&self) -> Option<&str> {
        self.user.tenant.as_deref()
    }
    pub fn sees(&self, tenant: &str) -> bool {
        self.scope().is_none_or(|t| t == tenant)
    }
    pub fn name(&self) -> &str {
        &self.user.name
    }
}

fn session_cookie(parts: &Parts) -> Option<String> {
    parts
        .headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .find_map(|kv| kv.trim().strip_prefix(COOKIE)?.strip_prefix('=').map(str::to_owned))
}

impl FromRequestParts<St> for Ctx {
    type Rejection = ApiError;
    async fn from_request_parts(parts: &mut Parts, st: &St) -> Result<Self, ApiError> {
        let token = session_cookie(parts).ok_or_else(ApiError::unauthorized)?;
        let sid = sha256_hex(token.as_bytes());
        let now = catalog::now();
        let c = st.cat.conn();
        let row = c
            .query_row(
                &format!(
                    "SELECT s.csrf, s.created, s.last_seen, {} FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.id_hash = ?1",
                    USER_COLS.split(", ").map(|c| format!("u.{c}")).collect::<Vec<_>>().join(", ")
                ),
                [&sid],
                |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?, r.get::<_, i64>(2)?, User::from_row(r, 3)?)),
            )
            .optional()?;
        let Some((csrf, created, last_seen, user)) = row else {
            return Err(ApiError::unauthorized());
        };
        if user.disabled || now - last_seen > IDLE_SECS || now - created > ABSOLUTE_SECS {
            c.execute("DELETE FROM sessions WHERE id_hash = ?1", [&sid])?;
            return Err(ApiError(StatusCode::UNAUTHORIZED, "session expired".into()));
        }
        if parts.method != Method::GET && parts.method != Method::HEAD {
            let given = parts
                .headers
                .get("x-csrf-token")
                .map(|v| v.as_bytes())
                .unwrap_or_default();
            if !ct_eq(given, csrf.as_bytes()) {
                return Err(ApiError(
                    StatusCode::FORBIDDEN,
                    "missing or invalid X-CSRF-Token".into(),
                ));
            }
        }
        c.execute(
            "UPDATE sessions SET last_seen = ?1 WHERE id_hash = ?2",
            params![now, sid],
        )?;
        Ok(Ctx { user, sid, csrf })
    }
}

/// Peer IP (canonical form) from the connection; `unknown` in tests.
pub struct ClientIp(pub String);

impl<S: Send + Sync> FromRequestParts<S> for ClientIp {
    type Rejection = ApiError;
    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, ApiError> {
        Ok(ClientIp(
            parts
                .extensions
                .get::<ConnectInfo<SocketAddr>>()
                .map(|c| c.0.ip().to_canonical().to_string())
                .unwrap_or_else(|| "unknown".into()),
        ))
    }
}

// ---------------------------------------------------------------- rate limiter

#[derive(Default)]
struct Slot {
    fails: Vec<i64>,
    locked_until: i64,
}

/// 5 failures per key (user or IP) within 15 min → 15 min lockout.
/// In memory: a restart clears it, which is acceptable for a rate limiter
/// (the failures themselves are in the audit log).
#[derive(Default)]
pub struct Limiter {
    m: HashMap<String, Slot>,
}

impl Limiter {
    pub fn locked(&self, key: &str, now: i64) -> bool {
        self.m.get(key).is_some_and(|s| s.locked_until > now)
    }

    /// Records a failure; true if this one triggered the lockout.
    pub fn fail(&mut self, key: &str, now: i64) -> bool {
        if self.m.len() > 10_000 {
            self.m
                .retain(|_, s| s.locked_until > now || s.fails.iter().any(|t| now - t < WINDOW_SECS));
        }
        let s = self.m.entry(key.to_owned()).or_default();
        s.fails.retain(|t| now - t < WINDOW_SECS);
        s.fails.push(now);
        if s.fails.len() >= MAX_FAILURES {
            s.fails.clear();
            s.locked_until = now + LOCKOUT_SECS;
            return true;
        }
        false
    }

    pub fn clear(&mut self, key: &str) {
        self.m.remove(key);
    }
}

// ---------------------------------------------------------------- handlers

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoginReq {
    name: String,
    password: String,
    totp: String,
}

fn dummy_hash() -> &'static str {
    static H: OnceLock<String> = OnceLock::new();
    H.get_or_init(|| catalog::auth::hash_password(&random_hex()).expect("argon2"))
}

/// Login is the one non-GET endpoint without CSRF header (no session yet);
/// the JSON content type requirement and SameSite=Strict cover login CSRF.
pub async fn login(State(st): State<St>, ClientIp(ip): ClientIp, J(r): J<LoginReq>) -> ApiResult<Response> {
    let now = catalog::now();
    let valid_name = validate::name(&r.name, "name").is_ok();
    let ukey = format!("user:{}", if valid_name { r.name.as_str() } else { "?" });
    let ikey = format!("ip:{ip}");
    let target = if valid_name {
        format!("user/{}", r.name)
    } else {
        "user/?".into()
    };
    {
        let l = st.limiter.lock().unwrap();
        if l.locked(&ukey, now) || l.locked(&ikey, now) {
            st.failed_logins.fetch_add(1, Ordering::Relaxed);
            return Err(ApiError(
                StatusCode::TOO_MANY_REQUESTS,
                "too many failed logins, try again later".into(),
            ));
        }
    }
    let row = if valid_name {
        st.cat
            .conn()
            .query_row(
                &format!("SELECT {USER_COLS}, password_hash, totp_secret, totp_last_step FROM users WHERE name = ?1"),
                [&r.name],
                |row| {
                    Ok((
                        User::from_row(row, 0)?,
                        row.get::<_, String>(6)?,
                        row.get::<_, String>(7)?,
                        row.get::<_, i64>(8)?,
                    ))
                },
            )
            .optional()?
    } else {
        None
    };
    let (password, totp) = (r.password, r.totp);
    let (user, mut verdict) = tokio::task::spawn_blocking(move || {
        if password.len() > 1024 {
            return (None, Err("password too long"));
        }
        match row {
            Some((u, hash, secret, last_step)) => {
                let v = if !catalog::auth::verify_password(&password, &hash) {
                    Err("password")
                } else if u.disabled {
                    Err("disabled")
                } else {
                    match catalog::auth::totp_step(&secret, &totp) {
                        None => Err("totp"),
                        Some(s) if (s as i64) <= last_step => Err("totp replay"),
                        Some(s) => Ok(s as i64),
                    }
                };
                (Some(u), v)
            }
            None => {
                // same cost as a real check: no user enumeration by timing
                catalog::auth::verify_password(&password, dummy_hash());
                (None, Err("unknown user"))
            }
        }
    })
    .await
    .map_err(|e| anyhow::anyhow!("login task: {e}"))?;
    // consume the TOTP step atomically: a concurrent login with the same code loses
    if let (Some(u), Ok(step)) = (&user, verdict) {
        let n = st.cat.conn().execute(
            "UPDATE users SET totp_last_step = ?1 WHERE id = ?2 AND totp_last_step < ?1",
            params![step, u.id],
        )?;
        if n == 0 {
            verdict = Err("totp replay");
        }
    }
    let verdict = verdict.map(|_| ());

    let user = match (user, verdict) {
        (Some(u), Ok(())) => u,
        (_, Err(reason)) => {
            st.failed_logins.fetch_add(1, Ordering::Relaxed);
            let (lock_user, lock_ip) = {
                let mut l = st.limiter.lock().unwrap();
                (l.fail(&ukey, now), l.fail(&ikey, now))
            };
            st.audit(
                "anonymous",
                "auth.login_failed",
                &target,
                json!({"ip": ip, "reason": reason}),
            )?;
            if lock_user {
                st.audit(
                    "web-api",
                    "auth.lockout",
                    &target,
                    json!({"ip": ip, "until": now + LOCKOUT_SECS}),
                )?;
            }
            if lock_ip {
                st.audit(
                    "web-api",
                    "auth.lockout",
                    &format!("ip/{ip}"),
                    json!({"until": now + LOCKOUT_SECS}),
                )?;
            }
            return Err(ApiError(
                StatusCode::UNAUTHORIZED,
                "invalid name, password or TOTP code".into(),
            ));
        }
        (None, Ok(())) => unreachable!(),
    };
    st.limiter.lock().unwrap().clear(&ukey);

    let (token, csrf) = (random_hex(), random_hex());
    {
        let c = st.cat.conn();
        c.execute(
            "DELETE FROM sessions WHERE last_seen < ?1 OR created < ?2",
            params![now - IDLE_SECS, now - ABSOLUTE_SECS],
        )?;
        c.execute(
            "INSERT INTO sessions (id_hash, user_id, csrf, created, last_seen) VALUES (?1, ?2, ?3, ?4, ?4)",
            params![sha256_hex(token.as_bytes()), user.id, csrf, now],
        )?;
    }
    st.audit(&user.name, "auth.login", &target, json!({"ip": ip}))?;
    let cookie = format!("{COOKIE}={token}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age={ABSOLUTE_SECS}");
    let mut res = Json(json!({"csrf": csrf, "user": user})).into_response();
    res.headers_mut()
        .insert(header::SET_COOKIE, HeaderValue::from_str(&cookie).unwrap());
    Ok(res)
}

pub async fn logout(State(st): State<St>, ctx: Ctx) -> ApiResult<Response> {
    st.cat
        .conn()
        .execute("DELETE FROM sessions WHERE id_hash = ?1", [&ctx.sid])?;
    st.audit(ctx.name(), "auth.logout", &format!("user/{}", ctx.name()), json!({}))?;
    let mut res = Json(json!({"ok": true})).into_response();
    res.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&format!(
            "{COOKIE}=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0"
        ))
        .unwrap(),
    );
    Ok(res)
}

/// `{user, csrf}` — lets the SPA recover its CSRF token after a reload.
pub async fn me(ctx: Ctx) -> Json<serde_json::Value> {
    Json(json!({"user": ctx.user, "csrf": ctx.csrf}))
}
