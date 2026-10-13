//! Login (argon2id + TOTP via `catalog::auth`), cookie sessions, CSRF, RBAC
//! context and the login rate limiter.

use crate::{ct_eq, random_hex, sha256_hex, validate, ApiError, ApiResult, AppState, St, J};
use axum::extract::{ConnectInfo, FromRequestParts, State};
use axum::http::request::Parts;
use axum::http::{header, HeaderMap, HeaderValue, Method, StatusCode};
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
/// Default session timeouts; setting `session` overrides them (crate::access).
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
    /// created or reset, waiting for the person to set their own credentials
    pub pending_activation: bool,
    pub activation_expires: Option<i64>,
    /// `local` (password + TOTP) or `oidc` (signs in at the IdP, catalog v10)
    pub auth: String,
    /// may download restored files (`files_get`); explicit or the role's default (v15)
    pub can_download: bool,
    /// no login from then on (v15); `None` = never
    pub expires: Option<i64>,
    pub last_login: Option<i64>,
}

pub const USER_COLS: &str =
    "id, name, role, tenant, disabled, created, activation_hash, activation_expires, auth, can_download, expires, last_login";
/// Columns of [`USER_COLS`]: credentials selected after them start here.
pub const USER_NCOLS: usize = 12;

impl User {
    pub fn from_row(r: &Row, off: usize) -> catalog::rusqlite::Result<Self> {
        Ok(User {
            id: r.get(off)?,
            name: r.get(off + 1)?,
            role: r.get(off + 2)?,
            tenant: r.get(off + 3)?,
            disabled: r.get::<_, i64>(off + 4)? != 0,
            created: r.get(off + 5)?,
            pending_activation: r.get::<_, Option<String>>(off + 6)?.is_some(),
            activation_expires: r.get(off + 7)?,
            auth: r.get(off + 8)?,
            can_download: match r.get::<_, Option<bool>>(off + 9)? {
                Some(b) => b,
                None => catalog::access::role_can_download(&r.get::<_, String>(off + 2)?),
            },
            expires: r.get(off + 10)?,
            last_login: r.get(off + 11)?,
        })
    }

    pub fn expired(&self, now: i64) -> bool {
        self.expires.is_some_and(|e| now >= e)
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
/// API token requests (`crate::tokens`, authenticated by its middleware) carry
/// `token`, no session (`sid`, `csrf` empty) and the role capped by the scope.
pub struct Ctx {
    pub user: User,
    pub sid: String,
    pub csrf: String,
    pub token: Option<crate::tokens::TokenRef>,
    /// "view as tenant" (Phase 19b, `crate::impersonate`): the admin's session
    /// acts as `user.role` (viewer or tenant_admin) of `user.tenant`; the tenant
    pub impersonating: Option<String>,
}

/// Writers of a tenant's own configuration (sources, groups, agents, its
/// users): admins appliance-wide, tenant admins in their tenant ([`Ctx::owns`]).
pub const TENANT_WRITERS: &[&str] = &["admin", "tenant_admin"];

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
    /// 403 unless the object's `tenant` is within the user's scope.
    pub fn owns(&self, tenant: &str) -> ApiResult<()> {
        if self.sees(tenant) {
            Ok(())
        } else {
            Err(ApiError::forbidden())
        }
    }
    pub fn is_tenant_admin(&self) -> bool {
        self.user.role == "tenant_admin"
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
        if let Some(t) = parts.extensions.get::<crate::tokens::TokenAuth>() {
            return Ok(Ctx {
                user: t.user.clone(),
                sid: String::new(),
                csrf: String::new(),
                token: Some(t.token.clone()),
                impersonating: None,
            });
        }
        let token = session_cookie(parts).ok_or_else(ApiError::unauthorized)?;
        let sid = sha256_hex(token.as_bytes());
        let now = catalog::now();
        let c = st.cat.conn();
        let row = c
            .query_row(
                &format!(
                    "SELECT s.csrf, s.created, s.last_seen, s.impersonating, s.impersonating_role, {}
                     FROM sessions s JOIN users u ON u.id = s.user_id
                     WHERE s.id_hash = ?1 AND u.activation_hash IS NULL",
                    USER_COLS
                        .split(", ")
                        .map(|c| format!("u.{c}"))
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
                [&sid],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, i64>(1)?,
                        r.get::<_, i64>(2)?,
                        (r.get::<_, Option<String>>(3)?, r.get::<_, Option<String>>(4)?),
                        User::from_row(r, 5)?,
                    ))
                },
            )
            .optional()?;
        let Some((csrf, created, last_seen, imp, mut user)) = row else {
            return Err(ApiError::unauthorized());
        };
        if user.expired(now) {
            c.execute("DELETE FROM sessions WHERE user_id = ?1", [user.id])?;
            return Err(ApiError(StatusCode::UNAUTHORIZED, "account expired".into()));
        }
        let lim = catalog::access::session_limits(&c)?;
        if user.disabled
            || now - last_seen > lim.idle_secs()
            || now - created > lim.absolute_secs()
            || crate::tenants::blocked(&c, &user)?
        {
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
        let impersonating = crate::impersonate::apply(&c, &sid, &mut user, imp)?;
        Ok(Ctx {
            user,
            sid,
            csrf,
            token: None,
            impersonating,
        })
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
    #[serde(default)]
    totp: String,
    /// second factor instead of `totp` (crate::passkeys, options from `/auth/login/passkey`)
    #[serde(default)]
    passkey: Option<crate::passkeys::Assertion>,
}

/// Login failure answer; mentions passkeys while the policy may refuse TOTP
/// (the same text for every reason: no password oracle).
fn login_failed(st: &AppState) -> ApiError {
    let pk = crate::passkeys::policy(&st.cat.conn()).is_ok_and(|p| p.require_privileged);
    ApiError(
        StatusCode::UNAUTHORIZED,
        if pk {
            "invalid name, password or second factor (admins and security officers sign in with a passkey)"
        } else {
            "invalid name, password or TOTP code"
        }
        .into(),
    )
}

/// Password, enabled state and TOTP code (the step is not consumed yet;
/// `totp: None` = a passkey follows, step 0). TOTP is refused where the
/// passkey policy applies. Blocking (argon2): call from `spawn_blocking`.
fn check_credentials(
    st: &AppState,
    u: &User,
    hash: &str,
    stored_seed: &str,
    last_step: i64,
    password: &str,
    totp: Option<&str>,
) -> Result<i64, &'static str> {
    if password.len() > 1024 {
        return Err("password too long");
    }
    if u.auth != "local" {
        // same cost as a real check; OIDC accounts sign in at the IdP only
        catalog::auth::verify_password(password, dummy_hash());
        return Err("oidc account");
    }
    if !catalog::auth::verify_password(password, hash) {
        return Err("password");
    }
    if u.disabled {
        return Err("disabled");
    }
    if u.expired(catalog::now()) {
        return Err("expired");
    }
    let Some(totp) = totp else {
        return Ok(0);
    };
    if crate::passkeys::required(&st.cat.conn(), &u.role, &u.auth).unwrap_or(true) {
        return Err("totp refused: passkey required");
    }
    let seed = st.totp.decrypt(&u.name, stored_seed).map_err(|e| {
        eprintln!("<3>web-api: {e:#}");
        "totp seed undecryptable"
    })?;
    match catalog::auth::totp_step(&seed, totp) {
        None => Err("totp"),
        Some(s) if (s as i64) <= last_step => Err("totp replay"),
        Some(s) => Ok(s as i64),
    }
}

/// Consumes the TOTP step atomically: a concurrent use of the same code loses.
fn consume_step(st: &AppState, user_id: i64, step: i64) -> ApiResult<bool> {
    Ok(st.cat.conn().execute(
        "UPDATE users SET totp_last_step = ?1 WHERE id = ?2 AND totp_last_step < ?1",
        params![step, user_id],
    )? == 1)
}

/// Counts a failed login / re-authentication (per user and per IP), audits it
/// and the lockouts it triggers.
pub fn record_failure(
    st: &AppState,
    (actor, action, target): (&str, &str, &str),
    (ukey, ikey, ip): (&str, &str, &str),
    details: serde_json::Value,
) -> ApiResult<()> {
    let now = catalog::now();
    st.failed_logins.fetch_add(1, Ordering::Relaxed);
    let (lock_user, lock_ip) = {
        let mut l = st.limiter.lock().unwrap();
        (l.fail(ukey, now), l.fail(ikey, now))
    };
    st.audit(actor, action, target, details)?;
    if lock_user {
        st.audit(
            "web-api",
            "auth.lockout",
            target,
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
    Ok(())
}

pub fn locked_out(st: &AppState, ukey: &str, ikey: &str) -> bool {
    let (l, now) = (st.limiter.lock().unwrap(), catalog::now());
    l.locked(ukey, now) || l.locked(ikey, now)
}

/// Re-authentication of the acting user (security review M-5): changing a
/// password or TOTP secret (own or another user's) needs the actor's current
/// password and a fresh TOTP code. Same checks as login: replayed codes are
/// refused, failures count toward the login rate limiter and are audited
/// (`auth.reauth_failed`). Answers 403 (not 401: the session stays valid).
pub async fn reauth(
    st: &St,
    ctx: &Ctx,
    ip: &str,
    password: Option<String>,
    totp: Option<String>,
    purpose: &str,
) -> ApiResult<()> {
    let (Some(password), Some(totp)) = (password, totp) else {
        return Err(ApiError::bad(
            "current_password and current_totp are required to change a password or authenticator",
        ));
    };
    let (ukey, ikey) = (format!("user:{}", ctx.name()), format!("ip:{ip}"));
    if locked_out(st, &ukey, &ikey) {
        st.failed_logins.fetch_add(1, Ordering::Relaxed);
        return Err(ApiError(
            StatusCode::TOO_MANY_REQUESTS,
            "too many failed authentication attempts, try again later".into(),
        ));
    }
    let (hash, seed, last_step): (String, String, i64) = st.cat.conn().query_row(
        "SELECT password_hash, totp_secret, totp_last_step FROM users WHERE id = ?1",
        [ctx.user.id],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    )?;
    // `current_totp` may carry a passkey assertion (JSON, crate::passkeys)
    let passkey = totp
        .trim_start()
        .starts_with('{')
        .then(|| serde_json::from_str::<crate::passkeys::Assertion>(&totp).map_err(|_| "passkey"));
    let (st2, u) = (st.clone(), ctx.user.clone());
    let second = passkey.is_none().then_some(totp);
    let mut verdict = tokio::task::spawn_blocking(move || {
        check_credentials(&st2, &u, &hash, &seed, last_step, &password, second.as_deref())
    })
    .await
    .map_err(|e| anyhow::anyhow!("reauth task: {e}"))?;
    if let Ok(step) = verdict {
        verdict = match &passkey {
            Some(Err(e)) => Err(*e),
            Some(Ok(a)) => {
                crate::passkeys::verify_assertion(&st.cat.conn(), a, crate::passkeys::Purpose::Reauth, ctx.user.id)
                    .map(|_| 0)
            }
            None if !consume_step(st, ctx.user.id, step)? => Err("totp replay"),
            None => Ok(step),
        };
    }
    if let Err(reason) = verdict {
        let target = format!("user/{}", ctx.name());
        record_failure(
            st,
            (ctx.name(), "auth.reauth_failed", &target),
            (&ukey, &ikey, ip),
            json!({"ip": ip, "reason": reason, "for": purpose}),
        )?;
        return Err(ApiError(
            StatusCode::FORBIDDEN,
            "re-authentication failed: wrong current password, TOTP code or passkey".into(),
        ));
    }
    st.limiter.lock().unwrap().clear(&ukey);
    Ok(())
}

fn dummy_hash() -> &'static str {
    static H: OnceLock<String> = OnceLock::new();
    H.get_or_init(|| catalog::auth::hash_password(&random_hex()).expect("argon2"))
}

/// Login is the one non-GET endpoint without CSRF header (no session yet);
/// the JSON content type requirement and SameSite=Strict cover login CSRF.
pub async fn login(
    State(st): State<St>,
    ClientIp(ip): ClientIp,
    headers: HeaderMap,
    J(r): J<LoginReq>,
) -> ApiResult<Response> {
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
                        row.get::<_, String>(USER_NCOLS)?,
                        row.get::<_, String>(USER_NCOLS + 1)?,
                        row.get::<_, i64>(USER_NCOLS + 2)?,
                    ))
                },
            )
            .optional()?
    } else {
        None
    };
    // accounts of a deactivated tenant sign in no more (Phase 17f): as disabled
    let mut row = row;
    if let Some((u, ..)) = row.as_mut() {
        u.disabled |= crate::tenants::blocked(&st.cat.conn(), u)?;
    }
    let (password, totp, passkey, st2) = (r.password, r.totp, r.passkey, st.clone());
    let second = passkey.is_none().then_some(totp);
    let (user, mut verdict) = tokio::task::spawn_blocking(move || match row {
        Some((u, hash, secret, last_step)) => {
            let v = check_credentials(&st2, &u, &hash, &secret, last_step, &password, second.as_deref());
            (Some(u), v)
        }
        None => {
            // same cost as a real check: no user enumeration by timing
            catalog::auth::verify_password(&password, dummy_hash());
            (None, Err("unknown user"))
        }
    })
    .await
    .map_err(|e| anyhow::anyhow!("login task: {e}"))?;
    if let (Some(u), Ok(step)) = (&user, verdict) {
        verdict = match &passkey {
            Some(a) => {
                crate::passkeys::verify_assertion(&st.cat.conn(), a, crate::passkeys::Purpose::Login, u.id).map(|_| 0)
            }
            None if !consume_step(&st, u.id, step)? => Err("totp replay"),
            None => Ok(step),
        };
    }
    let verdict = verdict.map(|_| ());

    let user = match (user, verdict) {
        (Some(u), Ok(())) => u,
        (_, Err(reason)) => {
            record_failure(
                &st,
                ("anonymous", "auth.login_failed", &target),
                (&ukey, &ikey, &ip),
                json!({"ip": ip, "reason": reason}),
            )?;
            return Err(login_failed(&st));
        }
        (None, Ok(())) => unreachable!(),
    };
    st.limiter.lock().unwrap().clear(&ukey);

    let (cookie, csrf) = new_session(&st, user.id, &ip, &headers)?;
    let method = if passkey.is_some() { "passkey" } else { "totp" };
    st.audit(&user.name, "auth.login", &target, json!({"ip": ip, "method": method}))?;
    let mut res = Json(json!({"csrf": csrf, "user": user})).into_response();
    res.headers_mut().insert(header::SET_COOKIE, cookie);
    Ok(res)
}

/// A new session for `user_id` (local login and OIDC callback alike) from
/// `ip` with the request's user agent: the `Set-Cookie` value and the CSRF
/// token. Expired sessions are purged; the account's `last_login` is set.
/// Beyond the per-account cap (`max_sessions`, Phase 21b) the oldest sessions
/// of the account end (audited `session.limit`).
pub fn new_session(st: &AppState, user_id: i64, ip: &str, headers: &HeaderMap) -> ApiResult<(HeaderValue, String)> {
    let now = catalog::now();
    let (token, csrf) = (random_hex(), random_hex());
    let ua: String = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .chars()
        .filter(|c| !c.is_control())
        .take(256)
        .collect();
    let c = st.cat.conn();
    let lim = catalog::access::session_limits(&c)?;
    c.execute(
        "DELETE FROM sessions WHERE last_seen < ?1 OR created < ?2",
        params![now - lim.idle_secs(), now - lim.absolute_secs()],
    )?;
    c.execute(
        "INSERT INTO sessions (id_hash, user_id, csrf, created, last_seen, ip, user_agent)
         VALUES (?1, ?2, ?3, ?4, ?4, ?5, ?6)",
        params![sha256_hex(token.as_bytes()), user_id, csrf, now, ip, ua],
    )?;
    c.execute("UPDATE users SET last_login = ?2 WHERE id = ?1", params![user_id, now])?;
    let max = catalog::access::max_sessions(&c)?;
    let dropped = c.execute(
        "DELETE FROM sessions WHERE id IN (SELECT id FROM sessions WHERE user_id = ?1
         ORDER BY created DESC, id DESC LIMIT -1 OFFSET ?2)",
        params![user_id, max],
    )?;
    if dropped > 0 {
        let name: String = c.query_row("SELECT name FROM users WHERE id = ?1", [user_id], |r| r.get(0))?;
        drop(c);
        st.audit(
            &name,
            "session.limit",
            &format!("user/{name}"),
            json!({"ended": dropped, "max_sessions": max, "ip": ip}),
        )?;
    }
    let cookie = format!(
        "{COOKIE}={token}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age={}",
        lim.absolute_secs()
    );
    Ok((HeaderValue::from_str(&cookie).unwrap(), csrf))
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

/// `{user, csrf, break_glass}` — lets the SPA recover its CSRF token after a
/// reload; `break_glass` (`{at, user, alert, forced_solo}` or null) drives the
/// banner after a console recovery until the alert is acknowledged;
/// `console_shell` the banner while a console root shell runs (14c).
pub async fn me(State(st): State<St>, ctx: Ctx) -> ApiResult<Json<serde_json::Value>> {
    let bg = crate::dashboard::break_glass(&st.cat.conn(), &ctx)?;
    let shell = crate::console::shell_banner(&st.cat.conn(), &ctx)?;
    let vault = catalog::vault::enabled(&st.cat.conn())?;
    let incident = crate::incident::banner(&st.cat.conn(), &ctx)?;
    let imp = ctx
        .impersonating
        .as_ref()
        .map(|t| json!({"tenant": t, "role": ctx.user.role}));
    Ok(Json(
        json!({"user": ctx.user, "csrf": ctx.csrf, "break_glass": bg, "console_shell": shell, "vault_mode": vault,
               "impersonating": imp, "incident": incident}),
    ))
}
