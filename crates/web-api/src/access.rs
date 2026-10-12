//! Access controls of Phase 14d (docs/control-plane.md "Access"): session
//! list / revoke, session timeouts, dormant accounts, the login banner and the
//! management source-IP allow-list. Settings live in `catalog::access`.
//!
//! - Session timeouts: tightening applies at once; longer timeouts need
//!   approval (`security.session`).
//! - Management allow-list: every change needs approval
//!   (`security.mgmt_allow`); a list that does not contain the requesting
//!   client's address is refused unless `force` and `confirm` = that address.
//!   The scheduler writes the list into the firewall file, nexus-nft-sync loads
//!   it into `mgmt_allowed_v4/v6` (empty list = any). The console resets it
//!   (`nexus-setup reset-mgmt-allow`).
//! - Dormant accounts (`dormant_days`, 0 = off) and the login banner: admin,
//!   direct, audited. The scheduler disables dormant accounts.

use crate::auth::{reauth, ClientIp, Ctx};
use crate::quorum::gate;
use crate::{ApiError, ApiResult, St, J, Q};
use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use catalog::access::{self, SessionLimits};
use catalog::rusqlite::{params, Connection, OptionalExtension};
use serde::Deserialize;
use serde_json::{json, Value};

const ADMIN: &[&str] = &["admin"];
const SETTINGS_READ: &[&str] = &["admin", "security_officer"];

pub fn routes() -> Router<St> {
    Router::new()
        .route("/auth/banner", get(banner))
        .route("/auth/sessions", get(own_sessions))
        .route("/auth/sessions/{id}", delete(revoke_own))
        .route("/sessions", get(all_sessions))
        .route("/sessions/{id}", delete(revoke_any))
        .route("/sessions/revoke-all", post(revoke_all))
        .route("/users/{id}/sessions/revoke", post(revoke_user))
        .route("/settings/security", get(get_security))
        .route("/settings/session", put(put_session))
        .route("/settings/dormant", put(put_dormant))
        .route("/settings/banner", put(put_banner))
        .route("/settings/mgmt-allow", put(put_mgmt_allow))
}

// ---------------------------------------------------------------- sessions

const SESSION_COLS: &str = "s.id, s.user_id, u.name, s.ip, s.user_agent, s.created, s.last_seen, s.id_hash";

fn sessions(c: &Connection, user: Option<i64>, current: &str) -> ApiResult<Value> {
    let rows = c
        .prepare(&format!(
            "SELECT {SESSION_COLS} FROM sessions s JOIN users u ON u.id = s.user_id
             WHERE ?1 IS NULL OR s.user_id = ?1 ORDER BY s.last_seen DESC LIMIT 1000"
        ))?
        .query_map([user], |r| {
            Ok(json!({
                "id": r.get::<_, i64>(0)?, "user_id": r.get::<_, i64>(1)?, "user": r.get::<_, String>(2)?,
                "ip": r.get::<_, String>(3)?, "user_agent": r.get::<_, String>(4)?,
                "created": r.get::<_, i64>(5)?, "last_seen": r.get::<_, i64>(6)?,
                "current": r.get::<_, String>(7)? == current,
            }))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Value::Array(rows))
}

/// The caller's own sessions (`current` marks this one).
pub async fn own_sessions(State(st): State<St>, ctx: Ctx) -> ApiResult<Json<Value>> {
    Ok(Json(sessions(&st.cat.conn(), Some(ctx.user.id), &ctx.sid)?))
}

/// Ends session `id` (of `owner`, if given); audited. 404 if there is none.
fn end_session(st: &St, ctx: &Ctx, id: i64, owner: Option<i64>) -> ApiResult<Json<Value>> {
    let name: Option<String> = {
        let c = st.cat.conn();
        let name = c
            .query_row(
                "SELECT u.name FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.id = ?1
                 AND (?2 IS NULL OR s.user_id = ?2)",
                params![id, owner],
                |r| r.get(0),
            )
            .optional()?;
        if name.is_some() {
            c.execute("DELETE FROM sessions WHERE id = ?1", [id])?;
        }
        name
    };
    let name = name.ok_or_else(ApiError::not_found)?;
    st.audit(
        ctx.name(),
        "session.revoke",
        &format!("user/{name}"),
        json!({"session": id}),
    )?;
    Ok(Json(json!({"revoked": 1})))
}

pub async fn revoke_own(State(st): State<St>, ctx: Ctx, Path(id): Path<i64>) -> ApiResult<Json<Value>> {
    end_session(&st, &ctx, id, Some(ctx.user.id))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionFilter {
    user: Option<i64>,
}

/// Admin: every session (or one user's).
pub async fn all_sessions(State(st): State<St>, ctx: Ctx, Q(f): Q<SessionFilter>) -> ApiResult<Json<Value>> {
    ctx.require(ADMIN)?;
    Ok(Json(sessions(&st.cat.conn(), f.user, &ctx.sid)?))
}

pub async fn revoke_any(State(st): State<St>, ctx: Ctx, Path(id): Path<i64>) -> ApiResult<Json<Value>> {
    ctx.require(ADMIN)?;
    end_session(&st, &ctx, id, None)
}

/// Admin: ends every session of user `id`.
pub async fn revoke_user(State(st): State<St>, ctx: Ctx, Path(id): Path<i64>) -> ApiResult<Json<Value>> {
    ctx.require(ADMIN)?;
    let (name, n) = {
        let c = st.cat.conn();
        let name: String = c
            .query_row("SELECT name FROM users WHERE id = ?1", [id], |r| r.get(0))
            .optional()?
            .ok_or_else(ApiError::not_found)?;
        (name, c.execute("DELETE FROM sessions WHERE user_id = ?1", [id])?)
    };
    st.audit(
        ctx.name(),
        "session.revoke_user",
        &format!("user/{name}"),
        json!({"revoked": n}),
    )?;
    Ok(Json(json!({"revoked": n})))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Reauth {
    current_password: Option<String>,
    current_totp: Option<String>,
}

/// Admin, re-authenticated: ends every session on the appliance except the
/// caller's own (e.g. after a suspected session theft).
pub async fn revoke_all(
    State(st): State<St>,
    ctx: Ctx,
    ClientIp(ip): ClientIp,
    J(r): J<Reauth>,
) -> ApiResult<Json<Value>> {
    ctx.require(ADMIN)?;
    reauth(
        &st,
        &ctx,
        &ip,
        r.current_password,
        r.current_totp,
        "revoke all sessions",
    )
    .await?;
    let n = st
        .cat
        .conn()
        .execute("DELETE FROM sessions WHERE id_hash != ?1", [&ctx.sid])?;
    st.audit(
        ctx.name(),
        "session.revoke_all",
        "appliance",
        json!({"revoked": n, "ip": ip}),
    )?;
    Ok(Json(json!({"revoked": n})))
}

// ---------------------------------------------------------------- settings

/// Public (login page): `{banner}`.
pub async fn banner(State(st): State<St>) -> ApiResult<Json<Value>> {
    Ok(Json(json!({"banner": access::login_banner(&st.cat.conn())?})))
}

fn pending(c: &Connection, action: &str) -> ApiResult<Option<i64>> {
    Ok(c.query_row(
        "SELECT id FROM quorum WHERE action = ?1 AND state = 'pending' ORDER BY id DESC LIMIT 1",
        [action],
        |r| r.get(0),
    )
    .optional()?)
}

/// `{session, dormant_days, login_banner, mgmt_allow, client_ip,
/// client_allowed, pending: {session, mgmt_allow}}` (quorum ids or null).
pub async fn get_security(State(st): State<St>, ctx: Ctx, ClientIp(ip): ClientIp) -> ApiResult<Json<Value>> {
    ctx.require(SETTINGS_READ)?;
    let c = st.cat.conn();
    let allow = access::mgmt_allow(&c)?;
    Ok(Json(json!({
        "session": access::session_limits(&c)?,
        "dormant_days": access::dormant_days(&c)?,
        "login_banner": access::login_banner(&c)?,
        "client_allowed": access::allows(&allow, &ip),
        "mgmt_allow": allow,
        "client_ip": ip,
        "pending": {"session": pending(&c, "security.session")?, "mgmt_allow": pending(&c, "security.mgmt_allow")?},
    })))
}

/// Shorter timeouts apply at once (existing sessions included); longer ones
/// need approval.
pub async fn put_session(State(st): State<St>, ctx: Ctx, J(new): J<SessionLimits>) -> ApiResult<Response> {
    ctx.require(ADMIN)?;
    new.check().map_err(ApiError::bad)?;
    let old = access::session_limits(&st.cat.conn())?;
    if new.looser_than(&old) {
        let p = json!({"session": new, "old": old});
        return gate(&st, &ctx, "security.session", "settings/session", p);
    }
    catalog::set_setting(&st.cat.conn(), access::SESSION, &json!(new).to_string())?;
    st.audit(
        ctx.name(),
        "security.session",
        "settings/session",
        json!({"session": new, "old": old}),
    )?;
    Ok(Json(json!(new)).into_response())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DormantReq {
    days: i64,
}

pub async fn put_dormant(State(st): State<St>, ctx: Ctx, J(r): J<DormantReq>) -> ApiResult<Json<Value>> {
    ctx.require(ADMIN)?;
    if r.days != 0 && !(30..=access::DORMANT_MAX).contains(&r.days) {
        return Err(ApiError::bad(format!("days: 0 (off) or 30..={}", access::DORMANT_MAX)));
    }
    let old = access::dormant_days(&st.cat.conn())?;
    catalog::set_setting(&st.cat.conn(), access::DORMANT_DAYS, &r.days.to_string())?;
    st.audit(
        ctx.name(),
        "security.dormant",
        "settings/dormant_days",
        json!({"days": r.days, "old": old}),
    )?;
    Ok(Json(json!({"dormant_days": r.days})))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BannerReq {
    banner: String,
}

pub async fn put_banner(State(st): State<St>, ctx: Ctx, J(r): J<BannerReq>) -> ApiResult<Json<Value>> {
    ctx.require(ADMIN)?;
    let text = r.banner.trim_end().replace("\r\n", "\n");
    if text.chars().count() > access::BANNER_MAX || text.chars().any(|c| c.is_control() && c != '\n' && c != '\t') {
        return Err(ApiError::bad(format!(
            "banner: up to {} characters, no control characters",
            access::BANNER_MAX
        )));
    }
    catalog::set_setting(&st.cat.conn(), access::LOGIN_BANNER, &text)?;
    st.audit(
        ctx.name(),
        "security.login_banner",
        "settings/login_banner",
        json!({"banner": text}),
    )?;
    Ok(Json(json!({"banner": text})))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MgmtReq {
    mgmt_allow: Vec<String>,
    /// accept a list that does not contain the requesting client's address
    #[serde(default)]
    force: bool,
    /// with `force`: the client's address, typed
    #[serde(default)]
    confirm: String,
}

/// Every change needs approval (the requester could lock everybody out, or
/// open the management port to everyone).
pub async fn put_mgmt_allow(
    State(st): State<St>,
    ctx: Ctx,
    ClientIp(ip): ClientIp,
    J(r): J<MgmtReq>,
) -> ApiResult<Response> {
    ctx.require(ADMIN)?;
    if r.mgmt_allow.len() > access::MGMT_MAX {
        return Err(ApiError::bad(format!(
            "mgmt_allow: at most {} entries",
            access::MGMT_MAX
        )));
    }
    let mut list = Vec::new();
    for s in &r.mgmt_allow {
        let c = access::cidr_string(s)
            .ok_or_else(|| ApiError::bad(format!("mgmt_allow: {s:?} is not an address or CIDR (10.0.0.0/8)")))?;
        if !list.contains(&c) {
            list.push(c);
        }
    }
    let old = access::mgmt_allow(&st.cat.conn())?;
    if list == old {
        return Ok(Json(json!({"mgmt_allow": list})).into_response());
    }
    let confirmed = r.force && r.confirm.trim() == ip;
    if !access::allows(&list, &ip) && !confirmed {
        return Err(ApiError::conflict(format!(
            "mgmt_allow does not contain your address {ip}: you would lose access to the web UI; \
             add it, or confirm with force and confirm = \"{ip}\""
        )));
    }
    let p = json!({"mgmt_allow": list, "old": old, "requested_from": ip});
    gate(&st, &ctx, "security.mgmt_allow", "settings/mgmt_allow", p)
}

/// Approved `security.*` actions (crate::quorum), refused if the setting
/// changed since the request.
pub fn execute(c: &Connection, action: &str, p: &Value) -> ApiResult<()> {
    let (key, current, new) = match action {
        "security.session" => (access::SESSION, json!(access::session_limits(c)?), &p["session"]),
        "security.mgmt_allow" => (access::MGMT_ALLOW, json!(access::mgmt_allow(c)?), &p["mgmt_allow"]),
        _ => return Err(ApiError::bad("unknown action")),
    };
    if current != p["old"] {
        return Err(ApiError::conflict(
            "the setting changed since this request was made; reject it and request the change again",
        ));
    }
    catalog::set_setting(c, key, &new.to_string())?;
    Ok(())
}
