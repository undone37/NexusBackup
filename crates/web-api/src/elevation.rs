//! Just-in-time role elevation (Phase 30, docs/control-plane.md "Role
//! elevation", `catalog::elevation`).
//!
//! - `POST /auth/elevate {role, minutes, reason, current_password,
//!   current_totp}`: a browser session of an account whose eligible role is
//!   `role` acts in it for `minutes` (15..=480) after a re-authentication
//!   (password + TOTP, or password + passkey; only a passkey when the passkey
//!   policy requires one for that role). With the setting `elevation.approval`
//!   it is the approval `role.elevate` (applied to the requesting session when
//!   approved; the time counts from then). Audited `role.elevate`; an info
//!   alert `role_elevation` per elevation.
//! - `POST /auth/elevate/end`: back to the standing role (audited
//!   `role.elevate_end`); signing out ends it too, as does any change of the
//!   account (its sessions end) and the expiry (noticed by the next request).
//! - `PUT /settings/elevation {approval}`: admins; switching the approval
//!   off is a weakening (approval `security.elevation`).
//!
//! API tokens never elevate (their role is the standing one), nor does an
//! impersonating session.

use crate::auth::{reauth, ClientIp, Ctx, User};
use crate::quorum::{accepted, gate};
use crate::{ApiError, ApiResult, St, J};
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{post, put};
use axum::{Json, Router};
use catalog::elevation::{self as el, Settings};
use catalog::rusqlite::{params, Connection};
use serde::Deserialize;
use serde_json::{json, Value};

pub fn routes() -> Router<St> {
    Router::new()
        .route("/auth/elevate", post(elevate))
        .route("/auth/elevate/end", post(end))
        .route("/settings/elevation", put(put_settings))
}

/// The elevation a session acts in (`Ctx::elevated`).
#[derive(Clone, Debug)]
pub struct Elevated {
    pub role: String,
    pub until: i64,
    pub standing: String,
    /// `sessions.id`
    pub session: i64,
}

/// Applies the session's elevation to `user` (called by the `Ctx` extractor
/// with the session row's columns). An elevation that expired or no longer
/// matches the account is cleared; then the second value is true and the
/// caller audits its end ([`audit_expired`]) after releasing the connection.
pub fn apply(
    c: &Connection,
    session: i64,
    user: &mut User,
    elevated: (Option<String>, Option<i64>),
    now: i64,
) -> ApiResult<(Option<Elevated>, bool)> {
    let (role, until) = elevated;
    if role.is_none() {
        return Ok((None, false));
    }
    match el::effective(&user.role, user.eligible_role.as_deref(), role.as_deref(), until, now) {
        Some((role, until)) => {
            let standing = std::mem::replace(&mut user.role, role.clone());
            Ok((
                Some(Elevated {
                    role,
                    until,
                    standing,
                    session,
                }),
                false,
            ))
        }
        None => {
            el::end(c, session, user.id, "web-api")?;
            Ok((None, true))
        }
    }
}

/// `/auth/me`'s `elevation`: `{role, until, standing_role}` or null.
pub fn me(ctx: &Ctx) -> Value {
    ctx.elevated.as_ref().map_or(
        Value::Null,
        |e| json!({"role": e.role, "until": e.until, "standing_role": e.standing}),
    )
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ElevateReq {
    role: String,
    minutes: i64,
    reason: String,
    current_password: Option<String>,
    current_totp: Option<String>,
}

pub async fn elevate(
    State(st): State<St>,
    ctx: Ctx,
    ClientIp(ip): ClientIp,
    J(r): J<ElevateReq>,
) -> ApiResult<Response> {
    if ctx.token.is_some() || ctx.impersonating.is_some() {
        return Err(ApiError::forbidden());
    }
    if ctx.elevated.is_some() {
        return Err(ApiError::conflict(
            "this session is elevated already: end the elevation first",
        ));
    }
    let u = &ctx.user;
    if u.eligible_role.as_deref() != Some(r.role.as_str()) || !el::can_hold(&u.role, u.tenant.as_deref(), &u.auth) {
        return Err(ApiError(
            StatusCode::FORBIDDEN,
            format!("this account is not eligible for the role {}", r.role),
        ));
    }
    if !(el::MIN_MINUTES..=el::MAX_MINUTES).contains(&r.minutes) {
        return Err(ApiError::bad(format!(
            "minutes: {}..={}",
            el::MIN_MINUTES,
            el::MAX_MINUTES
        )));
    }
    let reason = r.reason.trim().to_owned();
    if reason.is_empty() || reason.len() > 200 || reason.chars().any(char::is_control) {
        return Err(ApiError::bad("reason: 1 to 200 characters, one line"));
    }
    // the passkey policy of the role applies to the elevation (Phase 21c)
    let passkey = r
        .current_totp
        .as_deref()
        .is_some_and(|t| t.trim_start().starts_with('{'));
    if !passkey && crate::passkeys::required(&st.cat.conn(), &r.role, &u.auth)? {
        return Err(ApiError::bad(format!(
            "passkeys are required for the role {}: confirm with a passkey",
            r.role
        )));
    }
    reauth(&st, &ctx, &ip, r.current_password, r.current_totp, "role elevation").await?;
    let session: i64 = st
        .cat
        .conn()
        .query_row("SELECT id FROM sessions WHERE id_hash = ?1", [&ctx.sid], |x| x.get(0))?;
    let p = json!({"user": ctx.name(), "user_id": u.id, "session": session, "role": r.role,
                   "minutes": r.minutes, "reason": reason});
    let target = format!("user/{}", ctx.name());
    if el::settings(&st.cat.conn())?.approval {
        let o = crate::quorum::request(&st, &ctx, el::ACTION, &target, p)?;
        return Ok(accepted(o, json!({})));
    }
    let until = execute(&st.cat.conn(), &p)?;
    st.audit(ctx.name(), el::ACTION, &target, json!({"params": p, "ip": ip}))?;
    Ok(Json(json!({"elevated": until["elevated"]})).into_response())
}

/// Starts an elevation (directly or approved): `{elevated: {role, until}}`.
pub fn execute(c: &Connection, p: &Value) -> ApiResult<Value> {
    let role = p["role"].as_str().unwrap_or_default();
    let until = el::start(
        c,
        p["session"].as_i64().unwrap_or_default(),
        p["user_id"].as_i64().unwrap_or_default(),
        role,
        p["minutes"].as_i64().unwrap_or(el::MIN_MINUTES),
        p["reason"].as_str().unwrap_or_default(),
    )?
    .ok_or_else(|| {
        ApiError::conflict(
            "the requesting session has ended or the account is no longer eligible: reject this request and ask again",
        )
    })?;
    Ok(json!({"elevated": {"role": role, "until": until}}))
}

pub async fn end(State(st): State<St>, ctx: Ctx) -> ApiResult<Json<Value>> {
    let Some(e) = &ctx.elevated else {
        return Err(ApiError::conflict("this session is not elevated"));
    };
    el::end(&st.cat.conn(), e.session, ctx.user.id, ctx.name())?;
    st.audit(
        ctx.name(),
        "role.elevate_end",
        &format!("user/{}", ctx.name()),
        json!({"role": e.role, "standing_role": e.standing, "reason": "ended"}),
    )?;
    Ok(Json(json!({"role": e.standing})))
}

/// Audits an elevation that ended by itself (noticed by the `Ctx` extractor).
pub fn audit_expired(st: &St, name: &str) -> ApiResult<()> {
    st.audit(
        name,
        "role.elevate_end",
        &format!("user/{name}"),
        json!({"reason": "expired"}),
    )
}

/// Ends the session's elevation at sign-out (resolves its alert).
pub fn sign_out(c: &Connection, ctx: &Ctx) -> ApiResult<()> {
    if let Some(e) = &ctx.elevated {
        el::end(c, e.session, ctx.user.id, ctx.name())?;
    }
    Ok(())
}

/// `GET /settings/security`'s `elevation`: the setting and a pending request.
pub fn security_value(c: &Connection) -> ApiResult<Value> {
    let pending: Option<i64> = c.query_row(
        "SELECT MAX(id) FROM quorum WHERE action = ?1 AND state = 'pending'",
        [el::SETTING_ACTION],
        |r| r.get(0),
    )?;
    Ok(json!({"settings": el::settings(c)?, "pending": pending,
              "min_minutes": el::MIN_MINUTES, "max_minutes": el::MAX_MINUTES}))
}

pub async fn put_settings(State(st): State<St>, ctx: Ctx, J(new): J<Settings>) -> ApiResult<Response> {
    ctx.require(&["admin"])?;
    let old = el::settings(&st.cat.conn())?;
    let p = json!({"elevation": new, "old": old});
    if old.approval && !new.approval {
        return gate(&st, &ctx, el::SETTING_ACTION, "settings/elevation", p);
    }
    catalog::set_setting(&st.cat.conn(), el::SETTING, &json!(new).to_string())?;
    st.audit(ctx.name(), el::SETTING_ACTION, "settings/elevation", p)?;
    Ok(Json(json!(new)).into_response())
}

/// Approved `security.elevation`.
pub fn execute_settings(c: &Connection, p: &Value) -> ApiResult<()> {
    catalog::set_setting(c, el::SETTING, &p["elevation"].to_string())?;
    Ok(())
}

/// The setting now, for the quorum's "unchanged since the request" check.
pub fn settings_value(c: &Connection) -> ApiResult<Option<Value>> {
    Ok(Some(json!(el::settings(c)?)))
}

/// Accounts eligible for a role and their elevated sessions (`GET /users`
/// extras): `elevated_until` when one of its sessions is elevated now.
pub fn user_extras(c: &Connection, rows: &mut [Value]) -> ApiResult<()> {
    let now = catalog::now();
    let mut q = c.prepare("SELECT MAX(elevated_until) FROM sessions WHERE user_id = ?1 AND elevated_until > ?2")?;
    for u in rows.iter_mut() {
        let Some(id) = u["id"].as_i64() else { continue };
        let until: Option<i64> = q.query_row(params![id, now], |r| r.get(0))?;
        u["elevated_until"] = json!(until);
    }
    Ok(())
}
