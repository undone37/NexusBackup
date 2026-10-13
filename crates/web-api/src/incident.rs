//! Incident mode (Phase 21b, docs/control-plane.md "Incident mode"): one
//! action of a security officer (re-authenticated) that, at once and in one
//! transaction,
//! - holds the snapshots of the chosen tenants / sources taken in a time range
//!   (legal holds, crate::holds; released one by one through approval as ever),
//! - pauses all groups or the chosen ones indefinitely (crate::runctl),
//! - ends every session except the officer's own and revokes all API tokens,
//! - raises the critical alert `incident` (banner for appliance-wide roles,
//!   state on the dashboard).
//!
//! While it is active no group can be resumed. Leaving is the approval action
//! `incident.leave`, requested by a security officer or an admin and approved by
//! another approver even while approvals are disabled (like `approvals.disable`):
//! groups the incident paused are resumed (to their earlier pause, if any),
//! the alert is resolved; holds stay. State: setting `incident` (the last
//! incident is kept with `active: false`); history: the audit log.

use crate::auth::{reauth, ClientIp, Ctx};
use crate::{validate, ApiError, ApiResult, St, J};
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use catalog::rusqlite::{params, Connection, OptionalExtension};
use serde::Deserialize;
use serde_json::{json, Value};

pub const SETTING: &str = "incident";
pub const LEAVE: &str = "incident.leave";
const ALERT_KEY: &str = "incident";
const ENTER: &[&str] = &["security_officer"];
const LEAVERS: &[&str] = &["security_officer", "admin"];
const READERS: &[&str] = &["admin", "security_officer", "operator", "viewer"];

pub fn routes() -> Router<St> {
    Router::new()
        .route("/incident", get(status).post(enter))
        .route("/incident/leave", post(leave))
}

/// The stored incident (active or the last one), if any.
pub fn load(c: &Connection) -> ApiResult<Option<Value>> {
    Ok(catalog::setting(c, SETTING)?.and_then(|v| serde_json::from_str(&v).ok()))
}

pub fn active(c: &Connection) -> ApiResult<bool> {
    Ok(load(c)?.is_some_and(|v| v["active"] == true))
}

/// 409 while incident mode is active (e.g. resuming a group).
pub fn refuse_while_active(c: &Connection) -> ApiResult<()> {
    if active(c)? {
        return Err(ApiError::conflict(
            "incident mode is active: groups stay paused until it is left (approval)",
        ));
    }
    Ok(())
}

/// The banner (`/auth/me`, dashboard): `{since, by, reason}` for appliance-wide
/// accounts while active, else null.
pub fn banner(c: &Connection, ctx: &Ctx) -> ApiResult<Value> {
    if ctx.scope().is_some() || ctx.user.role == "tenant_user" {
        return Ok(Value::Null);
    }
    Ok(load(c)?.filter(|v| v["active"] == true).map_or(
        Value::Null,
        |v| json!({"since": v["since"], "by": v["by"], "reason": v["reason"]}),
    ))
}

fn leave_quorum(c: &Connection) -> ApiResult<Option<i64>> {
    Ok(c.query_row(
        "SELECT id FROM quorum WHERE action = ?1 AND state = 'pending' ORDER BY id DESC LIMIT 1",
        [LEAVE],
        |r| r.get(0),
    )
    .optional()?)
}

/// `GET /incident`: the incident (or `{active: false}`) and the pending leave request.
pub async fn status(State(st): State<St>, ctx: Ctx) -> ApiResult<Json<Value>> {
    ctx.require(READERS)?;
    if ctx.scope().is_some() {
        return Err(ApiError::forbidden());
    }
    let c = st.cat.conn();
    let mut v = load(&c)?.unwrap_or_else(|| json!({"active": false}));
    v["leave_quorum"] = json!(leave_quorum(&c)?);
    Ok(Json(v))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HoldScope {
    /// empty = every tenant
    #[serde(default)]
    tenants: Vec<String>,
    /// empty = every source of those tenants
    #[serde(default)]
    sources: Vec<String>,
    from: i64,
    to: i64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnterReq {
    reason: String,
    /// absent = hold nothing
    #[serde(default)]
    hold: Option<HoldScope>,
    /// absent = pause every group; `[]` = none
    #[serde(default)]
    groups: Option<Vec<i64>>,
    current_password: Option<String>,
    current_totp: Option<String>,
}

/// `POST /incident`: enters incident mode (security officer, re-authenticated).
pub async fn enter(State(st): State<St>, ctx: Ctx, ClientIp(ip): ClientIp, J(r): J<EnterReq>) -> ApiResult<Response> {
    ctx.require(ENTER)?;
    if ctx.scope().is_some() {
        return Err(ApiError::forbidden());
    }
    let reason = crate::holds::reason(&r.reason)?;
    if let Some(h) = &r.hold {
        for t in &h.tenants {
            validate::name(t, "tenant")?;
        }
        for s in &h.sources {
            validate::source_ref(s)?;
        }
        if h.from > h.to {
            return Err(ApiError::bad("hold: from must not be after to"));
        }
    }
    reauth(
        &st,
        &ctx,
        &ip,
        r.current_password,
        r.current_totp,
        "enter incident mode",
    )
    .await?;
    let now = catalog::now();
    let v = {
        let mut c = st.cat.conn();
        let tx = c.transaction()?;
        if active(&tx)? {
            return Err(ApiError::conflict("incident mode is already active"));
        }
        // holds
        let mut held = Vec::new();
        if let Some(h) = &r.hold {
            let known: Vec<String> = tx
                .prepare("SELECT name FROM tenants ORDER BY name")?
                .query_map([], |x| x.get(0))?
                .collect::<Result<_, _>>()?;
            if let Some(t) = h.tenants.iter().find(|t| !known.contains(t)) {
                return Err(ApiError::bad(format!("hold: no tenant {t}")));
            }
            let tenants = if h.tenants.is_empty() { &known } else { &h.tenants };
            for t in tenants {
                let snaps: Vec<(String, i64)> = tx
                    .prepare(
                        "SELECT source, time FROM snapshots WHERE tenant = ?1 AND time BETWEEN ?2 AND ?3
                         ORDER BY source, time",
                    )?
                    .query_map(params![t, h.from, h.to], |x| Ok((x.get(0)?, x.get(1)?)))?
                    .collect::<Result<_, _>>()?;
                for (source, time) in snaps {
                    if !h.sources.is_empty() && !h.sources.contains(&source) {
                        continue;
                    }
                    let why = format!("incident: {reason}");
                    if crate::holds::hold_one(&tx, t, &source, time, &why, ctx.name())?.is_some() {
                        held.push(format!("{t}/{source}/{time}"));
                    }
                }
            }
        }
        // pauses: indefinitely; the earlier pause is restored when leaving
        let all: Vec<(i64, Option<i64>)> = tx
            .prepare("SELECT id, paused_until FROM groups ORDER BY id")?
            .query_map([], |x| Ok((x.get(0)?, x.get(1)?)))?
            .collect::<Result<_, _>>()?;
        if let Some(ids) = &r.groups {
            if let Some(id) = ids.iter().find(|id| !all.iter().any(|(g, _)| g == *id)) {
                return Err(ApiError::bad(format!("groups: no group {id}")));
            }
        }
        let mut paused = Vec::new();
        for (id, prev) in all {
            if r.groups.as_ref().is_some_and(|ids| !ids.contains(&id)) || prev == Some(-1) {
                continue;
            }
            tx.execute("UPDATE groups SET paused_until = -1 WHERE id = ?1", [id])?;
            paused.push(json!({"id": id, "prev": prev}));
        }
        let sessions = tx.execute("DELETE FROM sessions WHERE id_hash != ?1", [&ctx.sid])?;
        let tokens = tx.execute("DELETE FROM api_tokens", [])?;
        let msg = format!(
            "incident mode entered by {}: {reason} ({} snapshots held, {} groups paused, {sessions} sessions and \
             {tokens} API tokens ended)",
            ctx.name(),
            held.len(),
            paused.len()
        );
        tx.execute(
            "INSERT INTO alerts (ts, last_ts, severity, kind, key, message) VALUES (?1, ?1, 'critical', 'incident', ?2, ?3)",
            params![now, ALERT_KEY, msg],
        )?;
        let alert = tx.last_insert_rowid();
        let v = json!({
            "active": true, "since": now, "by": ctx.name(), "reason": reason,
            "hold": r.hold.as_ref().map(|h| json!({"tenants": h.tenants, "sources": h.sources, "from": h.from, "to": h.to})),
            "held": held, "paused": paused, "sessions_ended": sessions, "tokens_revoked": tokens, "alert": alert,
        });
        catalog::set_setting(&tx, SETTING, &v.to_string())?;
        tx.commit()?;
        v
    };
    st.audit(
        ctx.name(),
        "incident.enter",
        "appliance",
        json!({"ip": ip, "incident": v}),
    )?;
    Ok((StatusCode::CREATED, Json(v)).into_response())
}

/// `POST /incident/leave`: the approval request `incident.leave` (always a
/// second person, see the module doc).
pub async fn leave(State(st): State<St>, ctx: Ctx) -> ApiResult<Response> {
    ctx.require(LEAVERS)?;
    if ctx.scope().is_some() {
        return Err(ApiError::forbidden());
    }
    let since = {
        let c = st.cat.conn();
        let v = load(&c)?.filter(|v| v["active"] == true);
        let Some(v) = v else {
            return Err(ApiError::conflict("incident mode is not active"));
        };
        if leave_quorum(&c)?.is_some() {
            return Err(ApiError::conflict("leaving incident mode is already requested"));
        }
        v["since"].clone()
    };
    let id = crate::quorum::pending(&st, ctx.name(), LEAVE, "appliance", json!({"since": since}))?;
    Ok((StatusCode::ACCEPTED, Json(json!({"quorum_id": id}))).into_response())
}

/// Quorum execute arm of `incident.leave`.
pub fn execute(c: &Connection, p: &Value, approver: &str, requested_by: &str) -> ApiResult<()> {
    let mut v = load(c)?
        .filter(|v| v["active"] == true && v["since"] == p["since"])
        .ok_or_else(|| ApiError::conflict("this incident is no longer active"))?;
    let now = catalog::now();
    let mut resumed = 0;
    for g in v["paused"].as_array().cloned().unwrap_or_default() {
        // only what is still the incident's pause; an earlier pause that has not run out comes back
        let prev = g["prev"].as_i64().filter(|p| *p == -1 || *p > now);
        resumed += c.execute(
            "UPDATE groups SET paused_until = ?2 WHERE id = ?1 AND paused_until = -1",
            params![g["id"].as_i64(), prev],
        )?;
    }
    c.execute(
        "UPDATE alerts SET resolved_at = ?2, resolved_by = ?3 WHERE key = ?1 AND resolved_at IS NULL",
        params![ALERT_KEY, now, approver],
    )?;
    v["active"] = json!(false);
    v["ended_at"] = json!(now);
    v["ended_by"] = json!(requested_by);
    v["approved_by"] = json!(approver);
    v["resumed"] = json!(resumed);
    catalog::set_setting(c, SETTING, &v.to_string())?;
    Ok(())
}
