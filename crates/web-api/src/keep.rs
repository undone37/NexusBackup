//! "Back up now, keep until `<date>`" (Phase 23a, Veeam comparison row 11):
//! `backup` / `plugin_backup` jobs take `keep_until` (unix seconds). After the
//! job finished ok the scheduler extends the store lock of every snapshot it
//! wrote to that date (`chunkstore::Store::extend_lock`, scheduler `keep.rs`):
//! retention, GC and `snapshot.delete` cannot remove them before, nobody can
//! shorten the lock. The snapshots still take part in the normal GFS selection.
//!
//! Locks cannot be undone and hold storage, so a date further out than the
//! setting `keep_until_max_days` (default 90) needs approval: the job request
//! becomes the quorum action [`ACTION`], executed by queuing the job.
//! `GET|PUT /settings/keep-until {max_days}` (admin): lowering applies at once,
//! raising is the approval action [`SETTING_ACTION`].

use crate::auth::Ctx;
use crate::quorum::gate;
use crate::{ApiError, ApiResult, St, J};
use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::Json;
use catalog::rusqlite::{params, Connection};
use serde::Deserialize;
use serde_json::{json, Value};

pub const ACTION: &str = "backup.keep";
pub const SETTING_ACTION: &str = "settings.keep_until";
pub const SETTING: &str = "keep_until_max_days";
pub const DEFAULT_DAYS: i64 = 90;
/// Longest lock an ad-hoc backup can get at all.
pub const MAX_DAYS: i64 = 3650;
const DAY: i64 = 86400;

pub fn max_days(c: &Connection) -> ApiResult<i64> {
    Ok(catalog::setting(c, SETTING)?
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_DAYS))
}

/// `keep_until` of a backup request: at least an hour, at most [`MAX_DAYS`] ahead.
pub fn check(keep_until: Option<i64>) -> ApiResult<()> {
    let now = catalog::now();
    match keep_until {
        Some(t) if t < now + 3600 || t > now + MAX_DAYS * DAY => Err(ApiError::bad(format!(
            "keep_until: a time between one hour and {MAX_DAYS} days from now"
        ))),
        _ => Ok(()),
    }
}

/// A backup to keep longer than the setting allows: the approval request
/// (answered by the caller), else `None` (queue the job as usual).
pub fn gate_job(st: &St, ctx: &Ctx, kind: &str, tenant: &str, params: &Value) -> ApiResult<Option<Response>> {
    let Some(until) = params["keep_until"].as_i64() else {
        return Ok(None);
    };
    let limit = max_days(&st.cat.conn())?;
    if until <= catalog::now() + limit * DAY {
        return Ok(None);
    }
    let p = json!({"tenant": tenant, "kind": kind, "params": params, "max_days": limit});
    gate(st, ctx, ACTION, &format!("tenant/{tenant}"), p).map(Some)
}

/// Approved [`ACTION`]: queues the backup job (requested by the requester).
pub fn execute(c: &Connection, p: &Value, requested_by: &str) -> ApiResult<Value> {
    let (tenant, kind) = (
        p["tenant"].as_str().unwrap_or_default(),
        p["kind"].as_str().unwrap_or_default(),
    );
    if !matches!(kind, "backup" | "plugin_backup") {
        return Err(ApiError::bad("quorum params: kind"));
    }
    crate::tenants::refuse_paused(c, tenant, kind)?;
    c.execute(
        "INSERT INTO jobs (kind, tenant, params, state, requested_by, created) VALUES (?1, ?2, ?3, 'queued', ?4, ?5)",
        params![kind, tenant, p["params"].to_string(), requested_by, catalog::now()],
    )?;
    Ok(json!({"job_id": c.last_insert_rowid()}))
}

pub async fn get_setting(State(st): State<St>, ctx: Ctx) -> ApiResult<Json<Value>> {
    ctx.require(&["admin", "security_officer", "operator"])?;
    Ok(Json(json!({"max_days": max_days(&st.cat.conn())?})))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SettingReq {
    max_days: i64,
}

pub async fn put_setting(State(st): State<St>, ctx: Ctx, J(r): J<SettingReq>) -> ApiResult<Response> {
    ctx.require(&["admin"])?;
    if !(1..=MAX_DAYS).contains(&r.max_days) {
        return Err(ApiError::bad(format!("max_days: 1..={MAX_DAYS}")));
    }
    let old = max_days(&st.cat.conn())?;
    if r.max_days > old {
        let p = json!({"max_days": r.max_days, "old": old});
        return gate(&st, &ctx, SETTING_ACTION, "settings/keep_until", p);
    }
    catalog::set_setting(&st.cat.conn(), SETTING, &r.max_days.to_string())?;
    st.audit(
        ctx.name(),
        SETTING_ACTION,
        "settings/keep_until",
        json!({"max_days": r.max_days, "old": old}),
    )?;
    Ok(Json(json!({"max_days": r.max_days})).into_response())
}

/// Approved [`SETTING_ACTION`] (refused when the value changed since the request).
pub fn execute_setting(c: &Connection, p: &Value) -> ApiResult<()> {
    if json!(max_days(c)?) != p["old"] {
        return Err(ApiError::conflict(
            "the setting changed since this request was made; reject it and request the change again",
        ));
    }
    let n = p["max_days"].as_i64().filter(|n| (1..=MAX_DAYS).contains(n));
    let n = n.ok_or_else(|| ApiError::bad("quorum params: max_days"))?;
    catalog::set_setting(c, SETTING, &n.to_string())?;
    Ok(())
}
