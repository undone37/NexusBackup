//! Tenant lockdown (Phase 28, docs/control-plane.md "Tenant lockdown"):
//! incident mode for one tenant. One action of a security officer or an admin
//! (appliance-wide, re-authenticated) that, at once and in one transaction,
//! - holds the tenant's snapshots (all, or those taken in a time range),
//! - pauses the tenant's groups indefinitely,
//! - ends the sessions and revokes the API tokens of the tenant's accounts
//!   (they cannot sign in while it lasts: `tenants::blocked`),
//! - raises the critical alert `tenant_lockdown` (tenant set).
//!
//! While it is active, deletes (snapshots, sources, groups, agents, the tenant),
//! changes of the tenant's sources, groups and agents, backups and restores that
//! overwrite (replace a guest, files with overwrite, plugin restores) are
//! refused with 409 ([`refuse`]; the scheduler refuses the same jobs).
//! Restores to new targets and downloads stay possible. Other tenants keep
//! running. Lifting is the approval action `tenant.lockdown.lift` (always a
//! second person, even with approvals disabled): the groups it paused resume,
//! the alert resolves, holds stay. State: `tenant_lockdowns` (v43).
//!
//! Freezes (Phase 29): entering may also freeze the tenant's deletions
//! (snapshot deletes, retention, GC, offsite and replica pruning) and its
//! restores to production (catalog::incident); its configuration is refused by
//! the lockdown anyway. They end with the lockdown, or earlier with the
//! approval action `incident.freeze.lift` (scope `tenant`).

use crate::auth::{reauth, ClientIp, Ctx};
use crate::{validate, ApiError, ApiResult, St, J};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use catalog::rusqlite::{params, Connection, OptionalExtension};
use catalog::tenants::{LOCKDOWN_ALERT, LOCKDOWN_LIFT};
use serde::Deserialize;
use serde_json::{json, Value};

const ENTER: &[&str] = &["security_officer", "admin"];
const READERS: &[&str] = &["admin", "security_officer", "operator", "viewer"];

pub fn routes() -> Router<St> {
    Router::new()
        .route("/lockdowns", get(list))
        .route("/tenants/{name}/lockdown", get(status).post(enter))
        .route("/tenants/{name}/lockdown/lift", post(lift))
        .route("/tenants/{name}/lockdown/freeze/lift", post(lift_freeze))
}

fn alert_key(tenant: &str) -> String {
    format!("{LOCKDOWN_ALERT}:{tenant}")
}

pub fn load(c: &Connection, tenant: &str) -> ApiResult<Option<Value>> {
    Ok(
        c.query_row("SELECT state FROM tenant_lockdowns WHERE tenant = ?1", [tenant], |r| {
            r.get::<_, String>(0)
        })
        .optional()?
        .and_then(|v| serde_json::from_str(&v).ok()),
    )
}

/// 409 while `tenant` is locked down (`what`: "deletes", "group changes", ...).
pub fn refuse(c: &Connection, tenant: &str, what: &str) -> ApiResult<()> {
    if catalog::tenants::locked_down(c, tenant)? {
        return Err(ApiError::conflict(format!(
            "tenant {tenant} is locked down: {what} are refused until the lockdown is lifted (approval)"
        )));
    }
    Ok(())
}

/// Job requests refused for a locked-down tenant: backups and restores that
/// write over existing data (`params` as checked by `jobs::check_params`).
pub fn refuse_job(c: &Connection, tenant: &str, kind: &str, params: &Value) -> ApiResult<()> {
    let overwrites = match kind {
        "backup" | "agent_update" | "agent_renew" | "plugin_restore" => true,
        "restore" | "restore_ct" => params.get("replace").is_some(),
        "restore_files" => params["overwrite"].as_str().is_some_and(|o| o != "never"),
        "synthetic_restore" => params["mode"] == "host" && params["overwrite"].as_str().is_some_and(|o| o != "never"),
        _ => false,
    };
    if overwrites {
        refuse(c, tenant, &format!("{kind} jobs that change its data"))?;
    }
    Ok(())
}

fn lift_quorum(c: &Connection, tenant: &str) -> ApiResult<Option<i64>> {
    Ok(c.query_row(
        "SELECT id FROM quorum WHERE action = ?1 AND state = 'pending' AND json_extract(params, '$.tenant') = ?2
         ORDER BY id DESC LIMIT 1",
        params![LOCKDOWN_LIFT, tenant],
        |r| r.get(0),
    )
    .optional()?)
}

fn require(ctx: &Ctx, roles: &[&str]) -> ApiResult<()> {
    ctx.require(roles)?;
    if ctx.scope().is_some() {
        return Err(ApiError::forbidden());
    }
    Ok(())
}

/// `GET /lockdowns`: the active lockdowns `[{tenant, since, by, reason, lift_quorum}]`.
pub async fn list(State(st): State<St>, ctx: Ctx) -> ApiResult<Json<Value>> {
    require(&ctx, READERS)?;
    let c = st.cat.conn();
    let tenants: Vec<String> = c
        .prepare("SELECT tenant FROM tenant_lockdowns WHERE active = 1 ORDER BY tenant")?
        .query_map([], |r| r.get(0))?
        .collect::<Result<_, _>>()?;
    let mut out = Vec::new();
    for t in tenants {
        if let Some(v) = load(&c, &t)? {
            out.push(
                json!({"tenant": t, "since": v["since"], "by": v["by"], "reason": v["reason"],
                            "lift_quorum": lift_quorum(&c, &t)?, "freeze": v["freeze"],
                            "freeze_lift_quorum": crate::incident::freeze_lift_quorum(&c, Some(&t))?}),
            );
        }
    }
    Ok(Json(Value::Array(out)))
}

/// `GET /tenants/{name}/lockdown`: the lockdown (active or the last one) or `{active: false}`.
pub async fn status(State(st): State<St>, ctx: Ctx, Path(name): Path<String>) -> ApiResult<Json<Value>> {
    require(&ctx, READERS)?;
    validate::name(&name, "tenant")?;
    let c = st.cat.conn();
    let mut v = load(&c, &name)?.unwrap_or_else(|| json!({"active": false}));
    v["lift_quorum"] = json!(lift_quorum(&c, &name)?);
    v["freeze_lift_quorum"] = json!(crate::incident::freeze_lift_quorum(&c, Some(&name))?);
    Ok(Json(v))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Range {
    from: i64,
    to: i64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnterReq {
    reason: String,
    /// absent = hold every snapshot of the tenant; `null` = hold nothing
    #[serde(default = "all", deserialize_with = "range_or_null")]
    hold: Option<Option<Range>>,
    /// Phase 29: deletions / restores to production frozen while it lasts
    #[serde(default)]
    freeze: TenantFreeze,
    current_password: Option<String>,
    current_totp: Option<String>,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct TenantFreeze {
    #[serde(default)]
    deletions: bool,
    #[serde(default)]
    restores: bool,
}

fn all() -> Option<Option<Range>> {
    None
}

fn range_or_null<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<Option<Range>>, D::Error> {
    Ok(Some(Option::<Range>::deserialize(d)?))
}

/// `POST /tenants/{name}/lockdown`: locks the tenant down (module doc).
pub async fn enter(
    State(st): State<St>,
    ctx: Ctx,
    ClientIp(ip): ClientIp,
    Path(name): Path<String>,
    J(r): J<EnterReq>,
) -> ApiResult<Response> {
    require(&ctx, ENTER)?;
    validate::name(&name, "tenant")?;
    let reason = crate::holds::reason(&r.reason)?;
    if let Some(Some(h)) = &r.hold {
        if h.from > h.to {
            return Err(ApiError::bad("hold: from must not be after to"));
        }
    }
    {
        let c = st.cat.conn();
        c.query_row("SELECT 1 FROM tenants WHERE name = ?1", [&name], |_| Ok(()))
            .optional()?
            .ok_or_else(ApiError::not_found)?;
    }
    reauth(
        &st,
        &ctx,
        &ip,
        r.current_password,
        r.current_totp,
        "lock the tenant down",
    )
    .await?;
    let now = catalog::now();
    let v = {
        let mut c = st.cat.conn();
        let tx = c.transaction()?;
        if catalog::tenants::locked_down(&tx, &name)? {
            return Err(ApiError::conflict("the tenant is already locked down"));
        }
        let mut held = Vec::new();
        if let Some(range) = match &r.hold {
            None => Some((i64::MIN, i64::MAX)),
            Some(Some(h)) => Some((h.from, h.to)),
            Some(None) => None,
        } {
            let snaps: Vec<(String, i64)> = tx
                .prepare(
                    "SELECT source, time FROM snapshots WHERE tenant = ?1 AND time BETWEEN ?2 AND ?3
                     ORDER BY source, time",
                )?
                .query_map(params![name, range.0, range.1], |x| Ok((x.get(0)?, x.get(1)?)))?
                .collect::<Result<_, _>>()?;
            let why = format!("tenant lockdown: {reason}");
            for (source, time) in snaps {
                if crate::holds::hold_one(&tx, &name, &source, time, &why, ctx.name())?.is_some() {
                    held.push(format!("{source}/{time}"));
                }
            }
        }
        let groups: Vec<(i64, Option<i64>)> = tx
            .prepare("SELECT id, paused_until FROM groups WHERE tenant = ?1 ORDER BY id")?
            .query_map([&name], |x| Ok((x.get(0)?, x.get(1)?)))?
            .collect::<Result<_, _>>()?;
        let mut paused = Vec::new();
        for (id, prev) in groups {
            if prev == Some(-1) {
                continue;
            }
            tx.execute("UPDATE groups SET paused_until = -1 WHERE id = ?1", [id])?;
            paused.push(json!({"id": id, "prev": prev}));
        }
        let sessions = tx.execute(
            "DELETE FROM sessions WHERE user_id IN (SELECT id FROM users WHERE tenant = ?1) AND id_hash != ?2",
            params![name, ctx.sid],
        )?;
        let tokens = tx.execute(
            "DELETE FROM api_tokens WHERE user_id IN (SELECT id FROM users WHERE tenant = ?1)",
            [&name],
        )?;
        let msg = format!(
            "tenant {name} locked down by {}: {reason} ({} snapshots held, {} groups paused, {sessions} sessions and \
             {tokens} API tokens of its accounts ended)",
            ctx.name(),
            held.len(),
            paused.len()
        );
        tx.execute(
            "INSERT INTO alerts (ts, last_ts, severity, kind, key, message, tenant)
             VALUES (?1, ?1, 'critical', ?2, ?3, ?4, ?5)",
            params![now, LOCKDOWN_ALERT, alert_key(&name), msg, name],
        )?;
        let alert = tx.last_insert_rowid();
        let v = json!({
            "active": true, "tenant": name, "since": now, "by": ctx.name(), "reason": reason,
            "hold": match &r.hold { None => json!("all"), Some(None) => Value::Null,
                                    Some(Some(h)) => json!({"from": h.from, "to": h.to}) },
            "held": held, "paused": paused, "sessions_ended": sessions, "tokens_revoked": tokens, "alert": alert,
            "freeze": {"config": false, "deletions": r.freeze.deletions, "restores": r.freeze.restores},
        });
        tx.execute(
            "INSERT INTO tenant_lockdowns (tenant, active, state) VALUES (?1, 1, ?2)
             ON CONFLICT (tenant) DO UPDATE SET active = 1, state = ?2",
            params![name, v.to_string()],
        )?;
        tx.commit()?;
        v
    };
    st.audit(
        ctx.name(),
        "tenant.lockdown",
        &format!("tenant/{name}"),
        json!({"ip": ip, "lockdown": v}),
    )?;
    Ok((StatusCode::CREATED, Json(v)).into_response())
}

/// `POST /tenants/{name}/lockdown/lift`: the approval request `tenant.lockdown.lift`.
pub async fn lift(State(st): State<St>, ctx: Ctx, Path(name): Path<String>) -> ApiResult<Response> {
    require(&ctx, ENTER)?;
    validate::name(&name, "tenant")?;
    let since = {
        let c = st.cat.conn();
        let Some(v) = load(&c, &name)?.filter(|v| v["active"] == true) else {
            return Err(ApiError::conflict("the tenant is not locked down"));
        };
        if lift_quorum(&c, &name)?.is_some() {
            return Err(ApiError::conflict("lifting the lockdown is already requested"));
        }
        v["since"].clone()
    };
    let id = crate::quorum::pending(
        &st,
        ctx.name(),
        LOCKDOWN_LIFT,
        &format!("tenant/{name}"),
        json!({"tenant": name, "since": since}),
    )?;
    Ok((StatusCode::ACCEPTED, Json(json!({"quorum_id": id}))).into_response())
}

/// `POST /tenants/{name}/lockdown/freeze/lift`: the approval request
/// `incident.freeze.lift` for the lockdown's freezes (always a second person).
pub async fn lift_freeze(State(st): State<St>, ctx: Ctx, Path(name): Path<String>) -> ApiResult<Response> {
    require(&ctx, ENTER)?;
    validate::name(&name, "tenant")?;
    let since = {
        let c = st.cat.conn();
        let Some(v) = load(&c, &name)?.filter(|v| v["active"] == true) else {
            return Err(ApiError::conflict("the tenant is not locked down"));
        };
        if !catalog::incident::tenant(&c, &name)?.any() {
            return Err(ApiError::conflict("nothing is frozen"));
        }
        if crate::incident::freeze_lift_quorum(&c, Some(&name))?.is_some() {
            return Err(ApiError::conflict("lifting the freezes is already requested"));
        }
        v["since"].clone()
    };
    let id = crate::quorum::pending(
        &st,
        ctx.name(),
        catalog::incident::FREEZE_LIFT,
        &format!("tenant/{name}"),
        json!({"scope": "tenant", "tenant": name, "since": since}),
    )?;
    Ok((StatusCode::ACCEPTED, Json(json!({"quorum_id": id}))).into_response())
}

/// Quorum execute arm of `tenant.lockdown.lift`.
pub fn execute(c: &Connection, p: &Value, approver: &str, requested_by: &str) -> ApiResult<()> {
    let tenant = p["tenant"].as_str().unwrap_or_default();
    let mut v = load(c, tenant)?
        .filter(|v| v["active"] == true && v["since"] == p["since"])
        .ok_or_else(|| ApiError::conflict("this lockdown is no longer active"))?;
    let now = catalog::now();
    let mut resumed = 0;
    for g in v["paused"].as_array().cloned().unwrap_or_default() {
        let prev = g["prev"].as_i64().filter(|p| *p == -1 || *p > now);
        resumed += c.execute(
            "UPDATE groups SET paused_until = ?2 WHERE id = ?1 AND paused_until = -1",
            params![g["id"].as_i64(), prev],
        )?;
    }
    c.execute(
        "UPDATE alerts SET resolved_at = ?2, resolved_by = ?3 WHERE key = ?1 AND resolved_at IS NULL",
        params![alert_key(tenant), now, approver],
    )?;
    v["active"] = json!(false);
    v["ended_at"] = json!(now);
    v["ended_by"] = json!(requested_by);
    v["approved_by"] = json!(approver);
    v["resumed"] = json!(resumed);
    c.execute(
        "UPDATE tenant_lockdowns SET active = 0, state = ?2 WHERE tenant = ?1",
        params![tenant, v.to_string()],
    )?;
    Ok(())
}
