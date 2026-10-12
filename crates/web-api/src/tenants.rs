//! Tenant deactivation (Phase 17f, catalog v22, docs/control-plane.md "Tenant
//! deactivation").
//!
//! - `POST /tenants/{name}/deactivate {reason}` (admin): approval
//!   `tenant.disable` (backups stop, a weakening of protection). On execution
//!   the tenant's accounts lose their sessions; from then on their logins,
//!   sessions and API tokens are refused ([`blocked`]), backup jobs for the
//!   tenant are refused, the scheduler skips its backups, offsite copies and
//!   replication and suppresses its alerts (one info `tenant_disabled`).
//!   Retention keeps running; snapshots stay restorable by appliance-wide roles.
//! - `POST /tenants/{name}/reactivate` (admin): immediate (it only restores
//!   protection), audited `tenant.enable`.

use crate::auth::{Ctx, User};
use crate::{validate, ApiError, ApiResult, St, J};
use axum::extract::{Path, State};
use axum::response::Response;
use axum::routing::post;
use axum::{Json, Router};
use catalog::rusqlite::{params, Connection};
use catalog::tenants::DISABLE_ACTION;
use serde::Deserialize;
use serde_json::{json, Value};

const ADMIN: &[&str] = &["admin"];
/// Job kinds a deactivated tenant no longer runs.
pub const PAUSED_KINDS: &[&str] = &["backup", "plugin_backup", "offsite", "replica_sync"];

pub fn routes() -> Router<St> {
    Router::new()
        .route("/tenants/{name}/deactivate", post(deactivate))
        .route("/tenants/{name}/reactivate", post(reactivate))
}

/// Is `user` scoped to a deactivated tenant? Their logins, sessions and API
/// tokens are refused.
pub fn blocked(c: &Connection, user: &User) -> ApiResult<bool> {
    Ok(match &user.tenant {
        Some(t) => catalog::tenants::disabled(c, t)?,
        None => false,
    })
}

/// 409 for `kind` jobs of a deactivated tenant.
pub fn refuse_paused(c: &Connection, tenant: &str, kind: &str) -> ApiResult<()> {
    if PAUSED_KINDS.contains(&kind) && catalog::tenants::disabled(c, tenant)? {
        return Err(ApiError::conflict(format!(
            "tenant {tenant} is deactivated: no {kind} jobs until it is reactivated"
        )));
    }
    Ok(())
}

fn require(ctx: &Ctx) -> ApiResult<()> {
    ctx.require(ADMIN)?;
    if ctx.scope().is_some() {
        return Err(ApiError::forbidden());
    }
    Ok(())
}

fn state(c: &Connection, name: &str) -> ApiResult<bool> {
    c.query_row("SELECT disabled FROM tenants WHERE name = ?1", [name], |r| {
        r.get::<_, bool>(0)
    })
    .map_err(|e| match e {
        catalog::rusqlite::Error::QueryReturnedNoRows => ApiError::not_found(),
        e => e.into(),
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeactivateReq {
    reason: String,
}

pub async fn deactivate(
    State(st): State<St>,
    ctx: Ctx,
    Path(name): Path<String>,
    J(r): J<DeactivateReq>,
) -> ApiResult<Response> {
    require(&ctx)?;
    validate::name(&name, "tenant")?;
    let reason = r.reason.trim();
    if reason.is_empty() || reason.chars().count() > 500 || reason.chars().any(char::is_control) {
        return Err(ApiError::bad("reason: 1 to 500 characters, one line"));
    }
    {
        let c = st.cat.conn();
        if state(&c, &name)? {
            return Err(ApiError::conflict("tenant is already deactivated"));
        }
        let open: i64 = c.query_row(
            "SELECT COUNT(*) FROM quorum WHERE action = ?1 AND state = 'pending' AND json_extract(params, '$.name') = ?2",
            params![DISABLE_ACTION, name],
            |r| r.get(0),
        )?;
        if open > 0 {
            return Err(ApiError::conflict(
                "a request to deactivate this tenant is already pending",
            ));
        }
    }
    let p = json!({"name": name, "reason": reason});
    crate::quorum::gate(&st, &ctx, DISABLE_ACTION, &format!("tenant/{name}"), p)
}

/// Approved `tenant.disable` (crate::quorum): flags the tenant and ends its
/// accounts' sessions.
pub fn execute_disable(c: &Connection, p: &Value, requested_by: &str) -> ApiResult<()> {
    let name = p["name"].as_str().unwrap_or_default();
    let n = c.execute(
        "UPDATE tenants SET disabled = 1, disabled_at = ?2, disabled_by = ?3, disabled_reason = ?4
         WHERE name = ?1 AND disabled = 0",
        params![name, catalog::now(), requested_by, p["reason"].as_str()],
    )?;
    if n != 1 {
        return Err(ApiError::conflict(
            "the tenant no longer exists or is already deactivated",
        ));
    }
    c.execute(
        "DELETE FROM sessions WHERE user_id IN (SELECT id FROM users WHERE tenant = ?1)",
        [name],
    )?;
    Ok(())
}

pub async fn reactivate(State(st): State<St>, ctx: Ctx, Path(name): Path<String>) -> ApiResult<Json<Value>> {
    require(&ctx)?;
    validate::name(&name, "tenant")?;
    let reason: Option<String> = {
        let c = st.cat.conn();
        if !state(&c, &name)? {
            return Err(ApiError::conflict("tenant is not deactivated"));
        }
        let reason = c.query_row("SELECT disabled_reason FROM tenants WHERE name = ?1", [&name], |r| {
            r.get(0)
        })?;
        c.execute(
            "UPDATE tenants SET disabled = 0, disabled_at = NULL, disabled_by = NULL, disabled_reason = NULL
             WHERE name = ?1",
            [&name],
        )?;
        reason
    };
    st.audit(
        ctx.name(),
        "tenant.enable",
        &format!("tenant/{name}"),
        json!({"was_reason": reason}),
    )?;
    Ok(Json(json!({"name": name, "disabled": false})))
}
