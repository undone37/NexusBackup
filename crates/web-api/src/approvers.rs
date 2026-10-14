//! Tenant-side approvers (Phase 33, docs/control-plane.md "Tenant-side
//! approvers", `catalog::approvers`): a tenant opts in, and from then on its
//! tenant admins co-approve every request that destroys or weakens its data
//! (crate::quorum).
//!
//! - `GET /tenants/{name}/approvers`: the setting and the tenant's approvers with
//!   the time each may decide from (provider roles; tenant admins of the tenant).
//! - `PUT /tenants/{name}/approvers {enabled: true}`: opt in at once (an admin or
//!   a tenant admin of the tenant; it only adds protection), audited
//!   `tenant.approvers`. Needs at least one activated tenant admin.
//! - `PUT … {enabled: false}`: approval `tenant.approvers.disable`, which the
//!   tenant's approvers must co-approve like every weakening request.

use crate::auth::Ctx;
use crate::{validate, ApiError, ApiResult, St, J};
use axum::extract::{Path, State};
use axum::response::Response;
use axum::routing::get;
use axum::{Json, Router};
use catalog::approvers::{self, DISABLE_ACTION};
use catalog::rusqlite::{params, Connection, OptionalExtension};
use serde::Deserialize;
use serde_json::{json, Value};

const READERS: &[&str] = &["admin", "security_officer", "operator", "viewer", "tenant_admin"];
const WRITERS: &[&str] = &["admin", "tenant_admin"];

pub fn routes() -> Router<St> {
    Router::new().route("/tenants/{name}/approvers", get(get_approvers).put(put_approvers))
}

fn exists(c: &Connection, name: &str) -> ApiResult<()> {
    c.query_row("SELECT 1 FROM tenants WHERE name = ?1", [name], |_| Ok(()))
        .optional()?
        .ok_or_else(ApiError::not_found)
}

fn view(c: &Connection, tenant: &str) -> ApiResult<Value> {
    let row: Option<(i64, String)> = c
        .query_row(
            "SELECT enabled_at, enabled_by FROM tenant_approvals WHERE tenant = ?1",
            [tenant],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let now = catalog::now();
    let list: Vec<Value> = approvers::approvers(c, tenant)?
        .into_iter()
        .map(|a| json!({"name": a.name, "eligible_from": a.eligible_from, "eligible": a.eligible_from <= now}))
        .collect();
    let pending: Option<i64> = c
        .query_row(
            "SELECT id FROM quorum WHERE action = ?1 AND state = 'pending' AND json_extract(params, '$.tenant') = ?2",
            params![DISABLE_ACTION, tenant],
            |r| r.get(0),
        )
        .optional()?;
    Ok(json!({
        "tenant": tenant, "enabled": row.is_some(), "enabled_at": row.as_ref().map(|r| r.0),
        "enabled_by": row.map(|r| r.1), "wait_hours": approvers::WAIT_SECS / 3600, "approvers": list,
        "disable_request": pending,
    }))
}

pub async fn get_approvers(State(st): State<St>, ctx: Ctx, Path(name): Path<String>) -> ApiResult<Json<Value>> {
    ctx.require(READERS)?;
    validate::name(&name, "tenant")?;
    ctx.owns(&name)?;
    let c = st.cat.conn();
    exists(&c, &name)?;
    Ok(Json(view(&c, &name)?))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApproversReq {
    enabled: bool,
}

pub async fn put_approvers(
    State(st): State<St>,
    ctx: Ctx,
    Path(name): Path<String>,
    J(r): J<ApproversReq>,
) -> ApiResult<Response> {
    ctx.require(WRITERS)?;
    validate::name(&name, "tenant")?;
    ctx.owns(&name)?;
    if ctx.impersonating.is_some() {
        return Err(ApiError::forbidden());
    }
    let on = {
        let c = st.cat.conn();
        exists(&c, &name)?;
        approvers::enabled_at(&c, &name)?.is_some()
    };
    if r.enabled {
        if on {
            return Err(ApiError::conflict("tenant-side approvers are already required"));
        }
        let shown = {
            let c = st.cat.conn();
            if approvers::approvers(&c, &name)?.is_empty() {
                return Err(ApiError::conflict(
                    "the tenant has no activated tenant admin who could approve",
                ));
            }
            c.execute(
                "INSERT INTO tenant_approvals (tenant, enabled_at, enabled_by) VALUES (?1, ?2, ?3)",
                params![name, catalog::now(), ctx.name()],
            )?;
            view(&c, &name)?
        };
        st.audit(
            ctx.name(),
            "tenant.approvers",
            &format!("tenant/{name}"),
            json!({"tenant": name, "enabled": true}),
        )?;
        return Ok(axum::response::IntoResponse::into_response(Json(shown)));
    }
    if !on {
        return Err(ApiError::conflict("tenant-side approvers are not required"));
    }
    let pending: bool = st.cat.conn().query_row(
        "SELECT EXISTS (SELECT 1 FROM quorum WHERE action = ?1 AND state = 'pending'
           AND json_extract(params, '$.tenant') = ?2)",
        params![DISABLE_ACTION, name],
        |r| r.get(0),
    )?;
    if pending {
        return Err(ApiError::conflict("a request to switch them off is already pending"));
    }
    crate::quorum::gate(
        &st,
        &ctx,
        DISABLE_ACTION,
        &format!("tenant/{name}"),
        json!({"tenant": name}),
    )
}

/// Approved `tenant.approvers.disable` (crate::quorum).
pub fn execute_disable(c: &Connection, p: &Value) -> ApiResult<()> {
    let n = c.execute(
        "DELETE FROM tenant_approvals WHERE tenant = ?1",
        [p["tenant"].as_str().unwrap_or_default()],
    )?;
    if n != 1 {
        return Err(ApiError::conflict("tenant-side approvers are no longer required"));
    }
    Ok(())
}
