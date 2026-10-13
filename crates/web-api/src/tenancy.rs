//! Service-provider tenancy (Phase 19b, docs/control-plane.md "Tenant admins"):
//! policies assigned to a tenant, policy tier templates, tombstones of deleted
//! tenant names, impersonation routes and the limits of the `tenant_admin` role.

use crate::auth::{Ctx, User};
use crate::{validate, ApiError, ApiResult, St, J};
use axum::extract::{Path, State};
use axum::response::Response;
use axum::routing::{get, post, put};
use axum::{Json, Router};
use catalog::rusqlite::{Connection, OptionalExtension};
use catalog::tenancy;
use serde::Deserialize;
use serde_json::{json, Value};

/// Roles a tenant admin hands out (always in their own tenant).
pub const TENANT_ROLES: &[&str] = &["tenant_admin", "tenant_user", "viewer"];

pub fn routes() -> Router<St> {
    Router::new()
        .route("/tenants/tombstones", get(tombstones))
        .route("/tenants/{name}/policies", put(put_policies))
        .route("/tenants/{name}/impersonate", post(crate::impersonate::start))
        .route("/auth/impersonation/end", post(crate::impersonate::end))
        .route("/policies/templates", get(list_templates).post(from_template))
}

/// A tenant admin's group may only use a policy the provider assigned to the tenant.
pub fn check_policy(c: &Connection, ctx: &Ctx, tenant: &str, policy_id: i64) -> ApiResult<()> {
    if ctx.is_tenant_admin() && !tenancy::is_assigned(c, tenant, policy_id)? {
        return Err(ApiError::bad("policy_id: not assigned to this tenant"));
    }
    Ok(())
}

/// Approving a tenant admin's group change: the policy must still be assigned.
pub fn check_requested_policy(c: &Connection, p: &Value, requested_by: &str) -> ApiResult<()> {
    let role: Option<String> = c
        .query_row("SELECT role FROM users WHERE name = ?1", [requested_by], |r| r.get(0))
        .optional()?;
    let (tenant, pid) = (p["tenant"].as_str().unwrap_or_default(), p["policy_id"].as_i64());
    if role.as_deref() == Some("tenant_admin")
        && !pid.is_some_and(|id| tenancy::is_assigned(c, tenant, id).unwrap_or(false))
    {
        return Err(ApiError::conflict(
            "the policy is no longer assigned to the tenant: reject this request",
        ));
    }
    Ok(())
}

/// A tenant admin manages accounts of their own tenant with tenant roles only:
/// the account as it is (`old`, None on create) and as it would be.
pub fn check_user_change(ctx: &Ctx, old: Option<&User>, role: &str, tenant: Option<&str>) -> ApiResult<()> {
    if !ctx.is_tenant_admin() {
        return Ok(());
    }
    let own = ctx.scope();
    let fits = |r: &str, t: Option<&str>| TENANT_ROLES.contains(&r) && t.is_some() && t == own;
    if old.is_some_and(|u| !fits(&u.role, u.tenant.as_deref())) || !fits(role, tenant) {
        return Err(ApiError::forbidden());
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PoliciesReq {
    policy_ids: Vec<i64>,
}

/// Assigns policies to a tenant (admins). Directly: the assignment only limits
/// what the tenant's admins may choose; groups keep their policy.
pub async fn put_policies(
    State(st): State<St>,
    ctx: Ctx,
    Path(name): Path<String>,
    J(r): J<PoliciesReq>,
) -> ApiResult<Json<Value>> {
    ctx.require(&["admin"])?;
    if ctx.scope().is_some() {
        return Err(ApiError::forbidden());
    }
    validate::name(&name, "tenant")?;
    if r.policy_ids.len() > 256 {
        return Err(ApiError::bad("policy_ids: at most 256"));
    }
    let mut ids = r.policy_ids;
    ids.sort_unstable();
    ids.dedup();
    let old = {
        let mut c = st.cat.conn();
        let tx = c.transaction()?;
        tx.query_row("SELECT 1 FROM tenants WHERE name = ?1", [&name], |_| Ok(()))
            .optional()?
            .ok_or_else(ApiError::not_found)?;
        for id in &ids {
            tx.query_row("SELECT 1 FROM policies WHERE id = ?1", [id], |_| Ok(()))
                .optional()?
                .ok_or_else(|| ApiError::bad(format!("policy_ids: no policy {id}")))?;
        }
        let old = tenancy::assigned(&tx, &name)?;
        tenancy::assign(&tx, &name, &ids)?;
        tx.commit()?;
        old
    };
    st.audit(
        ctx.name(),
        "tenant.policies",
        &format!("tenant/{name}"),
        json!({"tenant": name, "policy_ids": ids, "old": old}),
    )?;
    Ok(Json(json!({"tenant": name, "policy_ids": ids})))
}

/// Deleted tenant names (never re-created) with their uid.
pub async fn tombstones(State(st): State<St>, ctx: Ctx) -> ApiResult<Json<Value>> {
    ctx.require(&["admin", "security_officer"])?;
    if ctx.scope().is_some() {
        return Err(ApiError::forbidden());
    }
    let c = st.cat.conn();
    let rows = c
        .prepare("SELECT name, uid, deleted_at, deleted_by FROM tenant_tombstones ORDER BY name")?
        .query_map([], |r| {
            Ok(
                json!({"name": r.get::<_, String>(0)?, "uid": r.get::<_, Option<String>>(1)?,
                      "deleted_at": r.get::<_, i64>(2)?, "deleted_by": r.get::<_, String>(3)?}),
            )
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Json(Value::Array(rows)))
}

pub async fn list_templates(_ctx: Ctx) -> Json<Value> {
    Json(tenancy::templates())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TemplateReq {
    tier: String,
    #[serde(default)]
    name: Option<String>,
}

/// Creates a policy from a tier template (admins; audited as `policy.create`).
pub async fn from_template(st: State<St>, ctx: Ctx, J(r): J<TemplateReq>) -> ApiResult<Response> {
    ctx.require(&["admin"])?;
    let t = tenancy::templates()
        .as_array()
        .and_then(|a| a.iter().find(|t| t["tier"] == r.tier.as_str()).cloned())
        .ok_or_else(|| ApiError::bad("tier: bronze, silver or gold"))?;
    let name = r
        .name
        .unwrap_or_else(|| t["name"].as_str().unwrap_or_default().to_owned());
    let req = json!({"name": name, "schedule": t["schedule"], "gfs": t["gfs"], "offsite": t["offsite"],
                     "tier": r.tier});
    let req = serde_json::from_value(req).map_err(|e| ApiError::bad(e.to_string()))?;
    crate::resources::create_policy(st, ctx, J(req)).await
}
