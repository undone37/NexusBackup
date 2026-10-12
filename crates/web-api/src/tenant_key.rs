//! Optional per-tenant recovery key (Phase 17e, docs/key-management.md
//! "Tenant recovery key"). An admin of the tenant (appliance-wide or scoped
//! to it) requests `tenant.recovery_key`; a second person approves it while
//! approvals are enabled (the row stays `approved`, executed nowhere). The
//! requester then opens the key exactly once (`executed`): it is generated
//! at that moment, returned in the answer and never stored. The catalog keeps
//! only its public key (setting `tenant_recovery_key:<t>`), which the
//! scheduler hands to keyd before the next offsite run. Opening a new key
//! replaces the old one (its escrow files are removed from the escrow dir and
//! the box). Audit entries carry the key id, never the key.

use crate::auth::Ctx;
use crate::quorum::{accepted, request};
use crate::{ApiError, ApiResult, St};
use axum::extract::{Path, State};
use axum::response::Response;
use axum::Json;
use catalog::rusqlite::{params, Connection, OptionalExtension};
use catalog::tenant_key::{self, Status, ACTION, SHOW_TTL_SECS};
use serde_json::{json, Value};

const ADMIN: &[&str] = &["admin"];
const VIEW: &[&str] = &["admin", "security_officer"];

fn require(ctx: &Ctx, roles: &[&str], tenant: &str) -> ApiResult<()> {
    ctx.require(roles)?;
    if !ctx.sees(tenant) {
        return Err(ApiError::forbidden());
    }
    Ok(())
}

fn tenant_exists(c: &Connection, tenant: &str) -> ApiResult<()> {
    c.query_row("SELECT 1 FROM tenants WHERE name = ?1", [tenant], |_| Ok(()))
        .optional()?
        .ok_or_else(ApiError::not_found)
}

fn target(tenant: &str) -> String {
    format!("tenant/{tenant}/recovery-key")
}

struct Row {
    id: i64,
    by: String,
    created: i64,
    decided_by: Option<String>,
    decided_at: Option<i64>,
    state: String,
}

fn rows(c: &Connection, tenant: &str) -> ApiResult<Vec<Row>> {
    let mut q = c.prepare(
        "SELECT id, requested_by, created, decided_by, decided_at, state FROM quorum
         WHERE action = ?1 AND json_extract(params, '$.tenant') = ?2 ORDER BY id DESC LIMIT 20",
    )?;
    let r = q.query_map(params![ACTION, tenant], |r| {
        Ok(Row {
            id: r.get(0)?,
            by: r.get(1)?,
            created: r.get(2)?,
            decided_by: r.get(3)?,
            decided_at: r.get(4)?,
            state: r.get(5)?,
        })
    })?;
    Ok(r.collect::<Result<_, _>>()?)
}

/// `pending | rejected | approved` (ready to open) `| expired | shown`.
fn status(r: &Row, now: i64) -> &'static str {
    match r.state.as_str() {
        "pending" => "pending",
        "rejected" => "rejected",
        "approved" if r.decided_at.is_some_and(|t| t + SHOW_TTL_SECS > now) => "approved",
        "executed" => "shown",
        _ => "expired",
    }
}

/// Status of the tenant's key (no secret) and its recent requests.
pub async fn get(State(st): State<St>, ctx: Ctx, Path(tenant): Path<String>) -> ApiResult<Json<Value>> {
    require(&ctx, VIEW, &tenant)?;
    crate::quorum::expire(&st)?;
    let c = st.cat.conn();
    tenant_exists(&c, &tenant)?;
    let now = catalog::now();
    let reqs: Vec<Value> = rows(&c, &tenant)?
        .iter()
        .map(|r| {
            json!({"id": r.id, "requested_by": r.by, "created": r.created, "decided_by": r.decided_by,
                   "decided_at": r.decided_at, "show_until": r.decided_at.map(|t| t + SHOW_TTL_SECS),
                   "status": status(r, now)})
        })
        .collect();
    let key = tenant_key::get(&c, &tenant)?.map(
        |s| json!({"kid": s.kid, "set_at": s.set_at, "requested_by": s.requested_by, "approved_by": s.approved_by}),
    );
    Ok(Json(json!({"tenant": tenant, "key": key, "requests": reqs})))
}

/// Requests a new (or replacement) tenant recovery key.
pub async fn request_key(State(st): State<St>, ctx: Ctx, Path(tenant): Path<String>) -> ApiResult<Response> {
    require(&ctx, ADMIN, &tenant)?;
    crate::quorum::expire(&st)?;
    let replace = {
        let c = st.cat.conn();
        tenant_exists(&c, &tenant)?;
        let now = catalog::now();
        if rows(&c, &tenant)?
            .iter()
            .any(|r| matches!(status(r, now), "pending" | "approved"))
        {
            return Err(ApiError::conflict(
                "a request for this tenant's recovery key is still open",
            ));
        }
        tenant_key::get(&c, &tenant)?.is_some()
    };
    let o = request(
        &st,
        &ctx,
        ACTION,
        &target(&tenant),
        json!({"tenant": tenant, "replace": replace}),
    )?;
    Ok(accepted(o, json!({})))
}

/// Generates the key and shows it once, to the requester only, while the
/// request is `approved`. Replaces the tenant's previous key.
pub async fn show(State(st): State<St>, ctx: Ctx, Path((tenant, id)): Path<(String, i64)>) -> ApiResult<Json<Value>> {
    require(&ctx, ADMIN, &tenant)?;
    let now = catalog::now();
    let row = {
        let c = st.cat.conn();
        rows(&c, &tenant)?
            .into_iter()
            .find(|r| r.id == id)
            .ok_or_else(ApiError::not_found)?
    };
    if row.by != ctx.name() {
        return Err(ApiError::forbidden());
    }
    match status(&row, now) {
        "approved" => {}
        "shown" => return Err(ApiError::conflict("this key was already shown")),
        s => return Err(ApiError::conflict(format!("request is {s}"))),
    }
    let (key, public) = tenant_key::generate();
    let approved_by = row.decided_by.clone().unwrap_or_default();
    let s = Status {
        kid: public[..16].to_owned(),
        public,
        set_at: now,
        requested_by: row.by.clone(),
        approved_by: approved_by.clone(),
        quorum: id,
    };
    let previous = {
        let mut c = st.cat.conn();
        let tx = c.transaction()?;
        if tx.execute(
            "UPDATE quorum SET state = 'executed' WHERE id = ?1 AND state = 'approved'",
            [id],
        )? != 1
        {
            return Err(ApiError::conflict("this key was already shown"));
        }
        let previous = tenant_key::get(&tx, &tenant)?.map(|p| p.kid);
        tenant_key::put(&tx, &tenant, &s)?;
        tx.commit()?;
        previous
    };
    let solo = row.decided_by.as_deref() == Some(row.by.as_str());
    st.audit(
        ctx.name(),
        "tenant.recovery_key_shown",
        &target(&tenant),
        json!({"kid": s.kid, "replaced": previous, "quorum_id": id, "approved_by": approved_by,
               "approvals": if solo { "disabled" } else { "enabled" }}),
    )?;
    Ok(Json(
        json!({"tenant": tenant, "key": key.as_str(), "kid": s.kid, "replaced": previous}),
    ))
}
