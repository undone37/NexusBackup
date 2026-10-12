//! The approval system's switch (plan §2 "Approval system (quorum)", user
//! decision 2026-10-10) and the single-admin GC confirmation used while it is off.
//!
//! - Enabling: any admin, immediately (it only strengthens), audited.
//! - Disabling: quorum request `approvals.disable`, approved by one other admin
//!   or security officer (requester + 1).
//! - Enabling needs a second possible approver: otherwise nothing could ever be
//!   approved again (not even disabling).
//! - Off: a GC that would delete more than the configured share does not run; the
//!   scheduler records `gc_confirm/<tenant>` and alerts, and an admin confirms it
//!   with `POST /gc/approve-large` (audited) instead of a quorum request.

use crate::auth::Ctx;
use crate::{ApiError, ApiResult, St, J};
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use catalog::rusqlite::{params, OptionalExtension};
use serde::Deserialize;
use serde_json::{json, Value};

const ADMIN: &[&str] = &["admin"];
const READ: &[&str] = &["admin", "security_officer", "operator"];

/// Settings key prefix the scheduler writes for a GC waiting for confirmation.
pub const GC_CONFIRM: &str = "gc_confirm/";

/// Below this many possible approvers, one absence can block every approval
/// (the requester never approves their own request): `few_approvers` warning.
pub const SAFE_APPROVERS: usize = 3;

/// `{enabled, possible_approvers, recommend, few_approvers, pending_disable}`;
/// `recommend` drives the dashboard banner (approvals off although two people
/// could approve), `few_approvers` the warning that approvals are on with fewer
/// than three people who could approve (manual chapter 10: what to do when
/// approvers are unavailable).
pub async fn get_approvals(State(st): State<St>, ctx: Ctx) -> ApiResult<Json<Value>> {
    ctx.require(READ)?;
    let c = st.cat.conn();
    let enabled = catalog::approvals_enabled(&c)?;
    let n = catalog::possible_approvers(&c)?.len();
    let pending: Option<i64> = c
        .query_row(
            "SELECT id FROM quorum WHERE action = 'approvals.disable' AND state = 'pending' ORDER BY id DESC LIMIT 1",
            [],
            |r| r.get(0),
        )
        .optional()?;
    Ok(Json(json!({
        "enabled": enabled,
        "possible_approvers": n,
        "recommend": !enabled && n >= 2,
        "few_approvers": enabled && n < SAFE_APPROVERS,
        "pending_disable": pending,
    })))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalsReq {
    enabled: bool,
}

pub async fn set_approvals(State(st): State<St>, ctx: Ctx, J(r): J<ApprovalsReq>) -> ApiResult<Response> {
    ctx.require(ADMIN)?;
    let (enabled, approvers) = {
        let c = st.cat.conn();
        (catalog::approvals_enabled(&c)?, catalog::possible_approvers(&c)?)
    };
    if r.enabled == enabled {
        return Ok(Json(json!({"enabled": enabled})).into_response());
    }
    if r.enabled {
        if approvers.iter().all(|a| a == ctx.name()) {
            return Err(ApiError::conflict(
                "approvals need a second person: create and activate another admin or security officer first",
            ));
        }
        catalog::set_setting(&st.cat.conn(), "approvals_enabled", "true")?;
        st.audit(
            ctx.name(),
            "approvals.enable",
            "settings/approvals_enabled",
            json!({"enabled": true}),
        )?;
        return Ok(Json(json!({"enabled": true})).into_response());
    }
    let open: i64 = st.cat.conn().query_row(
        "SELECT COUNT(*) FROM quorum WHERE action = 'approvals.disable' AND state = 'pending'",
        [],
        |r| r.get(0),
    )?;
    if open > 0 {
        return Err(ApiError::conflict("a request to disable approvals is already pending"));
    }
    let id = crate::quorum::pending(
        &st,
        ctx.name(),
        "approvals.disable",
        "settings/approvals_enabled",
        json!({"enabled": false}),
    )?;
    Ok((StatusCode::ACCEPTED, Json(json!({"quorum_id": id}))).into_response())
}

/// GC runs waiting for an admin's confirmation (approvals disabled).
pub async fn gc_pending(State(st): State<St>, ctx: Ctx) -> ApiResult<Json<Value>> {
    ctx.require(READ)?;
    let c = st.cat.conn();
    let rows = c
        .prepare("SELECT key, value FROM settings WHERE key LIKE 'gc_confirm/%' ORDER BY key")?
        .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?
        .collect::<Result<Vec<_>, _>>()?;
    let out: Vec<Value> = rows
        .into_iter()
        .map(|(k, v)| {
            let mut v: Value = serde_json::from_str(&v).unwrap_or_else(|_| json!({}));
            v["tenant"] = json!(k.trim_start_matches(GC_CONFIRM));
            v
        })
        .collect();
    Ok(Json(Value::Array(out)))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GcApproveReq {
    tenant: String,
}

/// Approvals disabled: one admin confirms a large GC (audited). Queues a GC
/// job carrying `confirmed_by`; the scheduler honours it only while approvals
/// are still disabled.
pub async fn gc_approve_large(State(st): State<St>, ctx: Ctx, J(r): J<GcApproveReq>) -> ApiResult<Response> {
    ctx.require(ADMIN)?;
    crate::validate::name(&r.tenant, "tenant")?;
    let key = format!("{GC_CONFIRM}{}", r.tenant);
    let (job, pending) = {
        let mut c = st.cat.conn();
        let tx = c.transaction()?;
        if catalog::approvals_enabled(&tx)? {
            return Err(ApiError::conflict(
                "approvals are enabled: a large GC needs a quorum approval (Approvals page)",
            ));
        }
        let pending = catalog::setting(&tx, &key)?
            .ok_or_else(|| ApiError::conflict("no GC is waiting for confirmation for this tenant"))?;
        tx.execute("DELETE FROM settings WHERE key = ?1", [&key])?;
        tx.execute(
            "INSERT INTO jobs (kind, tenant, params, state, requested_by, created) VALUES ('gc', ?1, ?2, 'queued', ?3, ?4)",
            params![
                r.tenant,
                json!({"approved": true, "confirmed_by": ctx.name()}).to_string(),
                ctx.name(),
                catalog::now()
            ],
        )?;
        let job = tx.last_insert_rowid();
        tx.commit()?;
        (job, pending)
    };
    st.audit(
        ctx.name(),
        "gc.approve_large",
        &format!("tenant/{}", r.tenant),
        json!({"approvals": "disabled", "job": job, "pending": serde_json::from_str::<Value>(&pending).unwrap_or(Value::Null)}),
    )?;
    Ok((StatusCode::ACCEPTED, Json(json!({"job_id": job}))).into_response())
}
