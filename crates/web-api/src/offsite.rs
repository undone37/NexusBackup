//! Attach an existing offsite copy to this appliance (Phase 17d, DR without
//! the console; docs/control-plane.md "Attach an offsite copy"). Two steps:
//!
//! 1. `POST /tenants/attach {name, offsite}` (admin or security_officer): the
//!    tenant's original name and its offsite target, entered as for a new
//!    tenant (S3 secret sealed to the scheduler). Approval
//!    `tenant.attach_offsite`: a *different* admin or security officer
//!    approves. The request carries no recovery key (approvers read quorum
//!    params). Once approved, the scheduler allows egress to the target.
//! 2. `POST /tenants/attach/{quorum_id}/run {recovery_key}` (the requester,
//!    within 72 h of the approval): the recovery key of the appliance that
//!    wrote the copy is sealed to the scheduler, bound to this request, into an
//!    `offsite_attach` job; the scheduler removes it from the job row when it
//!    starts the job and hands it to keyd through a one-time 0600 file. It is
//!    never stored in clear, logged or audited. A failed attempt (wrong key)
//!    can be repeated while the approval is valid; success creates the tenant.
//!
//! `offsite_list` / `offsite_restore` (browse and fetch back) are plain job
//! kinds (`jobs.rs`).

use crate::auth::Ctx;
use crate::quorum::accepted;
use crate::resources::{check_offsite, sealed_offsite};
use crate::{validate, ApiError, ApiResult, St, J};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use catalog::rusqlite::{params, OptionalExtension};
use serde::Deserialize;
use serde_json::{json, Value};

/// Quorum action (scheduler `offsite_ui.rs` uses the same name).
pub const ATTACH_ACTION: &str = "tenant.attach_offsite";
/// The requester runs an approved attach within this time (scheduler: same window).
pub const ATTACH_WINDOW_SECS: i64 = 72 * 3600;
const REQUESTERS: &[&str] = &["admin", "security_officer"];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttachReq {
    name: String,
    offsite: Value,
}

fn tenant_exists(st: &St, name: &str) -> ApiResult<bool> {
    Ok(st
        .cat
        .conn()
        .query_row("SELECT 1 FROM tenants WHERE name = ?1", [name], |_| Ok(()))
        .optional()?
        .is_some())
}

pub async fn request_attach(State(st): State<St>, ctx: Ctx, J(r): J<AttachReq>) -> ApiResult<Response> {
    ctx.require(REQUESTERS)?;
    validate::name(&r.name, "name")?;
    let s3 = check_offsite(&r.offsite)?;
    let remote = &r.offsite["remote"];
    match remote["type"].as_str() {
        Some("sftp") if remote["host"].is_string() && remote["user"].is_string() => {}
        Some("s3") if remote["secret_key"].as_str().is_some_and(|k| !k.is_empty()) => {}
        Some("s3") => return Err(ApiError::bad("offsite.remote.secret_key: required")),
        _ => {
            return Err(ApiError::bad(
                "offsite.remote: an SFTP (host, user, key_file, host_key) or S3 target",
            ))
        }
    }
    if tenant_exists(&st, &r.name)? {
        return Err(ApiError::conflict("a tenant with this name exists"));
    }
    let open: Option<i64> = st
        .cat
        .conn()
        .query_row(
            "SELECT id FROM quorum WHERE action = ?1 AND json_extract(params, '$.name') = ?2
             AND (state = 'pending' OR (state = 'approved' AND decided_at >= ?3))",
            params![ATTACH_ACTION, r.name, catalog::now() - ATTACH_WINDOW_SECS],
            |r| r.get(0),
        )
        .optional()?;
    if let Some(id) = open {
        return Err(ApiError::conflict(format!(
            "an attach request for this tenant is open (#{id})"
        )));
    }
    let offsite = sealed_offsite(&st, &r.name, &r.offsite, s3)?;
    let o = crate::quorum::request(
        &st,
        &ctx,
        ATTACH_ACTION,
        &format!("tenant/{}", r.name),
        json!({"name": r.name, "offsite": offsite}),
    )?;
    Ok(accepted(o, json!({"name": r.name})))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunReq {
    recovery_key: String,
}

/// `16 groups of 4 hex digits` (keyd's format), separators optional.
fn recovery_key(s: &str) -> ApiResult<String> {
    let h: String = s.chars().filter(|c| c.is_ascii_alphanumeric()).collect();
    if h.len() != 64 || !h.bytes().all(|b| b.is_ascii_hexdigit()) || s.len() > 200 {
        return Err(ApiError::bad("recovery_key: 64 hex digits (16 groups of 4)"));
    }
    let h = h.to_ascii_lowercase();
    Ok((0..16).map(|i| &h[i * 4..i * 4 + 4]).collect::<Vec<_>>().join("-"))
}

pub async fn run_attach(State(st): State<St>, ctx: Ctx, Path(id): Path<i64>, J(r): J<RunReq>) -> ApiResult<Response> {
    ctx.require(REQUESTERS)?;
    let row: Option<(String, String, String, Option<i64>)> = st
        .cat
        .conn()
        .query_row(
            "SELECT params, requested_by, state, decided_at FROM quorum WHERE id = ?1 AND action = ?2",
            params![id, ATTACH_ACTION],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .optional()?;
    let (p, by, state, decided) = row.ok_or_else(ApiError::not_found)?;
    if by != ctx.name() {
        return Err(ApiError(
            StatusCode::FORBIDDEN,
            "only the requester of the attach submits the recovery key".into(),
        ));
    }
    if state != "approved" {
        return Err(ApiError::conflict(format!("request is {state}")));
    }
    if decided.unwrap_or(0) < catalog::now() - ATTACH_WINDOW_SECS {
        return Err(ApiError::conflict(
            "the approval is older than 72 h: request the attach again",
        ));
    }
    let p: Value = serde_json::from_str(&p).unwrap_or_default();
    let name = p["name"].as_str().unwrap_or_default().to_owned();
    if tenant_exists(&st, &name)? {
        return Err(ApiError::conflict("a tenant with this name exists"));
    }
    let busy = st
        .cat
        .conn()
        .query_row(
            "SELECT 1 FROM jobs WHERE kind = 'offsite_attach' AND state IN ('queued','running')
             AND json_extract(params, '$.attach_quorum') = ?1",
            [id],
            |_| Ok(()),
        )
        .optional()?;
    if busy.is_some() {
        return Err(ApiError::conflict("this attach is already running"));
    }
    let rk = recovery_key(&r.recovery_key)?;
    let sealed = st
        .seal_key()?
        .seal(&catalog::secret::attach_key_location(id, &name), &rk)?;
    let job = {
        let c = st.cat.conn();
        c.execute(
            "INSERT INTO jobs (kind, tenant, params, state, requested_by, created)
             VALUES ('offsite_attach', ?1, ?2, 'queued', ?3, ?4)",
            params![
                name,
                json!({"attach_quorum": id, "recovery_key": sealed}).to_string(),
                ctx.name(),
                catalog::now()
            ],
        )?;
        c.last_insert_rowid()
    };
    st.audit(
        ctx.name(),
        "tenant.attach_offsite.run",
        &format!("tenant/{name}"),
        json!({"quorum_id": id, "job": job}),
    )?;
    Ok((StatusCode::ACCEPTED, Json(json!({"id": job}))).into_response())
}
