//! Restores of flagged snapshots and frozen restores (Phase 29,
//! docs/control-plane.md "Restores of flagged snapshots"; catalog::incident).
//!
//! A production restore (catalog::incident::production_restore) of a snapshot
//! flagged as infected (an uncleared anomaly flag or YARA hit) is not queued
//! as a job: it becomes the approval request `restore.infected` (the scheduler
//! queues the job once it is approved, like `restore.replace`; one request
//! covers a replace too). With approvals disabled only administrators may do
//! it (recorded as an approved request). API tokens never. Isolated restores
//! (network disconnected, another path), downloads, mounts and restore tests
//! stay as they are. While incident mode or a tenant lockdown freezes restores
//! to production, they are refused with 409.

use crate::auth::Ctx;
use crate::{ApiError, ApiResult, St};
use axum::http::StatusCode;
use axum::response::Response;
use catalog::incident::{flagged, frozen, job_snapshot, production_restore, RESTORE_INFECTED};
use serde_json::{json, Value};

const ISOLATED: &str = "restore it isolated instead (network disconnected, or files to another path without \
                        overwriting), download it, or run a restore test";

/// 409 while restores to production are frozen for `tenant`.
pub fn refuse_frozen(c: &catalog::rusqlite::Connection, tenant: &str, kind: &str, p: &Value) -> ApiResult<()> {
    if production_restore(kind, p) && frozen(c, tenant)?.restores {
        return Err(ApiError::conflict(format!(
            "incident mode: restores to production are frozen; {ISOLATED}"
        )));
    }
    Ok(())
}

/// The job request's answer when it is a production restore of a flagged
/// snapshot (an approval request), else `None` (queue the job as usual).
pub fn gate(st: &St, ctx: &Ctx, kind: &str, tenant: &str, p: &Value) -> ApiResult<Option<Response>> {
    refuse_frozen(&st.cat.conn(), tenant, kind, p)?;
    if !production_restore(kind, p) {
        return Ok(None);
    }
    let Some((source, time)) = job_snapshot(p) else {
        return Ok(None);
    };
    let Some(reason) = flagged(&st.cat.conn(), tenant, source, time)? else {
        return Ok(None);
    };
    if ctx.token.is_some() {
        return Err(ApiError(
            StatusCode::FORBIDDEN,
            "API tokens cannot restore a snapshot flagged as infected to production".into(),
        ));
    }
    if !crate::quorum::enabled(st)? && ctx.user.role != "admin" {
        return Err(ApiError(
            StatusCode::FORBIDDEN,
            format!(
                "the snapshot is flagged as infected ({reason}): with approvals disabled only administrators \
                 restore it to production; {ISOLATED}"
            ),
        ));
    }
    let o = crate::quorum::request(
        st,
        ctx,
        RESTORE_INFECTED,
        &format!("snapshot/{tenant}/{source}/{time}"),
        json!({"tenant": tenant, "kind": kind, "params": p, "reason": reason}),
    )?;
    Ok(Some(crate::quorum::accepted(o, json!({"infected": true}))))
}
