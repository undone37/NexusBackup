//! Vault mode (Phase 17c, docs/control-plane.md "Vault mode"; user decision
//! 2026-10-12: a one-way profile for secondaries, switching it off needs
//! approval plus the recovery key).
//!
//! - `GET /vault`: the state; for appliance-wide roles also the preconditions.
//! - `PUT /vault {enabled: true}` (admin): approval `vault.enable`. Only on a
//!   replication secondary (≥ 1 replication source) whose tenants are all
//!   replicated, with no replication peers (it is nobody's primary), approvals
//!   enabled and the `web` inbound rule restricted (Settings → Firewall). The
//!   preconditions are checked again on approval.
//! - While on: `approvals.disable` is refused; restores, mounts and downloads
//!   become `vault.restore` requests (the web-api queues the jobs on approval,
//!   as the requester); new tenants, sources, groups, agents and replication
//!   peers are refused; the `web` inbound list cannot be emptied.
//! - `PUT /vault {enabled: false}` (admin): approval `vault.disable`, which the
//!   web-api does not execute. After approval, root at the console runs
//!   `nexus-setup vault-disable` and types the recovery key (setup::recover):
//!   the web-api has no access to keyd's escrow and is not given one.

use crate::auth::Ctx;
use crate::{ApiError, ApiResult, St, J};
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use catalog::rusqlite::{params, Connection, OptionalExtension};
use catalog::vault::{self, Vault, DISABLE, ENABLE, RESTORE};
use serde::Deserialize;
use serde_json::{json, Value};

const ADMIN: &[&str] = &["admin"];
const DETAIL: &[&str] = &["admin", "security_officer", "operator"];
/// Job kinds that need approval while vault mode is on: everything that puts
/// data back or out (restores, mounts, downloads). `files_list` (browsing a
/// snapshot's file names) stays direct.
pub const GATED_KINDS: &[&str] = &[
    "restore",
    "restore_ct",
    "instant_recover",
    "files_get",
    "restore_files",
    "plugin_restore",
    "plugin_mount",
    "offsite_restore",
];

pub fn routes() -> Router<St> {
    Router::new().route("/vault", get(get_vault).put(put_vault))
}

pub fn enabled(c: &Connection) -> ApiResult<bool> {
    Ok(vault::enabled(c)?)
}

/// 409 for `what` (e.g. "new tenants") while vault mode is on.
pub fn refuse(c: &Connection, what: &str) -> ApiResult<()> {
    if enabled(c)? {
        return Err(ApiError::conflict(format!(
            "vault mode is on: {what} are not allowed on this appliance (Settings → Vault)"
        )));
    }
    Ok(())
}

/// The preconditions of enabling, each `{ok, ..details}`.
fn checks(c: &Connection) -> ApiResult<Value> {
    let sources: i64 = c.query_row("SELECT COUNT(*) FROM replication_sources", [], |r| r.get(0))?;
    let mut local = Vec::new();
    for t in c
        .prepare("SELECT name FROM tenants ORDER BY name")?
        .query_map([], |r| r.get::<_, String>(0))?
    {
        let t = t?;
        if !crate::replication::replicated_tenant(c, &t)? {
            local.push(t);
        }
    }
    let peers: i64 = c.query_row("SELECT COUNT(*) FROM replication_peers", [], |r| r.get(0))?;
    let approvals = catalog::approvals_enabled(c)?;
    let web = catalog::firewall::load(c)?.rule("web").allow;
    Ok(json!({
        "secondary": {"ok": sources > 0, "sources": sources},
        "no_local_tenants": {"ok": local.is_empty(), "tenants": local},
        "no_peers": {"ok": peers == 0, "peers": peers},
        "approvals": {"ok": approvals},
        "web_restricted": {"ok": !web.is_empty(), "allow": web},
    }))
}

fn ready(checks: &Value) -> bool {
    checks.as_object().is_some_and(|o| o.values().all(|v| v["ok"] == true))
}

/// 409 naming the first unmet precondition.
fn require_ready(c: &Connection) -> ApiResult<()> {
    let ch = checks(c)?;
    for (k, msg) in [
        (
            "secondary",
            "this appliance is not a replication secondary (no replication source)",
        ),
        (
            "no_local_tenants",
            "some tenants are not replicated (local backup tenants)",
        ),
        (
            "no_peers",
            "this appliance is a replication primary (replication peers exist)",
        ),
        ("approvals", "approvals are disabled"),
        (
            "web_restricted",
            "the web inbound rule is not restricted (Settings → Firewall, service web)",
        ),
    ] {
        if ch[k]["ok"] != true {
            return Err(ApiError::conflict(format!("vault mode cannot be enabled: {msg}")));
        }
    }
    Ok(())
}

fn pending_id(c: &Connection, action: &str) -> ApiResult<Option<i64>> {
    Ok(c.query_row(
        "SELECT id FROM quorum WHERE action = ?1 AND state = 'pending' ORDER BY id DESC LIMIT 1",
        [action],
        |r| r.get(0),
    )
    .optional()?)
}

/// The newest approved, not yet executed `vault.disable` within its validity.
pub fn approved_disable(c: &Connection) -> ApiResult<Option<i64>> {
    Ok(c.query_row(
        "SELECT id FROM quorum WHERE action = ?1 AND state = 'approved' AND decided_at > ?2 ORDER BY id DESC LIMIT 1",
        params![DISABLE, catalog::now() - vault::DISABLE_VALID_SECS],
        |r| r.get(0),
    )
    .optional()?)
}

/// `{enabled, since, by}`; appliance-wide roles also get `checks`, `ready` and
/// the open requests (`pending_enable`, `pending_disable`, `approved_disable`).
pub async fn get_vault(State(st): State<St>, ctx: Ctx) -> ApiResult<Json<Value>> {
    let c = st.cat.conn();
    let v = vault::load(&c)?;
    let mut out = json!({"enabled": v.enabled, "since": v.since, "by": v.by});
    if ctx.require(DETAIL).is_ok() && ctx.scope().is_none() {
        let ch = checks(&c)?;
        out["ready"] = json!(ready(&ch));
        out["checks"] = ch;
        out["pending_enable"] = json!(pending_id(&c, ENABLE)?);
        out["pending_disable"] = json!(pending_id(&c, DISABLE)?);
        out["approved_disable"] = json!(approved_disable(&c)?);
    }
    Ok(Json(out))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VaultReq {
    enabled: bool,
}

pub async fn put_vault(State(st): State<St>, ctx: Ctx, J(r): J<VaultReq>) -> ApiResult<Response> {
    ctx.require(ADMIN)?;
    if ctx.scope().is_some() {
        return Err(ApiError::forbidden());
    }
    let action = if r.enabled { ENABLE } else { DISABLE };
    {
        let c = st.cat.conn();
        if vault::enabled(&c)? == r.enabled {
            return Ok(Json(json!({"enabled": r.enabled})).into_response());
        }
        if pending_id(&c, action)?.is_some() {
            return Err(ApiError::conflict(format!("a {action} request is already pending")));
        }
        if r.enabled {
            require_ready(&c)?;
        } else if approved_disable(&c)?.is_some() {
            return Err(ApiError::conflict(
                "a vault.disable request is already approved: complete it at the console (nexus-setup vault-disable)",
            ));
        }
    }
    // approvals are on (precondition, and forced while the vault is on): always pending
    let id = crate::quorum::pending(
        &st,
        ctx.name(),
        action,
        "settings/vault_mode",
        json!({"enabled": r.enabled}),
    )?;
    Ok((StatusCode::ACCEPTED, Json(json!({"quorum_id": id}))).into_response())
}

/// Approved `vault.enable` (crate::quorum): the preconditions again, then on.
pub fn execute_enable(c: &Connection, requested_by: &str) -> ApiResult<()> {
    if vault::enabled(c)? {
        return Ok(());
    }
    require_ready(c)?;
    vault::store(
        c,
        &Vault {
            enabled: true,
            since: Some(catalog::now()),
            by: Some(requested_by.to_owned()),
        },
    )?;
    Ok(())
}

/// A restore/download while vault mode is on: one `vault.restore` request
/// wrapping the jobs (`[(kind, params)]`, already validated); `None` when
/// vault mode is off (the caller queues the jobs itself).
pub fn gate_jobs(st: &St, ctx: &Ctx, tenant: &str, jobs: &[(&str, &Value)]) -> ApiResult<Option<Response>> {
    if !enabled(&st.cat.conn())? || !jobs.iter().any(|(k, _)| GATED_KINDS.contains(k)) {
        return Ok(None);
    }
    let list: Vec<Value> = jobs.iter().map(|(k, p)| json!({"kind": k, "params": p})).collect();
    let id = crate::quorum::pending(
        st,
        ctx.name(),
        RESTORE,
        &format!("tenant/{tenant}"),
        json!({"tenant": tenant, "jobs": list}),
    )?;
    Ok(Some(
        (StatusCode::ACCEPTED, Json(json!({"quorum_id": id, "vault": true}))).into_response(),
    ))
}

/// Approved `vault.restore`: queues the wrapped jobs as the requester (their
/// downloads stay theirs). Returns `{job_ids}`.
pub fn execute_restore(c: &Connection, p: &Value, requested_by: &str) -> ApiResult<Value> {
    let tenant = p["tenant"].as_str().unwrap_or_default();
    if c.query_row("SELECT 1 FROM tenants WHERE name = ?1", [tenant], |_| Ok(()))
        .optional()?
        .is_none()
    {
        return Err(ApiError::conflict("the tenant no longer exists"));
    }
    let jobs = p["jobs"]
        .as_array()
        .ok_or_else(|| ApiError::bad("quorum params: jobs"))?;
    let mut ids = Vec::new();
    for j in jobs {
        let kind = j["kind"].as_str().unwrap_or_default();
        if !GATED_KINDS.contains(&kind) && kind != "files_list" {
            return Err(ApiError::bad("quorum params: not a restore job"));
        }
        c.execute(
            "INSERT INTO jobs (kind, tenant, params, state, requested_by, created) VALUES (?1, ?2, ?3, 'queued', ?4, ?5)",
            params![kind, tenant, j["params"].to_string(), requested_by, catalog::now()],
        )?;
        ids.push(c.last_insert_rowid());
    }
    Ok(json!({"job_ids": ids}))
}
