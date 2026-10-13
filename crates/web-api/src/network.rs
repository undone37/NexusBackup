//! Settings → Network (Phase 22a, docs/control-plane.md "Network interfaces"): extra NICs, bonds,
//! VLANs, MTU, static addresses and routes, interface roles. The root helper `nexus-net` writes
//! `status.json` / `ops.json` into its control dir (default /var/lib/nexus/net); the web-api
//! serves them and writes intent only: `req-<id>.json` (nexus-net.path) and `confirm.json`.
//!
//! - `GET /network` (admin, security officer, operator, viewer): devices, the applied
//!   configuration, the management interface, a change waiting for its confirmation, the
//!   path-MTU results, recent operations.
//! - `PUT /network` (admin): the whole configuration, validated here (catalog::network) and
//!   again by the helper; every change needs approval (`network.apply`). On approval the request
//!   file is written ([`after_approve`]).
//! - `POST /network/confirm` (admin) `{id, keep}`: a change of the management interface is
//!   rolled back by the helper unless confirmed within 120 s (from the new address); `keep:
//!   false` reverts at once.
//! - `POST /network/mtu-check` (admin, operator): run the path-MTU check now.

use crate::auth::{ClientIp, Ctx};
use crate::{random_hex, ApiError, ApiResult, St, J};
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use catalog::network::{self, Config, Host};
use serde::Deserialize;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

const READ: &[&str] = &["admin", "security_officer", "operator", "viewer"];
const CHECK: &[&str] = &["admin", "operator"];
const ADMIN: &[&str] = &["admin"];
pub const ACTION: &str = "network.apply";
/// The timer runs every 15 minutes: older than this is shown as stale.
const STALE_SECS: i64 = 3600;

fn dir(st: &St) -> PathBuf {
    st.net_dir
        .get_or_init(|| {
            std::env::var_os("NEXUS_NET_DIR")
                .map(Into::into)
                .unwrap_or_else(|| network::DIR.into())
        })
        .clone()
}

/// Appliance-wide: never for tenant-scoped accounts.
fn require(ctx: &Ctx, roles: &[&str]) -> ApiResult<()> {
    ctx.require(roles)?;
    if ctx.scope().is_some() {
        return Err(ApiError::forbidden());
    }
    Ok(())
}

fn read_json(p: &Path) -> Option<Value> {
    let b = std::fs::read(p).ok()?;
    (b.len() <= 4 << 20).then(|| serde_json::from_slice(&b).ok())?
}

fn status(st: &St) -> Option<Value> {
    read_json(&dir(st).join("status.json")).filter(Value::is_object)
}

/// Writes a control file for nexus-net (tmp + rename, group-readable: the helper is root
/// without DAC override, the web-api's UMask=0077 would leave 0600).
fn write_file(st: &St, name: &str, v: &Value) -> ApiResult<()> {
    let d = dir(st);
    let tmp = d.join(format!(".{name}.tmp"));
    std::fs::write(&tmp, v.to_string()).map_err(|e| anyhow::anyhow!("{}: {e}", tmp.display()))?;
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o640))
        .map_err(|e| anyhow::anyhow!("{}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, d.join(name)).map_err(|e| anyhow::anyhow!("{}: {e}", d.display()))?;
    Ok(())
}

fn submit(st: &St, by: &str, op: &str, quorum_id: Option<i64>, fields: Value) -> ApiResult<String> {
    let id = random_hex()[..32].to_owned();
    let mut req = json!({"id": id, "op": op, "by": by, "quorum_id": quorum_id});
    crate::quorum::merge(&mut req, &fields);
    write_file(st, &format!("req-{id}.json"), &req)?;
    Ok(id)
}

/// Queued requests (not picked up yet), as operations in state `queued`.
fn queued(d: &Path) -> Vec<Value> {
    let Ok(rd) = std::fs::read_dir(d) else {
        return vec![];
    };
    rd.filter_map(Result::ok)
        .filter(|e| {
            let n = e.file_name();
            let n = n.to_string_lossy();
            n.starts_with("req-") && n.ends_with(".json")
        })
        .filter_map(|e| {
            let r = read_json(&e.path())?;
            let created = e.metadata().ok()?.modified().ok()?.duration_since(std::time::UNIX_EPOCH).ok()?.as_secs();
            Some(json!({"id": r["id"], "op": r["op"], "by": r["by"], "quorum_id": r["quorum_id"], "state": "queued",
                        "created": created, "finished": null, "detail": null, "error": null,
                        "params": {"config": r["config"]}}))
        })
        .collect()
}

/// The newest pending `network.apply` request.
fn pending_request(st: &St) -> ApiResult<Option<i64>> {
    use catalog::rusqlite::OptionalExtension;
    Ok(st
        .cat
        .conn()
        .query_row(
            "SELECT id FROM quorum WHERE action = ?1 AND state = 'pending' ORDER BY id DESC LIMIT 1",
            [ACTION],
            |r| r.get(0),
        )
        .optional()?)
}

/// GET /network
pub async fn get_network(State(st): State<St>, ctx: Ctx, ClientIp(ip): ClientIp) -> ApiResult<Json<Value>> {
    require(&ctx, READ)?;
    let d = dir(&st);
    let s = status(&st);
    let mut ops: Vec<Value> = read_json(&d.join("ops.json"))
        .and_then(|v| v.as_array().cloned())
        .unwrap_or_default();
    ops.extend(queued(&d));
    ops.sort_by_key(|o| std::cmp::Reverse(o["created"].as_i64().unwrap_or(0)));
    let empty = json!({});
    let v = s.as_ref().unwrap_or(&empty);
    let now = catalog::now();
    let scanned = v["scanned"].as_i64();
    let pending = v["pending"]
        .as_object()
        .filter(|p| p["deadline"].as_i64().is_some_and(|t| t > now))
        .map(|p| json!({"id": p["id"], "by": p["by"], "deadline": p["deadline"],
                        "remaining": p["deadline"].as_i64().unwrap_or(now) - now}));
    Ok(Json(json!({
        "available": s.is_some(),
        "stale": scanned.is_some_and(|t| now - t > STALE_SECS),
        "scanned": scanned,
        "devices": v.get("devices").cloned().unwrap_or_else(|| json!([])),
        "config": serde_json::to_value(network::applied(v)).unwrap_or(Value::Null),
        "management": v.get("management").cloned().unwrap_or(Value::Null),
        "reset": v.get("reset").cloned().unwrap_or(Value::Null),
        "pending": pending,
        "mtu": v.get("mtu").cloned().unwrap_or(Value::Null),
        "ops": ops,
        "request_pending": pending_request(&st)?,
        "confirm_secs": network::CONFIRM_SECS,
        "client_ip": ip,
    })))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PutNetwork {
    config: Config,
}

/// PUT /network {config}: validated, then gated (`network.apply`).
pub async fn put_network(State(st): State<St>, ctx: Ctx, J(r): J<PutNetwork>) -> ApiResult<Response> {
    require(&ctx, ADMIN)?;
    let s = status(&st).ok_or_else(|| ApiError::conflict("no network status yet: nexus-net has not run"))?;
    if s["pending"]["deadline"].as_i64().is_some_and(|t| t > catalog::now()) {
        return Err(ApiError::conflict(
            "a change of the management interface waits for its confirmation; confirm or revert it first",
        ));
    }
    let old = network::applied(&s);
    if r.config == old {
        return Ok(Json(json!({"unchanged": true})).into_response());
    }
    network::validate(&r.config, &Host::from_status(&s)).map_err(ApiError::bad)?;
    let mgmt = network::management_changed(&old, &r.config);
    // `old` as the helper wrote it: it compares this with its applied configuration
    let params = json!({"config": r.config, "old": s["config"], "management_change": mgmt});
    crate::quorum::gate(&st, &ctx, ACTION, "network", params)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Confirm {
    id: String,
    keep: bool,
}

/// POST /network/confirm {id, keep}: keep (or revert) the management change waiting for it.
pub async fn confirm(State(st): State<St>, ctx: Ctx, ClientIp(ip): ClientIp, J(r): J<Confirm>) -> ApiResult<Response> {
    require(&ctx, ADMIN)?;
    let s = status(&st).unwrap_or(Value::Null);
    let p = &s["pending"];
    if p["id"].as_str() != Some(r.id.as_str()) || p["deadline"].as_i64().is_none_or(|t| t <= catalog::now()) {
        return Err(ApiError::conflict(
            "no such change waits for confirmation (confirmed, reverted or rolled back already)",
        ));
    }
    write_file(&st, "confirm.json", &json!({"id": r.id, "keep": r.keep, "by": ctx.name()}))?;
    let action = if r.keep { "network.confirm" } else { "network.revert" };
    st.audit(ctx.name(), action, "network", json!({"id": r.id, "from": ip}))?;
    Ok((StatusCode::ACCEPTED, Json(json!({"id": r.id, "keep": r.keep}))).into_response())
}

/// POST /network/mtu-check: the path-MTU check now (results in a few seconds).
pub async fn mtu_check(State(st): State<St>, ctx: Ctx) -> ApiResult<Response> {
    require(&ctx, CHECK)?;
    let id = submit(&st, ctx.name(), "mtu_check", None, json!({}))?;
    st.audit(ctx.name(), "network.mtu_check", "network", json!({"id": id}))?;
    Ok((StatusCode::ACCEPTED, Json(json!({"id": id, "state": "queued"}))).into_response())
}

/// After an approved (or, with approvals disabled, direct) `network.apply`: hand it to
/// nexus-net. Its outcome appears under the operations and is audited by the scheduler
/// (`network.op`).
pub fn after_approve(st: &St, action: &str, requested_by: &str, p: &Value, quorum_id: Option<i64>) {
    if action != ACTION {
        return;
    }
    let fields = json!({"config": p["config"], "old": p["old"]});
    match submit(st, requested_by, "apply", quorum_id, fields) {
        Ok(id) => eprintln!("web-api: {action} handed to nexus-net as {id}"),
        Err(e) => eprintln!("<3>web-api: after {action}: {}", e.1),
    }
}

pub fn routes() -> axum::Router<St> {
    use axum::routing::{get, post};
    axum::Router::new()
        .route("/network", get(get_network).put(put_network))
        .route("/network/confirm", post(confirm))
        .route("/network/mtu-check", post(mtu_check))
}
