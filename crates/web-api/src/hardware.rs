//! Configuration → Hardware (Phase 16a/b, docs/hardware.md): disks, SMART, md arrays and
//! the data-array layout. The root helper `nexus-disks` scans every 5 minutes and writes
//! `status.json` / `ops.json` into its control dir (default /var/lib/nexus/disks); the
//! web-api serves them and writes intent only: `req-<id>.json`, which `nexus-disks.path`
//! hands to the helper.
//!
//! Reading: admins, security officers, operators and viewers (appliance-wide accounts).
//! Rescan: admins and operators. SMART self-tests: admins (audited). Layout changes
//! (create the data array, add a spare, replace a disk, grow) are requested by an admin
//! with the serial numbers of the disks typed in as confirmation and go through approval
//! (`disks.*`); on approval the request file is written (see [`after_approve`]). The
//! checks here (empty disks only, never system disks, store empty) are repeated by the
//! helper right before it acts.

use crate::auth::Ctx;
use crate::{random_hex, ApiError, ApiResult, St, J};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use catalog::hardware;
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::path::PathBuf;

const READ: &[&str] = &["admin", "security_officer", "operator", "viewer"];
const SCAN: &[&str] = &["admin", "operator"];
const ADMIN: &[&str] = &["admin"];
/// The scan runs every 5 minutes: older than this is shown as stale.
const STALE_SECS: i64 = 900;
pub const ACTIONS: &[&str] = &["disks.create_array", "disks.add_spare", "disks.replace", "disks.grow"];
const LEVELS: &[(&str, usize)] = &[("raid1", 2), ("raid5", 3), ("raid6", 4), ("raid10", 4)];

fn dir(st: &St) -> PathBuf {
    st.disks_dir
        .get_or_init(|| {
            std::env::var_os("NEXUS_DISKS_DIR")
                .map(Into::into)
                .unwrap_or_else(|| hardware::DIR.into())
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

fn read_json(p: &std::path::Path) -> Option<Value> {
    let b = std::fs::read(p).ok()?;
    (b.len() <= 4 << 20).then(|| serde_json::from_slice(&b).ok())?
}

fn status(st: &St) -> Option<Value> {
    read_json(&dir(st).join("status.json")).filter(Value::is_object)
}

/// The current status, or 409 when the helper has not reported yet.
fn current(st: &St) -> ApiResult<Value> {
    status(st).ok_or_else(|| ApiError::conflict("no disk status yet: nexus-disks has not run"))
}

/// Writes a request for nexus-disks (tmp + rename); returns its id.
fn submit(st: &St, by: &str, op: &str, quorum_id: Option<i64>, fields: Value) -> ApiResult<String> {
    let d = dir(st);
    let id = random_hex()[..32].to_owned();
    let mut req = json!({"id": id, "op": op, "by": by, "quorum_id": quorum_id});
    crate::quorum::merge(&mut req, &fields);
    let tmp = d.join(format!(".req-{id}.tmp"));
    std::fs::write(&tmp, req.to_string()).map_err(|e| anyhow::anyhow!("{}: {e}", tmp.display()))?;
    // group-readable for nexus-disks (root, group nexus-webapi, no DAC override); the
    // web-api's UMask=0077 would leave 0600
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o640))
        .map_err(|e| anyhow::anyhow!("{}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, d.join(format!("req-{id}.json"))).map_err(|e| anyhow::anyhow!("{}: {e}", d.display()))?;
    Ok(id)
}

/// Queued requests (not picked up yet), as operations in state `queued`.
fn queued(d: &std::path::Path) -> Vec<Value> {
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
            let created = e
                .metadata()
                .ok()?
                .modified()
                .ok()?
                .duration_since(std::time::UNIX_EPOCH)
                .ok()?
                .as_secs();
            let mut params = r.clone();
            for k in ["id", "op", "by", "quorum_id"] {
                params.as_object_mut()?.remove(k);
            }
            Some(
                json!({"id": r["id"], "op": r["op"], "by": r["by"], "quorum_id": r["quorum_id"], "state": "queued",
                        "created": created, "finished": null, "detail": null, "error": null, "params": params}),
            )
        })
        .collect()
}

fn with_issues(list: &Value, f: fn(&Value) -> hardware::Issues) -> Value {
    Value::Array(
        list.as_array()
            .into_iter()
            .flatten()
            .map(|x| {
                let mut x = x.clone();
                x["issues"] = f(&x)
                    .into_iter()
                    .map(|(s, m)| json!({"severity": s, "message": m}))
                    .collect();
                x
            })
            .collect(),
    )
}

/// GET /hardware: disks with SMART, arrays, the store, recent operations, a summary.
pub async fn get_status(State(st): State<St>, ctx: Ctx) -> ApiResult<Json<Value>> {
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
    let scanned = v["scanned"].as_i64();
    Ok(Json(json!({
        "available": s.is_some(),
        "stale": scanned.is_some_and(|t| catalog::now() - t > STALE_SECS),
        "scanned": scanned,
        "smart_scanned": v["smart_scanned"],
        "tools": v.get("tools").cloned().unwrap_or_else(|| json!({"smartctl": false, "mdadm": false})),
        "store": v.get("store").cloned().unwrap_or(Value::Null),
        "summary": hardware::summary(s.as_ref()),
        "disks": with_issues(&v["disks"], hardware::disk_issues),
        "arrays": with_issues(&v["arrays"], hardware::array_issues),
        "ops": ops,
    })))
}

fn accepted(id: String) -> Response {
    (StatusCode::ACCEPTED, Json(json!({"id": id, "state": "queued"}))).into_response()
}

/// POST /hardware/scan: rescan now, SMART included.
pub async fn scan(State(st): State<St>, ctx: Ctx) -> ApiResult<Response> {
    require(&ctx, SCAN)?;
    let id = submit(&st, ctx.name(), "scan", None, json!({}))?;
    st.audit(ctx.name(), "hardware.scan", "hardware", json!({"id": id}))?;
    Ok(accepted(id))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelfTest {
    disk: String,
    #[serde(rename = "type")]
    kind: String,
}

fn disk<'a>(s: &'a Value, serial: &str) -> ApiResult<&'a Value> {
    s["disks"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|d| d["serial"] == serial)
        .ok_or_else(|| ApiError(StatusCode::NOT_FOUND, format!("no disk with serial {serial}")))
}

/// POST /hardware/selftest {disk, type: short|long}: a SMART self-test (the disk keeps working).
pub async fn selftest(State(st): State<St>, ctx: Ctx, J(r): J<SelfTest>) -> ApiResult<Response> {
    require(&ctx, ADMIN)?;
    if !matches!(r.kind.as_str(), "short" | "long") {
        return Err(ApiError::bad("type must be short or long"));
    }
    let s = current(&st)?;
    let d = disk(&s, &r.disk)?;
    if d["smart"]["available"] != Value::Bool(true) {
        return Err(ApiError::conflict(format!(
            "SMART is not available on {} ({})",
            r.disk,
            d["name"].as_str().unwrap_or("?")
        )));
    }
    let id = submit(
        &st,
        ctx.name(),
        "selftest",
        None,
        json!({"disk": r.disk, "type": r.kind}),
    )?;
    st.audit(
        ctx.name(),
        "hardware.selftest",
        &format!("disk/{}", r.disk),
        json!({"type": r.kind, "id": id, "device": d["name"]}),
    )?;
    Ok(accepted(id))
}

// ---------------------------------------------------------------- layout (approval)

/// The typed confirmation must name exactly these serials (any order, spaces or commas).
fn confirmed(confirm: &str, serials: &[String]) -> ApiResult<()> {
    let typed: BTreeSet<&str> = confirm
        .split(|c: char| c.is_whitespace() || c == ',')
        .filter(|s| !s.is_empty())
        .collect();
    let want: BTreeSet<&str> = serials.iter().map(String::as_str).collect();
    if typed != want {
        return Err(ApiError::bad(if serials.len() == 1 {
            "type the serial number of the new disk to confirm (it is overwritten)"
        } else {
            "type the serial numbers of the selected disks to confirm (they are overwritten)"
        }));
    }
    Ok(())
}

/// An empty disk (no partitions, signatures, array or mount: the helper's role `empty`),
/// at least `min_size` bytes; returned as shown to the approver.
fn empty_disk(s: &Value, serial: &str, min_size: Option<i64>) -> ApiResult<Value> {
    let d = disk(s, serial)?;
    let name = d["name"].as_str().unwrap_or("?");
    if d["role"] != "empty" {
        let why = d["why"].as_str().map(|w| format!(", {w}")).unwrap_or_default();
        return Err(ApiError::conflict(format!(
            "disk {serial} ({name}) is not empty: {}{why}",
            d["role"].as_str().unwrap_or("?")
        )));
    }
    if let Some(min) = min_size.filter(|m| d["size"].as_i64().unwrap_or(0) < *m) {
        return Err(ApiError::conflict(format!(
            "disk {serial} ({name}) is smaller than the array members ({min} bytes needed)"
        )));
    }
    Ok(json!({"serial": serial, "model": d["model"], "size": d["size"], "name": name}))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateArray {
    role: String,
    level: String,
    disks: Vec<String>,
    confirm: String,
}

/// POST /hardware/arrays {role: data, level, disks: [serials], confirm}: the data array
/// (mdadm + XFS, mounted as the store). Only from empty disks, only while the store is empty.
pub async fn create_array(State(st): State<St>, ctx: Ctx, J(r): J<CreateArray>) -> ApiResult<Response> {
    require(&ctx, ADMIN)?;
    match r.role.as_str() {
        "data" => {}
        "metadata" => {
            return Err(ApiError::bad(
                "the metadata tier (catalog on NVMe) is a follow-up and cannot be created yet",
            ))
        }
        _ => return Err(ApiError::bad("role must be data")),
    }
    let min = LEVELS
        .iter()
        .find(|(l, _)| *l == r.level)
        .map(|(_, n)| *n)
        .ok_or_else(|| ApiError::bad("level must be raid1, raid5, raid6 or raid10"))?;
    let unique: BTreeSet<&String> = r.disks.iter().collect();
    if unique.len() != r.disks.len() || r.disks.len() > 32 {
        return Err(ApiError::bad("each disk once, at most 32"));
    }
    if r.disks.len() < min || (r.level == "raid10" && r.disks.len() % 2 == 1) {
        return Err(ApiError::bad(format!(
            "{} needs at least {min} disks{}",
            r.level,
            if r.level == "raid10" { " (an even number)" } else { "" }
        )));
    }
    confirmed(&r.confirm, &r.disks)?;
    let s = current(&st)?;
    if s["arrays"]
        .as_array()
        .into_iter()
        .flatten()
        .any(|a| a["md_name"] == "nexus-data")
    {
        return Err(ApiError::conflict("a data array exists already: add spares or grow it"));
    }
    if s["store"]["empty"] != Value::Bool(true) {
        return Err(ApiError::conflict(
            "the store is not empty: the data array is only created before the first backup (moving an existing store \
             is not supported, see the manual)",
        ));
    }
    let info = r
        .disks
        .iter()
        .map(|x| empty_disk(&s, x, None))
        .collect::<ApiResult<Vec<_>>>()?;
    let params = json!({"op": "create_array", "role": r.role, "level": r.level, "disks": r.disks, "disk_info": info});
    crate::quorum::gate(&st, &ctx, "disks.create_array", "hardware/data", params)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArrayDisk {
    disk: String,
    confirm: String,
    /// replace: the member to replace (default: the failed ones)
    #[serde(default)]
    failed: Option<String>,
}

/// A data or metadata array by its device name (system arrays are shown only).
fn managed_array<'a>(s: &'a Value, name: &str) -> ApiResult<&'a Value> {
    let a = s["arrays"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|a| a["name"] == name)
        .ok_or_else(ApiError::not_found)?;
    if !matches!(a["role"].as_str(), Some("data" | "metadata")) || a["uuid"].as_str().is_none() {
        return Err(ApiError::conflict(format!(
            "{name} is not a NexusBackup data or metadata array: shown only"
        )));
    }
    Ok(a)
}

async fn array_op(st: St, ctx: Ctx, name: String, op: &str, r: ArrayDisk) -> ApiResult<Response> {
    require(&ctx, ADMIN)?;
    confirmed(&r.confirm, std::slice::from_ref(&r.disk))?;
    let s = current(&st)?;
    let a = managed_array(&s, &name)?;
    let members = a["members"].as_array().map_or(&[][..], |v| v);
    match op {
        "replace" => {
            if let Some(f) = &r.failed {
                let m = members
                    .iter()
                    .find(|m| m["serial"] == f.as_str())
                    .ok_or_else(|| ApiError::conflict(format!("{f} is not a member of {name}")))?;
                if !matches!(m["state"].as_str(), Some("faulty" | "active")) {
                    return Err(ApiError::conflict(format!(
                        "{f} is {} in {name}",
                        m["state"].as_str().unwrap_or("?")
                    )));
                }
            } else if a["degraded"] != Value::Bool(true) && !members.iter().any(|m| m["state"] == "faulty") {
                return Err(ApiError::conflict(format!(
                    "{name} has no failed member: add the disk as a spare, or name the member to replace"
                )));
            }
        }
        "grow" => {
            if !matches!(a["level"].as_str(), Some("raid5" | "raid6")) {
                return Err(ApiError::conflict(format!(
                    "{name} is {}: only raid5 and raid6 grow by a disk (add a spare instead)",
                    a["level"].as_str().unwrap_or("?")
                )));
            }
            if a["state"] != "clean" || a["degraded"] == Value::Bool(true) {
                return Err(ApiError::conflict(format!(
                    "{name} is {}: grow only a clean array",
                    a["state"].as_str().unwrap_or("?")
                )));
            }
        }
        _ => {}
    }
    let info = empty_disk(&s, &r.disk, a["used_dev_size"].as_i64())?;
    let mut params = json!({"op": op, "array": a["uuid"], "array_name": name, "disk": r.disk, "disk_info": [info]});
    if op == "replace" {
        params["failed"] = json!(r.failed);
    }
    let action = format!("disks.{op}");
    crate::quorum::gate(&st, &ctx, &action, &format!("hardware/{name}"), params)
}

/// POST /hardware/arrays/{name}/spare {disk, confirm}: a hot spare (on a degraded array the
/// rebuild starts at once).
pub async fn add_spare(
    State(st): State<St>,
    ctx: Ctx,
    Path(name): Path<String>,
    J(r): J<ArrayDisk>,
) -> ApiResult<Response> {
    if r.failed.is_some() {
        return Err(ApiError::bad("failed is only for replace"));
    }
    array_op(st, ctx, name, "add_spare", r).await
}

/// POST /hardware/arrays/{name}/replace {disk, failed?, confirm}: a failed member out, the
/// new disk in (a working member named in `failed` is copied first: mdadm --replace).
pub async fn replace(
    State(st): State<St>,
    ctx: Ctx,
    Path(name): Path<String>,
    J(r): J<ArrayDisk>,
) -> ApiResult<Response> {
    array_op(st, ctx, name, "replace", r).await
}

/// POST /hardware/arrays/{name}/grow {disk, confirm}: raid5/6 by one disk (reshape, then
/// xfs_growfs; long-running).
pub async fn grow(State(st): State<St>, ctx: Ctx, Path(name): Path<String>, J(r): J<ArrayDisk>) -> ApiResult<Response> {
    if r.failed.is_some() {
        return Err(ApiError::bad("failed is only for replace"));
    }
    array_op(st, ctx, name, "grow", r).await
}

/// After an approved (or, with approvals disabled, direct) `disks.*` request: hand it to
/// nexus-disks. Its outcome appears under the operations on the Hardware page and is
/// audited by the scheduler (`hardware.op`).
pub fn after_approve(st: &St, action: &str, requested_by: &str, p: &Value, quorum_id: Option<i64>) {
    if !ACTIONS.contains(&action) {
        return;
    }
    let mut fields = p.clone();
    if let Some(o) = fields.as_object_mut() {
        for k in ["op", "disk_info", "array_name"] {
            o.remove(k);
        }
    }
    let op = p["op"].as_str().unwrap_or_default();
    match submit(st, requested_by, op, quorum_id, fields) {
        Ok(id) => eprintln!("web-api: {action} handed to nexus-disks as {id}"),
        Err(e) => eprintln!("<3>web-api: after {action}: {}", e.1),
    }
}

pub fn routes() -> axum::Router<St> {
    use axum::routing::{get, post};
    axum::Router::new()
        .route("/hardware", get(get_status))
        .route("/hardware/scan", post(scan))
        .route("/hardware/selftest", post(selftest))
        .route("/hardware/arrays", post(create_array))
        .route("/hardware/arrays/{name}/spare", post(add_spare))
        .route("/hardware/arrays/{name}/replace", post(replace))
        .route("/hardware/arrays/{name}/grow", post(grow))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn confirmation() {
        let s = vec!["A1".to_owned(), "B-2".to_owned()];
        assert!(confirmed("B-2 A1", &s).is_ok());
        assert!(confirmed(" A1,B-2\n", &s).is_ok());
        assert!(confirmed("A1", &s).is_err());
        assert!(confirmed("A1 B-2 C3", &s).is_err());
        assert!(confirmed("a1 b-2", &s).is_err());
    }
}
