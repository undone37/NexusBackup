//! Opt-in YARA scan of a snapshot (Phase 21e, docs/malware-scan.md).
//!
//! - `GET /scan/rules`, `PUT|DELETE /scan/rules/{name}`: the admin-supplied rule
//!   files (no feed), appliance-wide. Admins and security officers; immediate,
//!   audited (`scan.rules_put` / `scan.rules_delete`). At most 50 files of
//!   256 KiB, 1 MiB together; compiled only inside the restore micro-VM, so a
//!   syntax error shows in the next scan job.
//! - `POST /snapshots/{tenant}/{source}/{time}/scan {budget_min?}`: queues a
//!   `snapshot_scan` job for a local snapshot (202 `{id}`); admins, operators,
//!   tenant admins and security officers (own tenant). Audited `snapshot.scan_request`.
//! - `GET /scans?tenant=&source=&time=`: finished scans, newest first (any role,
//!   tenant-scoped): counts and matches `[{rule, path}]`.
//! - The restore option `scan_first` lives in `jobs::create_job`.
//! - `POST /snapshots/{tenant}/{source}/{time}/scan-back {budget_min?, max?}`
//!   (Phase 29): queues a `scan_back` job that scans the source's snapshots
//!   from this one back, newest first, each scan stopping at its first match,
//!   until one is clean; that one becomes the recommended restore point
//!   (`snapshots.clean_point`). Same roles as a scan; audited
//!   `snapshot.scan_back_request`.

use crate::auth::Ctx;
use crate::{validate, ApiError, ApiResult, St, J, Q};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use catalog::rusqlite::{params, Connection, OptionalExtension};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const RULE_ADMINS: &[&str] = &["admin", "security_officer"];
const SCANNERS: &[&str] = &["admin", "operator", "tenant_admin", "security_officer"];
pub const MAX_RULE_FILES: i64 = 50;
pub const MAX_RULE_BYTES: usize = 256 << 10;
pub const MAX_RULES_TOTAL: i64 = 1 << 20;
/// the scheduler's `scan_first` kinds (`scan::SCAN_FIRST_KINDS`)
pub const SCAN_FIRST_KINDS: &[&str] = &[
    "restore",
    "restore_ct",
    "instant_recover",
    "restore_files",
    "files_get",
    "plugin_restore",
];
/// `scan_first: link_down`: restores that create a guest with NICs
pub const LINK_DOWN_KINDS: &[&str] = &["restore", "restore_ct", "instant_recover"];

/// Rule file names (the VM agent's `valid_rule_name`; they double as YARA namespaces).
fn rule_name(n: &str) -> ApiResult<()> {
    let ok = (1..=64).contains(&n.len())
        && !n.starts_with('.')
        && n.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b));
    if ok {
        Ok(())
    } else {
        Err(ApiError::bad("name: [A-Za-z0-9._-]{1,64} without a leading dot"))
    }
}

pub fn has_rules(c: &Connection) -> ApiResult<bool> {
    Ok(c.query_row("SELECT EXISTS (SELECT 1 FROM yara_rules)", [], |r| r.get(0))?)
}

/// `scan_first` of a job request: validated and taken out of the params
/// (the kinds' parameter structs deny unknown fields); put back by the caller.
pub fn take_scan_first(c: &Connection, kind: &str, params: &mut Value) -> ApiResult<Option<String>> {
    let Some(v) = params.as_object_mut().and_then(|o| o.remove("scan_first")) else {
        return Ok(None);
    };
    if v.is_null() {
        return Ok(None);
    }
    if !SCAN_FIRST_KINDS.contains(&kind) {
        return Err(ApiError::bad("scan_first: only for restores and downloads"));
    }
    let v = match v.as_str() {
        Some("refuse") => "refuse",
        Some("link_down") if LINK_DOWN_KINDS.contains(&kind) => "link_down",
        Some("link_down") => {
            return Err(ApiError::bad(
                "scan_first: link_down only for VM and container restores",
            ))
        }
        _ => return Err(ApiError::bad("scan_first: refuse or link_down")),
    };
    if !has_rules(c)? {
        return Err(ApiError::conflict(
            "scan_first: no YARA rules uploaded (Settings → Malware scan)",
        ));
    }
    Ok(Some(v.to_owned()))
}

pub async fn list_rules(State(st): State<St>, ctx: Ctx) -> ApiResult<Json<Value>> {
    ctx.require(RULE_ADMINS)?;
    let c = st.cat.conn();
    let rows = c
        .prepare(
            "SELECT name, length(CAST(text AS BLOB)), sha256, uploaded_by, uploaded_at FROM yara_rules ORDER BY name",
        )?
        .query_map([], |r| {
            Ok(
                json!({"name": r.get::<_, String>(0)?, "size": r.get::<_, i64>(1)?, "sha256": r.get::<_, String>(2)?,
                      "uploaded_by": r.get::<_, String>(3)?, "uploaded_at": r.get::<_, i64>(4)?}),
            )
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Json(Value::Array(rows)))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleReq {
    text: String,
}

pub async fn put_rule(
    State(st): State<St>,
    ctx: Ctx,
    Path(name): Path<String>,
    J(r): J<RuleReq>,
) -> ApiResult<Json<Value>> {
    ctx.require(RULE_ADMINS)?;
    rule_name(&name)?;
    if r.text.trim().is_empty() || r.text.len() > MAX_RULE_BYTES || r.text.contains('\0') {
        return Err(ApiError::bad(format!(
            "text: 1 to {} KiB of YARA rules",
            MAX_RULE_BYTES >> 10
        )));
    }
    if !r.text.contains("rule") {
        return Err(ApiError::bad("text: no YARA rule in the file"));
    }
    let sha = format!("{:x}", Sha256::digest(r.text.as_bytes()));
    {
        let c = st.cat.conn();
        let (files, bytes): (i64, i64) = c.query_row(
            "SELECT COUNT(*), COALESCE(SUM(length(CAST(text AS BLOB))), 0) FROM yara_rules WHERE name != ?1",
            [&name],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        if files >= MAX_RULE_FILES || bytes + r.text.len() as i64 > MAX_RULES_TOTAL {
            return Err(ApiError::bad(format!(
                "at most {MAX_RULE_FILES} rule files and {} MiB together",
                MAX_RULES_TOTAL >> 20
            )));
        }
        c.execute(
            "INSERT INTO yara_rules (name, text, sha256, uploaded_by, uploaded_at) VALUES (?1,?2,?3,?4,?5)
             ON CONFLICT (name) DO UPDATE SET text=?2, sha256=?3, uploaded_by=?4, uploaded_at=?5",
            params![name, r.text, sha, ctx.name(), catalog::now()],
        )?;
    }
    let out = json!({"name": name, "size": r.text.len(), "sha256": sha});
    st.audit(ctx.name(), "scan.rules_put", &format!("yara_rule/{name}"), out.clone())?;
    Ok(Json(out))
}

pub async fn delete_rule(State(st): State<St>, ctx: Ctx, Path(name): Path<String>) -> ApiResult<StatusCode> {
    ctx.require(RULE_ADMINS)?;
    rule_name(&name)?;
    let sha: Option<String> = {
        let c = st.cat.conn();
        let sha = c
            .query_row("SELECT sha256 FROM yara_rules WHERE name = ?1", [&name], |r| r.get(0))
            .optional()?;
        c.execute("DELETE FROM yara_rules WHERE name = ?1", [&name])?;
        sha
    };
    let sha = sha.ok_or_else(ApiError::not_found)?;
    st.audit(
        ctx.name(),
        "scan.rules_delete",
        &format!("yara_rule/{name}"),
        json!({"sha256": sha}),
    )?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScanReq {
    /// time budget in minutes (default 240)
    #[serde(default)]
    budget_min: Option<u64>,
}

pub async fn scan_snapshot(
    State(st): State<St>,
    ctx: Ctx,
    Path((tenant, source, time)): Path<(String, String, i64)>,
    J(r): J<ScanReq>,
) -> ApiResult<Response> {
    ctx.require(SCANNERS)?;
    validate::name(&tenant, "tenant")?;
    validate::source_ref(&source)?;
    ctx.owns(&tenant)?;
    if r.budget_min.is_some_and(|b| !(1..=1440).contains(&b)) {
        return Err(ApiError::bad("budget_min: 1..=1440"));
    }
    let mut params = json!({"source": source, "time": time});
    if let Some(b) = r.budget_min {
        params["budget"] = json!(b * 60);
    }
    let id = {
        let c = st.cat.conn();
        c.query_row(
            "SELECT 1 FROM snapshots WHERE tenant=?1 AND source=?2 AND time=?3 AND local=1",
            params![tenant, source, time],
            |_| Ok(()),
        )
        .optional()?
        .ok_or_else(|| ApiError(StatusCode::NOT_FOUND, "no such local snapshot".into()))?;
        if !has_rules(&c)? {
            return Err(ApiError::conflict("no YARA rules uploaded (Settings → Malware scan)"));
        }
        c.execute(
            "INSERT INTO jobs (kind, tenant, params, state, requested_by, created) \
             VALUES ('snapshot_scan', ?1, ?2, 'queued', ?3, ?4)",
            params![tenant, params.to_string(), ctx.name(), catalog::now()],
        )?;
        c.last_insert_rowid()
    };
    st.audit(
        ctx.name(),
        "snapshot.scan_request",
        &format!("snapshot/{tenant}/{source}/{time}"),
        json!({"tenant": tenant, "job": id, "params": params}),
    )?;
    Ok((StatusCode::ACCEPTED, Json(json!({"id": id}))).into_response())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScanFilter {
    tenant: Option<String>,
    source: Option<String>,
    time: Option<i64>,
    limit: Option<u32>,
}

pub async fn list_scans(State(st): State<St>, ctx: Ctx, Q(f): Q<ScanFilter>) -> ApiResult<Json<Value>> {
    let c = st.cat.conn();
    let rows = c
        .prepare(
            "SELECT job_id, tenant, source, time, finished, rules, files, skipped, errors, complete, matches_total,
                    matches FROM snapshot_scans
             WHERE (?1 IS NULL OR tenant = ?1) AND (?2 IS NULL OR source = ?2) AND (?3 IS NULL OR time = ?3)
               AND (?4 IS NULL OR tenant = ?4)
             ORDER BY job_id DESC LIMIT ?5",
        )?
        .query_map(
            params![f.tenant, f.source, f.time, ctx.scope(), f.limit.unwrap_or(50).min(500)],
            |r| {
                Ok(json!({
                    "job": r.get::<_, i64>(0)?, "tenant": r.get::<_, String>(1)?, "source": r.get::<_, String>(2)?,
                    "time": r.get::<_, i64>(3)?, "finished": r.get::<_, i64>(4)?, "rules": r.get::<_, String>(5)?,
                    "files": r.get::<_, i64>(6)?, "skipped": r.get::<_, i64>(7)?, "errors": r.get::<_, i64>(8)?,
                    "complete": r.get::<_, bool>(9)?, "matches_total": r.get::<_, i64>(10)?,
                    "matches": serde_json::from_str::<Value>(&r.get::<_, String>(11)?).unwrap_or_default(),
                }))
            },
        )?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Json(Value::Array(rows)))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScanBackReq {
    /// time budget per snapshot in minutes (default: the scanner's)
    #[serde(default)]
    budget_min: Option<u64>,
    /// snapshots scanned at most (default 30)
    #[serde(default)]
    max: Option<u64>,
}

/// `POST /snapshots/{tenant}/{source}/{time}/scan-back` (module doc).
pub async fn scan_back(
    State(st): State<St>,
    ctx: Ctx,
    Path((tenant, source, time)): Path<(String, String, i64)>,
    J(r): J<ScanBackReq>,
) -> ApiResult<Response> {
    ctx.require(SCANNERS)?;
    validate::name(&tenant, "tenant")?;
    validate::source_ref(&source)?;
    ctx.owns(&tenant)?;
    if r.budget_min.is_some_and(|b| !(1..=1440).contains(&b)) {
        return Err(ApiError::bad("budget_min: 1..=1440"));
    }
    if r.max.is_some_and(|m| !(1..=100).contains(&m)) {
        return Err(ApiError::bad("max: 1..=100"));
    }
    let mut params = json!({"source": source, "from": time});
    if let Some(b) = r.budget_min {
        params["budget"] = json!(b * 60);
    }
    if let Some(m) = r.max {
        params["max"] = json!(m);
    }
    let id = {
        let c = st.cat.conn();
        c.query_row(
            "SELECT 1 FROM snapshots WHERE tenant=?1 AND source=?2 AND time=?3 AND local=1",
            params![tenant, source, time],
            |_| Ok(()),
        )
        .optional()?
        .ok_or_else(|| ApiError(StatusCode::NOT_FOUND, "no such local snapshot".into()))?;
        if !has_rules(&c)? {
            return Err(ApiError::conflict("no YARA rules uploaded (Settings → Malware scan)"));
        }
        let running: Option<i64> = c
            .query_row(
                "SELECT id FROM jobs WHERE kind = 'scan_back' AND tenant = ?1 AND state IN ('queued', 'running')
                   AND json_extract(params, '$.source') = ?2 LIMIT 1",
                params![tenant, source],
                |r| r.get(0),
            )
            .optional()?;
        if let Some(j) = running {
            return Err(ApiError::conflict(format!(
                "a scan back of this source is already queued (job {j})"
            )));
        }
        c.execute(
            "INSERT INTO jobs (kind, tenant, params, state, requested_by, created) \
             VALUES ('scan_back', ?1, ?2, 'queued', ?3, ?4)",
            params![tenant, params.to_string(), ctx.name(), catalog::now()],
        )?;
        c.last_insert_rowid()
    };
    st.audit(
        ctx.name(),
        "snapshot.scan_back_request",
        &format!("snapshot/{tenant}/{source}/{time}"),
        json!({"tenant": tenant, "job": id, "params": params}),
    )?;
    Ok((StatusCode::ACCEPTED, Json(json!({"id": id}))).into_response())
}
