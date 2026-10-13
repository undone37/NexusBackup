//! Phase 28 (docs/commvault-comparison.md Tier 1): scheduled threat scans and
//! the IOC hash hunt (scheduler `threat.rs`).
//!
//! - `PUT /groups/{id}/threat-scan {schedule, budget_min?}`: the group's scan
//!   schedule (policy grammar; `null` = off) and time budget per scan; admins,
//!   tenant admins (own tenant) and security officers. Audited
//!   `group.threat_scan`. No approval: scans only read.
//! - `PUT /groups/{id}/file-hashes {enabled}`: record the SHA-256 of every file
//!   in the name index (IOC hash hunt). Admins and tenant admins; audited
//!   `group.file_hashes`.
//! - `GET /hash-lists`, `PUT|DELETE /hash-lists/{name}`: uploaded IOC lists
//!   (text or CSV: every SHA-256 found, one per line or in any column; MD5 and
//!   SHA-1 are counted as skipped). Appliance-wide, admins and security
//!   officers; at most 20 lists, 100 000 hashes each, 500 000 together.
//!   Audited `hash_list.put` / `hash_list.delete`.
//! - `POST /hunts {tenant, lists?, source?, from?, to?}`: queues a `hash_hunt`
//!   job (202 `{id}`); admins, operators, security officers, tenant admins (own
//!   tenant). Audited `hash_hunt.request`. Results: `GET /jobs/{id}`.

use crate::auth::Ctx;
use crate::{validate, ApiError, ApiResult, St, J};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use catalog::rusqlite::{params, Connection, OptionalExtension};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const SCAN_SETTERS: &[&str] = &["admin", "tenant_admin", "security_officer"];
const LIST_ADMINS: &[&str] = &["admin", "security_officer"];
const HUNTERS: &[&str] = &["admin", "operator", "tenant_admin", "security_officer"];
pub const MAX_LISTS: i64 = 20;
pub const MAX_HASHES: usize = 100_000;
pub const MAX_HASHES_TOTAL: i64 = 500_000;
/// upload size (text with comments, CSV with several columns)
pub const MAX_LIST_BYTES: usize = 16 << 20;
pub const MAX_BUDGET_MIN: u64 = 1440;

pub fn routes() -> Router<St> {
    Router::new()
        .route("/groups/{id}/threat-scan", put(put_threat_scan))
        .route("/groups/{id}/file-hashes", put(put_file_hashes))
        .route("/hash-lists", get(list_lists))
        .route("/hash-lists/{name}", put(put_list).delete(delete_list))
        .route("/hunts", post(hunt))
}

/// The group's tenant within the caller's scope, else 404.
fn group_tenant(c: &Connection, ctx: &Ctx, id: i64) -> ApiResult<String> {
    c.query_row(
        "SELECT tenant FROM groups WHERE id = ?1 AND (?2 IS NULL OR tenant = ?2)",
        params![id, ctx.scope()],
        |r| r.get(0),
    )
    .optional()?
    .ok_or_else(ApiError::not_found)
}

/// Phase 28 fields of every group (`GET /groups`).
pub fn group_extras(c: &Connection, rows: &mut [Value]) -> ApiResult<()> {
    let mut q = c.prepare("SELECT scan_schedule, scan_budget_min, file_hashes FROM groups WHERE id = ?1")?;
    for g in rows.iter_mut() {
        let Some(id) = g["id"].as_i64() else { continue };
        if let Some((s, b, h)) = q
            .query_row([id], |r| {
                Ok((
                    r.get::<_, Option<String>>(0)?,
                    r.get::<_, Option<i64>>(1)?,
                    r.get::<_, bool>(2)?,
                ))
            })
            .optional()?
        {
            g["scan_schedule"] = json!(s);
            g["scan_budget_min"] = json!(b);
            g["file_hashes"] = json!(h);
        }
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ThreatScanReq {
    /// `null` = off
    schedule: Option<String>,
    #[serde(default)]
    budget_min: Option<u64>,
}

pub async fn put_threat_scan(
    State(st): State<St>,
    ctx: Ctx,
    Path(id): Path<i64>,
    J(r): J<ThreatScanReq>,
) -> ApiResult<Json<Value>> {
    ctx.require(SCAN_SETTERS)?;
    let schedule = r.schedule.as_deref().map(str::trim).filter(|s| !s.is_empty());
    if let Some(s) = schedule {
        validate::schedule(s)?;
    }
    if r.budget_min.is_some_and(|b| !(1..=MAX_BUDGET_MIN).contains(&b)) {
        return Err(ApiError::bad(format!("budget_min: 1..={MAX_BUDGET_MIN}")));
    }
    let tenant = {
        let c = st.cat.conn();
        let tenant = group_tenant(&c, &ctx, id)?;
        crate::lockdown::refuse(&c, &tenant, "group changes")?;
        c.execute(
            "UPDATE groups SET scan_schedule = ?2, scan_budget_min = ?3 WHERE id = ?1",
            params![id, schedule, r.budget_min.map(|b| b as i64)],
        )?;
        tenant
    };
    let rules = crate::scan::has_rules(&st.cat.conn())?;
    let out = json!({"id": id, "tenant": tenant, "scan_schedule": schedule, "scan_budget_min": r.budget_min,
                     "rules": rules});
    st.audit(ctx.name(), "group.threat_scan", &format!("group/{id}"), out.clone())?;
    Ok(Json(out))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileHashesReq {
    enabled: bool,
}

pub async fn put_file_hashes(
    State(st): State<St>,
    ctx: Ctx,
    Path(id): Path<i64>,
    J(r): J<FileHashesReq>,
) -> ApiResult<Json<Value>> {
    ctx.require(crate::auth::TENANT_WRITERS)?;
    let tenant = {
        let c = st.cat.conn();
        let tenant = group_tenant(&c, &ctx, id)?;
        crate::lockdown::refuse(&c, &tenant, "group changes")?;
        c.execute(
            "UPDATE groups SET file_hashes = ?2 WHERE id = ?1",
            params![id, r.enabled],
        )?;
        tenant
    };
    let out = json!({"id": id, "tenant": tenant, "file_hashes": r.enabled});
    st.audit(ctx.name(), "group.file_hashes", &format!("group/{id}"), out.clone())?;
    Ok(Json(out))
}

/// Every SHA-256 (64 hex digits) in `text`: per line the first field that is
/// one (separators `,` `;` tab space). Returns (sorted unique hashes, lines
/// with something else that looks like a hash: MD5 / SHA-1 / other lengths).
pub fn parse_list(text: &str) -> (Vec<String>, usize) {
    let mut out = Vec::new();
    let mut skipped = 0;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fields = line.split([',', ';', '\t', ' ']).map(|f| f.trim().trim_matches('"'));
        let hex: Vec<&str> = fields
            .filter(|f| f.len() >= 32 && f.bytes().all(|b| b.is_ascii_hexdigit()))
            .collect();
        match hex.iter().find(|f| f.len() == 64) {
            Some(h) => out.push(h.to_ascii_lowercase()),
            None if !hex.is_empty() => skipped += 1,
            None => {}
        }
    }
    out.sort_unstable();
    out.dedup();
    (out, skipped)
}

pub async fn list_lists(State(st): State<St>, ctx: Ctx) -> ApiResult<Json<Value>> {
    ctx.require(LIST_ADMINS)?;
    let c = st.cat.conn();
    let rows = c
        .prepare("SELECT name, count, sha256, uploaded_by, uploaded_at FROM hash_lists ORDER BY name")?
        .query_map([], |r| {
            Ok(json!({"name": r.get::<_, String>(0)?, "count": r.get::<_, i64>(1)?,
                      "sha256": r.get::<_, String>(2)?, "uploaded_by": r.get::<_, String>(3)?,
                      "uploaded_at": r.get::<_, i64>(4)?}))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Json(Value::Array(rows)))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListReq {
    text: String,
}

pub async fn put_list(
    State(st): State<St>,
    ctx: Ctx,
    Path(name): Path<String>,
    J(r): J<ListReq>,
) -> ApiResult<Json<Value>> {
    ctx.require(LIST_ADMINS)?;
    validate::name(&name, "name")?;
    if r.text.len() > MAX_LIST_BYTES || r.text.contains('\0') {
        return Err(ApiError::bad(format!("text: at most {} MiB", MAX_LIST_BYTES >> 20)));
    }
    let (hashes, skipped) = parse_list(&r.text);
    if hashes.is_empty() {
        return Err(ApiError::bad(
            "text: no SHA-256 hash in the file (MD5 and SHA-1 are not supported)",
        ));
    }
    if hashes.len() > MAX_HASHES {
        return Err(ApiError::bad(format!("text: at most {MAX_HASHES} hashes per list")));
    }
    let body = hashes.join("\n") + "\n";
    let sha = format!("{:x}", Sha256::digest(body.as_bytes()));
    {
        let c = st.cat.conn();
        let (lists, total): (i64, i64) = c.query_row(
            "SELECT COUNT(*), COALESCE(SUM(count), 0) FROM hash_lists WHERE name != ?1",
            [&name],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        if lists >= MAX_LISTS || total + hashes.len() as i64 > MAX_HASHES_TOTAL {
            return Err(ApiError::bad(format!(
                "at most {MAX_LISTS} lists and {MAX_HASHES_TOTAL} hashes together"
            )));
        }
        c.execute(
            "INSERT INTO hash_lists (name, hashes, count, sha256, uploaded_by, uploaded_at) VALUES (?1,?2,?3,?4,?5,?6)
             ON CONFLICT (name) DO UPDATE SET hashes=?2, count=?3, sha256=?4, uploaded_by=?5, uploaded_at=?6",
            params![name, body, hashes.len() as i64, sha, ctx.name(), catalog::now()],
        )?;
    }
    let out = json!({"name": name, "count": hashes.len(), "skipped": skipped, "sha256": sha});
    st.audit(ctx.name(), "hash_list.put", &format!("hash_list/{name}"), out.clone())?;
    Ok(Json(out))
}

pub async fn delete_list(State(st): State<St>, ctx: Ctx, Path(name): Path<String>) -> ApiResult<StatusCode> {
    ctx.require(LIST_ADMINS)?;
    validate::name(&name, "name")?;
    let sha: Option<String> = {
        let c = st.cat.conn();
        let sha = c
            .query_row("SELECT sha256 FROM hash_lists WHERE name = ?1", [&name], |r| r.get(0))
            .optional()?;
        c.execute("DELETE FROM hash_lists WHERE name = ?1", [&name])?;
        sha
    };
    let sha = sha.ok_or_else(ApiError::not_found)?;
    st.audit(
        ctx.name(),
        "hash_list.delete",
        &format!("hash_list/{name}"),
        json!({"sha256": sha}),
    )?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HuntReq {
    tenant: String,
    /// list names; absent = every list
    #[serde(default)]
    lists: Option<Vec<String>>,
    #[serde(default)]
    source: Option<String>,
    #[serde(default)]
    from: Option<u64>,
    #[serde(default)]
    to: Option<u64>,
}

pub async fn hunt(State(st): State<St>, ctx: Ctx, J(r): J<HuntReq>) -> ApiResult<Response> {
    ctx.require(HUNTERS)?;
    validate::name(&r.tenant, "tenant")?;
    ctx.owns(&r.tenant)?;
    if let Some(s) = &r.source {
        validate::source_ref(s)?;
    }
    if let (Some(f), Some(t)) = (r.from, r.to) {
        if f > t {
            return Err(ApiError::bad("from: after to"));
        }
    }
    let mut params = json!({});
    let id = {
        let c = st.cat.conn();
        c.query_row("SELECT 1 FROM tenants WHERE name = ?1", [&r.tenant], |_| Ok(()))
            .optional()?
            .ok_or_else(|| ApiError::bad("tenant: does not exist"))?;
        if let Some(lists) = &r.lists {
            if lists.is_empty() {
                return Err(ApiError::bad("lists: name at least one list, or leave it out for all"));
            }
            for l in lists {
                validate::name(l, "lists")?;
                c.query_row("SELECT 1 FROM hash_lists WHERE name = ?1", [l], |_| Ok(()))
                    .optional()?
                    .ok_or_else(|| ApiError::bad(format!("lists: no list {l}")))?;
            }
            params["lists"] = json!(lists);
        } else if !c.query_row("SELECT EXISTS (SELECT 1 FROM hash_lists)", [], |r| r.get::<_, bool>(0))? {
            return Err(ApiError::conflict(
                "no IOC hash lists uploaded (Settings → IOC hash lists)",
            ));
        }
        for (k, v) in [
            ("source", json!(r.source)),
            ("from", json!(r.from)),
            ("to", json!(r.to)),
        ] {
            if !v.is_null() {
                params[k] = v;
            }
        }
        c.execute(
            "INSERT INTO jobs (kind, tenant, params, state, requested_by, created) \
             VALUES ('hash_hunt', ?1, ?2, 'queued', ?3, ?4)",
            params![r.tenant, params.to_string(), ctx.name(), catalog::now()],
        )?;
        c.last_insert_rowid()
    };
    st.audit(
        ctx.name(),
        "hash_hunt.request",
        &format!("job/{id}"),
        json!({"tenant": r.tenant, "params": params}),
    )?;
    Ok((StatusCode::ACCEPTED, Json(json!({"id": id}))).into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lists_from_text_and_csv() {
        let a = "a".repeat(64);
        let b = "B".repeat(64);
        let text = format!(
            "# feed\n{a}\n\"{b}\",evil.exe,2026-10-01\nfilename;{}\nmd5,{}\n{a}\n\n",
            "c".repeat(64),
            "d".repeat(32)
        );
        let (h, skipped) = parse_list(&text);
        assert_eq!(h, vec![a.clone(), "b".repeat(64), "c".repeat(64)]);
        assert_eq!(skipped, 1);
        assert_eq!(parse_list("nothing here").0.len(), 0);
    }
}
