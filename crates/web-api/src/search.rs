//! File search (Phase 15g, docs/file-index.md). The web-api has no tenant keys:
//! `POST /search` queues a `file_search` job that the scheduler runs on the
//! tenant's sealed name indexes; the result comes back through `GET /jobs/{id}`.
//! Whoever may browse the tenant's snapshots may search them (the `files_list`
//! rule: admin, operator, tenant_user for their tenant). The query is audited
//! (`file.search`). `PUT /groups/{id}/index-files` switches the VM/CT disk
//! indexing of a PVE group (admin, `group.index_files`).

use crate::auth::Ctx;
use crate::{validate, ApiError, ApiResult, St, J};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use catalog::rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::json;

const SEARCHERS: &[&str] = &["admin", "operator", "tenant_user"];

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SearchReq {
    tenant: String,
    query: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    from: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    to: Option<u64>,
    #[serde(default)]
    case_sensitive: bool,
    #[serde(default = "default_limit")]
    limit: u64,
}

// the scheduler's `search::{DEFAULT_LIMIT, MAX_LIMIT, MAX_QUERY}`
const DEFAULT_LIMIT: u64 = 500;
const MAX_LIMIT: u64 = 2000;
const MAX_QUERY: usize = 256;

fn default_limit() -> u64 {
    DEFAULT_LIMIT
}

/// 202 `{id}`: the `file_search` job.
pub async fn search(State(st): State<St>, ctx: Ctx, J(mut r): J<SearchReq>) -> ApiResult<Response> {
    ctx.require(SEARCHERS)?;
    validate::name(&r.tenant, "tenant")?;
    if !ctx.sees(&r.tenant) {
        return Err(ApiError::forbidden());
    }
    r.query = r.query.trim().to_owned();
    if r.query.is_empty() || r.query.len() > MAX_QUERY || r.query.chars().any(char::is_control) {
        return Err(ApiError::bad(format!(
            "query: 1..={} characters, no control characters",
            MAX_QUERY
        )));
    }
    if let Some(s) = &r.source {
        validate::source_ref(s)?;
    }
    if !(1..=MAX_LIMIT).contains(&r.limit) {
        return Err(ApiError::bad(format!("limit: 1..={}", MAX_LIMIT)));
    }
    if let (Some(f), Some(t)) = (r.from, r.to) {
        if f > t {
            return Err(ApiError::bad("from: after to"));
        }
    }
    let params = json!(r);
    let id = {
        let c = st.cat.conn();
        c.query_row("SELECT 1 FROM tenants WHERE name = ?1", [&r.tenant], |_| Ok(()))
            .optional()?
            .ok_or_else(|| ApiError::bad("tenant: does not exist"))?;
        c.execute(
            "INSERT INTO jobs (kind, tenant, params, state, requested_by, created) \
             VALUES ('file_search', ?1, ?2, 'queued', ?3, ?4)",
            params![r.tenant, params.to_string(), ctx.name(), catalog::now()],
        )?;
        c.last_insert_rowid()
    };
    st.audit(ctx.name(), "file.search", &format!("job/{id}"), params)?;
    Ok((StatusCode::ACCEPTED, Json(json!({"id": id}))).into_response())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IndexFilesReq {
    enabled: bool,
}

/// Turns the file indexing of a PVE group's VM/CT disks on or off. Not a
/// weakening of protection (no approval): it only feeds the search.
pub async fn put_index_files(
    State(st): State<St>,
    ctx: Ctx,
    Path(id): Path<i64>,
    J(r): J<IndexFilesReq>,
) -> ApiResult<Response> {
    ctx.require(&["admin"])?;
    let kind: String = st
        .cat
        .conn()
        .query_row(
            "SELECT s.kind FROM groups g JOIN sources s ON s.id = g.source_id \
             WHERE g.id = ?1 AND (?2 IS NULL OR g.tenant = ?2)",
            params![id, ctx.scope()],
            |r| r.get(0),
        )
        .optional()?
        .ok_or_else(ApiError::not_found)?;
    if kind != "pve" {
        return Err(ApiError::bad(
            "index_files applies to Proxmox VE groups (VM/CT disks); other snapshots are always indexed",
        ));
    }
    st.cat.conn().execute(
        "UPDATE groups SET index_files = ?2 WHERE id = ?1",
        params![id, r.enabled],
    )?;
    let out = json!({"id": id, "index_files": r.enabled});
    st.audit(ctx.name(), "group.index_files", &format!("group/{id}"), out.clone())?;
    Ok(Json(out).into_response())
}
