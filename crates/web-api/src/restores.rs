//! Restore several guests in one request (Phase 15a): `POST /restores` creates
//! one `restore` / `restore_ct` job per guest, targets `target_base + i`, the
//! same node, storage and options for all; audited once (`job.create_many`).
//! Same roles as single restores (admin, operator, tenant_user in their tenant);
//! not for API tokens (not on the allow-list); no replace (one approval each).

use crate::auth::Ctx;
use crate::jobs::check_params;
use crate::{validate, ApiError, ApiResult, St, J};
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use catalog::rusqlite::{params, OptionalExtension};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashSet;

pub const MAX_ITEMS: usize = 100;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Item {
    source: String,
    time: i64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreMany {
    tenant: String,
    items: Vec<Item>,
    node: String,
    storage: String,
    /// first new VMID; guest i gets `target_base + i`
    target_base: u32,
    #[serde(default)]
    name_prefix: Option<String>,
    #[serde(default)]
    pool: Option<String>,
    #[serde(default)]
    start: bool,
    #[serde(default)]
    link_down: bool,
}

/// 202 `{ids}`: every item validated before any job is created.
pub async fn restore_many(State(st): State<St>, ctx: Ctx, J(r): J<RestoreMany>) -> ApiResult<Response> {
    ctx.require(&["admin", "operator", "tenant_user"])?;
    validate::name(&r.tenant, "tenant")?;
    if !ctx.sees(&r.tenant) {
        return Err(ApiError::forbidden());
    }
    let tenant_ok = st
        .cat
        .conn()
        .query_row("SELECT 1 FROM tenants WHERE name = ?1", [&r.tenant], |_| Ok(()))
        .optional()?;
    tenant_ok.ok_or_else(|| ApiError::bad("tenant: does not exist"))?;
    if r.items.is_empty() || r.items.len() > MAX_ITEMS {
        return Err(ApiError::bad(format!("items: 1..={MAX_ITEMS} guests")));
    }
    let mut seen = HashSet::new();
    let mut jobs: Vec<(&str, Value)> = Vec::new();
    for (i, it) in r.items.iter().enumerate() {
        if !seen.insert(it.source.as_str()) {
            return Err(ApiError::bad(format!(
                "items: {} twice (one snapshot per guest)",
                it.source
            )));
        }
        let kind = if it.source.starts_with("ct-") {
            "restore_ct"
        } else {
            "restore"
        };
        let target = r
            .target_base
            .checked_add(i as u32)
            .ok_or_else(|| ApiError::bad("target_base: too large"))?;
        let mut p = json!({"source": it.source, "time": it.time, "node": r.node, "target": target,
                           "storage": r.storage, "start": r.start, "link_down": r.link_down});
        if let Some(x) = &r.name_prefix {
            p["name_prefix"] = json!(x);
        }
        if let Some(x) = &r.pool {
            p["pool"] = json!(x);
        }
        let p = check_params(&st, kind, &r.tenant, p).map_err(|e| ApiError(e.0, format!("{}: {}", it.source, e.1)))?;
        jobs.push((kind, p));
    }
    let ids = {
        let mut c = st.cat.conn();
        let tx = c.transaction()?;
        let mut ids = Vec::new();
        for (kind, p) in &jobs {
            tx.execute(
                "INSERT INTO jobs (kind, tenant, params, state, requested_by, created) VALUES (?1, ?2, ?3, 'queued', ?4, ?5)",
                params![kind, r.tenant, p.to_string(), ctx.name(), catalog::now()],
            )?;
            ids.push(tx.last_insert_rowid());
        }
        tx.commit()?;
        ids
    };
    st.audit(
        ctx.name(),
        "job.create_many",
        &format!("tenant/{}", r.tenant),
        json!({"ids": ids, "jobs": jobs.iter().map(|(k, p)| json!({"kind": k, "params": p})).collect::<Vec<_>>()}),
    )?;
    Ok((StatusCode::ACCEPTED, Json(json!({"ids": ids}))).into_response())
}
