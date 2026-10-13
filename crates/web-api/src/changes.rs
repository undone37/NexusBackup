//! Ransomware signals (Phase 21a, docs/ransomware-signals.md): clearing a
//! snapshot's anomaly flag, the snapshot diff and the per-source change trends.
//!
//! - `POST /snapshots/{tenant}/{source}/{time}/anomaly/clear {note}`: security
//!   officers, immediate, audited (`snapshot.anomaly_clear`). The reason stays.
//! - `POST /snapshots/diff {tenant, source, time, base?, change?, offset?,
//!   limit?}`: queues a read-only `snapshot_diff` job (the web-api has no
//!   tenant keys; the scheduler reads the sealed name indexes). Paths, sizes and
//!   mtimes only, never contents. The file search's roles (`search::SEARCHERS`).
//! - `GET /stats/trends?tenant=`: new bytes and changed files of each source's
//!   last 30 runs from `backup_stats`, with the anomaly flags.

use crate::auth::Ctx;
use crate::{validate, ApiError, ApiResult, St, J, Q};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use catalog::rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;

const CLEARERS: &[&str] = &["security_officer"];
/// the scheduler's `changes::DIFF_MAX_LIMIT`
const DIFF_MAX_LIMIT: u64 = 1000;
pub const TREND_RUNS: i64 = 30;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClearReq {
    note: String,
}

pub async fn clear(
    State(st): State<St>,
    ctx: Ctx,
    Path((tenant, source, time)): Path<(String, String, i64)>,
    J(r): J<ClearReq>,
) -> ApiResult<Json<Value>> {
    ctx.require(CLEARERS)?;
    validate::name(&tenant, "tenant")?;
    validate::source_ref(&source)?;
    ctx.owns(&tenant)?;
    let note = r.note.trim();
    if note.is_empty() || note.len() > 1000 || note.chars().any(char::is_control) {
        return Err(ApiError::bad("note: 1 to 1000 characters, one line"));
    }
    let reason: Option<String> = {
        let c = st.cat.conn();
        let row: Option<(Option<String>, Option<i64>)> = c
            .query_row(
                "SELECT anomaly, anomaly_cleared_at FROM snapshots WHERE tenant=?1 AND source=?2 AND time=?3",
                params![tenant, source, time],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let (reason, cleared) = row.ok_or_else(|| ApiError(StatusCode::NOT_FOUND, "no such snapshot".into()))?;
        if reason.is_none() || cleared.is_some() {
            return Err(ApiError::conflict("snapshot is not flagged as anomalous"));
        }
        c.execute(
            "UPDATE snapshots SET anomaly_cleared_by=?4, anomaly_cleared_at=?5, anomaly_note=?6
             WHERE tenant=?1 AND source=?2 AND time=?3",
            params![tenant, source, time, ctx.name(), catalog::now(), note],
        )?;
        reason
    };
    let out = json!({"tenant": tenant, "reason": reason, "note": note});
    st.audit(
        ctx.name(),
        "snapshot.anomaly_clear",
        &format!("snapshot/{tenant}/{source}/{time}"),
        out.clone(),
    )?;
    Ok(Json(out))
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiffReq {
    tenant: String,
    source: String,
    time: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    base: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    change: Option<String>,
    #[serde(default)]
    offset: u64,
    #[serde(default = "default_limit")]
    limit: u64,
}

fn default_limit() -> u64 {
    200
}

/// 202 `{id}`: the `snapshot_diff` job.
pub async fn diff(State(st): State<St>, ctx: Ctx, J(r): J<DiffReq>) -> ApiResult<Response> {
    ctx.require(crate::search::SEARCHERS)?;
    validate::name(&r.tenant, "tenant")?;
    validate::source_ref(&r.source)?;
    ctx.owns(&r.tenant)?;
    if r.base.is_some_and(|b| b >= r.time) {
        return Err(ApiError::bad("base: an earlier snapshot than time"));
    }
    if r.change
        .as_deref()
        .is_some_and(|c| !["added", "changed", "deleted"].contains(&c))
    {
        return Err(ApiError::bad("change: added, changed or deleted"));
    }
    if !(1..=DIFF_MAX_LIMIT).contains(&r.limit) || r.offset > 1 << 32 {
        return Err(ApiError::bad(format!("limit: 1..={DIFF_MAX_LIMIT}")));
    }
    let params = json!(r);
    let id = {
        let c = st.cat.conn();
        // only snapshots this appliance knows (and the user may see)
        for t in std::iter::once(r.time).chain(r.base) {
            c.query_row(
                "SELECT 1 FROM snapshots WHERE tenant=?1 AND source=?2 AND time=?3 AND local=1",
                params![r.tenant, r.source, t as i64],
                |_| Ok(()),
            )
            .optional()?
            .ok_or_else(|| ApiError(StatusCode::NOT_FOUND, format!("no local snapshot {}/{t}", r.source)))?;
        }
        c.execute(
            "INSERT INTO jobs (kind, tenant, params, state, requested_by, created) \
             VALUES ('snapshot_diff', ?1, ?2, 'queued', ?3, ?4)",
            params![r.tenant, params.to_string(), ctx.name(), catalog::now()],
        )?;
        c.last_insert_rowid()
    };
    st.audit(ctx.name(), "snapshot.diff", &format!("job/{id}"), params)?;
    Ok((StatusCode::ACCEPTED, Json(json!({"id": id}))).into_response())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrendFilter {
    tenant: Option<String>,
}

/// `[{tenant, source, runs: [{time, new_plain, new_stored, files_changed, anomalous}]}]`,
/// oldest run first; `files_changed` = added + changed + deleted (null: no name index).
pub async fn trends(State(st): State<St>, ctx: Ctx, Q(f): Q<TrendFilter>) -> ApiResult<Json<Value>> {
    let c = st.cat.conn();
    let mut q = c.prepare(
        "SELECT tenant, source, time, new_plain, new_stored, files_added + files_changed + files_deleted, anomalous
         FROM (SELECT b.*, s.anomaly IS NOT NULL AND s.anomaly_cleared_at IS NULL AS anomalous,
                 ROW_NUMBER() OVER (PARTITION BY b.tenant, b.source ORDER BY b.time DESC) AS n
               FROM backup_stats b LEFT JOIN snapshots s USING (tenant, source, time)
               WHERE (?1 IS NULL OR b.tenant = ?1) AND (?2 IS NULL OR b.tenant = ?2))
         WHERE n <= ?3 ORDER BY tenant, source, time",
    )?;
    let rows = q.query_map(params![f.tenant, ctx.scope(), TREND_RUNS], |r| {
        Ok((
            (r.get::<_, String>(0)?, r.get::<_, String>(1)?),
            json!({"time": r.get::<_, i64>(2)?, "new_plain": r.get::<_, i64>(3)?, "new_stored": r.get::<_, i64>(4)?,
                   "files_changed": r.get::<_, Option<i64>>(5)?, "anomalous": r.get::<_, Option<bool>>(6)?.unwrap_or(false)}),
        ))
    })?;
    let mut by: BTreeMap<(String, String), Vec<Value>> = BTreeMap::new();
    for row in rows {
        let (k, v) = row?;
        by.entry(k).or_default().push(v);
    }
    Ok(Json(Value::Array(
        by.into_iter()
            .map(|((tenant, source), runs)| json!({"tenant": tenant, "source": source, "runs": runs}))
            .collect(),
    )))
}
