//! Scheduled full read with a change-tracking drift check (Phase 29,
//! docs/control-plane.md "Full read"; scheduler `fullread.rs`).
//!
//! - `PUT /groups/{id}/full-read {days}`: the group's interval (`null` = the
//!   default of its source kind, catalog::fullread; 0 = off; at most 365).
//!   Admins and tenant admins (own tenant). Audited `group.full_read`. No
//!   approval: like the scan schedule it is detection, not protection.
//! - `GET /full-reads?tenant=&source=`: per source when the next full read is
//!   due and what the last one found (all reading roles, tenant-scoped).
//! - The dashboard's `full_reads` summary ([`summary`]).

use crate::auth::Ctx;
use crate::{validate, ApiError, ApiResult, St, J, Q};
use axum::extract::{Path, State};
use axum::routing::{get, put};
use axum::{Json, Router};
use catalog::rusqlite::{params, Connection, OptionalExtension};
use serde::Deserialize;
use serde_json::{json, Value};

pub fn routes() -> Router<St> {
    Router::new()
        .route("/groups/{id}/full-read", put(put_full_read))
        .route("/full-reads", get(list))
}

/// Phase 29 fields of every group (`GET /groups`): `full_read_days` (the
/// setting, null = default) and `full_read_default`.
pub fn group_extras(c: &Connection, rows: &mut [Value]) -> ApiResult<()> {
    let mut q = c.prepare(
        "SELECT g.full_read_days, s.kind FROM groups g JOIN sources s ON s.id = g.source_id WHERE g.id = ?1",
    )?;
    for g in rows.iter_mut() {
        let Some(id) = g["id"].as_i64() else { continue };
        if let Some((d, kind)) = q
            .query_row([id], |r| Ok((r.get::<_, Option<i64>>(0)?, r.get::<_, String>(1)?)))
            .optional()?
        {
            g["full_read_days"] = json!(d);
            g["full_read_default"] = json!(catalog::fullread::default_days(&kind));
        }
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FullReadReq {
    days: Option<i64>,
}

pub async fn put_full_read(
    State(st): State<St>,
    ctx: Ctx,
    Path(id): Path<i64>,
    J(r): J<FullReadReq>,
) -> ApiResult<Json<Value>> {
    ctx.require(crate::auth::TENANT_WRITERS)?;
    if r.days.is_some_and(|d| !(0..=catalog::fullread::MAX_DAYS).contains(&d)) {
        return Err(ApiError::bad(format!("days: 0..={}", catalog::fullread::MAX_DAYS)));
    }
    let (tenant, kind) = {
        let c = st.cat.conn();
        let (tenant, kind): (String, String) = c
            .query_row(
                "SELECT g.tenant, s.kind FROM groups g JOIN sources s ON s.id = g.source_id
                 WHERE g.id = ?1 AND (?2 IS NULL OR g.tenant = ?2)",
                params![id, ctx.scope()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?
            .ok_or_else(ApiError::not_found)?;
        crate::lockdown::refuse(&c, &tenant, "group changes")?;
        c.execute(
            "UPDATE groups SET full_read_days = ?2 WHERE id = ?1",
            params![id, r.days],
        )?;
        (tenant, kind)
    };
    let out = json!({"id": id, "tenant": tenant, "full_read_days": r.days,
                     "full_read_default": catalog::fullread::default_days(&kind),
                     "effective_days": catalog::fullread::days(r.days, &kind)});
    st.audit(ctx.name(), "group.full_read", &format!("group/{id}"), out.clone())?;
    Ok(Json(out))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListQ {
    tenant: Option<String>,
    source: Option<String>,
}

pub async fn list(State(st): State<St>, ctx: Ctx, Q(q): Q<ListQ>) -> ApiResult<Json<Value>> {
    if let Some(t) = &q.tenant {
        validate::name(t, "tenant")?;
        if !ctx.sees(t) {
            return Err(ApiError::forbidden());
        }
    }
    let tenant = ctx.scope().map(str::to_owned).or(q.tenant);
    let c = st.cat.conn();
    let rows: Vec<Value> = c
        .prepare(
            "SELECT tenant, source, next_due, last_at, last_snapshot, last_job, result, changed, unreported,
                    unreported_bytes, details, last_clean_at FROM full_reads
             WHERE (?1 IS NULL OR tenant = ?1) AND (?2 IS NULL OR source = ?2) ORDER BY tenant, source LIMIT 5000",
        )?
        .query_map(params![tenant, q.source], |r| {
            let details: Option<String> = r.get(10)?;
            Ok(json!({
                "tenant": r.get::<_, String>(0)?, "source": r.get::<_, String>(1)?,
                "next_due": r.get::<_, i64>(2)?, "last_at": r.get::<_, Option<i64>>(3)?,
                "last_snapshot": r.get::<_, Option<i64>>(4)?, "last_job": r.get::<_, Option<i64>>(5)?,
                "result": r.get::<_, Option<String>>(6)?, "changed": r.get::<_, Option<i64>>(7)?,
                "unreported": r.get::<_, Option<i64>>(8)?, "unreported_bytes": r.get::<_, Option<i64>>(9)?,
                "details": details.and_then(|d| serde_json::from_str::<Value>(&d).ok()),
                "last_clean_at": r.get::<_, Option<i64>>(11)?,
            }))
        })?
        .collect::<Result<_, _>>()?;
    Ok(Json(Value::Array(rows)))
}

/// Dashboard: `{sources, verified, drift, never, oldest_verified}` (sources
/// with a full-read row; `verified` = last full read without drift).
pub fn summary(c: &Connection, scope: Option<&str>) -> ApiResult<Value> {
    let (sources, verified, drift, never, oldest): (i64, i64, i64, i64, Option<i64>) = c.query_row(
        "SELECT COUNT(*),
                COALESCE(SUM(result IN ('clean', 'no_baseline')), 0),
                COALESCE(SUM(result = 'drift'), 0),
                COALESCE(SUM(last_at IS NULL), 0),
                MIN(last_clean_at)
         FROM full_reads WHERE ?1 IS NULL OR tenant = ?1",
        [scope],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
    )?;
    Ok(
        json!({"sources": sources, "verified": verified, "drift": drift, "never": never,
              "oldest_verified": oldest}),
    )
}
