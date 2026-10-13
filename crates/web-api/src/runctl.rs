//! Run control (Phase 13b, docs/control-plane.md "Run control"): pausing groups,
//! source maintenance, and the run state shown with groups. No approval: a
//! pause only stops new scheduled runs, is audited, and a pause of more than
//! 7 days (or indefinitely) raises a `paused` warning (scheduler).

use crate::auth::Ctx;
use crate::{ApiError, ApiResult, St, J};
use axum::extract::{Path, State};
use axum::Json;
use catalog::rusqlite::{params, Connection, OptionalExtension};
use catalog::schedule::{self, Window};
use serde::Deserialize;
use serde_json::{json, Value};

/// tenant admins: their own tenant's groups and sources (Phase 19b)
const OPS: &[&str] = &["admin", "operator", "tenant_admin"];
const MAX_PAUSE: i64 = 366 * 86400;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PauseReq {
    /// unix time; absent/null = indefinitely
    #[serde(default)]
    until: Option<i64>,
}

fn until(r: &PauseReq) -> ApiResult<i64> {
    match r.until {
        None => Ok(-1),
        Some(u) if u > catalog::now() && u <= catalog::now() + MAX_PAUSE => Ok(u),
        Some(_) => Err(ApiError::bad(
            "until: a time in the next 366 days (or none = indefinitely)",
        )),
    }
}

/// The group's guests as the scheduler resolves them (auto-protect groups, 13c).
fn resolved_guests(c: &Connection, group_id: i64) -> ApiResult<Vec<Value>> {
    let (sid, kind, mode, guests, sel, ex): (i64, String, String, String, String, String) = c.query_row(
        "SELECT g.source_id, s.kind, g.mode, g.guests, g.selector, g.exclude FROM groups g
         JOIN sources s ON s.id = g.source_id WHERE g.id = ?1",
        [group_id],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)),
    )?;
    Ok(catalog::inventory::resolve(c, sid, &kind, &mode, &guests, &sel, &ex)?)
}

/// Adds the run state to listed groups: `paused_until`, `maintenance_until`
/// (of the source), `blackout_active` (a window of the policy is active now) and
/// `resolved_guests` (what a backup of the group covers now).
pub fn group_states(c: &Connection, mut rows: Vec<Value>) -> ApiResult<Vec<Value>> {
    let now = catalog::now();
    for g in rows.iter_mut() {
        let (paused, maint, blackout): (Option<i64>, Option<i64>, String) = c.query_row(
            "SELECT g.paused_until, s.maintenance_until, p.blackout FROM groups g
             JOIN sources s ON s.id = g.source_id JOIN policies p ON p.id = g.policy_id WHERE g.id = ?1",
            [g["id"].as_i64()],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )?;
        let windows: Vec<Window> = serde_json::from_str(&blackout).unwrap_or_default();
        let active = schedule::tz(g["timezone"].as_str().unwrap_or("UTC"))
            .ok()
            .and_then(|tz| schedule::blackout(&windows, tz, now));
        g["paused_until"] = json!(paused);
        g["maintenance_until"] = json!(maint);
        g["blackout_active"] = json!(active.is_some());
        g["resolved_guests"] = json!(resolved_guests(c, g["id"].as_i64().unwrap_or_default())?);
    }
    Ok(rows)
}

/// `table` row of `id` visible to the user: its tenant, or 404.
fn tenant_of(st: &St, ctx: &Ctx, table: &str, id: i64) -> ApiResult<String> {
    st.cat
        .conn()
        .query_row(
            &format!("SELECT tenant FROM {table} WHERE id = ?1 AND (?2 IS NULL OR tenant = ?2)"),
            params![id, ctx.scope()],
            |r| r.get(0),
        )
        .optional()?
        .ok_or_else(ApiError::not_found)
}

fn set(st: &St, ctx: &Ctx, table: &str, col: &str, id: i64, v: Option<i64>, action: &str) -> ApiResult<Json<Value>> {
    ctx.require(OPS)?;
    let tenant = tenant_of(st, ctx, table, id)?;
    st.cat
        .conn()
        .execute(&format!("UPDATE {table} SET {col} = ?2 WHERE id = ?1"), params![id, v])?;
    let what = table.trim_end_matches('s');
    st.audit(
        ctx.name(),
        action,
        &format!("{what}/{id}"),
        json!({ "tenant": tenant, col: v }),
    )?;
    Ok(Json(json!({ "id": id, col: v })))
}

pub async fn pause_group(
    State(st): State<St>,
    ctx: Ctx,
    Path(id): Path<i64>,
    J(r): J<PauseReq>,
) -> ApiResult<Json<Value>> {
    let u = until(&r)?;
    set(&st, &ctx, "groups", "paused_until", id, Some(u), "group.pause")
}

pub async fn resume_group(State(st): State<St>, ctx: Ctx, Path(id): Path<i64>) -> ApiResult<Json<Value>> {
    crate::incident::refuse_while_active(&st.cat.conn())?;
    set(&st, &ctx, "groups", "paused_until", id, None, "group.resume")
}

pub async fn start_maintenance(
    State(st): State<St>,
    ctx: Ctx,
    Path(id): Path<i64>,
    J(r): J<PauseReq>,
) -> ApiResult<Json<Value>> {
    let u = until(&r)?;
    set(
        &st,
        &ctx,
        "sources",
        "maintenance_until",
        id,
        Some(u),
        "source.maintenance",
    )
}

pub async fn end_maintenance(State(st): State<St>, ctx: Ctx, Path(id): Path<i64>) -> ApiResult<Json<Value>> {
    set(
        &st,
        &ctx,
        "sources",
        "maintenance_until",
        id,
        None,
        "source.maintenance_end",
    )
}

/// "Back up now" for some guests of a group: `guests` (a subset of the group's
/// guests) or `failed_only` (the guests that failed in the group's last run,
/// from its `jobs.result`). Returns the guest list to store in the job params
/// (`None` = the whole group).
pub fn backup_guests(
    c: &Connection,
    group_id: i64,
    guests: Option<Vec<Value>>,
    failed_only: bool,
) -> ApiResult<Option<Vec<Value>>> {
    let all = resolved_guests(c, group_id)?;
    if failed_only {
        if guests.is_some() {
            return Err(ApiError::bad("params: guests or failed_only, not both"));
        }
        let last: Option<(String, Option<String>)> = c
            .query_row(
                "SELECT state, result FROM jobs WHERE kind = 'backup' AND json_extract(params, '$.group_id') = ?1
                 AND state IN ('ok', 'failed') ORDER BY id DESC LIMIT 1",
                [group_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        return match last {
            Some((s, r)) if s == "failed" => {
                let r: Value = r.and_then(|r| serde_json::from_str(&r).ok()).unwrap_or_default();
                // unknown which guests failed: the whole group
                Ok(r["failed_guests"].as_array().cloned())
            }
            _ => Err(ApiError::conflict("the group's last run did not fail")),
        };
    }
    let Some(mut g) = guests else { return Ok(None) };
    if g.is_empty() || g.iter().any(|x| !all.contains(x)) {
        return Err(ApiError::bad("guests: a non-empty subset of the group's guests"));
    }
    g.dedup();
    Ok(Some(g))
}
