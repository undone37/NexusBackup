//! Log runs on their own schedule (#43, docs/database-logs-design.md): a group of a database plugin source whose
//! manifest declares `backup.logs` may get a second schedule for log-only runs; the policy's schedule then takes
//! the base backups (scheduler: job params `mode` `full` / `log`).
//!
//! - `PUT /groups/{id}/log-schedule {schedule: null | "<schedule>"}`: admins and tenant admins (own tenant), the
//!   schedule syntax of policies (`every 15m`, ...), refused for kinds without log support. Audited
//!   `group.log_schedule`. No approval: it adds backups, it never removes one.
//! - `GET /groups` rows carry `log_schedule` and `logs_supported` ([`group_extras`]).

use crate::auth::Ctx;
use crate::{ApiError, ApiResult, St, J};
use axum::extract::{Path, State};
use axum::routing::put;
use axum::{Json, Router};
use catalog::rusqlite::{params, Connection, OptionalExtension};
use serde::Deserialize;
use serde_json::{json, Value};

pub fn routes() -> Router<St> {
    Router::new().route("/groups/{id}/log-schedule", put(put_log_schedule))
}

/// Whether the source kind takes log-only runs: a plugin kind whose installed manifest says `backup.logs: true`.
pub fn supported(c: &Connection, kind: &str) -> bool {
    let Some(k) = kind.strip_prefix("plugin:") else {
        return false;
    };
    plugin_manager::current_for_kind(c, k)
        .ok()
        .flatten()
        .and_then(|cur| cur.manifest.kinds.into_iter().find(|x| x.kind == k))
        .is_some_and(|s| s.backup.is_some_and(|b| b["logs"] == true))
}

/// #43 fields of every group (`GET /groups`): `log_schedule` (null = none) and `logs_supported`.
pub fn group_extras(c: &Connection, rows: &mut [Value]) -> ApiResult<()> {
    let mut q =
        c.prepare("SELECT g.log_schedule, s.kind FROM groups g JOIN sources s ON s.id = g.source_id WHERE g.id = ?1")?;
    for g in rows.iter_mut() {
        let Some(id) = g["id"].as_i64() else { continue };
        if let Some((ls, kind)) = q
            .query_row([id], |r| Ok((r.get::<_, Option<String>>(0)?, r.get::<_, String>(1)?)))
            .optional()?
        {
            g["log_schedule"] = json!(ls);
            g["logs_supported"] = json!(supported(c, &kind));
        }
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogScheduleReq {
    schedule: Option<String>,
}

pub async fn put_log_schedule(
    State(st): State<St>,
    ctx: Ctx,
    Path(id): Path<i64>,
    J(r): J<LogScheduleReq>,
) -> ApiResult<Json<Value>> {
    ctx.require(crate::auth::TENANT_WRITERS)?;
    let schedule = r.schedule.map(|s| s.trim().to_owned()).filter(|s| !s.is_empty());
    if let Some(s) = &schedule {
        if s.len() > 200 {
            return Err(ApiError::bad("schedule: at most 200 characters"));
        }
        catalog::schedule::Schedule::parse(s).map_err(|e| ApiError::bad(format!("schedule: {e}")))?;
    }
    let tenant = {
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
        if schedule.is_some() && !supported(&c, &kind) {
            return Err(ApiError::bad(
                "schedule: this source kind has no log backups (database plugins that declare backup.logs)",
            ));
        }
        c.execute(
            "UPDATE groups SET log_schedule = ?2 WHERE id = ?1",
            params![id, schedule],
        )?;
        tenant
    };
    let out = json!({"id": id, "tenant": tenant, "log_schedule": schedule});
    st.audit(ctx.name(), "group.log_schedule", &format!("group/{id}"), out.clone())?;
    Ok(Json(out))
}
