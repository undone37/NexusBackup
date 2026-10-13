//! Endpoint status of the agents (Phase 24a, docs/endpoint-ui.md): the per-agent UI
//! policy of the endpoint UIs (admins; sent to the agent with the next poll), the
//! laptop options (skip on battery / metered, missed runs) and the session summaries
//! the agent shows. Reachability and power state come from the scheduler's poll.

use crate::auth::{Ctx, TENANT_WRITERS};
use crate::{ApiError, ApiResult, St, J};
use axum::extract::{Path, Query, State};
use axum::Json;
use catalog::rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

#[derive(Deserialize, Serialize, Default)]
#[serde(deny_unknown_fields)]
pub struct UiPolicy {
    /// `#rrggbb` or empty
    #[serde(default)]
    accent: String,
    /// shown instead of the product name (≤ 64 characters)
    #[serde(default)]
    header: String,
    #[serde(default)]
    hide_backup_now: bool,
    #[serde(default)]
    hide_tray: bool,
}

#[derive(Deserialize, Serialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Laptop {
    /// skip scheduled runs on battery below this charge (0 = off)
    #[serde(default)]
    min_battery: u8,
    #[serde(default)]
    skip_metered: bool,
    /// queue a skipped / failed scheduled run when the agent is back
    #[serde(default)]
    run_missed: bool,
    /// ... within this many hours (1..=336, 0 = 24)
    #[serde(default)]
    retry_hours: u32,
}

/// (tenant, current value of `col`) of an agent in the caller's scope.
fn agent_col(st: &St, ctx: &Ctx, id: &str, col: &str) -> ApiResult<(String, String)> {
    st.cat
        .conn()
        .query_row(
            &format!("SELECT tenant, {col} FROM agents WHERE id = ?1 AND (?2 IS NULL OR tenant = ?2)"),
            params![id, ctx.scope()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?
        .ok_or_else(ApiError::not_found)
}

pub async fn set_ui_policy(
    State(st): State<St>,
    ctx: Ctx,
    Path(id): Path<String>,
    J(p): J<UiPolicy>,
) -> ApiResult<Json<Value>> {
    ctx.require(&["admin"])?;
    let hex = |s: &str| s.len() == 7 && s.starts_with('#') && s[1..].bytes().all(|b| b.is_ascii_hexdigit());
    if !p.accent.is_empty() && !hex(&p.accent) {
        return Err(ApiError::bad("accent: #rrggbb or empty"));
    }
    if p.header.chars().count() > 64 || p.header.chars().any(char::is_control) {
        return Err(ApiError::bad("header: at most 64 characters, no control characters"));
    }
    let (tenant, old) = agent_col(&st, &ctx, &id, "ui_policy")?;
    let new = json!(p);
    st.cat.conn().execute(
        "UPDATE agents SET ui_policy = ?2, ui_policy_version = ui_policy_version + 1 WHERE id = ?1",
        params![id, new.to_string()],
    )?;
    st.audit(
        ctx.name(),
        "agent.ui_policy",
        &format!("agent/{id}"),
        json!({"tenant": tenant, "new": new, "old": serde_json::from_str::<Value>(&old).unwrap_or_default()}),
    )?;
    let a = crate::agents::agent_value(&st.cat.conn(), &id)?.ok_or_else(ApiError::not_found)?;
    Ok(Json(a))
}

pub async fn set_laptop(
    State(st): State<St>,
    ctx: Ctx,
    Path(id): Path<String>,
    J(l): J<Laptop>,
) -> ApiResult<Json<Value>> {
    ctx.require(TENANT_WRITERS)?;
    if l.min_battery > 100 {
        return Err(ApiError::bad("min_battery: 0..=100"));
    }
    if l.retry_hours > 336 {
        return Err(ApiError::bad("retry_hours: 0..=336"));
    }
    let (tenant, old) = agent_col(&st, &ctx, &id, "laptop")?;
    let new = json!(l);
    let c = st.cat.conn();
    c.execute(
        "UPDATE agents SET laptop = ?2, missed_at = CASE WHEN ?3 THEN missed_at END WHERE id = ?1",
        params![id, new.to_string(), l.run_missed],
    )?;
    drop(c);
    st.audit(
        ctx.name(),
        "agent.laptop",
        &format!("agent/{id}"),
        json!({"tenant": tenant, "new": new, "old": serde_json::from_str::<Value>(&old).unwrap_or_default()}),
    )?;
    let a = crate::agents::agent_value(&st.cat.conn(), &id)?.ok_or_else(ApiError::not_found)?;
    Ok(Json(a))
}

#[derive(Deserialize)]
pub struct SessionsQuery {
    #[serde(default)]
    limit: Option<u32>,
}

/// The session summaries of an agent (newest first, without log lines), as its
/// endpoint UI shows them; `delivered` = the agent has it.
pub async fn agent_sessions(
    State(st): State<St>,
    ctx: Ctx,
    Path(id): Path<String>,
    Query(q): Query<SessionsQuery>,
) -> ApiResult<Json<Value>> {
    agent_col(&st, &ctx, &id, "id")?;
    let c = st.cat.conn();
    let rows = c
        .prepare("SELECT summary, delivered FROM agent_sessions WHERE agent_id = ?1 ORDER BY job_id DESC LIMIT ?2")?
        .query_map(params![id, q.limit.unwrap_or(30).min(100)], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, Option<i64>>(1)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let out: Vec<Value> = rows
        .into_iter()
        .map(|(s, delivered)| {
            let mut v: Value = serde_json::from_str(&s).unwrap_or_default();
            if let Some(o) = v.as_object_mut() {
                o.remove("log_tail");
                o.insert("delivered".into(), json!(delivered));
            }
            v
        })
        .collect();
    Ok(Json(Value::Array(out)))
}
