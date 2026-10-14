//! Alerts (catalog v14 lifecycle, docs/phase13-18-plan.md §13f): list with
//! open / resolved filter, acknowledge (seen, stays open) and resolve (closed),
//! both with an optional note. The scheduler raises, counts and auto-resolves.

use crate::auth::Ctx;
use crate::settings::opt_body;
use crate::{ApiError, ApiResult, St, Q};
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::Json;
use catalog::rusqlite::{params, OptionalExtension};
use serde::Deserialize;
use serde_json::{json, Value};

const ACK: &[&str] = &["admin", "security_officer", "operator"];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AlertFilter {
    acked: Option<bool>,
    /// `open` (not resolved), `resolved`, `all` (default)
    state: Option<String>,
    id: Option<i64>,
    /// one of `catalog::alerting::CATEGORIES`
    category: Option<String>,
}

/// Alerts may name other tenants (and most have none), so tenant-scoped users
/// get an empty list.
pub async fn list_alerts(State(st): State<St>, ctx: Ctx, Q(f): Q<AlertFilter>) -> ApiResult<Json<Value>> {
    if ctx.scope().is_some() {
        return Ok(Json(json!([])));
    }
    let resolved: Option<bool> = match f.state.as_deref() {
        None | Some("all") => None,
        Some("open") => Some(false),
        Some("resolved") => Some(true),
        Some(_) => return Err(ApiError::bad("state: open, resolved or all")),
    };
    if f.category
        .as_deref()
        .is_some_and(|c| !catalog::alerting::CATEGORIES.contains(&c))
    {
        return Err(ApiError::bad(format!(
            "category: one of {}",
            catalog::alerting::CATEGORIES.join(", ")
        )));
    }
    let c = st.cat.conn();
    let rows = c
        .prepare(&format!(
            "SELECT id, ts, COALESCE(last_ts, ts), count, severity, kind, key, tenant, message, acked_by,
                    resolved_at, resolved_by, note, auto,
                    (SELECT json_group_array(json_object('rule', t.rule, 'vendor', t.vendor, 'ticket', t.ticket,
                       'closed', t.closed)) FROM psa_tickets t WHERE t.key = alerts.key
                       AND (t.closed IS NULL OR t.closed >= alerts.ts)
                       AND t.opened <= COALESCE(alerts.resolved_at, 9223372036854775807)) FROM alerts
             WHERE (?1 IS NULL OR (acked_by IS NOT NULL) = ?1) AND (?2 IS NULL OR (resolved_at IS NOT NULL) = ?2)
               AND (?3 IS NULL OR id = ?3) AND (?4 IS NULL OR {} = ?4)
             ORDER BY id DESC LIMIT 1000",
            catalog::alerting::category_sql()
        ))?
        .query_map(params![f.acked, resolved, f.id, f.category], |r| {
            let kind: String = r.get(5)?;
            let (key, tenant, message) = (
                r.get::<_, Option<String>>(6)?,
                r.get::<_, Option<String>>(7)?,
                r.get::<_, String>(8)?,
            );
            Ok(json!({
                "id": r.get::<_, i64>(0)?, "ts": r.get::<_, i64>(1)?, "first_ts": r.get::<_, i64>(1)?,
                "last_ts": r.get::<_, i64>(2)?, "count": r.get::<_, i64>(3)?, "severity": r.get::<_, String>(4)?,
                "hint": catalog::alerting::hint(&kind), "category": catalog::alerting::category(&kind), "kind": kind,
                // the snapshot a security officer may put on hold from here (anomaly, advisory)
                "snapshot": crate::holds::alert_snapshot(&kind, key.as_deref(), &message, tenant.as_deref()),
                "key": key, "tenant": tenant, "message": message, "acked_by": r.get::<_, Option<String>>(9)?,
                "resolved_at": r.get::<_, Option<i64>>(10)?, "resolved_by": r.get::<_, Option<String>>(11)?,
                "note": r.get::<_, Option<String>>(12)?, "auto": r.get::<_, i64>(13)? != 0,
                // Phase 33: the PSA tickets of the alert's key while it was open
                "tickets": r.get::<_, Option<String>>(14)?.and_then(|t| serde_json::from_str::<Value>(&t).ok())
                    .unwrap_or_else(|| json!([])),
            }))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Json(Value::Array(rows)))
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct NoteReq {
    #[serde(default)]
    note: Option<String>,
}

fn note(b: &[u8]) -> ApiResult<Option<String>> {
    let r: NoteReq = opt_body(b)?;
    let n = r.note.map(|n| n.trim().to_owned()).filter(|n| !n.is_empty());
    if n.as_ref()
        .is_some_and(|n| n.chars().count() > 1000 || n.chars().any(|c| c.is_control() && c != '\n'))
    {
        return Err(ApiError::bad("note: up to 1000 characters"));
    }
    Ok(n)
}

/// The alert's kind; a console recovery of an admin account (`break_glass`,
/// nexus-setup recover-admin) is closed only by someone who could have approved it.
fn alert_kind(st: &St, ctx: &Ctx, id: i64) -> ApiResult<String> {
    ctx.require(ACK)?;
    if ctx.scope().is_some() {
        return Err(ApiError::forbidden());
    }
    let kind: String = st
        .cat
        .conn()
        .query_row("SELECT kind FROM alerts WHERE id = ?1", [id], |r| r.get(0))
        .optional()?
        .ok_or_else(ApiError::not_found)?;
    if kind == "break_glass" || crate::console::officer_only(&kind) {
        ctx.require(&["admin", "security_officer"])?;
    }
    Ok(kind)
}

/// Acknowledged = someone has seen it; it stays open until resolved.
pub async fn ack_alert(State(st): State<St>, ctx: Ctx, Path(id): Path<i64>, body: Bytes) -> ApiResult<Json<Value>> {
    let kind = alert_kind(&st, &ctx, id)?;
    let note = note(&body)?;
    let n = st.cat.conn().execute(
        "UPDATE alerts SET acked_by = ?2, note = COALESCE(?3, note) WHERE id = ?1 AND acked_by IS NULL",
        params![id, ctx.name(), note],
    )?;
    if n == 0 {
        return Err(ApiError::conflict("already acknowledged"));
    }
    // acknowledging the break-glass alert ends the banner
    if kind == "break_glass" {
        st.cat
            .conn()
            .execute("DELETE FROM settings WHERE key = 'break_glass'", [])?;
    }
    st.audit(
        ctx.name(),
        "alert.ack",
        &format!("alert/{id}"),
        json!({"kind": kind, "note": note}),
    )?;
    Ok(Json(json!({"id": id, "acked_by": ctx.name()})))
}

/// Closes an alert (also acknowledges it). If the problem comes back, the
/// scheduler raises a new alert.
pub async fn resolve_alert(State(st): State<St>, ctx: Ctx, Path(id): Path<i64>, body: Bytes) -> ApiResult<Json<Value>> {
    let kind = alert_kind(&st, &ctx, id)?;
    let note = note(&body)?;
    let n = st.cat.conn().execute(
        "UPDATE alerts SET resolved_at = ?2, resolved_by = ?3, auto = 0, acked_by = COALESCE(acked_by, ?3),
           note = COALESCE(?4, note) WHERE id = ?1 AND resolved_at IS NULL",
        params![id, catalog::now(), ctx.name(), note],
    )?;
    if n == 0 {
        return Err(ApiError::conflict("already resolved"));
    }
    if kind == "break_glass" {
        st.cat
            .conn()
            .execute("DELETE FROM settings WHERE key = 'break_glass'", [])?;
    }
    st.audit(
        ctx.name(),
        "alert.resolve",
        &format!("alert/{id}"),
        json!({"kind": kind, "note": note}),
    )?;
    Ok(Json(json!({"id": id, "resolved_by": ctx.name()})))
}
