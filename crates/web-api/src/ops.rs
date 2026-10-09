//! Health, Prometheus metrics, audit log.

use crate::auth::Ctx;
use crate::{ct_eq, ApiError, ApiResult, St, Q};
use axum::extract::State;
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};
use std::fmt::Write as _;
use std::sync::atomic::Ordering;

pub async fn health(State(st): State<St>) -> Response {
    let ok = st.cat.conn().query_row("SELECT 1", [], |_| Ok(())).is_ok();
    let code = if ok {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (code, Json(json!({"ok": ok}))).into_response()
}

fn esc(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"").replace('\n', "\\n")
}

/// Prometheus text format; `Authorization: Bearer <token from /etc/nexus/metrics-token>`.
pub async fn metrics(State(st): State<St>, headers: HeaderMap) -> ApiResult<Response> {
    let Some(want) = &st.metrics_token else {
        return Err(ApiError::not_found());
    };
    let given = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or_default();
    if !ct_eq(given.trim().as_bytes(), want.as_bytes()) {
        return Err(ApiError::unauthorized());
    }
    let mut out = String::new();
    let c = st.cat.conn();

    out.push_str("# HELP nexus_jobs Jobs by state.\n# TYPE nexus_jobs gauge\n");
    for state in ["queued", "running", "ok", "failed", "cancelled"] {
        let n: i64 = c.query_row("SELECT COUNT(*) FROM jobs WHERE state = ?1", [state], |r| r.get(0))?;
        writeln!(out, "nexus_jobs{{state=\"{state}\"}} {n}").unwrap();
    }

    out.push_str("# HELP nexus_snapshots Snapshots per tenant and location.\n# TYPE nexus_snapshots gauge\n");
    let mut s = c.prepare(
        "SELECT t.name, (SELECT COUNT(*) FROM snapshots s WHERE s.tenant = t.name AND s.local != 0),
                (SELECT COUNT(*) FROM snapshots s WHERE s.tenant = t.name AND s.offsite != 0)
         FROM tenants t ORDER BY t.name",
    )?;
    let rows = s
        .query_map([], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?, r.get::<_, i64>(2)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    for (t, local, offsite) in rows {
        let t = esc(&t);
        writeln!(out, "nexus_snapshots{{tenant=\"{t}\",location=\"local\"}} {local}").unwrap();
        writeln!(out, "nexus_snapshots{{tenant=\"{t}\",location=\"offsite\"}} {offsite}").unwrap();
    }

    out.push_str(
        "# HELP nexus_last_successful_backup_timestamp_seconds Finish time of the last ok backup job per group (0 = never).\n\
         # TYPE nexus_last_successful_backup_timestamp_seconds gauge\n",
    );
    let mut s = c.prepare(
        "SELECT g.tenant, g.name, COALESCE(MAX(j.finished), 0) FROM groups g
         LEFT JOIN jobs j ON j.kind = 'backup' AND j.state = 'ok' AND j.tenant = g.tenant
              AND json_extract(j.params, '$.group_id') = g.id
         GROUP BY g.id ORDER BY g.tenant, g.name",
    )?;
    let rows = s
        .query_map([], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, i64>(2)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    for (t, g, ts) in rows {
        writeln!(
            out,
            "nexus_last_successful_backup_timestamp_seconds{{tenant=\"{}\",group=\"{}\"}} {ts}",
            esc(&t),
            esc(&g)
        )
        .unwrap();
    }

    let audit: i64 = c.query_row("SELECT COALESCE(MAX(seq), 0) FROM audit", [], |r| r.get(0))?;
    let pending: i64 = c.query_row("SELECT COUNT(*) FROM quorum WHERE state = 'pending'", [], |r| r.get(0))?;
    writeln!(
        out,
        "# HELP nexus_failed_logins_total Failed or rate-limited logins since start.\n\
         # TYPE nexus_failed_logins_total counter\nnexus_failed_logins_total {}\n\
         # HELP nexus_audit_entries Length of the audit chain.\n# TYPE nexus_audit_entries gauge\nnexus_audit_entries {audit}\n\
         # HELP nexus_quorum_pending Pending quorum requests.\n# TYPE nexus_quorum_pending gauge\nnexus_quorum_pending {pending}",
        st.failed_logins.load(Ordering::Relaxed)
    )
    .unwrap();
    let mut res = out.into_response();
    res.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; version=0.0.4; charset=utf-8"),
    );
    Ok(res)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditFilter {
    after: Option<i64>,
    before: Option<i64>,
    order: Option<String>,
    limit: Option<u32>,
}

const AUDITORS: &[&str] = &["admin", "security_officer"];

pub async fn list_audit(State(st): State<St>, ctx: Ctx, Q(f): Q<AuditFilter>) -> ApiResult<Json<Value>> {
    ctx.require(AUDITORS)?;
    // ascending from `after` (default); newest first with `before` or `order=desc`
    let desc = match f.order.as_deref() {
        None => f.before.is_some(),
        Some("desc") => true,
        Some("asc") if f.before.is_none() => false,
        Some(_) => return Err(ApiError::bad("order: asc or desc (before implies desc)")),
    };
    let c = st.cat.conn();
    let rows = c
        .prepare(&format!(
            "SELECT seq, ts, actor, action, target, details, prev_hash, hash FROM audit \
             WHERE seq > ?1 AND seq < ?2 ORDER BY seq {} LIMIT ?3",
            if desc { "DESC" } else { "ASC" }
        ))?
        .query_map(
            catalog::rusqlite::params![
                f.after.unwrap_or(0),
                f.before.unwrap_or(i64::MAX),
                f.limit.unwrap_or(500).min(1000)
            ],
            |r| {
                let d: String = r.get(5)?;
                Ok(json!({
                    "seq": r.get::<_, i64>(0)?, "ts": r.get::<_, i64>(1)?, "actor": r.get::<_, String>(2)?,
                    "action": r.get::<_, String>(3)?, "target": r.get::<_, String>(4)?,
                    "details": serde_json::from_str::<Value>(&d).unwrap_or(Value::String(d)),
                    "prev_hash": r.get::<_, String>(6)?, "hash": r.get::<_, String>(7)?,
                }))
            },
        )?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Json(Value::Array(rows)))
}

pub async fn verify_audit(State(st): State<St>, ctx: Ctx) -> ApiResult<Json<Value>> {
    ctx.require(AUDITORS)?;
    Ok(Json(match st.cat.verify_audit() {
        Ok(n) => json!({"ok": true, "entries": n}),
        Err(e) => json!({"ok": false, "error": e.to_string()}),
    }))
}
