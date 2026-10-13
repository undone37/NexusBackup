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
    /// SIEM pull (Phase 23a): the same as `after` (entries with a higher seq, oldest first)
    since_seq: Option<i64>,
    before: Option<i64>,
    order: Option<String>,
    limit: Option<u32>,
    /// exact user (or `scheduler`, `web-api`, …)
    actor: Option<String>,
    /// prefix (`user.`, `quorum.approve`)
    action: Option<String>,
    /// substring (`tenant/acme`)
    target: Option<String>,
    /// unix seconds, inclusive
    from: Option<i64>,
    to: Option<i64>,
    /// entries concerning this tenant (`audit_tenants`, Phase 19b); forced to
    /// their own for tenant admins
    tenant: Option<String>,
}

const AUDITORS: &[&str] = &["admin", "security_officer"];
/// The tenant-scoped audit view (list, CSV): tenant admins see their tenant only.
const READERS: &[&str] = &["admin", "security_officer", "tenant_admin"];

/// `WHERE` of the audit filters: `?1` after, `?2` before, `?3` actor, `?4`
/// action prefix, `?5` target substring, `?6` from, `?7` to, `?9` tenant.
const AUDIT_WHERE: &str = "seq > ?1 AND seq < ?2 AND (?3 IS NULL OR actor = ?3) \
     AND (?4 IS NULL OR substr(action, 1, length(?4)) = ?4) AND (?5 IS NULL OR instr(target, ?5) > 0) \
     AND (?6 IS NULL OR ts >= ?6) AND (?7 IS NULL OR ts <= ?7) \
     AND (?9 IS NULL OR seq IN (SELECT seq FROM audit_tenants WHERE tenant = ?9))";

/// seq, ts, actor, action, target, details, prev_hash, hash
type AuditRow = (i64, i64, String, String, String, String, String, String);

impl AuditFilter {
    fn check(&self) -> ApiResult<()> {
        for (k, v) in [
            ("actor", &self.actor),
            ("action", &self.action),
            ("target", &self.target),
            ("tenant", &self.tenant),
        ] {
            if v.as_ref().is_some_and(|s| s.len() > 256) {
                return Err(ApiError::bad(format!("{k}: at most 256 characters")));
            }
        }
        Ok(())
    }

    /// Empty filter strings (an empty form field) mean "any".
    fn text(v: &Option<String>) -> Option<&str> {
        v.as_deref().filter(|s| !s.is_empty())
    }

    /// One page of entries after `after` / before `before`.
    fn query(&self, c: &catalog::rusqlite::Connection, desc: bool, limit: u32) -> ApiResult<Vec<AuditRow>> {
        Ok(c.prepare(&format!(
            "SELECT seq, ts, actor, action, target, details, prev_hash, hash FROM audit WHERE {AUDIT_WHERE} \
             ORDER BY seq {} LIMIT ?8",
            if desc { "DESC" } else { "ASC" }
        ))?
        .query_map(
            catalog::rusqlite::params![
                self.after.unwrap_or(0),
                self.before.unwrap_or(i64::MAX),
                Self::text(&self.actor),
                Self::text(&self.action),
                Self::text(&self.target),
                self.from,
                self.to,
                limit,
                Self::text(&self.tenant)
            ],
            |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                    r.get(6)?,
                    r.get(7)?,
                ))
            },
        )?
        .collect::<Result<Vec<_>, _>>()?)
    }

    /// The filters given (audited with the export).
    fn shown(&self) -> Value {
        let mut v = json!({"actor": self.actor, "action": self.action, "target": self.target, "tenant": self.tenant,
                           "from": self.from, "to": self.to, "after": self.after, "before": self.before});
        if let Some(o) = v.as_object_mut() {
            o.retain(|_, x| !x.is_null() && x != "");
        }
        v
    }
}

/// Filters: `actor` (exact), `action` (prefix), `target` (substring), `from` /
/// `to` (unix seconds); pages with `after` / `before` + `limit`.
pub async fn list_audit(State(st): State<St>, ctx: Ctx, Q(mut f): Q<AuditFilter>) -> ApiResult<Json<Value>> {
    scope_filter(&ctx, &mut f)?;
    f.check()?;
    // ascending from `after` (default); newest first with `before` or `order=desc`
    let desc = match f.order.as_deref() {
        None => f.before.is_some(),
        Some("desc") => true,
        Some("asc") if f.before.is_none() => false,
        Some(_) => return Err(ApiError::bad("order: asc or desc (before implies desc)")),
    };
    let rows = f.query(&st.cat.conn(), desc, f.limit.unwrap_or(500).min(1000))?;
    let rows = rows
        .into_iter()
        .map(|(seq, ts, actor, action, target, d, prev, hash)| {
            json!({
                "seq": seq, "ts": ts, "actor": actor, "action": action, "target": target,
                "details": serde_json::from_str::<Value>(&d).unwrap_or(Value::String(d)),
                "prev_hash": prev, "hash": hash,
            })
        })
        .collect();
    Ok(Json(Value::Array(rows)))
}

/// Admins and security officers filter freely; a tenant-scoped reader (tenant
/// admin) gets the entries concerning their tenant only.
fn scope_filter(ctx: &Ctx, f: &mut AuditFilter) -> ApiResult<()> {
    ctx.require(READERS)?;
    if let Some(t) = ctx.scope() {
        f.tenant = Some(t.to_owned());
    }
    if let Some(s) = f.since_seq.take() {
        if f.after.is_some() {
            return Err(ApiError::bad("since_seq: an alias of after, give one of them"));
        }
        f.after = Some(s);
    }
    Ok(())
}

/// RFC 4180 field: quoted when it contains a comma, quote or line break.
/// Values are exported unchanged (the hashes cover them): open the file as
/// text rather than letting a spreadsheet evaluate cells.
fn csv_field(s: &str) -> String {
    if s.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_owned()
    }
}

/// `GET /audit.csv`: the filtered entries, oldest first, with `prev_hash` and
/// `hash` (each row can be checked against the chain), streamed in pages of
/// 1000. Audited as `audit.export` (with the filters) before the first row.
pub async fn export_audit(State(st): State<St>, ctx: Ctx, Q(mut f): Q<AuditFilter>) -> ApiResult<Response> {
    use tokio::io::AsyncWriteExt;
    scope_filter(&ctx, &mut f)?;
    f.check()?;
    if f.order.is_some() || f.limit.is_some() {
        return Err(ApiError::bad(
            "audit.csv: no order or limit (all matching rows, oldest first)",
        ));
    }
    st.audit(ctx.name(), "audit.export", "audit", f.shown())?;
    let (mut w, r) = tokio::io::duplex(64 << 10);
    tokio::spawn(async move {
        let mut out = String::from("seq,ts,actor,action,target,details,prev_hash,hash\r\n");
        loop {
            let page = match f.query(&st.cat.conn(), false, 1000) {
                Ok(p) => p,
                Err(e) => {
                    // the body ends early: the client sees an incomplete transfer
                    return eprintln!("<3>web-api: audit.csv: {}", e.1);
                }
            };
            let Some(last) = page.last().map(|r| r.0) else { break };
            for (seq, ts, actor, action, target, d, prev, hash) in page {
                let row = [actor, action, target, d].map(|x| csv_field(&x)).join(",");
                out.push_str(&format!("{seq},{ts},{row},{prev},{hash}\r\n"));
            }
            if w.write_all(out.as_bytes()).await.is_err() {
                return;
            }
            out.clear();
            f.after = Some(last);
        }
        let _ = w.write_all(out.as_bytes()).await;
    });
    let mut res = axum::body::Body::from_stream(tokio_util::io::ReaderStream::new(r)).into_response();
    let h = res.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/csv; charset=utf-8"),
    );
    h.insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_static("attachment; filename=\"nexus-audit.csv\""),
    );
    Ok(res)
}

pub async fn verify_audit(State(st): State<St>, ctx: Ctx) -> ApiResult<Json<Value>> {
    ctx.require(AUDITORS)?;
    Ok(Json(match st.cat.verify_audit() {
        Ok(n) => json!({"ok": true, "entries": n}),
        Err(e) => json!({"ok": false, "error": e.to_string()}),
    }))
}
