//! Reports (Phase 14e, docs/control-plane.md "Reports"): CSV downloads
//! `GET /reports/{protection,failed,sla,storage}.csv?from&to&tenant` (every role;
//! tenant-scoped users get their tenant only; audited `report.export`) and the
//! scheduled reports (setting `reports`, admin): `GET|PUT /settings/reports`,
//! `POST /settings/reports/{name}/send` (queues `report_send`; the scheduler
//! composes and mails it through the SMTP server of Settings → Alert delivery).

use crate::auth::Ctx;
use crate::settings::{mailbox, queue, ALERTS_SETTING};
use crate::{ApiError, ApiResult, St, J, Q};
use axum::extract::{Path, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use catalog::rusqlite::{params, Connection, OptionalExtension};
use reports::{Kind, Scheduled};
use serde::Deserialize;
use serde_json::{json, Value};

/// Every role may export (tenant users: own tenant); `viewer` once 14d adds it.
const READ: &[&str] = &["admin", "operator", "security_officer", "tenant_user", "viewer"];
const ADMIN: &[&str] = &["admin"];
const SETTINGS_READ: &[&str] = &["admin", "security_officer"];
const DAY: i64 = 86400;
/// Longest range of one export.
const MAX_DAYS: i64 = 400;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReportQuery {
    from: Option<String>,
    to: Option<String>,
    tenant: Option<String>,
}

/// `YYYY-MM-DD` (UTC; as `to` the whole day counts) or unix seconds.
fn when(v: &str, what: &str, end: bool) -> ApiResult<i64> {
    if let Ok(n) = v.parse::<i64>() {
        return Ok(n);
    }
    reports::parse_day(v)
        .map(|d| (d + i64::from(end)) * DAY)
        .ok_or_else(|| ApiError::bad(format!("{what}: YYYY-MM-DD or unix seconds")))
}

/// `[from, to)` of a request: default the last 7 days up to now.
pub fn range(from: Option<&str>, to: Option<&str>, now: i64) -> ApiResult<(i64, i64)> {
    let to = to.map(|v| when(v, "to", true)).transpose()?.unwrap_or(now);
    let from = from
        .map(|v| when(v, "from", false))
        .transpose()?
        .unwrap_or(to - 7 * DAY);
    if from >= to {
        return Err(ApiError::bad("from must be before to"));
    }
    if to - from > MAX_DAYS * DAY {
        return Err(ApiError::bad(format!("range: at most {MAX_DAYS} days")));
    }
    Ok((from, to))
}

pub async fn export(
    State(st): State<St>,
    ctx: Ctx,
    Path(file): Path<String>,
    Q(q): Q<ReportQuery>,
) -> ApiResult<Response> {
    ctx.require(READ)?;
    let kind = file
        .strip_suffix(".csv")
        .and_then(Kind::parse)
        .ok_or_else(ApiError::not_found)?;
    let scope = match (ctx.scope(), q.tenant.as_deref().filter(|t| !t.is_empty())) {
        (Some(own), Some(t)) if t != own => return Err(ApiError::forbidden()),
        (Some(own), _) => Some(own.to_owned()),
        (None, t) => t.map(str::to_owned),
    };
    let now = catalog::now();
    let (from, to) = range(q.from.as_deref(), q.to.as_deref(), now)?;
    let table = reports::generate(&st.cat.conn(), kind, scope.as_deref(), from, to, now)?;
    st.audit(
        ctx.name(),
        "report.export",
        &format!("report/{}", kind.name()),
        json!({"type": kind.name(), "from": from, "to": to, "tenant": scope, "rows": table.rows.len()}),
    )?;
    let name = match &scope {
        Some(t) => format!("nexus-{}-{t}-{}.csv", kind.name(), reports::day(to - 1)),
        None => format!("nexus-{}-{}.csv", kind.name(), reports::day(to - 1)),
    };
    let mut res = table.csv().into_response();
    let h = res.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/csv; charset=utf-8"),
    );
    // tenant names are [a-z0-9-] (validate::name), so the header value is plain ASCII
    if let Ok(v) = HeaderValue::from_str(&format!("attachment; filename=\"{name}\"")) {
        h.insert(header::CONTENT_DISPOSITION, v);
    }
    Ok(res)
}

// ---------------------------------------------------------------- scheduled reports

/// The scheduled reports, each with its last run (`report_send` job).
fn view(c: &Connection) -> ApiResult<Value> {
    let mut out = Vec::new();
    for r in reports::load_scheduled(c)? {
        let last: Option<Value> = c
            .query_row(
                "SELECT id, state, created, finished, requested_by FROM jobs
                 WHERE kind = 'report_send' AND json_extract(params, '$.name') = ?1 ORDER BY id DESC LIMIT 1",
                [&r.name],
                |r| {
                    Ok(json!({"job_id": r.get::<_, i64>(0)?, "state": r.get::<_, String>(1)?,
                              "created": r.get::<_, i64>(2)?, "finished": r.get::<_, Option<i64>>(3)?,
                              "requested_by": r.get::<_, String>(4)?}))
                },
            )
            .optional()?;
        let mut v = json!(r);
        v["last"] = json!(last);
        out.push(v);
    }
    Ok(json!({"reports": out, "smtp": smtp_configured(c)?}))
}

fn smtp_configured(c: &Connection) -> ApiResult<bool> {
    Ok(catalog::setting(c, ALERTS_SETTING)?
        .and_then(|v| serde_json::from_str::<Value>(&v).ok())
        .is_some_and(|v| v["smtp"]["host"].is_string()))
}

pub async fn get_scheduled(State(st): State<St>, ctx: Ctx) -> ApiResult<Json<Value>> {
    ctx.require(SETTINGS_READ)?;
    Ok(Json(view(&st.cat.conn())?))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScheduledReq {
    reports: Vec<Scheduled>,
}

fn check(c: &Connection, list: &[Scheduled]) -> ApiResult<()> {
    if list.len() > reports::MAX_SCHEDULED {
        return Err(ApiError::bad(format!("reports: at most {}", reports::MAX_SCHEDULED)));
    }
    if !list.is_empty() && !smtp_configured(c)? {
        return Err(ApiError::bad(
            "scheduled reports are mailed through the SMTP server: configure it under Settings → Alert delivery first",
        ));
    }
    let mut names = std::collections::HashSet::new();
    for r in list {
        r.check().map_err(ApiError::bad)?;
        if !names.insert(r.name.as_str()) {
            return Err(ApiError::bad(format!("report {}: names must be unique", r.name)));
        }
        if let Some(bad) = r.recipients.iter().find(|m| !mailbox(m)) {
            return Err(ApiError::bad(format!(
                "report {}: recipients: {bad:?} is not a mail address",
                r.name
            )));
        }
        if let Some(t) = &r.tenant {
            let n: i64 = c.query_row("SELECT COUNT(*) FROM tenants WHERE name = ?1", [t], |r| r.get(0))?;
            if n == 0 {
                return Err(ApiError::bad(format!("report {}: unknown tenant {t}", r.name)));
            }
        }
    }
    Ok(())
}

/// Replaces the scheduled reports (admin; applies directly, audited).
pub async fn put_scheduled(State(st): State<St>, ctx: Ctx, J(r): J<ScheduledReq>) -> ApiResult<Json<Value>> {
    ctx.require(ADMIN)?;
    check(&st.cat.conn(), &r.reports)?;
    catalog::set_setting(&st.cat.conn(), reports::SETTING, &json!(r.reports).to_string())?;
    st.audit(
        ctx.name(),
        "settings.reports",
        "settings/reports",
        json!({"reports": r.reports}),
    )?;
    Ok(Json(view(&st.cat.conn())?))
}

/// Sends a scheduled report now, covering one schedule period up to now
/// (202 `{job_id}`; the result lands in the job and the report's `last`).
pub async fn send_now(State(st): State<St>, ctx: Ctx, Path(name): Path<String>) -> ApiResult<Response> {
    ctx.require(ADMIN)?;
    let r = reports::load_scheduled(&st.cat.conn())?
        .into_iter()
        .find(|r| r.name == name)
        .ok_or_else(ApiError::not_found)?;
    let period = r.schedule().map_err(|e| ApiError::bad(format!("{e:#}")))?.period();
    let to = catalog::now();
    let busy: i64 = st.cat.conn().query_row(
        "SELECT COUNT(*) FROM jobs WHERE kind = 'report_send' AND state IN ('queued', 'running')
         AND json_extract(params, '$.name') = ?1",
        params![name],
        |r| r.get(0),
    )?;
    if busy > 0 {
        return Err(ApiError::conflict("this report is already being sent"));
    }
    let id = queue(
        &st,
        &ctx,
        "report_send",
        json!({"name": name, "from": to - period, "to": to}),
    )?;
    Ok((StatusCode::ACCEPTED, Json(json!({"job_id": id}))).into_response())
}
