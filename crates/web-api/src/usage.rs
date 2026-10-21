//! Monthly per-tenant usage for billing (Phase 23a, docs/storage-accounting.md
//! "Usage export"): `GET /usage?month=YYYY-MM[&tenant][&format=csv]` (the rows of
//! `reports::usage`; default the current month up to now). Every role, tenant-scoped
//! users their tenant only; the CSV download is audited `report.export` like the
//! other reports. The same table is the `usage` report type, so a scheduled report
//! (`monthly 1 07:00`) mails last month's usage.

use crate::auth::Ctx;
use crate::{ApiError, ApiResult, St, Q};
use axum::extract::State;
use axum::http::{header, HeaderValue};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use serde_json::json;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UsageQ {
    month: Option<String>,
    tenant: Option<String>,
    format: Option<String>,
}

pub async fn usage(State(st): State<St>, ctx: Ctx, Q(q): Q<UsageQ>) -> ApiResult<Response> {
    let now = catalog::now();
    let month = q.month.unwrap_or_else(|| reports::day(now)[..7].to_owned());
    let (from, end) = reports::usage::month_range(&month).ok_or_else(|| ApiError::bad("month: YYYY-MM"))?;
    if from > now {
        return Err(ApiError::bad("month: lies in the future"));
    }
    // the period is [from, to): up to and including the current second
    let to = end.min((now + 1).max(from + 1));
    let scope = match (ctx.scope(), q.tenant.as_deref().filter(|t| !t.is_empty())) {
        (Some(own), Some(t)) if t != own => return Err(ApiError::forbidden()),
        (Some(own), _) => Some(own.to_owned()),
        (None, t) => t.map(str::to_owned),
    };
    match q.format.as_deref() {
        None | Some("json") => {
            let rows = reports::usage::compute(&st.cat.conn(), scope.as_deref(), from, to)?;
            Ok(
                Json(json!({"month": month, "from": from, "to": to, "complete": end <= now, "tenants": rows}))
                    .into_response(),
            )
        }
        Some("csv") => {
            let t = reports::usage::table(&st.cat.conn(), scope.as_deref(), from, to)?;
            st.audit(
                ctx.name(),
                "report.export",
                "report/usage",
                json!({"type": "usage", "month": month, "from": from, "to": to, "tenant": scope, "rows": t.rows.len()}),
            )?;
            let name = match &scope {
                Some(s) => format!("nexus-usage-{s}-{month}.csv"),
                None => format!("nexus-usage-{month}.csv"),
            };
            let mut res = t.csv().into_response();
            let h = res.headers_mut();
            h.insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("text/csv; charset=utf-8"),
            );
            if let Ok(v) = HeaderValue::from_str(&format!("attachment; filename=\"{name}\"")) {
                h.insert(header::CONTENT_DISPOSITION, v);
            }
            Ok(res)
        }
        Some(_) => Err(ApiError::bad("format: json or csv")),
    }
}
