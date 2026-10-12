//! Settings → Diagnostics (Phase 14b): self-checks and redacted support bundles.
//! The web-api writes intent only: `request.json` into the diagnostics control dir
//! (default /var/lib/nexus/diag), which `nexus-diag.path` hands to the root helper
//! `nexus-diag`. It writes `<id>/status.json`, `checks.json` and `bundle.tar.gz`, which
//! are served here: checks to administrators and security officers, a bundle only to
//! the administrator who requested it, for 24 h (like file-restore downloads).

use crate::auth::Ctx;
use crate::jobs::DOWNLOAD_TTL_SECS;
use crate::{random_hex, ApiError, ApiResult, St, J};
use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};
use std::path::PathBuf;

const ADMIN: &[&str] = &["admin"];
const READ: &[&str] = &["admin", "security_officer"];
/// nexus-diag refuses longer ranges as well
const MAX_RANGE_SECS: i64 = 31 * 86400;
/// a request nobody consumed for this long (helper not running) may be replaced
const STALE_REQUEST_SECS: u64 = 600;

fn dir(st: &St) -> PathBuf {
    st.diag_dir
        .get_or_init(|| {
            std::env::var_os("NEXUS_DIAG_DIR")
                .map(Into::into)
                .unwrap_or_else(|| "/var/lib/nexus/diag".into())
        })
        .clone()
}

fn valid_id(id: &str) -> bool {
    id.len() == 32 && id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Appliance-wide: never for tenant-scoped accounts.
fn require(ctx: &Ctx, roles: &[&str]) -> ApiResult<()> {
    ctx.require(roles)?;
    if ctx.scope().is_some() {
        return Err(ApiError::forbidden());
    }
    Ok(())
}

fn read_json(p: &std::path::Path) -> Option<Value> {
    let b = std::fs::read(p).ok()?;
    (b.len() <= 1 << 20).then(|| serde_json::from_slice(&b).ok())?
}

/// The pending request, if it is still fresh.
fn pending(d: &std::path::Path) -> Option<Value> {
    let p = d.join("request.json");
    let age = std::fs::metadata(&p)
        .ok()?
        .modified()
        .ok()?
        .elapsed()
        .map_or(0, |a| a.as_secs());
    (age < STALE_REQUEST_SECS).then(|| read_json(&p))?
}

fn submit(st: &St, ctx: &Ctx, kind: &str, since: Option<i64>, until: Option<i64>) -> ApiResult<String> {
    let d = dir(st);
    if pending(&d).is_some() {
        return Err(ApiError::conflict(
            "a diagnostics request is waiting to run; try again in a minute",
        ));
    }
    let id = random_hex()[..32].to_owned();
    let mut req = json!({"id": id, "kind": kind, "by": ctx.name()});
    if let (Some(s), Some(u)) = (since, until) {
        req["since"] = json!(s);
        req["until"] = json!(u);
    }
    let tmp = d.join(".request.json.tmp");
    std::fs::write(&tmp, req.to_string()).map_err(|e| anyhow::anyhow!("{}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, d.join("request.json")).map_err(|e| anyhow::anyhow!("{}: {e}", d.display()))?;
    Ok(id)
}

/// POST /diagnostics/checks: run the self-checks now.
pub async fn run_checks(State(st): State<St>, ctx: Ctx) -> ApiResult<Response> {
    require(&ctx, READ)?;
    let id = submit(&st, &ctx, "checks", None, None)?;
    st.audit(ctx.name(), "diag.checks", &format!("diag/{id}"), json!({}))?;
    Ok((StatusCode::ACCEPTED, Json(json!({"id": id, "state": "queued"}))).into_response())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleReq {
    since: Option<i64>,
    until: Option<i64>,
}

/// POST /diagnostics/bundle {since?, until?}: create a redacted support bundle
/// (default: the last 24 h).
pub async fn create_bundle(State(st): State<St>, ctx: Ctx, J(r): J<BundleReq>) -> ApiResult<Response> {
    require(&ctx, ADMIN)?;
    let now = catalog::now();
    let until = r.until.unwrap_or(now);
    let since = r.since.unwrap_or(until - 86400);
    if since < 0 || since >= until || until > now + 3600 {
        return Err(ApiError::bad("since must be before until, and until not in the future"));
    }
    if until - since > MAX_RANGE_SECS {
        return Err(ApiError::bad("the time range is limited to 31 days"));
    }
    let id = submit(&st, &ctx, "bundle", Some(since), Some(until))?;
    st.audit(
        ctx.name(),
        "diag.bundle",
        &format!("diag/{id}"),
        json!({"since": since, "until": until}),
    )?;
    Ok((StatusCode::ACCEPTED, Json(json!({"id": id, "state": "queued"}))).into_response())
}

/// One result as the UI sees it; `None` when it does not exist or is not the caller's.
fn view(d: &std::path::Path, id: &str, ctx: &Ctx) -> Option<Value> {
    let owner_only = |kind: &str, by: &str| kind != "bundle" || by == ctx.name();
    let Some(s) = read_json(&d.join(id).join("status.json")) else {
        // not started yet: the pending request
        let r = pending(d).filter(|r| r["id"] == id)?;
        let (kind, by) = (r["kind"].as_str()?, r["by"].as_str()?);
        return owner_only(kind, by).then(|| {
            json!({"id": id, "kind": kind, "by": by, "state": "queued", "since": r["since"], "until": r["until"],
                   "created": null, "finished": null, "error": null, "checks": null, "bundle": null})
        });
    };
    let (kind, by) = (s["kind"].as_str()?, s["by"].as_str()?);
    if !owner_only(kind, by) {
        return None;
    }
    let created = s["created"].as_i64()?;
    let expired = catalog::now() - created > DOWNLOAD_TTL_SECS;
    let checks = read_json(&d.join(id).join("checks.json")).filter(Value::is_array);
    let bundle = s["files"]["bundle.tar.gz"]
        .as_u64()
        .filter(|_| !expired)
        .map(|bytes| json!({"bytes": bytes, "url": format!("/api/v1/diagnostics/{id}/download")}));
    Some(json!({
        "id": id, "kind": kind, "by": by, "state": s["state"], "since": s["since"], "until": s["until"],
        "created": created, "finished": s["finished"], "error": s["error"],
        "expires": created + DOWNLOAD_TTL_SECS, "checks": checks, "bundle": bundle,
    }))
}

/// GET /diagnostics: recent results (newest first; bundles only the caller's own).
pub async fn list(State(st): State<St>, ctx: Ctx) -> ApiResult<Json<Value>> {
    require(&ctx, READ)?;
    let d = dir(&st);
    let mut items: Vec<Value> = std::fs::read_dir(&d)
        .map(|rd| {
            rd.filter_map(Result::ok)
                .filter_map(|e| e.file_name().into_string().ok())
                .filter(|n| valid_id(n))
                .filter_map(|n| view(&d, &n, &ctx))
                .collect()
        })
        .unwrap_or_default();
    if let Some(id) = pending(&d).and_then(|r| r["id"].as_str().map(str::to_owned)) {
        if !items.iter().any(|v| v["id"] == id.as_str()) {
            items.extend(view(&d, &id, &ctx));
        }
    }
    // queued first, then by creation time
    items.sort_by_key(|v| std::cmp::Reverse(v["created"].as_i64().unwrap_or(i64::MAX)));
    Ok(Json(json!({"items": items})))
}

/// GET /diagnostics/{id}
pub async fn get_one(State(st): State<St>, ctx: Ctx, Path(id): Path<String>) -> ApiResult<Json<Value>> {
    require(&ctx, READ)?;
    if !valid_id(&id) {
        return Err(ApiError::not_found());
    }
    view(&dir(&st), &id, &ctx).map(Json).ok_or_else(ApiError::not_found)
}

/// GET /diagnostics/{id}/download: the bundle, to the administrator who requested it,
/// for 24 h; audited like every download.
pub async fn download(State(st): State<St>, ctx: Ctx, Path(id): Path<String>) -> ApiResult<Response> {
    require(&ctx, ADMIN)?;
    if !valid_id(&id) {
        return Err(ApiError::not_found());
    }
    let d = dir(&st);
    let v = view(&d, &id, &ctx).ok_or_else(ApiError::not_found)?;
    if v["bundle"].is_null() {
        return Err(ApiError::not_found());
    }
    let path = d.join(&id).join("bundle.tar.gz");
    let file = tokio::fs::File::open(&path).await.map_err(|_| ApiError::not_found())?;
    let meta = file.metadata().await.map_err(|_| ApiError::not_found())?;
    if !meta.is_file() {
        return Err(ApiError::not_found());
    }
    st.audit(
        ctx.name(),
        "download.get",
        &format!("diag/{id}"),
        json!({"bytes": meta.len(), "kind": "support_bundle"}),
    )?;
    let mut res = Body::from_stream(tokio_util::io::ReaderStream::new(file)).into_response();
    let h = res.headers_mut();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static("application/gzip"));
    h.insert(header::CONTENT_LENGTH, HeaderValue::from(meta.len()));
    h.insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_str(&format!("attachment; filename=\"nexus-support-{id}.tar.gz\"")).unwrap(),
    );
    Ok(res)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids() {
        assert!(valid_id("0123456789abcdef0123456789abcdef"));
        for bad in ["", "../x", "0123456789ABCDEF0123456789abcdef", &"a".repeat(64)] {
            assert!(!valid_id(bad), "{bad}");
        }
    }
}
