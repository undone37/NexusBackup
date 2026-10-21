//! Settings → Backup of this appliance (docs/control-plane.md "Configuration backup"):
//! - `GET /settings/config-backup` (admin, security officer; not tenant-scoped): the
//!   latest bundle (helper `latest.json`), the last runs (`config_backup` and
//!   `config_upload` jobs), the offsite targets with their last upload;
//! - `POST /settings/config-backup/run` (admin): queues `config_backup` (202 `{job_id}`);
//! - `GET /settings/config-backup/download` (admin with the download permission): the
//!   latest sealed bundle. No approval: it opens only with the appliance recovery key
//!   (the same key that opens every backup). Audited `download.get`, never via API token.

use crate::auth::Ctx;
use crate::settings::queue;
use crate::{ApiError, ApiResult, St};
use axum::body::Body;
use axum::extract::State;
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use catalog::rusqlite::{params, Connection, OptionalExtension};
use serde_json::{json, Value};
use std::path::PathBuf;

const ADMIN: &[&str] = &["admin"];
const READ: &[&str] = &["admin", "security_officer"];
const LATEST: &str = "latest.bundle";
const RUNS: i64 = 20;

fn dir(st: &St) -> PathBuf {
    st.config_backup_dir
        .get_or_init(|| {
            std::env::var_os("NEXUS_CONFIG_BACKUP_DIR")
                .map(Into::into)
                .unwrap_or_else(|| "/var/lib/nexus/config-backup".into())
        })
        .clone()
}

/// Appliance-wide: never for tenant-scoped accounts.
fn require(ctx: &Ctx, roles: &[&str]) -> ApiResult<()> {
    ctx.require(roles)?;
    if ctx.scope().is_some() {
        return Err(ApiError::forbidden());
    }
    Ok(())
}

/// The bundle on disk now, as the helper described it (`None`: none yet).
fn latest(st: &St) -> Option<Value> {
    let d = dir(st);
    let s: Value = serde_json::from_slice(&std::fs::read(d.join("latest.json")).ok()?).ok()?;
    let bytes = std::fs::metadata(d.join(LATEST)).ok()?.len();
    Some(
        json!({"appliance": s["appliance"], "created": s["created"], "bytes": bytes, "sha256": s["sha256"],
                "files": s["files"].as_array().map(Vec::len)}),
    )
}

fn job_row(r: &catalog::rusqlite::Row<'_>) -> catalog::rusqlite::Result<Value> {
    let params: Value = serde_json::from_str(&r.get::<_, String>(6)?).unwrap_or(Value::Null);
    let result: Option<Value> = r
        .get::<_, Option<String>>(7)?
        .and_then(|s| serde_json::from_str(&s).ok());
    Ok(
        json!({"id": r.get::<_, i64>(0)?, "kind": r.get::<_, String>(1)?, "state": r.get::<_, String>(2)?,
              "created": r.get::<_, i64>(3)?, "finished": r.get::<_, Option<i64>>(4)?,
              "requested_by": r.get::<_, String>(5)?, "target": params["target"], "result": result}),
    )
}

const COLS: &str = "id, kind, state, created, finished, requested_by, params, result";

fn view(st: &St, c: &Connection) -> ApiResult<Value> {
    let runs: Vec<Value> = c
        .prepare(&format!(
            "SELECT {COLS} FROM jobs WHERE kind IN ('config_backup', 'config_upload') ORDER BY id DESC LIMIT {RUNS}"
        ))?
        .query_map([], job_row)?
        .collect::<Result<_, _>>()?;
    let last_ok: Option<i64> = c.query_row(
        "SELECT MAX(finished) FROM jobs WHERE kind = 'config_backup' AND state = 'ok'",
        [],
        |r| r.get(0),
    )?;
    let busy: i64 = c.query_row(
        "SELECT COUNT(*) FROM jobs WHERE kind = 'config_backup' AND state IN ('queued', 'running')",
        [],
        |r| r.get(0),
    )?;
    let mut targets = Vec::new();
    // every tenant's first and second offsite target (Phase 39 O1: the bundle goes to both)
    let names: Vec<(String, bool)> = c
        .prepare(
            "SELECT name, json_type(offsite, '$.second.remote') = 'object' FROM tenants
             WHERE json_valid(offsite) AND json_type(offsite, '$.remote') = 'object' ORDER BY name",
        )?
        .query_map([], |r| Ok((r.get(0)?, r.get::<_, Option<bool>>(1)?.unwrap_or(false))))?
        .collect::<Result<_, _>>()?;
    for (t, second) in names {
        for n in [1i64, 2].into_iter().filter(|n| *n == 1 || second) {
            // config_upload params carry `n: 2` for the second target, nothing for the first
            let of_n = "COALESCE(json_extract(params, '$.n'), 1) = ?2";
            let last: Option<Value> = c
                .query_row(
                    &format!(
                        "SELECT {COLS} FROM jobs WHERE kind = 'config_upload' AND json_extract(params, '$.target') = ?1
                         AND {of_n} ORDER BY id DESC LIMIT 1"
                    ),
                    params![t, n],
                    job_row,
                )
                .optional()?;
            let ok: Option<i64> = c.query_row(
                &format!(
                    "SELECT MAX(finished) FROM jobs WHERE kind = 'config_upload' AND state = 'ok'
                     AND json_extract(params, '$.target') = ?1 AND {of_n}"
                ),
                params![t, n],
                |r| r.get(0),
            )?;
            targets.push(json!({"tenant": t, "target": n, "last": last, "last_ok": ok}));
        }
    }
    Ok(json!({
        "appliance_id": catalog::setting(c, "appliance_id")?,
        "last_success": last_ok,
        "running": busy > 0,
        "latest": latest(st),
        "targets": targets,
        "runs": runs,
    }))
}

pub async fn get(State(st): State<St>, ctx: Ctx) -> ApiResult<Json<Value>> {
    require(&ctx, READ)?;
    let v = view(&st, &st.cat.conn())?;
    Ok(Json(v))
}

/// Run now (admin): one `config_backup`; the uploads follow when it succeeded.
pub async fn run(State(st): State<St>, ctx: Ctx) -> ApiResult<Response> {
    require(&ctx, ADMIN)?;
    let busy: i64 = st.cat.conn().query_row(
        "SELECT COUNT(*) FROM jobs WHERE kind = 'config_backup' AND state IN ('queued', 'running')",
        [],
        |r| r.get(0),
    )?;
    if busy > 0 {
        return Err(ApiError::conflict(
            "a configuration backup is already queued or running",
        ));
    }
    let id = queue(&st, &ctx, "config_backup", json!({}))?;
    Ok((StatusCode::ACCEPTED, Json(json!({"job_id": id}))).into_response())
}

/// The latest sealed bundle (admin with the download permission), audited.
pub async fn download(State(st): State<St>, ctx: Ctx) -> ApiResult<Response> {
    require(&ctx, ADMIN)?;
    if !ctx.user.can_download {
        return Err(ApiError::forbidden());
    }
    let info = latest(&st).ok_or_else(ApiError::not_found)?;
    let file = tokio::fs::File::open(dir(&st).join(LATEST))
        .await
        .map_err(|_| ApiError::not_found())?;
    let meta = file.metadata().await.map_err(|_| ApiError::not_found())?;
    let appliance = info["appliance"].as_str().unwrap_or("appliance");
    st.audit(
        ctx.name(),
        "download.get",
        &format!("config_backup/{appliance}"),
        json!({"kind": "config_backup", "bytes": meta.len(), "created": info["created"], "sha256": info["sha256"]}),
    )?;
    // the id is [a-z0-9-] (scheduler), so the header is plain ASCII
    let name = format!(
        "nexus-config-{appliance}-{}.bundle",
        info["created"].as_i64().unwrap_or(0)
    );
    let mut res = Body::from_stream(tokio_util::io::ReaderStream::new(file)).into_response();
    let h = res.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    h.insert(header::CONTENT_LENGTH, HeaderValue::from(meta.len()));
    if let Ok(v) = HeaderValue::from_str(&format!("attachment; filename=\"{name}\"")) {
        h.insert(header::CONTENT_DISPOSITION, v);
    }
    Ok(res)
}
