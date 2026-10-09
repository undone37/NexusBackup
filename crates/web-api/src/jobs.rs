//! Job requests, snapshots, downloads, alerts.

use crate::auth::Ctx;
use crate::{random_hex, validate, ApiError, ApiResult, St, J, Q};
use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use catalog::rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

const OPS: &[&str] = &["admin", "operator"];
/// Kinds a tenant_user may request (restores only, own tenant).
const RESTORE_KINDS: &[&str] = &[
    "restore",
    "restore_ct",
    "instant_recover",
    "files_list",
    "files_get",
    "restore_files",
];
/// Kinds only an admin may request (they change software or trust on a host).
const ADMIN_KINDS: &[&str] = &["agent_update", "agent_enroll"];
pub const DOWNLOAD_TTL_SECS: i64 = 24 * 3600;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobReq {
    kind: String,
    tenant: String,
    #[serde(default)]
    params: Value,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct BackupP {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    group_id: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    vmid: Option<u32>,
    /// one Linux agent (its linux source)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    agent_id: Option<String>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RestoreFilesP {
    /// `host-<agent_id>`
    source: String,
    time: i64,
    paths: Vec<String>,
    /// absolute path on the target agent
    target: String,
    overwrite: String,
    /// the target agent's name, typed by the user
    confirm: String,
    /// target agent (default: the snapshot's agent; same tenant)
    #[serde(default)]
    agent_id: Option<String>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AgentP {
    agent_id: String,
}

/// Name of an agent of `tenant`, or 400.
fn agent_name(st: &St, tenant: &str, id: &str) -> ApiResult<String> {
    validate::agent_id(id)?;
    let n = st
        .cat
        .conn()
        .query_row(
            "SELECT name FROM agents WHERE id = ?1 AND tenant = ?2",
            params![id, tenant],
            |r| r.get(0),
        )
        .optional()?;
    n.ok_or_else(|| ApiError::bad("agent_id: no such agent in this tenant"))
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RestoreP {
    source: String,
    time: i64,
    node: String,
    target: u32,
    storage: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct FilesListP {
    source: String,
    time: i64,
    path: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct FilesGetP {
    source: String,
    time: i64,
    paths: Vec<String>,
    format: String,
    /// set by the web-api: the scheduler writes `<downloads>/<token>.<format>`
    #[serde(default, skip_deserializing)]
    download_token: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct MaintP {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    source: Option<String>,
}

fn parse<T: serde::de::DeserializeOwned>(v: Value) -> ApiResult<T> {
    let v = if v.is_null() { json!({}) } else { v };
    serde_json::from_value(v).map_err(|e| ApiError::bad(format!("params: {e}")))
}

fn snapshot_exists(st: &St, tenant: &str, source: &str, time: i64) -> ApiResult<()> {
    validate::source_ref(source)?;
    let found = st
        .cat
        .conn()
        .query_row(
            "SELECT 1 FROM snapshots WHERE tenant = ?1 AND source = ?2 AND time = ?3",
            params![tenant, source, time],
            |_| Ok(()),
        )
        .optional()?;
    found.ok_or_else(|| ApiError(StatusCode::NOT_FOUND, "no such snapshot".into()))
}

/// Validates and canonicalises the params of a job request.
fn check_params(st: &St, kind: &str, tenant: &str, p: Value) -> ApiResult<Value> {
    Ok(match kind {
        "backup" => {
            crate::replication::refuse_replicated(&st.cat.conn(), tenant)?;
            let b: BackupP = parse(p)?;
            match (b.group_id, b.vmid, &b.agent_id) {
                (None, None, Some(a)) => {
                    agent_name(st, tenant, a)?;
                }
                (Some(g), None, None) => {
                    let ok = st
                        .cat
                        .conn()
                        .query_row(
                            "SELECT 1 FROM groups WHERE id = ?1 AND tenant = ?2",
                            params![g, tenant],
                            |_| Ok(()),
                        )
                        .optional()?;
                    ok.ok_or_else(|| ApiError::bad("group_id: no such group in this tenant"))?;
                }
                (None, Some(v), None) => validate::vmid(v)?,
                _ => return Err(ApiError::bad("params: exactly one of group_id, vmid, agent_id")),
            }
            json!(b)
        }
        "restore_files" => {
            let mut r: RestoreFilesP = parse(p)?;
            let src_agent = r
                .source
                .strip_prefix("host-")
                .ok_or_else(|| ApiError::bad("source: restore_files needs a host-<agent_id> snapshot"))?
                .to_owned();
            snapshot_exists(st, tenant, &r.source, r.time)?;
            if r.paths.is_empty() || r.paths.len() > 1000 {
                return Err(ApiError::bad("paths: 1..=1000 entries"));
            }
            for x in &r.paths {
                validate::host_path(x, "paths")?;
            }
            validate::host_path(&r.target, "target")?;
            if !["never", "if_older", "always"].contains(&r.overwrite.as_str()) {
                return Err(ApiError::bad("overwrite: never, if_older or always"));
            }
            let target_agent = r.agent_id.clone().unwrap_or(src_agent);
            let name = agent_name(st, tenant, &target_agent)?;
            if r.confirm != name {
                return Err(ApiError::bad(format!(
                    "confirm: type the target agent's name ({name}) to confirm the restore"
                )));
            }
            r.agent_id = Some(target_agent);
            json!(r)
        }
        "agent_update" | "agent_enroll" => {
            let a: AgentP = parse(p)?;
            agent_name(st, tenant, &a.agent_id)?;
            json!(a)
        }
        "restore" | "restore_ct" | "instant_recover" => {
            let r: RestoreP = parse(p)?;
            let want = if kind == "restore_ct" { "ct-" } else { "vm-" };
            if !r.source.starts_with(want) {
                return Err(ApiError::bad(format!("source: {kind} needs a {want}<vmid> snapshot")));
            }
            validate::name(&r.node, "node")?;
            validate::vmid(r.target)?;
            validate::name(&r.storage, "storage")?;
            snapshot_exists(st, tenant, &r.source, r.time)?;
            json!(r)
        }
        "files_list" => {
            let f: FilesListP = parse(p)?;
            validate::guest_path(&f.path)?;
            snapshot_exists(st, tenant, &f.source, f.time)?;
            json!(f)
        }
        "files_get" => {
            let mut f: FilesGetP = parse(p)?;
            if f.paths.is_empty() || f.paths.len() > 1000 {
                return Err(ApiError::bad("paths: 1..=1000 entries"));
            }
            for x in &f.paths {
                validate::guest_path(x)?;
            }
            if f.format != "tar" && f.format != "zip" {
                return Err(ApiError::bad("format: tar or zip"));
            }
            snapshot_exists(st, tenant, &f.source, f.time)?;
            f.download_token = random_hex();
            json!(f)
        }
        "offsite" | "retention" | "gc" | "verify" => {
            let m: MaintP = parse(p)?;
            if let Some(s) = &m.source {
                validate::source_ref(s)?;
            }
            json!(m)
        }
        _ => return Err(ApiError::bad("kind: unknown job kind")),
    })
}

/// 202 `{id}` (+ `download_token` for `files_get`).
pub async fn create_job(State(st): State<St>, ctx: Ctx, J(r): J<JobReq>) -> ApiResult<Response> {
    let allowed = match ctx.user.role.as_str() {
        "admin" => true,
        "operator" => !ADMIN_KINDS.contains(&r.kind.as_str()),
        "tenant_user" => RESTORE_KINDS.contains(&r.kind.as_str()),
        _ => false,
    };
    if !allowed {
        return Err(ApiError::forbidden());
    }
    validate::name(&r.tenant, "tenant")?;
    if !ctx.sees(&r.tenant) {
        return Err(ApiError::forbidden());
    }
    let tenant_ok = st
        .cat
        .conn()
        .query_row("SELECT 1 FROM tenants WHERE name = ?1", [&r.tenant], |_| Ok(()))
        .optional()?;
    tenant_ok.ok_or_else(|| ApiError::bad("tenant: does not exist"))?;
    let params = check_params(&st, &r.kind, &r.tenant, r.params)?;
    let id = {
        let c = st.cat.conn();
        c.execute(
            "INSERT INTO jobs (kind, tenant, params, state, requested_by, created) VALUES (?1, ?2, ?3, 'queued', ?4, ?5)",
            params![r.kind, r.tenant, params.to_string(), ctx.name(), catalog::now()],
        )?;
        c.last_insert_rowid()
    };
    st.audit(
        ctx.name(),
        "job.create",
        &format!("job/{id}"),
        json!({"kind": r.kind, "tenant": r.tenant, "params": params}),
    )?;
    let mut body = json!({"id": id});
    if let Some(t) = params.get("download_token") {
        body["download_token"] = t.clone();
    }
    Ok((StatusCode::ACCEPTED, Json(body)).into_response())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobFilter {
    state: Option<String>,
    kind: Option<String>,
    tenant: Option<String>,
    limit: Option<u32>,
}

fn job_json(r: &catalog::rusqlite::Row, with_log: bool) -> catalog::rusqlite::Result<Value> {
    let p: String = r.get(3)?;
    let mut v = json!({
        "id": r.get::<_, i64>(0)?, "kind": r.get::<_, String>(1)?, "tenant": r.get::<_, String>(2)?,
        "params": serde_json::from_str::<Value>(&p).unwrap_or_default(), "state": r.get::<_, String>(4)?,
        "requested_by": r.get::<_, String>(5)?, "created": r.get::<_, i64>(6)?,
        "started": r.get::<_, Option<i64>>(7)?, "finished": r.get::<_, Option<i64>>(8)?,
        "result": r.get::<_, Option<String>>(10)?.and_then(|s| serde_json::from_str::<Value>(&s).ok()),
    });
    if with_log {
        v["log"] = json!(r.get::<_, String>(9)?);
    }
    Ok(v)
}

const JOB_COLS: &str = "id, kind, tenant, params, state, requested_by, created, started, finished, log, result";

pub async fn list_jobs(State(st): State<St>, ctx: Ctx, Q(f): Q<JobFilter>) -> ApiResult<Json<Value>> {
    let c = st.cat.conn();
    let rows = c
        .prepare(&format!(
            "SELECT {JOB_COLS} FROM jobs WHERE (?1 IS NULL OR state = ?1) AND (?2 IS NULL OR kind = ?2)
             AND (?3 IS NULL OR tenant = ?3) AND (?4 IS NULL OR tenant = ?4) ORDER BY id DESC LIMIT ?5"
        ))?
        .query_map(
            params![f.state, f.kind, f.tenant, ctx.scope(), f.limit.unwrap_or(100).min(1000)],
            |r| job_json(r, false),
        )?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Json(Value::Array(rows)))
}

pub async fn get_job(State(st): State<St>, ctx: Ctx, Path(id): Path<i64>) -> ApiResult<Json<Value>> {
    let c = st.cat.conn();
    let job = c
        .query_row(
            &format!("SELECT {JOB_COLS} FROM jobs WHERE id = ?1 AND (?2 IS NULL OR tenant = ?2)"),
            params![id, ctx.scope()],
            |r| job_json(r, true),
        )
        .optional()?
        .ok_or_else(ApiError::not_found)?;
    Ok(Json(job))
}

/// Queued jobs only; running jobs are owned by the scheduler.
pub async fn cancel_job(State(st): State<St>, ctx: Ctx, Path(id): Path<i64>) -> ApiResult<Json<Value>> {
    ctx.require(OPS)?;
    {
        let c = st.cat.conn();
        let state: String = c
            .query_row(
                "SELECT state FROM jobs WHERE id = ?1 AND (?2 IS NULL OR tenant = ?2)",
                params![id, ctx.scope()],
                |r| r.get(0),
            )
            .optional()?
            .ok_or_else(ApiError::not_found)?;
        let n = c.execute(
            "UPDATE jobs SET state = 'cancelled', finished = ?2 WHERE id = ?1 AND state = 'queued'",
            params![id, catalog::now()],
        )?;
        if n == 0 {
            return Err(ApiError::conflict(format!(
                "job is {state}, only queued jobs can be cancelled"
            )));
        }
    }
    st.audit(ctx.name(), "job.cancel", &format!("job/{id}"), json!({}))?;
    Ok(Json(json!({"id": id, "state": "cancelled"})))
}

/// Streams `<downloads>/<token>.<format>` to the user who requested the
/// `files_get` job (everyone else gets 404). Files older than 24 h are gone
/// (the scheduler deletes them; we refuse to serve them meanwhile).
pub async fn download(State(st): State<St>, ctx: Ctx, Path(token): Path<String>) -> ApiResult<Response> {
    if token.len() != 64 || !token.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return Err(ApiError::not_found());
    }
    let job = st
        .cat
        .conn()
        .query_row(
            "SELECT id, requested_by, json_extract(params, '$.format') FROM jobs
             WHERE kind = 'files_get' AND json_extract(params, '$.download_token') = ?1",
            [&token],
            |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?)),
        )
        .optional()?;
    let Some((job_id, by, format)) = job.filter(|(_, by, _)| by == ctx.name()) else {
        return Err(ApiError::not_found());
    };
    let ext = if format == "zip" { "zip" } else { "tar" };
    let path = st.downloads.join(format!("{token}.{ext}"));
    let file = tokio::fs::File::open(&path).await.map_err(|_| ApiError::not_found())?;
    let meta = file.metadata().await.map_err(|_| ApiError::not_found())?;
    let age = meta
        .modified()
        .ok()
        .and_then(|m| m.elapsed().ok())
        .map_or(i64::MAX, |d| d.as_secs() as i64);
    if !meta.is_file() || age > DOWNLOAD_TTL_SECS {
        return Err(ApiError::not_found());
    }
    st.audit(
        &by,
        "download.get",
        &format!("job/{job_id}"),
        json!({"bytes": meta.len()}),
    )?;
    let mut res = Body::from_stream(tokio_util::io::ReaderStream::new(file)).into_response();
    let h = res.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(if ext == "zip" {
            "application/zip"
        } else {
            "application/x-tar"
        }),
    );
    h.insert(header::CONTENT_LENGTH, HeaderValue::from(meta.len()));
    h.insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_str(&format!("attachment; filename=\"restore-{job_id}.{ext}\"")).unwrap(),
    );
    Ok(res)
}

// ---------------------------------------------------------------- snapshots

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapFilter {
    tenant: Option<String>,
    source: Option<String>,
}

pub async fn list_snapshots(State(st): State<St>, ctx: Ctx, Q(f): Q<SnapFilter>) -> ApiResult<Json<Value>> {
    let c = st.cat.conn();
    let rows = c
        .prepare(
            "SELECT tenant, source, time, size, local, offsite, lock_until, verified, origin FROM snapshots
             WHERE (?1 IS NULL OR tenant = ?1) AND (?2 IS NULL OR source = ?2) AND (?3 IS NULL OR tenant = ?3)
             ORDER BY tenant, source, time DESC",
        )?
        .query_map(params![f.tenant, f.source, ctx.scope()], |r| {
            Ok(json!({
                "tenant": r.get::<_, String>(0)?, "source": r.get::<_, String>(1)?, "time": r.get::<_, i64>(2)?,
                "size": r.get::<_, i64>(3)?, "local": r.get::<_, bool>(4)?, "offsite": r.get::<_, bool>(5)?,
                "lock_until": r.get::<_, i64>(6)?, "verified": r.get::<_, Option<i64>>(7)?,
                "origin": r.get::<_, Option<String>>(8)?,
            }))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Json(Value::Array(rows)))
}

// ---------------------------------------------------------------- alerts

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AlertFilter {
    acked: Option<bool>,
}

/// Alerts are appliance-wide (no tenant column) and may name other tenants,
/// so tenant-scoped users get an empty list.
pub async fn list_alerts(State(st): State<St>, ctx: Ctx, Q(f): Q<AlertFilter>) -> ApiResult<Json<Value>> {
    if ctx.scope().is_some() {
        return Ok(Json(json!([])));
    }
    let c = st.cat.conn();
    let rows = c
        .prepare(
            "SELECT id, ts, severity, kind, message, acked_by FROM alerts
             WHERE ?1 IS NULL OR (acked_by IS NOT NULL) = ?1 ORDER BY id DESC LIMIT 1000",
        )?
        .query_map([f.acked], |r| {
            Ok(json!({
                "id": r.get::<_, i64>(0)?, "ts": r.get::<_, i64>(1)?, "severity": r.get::<_, String>(2)?,
                "kind": r.get::<_, String>(3)?, "message": r.get::<_, String>(4)?,
                "acked_by": r.get::<_, Option<String>>(5)?,
            }))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Json(Value::Array(rows)))
}

pub async fn ack_alert(State(st): State<St>, ctx: Ctx, Path(id): Path<i64>) -> ApiResult<Json<Value>> {
    ctx.require(&["admin", "security_officer", "operator"])?;
    if ctx.scope().is_some() {
        return Err(ApiError::forbidden());
    }
    {
        let c = st.cat.conn();
        let n = c.execute(
            "UPDATE alerts SET acked_by = ?2 WHERE id = ?1 AND acked_by IS NULL",
            params![id, ctx.name()],
        )?;
        if n == 0 {
            let found = c
                .query_row("SELECT 1 FROM alerts WHERE id = ?1", [id], |_| Ok(()))
                .optional()?;
            return Err(if found.is_some() {
                ApiError::conflict("already acknowledged")
            } else {
                ApiError::not_found()
            });
        }
    }
    st.audit(ctx.name(), "alert.ack", &format!("alert/{id}"), json!({}))?;
    Ok(Json(json!({"id": id, "acked_by": ctx.name()})))
}
