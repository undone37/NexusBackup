//! Job requests, snapshots, downloads (alerts: `alerts.rs`).

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
    "plugin_restore",
    "plugin_mount",
];
/// Kinds only an admin may request (they change software or trust on a host).
const ADMIN_KINDS: &[&str] = &["agent_update", "agent_enroll", "agent_renew"];
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
    /// group_id only: back up these guests of the group (Phase 13b)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    guests: Option<Vec<Value>>,
    /// group_id only: the guests that failed in the group's last run
    #[serde(default, skip_serializing)]
    failed_only: bool,
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
struct PluginSourceP {
    source_id: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    guests: Option<Vec<String>>,
}

/// `inventory`: refresh the guest inventory of one source (crate::inventory).
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct InventoryP {
    source_id: i64,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PluginRestoreP {
    /// `plugin-<plugin>-<source id>[-<guest>]`
    source: String,
    time: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    restore: Option<String>,
    #[serde(default)]
    params: Value,
    /// plugin_mount: 1..=1440
    #[serde(default, skip_serializing_if = "Option::is_none")]
    minutes: Option<u64>,
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
            let mut b: BackupP = parse(p)?;
            if b.group_id.is_none() && (b.guests.is_some() || b.failed_only) {
                return Err(ApiError::bad("params: guests and failed_only need group_id"));
            }
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
                    b.guests = crate::runctl::backup_guests(&st.cat.conn(), g, b.guests.take(), b.failed_only)?;
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
        "agent_update" | "agent_enroll" | "agent_renew" => {
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
        "plugin_validate" | "plugin_guests" | "plugin_backup" => {
            let mut r: PluginSourceP = parse(p)?;
            if kind == "plugin_backup" {
                crate::replication::refuse_replicated(&st.cat.conn(), tenant)?;
            }
            let c = st.cat.conn();
            let (_, spec) = crate::plugins::source_of(&c, tenant, r.source_id)?;
            if kind != "plugin_backup" {
                r.guests = None;
            } else if let Some(g) = &r.guests {
                let mut v: Vec<Value> = g.iter().map(|x| json!(x)).collect();
                let k = format!("plugin:{}", spec.kind);
                crate::plugins::check_guests(&c, &k, &mut v)?;
                r.guests = Some(v.iter().filter_map(|x| x.as_str().map(str::to_owned)).collect());
            }
            json!(r)
        }
        "plugin_restore" | "plugin_mount" => {
            let mut r: PluginRestoreP = parse(p)?;
            snapshot_exists(st, tenant, &r.source, r.time)?;
            let (pid, sid, guest) = plugin_proto::parse_source_name(&r.source)
                .ok_or_else(|| ApiError::bad("source: a plugin-<plugin>-<source-id> snapshot"))?;
            let (cur, spec) = crate::plugins::source_of(&st.cat.conn(), tenant, sid as i64)?;
            if cur.id != pid {
                return Err(ApiError::bad("source: the snapshot belongs to another plugin"));
            }
            let want = if kind == "plugin_mount" {
                r.minutes = Some(r.minutes.unwrap_or(60));
                if !(1..=1440).contains(&r.minutes.unwrap()) {
                    return Err(ApiError::bad("minutes: 1..=1440"));
                }
                r.restore = None;
                "mount".to_owned()
            } else {
                r.minutes = None;
                r.restore.clone().ok_or_else(|| ApiError::bad("restore: required"))?
            };
            if want == "download" {
                return Err(ApiError::bad("restore: download runs as files_get"));
            }
            let action = spec
                .restores
                .iter()
                .find(|x| x.id == want)
                .ok_or_else(|| ApiError::bad(format!("restore: {want} is not offered by this plugin")))?;
            if !action.applies(guest.is_some()) {
                return Err(ApiError::bad(format!(
                    "restore: {want} applies to {} snapshots only",
                    action.applies_to.as_deref().unwrap_or("any")
                )));
            }
            if r.params.is_null() {
                r.params = json!({});
            }
            match &action.params_schema {
                Some(schema) => crate::plugins::check_schema(schema, &r.params, "params", &[])?,
                None if r.params.as_object().is_some_and(|o| o.is_empty()) => {}
                None => return Err(ApiError::bad("params: this restore takes no parameters")),
            }
            json!(r)
        }
        "inventory" => {
            let r: InventoryP = parse(p)?;
            let c = st.cat.conn();
            let kind: String = c
                .query_row(
                    "SELECT kind FROM sources WHERE id = ?1 AND tenant = ?2",
                    params![r.source_id, tenant],
                    |r| r.get(0),
                )
                .optional()?
                .ok_or_else(|| ApiError::bad("source_id: no such source in this tenant"))?;
            if !crate::inventory::has_inventory(&c, &kind) {
                return Err(ApiError::bad("source_id: this source has no guest inventory"));
            }
            json!(r)
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

/// 202 `{id}` (+ `download_token` for `files_get`, which also needs the
/// account's download privilege). Viewers and security officers request no jobs.
pub async fn create_job(State(st): State<St>, ctx: Ctx, J(r): J<JobReq>) -> ApiResult<Response> {
    let allowed = match ctx.user.role.as_str() {
        "admin" => true,
        "operator" => !ADMIN_KINDS.contains(&r.kind.as_str()),
        "tenant_user" => RESTORE_KINDS.contains(&r.kind.as_str()),
        "viewer" | "security_officer" => false,
        _ => false,
    };
    if !allowed || (r.kind == "files_get" && !ctx.user.can_download) {
        return Err(ApiError::forbidden());
    }
    if ctx.token.is_some() && crate::tokens::DENIED_KINDS.contains(&r.kind.as_str()) {
        return Err(ApiError(
            StatusCode::FORBIDDEN,
            "API tokens cannot start downloads or mounts".into(),
        ));
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
        "attempt": r.get::<_, i64>(11)?, "retry_of": r.get::<_, Option<i64>>(12)?,
        "not_before": r.get::<_, Option<i64>>(13)?, "cancel_by": r.get::<_, Option<String>>(14)?,
    });
    if with_log {
        v["log"] = json!(r.get::<_, String>(9)?);
    }
    Ok(v)
}

const JOB_COLS: &str = "id, kind, tenant, params, state, requested_by, created, started, finished, log, result, \
                        attempt, retry_of, not_before, cancel_by";

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

/// Queued jobs are cancelled here; running jobs get a cancel request
/// (`jobs.cancel_by`) that the scheduler carries out (Phase 13b: SIGTERM, then
/// SIGKILL after 30 s; the job ends `cancelled`). Answers the state after the
/// request: `cancelled` or `cancelling`.
pub async fn cancel_job(State(st): State<St>, ctx: Ctx, Path(id): Path<i64>) -> ApiResult<Json<Value>> {
    ctx.require(OPS)?;
    let state = {
        let c = st.cat.conn();
        let state: String = c
            .query_row(
                "SELECT state FROM jobs WHERE id = ?1 AND (?2 IS NULL OR tenant = ?2)",
                params![id, ctx.scope()],
                |r| r.get(0),
            )
            .optional()?
            .ok_or_else(ApiError::not_found)?;
        let queued = c.execute(
            "UPDATE jobs SET state = 'cancelled', finished = ?2 WHERE id = ?1 AND state = 'queued'",
            params![id, catalog::now()],
        )?;
        let running = c.execute(
            "UPDATE jobs SET cancel_by = ?2 WHERE id = ?1 AND state = 'running' AND cancel_by IS NULL",
            params![id, ctx.name()],
        )?;
        match (queued, running) {
            (1, _) => "cancelled",
            (_, 1) => "cancelling",
            _ if state == "running" => return Err(ApiError::conflict("cancellation already requested")),
            _ => {
                return Err(ApiError::conflict(format!(
                    "job is {state}, only queued or running jobs can be cancelled"
                )))
            }
        }
    };
    st.audit(
        ctx.name(),
        "job.cancel",
        &format!("job/{id}"),
        json!({"running": state == "cancelling"}),
    )?;
    Ok(Json(json!({"id": id, "state": state})))
}

/// Streams `<downloads>/<token>.<format>` to the user who requested the
/// `files_get` job (everyone else gets 404). Files older than 24 h are gone
/// (the scheduler deletes them; we refuse to serve them meanwhile).
pub async fn download(State(st): State<St>, ctx: Ctx, Path(token): Path<String>) -> ApiResult<Response> {
    if !ctx.user.can_download {
        return Err(ApiError::forbidden());
    }
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

/// Deletes one local snapshot (admin, approval action `snapshot.delete`, executed
/// by the scheduler). Refused at once while it is locked, when only the offsite
/// copy is left (offsite retention) and for replicated snapshots (the
/// replication source's retention; a deleted one would be fetched again).
pub async fn delete_snapshot(
    State(st): State<St>,
    ctx: Ctx,
    Path((tenant, source, time)): Path<(String, String, i64)>,
) -> ApiResult<Response> {
    ctx.require(&["admin"])?;
    validate::name(&tenant, "tenant")?;
    validate::source_ref(&source)?;
    if !ctx.sees(&tenant) {
        return Err(ApiError::forbidden());
    }
    let row: Option<(bool, i64, Option<String>)> = st
        .cat
        .conn()
        .query_row(
            "SELECT local, lock_until, origin FROM snapshots WHERE tenant = ?1 AND source = ?2 AND time = ?3",
            params![tenant, source, time],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()?;
    let (local, lock_until, origin) = row.ok_or_else(|| ApiError(StatusCode::NOT_FOUND, "no such snapshot".into()))?;
    if !local {
        return Err(ApiError::conflict(
            "only the offsite copy is left: it follows the offsite retention",
        ));
    }
    if origin.is_some() {
        return Err(ApiError::conflict(
            "replicated snapshot: it follows the replication source's retention",
        ));
    }
    if lock_until > catalog::now() {
        return Err(ApiError::conflict(format!(
            "snapshot is locked until {lock_until} (unix time)"
        )));
    }
    let o = crate::quorum::request(
        &st,
        &ctx,
        "snapshot.delete",
        &format!("snapshot/{tenant}/{source}/{time}"),
        json!({"tenant": tenant, "source": source, "time": time}),
    )?;
    Ok(crate::quorum::accepted(o, json!({})))
}
