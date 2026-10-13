//! Agent updates pushed from the appliance (Phase 27, docs/agent-update-plan.md
//! "Implementation"): the release store (list, signed upload, delete, installer
//! downloads), agent tags, rollouts (create, pause / resume / cancel; a rollback
//! needs approval: quorum action `agent.rollback`) and the automatic mode per tenant /
//! group. The scheduler runs the rollouts (crates/scheduler/src/agent_updates.rs).

use crate::auth::{Ctx, TENANT_WRITERS};
use crate::{ApiError, ApiResult, St, J};
use agent_core::releases::{self, Release};
use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use catalog::agent_updates::{self as au, Setting, Spec};
use catalog::rusqlite::{params, OptionalExtension};
use serde::Deserialize;
use serde_json::{json, Value};
use std::path::PathBuf;

/// Largest release upload (tar).
pub const MAX_UPLOAD: u64 = 512 << 20;
/// Installer download tokens are valid this long.
pub const DOWNLOAD_TTL_SECS: i64 = 3600;
/// Readers of rollouts and settings (appliance-wide roles).
pub const READERS: &[&str] = &["admin", "security_officer", "operator", "viewer"];

/// Where the release store lives (env overrides for tests and the lab).
#[derive(Clone, Debug)]
pub struct ReleasePaths {
    pub image: PathBuf,
    pub upload: PathBuf,
    pub keys: PathBuf,
}

impl Default for ReleasePaths {
    fn default() -> Self {
        let p = |k: &str, d: &str| PathBuf::from(std::env::var_os(k).unwrap_or_else(|| d.into()));
        ReleasePaths {
            image: p("NEXUS_AGENT_RELEASES_IMAGE", releases::IMAGE_DIR),
            upload: p("NEXUS_AGENT_RELEASES_UPLOAD", releases::UPLOAD_DIR),
            keys: p("NEXUS_AGENT_RELEASE_KEYS", releases::KEYS_DIR),
        }
    }
}

impl ReleasePaths {
    pub fn keys(&self) -> Vec<(String, Vec<u8>)> {
        agent_core::update::load_keys(&self.keys)
    }
    pub fn scan(&self) -> Vec<Release> {
        releases::scan(
            &[(self.image.clone(), "image"), (self.upload.clone(), "upload")],
            &self.keys(),
        )
    }
}

fn paths(st: &St) -> ReleasePaths {
    st.agent_releases.get_or_init(Default::default).clone()
}

/// `GET /agent-releases` (every role: the Add agent dialog offers installers).
pub async fn list_releases(State(st): State<St>, _ctx: Ctx) -> ApiResult<Json<Value>> {
    let rs = tokio::task::spawn_blocking(move || paths(&st).scan())
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;
    Ok(Json(json!({
        "recommended": releases::recommended(&rs).map(|r| r.version.clone()),
        "releases": rs.iter().map(Release::to_json).collect::<Vec<_>>(),
    })))
}

/// `POST /agent-releases`: a release as tar (`manifest.json` + `.sig`, the artifacts
/// with their `.sig`, at the top or below one directory). Verified completely
/// (manifest and every artifact against the pinned release keys) before it becomes
/// visible in the store.
pub async fn upload_release(State(st): State<St>, ctx: Ctx, body: Body) -> ApiResult<Response> {
    ctx.require(&["admin"])?;
    let p = paths(&st);
    std::fs::create_dir_all(&p.upload).map_err(|e| ApiError::internal(format!("{}: {e}", p.upload.display())))?;
    let incoming = p.upload.join(format!(".incoming-{}", &crate::random_hex()[..16]));
    std::fs::create_dir(&incoming).map_err(|e| ApiError::internal(format!("{}: {e}", incoming.display())))?;
    let tar = incoming.join("release.tar");
    let r = receive(body, &tar).await;
    let out = match r {
        Ok(()) => {
            let (p2, inc) = (p.clone(), incoming.clone());
            tokio::task::spawn_blocking(move || install_upload(&p2, &inc))
                .await
                .map_err(|e| ApiError::internal(e.to_string()))?
        }
        Err(e) => Err(e),
    };
    let _ = std::fs::remove_dir_all(&incoming);
    let rel = out?;
    st.audit(
        ctx.name(),
        "agent.release.upload",
        &format!("agent-release/{}", rel.version),
        json!({"key": rel.key, "artifacts": rel.manifest.as_ref().map(|m| m.artifacts.len())}),
    )?;
    Ok((StatusCode::CREATED, Json(json!({"version": rel.version}))).into_response())
}

async fn receive(body: Body, to: &std::path::Path) -> ApiResult<()> {
    use http_body_util::BodyExt;
    use tokio::io::AsyncWriteExt;
    let mut f = tokio::fs::File::create(to)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;
    let mut body = body;
    let mut n = 0u64;
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|e| ApiError::bad(format!("upload: {e}")))?;
        if let Ok(data) = frame.into_data() {
            n += data.len() as u64;
            if n > MAX_UPLOAD {
                return Err(ApiError(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "release larger than 512 MiB".into(),
                ));
            }
            f.write_all(&data)
                .await
                .map_err(|e| ApiError::internal(e.to_string()))?;
        }
    }
    f.flush().await.map_err(|e| ApiError::internal(e.to_string()))?;
    if n == 0 {
        return Err(ApiError::bad("empty upload"));
    }
    Ok(())
}

/// Extracts (regular files and directories with plain names only), verifies and
/// moves the release into the upload store.
fn install_upload(p: &ReleasePaths, incoming: &std::path::Path) -> ApiResult<Release> {
    let bad = |m: String| ApiError::bad(m);
    let x = incoming.join("x");
    std::fs::create_dir(&x).map_err(|e| ApiError::internal(e.to_string()))?;
    let f = std::fs::File::open(incoming.join("release.tar")).map_err(|e| ApiError::internal(e.to_string()))?;
    let mut ar = tar::Archive::new(f);
    let mut count = 0;
    for e in ar.entries().map_err(|e| bad(format!("not a tar archive: {e}")))? {
        let mut e = e.map_err(|e| bad(format!("tar: {e}")))?;
        count += 1;
        if count > 500 {
            return Err(bad("too many files in the release".into()));
        }
        let path = e.path().map_err(|e| bad(format!("tar: {e}")))?.into_owned();
        let name = path
            .to_string_lossy()
            .trim_start_matches("./")
            .trim_end_matches('/')
            .to_owned();
        if name.is_empty() {
            continue;
        }
        if !agent_proto::release::valid_name(&name) {
            return Err(bad(format!("{name}: not a plain relative path")));
        }
        let dst = x.join(&name);
        match e.header().entry_type() {
            tar::EntryType::Directory => {
                std::fs::create_dir_all(&dst).map_err(|e| ApiError::internal(e.to_string()))?
            }
            tar::EntryType::Regular => {
                if let Some(d) = dst.parent() {
                    std::fs::create_dir_all(d).map_err(|e| ApiError::internal(e.to_string()))?;
                }
                let mut out = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&dst)
                    .map_err(|e| bad(format!("{name}: {e}")))?;
                std::io::copy(&mut e, &mut out).map_err(|e| bad(format!("{name}: {e}")))?;
            }
            _ => return Err(bad(format!("{name}: only regular files and directories"))),
        }
    }
    // manifest at the top, or below exactly one directory
    let root = if x.join("manifest.json").is_file() {
        x.clone()
    } else {
        let dirs: Vec<PathBuf> = std::fs::read_dir(&x)
            .map_err(|e| ApiError::internal(e.to_string()))?
            .filter_map(|e| e.ok().map(|e| e.path()))
            .collect();
        match dirs.as_slice() {
            [d] if d.join("manifest.json").is_file() => d.clone(),
            _ => return Err(bad("manifest.json not found in the archive".into())),
        }
    };
    let m = agent_proto::release::Manifest::parse(
        &std::fs::read(root.join("manifest.json")).map_err(|e| ApiError::internal(e.to_string()))?,
    )
    .map_err(bad)?;
    let staged = incoming.join(&m.version);
    std::fs::rename(&root, &staged).map_err(|e| ApiError::internal(e.to_string()))?;
    let rel = releases::load(&staged, "upload", &p.keys(), true);
    if let Some(e) = &rel.error {
        return Err(bad(format!("release {} refused: {e}", m.version)));
    }
    if p.image.join(&m.version).exists() || p.upload.join(&m.version).exists() {
        return Err(ApiError::conflict(format!(
            "release {} is already in the store",
            m.version
        )));
    }
    // the web-api runs with umask 0077: the scheduler and nexus-agentctl read through
    // the group of the (setgid) store directory
    group_readable(&staged).map_err(|e| ApiError::internal(e.to_string()))?;
    let dst = p.upload.join(&m.version);
    std::fs::rename(&staged, &dst).map_err(|e| ApiError::internal(e.to_string()))?;
    Ok(Release { dir: dst, ..rel })
}

/// Directories 0750, files 0640 below `dir` (and `dir` itself).
fn group_readable(dir: &std::path::Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o750))?;
    for e in std::fs::read_dir(dir)? {
        let e = e?;
        let t = e.file_type()?;
        if t.is_dir() {
            group_readable(&e.path())?;
        } else if t.is_file() {
            std::fs::set_permissions(e.path(), std::fs::Permissions::from_mode(0o640))?;
        }
    }
    Ok(())
}

/// `DELETE /agent-releases/{version}`: uploaded releases only, not while a rollout
/// still needs it.
pub async fn delete_release(State(st): State<St>, ctx: Ctx, Path(version): Path<String>) -> ApiResult<Json<Value>> {
    ctx.require(&["admin"])?;
    if au::agent_version(&version).is_none() {
        return Err(ApiError::not_found());
    }
    let p = paths(&st);
    let dir = p.upload.join(&version);
    if !dir.is_dir() {
        return Err(if p.image.join(&version).is_dir() {
            ApiError::conflict("releases from the appliance image cannot be deleted")
        } else {
            ApiError::not_found()
        });
    }
    let busy: i64 = st.cat.conn().query_row(
        "SELECT COUNT(*) FROM agent_rollouts WHERE version = ?1 AND state IN ('pending_approval','running','paused')",
        [&version],
        |r| r.get(0),
    )?;
    if busy > 0 {
        return Err(ApiError::conflict("a rollout of this release is still active"));
    }
    std::fs::remove_dir_all(&dir).map_err(|e| ApiError::internal(e.to_string()))?;
    st.audit(
        ctx.name(),
        "agent.release.delete",
        &format!("agent-release/{version}"),
        json!({}),
    )?;
    Ok(Json(json!({"version": version, "deleted": true})))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DownloadReq {
    artifact: String,
}

/// `POST /agent-releases/{version}/download`: a one-hour token for `GET
/// /downloads/{token}` (installer downloads in the Add agent dialog).
pub async fn download_token(
    State(st): State<St>,
    ctx: Ctx,
    Path(version): Path<String>,
    J(r): J<DownloadReq>,
) -> ApiResult<Json<Value>> {
    ctx.require(TENANT_WRITERS)?;
    if !ctx.user.can_download {
        return Err(ApiError::forbidden());
    }
    let p = paths(&st);
    let rs = tokio::task::spawn_blocking(move || p.scan())
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;
    let rel = releases::find(&rs, &version)
        .filter(|r| r.usable())
        .ok_or_else(ApiError::not_found)?;
    let a = rel
        .manifest
        .as_ref()
        .and_then(|m| m.artifact(&r.artifact))
        .ok_or_else(|| ApiError::bad("artifact: not part of this release"))?
        .clone();
    let token = crate::random_hex();
    let expires = catalog::now() + DOWNLOAD_TTL_SECS;
    {
        let c = st.cat.conn();
        c.execute("DELETE FROM agent_downloads WHERE expires < ?1", [catalog::now()])?;
        c.execute(
            "INSERT INTO agent_downloads (token, version, artifact, requested_by, created, expires) VALUES (?1,?2,?3,?4,?5,?6)",
            params![token, version, a.name, ctx.name(), catalog::now(), expires],
        )?;
    }
    Ok(Json(json!({
        "token": token, "url": format!("/api/v1/downloads/{token}"),
        "name": a.name.rsplit('/').next().unwrap_or(&a.name), "size": a.size, "sha256": a.sha256, "expires": expires,
    })))
}

/// An installer download token of `user`: (file, file name).
pub fn installer_file(st: &St, token: &str, user: &str) -> ApiResult<Option<(PathBuf, String)>> {
    let row: Option<(String, String, String, i64)> = st
        .cat
        .conn()
        .query_row(
            "SELECT version, artifact, requested_by, expires FROM agent_downloads WHERE token = ?1",
            [token],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .optional()?;
    let Some((version, artifact, by, expires)) = row else {
        return Ok(None);
    };
    if by != user || expires < catalog::now() {
        return Err(ApiError::not_found());
    }
    let rs = paths(st).scan();
    let rel = releases::find(&rs, &version)
        .filter(|r| r.usable())
        .ok_or_else(ApiError::not_found)?;
    let a = rel
        .manifest
        .as_ref()
        .and_then(|m| m.artifact(&artifact))
        .ok_or_else(ApiError::not_found)?;
    let name = a.name.rsplit('/').next().unwrap_or(&a.name).to_owned();
    Ok(Some((rel.path_of(a), name)))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TagsReq {
    tags: Vec<String>,
}

/// `PUT /agents/{id}/tags` (rollout scope).
pub async fn set_tags(
    State(st): State<St>,
    ctx: Ctx,
    Path(id): Path<String>,
    J(r): J<TagsReq>,
) -> ApiResult<Json<Value>> {
    ctx.require(TENANT_WRITERS)?;
    if r.tags.len() > 16 || r.tags.iter().any(|t| !au::valid_tag(t)) {
        return Err(ApiError::bad("tags: at most 16, each [a-z0-9_.-]{1,32}"));
    }
    let mut tags = r.tags.clone();
    tags.sort();
    tags.dedup();
    let tenant: String = st
        .cat
        .conn()
        .query_row("SELECT tenant FROM agents WHERE id = ?1", [&id], |r| r.get(0))
        .optional()?
        .ok_or_else(ApiError::not_found)?;
    ctx.owns(&tenant)?;
    st.cat.conn().execute(
        "UPDATE agents SET tags = ?2 WHERE id = ?1",
        params![id, serde_json::to_string(&tags).unwrap_or_default()],
    )?;
    st.audit(ctx.name(), "agent.tags", &format!("agent/{id}"), json!({"tags": tags}))?;
    Ok(Json(json!({"id": id, "tags": tags})))
}

/// `GET /agent-rollouts`
pub async fn list_rollouts(State(st): State<St>, ctx: Ctx) -> ApiResult<Json<Value>> {
    ctx.require(READERS)?;
    let v = au::list(&st.cat.conn()).map_err(|e| ApiError::internal(e.to_string()))?;
    Ok(Json(Value::Array(v)))
}

/// `GET /agent-rollouts/{id}` with its items.
pub async fn get_rollout(State(st): State<St>, ctx: Ctx, Path(id): Path<i64>) -> ApiResult<Json<Value>> {
    ctx.require(READERS)?;
    let v = au::get(&st.cat.conn(), id, true).map_err(|e| ApiError::internal(e.to_string()))?;
    v.map(Json).ok_or_else(ApiError::not_found)
}

/// `POST /agent-rollouts`: 201 with the rollout; a rollback waits for approval
/// (`agent.rollback`): 202 `{quorum_id, id}` (or 200 when approvals are off).
pub async fn create_rollout(State(st): State<St>, ctx: Ctx, J(spec): J<Spec>) -> ApiResult<Response> {
    ctx.require(&["admin"])?;
    spec.check().map_err(|e| ApiError::bad(e.to_string()))?;
    let p = paths(&st);
    let version = spec.version.clone();
    let rs = tokio::task::spawn_blocking(move || p.scan())
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;
    if !releases::find(&rs, &version).is_some_and(Release::usable) {
        return Err(ApiError::bad(format!(
            "version: release {version} is not in the store or not signed by a pinned key"
        )));
    }
    if spec.rollback && releases::recommended(&rs).is_some_and(|r| !releases::older(&version, &r.version)) {
        return Err(ApiError::bad(
            "rollback: the target must be older than the newest release",
        ));
    }
    let state = if spec.rollback { "pending_approval" } else { "running" };
    let id = {
        let mut c = st.cat.conn();
        let tx = c.transaction()?;
        let id = au::create(&tx, &spec, ctx.name(), None, false, state, catalog::now())
            .map_err(|e| ApiError::bad(e.to_string()))?;
        tx.commit()?;
        id
    };
    st.audit(
        ctx.name(),
        "agent.rollout.create",
        &format!("agent-rollout/{id}"),
        json!({"spec": spec}),
    )?;
    if spec.rollback {
        let o = crate::quorum::request(
            &st,
            &ctx,
            au::ROLLBACK_ACTION,
            &format!("agent-rollout/{id}"),
            json!({"rollout_id": id, "version": spec.version, "scope": spec.scope}),
        )?;
        if let crate::quorum::Outcome::Pending(q) = &o {
            st.cat
                .conn()
                .execute("UPDATE agent_rollouts SET quorum_id = ?2 WHERE id = ?1", params![id, q])?;
        }
        return Ok(crate::quorum::accepted(o, json!({"id": id})));
    }
    let v = au::get(&st.cat.conn(), id, false).map_err(|e| ApiError::internal(e.to_string()))?;
    Ok((StatusCode::CREATED, Json(v.unwrap_or_default())).into_response())
}

/// Quorum execution of `agent.rollback`: the approved rollout starts.
pub fn execute_rollback(c: &catalog::rusqlite::Connection, p: &Value) -> ApiResult<()> {
    let id = p["rollout_id"]
        .as_i64()
        .ok_or_else(|| ApiError::bad("quorum params: rollout_id"))?;
    let n = c.execute(
        "UPDATE agent_rollouts SET state = 'running' WHERE id = ?1 AND state = 'pending_approval'",
        [id],
    )?;
    if n != 1 {
        return Err(ApiError::conflict("the rollout is no longer waiting for approval"));
    }
    Ok(())
}

/// `POST /agent-rollouts/{id}/{pause|resume|cancel}`
pub async fn rollout_action(
    State(st): State<St>,
    ctx: Ctx,
    Path((id, action)): Path<(i64, String)>,
) -> ApiResult<Json<Value>> {
    ctx.require(&["admin"])?;
    let (from, to): (&[&str], &str) = match action.as_str() {
        "pause" => (&["running"], "paused"),
        "resume" => (&["paused"], "running"),
        "cancel" => (&["running", "paused", "pending_approval"], "cancelled"),
        _ => return Err(ApiError::not_found()),
    };
    {
        let mut c = st.cat.conn();
        let tx = c.transaction()?;
        let state: String = tx
            .query_row("SELECT state FROM agent_rollouts WHERE id = ?1", [id], |r| r.get(0))
            .optional()?
            .ok_or_else(ApiError::not_found)?;
        if !from.contains(&state.as_str()) {
            return Err(ApiError::conflict(format!("the rollout is {state}")));
        }
        let now = catalog::now();
        tx.execute(
            "UPDATE agent_rollouts SET state = ?2, reason = CASE WHEN ?2 = 'running' THEN NULL ELSE ?3 END, \
             finished = CASE WHEN ?2 = 'cancelled' THEN ?4 ELSE finished END WHERE id = ?1",
            params![id, to, format!("{action} by {}", ctx.name()), now],
        )?;
        if to == "cancelled" {
            tx.execute(
                "UPDATE agent_rollout_items SET state = 'cancelled', updated = ?2 WHERE rollout_id = ?1 AND state = 'waiting'",
                params![id, now],
            )?;
        }
        tx.commit()?;
    }
    st.audit(
        ctx.name(),
        &format!("agent.rollout.{action}"),
        &format!("agent-rollout/{id}"),
        json!({}),
    )?;
    let v = au::get(&st.cat.conn(), id, false).map_err(|e| ApiError::internal(e.to_string()))?;
    Ok(Json(v.unwrap_or_default()))
}

/// `GET /agent-update-settings`
pub async fn list_settings(State(st): State<St>, ctx: Ctx) -> ApiResult<Json<Value>> {
    ctx.require(READERS)?;
    let v = au::settings(&st.cat.conn()).map_err(|e| ApiError::internal(e.to_string()))?;
    Ok(Json(Value::Array(v)))
}

/// `PUT /agent-update-settings` (automatic mode per tenant / group).
pub async fn put_settings(State(st): State<St>, ctx: Ctx, J(s): J<Setting>) -> ApiResult<Json<Value>> {
    ctx.require(&["admin"])?;
    s.check().map_err(|e| ApiError::bad(e.to_string()))?;
    {
        let c = st.cat.conn();
        c.query_row("SELECT 1 FROM tenants WHERE name = ?1", [&s.tenant], |_| Ok(()))
            .optional()?
            .ok_or_else(|| ApiError::bad("tenant: does not exist"))?;
        if let Some(g) = s.group_id {
            let t: Option<String> = c
                .query_row("SELECT tenant FROM groups WHERE id = ?1", [g], |r| r.get(0))
                .optional()?;
            if t.as_deref() != Some(s.tenant.as_str()) {
                return Err(ApiError::bad("group_id: no such group in this tenant"));
            }
        }
        au::put_setting(&c, &s, ctx.name(), catalog::now()).map_err(|e| ApiError::bad(e.to_string()))?;
    }
    st.audit(
        ctx.name(),
        "agent.update_settings",
        &format!("tenant/{}", s.tenant),
        json!({"setting": s}),
    )?;
    Ok(Json(json!(s)))
}

/// Single-agent update job (`agent_update {agent_id, version?}`): the version must be
/// a usable release newer than what the agent runs (rollbacks only as a rollout).
/// Without a version and without any signed release in the store: `None`, the
/// scheduler then uses the single-binary update directory of earlier releases.
pub fn check_update_version(st: &St, agent_id: &str, version: Option<&str>) -> ApiResult<Option<String>> {
    let rs = paths(st).scan();
    let target = match version {
        Some(v) => releases::find(&rs, v)
            .filter(|r| r.usable())
            .ok_or_else(|| ApiError::bad(format!("version: release {v} is not in the store or not signed")))?,
        None => match releases::recommended(&rs) {
            Some(r) => r,
            None => return Ok(None),
        },
    };
    let current: Option<String> = st
        .cat
        .conn()
        .query_row("SELECT version FROM agents WHERE id = ?1", [agent_id], |r| r.get(0))
        .optional()?
        .flatten();
    if let Some(c) = current.filter(|c| au::agent_version(c).is_some()) {
        if !releases::older(&c, &target.version) {
            return Err(ApiError::conflict(format!(
                "the agent runs {c}; {} is not newer (a downgrade needs an approved rollback rollout)",
                target.version
            )));
        }
    }
    Ok(Some(target.version.clone()))
}
