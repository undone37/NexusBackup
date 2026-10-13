//! Bare-metal recovery and P2V of Linux agent hosts (docs/bmr.md).
//!
//! - `POST /agents/{id}/rescue` issues a one-time recovery token (128 bit, shown
//!   once, 4 h) for a rescue session; the catalog keeps the token's public lookup
//!   key and its digest sealed to the scheduler.
//! - `POST /rescue/checkin` (no login: the rescue console) records where the
//!   rescue agent listens and which disks it has. It is a hint only: the scheduler
//!   enrolls the address with the token proofs, which a forged check-in cannot pass.
//! - `POST /rescue/{id}/start` picks the snapshot and queues the `bmr` job.
//! - `POST /agents/{id}/p2v` creates a session with the snapshot preselected and
//!   queues a `p2v` job: a PVE VM with matching disks boots the rescue ISO plus a
//!   config disk with the token; its check-in starts the `bmr` job unattended.
//!
//! Roles: admin and operator (tenant-scoped users see their tenant only). Every
//! change is audited. Destructive only for the target machine, whose disks the
//! console operator confirms by typing their names (P2V: the new, empty VM).

use crate::agents::{agent_value, new_token};
use crate::auth::{ClientIp, Ctx};
use crate::{validate, ApiError, ApiResult, St, J};
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use catalog::rusqlite::{params, Connection, OptionalExtension};
use catalog::secret::{rescue_p2v_token_location, rescue_token_location};
use serde::Deserialize;
use serde_json::{json, Value};

const ROLES: &[&str] = &["admin", "operator"];
pub const TOKEN_TTL_SECS: i64 = 4 * 3600;

const COLS: &str = "s.id, s.tenant, s.agent_id, a.name, s.token_expires, s.state, s.host, s.port, s.disks, \
                    s.checked_in, s.snapshot_time, s.reboot, s.step, s.job_id, s.p2v, s.message, s.created, s.created_by, \
                    s.token_hash IS NOT NULL";

fn row(r: &catalog::rusqlite::Row) -> catalog::rusqlite::Result<Value> {
    let p2v = r
        .get::<_, Option<String>>(14)?
        .and_then(|t| serde_json::from_str::<Value>(&t).ok())
        .map(|mut v| {
            // the sealed token stays in the catalog
            if let Some(o) = v.as_object_mut() {
                o.remove("token");
            }
            v
        });
    Ok(json!({
        "id": r.get::<_, String>(0)?, "tenant": r.get::<_, String>(1)?, "agent_id": r.get::<_, String>(2)?,
        "agent_name": r.get::<_, Option<String>>(3)?, "token_expires": r.get::<_, i64>(4)?,
        "state": r.get::<_, String>(5)?, "host": r.get::<_, Option<String>>(6)?, "port": r.get::<_, Option<i64>>(7)?,
        "disks": serde_json::from_str::<Value>(&r.get::<_, String>(8)?).unwrap_or_default(),
        "checked_in": r.get::<_, Option<i64>>(9)?, "snapshot_time": r.get::<_, Option<i64>>(10)?,
        "reboot": r.get::<_, bool>(11)?, "step": r.get::<_, Option<String>>(12)?, "job_id": r.get::<_, Option<i64>>(13)?,
        "p2v": p2v, "message": r.get::<_, Option<String>>(15)?, "created": r.get::<_, i64>(16)?,
        "created_by": r.get::<_, String>(17)?, "token_valid": r.get::<_, bool>(18)?,
    }))
}

fn session(c: &Connection, id: &str) -> ApiResult<Option<Value>> {
    Ok(c.query_row(
        &format!("SELECT {COLS} FROM rescue_sessions s LEFT JOIN agents a ON a.id = s.agent_id WHERE s.id = ?1"),
        [id],
        row,
    )
    .optional()?)
}

/// Sessions past their token lifetime that never got going.
fn expire(c: &Connection) -> ApiResult<()> {
    c.execute(
        "UPDATE rescue_sessions SET state = 'expired', token_hash = NULL \
         WHERE state IN ('issued','waiting') AND token_expires <= ?1",
        [catalog::now()],
    )?;
    Ok(())
}

pub async fn list(State(st): State<St>, ctx: Ctx) -> ApiResult<Json<Value>> {
    ctx.require(&["admin", "operator", "viewer", "security_officer"])?;
    let c = st.cat.conn();
    expire(&c)?;
    let rows = c
        .prepare(&format!(
            "SELECT {COLS} FROM rescue_sessions s LEFT JOIN agents a ON a.id = s.agent_id \
             WHERE ?1 IS NULL OR s.tenant = ?1 ORDER BY s.created DESC LIMIT 200"
        ))?
        .query_map([ctx.scope()], row)?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Json(Value::Array(rows)))
}

pub async fn get(State(st): State<St>, ctx: Ctx, Path(id): Path<String>) -> ApiResult<Json<Value>> {
    ctx.require(&["admin", "operator", "viewer", "security_officer"])?;
    let c = st.cat.conn();
    expire(&c)?;
    let s = session(&c, &id)?.ok_or_else(ApiError::not_found)?;
    if !ctx.sees(s["tenant"].as_str().unwrap_or_default()) {
        return Err(ApiError::not_found());
    }
    Ok(Json(s))
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields, default)]
pub struct IssueReq {
    /// reboot into the restored system when done (default true)
    reboot: Option<bool>,
}

/// New session + token for the agent; open sessions of the agent are cancelled.
fn issue(
    st: &St,
    ctx: &Ctx,
    agent: &str,
    reboot: bool,
    p2v: Option<Value>,
    time: Option<u64>,
) -> ApiResult<(Value, String)> {
    ctx.require(ROLES)?;
    let a = agent_value(&st.cat.conn(), agent)?.ok_or_else(ApiError::not_found)?;
    let tenant = a["tenant"].as_str().unwrap_or_default().to_owned();
    if !ctx.sees(&tenant) {
        return Err(ApiError::not_found());
    }
    {
        let c = st.cat.conn();
        crate::vault::refuse(&c, "bare-metal recoveries")?;
        crate::tenants::refuse_paused(&c, &tenant, "restore")?;
    }
    let id: String = rand::random::<[u8; 8]>().iter().map(|b| format!("{b:02x}")).collect();
    let token = new_token();
    let pk = st.seal_key()?;
    let sealed = pk.seal(&rescue_token_location(&id, agent), &agent_proto::token_digest(&token))?;
    let p2v = match p2v {
        Some(mut v) => {
            v["token"] = json!(pk.seal(&rescue_p2v_token_location(&id, agent), &token)?);
            Some(v.to_string())
        }
        None => None,
    };
    let expires = catalog::now() + TOKEN_TTL_SECS;
    let out = {
        let c = st.cat.conn();
        c.execute(
            "UPDATE rescue_sessions SET state = 'cancelled', token_hash = NULL \
             WHERE agent_id = ?1 AND state IN ('issued','waiting')",
            [agent],
        )?;
        c.execute(
            "INSERT INTO rescue_sessions (id, tenant, agent_id, lookup, token_hash, token_expires, reboot, \
             snapshot_time, p2v, created, created_by) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
            params![
                id,
                tenant,
                agent,
                agent_proto::rescue_lookup(&token),
                sealed,
                expires,
                reboot,
                time.map(|t| t as i64),
                p2v,
                catalog::now(),
                ctx.name()
            ],
        )?;
        session(&c, &id)?.ok_or_else(ApiError::not_found)?
    };
    Ok((out, token))
}

pub async fn create(
    State(st): State<St>,
    ctx: Ctx,
    Path(agent): Path<String>,
    J(r): J<IssueReq>,
) -> ApiResult<Response> {
    let (s, token) = issue(&st, &ctx, &agent, r.reboot.unwrap_or(true), None, None)?;
    st.audit(
        ctx.name(),
        "rescue.create",
        &format!("rescue/{}", s["id"].as_str().unwrap_or_default()),
        json!({"agent_id": agent, "tenant": s["tenant"], "token_expires": s["token_expires"]}),
    )?;
    let mut body = s;
    body["token"] = json!(token);
    Ok((StatusCode::CREATED, Json(body)).into_response())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckinReq {
    lookup: String,
    host: String,
    port: u16,
    #[serde(default)]
    disks: Vec<CheckinDisk>,
    #[serde(default)]
    version: String,
}

#[derive(Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct CheckinDisk {
    path: String,
    size: u64,
}

/// `POST /rescue/checkin` (rescue console, no login). Unknown lookups count as
/// failures of the client's IP (login rate limiter): 5 in 15 minutes lock it out.
pub async fn checkin(State(st): State<St>, ClientIp(ip): ClientIp, J(r): J<CheckinReq>) -> ApiResult<Json<Value>> {
    let now = catalog::now();
    let key = format!("rescue-ip:{ip}");
    if st.limiter.lock().unwrap().locked(&key, now) {
        return Err(ApiError(
            StatusCode::TOO_MANY_REQUESTS,
            "too many failed check-ins".into(),
        ));
    }
    let lookup_ok = r.lookup.len() == 64 && r.lookup.bytes().all(|b| b.is_ascii_hexdigit());
    validate::host(&r.host)?;
    if r.port == 0 || r.disks.len() > 64 || r.version.len() > 64 {
        return Err(ApiError::bad("invalid check-in"));
    }
    for d in &r.disks {
        let ok = d.path.len() <= 64
            && d.path.starts_with("/dev/")
            && d.path[5..]
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"/_-.:".contains(&b));
        if !ok {
            return Err(ApiError::bad("invalid disk path"));
        }
    }
    let c = st.cat.conn();
    expire(&c)?;
    let found: Option<(String, String, String, Option<String>, Option<i64>, Option<i64>)> = if lookup_ok {
        c.query_row(
            "SELECT id, tenant, agent_id, p2v, snapshot_time, job_id FROM rescue_sessions \
             WHERE lookup = ?1 AND state IN ('issued','waiting') AND token_hash IS NOT NULL",
            [&r.lookup],
            |x| Ok((x.get(0)?, x.get(1)?, x.get(2)?, x.get(3)?, x.get(4)?, x.get(5)?)),
        )
        .optional()?
    } else {
        None
    };
    let Some((id, tenant, agent, p2v, time, job)) = found else {
        drop(c);
        st.limiter.lock().unwrap().fail(&key, now);
        st.audit("rescue", "rescue.checkin_rejected", "rescue/?", json!({"ip": ip}))?;
        return Err(ApiError::not_found());
    };
    let disks = serde_json::to_string(&r.disks).unwrap_or_else(|_| "[]".into());
    c.execute(
        "UPDATE rescue_sessions SET state = 'waiting', host = ?2, port = ?3, disks = ?4, checked_in = ?5 WHERE id = ?1",
        params![id, r.host, r.port, disks, now],
    )?;
    drop(c);
    st.audit(
        "rescue",
        "rescue.checkin",
        &format!("rescue/{id}"),
        json!({"ip": ip, "host": r.host, "port": r.port, "disks": r.disks.len(), "version": r.version}),
    )?;
    // P2V: the snapshot was chosen with the VM; start unattended
    if let (Some(_), Some(t), None) = (p2v, time, job) {
        queue(&st, "rescue", &id, &tenant, &agent, t as u64)?;
    }
    Ok(Json(json!({"session": id, "state": "waiting"})))
}

fn queue(st: &St, actor: &str, id: &str, tenant: &str, agent: &str, time: u64) -> ApiResult<i64> {
    let params = json!({"session": id, "source_agent": agent, "time": time});
    let job = {
        let c = st.cat.conn();
        c.execute(
            "INSERT INTO jobs (kind, tenant, params, state, requested_by, created) VALUES ('bmr', ?1, ?2, 'queued', ?3, ?4)",
            params![tenant, params.to_string(), actor, catalog::now()],
        )?;
        let job = c.last_insert_rowid();
        c.execute(
            "UPDATE rescue_sessions SET state = 'running', snapshot_time = ?2, job_id = ?3, step = NULL, message = NULL \
             WHERE id = ?1",
            params![id, time as i64, job],
        )?;
        job
    };
    st.audit(
        actor,
        "job.create",
        &format!("job/{job}"),
        json!({"kind": "bmr", "tenant": tenant, "params": params}),
    )?;
    Ok(job)
}

fn snapshot_exists(c: &Connection, tenant: &str, agent: &str, time: u64) -> ApiResult<bool> {
    Ok(c.query_row(
        "SELECT 1 FROM snapshots WHERE tenant = ?1 AND source = ?2 AND time = ?3",
        params![tenant, format!("host-{agent}"), time as i64],
        |_| Ok(()),
    )
    .optional()?
    .is_some())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StartReq {
    time: u64,
    #[serde(default)]
    reboot: Option<bool>,
}

pub async fn start(State(st): State<St>, ctx: Ctx, Path(id): Path<String>, J(r): J<StartReq>) -> ApiResult<Response> {
    ctx.require(ROLES)?;
    let s = {
        let c = st.cat.conn();
        expire(&c)?;
        session(&c, &id)?.ok_or_else(ApiError::not_found)?
    };
    let (tenant, agent) = (
        s["tenant"].as_str().unwrap_or_default().to_owned(),
        s["agent_id"].as_str().unwrap_or_default().to_owned(),
    );
    if !ctx.sees(&tenant) {
        return Err(ApiError::not_found());
    }
    if s["state"] != "waiting" {
        return Err(ApiError::conflict(format!(
            "the session is {}: the rescue console must have checked in (state waiting)",
            s["state"].as_str().unwrap_or_default()
        )));
    }
    {
        let c = st.cat.conn();
        if !snapshot_exists(&c, &tenant, &agent, r.time)? {
            return Err(ApiError::bad("time: no such snapshot of this host"));
        }
        if let Some(rb) = r.reboot {
            c.execute("UPDATE rescue_sessions SET reboot = ?2 WHERE id = ?1", params![id, rb])?;
        }
    }
    let job = queue(&st, ctx.name(), &id, &tenant, &agent, r.time)?;
    st.audit(
        ctx.name(),
        "rescue.start",
        &format!("rescue/{id}"),
        json!({"agent_id": agent, "time": r.time, "job": job, "target": s["host"], "disks": s["disks"]}),
    )?;
    Ok((StatusCode::ACCEPTED, Json(json!({"id": job}))).into_response())
}

pub async fn cancel(State(st): State<St>, ctx: Ctx, Path(id): Path<String>) -> ApiResult<Json<Value>> {
    ctx.require(ROLES)?;
    let s = session(&st.cat.conn(), &id)?.ok_or_else(ApiError::not_found)?;
    if !ctx.sees(s["tenant"].as_str().unwrap_or_default()) {
        return Err(ApiError::not_found());
    }
    let n = st.cat.conn().execute(
        "UPDATE rescue_sessions SET state = 'cancelled', token_hash = NULL WHERE id = ?1 AND state IN ('issued','waiting')",
        [&id],
    )?;
    if n == 0 {
        return Err(ApiError::conflict(
            "only sessions that have not started can be cancelled (cancel the running job instead)",
        ));
    }
    st.audit(
        ctx.name(),
        "rescue.cancel",
        &format!("rescue/{id}"),
        json!({"agent_id": s["agent_id"]}),
    )?;
    Ok(Json(session(&st.cat.conn(), &id)?.unwrap_or_default()))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct P2vReq {
    time: u64,
    /// PVE source (tenant's) whose API creates the VM
    source_id: i64,
    node: String,
    /// new VM id (0 / absent = next free)
    #[serde(default)]
    vmid: u32,
    #[serde(default)]
    name: String,
    /// storage for the VM disks
    storage: String,
    /// rescue ISO volume, e.g. `local:iso/nexus-rescue-0.2.0.iso`
    iso: String,
    /// ISO storage the config disk is uploaded to (default: the storage of `iso`)
    #[serde(default)]
    iso_storage: String,
    #[serde(default)]
    bridge: String,
    #[serde(default)]
    memory: u32,
    #[serde(default)]
    cores: u32,
    /// appliance address the rescue system checks in with (default: this request's Host)
    #[serde(default)]
    appliance: String,
    /// optional pin of the appliance's web certificate for the check-in
    #[serde(default)]
    appliance_sha256: String,
}

fn ident(s: &str, what: &str) -> ApiResult<()> {
    let ok = !s.is_empty() && s.len() <= 128 && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b));
    if ok {
        Ok(())
    } else {
        Err(ApiError::bad(format!("{what}: invalid")))
    }
}

pub async fn p2v(
    State(st): State<St>,
    ctx: Ctx,
    headers: HeaderMap,
    Path(agent): Path<String>,
    J(r): J<P2vReq>,
) -> ApiResult<Response> {
    ctx.require(ROLES)?;
    ident(&r.node, "node")?;
    ident(&r.storage, "storage")?;
    let (iso_store, iso_file) = r
        .iso
        .split_once(":iso/")
        .ok_or_else(|| ApiError::bad("iso: expected <storage>:iso/<file>.iso"))?;
    ident(iso_store, "iso")?;
    ident(iso_file, "iso")?;
    let iso_storage = if r.iso_storage.is_empty() {
        iso_store.to_string()
    } else {
        r.iso_storage.clone()
    };
    ident(&iso_storage, "iso_storage")?;
    let bridge = if r.bridge.is_empty() {
        "vmbr0".to_string()
    } else {
        r.bridge.clone()
    };
    ident(&bridge, "bridge")?;
    if !r.name.is_empty() {
        ident(&r.name, "name")?;
    }
    if r.vmid != 0 && !(100..=999_999_999).contains(&r.vmid) {
        return Err(ApiError::bad("vmid: 100..999999999"));
    }
    let memory = if r.memory == 0 { 2048 } else { r.memory };
    let cores = if r.cores == 0 { 2 } else { r.cores };
    if !(512..=1_048_576).contains(&memory) || cores > 256 {
        return Err(ApiError::bad("memory (MiB) or cores out of range"));
    }
    let appliance = if r.appliance.is_empty() {
        headers
            .get("host")
            .and_then(|h| h.to_str().ok())
            .unwrap_or_default()
            .to_string()
    } else {
        r.appliance.clone()
    };
    validate::host(appliance.rsplit_once(':').map_or(appliance.as_str(), |(h, p)| {
        if p.bytes().all(|b| b.is_ascii_digit()) {
            h
        } else {
            appliance.as_str()
        }
    }))
    .map_err(|_| ApiError::bad("appliance: invalid address"))?;
    if !r.appliance_sha256.is_empty()
        && (r.appliance_sha256.len() != 64 || !r.appliance_sha256.bytes().all(|b| b.is_ascii_hexdigit()))
    {
        return Err(ApiError::bad("appliance_sha256: 64 hex characters"));
    }
    let tenant = agent_value(&st.cat.conn(), &agent)?
        .and_then(|a| a["tenant"].as_str().map(str::to_owned))
        .ok_or_else(ApiError::not_found)?;
    {
        let c = st.cat.conn();
        let kind: Option<String> = c
            .query_row(
                "SELECT kind FROM sources WHERE id = ?1 AND tenant = ?2",
                params![r.source_id, tenant],
                |x| x.get(0),
            )
            .optional()?;
        if kind.as_deref() != Some("pve") {
            return Err(ApiError::bad("source_id: not a PVE source of the agent's tenant"));
        }
        if !snapshot_exists(&c, &tenant, &agent, r.time)? {
            return Err(ApiError::bad("time: no such snapshot of this host"));
        }
    }
    let p = json!({
        "source_id": r.source_id, "node": r.node, "vmid": r.vmid, "name": r.name, "storage": r.storage,
        "iso": r.iso, "iso_storage": iso_storage, "bridge": bridge, "memory": memory, "cores": cores,
        "appliance": appliance, "appliance_sha256": r.appliance_sha256,
    });
    let (s, _token) = issue(&st, &ctx, &agent, true, Some(p.clone()), Some(r.time))?;
    let id = s["id"].as_str().unwrap_or_default().to_owned();
    let params = json!({"session": id, "source_agent": agent, "time": r.time});
    let job = {
        let c = st.cat.conn();
        c.execute(
            "INSERT INTO jobs (kind, tenant, params, state, requested_by, created) VALUES ('p2v', ?1, ?2, 'queued', ?3, ?4)",
            params![tenant, params.to_string(), ctx.name(), catalog::now()],
        )?;
        c.last_insert_rowid()
    };
    st.audit(
        ctx.name(),
        "rescue.p2v",
        &format!("rescue/{id}"),
        json!({"agent_id": agent, "time": r.time, "job": job, "vm": p}),
    )?;
    let mut body = s;
    body["p2v_job"] = json!(job);
    Ok((StatusCode::ACCEPTED, Json(body)).into_response())
}
