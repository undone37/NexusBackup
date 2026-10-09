//! Config CRUD: tenants, sources, policies, groups, users (admin only for
//! writes; destructive or weakening changes go through the quorum).

use crate::auth::{reauth, ClientIp, Ctx, User, USER_COLS};
use crate::quorum::{accepted, gate, request};
use crate::validate::{self, Gfs};
use crate::{ApiError, ApiResult, St, J};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use catalog::rusqlite::{params, Connection, OptionalExtension};
use catalog::secret::{source_owner, SealKey};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

const ADMIN: &[&str] = &["admin"];

fn created(v: Value) -> Response {
    (StatusCode::CREATED, Json(v)).into_response()
}

fn exists(c: &Connection, sql: &str, p: impl catalog::rusqlite::Params) -> ApiResult<bool> {
    Ok(c.query_row(sql, p, |_| Ok(())).optional()?.is_some())
}

/// Opaque JSON config blobs: bounded size, and secrets must live in files
/// referenced by path, never inline (they would be readable via GET).
fn opaque(v: &Value, what: &str, max: usize) -> ApiResult<()> {
    fn has_secret(v: &Value) -> bool {
        match v {
            Value::Object(o) => o.iter().any(|(k, v)| {
                let k = k.to_ascii_lowercase();
                ["secret", "password", "passphrase", "private", "key_pem"]
                    .iter()
                    .any(|s| k.contains(s))
                    || has_secret(v)
            }),
            Value::Array(a) => a.iter().any(has_secret),
            // a PEM private key under any other name
            Value::String(s) => s.contains("PRIVATE KEY"),
            _ => false,
        }
    }
    if v.to_string().len() > max {
        return Err(ApiError::bad(format!("{what}: too large")));
    }
    if has_secret(v) {
        return Err(ApiError::bad(format!(
            "{what}: inline secrets are not accepted, reference a file path instead"
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------- tenants

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TenantReq {
    name: String,
    #[serde(default = "empty")]
    offsite: Value,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TenantUpdate {
    offsite: Value,
}

fn empty() -> Value {
    json!({})
}

fn check_offsite(v: &Value) -> ApiResult<()> {
    if !v.is_object() {
        return Err(ApiError::bad("offsite: must be an object"));
    }
    opaque(v, "offsite", 16 << 10)
}

pub async fn list_tenants(State(st): State<St>, ctx: Ctx) -> ApiResult<Json<Value>> {
    let c = st.cat.conn();
    let mut s = c.prepare("SELECT name, offsite FROM tenants WHERE ?1 IS NULL OR name = ?1 ORDER BY name")?;
    let rows = s
        .query_map([ctx.scope()], |r| {
            let o: String = r.get(1)?;
            Ok(json!({"name": r.get::<_, String>(0)?, "offsite": serde_json::from_str::<Value>(&o).unwrap_or_default()}))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Json(Value::Array(rows)))
}

pub async fn create_tenant(State(st): State<St>, ctx: Ctx, J(r): J<TenantReq>) -> ApiResult<Response> {
    ctx.require(ADMIN)?;
    validate::name(&r.name, "name")?;
    check_offsite(&r.offsite)?;
    st.cat.conn().execute(
        "INSERT INTO tenants (name, offsite) VALUES (?1, ?2)",
        params![r.name, r.offsite.to_string()],
    )?;
    st.audit(
        ctx.name(),
        "tenant.create",
        &format!("tenant/{}", r.name),
        json!({"offsite": r.offsite}),
    )?;
    Ok(created(json!({"name": r.name, "offsite": r.offsite})))
}

/// `{name, offsite}` of a tenant as stored (quorum `old` snapshots compare against it).
pub fn tenant_value(c: &Connection, name: &str) -> ApiResult<Option<Value>> {
    Ok(c.query_row("SELECT name, offsite FROM tenants WHERE name = ?1", [name], |r| {
        let o: String = r.get(1)?;
        Ok(json!({"name": r.get::<_, String>(0)?, "offsite": serde_json::from_str::<Value>(&o).unwrap_or_default()}))
    })
    .optional()?)
}

/// Setting up offsite for a tenant applies directly; changing or removing an
/// existing offsite target (another box, no box, other credentials) would
/// silently stop or redirect the offsite copy, so it needs a quorum.
pub async fn update_tenant(
    State(st): State<St>,
    ctx: Ctx,
    Path(name): Path<String>,
    J(r): J<TenantUpdate>,
) -> ApiResult<Response> {
    ctx.require(ADMIN)?;
    check_offsite(&r.offsite)?;
    let old = tenant_value(&st.cat.conn(), &name)?.ok_or_else(ApiError::not_found)?;
    let target = format!("tenant/{name}");
    let had_offsite = old["offsite"].as_object().is_some_and(|o| !o.is_empty());
    if had_offsite && old["offsite"] != r.offsite {
        let p = json!({"name": name, "offsite": r.offsite, "old": old});
        return gate(&st, &ctx, "tenant.update", &target, p);
    }
    let n = st.cat.conn().execute(
        "UPDATE tenants SET offsite = ?2 WHERE name = ?1",
        params![name, r.offsite.to_string()],
    )?;
    if n == 0 {
        return Err(ApiError::not_found());
    }
    st.audit(ctx.name(), "tenant.update", &target, json!({"offsite": r.offsite}))?;
    Ok(Json(json!({"name": name, "offsite": r.offsite})).into_response())
}

/// A tenant can only be deleted once no source, group or user refers to it.
pub fn tenant_deletable(c: &Connection, name: &str) -> ApiResult<()> {
    for t in ["sources", "groups", "users", "agents"] {
        if exists(c, &format!("SELECT 1 FROM {t} WHERE tenant = ?1"), [name])? {
            return Err(ApiError::conflict(format!("tenant still has {t}")));
        }
    }
    Ok(())
}

pub async fn delete_tenant(State(st): State<St>, ctx: Ctx, Path(name): Path<String>) -> ApiResult<Response> {
    ctx.require(ADMIN)?;
    {
        let c = st.cat.conn();
        if !exists(&c, "SELECT 1 FROM tenants WHERE name = ?1", [&name])? {
            return Err(ApiError::not_found());
        }
        tenant_deletable(&c, &name)?;
    }
    gate(
        &st,
        &ctx,
        "tenant.delete",
        &format!("tenant/{name}"),
        json!({"name": name}),
    )
}

// ---------------------------------------------------------------- sources

/// PVE source config. `token_secret` is write-only: required on create,
/// optional on update (omitted = keep), never returned.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PveConfig {
    host: String,
    port: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    connect_addr: Option<String>,
    ca_pem: String,
    token_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    token_secret: Option<String>,
    nodes: Value,
    storage: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    fleecing_storage: Option<String>,
}

impl PveConfig {
    fn check(&self) -> ApiResult<()> {
        validate::host(&self.host)?;
        if self.port == 0 {
            return Err(ApiError::bad("port: must be 1..=65535"));
        }
        if let Some(a) = &self.connect_addr {
            a.parse::<std::net::SocketAddr>()
                .map_err(|_| ApiError::bad("connect_addr: expected ip:port"))?;
        }
        if self.ca_pem.len() > 64 << 10 || !self.ca_pem.contains("-----BEGIN CERTIFICATE-----") {
            return Err(ApiError::bad("ca_pem: expected a PEM certificate (at most 64 KiB)"));
        }
        let tid_ok = self.token_id.len() <= 128
            && self.token_id.contains('@')
            && self.token_id.contains('!')
            && self
                .token_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"@!._-".contains(&b));
        if !tid_ok {
            return Err(ApiError::bad("token_id: expected user@realm!tokenid"));
        }
        if let Some(s) = &self.token_secret {
            if s.is_empty() || s.len() > 256 || !s.bytes().all(|b| b.is_ascii_graphic()) {
                return Err(ApiError::bad("token_secret: 1..=256 printable characters"));
            }
        }
        if !(self.nodes.is_object() || self.nodes.is_array()) {
            return Err(ApiError::bad("nodes: must be an object or array"));
        }
        opaque(&self.nodes, "nodes", 64 << 10)?;
        validate::name(&self.storage, "storage")?;
        if let Some(f) = &self.fleecing_storage {
            validate::name(f, "fleecing_storage")?;
        }
        Ok(())
    }
}

/// The config as stored: secrets sealed to the scheduler (review H-2), bound
/// to the source id and endpoint. Already sealed values (kept on update) stay.
fn sealed_config(pk: &SealKey, id: i64, cfg: &PveConfig) -> ApiResult<String> {
    let mut v = serde_json::to_value(cfg).map_err(anyhow::Error::from)?;
    pk.seal_all(&source_owner(id), &mut v)?;
    Ok(v.to_string())
}

/// Removes the secret, adds `token_secret_set`.
fn public_config(raw: &str) -> Value {
    let mut v: Value = serde_json::from_str(raw).unwrap_or_default();
    if let Some(o) = v.as_object_mut() {
        let set = o
            .remove("token_secret")
            .is_some_and(|s| s.as_str().is_some_and(|s| !s.is_empty()));
        o.insert("token_secret_set".into(), json!(set));
    }
    v
}

/// Linux agent source (docs/agent-protocol.md): which agent, what to back up.
/// No secrets (the agent trust lives in the `agents` table / appliance CA).
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LinuxConfig {
    agent_id: String,
    paths: Vec<String>,
    #[serde(default)]
    excludes: Vec<String>,
    #[serde(default)]
    hooks: bool,
}

impl LinuxConfig {
    fn check(&self, c: &Connection, tenant: &str) -> ApiResult<()> {
        validate::agent_id(&self.agent_id)?;
        if !exists(
            c,
            "SELECT 1 FROM agents WHERE id = ?1 AND tenant = ?2",
            params![self.agent_id, tenant],
        )? {
            return Err(ApiError::bad("config.agent_id: no such agent in this tenant"));
        }
        if self.paths.is_empty() || self.paths.len() > 64 {
            return Err(ApiError::bad("config.paths: 1..=64 absolute paths"));
        }
        for p in &self.paths {
            validate::host_path(p, "config.paths")?;
        }
        if self.excludes.len() > 256 {
            return Err(ApiError::bad("config.excludes: at most 256 patterns"));
        }
        for x in &self.excludes {
            if x.is_empty() {
                return Err(ApiError::bad("config.excludes: empty pattern"));
            }
            validate::text(x, "config.excludes", 4096)?;
            if x.contains(['\n', '\r']) {
                return Err(ApiError::bad("config.excludes: one pattern per entry"));
            }
        }
        Ok(())
    }
}

fn parse_config<T: serde::de::DeserializeOwned>(v: Value) -> ApiResult<T> {
    serde_json::from_value(v).map_err(|e| ApiError::bad(format!("config: {e}")))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceReq {
    tenant: String,
    kind: String,
    name: String,
    config: Value,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceUpdate {
    name: String,
    config: Value,
}

struct PveSourceUpdate {
    name: String,
    config: PveConfig,
}

struct PveSourceReq {
    tenant: String,
    kind: String,
    name: String,
    config: PveConfig,
}

fn source_json(c: &Connection, id: i64) -> ApiResult<Value> {
    Ok(c.query_row(
        "SELECT id, tenant, kind, name, config FROM sources WHERE id = ?1",
        [id],
        |r| {
            Ok(
                json!({"id": r.get::<_, i64>(0)?, "tenant": r.get::<_, String>(1)?, "kind": r.get::<_, String>(2)?,
                      "name": r.get::<_, String>(3)?, "config": public_config(&r.get::<_, String>(4)?)}),
            )
        },
    )?)
}

pub async fn list_sources(State(st): State<St>, ctx: Ctx) -> ApiResult<Json<Value>> {
    let c = st.cat.conn();
    let ids: Vec<i64> = c
        .prepare("SELECT id FROM sources WHERE ?1 IS NULL OR tenant = ?1 ORDER BY tenant, name")?
        .query_map([ctx.scope()], |r| r.get(0))?
        .collect::<Result<_, _>>()?;
    Ok(Json(Value::Array(
        ids.into_iter()
            .map(|id| source_json(&c, id))
            .collect::<Result<_, _>>()?,
    )))
}

pub async fn create_source(State(st): State<St>, ctx: Ctx, J(r): J<SourceReq>) -> ApiResult<Response> {
    ctx.require(ADMIN)?;
    validate::name(&r.name, "name")?;
    match r.kind.as_str() {
        "pve" => {}
        "linux" => {
            let cfg: LinuxConfig = parse_config(r.config)?;
            let (id, out) = {
                let c = st.cat.conn();
                if !exists(&c, "SELECT 1 FROM tenants WHERE name = ?1", [&r.tenant])? {
                    return Err(ApiError::bad("tenant: does not exist"));
                }
                cfg.check(&c, &r.tenant)?;
                c.execute(
                    "INSERT INTO sources (tenant, kind, name, config) VALUES (?1, 'linux', ?2, ?3)",
                    params![r.tenant, r.name, json!(cfg).to_string()],
                )?;
                let id = c.last_insert_rowid();
                (id, source_json(&c, id)?)
            };
            st.audit(
                ctx.name(),
                "source.create",
                &format!("source/{id}"),
                json!({"tenant": r.tenant, "kind": "linux", "name": r.name, "config": out["config"]}),
            )?;
            return Ok(created(out));
        }
        _ => return Err(ApiError::bad("kind: `pve` or `linux`")),
    }
    let r = PveSourceReq {
        config: parse_config(r.config)?,
        tenant: r.tenant,
        kind: r.kind,
        name: r.name,
    };
    r.config.check()?;
    if r.config.token_secret.is_none() {
        return Err(ApiError::bad("config.token_secret: required"));
    }
    let pk = st.seal_key()?;
    let (id, out) = {
        let mut c = st.cat.conn();
        if !exists(&c, "SELECT 1 FROM tenants WHERE name = ?1", [&r.tenant])? {
            return Err(ApiError::bad("tenant: does not exist"));
        }
        // the sealed secret is bound to the row id: insert, then seal, in one transaction
        let tx = c.transaction()?;
        tx.execute(
            "INSERT INTO sources (tenant, kind, name, config) VALUES (?1, ?2, ?3, '{}')",
            params![r.tenant, r.kind, r.name],
        )?;
        let id = tx.last_insert_rowid();
        tx.execute(
            "UPDATE sources SET config = ?2 WHERE id = ?1",
            params![id, sealed_config(&pk, id, &r.config)?],
        )?;
        tx.commit()?;
        (id, source_json(&c, id)?)
    };
    st.audit(
        ctx.name(),
        "source.create",
        &format!("source/{id}"),
        json!({"tenant": r.tenant, "name": r.name, "config": out["config"]}),
    )?;
    Ok(created(out))
}

pub async fn update_source(
    State(st): State<St>,
    ctx: Ctx,
    Path(id): Path<i64>,
    J(r): J<SourceUpdate>,
) -> ApiResult<Json<Value>> {
    ctx.require(ADMIN)?;
    validate::name(&r.name, "name")?;
    let (tenant, kind): (String, String) = st
        .cat
        .conn()
        .query_row("SELECT tenant, kind FROM sources WHERE id = ?1", [id], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .optional()?
        .ok_or_else(ApiError::not_found)?;
    if kind == "linux" {
        let cfg: LinuxConfig = parse_config(r.config)?;
        let out = {
            let c = st.cat.conn();
            cfg.check(&c, &tenant)?;
            c.execute(
                "UPDATE sources SET name = ?2, config = ?3 WHERE id = ?1",
                params![id, r.name, json!(cfg).to_string()],
            )?;
            source_json(&c, id)?
        };
        st.audit(
            ctx.name(),
            "source.update",
            &format!("source/{id}"),
            json!({"name": r.name, "config": out["config"]}),
        )?;
        return Ok(Json(out));
    }
    let mut r = PveSourceUpdate {
        name: r.name,
        config: parse_config(r.config)?,
    };
    r.config.check()?;
    let pk = st.seal_key()?;
    let out = {
        let c = st.cat.conn();
        let old: String = c
            .query_row("SELECT config FROM sources WHERE id = ?1", [id], |r| r.get(0))
            .optional()?
            .ok_or_else(ApiError::not_found)?;
        if r.config.token_secret.is_none() {
            // keeping the stored secret is only allowed for the same endpoint: otherwise
            // an admin could send the (write-only) token to a host of their choice
            let old: Value = serde_json::from_str(&old).unwrap_or_default();
            let new = serde_json::to_value(&r.config).unwrap_or_default();
            if ["host", "port", "connect_addr", "ca_pem", "token_id"]
                .iter()
                .any(|k| old.get(*k) != new.get(*k))
            {
                return Err(ApiError::bad(
                    "config.token_secret: required when host, port, connect_addr, ca_pem or token_id change",
                ));
            }
            // kept as stored: sealed (bound to this source and the unchanged endpoint)
            r.config.token_secret = old["token_secret"].as_str().map(str::to_owned);
        }
        let config = sealed_config(&pk, id, &r.config)?;
        c.execute(
            "UPDATE sources SET name = ?2, config = ?3 WHERE id = ?1",
            params![id, r.name, config],
        )?;
        source_json(&c, id)?
    };
    st.audit(
        ctx.name(),
        "source.update",
        &format!("source/{id}"),
        json!({"name": r.name, "config": out["config"]}),
    )?;
    Ok(Json(out))
}

pub async fn delete_source(State(st): State<St>, ctx: Ctx, Path(id): Path<i64>) -> ApiResult<Response> {
    ctx.require(ADMIN)?;
    let (tenant, name) = {
        let c = st.cat.conn();
        let row: (String, String) = c
            .query_row("SELECT tenant, name FROM sources WHERE id = ?1", [id], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .optional()?
            .ok_or_else(ApiError::not_found)?;
        if exists(&c, "SELECT 1 FROM groups WHERE source_id = ?1", [id])? {
            return Err(ApiError::conflict("source is still used by groups"));
        }
        row
    };
    gate(
        &st,
        &ctx,
        "source.delete",
        &format!("source/{id}"),
        json!({"id": id, "tenant": tenant, "name": name}),
    )
}

// ---------------------------------------------------------------- policies

#[derive(Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct PolicyReq {
    name: String,
    schedule: String,
    gfs: Gfs,
    #[serde(default = "yes")]
    offsite: bool,
}

fn yes() -> bool {
    true
}

impl PolicyReq {
    fn check(&self) -> ApiResult<()> {
        validate::name(&self.name, "name")?;
        validate::schedule(&self.schedule)?;
        self.gfs.check()
    }
    /// Any GFS count lowered or offsite disabled.
    fn weakened_by(&self, new: &PolicyReq) -> bool {
        self.gfs.lowered_by(&new.gfs) || (self.offsite && !new.offsite)
    }
}

fn load_policy(c: &Connection, id: i64) -> ApiResult<Option<PolicyReq>> {
    Ok(c.query_row(
        "SELECT name, schedule, gfs, offsite FROM policies WHERE id = ?1",
        [id],
        |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, bool>(3)?,
            ))
        },
    )
    .optional()?
    .map(|(name, schedule, gfs, offsite)| PolicyReq {
        name,
        schedule,
        gfs: serde_json::from_str(&gfs).unwrap_or(Gfs {
            daily: 0,
            weekly: 0,
            monthly: 0,
            yearly: 0,
        }),
        offsite,
    }))
}

fn policy_json(id: i64, p: &PolicyReq) -> Value {
    json!({"id": id, "name": p.name, "schedule": p.schedule, "gfs": p.gfs, "offsite": p.offsite})
}

/// A policy as `policy_json` (quorum `old` snapshots compare against it).
pub fn policy_value(c: &Connection, id: i64) -> ApiResult<Option<Value>> {
    Ok(load_policy(c, id)?.map(|p| policy_json(id, &p)))
}

pub async fn list_policies(State(st): State<St>, _ctx: Ctx) -> ApiResult<Json<Value>> {
    let c = st.cat.conn();
    let ids: Vec<i64> = c
        .prepare("SELECT id FROM policies ORDER BY name")?
        .query_map([], |r| r.get(0))?
        .collect::<Result<_, _>>()?;
    let mut out = Vec::new();
    for id in ids {
        if let Some(p) = load_policy(&c, id)? {
            out.push(policy_json(id, &p));
        }
    }
    Ok(Json(Value::Array(out)))
}

pub async fn create_policy(State(st): State<St>, ctx: Ctx, J(r): J<PolicyReq>) -> ApiResult<Response> {
    ctx.require(ADMIN)?;
    r.check()?;
    let id = {
        let c = st.cat.conn();
        c.execute(
            "INSERT INTO policies (name, schedule, gfs, offsite) VALUES (?1, ?2, ?3, ?4)",
            params![r.name, r.schedule, serde_json::to_string(&r.gfs).unwrap(), r.offsite],
        )?;
        c.last_insert_rowid()
    };
    let out = policy_json(id, &r);
    st.audit(ctx.name(), "policy.create", &format!("policy/{id}"), out.clone())?;
    Ok(created(out))
}

/// Strengthening or neutral changes apply directly; weakening ones (any GFS
/// value lowered, offsite disabled) need a quorum.
pub async fn update_policy(
    State(st): State<St>,
    ctx: Ctx,
    Path(id): Path<i64>,
    J(r): J<PolicyReq>,
) -> ApiResult<Response> {
    ctx.require(ADMIN)?;
    r.check()?;
    let old = {
        let c = st.cat.conn();
        let old = load_policy(&c, id)?.ok_or_else(ApiError::not_found)?;
        if exists(
            &c,
            "SELECT 1 FROM policies WHERE name = ?1 AND id != ?2",
            params![r.name, id],
        )? {
            return Err(ApiError::conflict("a policy with this name exists"));
        }
        old
    };
    let target = format!("policy/{id}");
    if old.weakened_by(&r) {
        let mut p = policy_json(id, &r);
        p["old"] = policy_json(id, &old);
        return gate(&st, &ctx, "policy.update", &target, p);
    }
    st.cat.conn().execute(
        "UPDATE policies SET name = ?2, schedule = ?3, gfs = ?4, offsite = ?5 WHERE id = ?1",
        params![
            id,
            r.name,
            r.schedule,
            serde_json::to_string(&r.gfs).unwrap(),
            r.offsite
        ],
    )?;
    let out = policy_json(id, &r);
    st.audit(
        ctx.name(),
        "policy.update",
        &target,
        json!({"new": out, "old": policy_json(id, &old)}),
    )?;
    Ok(Json(out).into_response())
}

pub async fn delete_policy(State(st): State<St>, ctx: Ctx, Path(id): Path<i64>) -> ApiResult<Response> {
    ctx.require(ADMIN)?;
    let name = {
        let c = st.cat.conn();
        let p = load_policy(&c, id)?.ok_or_else(ApiError::not_found)?;
        if exists(&c, "SELECT 1 FROM groups WHERE policy_id = ?1", [id])? {
            return Err(ApiError::conflict("policy is still used by groups"));
        }
        p.name
    };
    gate(
        &st,
        &ctx,
        "policy.delete",
        &format!("policy/{id}"),
        json!({"id": id, "name": name}),
    )
}

// ---------------------------------------------------------------- groups

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroupReq {
    tenant: String,
    source_id: i64,
    policy_id: i64,
    name: String,
    guests: Vec<Value>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroupUpdate {
    source_id: i64,
    policy_id: i64,
    name: String,
    guests: Vec<Value>,
}

fn check_group(
    c: &Connection,
    tenant: &str,
    source_id: i64,
    policy_id: i64,
    name: &str,
    guests: &mut Vec<Value>,
) -> ApiResult<()> {
    validate::name(name, "name")?;
    if guests.len() > 1000 {
        return Err(ApiError::bad("guests: at most 1000"));
    }
    let (kind, config): (String, String) = c
        .query_row(
            "SELECT kind, config FROM sources WHERE id = ?1 AND tenant = ?2",
            params![source_id, tenant],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?
        .ok_or_else(|| ApiError::bad("source_id: no such source in this tenant"))?;
    if kind == "linux" {
        // the guest of a linux source is its agent (the source says what to back up)
        let agent = serde_json::from_str::<Value>(&config).unwrap_or_default()["agent_id"].clone();
        if guests.iter().any(|g| *g != agent) {
            return Err(ApiError::bad(
                "guests: a linux source's group contains its agent id only",
            ));
        }
        *guests = vec![agent];
    } else {
        let mut ids = Vec::with_capacity(guests.len());
        for g in guests.iter() {
            let v = g
                .as_u64()
                .and_then(|v| u32::try_from(v).ok())
                .ok_or_else(|| ApiError::bad("guests: vmids (numbers) for a pve source"))?;
            validate::vmid(v)?;
            ids.push(v);
        }
        ids.sort_unstable();
        ids.dedup();
        *guests = ids.into_iter().map(Value::from).collect();
    }
    if !exists(c, "SELECT 1 FROM policies WHERE id = ?1", [policy_id])? {
        return Err(ApiError::bad("policy_id: no such policy"));
    }
    Ok(())
}

fn group_row(r: &catalog::rusqlite::Row) -> catalog::rusqlite::Result<Value> {
    let guests: String = r.get(5)?;
    Ok(
        json!({"id": r.get::<_, i64>(0)?, "tenant": r.get::<_, String>(1)?, "source_id": r.get::<_, i64>(2)?,
              "policy_id": r.get::<_, i64>(3)?, "name": r.get::<_, String>(4)?,
              "guests": serde_json::from_str::<Value>(&guests).unwrap_or_default()}),
    )
}

const GROUP_COLS: &str = "id, tenant, source_id, policy_id, name, guests";

/// A group as `group_row` (quorum `old` snapshots compare against it).
pub fn group_value(c: &Connection, id: i64) -> ApiResult<Option<Value>> {
    Ok(c.query_row(
        &format!("SELECT {GROUP_COLS} FROM groups WHERE id = ?1"),
        [id],
        group_row,
    )
    .optional()?)
}

pub async fn list_groups(State(st): State<St>, ctx: Ctx) -> ApiResult<Json<Value>> {
    let c = st.cat.conn();
    let rows = c
        .prepare(&format!(
            "SELECT {GROUP_COLS} FROM groups WHERE ?1 IS NULL OR tenant = ?1 ORDER BY tenant, name"
        ))?
        .query_map([ctx.scope()], group_row)?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Json(Value::Array(rows)))
}

pub async fn create_group(State(st): State<St>, ctx: Ctx, J(mut r): J<GroupReq>) -> ApiResult<Response> {
    ctx.require(ADMIN)?;
    let out = {
        let c = st.cat.conn();
        check_group(&c, &r.tenant, r.source_id, r.policy_id, &r.name, &mut r.guests)?;
        c.execute(
            "INSERT INTO groups (tenant, source_id, policy_id, name, guests) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![r.tenant, r.source_id, r.policy_id, r.name, json!(r.guests).to_string()],
        )?;
        let id = c.last_insert_rowid();
        c.query_row(
            &format!("SELECT {GROUP_COLS} FROM groups WHERE id = ?1"),
            [id],
            group_row,
        )?
    };
    st.audit(ctx.name(), "group.create", &format!("group/{}", out["id"]), out.clone())?;
    Ok(created(out))
}

/// Moving a group to a policy that is weaker in any dimension is a
/// weakening (it would otherwise bypass the policy quorum) → quorum.
pub async fn update_group(
    State(st): State<St>,
    ctx: Ctx,
    Path(id): Path<i64>,
    J(mut r): J<GroupUpdate>,
) -> ApiResult<Response> {
    ctx.require(ADMIN)?;
    let (old, weakening) = {
        let c = st.cat.conn();
        let old = c
            .query_row(
                &format!("SELECT {GROUP_COLS} FROM groups WHERE id = ?1"),
                [id],
                group_row,
            )
            .optional()?
            .ok_or_else(ApiError::not_found)?;
        let tenant = old["tenant"].as_str().unwrap_or_default().to_owned();
        check_group(&c, &tenant, r.source_id, r.policy_id, &r.name, &mut r.guests)?;
        let old_pid = old["policy_id"].as_i64().unwrap_or_default();
        let weakening = old_pid != r.policy_id
            && match (load_policy(&c, old_pid)?, load_policy(&c, r.policy_id)?) {
                (Some(a), Some(b)) => a.weakened_by(&b),
                _ => false,
            };
        (old, weakening)
    };
    let new = json!({"id": id, "tenant": old["tenant"], "source_id": r.source_id, "policy_id": r.policy_id,
                     "name": r.name, "guests": r.guests});
    let target = format!("group/{id}");
    if weakening {
        let mut p = new.clone();
        p["old"] = old;
        return gate(&st, &ctx, "group.update", &target, p);
    }
    st.cat.conn().execute(
        "UPDATE groups SET source_id = ?2, policy_id = ?3, name = ?4, guests = ?5 WHERE id = ?1",
        params![id, r.source_id, r.policy_id, r.name, json!(r.guests).to_string()],
    )?;
    st.audit(ctx.name(), "group.update", &target, json!({"new": new, "old": old}))?;
    Ok(Json(new).into_response())
}

pub async fn delete_group(State(st): State<St>, ctx: Ctx, Path(id): Path<i64>) -> ApiResult<Response> {
    ctx.require(ADMIN)?;
    let g = st
        .cat
        .conn()
        .query_row(
            &format!("SELECT {GROUP_COLS} FROM groups WHERE id = ?1"),
            [id],
            group_row,
        )
        .optional()?
        .ok_or_else(ApiError::not_found)?;
    gate(&st, &ctx, "group.delete", &format!("group/{id}"), g)
}

// ---------------------------------------------------------------- users

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserReq {
    name: String,
    password: String,
    role: String,
    #[serde(default)]
    tenant: Option<String>,
}

/// All fields optional; `tenant: null` clears the restriction.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserUpdate {
    #[serde(default)]
    role: Option<String>,
    #[serde(default, deserialize_with = "present")]
    tenant: Option<Value>,
    #[serde(default)]
    disabled: Option<bool>,
    #[serde(default)]
    password: Option<String>,
    #[serde(default)]
    reset_totp: bool,
    /// re-authentication of the acting user, required with `password` / `reset_totp`
    #[serde(default)]
    current_password: Option<String>,
    #[serde(default)]
    current_totp: Option<String>,
}

/// `Option<Value>` that keeps an explicit `null` as `Some(Null)` (serde maps
/// it to `None` otherwise, which made `tenant: null` mean "keep").
fn present<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<Value>, D::Error> {
    Value::deserialize(d).map(Some)
}

fn check_user_tenant(c: &Connection, role: &str, tenant: Option<&str>) -> ApiResult<()> {
    // config CRUD and quorum decisions are appliance-wide: a "tenant admin" would
    // write across tenants and could lift its own restriction
    if tenant.is_some() && validate::privileged(role) {
        return Err(ApiError::bad(
            "tenant: admin and security_officer accounts cannot be tenant-scoped",
        ));
    }
    match tenant {
        Some(t) => {
            if !exists(c, "SELECT 1 FROM tenants WHERE name = ?1", [t])? {
                return Err(ApiError::bad("tenant: does not exist"));
            }
        }
        None if role == "tenant_user" => return Err(ApiError::bad("tenant: required for tenant_user")),
        None => {}
    }
    Ok(())
}

async fn hash(pw: String) -> ApiResult<String> {
    tokio::task::spawn_blocking(move || catalog::auth::hash_password(&pw))
        .await
        .map_err(|e| anyhow::anyhow!("hash task: {e}"))?
        .map_err(|e| ApiError::bad(format!("password: {e}")))
}

pub async fn list_users(State(st): State<St>, ctx: Ctx) -> ApiResult<Json<Value>> {
    let c = st.cat.conn();
    let rows = c
        .prepare(&format!(
            "SELECT {USER_COLS} FROM users WHERE ?1 IS NULL OR tenant = ?1 ORDER BY name"
        ))?
        .query_map([ctx.scope()], |r| User::from_row(r, 0))?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Json(json!(rows)))
}

/// Returns the TOTP provisioning URI exactly once. Creating an admin or
/// security_officer creates the account *disabled* and raises a quorum
/// request that enables it.
pub async fn create_user(State(st): State<St>, ctx: Ctx, J(r): J<UserReq>) -> ApiResult<Response> {
    ctx.require(ADMIN)?;
    validate::name(&r.name, "name")?;
    validate::role(&r.role)?;
    if let Some(t) = &r.tenant {
        validate::name(t, "tenant")?;
    }
    if r.password.len() > 1024 {
        return Err(ApiError::bad("password: too long"));
    }
    check_user_tenant(&st.cat.conn(), &r.role, r.tenant.as_deref())?;
    let pw_hash = hash(r.password).await?;
    let secret = catalog::auth::new_totp_secret();
    let uri = catalog::auth::totp_uri(&secret, &r.name)?;
    let enc = st.totp.encrypt(&r.name, &secret)?;
    let gated = validate::privileged(&r.role);
    let user = {
        let c = st.cat.conn();
        c.execute(
            "INSERT INTO users (name, password_hash, totp_secret, role, tenant, disabled, created) VALUES (?1,?2,?3,?4,?5,?6,?7)",
            params![r.name, pw_hash, enc, r.role, r.tenant, gated, catalog::now()],
        )?;
        User::load(&c, c.last_insert_rowid())?
    };
    st.audit(
        ctx.name(),
        "user.create",
        &format!("user/{}", user.name),
        json!({"user": user}),
    )?;
    if gated {
        let q = request(
            &st,
            &ctx,
            "user.update",
            &format!("user/{}", user.name),
            json!({"id": user.id, "name": user.name, "role": user.role, "disabled": false}),
        )?;
        return Ok(accepted(q, json!({"user": user, "totp_uri": uri})));
    }
    Ok(created(json!({"user": user, "totp_uri": uri})))
}

/// Applies a (possibly approved) user change; ends the user's sessions.
pub fn apply_user_update(c: &Connection, p: &Value) -> ApiResult<()> {
    let id = p["id"].as_i64().ok_or_else(|| ApiError::bad("missing id"))?;
    User::load(c, id).map_err(|_| ApiError::conflict("the object no longer exists"))?;
    if let Some(r) = p["role"].as_str() {
        c.execute("UPDATE users SET role = ?2 WHERE id = ?1", params![id, r])?;
    }
    if let Some(t) = p.get("tenant") {
        c.execute("UPDATE users SET tenant = ?2 WHERE id = ?1", params![id, t.as_str()])?;
    }
    if let Some(d) = p["disabled"].as_bool() {
        c.execute("UPDATE users SET disabled = ?2 WHERE id = ?1", params![id, d])?;
    }
    if let Some(h) = p["password_hash"].as_str() {
        c.execute("UPDATE users SET password_hash = ?2 WHERE id = ?1", params![id, h])?;
    }
    if let Some(s) = p["totp_secret"].as_str() {
        c.execute("UPDATE users SET totp_secret = ?2 WHERE id = ?1", params![id, s])?;
    }
    c.execute("DELETE FROM sessions WHERE user_id = ?1", [id])?;
    Ok(())
}

/// Quorum-gated: granting admin/security_officer (incl. re-enabling such an
/// account), disabling or demoting the last enabled admin/security_officer,
/// and resetting another privileged user's password or TOTP (account takeover).
/// Any password / TOTP change (own or another user's) first re-authenticates
/// the acting user (`current_password` + `current_totp`, review M-5).
pub async fn update_user(
    State(st): State<St>,
    ctx: Ctx,
    ClientIp(ip): ClientIp,
    Path(id): Path<i64>,
    J(mut r): J<UserUpdate>,
) -> ApiResult<Response> {
    ctx.require(ADMIN)?;
    let old = User::load(&st.cat.conn(), id)?;
    if r.password.is_some() || r.reset_totp {
        let purpose = format!("credentials of user/{}", old.name);
        reauth(
            &st,
            &ctx,
            &ip,
            r.current_password.take(),
            r.current_totp.take(),
            &purpose,
        )
        .await?;
    }
    let role = r.role.clone().unwrap_or_else(|| old.role.clone());
    validate::role(&role)?;
    let tenant: Option<String> = match &r.tenant {
        None => old.tenant.clone(),
        Some(Value::Null) => None,
        Some(Value::String(t)) => {
            validate::name(t, "tenant")?;
            Some(t.clone())
        }
        Some(_) => return Err(ApiError::bad("tenant: string or null")),
    };
    let disabled = r.disabled.unwrap_or(old.disabled);
    let others_enabled: i64 = {
        let c = st.cat.conn();
        check_user_tenant(&c, &role, tenant.as_deref())?;
        c.query_row(
            "SELECT COUNT(*) FROM users WHERE role = ?1 AND disabled = 0 AND id != ?2",
            params![old.role, id],
            |r| r.get(0),
        )?
    };
    let was_priv = validate::privileged(&old.role) && !old.disabled;
    let grant = validate::privileged(&role) && !disabled && !(was_priv && old.role == role);
    let removes_last = was_priv && (disabled || role != old.role) && others_enabled == 0;
    let cred_reset = (r.password.is_some() || r.reset_totp)
        && (validate::privileged(&old.role) || validate::privileged(&role))
        && id != ctx.user.id;

    let mut p = json!({"id": id, "name": old.name});
    if role != old.role {
        p["role"] = json!(role);
    }
    if tenant != old.tenant {
        p["tenant"] = json!(tenant);
    }
    if disabled != old.disabled {
        p["disabled"] = json!(disabled);
    }
    if let Some(pw) = r.password {
        if pw.len() > 1024 {
            return Err(ApiError::bad("password: too long"));
        }
        p["password_hash"] = json!(hash(pw).await?);
    }
    let mut extra = json!({});
    if r.reset_totp {
        let s = catalog::auth::new_totp_secret();
        extra["totp_uri"] = json!(catalog::auth::totp_uri(&s, &old.name)?);
        // encrypted already in the quorum params, bound to this user's name
        p["totp_secret"] = json!(st.totp.encrypt(&old.name, &s)?);
    }
    let target = format!("user/{}", old.name);
    if grant || removes_last || cred_reset {
        // the approver sees (and approves) the role the account ends up with
        p["role"] = json!(role);
        let q = request(&st, &ctx, "user.update", &target, p)?;
        return Ok(accepted(q, extra));
    }
    let user = {
        let c = st.cat.conn();
        apply_user_update(&c, &p)?;
        User::load(&c, id)?
    };
    st.audit(ctx.name(), "user.update", &target, crate::quorum::redact(p))?;
    extra["user"] = json!(user);
    Ok(Json(extra).into_response())
}
