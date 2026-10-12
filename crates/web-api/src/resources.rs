//! Config CRUD: tenants, sources, policies, groups, users (admin only for
//! writes; destructive or weakening changes go through the quorum).

use crate::activation;
use crate::auth::{reauth, ClientIp, Ctx, User, USER_COLS};
use crate::quorum::{accepted, gate, Outcome};
use crate::validate::{self, Gfs};
use crate::{ApiError, ApiResult, St, J};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use catalog::rusqlite::{params, Connection, OptionalExtension};
use catalog::schedule::{Retry, Window};
use catalog::secret::{source_owner, tenant_owner, SealKey};
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

/// S3 offsite remote (`tenants.offsite.remote` with `type: "s3"`,
/// docs/s3-offsite.md). `secret_key` is write-only and sealed to the
/// scheduler, bound to endpoint/region/bucket/access_key/path_style/ca_pem.
#[derive(Deserialize, Serialize, Clone, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct S3Remote {
    #[serde(rename = "type")]
    kind: String,
    endpoint: String,
    region: String,
    bucket: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    prefix: String,
    access_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    secret_key: Option<String>,
    /// echoed by clients from GET; ignored
    #[serde(default, skip_serializing)]
    #[allow(dead_code)]
    secret_key_set: Option<bool>,
    #[serde(default)]
    path_style: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ca_pem: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    storage_class_packs: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    storage_class_meta: Option<String>,
    #[serde(default)]
    lock: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    conditional_put: Option<bool>,
}

/// Fields a stored S3 secret is bound to (see `catalog::secret`).
const S3_BINDING: &[&str] = &["endpoint", "region", "bucket", "access_key", "path_style", "ca_pem"];

fn printable(s: &str, max: usize) -> bool {
    (1..=max).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_graphic())
}

impl S3Remote {
    fn check(&self) -> ApiResult<()> {
        let bad = |m: &str| Err(ApiError::bad(format!("offsite.remote.{m}")));
        let ep = self.endpoint.strip_prefix("https://").unwrap_or("");
        let ep = ep.strip_suffix('/').unwrap_or(ep);
        let (h, port) = match ep.rsplit_once(':') {
            Some((h, p)) if !ep.ends_with(']') => (h, Some(p)),
            _ => (ep, None),
        };
        let host_ok = !h.is_empty()
            && h.len() <= 253
            && (h.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'.' || c == b'-')
                || (h.starts_with('[') && h.ends_with(']') && h[1..h.len() - 1].parse::<std::net::Ipv6Addr>().is_ok()));
        if !host_ok || port.is_some_and(|p| p.parse::<u16>().map_or(true, |p| p == 0)) {
            return bad("endpoint: expected https://host[:port] (HTTPS only, no path)");
        }
        if !(1..=32).contains(&self.region.len())
            || !self
                .region
                .bytes()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
        {
            return bad("region: 1..=32 of [a-z0-9-]");
        }
        let b = self.bucket.as_bytes();
        if !(3..=63).contains(&b.len())
            || !b
                .iter()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-' || *c == b'.')
            || !b[0].is_ascii_alphanumeric()
            || !b[b.len() - 1].is_ascii_alphanumeric()
            || self.bucket.contains("..")
        {
            return bad("bucket: 3..=63 of [a-z0-9.-]");
        }
        if !self.path_style && (self.bucket.contains('.') || h.starts_with('[')) {
            return bad("path_style: required for bucket names with dots and IP endpoints");
        }
        if self.prefix.len() > 256
            || (!self.prefix.is_empty()
                && !self.prefix.split('/').all(|c| {
                    !c.is_empty()
                        && c != "."
                        && c != ".."
                        && c.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
                }))
        {
            return bad("prefix: path components of [A-Za-z0-9._-], no leading or trailing /");
        }
        if !printable(&self.access_key, 128) {
            return bad("access_key: 1..=128 printable characters");
        }
        if self.secret_key.as_deref().is_some_and(|s| !printable(s, 256)) {
            return bad("secret_key: 1..=256 printable characters");
        }
        if let Some(ca) = &self.ca_pem {
            if ca.len() > 64 << 10 || !ca.contains("-----BEGIN CERTIFICATE-----") || ca.contains("PRIVATE KEY") {
                return bad("ca_pem: expected PEM certificate(s) (at most 64 KiB)");
            }
        }
        for c in [&self.storage_class_packs, &self.storage_class_meta]
            .into_iter()
            .flatten()
        {
            if !(1..=32).contains(&c.len()) || !c.bytes().all(|b| b.is_ascii_uppercase() || b == b'_') {
                return bad("storage_class: 1..=32 of [A-Z_]");
            }
            // archive classes need a restore request before a GET: DR and verify would fail
            if matches!(c.as_str(), "GLACIER" | "DEEP_ARCHIVE") {
                return bad("storage_class: GLACIER and DEEP_ARCHIVE are not readable without a restore; use e.g. GLACIER_IR or STANDARD_IA");
            }
        }
        Ok(())
    }
}

/// Validates `tenants.offsite`. An S3 remote is parsed strictly (its
/// `secret_key` is the one inline secret allowed); anything else stays an
/// opaque blob without inline secrets.
fn check_offsite(v: &Value) -> ApiResult<Option<S3Remote>> {
    if !v.is_object() {
        return Err(ApiError::bad("offsite: must be an object"));
    }
    if v["remote"]["type"] != "s3" {
        opaque(v, "offsite", 16 << 10)?;
        return Ok(None);
    }
    let r: S3Remote =
        serde_json::from_value(v["remote"].clone()).map_err(|e| ApiError::bad(format!("offsite.remote: {e}")))?;
    r.check()?;
    let mut rest = v.clone();
    let rr = rest["remote"].as_object_mut().unwrap();
    rr.remove("secret_key");
    rr.remove("secret_key_set");
    opaque(&rest, "offsite", 80 << 10)?;
    Ok(Some(r))
}

/// The offsite config as stored: an S3 remote normalized, its secret sealed
/// to the scheduler (bound to the tenant and the S3 endpoint fields).
fn sealed_offsite(st: &St, tenant: &str, v: &Value, s3: Option<S3Remote>) -> ApiResult<Value> {
    let Some(r) = s3 else { return Ok(v.clone()) };
    let mut out = v.clone();
    out["remote"] = serde_json::to_value(&r).map_err(anyhow::Error::from)?;
    if r.secret_key.as_deref().is_some_and(|s| !catalog::secret::is_sealed(s)) {
        st.seal_key()?.seal_all(&tenant_owner(tenant), &mut out)?;
    }
    Ok(out)
}

/// The offsite config as shown: `secret_key` replaced by `secret_key_set`.
pub fn public_offsite(v: &Value) -> Value {
    let mut v = v.clone();
    if let Some(r) = v.get_mut("remote").and_then(Value::as_object_mut) {
        if let Some(s) = r.remove("secret_key") {
            r.insert(
                "secret_key_set".into(),
                json!(s.as_str().is_some_and(|s| !s.is_empty())),
            );
        }
    }
    v
}

pub async fn list_tenants(State(st): State<St>, ctx: Ctx) -> ApiResult<Json<Value>> {
    let c = st.cat.conn();
    let mut s =
        c.prepare("SELECT name, offsite, quota_bytes FROM tenants WHERE ?1 IS NULL OR name = ?1 ORDER BY name")?;
    let rows = s
        .query_map([ctx.scope()], |r| {
            let o: String = r.get(1)?;
            let o = serde_json::from_str::<Value>(&o).unwrap_or_default();
            Ok(json!({"name": r.get::<_, String>(0)?, "offsite": public_offsite(&o),
                      "quota_bytes": r.get::<_, Option<i64>>(2)?}))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Json(Value::Array(rows)))
}

pub async fn create_tenant(State(st): State<St>, ctx: Ctx, J(r): J<TenantReq>) -> ApiResult<Response> {
    ctx.require(ADMIN)?;
    validate::name(&r.name, "name")?;
    let s3 = check_offsite(&r.offsite)?;
    if s3.as_ref().is_some_and(|s| s.secret_key.is_none()) {
        return Err(ApiError::bad("offsite.remote.secret_key: required"));
    }
    let offsite = sealed_offsite(&st, &r.name, &r.offsite, s3)?;
    st.cat.conn().execute(
        "INSERT INTO tenants (name, offsite) VALUES (?1, ?2)",
        params![r.name, offsite.to_string()],
    )?;
    let shown = public_offsite(&offsite);
    st.audit(
        ctx.name(),
        "tenant.create",
        &format!("tenant/{}", r.name),
        json!({"offsite": shown}),
    )?;
    Ok(created(json!({"name": r.name, "offsite": shown})))
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
    let mut s3 = check_offsite(&r.offsite)?;
    let old = tenant_value(&st.cat.conn(), &name)?.ok_or_else(ApiError::not_found)?;
    if let Some(new) = s3.as_mut().filter(|s| s.secret_key.is_none()) {
        // keeping the stored (sealed) secret only for the same S3 endpoint:
        // otherwise an admin could send the write-only key to a host of their choice
        let o = &old["offsite"]["remote"];
        let n = serde_json::to_value(&*new).map_err(anyhow::Error::from)?;
        if o["type"] != "s3" || !o["secret_key"].is_string() || S3_BINDING.iter().any(|k| o.get(*k) != n.get(*k)) {
            return Err(ApiError::bad(
                "offsite.remote.secret_key: required when endpoint, region, bucket, access_key, path_style or ca_pem change",
            ));
        }
        new.secret_key = o["secret_key"].as_str().map(str::to_owned);
    }
    let offsite = sealed_offsite(&st, &name, &r.offsite, s3)?;
    let target = format!("tenant/{name}");
    let had_offsite = old["offsite"].as_object().is_some_and(|o| !o.is_empty());
    if had_offsite && old["offsite"] != offsite {
        let p = json!({"name": name, "offsite": offsite, "old": old});
        return gate(&st, &ctx, "tenant.update", &target, p);
    }
    let n = st.cat.conn().execute(
        "UPDATE tenants SET offsite = ?2 WHERE name = ?1",
        params![name, offsite.to_string()],
    )?;
    if n == 0 {
        return Err(ApiError::not_found());
    }
    let shown = public_offsite(&offsite);
    st.audit(ctx.name(), "tenant.update", &target, json!({"offsite": shown}))?;
    Ok(Json(json!({"name": name, "offsite": shown})).into_response())
}

/// A tenant can only be deleted once no source, group or user refers to it.
pub fn tenant_deletable(c: &Connection, name: &str) -> ApiResult<()> {
    for t in ["sources", "groups", "users", "agents"] {
        if exists(c, &format!("SELECT 1 FROM {t} WHERE tenant = ?1"), [name])? {
            return Err(ApiError::conflict(format!("tenant still has {t}")));
        }
    }
    if crate::replication::replicated_tenant(c, name)?
        || exists(
            c,
            "SELECT 1 FROM replication_peers, json_each(replication_peers.tenants) j
             WHERE j.value = ?1 AND replication_peers.state != 'revoked'",
            [name],
        )?
    {
        return Err(ApiError::conflict("tenant is used by replication"));
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

/// Removes every secret (`token_secret`, `key_pem`, at any depth) and adds
/// `<field>_set: bool` next to it (`token_secret_set` always, as before).
/// TrueNAS sources also get `authorized_keys`, the line to paste on TrueNAS.
fn public_config(raw: &str) -> Value {
    fn strip(v: &mut Value) {
        match v {
            Value::Object(o) => {
                for k in catalog::secret::SECRET_FIELDS {
                    if let Some(s) = o.remove(*k) {
                        o.insert(format!("{k}_set"), json!(s.as_str().is_some_and(|s| !s.is_empty())));
                    }
                }
                o.values_mut().for_each(strip);
            }
            Value::Array(a) => a.iter_mut().for_each(strip),
            _ => {}
        }
    }
    let mut v: Value = serde_json::from_str(raw).unwrap_or_default();
    strip(&mut v);
    if let Some(o) = v.as_object_mut() {
        o.entry("token_secret_set").or_insert(json!(false));
        if o.get("ssh").is_some_and(|s| s.get("public_key").is_some()) {
            let mut c = Value::Object(o.clone());
            c.as_object_mut().unwrap().remove("token_secret_set");
            if let Some(s) = c["ssh"].as_object_mut() {
                s.remove("key_pem_set");
            }
            if let Some(line) = serde_json::from_value::<TrueNasConfig>(c)
                .ok()
                .and_then(|t| t.authorized_keys())
            {
                o.insert("authorized_keys".into(), json!(line));
            }
        }
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
    /// Phase 15e (crate::selection, agents v1.3): include roots, regex excludes,
    /// nested mounts backed up except the `skip_fstypes` (empty = default list)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    include: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    exclude_regex: Vec<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    cross_mounts: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    skip_fstypes: Vec<String>,
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
        crate::selection::check_include(&self.include, "config.include")?;
        crate::selection::check_regex(&self.exclude_regex, "config.exclude_regex")?;
        crate::selection::check_fstypes(&self.skip_fstypes)?;
        Ok(())
    }
}

fn https_port() -> u16 {
    443
}
fn ssh_port() -> u16 {
    22
}
fn truenas_user() -> String {
    "nexusbackup".into()
}

/// SSH endpoint of a TrueNAS source. `key_pem` (the appliance's private key)
/// is write-only and sealed, bound to host/port/user/host_key.
#[derive(Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct TrueNasSsh {
    host: String,
    #[serde(default = "ssh_port")]
    port: u16,
    #[serde(default = "truenas_user")]
    user: String,
    /// `ssh-ed25519 AAAA…` (pinned, no TOFU)
    host_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    key_pem: Option<String>,
    /// public half of `key_pem`: the web-api returns the authorized_keys line for it
    #[serde(default, skip_serializing_if = "Option::is_none")]
    public_key: Option<String>,
    /// `from="…"` of the authorized_keys line (appliance address as TrueNAS sees it)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    from: Option<String>,
}

/// TrueNAS source (docs/truenas-connector.md). `token_secret` = API key of
/// `user` (write-only, sealed, bound to host/port/connect_addr/ca_pem/user).
#[derive(Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct TrueNasConfig {
    host: String,
    #[serde(default = "https_port")]
    port: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    connect_addr: Option<String>,
    /// the TrueNAS certificate (pinned) and/or the CA that issued it
    ca_pem: String,
    #[serde(default = "truenas_user")]
    user: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    token_secret: Option<String>,
    ssh: TrueNasSsh,
    datasets: Vec<String>,
    #[serde(default)]
    recursive: bool,
    #[serde(default = "yes")]
    sudo: bool,
    #[serde(default = "yes")]
    zfs_sudo: bool,
}

fn unix_user(s: &str, what: &str) -> ApiResult<()> {
    let ok = (1..=32).contains(&s.len())
        && s.bytes().next().is_some_and(|b| b.is_ascii_lowercase() || b == b'_')
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"_-".contains(&b));
    if ok {
        Ok(())
    } else {
        Err(ApiError::bad(format!(
            "{what}: expected a user name [a-z_][a-z0-9_-]{{0,31}}"
        )))
    }
}

/// `<type> <base64>` (an SSH public host key, no comment needed).
fn ssh_public_key(s: &str, what: &str) -> ApiResult<()> {
    let mut it = s.split_whitespace();
    let ok = s.len() <= 8192
        && it.next().is_some_and(|t| {
            matches!(
                t,
                "ssh-ed25519" | "ecdsa-sha2-nistp256" | "ecdsa-sha2-nistp384" | "ecdsa-sha2-nistp521" | "ssh-rsa"
            )
        })
        && it
            .next()
            .is_some_and(|b| b.bytes().all(|c| c.is_ascii_alphanumeric() || b"+/=".contains(&c)))
        && !s.contains(['\n', '\r', '\0']);
    if ok {
        Ok(())
    } else {
        Err(ApiError::bad(format!("{what}: expected `ssh-ed25519 AAAA…`")))
    }
}

impl TrueNasConfig {
    fn fc(&self) -> truenas::fc::Fc {
        truenas::fc::Fc {
            datasets: self.datasets.clone(),
            recursive: self.recursive,
            sudo: self.sudo,
            zfs_sudo: self.zfs_sudo,
        }
    }

    fn check(&self) -> ApiResult<()> {
        validate::host(&self.host)?;
        validate::host(&self.ssh.host).map_err(|_| ApiError::bad("ssh.host: invalid host name or address"))?;
        if self.port == 0 || self.ssh.port == 0 {
            return Err(ApiError::bad("port: must be 1..=65535"));
        }
        if let Some(a) = &self.connect_addr {
            a.parse::<std::net::SocketAddr>()
                .map_err(|_| ApiError::bad("connect_addr: expected ip:port"))?;
        }
        if self.ca_pem.len() > 64 << 10 || !self.ca_pem.contains("-----BEGIN CERTIFICATE-----") {
            return Err(ApiError::bad("ca_pem: expected a PEM certificate (at most 64 KiB)"));
        }
        unix_user(&self.user, "user")?;
        unix_user(&self.ssh.user, "ssh.user")?;
        if let Some(s) = &self.token_secret {
            if s.is_empty() || s.len() > 256 || !s.bytes().all(|b| b.is_ascii_graphic()) {
                return Err(ApiError::bad("token_secret: the API key, 1..=256 printable characters"));
            }
        }
        ssh_public_key(&self.ssh.host_key, "ssh.host_key")?;
        if let Some(k) = &self.ssh.key_pem {
            if k.len() > 16 << 10 || !k.contains("PRIVATE KEY-----") {
                return Err(ApiError::bad(
                    "ssh.key_pem: expected a PEM/OpenSSH private key (at most 16 KiB)",
                ));
            }
        }
        if self.datasets.is_empty() || self.datasets.len() > 64 {
            return Err(ApiError::bad("datasets: 1..=64 datasets"));
        }
        for d in &self.datasets {
            if !truenas::valid_dataset(d) {
                return Err(ApiError::bad(format!(
                    "datasets: {d:?} is not supported (pool/a/b, components of A-Z a-z 0-9 _ -)"
                )));
            }
            if self
                .datasets
                .iter()
                .filter(|o| truenas::under(d, o) || truenas::under(o, d))
                .count()
                > 1
            {
                return Err(ApiError::bad(format!("datasets: {d:?} overlaps another dataset")));
            }
        }
        if let Some(p) = &self.ssh.public_key {
            ssh_public_key(p, "ssh.public_key")?;
            validate::text(p, "ssh.public_key", 8192)?;
        }
        // the forced command must be buildable from this config (also checks `from`)
        truenas::fc::authorized_keys(
            &self.fc(),
            &truenas::fc::Tools::default(),
            self.ssh.public_key.as_deref().unwrap_or("ssh-ed25519 AAAA"),
            self.ssh.from.as_deref(),
        )
        .map_err(|e| ApiError::bad(format!("ssh: {e:#}")))?;
        Ok(())
    }

    /// The line for the TrueNAS user's "SSH public key" field (None without public_key).
    fn authorized_keys(&self) -> Option<String> {
        let pk = self.ssh.public_key.as_deref()?;
        truenas::fc::authorized_keys(&self.fc(), &truenas::fc::Tools::default(), pk, self.ssh.from.as_deref()).ok()
    }
}

/// NFS or SMB share source (docs/nas-connector.md); one share per source. SMB
/// secrets (`password`, or `keytab` as base64 for `sec: "krb5"`) are write-only
/// and sealed, bound to `host`/`port`/`user`.
#[derive(Deserialize, Serialize, Clone, Default)]
#[serde(deny_unknown_fields)]
pub struct ShareConfig {
    host: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    port: Option<u16>,
    /// NFS: 3 | 4.0 | 4.1 | 4.2 (default 4.2); SMB: 2.1 | 3 | 3.0 | 3.02 | 3.1.1 (default 3)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    version: Option<String>,
    /// NFS export path
    #[serde(default, skip_serializing_if = "Option::is_none")]
    export: Option<String>,
    /// NFSv3 mountd port (default 20048; no portmapper)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    mount_port: Option<u16>,
    /// SMB share name
    #[serde(default, skip_serializing_if = "Option::is_none")]
    share: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    user: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    domain: Option<String>,
    /// SMB: ntlmssp (default) | krb5
    #[serde(default, skip_serializing_if = "Option::is_none")]
    sec: Option<String>,
    /// SMB: require signing (default true)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    sign: Option<bool>,
    /// SMB 3: require encryption (default false)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    seal: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    password: Option<String>,
    /// base64 keytab (sec krb5)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    keytab: Option<String>,
    /// Kerberos principal `user@REALM` (sec krb5)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    principal: Option<String>,
    /// NAS snapshot directory below the share root (`.zfs/snapshot`, `.snapshot`, `~snapshot`)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    snapshot_dir: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    snapshot_prefix: Option<String>,
    /// name (default) | mtime
    #[serde(default, skip_serializing_if = "Option::is_none")]
    snapshot_order: Option<String>,
    #[serde(default)]
    excludes: Vec<String>,
    /// Phase 15e: include roots (share paths, `/projects/a`) and regex excludes
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    include: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    exclude_regex: Vec<String>,
    /// scan threads (1..=64, default 16)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    threads: Option<u32>,
    /// back up xattrs/ACLs (default true)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    xattrs: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    timeout_secs: Option<u32>,
}

impl ShareConfig {
    /// The helper request this config produces (secrets replaced by placeholders
    /// when they are kept from the stored config), checked like the helper does.
    fn check(&self, kind: &str) -> ApiResult<()> {
        use nas::proto::Request;
        let bad = |m: String| ApiError::bad(m);
        if !nas::valid_host(&self.host) {
            return Err(bad("host: invalid host name or address".into()));
        }
        let addr: std::net::IpAddr = "192.0.2.1".parse().unwrap();
        let mut r = match kind {
            "nfs" => {
                if self.share.is_some()
                    || self.user.is_some()
                    || self.domain.is_some()
                    || self.sec.is_some()
                    || self.sign.is_some()
                    || self.seal.is_some()
                    || self.password.is_some()
                    || self.keytab.is_some()
                    || self.principal.is_some()
                {
                    return Err(bad(
                        "config: share, user, domain, sec, sign, seal, password, keytab and principal are SMB fields"
                            .into(),
                    ));
                }
                let export = self.export.as_deref().ok_or_else(|| bad("export: required".into()))?;
                if !nas::valid_export(export) {
                    return Err(bad(
                        "export: absolute path without `,` `\"` `'` `\\`, `.`/`..` or control characters".into(),
                    ));
                }
                let mut r = Request::nfs(&self.host, addr, export);
                if let Some(p) = self.mount_port {
                    r.mount_port = p;
                }
                r
            }
            _ => {
                if self.export.is_some() || self.mount_port.is_some() {
                    return Err(bad("config: export and mount_port are NFS fields".into()));
                }
                let share = self.share.as_deref().ok_or_else(|| bad("share: required".into()))?;
                if !nas::valid_share(share) {
                    return Err(bad("share: 1..=80 characters, none of \\ / : * ? \" < > | , =".into()));
                }
                let mut r = Request::smb(
                    &self.host,
                    addr,
                    share,
                    self.user.as_deref().unwrap_or(""),
                    "placeholder",
                );
                r.domain = self.domain.clone().unwrap_or_default();
                r.sign = self.sign.unwrap_or(true);
                r.seal = self.seal.unwrap_or(false);
                match self.sec.as_deref().unwrap_or("ntlmssp") {
                    "ntlmssp" => {
                        if self.keytab.is_some() || self.principal.is_some() {
                            return Err(bad("keytab, principal: only with sec krb5".into()));
                        }
                        if let Some(p) = &self.password {
                            if !nas::valid_password(p) {
                                return Err(bad("password: 1..=256 bytes, no NUL".into()));
                            }
                        }
                    }
                    // user decision 2026-10-10: no SMB Kerberos in v1 (cifs-utils/krb5 are not in the
                    // image and it is untested); the mount helper keeps its krb5 support for later
                    "krb5" => {
                        return Err(bad(
                            "sec krb5: not supported in this version (use ntlmssp with signed/encrypted SMB3)".into(),
                        ))
                    }
                    _ => return Err(bad("sec: ntlmssp".into())),
                }
                r
            }
        };
        if let Some(v) = &self.version {
            r.version = v.clone();
        }
        if let Some(p) = self.port {
            r.port = p;
        }
        if let Some(t) = self.timeout_secs {
            r.timeout_secs = t;
        }
        r.check().map_err(|e| bad(format!("config: {e:#}")))?;
        if let Some(d) = &self.snapshot_dir {
            if !nas::valid_rel_dir(d) {
                return Err(bad(
                    "snapshot_dir: relative directory below the share root (e.g. .zfs/snapshot)".into(),
                ));
            }
        }
        if let Some(p) = &self.snapshot_prefix {
            validate::text(p, "snapshot_prefix", 128)?;
            if p.contains('/') {
                return Err(bad("snapshot_prefix: a name prefix, no `/`".into()));
            }
        }
        if !matches!(self.snapshot_order.as_deref(), None | Some("name") | Some("mtime")) {
            return Err(bad("snapshot_order: name or mtime".into()));
        }
        if self.excludes.len() > 256 {
            return Err(bad("excludes: at most 256 patterns".into()));
        }
        for x in &self.excludes {
            if x.is_empty() || x.contains(['\n', '\r']) {
                return Err(bad("excludes: one non-empty pattern per entry".into()));
            }
            validate::text(x, "excludes", 4096)?;
        }
        if self.threads.is_some_and(|t| !(1..=64).contains(&t)) {
            return Err(bad("threads: 1..=64".into()));
        }
        crate::selection::check_include(&self.include, "include")?;
        crate::selection::check_regex(&self.exclude_regex, "exclude_regex")?;
        Ok(())
    }

    fn has_secret(&self) -> bool {
        self.password.is_some() || self.keytab.is_some()
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
        "SELECT id, tenant, kind, name, config, maintenance_until FROM sources WHERE id = ?1",
        [id],
        |r| {
            let kind: String = r.get(2)?;
            let raw: String = r.get(4)?;
            let config = if kind.starts_with("plugin:") {
                crate::plugins::public_plugin_config(c, &kind, &raw)
            } else {
                public_config(&raw)
            };
            Ok(
                json!({"id": r.get::<_, i64>(0)?, "tenant": r.get::<_, String>(1)?, "kind": kind,
                      "name": r.get::<_, String>(3)?, "config": config,
                      "maintenance_until": r.get::<_, Option<i64>>(5)?}),
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
        kind if kind.starts_with("plugin:") => {
            let id = crate::plugins::create_source(&st, &r.tenant, kind, &r.name, r.config)?;
            let out = source_json(&st.cat.conn(), id)?;
            st.audit(
                ctx.name(),
                "source.create",
                &format!("source/{id}"),
                json!({"tenant": r.tenant, "kind": kind, "name": r.name, "config": out["config"]}),
            )?;
            return Ok(created(out));
        }
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
        "truenas" => {
            let cfg: TrueNasConfig = parse_config(r.config)?;
            cfg.check()?;
            if cfg.token_secret.is_none() || cfg.ssh.key_pem.is_none() {
                return Err(ApiError::bad("config.token_secret and config.ssh.key_pem: required"));
            }
            let pk = st.seal_key()?;
            let (id, out) = {
                let mut c = st.cat.conn();
                if !exists(&c, "SELECT 1 FROM tenants WHERE name = ?1", [&r.tenant])? {
                    return Err(ApiError::bad("tenant: does not exist"));
                }
                let tx = c.transaction()?;
                tx.execute(
                    "INSERT INTO sources (tenant, kind, name, config) VALUES (?1, 'truenas', ?2, '{}')",
                    params![r.tenant, r.name],
                )?;
                let id = tx.last_insert_rowid();
                let mut v = serde_json::to_value(&cfg).map_err(anyhow::Error::from)?;
                pk.seal_all(&source_owner(id), &mut v)?;
                tx.execute(
                    "UPDATE sources SET config = ?2 WHERE id = ?1",
                    params![id, v.to_string()],
                )?;
                tx.commit()?;
                (id, source_json(&c, id)?)
            };
            st.audit(
                ctx.name(),
                "source.create",
                &format!("source/{id}"),
                json!({"tenant": r.tenant, "kind": "truenas", "name": r.name, "config": out["config"]}),
            )?;
            return Ok(created(out));
        }
        kind @ ("nfs" | "smb") => {
            let cfg: ShareConfig = parse_config(r.config)?;
            cfg.check(kind)?;
            if kind == "smb" && !cfg.has_secret() {
                return Err(ApiError::bad(
                    "config.password (or config.keytab with sec krb5): required",
                ));
            }
            if cfg.sec.as_deref() == Some("krb5") && (cfg.keytab.is_none() || cfg.principal.is_none()) {
                return Err(ApiError::bad(
                    "config.keytab and config.principal: required with sec krb5",
                ));
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
                    params![r.tenant, kind, r.name],
                )?;
                let id = tx.last_insert_rowid();
                let mut v = serde_json::to_value(&cfg).map_err(anyhow::Error::from)?;
                pk.seal_all(&source_owner(id), &mut v)?;
                tx.execute(
                    "UPDATE sources SET config = ?2 WHERE id = ?1",
                    params![id, v.to_string()],
                )?;
                tx.commit()?;
                (id, source_json(&c, id)?)
            };
            st.audit(
                ctx.name(),
                "source.create",
                &format!("source/{id}"),
                json!({"tenant": r.tenant, "kind": kind, "name": r.name, "config": out["config"]}),
            )?;
            return Ok(created(out));
        }
        _ => {
            return Err(ApiError::bad(
                "kind: `pve`, `linux`, `truenas`, `nfs`, `smb` or `plugin:<kind>` of an installed plugin",
            ))
        }
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
    if kind.starts_with("plugin:") {
        crate::plugins::update_source(&st, id, &kind, &r.name, r.config)?;
        let out = source_json(&st.cat.conn(), id)?;
        st.audit(
            ctx.name(),
            "source.update",
            &format!("source/{id}"),
            json!({"name": r.name, "config": out["config"]}),
        )?;
        return Ok(Json(out));
    }
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
    if kind == "truenas" {
        let mut cfg: TrueNasConfig = parse_config(r.config)?;
        cfg.check()?;
        let pk = st.seal_key()?;
        let out = {
            let c = st.cat.conn();
            let old: String = c
                .query_row("SELECT config FROM sources WHERE id = ?1", [id], |r| r.get(0))
                .optional()?
                .ok_or_else(ApiError::not_found)?;
            let old: Value = serde_json::from_str(&old).unwrap_or_default();
            let new = serde_json::to_value(&cfg).map_err(anyhow::Error::from)?;
            // keeping a stored secret is only allowed for the same endpoint (see PVE below)
            if cfg.token_secret.is_none() {
                if ["host", "port", "connect_addr", "ca_pem", "user"]
                    .iter()
                    .any(|k| old.get(*k) != new.get(*k))
                {
                    return Err(ApiError::bad(
                        "config.token_secret: required when host, port, connect_addr, ca_pem or user change",
                    ));
                }
                cfg.token_secret = old["token_secret"].as_str().map(str::to_owned);
            }
            if cfg.ssh.key_pem.is_none() {
                if ["host", "port", "user", "host_key"]
                    .iter()
                    .any(|k| old["ssh"].get(*k) != new["ssh"].get(*k))
                {
                    return Err(ApiError::bad(
                        "config.ssh.key_pem: required when ssh.host, ssh.port, ssh.user or ssh.host_key change",
                    ));
                }
                cfg.ssh.key_pem = old["ssh"]["key_pem"].as_str().map(str::to_owned);
            }
            let mut v = serde_json::to_value(&cfg).map_err(anyhow::Error::from)?;
            pk.seal_all(&source_owner(id), &mut v)?;
            c.execute(
                "UPDATE sources SET name = ?2, config = ?3 WHERE id = ?1",
                params![id, r.name, v.to_string()],
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
    if kind == "nfs" || kind == "smb" {
        let mut cfg: ShareConfig = parse_config(r.config)?;
        cfg.check(&kind)?;
        let pk = st.seal_key()?;
        let out = {
            let c = st.cat.conn();
            let old: String = c
                .query_row("SELECT config FROM sources WHERE id = ?1", [id], |r| r.get(0))
                .optional()?
                .ok_or_else(ApiError::not_found)?;
            let old: Value = serde_json::from_str(&old).unwrap_or_default();
            if kind == "smb" && !cfg.has_secret() {
                // keeping the stored secret is only allowed for the same server and user
                // (see PVE below); a change of sec needs the new kind of secret anyway
                let new = serde_json::to_value(&cfg).map_err(anyhow::Error::from)?;
                if ["host", "port", "user", "sec", "principal"]
                    .iter()
                    .any(|k| old.get(*k) != new.get(*k))
                {
                    return Err(ApiError::bad(
                        "config.password / config.keytab: required when host, port, user, sec or principal change",
                    ));
                }
                cfg.password = old["password"].as_str().map(str::to_owned);
                cfg.keytab = old["keytab"].as_str().map(str::to_owned);
            }
            let mut v = serde_json::to_value(&cfg).map_err(anyhow::Error::from)?;
            pk.seal_all(&source_owner(id), &mut v)?;
            c.execute(
                "UPDATE sources SET name = ?2, config = ?3 WHERE id = ?1",
                params![id, r.name, v.to_string()],
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
    /// Phase 13b run control: retries of failed backups, blackout windows, run-time SLA
    #[serde(default)]
    retry: Retry,
    #[serde(default)]
    blackout: Vec<Window>,
    #[serde(default)]
    sla_minutes: Option<u32>,
    /// Phase 15d: minimum consistency of group backups (scheduler `consistency.rs`)
    #[serde(default)]
    require_consistency: RequireConsistency,
    /// Phase 15e: global excludes for every file source of the policy's groups
    #[serde(default)]
    file_filters: crate::selection::FileFilters,
}

fn yes() -> bool {
    true
}

/// `{"mode": "off"|"warn"|"fail", "level": "application"|"crash"}`
#[derive(Deserialize, Serialize, Clone, PartialEq, Debug)]
#[serde(deny_unknown_fields)]
pub struct RequireConsistency {
    mode: String,
    #[serde(default = "crash")]
    level: String,
}

fn crash() -> String {
    "crash".into()
}

impl Default for RequireConsistency {
    fn default() -> Self {
        RequireConsistency {
            mode: "off".into(),
            level: crash(),
        }
    }
}

impl RequireConsistency {
    const MODES: [&str; 3] = ["off", "warn", "fail"];
    fn check(&self) -> ApiResult<()> {
        if !Self::MODES.contains(&self.mode.as_str()) {
            return Err(ApiError::bad("require_consistency.mode: off, warn or fail"));
        }
        if self.level != "application" && self.level != "crash" {
            return Err(ApiError::bad("require_consistency.level: application or crash"));
        }
        Ok(())
    }
    /// A milder mode, or a lower level while the requirement is on.
    fn weakened_by(&self, new: &Self) -> bool {
        let rank = |m: &str| Self::MODES.iter().position(|x| *x == m).unwrap_or(0);
        rank(&new.mode) < rank(&self.mode) || (new.mode != "off" && self.level == "application" && new.level == "crash")
    }
}

impl PolicyReq {
    fn check(&self) -> ApiResult<()> {
        validate::name(&self.name, "name")?;
        validate::schedule(&self.schedule)?;
        let bad = |e: anyhow::Error| ApiError::bad(e.to_string());
        self.retry.check().map_err(bad)?;
        if self.blackout.len() > 20 {
            return Err(ApiError::bad("blackout: at most 20 windows"));
        }
        self.blackout.iter().try_for_each(|w| w.check().map_err(bad))?;
        if self.sla_minutes.is_some_and(|m| !(1..=10080).contains(&m)) {
            return Err(ApiError::bad("sla_minutes: 1..=10080"));
        }
        self.require_consistency.check()?;
        self.file_filters.check()?;
        self.gfs.check()
    }
    /// Any GFS count lowered, offsite disabled, a blackout window added
    /// (fewer runs: it could stop backups altogether), the consistency
    /// requirement relaxed or a global exclude added.
    fn weakened_by(&self, new: &PolicyReq) -> bool {
        self.gfs.lowered_by(&new.gfs)
            || (self.offsite && !new.offsite)
            || new.blackout.iter().any(|w| !self.blackout.contains(w))
            || self.require_consistency.weakened_by(&new.require_consistency)
            || self.file_filters.widened_by(&new.file_filters)
    }
}

fn load_policy(c: &Connection, id: i64) -> ApiResult<Option<PolicyReq>> {
    Ok(c.query_row(
        "SELECT name, schedule, gfs, offsite, retry, blackout, sla_minutes, require_consistency, file_filters \
         FROM policies WHERE id = ?1",
        [id],
        |r| {
            Ok((
                (
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, bool>(3)?,
                ),
                (
                    r.get::<_, String>(4)?,
                    r.get::<_, String>(5)?,
                    r.get::<_, Option<u32>>(6)?,
                    r.get::<_, String>(7)?,
                    r.get::<_, String>(8)?,
                ),
            ))
        },
    )
    .optional()?
    .map(
        |((name, schedule, gfs, offsite), (retry, blackout, sla_minutes, req, filters))| PolicyReq {
            file_filters: serde_json::from_str(&filters).unwrap_or_default(),
            retry: serde_json::from_str(&retry).unwrap_or_default(),
            require_consistency: serde_json::from_str(&req).unwrap_or_default(),
            blackout: serde_json::from_str(&blackout).unwrap_or_default(),
            sla_minutes,
            name,
            schedule,
            gfs: serde_json::from_str(&gfs).unwrap_or(Gfs {
                daily: 0,
                weekly: 0,
                monthly: 0,
                yearly: 0,
            }),
            offsite,
        },
    ))
}

fn policy_json(id: i64, p: &PolicyReq) -> Value {
    json!({"id": id, "name": p.name, "schedule": p.schedule, "gfs": p.gfs, "offsite": p.offsite,
           "retry": p.retry, "blackout": p.blackout, "sla_minutes": p.sla_minutes,
           "require_consistency": p.require_consistency, "file_filters": p.file_filters})
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
            "INSERT INTO policies (name, schedule, gfs, offsite, retry, blackout, sla_minutes, require_consistency,
             file_filters)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                r.name,
                r.schedule,
                serde_json::to_string(&r.gfs).unwrap(),
                r.offsite,
                json!(r.retry).to_string(),
                json!(r.blackout).to_string(),
                r.sla_minutes,
                json!(r.require_consistency).to_string(),
                json!(r.file_filters).to_string()
            ],
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
        "UPDATE policies SET name = ?2, schedule = ?3, gfs = ?4, offsite = ?5, retry = ?6, blackout = ?7,
         sla_minutes = ?8, require_consistency = ?9, file_filters = ?10 WHERE id = ?1",
        params![
            id,
            r.name,
            r.schedule,
            serde_json::to_string(&r.gfs).unwrap(),
            r.offsite,
            json!(r.retry).to_string(),
            json!(r.blackout).to_string(),
            r.sla_minutes,
            json!(r.require_consistency).to_string(),
            json!(r.file_filters).to_string()
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
    #[serde(default)]
    guests: Vec<Value>,
    /// `explicit` (default), `all` or `tags` (crate::inventory::check_mode)
    #[serde(default = "explicit")]
    mode: String,
    #[serde(default)]
    selector: Vec<String>,
    #[serde(default)]
    exclude: Vec<Value>,
    /// the schedule's and blackout windows' time zone (IANA, Phase 13b)
    #[serde(default = "utc")]
    timezone: String,
    /// Phase 15e/f (crate::selection): PVE disks not backed up, their restore mode,
    /// guests backed up at once
    #[serde(default = "crate::selection::no_disks")]
    exclude_disks: Value,
    #[serde(default = "crate::selection::placeholder")]
    exclude_disks_mode: String,
    #[serde(default = "crate::selection::one")]
    parallel_guests: u32,
}

fn explicit() -> String {
    "explicit".into()
}

fn utc() -> String {
    "UTC".into()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroupUpdate {
    source_id: i64,
    policy_id: i64,
    name: String,
    #[serde(default)]
    guests: Vec<Value>,
    #[serde(default = "explicit")]
    mode: String,
    #[serde(default)]
    selector: Vec<String>,
    #[serde(default)]
    exclude: Vec<Value>,
    #[serde(default = "utc")]
    timezone: String,
    #[serde(default = "crate::selection::no_disks")]
    exclude_disks: Value,
    #[serde(default = "crate::selection::placeholder")]
    exclude_disks_mode: String,
    #[serde(default = "crate::selection::one")]
    parallel_guests: u32,
}

/// The auto-protect fields of a group request (mode, selector, exclude).
struct Auto<'a> {
    mode: &'a mut String,
    selector: &'a mut Vec<String>,
    exclude: &'a mut Vec<Value>,
}

fn check_group(
    c: &Connection,
    tenant: &str,
    source_id: i64,
    policy_id: i64,
    name: &str,
    guests: &mut Vec<Value>,
    a: Auto,
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
    if crate::inventory::check_mode(c, &kind, guests, a.mode, a.selector, a.exclude)? {
        // guests come from the inventory at run time
    } else if kind.starts_with("plugin:") {
        crate::plugins::check_guests(c, &kind, guests)?;
    } else if kind == "linux" {
        // the guest of a linux source is its agent (the source says what to back up)
        let agent = serde_json::from_str::<Value>(&config).unwrap_or_default()["agent_id"].clone();
        if guests.iter().any(|g| *g != agent) {
            return Err(ApiError::bad(
                "guests: a linux source's group contains its agent id only",
            ));
        }
        *guests = vec![agent];
    } else if kind == "nfs" || kind == "smb" {
        // a share source is one share: the group backs up the source itself
        if !guests.is_empty() {
            return Err(ApiError::bad(
                "guests: a share source's group lists no guests (the share is the source)",
            ));
        }
    } else if kind == "truenas" {
        // guests = datasets of the source (none = all of them: mode `all`, check_mode)
        let cfg: Value = serde_json::from_str(&config).unwrap_or_default();
        let all: Vec<Value> = cfg["datasets"].as_array().cloned().unwrap_or_default();
        if guests.iter().any(|g| !all.contains(g)) {
            return Err(ApiError::bad(
                "guests: a truenas source's group lists datasets of that source (or none = all)",
            ));
        } else {
            guests.sort_by_key(|g| g.as_str().unwrap_or_default().to_owned());
            guests.dedup();
        }
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
    let list = |i: usize| -> catalog::rusqlite::Result<Value> {
        Ok(serde_json::from_str::<Value>(&r.get::<_, String>(i)?).unwrap_or_default())
    };
    Ok(
        json!({"id": r.get::<_, i64>(0)?, "tenant": r.get::<_, String>(1)?, "source_id": r.get::<_, i64>(2)?,
              "policy_id": r.get::<_, i64>(3)?, "name": r.get::<_, String>(4)?, "guests": list(5)?,
              "mode": r.get::<_, String>(6)?, "selector": list(7)?, "exclude": list(8)?,
              "timezone": r.get::<_, String>(9)?, "index_files": r.get::<_, bool>(10)?,
              "exclude_disks": list(11)?, "exclude_disks_mode": r.get::<_, String>(12)?,
              "parallel_guests": r.get::<_, u32>(13)?}),
    )
}

const GROUP_COLS: &str = "id, tenant, source_id, policy_id, name, guests, mode, selector, exclude, timezone, \
                          index_files, exclude_disks, exclude_disks_mode, parallel_guests";

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
    Ok(Json(Value::Array(crate::runctl::group_states(&c, rows)?)))
}

pub async fn create_group(State(st): State<St>, ctx: Ctx, J(mut r): J<GroupReq>) -> ApiResult<Response> {
    ctx.require(ADMIN)?;
    let out = {
        let c = st.cat.conn();
        crate::replication::refuse_replicated(&c, &r.tenant)?;
        let a = Auto {
            mode: &mut r.mode,
            selector: &mut r.selector,
            exclude: &mut r.exclude,
        };
        check_group(&c, &r.tenant, r.source_id, r.policy_id, &r.name, &mut r.guests, a)?;
        validate::timezone(&r.timezone)?;
        crate::selection::check_group_fields(
            &c,
            r.source_id,
            &mut r.exclude_disks,
            &r.exclude_disks_mode,
            r.parallel_guests,
        )?;
        c.execute(
            "INSERT INTO groups (tenant, source_id, policy_id, name, guests, mode, selector, exclude, timezone, \
             exclude_disks, exclude_disks_mode, parallel_guests) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                r.tenant,
                r.source_id,
                r.policy_id,
                r.name,
                json!(r.guests).to_string(),
                r.mode,
                json!(r.selector).to_string(),
                json!(r.exclude).to_string(),
                r.timezone,
                r.exclude_disks.to_string(),
                r.exclude_disks_mode,
                r.parallel_guests
            ],
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
        let a = Auto {
            mode: &mut r.mode,
            selector: &mut r.selector,
            exclude: &mut r.exclude,
        };
        check_group(&c, &tenant, r.source_id, r.policy_id, &r.name, &mut r.guests, a)?;
        validate::timezone(&r.timezone)?;
        crate::selection::check_group_fields(
            &c,
            r.source_id,
            &mut r.exclude_disks,
            &r.exclude_disks_mode,
            r.parallel_guests,
        )?;
        let old_pid = old["policy_id"].as_i64().unwrap_or_default();
        let weakening = (old_pid != r.policy_id
            && match (load_policy(&c, old_pid)?, load_policy(&c, r.policy_id)?) {
                (Some(a), Some(b)) => a.weakened_by(&b),
                _ => false,
            })
            // excluding another disk backs up less (Phase 15e)
            || crate::selection::disks_added(&old["exclude_disks"], &r.exclude_disks);
        (old, weakening)
    };
    let new = json!({"id": id, "tenant": old["tenant"], "source_id": r.source_id, "policy_id": r.policy_id,
                     "name": r.name, "guests": r.guests, "mode": r.mode, "selector": r.selector, "exclude": r.exclude,
                     "timezone": r.timezone, "exclude_disks": r.exclude_disks,
                     "exclude_disks_mode": r.exclude_disks_mode, "parallel_guests": r.parallel_guests});
    let target = format!("group/{id}");
    if weakening {
        let mut p = new.clone();
        p["old"] = old;
        return gate(&st, &ctx, "group.update", &target, p);
    }
    st.cat.conn().execute(
        "UPDATE groups SET source_id = ?2, policy_id = ?3, name = ?4, guests = ?5, mode = ?6, selector = ?7, \
         exclude = ?8, timezone = ?9, exclude_disks = ?10, exclude_disks_mode = ?11, parallel_guests = ?12 \
         WHERE id = ?1",
        params![
            id,
            r.source_id,
            r.policy_id,
            r.name,
            json!(r.guests).to_string(),
            r.mode,
            json!(r.selector).to_string(),
            json!(r.exclude).to_string(),
            r.timezone,
            r.exclude_disks.to_string(),
            r.exclude_disks_mode,
            r.parallel_guests
        ],
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

/// No password: the person sets it at activation (crate::activation).
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserReq {
    name: String,
    role: String,
    #[serde(default)]
    tenant: Option<String>,
    /// default: the role's ([`catalog::access::role_can_download`])
    #[serde(default)]
    can_download: Option<bool>,
    /// unix time from which the account cannot log in; default never
    #[serde(default)]
    expires: Option<i64>,
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
    /// download privilege (`files_get`)
    #[serde(default)]
    can_download: Option<bool>,
    /// unix time, or `null` = never expires
    #[serde(default, deserialize_with = "present")]
    expires: Option<Value>,
    /// own account only
    #[serde(default)]
    password: Option<String>,
    /// own account only
    #[serde(default)]
    reset_totp: bool,
    /// other accounts: invalidate the credentials, issue a new activation code
    #[serde(default)]
    new_activation: bool,
    /// re-authentication of the acting user, required with `password` /
    /// `reset_totp` / `new_activation`
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

fn check_expires(e: Option<i64>) -> ApiResult<()> {
    if e.is_some_and(|e| !(0..=253_402_300_799).contains(&e)) {
        return Err(ApiError::bad("expires: unix time (seconds) or null"));
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

/// Creates an account pending activation and returns its one-time activation
/// code (shown once). With approvals enabled, an admin or security_officer is
/// created *disabled* with a quorum request that enables it; the requester gets
/// only part 1 of a split code, the approver part 2 (crate::activation).
pub async fn create_user(State(st): State<St>, ctx: Ctx, J(r): J<UserReq>) -> ApiResult<Response> {
    ctx.require(ADMIN)?;
    validate::name(&r.name, "name")?;
    validate::role(&r.role)?;
    if let Some(t) = &r.tenant {
        validate::name(t, "tenant")?;
    }
    check_user_tenant(&st.cat.conn(), &r.role, r.tenant.as_deref())?;
    check_expires(r.expires)?;
    let privileged = validate::privileged(&r.role);
    let gated = privileged && crate::quorum::enabled(&st)?;
    let (code, digest) = activation::new_part();
    let now = catalog::now();
    let (stored, expires) = if gated {
        (activation::split_pending(&digest), None)
    } else {
        (digest.clone(), Some(now + activation::ACTIVATION_SECS))
    };
    let user = {
        let c = st.cat.conn();
        c.execute(
            "INSERT INTO users (name, password_hash, totp_secret, role, tenant, disabled, created, activation_hash,
               activation_expires, can_download, expires)
             VALUES (?1, ?2, '', ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                r.name,
                catalog::NO_PASSWORD,
                r.role,
                r.tenant,
                gated,
                now,
                stored,
                expires,
                r.can_download,
                r.expires
            ],
        )?;
        User::load(&c, c.last_insert_rowid())?
    };
    let mut details = json!({"user": user});
    if privileged && !gated {
        details["approvals"] = json!("disabled");
    }
    let target = format!("user/{}", user.name);
    st.audit(ctx.name(), "user.create", &target, details)?;
    if gated {
        let q = crate::quorum::pending(
            &st,
            ctx.name(),
            "user.update",
            &target,
            json!({"id": user.id, "name": user.name, "role": user.role, "disabled": false,
                   "activation_hash": digest, "activation_split": true}),
        )?;
        return Ok(accepted(
            Outcome::Pending(q),
            json!({"user": user, "activation": activation::shown(&user.name, &code, 1, 2, None)}),
        ));
    }
    Ok(created(
        json!({"user": user, "activation": activation::shown(&user.name, &code, 1, 1, expires)}),
    ))
}

/// The digest of a pending activation, if any.
fn activation_digest(c: &Connection, id: i64) -> ApiResult<Option<String>> {
    Ok(c.query_row("SELECT activation_hash FROM users WHERE id = ?1", [id], |r| r.get(0))?)
}

/// With approvals enabled, an account must not become an enabled admin or
/// security officer while it waits for activation with a code that one admin
/// knows in full: that admin could activate it and approve their own requests.
fn refuse_known_code_grant(c: &Connection, user: &User, grant: bool, split: bool) -> ApiResult<()> {
    if grant
        && !split
        && catalog::approvals_enabled(c)?
        && activation_digest(c, user.id)?.is_some_and(|d| !d.contains(':'))
    {
        return Err(ApiError::conflict(
            "the account is waiting for activation with a code an admin knows: let the person activate it first, \
             or issue a new activation code together with the role change",
        ));
    }
    Ok(())
}

/// Applies a (possibly approved) user change; ends the user's sessions.
/// Returns what the approver is shown (part 2 of a split activation code).
/// With approvals enabled, refuses changes that would leave fewer than two
/// people able to approve (nobody but the requester could approve anything,
/// not even disabling approvals). Call inside a transaction.
pub fn apply_user_update(c: &Connection, p: &Value) -> ApiResult<Value> {
    let id = p["id"].as_i64().ok_or_else(|| ApiError::bad("missing id"))?;
    let before = User::load(c, id).map_err(|_| ApiError::conflict("the object no longer exists"))?;
    let approvers_before = catalog::possible_approvers(c)?.len();
    let role = p["role"].as_str().unwrap_or(&before.role);
    let disabled = p["disabled"].as_bool().unwrap_or(before.disabled);
    let grant = validate::privileged(role) && !disabled && (before.disabled || !validate::privileged(&before.role));
    refuse_known_code_grant(c, &before, grant, p["activation_split"] == true)?;
    if let Some(r) = p["role"].as_str() {
        c.execute("UPDATE users SET role = ?2 WHERE id = ?1", params![id, r])?;
    }
    if let Some(t) = p.get("tenant") {
        c.execute("UPDATE users SET tenant = ?2 WHERE id = ?1", params![id, t.as_str()])?;
    }
    if let Some(d) = p["disabled"].as_bool() {
        c.execute("UPDATE users SET disabled = ?2 WHERE id = ?1", params![id, d])?;
    }
    if let Some(d) = p["can_download"].as_bool() {
        c.execute("UPDATE users SET can_download = ?2 WHERE id = ?1", params![id, d])?;
    }
    if let Some(e) = p.get("expires") {
        c.execute("UPDATE users SET expires = ?2 WHERE id = ?1", params![id, e.as_i64()])?;
    }
    if let Some(h) = p["password_hash"].as_str() {
        c.execute("UPDATE users SET password_hash = ?2 WHERE id = ?1", params![id, h])?;
    }
    if let Some(s) = p["totp_secret"].as_str() {
        c.execute("UPDATE users SET totp_secret = ?2 WHERE id = ?1", params![id, s])?;
    }
    let mut extra = json!({});
    if let Some(h) = p["activation_hash"].as_str() {
        let expires = catalog::now() + activation::ACTIVATION_SECS;
        let stored = if p["activation_split"] == true {
            let (code, h2) = activation::new_part();
            extra["activation"] = activation::shown(&before.name, &code, 2, 2, Some(expires));
            format!("{h}:{h2}")
        } else {
            h.to_owned()
        };
        // the old credentials stop working now
        c.execute(
            "UPDATE users SET password_hash = ?2, totp_secret = '', activation_hash = ?3, activation_expires = ?4 WHERE id = ?1",
            params![id, catalog::NO_PASSWORD, stored, expires],
        )?;
    }
    c.execute("DELETE FROM sessions WHERE user_id = ?1", [id])?;
    if catalog::approvals_enabled(c)? {
        let after = catalog::possible_approvers(c)?.len();
        if after < approvers_before && after < 2 {
            return Err(ApiError::conflict(
                "approvals are enabled and this change would leave fewer than two people (admins or security \
                 officers) who can approve requests; add another one first, or disable approvals",
            ));
        }
    }
    Ok(extra)
}

/// Gated (quorum while approvals are enabled, else executed directly and
/// audited with `"approvals": "disabled"`): granting admin/security_officer
/// (incl. re-enabling such an account), disabling or demoting the last enabled
/// admin/security_officer, and issuing a new activation code for a privileged
/// account (split code: requester part 1, approver part 2). Without approvals
/// the last enabled admin cannot be disabled or demoted at all.
/// `password` / `reset_totp` change the acting user's own credentials;
/// `new_activation` resets another user's. All three re-authenticate the
/// acting user first (`current_password` + `current_totp`, review M-5).
pub async fn update_user(
    State(st): State<St>,
    ctx: Ctx,
    ClientIp(ip): ClientIp,
    Path(id): Path<i64>,
    J(mut r): J<UserUpdate>,
) -> ApiResult<Response> {
    ctx.require(ADMIN)?;
    let old = User::load(&st.cat.conn(), id)?;
    let own = id == ctx.user.id;
    if old.auth == "oidc" {
        let role_change = r.role.as_ref().is_some_and(|x| *x != old.role);
        let tenant_change = r.tenant.as_ref().is_some_and(|t| t.as_str() != old.tenant.as_deref());
        if r.password.is_some() || r.reset_totp || r.new_activation || role_change || tenant_change {
            return Err(ApiError::bad(
                "OIDC account: credentials, role and tenant come from the identity provider (mappings); \
                 only `disabled`, `can_download` and `expires` can be changed here",
            ));
        }
    }
    if (r.password.is_some() || r.reset_totp) && !own {
        return Err(ApiError::bad(
            "password and reset_totp change your own credentials; for another user issue a new activation code (new_activation)",
        ));
    }
    if r.new_activation && own {
        return Err(ApiError::bad(
            "new_activation: not for your own account (change your password or authenticator instead)",
        ));
    }
    if r.new_activation && (r.password.is_some() || r.reset_totp) {
        return Err(ApiError::bad(
            "new_activation cannot be combined with password or reset_totp",
        ));
    }
    if r.password.is_some() || r.reset_totp || r.new_activation {
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
    let expires = match &r.expires {
        None => old.expires,
        Some(Value::Null) => None,
        Some(v) => Some(v.as_i64().ok_or_else(|| ApiError::bad("expires: unix time or null"))?),
    };
    if expires != old.expires {
        check_expires(expires)?;
        // the account that can always fix things must not run out unnoticed
        let unexpiring_admins: i64 = st.cat.conn().query_row(
            "SELECT COUNT(*) FROM users WHERE role = 'admin' AND disabled = 0 AND expires IS NULL AND id != ?1",
            [id],
            |r| r.get(0),
        )?;
        if expires.is_some() && role == "admin" && unexpiring_admins == 0 {
            return Err(ApiError::conflict(
                "expires: the last admin without an expiry date cannot get one",
            ));
        }
    }
    let approvals = crate::quorum::enabled(&st)?;
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
    let cred_reset = r.new_activation && (validate::privileged(&old.role) || validate::privileged(&role));
    let gated = grant || removes_last || cred_reset;
    if !approvals && removes_last && old.role == "admin" {
        return Err(ApiError::conflict(
            "the last enabled admin cannot be disabled or demoted",
        ));
    }
    refuse_known_code_grant(&st.cat.conn(), &old, grant, r.new_activation)?;

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
    if let Some(d) = r.can_download.filter(|d| *d != old.can_download) {
        p["can_download"] = json!(d);
    }
    if expires != old.expires {
        p["expires"] = json!(expires);
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
    let split = approvals && gated && r.new_activation;
    if r.new_activation {
        let (code, digest) = activation::new_part();
        p["activation_hash"] = json!(digest);
        extra["activation"] = if split {
            p["activation_split"] = json!(true);
            activation::shown(&old.name, &code, 1, 2, None)
        } else {
            let expires = catalog::now() + activation::ACTIVATION_SECS;
            activation::shown(&old.name, &code, 1, 1, Some(expires))
        };
    }
    let target = format!("user/{}", old.name);
    if approvals && gated {
        // the approver sees (and approves) the role the account ends up with
        p["role"] = json!(role);
        let q = crate::quorum::pending(&st, ctx.name(), "user.update", &target, p)?;
        return Ok(accepted(Outcome::Pending(q), extra));
    }
    let user = {
        let mut c = st.cat.conn();
        let tx = c.transaction()?;
        apply_user_update(&tx, &p)?;
        let user = User::load(&tx, id)?;
        tx.commit()?;
        user
    };
    let mut details = crate::quorum::redact(p);
    if gated {
        details["approvals"] = json!("disabled");
    }
    st.audit(ctx.name(), "user.update", &target, details)?;
    extra["user"] = json!(user);
    Ok(Json(extra).into_response())
}
