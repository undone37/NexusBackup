//! Plugins (docs/plugin-system.md): signed uploads → quorum → installer, lifecycle,
//! publisher keys, plugin sources (config validated against the manifest's
//! `config_schema`, `secret_fields` sealed and write-only) and the JSON-Schema
//! subset the UI renders.

use crate::auth::Ctx;
use crate::quorum::{accepted, gate, request_as};
use crate::{ApiError, ApiResult, St};
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::Response;
use axum::Json;
use catalog::rusqlite::{params, Connection, OptionalExtension};
use catalog::secret::{source_owner, SealKey};
use plugin_manager::{Current, ROW_COLS};
use plugin_proto::bundle;
use plugin_proto::{KindSpec, Manifest};
use serde::Deserialize;
use serde_json::{json, Map, Value};
use std::path::PathBuf;

const ADMIN: &[&str] = &["admin"];
/// Upload limit (route-level body limit).
pub const MAX_UPLOAD: usize = bundle::MAX_BUNDLE;

/// Plugin paths of the web-api (env NEXUS_PLUGIN_STAGING / _KEYS / NEXUS_PLUGINS).
#[derive(Clone, Debug)]
pub struct PluginPaths {
    pub staging: PathBuf,
    pub keys: PathBuf,
    pub plugins: PathBuf,
}

impl Default for PluginPaths {
    fn default() -> Self {
        let p = |k: &str, d: &str| PathBuf::from(std::env::var_os(k).unwrap_or_else(|| d.into()));
        PluginPaths {
            staging: p("NEXUS_PLUGIN_STAGING", "/var/lib/nexus/plugins-staging"),
            keys: p("NEXUS_PLUGIN_KEYS", "/etc/pki/nexus/plugin-keys"),
            plugins: p("NEXUS_PLUGINS", "/var/lib/nexus/plugins"),
        }
    }
}

fn merr(e: plugin_manager::Error) -> ApiError {
    match e.status {
        400 => ApiError::bad(e.message),
        409 => ApiError::conflict(e.message),
        _ => ApiError(StatusCode::INTERNAL_SERVER_ERROR, e.message),
    }
}

fn row(c: &Connection, id: &str, version: &str) -> ApiResult<Value> {
    Ok(c.query_row(
        &format!("SELECT {ROW_COLS} FROM plugins WHERE id = ?1 AND version = ?2"),
        params![id, version],
        plugin_manager::row_json,
    )?)
}

pub async fn list_plugins(State(st): State<St>, _ctx: Ctx) -> ApiResult<Json<Value>> {
    let c = st.cat.conn();
    let rows = c
        .prepare(&format!("SELECT {ROW_COLS} FROM plugins ORDER BY id, uploaded_at"))?
        .query_map([], plugin_manager::row_json)?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Json(Value::Array(rows)))
}

/// `POST /plugins`: raw bundle body, detached signature in `X-Plugin-Signature`.
pub async fn upload_plugin(State(st): State<St>, ctx: Ctx, headers: HeaderMap, body: Bytes) -> ApiResult<Response> {
    ctx.require(ADMIN)?;
    let ct = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    if ct != "application/octet-stream" {
        return Err(ApiError(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "upload the bundle as application/octet-stream".into(),
        ));
    }
    let sig: String = headers
        .get("x-plugin-signature")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    if sig.is_empty() || sig.len() > 512 {
        return Err(ApiError::bad(
            "X-Plugin-Signature: the detached signature (base64) is required",
        ));
    }
    let paths = st.plugin_paths();
    let st2 = st.clone();
    let by = ctx.name().to_owned();
    let (v, quorum_id) = tokio::task::spawn_blocking(move || -> ApiResult<_> {
        let v = {
            let c = st2.cat.conn();
            plugin_manager::verify_upload(&c, &paths.keys, &body, sig.as_bytes()).map_err(merr)?
        };
        plugin_manager::stage(&paths.staging, &v, &body, sig.as_bytes())
            .map_err(|e| anyhow::anyhow!("staging {}: {e}", paths.staging.display()))?;
        let m = &v.bundle.manifest;
        let q = request_as(
            &st2,
            &by,
            "plugin.install",
            &format!("plugin/{}", m.id),
            json!({"id": m.id, "version": m.version, "name": m.name, "publisher": m.publisher, "sha256": v.sha256,
                   "bin_sha256": v.bundle.bin_sha256(), "signer": v.signer, "upgrade_from": v.upgrade_from,
                   "kinds": m.kinds.iter().map(|k| &k.kind).collect::<Vec<_>>(), "sandbox": m.sandbox}),
        )?;
        plugin_manager::record_pending(&st2.cat.conn(), &v, &by, q).map_err(merr)?;
        Ok((v, q))
    })
    .await
    .map_err(|e| anyhow::anyhow!("{e}"))??;
    let m = &v.bundle.manifest;
    st.audit(
        ctx.name(),
        "plugin.upload",
        &format!("plugin/{}", m.id),
        json!({"version": m.version, "sha256": v.sha256, "signer": v.signer, "quorum_id": quorum_id}),
    )?;
    let entry = row(&st.cat.conn(), &m.id, &m.version)?;
    Ok(accepted(
        quorum_id,
        json!({"plugin": entry, "upgrade_from": v.upgrade_from}),
    ))
}

fn current_row(c: &Connection, id: &str) -> ApiResult<(String, String)> {
    c.query_row(
        "SELECT version, name FROM plugins WHERE id = ?1 AND current = 1",
        [id],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )
    .optional()?
    .ok_or_else(ApiError::not_found)
}

pub async fn enable_plugin(State(st): State<St>, ctx: Ctx, Path(id): Path<String>) -> ApiResult<Json<Value>> {
    ctx.require(ADMIN)?;
    let out = {
        let c = st.cat.conn();
        let (v, _) = current_row(&c, &id)?;
        c.execute("UPDATE plugins SET enabled = 1 WHERE id = ?1", [&id])?;
        row(&c, &id, &v)?
    };
    st.audit(ctx.name(), "plugin.enable", &format!("plugin/{id}"), json!({}))?;
    Ok(Json(out))
}

pub async fn disable_plugin(State(st): State<St>, ctx: Ctx, Path(id): Path<String>) -> ApiResult<Response> {
    ctx.require(ADMIN)?;
    let (version, name) = current_row(&st.cat.conn(), &id)?;
    gate(
        &st,
        &ctx,
        "plugin.disable",
        &format!("plugin/{id}"),
        json!({"id": id, "name": name, "version": version}),
    )
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActivateReq {
    version: String,
}

pub async fn activate_plugin(
    State(st): State<St>,
    ctx: Ctx,
    Path(id): Path<String>,
    crate::J(r): crate::J<ActivateReq>,
) -> ApiResult<Response> {
    ctx.require(ADMIN)?;
    let (cur, name) = {
        let c = st.cat.conn();
        let state: Option<String> = c
            .query_row(
                "SELECT state FROM plugins WHERE id = ?1 AND version = ?2",
                params![id, r.version],
                |x| x.get(0),
            )
            .optional()?;
        if state.as_deref() != Some("installed") {
            return Err(ApiError::bad("version: not an installed version of this plugin"));
        }
        current_row(&c, &id)?
    };
    if cur == r.version {
        return Err(ApiError::conflict("already the current version"));
    }
    gate(
        &st,
        &ctx,
        "plugin.activate",
        &format!("plugin/{id}"),
        json!({"id": id, "name": name, "version": r.version, "from": cur}),
    )
}

pub async fn delete_plugin(State(st): State<St>, ctx: Ctx, Path(id): Path<String>) -> ApiResult<Response> {
    ctx.require(ADMIN)?;
    {
        let c = st.cat.conn();
        let n: i64 = c.query_row("SELECT COUNT(*) FROM plugins WHERE id = ?1", [&id], |r| r.get(0))?;
        if n == 0 {
            return Err(ApiError::not_found());
        }
        let used = plugin_manager::sources_using(&c, &id).map_err(merr)?;
        if used > 0 {
            return Err(ApiError::conflict(format!(
                "{used} source(s) still use this plugin's kinds: delete them first"
            )));
        }
    }
    gate(&st, &ctx, "plugin.remove", &format!("plugin/{id}"), json!({"id": id}))
}

// ---------------------------------------------------------------- publisher keys

pub async fn list_keys(State(st): State<St>, ctx: Ctx) -> ApiResult<Json<Value>> {
    ctx.require(&["admin", "security_officer", "operator"])?;
    let mut out: Vec<Value> = bundle::load_project_keys(&st.plugin_paths().keys)
        .iter()
        .map(|k| {
            json!({"fingerprint": plugin_manager::key_id(k), "publisher": k.publisher, "name": k.name,
                   "public_key": bundle::public_key_pem(&k.point), "builtin": true})
        })
        .collect();
    let c = st.cat.conn();
    let rows = c
        .prepare("SELECT fingerprint, publisher, public_key, added_by, approved_by, added_at FROM plugin_keys ORDER BY added_at")?
        .query_map([], |r| {
            Ok(json!({"fingerprint": r.get::<_, String>(0)?, "publisher": r.get::<_, String>(1)?,
                      "public_key": r.get::<_, String>(2)?, "added_by": r.get::<_, String>(3)?,
                      "approved_by": r.get::<_, Option<String>>(4)?, "added_at": r.get::<_, i64>(5)?, "builtin": false}))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    out.extend(rows);
    Ok(Json(Value::Array(out)))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyReq {
    publisher: String,
    public_key: String,
}

pub async fn add_key(State(st): State<St>, ctx: Ctx, crate::J(r): crate::J<KeyReq>) -> ApiResult<Response> {
    ctx.require(ADMIN)?;
    let p = &r.publisher;
    let ok = (2..=32).contains(&p.len())
        && p.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !p.starts_with('-');
    if !ok {
        return Err(ApiError::bad("publisher: [a-z0-9-]{2,32}"));
    }
    if p == bundle::PROJECT_PUBLISHER {
        return Err(ApiError::bad(
            "publisher: reserved for the project's own keys (shipped with the image)",
        ));
    }
    if r.public_key.len() > 4096 {
        return Err(ApiError::bad("public_key: too long"));
    }
    let point = bundle::parse_public_key(&r.public_key).map_err(ApiError::bad)?;
    let fp = format!("sha256:{}", bundle::fingerprint(&point));
    let exists = st
        .cat
        .conn()
        .query_row("SELECT 1 FROM plugin_keys WHERE fingerprint = ?1", [&fp], |_| Ok(()))
        .optional()?;
    if exists.is_some()
        || bundle::load_project_keys(&st.plugin_paths().keys)
            .iter()
            .any(|k| k.point == point)
    {
        return Err(ApiError::conflict("this key is already trusted"));
    }
    gate(
        &st,
        &ctx,
        "plugin_key.add",
        &format!("plugin-key/{fp}"),
        json!({"publisher": p, "public_key": bundle::public_key_pem(&point), "fingerprint": fp}),
    )
}

pub async fn delete_key(State(st): State<St>, ctx: Ctx, Path(fp): Path<String>) -> ApiResult<Response> {
    ctx.require(ADMIN)?;
    if bundle::load_project_keys(&st.plugin_paths().keys)
        .iter()
        .any(|k| plugin_manager::key_id(k) == fp)
    {
        return Err(ApiError::conflict(
            "project keys come with the image and cannot be removed here",
        ));
    }
    let publisher: String = st
        .cat
        .conn()
        .query_row("SELECT publisher FROM plugin_keys WHERE fingerprint = ?1", [&fp], |r| {
            r.get(0)
        })
        .optional()?
        .ok_or_else(ApiError::not_found)?;
    gate(
        &st,
        &ctx,
        "plugin_key.remove",
        &format!("plugin-key/{fp}"),
        json!({"fingerprint": fp, "publisher": publisher}),
    )
}

// ---------------------------------------------------------------- quorum execution

fn s<'a>(p: &'a Value, k: &str) -> ApiResult<&'a str> {
    p[k].as_str()
        .ok_or_else(|| ApiError::bad(format!("quorum params: missing {k}")))
}

/// Approved plugin actions (inside the approval transaction).
pub fn execute(c: &Connection, action: &str, p: &Value, approver: &str, requested_by: &str) -> ApiResult<bool> {
    match action {
        "plugin.install" => {
            plugin_manager::approve_install(c, s(p, "id")?, s(p, "version")?, s(p, "sha256")?).map_err(merr)?
        }
        "plugin.disable" => {
            c.execute("UPDATE plugins SET enabled = 0 WHERE id = ?1", [s(p, "id")?])?;
        }
        "plugin.activate" => {
            let (id, v) = (s(p, "id")?, s(p, "version")?);
            let state: Option<String> = c
                .query_row(
                    "SELECT state FROM plugins WHERE id = ?1 AND version = ?2",
                    params![id, v],
                    |r| r.get(0),
                )
                .optional()?;
            if state.as_deref() != Some("installed") {
                return Err(ApiError::conflict("that version is no longer installed"));
            }
            c.execute("UPDATE plugins SET current = 0 WHERE id = ?1", [id])?;
            c.execute(
                "UPDATE plugins SET current = 1 WHERE id = ?1 AND version = ?2",
                params![id, v],
            )?;
        }
        "plugin.remove" => {
            let id = s(p, "id")?;
            if plugin_manager::sources_using(c, id).map_err(merr)? > 0 {
                return Err(ApiError::conflict("sources still use this plugin's kinds"));
            }
            c.execute(
                "UPDATE plugins SET state = 'rejected' WHERE id = ?1 AND state = 'pending'",
                [id],
            )?;
            c.execute(
                "UPDATE plugins SET state = 'removing', current = 0, enabled = 0 WHERE id = ?1 AND state IN ('installed','approved','failed')",
                [id],
            )?;
        }
        "plugin_key.add" => {
            c.execute(
                "INSERT INTO plugin_keys (fingerprint, publisher, public_key, added_by, approved_by, added_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    s(p, "fingerprint")?,
                    s(p, "publisher")?,
                    s(p, "public_key")?,
                    requested_by,
                    approver,
                    catalog::now()
                ],
            )?;
        }
        "plugin_key.remove" => {
            c.execute("DELETE FROM plugin_keys WHERE fingerprint = ?1", [s(p, "fingerprint")?])?;
        }
        _ => return Ok(false),
    }
    Ok(true)
}

/// After an approved plugin action: wake the installer (`.trigger` in the staging dir).
pub fn after_approve(st: &St, action: &str) {
    if matches!(action, "plugin.install" | "plugin.activate" | "plugin.remove") {
        let t = st.plugin_paths().staging.join(".trigger");
        if let Err(e) = std::fs::write(&t, catalog::now().to_string()) {
            eprintln!("<4>web-api: cannot touch {}: {e}", t.display());
        }
    }
}

/// A rejected / expired install request: the upload is rejected and its staged files removed.
pub fn after_reject(st: &St, action: &str, p: &Value) {
    if action != "plugin.install" {
        return;
    }
    let (Some(id), Some(v), Some(sha)) = (p["id"].as_str(), p["version"].as_str(), p["sha256"].as_str()) else {
        return;
    };
    let _ = st.cat.conn().execute(
        "UPDATE plugins SET state = 'rejected' WHERE id = ?1 AND version = ?2 AND state = 'pending'",
        params![id, v],
    );
    let (b, s) = plugin_manager::staged_paths(&st.plugin_paths().staging, sha);
    let _ = std::fs::remove_file(b);
    let _ = std::fs::remove_file(s);
}

// ---------------------------------------------------------------- plugin sources

/// The current plugin providing `plugin:<kind>` (installed + enabled), its kind spec.
pub fn kind_spec(c: &Connection, source_kind: &str) -> ApiResult<(Current, KindSpec)> {
    let k = source_kind
        .strip_prefix("plugin:")
        .ok_or_else(|| ApiError::bad("not a plugin kind"))?;
    let cur = plugin_manager::current_for_kind(c, k)
        .map_err(merr)?
        .ok_or_else(|| ApiError::bad(format!("kind: no installed plugin provides {source_kind}")))?;
    if !cur.enabled {
        return Err(ApiError::bad(format!("kind: plugin {} is disabled", cur.id)));
    }
    let spec = cur.manifest.kinds.iter().find(|x| x.kind == k).cloned().unwrap();
    Ok((cur, spec))
}

fn hostname_ok(s: &str) -> bool {
    if s.parse::<std::net::IpAddr>().is_ok() {
        return true;
    }
    (1..=253).contains(&s.len())
        && s.split('.').all(|l| {
            (1..=63).contains(&l.len())
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

fn check_prop(name: &str, sch: &Value, v: &Value) -> ApiResult<()> {
    let err = |m: String| Err(ApiError::bad(format!("{name}: {m}")));
    if let Some(e) = sch["enum"].as_array() {
        if !e.contains(v) {
            return err("not one of the allowed values".into());
        }
    }
    match sch["type"].as_str().unwrap_or("string") {
        "string" => {
            let Some(s) = v.as_str() else {
                return err("must be a string".into());
            };
            let max = sch["maxLength"].as_u64().unwrap_or(4096) as usize;
            let min = sch["minLength"].as_u64().unwrap_or(0) as usize;
            if s.chars().count() > max || s.chars().count() < min {
                return err(format!("length must be {min}..={max}"));
            }
            if s.contains('\0') {
                return err("must not contain NUL".into());
            }
            if let Some(p) = sch["pattern"].as_str() {
                let re = regex::RegexBuilder::new(p)
                    .size_limit(1 << 20)
                    .build()
                    .map_err(|_| ApiError::bad(format!("{name}: the plugin's pattern is invalid")))?;
                if !re.is_match(s) {
                    return err(format!("must match {p}"));
                }
            }
            match sch["format"].as_str() {
                Some("hostname") if !hostname_ok(s) => return err("not a host name or IP address".into()),
                Some("port") if !s.parse::<u16>().is_ok_and(|p| p > 0) => return err("not a port".into()),
                _ => {}
            }
        }
        "integer" => {
            let Some(n) = v.as_i64() else {
                return err("must be an integer".into());
            };
            let (lo, hi) = if sch["format"] == "port" {
                (1, 65535)
            } else {
                (i64::MIN, i64::MAX)
            };
            let lo = sch["minimum"].as_i64().unwrap_or(lo).max(lo);
            let hi = sch["maximum"].as_i64().unwrap_or(hi).min(hi);
            if n < lo || n > hi {
                return err(format!("must be in {lo}..={hi}"));
            }
        }
        "boolean" if !v.is_boolean() => return err("must be true or false".into()),
        "boolean" => {}
        "array" => {
            let Some(a) = v.as_array() else {
                return err("must be a list".into());
            };
            if a.len() > sch["maxItems"].as_u64().unwrap_or(1000) as usize {
                return err("too many items".into());
            }
            let items = if sch["items"].is_object() {
                sch["items"].clone()
            } else {
                json!({"type": "string"})
            };
            if items["type"] != "string" {
                return err("only lists of strings are supported".into());
            }
            for x in a {
                check_prop(name, &items, x)?;
            }
        }
        t => return err(format!("unsupported schema type {t}")),
    }
    Ok(())
}

/// Validates `v` against the contract's JSON-Schema subset (object of scalar
/// properties / string arrays; unknown properties refused). `skip` = properties not
/// checked (write-only secrets kept from the stored config).
pub fn check_schema(schema: &Value, v: &Value, what: &str, skip: &[&str]) -> ApiResult<()> {
    let Some(o) = v.as_object() else {
        return Err(ApiError::bad(format!("{what}: must be an object")));
    };
    if v.to_string().len() > 64 << 10 {
        return Err(ApiError::bad(format!("{what}: too large")));
    }
    let props = schema["properties"].as_object().cloned().unwrap_or_default();
    for (k, x) in o {
        let Some(sch) = props.get(k) else {
            return Err(ApiError::bad(format!("{what}.{k}: unknown property")));
        };
        if x.is_null() {
            continue;
        }
        check_prop(&format!("{what}.{k}"), sch, x)?;
    }
    for r in schema["required"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
    {
        if !skip.contains(&r) && o.get(r).is_none_or(Value::is_null) {
            return Err(ApiError::bad(format!("{what}.{r}: required")));
        }
    }
    Ok(())
}

/// Values of the config fields the kind's endpoints point at (host/port).
fn endpoint_values(spec: &KindSpec, v: &Value) -> Vec<Value> {
    spec.endpoints
        .iter()
        .flat_map(|e| [Some(e.host.as_str()), e.port.as_deref()])
        .flatten()
        .map(|p| v.pointer(p).cloned().unwrap_or(Value::Null))
        .collect()
}

/// Plugin source config as stored: validated, secrets sealed to the scheduler.
/// `old` (update): omitted secrets are kept unless an endpoint field changed.
pub fn sealed_plugin_config(
    pk: &SealKey,
    id: i64,
    spec: &KindSpec,
    mut cfg: Value,
    old: Option<&Value>,
) -> ApiResult<Value> {
    if !cfg.is_object() {
        return Err(ApiError::bad("config: must be an object"));
    }
    let secrets: Vec<&str> = spec.secret_fields.iter().map(String::as_str).collect();
    let o = cfg.as_object_mut().unwrap();
    o.retain(|_, v| !v.is_null() && v != "");
    let missing: Vec<&str> = secrets.iter().copied().filter(|f| !o.contains_key(*f)).collect();
    check_schema(&spec.config_schema, &cfg, "config", &missing)?;
    if let Some(old) = old {
        let moved = endpoint_values(spec, old) != endpoint_values(spec, &cfg);
        for f in &missing {
            if let Some(x) = old.get(*f).filter(|x| x.is_string()) {
                if moved {
                    return Err(ApiError::bad(format!(
                        "config.{f}: required when the endpoint (host/port) changes"
                    )));
                }
                cfg[*f] = x.clone();
            }
        }
    }
    let req: Vec<&str> = spec.config_schema["required"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect();
    for f in &missing {
        if req.contains(f) && cfg.get(*f).is_none() {
            return Err(ApiError::bad(format!("config.{f}: required")));
        }
    }
    pk.seal_all_with(&source_owner(id), &mut cfg, &secrets)?;
    Ok(cfg)
}

/// The public form of a stored plugin config: secrets replaced by `<field>_set`.
pub fn public_plugin_config(c: &Connection, kind: &str, raw: &str) -> Value {
    let mut v: Value = serde_json::from_str(raw).unwrap_or_default();
    let fields: Vec<String> = kind
        .strip_prefix("plugin:")
        .and_then(|k| {
            let mut st = c
                .prepare("SELECT manifest FROM plugins WHERE state != 'rejected'")
                .ok()?;
            let rows = st.query_map([], |r| r.get::<_, String>(0)).ok()?;
            let mut f = Vec::new();
            for m in rows.flatten() {
                if let Ok(m) = serde_json::from_str::<Manifest>(&m) {
                    for ks in m.kinds.iter().filter(|x| x.kind == k) {
                        f.extend(ks.secret_fields.clone());
                    }
                }
            }
            Some(f)
        })
        .unwrap_or_default();
    if let Some(o) = v.as_object_mut() {
        let mut add = Map::new();
        let mut all: Vec<String> = fields.clone();
        all.extend(catalog::secret::SECRET_FIELDS.iter().map(|s| s.to_string()));
        all.sort();
        all.dedup();
        for f in &all {
            let set = o
                .remove(f.as_str())
                .is_some_and(|x| x.as_str().is_some_and(|s| !s.is_empty()));
            if set || fields.contains(f) {
                add.insert(format!("{f}_set"), json!(set));
            }
        }
        o.extend(add);
    }
    v
}

/// Creates a plugin source (insert, then seal with the row id, one transaction).
pub fn create_source(st: &St, tenant: &str, kind: &str, name: &str, cfg: Value) -> ApiResult<i64> {
    let pk = st.seal_key()?;
    let mut c = st.cat.conn();
    let (_, spec) = kind_spec(&c, kind)?;
    if c.query_row("SELECT 1 FROM tenants WHERE name = ?1", [tenant], |_| Ok(()))
        .optional()?
        .is_none()
    {
        return Err(ApiError::bad("tenant: does not exist"));
    }
    crate::replication::refuse_replicated(&c, tenant)?;
    let tx = c.transaction()?;
    tx.execute(
        "INSERT INTO sources (tenant, kind, name, config) VALUES (?1, ?2, ?3, '{}')",
        params![tenant, kind, name],
    )?;
    let id = tx.last_insert_rowid();
    let v = sealed_plugin_config(&pk, id, &spec, cfg, None)?;
    tx.execute(
        "UPDATE sources SET config = ?2 WHERE id = ?1",
        params![id, v.to_string()],
    )?;
    tx.commit()?;
    Ok(id)
}

pub fn update_source(st: &St, id: i64, kind: &str, name: &str, cfg: Value) -> ApiResult<()> {
    let pk = st.seal_key()?;
    let c = st.cat.conn();
    let (_, spec) = kind_spec(&c, kind)?;
    let old: String = c.query_row("SELECT config FROM sources WHERE id = ?1", [id], |r| r.get(0))?;
    let old: Value = serde_json::from_str(&old).unwrap_or_default();
    let v = sealed_plugin_config(&pk, id, &spec, cfg, Some(&old))?;
    c.execute(
        "UPDATE sources SET name = ?2, config = ?3 WHERE id = ?1",
        params![id, name, v.to_string()],
    )?;
    Ok(())
}

/// Group guests of a plugin source: guest ids if the kind lists guests, else none.
pub fn check_guests(c: &Connection, kind: &str, guests: &mut Vec<Value>) -> ApiResult<()> {
    let k = kind.strip_prefix("plugin:").unwrap_or_default();
    let cur = plugin_manager::current_for_kind(c, k).map_err(merr)?;
    let lists = cur
        .as_ref()
        .and_then(|c| c.manifest.kinds.iter().find(|x| x.kind == k))
        .is_some_and(|s| s.guests.as_ref().is_some_and(|g| g["list"] == true));
    if !lists {
        if !guests.is_empty() {
            return Err(ApiError::bad(
                "guests: this plugin kind has no guests (the source is backed up as a whole)",
            ));
        }
        return Ok(());
    }
    for g in guests.iter() {
        if !g.as_str().is_some_and(plugin_proto::valid_guest_id) {
            return Err(ApiError::bad("guests: guest ids [A-Za-z0-9._-]{1,64}"));
        }
    }
    guests.sort_by_key(|g| g.as_str().unwrap_or_default().to_owned());
    guests.dedup();
    Ok(())
}

/// A plugin source of the tenant: (kind spec, plugin current) for job checks.
pub fn source_of(c: &Connection, tenant: &str, id: i64) -> ApiResult<(Current, KindSpec)> {
    let kind: String = c
        .query_row(
            "SELECT kind FROM sources WHERE id = ?1 AND tenant = ?2",
            params![id, tenant],
            |r| r.get(0),
        )
        .optional()?
        .ok_or_else(|| ApiError::bad("source_id: no such source in this tenant"))?;
    if !kind.starts_with("plugin:") {
        return Err(ApiError::bad("source_id: not a plugin source"));
    }
    kind_spec(c, &kind)
}
