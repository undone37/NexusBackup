//! The tenant directory (#52): an LDAPS server (Active Directory, Samba AD) the scheduler reads daily
//! (`directory_sync`) for the names of domain accounts, so file search names owners of files in VM snapshots that
//! the guest itself only knows by SID.
//!
//! `GET /tenants/{name}/directory`, `PUT /tenants/{name}/directory {directory}` (`null` removes it) and
//! `POST /tenants/{name}/directory/sync` (admins). LDAPS only, the server's certificate (or its CA) pinned; the bind
//! password is write-only, sealed to the scheduler and kept on updates only for the same server, certificate and
//! bind DN. Saving queues a sync. Audited `tenant.directory`.

use crate::auth::Ctx;
use crate::{validate, ApiError, ApiResult, St, J};
use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use axum::Json;
use catalog::rusqlite::{params, Connection, OptionalExtension};
use catalog::secret::tenant_owner;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

/// The stored password stays only for these unchanged.
const BINDING: &[&str] = &["host", "port", "ca_pem", "bind_dn"];

#[derive(Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct DirectoryCfg {
    /// a domain controller (LDAPS)
    host: String,
    #[serde(default = "ldaps")]
    port: u16,
    /// the server's certificate or the CA that issued it (pinned)
    ca_pem: String,
    /// the account to bind as: `nexus@contoso.example` or `CN=…,DC=…`
    bind_dn: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    password: Option<String>,
    /// where users and groups are searched (`DC=contoso,DC=example`)
    base_dn: String,
}

fn ldaps() -> u16 {
    636
}

fn line(s: &str, what: &str, max: usize) -> ApiResult<()> {
    if s.is_empty() || s.len() > max || s.chars().any(char::is_control) {
        return Err(ApiError::bad(format!(
            "{what}: 1..={max} characters, no control characters"
        )));
    }
    Ok(())
}

impl DirectoryCfg {
    fn check(&self) -> ApiResult<()> {
        validate::host(&self.host)?;
        if self.port == 0 {
            return Err(ApiError::bad("port: 1..=65535"));
        }
        if self.ca_pem.len() > 64 << 10 || !self.ca_pem.contains("-----BEGIN CERTIFICATE-----") {
            return Err(ApiError::bad("ca_pem: expected a PEM certificate (at most 64 KiB)"));
        }
        line(&self.bind_dn, "bind_dn", 256)?;
        line(&self.base_dn, "base_dn", 512)?;
        if !self.base_dn.contains('=') {
            return Err(ApiError::bad("base_dn: a DN such as DC=contoso,DC=example"));
        }
        if let Some(p) = &self.password {
            line(p, "password", 256)?;
        }
        Ok(())
    }
}

fn stored(c: &Connection, name: &str) -> ApiResult<Option<Value>> {
    let d: Option<Option<String>> = c
        .query_row("SELECT directory FROM tenants WHERE name = ?1", [name], |r| r.get(0))
        .optional()?;
    let d = d.ok_or_else(ApiError::not_found)?;
    Ok(d.and_then(|s| serde_json::from_str(&s).ok()))
}

/// The config without the password, with `password_set`.
fn public(v: &Value) -> Value {
    let mut out = v.clone();
    if let Some(o) = out.as_object_mut() {
        let set = o.remove("password").is_some_and(|p| p.is_string());
        o.insert("password_set".into(), json!(set));
    }
    out
}

pub async fn get_directory(State(st): State<St>, ctx: Ctx, Path(name): Path<String>) -> ApiResult<Response> {
    ctx.require(&["admin"])?;
    let d = stored(&st.cat.conn(), &name)?;
    Ok(Json(json!({"name": name, "directory": d.as_ref().map(public)})).into_response())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PutReq {
    directory: Option<Value>,
}

fn queue_sync(st: &St, ctx: &Ctx, name: &str) -> ApiResult<i64> {
    let c = st.cat.conn();
    c.execute(
        "INSERT INTO jobs (kind, tenant, params, state, requested_by, created) VALUES ('directory_sync', ?1, '{}', 'queued', ?2, ?3)",
        params![name, ctx.name(), catalog::now()],
    )?;
    Ok(c.last_insert_rowid())
}

pub async fn put_directory(
    State(st): State<St>,
    ctx: Ctx,
    Path(name): Path<String>,
    J(r): J<PutReq>,
) -> ApiResult<Response> {
    ctx.require(&["admin"])?;
    crate::lockdown::refuse(&st.cat.conn(), &name, "tenant changes")?;
    let old = stored(&st.cat.conn(), &name)?;
    let new = match r.directory {
        None | Some(Value::Null) => None,
        Some(v) => {
            let cfg: DirectoryCfg = serde_json::from_value(v).map_err(|e| ApiError::bad(format!("directory: {e}")))?;
            cfg.check()?;
            let mut v = serde_json::to_value(&cfg).map_err(anyhow::Error::from)?;
            if cfg.password.is_none() {
                // the stored (sealed) password only for the same server and account
                let o = old.as_ref().unwrap_or(&Value::Null);
                if !o["password"].is_string() || BINDING.iter().any(|k| o.get(*k) != v.get(*k)) {
                    return Err(ApiError::bad(
                        "directory.password: required when host, port, ca_pem or bind_dn change",
                    ));
                }
                v["password"] = o["password"].clone();
            }
            st.seal_key()?.seal_all(&tenant_owner(&name), &mut v)?;
            Some(v)
        }
    };
    st.cat.conn().execute(
        "UPDATE tenants SET directory = ?2 WHERE name = ?1",
        params![name, new.as_ref().map(Value::to_string)],
    )?;
    // a sync applies the new names (or, without a directory, drops them from the index)
    let job = queue_sync(&st, &ctx, &name)?;
    let shown = new.as_ref().map(public);
    st.audit(
        ctx.name(),
        "tenant.directory",
        &format!("tenant/{name}"),
        json!({"directory": shown}),
    )?;
    Ok(Json(json!({"name": name, "directory": shown, "job": job})).into_response())
}

pub async fn sync(State(st): State<St>, ctx: Ctx, Path(name): Path<String>) -> ApiResult<Response> {
    ctx.require(&["admin"])?;
    if stored(&st.cat.conn(), &name)?.is_none() {
        return Err(ApiError::bad("the tenant has no directory"));
    }
    let job = queue_sync(&st, &ctx, &name)?;
    Ok((axum::http::StatusCode::ACCEPTED, Json(json!({"job": job}))).into_response())
}
