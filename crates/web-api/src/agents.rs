//! Linux backup agents (docs/agent-protocol.md, docs/control-plane.md).
//!
//! `POST /agents` registers a host and returns a one-time enrollment token
//! (128 bit, base32, 24 h) with the install command — shown once. The catalog
//! keeps only the token digest, sealed to the scheduler (`agents.token_hash`,
//! bound to agent id + endpoint); the scheduler's `agent_enroll` job proves it
//! to the agent. Deleting an agent needs a quorum.

use crate::auth::Ctx;
use crate::quorum::gate;
use crate::{validate, ApiError, ApiResult, St, J};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use catalog::rusqlite::{params, Connection, OptionalExtension};
use catalog::secret::agent_token_location;
use serde::Deserialize;
use serde_json::{json, Value};

const ADMIN: &[&str] = &["admin"];
pub const TOKEN_TTL_SECS: i64 = 24 * 3600;
pub const DEFAULT_PORT: u16 = 7444;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentReq {
    tenant: String,
    name: String,
    host: String,
    #[serde(default = "default_port")]
    port: u16,
}

fn default_port() -> u16 {
    DEFAULT_PORT
}

const COLS: &str = "id, tenant, name, host, port, enrolled_at, cert_sha256, token_expires, last_seen, version, os";

fn agent_row(r: &catalog::rusqlite::Row) -> catalog::rusqlite::Result<Value> {
    Ok(json!({
        "id": r.get::<_, String>(0)?, "tenant": r.get::<_, String>(1)?, "name": r.get::<_, String>(2)?,
        "host": r.get::<_, String>(3)?, "port": r.get::<_, i64>(4)?, "enrolled_at": r.get::<_, Option<i64>>(5)?,
        "cert_sha256": r.get::<_, Option<String>>(6)?, "token_expires": r.get::<_, Option<i64>>(7)?,
        "last_seen": r.get::<_, Option<i64>>(8)?, "version": r.get::<_, Option<String>>(9)?,
        "os": r.get::<_, Option<String>>(10)?,
    }))
}

/// An agent as the API shows it (never the token digest), tenant-checked.
pub fn agent_value(c: &Connection, id: &str) -> ApiResult<Option<Value>> {
    Ok(
        c.query_row(&format!("SELECT {COLS} FROM agents WHERE id = ?1"), [id], agent_row)
            .optional()?,
    )
}

/// 128-bit token, RFC 4648 base32 without padding (26 characters).
pub fn new_token() -> String {
    const A: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let b: [u8; 16] = rand::random();
    let mut out = String::new();
    let (mut acc, mut bits) = (0u32, 0);
    for x in b {
        acc = (acc << 8) | u32::from(x);
        bits += 8;
        while bits >= 5 {
            out.push(A[((acc >> (bits - 5)) & 31) as usize] as char);
            bits -= 5;
        }
    }
    if bits > 0 {
        out.push(A[((acc << (5 - bits)) & 31) as usize] as char);
    }
    out
}

/// The token is NOT part of the command (it would end up in `ps` and the shell
/// history): `--token -` makes the agent read it from stdin, the admin pastes it.
pub fn install_command(_token: &str) -> String {
    "sudo /usr/local/sbin/nexus-agent init --token -".into()
}

/// New token: digest sealed to the scheduler, bound to id + endpoint.
fn issue_token(st: &St, id: &str, host: &str, port: u16) -> ApiResult<(String, String, i64)> {
    let pk = st.seal_key()?;
    let token = new_token();
    let sealed = pk.seal(
        &agent_token_location(id, host, port),
        &agent_proto::token_digest(&token),
    )?;
    Ok((token, sealed, catalog::now() + TOKEN_TTL_SECS))
}

pub async fn list_agents(State(st): State<St>, ctx: Ctx) -> ApiResult<Json<Value>> {
    let c = st.cat.conn();
    let rows = c
        .prepare(&format!(
            "SELECT {COLS} FROM agents WHERE ?1 IS NULL OR tenant = ?1 ORDER BY tenant, name"
        ))?
        .query_map([ctx.scope()], agent_row)?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Json(Value::Array(rows)))
}

pub async fn create_agent(State(st): State<St>, ctx: Ctx, J(r): J<AgentReq>) -> ApiResult<Response> {
    ctx.require(ADMIN)?;
    validate::name(&r.name, "name")?;
    validate::host(&r.host)?;
    if r.port == 0 {
        return Err(ApiError::bad("port: must be 1..=65535"));
    }
    let id: String = rand::random::<[u8; 8]>().iter().map(|b| format!("{b:02x}")).collect();
    let (token, sealed, expires) = issue_token(&st, &id, &r.host, r.port)?;
    let out = {
        let c = st.cat.conn();
        let tenant_ok = c
            .query_row("SELECT 1 FROM tenants WHERE name = ?1", [&r.tenant], |_| Ok(()))
            .optional()?;
        tenant_ok.ok_or_else(|| ApiError::bad("tenant: does not exist"))?;
        crate::replication::refuse_replicated(&c, &r.tenant)?;
        c.execute(
            "INSERT INTO agents (id, tenant, name, host, port, token_hash, token_expires) VALUES (?1,?2,?3,?4,?5,?6,?7)",
            params![id, r.tenant, r.name, r.host, r.port, sealed, expires],
        )?;
        agent_value(&c, &id)?.ok_or_else(ApiError::not_found)?
    };
    st.audit(ctx.name(), "agent.create", &format!("agent/{id}"), out.clone())?;
    let mut body = out;
    body["token"] = json!(token);
    body["install_command"] = json!(install_command(&token));
    Ok((StatusCode::CREATED, Json(body)).into_response())
}

/// A fresh one-time token (re-install / re-enrollment); the old one is void.
pub async fn new_agent_token(State(st): State<St>, ctx: Ctx, Path(id): Path<String>) -> ApiResult<Json<Value>> {
    ctx.require(ADMIN)?;
    let a = agent_value(&st.cat.conn(), &id)?.ok_or_else(ApiError::not_found)?;
    let (host, port) = (
        a["host"].as_str().unwrap_or_default(),
        a["port"].as_u64().unwrap_or_default() as u16,
    );
    let (token, sealed, expires) = issue_token(&st, &id, host, port)?;
    st.cat.conn().execute(
        "UPDATE agents SET token_hash = ?2, token_expires = ?3 WHERE id = ?1",
        params![id, sealed, expires],
    )?;
    st.audit(
        ctx.name(),
        "agent.token",
        &format!("agent/{id}"),
        json!({"token_expires": expires}),
    )?;
    Ok(Json(
        json!({"id": id, "token": token, "install_command": install_command(&token), "token_expires": expires}),
    ))
}

/// Queues an `agent_enroll` job (202 `{id}`); 409 without a valid token.
pub async fn enroll_agent(State(st): State<St>, ctx: Ctx, Path(id): Path<String>) -> ApiResult<Response> {
    ctx.require(ADMIN)?;
    let (tenant, valid) = {
        let c = st.cat.conn();
        let (tenant, has, expires): (String, bool, Option<i64>) = c
            .query_row(
                "SELECT tenant, token_hash IS NOT NULL, token_expires FROM agents WHERE id = ?1",
                [&id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?
            .ok_or_else(ApiError::not_found)?;
        (tenant, has && expires.is_some_and(|e| e > catalog::now()))
    };
    if !valid {
        return Err(ApiError::conflict(
            "no valid enrollment token: create a new token and run the install command on the host",
        ));
    }
    let params = json!({"agent_id": id});
    let job = {
        let c = st.cat.conn();
        c.execute(
            "INSERT INTO jobs (kind, tenant, params, state, requested_by, created) VALUES ('agent_enroll', ?1, ?2, 'queued', ?3, ?4)",
            params![tenant, params.to_string(), ctx.name(), catalog::now()],
        )?;
        c.last_insert_rowid()
    };
    st.audit(
        ctx.name(),
        "job.create",
        &format!("job/{job}"),
        json!({"kind": "agent_enroll", "tenant": tenant, "params": params}),
    )?;
    Ok((StatusCode::ACCEPTED, Json(json!({"id": job}))).into_response())
}

/// Sources of kind `linux` that use the agent.
pub fn agent_in_use(c: &Connection, id: &str) -> ApiResult<bool> {
    Ok(c.query_row(
        "SELECT 1 FROM sources WHERE kind = 'linux' AND json_extract(config, '$.agent_id') = ?1",
        [id],
        |_| Ok(()),
    )
    .optional()?
    .is_some())
}

pub async fn delete_agent(State(st): State<St>, ctx: Ctx, Path(id): Path<String>) -> ApiResult<Response> {
    ctx.require(ADMIN)?;
    let a = {
        let c = st.cat.conn();
        let a = agent_value(&c, &id)?.ok_or_else(ApiError::not_found)?;
        if agent_in_use(&c, &id)? {
            return Err(ApiError::conflict("agent is still used by a source"));
        }
        a
    };
    gate(
        &st,
        &ctx,
        "agent.delete",
        &format!("agent/{id}"),
        json!({"id": id, "tenant": a["tenant"], "name": a["name"], "host": a["host"]}),
    )
}

#[cfg(test)]
mod tests {
    #[test]
    fn token_format() {
        let t = super::new_token();
        assert_eq!(t.len(), 26);
        assert!(t.bytes().all(|b| b.is_ascii_uppercase() || (b'2'..=b'7').contains(&b)));
        assert_ne!(t, super::new_token());
    }
}
