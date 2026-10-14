//! Linux backup agents (docs/agent-protocol.md, docs/control-plane.md).
//!
//! `POST /agents` registers a host and returns a one-time enrollment token
//! (128 bit, base32, 24 h) with the install command — shown once. The catalog
//! keeps only the token digest, sealed to the scheduler (`agents.token_hash`,
//! bound to agent id + endpoint); the scheduler's `agent_enroll` job proves it
//! to the agent. Deleting an agent needs a quorum.

use crate::auth::{Ctx, TENANT_WRITERS};
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

const COLS: &str = "id, tenant, name, host, port, enrolled_at, cert_sha256, token_expires, last_seen, version, os, \
                    limits, cert_issued, cert_expires, cert_sha256_next IS NOT NULL, reachable, last_poll, power, \
                    ui_policy, ui_policy_version, ui_policy_seen, laptop, missed_at, last_request, edge_id, via, edge_pushed, \
                    arch, install, gui_version, caps, tags, update_target, update_state, update_error, \
                    update_attempts, update_at";

fn agent_row(r: &catalog::rusqlite::Row) -> catalog::rusqlite::Result<Value> {
    Ok(json!({
        "id": r.get::<_, String>(0)?, "tenant": r.get::<_, String>(1)?, "name": r.get::<_, String>(2)?,
        "host": r.get::<_, String>(3)?, "port": r.get::<_, i64>(4)?, "enrolled_at": r.get::<_, Option<i64>>(5)?,
        "cert_sha256": r.get::<_, Option<String>>(6)?, "token_expires": r.get::<_, Option<i64>>(7)?,
        "last_seen": r.get::<_, Option<i64>>(8)?, "version": r.get::<_, Option<String>>(9)?,
        "os": r.get::<_, Option<String>>(10)?,
        // Phase 15f: limits sent with every backup, certificate validity / renewal in progress
        "limits": serde_json::from_str::<Value>(&r.get::<_, String>(11)?).unwrap_or_default(),
        "cert_issued": r.get::<_, Option<i64>>(12)?, "cert_expires": r.get::<_, Option<i64>>(13)?,
        "cert_renewal_pending": r.get::<_, bool>(14)?,
        // Phase 24a endpoint status (crate::endpoint, scheduler endpoint.rs)
        "reachable": r.get::<_, Option<bool>>(15)?, "last_poll": r.get::<_, Option<i64>>(16)?,
        "power": json_col(r, 17)?,
        "ui_policy": json_col(r, 18)?, "ui_policy_version": r.get::<_, i64>(19)?,
        "ui_policy_seen": r.get::<_, Option<i64>>(20)?, "laptop": json_col(r, 21)?,
        "missed_at": r.get::<_, Option<i64>>(22)?, "last_request": json_col(r, 23)?,
        // Phase 26: reach via an edge proxy (crate::edges), route of the last session
        "edge_id": r.get::<_, Option<String>>(24)?, "via": r.get::<_, Option<String>>(25)?,
        "edge_pushed": r.get::<_, Option<String>>(26)?,
        // Phase 27: host facts (protocol v1.8) and the update state
        "arch": r.get::<_, Option<String>>(27)?, "install": r.get::<_, Option<String>>(28)?,
        "gui_version": r.get::<_, Option<String>>(29)?,
        "protocol": r.get::<_, Option<String>>(30)?.map(|c| {
            let caps: Vec<String> = serde_json::from_str(&c).unwrap_or_default();
            agent_proto::release::protocol_of(&caps)
        }),
        "tags": json_col(r, 31)?,
        "update_target": r.get::<_, Option<String>>(32)?, "update_state": r.get::<_, Option<String>>(33)?,
        "update_error": r.get::<_, Option<String>>(34)?, "update_attempts": r.get::<_, i64>(35)?,
        "update_at": r.get::<_, Option<i64>>(36)?,
    }))
}

fn json_col(r: &catalog::rusqlite::Row, i: usize) -> catalog::rusqlite::Result<Value> {
    Ok(r.get::<_, Option<String>>(i)?
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or(Value::Null))
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
    catalog::auth::new_code()
}

/// The token is NOT part of the command (it would end up in `ps` and the shell
/// history): `--token -` makes the agent read it from stdin, the admin pastes it. Packages
/// install /usr/bin/nexus-agent; bundle installs (/usr/local/sbin) on EL/Fedora need the full
/// path with sudo (manual 04).
pub fn install_command(_token: &str) -> String {
    "sudo nexus-agent init --token -".into()
}

/// New token: digest sealed to the scheduler, bound to id + endpoint.
pub(crate) fn issue_token(st: &St, id: &str, host: &str, port: u16) -> ApiResult<(String, String, i64)> {
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
    ctx.require(TENANT_WRITERS)?;
    ctx.owns(&r.tenant)?;
    crate::vault::refuse(&st.cat.conn(), "new agents")?;
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
/// Re-enrollment of an enrolled agent (it lost its key, the host was reinstalled)
/// keeps the agent id: sources, groups and `host-<id>` snapshots stay attached,
/// the new certificate replaces the pinned one when the enrollment job ran.
pub async fn new_agent_token(State(st): State<St>, ctx: Ctx, Path(id): Path<String>) -> ApiResult<Json<Value>> {
    ctx.require(TENANT_WRITERS)?;
    let a = agent_value(&st.cat.conn(), &id)?.ok_or_else(ApiError::not_found)?;
    ctx.owns(a["tenant"].as_str().unwrap_or_default())?;
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
        json!({"token_expires": expires, "reenroll": a["enrolled_at"].is_i64()}),
    )?;

    Ok(Json(
        json!({"id": id, "token": token, "install_command": install_command(&token), "token_expires": expires}),
    ))
}

/// Queues an `agent_enroll` job (202 `{id}`); 409 without a valid token.
pub async fn enroll_agent(State(st): State<St>, ctx: Ctx, Path(id): Path<String>) -> ApiResult<Response> {
    ctx.require(TENANT_WRITERS)?;
    let (tenant, valid, fleet) = {
        let c = st.cat.conn();
        let (tenant, has, expires, fleet, enrolled): (String, bool, Option<i64>, Option<String>, bool) = c
            .query_row(
                "SELECT tenant, token_hash IS NOT NULL, token_expires, fleet_id, cert_sha256 IS NOT NULL FROM agents WHERE id = ?1",
                [&id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )
            .optional()?
            .ok_or_else(ApiError::not_found)?;
        // accepted from a fleet and not enrolled yet: the fleet secret, while valid (crate::fleet)
        let fleet = match fleet {
            Some(f) if !enrolled => catalog::fleet::load(&c, &f)?.filter(|f| f.invalid(catalog::now()).is_none()),
            _ => None,
        };
        (tenant, has && expires.is_some_and(|e| e > catalog::now()), fleet)
    };
    ctx.owns(&tenant)?;
    let params = match (valid, fleet) {
        (true, _) => json!({"agent_id": id}),
        (false, Some(f)) => json!({"agent_id": id, "fleet_id": f.id}),
        (false, None) => {
            return Err(ApiError::conflict(
                "no valid enrollment token: create a new token and run the install command on the host",
            ))
        }
    };
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
    ctx.require(TENANT_WRITERS)?;
    let a = {
        let c = st.cat.conn();
        let a = agent_value(&c, &id)?.ok_or_else(ApiError::not_found)?;
        ctx.owns(a["tenant"].as_str().unwrap_or_default())?;
        crate::lockdown::refuse(&c, a["tenant"].as_str().unwrap_or_default(), "deletes")?;
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
