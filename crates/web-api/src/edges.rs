//! Edge proxies for roaming agents (Phase 26, docs/edge.md). Admin only, every
//! change audited. `POST /edges` registers an edge VM and returns a one-time
//! enrollment token (24 h, shown once, digest sealed to the scheduler, bound to
//! edge id + control address); `POST /edges/{id}/enroll` queues the scheduler's
//! `edge_enroll` job that proves it to the edge. Agents are routed through an edge
//! with `PUT /agents/{id}/edge` (direct first, then the edge).

use crate::auth::Ctx;
use crate::settings::queue;
use crate::{validate, ApiError, ApiResult, St, J};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use catalog::rusqlite::{params, OptionalExtension};
use catalog::secret::edge_token_location;
use serde::Deserialize;
use serde_json::{json, Value};

const ADMIN: &[&str] = &["admin"];
pub const DEFAULT_CONTROL_PORT: u16 = 7445;
pub const DEFAULT_PUBLIC_PORT: u16 = 443;
/// An edge whose control link reported within this many seconds is online.
pub const ONLINE_SECS: i64 = 120;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EdgeReq {
    name: String,
    host: String,
    #[serde(default = "control_port")]
    port: u16,
    public_host: String,
    #[serde(default = "public_port")]
    public_port: u16,
}

fn control_port() -> u16 {
    DEFAULT_CONTROL_PORT
}
fn public_port() -> u16 {
    DEFAULT_PUBLIC_PORT
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentEdgeReq {
    edge_id: Option<String>,
}

/// The console command on the edge; the token is pasted (stdin), never on the command line.
pub const SETUP_COMMAND: &str = "nexus-edge init --token -";

const COLS: &str = "e.id, e.name, e.host, e.port, e.public_host, e.public_port, e.cert_sha256, e.enrolled_at, \
                    e.token_expires, e.last_seen, e.version, e.health, e.log, \
                    (SELECT COUNT(*) FROM agents a WHERE a.edge_id = e.id)";

fn edge_row(r: &catalog::rusqlite::Row) -> catalog::rusqlite::Result<Value> {
    let js = |i: usize| -> catalog::rusqlite::Result<Value> {
        Ok(r.get::<_, Option<String>>(i)?
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or(Value::Null))
    };
    let last_seen: Option<i64> = r.get(9)?;
    Ok(json!({
        "id": r.get::<_, String>(0)?, "name": r.get::<_, String>(1)?, "host": r.get::<_, String>(2)?,
        "port": r.get::<_, i64>(3)?, "public_host": r.get::<_, String>(4)?, "public_port": r.get::<_, i64>(5)?,
        "cert_sha256": r.get::<_, Option<String>>(6)?, "enrolled_at": r.get::<_, Option<i64>>(7)?,
        "token_expires": r.get::<_, Option<i64>>(8)?, "last_seen": last_seen,
        "online": last_seen.is_some_and(|t| catalog::now() - t <= ONLINE_SECS),
        "version": r.get::<_, Option<String>>(10)?, "health": js(11)?,
        "log": match js(12)? { Value::Array(a) => Value::Array(a), _ => json!([]) },
        "agents": r.get::<_, i64>(13)?,
    }))
}

fn edge_value(st: &St, id: &str) -> ApiResult<Option<Value>> {
    Ok(st
        .cat
        .conn()
        .query_row(&format!("SELECT {COLS} FROM edges e WHERE e.id = ?1"), [id], edge_row)
        .optional()?)
}

fn issue_token(st: &St, id: &str, host: &str, port: u16) -> ApiResult<(String, String, i64)> {
    let pk = st.seal_key()?;
    let token = crate::agents::new_token();
    let sealed = pk.seal(&edge_token_location(id, host, port), &agent_proto::token_digest(&token))?;
    Ok((token, sealed, catalog::now() + crate::agents::TOKEN_TTL_SECS))
}

pub async fn list_edges(State(st): State<St>, ctx: Ctx) -> ApiResult<Json<Value>> {
    ctx.require(ADMIN)?;
    let c = st.cat.conn();
    let rows = c
        .prepare(&format!("SELECT {COLS} FROM edges e ORDER BY e.name"))?
        .query_map([], edge_row)?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Json(Value::Array(rows)))
}

pub async fn create_edge(State(st): State<St>, ctx: Ctx, J(r): J<EdgeReq>) -> ApiResult<Response> {
    ctx.require(ADMIN)?;
    validate::name(&r.name, "name")?;
    validate::host(&r.host)?;
    validate::host(&r.public_host)?;
    if r.port == 0 || r.public_port == 0 {
        return Err(ApiError::bad("port, public_port: must be 1..=65535"));
    }
    let id: String = rand::random::<[u8; 8]>().iter().map(|b| format!("{b:02x}")).collect();
    let (token, sealed, expires) = issue_token(&st, &id, &r.host, r.port)?;
    {
        let c = st.cat.conn();
        let dup = c
            .query_row("SELECT 1 FROM edges WHERE name = ?1", [&r.name], |_| Ok(()))
            .optional()?;
        if dup.is_some() {
            return Err(ApiError::conflict("an edge with this name exists"));
        }
        c.execute(
            "INSERT INTO edges (id, name, host, port, public_host, public_port, token_hash, token_expires, created, created_by) \
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
            params![id, r.name, r.host, r.port, r.public_host, r.public_port, sealed, expires, catalog::now(), ctx.name()],
        )?;
    }
    let out = edge_value(&st, &id)?.ok_or_else(ApiError::not_found)?;
    st.audit(ctx.name(), "edge.create", &format!("edge/{id}"), out.clone())?;
    let mut body = out;
    body["token"] = json!(token);
    body["expires"] = json!(expires);
    body["setup"] = json!(SETUP_COMMAND);
    Ok((StatusCode::CREATED, Json(body)).into_response())
}

/// A fresh one-time token (first setup expired, edge VM reinstalled); the old one is void.
pub async fn new_edge_token(State(st): State<St>, ctx: Ctx, Path(id): Path<String>) -> ApiResult<Json<Value>> {
    ctx.require(ADMIN)?;
    let e = edge_value(&st, &id)?.ok_or_else(ApiError::not_found)?;
    let (host, port) = (
        e["host"].as_str().unwrap_or_default(),
        e["port"].as_u64().unwrap_or_default() as u16,
    );
    let (token, sealed, expires) = issue_token(&st, &id, host, port)?;
    st.cat.conn().execute(
        "UPDATE edges SET token_hash = ?2, token_expires = ?3 WHERE id = ?1",
        params![id, sealed, expires],
    )?;
    st.audit(
        ctx.name(),
        "edge.token",
        &format!("edge/{id}"),
        json!({"token_expires": expires, "reenroll": e["enrolled_at"].is_i64()}),
    )?;
    Ok(Json(
        json!({"id": id, "token": token, "expires": expires, "setup": SETUP_COMMAND}),
    ))
}

/// Queues an `edge_enroll` job (appliance job, 202 `{id}`); 409 without a valid token.
pub async fn enroll_edge(State(st): State<St>, ctx: Ctx, Path(id): Path<String>) -> ApiResult<Response> {
    ctx.require(ADMIN)?;
    let valid = {
        let c = st.cat.conn();
        let (has, expires): (bool, Option<i64>) = c
            .query_row(
                "SELECT token_hash IS NOT NULL, token_expires FROM edges WHERE id = ?1",
                [&id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?
            .ok_or_else(ApiError::not_found)?;
        has && expires.is_some_and(|e| e > catalog::now())
    };
    if !valid {
        return Err(ApiError::conflict(
            "no valid enrollment token: create a new token and enter it on the edge console",
        ));
    }
    let job = queue(&st, &ctx, "edge_enroll", json!({"edge_id": id}))?;
    st.audit(ctx.name(), "edge.enroll", &format!("edge/{id}"), json!({"job": job}))?;
    Ok((StatusCode::ACCEPTED, Json(json!({"id": job}))).into_response())
}

pub async fn delete_edge(State(st): State<St>, ctx: Ctx, Path(id): Path<String>) -> ApiResult<Json<Value>> {
    ctx.require(ADMIN)?;
    let e = edge_value(&st, &id)?.ok_or_else(ApiError::not_found)?;
    let agents = {
        let c = st.cat.conn();
        let n = c.execute("UPDATE agents SET edge_id = NULL WHERE edge_id = ?1", [&id])?;
        c.execute("DELETE FROM edges WHERE id = ?1", [&id])?;
        n
    };
    st.audit(
        ctx.name(),
        "edge.delete",
        &format!("edge/{id}"),
        json!({"name": e["name"], "host": e["host"], "public_host": e["public_host"], "agents": agents}),
    )?;
    Ok(Json(json!({"id": id, "agents": agents})))
}

/// Reach an agent via an edge (`null` = direct only).
pub async fn set_agent_edge(
    State(st): State<St>,
    ctx: Ctx,
    Path(id): Path<String>,
    J(r): J<AgentEdgeReq>,
) -> ApiResult<Json<Value>> {
    ctx.require(ADMIN)?;
    let (tenant, old): (String, Option<String>) = st
        .cat
        .conn()
        .query_row("SELECT tenant, edge_id FROM agents WHERE id = ?1", [&id], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .optional()?
        .ok_or_else(ApiError::not_found)?;
    if let Some(e) = &r.edge_id {
        if edge_value(&st, e)?.is_none() {
            return Err(ApiError::bad("edge_id: no such edge"));
        }
    }
    st.cat
        .conn()
        .execute("UPDATE agents SET edge_id = ?2 WHERE id = ?1", params![id, r.edge_id])?;
    st.audit(
        ctx.name(),
        "agent.edge",
        &format!("agent/{id}"),
        json!({"tenant": tenant, "edge": r.edge_id, "old": old}),
    )?;
    let a = crate::agents::agent_value(&st.cat.conn(), &id)?.ok_or_else(ApiError::not_found)?;
    Ok(Json(a))
}
