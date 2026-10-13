//! Fleet enrollment and CSV bulk enrollment (catalog::fleet, docs/agent-protocol.md
//! "Fleet enrollment", manual 04).
//!
//! Fleet secrets are admin-only: `POST /fleets` returns the secret once (the catalog
//! keeps its token digest sealed to the scheduler, like agent tokens), `DELETE`
//! revokes, `/scan` queues a scan now (the scheduler scans every 15 minutes anyway).
//! Candidates (agents a scan found) are accepted or rejected by the tenant's writers.
//! `POST /agents/bulk` registers many agents from a CSV at once and returns their
//! one-time tokens as a CSV (shown once).

use crate::agents::{agent_value, install_command, issue_token, DEFAULT_PORT};
use crate::auth::{Ctx, TENANT_WRITERS};
use crate::{validate, ApiError, ApiResult, St, J};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use catalog::fleet::{self, Rule};
use catalog::rusqlite::{params, Connection, OptionalExtension};
use serde::Deserialize;
use serde_json::{json, Value};

const ADMIN: &[&str] = &["admin"];
const MAX_RULES: usize = 64;
const MAX_BULK: usize = 500;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FleetReq {
    name: String,
    tenant: String,
    expires_days: i64,
    #[serde(default)]
    max_uses: Option<i64>,
    #[serde(default)]
    auto_accept: bool,
    #[serde(default = "default_port")]
    port: u16,
    #[serde(default)]
    ranges: Vec<String>,
    #[serde(default)]
    group: Option<String>,
    #[serde(default)]
    group_rules: Vec<Rule>,
}

fn default_port() -> u16 {
    DEFAULT_PORT
}

fn fleet_json(c: &Connection, f: &fleet::Fleet) -> ApiResult<Value> {
    let (created, created_by): (i64, String) =
        c.query_row("SELECT created, created_by FROM fleets WHERE id = ?1", [&f.id], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })?;
    let awaiting: i64 = c.query_row(
        "SELECT COUNT(*) FROM fleet_candidates WHERE fleet_id = ?1 AND state = 'awaiting'",
        [&f.id],
        |r| r.get(0),
    )?;
    Ok(json!({
        "id": f.id, "name": f.name, "tenant": f.tenant, "created": created, "created_by": created_by,
        "expires": f.expires, "max_uses": f.max_uses, "uses": f.uses, "revoked": f.revoked,
        "auto_accept": f.auto_accept, "port": f.port, "ranges": f.ranges, "group": f.group,
        "group_rules": f.rules, "last_scan": f.last_scan, "awaiting": awaiting,
    }))
}

fn load(c: &Connection, id: &str) -> ApiResult<fleet::Fleet> {
    fleet::load(c, id)?.ok_or_else(ApiError::not_found)
}

/// The template group must be a group of a linux source in the tenant.
fn check_template(c: &Connection, tenant: &str, group: &str, what: &str) -> ApiResult<()> {
    let ok = c
        .query_row(
            "SELECT 1 FROM groups g JOIN sources s ON s.id = g.source_id \
             WHERE g.tenant = ?1 AND g.name = ?2 AND s.kind = 'linux'",
            params![tenant, group],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    if ok {
        Ok(())
    } else {
        Err(ApiError::bad(format!(
            "{what}: {group:?} is no protection group of a linux source in tenant {tenant}"
        )))
    }
}

pub async fn list_fleets(State(st): State<St>, ctx: Ctx) -> ApiResult<Json<Value>> {
    ctx.require(ADMIN)?;
    let c = st.cat.conn();
    let fleets = c
        .prepare(&format!("SELECT {} FROM fleets ORDER BY created DESC", fleet::COLS))?
        .query_map([], fleet::row)?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Json(Value::Array(
        fleets.iter().map(|f| fleet_json(&c, f)).collect::<ApiResult<_>>()?,
    )))
}

pub async fn create_fleet(State(st): State<St>, ctx: Ctx, J(r): J<FleetReq>) -> ApiResult<Response> {
    ctx.require(ADMIN)?;
    validate::name(&r.name, "name")?;
    if !(1..=fleet::MAX_DAYS).contains(&r.expires_days) {
        return Err(ApiError::bad(format!("expires_days: 1..={}", fleet::MAX_DAYS)));
    }
    if r.max_uses.is_some_and(|m| !(1..=100_000).contains(&m)) {
        return Err(ApiError::bad("max_uses: 1..=100000 (or none)"));
    }
    if r.port == 0 {
        return Err(ApiError::bad("port: must be 1..=65535"));
    }
    let ranges: Vec<String> = r
        .ranges
        .iter()
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
        .collect();
    fleet::expand(&ranges).map_err(ApiError::bad)?;
    if r.group_rules.len() > MAX_RULES {
        return Err(ApiError::bad(format!("group_rules: at most {MAX_RULES}")));
    }
    for rule in &r.group_rules {
        let ok = (1..=64).contains(&rule.pattern.len())
            && rule
                .pattern
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-*?".contains(&b));
        if !ok {
            return Err(ApiError::bad("group_rules: pattern must match [A-Za-z0-9._-*?]{1,64}"));
        }
    }
    let id: String = rand::random::<[u8; 8]>().iter().map(|b| format!("{b:02x}")).collect();
    let secret = format!("nxf1.{id}.{}", catalog::auth::new_code());
    let sealed = st
        .seal_key()?
        .seal(&fleet::secret_location(&id), &agent_proto::token_digest(&secret))?;
    let now = catalog::now();
    let out = {
        let c = st.cat.conn();
        crate::vault::refuse(&c, "new agents")?;
        c.query_row("SELECT 1 FROM tenants WHERE name = ?1", [&r.tenant], |_| Ok(()))
            .optional()?
            .ok_or_else(|| ApiError::bad("tenant: does not exist"))?;
        crate::replication::refuse_replicated(&c, &r.tenant)?;
        if let Some(g) = &r.group {
            check_template(&c, &r.tenant, g, "group")?;
        }
        for rule in &r.group_rules {
            check_template(&c, &r.tenant, &rule.group, "group_rules")?;
        }
        c.execute(
            "INSERT INTO fleets (id, tenant, name, secret_hash, created, created_by, expires, max_uses, auto_accept, \
             port, ranges, default_group, group_rules) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)",
            params![
                id,
                r.tenant,
                r.name,
                sealed,
                now,
                ctx.name(),
                now + r.expires_days * 86_400,
                r.max_uses,
                r.auto_accept,
                r.port,
                json!(ranges).to_string(),
                r.group,
                json!(r.group_rules).to_string()
            ],
        )?;
        fleet_json(&c, &load(&c, &id)?)?
    };
    st.audit(ctx.name(), "fleet.create", &format!("fleet/{id}"), out.clone())?;
    let mut body = out;
    body["secret"] = json!(secret);
    body["install"] = json!({
        "linux": "sudo nexus-agent init --fleet-secret -",
        "linux_file": "/etc/nexus-agent/fleet-secret",
        "windows": "msiexec /i nexus-agent-<version>-x64.msi /qn FLEETSECRET=<secret>",
    });
    Ok((StatusCode::CREATED, Json(body)).into_response())
}

pub async fn revoke_fleet(State(st): State<St>, ctx: Ctx, Path(id): Path<String>) -> ApiResult<Json<Value>> {
    ctx.require(ADMIN)?;
    let out = {
        let c = st.cat.conn();
        load(&c, &id)?;
        c.execute("UPDATE fleets SET revoked = 1 WHERE id = ?1", [&id])?;
        fleet_json(&c, &load(&c, &id)?)?
    };
    st.audit(
        ctx.name(),
        "fleet.revoke",
        &format!("fleet/{id}"),
        json!({"tenant": out["tenant"], "name": out["name"], "uses": out["uses"]}),
    )?;
    Ok(Json(out))
}

/// Queues a scan now (202 `{id}`).
pub async fn scan_fleet(State(st): State<St>, ctx: Ctx, Path(id): Path<String>) -> ApiResult<Response> {
    ctx.require(ADMIN)?;
    let now = catalog::now();
    let (job, tenant) = {
        let c = st.cat.conn();
        let f = load(&c, &id)?;
        if let Some(why) = f.unusable(now) {
            return Err(ApiError::conflict(why));
        }
        if f.ranges.is_empty() {
            return Err(ApiError::conflict("the fleet has no address ranges to scan"));
        }
        c.execute(
            "INSERT INTO jobs (kind, tenant, params, state, requested_by, created) VALUES ('fleet_scan', ?1, ?2, 'queued', ?3, ?4)",
            params![f.tenant, json!({"fleet_id": id}).to_string(), ctx.name(), now],
        )?;
        let job = c.last_insert_rowid();
        c.execute("UPDATE fleets SET last_scan = ?2 WHERE id = ?1", params![id, now])?;
        (job, f.tenant)
    };
    st.audit(
        ctx.name(),
        "job.create",
        &format!("job/{job}"),
        json!({"kind": "fleet_scan", "tenant": tenant, "params": {"fleet_id": id}}),
    )?;
    Ok((StatusCode::ACCEPTED, Json(json!({"id": job}))).into_response())
}

const CAND_COLS: &str = "c.id, c.fleet_id, f.name, f.tenant, c.host, c.port, c.hostname, c.os, c.version, \
                         c.first_seen, c.last_seen, c.state, c.agent_id";

fn cand_row(r: &catalog::rusqlite::Row) -> catalog::rusqlite::Result<Value> {
    Ok(json!({
        "id": r.get::<_, i64>(0)?, "fleet_id": r.get::<_, String>(1)?, "fleet": r.get::<_, String>(2)?,
        "tenant": r.get::<_, String>(3)?, "host": r.get::<_, String>(4)?, "port": r.get::<_, i64>(5)?,
        "hostname": r.get::<_, String>(6)?, "os": r.get::<_, String>(7)?, "version": r.get::<_, String>(8)?,
        "first_seen": r.get::<_, i64>(9)?, "last_seen": r.get::<_, i64>(10)?, "state": r.get::<_, String>(11)?,
        "agent_id": r.get::<_, Option<String>>(12)?,
    }))
}

fn candidate(c: &Connection, id: i64) -> ApiResult<Value> {
    c.query_row(
        &format!("SELECT {CAND_COLS} FROM fleet_candidates c JOIN fleets f ON f.id = c.fleet_id WHERE c.id = ?1"),
        [id],
        cand_row,
    )
    .optional()?
    .ok_or_else(ApiError::not_found)
}

pub async fn list_candidates(State(st): State<St>, ctx: Ctx) -> ApiResult<Json<Value>> {
    let c = st.cat.conn();
    let rows = c
        .prepare(&format!(
            "SELECT {CAND_COLS} FROM fleet_candidates c JOIN fleets f ON f.id = c.fleet_id \
             WHERE ?1 IS NULL OR f.tenant = ?1 ORDER BY c.state = 'awaiting' DESC, c.last_seen DESC LIMIT 1000"
        ))?
        .query_map([ctx.scope()], cand_row)?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Json(Value::Array(rows)))
}

fn writable_candidate(st: &St, ctx: &Ctx, id: i64) -> ApiResult<Value> {
    ctx.require(TENANT_WRITERS)?;
    let cand = candidate(&st.cat.conn(), id)?;
    ctx.owns(cand["tenant"].as_str().unwrap_or_default())?;
    if cand["state"] != "awaiting" {
        return Err(ApiError::conflict(format!(
            "the candidate was already {}",
            cand["state"].as_str().unwrap_or_default()
        )));
    }
    Ok(cand)
}

/// Accept: the agent, its source + group from the template, the enrollment job.
pub async fn accept_candidate(State(st): State<St>, ctx: Ctx, Path(id): Path<i64>) -> ApiResult<Json<Value>> {
    let cand = writable_candidate(&st, &ctx, id)?;
    crate::vault::refuse(&st.cat.conn(), "new agents")?;
    let a = fleet::accept(&mut st.cat.conn(), id, ctx.name(), catalog::now())
        .map_err(|e| ApiError::conflict(format!("{e:#}")))?;
    st.audit(
        ctx.name(),
        "fleet.accept",
        &format!("agent/{}", a.agent_id),
        json!({"fleet": cand["fleet_id"], "candidate": id, "tenant": a.tenant, "name": a.name,
               "host": cand["host"], "hostname": cand["hostname"], "group": a.group, "job": a.job}),
    )?;
    Ok(Json(
        json!({"agent_id": a.agent_id, "name": a.name, "group": a.group, "job": a.job}),
    ))
}

pub async fn reject_candidate(State(st): State<St>, ctx: Ctx, Path(id): Path<i64>) -> ApiResult<Json<Value>> {
    let cand = writable_candidate(&st, &ctx, id)?;
    let out = {
        let c = st.cat.conn();
        c.execute(
            "UPDATE fleet_candidates SET state = 'rejected', decided_by = ?2 WHERE id = ?1 AND state = 'awaiting'",
            params![id, ctx.name()],
        )?;
        candidate(&c, id)?
    };
    st.audit(
        ctx.name(),
        "fleet.reject",
        &format!("fleet/{}", cand["fleet_id"].as_str().unwrap_or_default()),
        json!({"candidate": id, "tenant": cand["tenant"], "host": cand["host"], "hostname": cand["hostname"]}),
    )?;
    Ok(Json(out))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BulkReq {
    csv: String,
}

struct BulkRow {
    line: usize,
    host: String,
    tenant: String,
    name: String,
    port: u16,
    group: Option<String>,
}

/// CSV with a header line: `host` and `tenant` required, `name` (default: the
/// host), `port` (default 7444), `group` (template group) optional. No quoting:
/// none of the values may contain a comma anyway. `#` lines and blank lines are skipped.
fn parse_csv(text: &str) -> ApiResult<Vec<BulkRow>> {
    let mut lines = text
        .lines()
        .enumerate()
        .map(|(i, l)| (i + 1, l.trim()))
        .filter(|(_, l)| !l.is_empty() && !l.starts_with('#'));
    let (_, header) = lines.next().ok_or_else(|| ApiError::bad("csv: empty"))?;
    let cols: Vec<String> = header
        .split([',', ';'])
        .map(|c| c.trim().to_ascii_lowercase())
        .collect();
    let col = |n: &str| cols.iter().position(|c| c == n);
    let (Some(h), Some(t)) = (col("host"), col("tenant")) else {
        return Err(ApiError::bad(
            "csv: the header needs the columns host and tenant (optional: name, port, group)",
        ));
    };
    if let Some(c) = cols
        .iter()
        .find(|c| !["host", "tenant", "name", "port", "group"].contains(&c.as_str()))
    {
        return Err(ApiError::bad(format!("csv: unknown column {c:?}")));
    }
    let mut out = Vec::new();
    for (line, l) in lines {
        let f: Vec<&str> = l.split([',', ';']).map(str::trim).collect();
        let get = |i: Option<usize>| i.and_then(|i| f.get(i)).copied().filter(|v| !v.is_empty());
        let err = |m: String| ApiError::bad(format!("line {line}: {m}"));
        let host = get(Some(h)).ok_or_else(|| err("host missing".into()))?.to_owned();
        let tenant = get(Some(t)).ok_or_else(|| err("tenant missing".into()))?.to_owned();
        let name = get(col("name")).unwrap_or(&host).to_owned();
        let port = match get(col("port")) {
            Some(p) => p
                .parse::<u16>()
                .ok()
                .filter(|p| *p != 0)
                .ok_or_else(|| err("port: 1..=65535".into()))?,
            None => DEFAULT_PORT,
        };
        validate::host(&host).map_err(|e| err(e.1))?;
        validate::name(&name, "name").map_err(|e| err(e.1))?;
        out.push(BulkRow {
            line,
            host,
            tenant,
            name,
            port,
            group: get(col("group")).map(str::to_owned),
        });
        if out.len() > MAX_BULK {
            return Err(ApiError::bad(format!("csv: at most {MAX_BULK} agents at once")));
        }
    }
    if out.is_empty() {
        return Err(ApiError::bad("csv: no agents"));
    }
    Ok(out)
}

fn csv_field(v: &Value) -> String {
    match v {
        Value::Null => String::new(),
        Value::String(s) => s.clone(),
        v => v.to_string(),
    }
}

/// All or nothing: every row is checked inside one transaction.
pub async fn bulk_agents(State(st): State<St>, ctx: Ctx, J(r): J<BulkReq>) -> ApiResult<Response> {
    ctx.require(TENANT_WRITERS)?;
    let rows = parse_csv(&r.csv)?;
    for row in &rows {
        ctx.owns(&row.tenant).map_err(|_| {
            ApiError(
                StatusCode::FORBIDDEN,
                format!("line {}: tenant {}: not yours", row.line, row.tenant),
            )
        })?;
    }
    let mut created = Vec::new();
    {
        let mut c = st.cat.conn();
        crate::vault::refuse(&c, "new agents")?;
        let tx = c.transaction()?;
        for row in &rows {
            let err = |m: String| ApiError::bad(format!("line {}: {m}", row.line));
            tx.query_row("SELECT 1 FROM tenants WHERE name = ?1", [&row.tenant], |_| Ok(()))
                .optional()?
                .ok_or_else(|| err(format!("tenant {} does not exist", row.tenant)))?;
            crate::replication::refuse_replicated(&tx, &row.tenant).map_err(|e| err(e.1))?;
            let id: String = rand::random::<[u8; 8]>().iter().map(|b| format!("{b:02x}")).collect();
            let (token, sealed, expires) = issue_token(&st, &id, &row.host, row.port)?;
            tx.execute(
                "INSERT INTO agents (id, tenant, name, host, port, token_hash, token_expires) VALUES (?1,?2,?3,?4,?5,?6,?7)",
                params![id, row.tenant, row.name, row.host, row.port, sealed, expires],
            )
            .map_err(|_| err(format!("an agent named {} exists in tenant {}", row.name, row.tenant)))?;
            if let Some(g) = &row.group {
                check_template(&tx, &row.tenant, g, "group").map_err(|e| err(e.1))?;
                fleet::assign_group(&tx, &row.tenant, &id, &row.name, g).map_err(|_| {
                    err(format!(
                        "a source or group named {} exists in tenant {}",
                        row.name, row.tenant
                    ))
                })?;
            }
            let v = agent_value(&tx, &id)?.ok_or_else(ApiError::not_found)?;
            created.push((v, row.group.clone(), token));
        }
        tx.commit()?;
    }
    let mut csv = String::from("name,tenant,host,port,group,agent_id,token,token_expires,install_command\n");
    let mut agents = Vec::new();
    for (v, group, token) in created {
        st.audit(
            ctx.name(),
            "agent.create",
            &format!("agent/{}", v["id"].as_str().unwrap_or_default()),
            json!({"tenant": v["tenant"], "name": v["name"], "host": v["host"], "port": v["port"],
                   "group": group, "bulk": true}),
        )?;
        csv.push_str(
            &[
                csv_field(&v["name"]),
                csv_field(&v["tenant"]),
                csv_field(&v["host"]),
                csv_field(&v["port"]),
                group.unwrap_or_default(),
                csv_field(&v["id"]),
                token.clone(),
                csv_field(&v["token_expires"]),
                install_command(&token),
            ]
            .join(","),
        );
        csv.push('\n');
        agents.push(v);
    }
    Ok((
        StatusCode::CREATED,
        Json(json!({"created": agents.len(), "agents": agents, "csv": csv})),
    )
        .into_response())
}
