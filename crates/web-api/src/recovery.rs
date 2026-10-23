//! Restore tests and recovery plans (Phase 25, docs/control-plane.md "Restore
//! tests and recovery plans"; executed by the scheduler, crates/scheduler/src/recovery.rs).
//!
//! - `GET /restore-tests?tenant=&source=&limit=`: results, newest first (every role, own tenant).
//! - manual test: `POST /jobs {kind: "restore_test", params: {source, time, node,
//!   storage, bridge?, checks?}}` (`check_test`); not for tenant users.
//! - `GET /restore-tests/schedules`, `PUT|DELETE /restore-tests/schedules/{group_id}
//!   {every_days, node, storage, bridge?, checks?}`: per PVE group (admins, tenant admins).
//! - `GET|POST /recovery-plans`, `PUT|DELETE /recovery-plans/{id}` (admins, tenant
//!   admins); `POST /recovery-plans/{id}/readiness` and `/test` (admins, operators,
//!   tenant admins: 202 `{id}` / `{run_id, job_id}`); `POST /recovery-plans/{id}/execute
//!   {confirm: <plan name>}`: approval `recovery_plan.execute` (never via a token), the
//!   approver sees the plan as it will run; `GET /recovery-plans/{id}/runs`;
//!   `GET /recovery-runs/{id}/report`: the DR report (HTML, `crates/reports/src/dr.rs`).
//!
//! Test guests are isolated (links down or the plan's bridge) and destroyed; in vault
//! mode tests need no approval (nothing leaves the PVE cluster it came from), an
//! execution always goes through the approval gate.

use crate::auth::{Ctx, TENANT_WRITERS};
use crate::{validate, ApiError, ApiResult, St, J, Q};
use axum::extract::{Path, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use catalog::rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;

/// Start tests / readiness checks / request an execution.
const RUNNERS: &[&str] = &["admin", "operator", "tenant_admin"];
pub const EXECUTE_ACTION: &str = "recovery_plan.execute";
const MAX_STEPS: usize = 50;

#[derive(Deserialize, Serialize, Clone, Default)]
#[serde(deny_unknown_fields)]
pub struct Checks {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    boot_timeout: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    agent: Option<bool>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    ports: Vec<u16>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    command: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    expect_exit: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    command_timeout: Option<u64>,
}

impl Checks {
    /// Bounds; containers have no guest agent: only the boot timeout.
    fn check(&self, ct: bool) -> ApiResult<()> {
        if self.boot_timeout.is_some_and(|t| !(30..=3600).contains(&t)) {
            return Err(ApiError::bad("checks.boot_timeout: 30..=3600 seconds"));
        }
        if self.command_timeout.is_some_and(|t| !(1..=600).contains(&t)) {
            return Err(ApiError::bad("checks.command_timeout: 1..=600 seconds"));
        }
        if self.ports.len() > 16 || self.ports.contains(&0) {
            return Err(ApiError::bad("checks.ports: at most 16 ports 1..=65535"));
        }
        if self.command.len() > 16
            || self
                .command
                .iter()
                .any(|a| a.is_empty() || a.len() > 256 || a.chars().any(char::is_control))
        {
            return Err(ApiError::bad(
                "checks.command: at most 16 arguments of 1..=256 characters",
            ));
        }
        if self.agent == Some(false) && (!self.ports.is_empty() || !self.command.is_empty()) {
            return Err(ApiError::bad("checks: ports and command run through the guest agent"));
        }
        if ct && (self.agent == Some(true) || !self.ports.is_empty() || !self.command.is_empty()) {
            return Err(ApiError::bad(
                "checks: containers have no guest agent (only boot_timeout; the init process is checked)",
            ));
        }
        Ok(())
    }
}

fn opt_name(v: &Option<String>, what: &str) -> ApiResult<()> {
    v.as_deref().map_or(Ok(()), |b| validate::name(b, what))
}

/// `vm-<id>` / `ct-<id>` -> container?
fn guest_source(s: &str) -> ApiResult<bool> {
    let ok = |p: &str| {
        s.strip_prefix(p)
            .and_then(|v| v.parse::<u32>().ok())
            .is_some_and(|v| v >= 100)
    };
    match (ok("vm-"), ok("ct-")) {
        (true, _) => Ok(false),
        (_, true) => Ok(true),
        _ => Err(ApiError::bad("source: vm-<vmid> or ct-<vmid>")),
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct TestP {
    source: String,
    time: i64,
    node: String,
    storage: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    bridge: Option<String>,
    #[serde(default)]
    checks: Checks,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    source_id: Option<i64>,
}

/// Params of a manual `restore_test` job (jobs.rs `check_params`).
pub(crate) fn check_test(st: &St, tenant: &str, p: Value) -> ApiResult<Value> {
    let p = if p.is_null() { json!({}) } else { p };
    let t: TestP = serde_json::from_value(p).map_err(|e| ApiError::bad(format!("params: {e}")))?;
    let ct = guest_source(&t.source)?;
    validate::name(&t.node, "node")?;
    validate::name(&t.storage, "storage")?;
    opt_name(&t.bridge, "bridge")?;
    t.checks.check(ct)?;
    if let Some(sid) = t.source_id {
        pve_source(&st.cat.conn(), tenant, sid)?;
    }
    let found = st
        .cat
        .conn()
        .query_row(
            "SELECT 1 FROM snapshots WHERE tenant = ?1 AND source = ?2 AND time = ?3 AND local = 1",
            params![tenant, t.source, t.time],
            |_| Ok(()),
        )
        .optional()?;
    found.ok_or_else(|| ApiError(StatusCode::NOT_FOUND, "no such local snapshot".into()))?;
    Ok(json!(t))
}

fn pve_source(c: &Connection, tenant: &str, id: i64) -> ApiResult<()> {
    let ok = c
        .query_row(
            "SELECT 1 FROM sources WHERE id = ?1 AND tenant = ?2 AND kind = 'pve'",
            params![id, tenant],
            |_| Ok(()),
        )
        .optional()?;
    ok.ok_or_else(|| ApiError::bad("source_id: no PVE source of this tenant"))
}

// ------------------------------------------------------------ results

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestFilter {
    tenant: Option<String>,
    source: Option<String>,
    limit: Option<u32>,
}

pub async fn list_tests(State(st): State<St>, ctx: Ctx, Q(f): Q<TestFilter>) -> ApiResult<Json<Value>> {
    let c = st.cat.conn();
    let mut q = c.prepare(
        "SELECT id, tenant, source, time, job_id, run_id, state, started, finished, details FROM restore_tests
         WHERE (?1 IS NULL OR tenant = ?1) AND (?2 IS NULL OR tenant = ?2) AND (?3 IS NULL OR source = ?3)
         ORDER BY finished DESC, id DESC LIMIT ?4",
    )?;
    let rows = q
        .query_map(
            params![f.tenant, ctx.scope(), f.source, f.limit.unwrap_or(500).min(2000)],
            |r| {
                let d: String = r.get(9)?;
                let d: Value = serde_json::from_str(&d).unwrap_or(Value::Null);
                Ok(json!({"id": r.get::<_, i64>(0)?, "tenant": r.get::<_, String>(1)?, "source": r.get::<_, String>(2)?,
                          "time": r.get::<_, i64>(3)?, "job_id": r.get::<_, i64>(4)?, "run_id": r.get::<_, Option<i64>>(5)?,
                          "state": r.get::<_, String>(6)?, "started": r.get::<_, i64>(7)?, "finished": r.get::<_, i64>(8)?,
                          "target": d["target"], "name": d["name"], "boot_secs": d["boot_secs"],
                          "checks": d["checks"], "error": d["error"], "destroyed": d["destroyed"],
                          // plugin restore tests (databases): what the plugin checked
                          "summary": d["summary"]}))
            },
        )?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Json(Value::Array(rows)))
}

// ------------------------------------------------------------ schedules

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ScheduleReq {
    every_days: i64,
    /// PVE groups only (plugin groups test with the plugin's `verify` restore)
    #[serde(default)]
    node: String,
    #[serde(default)]
    storage: String,
    #[serde(default)]
    bridge: Option<String>,
    #[serde(default)]
    checks: Checks,
}

/// Whether the current version of a plugin declares the restore `verify` (restore test).
fn plugin_has_verify(c: &Connection, plugin: &str) -> ApiResult<bool> {
    let m: Option<String> = c
        .query_row(
            "SELECT manifest FROM plugins WHERE id = ?1 AND current = 1",
            [plugin],
            |r| r.get(0),
        )
        .optional()?;
    let m: Value = m.and_then(|m| serde_json::from_str(&m).ok()).unwrap_or(Value::Null);
    Ok(m["kinds"]
        .as_array()
        .into_iter()
        .flatten()
        .flat_map(|k| k["restores"].as_array().into_iter().flatten())
        .any(|r| r["id"] == "verify"))
}

/// (tenant, source kind) of a group.
fn group_of(c: &Connection, id: i64) -> ApiResult<(String, String)> {
    c.query_row(
        "SELECT g.tenant, s.kind FROM groups g JOIN sources s ON s.id = g.source_id WHERE g.id = ?1",
        [id],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )
    .optional()?
    .ok_or_else(ApiError::not_found)
}

pub async fn list_schedules(State(st): State<St>, ctx: Ctx) -> ApiResult<Json<Value>> {
    let c = st.cat.conn();
    let mut q = c.prepare(
        "SELECT r.group_id, g.name, g.tenant, r.every_days, r.node, r.storage, r.bridge, r.checks, r.last_run
         FROM restore_test_schedules r JOIN groups g ON g.id = r.group_id
         WHERE ?1 IS NULL OR g.tenant = ?1 ORDER BY g.tenant, g.name",
    )?;
    let rows = q
        .query_map([ctx.scope()], |r| {
            let checks: String = r.get(7)?;
            Ok(json!({"group_id": r.get::<_, i64>(0)?, "group": r.get::<_, String>(1)?, "tenant": r.get::<_, String>(2)?,
                      "every_days": r.get::<_, i64>(3)?, "node": r.get::<_, String>(4)?, "storage": r.get::<_, String>(5)?,
                      "bridge": r.get::<_, Option<String>>(6)?,
                      "checks": serde_json::from_str::<Value>(&checks).unwrap_or(json!({})),
                      "last_run": r.get::<_, Option<i64>>(8)?}))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Json(Value::Array(rows)))
}

pub async fn put_schedule(
    State(st): State<St>,
    ctx: Ctx,
    Path(id): Path<i64>,
    J(mut r): J<ScheduleReq>,
) -> ApiResult<Json<Value>> {
    ctx.require(TENANT_WRITERS)?;
    let (tenant, kind) = group_of(&st.cat.conn(), id)?;
    ctx.owns(&tenant)?;
    if !(1..=365).contains(&r.every_days) {
        return Err(ApiError::bad("every_days: 1..=365"));
    }
    if let Some(plugin) = kind.strip_prefix("plugin:") {
        // databases (Phase 44): the plugin's own restore test, no PVE target
        if !plugin_has_verify(&st.cat.conn(), plugin)? {
            return Err(ApiError::bad(format!(
                "the {plugin} plugin offers no restore test (restore `verify`); update the plugin"
            )));
        }
        r.node.clear();
        r.storage.clear();
        r.bridge = None;
        r.checks = Checks::default();
    } else if kind != "pve" {
        return Err(ApiError::bad(
            "restore tests need a group of a Proxmox VE source or of a plugin with restore tests",
        ));
    } else {
        validate::name(&r.node, "node")?;
        validate::name(&r.storage, "storage")?;
        opt_name(&r.bridge, "bridge")?;
        // the group's containers get only the boot timeout (scheduler)
        r.checks.check(false)?;
    }
    st.cat.conn().execute(
        "INSERT INTO restore_test_schedules (group_id, every_days, node, storage, bridge, checks) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
         ON CONFLICT (group_id) DO UPDATE SET every_days = excluded.every_days, node = excluded.node,
           storage = excluded.storage, bridge = excluded.bridge, checks = excluded.checks",
        params![id, r.every_days, r.node, r.storage, r.bridge, json!(r.checks).to_string()],
    )?;
    let out = json!(r);
    st.audit(ctx.name(), "restore_test.schedule", &format!("group/{id}"), out.clone())?;
    Ok(Json(out))
}

pub async fn delete_schedule(State(st): State<St>, ctx: Ctx, Path(id): Path<i64>) -> ApiResult<StatusCode> {
    ctx.require(TENANT_WRITERS)?;
    let (tenant, _) = group_of(&st.cat.conn(), id)?;
    ctx.owns(&tenant)?;
    let n = st
        .cat
        .conn()
        .execute("DELETE FROM restore_test_schedules WHERE group_id = ?1", [id])?;
    if n == 0 {
        return Err(ApiError::not_found());
    }
    st.audit(ctx.name(), "restore_test.unschedule", &format!("group/{id}"), json!({}))?;
    Ok(StatusCode::NO_CONTENT)
}

// ------------------------------------------------------------ recovery plans

#[derive(Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct Step {
    source: String,
    #[serde(default = "one")]
    wave: u32,
    /// seconds before the wave starts
    #[serde(default)]
    delay: u64,
    #[serde(default)]
    checks: Checks,
    /// execute only: VMID of the restored guest (default: the original)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    target: Option<u32>,
}

fn one() -> u32 {
    1
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlanReq {
    #[serde(default)]
    tenant: String,
    name: String,
    source_id: i64,
    node: String,
    storage: String,
    #[serde(default)]
    test_bridge: Option<String>,
    #[serde(default)]
    network_map: BTreeMap<String, String>,
    steps: Vec<Step>,
    #[serde(default = "rpo")]
    rpo_hours: i64,
}

fn rpo() -> i64 {
    24
}

impl PlanReq {
    fn check(&self, c: &Connection, tenant: &str) -> ApiResult<()> {
        validate::name(&self.name, "name")?;
        pve_source(c, tenant, self.source_id)?;
        validate::name(&self.node, "node")?;
        validate::name(&self.storage, "storage")?;
        opt_name(&self.test_bridge, "test_bridge")?;
        if self.network_map.len() > 32 {
            return Err(ApiError::bad("network_map: at most 32 bridges"));
        }
        for (k, v) in &self.network_map {
            validate::name(k, "network_map")?;
            validate::name(v, "network_map")?;
        }
        if !(1..=8760).contains(&self.rpo_hours) {
            return Err(ApiError::bad("rpo_hours: 1..=8760"));
        }
        if self.steps.is_empty() || self.steps.len() > MAX_STEPS {
            return Err(ApiError::bad(format!("steps: 1..={MAX_STEPS} guests")));
        }
        let mut seen = std::collections::HashSet::new();
        for s in &self.steps {
            let ct = guest_source(&s.source)?;
            if !seen.insert(s.source[3..].to_owned()) {
                return Err(ApiError::bad(format!("steps: {} twice", s.source)));
            }
            if !(1..=20).contains(&s.wave) || s.delay > 3600 {
                return Err(ApiError::bad("steps: wave 1..=20, delay 0..=3600 seconds"));
            }
            if let Some(t) = s.target {
                validate::vmid(t)?;
            }
            s.checks.check(ct)?;
        }
        Ok(())
    }
}

fn plan_json(r: &catalog::rusqlite::Row) -> catalog::rusqlite::Result<Value> {
    let j = |s: Option<String>| {
        s.and_then(|s| serde_json::from_str::<Value>(&s).ok())
            .unwrap_or(Value::Null)
    };
    Ok(
        json!({"id": r.get::<_, i64>(0)?, "tenant": r.get::<_, String>(1)?, "name": r.get::<_, String>(2)?,
              "source_id": r.get::<_, i64>(3)?, "node": r.get::<_, String>(4)?, "storage": r.get::<_, String>(5)?,
              "test_bridge": r.get::<_, Option<String>>(6)?, "network_map": j(r.get(7)?), "steps": j(r.get(8)?),
              "rpo_hours": r.get::<_, i64>(9)?, "readiness": j(r.get(10)?), "created": r.get::<_, i64>(11)?,
              "created_by": r.get::<_, String>(12)?}),
    )
}

const PLAN_COLS: &str = "id, tenant, name, source_id, node, storage, test_bridge, network_map, steps, rpo_hours, \
                         readiness, created, created_by";

/// The plan with the result of its last run; 404 outside the user's scope.
fn load_plan(c: &Connection, ctx: &Ctx, id: i64) -> ApiResult<Value> {
    let p = c
        .query_row(
            &format!("SELECT {PLAN_COLS} FROM recovery_plans WHERE id = ?1"),
            [id],
            plan_json,
        )
        .optional()?
        .ok_or_else(ApiError::not_found)?;
    if !ctx.sees(p["tenant"].as_str().unwrap_or_default()) {
        return Err(ApiError::not_found());
    }
    Ok(p)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanFilter {
    tenant: Option<String>,
}

pub async fn list_plans(State(st): State<St>, ctx: Ctx, Q(f): Q<PlanFilter>) -> ApiResult<Json<Value>> {
    let c = st.cat.conn();
    let mut q = c.prepare(&format!(
        "SELECT {PLAN_COLS} FROM recovery_plans WHERE (?1 IS NULL OR tenant = ?1) AND (?2 IS NULL OR tenant = ?2)
         ORDER BY tenant, name"
    ))?;
    let mut plans = q
        .query_map(params![f.tenant, ctx.scope()], plan_json)?
        .collect::<Result<Vec<_>, _>>()?;
    for p in &mut plans {
        p["last_run"] = c
            .query_row(
                "SELECT json_object('id', id, 'mode', mode, 'state', state, 'started', started, 'finished', finished)
                 FROM recovery_runs WHERE plan_id = ?1 ORDER BY id DESC LIMIT 1",
                [p["id"].as_i64()],
                |r| r.get::<_, String>(0),
            )
            .optional()?
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or(Value::Null);
    }
    Ok(Json(Value::Array(plans)))
}

/// A new plan is checked at once (then daily).
fn queue_readiness(c: &Connection, tenant: &str, id: i64, by: &str) -> ApiResult<i64> {
    c.execute(
        "INSERT INTO jobs (kind, tenant, params, state, requested_by, created) VALUES ('recovery_readiness', ?1, ?2, 'queued', ?3, ?4)",
        params![tenant, json!({"plan_id": id}).to_string(), by, catalog::now()],
    )?;
    Ok(c.last_insert_rowid())
}

pub async fn create_plan(State(st): State<St>, ctx: Ctx, J(r): J<PlanReq>) -> ApiResult<Response> {
    ctx.require(TENANT_WRITERS)?;
    let tenant = match (ctx.scope(), r.tenant.as_str()) {
        (Some(s), "") => s.to_owned(),
        (_, t) => t.to_owned(),
    };
    validate::name(&tenant, "tenant")?;
    ctx.owns(&tenant)?;
    let id = {
        let c = st.cat.conn();
        r.check(&c, &tenant)?;
        let dup = c
            .query_row(
                "SELECT 1 FROM recovery_plans WHERE tenant = ?1 AND name = ?2",
                params![tenant, r.name],
                |_| Ok(()),
            )
            .optional()?;
        if dup.is_some() {
            return Err(ApiError::conflict("a recovery plan with this name exists"));
        }
        c.execute(
            "INSERT INTO recovery_plans (tenant, name, source_id, node, storage, test_bridge, network_map, steps, rpo_hours, created, created_by)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                tenant,
                r.name,
                r.source_id,
                r.node,
                r.storage,
                r.test_bridge,
                json!(r.network_map).to_string(),
                json!(r.steps).to_string(),
                r.rpo_hours,
                catalog::now(),
                ctx.name()
            ],
        )?;
        let id = c.last_insert_rowid();
        queue_readiness(&c, &tenant, id, ctx.name())?;
        id
    };
    let mut out = json!(r);
    out["tenant"] = json!(tenant);
    out["id"] = json!(id);
    st.audit(
        ctx.name(),
        "recovery_plan.create",
        &format!("recovery_plan/{id}"),
        out.clone(),
    )?;
    Ok((StatusCode::CREATED, Json(out)).into_response())
}

pub async fn update_plan(
    State(st): State<St>,
    ctx: Ctx,
    Path(id): Path<i64>,
    J(r): J<PlanReq>,
) -> ApiResult<Json<Value>> {
    ctx.require(TENANT_WRITERS)?;
    let c = st.cat.conn();
    let old = load_plan(&c, &ctx, id)?;
    let tenant = old["tenant"].as_str().unwrap_or_default().to_owned();
    if !r.tenant.is_empty() && r.tenant != tenant {
        return Err(ApiError::bad("tenant: a plan cannot move to another tenant"));
    }
    r.check(&c, &tenant)?;
    let n = c.execute(
        "UPDATE recovery_plans SET name = ?2, source_id = ?3, node = ?4, storage = ?5, test_bridge = ?6, network_map = ?7,
           steps = ?8, rpo_hours = ?9 WHERE id = ?1",
        params![
            id,
            r.name,
            r.source_id,
            r.node,
            r.storage,
            r.test_bridge,
            json!(r.network_map).to_string(),
            json!(r.steps).to_string(),
            r.rpo_hours
        ],
    );
    if let Err(catalog::rusqlite::Error::SqliteFailure(e, _)) = &n {
        if e.code == catalog::rusqlite::ErrorCode::ConstraintViolation {
            return Err(ApiError::conflict("a recovery plan with this name exists"));
        }
    }
    n?;
    queue_readiness(&c, &tenant, id, ctx.name())?;
    drop(c);
    let mut out = json!(r);
    out["tenant"] = json!(tenant);
    out["id"] = json!(id);
    st.audit(
        ctx.name(),
        "recovery_plan.update",
        &format!("recovery_plan/{id}"),
        json!({"old": old, "new": out}),
    )?;
    Ok(Json(out))
}

pub async fn delete_plan(State(st): State<St>, ctx: Ctx, Path(id): Path<i64>) -> ApiResult<StatusCode> {
    ctx.require(TENANT_WRITERS)?;
    let old = {
        let c = st.cat.conn();
        let old = load_plan(&c, &ctx, id)?;
        // the runs (DR reports) stay
        c.execute("DELETE FROM recovery_plans WHERE id = ?1", [id])?;
        old
    };
    st.audit(
        ctx.name(),
        "recovery_plan.delete",
        &format!("recovery_plan/{id}"),
        json!({"old": old}),
    )?;
    Ok(StatusCode::NO_CONTENT)
}

/// The plan as it runs (no readiness / bookkeeping fields).
fn run_plan(p: &Value) -> Value {
    let mut r = p.clone();
    if let Some(o) = r.as_object_mut() {
        for k in ["readiness", "created", "created_by", "last_run"] {
            o.remove(k);
        }
    }
    r
}

pub async fn readiness(State(st): State<St>, ctx: Ctx, Path(id): Path<i64>) -> ApiResult<Response> {
    ctx.require(RUNNERS)?;
    let job = {
        let c = st.cat.conn();
        let p = load_plan(&c, &ctx, id)?;
        queue_readiness(&c, p["tenant"].as_str().unwrap_or_default(), id, ctx.name())?
    };
    st.audit(
        ctx.name(),
        "recovery_plan.readiness",
        &format!("recovery_plan/{id}"),
        json!({"job": job}),
    )?;
    Ok((StatusCode::ACCEPTED, Json(json!({"id": job}))).into_response())
}

pub async fn test_run(State(st): State<St>, ctx: Ctx, Path(id): Path<i64>) -> ApiResult<Response> {
    ctx.require(RUNNERS)?;
    let (run, job) = {
        let c = st.cat.conn();
        let p = load_plan(&c, &ctx, id)?;
        let tenant = p["tenant"].as_str().unwrap_or_default();
        let busy = c
            .query_row(
                "SELECT 1 FROM recovery_runs WHERE plan_id = ?1 AND state = 'running'",
                [id],
                |_| Ok(()),
            )
            .optional()?;
        if busy.is_some() {
            return Err(ApiError::conflict("a run of this plan is in progress"));
        }
        let now = catalog::now();
        c.execute(
            "INSERT INTO recovery_runs (plan_id, tenant, mode, requested_by, plan, started) VALUES (?1, ?2, 'test', ?3, ?4, ?5)",
            params![id, tenant, ctx.name(), run_plan(&p).to_string(), now],
        )?;
        let run = c.last_insert_rowid();
        c.execute(
            "INSERT INTO jobs (kind, tenant, params, state, requested_by, created) VALUES ('recovery_test', ?1, ?2, 'queued', ?3, ?4)",
            params![tenant, json!({"run_id": run, "plan_id": id}).to_string(), ctx.name(), now],
        )?;
        let job = c.last_insert_rowid();
        c.execute("UPDATE recovery_runs SET job_id = ?2 WHERE id = ?1", params![run, job])?;
        (run, job)
    };
    st.audit(
        ctx.name(),
        "recovery_plan.test",
        &format!("recovery_plan/{id}"),
        json!({"run": run, "job": job}),
    )?;
    Ok((StatusCode::ACCEPTED, Json(json!({"run_id": run, "job_id": job}))).into_response())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecuteReq {
    confirm: String,
}

/// Real DR: approval `recovery_plan.execute` (the scheduler executes it).
pub async fn execute(State(st): State<St>, ctx: Ctx, Path(id): Path<i64>, J(r): J<ExecuteReq>) -> ApiResult<Response> {
    ctx.require(RUNNERS)?;
    if ctx.token.is_some() {
        return Err(ApiError(
            StatusCode::FORBIDDEN,
            "API tokens cannot execute recovery plans".into(),
        ));
    }
    let p = load_plan(&st.cat.conn(), &ctx, id)?;
    let name = p["name"].as_str().unwrap_or_default();
    if r.confirm != name {
        return Err(ApiError::bad(format!(
            "confirm: type the plan's name ({name}) to confirm"
        )));
    }
    let tenant = p["tenant"].as_str().unwrap_or_default().to_owned();
    if catalog::tenants::disabled(&st.cat.conn(), &tenant)? {
        return Err(ApiError::conflict(format!("tenant {tenant} is deactivated")));
    }
    crate::quorum::gate(
        &st,
        &ctx,
        EXECUTE_ACTION,
        &format!("recovery_plan/{id}"),
        json!({"tenant": tenant, "plan_id": id, "plan": run_plan(&p)}),
    )
}

pub async fn runs(State(st): State<St>, ctx: Ctx, Path(id): Path<i64>) -> ApiResult<Json<Value>> {
    let c = st.cat.conn();
    load_plan(&c, &ctx, id)?;
    let mut q = c.prepare(
        "SELECT id, mode, state, requested_by, quorum_id, job_id, results, started, finished FROM recovery_runs
         WHERE plan_id = ?1 ORDER BY id DESC LIMIT 100",
    )?;
    let rows = q
        .query_map([id], |r| {
            let res: String = r.get(6)?;
            Ok(
                json!({"id": r.get::<_, i64>(0)?, "mode": r.get::<_, String>(1)?, "state": r.get::<_, String>(2)?,
                      "requested_by": r.get::<_, String>(3)?, "quorum_id": r.get::<_, Option<i64>>(4)?,
                      "job_id": r.get::<_, Option<i64>>(5)?,
                      "results": serde_json::from_str::<Value>(&res).unwrap_or(json!([])),
                      "started": r.get::<_, i64>(7)?, "finished": r.get::<_, Option<i64>>(8)?}),
            )
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Json(Value::Array(rows)))
}

/// The DR report of a run (HTML attachment).
pub async fn report(State(st): State<St>, ctx: Ctx, Path(id): Path<i64>) -> ApiResult<Response> {
    let html = {
        let c = st.cat.conn();
        let host = catalog::setting(&c, "appliance_id")?.unwrap_or_else(|| "-".into());
        reports::dr::dr_report(&c, id, ctx.scope(), &host)?.ok_or_else(ApiError::not_found)?
    };
    let mut res = html.into_response();
    let h = res.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    if let Ok(v) = HeaderValue::from_str(&format!("attachment; filename=\"dr-report-run-{id}.html\"")) {
        h.insert(header::CONTENT_DISPOSITION, v);
    }
    // no scripts, nothing loaded from elsewhere, even when opened in the app's origin
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("default-src 'none'; style-src 'unsafe-inline'"),
    );
    Ok(res)
}
