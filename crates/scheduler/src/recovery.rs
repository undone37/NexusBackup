//! Restore tests and recovery plans (Phase 25, docs/control-plane.md "Restore
//! tests and recovery plans"; the PVE side is `nexus-pve restore-test`,
//! crates/pve/src/restoretest.rs).
//!
//! - `restore_test {source, time, node, storage, bridge?, checks?, group_id?}`:
//!   one guest snapshot booted isolated, checked, destroyed. Manual (Restore
//!   tests page) or from a group's schedule ([`Scheduler::queue_restore_tests`]:
//!   the newest local snapshot of each guest every N days, one guest at a time
//!   per group). Each result becomes a `restore_tests` row; a failure raises the
//!   warning `restore_test:<tenant>/<source>`, the next pass resolves it.
//! - `recovery_test {run_id, plan_id}` (web-api "Test run") and
//!   `recovery_execute {run_id, plan_id, quorum_id}` (approved
//!   `recovery_plan.execute`, queued here): the plan of the `recovery_runs` row,
//!   newest local snapshot per guest. The results go into the run (DR report)
//!   and `restore_tests`; a failed test run or execution raises `recovery_plan`.
//! - `recovery_readiness {plan_id}` (daily per plan, or "Check now"):
//!   `nexus-pve lab-check` (node, storage, bridges) plus the catalog (a local
//!   snapshot within the RPO per guest, enough free space for them, no open
//!   restore-test / verify / inventory alert of the tenant's guests). The result
//!   is stored on the plan; failure raises `recovery_ready:<plan>`.

use crate::run::{Plan, Step};
use crate::{lifecycle, Job, Scheduler, ACTOR};
use anyhow::{bail, Context, Result};
use catalog::rusqlite::{params, OptionalExtension};
use catalog::schedule::Schedule;
use serde_json::{json, Value};

pub const KINDS: &[&str] = &[
    "restore_test",
    "recovery_test",
    "recovery_execute",
    "recovery_readiness",
];
pub const EXECUTE_ACTION: &str = "recovery_plan.execute";
/// readiness checks of every plan (UTC)
pub const READINESS: &str = "daily 05:30";
const SPEC: &str = "restore-test.json";

pub(crate) fn test_alert_key(tenant: &str, source: &str) -> String {
    format!("restore_test:{tenant}/{source}")
}

/// Test VMIDs per job: 90 ranges of 100 above `restoretest::VMID_BASE`, so
/// concurrent jobs on one cluster rarely probe the same IDs.
fn vmid_base(job: i64) -> u64 {
    990_000 + (job.rem_euclid(90) as u64) * 100
}

/// `restore-test {json}` lines of a log.
fn results(log: &str) -> Vec<Value> {
    log.lines()
        .filter_map(|l| serde_json::from_str::<Value>(l.strip_prefix("restore-test ")?).ok())
        .filter(|v| v["source"].is_string())
        .collect()
}

impl Scheduler {
    /// The newest local snapshot time of a guest source.
    fn newest_local(&self, tenant: &str, source: &str) -> Result<Option<(i64, i64)>> {
        Ok(self
            .db
            .conn()
            .query_row(
                "SELECT time, size FROM snapshots WHERE tenant = ?1 AND source = ?2 AND local = 1 ORDER BY time DESC LIMIT 1",
                params![tenant, source],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?)
    }

    fn recovery_plan_row(&self, tenant: &str, id: i64) -> Result<Value> {
        let c = self.db.conn();
        c.query_row(
            "SELECT name, source_id, node, storage, test_bridge, network_map, steps, rpo_hours FROM recovery_plans \
             WHERE id = ?1 AND tenant = ?2",
            params![id, tenant],
            |r| {
                let j = |s: String| serde_json::from_str::<Value>(&s).unwrap_or(Value::Null);
                Ok(
                    json!({"id": id, "tenant": tenant, "name": r.get::<_, String>(0)?, "source_id": r.get::<_, i64>(1)?,
                          "node": r.get::<_, String>(2)?, "storage": r.get::<_, String>(3)?,
                          "test_bridge": r.get::<_, Option<String>>(4)?, "network_map": j(r.get(5)?),
                          "steps": j(r.get(6)?), "rpo_hours": r.get::<_, i64>(7)?}),
                )
            },
        )
        .optional()?
        .with_context(|| format!("recovery plan {id} not found in tenant {tenant}"))
    }

    fn spec_step(&self, plan: &mut Plan, spec: &Value, cmd: &str, capture: bool) -> Result<()> {
        plan.files.push((SPEC.into(), serde_json::to_vec_pretty(spec)?));
        plan.steps.push(Step::Cli {
            bin: self.cfg.pve_bin.clone(),
            args: vec![
                plan.dir.join("pve.json").to_string_lossy().into_owned(),
                cmd.into(),
                plan.dir.join(SPEC).to_string_lossy().into_owned(),
            ],
            alert: None,
            capture,
        });
        Ok(())
    }

    pub(crate) fn plan_recovery(&self, job: &Job, mut plan: Plan) -> Result<Plan> {
        let (p, tenant) = (&job.params, job.tenant.as_str());
        let name = |k: &str| -> Result<String> {
            p[k].as_str()
                .filter(|v| crate::valid_name(v))
                .map(str::to_owned)
                .with_context(|| format!("invalid {k}"))
        };
        match job.kind.as_str() {
            "restore_test" => {
                let source = crate::ident(p, "source")?;
                let (_, vmid) = crate::guest(source)?;
                let sid = self.resolve_source(job, Some(vmid))?;
                plan.key = match p["group_id"].as_i64() {
                    // a group's scheduled tests run one guest at a time
                    Some(g) => format!("restore_test:group/{g}"),
                    None => format!("guest:{tenant}/{source}"),
                };
                plan.files = self.pve_config(tenant, sid, &plan.dir, &[])?;
                let bridge = p["bridge"].as_str().map(|_| name("bridge")).transpose()?;
                let spec = json!({
                    "mode": "test", "node": name("node")?, "storage": name("storage")?, "bridge": bridge,
                    "vmid_base": vmid_base(job.id),
                    "guests": [{"source": source, "time": crate::num(p, "time")?,
                                "checks": p.get("checks").filter(|c| !c.is_null()).cloned().unwrap_or(json!({}))}],
                });
                self.spec_step(&mut plan, &spec, "restore-test", false)?;
            }
            "recovery_test" | "recovery_execute" => {
                let run_id = crate::num(p, "run_id")? as i64;
                let (mode, run_plan): (String, String) = self
                    .db
                    .conn()
                    .query_row(
                        "SELECT mode, plan FROM recovery_runs WHERE id = ?1 AND tenant = ?2",
                        params![run_id, tenant],
                        |r| Ok((r.get(0)?, r.get(1)?)),
                    )
                    .optional()?
                    .with_context(|| format!("recovery run {run_id} not found"))?;
                let execute = job.kind == "recovery_execute";
                if (mode == "execute") != execute {
                    bail!("recovery run {run_id} is a {mode} run");
                }
                if execute && !p["quorum_id"].is_i64() {
                    bail!("recovery_execute without an approved {EXECUTE_ACTION} request");
                }
                let rp: Value = serde_json::from_str(&run_plan).context("run plan")?;
                plan.key = format!("recovery_plan:{}", rp["id"]);
                let mut guests = Vec::new();
                for st in rp["steps"].as_array().into_iter().flatten() {
                    let source = st["source"].as_str().context("plan step without source")?;
                    crate::guest(source)?;
                    let (time, _) = self
                        .newest_local(tenant, source)?
                        .with_context(|| format!("{source}: no local snapshot"))?;
                    let mut g = json!({"source": source, "time": time, "wave": st["wave"], "delay": st["delay"],
                                       "checks": st.get("checks").filter(|c| !c.is_null()).cloned().unwrap_or(json!({}))});
                    if execute && st["target"].is_u64() {
                        g["target"] = st["target"].clone();
                    }
                    guests.push(g);
                }
                if guests.is_empty() {
                    bail!("the recovery plan has no guests");
                }
                let sid = rp["source_id"].as_i64().context("plan without source")?;
                plan.files = self.pve_config(tenant, sid, &plan.dir, &[])?;
                let valid = |k: &str| -> Result<Value> {
                    match rp[k].as_str() {
                        Some(v) if crate::valid_name(v) => Ok(json!(v)),
                        None if k == "test_bridge" => Ok(Value::Null),
                        _ => bail!("plan: invalid {k}"),
                    }
                };
                let mut spec = json!({"mode": if execute { "execute" } else { "test" }, "node": valid("node")?,
                                      "storage": valid("storage")?, "vmid_base": vmid_base(job.id), "guests": guests});
                if execute {
                    spec["network_map"] = rp["network_map"].clone();
                } else {
                    spec["bridge"] = valid("test_bridge")?;
                }
                self.spec_step(&mut plan, &spec, "restore-test", false)?;
                self.db.conn().execute(
                    "UPDATE recovery_runs SET job_id = ?2 WHERE id = ?1",
                    params![run_id, job.id],
                )?;
            }
            "recovery_readiness" => {
                let id = crate::num(p, "plan_id")? as i64;
                let rp = self.recovery_plan_row(tenant, id)?;
                plan.key = format!("recovery_readiness:{id}");
                let sid = rp["source_id"].as_i64().unwrap_or_default();
                plan.files = self.pve_config(tenant, sid, &plan.dir, &[])?;
                let spec = json!({"mode": "test", "node": rp["node"], "storage": rp["storage"],
                                  "bridge": rp["test_bridge"], "network_map": rp["network_map"], "guests": []});
                self.spec_step(&mut plan, &spec, "lab-check", true)?;
            }
            k => bail!("not a recovery job: {k}"),
        }
        Ok(plan)
    }

    /// Group schedules: the newest local snapshot of every guest once the
    /// schedule's days have passed since its last run.
    pub(crate) fn queue_restore_tests(&mut self, now: i64) -> Result<()> {
        let rows: Vec<(i64, i64, String, String, Option<String>, String, Option<i64>)> = {
            let c = self.db.conn();
            let mut st = c.prepare(
                "SELECT group_id, every_days, node, storage, bridge, checks, last_run FROM restore_test_schedules",
            )?;
            let rows = st.query_map([], |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                    r.get(6)?,
                ))
            })?;
            rows.collect::<std::result::Result<_, _>>()?
        };
        if rows.is_empty() {
            return Ok(());
        }
        let off = self.disabled_tenants()?;
        let groups = self.groups()?;
        for (gid, days, node, storage, bridge, checks, last) in rows {
            if last.is_some_and(|l| now - l < days * 86400) {
                continue;
            }
            let Some(g) = groups.iter().find(|g| g.id == gid && !off.contains(&g.tenant)) else {
                continue;
            };
            let busy: i64 = self.db.conn().query_row(
                "SELECT COUNT(*) FROM jobs WHERE kind = 'restore_test' AND state IN ('queued', 'running') \
                 AND json_extract(params, '$.group_id') = ?1",
                [gid],
                |r| r.get(0),
            )?;
            if busy > 0 {
                continue;
            }
            let checks: Value = serde_json::from_str(&checks).unwrap_or(json!({}));
            for v in &g.guests {
                let newest = [format!("vm-{v}"), format!("ct-{v}")]
                    .into_iter()
                    .filter_map(|s| Some((s.clone(), self.newest_local(&g.tenant, &s).ok()??.0)))
                    .max_by_key(|(_, t)| *t);
                let Some((source, time)) = newest else { continue };
                // containers have no guest agent checks
                let checks = if source.starts_with("ct-") {
                    json!({"boot_timeout": checks["boot_timeout"]})
                } else {
                    checks.clone()
                };
                self.insert_job(
                    "restore_test",
                    &g.tenant,
                    &json!({"source": source, "time": time, "node": node, "storage": storage, "bridge": bridge,
                            "checks": checks, "group_id": gid, "source_id": g.source_id}),
                )?;
            }
            self.db.conn().execute(
                "UPDATE restore_test_schedules SET last_run = ?2 WHERE group_id = ?1",
                params![gid, now],
            )?;
        }
        Ok(())
    }

    /// Approved `recovery_plan.execute` requests become a run and its job.
    pub(crate) fn queue_recovery_executes(&mut self) -> Result<()> {
        let rows: Vec<(i64, String, String, Option<String>)> = {
            let c = self.db.conn();
            let mut st = c.prepare(
                "SELECT q.id, q.params, q.requested_by, q.decided_by FROM quorum q \
                 WHERE q.action = ?1 AND q.state = 'approved' \
                 AND NOT EXISTS (SELECT 1 FROM recovery_runs r WHERE r.quorum_id = q.id)",
            )?;
            let rows = st.query_map([EXECUTE_ACTION], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?;
            rows.collect::<std::result::Result<_, _>>()?
        };
        for (qid, p, by, decided) in rows {
            if decided.as_deref() == Some(by.as_str()) && catalog::approvals_enabled(&self.db.conn())? {
                continue;
            }
            let p: Value = serde_json::from_str(&p).unwrap_or(Value::Null);
            let (Some(tenant), Some(plan_id)) = (p["tenant"].as_str(), p["plan_id"].as_i64()) else {
                continue;
            };
            let run = {
                let c = self.db.conn();
                c.execute(
                    "INSERT INTO recovery_runs (plan_id, tenant, mode, requested_by, quorum_id, plan, started) \
                     VALUES (?1, ?2, 'execute', ?3, ?4, ?5, ?6)",
                    params![plan_id, tenant, by, qid, p["plan"].to_string(), catalog::now()],
                )?;
                c.last_insert_rowid()
            };
            let job = self.insert_job(
                "recovery_execute",
                tenant,
                &json!({"run_id": run, "plan_id": plan_id, "quorum_id": qid, "requested_by": by}),
            )?;
            self.db
                .conn()
                .execute("UPDATE recovery_runs SET job_id = ?2 WHERE id = ?1", params![run, job])?;
        }
        Ok(())
    }

    /// Daily readiness check of every plan.
    pub(crate) fn queue_readiness(&mut self, now: i64) -> Result<()> {
        let plans: Vec<(i64, String)> = {
            let c = self.db.conn();
            let mut st = c.prepare("SELECT id, tenant FROM recovery_plans")?;
            let rows = st.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?;
            rows.collect::<std::result::Result<_, _>>()?
        };
        if plans.is_empty() {
            return Ok(());
        }
        let sched = Schedule::parse(READINESS)?;
        let off = self.disabled_tenants()?;
        for (id, tenant) in plans.into_iter().filter(|(_, t)| !off.contains(t)) {
            let busy: i64 = self.db.conn().query_row(
                "SELECT COUNT(*) FROM jobs WHERE kind = 'recovery_readiness' AND state IN ('queued', 'running') \
                 AND json_extract(params, '$.plan_id') = ?1",
                [id],
                |r| r.get(0),
            )?;
            let last = self.last_run(
                &format!("recovery_plan/{id}"),
                "SELECT MAX(created) FROM jobs WHERE kind = 'recovery_readiness' AND requested_by = 'scheduler' \
                 AND json_extract(params, '$.plan_id') = ?1",
                &[&id],
                now,
            )?;
            if busy == 0 && sched.due(last, now) {
                self.insert_job("recovery_readiness", &tenant, &json!({"plan_id": id}))?;
            }
        }
        Ok(())
    }

    /// A recovery job that could not even start: its run fails too.
    pub(crate) fn recovery_unstartable(&self, job: &Job, msg: &str) -> Result<()> {
        if let Some(run) = job.params["run_id"].as_i64() {
            self.db.conn().execute(
                "UPDATE recovery_runs SET state = 'failed', finished = ?2, results = ?3 WHERE id = ?1 AND state = 'running'",
                params![run, catalog::now(), json!([{"error": msg}]).to_string()],
            )?;
        }
        Ok(())
    }

    /// Bookkeeping of a finished recovery job (results, runs, readiness, alerts).
    pub(crate) fn recovery_finished(&mut self, job: &Job, state: &str, log: &str, stdout: Option<&str>) -> Result<()> {
        let tenant = job.tenant.as_str();
        if job.kind == "recovery_readiness" {
            return self.readiness_finished(job, state, log, stdout);
        }
        let run_id = job.params["run_id"].as_i64();
        let out = results(log);
        let test = job.kind != "recovery_execute";
        for r in &out {
            let source = r["source"].as_str().unwrap_or_default();
            let st = r["state"].as_str().unwrap_or("failed");
            self.db.conn().execute(
                "INSERT OR IGNORE INTO restore_tests (tenant, source, time, job_id, run_id, state, started, finished, details) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    tenant,
                    source,
                    r["time"].as_i64().unwrap_or_default(),
                    job.id,
                    run_id,
                    st,
                    r["started"].as_i64().unwrap_or_default(),
                    r["finished"].as_i64().unwrap_or_else(catalog::now),
                    r.to_string()
                ],
            )?;
            if !test {
                continue;
            }
            let key = test_alert_key(tenant, source);
            match st {
                "passed" => self.resolve(&key)?,
                "failed" => {
                    let why: Vec<String> = r["checks"]
                        .as_array()
                        .into_iter()
                        .flatten()
                        .filter(|c| c["ok"] == false)
                        .map(|c| {
                            format!(
                                "{}: {}",
                                c["name"].as_str().unwrap_or("?"),
                                c["detail"].as_str().unwrap_or("")
                            )
                        })
                        .chain(r["error"].as_str().map(str::to_owned))
                        .collect();
                    let leftover = if r["destroyed"] == false {
                        format!(
                            " — test guest {} could not be destroyed, remove it by hand",
                            r["target"]
                        )
                    } else {
                        String::new()
                    };
                    self.raise(
                        "warning",
                        "restore_test",
                        &key,
                        &format!(
                            "restore test of {source} ({}) failed (job {}): {}{leftover}",
                            r["time"],
                            job.id,
                            why.join("; ")
                        ),
                        Some(tenant),
                    )?;
                }
                _ => {}
            }
        }
        let tail = log
            .lines()
            .rev()
            .find(|l| !l.trim().is_empty())
            .unwrap_or("see the job log");
        if job.kind == "restore_test" && state == "failed" && out.is_empty() {
            // nothing booted (no PVE, bad source): still the guest's test failed
            let source = job.params["source"].as_str().unwrap_or_default();
            self.raise(
                "warning",
                "restore_test",
                &test_alert_key(tenant, source),
                &format!("restore test of {source} failed (job {}): {tail}", job.id),
                Some(tenant),
            )?;
        }
        let Some(run) = run_id else { return Ok(()) };
        let run_state = match state {
            "ok" => "passed",
            "cancelled" => "cancelled",
            _ => "failed",
        };
        let mut res = Value::Array(out);
        if res.as_array().is_some_and(Vec::is_empty) && state != "ok" {
            res = json!([{"error": tail}]);
        }
        self.db.conn().execute(
            "UPDATE recovery_runs SET state = ?2, finished = ?3, results = ?4 WHERE id = ?1",
            params![run, run_state, catalog::now(), res.to_string()],
        )?;
        let plan_id = job.params["plan_id"].as_i64().unwrap_or_default();
        let plan_name: String = self
            .db
            .conn()
            .query_row(
                "SELECT json_extract(plan, '$.name') FROM recovery_runs WHERE id = ?1",
                [run],
                |r| r.get::<_, Option<String>>(0),
            )?
            .unwrap_or_default();
        self.db.audit(
            ACTOR,
            if test {
                "recovery_plan.test_run"
            } else {
                "recovery_plan.executed"
            },
            &format!("recovery_plan/{plan_id}"),
            &json!({"run": run, "job": job.id, "state": run_state}),
        )?;
        let key = format!("recovery_run:{plan_id}");
        match (run_state, test) {
            ("passed", true) => self.resolve(&key)?,
            ("failed", _) => self.raise(
                if test { "warning" } else { "critical" },
                "recovery_plan",
                &key,
                &format!(
                    "{} of recovery plan {plan_name} failed (run {run}, job {}): {tail}",
                    if test { "the test run" } else { "the execution" },
                    job.id
                ),
                lifecycle::tenant_of(job),
            )?,
            _ => {}
        }
        Ok(())
    }

    fn readiness_finished(&mut self, job: &Job, state: &str, log: &str, stdout: Option<&str>) -> Result<()> {
        if state == "cancelled" {
            return Ok(());
        }
        let tenant = job.tenant.as_str();
        let id = job.params["plan_id"].as_i64().unwrap_or_default();
        let Ok(rp) = self.recovery_plan_row(tenant, id) else {
            return Ok(()); // deleted meanwhile
        };
        let now = catalog::now();
        let mut checks: Vec<Value> = Vec::new();
        let mut check =
            |name: String, ok: bool, detail: String| checks.push(json!({"name": name, "ok": ok, "detail": detail}));
        let rpo = rp["rpo_hours"].as_i64().unwrap_or(24) * 3600;
        let mut need: i64 = 0;
        let mut sources = Vec::new();
        for st in rp["steps"].as_array().into_iter().flatten() {
            let source = st["source"].as_str().unwrap_or_default().to_owned();
            match self.newest_local(tenant, &source)? {
                Some((t, size)) => {
                    need += size;
                    let age = now - t;
                    check(
                        format!("snapshot {source}"),
                        age <= rpo,
                        format!("newest local snapshot {} h old (RPO {} h)", age / 3600, rpo / 3600),
                    );
                }
                None => check(format!("snapshot {source}"), false, "no local snapshot".into()),
            }
            sources.push(source);
        }
        if sources.is_empty() {
            check("guests".into(), false, "the plan has no guests".into());
        }
        let lab: Option<Value> = stdout.and_then(|s| serde_json::from_str(s.trim()).ok());
        match lab {
            Some(l) if state == "ok" => {
                let node = rp["node"].as_str().unwrap_or_default();
                check(
                    format!("node {node}"),
                    l["online"] == true,
                    if l["online"] == true {
                        "online".into()
                    } else {
                        l["error"].as_str().unwrap_or("not online").to_owned()
                    },
                );
                for (k, what) in [("storage", "target"), ("ir_storage", "instant recovery")] {
                    let s = &l[k];
                    let sid = s["id"].as_str().unwrap_or_default();
                    let avail = s["avail"].as_i64();
                    let (ok, detail) = match (s["error"].as_str(), s["active"] == true) {
                        (Some(e), _) => (false, e.to_owned()),
                        (None, false) => (false, "not active on the node".to_owned()),
                        (None, true) if k == "storage" && avail.is_some_and(|a| a < need) => (
                            false,
                            format!(
                                "{} GiB free, the guests need about {} GiB",
                                avail.unwrap_or(0) >> 30,
                                need >> 30
                            ),
                        ),
                        (None, true) => (true, format!("active, {} GiB free", avail.unwrap_or(0) >> 30)),
                    };
                    check(format!("{what} storage {sid}"), ok, detail);
                }
                let missing: Vec<&str> = l["missing_bridges"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(Value::as_str)
                    .collect();
                check(
                    "bridges".into(),
                    missing.is_empty(),
                    if missing.is_empty() {
                        "present".into()
                    } else {
                        format!("missing on the node: {}", missing.join(", "))
                    },
                );
            }
            _ => {
                let tail = log.lines().rev().find(|l| !l.trim().is_empty()).unwrap_or("no answer");
                check(
                    "target".into(),
                    false,
                    format!("the PVE cluster could not be checked: {tail}"),
                );
            }
        }
        // open alerts that make a recovery doubtful: failed restore tests of the
        // plan's guests, failed verification or an offsite inventory anomaly
        let mut keys: Vec<String> = sources.iter().map(|s| test_alert_key(tenant, s)).collect();
        keys.push(format!("verify:{tenant}"));
        keys.push(format!("inventory:{tenant}"));
        let blocking: Vec<String> = {
            let c = self.db.conn();
            let mut st = c.prepare(
                "SELECT message FROM alerts WHERE resolved_at IS NULL AND key IN (SELECT value FROM json_each(?1))",
            )?;
            let rows = st.query_map([json!(keys).to_string()], |r| r.get(0))?;
            rows.collect::<std::result::Result<_, _>>()?
        };
        check(
            "alerts".into(),
            blocking.is_empty(),
            if blocking.is_empty() {
                "no blocking alerts".into()
            } else {
                blocking.join("; ")
            },
        );
        let ok = checks.iter().all(|c| c["ok"] == true);
        let v = json!({"ok": ok, "at": now, "job": job.id, "checks": checks});
        self.db.conn().execute(
            "UPDATE recovery_plans SET readiness = ?2, readiness_at = ?3 WHERE id = ?1",
            params![id, v.to_string(), now],
        )?;
        let key = format!("recovery_ready:{id}");
        if ok {
            return self.resolve(&key);
        }
        let failed: Vec<String> = v["checks"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|c| c["ok"] == false)
            .map(|c| {
                format!(
                    "{}: {}",
                    c["name"].as_str().unwrap_or(""),
                    c["detail"].as_str().unwrap_or("")
                )
            })
            .collect();
        self.raise(
            "warning",
            "recovery_plan",
            &key,
            &format!(
                "recovery plan {} is not ready: {}",
                rp["name"].as_str().unwrap_or_default(),
                failed.join("; ")
            ),
            Some(tenant),
        )
    }
}
