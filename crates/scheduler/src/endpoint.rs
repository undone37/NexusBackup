//! Endpoint status of the agents (Phase 24a, docs/endpoint-ui.md, protocol v1.4).
//!
//! - **Poll:** every `agent_poll_secs` (2 min) each enrolled agent of an active
//!   tenant gets a short mTLS session (`nexus-agentctl <cfg> poll`, one process for
//!   all due agents, bounded concurrency, run on a helper thread). The answer
//!   records `agents.last_seen` / `reachable` / `power`; an unreachable agent is
//!   polled with backoff (2, 4, 8, 15 min). The session also delivers the pending
//!   session summaries (`agent_sessions`) and acknowledges handled requests.
//! - **Requests:** a "back up now" request from the endpoint queues a backup of the
//!   agent in each of its groups (`requested_by = agent:<id>`, audit
//!   `agent.request_backup` with that actor); duplicates (same request id) and
//!   requests within 10 minutes of the previous one are only acknowledged.
//! - **Summaries:** every finished backup / file restore of an agent stores a
//!   `SessionSummary` (bytes, warnings, first error, the agent's part of the job log)
//!   and makes the agent due for a poll.
//! - **Laptop policy** (`agents.laptop`): a scheduled run skips an agent on battery
//!   below `min_battery` %, on a metered network (`skip_metered`) or — with
//!   `run_missed` — while it is unreachable; with `run_missed` the skipped or failed
//!   run is queued again once the agent is reachable and fit, within `retry_hours`.

use super::*;

/// Poll interval while reachable; the backoff doubles it up to [`MAX_BACKOFF`].
pub const MAX_BACKOFF: i64 = 900;
/// Power / network state older than this is not used for laptop decisions.
pub const POWER_FRESH_SECS: i64 = 600;
/// Requests closer together than this are acknowledged without a new job.
pub const REQUEST_INTERVAL_SECS: i64 = 600;
const MAX_LOG_TAIL: usize = 200;
const MAX_LOG_LINE: usize = 1000;
/// Summaries delivered per poll (the rest follow with the next one).
const SUMMARIES_PER_POLL: i64 = 20;

/// In-memory poll state of the scheduler.
#[derive(Default)]
pub(crate) struct PollState {
    /// agent → next poll time (absent = due)
    pub(crate) next: HashMap<String, i64>,
    /// agent → `edges` key of the `SetEdge` sent in the running round (edge.rs)
    pushing: HashMap<String, String>,
    /// request ids to acknowledge with the next successful poll
    ack: HashMap<String, Vec<String>>,
    /// results of the running `nexus-agentctl poll` and when it started
    inflight: Option<(Receiver<Vec<Value>>, i64)>,
}

/// Laptop options of an agent (`agents.laptop`).
#[derive(Deserialize, Default, Clone, Debug, PartialEq)]
#[serde(default)]
pub struct Laptop {
    /// skip scheduled runs on battery below this charge (0 = off)
    pub min_battery: u8,
    pub skip_metered: bool,
    /// queue a skipped / failed scheduled run when the agent is reachable again
    pub run_missed: bool,
    /// ... within this many hours (default 24)
    pub retry_hours: u32,
}

impl Laptop {
    fn retry_secs(&self) -> i64 {
        i64::from(if self.retry_hours == 0 {
            24
        } else {
            self.retry_hours.min(24 * 14)
        }) * 3600
    }
}

/// Seconds until the next poll after `failures` consecutive failures.
pub fn backoff(base: i64, failures: i64) -> i64 {
    if failures <= 0 {
        return base;
    }
    (base << failures.min(3)).min(MAX_BACKOFF.max(base))
}

/// Why a scheduled run skips this agent now (`None` = it runs).
pub fn laptop_hold(l: &Laptop, reachable: Option<bool>, power: &Value, fresh: bool) -> Option<String> {
    if l.run_missed && reachable == Some(false) {
        return Some("not reachable".into());
    }
    if !fresh {
        return None;
    }
    if l.min_battery > 0 && power["on_battery"] == true {
        if let Some(p) = power["battery_percent"]
            .as_u64()
            .filter(|p| *p < u64::from(l.min_battery))
        {
            return Some(format!("on battery ({p} % < {} %)", l.min_battery));
        }
    }
    if l.skip_metered && power["metered"] == true {
        return Some("metered network".into());
    }
    None
}

struct EpAgent {
    id: String,
    tenant: String,
    host: String,
    port: u16,
    pins: Vec<String>,
    ui_policy: Value,
    ui_policy_version: i64,
    laptop: Laptop,
    reachable: Option<bool>,
    last_poll: Option<i64>,
    power: Value,
    missed_at: Option<i64>,
    poll_failures: i64,
    /// edge setting the agent confirmed (`SetEdge`, edge.rs)
    edge_pushed: Option<String>,
}

/// The agent's lines of a (group) job log: from its `agent-info` line up to the next
/// agent's; if it never answered, the lines naming it.
pub fn agent_section<'a>(log: &'a str, agent: &str) -> Vec<&'a str> {
    let mut out = Vec::new();
    let mut inside = false;
    for l in log.lines() {
        if let Some(j) = l.strip_prefix("agent-info ") {
            inside = serde_json::from_str::<Value>(j).is_ok_and(|v| v["agent_id"] == agent);
        }
        if inside {
            out.push(l);
        }
    }
    if out.is_empty() {
        out = log.lines().filter(|l| l.contains(agent)).collect();
    }
    out
}

fn number_before(line: &str, unit: &str) -> Option<u64> {
    let i = line.find(unit)?;
    line[..i]
        .split_whitespace()
        .last()?
        .trim_start_matches('(')
        .parse()
        .ok()
}

/// `SessionSummary` (agent_proto JSON) of one agent's part of a finished job.
pub fn summary(job: &Job, agent: &str, state: &str, started: i64, ended: i64, log: &str) -> Value {
    let lines = agent_section(log, agent);
    let restore = job.kind == "restore_files" || job.kind == "synthetic_restore";
    let mut snapshot_time = Value::Null;
    let (mut read, mut transferred, mut new) = (0u64, 0u64, 0u64);
    let mut warnings = 0u32;
    let mut committed = false;
    for l in &lines {
        if let Some(rest) = l.strip_prefix(&format!("committed host-{agent}/")) {
            committed = true;
            snapshot_time = rest
                .split_whitespace()
                .next()
                .and_then(|t| t.parse::<u64>().ok())
                .into();
        } else if let Some(r) = l.strip_prefix("scan: ") {
            read = number_before(r, " bytes").unwrap_or(0);
        } else if let Some(j) = l.strip_prefix("nexus-stats ") {
            let v: Value = serde_json::from_str(j).unwrap_or_default();
            transferred = v["read"].as_u64().unwrap_or(0);
            new = v["new_stored"].as_u64().unwrap_or(0);
        } else if let Some(j) = l.strip_prefix("restored ") {
            let v: Value = serde_json::from_str(j).unwrap_or_default();
            committed = v["errors"] == 0;
            transferred = v["bytes"].as_u64().unwrap_or(0);
            read = transferred;
            warnings += v["errors"].as_u64().unwrap_or(0) as u32;
        }
        if l.starts_with("warning:") || l.starts_with("agent: ") || l.starts_with("inconsistent ") {
            warnings += 1;
        }
    }
    let result = match state {
        "cancelled" => "Cancelled",
        _ if !committed && (state != "ok" || !restore) => "Failed",
        _ if warnings > 0 => "Warning",
        _ => "Success",
    };
    let first_error = if result == "Failed" {
        lines
            .iter()
            .rev()
            .find(|l| l.contains("rror"))
            .or(lines.last())
            .copied()
            .or(log.lines().rev().find(|l| !crate::run::is_time_mark(l)))
            .map(|l| l.chars().take(MAX_LOG_LINE).collect::<String>())
            .unwrap_or_default()
    } else {
        String::new()
    };
    let tail: Vec<String> = lines
        .iter()
        .rev()
        .take(MAX_LOG_TAIL)
        .rev()
        .map(|l| l.chars().take(MAX_LOG_LINE).collect())
        .collect();
    json!({
        "job": job.id, "kind": if restore { "Restore" } else { "Backup" },
        "started": started.max(0), "ended": ended.max(0), "result": result,
        "read_bytes": read, "transferred_bytes": transferred, "new_bytes": new,
        "warnings": warnings, "first_error": first_error, "snapshot_time": snapshot_time,
        "log_tail": tail,
    })
}

impl Scheduler {
    fn ep_agents(&self, only: Option<&str>) -> Result<Vec<EpAgent>> {
        let c = self.db.conn();
        let mut st = c.prepare(
            "SELECT id, tenant, host, port, cert_sha256, cert_sha256_next, ui_policy, ui_policy_version, laptop, \
             reachable, last_poll, power, missed_at, poll_failures, edge_pushed FROM agents \
             WHERE cert_sha256 IS NOT NULL AND (?1 IS NULL OR id = ?1) ORDER BY id",
        )?;
        let rows = st.query_map([only], |r| {
            let json = |i: usize| -> catalog::rusqlite::Result<Value> {
                Ok(r.get::<_, Option<String>>(i)?
                    .and_then(|s| serde_json::from_str(&s).ok())
                    .unwrap_or_default())
            };
            Ok(EpAgent {
                id: r.get(0)?,
                tenant: r.get(1)?,
                host: r.get(2)?,
                port: r.get(3)?,
                pins: [r.get::<_, Option<String>>(4)?, r.get(5)?]
                    .into_iter()
                    .flatten()
                    .collect(),
                ui_policy: json(6)?,
                ui_policy_version: r.get(7)?,
                laptop: serde_json::from_value(json(8)?).unwrap_or_default(),
                reachable: r.get::<_, Option<i64>>(9)?.map(|x| x != 0),
                last_poll: r.get(10)?,
                power: json(11)?,
                missed_at: r.get(12)?,
                poll_failures: r.get(13)?,
                edge_pushed: r.get(14)?,
            })
        })?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    /// Groups (with an enrolled linux source) that back up `agent`.
    fn agent_groups(&self, tenant: &str, agent: &str) -> Result<Vec<GroupRow>> {
        Ok(self
            .groups()?
            .into_iter()
            .filter(|g| g.tenant == tenant && g.agents.iter().any(|a| a == agent))
            .collect())
    }

    /// Next scheduled run of any group of the agent.
    fn agent_next_run(&self, tenant: &str, agent: &str, now: i64) -> Option<i64> {
        self.agent_groups(tenant, agent)
            .ok()?
            .iter()
            .filter_map(|g| {
                let ctl = self.control(g.id).ok()?;
                Schedule::parse(&g.schedule)
                    .and_then(|s| s.in_tz(&ctl.tz))
                    .ok()?
                    .next_slot(now)
            })
            .min()
    }

    fn appliance_status(&self, a: &EpAgent, now: i64) -> Value {
        let p = &a.ui_policy;
        let text = |k: &str, n: usize| p[k].as_str().unwrap_or_default().chars().take(n).collect::<String>();
        json!({
            "appliance": self.host.chars().take(64).collect::<String>(), "now": now.max(0),
            "next_run": self.agent_next_run(&a.tenant, &a.id, now),
            "ui_policy": {"accent": text("accent", 16), "header": text("header", 128),
                          "hide_backup_now": p["hide_backup_now"] == true, "hide_tray": p["hide_tray"] == true},
            "policy_version": a.ui_policy_version.clamp(0, u32::MAX as i64),
        })
    }

    /// Starts a poll round for the due agents (if none is running). Called every tick.
    pub(crate) fn start_agent_poll(&mut self, now: i64) -> Result<()> {
        let base = self.cfg.agent_poll_secs as i64;
        if base <= 0 || self.poll.inflight.is_some() {
            return Ok(());
        }
        let off = self.disabled_tenants()?;
        let due: Vec<EpAgent> = self
            .ep_agents(None)?
            .into_iter()
            .filter(|a| !off.contains(&a.tenant) && self.poll.next.get(&a.id).is_none_or(|t| *t <= now))
            .collect();
        if due.is_empty() {
            return Ok(());
        }
        let mut targets = Vec::new();
        for a in &due {
            let summaries: Vec<Value> = {
                let c = self.db.conn();
                let mut st = c.prepare(
                    "SELECT summary FROM agent_sessions WHERE agent_id=?1 AND delivered IS NULL ORDER BY job_id LIMIT ?2",
                )?;
                let rows = st.query_map(params![a.id, SUMMARIES_PER_POLL], |r| r.get::<_, String>(0))?;
                rows.filter_map(|s| s.ok().and_then(|s| serde_json::from_str(&s).ok()))
                    .collect()
            };
            let mut t = json!({
                "id": a.id, "host": a.host, "port": a.port, "pins": a.pins,
                "status": self.appliance_status(a, now),
                "ack": self.poll.ack.get(&a.id).cloned().unwrap_or_default(),
                "summaries": summaries,
            });
            // edge proxy (edge.rs): route, and the setting the agent does not have yet
            if let Some(e) = self.agent_edge_route(&a.id)? {
                t["edge"] = e;
            }
            if let Some((set, key)) = self.agent_edge_push(&a.id, a.edge_pushed.as_deref())? {
                t["set_edge"] = set;
                self.poll.pushing.insert(a.id.clone(), key);
            }
            targets.push(t);
            // not again before this round is processed
            self.poll
                .next
                .insert(a.id.clone(), now + backoff(base, a.poll_failures));
        }
        let cfg = json!({
            "tenant": "", "ca_dir": self.cfg.agent_ca_path(), "timeout_secs": 20,
            "poll": {"agents": targets, "concurrency": self.cfg.agent_poll_concurrency},
        });
        fs::create_dir_all(&self.cfg.runtime_dir)?;
        let path = self.cfg.runtime_dir.join("agent-poll.json");
        let tmp = path.with_extension("tmp");
        {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            let _ = fs::remove_file(&tmp);
            let mut f = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&tmp)?;
            f.write_all(serde_json::to_vec(&cfg)?.as_slice())?;
        }
        fs::rename(&tmp, &path)?;
        let (tx, rx) = channel();
        let bin = self.cfg.agentctl_bin.clone();
        std::thread::spawn(move || {
            let out = std::process::Command::new(&bin)
                .arg(&path)
                .arg("poll")
                .stdin(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .output();
            let _ = fs::remove_file(&path);
            let lines = match out {
                Ok(o) => String::from_utf8_lossy(&o.stdout)
                    .lines()
                    .filter_map(|l| l.strip_prefix("poll ").and_then(|j| serde_json::from_str(j).ok()))
                    .collect(),
                Err(e) => {
                    eprintln!("<4>scheduler: {}: {e}", bin.display());
                    Vec::new()
                }
            };
            let _ = tx.send(lines);
        });
        self.poll.inflight = Some((rx, now));
        Ok(())
    }

    /// Processes a finished poll round (non-blocking; `wait` blocks up to that long).
    pub(crate) fn collect_agent_poll(&mut self, wait: Option<Duration>) -> Result<()> {
        let Some((rx, now)) = &self.poll.inflight else {
            return Ok(());
        };
        // times relative to the round's start (a round takes seconds)
        let now = *now;
        let got = match wait {
            Some(w) => rx.recv_timeout(w).ok(),
            None => rx.try_recv().ok(),
        };
        let Some(results) = got else {
            // a dead helper thread: start over
            if matches!(rx.try_recv(), Err(std::sync::mpsc::TryRecvError::Disconnected)) {
                self.poll.inflight = None;
            }
            return Ok(());
        };
        self.poll.inflight = None;
        for v in results {
            self.log_err(|s| s.apply_poll(&v, now));
        }
        Ok(())
    }

    fn apply_poll(&mut self, v: &Value, now: i64) -> Result<()> {
        let Some(id) = v["agent_id"].as_str().filter(|a| valid_agent_id(a)) else {
            return Ok(());
        };
        let Some(a) = self.ep_agents(Some(id))?.into_iter().next() else {
            return Ok(());
        };
        let base = self.cfg.agent_poll_secs as i64;
        if v["ok"] != true {
            let failures = a.poll_failures + 1;
            self.db.conn().execute(
                "UPDATE agents SET reachable=0, last_poll=?2, poll_failures=?3 WHERE id=?1",
                params![id, now, failures],
            )?;
            self.poll.next.insert(id.to_owned(), now + backoff(base, failures));
            return Ok(());
        }
        let short = |k: &str| v["info"][k].as_str().map(|s| s.chars().take(128).collect::<String>());
        let power = v.get("power").filter(|p| p.is_object()).map(|p| {
            let name = p["network_name"].as_str().map(|n| n.chars().take(64).collect::<String>());
            json!({"on_battery": p["on_battery"].as_bool(), "battery_percent": p["battery_percent"].as_u64().map(|x| x.min(100)),
                   "metered": p["metered"].as_bool(), "network_name": name})
        });
        self.db.conn().execute(
            "UPDATE agents SET reachable=1, last_poll=?2, last_seen=?2, poll_failures=0, \
             version=COALESCE(?3, version), os=COALESCE(?4, os), power=COALESCE(?5, power), \
             ui_policy_seen=COALESCE(?6, ui_policy_seen) WHERE id=?1",
            params![
                id,
                now,
                short("version"),
                short("os"),
                power.as_ref().map(|p| p.to_string()),
                v["policy_version"].as_i64()
            ],
        )?;
        self.agent_facts(id, &v["info"])?; // agent_updates.rs
        self.poll.next.insert(id.to_owned(), now + base);
        self.poll.ack.remove(id);
        if let Some(via) = v["info"]["via"].as_str().filter(|x| matches!(*x, "direct" | "edge")) {
            self.db
                .conn()
                .execute("UPDATE agents SET via=?2 WHERE id=?1", params![id, via])?;
        }
        if let Some(key) = self.poll.pushing.remove(id).filter(|_| v["edge_set"].is_string()) {
            self.db
                .conn()
                .execute("UPDATE agents SET edge_pushed=?2 WHERE id=?1", params![id, key])?;
        }
        for job in v["delivered"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_i64)
        {
            self.db.conn().execute(
                "UPDATE agent_sessions SET delivered=?3 WHERE agent_id=?1 AND job_id=?2",
                params![id, job, now],
            )?;
        }
        for r in v["requests"].as_array().into_iter().flatten() {
            self.agent_request(&a, r, now)?;
        }
        // fresh state for the missed-run decision
        let a = self.ep_agents(Some(id))?.into_iter().next().unwrap_or(a);
        self.retry_missed(&a, now)
    }

    /// One "back up now" request from the endpoint.
    fn agent_request(&mut self, a: &EpAgent, r: &Value, now: i64) -> Result<()> {
        let Some(rid) = r["id"]
            .as_str()
            .filter(|x| !x.is_empty() && x.len() <= 64 && x.bytes().all(|b| b.is_ascii_hexdigit()))
        else {
            return Ok(());
        };
        self.poll.ack.entry(a.id.clone()).or_default().push(rid.to_owned());
        let known: i64 = self.db.conn().query_row(
            "SELECT COUNT(*) FROM jobs WHERE kind='backup' AND json_extract(params,'$.request_id')=?1",
            [rid],
            |r| r.get(0),
        )?;
        let last: Option<Value> = self
            .db
            .conn()
            .query_row("SELECT last_request FROM agents WHERE id=?1", [&a.id], |r| {
                r.get::<_, Option<String>>(0)
            })?
            .and_then(|s| serde_json::from_str(&s).ok());
        if known > 0 || last.as_ref().is_some_and(|l| l["id"] == rid) {
            return Ok(()); // already handled (scheduler restart before the acknowledgement)
        }
        let actor = format!("agent:{}", a.id);
        let refuse = if self.disabled_tenants()?.contains(&a.tenant) {
            Some("tenant deactivated")
        } else if last
            .as_ref()
            .and_then(|l| l["received"].as_i64())
            .is_some_and(|t| now - t < REQUEST_INTERVAL_SECS)
        {
            Some("rate limited")
        } else {
            None
        };
        let mut jobs = Vec::new();
        if refuse.is_none() {
            let groups = self.agent_groups(&a.tenant, &a.id)?;
            let mut params_list: Vec<Value> = groups
                .iter()
                .map(|g| json!({"group_id": g.id, "guests": [a.id], "request_id": rid}))
                .collect();
            if params_list.is_empty() && self.agent_source(&a.tenant, &a.id).is_ok() {
                params_list.push(json!({"agent_id": a.id, "request_id": rid}));
            }
            for p in params_list {
                let busy: i64 = self.db.conn().query_row(
                    "SELECT COUNT(*) FROM jobs WHERE kind='backup' AND state IN ('queued','running') AND tenant=?1 \
                     AND (json_extract(params,'$.agent_id')=?2 OR (json_extract(params,'$.group_id')=?3 \
                     AND (json_extract(params,'$.guests') IS NULL OR EXISTS (SELECT 1 FROM json_each(params,'$.guests') WHERE value=?2))))",
                    params![a.tenant, a.id, p["group_id"].as_i64()],
                    |r| r.get(0),
                )?;
                if busy > 0 {
                    continue;
                }
                let id = {
                    let c = self.db.conn();
                    c.execute(
                        "INSERT INTO jobs (kind, tenant, params, state, requested_by, created) VALUES ('backup',?1,?2,'queued',?3,?4)",
                        params![a.tenant, p.to_string(), actor, now],
                    )?;
                    c.last_insert_rowid()
                };
                jobs.push(id);
            }
        }
        self.db.conn().execute(
            "UPDATE agents SET last_request=?2 WHERE id=?1",
            params![
                a.id,
                json!({"id": rid, "queued_at": r["queued_at"], "received": now, "jobs": jobs, "refused": refuse})
                    .to_string()
            ],
        )?;
        self.db.audit(
            &actor,
            "agent.request_backup",
            &format!("agent/{}", a.id),
            &json!({"tenant": a.tenant, "request_id": rid, "jobs": jobs, "refused": refuse}),
        )?;
        Ok(())
    }

    /// A missed scheduled run of a `run_missed` agent: queued when it is reachable
    /// and fit again, dropped after `retry_hours`.
    fn retry_missed(&mut self, a: &EpAgent, now: i64) -> Result<()> {
        let Some(missed) = a.missed_at else { return Ok(()) };
        if !a.laptop.run_missed || now - missed > a.laptop.retry_secs() {
            self.db
                .conn()
                .execute("UPDATE agents SET missed_at=NULL WHERE id=?1", [&a.id])?;
            self.db.audit(
                ACTOR,
                "agent.missed_run_expired",
                &format!("agent/{}", a.id),
                &json!({"tenant": a.tenant, "missed_at": missed}),
            )?;
            return Ok(());
        }
        if let Some(why) = laptop_hold(&a.laptop, a.reachable, &a.power, true) {
            let _ = why; // still unfit: wait for the next poll
            return Ok(());
        }
        let mut jobs = Vec::new();
        for g in self.agent_groups(&a.tenant, &a.id)? {
            let busy: i64 = self.db.conn().query_row(
                "SELECT COUNT(*) FROM jobs WHERE kind='backup' AND state IN ('queued','running') \
                 AND json_extract(params,'$.group_id')=?1",
                [g.id],
                |r| r.get(0),
            )?;
            if busy == 0 {
                jobs.push(self.insert_job(
                    "backup",
                    &a.tenant,
                    &json!({"group_id": g.id, "guests": [a.id], "missed": true}),
                )?);
            }
        }
        self.db
            .conn()
            .execute("UPDATE agents SET missed_at=NULL WHERE id=?1", [&a.id])?;
        self.db.audit(
            ACTOR,
            "agent.missed_run_queued",
            &format!("agent/{}", a.id),
            &json!({"tenant": a.tenant, "missed_at": missed, "jobs": jobs}),
        )?;
        Ok(())
    }

    /// The scheduled backup of a group (queue_scheduled): agents held by their laptop
    /// policy are left out (and marked missed); if all are, the run is recorded as a
    /// cancelled job (the schedule moves on, no alert).
    pub(crate) fn queue_group_backup(&mut self, g: &GroupRow, now: i64) -> Result<()> {
        if g.agents.is_empty() {
            self.insert_job("backup", &g.tenant, &json!({"group_id": g.id}))?;
            return Ok(());
        }
        let mut held = Vec::new();
        for a in self.ep_agents(None)?.into_iter().filter(|a| g.agents.contains(&a.id)) {
            let fresh = a.last_poll.is_some_and(|t| now - t <= POWER_FRESH_SECS);
            if let Some(why) = laptop_hold(&a.laptop, a.reachable, &a.power, fresh) {
                if a.laptop.run_missed {
                    self.db.conn().execute(
                        "UPDATE agents SET missed_at=COALESCE(missed_at, ?2) WHERE id=?1",
                        params![a.id, now],
                    )?;
                }
                self.db.audit(
                    ACTOR,
                    "agent.backup_skipped",
                    &format!("agent/{}", a.id),
                    &json!({"tenant": g.tenant, "group_id": g.id, "reason": why, "retry": a.laptop.run_missed}),
                )?;
                held.push((a.id, why));
            }
        }
        if held.is_empty() {
            self.insert_job("backup", &g.tenant, &json!({"group_id": g.id}))?;
            return Ok(());
        }
        let run: Vec<&String> = g.agents.iter().filter(|a| !held.iter().any(|(h, _)| h == *a)).collect();
        if !run.is_empty() {
            self.insert_job("backup", &g.tenant, &json!({"group_id": g.id, "guests": run}))?;
            return Ok(());
        }
        let log: String = held
            .iter()
            .map(|(a, why)| format!("[scheduler] agent {a} skipped: {why}\n"))
            .collect();
        let c = self.db.conn();
        c.execute(
            "INSERT INTO jobs (kind, tenant, params, state, requested_by, created, started, finished, log) \
             VALUES ('backup',?1,?2,'cancelled',?3,?4,?4,?4,?5)",
            params![
                g.tenant,
                json!({"group_id": g.id, "skipped": true}).to_string(),
                ACTOR,
                self.now,
                log
            ],
        )?;
        Ok(())
    }

    /// After an agent backup / file restore: one summary per agent for its endpoint
    /// UI, a poll soon; a failed scheduled run of a `run_missed` agent is marked missed.
    pub(crate) fn endpoint_bookkeeping(&mut self, job: &Job, state: &str, log: &str) -> Result<()> {
        let agents: Vec<String> = match job.kind.as_str() {
            "backup" => match (job.params["agent_id"].as_str(), job.params["group_id"].as_i64()) {
                (Some(a), _) => vec![a.to_owned()],
                (None, Some(gid)) => self
                    .groups()?
                    .into_iter()
                    .find(|g| g.id == gid && g.tenant == job.tenant)
                    .map(|g| runctl::restrict(g, &job.params).agents)
                    .unwrap_or_default(),
                _ => vec![],
            },
            // Phase 33: a synthetic restore onto a host (a download involves no agent)
            "synthetic_restore" if job.params["mode"] != "host" => vec![],
            "restore_files" | "synthetic_restore" => job.params["agent_id"]
                .as_str()
                .or(job.params["source"].as_str().and_then(|s| s.strip_prefix("host-")))
                .map(|a| vec![a.to_owned()])
                .unwrap_or_default(),
            _ => vec![],
        };
        if agents.is_empty() || job.params["skipped"] == true {
            return Ok(());
        }
        let (started, ended): (Option<i64>, Option<i64>) =
            self.db
                .conn()
                .query_row("SELECT started, finished FROM jobs WHERE id=?1", [job.id], |r| {
                    Ok((r.get(0)?, r.get(1)?))
                })?;
        let ended = ended.unwrap_or_else(catalog::now);
        for a in agents.iter().filter(|a| valid_agent_id(a)) {
            let s = summary(job, a, state, started.unwrap_or(ended), ended, log);
            let n = self.db.conn().execute(
                "INSERT OR REPLACE INTO agent_sessions (agent_id, job_id, tenant, summary, created) \
                 SELECT ?1, ?2, ?3, ?4, ?5 FROM agents WHERE id=?1 AND tenant=?3",
                params![a, job.id, job.tenant, s.to_string(), ended],
            )?;
            if n == 0 {
                continue;
            }
            // keep the newest 100 per agent (the agent keeps as many)
            self.db.conn().execute(
                "DELETE FROM agent_sessions WHERE agent_id=?1 AND job_id NOT IN \
                 (SELECT job_id FROM agent_sessions WHERE agent_id=?1 ORDER BY job_id DESC LIMIT 100)",
                [a],
            )?;
            self.poll.next.remove(a);
            if job.kind == "backup" && s["result"] == "Failed" && job.params["request_id"].is_null() {
                self.db.conn().execute(
                    "UPDATE agents SET missed_at=COALESCE(missed_at, ?2) \
                     WHERE id=?1 AND json_extract(laptop,'$.run_missed')=1",
                    params![a, ended],
                )?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_doubles_and_caps() {
        assert_eq!(backoff(120, 0), 120);
        assert_eq!(backoff(120, 1), 240);
        assert_eq!(backoff(120, 2), 480);
        assert_eq!(backoff(120, 3), 900);
        assert_eq!(backoff(120, 50), 900);
    }

    #[test]
    fn laptop_rules() {
        let l = Laptop {
            min_battery: 20,
            skip_metered: true,
            run_missed: true,
            retry_hours: 0,
        };
        let p = |b: bool, pct: u64, m: bool| json!({"on_battery": b, "battery_percent": pct, "metered": m});
        assert_eq!(
            laptop_hold(&l, Some(true), &p(true, 15, false), true).as_deref(),
            Some("on battery (15 % < 20 %)")
        );
        assert_eq!(laptop_hold(&l, Some(true), &p(true, 25, false), true), None);
        assert_eq!(laptop_hold(&l, Some(true), &p(false, 5, false), true), None, "on mains");
        assert_eq!(
            laptop_hold(&l, Some(true), &p(false, 90, true), true).as_deref(),
            Some("metered network")
        );
        assert_eq!(
            laptop_hold(&l, Some(true), &p(true, 5, true), false),
            None,
            "stale power state"
        );
        assert_eq!(
            laptop_hold(&l, Some(false), &Value::Null, true).as_deref(),
            Some("not reachable")
        );
        assert_eq!(
            laptop_hold(&Laptop::default(), Some(false), &p(true, 1, true), true),
            None
        );
        assert_eq!(l.retry_secs(), 24 * 3600);
    }

    #[test]
    fn summary_from_group_log() {
        let a = "0123456789abcdef";
        let b = "fedcba9876543210";
        let log = format!(
            "agent-info {{\"agent_id\":\"{b}\"}}\nscan: 1 entries, 1 files, 5 bytes\ncommitted host-{b}/77 in 1s\n\
             agent-info {{\"agent_id\":\"{a}\"}}\nscan: 9 entries, 4 files, 1000 bytes, 0 unchanged, 3 distinct chunks\n\
             agent: \"/x: permission denied\"\ncommitted host-{a}/88 in 2s: …\n\
             nexus-stats {{\"source\":\"host-{a}\",\"time\":88,\"read\":600,\"logical\":1000,\"new_chunks\":2,\"new_plain\":500,\"new_stored\":300}}\n"
        );
        let job = Job {
            id: 5,
            kind: "backup".into(),
            tenant: "t".into(),
            params: json!({"group_id": 1}),
        };
        let s = summary(&job, a, "ok", 10, 20, &log);
        assert_eq!(s["result"], "Warning");
        assert_eq!(
            (
                s["read_bytes"].as_u64(),
                s["transferred_bytes"].as_u64(),
                s["new_bytes"].as_u64()
            ),
            (Some(1000), Some(600), Some(300))
        );
        assert_eq!(s["snapshot_time"], 88);
        assert!(!s["log_tail"].to_string().contains(b), "other agents' lines stay out");
        let f = summary(
            &job,
            a,
            "failed",
            10,
            20,
            &format!("[scheduler] x\nError: connect {a}: refused\n"),
        );
        assert_eq!(f["result"], "Failed");
        assert!(f["first_error"].as_str().unwrap().contains("refused"));
        assert_eq!(summary(&job, a, "cancelled", 1, 2, "")["result"], "Cancelled");
    }
}
