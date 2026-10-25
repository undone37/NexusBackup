//! Agent updates pushed from the appliance (Phase 27, docs/agent-update-plan.md
//! "Implementation"):
//! - `agent_update` jobs install a signed release from the release store
//!   (`nexus-agentctl update`, config `update`); without any release in the store the
//!   single-binary update directory of earlier releases is used;
//! - the rollout poller queues those jobs per wave (canary first, the rest after the
//!   soak time), within the concurrency cap and the maintenance windows, never for busy,
//!   unreachable or blacked-out agents, and pauses a rollout at the failure threshold;
//! - automatic mode (per tenant / group) starts one rollout per new release;
//! - per agent the update state, `agent_update_failed` / `rollout_paused` alerts.

use crate::{valid_agent_id, Job, Scheduler, ACTOR};
use agent_core::releases::{self, Release};
use anyhow::{bail, Context, Result};
use catalog::agent_updates::{self as au, Scope, Spec, ALERT_FAILED, ALERT_PAUSED};
use catalog::rusqlite::{params, OptionalExtension};
use catalog::schedule::{self, Window};
use serde_json::{json, Value};
use std::path::PathBuf;

/// Automatic mode looks for new releases this often.
pub(crate) const AUTO_EVERY_SECS: i64 = 600;
/// The failure share pauses a rollout only once this many agents finished.
pub(crate) const MIN_SAMPLE: i64 = 5;

/// The outcome line of `nexus-agentctl update`.
pub(crate) fn update_result(log: &str) -> Option<Value> {
    log.lines()
        .rev()
        .find_map(|l| serde_json::from_str::<Value>(l.strip_prefix("update-result ")?).ok())
}

/// Any maintenance window active at `now` (UTC); no windows = any time.
pub(crate) fn in_windows(windows: &[Window], now: i64) -> bool {
    windows.is_empty() || schedule::blackout(windows, schedule::Tz::UTC, now).is_some()
}

impl Scheduler {
    fn release_dirs(&self) -> Vec<(PathBuf, &'static str)> {
        vec![
            (self.cfg.agent_update_dir.clone(), "image"),
            (self.cfg.agent_release_upload.clone(), "upload"),
        ]
    }

    pub(crate) fn agent_releases(&self) -> Vec<Release> {
        releases::scan(
            &self.release_dirs(),
            &agent_core::update::load_keys(&self.cfg.agent_release_keys),
        )
    }

    /// `nexus-agentctl update` config of an `agent_update` job: a release of the
    /// store (`version`, default the recommended one) or, without any, the legacy
    /// update directory. A rollback only for an approved, running rollback rollout.
    pub(crate) fn agent_update_config(&self, p: &Value) -> Result<Value> {
        let rollback = p["rollback"].as_bool() == Some(true);
        if rollback {
            let id = p["rollout_id"].as_i64().context("rollback without a rollout")?;
            let ok: Option<(bool, String, String)> = self
                .db
                .conn()
                .query_row(
                    "SELECT rollback, state, version FROM agent_rollouts WHERE id = ?1",
                    [id],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
                .optional()?;
            match ok {
                Some((true, s, v)) if s == "running" && Some(v.as_str()) == p["version"].as_str() => {}
                _ => bail!("rollback refused: rollout {id} is not an approved, running rollback"),
            }
        }
        let rs = self.agent_releases();
        let version = match p["version"].as_str() {
            Some(v) => Some(v.to_owned()),
            None => releases::recommended(&rs).map(|r| r.version.clone()),
        };
        Ok(match version {
            Some(v) => json!({"update": {
                "version": v, "rollback": rollback,
                "dirs": self.release_dirs().into_iter().map(|d| d.0).collect::<Vec<_>>(),
                "keys_dir": self.cfg.agent_release_keys,
            }}),
            None => json!({"update_dir": self.cfg.agent_update_dir}),
        })
    }

    /// After an `agent_update` job: the agent's update state, the rollout item, alerts.
    /// Returns true when the failure is handled here (no generic `job_failed` alert).
    pub(crate) fn update_bookkeeping(&mut self, job: &Job, state: &str, log: &str) -> Result<bool> {
        let Some(agent) = job.params["agent_id"].as_str().filter(|a| valid_agent_id(a)) else {
            return Ok(false);
        };
        let r = update_result(log);
        let outcome = match (&r, state) {
            (_, "cancelled") => "cancelled".to_owned(),
            (Some(r), _) => r["state"].as_str().unwrap_or("failed").to_owned(),
            (None, "ok") => "ok".into(),
            // never reached the agent (no `agent-info`): it is away, e.g. a laptop between networks; the rollout
            // waits for it instead of counting a failure (#66)
            (None, _) if !log.lines().any(|l| l.starts_with("agent-info ")) => "unreachable".into(),
            (None, _) => "failed".into(),
        };
        let error = r
            .as_ref()
            .and_then(|r| r["error"].as_str().map(str::to_owned))
            .filter(|e| !e.is_empty())
            .or_else(|| {
                (outcome == "failed").then(|| {
                    log.lines()
                        .rev()
                        .find(|l| !l.trim().is_empty() && !crate::run::is_time_mark(l))
                        .unwrap_or("failed")
                        .to_owned()
                })
            })
            .map(|e| e.chars().take(500).collect::<String>());
        let target = job.params["version"]
            .as_str()
            .map(str::to_owned)
            .or_else(|| {
                log.lines()
                    .find_map(|l| serde_json::from_str::<Value>(l.strip_prefix("update-plan ")?).ok())
                    .and_then(|v| v["to"].as_str().map(str::to_owned))
            })
            .or_else(|| {
                r.as_ref()
                    .filter(|_| outcome == "ok")
                    .and_then(|r| r["version"].as_str().map(str::to_owned))
            });
        let now = catalog::now();
        let col = match outcome.as_str() {
            "ok" => Some("ok"),
            "rolled_back" => Some("rolled_back"),
            "busy" | "cancelled" | "unreachable" => None,
            _ => Some("failed"),
        };
        if outcome == "unreachable" {
            // held (update_hold) until the poller sees it again
            self.db
                .conn()
                .execute("UPDATE agents SET reachable = 0 WHERE id = ?1", [agent])?;
        }
        {
            let c = self.db.conn();
            match col {
                Some(s) => c.execute(
                    "UPDATE agents SET update_state = ?2, update_error = ?3, update_target = COALESCE(?4, update_target), \
                     update_attempts = update_attempts + 1, update_at = ?5 WHERE id = ?1",
                    params![agent, s, if s == "ok" { None } else { error.clone() }, target, now],
                )?,
                None => c.execute(
                    "UPDATE agents SET update_state = CASE WHEN update_state IN ('pending','sending','installing') \
                     THEN NULL ELSE update_state END, update_at = ?2 WHERE id = ?1",
                    params![agent, now],
                )?,
            };
        }
        let key = format!("{ALERT_FAILED}:{agent}");
        match col {
            Some("ok") => self.resolve(&key)?,
            Some(s) => {
                let (name, install): (String, Option<String>) = self
                    .db
                    .conn()
                    .query_row("SELECT name, install FROM agents WHERE id = ?1", [agent], |r| {
                        Ok((r.get(0)?, r.get(1)?))
                    })
                    .optional()?
                    .unwrap_or_else(|| (agent.to_owned(), None));
                let to = target.as_deref().unwrap_or("the new release");
                // #96: the agent is offline after its update (a failed Windows Installer upgrade can leave no
                // agent at all): critical, with what the admin has to do on the host
                let lost = error.as_deref().is_some_and(|e| e.contains("did not come back"));
                let msg = if lost {
                    let fix = if install.as_deref() == Some("msi") {
                        let msi = target
                            .as_deref()
                            .map_or("the current nexus-agent .msi".to_owned(), |v| {
                                format!("nexus-agent {v} (.msi)")
                            });
                        format!(
                            "if the NexusAgent service is gone, install {msi} by hand: the enrollment in \
                             ProgramData is kept and the agent comes back on its own"
                        )
                    } else {
                        "check the agent service on the host (its previous version is restored after three \
                         failed starts)"
                            .to_owned()
                    };
                    format!("agent {name} is offline after its update to {to}: {fix}")
                } else {
                    format!(
                        "update of agent {name} to {to} {}: {}",
                        if s == "rolled_back" {
                            "was rolled back"
                        } else {
                            "failed"
                        },
                        error.as_deref().unwrap_or("")
                    )
                };
                self.raise(
                    if lost { "critical" } else { "warning" },
                    ALERT_FAILED,
                    &key,
                    &msg,
                    crate::lifecycle::tenant_of(job),
                )?;
            }
            None => {}
        }
        // the rollout item follows its job
        if let Some(rid) = job.params["rollout_id"].as_i64() {
            let item = match outcome.as_str() {
                "ok" => "ok",
                "busy" | "unreachable" => "waiting",
                "cancelled" => "cancelled",
                _ => "failed",
            };
            self.db.conn().execute(
                "UPDATE agent_rollout_items SET state = CASE WHEN ?3 = 'cancelled' AND \
                   (SELECT state FROM agent_rollouts WHERE id = ?1) NOT IN ('cancelled') THEN 'waiting' ELSE ?3 END, \
                 job_id = CASE WHEN ?3 = 'waiting' THEN NULL ELSE job_id END, \
                 attempts = attempts + CASE WHEN ?3 = 'waiting' THEN 0 ELSE 1 END, \
                 error = ?4, updated = ?5 WHERE rollout_id = ?1 AND agent_id = ?2",
                params![rid, agent, item, if item == "ok" { None } else { error }, now],
            )?;
        }
        Ok(true)
    }

    /// Host facts of an `agent-info` line / poll result (protocol v1.8 capabilities).
    pub(crate) fn agent_facts(&self, id: &str, info: &Value) -> Result<()> {
        let Some(caps) = info["caps"].as_array() else {
            return Ok(());
        };
        let caps: Vec<String> = caps
            .iter()
            .filter_map(|c| c.as_str())
            .filter(|c| c.len() <= 64)
            .take(64)
            .map(str::to_owned)
            .collect();
        let os = info["os"].as_str().unwrap_or_default();
        let f = agent_proto::release::HostFacts::from_caps(os, &caps);
        self.db.conn().execute(
            "UPDATE agents SET arch = ?2, install = ?3, gui_version = ?4, caps = ?5 WHERE id = ?1",
            params![id, f.arch, f.install, f.gui_version, serde_json::to_string(&caps)?],
        )?;
        Ok(())
    }

    /// The rollout poller (every tick).
    pub(crate) fn agent_rollouts(&mut self, now: i64) -> Result<()> {
        self.rollout_approvals(now)?;
        let ids: Vec<i64> = self
            .db
            .conn()
            .prepare("SELECT id FROM agent_rollouts WHERE state = 'running' ORDER BY id")?
            .query_map([], |r| r.get(0))?
            .collect::<Result<_, _>>()?;
        for id in ids {
            if let Err(e) = self.rollout_step(id, now) {
                eprintln!("<3>scheduler: rollout {id}: {e:#}");
            }
        }
        if now - self.auto_checked >= AUTO_EVERY_SECS {
            self.auto_checked = now;
            self.automatic_rollouts(now)?;
        }
        Ok(())
    }

    /// Rollback rollouts whose approval was rejected or expired.
    fn rollout_approvals(&mut self, now: i64) -> Result<()> {
        let c = self.db.conn();
        let n = c.execute(
            "UPDATE agent_rollouts SET state = 'rejected', finished = ?1, reason = 'approval ' || \
               (SELECT q.state FROM quorum q WHERE q.id = agent_rollouts.quorum_id) \
             WHERE state = 'pending_approval' AND quorum_id IN (SELECT id FROM quorum WHERE state IN ('rejected','expired'))",
            [now],
        )?;
        if n > 0 {
            c.execute(
                "UPDATE agent_rollout_items SET state = 'cancelled', updated = ?1 WHERE state = 'waiting' AND \
                 rollout_id IN (SELECT id FROM agent_rollouts WHERE state = 'rejected')",
                [now],
            )?;
        }
        Ok(())
    }

    fn rollout_step(&mut self, id: i64, now: i64) -> Result<()> {
        struct R {
            version: String,
            soak: i64,
            concurrency: i64,
            max_failures: i64,
            max_pct: i64,
            windows: Vec<Window>,
            rollback: bool,
            wave: i64,
            wave_done_at: Option<i64>,
            created_by: String,
        }
        let r = self.db.conn().query_row(
            "SELECT version, soak_minutes, concurrency, max_failures, max_failure_pct, windows, rollback, wave, \
             wave_done_at, created_by FROM agent_rollouts WHERE id = ?1",
            [id],
            |r| {
                Ok(R {
                    version: r.get(0)?,
                    soak: r.get(1)?,
                    concurrency: r.get(2)?,
                    max_failures: r.get(3)?,
                    max_pct: r.get(4)?,
                    windows: serde_json::from_str(&r.get::<_, String>(5)?).unwrap_or_default(),
                    rollback: r.get(6)?,
                    wave: r.get(7)?,
                    wave_done_at: r.get(8)?,
                    created_by: r.get(9)?,
                })
            },
        )?;
        self.resolve(&format!("{ALERT_PAUSED}:{id}"))?;
        // items whose job ended without bookkeeping (scheduler restart): follow the job
        self.db.conn().execute(
            "UPDATE agent_rollout_items SET state = CASE (SELECT state FROM jobs WHERE id = job_id) \
               WHEN 'running' THEN 'running' WHEN 'queued' THEN 'queued' WHEN 'ok' THEN 'ok' \
               WHEN 'cancelled' THEN 'waiting' ELSE 'failed' END, updated = ?2 \
             WHERE rollout_id = ?1 AND state IN ('queued','running') AND job_id IS NOT NULL \
               AND (SELECT state FROM jobs WHERE id = job_id) IS NOT state",
            params![id, now],
        )?;
        let count = |sql: &str| -> Result<i64> {
            Ok(self.db.conn().query_row(
                &format!("SELECT COUNT(*) FROM agent_rollout_items WHERE rollout_id = ?1 AND {sql}"),
                [id],
                |r| r.get(0),
            )?)
        };
        // failure threshold; a failed canary always pauses
        let failed = count("state = 'failed'")?;
        let finished = count("state IN ('ok','failed')")?;
        let canary_failed = count("wave = 0 AND state = 'failed'")?;
        let pause = if canary_failed > 0 && r.wave == 0 {
            Some(format!("{canary_failed} canary agent(s) failed"))
        } else if r.max_failures > 0 && failed >= r.max_failures {
            Some(format!("{failed} agents failed (threshold {})", r.max_failures))
        } else if r.max_pct > 0 && finished >= MIN_SAMPLE && failed * 100 >= r.max_pct * finished {
            Some(format!(
                "{failed} of {finished} agents failed (threshold {} %)",
                r.max_pct
            ))
        } else {
            None
        };
        if let Some(why) = pause {
            self.db.conn().execute(
                "UPDATE agent_rollouts SET state = 'paused', reason = ?2 WHERE id = ?1",
                params![id, why],
            )?;
            self.db.audit(
                ACTOR,
                "agent.rollout.pause",
                &format!("agent-rollout/{id}"),
                &json!({"reason": why}),
            )?;
            self.raise(
                "warning",
                ALERT_PAUSED,
                &format!("{ALERT_PAUSED}:{id}"),
                &format!("agent rollout {id} to {} paused: {why}", r.version),
                None,
            )?;
            return Ok(());
        }
        // done?
        if count("state IN ('waiting','queued','running')")? == 0 {
            self.db.conn().execute(
                "UPDATE agent_rollouts SET state = 'done', finished = ?2 WHERE id = ?1",
                params![id, now],
            )?;
            self.db.audit(
                ACTOR,
                "agent.rollout.done",
                &format!("agent-rollout/{id}"),
                &json!({"failed": failed}),
            )?;
            return Ok(());
        }
        // canary wave finished: soak, then the rest
        if r.wave == 0 && count("wave = 0 AND state IN ('waiting','queued','running')")? == 0 {
            match r.wave_done_at {
                None => {
                    self.db.conn().execute(
                        "UPDATE agent_rollouts SET wave_done_at = ?2 WHERE id = ?1",
                        params![id, now],
                    )?;
                    if r.soak > 0 {
                        return Ok(());
                    }
                }
                Some(t) if now < t + r.soak * 60 => return Ok(()),
                Some(_) => {}
            }
            self.db
                .conn()
                .execute("UPDATE agent_rollouts SET wave = 1 WHERE id = ?1", [id])?;
            return Ok(());
        }
        if !in_windows(&r.windows, now) {
            return Ok(());
        }
        let active = count("state IN ('queued','running')")?;
        let mut free = (r.concurrency - active).max(0);
        if free == 0 {
            return Ok(());
        }
        let waiting: Vec<(String, String)> = self
            .db
            .conn()
            .prepare(
                "SELECT agent_id, tenant FROM agent_rollout_items WHERE rollout_id = ?1 AND state = 'waiting' \
                 AND wave <= ?2 ORDER BY wave, tenant, agent_id",
            )?
            .query_map(params![id, r.wave], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect::<Result<_, _>>()?;
        for (agent, tenant) in waiting {
            if free == 0 {
                break;
            }
            // updated meanwhile (another rollout, by hand): nothing to do
            let current: Option<String> = self
                .db
                .conn()
                .query_row("SELECT version FROM agents WHERE id = ?1", [&agent], |r| r.get(0))
                .optional()?
                .flatten();
            if let Some(why) = au::skip_reason(current.as_deref(), &r.version, r.rollback) {
                self.db.conn().execute(
                    "UPDATE agent_rollout_items SET state = 'skipped', error = ?3, updated = ?4 \
                     WHERE rollout_id = ?1 AND agent_id = ?2",
                    params![id, agent, why, now],
                )?;
                continue;
            }
            if self.update_hold(&tenant, &agent, now)?.is_some() {
                continue; // busy, unreachable or blacked out: stays waiting, picked up later
            }
            let mut p = json!({"agent_id": agent, "version": r.version, "rollout_id": id});
            if r.rollback {
                p["rollback"] = json!(true);
            }
            let job = self.insert_job("agent_update", &tenant, &p)?;
            let c = self.db.conn();
            c.execute(
                "UPDATE jobs SET requested_by = ?2 WHERE id = ?1",
                params![job, format!("rollout:{id} ({})", r.created_by)],
            )?;
            c.execute(
                "UPDATE agent_rollout_items SET state = 'queued', job_id = ?3, updated = ?4 WHERE rollout_id = ?1 AND agent_id = ?2",
                params![id, agent, job, now],
            )?;
            c.execute(
                "UPDATE agents SET update_state = 'pending', update_target = ?2, update_at = ?3 WHERE id = ?1",
                params![agent, r.version, now],
            )?;
            free -= 1;
        }
        Ok(())
    }

    /// Why an agent's update waits (`None` = it may start now): a job of the agent
    /// queued or running (busy), unreachable at the last poll (picked up once it is
    /// back), or a blackout window of one of its groups' policies.
    pub(crate) fn update_hold(&self, tenant: &str, agent: &str, now: i64) -> Result<Option<&'static str>> {
        let groups: Vec<i64> = self
            .groups()?
            .into_iter()
            .filter(|g| g.tenant == tenant && g.agents.iter().any(|a| a == agent))
            .map(|g| g.id)
            .collect();
        let busy: i64 = self.db.conn().query_row(
            "SELECT COUNT(*) FROM jobs WHERE state IN ('queued','running') AND tenant = ?1 AND \
             (json_extract(params, '$.agent_id') = ?2 OR json_extract(params, '$.group_id') IN \
               (SELECT value FROM json_each(?3)))",
            params![tenant, agent, serde_json::to_string(&groups)?],
            |r| r.get(0),
        )?;
        if busy > 0 {
            return Ok(Some("busy"));
        }
        let reachable: Option<bool> = self
            .db
            .conn()
            .query_row("SELECT reachable FROM agents WHERE id = ?1", [agent], |r| r.get(0))
            .optional()?
            .flatten();
        if reachable == Some(false) {
            return Ok(Some("unreachable"));
        }
        for g in groups {
            if let Ok(ctl) = self.control(g) {
                if let Ok(tz) = schedule::tz(&ctl.tz) {
                    if schedule::blackout(&ctl.blackout, tz, now).is_some() {
                        return Ok(Some("blackout"));
                    }
                }
            }
        }
        Ok(None)
    }

    /// Automatic mode: per `agent_update_settings` row with `automatic`, one rollout to
    /// the recommended release for the outdated agents of its scope.
    pub(crate) fn automatic_rollouts(&mut self, now: i64) -> Result<()> {
        let rows: Vec<(String, i64, String, i64, i64)> = self
            .db
            .conn()
            .prepare(
                "SELECT tenant, group_id, windows, canary, soak_minutes FROM agent_update_settings \
                 WHERE mode = 'automatic' ORDER BY tenant, group_id",
            )?
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)))?
            .collect::<Result<_, _>>()?;
        if rows.is_empty() {
            return Ok(());
        }
        let rs = self.agent_releases();
        let Some(rec) = releases::recommended(&rs) else {
            return Ok(());
        };
        let disabled = self.disabled_tenants()?;
        for (tenant, group, windows, canary, soak) in rows {
            if disabled.contains(&tenant) {
                continue;
            }
            let scope = Scope {
                tenant: Some(tenant.clone()),
                group_id: (group != 0).then_some(group),
                ..Default::default()
            };
            let scope_json = serde_json::to_string(&scope)?;
            let exists: i64 = self.db.conn().query_row(
                "SELECT COUNT(*) FROM agent_rollouts WHERE automatic = 1 AND version = ?1 AND scope = ?2",
                params![rec.version, scope_json],
                |r| r.get(0),
            )?;
            if exists > 0 {
                continue;
            }
            let outdated = {
                let c = self.db.conn();
                au::scope_agents(&c, &scope, None)?
                    .into_iter()
                    .filter(|a| au::skip_reason(a.version.as_deref(), &rec.version, false).is_none())
                    .count()
            };
            if outdated == 0 {
                continue;
            }
            let spec = Spec {
                version: rec.version.clone(),
                scope,
                canary: u32::try_from(canary).unwrap_or(1),
                canary_pct: None,
                soak_minutes: u32::try_from(soak).unwrap_or(60),
                concurrency: 5,
                max_failures: 3,
                max_failure_pct: 20,
                windows: serde_json::from_str(&windows).unwrap_or_default(),
                rollback: false,
            };
            let id = {
                let mut c = self.db.conn();
                let tx = c.transaction()?;
                let id = au::create(&tx, &spec, ACTOR, None, true, "running", now)?;
                tx.commit()?;
                id
            };
            self.db.audit(
                ACTOR,
                "agent.rollout.create",
                &format!("agent-rollout/{id}"),
                &json!({"automatic": true, "spec": spec}),
            )?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn result_lines_and_windows() {
        let log = "agent-info {}\nupdate-result {\"state\":\"busy\"}\nx\nupdate-result {\"state\":\"ok\",\"version\":\"0.2.0\"}\n";
        assert_eq!(update_result(log).unwrap()["state"], "ok");
        assert!(update_result("nothing").is_none());
        assert!(in_windows(&[], 0));
        let w = Window {
            days: vec![],
            from: "02:00".into(),
            to: "04:00".into(),
            abort: false,
        };
        let day = 1_700_006_400; // 2023-11-15 00:00 UTC
        assert!(!in_windows(std::slice::from_ref(&w), day + 3600));
        assert!(in_windows(std::slice::from_ref(&w), day + 3 * 3600));
    }
}
