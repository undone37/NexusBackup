//! Run control (Phase 13b, docs/control-plane.md "Run control"): pause and
//! maintenance, blackout windows, retries of failed backups, the run-time SLA,
//! and cancelling running jobs.
//!
//! Cancelling: the web-api (or a blackout window with `abort`) sets
//! `jobs.cancel_by` on a running job; [`Scheduler::process_cancels`] marks it in
//! the worker's [`run::Cancels`] (SIGTERM to the connector's process group,
//! SIGKILL after `cancel_grace_secs`) and the job ends `cancelled`. A connector
//! killed mid-backup leaves no snapshot behind: the chunk store writes the
//! manifest last (`Store::commit_snapshot`), and chunks without a manifest are
//! removed by the next GC after the grace period.

use super::*;
use catalog::schedule::{self, Retry, Window};

/// Run-control settings of a group (its policy, its source).
pub(crate) struct Control {
    pub name: String,
    pub tz: String,
    pub paused_until: Option<i64>,
    pub maintenance_until: Option<i64>,
    pub blackout: Vec<Window>,
    pub retry: Retry,
}

impl Control {
    /// Why no scheduled run may start now (`None` = it may).
    pub fn hold(&self, now: i64) -> Option<&'static str> {
        if schedule::paused(self.paused_until, now) {
            return Some("paused");
        }
        if schedule::paused(self.maintenance_until, now) {
            return Some("maintenance");
        }
        let tz = schedule::tz(&self.tz).ok()?;
        schedule::blackout(&self.blackout, tz, now).map(|_| "blackout")
    }
}

/// The group's guests restricted to `params.guests` (retries, "back up now" for
/// some guests). Without the key, or for a whole-source plugin group, unchanged.
pub(crate) fn restrict(mut g: GroupRow, p: &Value) -> GroupRow {
    let Some(only) = p["guests"].as_array() else { return g };
    let has_str = |x: &str| only.iter().any(|v| v.as_str() == Some(x));
    g.guests
        .retain(|v| only.iter().any(|x| x.as_u64() == Some(u64::from(*v))));
    g.agents.retain(|a| has_str(a));
    g.datasets.retain(|d| has_str(d));
    if let Some((_, guests)) = &mut g.plugin {
        if !guests.is_empty() {
            guests.retain(|x| has_str(x));
        }
    }
    g
}

/// Snapshot sources with a `committed <source>/<time>` line in a backup log.
fn committed(log: &str) -> HashSet<&str> {
    log.lines()
        .filter_map(|l| {
            let id = l.strip_prefix("committed ")?.split_whitespace().next()?;
            Some(id.rsplit_once('/')?.0)
        })
        .collect()
}

impl Scheduler {
    pub(crate) fn control(&self, group_id: i64) -> Result<Control> {
        Ok(self.db.conn().query_row(
            "SELECT g.name, g.timezone, g.paused_until, s.maintenance_until, p.blackout, p.retry \
             FROM groups g JOIN policies p ON p.id = g.policy_id JOIN sources s ON s.id = g.source_id WHERE g.id = ?1",
            [group_id],
            |r| {
                Ok(Control {
                    name: r.get(0)?,
                    tz: r.get(1)?,
                    paused_until: r.get(2)?,
                    maintenance_until: r.get(3)?,
                    blackout: serde_json::from_str(&r.get::<_, String>(4)?).unwrap_or_default(),
                    retry: serde_json::from_str(&r.get::<_, String>(5)?).unwrap_or_default(),
                })
            },
        )?)
    }

    /// Guests of a failed group backup without a committed snapshot (`None`:
    /// not determinable, e.g. a share or a whole plugin source: retry all of it).
    fn failed_guests(&self, job: &Job, log: &str) -> Option<Vec<Value>> {
        let gid = job.params["group_id"].as_i64()?;
        let g = self
            .groups()
            .ok()?
            .into_iter()
            .find(|g| g.id == gid && g.tenant == job.tenant)?;
        let g = restrict(g, &job.params);
        if g.share || g.plugin.as_ref().is_some_and(|(_, x)| x.is_empty()) {
            return None;
        }
        let done = committed(log);
        let sid = g.source_id as u64;
        let mut out: Vec<Value> = Vec::new();
        for v in &g.guests {
            if !done.contains(format!("vm-{v}").as_str()) && !done.contains(format!("ct-{v}").as_str()) {
                out.push(json!(v));
            }
        }
        for a in &g.agents {
            if !done.contains(format!("host-{a}").as_str()) {
                out.push(json!(a));
            }
        }
        for d in &g.datasets {
            if !done.contains(truenas::source_name(sid, d).as_str()) {
                out.push(json!(d));
            }
        }
        if let Some((pid, guests)) = &g.plugin {
            for x in guests {
                if !done.contains(plugin_proto::source_name(pid, sid, Some(x)).as_str()) {
                    out.push(json!(x));
                }
            }
        }
        (!out.is_empty()).then_some(out)
    }

    /// `jobs.result` of a failed group backup: the guests to retry ("back up
    /// now" with `failed_only` reads it).
    pub(crate) fn failed_result(&self, job: &Job, log: &str) -> Option<Value> {
        if job.kind != "backup" || job.params["group_id"].is_null() {
            return None;
        }
        let failed = self.failed_guests(job, log).map_or(Value::Null, Value::from);
        Some(json!({ "failed_guests": failed }))
    }

    /// A failed group backup with attempts left: queues the next attempt for
    /// the failed guests after the policy's delay; the failure goes into the log
    /// (no `job_failed` alert yet). Not while the group or source is paused.
    pub(crate) fn retry_failed(&mut self, job: &Job, log: &str) -> Result<bool> {
        let Some(gid) = job.params["group_id"].as_i64().filter(|_| job.kind == "backup") else {
            return Ok(false);
        };
        let Ok(ctl) = self.control(gid) else { return Ok(false) };
        let now = catalog::now();
        if schedule::paused(ctl.paused_until, now) || schedule::paused(ctl.maintenance_until, now) {
            return Ok(false);
        }
        let (attempt, root): (i64, Option<i64>) =
            self.db
                .conn()
                .query_row("SELECT attempt, retry_of FROM jobs WHERE id=?1", [job.id], |r| {
                    Ok((r.get(0)?, r.get(1)?))
                })?;
        let total = 1 + i64::from(ctl.retry.count);
        if attempt >= total {
            return Ok(false);
        }
        let mut params = job.params.clone();
        let guests = self.failed_guests(job, log);
        if let Some(f) = &guests {
            params["guests"] = json!(f);
        }
        let not_before = now + i64::from(ctl.retry.delay_min) * 60;
        let root = root.unwrap_or(job.id);
        let id =
            {
                let c = self.db.conn();
                c.execute(
                "INSERT INTO jobs (kind, tenant, params, state, requested_by, created, not_before, attempt, retry_of) \
                 VALUES ('backup', ?1, ?2, 'queued', ?3, ?4, ?5, ?6, ?7)",
                params![job.tenant, params.to_string(), ACTOR, self.now, not_before, attempt + 1, root],
            )?;
                let id = c.last_insert_rowid();
                c.execute(
                    "UPDATE jobs SET log = log || ?2 WHERE id = ?1",
                    params![
                        job.id,
                        format!(
                            "[scheduler] attempt {attempt} of {total} failed; retry as job {id} in {} min{}\n",
                            ctl.retry.delay_min,
                            guests
                                .as_ref()
                                .map_or(String::new(), |g| format!(" for {}", Value::from(g.clone())))
                        )
                    ],
                )?;
                id
            };
        self.db.audit(
            ACTOR,
            "job.retry",
            &format!("job/{id}"),
            &json!({"retry_of": root, "failed_job": job.id, "attempt": attempt + 1, "not_before": not_before,
                    "params": params}),
        )?;
        Ok(true)
    }

    /// ` (attempt n of m)` for the final failure of a retried job.
    pub(crate) fn attempt_note(&self, id: i64) -> String {
        let a: i64 = self
            .db
            .conn()
            .query_row("SELECT attempt FROM jobs WHERE id=?1", [id], |r| r.get(0))
            .unwrap_or(1);
        if a > 1 {
            format!(" after {a} attempts")
        } else {
            String::new()
        }
    }

    /// Cancel requests (`jobs.cancel_by`) of running jobs: SIGTERM first, SIGKILL
    /// after the grace period.
    pub(crate) fn process_cancels(&mut self) -> Result<()> {
        let ids: Vec<(i64, String)> = {
            let c = self.db.conn();
            let mut st = c.prepare("SELECT id, cancel_by FROM jobs WHERE state='running' AND cancel_by IS NOT NULL")?;
            let rows = st.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?;
            rows.collect::<std::result::Result<_, _>>()?
        };
        let grace = Duration::from_secs(self.cfg.cancel_grace_secs);
        for (id, by) in ids {
            if !self.running.contains_key(&id) {
                continue;
            }
            match self.cancel_sent.get(&id) {
                None => {
                    eprintln!("scheduler: cancelling job {id} (requested by {by})");
                    self.ctx.cancels.request(id);
                    self.cancel_sent.insert(id, Instant::now());
                }
                Some(t) if t.elapsed() >= grace => self.ctx.cancels.kill(id),
                Some(_) => {}
            }
        }
        Ok(())
    }

    /// Running backups of groups whose policy has a blackout window with
    /// `abort` that began after the job started: cancelled (`cancel_by = blackout`).
    pub(crate) fn blackout_aborts(&self, now: i64) -> Result<()> {
        let rows: Vec<(i64, i64, i64)> = {
            let c = self.db.conn();
            let mut st = c.prepare(
                "SELECT id, json_extract(params,'$.group_id'), started FROM jobs \
                 WHERE kind='backup' AND state='running' AND cancel_by IS NULL \
                 AND json_extract(params,'$.group_id') IS NOT NULL AND started IS NOT NULL",
            )?;
            let rows = st.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
            rows.collect::<std::result::Result<_, _>>()?
        };
        for (id, gid, started) in rows {
            let Ok(ctl) = self.control(gid) else { continue };
            let Ok(tz) = schedule::tz(&ctl.tz) else { continue };
            let Some(start) = schedule::abort_since(&ctl.blackout, tz, now) else {
                continue;
            };
            if started >= start {
                continue; // started inside the window (manual run): allowed
            }
            let n = self.db.conn().execute(
                "UPDATE jobs SET cancel_by='blackout' WHERE id=?1 AND state='running' AND cancel_by IS NULL",
                [id],
            )?;
            if n == 1 {
                self.db.audit(
                    ACTOR,
                    "job.cancel",
                    &format!("job/{id}"),
                    &json!({"reason": "blackout", "group": ctl.name}),
                )?;
            }
        }
        Ok(())
    }

    /// Running group backups longer than their policy's `sla_minutes`: one
    /// `sla_missed` warning per job.
    pub(crate) fn check_sla(&self, now: i64) -> Result<()> {
        let rows: Vec<(i64, String, String, i64, i64)> = {
            let c = self.db.conn();
            let mut st = c.prepare(
                "SELECT j.id, j.tenant, g.name, j.started, p.sla_minutes FROM jobs j \
                 JOIN groups g ON g.id = json_extract(j.params,'$.group_id') AND g.tenant = j.tenant \
                 JOIN policies p ON p.id = g.policy_id \
                 WHERE j.kind='backup' AND j.state='running' AND j.sla_alerted=0 AND p.sla_minutes IS NOT NULL \
                 AND j.started IS NOT NULL AND j.started + p.sla_minutes * 60 < ?1",
            )?;
            let rows = st.query_map([now], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)))?;
            rows.collect::<std::result::Result<_, _>>()?
        };
        for (id, tenant, group, started, sla) in rows {
            self.raise(
                "warning",
                "sla_missed",
                &format!("sla_missed:{id}"),
                &format!(
                    "backup job {id} of group {group} ({tenant}) still running after {} min (SLA {sla} min)",
                    (now - started) / 60
                ),
                Some(&tenant),
            )?;
            self.db
                .conn()
                .execute("UPDATE jobs SET sla_alerted=1 WHERE id=?1", [id])?;
        }
        Ok(())
    }

    /// Groups paused (or sources in maintenance) for more than 7 days or
    /// indefinitely: one `paused` warning per pause (key
    /// `paused:<group|source>:<id>:<until>`); resolved automatically once the
    /// group is resumed / the maintenance ended or changed.
    pub(crate) fn check_paused(&self, now: i64) -> Result<()> {
        let rows: Vec<(String, i64, String, String, Option<i64>)> = {
            let c = self.db.conn();
            let mut st = c.prepare(
                "SELECT 'group', id, name || ' (' || tenant || ')', tenant, paused_until FROM groups \
                 UNION ALL SELECT 'source', id, name || ' (' || tenant || ')', tenant, maintenance_until FROM sources",
            )?;
            let rows = st.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)))?;
            rows.collect::<std::result::Result<_, _>>()?
        };
        for (what, id, name, tenant, until) in rows {
            let long = until.filter(|u| *u == -1 || *u > now + 7 * 86400);
            let key = long.map(|u| format!("paused:{what}:{id}:{u}"));
            // open alerts of an earlier (or ended) pause of this group / source
            let stale: Vec<String> = {
                let c = self.db.conn();
                let mut st =
                    c.prepare("SELECT key FROM alerts WHERE kind = 'paused' AND resolved_at IS NULL AND key LIKE ?1")?;
                let rows = st.query_map([format!("paused:{what}:{id}:%")], |r| r.get::<_, String>(0))?;
                rows.collect::<std::result::Result<_, _>>()?
            };
            for k in stale.iter().filter(|k| Some(*k) != key.as_ref()) {
                self.resolve(k)?;
            }
            let (Some(key), Some(u)) = (key, long) else { continue };
            let seen: i64 = self
                .db
                .conn()
                .query_row("SELECT COUNT(*) FROM alerts WHERE key = ?1", [&key], |r| r.get(0))?;
            if seen > 0 {
                continue; // raised before (maybe resolved by a person): not again for this pause
            }
            let until = if u == -1 {
                "further notice".to_owned()
            } else {
                schedule::day(u)
            };
            let state = if what == "group" { "paused" } else { "in maintenance" };
            self.raise(
                "warning",
                "paused",
                &key,
                &format!("{what} {id} {name} {state} until {until}: no scheduled backups meanwhile"),
                Some(&tenant),
            )?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn committed_sources() {
        let log = "$ pve backup-all\ncommitted vm-100/5\nbackup of guest 101 failed: x\ncommitted host-ab/7 in 1s\n";
        let c = committed(log);
        assert!(c.contains("vm-100") && c.contains("host-ab") && c.len() == 2);
    }
}
