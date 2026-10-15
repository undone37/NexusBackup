//! Fleet enrollment, scheduler side (catalog::fleet, docs/agent-protocol.md "Fleet
//! enrollment"): `fleet_scan` jobs every `SCAN_SECS` per usable fleet with ranges
//! (nexus-agentctl `fleet-scan` probes the expanded addresses on the fleet port, at
//! most 8 at a time and 20 per second), the found agents become candidates, which an
//! `auto_accept` fleet accepts right away; `agent_enroll` of an agent accepted from a
//! fleet proves the fleet secret instead of a token. The firewall allows the range
//! addresses on the fleet port while the fleet is usable.

use super::*;
use catalog::fleet::{self, Fleet};

impl Scheduler {
    fn usable_fleets(&self, now: i64) -> Result<Vec<Fleet>> {
        let c = self.db.conn();
        let mut q = c.prepare(&format!(
            "SELECT {} FROM fleets WHERE revoked = 0 AND expires > ?1",
            fleet::COLS
        ))?;
        let rows = q.query_map([now], fleet::row)?;
        Ok(rows
            .filter_map(std::result::Result::ok)
            .filter(|f| f.unusable(now).is_none())
            .collect())
    }

    /// Queues a scan per usable fleet with ranges once `SCAN_SECS` passed.
    pub(crate) fn queue_fleet_scans(&self, now: i64) -> Result<()> {
        for f in self.usable_fleets(now)? {
            if f.ranges.is_empty() || f.last_scan.is_some_and(|t| now - t < fleet::SCAN_SECS) {
                continue;
            }
            let busy: bool = self.db.conn().query_row(
                "SELECT EXISTS (SELECT 1 FROM jobs WHERE kind = 'fleet_scan' AND state IN ('queued','running') \
                 AND json_extract(params,'$.fleet_id') = ?1)",
                [&f.id],
                |r| r.get(0),
            )?;
            if !busy {
                self.insert_job("fleet_scan", &f.tenant, &json!({"fleet_id": f.id}))?;
            }
            self.db
                .conn()
                .execute("UPDATE fleets SET last_scan = ?2 WHERE id = ?1", params![f.id, now])?;
        }
        Ok(())
    }

    /// The fleet of a job, valid now, and its secret digest. A scan also needs uses
    /// left; enrolling an agent already accepted (its use counted) does not.
    fn job_fleet(&self, job: &Job, scan: bool) -> Result<(Fleet, zeroize::Zeroizing<String>)> {
        let id = job.params["fleet_id"].as_str().unwrap_or_default();
        let f = fleet::load(&self.db.conn(), id)?
            .filter(|f| f.tenant == job.tenant)
            .with_context(|| format!("fleet {id:?} not found in tenant {}", job.tenant))?;
        let now = catalog::now();
        if let Some(why) = if scan { f.unusable(now) } else { f.invalid(now) } {
            bail!("fleet {}: {why}", f.name);
        }
        let digest = self
            .secrets
            .open(&fleet::secret_location(&f.id), &f.secret_hash)
            .with_context(|| format!("fleet {}", f.id))?;
        Ok((f, digest))
    }

    pub(crate) fn plan_fleet_scan(&self, job: &Job, mut plan: Plan) -> Result<Plan> {
        let (f, digest) = self.job_fleet(job, true)?;
        let targets = fleet::expand(&f.ranges).map_err(anyhow::Error::msg)?;
        plan.key = format!("fleet:{}", f.id);
        plan.files.push(("fleet-digest".into(), digest.as_bytes().to_vec()));
        let cfg = self.agentctl_base(
            &job.tenant,
            job,
            None,
            json!({"fleet": {"id": f.id, "digest_file": plan.dir.join("fleet-digest"), "port": f.port,
                             "targets": targets}}),
        );
        plan.files
            .push(("agentctl.json".into(), serde_json::to_vec_pretty(&cfg)?));
        plan.steps.push(Step::Cli {
            bin: self.cfg.agentctl_bin.clone(),
            args: vec![
                plan.dir.join("agentctl.json").to_string_lossy().into_owned(),
                "fleet-scan".into(),
            ],
            alert: None,
            capture: false,
        });
        Ok(plan)
    }

    /// `agent_enroll` of an agent accepted from a fleet: the fleet secret digest.
    pub(crate) fn fleet_enroll_digest(&self, job: &Job, a: &AgentRow) -> Result<zeroize::Zeroizing<String>> {
        let (f, digest) = self.job_fleet(job, false)?;
        let own: Option<String> =
            self.db
                .conn()
                .query_row("SELECT fleet_id FROM agents WHERE id = ?1", [&a.id], |r| r.get(0))?;
        if own.as_deref() != Some(f.id.as_str()) {
            bail!("agent {} was not accepted from fleet {}", a.name, f.name);
        }
        Ok(digest)
    }

    /// `fleet-agent {json}` lines of a scan: candidates, auto-accepted if the fleet says so.
    pub(crate) fn fleet_bookkeeping(&self, job: &Job, log: &str) -> Result<()> {
        let id = job.params["fleet_id"].as_str().unwrap_or_default();
        let Some(f) = fleet::load(&self.db.conn(), id)?.filter(|f| f.tenant == job.tenant) else {
            return Ok(());
        };
        let now = catalog::now();
        for l in log.lines() {
            let Some(v) = l
                .strip_prefix("fleet-agent ")
                .and_then(|j| serde_json::from_str::<Value>(j).ok())
            else {
                continue;
            };
            let Some(cand) = fleet::record(&self.db.conn(), &f.id, &v, now)? else {
                continue;
            };
            // re-read: uses / revocation change while accepting
            let usable = fleet::load(&self.db.conn(), &f.id)?.is_some_and(|f| f.unusable(now).is_none());
            if !(f.auto_accept && usable) {
                continue;
            }
            let r = fleet::accept(&mut self.db.conn(), cand, ACTOR, now);
            match r {
                Ok(a) => {
                    self.db.audit(
                        ACTOR,
                        "fleet.auto_accept",
                        &format!("agent/{}", a.agent_id),
                        &json!({"fleet": f.id, "candidate": cand, "tenant": a.tenant, "name": a.name,
                                "host": v["host"], "group": a.group, "job": a.job}),
                    )?;
                }
                Err(e) => eprintln!("<4>scheduler: fleet {}: auto-accept of {}: {e:#}", f.id, v["host"]),
            }
        }
        Ok(())
    }

    /// Firewall: the expanded ranges on the fleet port, while the fleet is usable.
    pub(crate) fn fleet_targets(&self) -> Result<Vec<(String, u16)>> {
        let mut out = Vec::new();
        for f in self.usable_fleets(catalog::now())? {
            if let Ok(t) = fleet::expand(&f.ranges) {
                out.extend(t.into_iter().map(|h| (h, f.port)));
            }
        }
        Ok(out)
    }
}
