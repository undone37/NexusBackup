//! Scheduled full read with a change-tracking drift check (Phase 29,
//! docs/netbackup-comparison.md Tier 1 #1; catalog::fullread).
//!
//! When a backup is planned, every source of it that already has a snapshot
//! and whose full read is due (`full_reads.next_due`, first due staggered over
//! the interval) gets its connector told to ignore change tracking for this
//! run: `full_read` in `pve.json` (VMIDs), the nexus-agentctl `backup` object,
//! `nas.json` and `truenas.json`. Not during restore priority. The connector
//! reads everything, commits as usual and prints `full-read <source>/<time>
//! {tracker, baseline, compared, changed, unreported, unreported_bytes,
//! examples}`: what changed since the previous snapshot although the tracker
//! had not reported it. [`Scheduler::full_read_bookkeeping`] records that in
//! `full_reads` (next due = now + interval), adds a job log line and raises
//! `change_tracking` (critical) when anything was unreported.

use super::*;

impl Scheduler {
    /// The group a backup job runs for (by group, agent or VMID).
    fn backup_group(&self, job: &Job) -> Result<Option<GroupRow>> {
        let p = &job.params;
        Ok(self.groups()?.into_iter().find(|g| {
            g.tenant == job.tenant
                && match (p["group_id"].as_i64(), p["agent_id"].as_str(), p["vmid"].as_u64()) {
                    (Some(id), _, _) => g.id == id,
                    (None, Some(a), _) => g.agents.iter().any(|x| x == a),
                    (None, None, Some(v)) => u32::try_from(v).is_ok_and(|v| g.guests.contains(&v)),
                    _ => false,
                }
        }))
    }

    /// Candidates that already have a snapshot (a first backup reads everything anyway).
    fn with_snapshots(&self, tenant: &str, sources: Vec<String>) -> Result<Vec<String>> {
        let c = self.db.conn();
        let mut q = c.prepare("SELECT 1 FROM snapshots WHERE tenant = ?1 AND source = ?2 AND local = 1 LIMIT 1")?;
        let mut out = Vec::new();
        for s in sources {
            if q.exists(params![tenant, s])? {
                out.push(s);
            }
        }
        Ok(out)
    }

    /// Tells the connectors of a backup plan which sources to read in full.
    pub(crate) fn patch_full_read(&self, job: &Job, plan: &mut Plan) -> Result<()> {
        if job.kind != "backup" || self.restore_priority()?.is_some() {
            return Ok(());
        }
        let Some(g) = self.backup_group(job)? else {
            return Ok(());
        };
        if g.full_read_days <= 0 {
            return Ok(());
        }
        let now = catalog::now();
        let due = |sources: Vec<String>| -> Result<Vec<String>> {
            let sources = self.with_snapshots(&job.tenant, sources)?;
            Ok(catalog::fullread::due(
                &self.db.conn(),
                &job.tenant,
                &sources,
                g.full_read_days,
                now,
            )?)
        };
        for (name, body) in plan.files.iter_mut().filter(|(n, _)| n.ends_with(".json")) {
            let mut cfg: Value = serde_json::from_slice(body)?;
            let read: Vec<String> = if cfg["backup"].is_object() {
                let a = cfg["agent"]["id"].as_str().unwrap_or_default().to_owned();
                let d = due(vec![format!("host-{a}")])?;
                if !d.is_empty() {
                    cfg["backup"]["full_read"] = json!(true);
                }
                d
            } else if name == "nas.json" {
                let d = due(vec![nas::source_name(g.source_id as u64)])?;
                if !d.is_empty() {
                    cfg["full_read"] = json!(true);
                }
                d
            } else if name == "truenas.json" {
                let srcs = g
                    .datasets
                    .iter()
                    .map(|d| truenas::source_name(g.source_id as u64, d))
                    .collect();
                let d = due(srcs)?;
                if !d.is_empty() {
                    cfg["full_read"] = json!(true);
                }
                d
            } else if name == "vmware.json" {
                // ponytail: one flag for the run, so every VM of the job is read in full when one is due (as for
                // TrueNAS datasets); a per-VM list in the config if that costs too much
                let d = due(g.vms.iter().map(|u| vmware::names::source_name(u)).collect())?;
                if !d.is_empty() {
                    cfg["full_read"] = json!(true);
                }
                d
            } else if name == "pve.json" {
                let vmids: Vec<u64> = cfg["vmids"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(Value::as_u64)
                    .collect();
                let d = due(vmids.iter().map(|v| format!("vm-{v}")).collect())?;
                let ids: Vec<u64> = vmids.into_iter().filter(|v| d.contains(&format!("vm-{v}"))).collect();
                if !ids.is_empty() {
                    cfg["full_read"] = json!(ids);
                }
                d
            } else {
                continue;
            };
            if !read.is_empty() {
                eprintln!(
                    "scheduler: job {} reads {} in full (change-tracking check)",
                    job.id,
                    read.join(", ")
                );
                *body = serde_json::to_vec_pretty(&cfg)?;
            }
        }
        Ok(())
    }

    /// `full-read <source>/<time> {json}` lines of a finished backup (module doc).
    pub(crate) fn full_read_bookkeeping(&self, job: &Job, log: &mut String) -> Result<()> {
        let lines: Vec<(String, i64, Value)> = log
            .lines()
            .filter_map(|l| {
                let (id, js) = l.strip_prefix("full-read ")?.split_once(' ')?;
                let (s, t) = id.rsplit_once('/')?;
                let v: Value = serde_json::from_str(js).ok()?;
                Some((s.to_owned(), t.parse().ok()?, v))
            })
            .filter(|(s, _, _)| s.len() <= 200 && !s.contains(char::is_whitespace))
            .collect();
        if lines.is_empty() {
            return Ok(());
        }
        let days = self.backup_group(job)?.map_or(0, |g| g.full_read_days).max(1);
        let now = catalog::now();
        for (source, time, v) in lines {
            let n = |k: &str| v[k].as_u64().unwrap_or(0) as i64;
            let (unreported, bytes) = (n("unreported"), n("unreported_bytes"));
            let result = if v["baseline"].is_null() {
                "no_baseline"
            } else if unreported > 0 {
                "drift"
            } else {
                "clean"
            };
            let examples: Vec<String> = v["examples"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|e| e.as_str())
                .take(10)
                .map(|e| e.chars().take(300).collect())
                .collect();
            let details = json!({"tracker": v["tracker"].as_str().unwrap_or("none"), "baseline": v["baseline"],
                                 "compared": n("compared"), "examples": examples});
            self.db.conn().execute(
                "INSERT INTO full_reads (tenant, source, next_due, last_at, last_snapshot, last_job, result, changed,
                   unreported, unreported_bytes, details, last_clean_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, CASE WHEN ?7 = 'drift' THEN NULL ELSE ?4 END)
                 ON CONFLICT (tenant, source) DO UPDATE SET next_due = ?3, last_at = ?4, last_snapshot = ?5,
                   last_job = ?6, result = ?7, changed = ?8, unreported = ?9, unreported_bytes = ?10, details = ?11,
                   last_clean_at = CASE WHEN ?7 = 'drift' THEN last_clean_at ELSE ?4 END",
                params![
                    job.tenant,
                    source,
                    now + days * 86_400,
                    now,
                    time,
                    job.id,
                    result,
                    n("changed"),
                    unreported,
                    bytes,
                    details.to_string()
                ],
            )?;
            let what = match result {
                "drift" => format!(
                    "{unreported} changes ({bytes} bytes) the change tracking ({}) had not reported, e.g. {}",
                    details["tracker"].as_str().unwrap_or("none"),
                    examples.first().map_or("?", String::as_str)
                ),
                "clean" => format!(
                    "no unreported changes ({} compared, {} changed)",
                    n("compared"),
                    n("changed")
                ),
                _ => "no change tracking to compare with (read in full)".into(),
            };
            log.push_str(&format!(
                "[scheduler] full read of {source}/{time}: {what}; next in {days} days\n"
            ));
            self.db.audit(
                ACTOR,
                "full_read",
                &format!("snapshot/{}/{source}/{time}", job.tenant),
                &json!({"tenant": job.tenant, "job": job.id, "result": result, "unreported": unreported}),
            )?;
            if result == "drift" {
                self.raise(
                    "critical",
                    catalog::fullread::ALERT_KIND,
                    &format!("{}:{}/{source}", catalog::fullread::ALERT_KIND, job.tenant),
                    &format!(
                        "Full read of {}/{source} (snapshot {time}, job {}): {what}. Snapshots taken with change \
                         tracking since the last verified full read may miss these changes; this snapshot is complete.",
                        job.tenant, job.id
                    ),
                    Some(&job.tenant),
                )?;
            }
        }
        Ok(())
    }
}
