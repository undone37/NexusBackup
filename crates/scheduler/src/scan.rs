//! Opt-in YARA scan of a snapshot and "scan first" restores (Phase 21e,
//! docs/malware-scan.md).
//!
//! - `snapshot_scan {source, time, budget?, for_job?}` runs `nexus-pve scan` with
//!   a store-only configuration and the admin's rule files (`yara_rules`). The
//!   scanner runs inside the restore micro-VM only (no network, read-only disks;
//!   one scan at a time, key `snapshot_scan`). The result goes into
//!   `snapshot_scans`; a match flags the snapshot anomalous (21a) and raises the
//!   critical `malware` alert.
//! - A restore job with `scan_first` (`refuse` | `link_down`) is held
//!   (`jobs.not_before`) until a `snapshot_scan` of its snapshot has finished.
//!   Clean: it runs. A match or an incomplete scan: `refuse` fails it,
//!   `link_down` runs it with every NIC of the new guest disconnected. A failed
//!   scan refuses the restore (fail-closed).

use super::*;

/// Restore kinds that accept `scan_first` (web-api `jobs::check_params`).
pub const SCAN_FIRST_KINDS: &[&str] = &[
    "restore",
    "restore_ct",
    "instant_recover",
    "restore_files",
    "files_get",
    "plugin_restore",
];
/// `scan_first: link_down` applies to these (they create a guest with NICs)
pub const LINK_DOWN_KINDS: &[&str] = &["restore", "restore_ct", "instant_recover"];
/// `not_before` of a restore waiting for its scan; cleared by the scan's bookkeeping
const HELD: i64 = 1 << 62;
/// rule names listed in an anomaly reason / alert
const RULES_NAMED: usize = 3;

/// The rule set (`[{name, text}]`) and its label for `snapshot_scans.rules`
/// (`name@sha256-prefix`, comma-separated).
pub(crate) fn rule_set(c: &catalog::rusqlite::Connection) -> Result<(Value, String)> {
    let mut q = c.prepare("SELECT name, text, sha256 FROM yara_rules ORDER BY name")?;
    let rows = q
        .query_map([], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let label = rows
        .iter()
        .map(|(n, _, h)| format!("{n}@{}", &h[..h.len().min(12)]))
        .collect::<Vec<_>>()
        .join(",");
    let set = rows
        .into_iter()
        .map(|(name, text, _)| json!({"name": name, "text": text}))
        .collect();
    Ok((Value::Array(set), label))
}

fn waiting(job: &Job) -> bool {
    SCAN_FIRST_KINDS.contains(&job.kind.as_str())
        && job.params["scan_first"].is_string()
        && !job.params["scan"].is_object()
}

impl Scheduler {
    pub(crate) fn plan_scan(&self, job: &Job, mut plan: Plan) -> Result<Plan> {
        let (p, tenant) = (&job.params, job.tenant.as_str());
        let source = ident(p, "source")?.to_owned();
        let time = num(p, "time")?;
        let (rules, _) = rule_set(&self.db.conn())?;
        if rules.as_array().is_none_or(|a| a.is_empty()) {
            bail!("no YARA rules uploaded (Settings → Malware scan)");
        }
        plan.key = "snapshot_scan".into();
        let cfg = json!({"store": self.cfg.store_base.join(tenant), "tenant": tenant,
                         "keyd_socket": self.cfg.keyd_socket});
        plan.files = vec![
            ("pve.json".into(), serde_json::to_vec_pretty(&cfg)?),
            ("rules.json".into(), serde_json::to_vec(&rules)?),
        ];
        let mut args = vec![
            plan.dir.join("pve.json").to_string_lossy().into_owned(),
            "scan".into(),
            source,
            time.to_string(),
            plan.dir.join("rules.json").to_string_lossy().into_owned(),
        ];
        if let Some(b) = p["budget"].as_u64() {
            args.push(b.to_string());
        }
        // Phase 29: scans of a scan back stop at their first match (scanback.rs)
        if p["stop_on_match"] == true {
            args.push("--stop-on-match".into());
        }
        plan.steps.push(Step::Cli {
            bin: self.cfg.pve_bin.clone(),
            args,
            alert: None,
            capture: true,
        });
        Ok(plan)
    }

    /// A restore with `scan_first` and no verdict yet: queues its scan (once) and
    /// holds the job. True if held.
    pub(crate) fn hold_for_scan(&self, job: &Job) -> Result<bool> {
        if !waiting(job) {
            return Ok(false);
        }
        let (log, params) = match job.params["scan_job"].as_i64() {
            Some(s) => (
                format!("[scheduler] scan first: waiting for snapshot_scan job {s}\n"),
                job.params.clone(),
            ),
            None => {
                let s = self.insert_job(
                    "snapshot_scan",
                    &job.tenant,
                    &json!({"source": job.params["source"], "time": job.params["time"], "for_job": job.id}),
                )?;
                let mut p = job.params.clone();
                p["scan_job"] = json!(s);
                (format!("[scheduler] scan first: snapshot_scan job {s} queued\n"), p)
            }
        };
        self.db.conn().execute(
            "UPDATE jobs SET params = ?2, not_before = ?3, log = log || ?4 WHERE id = ?1 AND state = 'queued'",
            params![job.id, params.to_string(), HELD, log],
        )?;
        Ok(true)
    }

    /// Never plans a restore whose scan has not decided yet (a held job that
    /// got its `not_before` cleared some other way).
    pub(crate) fn check_scanned(job: &Job) -> Result<()> {
        if waiting(job) {
            bail!("scan first: the snapshot has not been scanned");
        }
        Ok(())
    }

    /// A finished `snapshot_scan`: result row, flag + alert on a match, and the
    /// verdict for a restore that waits for it.
    pub(crate) fn scan_bookkeeping(&mut self, job: &Job, ok: bool, r: Option<&Value>) -> Result<()> {
        let (source, time) = (
            ident(&job.params, "source")?.to_owned(),
            num(&job.params, "time")? as i64,
        );
        let r = r.filter(|_| ok);
        let mut verdict: Option<(u64, bool)> = None; // (matches, complete)
        if let Some(r) = r {
            let (_, rules) = rule_set(&self.db.conn())?;
            let (total, complete) = (r["matches_total"].as_u64().unwrap_or(0), r["complete"] == true);
            verdict = Some((total, complete));
            self.db.conn().execute(
                "INSERT OR REPLACE INTO snapshot_scans (job_id, tenant, source, time, finished, rules, files, skipped,
                   errors, complete, matches_total, matches) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)",
                params![
                    job.id,
                    job.tenant,
                    source,
                    time,
                    catalog::now(),
                    rules,
                    r["files"].as_i64().unwrap_or(0),
                    r["skipped"].as_i64().unwrap_or(0),
                    r["errors"].as_i64().unwrap_or(0),
                    complete,
                    total as i64,
                    r["matches"].to_string()
                ],
            )?;
            // Phase 28: the snapshot's verdict (recovery calendar, "latest clean")
            let state = if total > 0 {
                "hit"
            } else if complete {
                "clean"
            } else {
                "incomplete"
            };
            self.db.conn().execute(
                "UPDATE snapshots SET scan_state = ?4 WHERE tenant = ?1 AND source = ?2 AND time = ?3",
                params![job.tenant, source, time, state],
            )?;
            self.db.audit(
                ACTOR,
                "snapshot.scan",
                &format!("snapshot/{}/{source}/{time}", job.tenant),
                &json!({"tenant": job.tenant, "job": job.id, "files": r["files"], "matches": total,
                        "complete": complete, "rules": rules}),
            )?;
            if total > 0 {
                let mut named: Vec<&str> = Vec::new();
                for m in r["matches"].as_array().into_iter().flatten() {
                    if let Some(x) = m["rule"].as_str().filter(|x| !named.contains(x)) {
                        named.push(x);
                    }
                }
                let more = if named.len() > RULES_NAMED { ", …" } else { "" };
                let why = format!(
                    "YARA: {total} matches ({}{more})",
                    named[..named.len().min(RULES_NAMED)].join(", ")
                );
                self.flag_snapshot(&job.tenant, &source, time, &why)?;
                let first = &r["matches"][0];
                let last = self.last_clean(&job.tenant, &source, time)?;
                // Phase 28: scheduled scans (threat.rs) raise their own kind
                let (kind, what) = if job.params["scheduled"] == true {
                    ("scan_hit", "Scheduled YARA scan")
                } else {
                    ("malware", "YARA scan")
                };
                // Phase 29: the hits of a scan back are expected (scanback.rs): flagged, no alert
                let quiet = job.params["for_scan_back"].is_i64();
                if !quiet {
                    self.raise(
                        "critical",
                        kind,
                        &format!("{kind}:{}/{source}", job.tenant),
                        &format!(
                            "{what} of {}/{source} snapshot {time}: {why}, e.g. {} in {}; {last}",
                            job.tenant,
                            first["rule"].as_str().unwrap_or("?"),
                            first["path"].as_str().unwrap_or("?")
                        ),
                        Some(&job.tenant),
                    )?;
                }
            }
        }
        self.scan_back_step(job, ok, r)?; // scanback.rs
        let Some(rid) = job.params["for_job"].as_i64() else {
            return Ok(());
        };
        let Ok(restore) = self.job(rid) else {
            return Ok(());
        };
        let on_hit = restore.params["scan_first"].as_str().unwrap_or("refuse");
        let (refuse, why) = match verdict {
            None => (true, format!("scan job {} failed", job.id)),
            Some((0, true)) => (false, String::new()),
            // a match, or an incomplete scan: not proven clean
            Some((n, _)) => {
                let w = if n > 0 {
                    format!("{n} YARA matches in the snapshot (scan job {})", job.id)
                } else {
                    format!("the scan did not finish within its time budget (scan job {})", job.id)
                };
                (
                    on_hit != "link_down" || !LINK_DOWN_KINDS.contains(&restore.kind.as_str()),
                    w,
                )
            }
        };
        let target = format!("job/{rid}");
        if refuse {
            self.fail_unstartable(&restore, &format!("scan first: {why}; restore refused"))?;
            self.db.audit(
                ACTOR,
                "restore.refused",
                &target,
                &json!({"tenant": restore.tenant, "scan_job": job.id, "reason": why}),
            )?;
            return Ok(());
        }
        let mut p = restore.params.clone();
        p["scan"] = json!({"job": job.id, "matches": verdict.map_or(0, |v| v.0)});
        let log = if why.is_empty() {
            format!("[scheduler] scan first: clean (scan job {})\n", job.id)
        } else {
            p["link_down"] = json!(true);
            format!("[scheduler] scan first: {why}; restoring with the network disconnected\n")
        };
        self.db.conn().execute(
            "UPDATE jobs SET params = ?2, not_before = NULL, log = log || ?3 WHERE id = ?1 AND state = 'queued'",
            params![rid, p.to_string(), log],
        )?;
        if !why.is_empty() {
            self.db.audit(
                ACTOR,
                "restore.link_down",
                &target,
                &json!({"tenant": restore.tenant, "scan_job": job.id, "reason": why}),
            )?;
        }
        Ok(())
    }
}
