//! Scan back to the last clean snapshot (Phase 29, docs/malware-scan.md "Scan
//! back"; NetBackup Tier 1 #3).
//!
//! `scan_back {source, from, budget?, max?}` never runs steps itself: it is held
//! (`jobs.not_before`) while it drives one ordinary `snapshot_scan {source,
//! time, stop_on_match, for_scan_back}` after the other, newest first from
//! `from`. Each scan stops at its first match (`nexus-pve scan
//! --stop-on-match`); its row in `snapshot_scans`, the verdict and the anomaly
//! flag are written as for any scan (scan.rs, without an alert: the hits of a
//! scan back are expected). The first complete scan without a match ends it:
//! that snapshot becomes the source's recommended restore point
//! (`snapshots.clean_point`, one per source). No clean snapshot within `max`
//! (default 30) or before the oldest one: it ends with `recommended: null`.
//! Result: `{source, from, scanned: [{time, job, matches_total, complete,
//! stopped}], recommended, truncated}`.

use super::*;

/// Snapshots scanned at most by one scan back unless the request says otherwise.
pub const MAX_SCANS: u64 = 30;
/// Seconds per snapshot unless the request says otherwise.
pub const BUDGET: u64 = 3600;
/// `not_before` of a scan back waiting for its current scan
const HELD: i64 = 1 << 62;

impl Scheduler {
    /// A queued `scan_back`: starts its first scan (or keeps waiting). True if
    /// the job was taken care of here.
    pub(crate) fn drive_scan_back(&mut self, job: &Job) -> Result<bool> {
        if job.kind != "scan_back" {
            return Ok(false);
        }
        if job.params["scan_job"].is_i64() {
            self.db.conn().execute(
                "UPDATE jobs SET not_before = ?2 WHERE id = ?1 AND state = 'queued'",
                params![job.id, HELD],
            )?;
            return Ok(true);
        }
        let start = (|| -> Result<(String, i64)> {
            let source = ident(&job.params, "source")?.to_owned();
            let from = num(&job.params, "from")? as i64;
            let (rules, _) = scan::rule_set(&self.db.conn())?;
            if rules.as_array().is_none_or(std::vec::Vec::is_empty) {
                bail!("no YARA rules uploaded (Settings → Malware scan)");
            }
            let local = self.db.conn().query_row(
                "SELECT COUNT(*) FROM snapshots WHERE tenant = ?1 AND source = ?2 AND time = ?3 AND local = 1",
                params![job.tenant, source, from],
                |r| r.get::<_, i64>(0),
            )?;
            if local == 0 {
                bail!("no local snapshot {source}/{from}");
            }
            Ok((source, from))
        })();
        match start {
            Ok((source, from)) => self.next_scan(job, &source, from, json!([]))?,
            Err(e) => self.fail_unstartable(job, &format!("scan back: {e:#}"))?,
        }
        Ok(true)
    }

    /// Queues the scan of `time` for the scan back `job` and holds it.
    fn next_scan(&self, job: &Job, source: &str, time: i64, scanned: Value) -> Result<()> {
        let mut sp = json!({"source": source, "time": time, "stop_on_match": true, "for_scan_back": job.id});
        if let Some(b) = job.params["budget"].as_u64() {
            sp["budget"] = json!(b);
        } else {
            sp["budget"] = json!(BUDGET);
        }
        let s = self.insert_job("snapshot_scan", &job.tenant, &sp)?;
        let mut p = job.params.clone();
        p["scan_job"] = json!(s);
        p["scanned"] = scanned;
        self.db.conn().execute(
            "UPDATE jobs SET params = ?2, not_before = ?3, log = log || ?4 WHERE id = ?1 AND state = 'queued'",
            params![
                job.id,
                p.to_string(),
                HELD,
                format!("[scheduler] scan back: snapshot_scan job {s} for {source}/{time}\n")
            ],
        )?;
        Ok(())
    }

    /// Ends a held scan back (state `ok` or `failed`).
    fn end_scan_back(&self, job: &Job, ok: bool, result: &Value, line: &str) -> Result<()> {
        let state = if ok { "ok" } else { "failed" };
        let now = catalog::now();
        let n = self.db.conn().execute(
            "UPDATE jobs SET state = ?2, started = COALESCE(started, ?3), finished = ?3, not_before = NULL,
               log = log || ?4, result = ?5 WHERE id = ?1 AND state = 'queued'",
            params![job.id, state, now, format!("[scheduler] {line}\n"), result.to_string()],
        )?;
        if n > 0 {
            self.db.audit(
                ACTOR,
                &format!("job.{state}"),
                &format!("job/{}", job.id),
                &json!({"kind": job.kind, "tenant": job.tenant}),
            )?;
        }
        Ok(())
    }

    /// A finished scan of a scan back (`for_scan_back`): the next older
    /// snapshot, or the end (module doc).
    pub(crate) fn scan_back_step(&self, scan_job: &Job, ok: bool, r: Option<&Value>) -> Result<()> {
        let Some(id) = scan_job.params["for_scan_back"].as_i64() else {
            return Ok(());
        };
        let Ok(job) = self.job(id) else {
            return Ok(());
        };
        let queued: bool = self
            .db
            .conn()
            .query_row("SELECT state = 'queued' FROM jobs WHERE id = ?1", [id], |r| r.get(0))?;
        if !queued || job.params["scan_job"].as_i64() != Some(scan_job.id) {
            return Ok(()); // cancelled, or an older scan
        }
        let source = ident(&job.params, "source")?.to_owned();
        let from = job.params["from"].clone();
        let time = num(&scan_job.params, "time")? as i64;
        let mut scanned = job.params["scanned"].as_array().cloned().unwrap_or_default();
        let r = r.filter(|_| ok);
        let Some(r) = r else {
            scanned.push(json!({"time": time, "job": scan_job.id, "failed": true}));
            let result = json!({"source": source, "from": from, "scanned": scanned, "recommended": null,
                                "truncated": false});
            return self.end_scan_back(
                &job,
                false,
                &result,
                &format!("scan back: scan job {} of {source}/{time} failed", scan_job.id),
            );
        };
        let (total, complete) = (r["matches_total"].as_u64().unwrap_or(0), r["complete"] == true);
        scanned.push(
            json!({"time": time, "job": scan_job.id, "matches_total": total, "complete": complete,
                            "stopped": r["stopped"] == true}),
        );
        if total == 0 && complete {
            {
                let c = self.db.conn();
                c.execute(
                    "UPDATE snapshots SET clean_point = NULL WHERE tenant = ?1 AND source = ?2",
                    params![job.tenant, source],
                )?;
                c.execute(
                    "UPDATE snapshots SET clean_point = ?4 WHERE tenant = ?1 AND source = ?2 AND time = ?3",
                    params![job.tenant, source, time, catalog::now()],
                )?;
            }
            self.db.audit(
                ACTOR,
                "snapshot.clean_point",
                &format!("snapshot/{}/{source}/{time}", job.tenant),
                &json!({"tenant": job.tenant, "job": job.id, "scanned": scanned.len()}),
            )?;
            let result = json!({"source": source, "from": from, "scanned": scanned, "recommended": time,
                                "truncated": false});
            return self.end_scan_back(
                &job,
                true,
                &result,
                &format!(
                    "scan back: {source}/{time} is clean ({} snapshots scanned): the recommended restore point",
                    scanned.len()
                ),
            );
        }
        let max = job.params["max"].as_u64().unwrap_or(MAX_SCANS);
        let older: Option<i64> = self.db.conn().query_row(
            "SELECT MAX(time) FROM snapshots WHERE tenant = ?1 AND source = ?2 AND time < ?3 AND local = 1",
            params![job.tenant, source, time],
            |r| r.get(0),
        )?;
        match older {
            Some(t) if (scanned.len() as u64) < max => self.next_scan(&job, &source, t, Value::Array(scanned)),
            older => {
                let truncated = older.is_some();
                let why = if truncated {
                    format!("{max} snapshots scanned, none clean (scan back again from {source}/{time} for more)")
                } else {
                    "no clean snapshot: the oldest local snapshot is not clean either".into()
                };
                let result = json!({"source": source, "from": from, "scanned": scanned, "recommended": null,
                                    "truncated": truncated});
                self.end_scan_back(&job, true, &result, &format!("scan back: {why}"))
            }
        }
    }
}
