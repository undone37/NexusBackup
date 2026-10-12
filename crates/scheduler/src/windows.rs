//! Bandwidth and sync windows, "close vault now" (Phase 17a/b,
//! docs/replication.md "Windows and closing the vault", docs/control-plane.md).
//!
//! The transfer engines follow the bandwidth windows themselves (nexus-offsite
//! and nexus-replica get them in their job config, `catalog::schedule::Throttle`).
//! The scheduler adds what needs the catalog:
//! - an offsite upload that would start inside a pause window waits for its end
//!   (`jobs.not_before`);
//! - a replication source outside its sync window, or closed, has no firewall
//!   target and gets no syncs; queued syncs are cancelled, running ones get a
//!   cancel request (the next sync resumes: chunks already fetched stay, the
//!   snapshot is committed manifest-last);
//! - a closed source has an open `vault_closed` info alert.

use super::*;
use crate::schedule::Bandwidth;

impl Scheduler {
    /// Bandwidth of a tenant's offsite uploads (`tenants.offsite`: `bwlimit`,
    /// `windows`, `timezone`).
    pub(crate) fn offsite_bandwidth(&self, tenant: &str) -> Result<Option<Bandwidth>> {
        let Some(o) = self.offsite_cfg(tenant)? else { return Ok(None) };
        Ok(Some(Bandwidth {
            base: o["bwlimit"].as_u64(),
            windows: serde_json::from_value(o["windows"].clone()).unwrap_or_default(),
            tz: schedule::tz(o["timezone"].as_str().unwrap_or("UTC")).unwrap_or(schedule::Tz::UTC),
        }))
    }

    /// An offsite job inside a pause window of its tenant: postponed to the
    /// end of the pause (`not_before`) instead of starting. True if postponed.
    pub(crate) fn hold_offsite(&self, job: &Job) -> Result<bool> {
        if job.kind != "offsite" {
            return Ok(false);
        }
        let Some(until) = self
            .offsite_bandwidth(&job.tenant)?
            .and_then(|b| b.paused_until(self.now))
        else {
            return Ok(false);
        };
        self.db.conn().execute(
            "UPDATE jobs SET not_before = ?2, log = log || ?3 WHERE id = ?1 AND state = 'queued'",
            params![
                job.id,
                until,
                format!("[scheduler] offsite pause window: waiting until {until}\n")
            ],
        )?;
        Ok(true)
    }

    /// Replication sources that are closed or outside their sync window:
    /// their queued syncs are cancelled and running ones get a cancel request;
    /// `vault_closed` (info) is open while a source is closed.
    pub(crate) fn replication_windows(&mut self, now: i64) -> Result<()> {
        for s in self.replication_sources()? {
            let key = format!("vault_closed:{}", s.id);
            if s.closed(now) {
                let until = match s.closed_until {
                    Some(-1) | None => "it is reopened".to_owned(),
                    Some(u) => schedule::day(u),
                };
                self.raise(
                    "info",
                    "vault_closed",
                    &key,
                    &format!(
                        "replication source {} is closed (by {}) until {until}: no syncs, the primary is not reachable",
                        s.name,
                        s.closed_by.as_deref().unwrap_or("?")
                    ),
                    None,
                )?;
            } else {
                self.resolve(&key)?;
            }
            if s.open(now) {
                continue;
            }
            let reason = if s.closed(now) { "vault_closed" } else { "sync_window" };
            let jobs: Vec<(i64, String)> = {
                let c = self.db.conn();
                let mut st = c.prepare(
                    "SELECT id, state FROM jobs WHERE kind = 'replica_sync' AND state IN ('queued','running') \
                     AND cancel_by IS NULL AND json_extract(params,'$.replication_source_id') = ?1",
                )?;
                let rows = st.query_map([s.id], |r| Ok((r.get(0)?, r.get(1)?)))?;
                rows.collect::<std::result::Result<_, _>>()?
            };
            for (id, state) in jobs {
                let n = if state == "queued" {
                    self.db.conn().execute(
                        "UPDATE jobs SET state = 'cancelled', finished = ?2, log = log || ?3 WHERE id = ?1 AND state = 'queued'",
                        params![id, catalog::now(), format!("[scheduler] cancelled: {reason}\n")],
                    )?
                } else {
                    self.db.conn().execute(
                        "UPDATE jobs SET cancel_by = ?2 WHERE id = ?1 AND state = 'running' AND cancel_by IS NULL",
                        params![id, reason],
                    )?
                };
                if n == 1 {
                    self.db.audit(
                        ACTOR,
                        "job.cancel",
                        &format!("job/{id}"),
                        &json!({"reason": reason, "replication_source": s.name, "running": state == "running"}),
                    )?;
                }
            }
        }
        Ok(())
    }
}
