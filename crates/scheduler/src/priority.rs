//! "Restore priority" (Phase 22b, `catalog::priority`): while it is on, no
//! scheduled backup, GC, verify, file index or replication sync is queued
//! (due slots run afterwards, as after a pause) and queued jobs of the held
//! kinds wait in `start_jobs`; restores and manual jobs run. Expiry is audited
//! here; the `restore_priority` warning is open while it is on.

use crate::{Job, Scheduler, ACTOR};
use anyhow::Result;
use catalog::priority::{self, Priority};
use serde_json::json;

impl Scheduler {
    /// The switch if it is on now.
    pub(crate) fn restore_priority(&self) -> Result<Option<Priority>> {
        Ok(priority::active(&self.db.conn(), catalog::now())?)
    }

    /// Expires the switch (audit `restore_priority.expire`) and keeps its
    /// warning in step with it.
    pub(crate) fn check_restore_priority(&mut self, now: i64) -> Result<()> {
        let p = priority::load(&self.db.conn())?;
        match p {
            Some(p) if p.until > now => self.raise(
                "warning",
                priority::ALERT_KIND,
                priority::ALERT_KIND,
                &format!(
                    "restore priority is on (by {}{}) until {}: scheduled backups, GC, verify, offsite uploads and replication are held",
                    p.by,
                    if p.reason.is_empty() { String::new() } else { format!(": {}", p.reason) },
                    catalog::schedule::day(p.until)
                ),
                None,
            ),
            Some(p) => {
                if priority::clear(&self.db.conn())? {
                    self.db.audit(
                        ACTOR,
                        "restore_priority.expire",
                        priority::SETTING,
                        &json!({"since": p.since, "until": p.until, "by": p.by}),
                    )?;
                }
                self.resolve(priority::ALERT_KIND)
            }
            None => self.resolve(priority::ALERT_KIND),
        }
    }

    /// A queued job that waits for the end of the restore priority.
    pub(crate) fn held_by_priority(&self, job: &Job, on: bool) -> Result<bool> {
        if !on {
            return Ok(false);
        }
        if priority::HELD_KINDS.contains(&job.kind.as_str()) {
            return Ok(true);
        }
        if job.kind != "backup" {
            return Ok(false);
        }
        let by: String = self
            .db
            .conn()
            .query_row("SELECT requested_by FROM jobs WHERE id = ?1", [job.id], |r| r.get(0))?;
        Ok(by == ACTOR)
    }
}
