//! Cases (Phase 33, docs/control-plane.md "Cases"): a case's search is an
//! ordinary `file_search` job with `case_id` (web-api `cases.rs` queues it);
//! when it finishes, the snapshots it matched replace the case's list
//! (`case_snapshots`, with the number of matched items per snapshot). Holds the
//! case placed stay recorded on snapshots that still match.

use crate::{Job, Scheduler};
use anyhow::Result;
use catalog::rusqlite::params;
use serde_json::Value;
use std::collections::BTreeMap;

impl Scheduler {
    pub(crate) fn case_bookkeeping(&self, job: &Job, r: Option<&Value>) -> Result<()> {
        let (Some(case), Some(r)) = (job.params["case_id"].as_i64(), r) else {
            return Ok(());
        };
        let mut per: BTreeMap<(String, i64), i64> = BTreeMap::new();
        for m in r["matches"].as_array().into_iter().flatten() {
            let Some(source) = m["source"].as_str() else { continue };
            for t in m["times"].as_array().into_iter().flatten().filter_map(Value::as_i64) {
                *per.entry((source.to_owned(), t)).or_default() += 1;
            }
        }
        let mut c = self.db.conn();
        let tx = c.transaction()?;
        // the case is the job's tenant's (a stale job of a deleted case changes nothing)
        let n = tx.execute(
            "UPDATE cases SET last_job = ?2, searched_at = ?3, truncated = ?4 WHERE id = ?1 AND tenant = ?5",
            params![case, job.id, catalog::now(), r["truncated"] == true, job.tenant],
        )?;
        if n == 1 {
            tx.execute(
                "DELETE FROM case_snapshots WHERE case_id = ?1 AND hold_id IS NULL",
                [case],
            )?;
            tx.execute("UPDATE case_snapshots SET items = 0 WHERE case_id = ?1", [case])?;
            for ((source, time), items) in &per {
                tx.execute(
                    "INSERT INTO case_snapshots (case_id, source, time, items) VALUES (?1, ?2, ?3, ?4)
                     ON CONFLICT (case_id, source, time) DO UPDATE SET items = excluded.items",
                    params![case, source, time, items],
                )?;
            }
        }
        tx.commit()?;
        Ok(())
    }
}
