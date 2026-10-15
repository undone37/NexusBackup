//! "Back up now, keep until `<date>`" (Phase 23a, web-api `keep.rs`): after a
//! `backup` / `plugin_backup` job with `keep_until` finished ok, every snapshot
//! it wrote (its `nexus-stats` lines) gets its store lock extended to that date.
//! Locks only grow (`Store::extend_lock`); audited `snapshot.keep_until`.

use crate::{stats, valid_name, Job, Scheduler, ACTOR};
use anyhow::Result;
use serde_json::json;

impl Scheduler {
    pub(crate) fn keep_until_bookkeeping(&mut self, job: &Job, log: &str) -> Result<()> {
        let Some(until) = job.params["keep_until"].as_i64().filter(|t| *t > 0) else {
            return Ok(());
        };
        let snaps = stats::parse(log);
        if snaps.is_empty() || !valid_name(&job.tenant) {
            return Ok(());
        }
        let root = self.cfg.store_base.join(&job.tenant);
        let store = chunkstore::Store::open(&root, (self.ctx.keys)(&job.tenant)?, (self.ctx.store_options)())?;
        let mut locked = Vec::new();
        for s in &snaps {
            match store.extend_lock(&s.source, s.time as u64, until as u64) {
                Ok(lock) => locked.push(json!({"source": s.source, "time": s.time, "lock_until": lock})),
                Err(e) => eprintln!("<4>keep_until {}/{}/{}: {e}", job.tenant, s.source, s.time),
            }
        }
        drop(store);
        self.dirty.insert(job.tenant.clone());
        self.db.audit(
            ACTOR,
            "snapshot.keep_until",
            &format!("tenant/{}", job.tenant),
            &json!({"job": job.id, "keep_until": until, "snapshots": locked}),
        )?;
        Ok(())
    }
}
