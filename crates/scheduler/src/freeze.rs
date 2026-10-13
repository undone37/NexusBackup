//! The scheduler's half of the Phase 29 incident guards (catalog::incident;
//! docs/control-plane.md "Incident freezes", "Restores of flagged snapshots"):
//!
//! - **frozen deletions** (incident mode or the tenant's lockdown): snapshot
//!   deletes are refused; retention, orphan cleanup, local GC, offsite
//!   retention and GC are taken out of the plan (a log line says so) and a
//!   replica sync runs without its local retention (`prune: false`);
//! - **production restores** (re-checked when the job is planned, whoever
//!   queued it: recovery plans, the vault, an older client): refused while
//!   restores to production are frozen, and for a flagged snapshot unless the
//!   job carries an approved `restore.infected` request (`quorum_id`);
//!   approved `restore.infected` requests become jobs here
//!   ([`Scheduler::queue_restore_replaces`] in restore.rs).

use super::*;
use catalog::incident::{flagged, frozen, infected_approved, job_snapshot, production_restore};

const DELETIONS_FROZEN: &str = "deletions frozen (incident mode)";

impl Scheduler {
    /// Production restores: frozen, or a flagged snapshot without approval.
    pub(crate) fn check_restore_guard(&self, job: &Job) -> Result<()> {
        let p = &job.params;
        if !production_restore(&job.kind, p) {
            return Ok(());
        }
        let c = self.db.conn();
        if frozen(&c, &job.tenant)?.restores {
            bail!(
                "incident mode: restores to production are frozen; restore with the network disconnected or to \
                 another path, or lift the freeze (approval)"
            );
        }
        let Some((source, time)) = job_snapshot(p) else {
            return Ok(());
        };
        if let Some(why) = flagged(&c, &job.tenant, source, time)? {
            let ok = p["quorum_id"]
                .as_i64()
                .map(|q| infected_approved(&c, q, &job.tenant, source, time))
                .transpose()?
                .unwrap_or(false);
            if !ok {
                bail!(
                    "snapshot {source}/{time} is flagged as infected ({why}): restoring it to production needs the \
                     approval restore.infected; restore it isolated (network disconnected, another path) instead"
                );
            }
        }
        Ok(())
    }

    /// Takes deletions out of a plan while they are frozen for its tenant.
    pub(crate) fn patch_freeze(&self, job: &Job, plan: &mut Plan) -> Result<()> {
        if plan.tenant == "-" || !frozen(&self.db.conn(), &plan.tenant)?.deletions {
            return Ok(());
        }
        if job.kind == "snapshot_delete" {
            bail!("{DELETIONS_FROZEN}: the snapshot is not deleted; lift the freeze (approval) first");
        }
        let offsite = self.cfg.offsite_bin.clone();
        let mut skipped = Vec::new();
        plan.steps.retain(|s| {
            let what = match s {
                Step::Retention { .. } => "retention",
                Step::Orphans { .. } => "retention of orphaned sources",
                Step::Gc { .. } => "garbage collection",
                Step::Delete { .. } => "snapshot delete",
                Step::Cli { bin, args, .. } if *bin == offsite && args.get(1).is_some_and(|a| a == "retention") => {
                    "offsite retention"
                }
                Step::Cli { bin, args, .. } if *bin == offsite && args.get(1).is_some_and(|a| a == "gc") => {
                    "offsite garbage collection"
                }
                _ => return true,
            };
            skipped.push(what);
            false
        });
        for (name, body) in plan.files.iter_mut().filter(|(n, _)| n == "replica.json") {
            let mut cfg: Value = serde_json::from_slice(body)?;
            cfg["prune"] = json!(false);
            *body = serde_json::to_vec_pretty(&cfg)?;
            let _ = name;
            skipped.push("replica retention");
        }
        if !skipped.is_empty() {
            skipped.dedup();
            plan.steps.insert(
                0,
                Step::Note(format!(
                    "[scheduler] {DELETIONS_FROZEN}: {} skipped",
                    skipped.join(", ")
                )),
            );
        }
        Ok(())
    }
}
