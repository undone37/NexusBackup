//! Health check with repair (Phase 21d, docs/control-plane.md "Health check
//! with repair"; the store side is chunkstore::health).
//!
//! - `verify`: chunks that fail (corrupt or missing) go on the tenant's bad-chunk
//!   list ([`after_verify`]); the job's stdout carries `{"health": …}` with the
//!   damaged snapshots. New backups store such chunks again and do not build on a
//!   damaged base (the connectors check `Store::is_damaged`).
//! - `chunk_repair` (admin, or queued after a verify that found new damage when a
//!   repair source exists): `nexus-offsite repair` and/or `nexus-replica repair`
//!   (replicated tenants, while the source is open) fetch the sealed chunks by id
//!   and store them after full verification; a final store step reports `health`.
//! - [`Scheduler::health_bookkeeping`]: `snapshots.damaged` (v32), audit
//!   `snapshot.damaged` / `snapshot.repaired`, critical alert
//!   `snapshot_damaged:<tenant>` listing the affected snapshots (resolved when none
//!   is left).

use crate::run::{Plan, Step, StoreOp};
use crate::{Job, Scheduler, ACTOR};
use anyhow::{bail, Result};
use catalog::rusqlite::params;
use chunkstore::store::VerifyReport;
use chunkstore::Store;
use serde_json::{json, Value};
use std::collections::BTreeMap;

/// Alert kind and key prefix.
pub const ALERT: &str = "snapshot_damaged";
/// Snapshots named in the alert text.
const LISTED: usize = 10;

/// Health part of a verify / repair job's stdout.
pub(crate) fn health_json(store: &Store, new_bad: usize) -> std::io::Result<String> {
    store.prune_bad()?;
    let damaged: Vec<Value> = store
        .damaged_snapshots()?
        .into_iter()
        .map(|d| json!({"source": d.source, "time": d.time, "chunks": d.chunks}))
        .collect();
    Ok(
        json!({"health": {"bad_chunks": store.bad_chunks()?.len(), "new_bad": new_bad, "damaged": damaged}})
            .to_string(),
    )
}

/// After a local verify: the failed chunks on the bad list, then the health report.
pub(crate) fn after_verify(store: &Store, r: &VerifyReport) -> std::io::Result<String> {
    let n = store.mark_bad(r.corrupt.iter().chain(&r.missing))?;
    health_json(store, n)
}

impl Scheduler {
    /// `chunk_repair {}`: from the offsite target and/or the replication primary.
    pub(crate) fn plan_chunk_repair(&self, mut plan: Plan) -> Result<Plan> {
        let tenant = plan.tenant.clone();
        if let Some(f) = self.offsite_config(&tenant, &plan.dir)? {
            plan.files.extend(f);
            plan.steps.push(Step::Cli {
                bin: self.cfg.offsite_bin.clone(),
                args: vec![
                    plan.dir.join("offsite.json").to_string_lossy().into_owned(),
                    "repair".into(),
                ],
                alert: None,
                capture: false,
            });
        }
        self.replica_repair(&mut plan)?;
        if plan.steps.is_empty() {
            bail!("tenant {tenant} has no repair source: neither an offsite target nor an open replication source");
        }
        plan.steps.push(Step::Store(StoreOp(Box::new(|s: &Store| {
            health_json(s, 0).map_err(|e| format!("health report: {e}"))
        }))));
        Ok(plan)
    }

    /// True if `chunk_repair` has a source for the tenant (auto-queue after verify).
    fn has_repair_source(&self, tenant: &str) -> Result<bool> {
        Ok(self.offsite_cfg(tenant)?.is_some()
            || self
                .replication_sources()?
                .iter()
                .any(|s| s.state == "enrolled" && s.tenants.iter().any(|t| t == tenant)))
    }

    /// `{"health": …}` of a verify / chunk_repair job → catalog, audit, alert.
    pub(crate) fn health_bookkeeping(&self, job: &Job, stdout: Option<&str>) -> Result<()> {
        let Some(h) = stdout
            .and_then(|s| serde_json::from_str::<Value>(s).ok())
            .map(|v| v["health"].clone())
            .filter(Value::is_object)
        else {
            return Ok(());
        };
        let t = &job.tenant;
        let now: BTreeMap<(String, i64), i64> = h["damaged"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|d| {
                Some((
                    (d["source"].as_str()?.to_owned(), d["time"].as_i64()?),
                    d["chunks"].as_i64()?,
                ))
            })
            .collect();
        let before: Vec<(String, i64)> = {
            let c = self.db.conn();
            let mut st = c.prepare("SELECT source, time FROM snapshots WHERE tenant=?1 AND damaged IS NOT NULL")?;
            let rows = st.query_map([t], |r| Ok((r.get(0)?, r.get(1)?)))?;
            rows.collect::<std::result::Result<_, _>>()?
        };
        let ts = catalog::now();
        let healed: Vec<String> = before
            .iter()
            .filter(|k| !now.contains_key(*k))
            .map(|(s, time)| format!("{s}/{time}"))
            .collect();
        let fresh: Vec<String> = now
            .keys()
            .filter(|k| !before.contains(k))
            .map(|(s, time)| format!("{s}/{time}"))
            .collect();
        {
            let mut c = self.db.conn();
            let tx = c.transaction()?;
            for (s, time) in before.iter().filter(|k| !now.contains_key(*k)) {
                tx.execute(
                    "UPDATE snapshots SET damaged=NULL, damaged_at=NULL WHERE tenant=?1 AND source=?2 AND time=?3",
                    params![t, s, time],
                )?;
            }
            for ((s, time), n) in &now {
                // the first detection time stays while it is damaged
                tx.execute(
                    "UPDATE snapshots SET damaged=?4, damaged_at=COALESCE(damaged_at, ?5) \
                     WHERE tenant=?1 AND source=?2 AND time=?3",
                    params![t, s, time, n, ts],
                )?;
            }
            tx.commit()?;
        }
        if !fresh.is_empty() {
            self.db.audit(
                ACTOR,
                "snapshot.damaged",
                &format!("tenant/{t}"),
                &json!({"job": job.id, "snapshots": fresh, "bad_chunks": h["bad_chunks"]}),
            )?;
        }
        if !healed.is_empty() {
            self.db.audit(
                ACTOR,
                "snapshot.repaired",
                &format!("tenant/{t}"),
                &json!({"job": job.id, "kind": job.kind, "snapshots": healed}),
            )?;
        }
        let key = format!("{ALERT}:{t}");
        if now.is_empty() {
            return self.resolve(&key);
        }
        let mut names: Vec<String> = now.keys().map(|(s, time)| format!("{s}/{time}")).collect();
        let more = names.len().saturating_sub(LISTED);
        names.truncate(LISTED);
        self.raise(
            "critical",
            ALERT,
            &key,
            &format!(
                "{} snapshot(s) of tenant {t} reference {} chunk(s) that failed verification: {}{}. \
                 Run Repair on the Snapshots page; the next backup of these sources reads in full.",
                now.len(),
                h["bad_chunks"],
                names.join(", "),
                if more > 0 {
                    format!(" and {more} more")
                } else {
                    String::new()
                }
            ),
            Some(t),
        )?;
        let queued: i64 = self.db.conn().query_row(
            "SELECT COUNT(*) FROM jobs WHERE kind='chunk_repair' AND tenant=?1 AND state IN ('queued','running')",
            [t],
            |r| r.get(0),
        )?;
        if job.kind == "verify" && h["new_bad"].as_u64().unwrap_or(0) > 0 && queued == 0 && self.has_repair_source(t)? {
            self.insert_job("chunk_repair", t, &json!({"after_verify": job.id}))?;
        }
        Ok(())
    }
}
