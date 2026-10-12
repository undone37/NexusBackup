//! `fleecing_space` alerts (Phase 18) from the `fleecing-space {json}` lines
//! nexus-pve prints when it checks a node's fleecing storage before and during
//! a VM backup (`pve/src/fleecing.rs`): a storage below the guard (guest
//! skipped) or the critical level (backup cancelled) raises a critical alert
//! keyed `fleecing_space:<tenant>/<node>/<storage>`; the next check that finds
//! enough room resolves it. Per job and storage the last line counts.

use super::*;

impl Scheduler {
    pub(crate) fn fleecing_bookkeeping(&self, job: &Job, log: &str) -> Result<()> {
        let mut last: BTreeMap<(String, String), Value> = BTreeMap::new();
        for v in log
            .lines()
            .filter_map(|l| serde_json::from_str::<Value>(l.strip_prefix("fleecing-space ")?).ok())
        {
            let (Some(node), Some(storage)) = (v["node"].as_str(), v["storage"].as_str()) else {
                continue;
            };
            last.insert((node.to_owned(), storage.to_owned()), v);
        }
        for ((node, storage), v) in last {
            let key = format!("fleecing_space:{}/{node}/{storage}", job.tenant);
            let what = match v["state"].as_str() {
                Some("ok") => {
                    self.resolve(&key)?;
                    continue;
                }
                Some("low") => "below the guard: guests on this node are skipped",
                Some("critical") => "below the critical level: running backups on this node are cancelled",
                _ => continue,
            };
            let mut free = format!(
                "{:.1} GiB ({} %) free",
                v["free"].as_f64().unwrap_or(0.0) / f64::from(1u32 << 30),
                v["free_pct"]
            );
            if let Some(m) = v["meta_free_pct"].as_f64() {
                free.push_str(&format!(", metadata {m:.0} % free"));
            }
            self.raise(
                "critical",
                "fleecing_space",
                &key,
                &format!(
                    "fleecing storage {storage} on node {node} has {free}, {what} (backup job {}, tenant {})",
                    job.id, job.tenant
                ),
                lifecycle::tenant_of(job),
            )?;
        }
        Ok(())
    }
}
