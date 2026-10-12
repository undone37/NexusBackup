//! Orphaned snapshots and approved snapshot deletes (Phase 13a).
//!
//! A store source no protection group of its tenant covers any more (guest
//! removed from its group, group deleted, ad-hoc backups) gets no per-group
//! retention. The daily `gc` job therefore prunes those sources first, with the
//! GFS of setting `orphan_gfs` (JSON like `policies.gfs`; default 14/4/6/2),
//! raises an `orphaned` info alert once per source and audits
//! `retention.orphans` when it deleted something. Replicated tenants are left
//! alone: their snapshots follow the replication source's GFS.
//!
//! `snapshot.delete` approval requests (web-api `DELETE /snapshots/...`) become
//! `snapshot_delete` jobs once approved; the store refuses locked snapshots.

use super::*;

/// Catalog setting with the GFS for orphaned sources.
pub const ORPHAN_GFS: &str = "orphan_gfs";

/// Which store sources a tenant's groups cover.
#[derive(Debug, Default)]
pub struct Coverage {
    pub sources: HashSet<String>,
    /// TrueNAS child datasets (see `group_prefixes`)
    pub prefixes: Vec<String>,
    /// plugin sources (by source id) with a group: all their guests, also while
    /// the plugin is not installed
    pub plugin_sources: HashSet<u64>,
}

impl Coverage {
    pub fn covers(&self, src: &str) -> bool {
        self.sources.contains(src)
            || self.prefixes.iter().any(|p| src.starts_with(p.as_str()))
            || plugin_proto::parse_source_name(src).is_some_and(|(_, sid, _)| self.plugin_sources.contains(&sid))
    }
}

impl Scheduler {
    /// The orphan sweep of `tenant`'s gc job; `None` for replicated tenants.
    pub(crate) fn orphan_step(&self, tenant: &str) -> Result<Option<Step>> {
        if self.replicated_tenants()?.contains_key(tenant) {
            return Ok(None);
        }
        let plugin_ids: HashSet<i64> = {
            let c = self.db.conn();
            let mut st = c.prepare("SELECT id FROM sources WHERE kind LIKE 'plugin:%'")?;
            let rows = st.query_map([], |r| r.get(0))?;
            rows.collect::<std::result::Result<_, _>>()?
        };
        let mut cov = Coverage::default();
        for g in self.groups()?.into_iter().filter(|g| g.tenant == tenant) {
            cov.sources.extend(group_sources(&g));
            cov.prefixes.extend(group_prefixes(&g));
            if plugin_ids.contains(&g.source_id) {
                cov.plugin_sources.insert(g.source_id as u64);
            }
        }
        let gfs = catalog::setting(&self.db.conn(), ORPHAN_GFS)?
            .and_then(|s| serde_json::from_str::<Value>(&s).ok())
            .map_or_else(Gfs::default, |v| gfs_of(&v));
        Ok(Some(Step::Orphans { coverage: cov, gfs }))
    }

    /// After a gc job: alerts for newly seen orphans, audit of what was pruned.
    /// `stdout` is the orphan step's `{"orphans": {source: deleted}}`.
    pub(crate) fn orphan_bookkeeping(&self, tenant: &str, stdout: Option<&str>) -> Result<()> {
        let Some(v) = stdout.and_then(|s| serde_json::from_str::<Value>(s).ok()) else {
            return Ok(());
        };
        let Some(orphans) = v["orphans"].as_object() else {
            return Ok(());
        };
        let mut deleted = BTreeMap::new();
        for (src, n) in orphans {
            let prefix = format!("{tenant}/{src} is in no protection group");
            if !self.ever_alerted("orphaned", &prefix)? {
                self.alert(
                    "info",
                    "orphaned",
                    &format!("{prefix}; pruned with the default retention"),
                    None,
                )?;
            }
            if n.as_u64().unwrap_or(0) > 0 {
                deleted.insert(src.clone(), n.clone());
            }
        }
        if !deleted.is_empty() {
            self.db.audit(
                ACTOR,
                "retention.orphans",
                &format!("tenant/{tenant}"),
                &json!({"deleted": deleted}),
            )?;
        }
        Ok(())
    }

    /// Approved `snapshot.delete` requests become `snapshot_delete` jobs. A
    /// request decided by its own requester (approvals were disabled) only while
    /// approvals are still disabled.
    pub(crate) fn queue_snapshot_deletes(&mut self) -> Result<()> {
        let rows: Vec<(i64, String, String, Option<String>)> = {
            let c = self.db.conn();
            let mut st = c.prepare(
                "SELECT q.id, q.params, q.requested_by, q.decided_by FROM quorum q \
                 WHERE q.action='snapshot.delete' AND q.state='approved' \
                 AND NOT EXISTS (SELECT 1 FROM jobs j WHERE j.kind='snapshot_delete' AND json_extract(j.params,'$.quorum_id')=q.id)",
            )?;
            let rows = st.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?;
            rows.collect::<std::result::Result<_, _>>()?
        };
        for (id, p, by, decided) in rows {
            if decided.as_deref() == Some(by.as_str()) && catalog::approvals_enabled(&self.db.conn())? {
                continue;
            }
            let p: Value = serde_json::from_str(&p).unwrap_or(Value::Null);
            let (Some(tenant), Some(source), Some(time)) =
                (p["tenant"].as_str(), p["source"].as_str(), p["time"].as_u64())
            else {
                continue;
            };
            self.insert_job(
                "snapshot_delete",
                tenant,
                &json!({"source": source, "time": time, "quorum_id": id, "requested_by": by}),
            )?;
        }
        Ok(())
    }
}
