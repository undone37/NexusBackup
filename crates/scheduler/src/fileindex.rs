//! Phase 31 (docs/file-index-v2-plan.md): the scheduler's side of the file
//! search. It keeps `snapshot_index` (catalog v42) for VM/CT snapshots,
//! writes the resolved `group_sources`, sends nexus-index the per-source
//! rules (`groups.index_rules`, `groups.index_files`) and nudges it after
//! jobs that change snapshots, and raises `index_backlog` / `index_space`.
//! nexus-index may be missing (tests, a stopped service): every call is best
//! effort, from a background thread, with short timeouts.

use crate::{group_sources, Job, Scheduler};
use anyhow::Result;
use catalog::rusqlite::params;
use index_proto::{Request, SourceRules};
use serde_json::Value;
use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{channel, Sender};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

/// A snapshot waiting longer than this for its index raises `index_backlog` (Cohesity: 48 h).
pub const BACKLOG_SECS: i64 = 48 * 3600;
const CALL_TIMEOUT: Duration = Duration::from_secs(5);

/// Jobs after which the tenant's snapshots (or their name indexes) changed.
const CHANGES: &[&str] = &[
    "backup",
    "plugin_backup",
    "retention",
    "snapshot_delete",
    "offsite_restore",
    "replica_sync",
    "file_index",
    "gc",
];

static OUTBOX: OnceLock<Mutex<Sender<(PathBuf, Request)>>> = OnceLock::new();

/// Sends a request to nexus-index from a background thread (never blocks the scheduler).
pub fn post(socket: &Path, req: Request) {
    let tx = OUTBOX.get_or_init(|| {
        let (tx, rx) = channel::<(PathBuf, Request)>();
        std::thread::Builder::new()
            .name("index-outbox".into())
            .spawn(move || {
                for (sock, req) in rx {
                    if !sock.exists() {
                        continue;
                    }
                    if let Err(e) = index_proto::call(&sock, &req, CALL_TIMEOUT) {
                        eprintln!("<6>nexus-index: {e}");
                    }
                }
            })
            .expect("index outbox thread");
        Mutex::new(tx)
    });
    let _ = tx.lock().unwrap().send((socket.to_owned(), req));
}

/// The rules of a group (`groups.index_rules`, NULL = defaults).
pub fn group_rules(json: Option<&str>, enabled: bool) -> SourceRules {
    let mut r: SourceRules = json.and_then(|j| serde_json::from_str(j).ok()).unwrap_or_default();
    r.enabled = enabled;
    r
}

impl Scheduler {
    /// After a job: `snapshot_index` bookkeeping for `file_index`, a nudge
    /// for nexus-index when snapshots may have changed.
    pub(crate) fn index_after_job(&self, job: &Job, ok: bool, result: Option<&Value>, log: &str) -> Result<()> {
        if job.kind == "file_index" {
            if let (Some(source), Some(time)) = (job.params["source"].as_str(), job.params["time"].as_i64()) {
                self.index_state(job, source, time, ok, result, log)?;
            }
        }
        if CHANGES.contains(&job.kind.as_str()) && valid(&job.tenant) {
            post(
                &self.cfg.index_socket,
                Request::Sync {
                    tenant: job.tenant.clone(),
                },
            );
        }
        Ok(())
    }

    fn index_state(&self, job: &Job, source: &str, time: i64, ok: bool, result: Option<&Value>, log: &str) -> Result<()> {
        let (state, reason, entries, volumes) = match result {
            Some(r) if ok => {
                let vols = r["volumes"].as_array().cloned().unwrap_or_default();
                let problems: Vec<String> = vols
                    .iter()
                    .filter(|v| matches!(v["state"].as_str(), Some("unsupported" | "failed" | "partial")))
                    .map(|v| {
                        format!(
                            "{}: {}",
                            v["browse"].as_str().unwrap_or("?"),
                            v["reason"].as_str().unwrap_or("not indexed")
                        )
                    })
                    .collect();
                let partial = !problems.is_empty() || r["complete"] == false;
                (
                    if partial { "partial" } else { "indexed" },
                    (!problems.is_empty()).then(|| problems.join("; ")),
                    r["entries"].as_i64(),
                    (!vols.is_empty()).then(|| Value::Array(vols).to_string()),
                )
            }
            _ => {
                let last = log.lines().rev().find(|l| !l.trim().is_empty()).unwrap_or("file index job failed");
                ("failed", Some(last.chars().take(300).collect()), None, None)
            }
        };
        let now = catalog::now();
        self.db.conn().execute(
            "INSERT INTO snapshot_index (tenant, source, time, state, reason, entries, volumes, job_id, queued, updated) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?9) \
             ON CONFLICT(tenant, source, time) DO UPDATE SET state = excluded.state, reason = excluded.reason, \
             entries = excluded.entries, volumes = excluded.volumes, job_id = excluded.job_id, updated = excluded.updated",
            params![job.tenant, source, time, state, reason, entries, volumes, job.id, now],
        )?;
        Ok(())
    }

    /// `file_index` queued for a VM/CT snapshot: its index state is pending.
    pub(crate) fn index_pending(&self, tenant: &str, source: &str, time: i64, job_id: i64) -> Result<()> {
        let now = catalog::now();
        self.db.conn().execute(
            "INSERT INTO snapshot_index (tenant, source, time, state, job_id, queued, updated) \
             VALUES (?1, ?2, ?3, 'pending', ?4, ?5, ?5) \
             ON CONFLICT(tenant, source, time) DO UPDATE SET state = 'pending', job_id = excluded.job_id, \
             queued = excluded.queued, updated = excluded.updated",
            params![tenant, source, time, job_id, now],
        )?;
        Ok(())
    }

    /// With the full refresh: group -> sources (search filter), the rules per
    /// source for nexus-index, stale rows, and the health alerts.
    pub(crate) fn index_maintenance(&self, now: i64) -> Result<()> {
        let groups = self.groups()?;
        let rules: BTreeMap<i64, (Option<String>, bool, String)> = {
            let c = self.db.conn();
            let mut st = c.prepare(
                "SELECT g.id, g.index_rules, g.index_files, s.kind FROM groups g JOIN sources s ON s.id = g.source_id",
            )?;
            let rows = st.query_map([], |r| Ok((r.get::<_, i64>(0)?, (r.get(1)?, r.get(2)?, r.get(3)?))))?;
            rows.collect::<std::result::Result<_, _>>()?
        };
        let mut per_tenant: BTreeMap<String, BTreeMap<String, SourceRules>> = BTreeMap::new();
        {
            let mut c = self.db.conn();
            let tx = c.transaction()?;
            tx.execute("DELETE FROM group_sources", [])?;
            for g in &groups {
                let (json, index_files, kind) = rules.get(&g.id).cloned().unwrap_or((None, true, String::new()));
                // VM/CT: the group's index_files switch; file trees are always indexed
                for s in group_sources(g) {
                    tx.execute(
                        "INSERT OR IGNORE INTO group_sources (group_id, tenant, source) VALUES (?1, ?2, ?3)",
                        params![g.id, g.tenant, s],
                    )?;
                    let guest = s.starts_with("vm-") || s.starts_with("ct-");
                    let enabled = !(kind == "pve" && guest) || index_files;
                    let t = per_tenant.entry(g.tenant.clone()).or_default();
                    // a source in several groups: the first group (lowest id) decides
                    t.entry(s).or_insert_with(|| group_rules(json.as_deref(), enabled));
                }
            }
            // rows of deleted snapshots (a day of grace: the snapshot list may lag)
            tx.execute(
                "DELETE FROM snapshot_index WHERE updated < ?1 AND NOT EXISTS (SELECT 1 FROM snapshots s \
                 WHERE s.tenant = snapshot_index.tenant AND s.source = snapshot_index.source AND s.time = snapshot_index.time)",
                [now - 86400],
            )?;
            tx.commit()?;
        }
        for (tenant, sources) in per_tenant {
            if valid(&tenant) {
                post(&self.cfg.index_socket, Request::Config { tenant, sources });
            }
        }
        self.index_alerts(now)
    }

    fn index_alerts(&self, now: i64) -> Result<()> {
        // snapshots whose file_index job has not finished for 48 h
        let mut late: BTreeMap<String, (i64, i64)> = BTreeMap::new();
        {
            let c = self.db.conn();
            let mut st = c.prepare(
                "SELECT tenant, COUNT(*), MIN(queued) FROM snapshot_index WHERE state = 'pending' AND queued < ?1 GROUP BY tenant",
            )?;
            let rows = st.query_map([now - BACKLOG_SECS], |r| Ok((r.get::<_, String>(0)?, (r.get(1)?, r.get(2)?))))?;
            for r in rows {
                let (t, v) = r?;
                late.insert(t, v);
            }
        }
        // snapshots with a name index that nexus-index has not taken in for 48 h
        let status = self
            .cfg
            .index_socket
            .exists()
            .then(|| index_proto::call(&self.cfg.index_socket, &Request::Status { tenant: None }, CALL_TIMEOUT).ok())
            .flatten()
            .and_then(|v| serde_json::from_value::<index_proto::Status>(v).ok());
        if let Some(s) = &status {
            for t in &s.tenants {
                if let Some(o) = t.oldest_pending.filter(|o| (*o as i64) < now - BACKLOG_SECS) {
                    let e = late.entry(t.tenant.clone()).or_insert((0, o as i64));
                    e.0 += t.snapshots_pending as i64;
                    e.1 = e.1.min(o as i64);
                }
            }
            if s.paused {
                self.raise(
                    "warning",
                    "index_space",
                    "index_space",
                    &format!(
                        "file indexing paused: {} MiB free on the index volume, floor {} MiB",
                        s.free_bytes >> 20,
                        s.floor_bytes >> 20
                    ),
                    None,
                )?;
            } else {
                self.resolve("index_space")?;
            }
        }
        let mut seen = HashSet::new();
        for (t, (n, oldest)) in &late {
            seen.insert(t.clone());
            self.raise(
                "warning",
                "index_backlog",
                &format!("index_backlog:{t}"),
                &format!(
                    "{n} snapshot(s) of tenant {t} wait for the file index for more than 48 h (oldest since {} h)",
                    (now - oldest) / 3600
                ),
                Some(t),
            )?;
        }
        for (t, _) in self.tenants()? {
            if !seen.contains(&t) {
                self.resolve(&format!("index_backlog:{t}"))?;
            }
        }
        Ok(())
    }
}

fn valid(t: &str) -> bool {
    crate::valid_name(t) && t != "-"
}
