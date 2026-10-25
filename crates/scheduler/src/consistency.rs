//! Consistency per snapshot (Phase 15d, docs/control-plane.md "Consistency").
//!
//! Levels, strongest first: `application` (quiesced), `crash` (point in time,
//! no quiesce), `inconsistent` (read live), `unknown`. Where they come from:
//! - `vm-` / `ct-`: nexus-pve's `consistency <source>/<time>: <level> (…)` line,
//!   parsed from the vzdump task log (`crates/pve/src/consistency.rs`);
//! - `host-` (agents): `inconsistent …` line → inconsistent; else `application`
//!   with pre/post hooks (Linux source `hooks`) or on Windows (VSS writers),
//!   otherwise `crash` (volume snapshot only);
//! - `share-` (NFS/SMB): `inconsistent …` → inconsistent, else `crash` (NAS snapshot);
//! - `nas-` (TrueNAS): `crash` (ZFS snapshot);
//! - `vmw-` (VMware): nexus-vmware's `consistency` line: `application` when VMware Tools quiesced the
//!   snapshot, else `crash`;
//! - `xcp-` (XCP-ng): nexus-xcpng's `consistency` line, always `crash` (XCP-ng 8 has no quiesced snapshots);
//! - `plugin-`: `inconsistent …` → inconsistent; else the manifest's
//!   `backup.consistent` (`application` or else `crash`).
//!
//! The policy option `require_consistency` (`{"mode": "off"|"warn"|"fail",
//! "level": "application"|"crash"}`) applies to group backups: a snapshot below
//! the level raises a `consistency` warning (one per source, resolved by the next
//! snapshot that meets it) or, with `fail`, also fails the job (the snapshot is
//! kept; retries follow the policy).

use crate::{Job, Scheduler};
use anyhow::Result;
use catalog::rusqlite::{params, OptionalExtension};
use serde_json::{json, Value};

pub const LEVELS: &[&str] = &["application", "crash", "inconsistent", "unknown"];

fn rank(level: &str) -> usize {
    LEVELS.iter().position(|l| *l == level).unwrap_or(LEVELS.len())
}

/// Level of snapshot `id` (`<source>/<time>`) from the backup job's log;
/// `quiesced`: the source quiesces when it has a consistent view (see module doc).
pub fn from_log(id: &str, log: &str, quiesced: bool) -> &'static str {
    let tag = format!("consistency {id}: ");
    if let Some(l) = log.lines().find_map(|l| l.strip_prefix(&tag)) {
        let w = l.split_whitespace().next().unwrap_or_default();
        return LEVELS.iter().find(|x| **x == w).copied().unwrap_or("unknown");
    }
    let src = id.split('/').next().unwrap_or_default();
    let bad = format!("inconsistent {id}:");
    if log.lines().any(|l| l.starts_with(&bad)) {
        return "inconsistent";
    }
    if src.starts_with("host-") || src.starts_with("plugin-") {
        if quiesced {
            "application"
        } else {
            "crash"
        }
    } else if src.starts_with("share-") || src.starts_with("nas-") {
        "crash"
    } else {
        "unknown" // vm-/ct- without the line: a connector before Phase 15d
    }
}

/// `require_consistency` of a policy: (mode, minimum level).
pub fn requirement(v: &Value) -> (&str, &str) {
    let mode = v["mode"]
        .as_str()
        .filter(|m| ["warn", "fail"].contains(m))
        .unwrap_or("off");
    let level = if v["level"].as_str() == Some("application") {
        "application"
    } else {
        "crash"
    };
    (mode, level)
}

/// Whether `level` meets the minimum `min`.
pub fn meets(level: &str, min: &str) -> bool {
    rank(level) <= rank(min)
}

impl Scheduler {
    /// Does the source quiesce when it has a consistent view (hooks / VSS / plugin)?
    fn quiesced(&self, tenant: &str, source: &str) -> Result<bool> {
        let c = self.db.conn();
        if let Some(agent) = source.strip_prefix("host-") {
            let n: i64 = c.query_row(
                "SELECT (SELECT COUNT(*) FROM agents WHERE id=?1 AND tenant=?2 AND lower(COALESCE(os,'')) LIKE '%windows%')
                      + (SELECT COUNT(*) FROM sources WHERE tenant=?2 AND kind='linux'
                         AND json_extract(config,'$.agent_id')=?1 AND json_extract(config,'$.hooks')=1)",
                params![agent, tenant],
                |r| r.get(0),
            )?;
            return Ok(n > 0);
        }
        if let Some((_, sid, _)) = plugin_proto::parse_source_name(source) {
            let kind: Option<String> = c
                .query_row("SELECT kind FROM sources WHERE id=?1", [sid as i64], |r| r.get(0))
                .optional()?;
            let Some(k) = kind.as_deref().and_then(|k| k.strip_prefix("plugin:")) else {
                return Ok(false);
            };
            let cur = plugin_manager::current_for_kind(&c, k).map_err(|e| anyhow::anyhow!("{e}"))?;
            let m: Value = cur
                .and_then(|x| serde_json::from_str(&x.manifest_raw).ok())
                .unwrap_or_default();
            let app =
                m["kinds"].as_array().into_iter().flatten().any(|x| {
                    x["kind"].as_str() == Some(k) && x["backup"]["consistent"].as_str() == Some("application")
                });
            return Ok(app);
        }
        Ok(false)
    }

    /// Adds `consistency` to each snapshot of a backup result.
    pub(crate) fn add_consistency(&self, tenant: &str, log: &str, snaps: &mut [Value]) {
        for s in snaps {
            let (Some(src), Some(t)) = (s["source"].as_str(), s["time"].as_i64()) else {
                continue;
            };
            let q = self.quiesced(tenant, src).unwrap_or(false);
            s["consistency"] = json!(from_log(&format!("{src}/{t}"), log, q));
        }
    }

    /// Records the levels of a finished backup in `snapshots` (the row may not
    /// exist yet: the refresh fills in the rest) and applies the group's policy.
    /// Returns the reason when the policy fails the job.
    pub(crate) fn consistency_bookkeeping(&self, job: &Job, result: Option<&Value>) -> Result<Option<String>> {
        let snaps: Vec<(String, i64, String)> = result
            .and_then(|r| r["snapshots"].as_array())
            .into_iter()
            .flatten()
            .filter_map(|s| {
                Some((
                    s["source"].as_str()?.to_owned(),
                    s["time"].as_i64()?,
                    s["consistency"].as_str()?.to_owned(),
                ))
            })
            .collect();
        for (src, t, lvl) in &snaps {
            self.db.conn().execute(
                "INSERT INTO snapshots (tenant, source, time, local, offsite, consistency) VALUES (?1,?2,?3,1,0,?4)
                 ON CONFLICT (tenant, source, time) DO UPDATE SET consistency=?4",
                params![job.tenant, src, t, lvl],
            )?;
        }
        let Some(g) = job.params["group_id"].as_i64() else {
            return Ok(None);
        };
        let req: Option<String> = self
            .db
            .conn()
            .query_row(
                "SELECT p.require_consistency FROM groups g JOIN policies p ON p.id = g.policy_id WHERE g.id=?1",
                [g],
                |r| r.get(0),
            )
            .optional()?;
        let req: Value = req.and_then(|r| serde_json::from_str(&r).ok()).unwrap_or_default();
        let (mode, min) = requirement(&req);
        let mut failed = Vec::new();
        for (src, t, lvl) in &snaps {
            let key = format!("consistency:{}/{src}", job.tenant);
            if mode == "off" || meets(lvl, min) {
                self.resolve(&key)?;
                continue;
            }
            self.raise(
                "warning",
                "consistency",
                &key,
                &format!(
                    "{src}/{t} is {lvl}, the policy requires {min} (backup job {}, tenant {})",
                    job.id, job.tenant
                ),
                Some(&job.tenant),
            )?;
            failed.push(format!("{src}/{t}: {lvl}"));
        }
        Ok((mode == "fail" && !failed.is_empty())
            .then(|| format!("consistency below the policy minimum ({min}): {}", failed.join(", "))))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn levels_from_logs() {
        let log = "committed vm-100/17\nconsistency vm-100/17: application (guest-agent fs-freeze/fs-thaw)\n\
                   consistency ct-200/18: crash (frozen container, storage snapshot)\n";
        assert_eq!(from_log("vm-100/17", log, false), "application");
        assert_eq!(from_log("ct-200/18", log, false), "crash");
        assert_eq!(from_log("vm-101/17", log, false), "unknown");
        let agent = "committed host-a/5 in 1s\ninconsistent host-a/5: consistent=false (3 files changed)\n";
        assert_eq!(from_log("host-a/5", agent, true), "inconsistent");
        assert_eq!(from_log("host-b/5", agent, true), "application");
        assert_eq!(from_log("host-b/5", agent, false), "crash");
        assert_eq!(from_log("share-2/9", "", false), "crash");
        assert_eq!(from_log("nas-1-tank.data/9", "", false), "crash");
        assert_eq!(from_log("plugin-pg-3/9", "", true), "application");
        assert_eq!(from_log("vm-1/1", "consistency vm-1/1: bogus", false), "unknown");
    }

    #[test]
    fn requirements() {
        assert_eq!(
            requirement(&json!({"mode": "fail", "level": "application"})),
            ("fail", "application")
        );
        assert_eq!(requirement(&json!({"mode": "x"})), ("off", "crash"));
        assert_eq!(requirement(&Value::Null), ("off", "crash"));
        assert!(meets("application", "crash"));
        assert!(meets("crash", "crash"));
        assert!(!meets("crash", "application"));
        assert!(!meets("inconsistent", "crash"));
        assert!(!meets("unknown", "crash"));
    }
}
