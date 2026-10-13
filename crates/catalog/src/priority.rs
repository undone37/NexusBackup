//! "Restore priority" (Phase 22b, docs/control-plane.md "Restore priority"):
//! while a disaster recovery runs, the appliance holds everything that competes
//! with restores for disks and network: scheduled backups, GC, verify, file
//! indexing, offsite uploads and replication syncs (queued jobs of those kinds
//! wait; running ones finish). Manual jobs and every restore run as usual. The
//! switch always expires (at most [`MAX_SECS`]); the web-api sets and clears it
//! (audited), the scheduler expires it (audited) and keeps the `restore_priority`
//! warning open while it is on. Kept in `settings` (no schema change).

use rusqlite::Connection;
use serde::{Deserialize, Serialize};

pub const SETTING: &str = "restore_priority";
/// Longest restore-priority period (renewable, each renewal audited).
pub const MAX_SECS: i64 = 24 * 3600;
pub const ALERT_KIND: &str = "restore_priority";
/// Job kinds that wait while it is on (plus backups the scheduler queued).
pub const HELD_KINDS: &[&str] = &["gc", "verify", "file_index", "offsite", "replica_sync"];

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Priority {
    pub until: i64,
    pub since: i64,
    pub by: String,
    #[serde(default)]
    pub reason: String,
}

/// The stored switch (also an expired one the scheduler has not cleared yet).
pub fn load(c: &Connection) -> rusqlite::Result<Option<Priority>> {
    Ok(crate::setting(c, SETTING)?.and_then(|s| serde_json::from_str(&s).ok()))
}

/// The switch if it is on at `now`.
pub fn active(c: &Connection, now: i64) -> rusqlite::Result<Option<Priority>> {
    Ok(load(c)?.filter(|p| p.until > now))
}

pub fn store(c: &Connection, p: &Priority) -> rusqlite::Result<()> {
    crate::set_setting(c, SETTING, &serde_json::to_string(p).expect("serializable"))
}

pub fn clear(c: &Connection) -> rusqlite::Result<bool> {
    Ok(c.execute("DELETE FROM settings WHERE key = ?1", [SETTING])? > 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn store_load_expire() {
        let cat = crate::Catalog::open_memory().unwrap();
        let c = cat.conn();
        assert!(load(&c).unwrap().is_none());
        let p = Priority {
            until: 200,
            since: 100,
            by: "alice".into(),
            reason: "DR of the ERP cluster".into(),
        };
        store(&c, &p).unwrap();
        assert_eq!(active(&c, 150).unwrap(), Some(p.clone()));
        assert!(active(&c, 200).unwrap().is_none(), "expired at until");
        assert_eq!(load(&c).unwrap(), Some(p));
        assert!(clear(&c).unwrap());
        assert!(!clear(&c).unwrap());
    }
}
