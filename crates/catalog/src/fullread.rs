//! Scheduled full read with a change-tracking drift check (Phase 29, catalog
//! v44; docs/netbackup-comparison.md Tier 1 #1), shared by the web-api
//! (group setting, list, dashboard) and the scheduler (due sources, results).

use rusqlite::{params, Connection};

/// Alert kind of a full read that found changes the tracker had not reported.
pub const ALERT_KIND: &str = "change_tracking";
pub const MAX_DAYS: i64 = 365;

/// Interval in days when the group sets none (`groups.full_read_days` NULL):
/// Proxmox VE VMs 90 (I/O on production storage, fleecing space), agents and
/// NAS 30; other sources have no change tracking to check (0).
pub fn default_days(source_kind: &str) -> i64 {
    match source_kind {
        "pve" => 90,
        "linux" | "nfs" | "smb" | "truenas" => 30,
        _ => 0,
    }
}

/// The group's effective interval (0 = off).
pub fn days(setting: Option<i64>, source_kind: &str) -> i64 {
    setting.unwrap_or_else(|| default_days(source_kind)).clamp(0, MAX_DAYS)
}

/// First due time of a source never read in full: spread over the interval by
/// a hash of its name, so not every guest rescans on the same night.
pub fn first_due(now: i64, tenant: &str, source: &str, days: i64) -> i64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325; // FNV-1a
    for b in tenant.bytes().chain([0]).chain(source.bytes()) {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    now + (h % days.max(1) as u64) as i64 * 86_400
}

/// Sources of `tenant` whose full read is due at `now` (a source without a
/// row gets one, due at [`first_due`]).
pub fn due(c: &Connection, tenant: &str, sources: &[String], days: i64, now: i64) -> rusqlite::Result<Vec<String>> {
    if days <= 0 {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for s in sources {
        c.execute(
            "INSERT OR IGNORE INTO full_reads (tenant, source, next_due) VALUES (?1, ?2, ?3)",
            params![tenant, s, first_due(now, tenant, s, days)],
        )?;
        let next: i64 = c.query_row(
            "SELECT next_due FROM full_reads WHERE tenant = ?1 AND source = ?2",
            params![tenant, s],
            |r| r.get(0),
        )?;
        if next <= now {
            out.push(s.clone());
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_stagger_and_due() {
        assert_eq!(days(None, "pve"), 90);
        assert_eq!(days(None, "linux"), 30);
        assert_eq!(days(Some(0), "pve"), 0);
        assert_eq!(days(Some(7), "plugin:pg"), 7);
        assert_eq!(days(None, "plugin:pg"), 0);
        let d = first_due(1000, "t", "vm-100", 30);
        assert!((1000..1000 + 30 * 86_400).contains(&d));
        assert_eq!(d, first_due(1000, "t", "vm-100", 30), "stable");
        let spread: std::collections::BTreeSet<i64> =
            (100..140).map(|v| first_due(0, "t", &format!("vm-{v}"), 30)).collect();
        assert!(spread.len() > 10, "spread over the interval");

        let cat = crate::Catalog::open_memory().unwrap();
        let c = cat.conn();
        let srcs = vec!["vm-1".to_owned(), "vm-2".to_owned()];
        assert!(due(&c, "t", &srcs, 0, 5).unwrap().is_empty(), "off");
        let now = 1_000_000;
        let first = due(&c, "t", &srcs, 30, now).unwrap();
        c.execute("UPDATE full_reads SET next_due = ?1 WHERE source = 'vm-2'", [now - 1])
            .unwrap();
        let second = due(&c, "t", &srcs, 30, now).unwrap();
        assert!(second.contains(&"vm-2".to_owned()));
        assert!(first.len() <= second.len());
    }
}
