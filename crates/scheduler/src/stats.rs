//! Storage accounting (docs/storage-accounting.md): the connectors' per-snapshot
//! `nexus-stats {json}` lines go into `backup_stats` (catalog v13), each new row
//! is checked for a change-rate anomaly (`anomaly.rs`), and the daily capacity
//! sample is compared with the tenant's soft quota (`tenants.quota_bytes`).

use crate::{valid_name, Scheduler};
use anyhow::Result;
use catalog::rusqlite::params;
use serde::Deserialize;

/// One `nexus-stats` line (all byte counts; see `chunkstore::Store::stats_line`).
#[derive(Deserialize, Debug, Clone, PartialEq, Default)]
pub struct Stats {
    pub source: String,
    pub time: i64,
    /// bytes read from the source
    pub read: u64,
    /// the snapshot's logical size
    pub logical: u64,
    pub new_chunks: u64,
    /// plain bytes of the chunks this snapshot added to the store
    pub new_plain: u64,
    /// their sealed size on disk (after compression + encryption)
    pub new_stored: u64,
}

/// The well-formed `nexus-stats` lines of a job log.
pub fn parse(log: &str) -> Vec<Stats> {
    log.lines()
        .filter_map(|l| serde_json::from_str::<Stats>(l.strip_prefix("nexus-stats ")?).ok())
        .filter(|s| valid_name(&s.source) && s.time > 0)
        .collect()
}

/// Quota alert level for `used` of `quota` bytes: 100 % = critical, 80 % = warning.
pub fn quota_level(used: i64, quota: i64) -> Option<&'static str> {
    if quota <= 0 {
        return None;
    }
    if used >= quota {
        Some("critical")
    } else if used * 5 >= quota * 4 {
        Some("warning")
    } else {
        None
    }
}

impl Scheduler {
    /// Stores the stats of a finished backup job (idempotent upsert per
    /// snapshot), then runs the anomaly check on each new row.
    pub(crate) fn record_stats(&self, tenant: &str, log: &str) -> Result<()> {
        for s in parse(log) {
            self.db.conn().execute(
                "INSERT INTO backup_stats (tenant, source, time, read, logical, new_chunks, new_plain, new_stored)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8)
                 ON CONFLICT(tenant, source, time) DO UPDATE SET read=excluded.read, logical=excluded.logical,
                   new_chunks=excluded.new_chunks, new_plain=excluded.new_plain, new_stored=excluded.new_stored",
                params![
                    tenant,
                    s.source,
                    s.time,
                    s.read as i64,
                    s.logical as i64,
                    s.new_chunks as i64,
                    s.new_plain as i64,
                    s.new_stored as i64
                ],
            )?;
            self.check_anomaly(tenant, &s)?;
        }
        Ok(())
    }

    /// Soft quotas: compares each tenant's latest capacity sample (bytes in
    /// its store) with `tenants.quota_bytes`. Alerts only; backups go on.
    pub(crate) fn check_quotas(&self) -> Result<()> {
        let rows: Vec<(String, i64, i64)> = {
            let c = self.db.conn();
            let mut st = c.prepare(
                "SELECT t.name, t.quota_bytes, (SELECT used FROM capacity_samples s WHERE s.tenant = t.name
                   ORDER BY day DESC LIMIT 1) FROM tenants t WHERE t.quota_bytes IS NOT NULL",
            )?;
            let rows = st.query_map([], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get::<_, Option<i64>>(2)?.unwrap_or(0)))
            })?;
            rows.collect::<std::result::Result<_, _>>()?
        };
        for (tenant, quota, used) in rows {
            let Some(sev) = quota_level(used, quota) else { continue };
            let pfx = match sev {
                "critical" => format!("tenant {tenant} exceeds its storage quota"),
                _ => format!("tenant {tenant} uses over 80 % of its storage quota"),
            };
            let msg = format!(
                "{pfx}: {} of {} ({:.0} %); soft quota, backups continue",
                crate::anomaly::human(used as u64),
                crate::anomaly::human(quota as u64),
                used as f64 * 100.0 / quota as f64
            );
            self.alert(sev, "quota", &msg, Some(&pfx))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_stats_lines() {
        let log = "committed vm-100/1700000000 in 3s\n\
            nexus-stats {\"source\":\"vm-100\",\"time\":1700000000,\"read\":10,\"logical\":100,\"new_chunks\":2,\"new_plain\":8,\"new_stored\":5}\n\
            nexus-stats {\"source\":\"../x\",\"time\":1,\"read\":0,\"logical\":0,\"new_chunks\":0,\"new_plain\":0,\"new_stored\":0}\n\
            nexus-stats {broken\n\
            nexus-stats {\"source\":\"ct-7\",\"time\":5}\n";
        let v = parse(log);
        assert_eq!(
            v,
            vec![Stats {
                source: "vm-100".into(),
                time: 1700000000,
                read: 10,
                logical: 100,
                new_chunks: 2,
                new_plain: 8,
                new_stored: 5
            }]
        );
    }

    #[test]
    fn quota_levels() {
        assert_eq!(quota_level(79, 100), None);
        assert_eq!(quota_level(80, 100), Some("warning"));
        assert_eq!(quota_level(99, 100), Some("warning"));
        assert_eq!(quota_level(100, 100), Some("critical"));
        assert_eq!(quota_level(500, 0), None);
    }
}
