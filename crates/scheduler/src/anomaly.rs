//! Change-rate anomaly alert (Phase 13e, docs/storage-accounting.md): after
//! each backup's stats are stored, its new data is compared with the source's
//! own history. Critical `anomaly` alert when
//! - `new_plain` > max(factor × median `new_plain` of the last N runs, floor), or
//! - the new data hardly compresses (< 1.05) while the source's median
//!   compression is > 1.3 and `new_plain` > floor / 4 (an entropy proxy:
//!   encrypted files do not compress).
//!
//! Both need at least `MIN_HISTORY` earlier runs. Setting `anomaly`:
//! `{enabled, factor, history, floor_bytes}`.

use crate::stats::Stats;
use crate::Scheduler;
use anyhow::Result;
use catalog::rusqlite::params;
use serde::{Deserialize, Serialize};

pub const SETTING: &str = "anomaly";
pub const MIN_HISTORY: usize = 5;
const LOW_COMPRESSION: f64 = 1.05;
const USUAL_COMPRESSION: f64 = 1.3;

#[derive(Deserialize, Serialize, Debug, Clone, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub enabled: bool,
    pub factor: f64,
    /// runs of the median
    pub history: usize,
    pub floor_bytes: u64,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            enabled: true,
            factor: 3.0,
            history: 14,
            floor_bytes: 1 << 30,
        }
    }
}

impl Config {
    /// The setting, or the defaults when it is missing or unreadable.
    pub fn load(c: &catalog::rusqlite::Connection) -> Config {
        catalog::setting(c, SETTING)
            .ok()
            .flatten()
            .and_then(|v| serde_json::from_str(&v).ok())
            .unwrap_or_default()
    }
}

#[derive(Debug, PartialEq)]
pub enum Finding {
    /// (median new_plain, limit)
    Volume { median: f64, limit: f64 },
    /// (compression of the new data, median compression)
    Entropy { ratio: f64, median: f64 },
}

pub fn median(mut v: Vec<f64>) -> Option<f64> {
    if v.is_empty() {
        return None;
    }
    v.sort_by(f64::total_cmp);
    let n = v.len();
    Some(if n % 2 == 1 {
        v[n / 2]
    } else {
        (v[n / 2 - 1] + v[n / 2]) / 2.0
    })
}

/// Compression of new data (plain / stored); `None` without new data.
fn ratio(plain: u64, stored: u64) -> Option<f64> {
    (stored > 0 && plain > 0).then(|| plain as f64 / stored as f64)
}

/// `history`: (new_plain, new_stored) of earlier runs, newest first.
pub fn check(cfg: &Config, history: &[(u64, u64)], new_plain: u64, new_stored: u64) -> Option<Finding> {
    if !cfg.enabled || history.len() < MIN_HISTORY {
        return None;
    }
    let med = median(history.iter().map(|h| h.0 as f64).collect())?;
    let limit = (cfg.factor * med).max(cfg.floor_bytes as f64);
    if new_plain as f64 > limit {
        return Some(Finding::Volume { median: med, limit });
    }
    let r = ratio(new_plain, new_stored)?;
    let usual = median(history.iter().filter_map(|h| ratio(h.0, h.1)).collect())?;
    (r < LOW_COMPRESSION && usual > USUAL_COMPRESSION && new_plain > cfg.floor_bytes / 4).then_some(Finding::Entropy {
        ratio: r,
        median: usual,
    })
}

/// `1.5 GiB` style.
pub fn human(b: u64) -> String {
    const U: [&str; 6] = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
    let mut v = b as f64;
    let mut i = 0;
    while v >= 1024.0 && i < U.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{b} B")
    } else {
        format!("{v:.1} {}", U[i])
    }
}

impl Scheduler {
    pub(crate) fn check_anomaly(&self, tenant: &str, s: &Stats) -> Result<()> {
        let cfg = Config::load(&self.db.conn());
        if !cfg.enabled {
            return Ok(());
        }
        let (history, before): (Vec<(u64, u64)>, Option<i64>) = {
            let c = self.db.conn();
            let mut st = c.prepare(
                "SELECT new_plain, new_stored FROM backup_stats WHERE tenant=?1 AND source=?2 AND time < ?3
                 ORDER BY time DESC LIMIT ?4",
            )?;
            let rows = st.query_map(params![tenant, s.source, s.time, cfg.history as i64], |r| {
                Ok((r.get::<_, i64>(0)? as u64, r.get::<_, i64>(1)? as u64))
            })?;
            let h = rows.collect::<std::result::Result<_, _>>()?;
            let before = c.query_row(
                "SELECT MAX(time) FROM snapshots WHERE tenant=?1 AND source=?2 AND time < ?3",
                params![tenant, s.source, s.time],
                |r| r.get(0),
            )?;
            (h, before)
        };
        let Some(f) = check(&cfg, &history, s.new_plain, s.new_stored) else {
            return Ok(());
        };
        let what = match f {
            Finding::Volume { median, limit } => format!(
                "{} new data, limit {} ({}× the median {} of the last {} runs)",
                human(s.new_plain),
                human(limit as u64),
                cfg.factor,
                human(median as u64),
                history.len()
            ),
            Finding::Entropy { ratio, median } => format!(
                "{} new data that does not compress ({ratio:.2}, usually {median:.2}): possibly encrypted",
                human(s.new_plain)
            ),
        };
        let last = match before {
            Some(t) => format!("last snapshot before: {}/{t}", s.source),
            None => "no earlier snapshot is kept".into(),
        };
        self.raise(
            "critical",
            "anomaly",
            &format!("anomaly:{tenant}/{}", s.source),
            &format!(
                "change-rate anomaly on {tenant}/{}: snapshot {}: {what}; {last}",
                s.source, s.time
            ),
            Some(tenant),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const G: u64 = 1 << 30;

    #[test]
    fn median_odd_even_empty() {
        assert_eq!(median(vec![3.0, 1.0, 2.0]), Some(2.0));
        assert_eq!(median(vec![4.0, 1.0, 3.0, 2.0]), Some(2.5));
        assert_eq!(median(vec![]), None);
    }

    #[test]
    fn volume_rule_with_floor_and_history() {
        let cfg = Config::default();
        let h = vec![(2 * G, G); 5];
        // 3 × 2 GiB = 6 GiB
        assert_eq!(check(&cfg, &h, 6 * G, 3 * G), None);
        assert!(matches!(check(&cfg, &h, 7 * G, 3 * G), Some(Finding::Volume { .. })));
        // too little history
        assert_eq!(check(&cfg, &h[..4], 70 * G, 30 * G), None);
        // small sources: the 1 GiB floor applies
        let small = vec![(10 << 20, 5 << 20); 6];
        assert_eq!(check(&cfg, &small, 900 << 20, 450 << 20), None);
        assert!(check(&cfg, &small, 2 * G, G).is_some());
        let off = Config {
            enabled: false,
            ..Config::default()
        };
        assert_eq!(check(&off, &h, 70 * G, 30 * G), None);
    }

    #[test]
    fn compression_rule() {
        let cfg = Config::default();
        // usually compresses 2:1
        let h = vec![(G, G / 2); 5];
        // same volume, but incompressible: entropy finding
        assert!(matches!(check(&cfg, &h, G, G), Some(Finding::Entropy { .. })));
        // too small to matter (≤ floor / 4)
        assert_eq!(check(&cfg, &h, G / 8, G / 8), None);
        // compresses fine
        assert_eq!(check(&cfg, &h, G, G / 2), None);
        // a source that never compressed (media files): no finding
        let media = vec![(G, G); 5];
        assert_eq!(check(&cfg, &media, G, G), None);
    }

    #[test]
    fn human_sizes() {
        assert_eq!(human(512), "512 B");
        assert_eq!(human(3 * G / 2), "1.5 GiB");
    }
}
