//! Change-rate anomaly alert (Phase 13e, docs/storage-accounting.md): after
//! each backup's stats are stored, its new data is compared with the source's
//! own history. Critical `anomaly` alert when
//! - `new_plain` > max(factor × median `new_plain` of the last N runs, floor), or
//! - the new data hardly compresses (< 1.05) while the source's median
//!   compression is > 1.3 and `new_plain` > floor / 4 (an entropy proxy:
//!   encrypted files do not compress).
//!
//! Phase 30 (docs/ransomware-signals.md "Duration and dedup rate") adds two
//! signals with the same median-of-history model:
//! - **dedup rate**: the share of the data read that did not deduplicate
//!   (`new_plain / read`) above max(factor × its median, a floor), when at least
//!   floor / 4 bytes were read (critical): "same size, nothing deduplicates";
//! - **duration**: the backup took longer than max(factor × the median
//!   duration, median + a margin) (warning; slow storage or a busy network
//!   look the same, so it is critical only together with another signal).
//!
//! The per-source sensitivity (catalog::anomaly, `low` | `medium` | `high`)
//! picks the factors ([`Levels`]); `medium` keeps the setting's `factor` for the
//! change rate. All need at least `MIN_HISTORY` earlier runs (with a duration,
//! for the duration rule). Setting `anomaly`:
//! `{enabled, factor, history, floor_bytes, ransom_notes}` (the last: extra
//! ransom-note name globs for the file-level signals, `changes.rs`). A finding
//! also flags the snapshot (`snapshots.anomaly`, Phase 21a); the alert names
//! the newest clean snapshot before it.

use crate::stats::Stats;
use crate::Scheduler;
use anyhow::Result;
use catalog::anomaly::Sensitivity;
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
    /// extra ransom-note file name globs (changes.rs adds them to its own list)
    pub ransom_notes: Vec<String>,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            enabled: true,
            factor: 3.0,
            history: 14,
            floor_bytes: 1 << 30,
            ransom_notes: Vec::new(),
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

/// One earlier or current run of a source (a `backup_stats` row).
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct Run {
    pub read: u64,
    pub new_plain: u64,
    pub new_stored: u64,
    /// the backup's duration (`nexus-stats` `secs`); `None` for older rows
    pub secs: Option<u64>,
}

/// Thresholds of one sensitivity level.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Levels {
    /// multiplies the setting's change-rate `factor` (at least 1.5 after it)
    pub volume: f64,
    /// duration limit: max(`duration` × median, median + `duration_margin` s)
    pub duration: f64,
    pub duration_margin: u64,
    /// dedup-rate limit: max(`dedup` × median, `dedup_floor`)
    pub dedup: f64,
    pub dedup_floor: f64,
}

pub fn levels(s: Sensitivity) -> Levels {
    match s {
        Sensitivity::Low => Levels {
            volume: 1.5,
            duration: 4.0,
            duration_margin: 1800,
            dedup: 4.0,
            dedup_floor: 0.9,
        },
        Sensitivity::Medium => Levels {
            volume: 1.0,
            duration: 3.0,
            duration_margin: 900,
            dedup: 3.0,
            dedup_floor: 0.75,
        },
        Sensitivity::High => Levels {
            volume: 2.0 / 3.0,
            duration: 2.0,
            duration_margin: 300,
            dedup: 2.0,
            dedup_floor: 0.5,
        },
    }
}

#[derive(Debug, PartialEq)]
pub enum Finding {
    /// (median new_plain, limit)
    Volume { median: f64, limit: f64 },
    /// (compression of the new data, median compression)
    Entropy { ratio: f64, median: f64 },
    /// share of the data read that did not deduplicate, its median, the limit
    Dedup { ratio: f64, median: f64, limit: f64 },
    /// duration in seconds, its median, the limit
    Duration { secs: u64, median: f64, limit: f64 },
}

impl Finding {
    /// The duration rule alone is a warning, every other finding critical.
    pub fn critical(&self) -> bool {
        !matches!(self, Finding::Duration { .. })
    }
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

/// Share of the data read that was new (did not deduplicate); `None` when
/// nothing was read.
fn new_share(r: &Run) -> Option<f64> {
    (r.read > 0).then(|| (r.new_plain as f64 / r.read as f64).min(1.0))
}

/// The change-rate rules (volume, else entropy).
fn change_rate(cfg: &Config, lv: &Levels, history: &[Run], cur: &Run) -> Option<Finding> {
    if history.len() < MIN_HISTORY {
        return None;
    }
    let med = median(history.iter().map(|h| h.new_plain as f64).collect())?;
    let factor = (cfg.factor * lv.volume).max(1.5);
    let limit = (factor * med).max(cfg.floor_bytes as f64);
    if cur.new_plain as f64 > limit {
        return Some(Finding::Volume { median: med, limit });
    }
    let r = ratio(cur.new_plain, cur.new_stored)?;
    let usual = median(
        history
            .iter()
            .filter_map(|h| ratio(h.new_plain, h.new_stored))
            .collect(),
    )?;
    (r < LOW_COMPRESSION && usual > USUAL_COMPRESSION && cur.new_plain > cfg.floor_bytes / 4).then_some(
        Finding::Entropy {
            ratio: r,
            median: usual,
        },
    )
}

fn dedup(cfg: &Config, lv: &Levels, history: &[Run], cur: &Run) -> Option<Finding> {
    if cur.read < cfg.floor_bytes / 4 {
        return None;
    }
    let shares: Vec<f64> = history.iter().filter_map(new_share).collect();
    if shares.len() < MIN_HISTORY {
        return None;
    }
    let med = median(shares)?;
    let limit = (lv.dedup * med).max(lv.dedup_floor);
    let r = new_share(cur)?;
    (r > limit).then_some(Finding::Dedup {
        ratio: r,
        median: med,
        limit,
    })
}

fn duration(lv: &Levels, history: &[Run], cur: &Run) -> Option<Finding> {
    let secs = cur.secs?;
    let past: Vec<f64> = history.iter().filter_map(|h| h.secs).map(|s| s as f64).collect();
    if past.len() < MIN_HISTORY {
        return None;
    }
    let med = median(past)?;
    let limit = (lv.duration * med).max(med + lv.duration_margin as f64);
    (secs as f64 > limit).then_some(Finding::Duration {
        secs,
        median: med,
        limit,
    })
}

/// `history`: earlier runs, newest first. Every rule that fires, change rate
/// first.
pub fn check(cfg: &Config, sens: Sensitivity, history: &[Run], cur: &Run) -> Vec<Finding> {
    if !cfg.enabled {
        return Vec::new();
    }
    let lv = levels(sens);
    [
        change_rate(cfg, &lv, history, cur),
        dedup(cfg, &lv, history, cur),
        duration(&lv, history, cur),
    ]
    .into_iter()
    .flatten()
    .collect()
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

/// `1 h 05 min` / `12 min 30 s` / `45 s`.
pub fn human_secs(s: u64) -> String {
    match s {
        0..60 => format!("{s} s"),
        60..3600 => format!("{} min {:02} s", s / 60, s % 60),
        _ => format!("{} h {:02} min", s / 3600, s % 3600 / 60),
    }
}

impl Scheduler {
    pub(crate) fn check_anomaly(&self, tenant: &str, s: &Stats) -> Result<()> {
        let cfg = Config::load(&self.db.conn());
        if !cfg.enabled {
            return Ok(());
        }
        let (history, sens): (Vec<Run>, Sensitivity) = {
            let c = self.db.conn();
            let mut st = c.prepare(
                "SELECT read, new_plain, new_stored, secs FROM backup_stats WHERE tenant=?1 AND source=?2 AND time < ?3
                 ORDER BY time DESC LIMIT ?4",
            )?;
            let rows = st.query_map(params![tenant, s.source, s.time, cfg.history as i64], |r| {
                Ok(Run {
                    read: r.get::<_, i64>(0)? as u64,
                    new_plain: r.get::<_, i64>(1)? as u64,
                    new_stored: r.get::<_, i64>(2)? as u64,
                    secs: r.get::<_, Option<i64>>(3)?.map(|v| v as u64),
                })
            })?;
            let history = rows.collect::<std::result::Result<_, _>>()?;
            (history, catalog::anomaly::get(&c, tenant, &s.source)?)
        };
        let cur = Run {
            read: s.read,
            new_plain: s.new_plain,
            new_stored: s.new_stored,
            secs: s.secs,
        };
        let found = check(&cfg, sens, &history, &cur);
        let Some(first) = found.first() else {
            return Ok(());
        };
        let factor = (cfg.factor * levels(sens).volume).max(1.5);
        let what = found
            .iter()
            .map(|f| match f {
                Finding::Volume { median, limit } => format!(
                    "{} new data, limit {} ({}× the median {} of the last {} runs)",
                    human(s.new_plain),
                    human(*limit as u64),
                    (factor * 100.0).round() / 100.0,
                    human(*median as u64),
                    history.len()
                ),
                Finding::Entropy { ratio, median } => format!(
                    "{} new data that does not compress ({ratio:.2}, usually {median:.2}): possibly encrypted",
                    human(s.new_plain)
                ),
                Finding::Dedup { ratio, median, limit } => format!(
                    "{:.0} % of the {} read did not deduplicate (usually {:.0} %, limit {:.0} %)",
                    ratio * 100.0,
                    human(s.read),
                    median * 100.0,
                    limit * 100.0
                ),
                Finding::Duration { secs, median, limit } => format!(
                    "the backup took {} (usually {}, limit {})",
                    human_secs(*secs),
                    human_secs(*median as u64),
                    human_secs(*limit as u64)
                ),
            })
            .collect::<Vec<_>>()
            .join("; ");
        let label = match first {
            Finding::Volume { .. } | Finding::Entropy { .. } => "change-rate",
            Finding::Dedup { .. } => "dedup-rate",
            Finding::Duration { .. } => "backup-duration",
        };
        let severity = if found.iter().any(Finding::critical) {
            "critical"
        } else {
            "warning"
        };
        self.flag_snapshot(tenant, &s.source, s.time, &what)?;
        let last = self.last_clean(tenant, &s.source, s.time)?;
        let level = match sens {
            Sensitivity::Medium => String::new(),
            x => format!(" (sensitivity {})", x.as_str()),
        };
        self.raise(
            severity,
            "anomaly",
            &format!("anomaly:{tenant}/{}", s.source),
            &format!(
                "{label} anomaly on {tenant}/{}{level}: snapshot {}: {what}; {last}",
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

    fn run(plain: u64, stored: u64) -> Run {
        Run {
            read: plain,
            new_plain: plain,
            new_stored: stored,
            secs: None,
        }
    }

    fn one(cfg: &Config, h: &[Run], cur: Run) -> Option<Finding> {
        check(cfg, Sensitivity::Medium, h, &cur).into_iter().next()
    }

    #[test]
    fn volume_rule_with_floor_and_history() {
        let cfg = Config::default();
        let h = vec![run(2 * G, G); 5];
        // 3 × 2 GiB = 6 GiB
        assert_eq!(one(&cfg, &h, run(6 * G, 3 * G)), None);
        assert!(matches!(one(&cfg, &h, run(7 * G, 3 * G)), Some(Finding::Volume { .. })));
        // too little history
        assert_eq!(one(&cfg, &h[..4], run(70 * G, 30 * G)), None);
        // small sources: the 1 GiB floor applies
        let small = vec![run(10 << 20, 5 << 20); 6];
        assert_eq!(one(&cfg, &small, run(900 << 20, 450 << 20)), None);
        assert!(one(&cfg, &small, run(2 * G, G)).is_some());
        let off = Config {
            enabled: false,
            ..Config::default()
        };
        assert_eq!(one(&off, &h, run(70 * G, 30 * G)), None);
        // sensitivity scales the factor: high 2×, low 4.5×
        assert!(check(&cfg, Sensitivity::High, &h, &run(4 * G, 2 * G)).is_empty());
        assert!(!check(&cfg, Sensitivity::High, &h, &run(9 * G / 2, 3 * G)).is_empty());
        assert!(check(&cfg, Sensitivity::Low, &h, &run(9 * G, 5 * G)).is_empty());
        assert!(!check(&cfg, Sensitivity::Low, &h, &run(10 * G, 5 * G)).is_empty());
    }

    #[test]
    fn compression_rule() {
        let cfg = Config::default();
        // usually compresses 2:1
        let h = vec![run(G, G / 2); 5];
        // same volume, but incompressible: entropy finding
        assert!(matches!(one(&cfg, &h, run(G, G)), Some(Finding::Entropy { .. })));
        // too small to matter (≤ floor / 4)
        assert_eq!(one(&cfg, &h, run(G / 8, G / 8)), None);
        // compresses fine
        assert_eq!(one(&cfg, &h, run(G, G / 2)), None);
        // a source that never compressed (media files): no finding
        let media = vec![run(G, G); 5];
        assert_eq!(one(&cfg, &media, run(G, G)), None);
    }

    /// Phase 30: "same size, nothing deduplicates": an agent that reads 4 GiB
    /// of changed files of which usually 5 % is new data.
    #[test]
    fn dedup_rule() {
        let cfg = Config::default();
        let usual = Run {
            read: 4 * G,
            new_plain: G / 5,
            new_stored: G / 10,
            secs: None,
        };
        let h = vec![usual; 6];
        assert!(check(&cfg, Sensitivity::Medium, &h, &usual).is_empty());
        // everything read is new
        let enc = Run {
            new_plain: 4 * G,
            new_stored: 4 * G,
            ..usual
        };
        let f = check(&cfg, Sensitivity::Medium, &h, &enc);
        assert!(f.iter().any(|f| matches!(f, Finding::Dedup { .. })), "{f:?}");
        assert!(f.iter().all(Finding::critical));
        // 70 % new: over the high floor (50 %), under the medium floor (75 %)
        let part = Run {
            read: 4 * G,
            new_plain: 4 * G * 7 / 10,
            new_stored: 4 * G * 7 / 20,
            secs: None,
        };
        let has = |s| {
            check(&cfg, s, &h, &part)
                .iter()
                .any(|f| matches!(f, Finding::Dedup { .. }))
        };
        assert!(has(Sensitivity::High));
        assert!(!has(Sensitivity::Medium));
        // a VM whose dirty regions are always new: the floor cannot be passed (share <= 100 %)
        let vm = vec![run(2 * G, G); 6];
        assert!(!check(&cfg, Sensitivity::High, &vm, &run(2 * G, G))
            .iter()
            .any(|f| matches!(f, Finding::Dedup { .. })));
        // too little read to matter
        let small = Run {
            read: G / 8,
            new_plain: G / 8,
            new_stored: G / 16,
            secs: None,
        };
        assert!(check(&cfg, Sensitivity::High, &h, &small).is_empty());
    }

    #[test]
    fn duration_rule() {
        let cfg = Config::default();
        let t = |secs: Option<u64>| Run {
            secs,
            ..run(1 << 20, 1 << 19)
        };
        let h = vec![t(Some(600)); 5];
        // medium: max(3 × 10 min, 10 min + 15 min) = 30 min
        assert!(check(&cfg, Sensitivity::Medium, &h, &t(Some(1800))).is_empty());
        let f = check(&cfg, Sensitivity::Medium, &h, &t(Some(1801)));
        assert!(matches!(f[..], [Finding::Duration { secs: 1801, .. }]), "{f:?}");
        assert!(!f[0].critical(), "alone a warning");
        // high: max(2 × 10 min, 10 min + 5 min) = 20 min; low: max(40 min, 40 min)
        assert!(!check(&cfg, Sensitivity::High, &h, &t(Some(1300))).is_empty());
        assert!(check(&cfg, Sensitivity::Low, &h, &t(Some(2400))).is_empty());
        // short backups: the margin keeps 30 s -> 3 min quiet
        let quick = vec![t(Some(30)); 5];
        assert!(check(&cfg, Sensitivity::High, &quick, &t(Some(180))).is_empty());
        // older rows without a duration do not count
        let mut mixed = vec![t(None); 3];
        mixed.extend(vec![t(Some(600)); 4]);
        assert!(check(&cfg, Sensitivity::High, &mixed, &t(Some(9000))).is_empty());
        assert!(check(&cfg, Sensitivity::High, &h, &t(None)).is_empty());
    }

    #[test]
    fn human_sizes_and_durations() {
        assert_eq!(human(512), "512 B");
        assert_eq!(human(3 * G / 2), "1.5 GiB");
        assert_eq!(human_secs(45), "45 s");
        assert_eq!(human_secs(750), "12 min 30 s");
        assert_eq!(human_secs(3900), "1 h 05 min");
    }
}
