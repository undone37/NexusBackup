//! Fleecing space guard (Phase 18, docs/pve-connector.md "Fleecing space guard").
//!
//! A VM backup writes the old content of every block the guest overwrites into a
//! fleecing image on the node's fleecing storage (usually the LVM-thin pool
//! `local-lvm`). A full thin pool pauses every VM on it. So before each VM and
//! every [`Guard::interval_secs`] while it runs, the node's storage status is read
//! (`GET /nodes/{node}/storage/{storage}/status`; for LVM-thin also the pool's
//! metadata use from `/nodes/{node}/disks/lvmthin`, if the token may read it):
//!
//! - **low** (free below `min_free_pct` % *and* below `min_free_gib` GiB, i.e.
//!   whichever is smaller; or metadata free below `min_free_pct` %): the guest is
//!   skipped (fails; the group's retry policy applies);
//! - **critical** (free below `cancel_free_pct` %): a running backup is cancelled
//!   (vzdump task stopped, as a cancelled job is).
//!
//! Each check prints `fleecing-space {json}` (node, storage, state, free, total,
//! pct); the scheduler raises / resolves the alert `fleecing_space` from it.
//! A storage whose status cannot be read is not guarded (a note is printed).

use crate::api::Api;
use anyhow::{bail, Context, Result};
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

/// Thresholds (PVE source `fleecing_guard`; defaults when absent).
#[derive(Deserialize, Clone, Copy, Debug, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct Guard {
    pub min_free_pct: f64,
    pub min_free_gib: f64,
    pub cancel_free_pct: f64,
    pub interval_secs: u64,
}

impl Default for Guard {
    fn default() -> Self {
        Guard {
            min_free_pct: 15.0,
            min_free_gib: 20.0,
            cancel_free_pct: 5.0,
            interval_secs: 30,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Level {
    Ok,
    Low,
    Critical,
}

impl Level {
    pub fn name(self) -> &'static str {
        match self {
            Level::Ok => "ok",
            Level::Low => "low",
            Level::Critical => "critical",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Space {
    pub total: u64,
    pub avail: u64,
    /// LVM-thin metadata free %, when known
    pub meta_free_pct: Option<f64>,
}

impl Space {
    pub fn free_pct(&self) -> f64 {
        if self.total == 0 {
            return 0.0;
        }
        100.0 * self.avail as f64 / self.total as f64
    }

    /// From `/nodes/{node}/storage/{storage}/status` (`total`, `avail` in bytes).
    pub fn from_status(v: &Value) -> Result<Space> {
        if v["active"].as_u64() == Some(0) {
            bail!("storage is not active on this node");
        }
        let n = |k: &str| v[k].as_u64().with_context(|| format!("storage status without {k}"));
        Ok(Space {
            total: n("total")?,
            avail: n("avail")?,
            meta_free_pct: None,
        })
    }
}

/// Metadata free % of thin pool `pool` in VG `vg` from `/nodes/{node}/disks/lvmthin`
/// (`[{lv, vg, metadata_size, metadata_used, …}]`).
pub fn meta_free_pct(list: &Value, vg: &str, pool: &str) -> Option<f64> {
    let p = list
        .as_array()?
        .iter()
        .find(|p| p["lv"].as_str() == Some(pool) && p["vg"].as_str() == Some(vg))?;
    let (size, used) = (p["metadata_size"].as_u64()?, p["metadata_used"].as_u64()?);
    (size > 0).then(|| 100.0 * size.saturating_sub(used) as f64 / size as f64)
}

impl Guard {
    pub fn level(&self, s: &Space) -> Level {
        let pct = s.free_pct();
        let meta = s.meta_free_pct.unwrap_or(100.0);
        if pct < self.cancel_free_pct || meta < self.cancel_free_pct {
            Level::Critical
        } else if (pct < self.min_free_pct && (s.avail as f64) < self.min_free_gib * GIB) || meta < self.min_free_pct {
            Level::Low
        } else {
            Level::Ok
        }
    }

    pub fn describe(&self, s: &Space) -> String {
        let mut d = format!("{:.1} GiB ({:.0} %) free", s.avail as f64 / GIB, s.free_pct());
        if let Some(m) = s.meta_free_pct {
            d.push_str(&format!(", metadata {m:.0} % free"));
        }
        d
    }

    /// Polls `probe` every `interval` until `stop`; on [`Level::Critical`] calls
    /// `cancel` once and returns the reason. Probe errors are skipped.
    pub fn watch(
        &self,
        interval: Duration,
        stop: &AtomicBool,
        probe: impl Fn() -> Result<(Space, Level)>,
        cancel: impl FnOnce(),
    ) -> Option<String> {
        let mut next = Instant::now() + interval;
        while !stop.load(Ordering::SeqCst) {
            if Instant::now() < next {
                std::thread::sleep(Duration::from_millis(200).min(interval));
                continue;
            }
            next = Instant::now() + interval;
            if let Ok((s, Level::Critical)) = probe() {
                cancel();
                return Some(format!(
                    "{}, below the critical level ({} %): backup cancelled",
                    self.describe(&s),
                    self.cancel_free_pct
                ));
            }
        }
        None
    }
}

const GIB: f64 = (1u64 << 30) as f64;

/// The `fleecing-space` line for the scheduler.
pub fn line(node: &str, storage: &str, s: &Space, level: Level) -> String {
    format!(
        "fleecing-space {}",
        json!({"node": node, "storage": storage, "state": level.name(), "free": s.avail, "total": s.total,
               "free_pct": (s.free_pct() * 10.0).round() / 10.0, "meta_free_pct": s.meta_free_pct})
    )
}

/// Reads the fleecing storage's space on `node` (and the thin pool's metadata, best effort).
pub fn space(api: &Api, node: &str, storage: &str) -> Result<Space> {
    let st = api.get(&format!("/nodes/{node}/storage/{storage}/status"))?;
    let mut s = Space::from_status(&st)?;
    if st["type"].as_str() == Some("lvmthin") {
        let meta = api.get(&format!("/storage/{storage}")).ok().and_then(|cfg| {
            let (vg, pool) = (cfg["vgname"].as_str()?.to_owned(), cfg["thinpool"].as_str()?.to_owned());
            meta_free_pct(&api.get(&format!("/nodes/{node}/disks/lvmthin")).ok()?, &vg, &pool)
        });
        s.meta_free_pct = meta;
    }
    Ok(s)
}

pub fn report(node: &str, storage: &str, s: &Space, level: Level) {
    println!("{}", line(node, storage, s, level));
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    const G: u64 = 1 << 30;

    fn sp(total_gib: u64, avail_gib: f64) -> Space {
        Space {
            total: total_gib * G,
            avail: (avail_gib * G as f64) as u64,
            meta_free_pct: None,
        }
    }

    /// PVE's answer for an LVM-thin storage (fake response as the API returns it).
    #[test]
    fn parses_pve_responses() {
        let st = json!({"active": 1, "avail": 21474836480u64, "content": "images,rootdir", "enabled": 1,
                        "shared": 0, "total": 107374182400u64, "type": "lvmthin", "used": 85899345920u64});
        let s = Space::from_status(&st).unwrap();
        assert_eq!((s.total, s.avail), (100 * G, 20 * G));
        assert!((s.free_pct() - 20.0).abs() < 1e-9);
        assert!(Space::from_status(&json!({"active": 0, "total": 1, "avail": 1})).is_err());
        assert!(Space::from_status(&json!({"active": 1})).is_err());
        let thin = json!([
            {"lv": "data", "vg": "pve", "lv_size": 107374182400u64, "used": 85899345920u64,
             "metadata_size": 1073741824u64, "metadata_used": 1020054732u64},
            {"lv": "data", "vg": "other", "metadata_size": 100, "metadata_used": 0}
        ]);
        let m = meta_free_pct(&thin, "pve", "data").unwrap();
        assert!((m - 5.0).abs() < 0.01, "{m}");
        assert_eq!(meta_free_pct(&thin, "pve", "nope"), None);
        assert_eq!(meta_free_pct(&json!({"error": 1}), "pve", "data"), None);
    }

    #[test]
    fn levels() {
        let g = Guard::default();
        assert_eq!(g.level(&sp(100, 30.0)), Level::Ok);
        assert_eq!(g.level(&sp(100, 14.0)), Level::Low, "14 % and 14 GiB");
        assert_eq!(
            g.level(&sp(2000, 100.0)),
            Level::Ok,
            "5 % but 100 GiB: the smaller threshold counts"
        );
        assert_eq!(g.level(&sp(50, 15.0)), Level::Ok, "30 % of a small pool");
        assert_eq!(g.level(&sp(1000, 40.0)), Level::Critical, "4 %");
        let mut meta = sp(100, 50.0);
        meta.meta_free_pct = Some(10.0);
        assert_eq!(g.level(&meta), Level::Low, "thin pool metadata nearly full");
        meta.meta_free_pct = Some(3.0);
        assert_eq!(g.level(&meta), Level::Critical);
        assert_eq!(
            g.level(&Space {
                total: 0,
                avail: 0,
                meta_free_pct: None
            }),
            Level::Critical
        );
        let custom: Guard = serde_json::from_value(json!({"min_free_pct": 30, "cancel_free_pct": 10})).unwrap();
        assert_eq!((custom.min_free_gib, custom.interval_secs), (20.0, 30));
        assert_eq!(custom.level(&sp(100, 15.0)), Level::Low);
        assert!(serde_json::from_value::<Guard>(json!({"bogus": 1})).is_err());
    }

    #[test]
    fn line_format() {
        let l = line("pve1", "local-lvm", &sp(100, 4.0), Level::Critical);
        let v: Value = serde_json::from_str(l.strip_prefix("fleecing-space ").unwrap()).unwrap();
        assert_eq!(v["state"], "critical");
        assert_eq!(v["free_pct"], 4.0);
        assert_eq!(
            (v["node"].as_str(), v["storage"].as_str()),
            (Some("pve1"), Some("local-lvm"))
        );
    }

    /// The watcher cancels once on the first critical reading (fake probe answers).
    #[test]
    fn watch_cancels_on_critical() {
        let g = Guard::default();
        let calls = AtomicUsize::new(0);
        let readings = [sp(100, 30.0), sp(100, 10.0), sp(100, 3.0), sp(100, 50.0)];
        let stop = AtomicBool::new(false);
        let cancelled = AtomicUsize::new(0);
        let why = g.watch(
            Duration::from_millis(10),
            &stop,
            || {
                let s = readings[calls.fetch_add(1, Ordering::SeqCst)];
                Ok((s, g.level(&s)))
            },
            || {
                cancelled.fetch_add(1, Ordering::SeqCst);
            },
        );
        assert_eq!(calls.load(Ordering::SeqCst), 3);
        assert_eq!(cancelled.load(Ordering::SeqCst), 1);
        assert!(why
            .unwrap()
            .contains("3.0 GiB (3 %) free, below the critical level (5 %)"));
        // stopped before anything was critical: no cancel
        stop.store(true, Ordering::SeqCst);
        assert_eq!(
            g.watch(
                Duration::from_millis(1),
                &stop,
                || bail!("unused"),
                || panic!("cancelled")
            ),
            None
        );
    }
}
