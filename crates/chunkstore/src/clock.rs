//! Compliance clock: the only time source for retention locks.
//!
//! Advances with the monotonic clock and only slews *forward* toward system
//! time at a bounded rate, so `date -s` or a rogue NTP server cannot expire
//! locks early. Backward system-time jumps are ignored (clock never goes back).
//! After downtime the clock lags real time and catches up slowly; that only
//! makes locks last longer, which is the safe direction.
//!
//! The clock only advances while a process holds it, so every opener of the
//! same state file in one process shares one instance ([`ComplianceClock::shared`]),
//! and the scheduler keeps each tenant's clock open (`scheduler/src/clock.rs`):
//! time between two short-lived openers is not lost.

use std::fs;
use std::io;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, Weak};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

/// Default forward slew: 0.1 % of elapsed time (≈ 20 minutes over a 14-day
/// lock; ADR-011). Was 1 % before Phase 18.
pub const DEFAULT_SLEW: f64 = 0.001;

/// Clocks open in this process, by state file.
static OPEN: Mutex<Vec<(PathBuf, Weak<ComplianceClock>)>> = Mutex::new(Vec::new());

/// Pure step: `prev` compliance time, `elapsed` monotonic seconds since then,
/// `sys` current system time. `slew` = max forward correction per elapsed second.
pub fn step(prev: f64, elapsed: f64, sys: f64, slew: f64) -> f64 {
    let t = prev + elapsed;
    if sys > t {
        t + (sys - t).min(elapsed * slew)
    } else {
        t
    }
}

/// Tamper-resistant time source of one store (state file `<root>/clock`); see the module doc.
/// Open it with [`ComplianceClock::shared`] so one process keeps one instance per file.
pub struct ComplianceClock {
    path: PathBuf,
    slew: f64,
    state: Mutex<State>,
}

struct State {
    t: f64,
    at: Instant,
    persisted: f64,
}

fn sys_now() -> f64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs_f64()
}

impl ComplianceClock {
    /// First open trusts system time once (installation); afterwards only the
    /// persisted value counts.
    // ponytail: the state file is protected by file permissions/SELinux only;
    // TPM NV monotonic counter is the upgrade if root-level tamper matters.
    pub fn open(path: PathBuf, slew: f64) -> io::Result<Self> {
        let t = match fs::read_to_string(&path) {
            // `inf` / `NaN` parse as f64 but would expire every lock (or never advance)
            Ok(s) => s
                .trim()
                .parse::<f64>()
                .ok()
                .filter(|t| t.is_finite() && *t >= 0.0)
                .ok_or_else(|| crate::crypto::invalid("corrupt clock file"))?,
            Err(e) if e.kind() == io::ErrorKind::NotFound => sys_now(),
            Err(e) => return Err(e),
        };
        let clock = ComplianceClock {
            path,
            slew,
            state: Mutex::new(State {
                t,
                at: Instant::now(),
                persisted: f64::MIN,
            }),
        };
        clock.now()?;
        Ok(clock)
    }

    /// The process-wide instance for `path` (opened if nobody holds it), so
    /// stores and the scheduler's clock keeper advance one clock together.
    /// The first opener's `slew` counts.
    pub fn shared(path: PathBuf, slew: f64) -> io::Result<Arc<Self>> {
        // the same file under another spelling (relative path, symlink) is the same clock
        let key = match (path.parent().map(fs::canonicalize), path.file_name()) {
            (Some(Ok(dir)), Some(name)) => dir.join(name),
            _ => path.clone(),
        };
        let mut open = OPEN.lock().unwrap();
        open.retain(|(_, w)| w.strong_count() > 0);
        if let Some(c) = open.iter().find(|(p, _)| *p == key).and_then(|(_, w)| w.upgrade()) {
            return Ok(c);
        }
        let c = Arc::new(Self::open(path, slew)?);
        open.push((key, Arc::downgrade(&c)));
        Ok(c)
    }

    /// Current compliance time in unix seconds. Persists at most once a minute.
    pub fn now(&self) -> io::Result<u64> {
        let mut s = self.state.lock().unwrap();
        let elapsed = s.at.elapsed().as_secs_f64();
        s.t = step(s.t, elapsed, sys_now(), self.slew);
        s.at = Instant::now();
        if s.t - s.persisted >= 60.0 {
            crate::store::write_atomic(&self.path, format!("{}\n", s.t).as_bytes())?;
            s.persisted = s.t;
        }
        Ok(s.t as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forward_jump_is_slewed() {
        // attacker sets system time +1 year; after 1 h only 1 % of 1 h is accepted
        let t = step(1000.0, 3600.0, 1000.0 + 365.0 * 86400.0, 0.01);
        assert_eq!(t, 1000.0 + 3600.0 + 36.0);
    }

    #[test]
    fn default_slew_caps_a_year_jump_at_twenty_minutes_per_two_weeks() {
        let two_weeks = 14.0 * 86400.0;
        let t = step(0.0, two_weeks, 1e9, DEFAULT_SLEW);
        assert!((t - two_weeks - 1209.6).abs() < 1e-6, "{t}");
    }

    #[test]
    fn shared_per_file_and_reopened_after_drop() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("clock");
        let a = ComplianceClock::shared(p.clone(), DEFAULT_SLEW).unwrap();
        let b = ComplianceClock::shared(d.path().join(".").join("clock"), DEFAULT_SLEW).unwrap();
        assert!(Arc::ptr_eq(&a, &b), "one instance per file");
        let other = ComplianceClock::shared(d.path().join("clock2"), DEFAULT_SLEW).unwrap();
        assert!(!Arc::ptr_eq(&a, &other));
        let t = a.now().unwrap();
        drop((a, b));
        fs::write(&p, format!("{}\n", t - 3600)).unwrap();
        let c = ComplianceClock::shared(p, DEFAULT_SLEW).unwrap();
        assert!(c.now().unwrap() < t, "nobody held it: the file counts again");
    }

    #[test]
    fn backward_jump_ignored_and_small_drift_tracked() {
        assert_eq!(step(1000.0, 10.0, 0.0, 0.01), 1010.0);
        assert_eq!(step(1000.0, 100.0, 1100.5, 0.01), 1100.5);
    }

    /// Regression (security review): `inf` in the clock file expired every lock.
    #[test]
    fn non_finite_clock_file_is_corrupt() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("clock");
        for bad in ["inf", "+infinity", "NaN", "-5", "1e400"] {
            fs::write(&p, bad).unwrap();
            assert!(ComplianceClock::open(p.clone(), 0.01).is_err(), "{bad}");
        }
    }

    #[test]
    fn persists_and_survives_reopen() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("clock");
        let c = ComplianceClock::open(p.clone(), 0.01).unwrap();
        let t1 = c.now().unwrap();
        drop(c);
        fs::write(&p, format!("{}\n", t1 - 86400)).unwrap(); // simulate reboot 1 day ago value
        let c = ComplianceClock::open(p, 0.01).unwrap();
        assert!(c.now().unwrap() < t1, "reopened clock does not jump to system time");
    }
}
