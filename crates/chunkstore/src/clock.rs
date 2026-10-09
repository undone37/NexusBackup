//! Compliance clock: the only time source for retention locks.
//!
//! Advances with the monotonic clock and only slews *forward* toward system
//! time at a bounded rate, so `date -s` or a rogue NTP server cannot expire
//! locks early. Backward system-time jumps are ignored (clock never goes back).
//! After downtime the clock lags real time and catches up slowly; that only
//! makes locks last longer, which is the safe direction.

use std::fs;
use std::io;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

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
