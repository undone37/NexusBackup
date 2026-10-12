//! Compliance clock keeper and the `clock_skew` alert (Phase 18, ADR-011).
//!
//! The compliance clock of a store (`chunkstore::clock`) only advances while a
//! process holds it open. The scheduler keeps every tenant's clock open (one
//! shared instance per store, which the jobs' stores in this process use too)
//! and compares it with system time every tick (skew = system − compliance):
//!
//! - **jump**: the skew grew while the scheduler was running (system time moved
//!   forward, a rogue time source): warning above [`WARN_SECS`], critical above
//!   [`CRIT_SECS`];
//! - **ahead**: the compliance clock is ahead of system time (system time moved
//!   back): same thresholds;
//! - **lag after a restart**: the clock was already behind when the scheduler
//!   opened it (the appliance was off; it cannot tell a system time change while
//!   it was off from downtime): info above [`WARN_SECS`]. The clock catches up at
//!   the slew rate; meanwhile locks last longer, never shorter.
//!
//! Resolved when no tenant needs it any more. The worst skew goes to the setting
//! [`STATUS_SETTING`] once a minute for nexus-diag's check `time.compliance`
//! (it cannot read the stores).

use super::*;
use catalog::alerting;
use chunkstore::clock::ComplianceClock;

pub const WARN_SECS: i64 = 60;
pub const CRIT_SECS: i64 = 600;
pub const KEY: &str = "clock_skew";
/// `{"checked": unix, "tenant", "skew_secs": system − compliance, "jump_secs": growth while running}`
/// of the tenant that needs the most attention
pub const STATUS_SETTING: &str = "compliance_clock";

/// (alert level + 1, |skew|): which tenant's state is reported
type Rank = (u8, i64);
/// severity and message, None = fine
type Alert = Option<(&'static str, String)>;

#[derive(Default)]
pub struct Keeper {
    clocks: HashMap<String, Tracked>,
    written: i64,
}

struct Tracked {
    clock: Arc<ComplianceClock>,
    /// smallest skew seen since the scheduler opened the clock: what is left of
    /// the lag it found at start (downtime); growth above it is a jump
    floor: i64,
}

/// `90` → "1 min 30 s", `7200` → "2 h 0 min".
fn span(secs: i64) -> String {
    let s = secs.abs();
    match s {
        0..=59 => format!("{s} s"),
        60..=3599 => format!("{} min {} s", s / 60, s % 60),
        _ => format!("{} h {} min", s / 3600, s % 3600 / 60),
    }
}

fn level(secs: i64) -> Option<&'static str> {
    match secs {
        s if s > CRIT_SECS => Some("critical"),
        s if s > WARN_SECS => Some("warning"),
        _ => None,
    }
}

/// (severity, jump) for a tenant's `skew` and `floor`, None = fine.
pub fn assess(skew: i64, floor: i64) -> Option<(&'static str, i64)> {
    let jump = (skew - floor.max(0)).max(0);
    if skew < 0 {
        return level(-skew).map(|s| (s, jump));
    }
    if let Some(s) = level(jump) {
        return Some((s, jump));
    }
    (floor.min(skew) > WARN_SECS).then_some(("info", jump))
}

impl Scheduler {
    /// Keeps the tenants' compliance clocks running and raises / resolves `clock_skew`.
    pub(crate) fn check_clock(&mut self) -> Result<()> {
        let slew = (self.ctx.store_options)().clock_slew;
        // (rank, magnitude) of the worst tenant, its alert and status
        let mut worst: Option<(Rank, Alert, Value)> = None;
        for (tenant, _) in self.tenants()? {
            let root = self.cfg.store_base.join(&tenant);
            if !valid_name(&tenant) || !root.join("keycheck").exists() {
                continue;
            }
            let t = match self.clock.clocks.entry(tenant.clone()) {
                std::collections::hash_map::Entry::Occupied(o) => o.into_mut(),
                std::collections::hash_map::Entry::Vacant(v) => {
                    let clock = ComplianceClock::shared(root.join("clock"), slew)?;
                    let floor = catalog::now() - clock.now()? as i64;
                    v.insert(Tracked { clock, floor })
                }
            };
            let skew = catalog::now() - t.clock.now()? as i64;
            t.floor = t.floor.min(skew);
            let found = assess(skew, t.floor);
            let msg = found.map(|(sev, jump)| {
                let m = if skew < 0 {
                    format!(
                        "the compliance clock of tenant {tenant} is {} ahead of system time: system time was moved back \
                         (check the time sources: Diagnostics, check time.sync)",
                        span(skew)
                    )
                } else if sev == "info" {
                    format!(
                        "the compliance clock of tenant {tenant} is {} behind system time since the last restart \
                         (the appliance was off, or system time was changed while it was off); it catches up at {} % \
                         of elapsed time, retention locks last longer meanwhile",
                        span(skew),
                        slew * 100.0
                    )
                } else {
                    format!(
                        "system time jumped {} ahead of the compliance clock of tenant {tenant} while the appliance was \
                         running (time changed by hand or a wrong time source); retention locks are unaffected, the \
                         clock catches up at {} % of elapsed time (check the time sources: Diagnostics, check time.sync)",
                        span(jump),
                        slew * 100.0
                    )
                };
                (sev, m)
            });
            let rank = (found.map_or(0, |(s, _)| alerting::rank(s) + 1), skew.abs());
            if worst.as_ref().is_none_or(|(r, ..)| rank > *r) {
                let st = json!({"tenant": tenant, "skew_secs": skew, "jump_secs": found.map_or(0, |f| f.1)});
                worst = Some((rank, msg, st));
            }
        }
        let now = catalog::now();
        let Some((_, msg, mut st)) = worst else {
            return self.resolve(KEY);
        };
        if now - self.clock.written >= 60 {
            st["checked"] = json!(now);
            catalog::set_setting(&self.db.conn(), STATUS_SETTING, &st.to_string())?;
            self.clock.written = now;
        }
        let Some((sev, msg)) = msg else {
            return self.resolve(KEY);
        };
        let open: Option<String> = self
            .db
            .conn()
            .query_row(
                "SELECT severity FROM alerts WHERE key = ?1 AND resolved_at IS NULL",
                [KEY],
                |r| r.get(0),
            )
            .optional()?;
        match open {
            // still open at the same or a higher level: refresh the text, do not count a repeat per tick
            Some(old) if alerting::rank(sev) <= alerting::rank(&old) => {
                self.db.conn().execute(
                    "UPDATE alerts SET message = ?2, last_ts = ?3 WHERE key = ?1 AND resolved_at IS NULL",
                    params![KEY, msg, now],
                )?;
                Ok(())
            }
            _ => self.raise(sev, KEY, KEY, &msg, None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assessment() {
        assert_eq!(assess(0, 0), None);
        assert_eq!(assess(60, 0), None);
        assert_eq!(assess(61, 0), Some(("warning", 61)), "jump while running");
        assert_eq!(assess(700, 50), Some(("critical", 650)));
        assert_eq!(assess(3600, 3600), Some(("info", 0)), "lag found at start");
        assert_eq!(assess(3000, 2000), Some(("critical", 1000)), "jump on top of a lag");
        assert_eq!(assess(-61, -61), Some(("warning", 0)), "ahead");
        assert_eq!(assess(-700, -700), Some(("critical", 0)));
        assert_eq!(assess(0, -300), None, "back to normal after a backward move");
        assert_eq!(span(90), "1 min 30 s");
        assert_eq!(span(-7260), "2 h 1 min");
    }
}
