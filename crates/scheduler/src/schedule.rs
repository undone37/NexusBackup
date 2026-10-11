//! Policy schedules (`daily HH:MM`, `hourly MM`, UTC) and due computation.
//!
//! "Due" is period based: a run is due when the most recent slot at or before
//! `now` is later than the last run. After downtime this yields exactly one
//! catch-up run, not one per missed period.

use anyhow::{bail, Context, Result};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Schedule {
    Daily { hour: u32, minute: u32 },
    Hourly { minute: u32 },
}

const HOUR: i64 = 3600;
const DAY: i64 = 86400;

impl Schedule {
    pub fn parse(s: &str) -> Result<Self> {
        let parts: Vec<&str> = s.split_whitespace().collect();
        let num = |v: &str, max: u32| -> Result<u32> {
            let n: u32 = v
                .parse()
                .with_context(|| format!("bad number {v:?} in schedule {s:?}"))?;
            if n > max || v.len() != 2 {
                bail!("bad schedule {s:?}: expected two digits <= {max}");
            }
            Ok(n)
        };
        match parts.as_slice() {
            ["daily", hm] => {
                let (h, m) = hm.split_once(':').with_context(|| format!("bad schedule {s:?}"))?;
                Ok(Schedule::Daily {
                    hour: num(h, 23)?,
                    minute: num(m, 59)?,
                })
            }
            ["hourly", m] => Ok(Schedule::Hourly { minute: num(m, 59)? }),
            _ => bail!("bad schedule {s:?}: expected `daily HH:MM` or `hourly MM`"),
        }
    }

    /// Latest slot (unix seconds, UTC) at or before `now`.
    pub fn last_slot(self, now: i64) -> i64 {
        let (period, offset) = match self {
            Schedule::Daily { hour, minute } => (DAY, hour as i64 * HOUR + minute as i64 * 60),
            Schedule::Hourly { minute } => (HOUR, minute as i64 * 60),
        };
        let start = now.div_euclid(period) * period + offset;
        if start <= now {
            start
        } else {
            start - period
        }
    }

    /// Due iff a slot passed since the last run (`last_run` = when the last
    /// scheduled job was queued, or when the scheduler first saw the item).
    pub fn due(self, last_run: i64, now: i64) -> bool {
        self.last_slot(now) > last_run
    }
}

/// `YYYY-MM-DD` (UTC) of a unix time (civil-from-days, H. Hinnant).
pub fn day(ts: i64) -> String {
    let z = ts.div_euclid(DAY) + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02}")
}

#[cfg(test)]
mod tests {
    use super::*;

    const D: i64 = 20_000 * DAY; // 2024-10-04 00:00 UTC

    #[test]
    fn parse() {
        assert_eq!(
            Schedule::parse("daily 22:05").unwrap(),
            Schedule::Daily { hour: 22, minute: 5 }
        );
        assert_eq!(Schedule::parse(" hourly  07 ").unwrap(), Schedule::Hourly { minute: 7 });
        for bad in [
            "daily 24:00",
            "daily 2:00",
            "daily 22",
            "hourly 60",
            "weekly 01:00",
            "",
            "daily 22:5",
            "hourly -1",
        ] {
            assert!(Schedule::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn last_slot_daily() {
        let s = Schedule::parse("daily 22:00").unwrap();
        assert_eq!(s.last_slot(D + 22 * HOUR), D + 22 * HOUR, "exactly on the slot");
        assert_eq!(s.last_slot(D + 22 * HOUR - 1), D - DAY + 22 * HOUR);
        assert_eq!(s.last_slot(D + DAY - 1), D + 22 * HOUR);
        let m = Schedule::parse("daily 00:00").unwrap();
        assert_eq!(m.last_slot(D), D);
        assert_eq!(m.last_slot(D - 1), D - DAY, "midnight rollover");
        // year boundary: 2024-12-31 23:59:59 -> 2025-01-01 00:00 (UTC, no DST)
        let ny = 20_089 * DAY; // 2025-01-01
        assert_eq!(m.last_slot(ny - 1), ny - DAY);
        assert_eq!(m.last_slot(ny), ny);
    }

    #[test]
    fn last_slot_hourly() {
        let s = Schedule::parse("hourly 15").unwrap();
        assert_eq!(s.last_slot(D + 10 * HOUR + 15 * 60), D + 10 * HOUR + 15 * 60);
        assert_eq!(s.last_slot(D + 10 * HOUR + 14 * 60), D + 9 * HOUR + 15 * 60);
        assert_eq!(s.last_slot(D + 5 * 60), D - HOUR + 15 * 60, "across midnight");
    }

    #[test]
    fn once_per_period() {
        let s = Schedule::parse("daily 22:00").unwrap();
        let slot = D + 22 * HOUR;
        let last = D - DAY + 22 * HOUR + 30; // yesterday's run
        assert!(!s.due(last, slot - 1));
        assert!(s.due(last, slot));
        // queued at slot+30: not due again until tomorrow's slot
        let queued = slot + 30;
        assert!(!s.due(queued, slot + 60));
        assert!(!s.due(queued, slot + DAY - 1));
        assert!(s.due(queued, slot + DAY));
        // a run queued exactly at the slot second is not repeated
        assert!(!s.due(slot, slot + 10));
    }

    #[test]
    fn downtime_catches_up_once() {
        let s = Schedule::parse("daily 22:00").unwrap();
        let last = D - 3 * DAY + 22 * HOUR; // ran 3 days ago, then down
        let up = D + 10 * HOUR; // back at 10:00, missed 2 slots
        assert!(s.due(last, up), "one catch-up run");
        // the catch-up run counts for the missed periods: next run at today's slot
        assert!(!s.due(up, up + 30));
        assert!(!s.due(up, D + 22 * HOUR - 1));
        assert!(s.due(up, D + 22 * HOUR));

        let h = Schedule::parse("hourly 05").unwrap();
        let last = D + 2 * HOUR + 5 * 60;
        let up = D + 7 * HOUR + 59 * 60; // down for ~6 h
        assert!(h.due(last, up));
        assert!(!h.due(up, up + 60));
        assert!(h.due(up, D + 8 * HOUR + 5 * 60));
    }
}
