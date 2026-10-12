//! Policy schedules, blackout windows and retry settings (Phase 13b, docs/control-plane.md
//! "Run control"). Shared by the web-api (validation) and the scheduler (evaluation).
//!
//! Schedule forms (all evaluated in a time zone, default UTC):
//! - `hourly MM`, `every Nh` / `every Nh at MM` (N divides 24: slots at local hours 0, N, 2N, …)
//! - `daily HH:MM`
//! - `Mon,Wed,Fri HH:MM`, also ranges (`Mon-Fri HH:MM`)
//! - `monthly D HH:MM` (D 1..=31; a month without day D runs on its last day)
//!
//! "Due" is period based: a run is due when the most recent slot at or before
//! `now` is later than the last run. After downtime this yields exactly one
//! catch-up run, not one per missed period.
//!
//! Daylight saving time: a slot inside the spring-forward gap runs at the same
//! wall-clock offset after the gap (02:30 → 03:30); in the repeated autumn hour
//! a slot runs once (at its first occurrence).

use anyhow::{bail, Context, Result};
use chrono::{DateTime, Datelike, Duration, LocalResult, NaiveDate, NaiveDateTime, NaiveTime, TimeZone};
use chrono_tz::Tz;
use serde::{Deserialize, Serialize};

const DAY: i64 = 86400;
pub const DAYS: [&str; 7] = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// every `every` hours (1 = hourly) at `minute`
    Hours {
        every: u32,
        minute: u32,
    },
    /// on the weekdays of the mask (bit 0 = Monday; 0x7f = daily)
    Days {
        mask: u8,
        hour: u32,
        minute: u32,
    },
    Monthly {
        day: u32,
        hour: u32,
        minute: u32,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Schedule {
    pub kind: Kind,
    pub tz: Tz,
}

fn digits(v: &str, max: u32, exact2: bool) -> Option<u32> {
    let ok = !v.is_empty() && v.len() <= 2 && (!exact2 || v.len() == 2) && v.bytes().all(|b| b.is_ascii_digit());
    ok.then(|| v.parse().ok()).flatten().filter(|n| *n <= max)
}

fn hhmm(v: &str) -> Option<(u32, u32)> {
    let (h, m) = v.split_once(':')?;
    Some((digits(h, 23, true)?, digits(m, 59, true)?))
}

fn weekday(s: &str) -> Option<u32> {
    DAYS.iter().position(|d| *d == s).map(|i| i as u32)
}

/// `Mon,Wed,Fri` / `Mon-Fri` / `Sat,Sun` → bit mask (bit 0 = Monday).
pub fn day_mask(s: &str) -> Option<u8> {
    let mut mask = 0u8;
    for part in s.split(',') {
        match part.split_once('-') {
            Some((a, b)) => {
                let (a, b) = (weekday(a)?, weekday(b)?);
                if a > b {
                    return None;
                }
                for d in a..=b {
                    mask |= 1 << d;
                }
            }
            None => mask |= 1 << weekday(part)?,
        }
    }
    Some(mask)
}

/// IANA time zone name (`Europe/Berlin`, `UTC`).
pub fn tz(name: &str) -> Result<Tz> {
    name.parse::<Tz>()
        .map_err(|_| anyhow::anyhow!("unknown time zone {name:?}"))
}

impl Schedule {
    /// Parses in UTC (see [`Schedule::in_tz`]). Single spaces only.
    pub fn parse(s: &str) -> Result<Self> {
        let bad = || {
            format!("bad schedule {s:?}: expected `daily HH:MM`, `hourly MM`, `every Nh [at MM]`, `Mon,Wed HH:MM` or `monthly D HH:MM`")
        };
        let parts: Vec<&str> = s.split(' ').collect();
        let kind = match parts.as_slice() {
            ["daily", t] => {
                let (hour, minute) = hhmm(t).with_context(bad)?;
                Kind::Days {
                    mask: 0x7f,
                    hour,
                    minute,
                }
            }
            ["hourly", m] => Kind::Hours {
                every: 1,
                minute: digits(m, 59, true).with_context(bad)?,
            },
            ["every", n] | ["every", n, "at", _] => {
                let every = n
                    .strip_suffix('h')
                    .and_then(|n| digits(n, 24, false))
                    .filter(|n| *n > 0 && 24 % n == 0 && *n < 24)
                    .with_context(|| format!("bad schedule {s:?}: `every Nh` needs N in 1,2,3,4,6,8,12"))?;
                let minute = match parts.get(3) {
                    Some(m) => digits(m, 59, true).with_context(bad)?,
                    None => 0,
                };
                Kind::Hours { every, minute }
            }
            ["monthly", d, t] => {
                let day = digits(d, 31, false).filter(|d| *d >= 1).with_context(bad)?;
                let (hour, minute) = hhmm(t).with_context(bad)?;
                Kind::Monthly { day, hour, minute }
            }
            [days, t] => {
                let mask = day_mask(days).with_context(bad)?;
                let (hour, minute) = hhmm(t).with_context(bad)?;
                Kind::Days { mask, hour, minute }
            }
            _ => bail!(bad()),
        };
        Ok(Schedule { kind, tz: Tz::UTC })
    }

    /// Evaluate in the time zone `name` (IANA).
    pub fn in_tz(self, name: &str) -> Result<Self> {
        Ok(Schedule { tz: tz(name)?, ..self })
    }

    /// Local slot times on `date`.
    fn slots_on(&self, date: NaiveDate) -> Vec<(u32, u32)> {
        match self.kind {
            Kind::Hours { every, minute } => (0..24).step_by(every as usize).map(|h| (h, minute)).collect(),
            Kind::Days { mask, hour, minute } => {
                if mask & (1 << date.weekday().num_days_from_monday()) != 0 {
                    vec![(hour, minute)]
                } else {
                    vec![]
                }
            }
            Kind::Monthly { day, hour, minute } => {
                if date.day() == day.min(last_day(date)) {
                    vec![(hour, minute)]
                } else {
                    vec![]
                }
            }
        }
    }

    /// Latest slot (unix seconds) at or before `now`.
    pub fn last_slot(self, now: i64) -> i64 {
        let today = local(self.tz, now).date_naive();
        let (mut best, mut found): (Option<i64>, Option<i64>) = (None, None);
        // monthly: up to 31 days back; one more day after the first hit (slots moved by DST)
        for back in 0..=63 {
            if found.is_some_and(|f| back > f + 1) {
                break;
            }
            let d = today - Duration::days(back);
            for (h, m) in self.slots_on(d) {
                let t = to_utc(self.tz, d, h, m);
                if t <= now && best.is_none_or(|b| t > b) {
                    best = Some(t);
                    found.get_or_insert(back);
                }
            }
        }
        best.unwrap_or(i64::MIN)
    }

    /// Due iff a slot passed since the last run (`last_run` = when the last
    /// scheduled job was queued, or when the scheduler first saw the item).
    pub fn due(self, last_run: i64, now: i64) -> bool {
        self.last_slot(now) > last_run
    }

    /// Nominal period in seconds (RPO for the dashboard).
    pub fn period(self) -> i64 {
        match self.kind {
            Kind::Hours { every, .. } => every as i64 * 3600,
            Kind::Days { mask, .. } => {
                // longest gap between two run days of the week
                let days: Vec<i64> = (0..7).filter(|d| mask & (1 << d) != 0).collect();
                let gap = days
                    .iter()
                    .enumerate()
                    .map(|(i, d)| days.get(i + 1).map_or(days[0] + 7 - d, |n| n - d))
                    .max()
                    .unwrap_or(7);
                gap * DAY
            }
            Kind::Monthly { .. } => 31 * DAY,
        }
    }
}

fn last_day(d: NaiveDate) -> u32 {
    let (y, m) = if d.month() == 12 {
        (d.year() + 1, 1)
    } else {
        (d.year(), d.month() + 1)
    };
    NaiveDate::from_ymd_opt(y, m, 1).unwrap().pred_opt().unwrap().day()
}

fn local(tz: Tz, ts: i64) -> DateTime<Tz> {
    tz.timestamp_opt(ts, 0).single().expect("valid unix time")
}

/// Local wall-clock time → unix seconds (gap: shifted past it; repeated hour: first).
fn to_utc(tz: Tz, d: NaiveDate, h: u32, m: u32) -> i64 {
    let naive = NaiveDateTime::new(d, NaiveTime::from_hms_opt(h, m, 0).unwrap());
    match tz.from_local_datetime(&naive) {
        LocalResult::Single(t) => t.timestamp(),
        LocalResult::Ambiguous(a, _) => a.timestamp(),
        // in the gap: same offset as before the gap, i.e. the wall clock moved on
        LocalResult::None => {
            let before = tz.from_local_datetime(&(naive - Duration::hours(3))).earliest();
            let off = before.map_or(0, |b| naive.and_utc().timestamp() - 3 * 3600 - b.timestamp());
            naive.and_utc().timestamp() - off
        }
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

// ------------------------------------------------------------- blackout

/// A blackout window (`policies.blackout`): no scheduled runs from `from` to
/// `to` (local time of the group) on the given start days (empty = every day);
/// `to` <= `from` ends on the next day. `abort`: running backups that started
/// before the window are cancelled when it begins.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Window {
    #[serde(default)]
    pub days: Vec<String>,
    pub from: String,
    pub to: String,
    #[serde(default)]
    pub abort: bool,
}

impl Window {
    pub fn check(&self) -> Result<()> {
        for d in &self.days {
            weekday(d).with_context(|| format!("blackout: unknown day {d:?} (Mon..Sun)"))?;
        }
        let (f, t) = (hhmm(&self.from), hhmm(&self.to));
        if f.is_none() || t.is_none() || f == t {
            bail!("blackout: from/to must be different HH:MM times");
        }
        Ok(())
    }

    /// Start (unix seconds) of the occurrence of this window that contains `now`.
    pub fn active_start(&self, tz: Tz, now: i64) -> Option<i64> {
        let ((fh, fm), (th, tm)) = (hhmm(&self.from)?, hhmm(&self.to)?);
        let today = local(tz, now).date_naive();
        [today - Duration::days(1), today].into_iter().find_map(|d| {
            let wd = DAYS[d.weekday().num_days_from_monday() as usize];
            if !self.days.is_empty() && !self.days.iter().any(|x| x == wd) {
                return None;
            }
            let start = to_utc(tz, d, fh, fm);
            let end_day = if (th, tm) <= (fh, fm) { d + Duration::days(1) } else { d };
            let end = to_utc(tz, end_day, th, tm);
            (start <= now && now < end).then_some(start)
        })
    }
}

/// Earliest start of the windows active at `now` (and whether any of them aborts).
pub fn blackout(windows: &[Window], tz: Tz, now: i64) -> Option<(i64, bool)> {
    windows
        .iter()
        .filter_map(|w| w.active_start(tz, now).map(|s| (s, w.abort)))
        .fold(None, |acc, (s, a)| match acc {
            None => Some((s, a)),
            Some((s0, a0)) => Some((s0.min(s), a0 || a)),
        })
}

/// Windows with `abort` active at `now`: the earliest start among them.
pub fn abort_since(windows: &[Window], tz: Tz, now: i64) -> Option<i64> {
    windows
        .iter()
        .filter(|w| w.abort)
        .filter_map(|w| w.active_start(tz, now))
        .min()
}

// ------------------------------------------------------------- retry

/// `policies.retry`: failed backups are retried `count` times, `delay_min` apart.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Retry {
    pub count: u32,
    pub delay_min: u32,
}

impl Default for Retry {
    fn default() -> Self {
        Retry { count: 3, delay_min: 5 }
    }
}

impl Retry {
    pub fn check(&self) -> Result<()> {
        if self.count > 10 || !(1..=1440).contains(&self.delay_min) {
            bail!("retry: count 0..=10, delay_min 1..=1440");
        }
        Ok(())
    }
}

/// `paused_until` / `maintenance_until`: NULL = active, -1 = indefinitely, else until then.
pub fn paused(until: Option<i64>, now: i64) -> bool {
    until.is_some_and(|u| u == -1 || u > now)
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOUR: i64 = 3600;
    const D: i64 = 20_000 * DAY; // 2024-10-04 00:00 UTC (a Friday)

    fn p(s: &str) -> Schedule {
        Schedule::parse(s).unwrap()
    }

    #[test]
    fn parse() {
        assert_eq!(
            p("daily 22:05").kind,
            Kind::Days {
                mask: 0x7f,
                hour: 22,
                minute: 5
            }
        );
        assert_eq!(p("hourly 07").kind, Kind::Hours { every: 1, minute: 7 });
        assert_eq!(p("every 6h").kind, Kind::Hours { every: 6, minute: 0 });
        assert_eq!(p("every 4h at 15").kind, Kind::Hours { every: 4, minute: 15 });
        assert_eq!(
            p("Mon,Wed,Fri 01:30").kind,
            Kind::Days {
                mask: 0b10101,
                hour: 1,
                minute: 30
            }
        );
        assert_eq!(
            p("Mon-Fri 20:00").kind,
            Kind::Days {
                mask: 0x1f,
                hour: 20,
                minute: 0
            }
        );
        assert_eq!(
            p("monthly 1 03:00").kind,
            Kind::Monthly {
                day: 1,
                hour: 3,
                minute: 0
            }
        );
        for bad in [
            "daily 24:00",
            "daily 2:00",
            "daily 22",
            "hourly 60",
            "hourly +5",
            "weekly 01:00",
            "",
            "daily 22:5",
            "hourly -1",
            " hourly 07",
            "daily 12:00 ",
            "every 5h",
            "every 24h",
            "every 0h",
            "every 6",
            "every 6h at 60",
            "monthly 0 01:00",
            "monthly 32 01:00",
            "Fri-Mon 01:00",
            "mon 01:00",
            "Mon,,Tue 01:00",
        ] {
            assert!(Schedule::parse(bad).is_err(), "{bad}");
        }
        assert!(p("daily 01:00").in_tz("Europe/Berlin").is_ok());
        assert!(p("daily 01:00").in_tz("Mars/Olympus").is_err());
    }

    #[test]
    fn last_slot_daily() {
        let s = p("daily 22:00");
        assert_eq!(s.last_slot(D + 22 * HOUR), D + 22 * HOUR, "exactly on the slot");
        assert_eq!(s.last_slot(D + 22 * HOUR - 1), D - DAY + 22 * HOUR);
        assert_eq!(s.last_slot(D + DAY - 1), D + 22 * HOUR);
        let m = p("daily 00:00");
        assert_eq!(m.last_slot(D), D);
        assert_eq!(m.last_slot(D - 1), D - DAY, "midnight rollover");
        let ny = 20_089 * DAY; // 2025-01-01
        assert_eq!(m.last_slot(ny - 1), ny - DAY);
        assert_eq!(m.last_slot(ny), ny);
    }

    #[test]
    fn last_slot_hours() {
        let s = p("hourly 15");
        assert_eq!(s.last_slot(D + 10 * HOUR + 15 * 60), D + 10 * HOUR + 15 * 60);
        assert_eq!(s.last_slot(D + 10 * HOUR + 14 * 60), D + 9 * HOUR + 15 * 60);
        assert_eq!(s.last_slot(D + 5 * 60), D - HOUR + 15 * 60, "across midnight");
        let e = p("every 6h at 30");
        assert_eq!(e.last_slot(D + 13 * HOUR), D + 12 * HOUR + 30 * 60);
        assert_eq!(e.last_slot(D + 12 * HOUR + 29 * 60), D + 6 * HOUR + 30 * 60);
        assert_eq!(e.last_slot(D + 10 * 60), D - 6 * HOUR + 30 * 60);
    }

    #[test]
    fn weekdays_and_monthly() {
        // D is a Friday
        let s = p("Mon,Wed 02:00");
        assert_eq!(s.last_slot(D + 12 * HOUR), D - 2 * DAY + 2 * HOUR, "Wednesday");
        assert_eq!(s.last_slot(D - 2 * DAY + HOUR), D - 4 * DAY + 2 * HOUR, "Monday");
        assert_eq!(s.period(), 5 * DAY, "Wed → Mon");
        assert_eq!(p("Mon-Fri 20:00").period(), 3 * DAY);
        assert_eq!(p("daily 20:00").period(), DAY);
        let m = p("monthly 1 03:00"); // 2024-10-01 = D - 3 days
        assert_eq!(m.last_slot(D), D - 3 * DAY + 3 * HOUR);
        assert_eq!(
            m.last_slot(D - 3 * DAY + 3 * HOUR - 1),
            D - 33 * DAY + 3 * HOUR,
            "2024-09-01"
        );
        // day 31 in a 30-day month: the last day (2024-09-30)
        let m = p("monthly 31 03:00");
        assert_eq!(m.last_slot(D), D - 4 * DAY + 3 * HOUR);
    }

    #[test]
    fn time_zones_and_dst() {
        let berlin = |s: &str| p(s).in_tz("Europe/Berlin").unwrap();
        // 2024-10-04: CEST (UTC+2): 22:00 local = 20:00 UTC
        assert_eq!(berlin("daily 22:00").last_slot(D + 21 * HOUR), D + 20 * HOUR);
        // spring forward 2025-03-30 02:00 → 03:00 (UTC+1 → UTC+2)
        let d = NaiveDate::from_ymd_opt(2025, 3, 30).unwrap();
        let day0 = d.and_hms_opt(0, 0, 0).unwrap().and_utc().timestamp();
        let s = berlin("daily 02:30");
        // 02:30 does not exist: runs at 03:30 CEST = 01:30 UTC
        assert_eq!(s.last_slot(day0 + 6 * HOUR), day0 + HOUR + 30 * 60);
        assert!(!s.due(day0 + HOUR + 30 * 60, day0 + 20 * HOUR), "once that day");
        // the day before: 02:30 CET = 01:30 UTC
        assert_eq!(s.last_slot(day0), day0 - DAY + HOUR + 30 * 60);
        // fall back 2025-10-26 03:00 → 02:00 (UTC+2 → UTC+1): 02:30 happens twice, runs once
        let d = NaiveDate::from_ymd_opt(2025, 10, 26).unwrap();
        let day0 = d.and_hms_opt(0, 0, 0).unwrap().and_utc().timestamp();
        let first = day0 + 30 * 60; // 02:30 CEST = 00:30 UTC
        assert_eq!(s.last_slot(day0 + 6 * HOUR), first);
        assert!(
            !s.due(first + 10, first + HOUR + 10),
            "no second run in the repeated hour"
        );
        // hourly over the fall-back night: one slot per local hour
        let h = berlin("hourly 00");
        assert_eq!(h.last_slot(day0 + 2 * HOUR + 5), day0 + 2 * HOUR, "03:00 CET");
        // a group in New York: daily 01:00 EDT = 05:00 UTC
        let ny = p("daily 01:00").in_tz("America/New_York").unwrap();
        assert_eq!(ny.last_slot(D + 6 * HOUR), D + 5 * HOUR);
    }

    #[test]
    fn once_per_period() {
        let s = p("daily 22:00");
        let slot = D + 22 * HOUR;
        let last = D - DAY + 22 * HOUR + 30;
        assert!(!s.due(last, slot - 1));
        assert!(s.due(last, slot));
        let queued = slot + 30;
        assert!(!s.due(queued, slot + 60));
        assert!(!s.due(queued, slot + DAY - 1));
        assert!(s.due(queued, slot + DAY));
        assert!(!s.due(slot, slot + 10));
    }

    #[test]
    fn downtime_catches_up_once() {
        let s = p("daily 22:00");
        let last = D - 3 * DAY + 22 * HOUR;
        let up = D + 10 * HOUR;
        assert!(s.due(last, up), "one catch-up run");
        assert!(!s.due(up, up + 30));
        assert!(!s.due(up, D + 22 * HOUR - 1));
        assert!(s.due(up, D + 22 * HOUR));
        let h = p("hourly 05");
        let last = D + 2 * HOUR + 5 * 60;
        let up = D + 7 * HOUR + 59 * 60;
        assert!(h.due(last, up));
        assert!(!h.due(up, up + 60));
        assert!(h.due(up, D + 8 * HOUR + 5 * 60));
    }

    #[test]
    fn blackout_windows() {
        let w = |days: &[&str], from: &str, to: &str, abort: bool| Window {
            days: days.iter().map(|d| d.to_string()).collect(),
            from: from.into(),
            to: to.into(),
            abort,
        };
        let utc = Tz::UTC;
        let day = w(&[], "08:00", "18:00", false);
        assert!(day.check().is_ok());
        assert_eq!(day.active_start(utc, D + 9 * HOUR), Some(D + 8 * HOUR));
        assert_eq!(day.active_start(utc, D + 18 * HOUR), None, "end is exclusive");
        assert_eq!(day.active_start(utc, D + 7 * HOUR), None);
        // over midnight, started on Thursday only (D is a Friday)
        let night = w(&["Thu"], "22:00", "06:00", true);
        assert_eq!(night.active_start(utc, D + 5 * HOUR), Some(D - 2 * HOUR));
        assert_eq!(night.active_start(utc, D + 23 * HOUR), None, "Friday night not listed");
        assert_eq!(
            blackout(&[day.clone(), night.clone()], utc, D + 5 * HOUR),
            Some((D - 2 * HOUR, true))
        );
        assert_eq!(abort_since(&[day.clone()], utc, D + 9 * HOUR), None);
        assert_eq!(abort_since(&[night], utc, D + 5 * HOUR), Some(D - 2 * HOUR));
        // in Berlin (UTC+2 in October): 08:00 local = 06:00 UTC
        assert_eq!(
            day.active_start("Europe/Berlin".parse().unwrap(), D + 7 * HOUR),
            Some(D + 6 * HOUR)
        );
        for bad in [
            w(&["Xyz"], "01:00", "02:00", false),
            w(&[], "01:00", "01:00", false),
            w(&[], "1:00", "02:00", false),
        ] {
            assert!(bad.check().is_err(), "{bad:?}");
        }
        assert!(paused(Some(-1), 5) && paused(Some(10), 5) && !paused(Some(5), 5) && !paused(None, 5));
        assert!(
            Retry::default().check().is_ok()
                && Retry {
                    count: 11,
                    delay_min: 5
                }
                .check()
                .is_err()
        );
    }
}
