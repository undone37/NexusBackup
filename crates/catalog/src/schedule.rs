//! Policy schedules, blackout windows and retry settings (Phase 13b, docs/control-plane.md
//! "Run control"), bandwidth and sync windows (Phase 17a, [`Bandwidth`], [`Span`],
//! [`Throttle`]). Shared by the web-api (validation), the scheduler and the
//! transfer engines (evaluation).
//!
//! Schedule forms (all evaluated in a time zone, default UTC):
//! - `hourly MM`, `every Nh` / `every Nh at MM` (N divides 24: slots at local hours 0, N, 2N, …)
//! - `every Nm` (N ≥ 5 divides 60: slots at minutes 0, N, 2N, … of every hour; frequent
//!   WAL-only runs of database plugins)
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
pub use chrono_tz::Tz;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use std::time::{Duration as StdDuration, Instant};

const DAY: i64 = 86400;
pub const DAYS: [&str; 7] = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// every `every` hours (1 = hourly) at `minute`
    Hours {
        every: u32,
        minute: u32,
    },
    /// every `every` minutes (5..=30, divides 60), from the full hour
    Minutes {
        every: u32,
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
            format!("bad schedule {s:?}: expected `daily HH:MM`, `hourly MM`, `every Nh [at MM]`, `every Nm`, `Mon,Wed HH:MM` or `monthly D HH:MM`")
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
            ["every", n] if n.ends_with('m') => {
                let every = n
                    .strip_suffix('m')
                    .and_then(|n| digits(n, 30, false))
                    .filter(|n| *n >= 5 && 60 % n == 0)
                    .with_context(|| format!("bad schedule {s:?}: `every Nm` needs N in 5,6,10,12,15,20,30"))?;
                Kind::Minutes { every }
            }
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
            Kind::Minutes { every } => (0..24)
                .flat_map(|h| (0..60).step_by(every as usize).map(move |m| (h, m)))
                .collect(),
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

    /// First slot (unix seconds) after `now`, within the next 63 days (endpoint UIs).
    pub fn next_slot(self, now: i64) -> Option<i64> {
        let today = local(self.tz, now).date_naive();
        (0..=63).map(|d| today + Duration::days(d)).find_map(|d| {
            self.slots_on(d)
                .into_iter()
                .map(|(h, m)| to_utc(self.tz, d, h, m))
                .filter(|t| *t > now)
                .min()
        })
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
            Kind::Minutes { every } => every as i64 * 60,
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
        check_span(&self.days, &self.from, &self.to, "blackout")
    }

    /// Start (unix seconds) of the occurrence of this window that contains `now`.
    pub fn active_start(&self, tz: Tz, now: i64) -> Option<i64> {
        occurrence(&self.days, &self.from, &self.to, tz, now).map(|(s, _)| s)
    }
}

/// `[start, end)` (unix seconds) of the occurrence of a daily window (start
/// days, local `from`–`to`, `to` <= `from` = over midnight) containing `now`.
fn occurrence(days: &[String], from: &str, to: &str, tz: Tz, now: i64) -> Option<(i64, i64)> {
    let ((fh, fm), (th, tm)) = (hhmm(from)?, hhmm(to)?);
    let today = local(tz, now).date_naive();
    [today - Duration::days(1), today].into_iter().find_map(|d| {
        let wd = DAYS[d.weekday().num_days_from_monday() as usize];
        if !days.is_empty() && !days.iter().any(|x| x == wd) {
            return None;
        }
        let start = to_utc(tz, d, fh, fm);
        let end_day = if (th, tm) <= (fh, fm) { d + Duration::days(1) } else { d };
        let end = to_utc(tz, end_day, th, tm);
        (start <= now && now < end).then_some((start, end))
    })
}

fn check_span(days: &[String], from: &str, to: &str, what: &str) -> Result<()> {
    for d in days {
        weekday(d).with_context(|| format!("{what}: unknown day {d:?} (Mon..Sun)"))?;
    }
    let (f, t) = (hhmm(from), hhmm(to));
    if f.is_none() || t.is_none() || f == t {
        bail!("{what}: from/to must be different HH:MM times");
    }
    Ok(())
}

/// Unix times in `[start, start + days)` at which a window `from`/`to` may
/// begin or end (every day, weekday filters ignored: a superset is enough).
fn edges(from: &str, to: &str, tz: Tz, start: i64, days: i64) -> Vec<i64> {
    let first = local(tz, start).date_naive() - Duration::days(1);
    let mut out = Vec::new();
    for (h, m) in [hhmm(from), hhmm(to)].into_iter().flatten() {
        for i in 0..=days + 1 {
            out.push(to_utc(tz, first + Duration::days(i), h, m));
        }
    }
    out.retain(|t| (start..start + days * DAY).contains(t));
    out
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

// ------------------------------------------------------------- bandwidth windows

/// What a bandwidth window does while it is active.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    /// no transfer at all
    Pause,
    /// at most `rate_bytes` per second
    Limit,
}

/// A bandwidth window (offsite `windows`, replication source `windows`, Phase
/// 17a): from `from` to `to` (local time of the tenant / source) on the given
/// start days (empty = every day); `to` <= `from` ends on the next day.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RateWindow {
    #[serde(default)]
    pub days: Vec<String>,
    pub from: String,
    pub to: String,
    pub action: Action,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate_bytes: Option<u64>,
}

/// At most this many windows per list.
pub const MAX_WINDOWS: usize = 32;

impl RateWindow {
    pub fn check(&self) -> Result<()> {
        check_span(&self.days, &self.from, &self.to, "window")?;
        match (self.action, self.rate_bytes) {
            (Action::Limit, Some(r)) if r > 0 => Ok(()),
            (Action::Limit, _) => bail!("window: action limit needs rate_bytes > 0"),
            (Action::Pause, None) => Ok(()),
            (Action::Pause, Some(_)) => bail!("window: action pause takes no rate_bytes"),
        }
    }
}

/// Validates a bandwidth window list.
pub fn check_windows(w: &[RateWindow]) -> Result<()> {
    if w.len() > MAX_WINDOWS {
        bail!("at most {MAX_WINDOWS} windows");
    }
    w.iter().try_for_each(RateWindow::check)
}

/// Effective transfer limit at one point in time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Limit {
    Unlimited,
    /// bytes per second
    Rate(u64),
    Paused,
}

impl Limit {
    /// Bytes per second allowed (paused 0, unlimited `u64::MAX`): smaller = more restrictive.
    pub fn allowance(self) -> u64 {
        match self {
            Limit::Unlimited => u64::MAX,
            Limit::Rate(r) => r,
            Limit::Paused => 0,
        }
    }
}

/// A base limit plus bandwidth windows, evaluated in a time zone.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bandwidth {
    /// bytes per second outside limit windows (`None` = unlimited)
    pub base: Option<u64>,
    pub windows: Vec<RateWindow>,
    pub tz: Tz,
}

impl Default for Bandwidth {
    fn default() -> Self {
        Bandwidth {
            base: None,
            windows: Vec::new(),
            tz: Tz::UTC,
        }
    }
}

impl Bandwidth {
    /// Pause beats limit beats the base; among several active limit windows the
    /// lowest rate wins. A limit window replaces the base (it may also allow
    /// more, e.g. a faster night).
    pub fn limit_at(&self, now: i64) -> Limit {
        let mut rate: Option<u64> = None;
        for w in &self.windows {
            if occurrence(&w.days, &w.from, &w.to, self.tz, now).is_none() {
                continue;
            }
            match (w.action, w.rate_bytes) {
                (Action::Pause, _) => return Limit::Paused,
                (Action::Limit, Some(r)) if r > 0 => rate = Some(rate.map_or(r, |x| x.min(r))),
                (Action::Limit, _) => {}
            }
        }
        match rate.or(self.base.filter(|b| *b > 0)) {
            Some(r) => Limit::Rate(r),
            None => Limit::Unlimited,
        }
    }

    /// End of the pause active at `now` (chained pauses followed), `None` if not paused.
    pub fn paused_until(&self, now: i64) -> Option<i64> {
        let mut t = now;
        for _ in 0..64 {
            let end = self
                .windows
                .iter()
                .filter(|w| w.action == Action::Pause)
                .filter_map(|w| occurrence(&w.days, &w.from, &w.to, self.tz, t).map(|(_, e)| e))
                .max();
            match end {
                Some(e) => t = e,
                None => break,
            }
        }
        (t > now).then_some(t)
    }

    /// Whether `new` allows more than `self` at some time in the 8 days from
    /// `from`: a weakening (more bandwidth, a pause removed or shortened).
    pub fn weaker(&self, new: &Bandwidth, from: i64) -> bool {
        let mut ts = vec![from];
        for b in [self, new] {
            for w in &b.windows {
                ts.extend(edges(&w.from, &w.to, b.tz, from, 8));
            }
        }
        ts.into_iter()
            .any(|t| new.limit_at(t).allowance() > self.limit_at(t).allowance())
    }
}

/// A sync window span (replication source `sync_window`): syncs only from
/// `from` to `to` on the given start days (empty = every day).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Span {
    #[serde(default)]
    pub days: Vec<String>,
    pub from: String,
    pub to: String,
}

/// Validates a sync window.
pub fn check_spans(s: &[Span]) -> Result<()> {
    if s.len() > MAX_WINDOWS {
        bail!("at most {MAX_WINDOWS} windows");
    }
    s.iter()
        .try_for_each(|x| check_span(&x.days, &x.from, &x.to, "sync window"))
}

/// Inside the sync window (no spans = always).
pub fn sync_open(spans: &[Span], tz: Tz, now: i64) -> bool {
    spans.is_empty()
        || spans
            .iter()
            .any(|s| occurrence(&s.days, &s.from, &s.to, tz, now).is_some())
}

/// Whether the sync window `new` is open at some time (within 8 days from
/// `from`) where `old` is closed: a widening.
pub fn sync_widened(old: &[Span], old_tz: Tz, new: &[Span], new_tz: Tz, from: i64) -> bool {
    let mut ts = vec![from];
    for (s, tz) in old.iter().map(|s| (s, old_tz)).chain(new.iter().map(|s| (s, new_tz))) {
        ts.extend(edges(&s.from, &s.to, tz, from, 8));
    }
    ts.into_iter()
        .any(|t| sync_open(new, new_tz, t) && !sync_open(old, old_tz, t))
}

/// Shared rate limiter of several transfer threads following a [`Bandwidth`]
/// (offsite uploaders, replication chunk workers). The effective limit is
/// re-evaluated every `recheck`; a new limit starts a new token bucket.
pub struct Throttle {
    bw: Bandwidth,
    clock: Arc<dyn Fn() -> i64 + Send + Sync>,
    recheck: StdDuration,
    st: Mutex<ThrottleState>,
}

struct ThrottleState {
    limit: Limit,
    checked: Option<Instant>,
    start: Instant,
    bytes: u64,
}

impl Throttle {
    /// Wall clock, re-evaluated every 10 s.
    pub fn new(bw: Bandwidth) -> Self {
        Self::with_clock(bw, Arc::new(crate::now), StdDuration::from_secs(10))
    }

    pub fn with_clock(bw: Bandwidth, clock: Arc<dyn Fn() -> i64 + Send + Sync>, recheck: StdDuration) -> Self {
        Throttle {
            bw,
            clock,
            recheck,
            st: Mutex::new(ThrottleState {
                limit: Limit::Unlimited,
                checked: None,
                start: Instant::now(),
                bytes: 0,
            }),
        }
    }

    fn refresh(&self, st: &mut ThrottleState) -> Limit {
        if st.checked.is_none_or(|c| c.elapsed() >= self.recheck) {
            let l = self.bw.limit_at((self.clock)());
            if l != st.limit || st.checked.is_none() {
                st.limit = l;
                st.start = Instant::now();
                st.bytes = 0;
            }
            st.checked = Some(Instant::now());
        }
        st.limit
    }

    fn slice(&self) -> StdDuration {
        self.recheck
            .clamp(StdDuration::from_millis(200), StdDuration::from_secs(10))
    }

    /// The limit in force now.
    pub fn limit(&self) -> Limit {
        self.refresh(&mut self.st.lock().unwrap())
    }

    /// Blocks while a pause window is active; true if it waited (callers
    /// reconnect: an idle connection may have been dropped).
    pub fn wait_open(&self) -> bool {
        let mut waited = false;
        while self.limit() == Limit::Paused {
            waited = true;
            std::thread::sleep(self.slice());
        }
        waited
    }

    /// After `n` bytes were transferred: sleeps as long as the current rate
    /// requires (in slices, so a window change takes effect within one).
    pub fn account(&self, n: u64) {
        let mut add = n;
        loop {
            let wait = {
                let mut st = self.st.lock().unwrap();
                match self.refresh(&mut st) {
                    Limit::Rate(r) => {
                        st.bytes += std::mem::take(&mut add);
                        StdDuration::from_secs_f64(st.bytes as f64 / r as f64).checked_sub(st.start.elapsed())
                    }
                    _ => None,
                }
            };
            match wait {
                Some(w) if !w.is_zero() => std::thread::sleep(w.min(self.slice())),
                _ => return,
            }
        }
    }
}

/// Appliance-side read limit of a source (Phase 22b, docs/control-plane.md
/// "Concurrency caps and read limits"): `bwlimit` bytes per second (`None` =
/// unlimited) plus `limit` windows in `timezone`. Stored in the source config
/// (PVE, TrueNAS, NFS/SMB) and handed to the connector unchanged. Pause windows
/// are refused: a paused read would stall a running backup (VM fleecing grows);
/// keep backups out of a time span with a blackout window instead.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReadLimit {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bwlimit: Option<u64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub windows: Vec<RateWindow>,
    #[serde(default = "utc_name")]
    pub timezone: String,
}

fn utc_name() -> String {
    "UTC".into()
}

impl Default for ReadLimit {
    fn default() -> Self {
        ReadLimit {
            bwlimit: None,
            windows: Vec::new(),
            timezone: utc_name(),
        }
    }
}

impl ReadLimit {
    pub fn check(&self) -> Result<()> {
        if self.bwlimit == Some(0) {
            bail!("read_limit.bwlimit: bytes per second > 0 (omit for unlimited)");
        }
        check_windows(&self.windows).context("read_limit.windows")?;
        if self.windows.iter().any(|w| w.action == Action::Pause) {
            bail!("read_limit.windows: only `limit` windows (a paused read would stall a running backup; use a blackout window)");
        }
        tz(&self.timezone).context("read_limit.timezone")?;
        Ok(())
    }

    pub fn bandwidth(&self) -> Result<Bandwidth> {
        Ok(Bandwidth {
            base: self.bwlimit,
            windows: self.windows.clone(),
            tz: tz(&self.timezone)?,
        })
    }

    /// A shared throttle for all reads of one connector run (`None` = no limit at all).
    pub fn throttle(&self) -> Result<Option<Arc<Throttle>>> {
        if self.bwlimit.is_none() && self.windows.is_empty() {
            return Ok(None);
        }
        Ok(Some(Arc::new(Throttle::new(self.bandwidth()?))))
    }
}

/// A reader paced by a shared [`Throttle`] (the connectors' read limit);
/// `None` reads unlimited.
pub struct Throttled<R> {
    pub inner: R,
    pub limit: Option<Arc<Throttle>>,
}

impl<R: std::io::Read> std::io::Read for Throttled<R> {
    fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(b)?;
        if let Some(t) = &self.limit {
            t.account(n as u64);
        }
        Ok(n)
    }
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
        assert_eq!(p("every 15m").kind, Kind::Minutes { every: 15 });
        assert_eq!(p("every 5m").kind, Kind::Minutes { every: 5 });
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
            "every 4m",
            "every 7m",
            "every 60m",
            "every 0m",
            "every 15m at 05",
            "every m",
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
    fn next_slot() {
        let s = p("daily 22:00");
        assert_eq!(s.next_slot(D + 22 * HOUR - 1), Some(D + 22 * HOUR));
        assert_eq!(
            s.next_slot(D + 22 * HOUR),
            Some(D + DAY + 22 * HOUR),
            "strictly after now"
        );
        assert_eq!(
            p("hourly 15").next_slot(D + 23 * HOUR + 20 * 60),
            Some(D + DAY + 15 * 60)
        );
        let m = p("monthly 31 01:00");
        assert!(m.next_slot(D).is_some_and(|t| t > D && t < D + 32 * DAY));
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
    fn last_slot_minutes() {
        let s = p("every 15m");
        assert_eq!(s.period(), 15 * 60);
        assert_eq!(s.last_slot(D + 10 * HOUR + 14 * 60), D + 10 * HOUR);
        assert_eq!(s.last_slot(D + 10 * HOUR + 15 * 60), D + 10 * HOUR + 15 * 60);
        assert_eq!(s.last_slot(D + 10 * HOUR + 59 * 60), D + 10 * HOUR + 45 * 60);
        assert_eq!(s.last_slot(D + 5 * 60), D, "midnight");
        assert_eq!(s.last_slot(D - 1), D - 15 * 60, "across midnight");
        assert!(s.due(D + 10 * HOUR + 1, D + 10 * HOUR + 15 * 60));
        assert!(!s.due(D + 10 * HOUR + 15 * 60 + 2, D + 10 * HOUR + 29 * 60));
        // half-hour time zone: slots stay on the local quarter hours
        let k = p("every 30m").in_tz("Asia/Kolkata").unwrap(); // UTC+05:30
        assert_eq!(k.last_slot(D + 10 * HOUR + 10 * 60), D + 10 * HOUR);
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
        assert_eq!(abort_since(std::slice::from_ref(&day), utc, D + 9 * HOUR), None);
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

    fn rw(days: &[&str], from: &str, to: &str, rate: Option<u64>) -> RateWindow {
        RateWindow {
            days: days.iter().map(|d| d.to_string()).collect(),
            from: from.into(),
            to: to.into(),
            action: if rate.is_some() { Action::Limit } else { Action::Pause },
            rate_bytes: rate,
        }
    }

    fn span(days: &[&str], from: &str, to: &str) -> Span {
        Span {
            days: days.iter().map(|d| d.to_string()).collect(),
            from: from.into(),
            to: to.into(),
        }
    }

    #[test]
    fn bandwidth_windows() {
        // D is a Friday; business hours limited, a pause over midnight, base 10 MB/s
        let bw = Bandwidth {
            base: Some(10_000_000),
            windows: vec![
                rw(&["Mon", "Tue", "Wed", "Thu", "Fri"], "08:00", "18:00", Some(1_000_000)),
                rw(&[], "12:00", "13:00", Some(500_000)),
                rw(&["Thu"], "23:00", "02:00", None),
            ],
            tz: Tz::UTC,
        };
        assert!(check_windows(&bw.windows).is_ok());
        assert_eq!(bw.limit_at(D + 7 * HOUR), Limit::Rate(10_000_000), "base");
        assert_eq!(bw.limit_at(D + 9 * HOUR), Limit::Rate(1_000_000));
        assert_eq!(
            bw.limit_at(D + 12 * HOUR + 30 * 60),
            Limit::Rate(500_000),
            "lowest rate wins"
        );
        assert_eq!(bw.limit_at(D + 18 * HOUR), Limit::Rate(10_000_000), "end exclusive");
        // midnight wrap: Thursday 23:00 → Friday 02:00
        assert_eq!(bw.limit_at(D + HOUR), Limit::Paused);
        assert_eq!(bw.limit_at(D - HOUR), Limit::Paused);
        assert_eq!(bw.limit_at(D + 2 * HOUR), Limit::Rate(10_000_000));
        assert_eq!(
            bw.limit_at(D + 23 * HOUR + 30 * 60),
            Limit::Rate(10_000_000),
            "Friday not listed"
        );
        assert_eq!(bw.paused_until(D + HOUR), Some(D + 2 * HOUR));
        assert_eq!(bw.paused_until(D + 3 * HOUR), None);
        // a limit window may allow more than the base; no base = unlimited
        let night = Bandwidth {
            base: Some(1000),
            windows: vec![rw(&[], "22:00", "06:00", Some(50_000))],
            tz: Tz::UTC,
        };
        assert_eq!(night.limit_at(D + 23 * HOUR), Limit::Rate(50_000));
        assert_eq!(Bandwidth::default().limit_at(D), Limit::Unlimited);
        // chained pauses: 01:00–03:00 then 02:30–05:00
        let chain = Bandwidth {
            windows: vec![rw(&[], "01:00", "03:00", None), rw(&[], "02:30", "05:00", None)],
            ..Default::default()
        };
        assert_eq!(chain.paused_until(D + HOUR + 60), Some(D + 5 * HOUR));
        for bad in [
            rw(&[], "01:00", "01:00", None),
            rw(&["xx"], "01:00", "02:00", None),
            RateWindow {
                rate_bytes: Some(0),
                ..rw(&[], "01:00", "02:00", Some(1))
            },
            RateWindow {
                rate_bytes: None,
                ..rw(&[], "01:00", "02:00", Some(1))
            },
            RateWindow {
                rate_bytes: Some(5),
                ..rw(&[], "01:00", "02:00", None)
            },
        ] {
            assert!(bad.check().is_err(), "{bad:?}");
        }
        assert!(check_windows(&vec![rw(&[], "01:00", "02:00", None); MAX_WINDOWS + 1]).is_err());
        let j: Vec<RateWindow> =
            serde_json::from_str(r#"[{"from":"08:00","to":"18:00","action":"limit","rate_bytes":5}]"#).unwrap();
        assert_eq!(j[0].action, Action::Limit);
        assert!(serde_json::from_str::<Vec<RateWindow>>(r#"[{"from":"08:00","to":"18:00","action":"stop"}]"#).is_err());
    }

    #[test]
    fn read_limit() {
        let r: ReadLimit = serde_json::from_str(
            r#"{"bwlimit":100000000,"windows":[{"from":"08:00","to":"18:00","action":"limit","rate_bytes":20000000}],"timezone":"Europe/Berlin"}"#,
        )
        .unwrap();
        r.check().unwrap();
        let bw = r.bandwidth().unwrap();
        assert_eq!(bw.base, Some(100_000_000));
        assert!(r.throttle().unwrap().is_some());
        assert!(
            ReadLimit::default().throttle().unwrap().is_none(),
            "nothing set: no throttle"
        );
        assert_eq!(serde_json::from_str::<ReadLimit>("{}").unwrap().timezone, "UTC");
        for bad in [
            r#"{"bwlimit":0}"#,
            r#"{"windows":[{"from":"01:00","to":"02:00","action":"pause"}]}"#,
            r#"{"timezone":"Mars/Base"}"#,
        ] {
            assert!(
                serde_json::from_str::<ReadLimit>(bad).unwrap().check().is_err(),
                "{bad}"
            );
        }
        assert!(serde_json::from_str::<ReadLimit>(r#"{"rate":1}"#).is_err());
        // the reader passes the data through and accounts it
        let t = Arc::new(Throttle::new(Bandwidth {
            base: Some(1 << 30),
            ..Default::default()
        }));
        let mut r = Throttled {
            inner: &b"hello"[..],
            limit: Some(t),
        };
        let mut s = String::new();
        std::io::Read::read_to_string(&mut r, &mut s).unwrap();
        assert_eq!(s, "hello");
    }

    #[test]
    fn bandwidth_dst() {
        let berlin: Tz = "Europe/Berlin".parse().unwrap();
        // spring forward 2025-03-30 02:00 → 03:00: a pause 01:00–04:00 local is 2 h long
        let d = NaiveDate::from_ymd_opt(2025, 3, 30).unwrap();
        let day0 = d.and_hms_opt(0, 0, 0).unwrap().and_utc().timestamp();
        let bw = Bandwidth {
            windows: vec![rw(&[], "01:00", "04:00", None)],
            tz: berlin,
            ..Default::default()
        };
        // 01:00 CET = 00:00 UTC, 04:00 CEST = 02:00 UTC
        assert_eq!(bw.limit_at(day0 - 1), Limit::Unlimited);
        assert_eq!(bw.limit_at(day0), Limit::Paused);
        assert_eq!(bw.paused_until(day0 + 60), Some(day0 + 2 * HOUR));
        assert_eq!(bw.limit_at(day0 + 2 * HOUR), Limit::Unlimited);
        // a window starting inside the gap (02:30) starts after it (03:30 CEST = 01:30 UTC)
        let gap = Bandwidth {
            windows: vec![rw(&[], "02:30", "05:00", Some(7))],
            tz: berlin,
            ..Default::default()
        };
        assert_eq!(gap.limit_at(day0 + HOUR + 29 * 60), Limit::Unlimited);
        assert_eq!(gap.limit_at(day0 + HOUR + 30 * 60), Limit::Rate(7));
        // fall back 2025-10-26: 01:00–04:00 local is 4 h long (23:00–03:00 UTC)
        let d = NaiveDate::from_ymd_opt(2025, 10, 26).unwrap();
        let day0 = d.and_hms_opt(0, 0, 0).unwrap().and_utc().timestamp();
        assert_eq!(bw.limit_at(day0 - HOUR), Limit::Paused);
        assert_eq!(bw.limit_at(day0 + 2 * HOUR + 59 * 60), Limit::Paused);
        assert_eq!(bw.limit_at(day0 + 3 * HOUR), Limit::Unlimited);
    }

    #[test]
    fn weakening() {
        let pause = rw(&[], "08:00", "18:00", None);
        let old = Bandwidth {
            base: Some(1000),
            windows: vec![pause.clone()],
            tz: Tz::UTC,
        };
        let with = |w: Vec<RateWindow>| Bandwidth {
            windows: w,
            ..old.clone()
        };
        assert!(!old.weaker(&old, D), "unchanged");
        assert!(old.weaker(&with(vec![]), D), "pause removed");
        assert!(
            old.weaker(&with(vec![rw(&[], "09:00", "18:00", None)]), D),
            "pause shortened"
        );
        assert!(
            !old.weaker(&with(vec![rw(&[], "07:00", "19:00", None)]), D),
            "pause widened"
        );
        assert!(
            !old.weaker(&with(vec![pause.clone(), rw(&[], "20:00", "22:00", Some(10))]), D),
            "a lower limit added"
        );
        assert!(
            old.weaker(&with(vec![pause.clone(), rw(&[], "20:00", "22:00", Some(5000))]), D),
            "a faster window added"
        );
        assert!(
            old.weaker(&with(vec![rw(&["Mon"], "08:00", "18:00", None)]), D),
            "pause only on Mondays"
        );
        assert!(
            old.weaker(
                &Bandwidth {
                    tz: "Asia/Tokyo".parse().unwrap(),
                    ..old.clone()
                },
                D
            ),
            "time zone moved the pause"
        );
        assert!(
            old.weaker(
                &Bandwidth {
                    base: None,
                    ..old.clone()
                },
                D
            ),
            "base removed"
        );
        // sync windows
        let night = vec![span(&[], "22:00", "06:00")];
        assert!(sync_open(&night, Tz::UTC, D + HOUR) && !sync_open(&night, Tz::UTC, D + 12 * HOUR));
        assert!(sync_open(&[], Tz::UTC, D), "no window: always");
        assert!(!sync_widened(&night, Tz::UTC, &night, Tz::UTC, D));
        assert!(
            !sync_widened(&night, Tz::UTC, &[span(&[], "23:00", "05:00")], Tz::UTC, D),
            "narrower"
        );
        assert!(
            sync_widened(&night, Tz::UTC, &[span(&[], "21:00", "06:00")], Tz::UTC, D),
            "wider"
        );
        assert!(sync_widened(&night, Tz::UTC, &[], Tz::UTC, D), "removed = always open");
        assert!(!sync_widened(&[], Tz::UTC, &night, Tz::UTC, D), "added");
        assert!(check_spans(&night).is_ok() && check_spans(&[span(&["x"], "01:00", "02:00")]).is_err());
    }

    #[test]
    fn throttle_follows_the_windows() {
        use std::sync::atomic::{AtomicI64, Ordering};
        let clock = Arc::new(AtomicI64::new(D + 9 * HOUR));
        let c = clock.clone();
        let th = Throttle::with_clock(
            Bandwidth {
                base: None,
                windows: vec![
                    rw(&[], "08:00", "10:00", Some(100_000)),
                    rw(&[], "10:00", "11:00", None),
                ],
                tz: Tz::UTC,
            },
            Arc::new(move || c.load(Ordering::Relaxed)),
            StdDuration::ZERO,
        );
        assert_eq!(th.limit(), Limit::Rate(100_000));
        let t0 = Instant::now();
        th.account(30_000);
        assert!(t0.elapsed() >= StdDuration::from_millis(250), "{:?}", t0.elapsed());
        // the window ends: unlimited at once
        clock.store(D + 12 * HOUR, Ordering::Relaxed);
        let t0 = Instant::now();
        th.account(10_000_000);
        assert!(t0.elapsed() < StdDuration::from_millis(100));
        assert!(!th.wait_open());
        // a pause blocks until it ends
        clock.store(D + 10 * HOUR + 30 * 60, Ordering::Relaxed);
        let c = clock.clone();
        let h = std::thread::spawn(move || {
            std::thread::sleep(StdDuration::from_millis(300));
            c.store(D + 11 * HOUR, Ordering::Relaxed);
        });
        let t0 = Instant::now();
        assert!(th.wait_open());
        assert!(t0.elapsed() >= StdDuration::from_millis(250));
        h.join().unwrap();
    }
}
