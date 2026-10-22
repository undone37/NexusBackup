//! View model: what the tray and the Control Panel show for a status/sessions snapshot.
//! Pure functions (no iced, no IO), unit-tested.

use agent_ui_proto::{AgentState, Session, SessionResult, Status, UiPolicy};
use chrono::{Local, TimeZone};

/// Product name shown when the UI policy sets no header text.
pub const PRODUCT: &str = "NexusBackup Agent";
/// Sessions in the bar chart.
pub const CHART_SESSIONS: usize = 30;

/// Tray icon state (docs/endpoint-ui.md: Veeam's tray states plus "not reached since").
#[derive(Clone, Debug, PartialEq)]
pub enum TrayState {
    /// the agent service does not answer on the local socket/pipe
    NoService(String),
    /// not enrolled, or enrolled without any backup job yet
    NoJob,
    /// a backup is scheduled but none has run yet
    Waiting {
        next_run: Option<u64>,
    },
    Running {
        percent: Option<u8>,
        transferred: u64,
    },
    /// "back up now" queued, waiting for the appliance's poll
    Requested,
    /// the appliance has not reached this machine for a while (laptop off the network)
    NotReached {
        since: Option<u64>,
    },
    Success,
    Warning,
    Error,
    Cancelled,
}

/// Badge drawn on the tray logo; with the tooltip text the state is never colour-only.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Badge {
    None,
    Clock,
    Play,
    Check,
    Warn,
    Cross,
    Stop,
    Offline,
}

impl TrayState {
    pub fn from_snapshot(status: Result<&Status, &str>, sessions: &[Session]) -> TrayState {
        let st = match status {
            Err(e) => return TrayState::NoService(e.to_string()),
            Ok(s) => s,
        };
        if !st.enrolled {
            return TrayState::NoJob;
        }
        if st.state == AgentState::Running {
            let r = st.running.as_ref();
            return TrayState::Running {
                percent: r.and_then(|r| r.percent),
                transferred: r.map_or(0, |r| r.transferred_bytes),
            };
        }
        if !st.reachable {
            return TrayState::NotReached {
                since: st.last_seen_by_appliance,
            };
        }
        if st.state == AgentState::Requested {
            return TrayState::Requested;
        }
        // newest backup decides; restores do not change the protection state
        match sessions.iter().find(|s| s.kind == agent_ui_proto::SessionKind::Backup) {
            Some(s) => match s.result {
                SessionResult::Success => TrayState::Success,
                SessionResult::Warning => TrayState::Warning,
                SessionResult::Failed => TrayState::Error,
                SessionResult::Cancelled => TrayState::Cancelled,
            },
            None if st.state == AgentState::Error => TrayState::Error,
            None if st.next_run.is_some() => TrayState::Waiting { next_run: st.next_run },
            None => TrayState::NoJob,
        }
    }

    pub fn badge(&self) -> Badge {
        match self {
            TrayState::NoService(_) | TrayState::NotReached { .. } => Badge::Offline,
            TrayState::NoJob => Badge::None,
            TrayState::Waiting { .. } | TrayState::Requested => Badge::Clock,
            TrayState::Running { .. } => Badge::Play,
            TrayState::Success => Badge::Check,
            TrayState::Warning => Badge::Warn,
            TrayState::Error => Badge::Cross,
            TrayState::Cancelled => Badge::Stop,
        }
    }

    /// Short state label (window status card, first tooltip line).
    pub fn label(&self) -> String {
        match self {
            TrayState::NoService(_) => "Not connected to the agent service".into(),
            TrayState::NoJob => "No backup configured yet".into(),
            TrayState::Waiting { .. } => "Waiting for the first backup".into(),
            TrayState::Running { percent: Some(p), .. } => format!("Backup running ({p} %)"),
            TrayState::Running { percent: None, .. } => "Backup running".into(),
            TrayState::Requested => "Backup requested, waiting for the appliance".into(),
            TrayState::NotReached { since: Some(t) } => format!("Not reached by the appliance since {}", fmt_time(*t)),
            TrayState::NotReached { since: None } => "Not reached by the appliance yet".into(),
            TrayState::Success => "Last backup succeeded".into(),
            TrayState::Warning => "Last backup finished with warnings".into(),
            TrayState::Error => "Last backup failed".into(),
            TrayState::Cancelled => "Last backup was cancelled".into(),
        }
    }
}

/// Tray tooltip: product/header, state, then one detail line (Windows limits tooltips to
/// 127 characters).
pub fn tooltip(state: &TrayState, status: Option<&Status>) -> String {
    let head = status.map_or_else(|| PRODUCT.to_string(), |s| header_title(&s.ui_policy));
    let detail = match state {
        TrayState::Running { transferred, .. } => Some(format!("{} transferred", fmt_bytes(*transferred))),
        TrayState::NoService(_) => Some("Open the window for details".into()),
        _ => status
            .and_then(|s| s.next_run)
            .map(|t| format!("Next backup: {}", fmt_time(t))),
    };
    let mut t = format!("{head}\n{}", state.label());
    if let Some(d) = detail {
        t.push('\n');
        t.push_str(&d);
    }
    truncate(&t, 127)
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let mut out: String = s.chars().take(max - 1).collect();
    out.push('…');
    out
}

pub fn header_title(p: &UiPolicy) -> String {
    match p.header.as_deref().map(str::trim) {
        Some(h) if !h.is_empty() => truncate(h, 80),
        _ => PRODUCT.to_string(),
    }
}

/// `#rrggbb` or `#rgb` → RGB; anything else is ignored (default accent).
pub fn parse_accent(s: &str) -> Option<[u8; 3]> {
    let h = s.trim().strip_prefix('#')?;
    if !h.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let n = |i: usize, len: usize| u8::from_str_radix(&h[i..i + len], 16).ok();
    match h.len() {
        6 => Some([n(0, 2)?, n(2, 2)?, n(4, 2)?]),
        3 => Some([n(0, 1)? * 17, n(1, 1)? * 17, n(2, 1)? * 17]),
        _ => None,
    }
}

/// "Request backup now" is offered unless the policy hides it; it is disabled (not hidden)
/// while a backup runs or a request is already queued.
pub fn backup_now_visible(st: Option<&Status>) -> bool {
    st.is_some_and(|s| s.enrolled && !s.ui_policy.hide_backup_now)
}

pub fn backup_now_enabled(st: Option<&Status>) -> bool {
    backup_now_visible(st) && st.is_some_and(|s| matches!(s.state, AgentState::Idle | AgentState::Error))
}

pub fn tray_visible(st: Option<&Status>) -> bool {
    !st.is_some_and(|s| s.ui_policy.hide_tray)
}

/// Bar chart height metric.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Metric {
    #[default]
    Transferred,
    Duration,
}

impl Metric {
    pub fn label(self) -> &'static str {
        match self {
            Metric::Transferred => "Transferred",
            Metric::Duration => "Duration",
        }
    }
}

/// One bar of the session chart (oldest left, newest right).
#[derive(Clone, Debug, PartialEq)]
pub struct Bar {
    pub id: u64,
    /// 0.0..=1.0 of the chart height; never below [`MIN_BAR`] so empty sessions stay visible
    pub height: f32,
    pub result: SessionResult,
}

pub const MIN_BAR: f32 = 0.04;

pub fn duration(s: &Session) -> u64 {
    s.ended.saturating_sub(s.started)
}

/// Bars for the newest [`CHART_SESSIONS`] sessions (`sessions` newest first, as served).
pub fn chart_bars(sessions: &[Session], metric: Metric) -> Vec<Bar> {
    let value = |s: &Session| match metric {
        Metric::Transferred => s.transferred_bytes,
        Metric::Duration => duration(s),
    };
    let shown: Vec<&Session> = sessions.iter().take(CHART_SESSIONS).collect();
    let max = shown.iter().map(|s| value(s)).max().unwrap_or(0).max(1) as f64;
    shown
        .iter()
        .rev()
        .map(|s| Bar {
            id: s.id,
            height: ((value(s) as f64 / max) as f32).max(MIN_BAR),
            result: s.result,
        })
        .collect()
}

pub fn result_label(r: SessionResult) -> &'static str {
    match r {
        SessionResult::Success => "Success",
        SessionResult::Warning => "Warning",
        SessionResult::Failed => "Failed",
        SessionResult::Cancelled => "Cancelled",
    }
}

/// Text symbol next to the result (so results are not told apart by colour alone).
pub fn result_symbol(r: SessionResult) -> &'static str {
    match r {
        SessionResult::Success => "OK",
        SessionResult::Warning => "!",
        SessionResult::Failed => "X",
        SessionResult::Cancelled => "-",
    }
}

/// Hover text of a chart bar / summary line of a session.
pub fn session_summary(s: &Session) -> String {
    format!(
        "{} · {} · {} · {} transferred",
        result_label(s.result),
        fmt_time(s.started),
        fmt_duration(duration(s)),
        fmt_bytes(s.transferred_bytes)
    )
}

/// Desktop notification for sessions that appeared since the last refresh (failed or
/// with warnings). `seen` = newest session id known before; `None` on the first fetch
/// (nothing is announced at login).
pub fn notification(seen: Option<u64>, sessions: &[Session]) -> Option<(String, String)> {
    let seen = seen?;
    let s = sessions
        .iter()
        .take_while(|s| s.id != seen)
        .find(|s| matches!(s.result, SessionResult::Failed | SessionResult::Warning))?;
    let title = match s.result {
        SessionResult::Failed => "Backup failed",
        _ => "Backup finished with warnings",
    };
    let body = match &s.first_error {
        Some(e) => format!("{} – {}", fmt_time(s.started), truncate(e, 200)),
        None => format!("{} – {} warning(s)", fmt_time(s.started), s.warnings),
    };
    Some((title.to_string(), body))
}

pub fn fmt_bytes(b: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = b as f64;
    let mut u = 0;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 {
        format!("{b} B")
    } else {
        format!("{v:.1} {}", UNITS[u])
    }
}

pub fn fmt_duration(secs: u64) -> String {
    let (h, m, s) = (secs / 3600, secs / 60 % 60, secs % 60);
    if h > 0 {
        format!("{h} h {m:02} min")
    } else if m > 0 {
        format!("{m} min {s:02} s")
    } else {
        format!("{s} s")
    }
}

/// Local time, `YYYY-MM-DD HH:MM`.
pub fn fmt_time(t: u64) -> String {
    match Local.timestamp_opt(t as i64, 0).single() {
        Some(d) => d.format("%Y-%m-%d %H:%M").to_string(),
        None => "-".into(),
    }
}

pub fn fmt_opt_time(t: Option<u64>, none: &str) -> String {
    t.map_or_else(|| none.to_string(), fmt_time)
}

#[cfg(all(test, unix))] // ipc tests (unix socket)
pub(crate) mod tests_support {
    pub fn session(id: u64) -> agent_ui_proto::Session {
        super::tests::sess(id, agent_ui_proto::SessionResult::Success, 1024, 60)
    }
}

/// One line about a standalone job: queued, waiting, last failure, last success or never run.
pub fn job_state(j: &agent_ui_proto::Job) -> String {
    let next = j.next.map(|n| format!(" · next {}", fmt_time(n))).unwrap_or_default();
    if j.queued {
        return "Starting now".into();
    }
    if let Some(w) = &j.waiting {
        return format!("Waiting: {w}");
    }
    match (&j.last_error, j.last_ok) {
        (Some(e), _) => format!("Last run failed: {e}{next}"),
        (None, Some(t)) => format!("Last backup {}{next}", fmt_time(t)),
        (None, None) => format!("Not run yet{next}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_ui_proto::{Running, SessionKind};

    fn status() -> Status {
        Status {
            agent_id: "a1".into(),
            enrolled: true,
            version: "0.1.0".into(),
            reachable: true,
            ..Default::default()
        }
    }

    pub(crate) fn sess(id: u64, result: SessionResult, bytes: u64, secs: u64) -> Session {
        Session {
            id,
            kind: SessionKind::Backup,
            started: 1_700_000_000 + id * 86_400,
            ended: 1_700_000_000 + id * 86_400 + secs,
            result,
            read_bytes: bytes * 2,
            transferred_bytes: bytes,
            new_bytes: bytes / 2,
            warnings: 0,
            first_error: None,
            snapshot_time: None,
        }
    }

    #[test]
    fn tray_state_mapping() {
        let st = status();
        assert!(matches!(TrayState::from_snapshot(Err("refused"), &[]), TrayState::NoService(e) if e == "refused"));
        let mut s = st.clone();
        s.enrolled = false;
        assert_eq!(TrayState::from_snapshot(Ok(&s), &[]), TrayState::NoJob);
        assert_eq!(TrayState::from_snapshot(Ok(&st), &[]), TrayState::NoJob);
        let mut s = st.clone();
        s.next_run = Some(5);
        assert_eq!(
            TrayState::from_snapshot(Ok(&s), &[]),
            TrayState::Waiting { next_run: Some(5) }
        );

        let failed = [
            sess(2, SessionResult::Failed, 1, 1),
            sess(1, SessionResult::Success, 1, 1),
        ];
        assert_eq!(TrayState::from_snapshot(Ok(&st), &failed), TrayState::Error);
        let mut restore = sess(3, SessionResult::Failed, 1, 1);
        restore.kind = SessionKind::Restore;
        let ok = [restore, sess(1, SessionResult::Success, 1, 1)];
        assert_eq!(
            TrayState::from_snapshot(Ok(&st), &ok),
            TrayState::Success,
            "restores do not count"
        );
        assert_eq!(
            TrayState::from_snapshot(Ok(&st), &[sess(1, SessionResult::Warning, 1, 1)]),
            TrayState::Warning
        );
        assert_eq!(
            TrayState::from_snapshot(Ok(&st), &[sess(1, SessionResult::Cancelled, 1, 1)]),
            TrayState::Cancelled
        );

        // running beats unreachable (the appliance is obviously connected), unreachable
        // beats requested (the request waits for the next poll)
        let mut s = st.clone();
        s.reachable = false;
        s.last_seen_by_appliance = Some(9);
        s.state = AgentState::Requested;
        assert_eq!(
            TrayState::from_snapshot(Ok(&s), &failed),
            TrayState::NotReached { since: Some(9) }
        );
        s.reachable = true;
        assert_eq!(TrayState::from_snapshot(Ok(&s), &failed), TrayState::Requested);
        s.state = AgentState::Running;
        s.running = Some(Running {
            started: 1,
            percent: Some(42),
            read_bytes: 0,
            transferred_bytes: 2048,
        });
        assert_eq!(
            TrayState::from_snapshot(Ok(&s), &failed),
            TrayState::Running {
                percent: Some(42),
                transferred: 2048
            }
        );
    }

    #[test]
    fn badges_and_tooltips() {
        assert_eq!(TrayState::Success.badge(), Badge::Check);
        assert_eq!(TrayState::Error.badge(), Badge::Cross);
        assert_eq!(TrayState::NoService(String::new()).badge(), Badge::Offline);
        assert_eq!(TrayState::NotReached { since: None }.badge(), Badge::Offline);
        assert_eq!(TrayState::Requested.badge(), Badge::Clock);

        let mut st = status();
        st.ui_policy.header = Some("ACME IT backup".into());
        let t = tooltip(
            &TrayState::Running {
                percent: Some(42),
                transferred: 3 * 1024 * 1024,
            },
            Some(&st),
        );
        assert_eq!(t, "ACME IT backup\nBackup running (42 %)\n3.0 MiB transferred");
        st.next_run = Some(1_700_000_000);
        let t = tooltip(&TrayState::Success, Some(&st));
        assert!(
            t.starts_with("ACME IT backup\nLast backup succeeded\nNext backup: 2023-11-1"),
            "{t}"
        );
        st.ui_policy.header = Some("x".repeat(200));
        assert!(tooltip(&TrayState::Success, Some(&st)).chars().count() <= 127);
        assert!(tooltip(&TrayState::NoService("e".into()), None).starts_with(PRODUCT));
    }

    #[test]
    fn policy_and_branding() {
        let mut st = status();
        assert!(backup_now_visible(Some(&st)) && backup_now_enabled(Some(&st)));
        st.state = AgentState::Requested;
        assert!(backup_now_visible(Some(&st)) && !backup_now_enabled(Some(&st)));
        st.state = AgentState::Idle;
        st.ui_policy.hide_backup_now = true;
        assert!(!backup_now_visible(Some(&st)) && !backup_now_enabled(Some(&st)));
        assert!(!backup_now_visible(None));
        assert!(tray_visible(None) && tray_visible(Some(&st)));
        st.ui_policy.hide_tray = true;
        assert!(!tray_visible(Some(&st)));

        assert_eq!(header_title(&UiPolicy::default()), PRODUCT);
        let p = UiPolicy {
            header: Some("  ".into()),
            ..Default::default()
        };
        assert_eq!(header_title(&p), PRODUCT);
        assert_eq!(parse_accent("#0a7"), Some([0, 0xaa, 0x77]));
        assert_eq!(parse_accent(" #2ec4b2 "), Some([0x2e, 0xc4, 0xb2]));
        for bad in ["2ec4b2", "#2ec4b", "#zzzzzz", "#+1+2+3", ""] {
            assert_eq!(parse_accent(bad), None, "{bad}");
        }
    }

    #[test]
    fn chart_scaling() {
        assert!(chart_bars(&[], Metric::Transferred).is_empty());
        // newest first in, oldest left out
        let s = [
            sess(3, SessionResult::Success, 1000, 10),
            sess(2, SessionResult::Failed, 0, 40),
            sess(1, SessionResult::Warning, 500, 20),
        ];
        let b = chart_bars(&s, Metric::Transferred);
        assert_eq!(b.iter().map(|b| b.id).collect::<Vec<_>>(), [1, 2, 3]);
        assert_eq!(b[0].height, 0.5);
        assert_eq!(b[1].height, MIN_BAR, "empty sessions stay visible");
        assert_eq!(b[2].height, 1.0);
        assert_eq!(b[1].result, SessionResult::Failed);
        let b = chart_bars(&s, Metric::Duration);
        assert_eq!(b.iter().map(|b| b.height).collect::<Vec<_>>(), [0.5, 1.0, 0.25]);
        // all zero: no division by zero
        let z = [sess(1, SessionResult::Failed, 0, 0)];
        assert_eq!(chart_bars(&z, Metric::Transferred)[0].height, MIN_BAR);
        // at most 30 bars, the newest ones
        let many: Vec<Session> = (1..=40).rev().map(|i| sess(i, SessionResult::Success, i, i)).collect();
        let b = chart_bars(&many, Metric::Transferred);
        assert_eq!(b.len(), CHART_SESSIONS);
        assert_eq!((b[0].id, b[29].id), (11, 40));
    }

    #[test]
    fn notifications_only_for_new_problems() {
        let s = [
            sess(3, SessionResult::Success, 1, 1),
            sess(2, SessionResult::Failed, 1, 1),
            sess(1, SessionResult::Warning, 1, 1),
        ];
        assert_eq!(notification(None, &s), None, "nothing at login");
        assert_eq!(notification(Some(3), &s), None);
        assert_eq!(notification(Some(2), &s), None, "the new one succeeded");
        let (title, _) = notification(Some(1), &s).unwrap();
        assert_eq!(title, "Backup failed");
        let mut w = sess(4, SessionResult::Warning, 1, 1);
        w.warnings = 3;
        let (title, body) = notification(Some(3), &[w]).unwrap();
        assert_eq!(title, "Backup finished with warnings");
        assert!(body.ends_with("3 warning(s)"));
    }

    #[test]
    fn formatting() {
        assert_eq!(fmt_bytes(512), "512 B");
        assert_eq!(fmt_bytes(1536), "1.5 KiB");
        assert_eq!(fmt_bytes(5 * 1024 * 1024 * 1024), "5.0 GiB");
        assert_eq!(fmt_duration(42), "42 s");
        assert_eq!(fmt_duration(65), "1 min 05 s");
        assert_eq!(fmt_duration(3720), "1 h 02 min");
        assert_eq!(fmt_opt_time(None, "never"), "never");
        assert_eq!(result_symbol(SessionResult::Failed), "X");
        let s = sess(1, SessionResult::Success, 2048, 65);
        assert!(session_summary(&s).starts_with("Success · "));
        assert!(session_summary(&s).ends_with("· 1 min 05 s · 2.0 KiB transferred"));
    }
}
