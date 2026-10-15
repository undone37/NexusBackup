//! End-user view of the agent (docs/endpoint-ui.md): `nexus-agent tui` and the scriptable
//! `status` / `sessions` / `session` / `request-backup` commands. Everything comes from the
//! agent service's local socket (`proto`); nothing here reads agent files or talks to the
//! appliance.

pub mod cli;
pub mod tui;

pub use agent_ui_proto as proto;

use proto::{Client, Error, SessionResult};
use std::io::ErrorKind;
use std::path::Path;

/// Exit codes of the end-user commands (documented in docs/agent-linux.md).
pub mod exit {
    pub const OK: u8 = 0;
    /// usage error, invalid answer, anything unexpected
    pub const ERROR: u8 = 1;
    /// the socket exists but this user may not use it (not in `nexus-agent-ui`)
    pub const PERMISSION: u8 = 2;
    /// the agent service is not running (no socket / connection refused)
    pub const NOT_RUNNING: u8 = 3;
    /// the agent answered with an error: request refused (policy, rate limit), unknown session
    pub const REFUSED: u8 = 4;
}

/// A user-facing error with its exit code.
#[derive(Debug)]
pub struct Failure {
    pub code: u8,
    pub message: String,
}

pub fn failure(sock: &Path, e: Error) -> Failure {
    match e {
        Error::Io(e) if e.kind() == ErrorKind::PermissionDenied => Failure {
            code: exit::PERMISSION,
            message: format!(
                "permission denied on {}: add your user to the group {} \
                 (sudo usermod -aG {} $USER, then log in again) or run as root",
                sock.display(),
                proto::SOCKET_GROUP,
                proto::SOCKET_GROUP
            ),
        },
        Error::Io(e) if matches!(e.kind(), ErrorKind::NotFound | ErrorKind::ConnectionRefused) => Failure {
            code: exit::NOT_RUNNING,
            message: format!(
                "the agent service is not running ({}: {e}); check `systemctl status nexus-agent`",
                sock.display()
            ),
        },
        Error::Refused(e) => Failure {
            code: exit::REFUSED,
            message: e,
        },
        Error::Io(e) => Failure {
            code: exit::ERROR,
            message: format!("{}: {e}", sock.display()),
        },
    }
}

pub fn connect(sock: &Path) -> Result<Client, Failure> {
    Client::connect(sock).map_err(|e| failure(sock, Error::Io(e)))
}

/// How timestamps are shown: the host's local time, or UTC (tests, screenshots).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Clock {
    Local,
    Utc,
}

impl Clock {
    /// `2026-10-13 14:05`
    pub fn fmt(self, t: u64) -> String {
        let t = t as i64;
        let off = match self {
            Clock::Utc => 0,
            Clock::Local => local_offset(t),
        };
        let t = t + off;
        let (days, secs) = (t.div_euclid(86400), t.rem_euclid(86400));
        let (y, m, d) = civil(days);
        format!("{y:04}-{m:02}-{d:02} {:02}:{:02}", secs / 3600, secs % 3600 / 60)
    }

    pub fn fmt_opt(self, t: Option<u64>, none: &str) -> String {
        t.map_or_else(|| none.to_string(), |t| self.fmt(t))
    }
}

fn local_offset(t: i64) -> i64 {
    let tt = t as libc::time_t;
    // SAFETY: libc::tm is plain C data (integers and a pointer); all-zero is a valid value.
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    // SAFETY: `tt` and `tm` are valid, exclusive locals for the call; localtime_r is the reentrant variant and writes
    // only into `tm`.
    if unsafe { libc::localtime_r(&tt, &mut tm) }.is_null() {
        return 0;
    }
    tm.tm_gmtoff
}

/// days since 1970-01-01 → (year, month, day) (H. Hinnant's civil_from_days)
fn civil(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (yoe + era * 400 + i64::from(m <= 2), m, d)
}

pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Seconds from `a` to `b` (0 if `b` is earlier).
pub fn secs(a: u64, b: u64) -> i64 {
    b.saturating_sub(a) as i64
}

/// `1.5 GiB`
pub fn bytes(n: u64) -> String {
    const U: [&str; 6] = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1024.0 && i < U.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{n} B")
    } else {
        format!("{v:.1} {}", U[i])
    }
}

/// `1:02:03` / `12:34`
pub fn duration(secs: i64) -> String {
    let s = secs.max(0);
    if s >= 3600 {
        format!("{}:{:02}:{:02}", s / 3600, s % 3600 / 60, s % 60)
    } else {
        format!("{}:{:02}", s / 60, s % 60)
    }
}

/// Processing rate (bytes read per second), like Veeam's "Processing rate".
pub fn rate(read: u64, secs: i64) -> String {
    if secs <= 0 {
        return "-".into();
    }
    format!("{}/s", bytes(read / secs as u64))
}

/// Text label and short glyph of a result: never colour only.
pub fn result_label(r: SessionResult) -> (&'static str, &'static str) {
    match r {
        SessionResult::Success => ("[+]", "Success"),
        SessionResult::Warning => ("[!]", "Warning"),
        SessionResult::Failed => ("[x]", "Failed"),
        SessionResult::Cancelled => ("[-]", "Cancelled"),
    }
}

pub fn state_label(s: &proto::Status) -> String {
    use proto::AgentState as A;
    match s.state {
        _ if !s.enrolled => "Not enrolled".into(),
        A::Idle => "Idle".into(),
        A::Running => "Backup running".into(),
        A::Requested => "Backup requested (waiting for the appliance)".into(),
        A::Error => "Last backup failed".into(),
    }
}

/// "reachable" or "not reached since …"
pub fn reach_label(s: &proto::Status, clock: Clock) -> String {
    if s.reachable {
        "reachable".into()
    } else {
        format!("not reached since {}", clock.fmt_opt(s.last_seen_by_appliance, "never"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats() {
        assert_eq!(Clock::Utc.fmt(0), "1970-01-01 00:00");
        assert_eq!(Clock::Utc.fmt(1_791_900_300), "2026-10-13 14:05");
        assert_eq!(Clock::Utc.fmt(951_782_400), "2000-02-29 00:00");
        assert_eq!(bytes(512), "512 B");
        assert_eq!(bytes(1536), "1.5 KiB");
        assert_eq!(bytes(5 << 30), "5.0 GiB");
        assert_eq!(duration(754), "12:34");
        assert_eq!(duration(3723), "1:02:03");
        assert_eq!(rate(100 << 20, 10), "10.0 MiB/s");
        assert_eq!(rate(1, 0), "-");
    }
}
