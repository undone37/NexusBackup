//! Endpoint status for the local UIs (docs/endpoint-ui.md, crate `agent-ui-proto`).
//!
//! The appliance pushes session summaries and its view (next run, UI policy) over
//! the mTLS session (`SessionSummary`, `Poll`, protocol v1.4); the service keeps
//! them in `<state>/ui-state.json` (root only) and answers the local IPC requests
//! (`status`, `sessions`, `session`, `request_backup`) from memory. A "back up now"
//! request is only queued here: the appliance picks it up with its next `Poll`
//! (the agent never connects out to the appliance; with an edge proxy it tells the
//! edge at once, crate::edge, so that poll comes within seconds) and acknowledges it
//! in the poll after that.

use crate::config::{write_atomic, Paths};
use crate::server::{log, Agent, Mode, Platform};
use agent_proto::{ApplianceStatus, BackupRequest, Message, PowerState, SessionKind, SessionResult, Summary};
use agent_ui_proto as ui;
use serde::{Deserialize, Serialize};
use std::sync::Mutex;

/// The appliance counts as reaching us while its last session is at most this old
/// (poll interval 2 min, backoff while unreachable).
pub const REACHABLE_SECS: u64 = 600;
/// A request the appliance has not acknowledged for this long is dropped.
pub const REQUEST_TTL_SECS: u64 = 7 * 86_400;

#[derive(Serialize, Deserialize, Default, Clone, Debug, PartialEq)]
struct State {
    /// newest first, ≤ MAX_SESSIONS
    sessions: Vec<Summary>,
    appliance: Option<ApplianceStatus>,
    /// last mTLS session opened by the appliance
    last_seen: Option<u64>,
    /// "back up now" requests not yet acknowledged
    requests: Vec<BackupRequest>,
    /// time of the last accepted request (rate limit)
    last_request: Option<u64>,
}

/// Progress of the running backup (in memory only).
#[derive(Clone, Copy, Debug, Default)]
struct Progress {
    started: u64,
    read: u64,
    transferred: u64,
    jobs: u32,
}

pub struct Ui {
    path: std::path::PathBuf,
    state: Mutex<State>,
    progress: Mutex<Option<Progress>>,
    /// told about every accepted request (edge rendezvous, crate::edge)
    waker: Mutex<Option<std::sync::mpsc::Sender<()>>>,
}

pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

fn random_id() -> String {
    format!("{:016x}", crate::chunk::rand_u64())
}

/// Wire policy → IPC policy (empty strings = unset).
pub fn ui_policy(p: &agent_proto::UiPolicy) -> ui::UiPolicy {
    let opt = |s: &str| Some(s.to_string()).filter(|s| !s.is_empty());
    ui::UiPolicy {
        accent: opt(&p.accent),
        header: opt(&p.header),
        hide_backup_now: p.hide_backup_now,
        hide_tray: p.hide_tray,
    }
}

/// Wire summary → IPC session.
pub fn session(s: &Summary) -> ui::Session {
    ui::Session {
        id: s.job,
        kind: match s.kind {
            SessionKind::Backup => ui::SessionKind::Backup,
            SessionKind::Restore => ui::SessionKind::Restore,
        },
        started: s.started,
        ended: s.ended,
        result: match s.result {
            SessionResult::Success => ui::SessionResult::Success,
            SessionResult::Warning => ui::SessionResult::Warning,
            SessionResult::Failed => ui::SessionResult::Failed,
            SessionResult::Cancelled => ui::SessionResult::Cancelled,
        },
        read_bytes: s.read_bytes,
        transferred_bytes: s.transferred_bytes,
        new_bytes: s.new_bytes,
        warnings: s.warnings,
        first_error: Some(s.first_error.clone()).filter(|e| !e.is_empty()),
        snapshot_time: s.snapshot_time,
    }
}

impl Ui {
    /// Loads the state file (a missing or unreadable one starts empty).
    pub fn load(paths: &Paths) -> Ui {
        let path = paths.ui_state();
        let state = std::fs::read(&path)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default();
        Ui {
            path,
            state: Mutex::new(state),
            progress: Mutex::new(None),
            waker: Mutex::new(None),
        }
    }

    /// Notified after every accepted "back up now" request.
    pub fn set_waker(&self, tx: std::sync::mpsc::Sender<()>) {
        *lock(&self.waker) = Some(tx);
    }

    fn save(&self, st: &State) {
        let body = serde_json::to_vec(st).unwrap_or_default();
        if let Err(e) = write_atomic(&self.path, &body, 0o600) {
            log(format!("{}: {e}", self.path.display()));
        }
    }

    /// Any mTLS session of the appliance.
    pub fn seen(&self, now: u64) {
        let mut st = lock(&self.state);
        st.last_seen = Some(now);
        self.save(&st);
    }

    /// `SessionSummary`: stored (replacing an earlier one of the same job), capped.
    pub fn record_summary(&self, mut summary: Summary, status: ApplianceStatus, now: u64) {
        summary.log_tail.truncate(ui::MAX_LOG_TAIL);
        let mut st = lock(&self.state);
        st.sessions.retain(|s| s.job != summary.job);
        st.sessions.insert(0, summary);
        st.sessions
            .sort_by(|a, b| b.ended.cmp(&a.ended).then(b.job.cmp(&a.job)));
        st.sessions.truncate(ui::MAX_SESSIONS);
        st.appliance = Some(status);
        st.last_seen = Some(now);
        self.save(&st);
    }

    /// `Poll`: drop acknowledged (and stale) requests, store the appliance view,
    /// hand out the open requests.
    pub fn poll(&self, status: ApplianceStatus, ack: &[String], power: PowerState, now: u64) -> Message {
        let busy = lock(&self.progress).is_some();
        let mut st = lock(&self.state);
        st.requests
            .retain(|r| !ack.contains(&r.id) && r.queued_at + REQUEST_TTL_SECS > now);
        let policy_version = status.policy_version;
        st.appliance = Some(status);
        st.last_seen = Some(now);
        self.save(&st);
        Message::PollReply {
            requests: st.requests.iter().take(agent_proto::MAX_REQUESTS).cloned().collect(),
            power,
            policy_version,
            busy,
        }
    }

    /// `request_backup` from a local user: refused when hidden by policy or within
    /// the rate limit; persisted until the appliance acknowledges it.
    pub fn request_backup(&self, now: u64) -> Result<ui::Requested, String> {
        let mut st = lock(&self.state);
        if st.appliance.as_ref().is_some_and(|a| a.ui_policy.hide_backup_now) {
            return Err("backup requests are disabled by the administrator".into());
        }
        if let Some(last) = st.last_request.filter(|l| now < l + ui::REQUEST_INTERVAL_SECS) {
            let left = (last + ui::REQUEST_INTERVAL_SECS - now).div_ceil(60);
            return Err(format!("a backup was requested recently; try again in {left} min"));
        }
        let r = BackupRequest {
            id: random_id(),
            queued_at: now,
        };
        st.requests.push(r.clone());
        let n = st.requests.len();
        if n > agent_proto::MAX_REQUESTS {
            st.requests.drain(..n - agent_proto::MAX_REQUESTS);
        }
        st.last_request = Some(now);
        self.save(&st);
        log(format!("backup requested by a local user (request {})", r.id));
        drop(st);
        if let Some(w) = lock(&self.waker).as_ref() {
            let _ = w.send(());
        }
        Ok(ui::Requested {
            request_id: r.id,
            queued_at: now,
        })
    }

    /// A backup job was prepared (`Prepare`).
    pub fn job_started(&self, now: u64) {
        let mut p = lock(&self.progress);
        match p.as_mut() {
            Some(p) => p.jobs += 1,
            None => {
                *p = Some(Progress {
                    started: now,
                    jobs: 1,
                    ..Default::default()
                })
            }
        }
    }

    pub fn job_progress(&self, read: u64, transferred: u64) {
        if let Some(p) = lock(&self.progress).as_mut() {
            p.read += read;
            p.transferred += transferred;
        }
    }

    pub fn job_ended(&self) {
        let mut p = lock(&self.progress);
        if let Some(x) = p.as_mut() {
            x.jobs = x.jobs.saturating_sub(1);
            if x.jobs == 0 {
                *p = None;
            }
        }
    }

    /// `status` (identity fields are filled in by the caller).
    pub fn status(&self, now: u64) -> ui::Status {
        let st = lock(&self.state);
        let progress = *lock(&self.progress);
        let last_ok = st.sessions.iter().find(|s| {
            s.kind == SessionKind::Backup && matches!(s.result, SessionResult::Success | SessionResult::Warning)
        });
        let running = progress.map(|p| ui::Running {
            started: p.started,
            // estimate: the last successful backup read about as much
            percent: last_ok
                .filter(|s| s.read_bytes > 0)
                .map(|s| (p.read.saturating_mul(100) / s.read_bytes).min(99) as u8),
            read_bytes: p.read,
            transferred_bytes: p.transferred,
        });
        let state = if running.is_some() {
            ui::AgentState::Running
        } else if !st.requests.is_empty() {
            ui::AgentState::Requested
        } else if st
            .sessions
            .iter()
            .find(|s| s.kind == SessionKind::Backup)
            .is_some_and(|s| s.result == SessionResult::Failed)
        {
            ui::AgentState::Error
        } else {
            ui::AgentState::Idle
        };
        let app = st.appliance.as_ref();
        ui::Status {
            managed_by: app.map(|a| a.appliance.clone()).filter(|a| !a.is_empty()),
            state,
            running,
            last_success: last_ok.map(|s| s.ended),
            next_run: app.and_then(|a| a.next_run),
            last_seen_by_appliance: st.last_seen,
            reachable: st.last_seen.is_some_and(|t| now.saturating_sub(t) <= REACHABLE_SECS),
            ui_policy: app.map(|a| ui_policy(&a.ui_policy)).unwrap_or_default(),
            ..Default::default()
        }
    }

    pub fn sessions(&self, limit: Option<usize>) -> ui::Sessions {
        let st = lock(&self.state);
        let n = limit.unwrap_or(ui::MAX_SESSIONS).min(ui::MAX_SESSIONS);
        ui::Sessions {
            sessions: st.sessions.iter().take(n).map(session).collect(),
        }
    }

    pub fn session(&self, id: u64) -> Option<ui::SessionDetail> {
        let st = lock(&self.state);
        st.sessions.iter().find(|s| s.job == id).map(|s| ui::SessionDetail {
            session: session(s),
            log_tail: s.log_tail.iter().rev().take(ui::MAX_LOG_TAIL).rev().cloned().collect(),
        })
    }
}

impl<P: Platform> Agent<P> {
    /// One IPC request line → one reply line (`agent_ui_proto` framing).
    pub fn ui_request(&self, line: &str) -> String {
        let req = match ui::decode_request(line) {
            Ok(r) => r,
            Err(e) => return ui::encode_err(&e.to_string()),
        };
        let now = now();
        match req {
            ui::Request::Status => ui::encode_ok(&self.ui_status(now)),
            ui::Request::Sessions { limit } => ui::encode_ok(&self.ui.sessions(limit)),
            ui::Request::Session { id } => match self.ui.session(id) {
                Some(d) => ui::encode_ok(&d),
                None => ui::encode_err(&format!("no session {id}")),
            },
            ui::Request::RequestBackup => {
                if !matches!(self.mode(), Mode::Mtls { .. }) {
                    return ui::encode_err("this agent is not enrolled with an appliance yet");
                }
                match self.ui.request_backup(now) {
                    Ok(r) => ui::encode_ok(&r),
                    Err(e) => ui::encode_err(&e),
                }
            }
        }
    }

    pub fn ui_status(&self, now: u64) -> ui::Status {
        let mut s = self.ui.status(now);
        if let Mode::Mtls { agent_id, .. } = self.mode() {
            s.agent_id = agent_id;
            s.enrolled = true;
        }
        s.version = self.platform.host_info().agent_version;
        s.appliance = self.settings.appliance_id.clone().or_else(|| {
            let pem = std::fs::read_to_string(self.paths.ca()).ok()?;
            let der = crate::tls::certs_from_pem(&pem).ok()?.into_iter().next()?;
            Some(crate::tls::fingerprint(&der)[..16].to_string())
        });
        s
    }
}

/// Linux: the IPC socket (`/run/nexus-agent/ui.sock`, owner root, group
/// [`ui::SOCKET_GROUP`] if it exists, mode 0660; the run directory must allow
/// traversal: 0711). One thread per connection, at most `MAX_UI_CONNECTIONS`.
#[cfg(unix)]
pub mod unix {
    use super::*;
    use std::io::{BufReader, Write};
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::path::Path;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    pub const MAX_UI_CONNECTIONS: usize = 8;

    /// gid of a group (None if it does not exist).
    pub fn group_id(name: &str) -> Option<u32> {
        let c = std::ffi::CString::new(name).ok()?;
        let mut grp: libc::group = unsafe { std::mem::zeroed() };
        let mut buf = vec![0 as libc::c_char; 16 << 10];
        let mut out: *mut libc::group = std::ptr::null_mut();
        // SAFETY: valid pointers and buffer length; getgrnam_r is reentrant.
        let rc = unsafe { libc::getgrnam_r(c.as_ptr(), &mut grp, buf.as_mut_ptr(), buf.len(), &mut out) };
        (rc == 0 && !out.is_null()).then_some(grp.gr_gid)
    }

    /// Binds the socket (replacing a stale one) with the permissions above.
    pub fn bind(path: &Path, group: Option<u32>) -> std::io::Result<UnixListener> {
        let _ = std::fs::remove_file(path);
        let l = UnixListener::bind(path)?;
        if let Some(gid) = group {
            std::os::unix::fs::chown(path, None, Some(gid))?;
        }
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))?;
        Ok(l)
    }

    /// Accept loop (run it on its own thread).
    pub fn serve<P: Platform>(agent: Arc<Agent<P>>, l: UnixListener) {
        let active = Arc::new(AtomicUsize::new(0));
        for conn in l.incoming() {
            let Ok(s) = conn else { continue };
            if active.fetch_add(1, Ordering::SeqCst) >= MAX_UI_CONNECTIONS {
                active.fetch_sub(1, Ordering::SeqCst);
                continue;
            }
            let (agent, active) = (agent.clone(), active.clone());
            std::thread::spawn(move || {
                let _ = handle(&agent, s);
                active.fetch_sub(1, Ordering::SeqCst);
            });
        }
    }

    fn handle<P: Platform>(agent: &Agent<P>, s: UnixStream) -> std::io::Result<()> {
        s.set_read_timeout(Some(Duration::from_secs(300)))?;
        s.set_write_timeout(Some(Duration::from_secs(30)))?;
        let mut r = BufReader::new(s.try_clone()?);
        let mut w = s;
        while let Some(line) = ui::read_line(&mut r)? {
            w.write_all(agent.ui_request(&line).as_bytes())?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn paths(d: &std::path::Path) -> Paths {
        Paths {
            config: d.join("c"),
            state: d.to_path_buf(),
            run: d.to_path_buf(),
        }
    }

    fn summary(job: u64, ended: u64, result: SessionResult) -> Summary {
        Summary {
            job,
            kind: SessionKind::Backup,
            started: ended - 10,
            ended,
            result,
            read_bytes: 1000,
            transferred_bytes: 10,
            new_bytes: 5,
            warnings: 0,
            first_error: String::new(),
            snapshot_time: Some(ended),
            log_tail: (0..300).map(|i| format!("line {i}")).collect(),
        }
    }

    fn status(hide: bool) -> ApplianceStatus {
        ApplianceStatus {
            appliance: "nexus01".into(),
            now: 0,
            next_run: Some(99_999),
            ui_policy: agent_proto::UiPolicy {
                hide_backup_now: hide,
                ..Default::default()
            },
            policy_version: 2,
        }
    }

    #[test]
    fn summaries_stored_capped_and_persisted() {
        let d = tempfile::tempdir().unwrap();
        let u = Ui::load(&paths(d.path()));
        for j in 1..=120 {
            u.record_summary(summary(j, 1000 + j, SessionResult::Success), status(false), 5000);
        }
        // the same job again replaces its entry
        u.record_summary(summary(120, 1120, SessionResult::Failed), status(false), 5000);
        let u = Ui::load(&paths(d.path()));
        let s = u.sessions(None).sessions;
        assert_eq!(s.len(), ui::MAX_SESSIONS);
        assert_eq!((s[0].id, s[0].result), (120, ui::SessionResult::Failed));
        assert_eq!(s.last().unwrap().id, 21);
        assert_eq!(u.sessions(Some(3)).sessions.len(), 3);
        let d120 = u.session(120).unwrap();
        assert_eq!(d120.log_tail.len(), ui::MAX_LOG_TAIL);
        assert!(u.session(1).is_none());
        let st = u.status(5100);
        assert_eq!(st.state, ui::AgentState::Error);
        assert_eq!(st.last_success, Some(1119));
        assert_eq!((st.next_run, st.reachable), (Some(99_999), true));
        assert!(!u.status(5000 + REACHABLE_SECS + 1).reachable);
        assert_eq!(st.managed_by.as_deref(), Some("nexus01"));
    }

    #[test]
    fn requests_rate_limited_policy_gated_and_acked() {
        let d = tempfile::tempdir().unwrap();
        let u = Ui::load(&paths(d.path()));
        let r = u.request_backup(1000).unwrap();
        assert_eq!(u.status(1000).state, ui::AgentState::Requested);
        let e = u.request_backup(1000 + 60).unwrap_err();
        assert!(e.contains("try again in 9 min"), "{e}");
        // persisted across restarts, handed out until acknowledged
        let u = Ui::load(&paths(d.path()));
        let Message::PollReply {
            requests,
            policy_version,
            ..
        } = u.poll(status(false), &[], PowerState::default(), 1100)
        else {
            unreachable!()
        };
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].id, r.request_id);
        assert_eq!(policy_version, 2);
        let Message::PollReply { requests, .. } = u.poll(
            status(false),
            std::slice::from_ref(&r.request_id),
            PowerState::default(),
            1200,
        ) else {
            unreachable!()
        };
        assert!(requests.is_empty());
        assert_eq!(u.status(1200).state, ui::AgentState::Idle);
        assert!(u.request_backup(1000 + ui::REQUEST_INTERVAL_SECS).is_ok());
        // hidden by policy
        u.poll(status(true), &[], PowerState::default(), 3000);
        assert!(u.request_backup(5000).unwrap_err().contains("disabled"));
    }

    #[test]
    fn progress_while_running() {
        let d = tempfile::tempdir().unwrap();
        let u = Ui::load(&paths(d.path()));
        u.record_summary(summary(1, 100, SessionResult::Success), status(false), 100);
        u.job_started(200);
        u.job_progress(500, 20);
        let st = u.status(210);
        assert_eq!(st.state, ui::AgentState::Running);
        let r = st.running.unwrap();
        assert_eq!(
            (r.started, r.percent, r.read_bytes, r.transferred_bytes),
            (200, Some(50), 500, 20)
        );
        assert!(matches!(
            u.poll(status(false), &[], PowerState::default(), 220),
            Message::PollReply { busy: true, .. }
        ));
        u.job_ended();
        assert!(u.status(230).running.is_none());
    }

    #[cfg(unix)]
    #[test]
    fn socket_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("ui.sock");
        std::fs::write(&p, b"stale").unwrap();
        let gid = unsafe { libc::getgid() };
        let _l = unix::bind(&p, Some(gid)).unwrap();
        let m = std::fs::metadata(&p).unwrap();
        assert_eq!(m.permissions().mode() & 0o777, 0o660);
        assert_eq!(std::os::unix::fs::MetadataExt::gid(&m), gid);
        assert!(unix::group_id("root").is_some());
        assert!(unix::group_id("no-such-group-nexus").is_none());
    }
}
