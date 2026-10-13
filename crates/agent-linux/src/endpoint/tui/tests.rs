//! Rendering snapshots (80x24, monochrome, UTC). The text dumps in `snapshots/` are also the
//! screenshots of manual/04-sources.md; regenerate with `UPDATE_SNAPSHOTS=1 cargo test -p
//! agent-linux endpoint` and copy changed screens into the manual.

use super::*;
use crate::endpoint::proto::{AgentState, Running, SessionKind, SessionResult, UiPolicy};
use ratatui::backend::TestBackend;
use ratatui::Terminal;

const T0: u64 = 1_791_900_300; // 2026-10-13 14:05 UTC

fn status() -> Status {
    Status {
        agent_id: "web01".into(),
        appliance: Some("3f9a1c22".into()),
        managed_by: Some("nexus01.example.com".into()),
        enrolled: true,
        version: "0.6.0".into(),
        state: AgentState::Idle,
        running: None,
        last_success: Some(T0 - 12 * 3600),
        next_run: Some(T0 + 8 * 3600 - 300),
        last_seen_by_appliance: Some(T0 - 60),
        reachable: true,
        ui_policy: UiPolicy::default(),
    }
}

fn session(id: u64, days: u64, result: SessionResult, warnings: u32) -> Session {
    let started = T0 - 12 * 3600 - days * 86400;
    Session {
        id,
        kind: SessionKind::Backup,
        started,
        ended: started + 754 + id % 7 * 31,
        result,
        read_bytes: 48 << 30,
        transferred_bytes: (1 << 30) + id % 7 * (37 << 20),
        new_bytes: 700 << 20,
        warnings,
        first_error: (result == SessionResult::Failed).then(|| "connection to the appliance lost".into()),
        snapshot_time: (result != SessionResult::Failed).then_some(started),
    }
}

fn sessions() -> Vec<Session> {
    use SessionResult::*;
    vec![
        session(1207, 0, Success, 0),
        session(1188, 1, Warning, 2),
        session(1170, 2, Success, 0),
        session(1152, 3, Failed, 0),
        session(1139, 4, Success, 0),
        session(1121, 5, Cancelled, 0),
        session(1104, 6, Success, 0),
    ]
}

fn app() -> App {
    let mut a = App::new(Clock::Utc, false);
    a.now = T0;
    a.status = Some(status());
    a.sessions = sessions();
    a
}

fn detail() -> SessionDetail {
    SessionDetail {
        session: session(1188, 1, SessionResult::Warning, 2),
        log_tail: vec![
            "13:52:10 job 1188 started (policy daily-files)".into(),
            "13:52:11 snapshot: LVM thin vg0/root".into(),
            "13:52:40 warning: /home/anna/.cache/x: file vanished".into(),
            "13:58:02 warning: /srv/db.sock: socket skipped".into(),
            "14:04:44 48.0 GiB read, 1.7 GiB transferred".into(),
            "14:04:45 snapshot released, job finished with 2 warnings".into(),
        ],
    }
}

fn dump(a: &App) -> String {
    let mut t = Terminal::new(TestBackend::new(80, 24)).unwrap();
    t.draw(|f| a.render(f)).unwrap();
    let b = t.backend().buffer();
    let mut out = String::new();
    for y in 0..b.area.height {
        let line: String = (0..b.area.width).map(|x| b[(x, y)].symbol()).collect();
        out.push_str(line.trim_end());
        out.push('\n');
    }
    out
}

fn check(name: &str, a: &App) {
    let got = dump(a);
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(format!("src/endpoint/snapshots/{name}.txt"));
    if std::env::var_os("UPDATE_SNAPSHOTS").is_some() {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, &got).unwrap();
        return;
    }
    let want = std::fs::read_to_string(&path).unwrap_or_default();
    assert_eq!(
        got, want,
        "snapshot {name} differs (UPDATE_SNAPSHOTS=1 to accept):\n{got}"
    );
}

#[test]
fn main_screen() {
    let a = app();
    check("main", &a);
    let d = dump(&a);
    assert!(d.contains("Latest backup sessions") && d.contains("[!] Warning") && d.contains("[x] Failed"));
    assert!(d.contains(" S  Back up now"));
}

#[test]
fn detail_screen() {
    let mut a = app();
    a.view = View::Detail(detail());
    check("detail", &a);
    let d = dump(&a);
    assert!(d.contains("Session 1188 (backup)") && d.contains("Transferred") && d.contains("socket skipped"));
}

#[test]
fn log_screen() {
    let mut a = app();
    a.view = View::Log {
        detail: detail(),
        scroll: 0,
    };
    check("log", &a);
}

#[test]
fn confirm_and_requested() {
    let mut a = app();
    assert_eq!(a.key(KeyCode::Char('S'), KeyModifiers::SHIFT), Action::None);
    assert!(a.confirm);
    check("confirm", &a);
    assert_eq!(a.key(KeyCode::Char('y'), KeyModifiers::NONE), Action::RequestBackup);
    assert!(!a.confirm);
    // what the loop shows after a successful request
    a.status.as_mut().unwrap().state = AgentState::Requested;
    a.message = Some((
        false,
        "Backup requested at 2026-10-13 14:05; it starts at the appliance's next poll.".into(),
    ));
    check("requested", &a);
    assert!(dump(&a).contains("Backup requested (waiting for the appliance)"));
    // N cancels
    a.key(KeyCode::Char('s'), KeyModifiers::NONE);
    assert_eq!(a.key(KeyCode::Char('n'), KeyModifiers::NONE), Action::None);
    assert!(!a.confirm);
}

#[test]
fn running_backup() {
    let mut a = app();
    let s = a.status.as_mut().unwrap();
    s.state = AgentState::Running;
    s.running = Some(Running {
        started: T0 - 330,
        percent: Some(42),
        read_bytes: 20 << 30,
        transferred_bytes: 610 << 20,
    });
    check("running", &a);
    let d = dump(&a);
    assert!(d.contains("Running 42 %") && d.contains("read 20.0 GiB") && d.contains("(5:30)"));
    // first backup: no percentage, only the counters
    a.status.as_mut().unwrap().running.as_mut().unwrap().percent = None;
    let d = dump(&a);
    assert!(d.contains("Running  read 20.0 GiB") && !d.contains('%'));
}

#[test]
fn appliance_unreachable() {
    let mut a = app();
    let s = a.status.as_mut().unwrap();
    s.reachable = false;
    s.last_seen_by_appliance = Some(T0 - 3 * 86400);
    check("unreachable", &a);
    assert!(dump(&a).contains("not reached since 2026-10-10 14:05"));
}

#[test]
fn empty_and_policy() {
    let mut a = app();
    a.sessions.clear();
    let s = a.status.as_mut().unwrap();
    s.ui_policy.hide_backup_now = true;
    s.ui_policy.header = Some("ACME IT backup".into());
    s.last_success = None;
    check("empty", &a);
    let d = dump(&a);
    assert!(d.contains("No backup sessions yet") && d.contains("ACME IT backup") && !d.contains("Back up now"));
    // hidden "back up now": S does nothing
    a.key(KeyCode::Char('s'), KeyModifiers::NONE);
    assert!(!a.confirm);
}

#[test]
fn service_down() {
    let mut a = App::new(Clock::Utc, false);
    a.conn_error = Some("the agent service is not running (/run/nexus-agent/ui.sock: No such file or directory (os error 2)); check `systemctl status nexus-agent`".into());
    check("service-down", &a);
    assert_eq!(a.key(KeyCode::Char('r'), KeyModifiers::NONE), Action::Refresh);
    assert_eq!(a.key(KeyCode::Esc, KeyModifiers::NONE), Action::Quit);
}

#[test]
fn navigation() {
    let mut a = app();
    assert_eq!(a.key(KeyCode::Enter, KeyModifiers::NONE), Action::Open(1207));
    a.key(KeyCode::Down, KeyModifiers::NONE);
    a.key(KeyCode::Down, KeyModifiers::NONE);
    assert_eq!(a.key(KeyCode::Char('l'), KeyModifiers::NONE), Action::Log(1170));
    a.key(KeyCode::End, KeyModifiers::NONE);
    a.key(KeyCode::Down, KeyModifiers::NONE);
    assert_eq!(a.selected, 6);
    a.view = View::Detail(detail());
    assert_eq!(a.key(KeyCode::Char('r'), KeyModifiers::NONE), Action::Open(1188));
    a.key(KeyCode::Char('l'), KeyModifiers::NONE);
    assert!(matches!(a.view, View::Log { .. }));
    a.key(KeyCode::Esc, KeyModifiers::NONE);
    assert!(matches!(a.view, View::Detail(_)));
    a.key(KeyCode::Esc, KeyModifiers::NONE);
    assert!(matches!(a.view, View::Main));
    assert_eq!(a.key(KeyCode::Char('q'), KeyModifiers::NONE), Action::Quit);
    assert_eq!(a.key(KeyCode::Char('c'), KeyModifiers::CONTROL), Action::Quit);
}

#[test]
fn colour_does_not_change_text() {
    let mut a = app();
    let mono = dump(&a);
    a.color = true;
    assert_eq!(dump(&a), mono);
}
