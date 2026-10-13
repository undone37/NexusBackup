//! End-user commands (`status`, `sessions`, `session`, `request-backup`) against a fake
//! agent service on a temporary unix socket: output and exit codes (docs/agent-linux.md).

use agent_ui_proto::*;
use std::io::{BufReader, Write};
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::process::{Command, Output};

const T0: u64 = 1_791_900_300; // 2026-10-13 14:05 UTC

fn session(id: u64, result: SessionResult) -> Session {
    Session {
        id,
        kind: SessionKind::Backup,
        started: T0 - 3600,
        ended: T0 - 3600 + 754,
        result,
        read_bytes: 48 << 30,
        transferred_bytes: 3 << 29,
        new_bytes: 700 << 20,
        warnings: u32::from(result == SessionResult::Warning) * 2,
        first_error: None,
        snapshot_time: Some(T0 - 3600),
    }
}

/// Serves canned answers until the test ends; `request_backup` is refused after the first.
fn fake_service(path: &Path) {
    let l = UnixListener::bind(path).unwrap();
    std::thread::spawn(move || {
        let mut requested = false;
        for s in l.incoming() {
            let Ok(s) = s else { return };
            let mut r = BufReader::new(s.try_clone().unwrap());
            let mut w = s;
            while let Ok(Some(line)) = read_line(&mut r) {
                let reply = match decode_request(&line).unwrap() {
                    Request::Status => encode_ok(&Status {
                        agent_id: "web01".into(),
                        appliance: Some("3f9a1c22".into()),
                        managed_by: Some("nexus01".into()),
                        enrolled: true,
                        version: "0.6.0".into(),
                        state: AgentState::Running,
                        running: Some(Running {
                            started: T0 - 60,
                            percent: Some(42),
                            read_bytes: 1 << 30,
                            transferred_bytes: 1 << 20,
                        }),
                        last_success: Some(T0 - 86400),
                        next_run: None,
                        last_seen_by_appliance: Some(T0 - 7200),
                        reachable: false,
                        ui_policy: UiPolicy::default(),
                    }),
                    Request::Sessions { limit } => {
                        let all = vec![session(12, SessionResult::Warning), session(11, SessionResult::Failed)];
                        encode_ok(&Sessions {
                            sessions: all.into_iter().take(limit.unwrap_or(100)).collect(),
                        })
                    }
                    Request::Session { id: 12 } => encode_ok(&SessionDetail {
                        session: session(12, SessionResult::Warning),
                        log_tail: vec!["warning: /srv/db.sock: socket skipped".into()],
                    }),
                    Request::Session { .. } => encode_err("no such session"),
                    Request::RequestBackup if !requested => {
                        requested = true;
                        encode_ok(&Requested {
                            request_id: "r-1".into(),
                            queued_at: T0,
                        })
                    }
                    Request::RequestBackup => encode_err("rate limited: one request per 10 minutes"),
                };
                w.write_all(reply.as_bytes()).unwrap();
            }
        }
    });
}

fn agent(sock: &Path, args: &[&str]) -> (i32, String, String) {
    let o: Output = Command::new(env!("CARGO_BIN_EXE_nexus-agent"))
        .args(args)
        .arg("--socket")
        .arg(sock)
        .env("TZ", "UTC")
        .output()
        .unwrap();
    (
        o.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&o.stdout).into_owned(),
        String::from_utf8_lossy(&o.stderr).into_owned(),
    )
}

fn is_root() -> bool {
    // SAFETY: trivial syscall
    unsafe { libc::geteuid() == 0 }
}

#[test]
fn commands_against_a_fake_service() {
    let d = tempfile::tempdir().unwrap();
    let sock = d.path().join("ui.sock");
    fake_service(&sock);

    let (code, out, _) = agent(&sock, &["sessions"]);
    assert_eq!(code, 0);
    assert!(out.starts_with("ID       RESULT"), "{out}");
    assert!(
        out.contains("12       [!] Warning   2026-10-13 13:05     12:34      1.5 GiB        2"),
        "{out}"
    );
    assert!(out.contains("[x] Failed"), "{out}");

    let (code, out, _) = agent(&sock, &["sessions", "--limit", "1", "--json"]);
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v.as_array().map(Vec::len), Some(1), "{out}");
    assert_eq!(v[0]["result"], "warning");

    let (code, out, _) = agent(&sock, &["session", "12"]);
    assert_eq!(code, 0);
    for want in [
        "Result:         [!] Warning",
        "Duration:       12:34",
        "Rate:           65.2 MiB/s",
        "socket skipped",
    ] {
        assert!(out.contains(want), "{want}: {out}");
    }
    let (code, _, err) = agent(&sock, &["session", "99"]);
    assert_eq!((code, err.trim()), (4, "nexus-agent: no such session"));
    let (code, _, err) = agent(&sock, &["session", "x"]);
    assert_eq!(code, 1, "{err}");

    if !is_root() {
        // as root `status` appends the local diagnostics
        let (code, out, _) = agent(&sock, &["status"]);
        assert_eq!(code, 0);
        for want in [
            "Agent:          web01 (version 0.6.0)",
            "Managed by:     nexus01",
            "State:          Backup running",
            "Progress:       42 %, read 1.0 GiB, transferred 1.0 MiB (started 2026-10-13 14:04)",
            "Next run:       not scheduled",
            "Reachability:   not reached since 2026-10-13 12:05",
        ] {
            assert!(out.contains(want), "{want}: {out}");
        }
    }
    let (code, out, _) = agent(&sock, &["status", "--json"]);
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(
        (v["state"].as_str(), v["running"]["percent"].as_u64()),
        (Some("running"), Some(42))
    );

    let (code, out, _) = agent(&sock, &["request-backup"]);
    assert_eq!(code, 0);
    assert!(
        out.contains("backup requested at 2026-10-13 14:05 (request r-1)"),
        "{out}"
    );
    let (code, _, err) = agent(&sock, &["request-backup"]);
    assert_eq!(code, 4);
    assert!(err.contains("rate limited"), "{err}");
}

#[test]
fn service_not_running_or_not_permitted() {
    let d = tempfile::tempdir().unwrap();
    let sock = d.path().join("ui.sock");
    let (code, _, err) = agent(&sock, &["sessions"]);
    assert_eq!(code, 3);
    assert!(err.contains("the agent service is not running"), "{err}");

    if is_root() {
        return; // root ignores the socket mode
    }
    let _l = UnixListener::bind(&sock).unwrap();
    std::fs::set_permissions(&sock, std::os::unix::fs::PermissionsExt::from_mode(0o000)).unwrap();
    let (code, _, err) = agent(&sock, &["request-backup"]);
    assert_eq!(code, 2);
    assert!(err.contains("add your user to the group nexus-agent-ui"), "{err}");
}
