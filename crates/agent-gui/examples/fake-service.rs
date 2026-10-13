//! Fake agent service with demo data, to try the GUI without an enrolled agent (Unix only):
//!
//!   cargo run -p agent-gui --example fake-service -- /tmp/ui.sock [running|unreachable|hidden]
//!   cargo run -p agent-gui -- --open --socket /tmp/ui.sock

#[cfg(unix)]
fn main() {
    use agent_ui_proto::*;
    use std::io::{BufReader, Write};
    use std::sync::{Arc, Mutex};

    let mut args = std::env::args().skip(1);
    let path = args
        .next()
        .expect("usage: fake-service SOCKET [running|unreachable|hidden]");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut snap = nexus_agent_gui::demo::snapshot(now);
    match args.next().as_deref() {
        Some("running") => {
            snap.status.state = AgentState::Running;
            snap.status.running = Some(Running {
                started: now - 300,
                percent: Some(42),
                read_bytes: 3 << 30,
                transferred_bytes: 412 << 20,
            });
        }
        Some("unreachable") => {
            snap.status.reachable = false;
            snap.status.last_seen_by_appliance = Some(now - 3 * 86_400);
        }
        Some("hidden") => {
            snap.status.ui_policy = UiPolicy {
                accent: Some("#7c3aed".into()),
                header: Some("ACME IT – Backup".into()),
                hide_backup_now: true,
                hide_tray: false,
            };
        }
        _ => {}
    }
    let snap = Arc::new(Mutex::new(snap));
    let _ = std::fs::remove_file(&path);
    let l = std::os::unix::net::UnixListener::bind(&path).unwrap();
    eprintln!("fake agent service on {path}");
    for s in l.incoming() {
        let s = s.unwrap();
        let snap = snap.clone();
        std::thread::spawn(move || {
            let mut r = BufReader::new(s.try_clone().unwrap());
            let mut w = s;
            while let Ok(Some(line)) = read_line(&mut r) {
                let mut snap = snap.lock().unwrap();
                let reply = match decode_request(&line) {
                    Ok(Request::Status) => encode_ok(&snap.status),
                    Ok(Request::Sessions { limit }) => encode_ok(&Sessions {
                        sessions: snap
                            .sessions
                            .iter()
                            .take(limit.unwrap_or(MAX_SESSIONS))
                            .cloned()
                            .collect(),
                    }),
                    Ok(Request::Session { id }) => match snap.sessions.iter().find(|s| s.id == id) {
                        Some(s) => encode_ok(&nexus_agent_gui::demo::detail(s)),
                        None => encode_err("no such session"),
                    },
                    Ok(Request::RequestBackup) if snap.status.state == AgentState::Idle => {
                        snap.status.state = AgentState::Requested;
                        encode_ok(&Requested {
                            request_id: "demo-1".into(),
                            queued_at: now,
                        })
                    }
                    Ok(Request::RequestBackup) => encode_err("a backup is already requested or running"),
                    Err(e) => encode_err(&e.to_string()),
                };
                if w.write_all(reply.as_bytes()).is_err() {
                    break;
                }
            }
        });
    }
}

#[cfg(not(unix))]
fn main() {
    eprintln!("fake-service: Unix only");
}
