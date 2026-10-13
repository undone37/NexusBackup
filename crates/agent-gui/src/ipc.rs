//! Calls to the agent service over the local IPC contract (crate agent-ui-proto). Blocking,
//! one short connection per refresh; the UI runs them as background tasks.

use agent_ui_proto::{Client, Session, SessionDetail, Status, MAX_SESSIONS};
use std::path::PathBuf;

/// Where the service listens: the platform default or `--socket PATH` (tests, demos).
#[derive(Clone, Debug, Default)]
pub struct Endpoint(pub Option<PathBuf>);

impl Endpoint {
    fn connect(&self) -> Result<Client, String> {
        let c = match &self.0 {
            Some(p) => Client::connect(p),
            None => Client::connect_default(),
        };
        c.map_err(|e| connect_error(&e))
    }
}

/// Error text with the most likely fix (the window shows it in its notification bar).
fn connect_error(e: &std::io::Error) -> String {
    match e.kind() {
        std::io::ErrorKind::PermissionDenied if cfg!(unix) => format!(
            "{e}: your account is not in the group {} (an administrator runs `usermod -aG {} <user>`, then log in again)",
            agent_ui_proto::SOCKET_GROUP,
            agent_ui_proto::SOCKET_GROUP
        ),
        std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused => {
            format!("{e}: the nexus-agent service is not running")
        }
        _ => e.to_string(),
    }
}

/// Status and the newest sessions (newest first).
#[derive(Clone, Debug, PartialEq)]
pub struct Snapshot {
    pub status: Status,
    pub sessions: Vec<Session>,
}

pub fn fetch(ep: &Endpoint) -> Result<Snapshot, String> {
    let mut c = ep.connect()?;
    let status = c.status().map_err(|e| e.to_string())?;
    let sessions = c.sessions(Some(MAX_SESSIONS)).map_err(|e| e.to_string())?;
    Ok(Snapshot { status, sessions })
}

pub fn session(ep: &Endpoint, id: u64) -> Result<SessionDetail, String> {
    ep.connect()?.session(id).map_err(|e| e.to_string())
}

/// Queues "back up now"; the answer is shown as is (rate limit, policy refusals).
pub fn request_backup(ep: &Endpoint) -> Result<String, String> {
    let r = ep.connect()?.request_backup().map_err(|e| e.to_string())?;
    Ok(format!(
        "Backup requested at {}; the appliance starts it with its next poll.",
        crate::model::fmt_time(r.queued_at)
    ))
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use agent_ui_proto::*;
    use std::io::{BufReader, Write};
    use std::os::unix::net::UnixListener;

    /// Fake agent service: answers every request of every connection from fixed data.
    fn fake_service(dir: &std::path::Path) -> PathBuf {
        let path = dir.join("ui.sock");
        let l = UnixListener::bind(&path).unwrap();
        std::thread::spawn(move || {
            for s in l.incoming() {
                let s = s.unwrap();
                let mut r = BufReader::new(s.try_clone().unwrap());
                let mut w = s;
                while let Ok(Some(line)) = read_line(&mut r) {
                    let reply = match decode_request(&line).unwrap() {
                        Request::Status => encode_ok(&Status {
                            agent_id: "a1".into(),
                            enrolled: true,
                            version: "0.1.0".into(),
                            reachable: true,
                            ..Default::default()
                        }),
                        Request::Sessions { limit } => {
                            assert_eq!(limit, Some(MAX_SESSIONS));
                            encode_ok(&Sessions {
                                sessions: vec![crate::model::tests_support::session(7)],
                            })
                        }
                        Request::Session { id: 7 } => encode_ok(&SessionDetail {
                            session: crate::model::tests_support::session(7),
                            log_tail: vec!["done".into()],
                        }),
                        Request::Session { .. } => encode_err("no such session"),
                        Request::RequestBackup => encode_err("rate limited: try again in 9 min"),
                    };
                    w.write_all(reply.as_bytes()).unwrap();
                }
            }
        });
        path
    }

    #[test]
    fn client_against_a_fake_service() {
        let dir = std::env::temp_dir().join(format!("nexus-agent-gui-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let ep = Endpoint(Some(fake_service(&dir)));

        let snap = fetch(&ep).unwrap();
        assert_eq!(snap.status.agent_id, "a1");
        assert_eq!(snap.sessions.len(), 1);
        assert_eq!(session(&ep, 7).unwrap().log_tail, ["done"]);
        assert_eq!(session(&ep, 8).unwrap_err(), "no such session");
        assert!(request_backup(&ep).unwrap_err().contains("rate limited"));

        let missing = Endpoint(Some(dir.join("nope.sock")));
        assert!(fetch(&missing).unwrap_err().contains("service is not running"));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
