//! Local IPC between the `nexus-agent` service and its endpoint UIs (`nexus-agent tui`,
//! `nexus-agent-gui`), docs/endpoint-ui.md.
//!
//! Transport: Linux unix socket [`SOCKET_PATH`] (group [`SOCKET_GROUP`], mode 0660),
//! Windows named pipe [`PIPE_NAME`]. Framing: newline-delimited JSON, one request per
//! line (`{"op": ...}`), one reply line per request: `{"ok": true, ...fields}` or
//! `{"ok": false, "error": "..."}`. Nothing on this channel can change configuration,
//! start a restore or read backup data; `request_backup` only queues a request that the
//! appliance picks up with its next poll.

#![warn(missing_docs)]

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::time::Duration;

/// Linux: socket served by the agent service.
pub const SOCKET_PATH: &str = "/run/nexus-agent/ui.sock";
/// Linux: group whose members may use the socket.
pub const SOCKET_GROUP: &str = "nexus-agent-ui";
/// Windows: named pipe served by the agent service.
pub const PIPE_NAME: &str = r"\\.\pipe\nexus-agent-ui";
/// The agent keeps at most this many session summaries.
pub const MAX_SESSIONS: usize = 100;
/// `session` returns at most this many log lines.
pub const MAX_LOG_TAIL: usize = 200;
/// At most one accepted `request_backup` per this many seconds.
pub const REQUEST_INTERVAL_SECS: u64 = 600;
/// Longest accepted request or reply line (bytes, without the newline).
pub const MAX_LINE: usize = 1 << 20;

/// A request line. Times everywhere are Unix seconds (UTC).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Request {
    /// Agent and backup state; reply [`Status`].
    Status,
    /// Session summaries; reply [`Sessions`].
    Sessions {
        /// newest first, capped at [`MAX_SESSIONS`]; absent = all
        #[serde(default)]
        limit: Option<usize>,
    },
    /// One session with its log tail; reply [`SessionDetail`], refused for an unknown id.
    Session {
        /// appliance job id ([`Session::id`])
        id: u64,
    },
    /// Queue a "back up now" request for the appliance's next poll; reply [`Requested`].
    /// Refused within [`REQUEST_INTERVAL_SECS`] of the last one, before enrollment and
    /// while the UI policy hides the button.
    RequestBackup,
}

/// What the agent does right now (tray icon, status line).
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum AgentState {
    /// nothing running or queued, the last session did not fail
    #[default]
    Idle,
    /// a backup or restore session is in progress ([`Status::running`])
    Running,
    /// a "back up now" request waits for the appliance's next poll
    Requested,
    /// the last session failed
    Error,
}

/// Branding / visibility set by the appliance administrator per agent.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Default)]
pub struct UiPolicy {
    /// accent colour, `#rrggbb`
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accent: Option<String>,
    /// header text shown instead of the product name
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub header: Option<String>,
    /// hide "request backup now" (the service also refuses `request_backup`)
    #[serde(default)]
    pub hide_backup_now: bool,
    /// no tray icon; the menu entry still opens the window
    #[serde(default)]
    pub hide_tray: bool,
}

/// Progress of the backup that runs right now.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Default)]
pub struct Running {
    /// start of the session, Unix seconds
    pub started: u64,
    /// 0..=99, read bytes against the last successful backup; unknown on the first
    /// backup (no previous size to compare with)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub percent: Option<u8>,
    /// source bytes read so far
    pub read_bytes: u64,
    /// bytes sent to the appliance so far
    pub transferred_bytes: u64,
}

/// Reply to `status`.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
pub struct Status {
    /// "" while not enrolled
    pub agent_id: String,
    /// appliance identity (CA fingerprint prefix) once enrolled
    #[serde(default)]
    pub appliance: Option<String>,
    /// appliance display name, from its last session summary
    #[serde(default)]
    pub managed_by: Option<String>,
    /// the agent holds an appliance certificate
    pub enrolled: bool,
    /// agent version
    pub version: String,
    /// what the agent does right now
    pub state: AgentState,
    /// progress of the session in progress; absent while none runs
    #[serde(default)]
    pub running: Option<Running>,
    /// end of the newest successful session; absent: none recorded
    #[serde(default)]
    pub last_success: Option<u64>,
    /// next scheduled run as told by the appliance; absent: unknown or none scheduled
    #[serde(default)]
    pub next_run: Option<u64>,
    /// last session (poll or job) opened by the appliance
    #[serde(default)]
    pub last_seen_by_appliance: Option<u64>,
    /// the appliance reached this agent recently (within a few poll intervals)
    pub reachable: bool,
    /// branding and visibility from the appliance; absent: defaults (nothing hidden)
    #[serde(default)]
    pub ui_policy: UiPolicy,
}

/// What a session did.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SessionKind {
    /// backup of this agent
    Backup,
    /// file restore to this agent
    Restore,
}

/// Outcome of a session (chart colour: green, yellow, red, grey).
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SessionResult {
    /// finished without warnings
    Success,
    /// finished, with [`Session::warnings`] warnings
    Warning,
    /// no snapshot (backup) or not every file restored; see [`Session::first_error`]
    Failed,
    /// cancelled by an operator
    Cancelled,
}

/// One backup or restore session as reported by the appliance.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Session {
    /// appliance job id
    pub id: u64,
    /// backup or restore
    pub kind: SessionKind,
    /// start, Unix seconds
    pub started: u64,
    /// end, Unix seconds
    pub ended: u64,
    /// outcome
    pub result: SessionResult,
    /// source bytes read on the agent (restore: bytes written)
    pub read_bytes: u64,
    /// bytes the appliance received (restore: sent)
    pub transferred_bytes: u64,
    /// bytes newly stored after deduplication (0 for a restore)
    pub new_bytes: u64,
    /// number of warning lines in the session's log
    pub warnings: u32,
    /// first error line of a failed session; absent otherwise
    #[serde(default)]
    pub first_error: Option<String>,
    /// snapshot (restore point) time created by a backup session
    #[serde(default)]
    pub snapshot_time: Option<u64>,
}

/// Reply to `sessions`.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
pub struct Sessions {
    /// newest first
    pub sessions: Vec<Session>,
}

/// Reply to `session {id}`: the session's fields plus `log_tail`.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct SessionDetail {
    /// the summary, flattened into the reply object
    #[serde(flatten)]
    pub session: Session,
    /// ≤ [`MAX_LOG_TAIL`] lines, already redacted by the appliance
    #[serde(default)]
    pub log_tail: Vec<String>,
}

/// Reply to `request_backup`.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Requested {
    /// id of the queued request (16 hex digits), also in the agent log
    pub request_id: String,
    /// when it was queued, Unix seconds
    pub queued_at: u64,
}

/// Error reply or transport failure as seen by a client.
#[derive(Debug)]
pub enum Error {
    /// the service answered `{"ok": false, "error": ...}`
    Refused(String),
    /// connection, timeout or a malformed reply line
    Io(io::Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Refused(e) => write!(f, "{e}"),
            Error::Io(e) => write!(f, "agent service: {e}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(e)
    }
}

fn bad(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

/// `{"ok": true, ...fields of reply}` (one line, newline included).
pub fn encode_ok<T: Serialize>(reply: &T) -> String {
    let mut obj = match serde_json::to_value(reply) {
        Ok(serde_json::Value::Object(m)) => m,
        _ => serde_json::Map::new(),
    };
    obj.insert("ok".into(), true.into());
    let mut line = serde_json::Value::Object(obj).to_string();
    line.push('\n');
    line
}

/// `{"ok": false, "error": msg}` (one line, newline included).
pub fn encode_err(msg: &str) -> String {
    let mut line = serde_json::json!({"ok": false, "error": msg}).to_string();
    line.push('\n');
    line
}

/// Request line (newline included).
pub fn encode_request(r: &Request) -> String {
    let mut line = serde_json::to_string(r).expect("requests always serialize");
    line.push('\n');
    line
}

/// Parses a request line (service side); `InvalidData` for an unknown or malformed request.
pub fn decode_request(line: &str) -> io::Result<Request> {
    serde_json::from_str(line.trim_end()).map_err(|e| bad(format!("bad request: {e}")))
}

/// Parses a reply line into `T`, or the refusal it carries.
pub fn decode_reply<T: DeserializeOwned>(line: &str) -> Result<T, Error> {
    let v: serde_json::Value = serde_json::from_str(line.trim_end()).map_err(|e| bad(format!("bad reply: {e}")))?;
    match v.get("ok") {
        Some(serde_json::Value::Bool(true)) => {
            Ok(serde_json::from_value(v).map_err(|e| bad(format!("bad reply: {e}")))?)
        }
        Some(serde_json::Value::Bool(false)) => Err(Error::Refused(
            v.get("error").and_then(|e| e.as_str()).unwrap_or("refused").to_string(),
        )),
        _ => Err(bad("reply without \"ok\"").into()),
    }
}

/// Reads one line of at most [`MAX_LINE`] bytes; `Ok(None)` at end of stream.
pub fn read_line(r: &mut impl BufRead) -> io::Result<Option<String>> {
    let mut buf = Vec::new();
    let n = r.take(MAX_LINE as u64 + 1).read_until(b'\n', &mut buf)?;
    if n == 0 {
        return Ok(None);
    }
    if buf.last() != Some(&b'\n') && buf.len() > MAX_LINE {
        return Err(bad("line too long"));
    }
    String::from_utf8(buf).map(Some).map_err(|_| bad("line is not UTF-8"))
}

/// Blocking client: one connection, any number of sequential requests.
pub struct Client {
    reader: BufReader<Box<dyn Read + Send>>,
    writer: Box<dyn Write + Send>,
}

impl Client {
    /// Connects to the platform default endpoint ([`SOCKET_PATH`] / [`PIPE_NAME`]).
    pub fn connect_default() -> io::Result<Client> {
        #[cfg(windows)]
        return Client::connect(PIPE_NAME);
        #[cfg(not(windows))]
        return Client::connect(SOCKET_PATH);
    }

    /// Connects to a unix socket path (Unix) or a named pipe path (Windows).
    #[cfg(unix)]
    pub fn connect(path: impl AsRef<std::path::Path>) -> io::Result<Client> {
        let s = std::os::unix::net::UnixStream::connect(path)?;
        s.set_read_timeout(Some(Duration::from_secs(30)))?;
        s.set_write_timeout(Some(Duration::from_secs(30)))?;
        let r = s.try_clone()?;
        Ok(Client::from_parts(Box::new(r), Box::new(s)))
    }

    /// Connects to a named pipe (`\\.\pipe\...`); retries briefly while all pipe
    /// instances are busy.
    #[cfg(windows)]
    pub fn connect(path: impl AsRef<std::path::Path>) -> io::Result<Client> {
        const ERROR_PIPE_BUSY: i32 = 231;
        let mut tries = 0;
        let f = loop {
            match std::fs::OpenOptions::new().read(true).write(true).open(path.as_ref()) {
                Ok(f) => break f,
                Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY) && tries < 20 => {
                    tries += 1;
                    std::thread::sleep(Duration::from_millis(100));
                }
                Err(e) => return Err(e),
            }
        };
        let r = f.try_clone()?;
        Ok(Client::from_parts(Box::new(r), Box::new(f)))
    }

    /// Client over any byte stream (tests, custom transports).
    pub fn from_parts(r: Box<dyn Read + Send>, w: Box<dyn Write + Send>) -> Client {
        Client {
            reader: BufReader::new(r),
            writer: w,
        }
    }

    fn call<T: DeserializeOwned>(&mut self, req: &Request) -> Result<T, Error> {
        self.writer.write_all(encode_request(req).as_bytes())?;
        self.writer.flush()?;
        let line = read_line(&mut self.reader)?.ok_or_else(|| bad("service closed the connection"))?;
        decode_reply(&line)
    }

    /// Sends `status`.
    pub fn status(&mut self) -> Result<Status, Error> {
        self.call(&Request::Status)
    }

    /// Sends `sessions`: at most `limit` summaries (all when `None`), newest first.
    pub fn sessions(&mut self, limit: Option<usize>) -> Result<Vec<Session>, Error> {
        self.call::<Sessions>(&Request::Sessions { limit }).map(|s| s.sessions)
    }

    /// Sends `session`: one summary with its log tail.
    pub fn session(&mut self, id: u64) -> Result<SessionDetail, Error> {
        self.call(&Request::Session { id })
    }

    /// Sends `request_backup`; [`Error::Refused`] when rate-limited or not allowed.
    pub fn request_backup(&mut self) -> Result<Requested, Error> {
        self.call(&Request::RequestBackup)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session() -> Session {
        Session {
            id: 42,
            kind: SessionKind::Backup,
            started: 1_700_000_000,
            ended: 1_700_000_300,
            result: SessionResult::Warning,
            read_bytes: 10,
            transferred_bytes: 5,
            new_bytes: 3,
            warnings: 2,
            first_error: Some("/home/x: permission denied".into()),
            snapshot_time: Some(1_700_000_001),
        }
    }

    #[test]
    fn request_wire_format() {
        assert_eq!(encode_request(&Request::Status), "{\"op\":\"status\"}\n");
        assert_eq!(encode_request(&Request::RequestBackup), "{\"op\":\"request_backup\"}\n");
        assert_eq!(
            decode_request("{\"op\":\"sessions\",\"limit\":5}\n").unwrap(),
            Request::Sessions { limit: Some(5) }
        );
        assert_eq!(
            decode_request("{\"op\":\"sessions\"}").unwrap(),
            Request::Sessions { limit: None }
        );
        assert_eq!(
            decode_request("{\"op\":\"session\",\"id\":7}").unwrap(),
            Request::Session { id: 7 }
        );
        assert!(decode_request("{\"op\":\"restore\"}").is_err());
        assert!(decode_request("nonsense").is_err());
    }

    #[test]
    fn reply_roundtrip() {
        let st = Status {
            agent_id: "a1".into(),
            appliance: Some("ab12".into()),
            managed_by: Some("nexus01".into()),
            enrolled: true,
            version: "0.1.0".into(),
            state: AgentState::Running,
            running: Some(Running {
                started: 5,
                percent: Some(40),
                read_bytes: 1,
                transferred_bytes: 2,
            }),
            last_success: Some(1),
            next_run: None,
            last_seen_by_appliance: Some(4),
            reachable: true,
            ui_policy: UiPolicy {
                accent: Some("#0a7".into()),
                header: None,
                hide_backup_now: true,
                hide_tray: false,
            },
        };
        let line = encode_ok(&st);
        assert!(line.ends_with('\n') && line.matches('\n').count() == 1);
        let v: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(v["ok"], true);
        assert_eq!(v["state"], "running");
        assert_eq!(v["running"]["percent"], 40);
        assert_eq!(decode_reply::<Status>(&line).unwrap(), st);

        let d = SessionDetail {
            session: session(),
            log_tail: vec!["line 1".into()],
        };
        let line = encode_ok(&d);
        let v: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(v["id"], 42, "session fields are flattened");
        assert_eq!(v["result"], "warning");
        assert_eq!(decode_reply::<SessionDetail>(&line).unwrap(), d);

        let s = Sessions {
            sessions: vec![session()],
        };
        assert_eq!(decode_reply::<Sessions>(&encode_ok(&s)).unwrap(), s);
        // optional fields may be missing (older services)
        let min = r#"{"ok":true,"agent_id":"","enrolled":false,"version":"1","state":"idle","reachable":false}"#;
        assert_eq!(decode_reply::<Status>(min).unwrap().ui_policy, UiPolicy::default());
    }

    #[test]
    fn refusals_and_garbage() {
        match decode_reply::<Requested>(&encode_err("rate limited: try again in 9 min")) {
            Err(Error::Refused(m)) => assert!(m.contains("rate limited")),
            other => panic!("{other:?}"),
        }
        assert!(matches!(decode_reply::<Requested>("{}"), Err(Error::Io(_))));
        assert!(matches!(decode_reply::<Requested>("{\"ok\":true}"), Err(Error::Io(_))));
    }

    #[test]
    fn line_framing_limits() {
        let mut r = io::Cursor::new(b"{\"op\":\"status\"}\n{\"op\":\"request_backup\"}\n".to_vec());
        assert_eq!(read_line(&mut r).unwrap().unwrap(), "{\"op\":\"status\"}\n");
        assert_eq!(read_line(&mut r).unwrap().unwrap(), "{\"op\":\"request_backup\"}\n");
        assert!(read_line(&mut r).unwrap().is_none());
        let long = vec![b'a'; MAX_LINE + 10];
        assert!(read_line(&mut io::Cursor::new(long)).is_err());
        assert!(read_line(&mut io::Cursor::new(vec![0xff, b'\n'])).is_err());
    }

    #[test]
    fn client_over_a_byte_stream() {
        let replies = format!(
            "{}{}",
            encode_ok(&Requested {
                request_id: "r1".into(),
                queued_at: 9
            }),
            encode_err("no such session")
        );
        let sent = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        struct W(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
        impl Write for W {
            fn write(&mut self, b: &[u8]) -> io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(b);
                Ok(b.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let mut c = Client::from_parts(
            Box::new(io::Cursor::new(replies.into_bytes())),
            Box::new(W(sent.clone())),
        );
        assert_eq!(c.request_backup().unwrap().request_id, "r1");
        assert!(matches!(c.session(3), Err(Error::Refused(_))));
        assert!(matches!(c.status(), Err(Error::Io(_))), "closed stream");
        let sent = String::from_utf8(sent.lock().unwrap().clone()).unwrap();
        assert_eq!(
            sent,
            "{\"op\":\"request_backup\"}\n{\"op\":\"session\",\"id\":3}\n{\"op\":\"status\"}\n"
        );
    }

    #[cfg(unix)]
    #[test]
    fn client_over_a_unix_socket() {
        let dir = std::env::temp_dir().join(format!("nexus-ui-proto-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("ui.sock");
        let _ = std::fs::remove_file(&path);
        let l = std::os::unix::net::UnixListener::bind(&path).unwrap();
        let t = std::thread::spawn(move || {
            let (s, _) = l.accept().unwrap();
            let mut r = BufReader::new(s.try_clone().unwrap());
            let mut w = s;
            while let Some(line) = read_line(&mut r).unwrap() {
                let reply = match decode_request(&line).unwrap() {
                    Request::Sessions { limit } => encode_ok(&Sessions {
                        sessions: vec![session(); limit.unwrap_or(1)],
                    }),
                    _ => encode_err("unsupported"),
                };
                w.write_all(reply.as_bytes()).unwrap();
            }
        });
        let mut c = Client::connect(&path).unwrap();
        assert_eq!(c.sessions(Some(2)).unwrap().len(), 2);
        assert!(matches!(c.status(), Err(Error::Refused(_))));
        drop(c);
        t.join().unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
