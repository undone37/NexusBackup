//! Protocol between `nexus-pluginhost` (trusted) and a plugin process (untrusted),
//! see docs/plugin-system.md. Framing: `u32 BE length | postcard(Message)`, max `MAX_FRAME`.

use serde::{Deserialize, Serialize};
use std::io::{self, Read, Write};

pub const API: u32 = 1;
pub const MAX_FRAME: usize = 8 << 20;
pub const MAX_DATA: usize = 4 << 20;
pub const MAX_PATH: usize = 4096;
pub const MAX_STATE: usize = 1 << 20;
pub const MAX_XATTR: usize = 64 << 10;
pub const MAX_BATCH: usize = 10_000;

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum Op {
    Validate,
    ListGuests,
    Backup,
    Restore,
    Mount,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    File,
    Dir,
    Symlink,
    Hardlink,
    Device,
    Fifo,
    Socket,
}

/// File metadata as the plugin knows it (POSIX-ish; plugins fill what they have).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
pub struct Meta {
    pub kind: Option<Kind>,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub size: u64,
    pub mtime_ns: i64,
    pub ctime_ns: i64,
    pub inode: u64,
    pub link_target: Option<Vec<u8>>,
    pub xattrs: Vec<(Vec<u8>, Vec<u8>)>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Guest {
    pub id: String,
    pub title: String,
    pub size: Option<u64>,
}

/// What the host knows about the previous snapshot of this source.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct BaseInfo {
    pub time: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct BaseEntry {
    pub path: Vec<u8>,
    pub meta: Meta,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum Message {
    // host -> plugin, first message
    Init {
        api: u32,
        job: u64,
        kind: String,
        op: Op,
        /// source config (JSON) with secrets opened
        config: String,
        /// op parameters (JSON): guests for Backup, restore id + params for Restore, …
        params: String,
        base: Option<BaseInfo>,
        state: Option<Vec<u8>>,
    },
    // validate / list guests
    Valid,
    Invalid {
        field: String,
        message: String,
    },
    Guests {
        list: Vec<Guest>,
    },
    // backup stream (plugin -> host)
    FileBegin {
        path: Vec<u8>,
        meta: Meta,
    },
    Data {
        bytes: Vec<u8>,
    },
    FileEnd,
    Unchanged {
        path: Vec<u8>,
        meta: Meta,
    },
    Stream {
        name: String,
    },
    StreamEnd,
    Done {
        state: Option<Vec<u8>>,
        consistent: bool,
        summary: String,
    },
    // base metadata on demand
    BaseQuery {
        paths: Vec<Vec<u8>>,
    },
    BaseEntries {
        entries: Vec<BaseEntry>,
    },
    // restore (plugin asks, host streams FileBegin/Data/FileEnd and Stream/Data/StreamEnd back)
    NeedFiles {
        paths: Vec<Vec<u8>>,
    },
    NeedStreams {
        names: Vec<String>,
    },
    NeedDone,
    Progress {
        done: u64,
        total: u64,
        text: String,
    },
    // mount
    MountReady {
        info: String,
    },
    ReadFile {
        path: Vec<u8>,
        offset: u64,
        len: u32,
    },
    FileData {
        bytes: Vec<u8>,
    },
    Unmount,
    // any time
    Log {
        level: u8,
        text: String,
    },
    Error {
        code: u32,
        message: String,
    },
}

fn bad(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

pub fn write_msg(w: &mut impl Write, m: &Message) -> io::Result<()> {
    let body = postcard::to_stdvec(m).map_err(|e| bad(format!("encode: {e}")))?;
    if body.len() > MAX_FRAME {
        return Err(bad("frame too large"));
    }
    w.write_all(&(body.len() as u32).to_be_bytes())?;
    w.write_all(&body)?;
    w.flush()
}

pub fn read_msg(r: &mut impl Read) -> io::Result<Message> {
    let mut len = [0u8; 4];
    r.read_exact(&mut len)?;
    let len = u32::from_be_bytes(len) as usize;
    if len > MAX_FRAME {
        return Err(bad(format!("frame of {len} bytes exceeds the limit")));
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body)?;
    let m: Message = postcard::from_bytes(&body).map_err(|e| bad(format!("decode: {e}")))?;
    check(&m)?;
    Ok(m)
}

/// Relative path, no `..` / `.` components, no NUL, no leading `/`, bounded.
pub fn valid_path(p: &[u8]) -> bool {
    !p.is_empty()
        && p.len() <= MAX_PATH
        && p[0] != b'/'
        && !p.contains(&0)
        && p.split(|&b| b == b'/')
            .all(|c| !c.is_empty() && c != b"." && c != b"..")
}

/// Stream names: `[A-Za-z0-9._/-]{1,255}`, no `..` component, no leading `/`.
pub fn valid_stream_name(n: &str) -> bool {
    !n.is_empty()
        && n.len() <= 255
        && n.bytes().all(|b| b.is_ascii_alphanumeric() || b"._/-".contains(&b))
        && valid_path(n.as_bytes())
}

fn check_meta(m: &Meta) -> io::Result<()> {
    let x: usize = m.xattrs.iter().map(|(k, v)| k.len() + v.len()).sum();
    if x > MAX_XATTR
        || m.link_target
            .as_ref()
            .is_some_and(|t| t.len() > MAX_PATH || t.contains(&0))
    {
        return Err(bad("metadata exceeds limits"));
    }
    Ok(())
}

/// Structural limits every receiver enforces (the host additionally checks ordering).
pub fn check(m: &Message) -> io::Result<()> {
    match m {
        Message::FileBegin { path, meta } | Message::Unchanged { path, meta } => {
            if !valid_path(path) {
                return Err(bad("invalid path"));
            }
            check_meta(meta)
        }
        Message::Data { bytes } | Message::FileData { bytes } if bytes.len() > MAX_DATA => {
            Err(bad("data frame too large"))
        }
        Message::Stream { name } if !valid_stream_name(name) => Err(bad("invalid stream name")),
        Message::NeedStreams { names } if names.len() > MAX_BATCH || names.iter().any(|n| !valid_stream_name(n)) => {
            Err(bad("invalid stream list"))
        }
        Message::NeedFiles { paths } | Message::BaseQuery { paths }
            if paths.len() > MAX_BATCH || paths.iter().any(|p| !valid_path(p)) =>
        {
            Err(bad("invalid path list"))
        }
        Message::BaseEntries { entries } if entries.len() > MAX_BATCH => Err(bad("too many entries")),
        Message::Done { state: Some(s), .. } | Message::Init { state: Some(s), .. } if s.len() > MAX_STATE => {
            Err(bad("state blob too large"))
        }
        Message::ReadFile { path, len, .. } if !valid_path(path) || *len as usize > MAX_DATA => {
            Err(bad("invalid read"))
        }
        Message::Log { text, .. } | Message::Error { message: text, .. } if text.len() > 64 << 10 => {
            Err(bad("log text too long"))
        }
        _ => Ok(()),
    }
}

// ---- manifest -----------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Endpoint {
    /// JSON pointers into the source config
    pub host: String,
    pub port: Option<String>,
    pub default_port: u16,
    pub proto: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct RestoreAction {
    pub id: String,
    pub title: String,
    #[serde(default)]
    pub params_schema: Option<serde_json::Value>,
    #[serde(default)]
    pub app_specific: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct KindSpec {
    pub kind: String,
    pub title: String,
    pub config_schema: serde_json::Value,
    #[serde(default)]
    pub secret_fields: Vec<String>,
    #[serde(default)]
    pub endpoints: Vec<Endpoint>,
    #[serde(default)]
    pub guests: Option<serde_json::Value>,
    #[serde(default)]
    pub backup: Option<serde_json::Value>,
    pub restores: Vec<RestoreAction>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Manifest {
    pub id: String,
    pub name: String,
    pub version: String,
    pub publisher: String,
    pub api: u32,
    pub kinds: Vec<KindSpec>,
    #[serde(default)]
    pub sandbox: Option<serde_json::Value>,
}

fn valid_ident(s: &str, max: usize) -> bool {
    (2..=max).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !s.starts_with('-')
}

/// Plugin ids additionally have no empty and no all-digit `-` component, so a
/// snapshot source name `plugin-<id>-<source id>[-<guest>]` parses unambiguously
/// (the first all-digit component is the source id), see [`parse_source_name`].
pub fn valid_plugin_id(s: &str) -> bool {
    valid_ident(s, 32)
        && s.split('-')
            .all(|c| !c.is_empty() && !c.bytes().all(|b| b.is_ascii_digit()))
}

/// Guest ids (ListGuests, group guests): `[A-Za-z0-9._-]{1,64}`, not starting with `.`/`-`;
/// they become part of the snapshot source name.
pub fn valid_guest_id(s: &str) -> bool {
    (1..=64).contains(&s.len())
        && !s.starts_with(['.', '-'])
        && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}

/// Snapshot source of a plugin source (`plugin-<id>-<source id>`) or of one of its
/// guests (`plugin-<id>-<source id>-<guest>`).
pub fn source_name(plugin: &str, source_id: u64, guest: Option<&str>) -> String {
    match guest {
        Some(g) => format!("plugin-{plugin}-{source_id}-{g}"),
        None => format!("plugin-{plugin}-{source_id}"),
    }
}

/// Inverse of [`source_name`]: (plugin id, source id, guest).
pub fn parse_source_name(s: &str) -> Option<(String, u64, Option<String>)> {
    let rest = s.strip_prefix("plugin-")?;
    let parts: Vec<&str> = rest.split('-').collect();
    let i = parts
        .iter()
        .position(|c| !c.is_empty() && c.len() <= 19 && c.bytes().all(|b| b.is_ascii_digit()))?;
    let id = parts[..i].join("-");
    let sid: u64 = parts[i].parse().ok()?;
    let guest = (i + 1 < parts.len()).then(|| parts[i + 1..].join("-"));
    (valid_plugin_id(&id) && guest.as_deref().is_none_or(valid_guest_id)).then_some((id, sid, guest))
}

/// Restore/download view: streams appear below this top-level directory; plugins
/// may not use it as the first component of a file path.
pub const STREAMS_DIR: &str = ".nexus-streams";

impl KindSpec {
    /// TCP ports of the endpoints configured in `cfg` (port from the config, else
    /// `default_port`): the plugin's connect allow-list (Landlock).
    pub fn tcp_ports(&self, cfg: &serde_json::Value) -> Vec<u16> {
        let mut ports: Vec<u16> = self
            .endpoints
            .iter()
            .filter(|e| e.proto == "tcp" && cfg.pointer(&e.host).is_some())
            .map(|e| {
                e.port
                    .as_deref()
                    .and_then(|p| cfg.pointer(p))
                    .and_then(|v| v.as_u64().or_else(|| v.as_str().and_then(|s| s.parse().ok())))
                    .and_then(|p| u16::try_from(p).ok())
                    .unwrap_or(e.default_port)
            })
            .collect();
        ports.sort_unstable();
        ports.dedup();
        ports
    }
}

impl Manifest {
    /// Static checks before a bundle is accepted (signature is checked separately).
    pub fn validate(&self) -> Result<(), String> {
        if !valid_plugin_id(&self.id) {
            return Err("id: [a-z0-9-]{2,32}, no empty or all-digit `-` component".into());
        }
        if self.api != API {
            return Err(format!("api {} not supported (appliance speaks {API})", self.api));
        }
        if !semver_like(&self.version) {
            return Err("version: MAJOR.MINOR.PATCH".into());
        }
        if self.kinds.is_empty() {
            return Err("kinds: at least one".into());
        }
        if self.name.is_empty() || self.name.len() > 64 || self.name.chars().any(char::is_control) {
            return Err("name: 1..=64 printable characters".into());
        }
        if !valid_ident(&self.publisher, 32) {
            return Err("publisher: [a-z0-9-]{2,32}".into());
        }
        let mut kinds = std::collections::HashSet::new();
        for k in &self.kinds {
            if !valid_ident(&k.kind, 32) {
                return Err(format!("kind {:?}: [a-z0-9-]{{2,32}}", k.kind));
            }
            if !kinds.insert(k.kind.as_str()) {
                return Err(format!("kind {}: listed twice", k.kind));
            }
            let mut ids = std::collections::HashSet::new();
            for r in &k.restores {
                let id_ok = (2..=32).contains(&r.id.len())
                    && r.id
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_');
                if !id_ok || !ids.insert(r.id.as_str()) {
                    return Err(format!(
                        "kind {}: restore id {:?} invalid or listed twice",
                        k.kind, r.id
                    ));
                }
                if r.params_schema.as_ref().is_some_and(|p| !p.is_object()) {
                    return Err(format!(
                        "kind {}: restore {}: params_schema must be an object",
                        k.kind, r.id
                    ));
                }
            }
            for f in &k.secret_fields {
                if k.config_schema["properties"].get(f).is_none() {
                    return Err(format!("kind {}: secret field {f:?} is not a config property", k.kind));
                }
            }
            if !k.config_schema.is_object() {
                return Err(format!("kind {}: config_schema must be an object", k.kind));
            }
            if !k.restores.iter().any(|r| r.id == "download") {
                return Err(format!(
                    "kind {}: the generic `download` restore must be listed",
                    k.kind
                ));
            }
            for e in &k.endpoints {
                if !e.host.starts_with('/') || e.port.as_ref().is_some_and(|p| !p.starts_with('/')) {
                    return Err(format!("kind {}: endpoints use JSON pointers", k.kind));
                }
                if e.proto != "tcp" && e.proto != "udp" {
                    return Err(format!("kind {}: endpoint proto tcp|udp", k.kind));
                }
            }
        }
        Ok(())
    }

    /// Source kind as stored in the catalog: `plugin:<kind>`.
    pub fn source_kind(kind: &str) -> String {
        format!("plugin:{kind}")
    }
}

fn semver_like(v: &str) -> bool {
    let p: Vec<_> = v.split('.').collect();
    p.len() == 3
        && p.iter()
            .all(|x| !x.is_empty() && x.len() <= 6 && x.bytes().all(|b| b.is_ascii_digit()))
}

/// Strictly newer version (numeric MAJOR.MINOR.PATCH).
pub fn newer(a: &str, than: &str) -> bool {
    let n = |v: &str| v.split('.').map(|x| x.parse::<u64>().unwrap_or(0)).collect::<Vec<_>>();
    n(a) > n(than)
}

#[cfg(feature = "bundle")]
pub mod bundle;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_names() {
        assert_eq!(source_name("example-files", 5, None), "plugin-example-files-5");
        assert_eq!(
            parse_source_name("plugin-example-files-5"),
            Some(("example-files".into(), 5, None))
        );
        assert_eq!(
            parse_source_name("plugin-postgresql-12-db-1"),
            Some(("postgresql".into(), 12, Some("db-1".into())))
        );
        assert_eq!(
            parse_source_name(&source_name("pg", 7, Some("2024"))),
            Some(("pg".into(), 7, Some("2024".into())))
        );
        for bad in [
            "plugin-",
            "plugin-x",
            "plugin-5",
            "vm-100",
            "plugin-a-b",
            "plugin-ab-1-.x",
            "plugin-Ab-1",
        ] {
            assert_eq!(parse_source_name(bad), None, "{bad}");
        }
        assert!(valid_plugin_id("example-files") && !valid_plugin_id("pg-15") && !valid_plugin_id("a--b"));
        assert!(valid_guest_id("db_1.x") && !valid_guest_id("-x") && !valid_guest_id("a/b") && !valid_guest_id(""));
    }

    #[test]
    fn framing_and_limits() {
        let m = Message::FileBegin {
            path: b"base/16384/1259".to_vec(),
            meta: Meta {
                size: 8192,
                ..Default::default()
            },
        };
        let mut buf = Vec::new();
        write_msg(&mut buf, &m).unwrap();
        assert_eq!(read_msg(&mut &buf[..]).unwrap(), m);
        for bad_path in [&b"/etc/passwd"[..], b"a/../b", b"a//b", b"./a", b"a\0b", b""] {
            let mut buf = Vec::new();
            write_msg(
                &mut buf,
                &Message::FileBegin {
                    path: bad_path.to_vec(),
                    meta: Meta::default(),
                },
            )
            .unwrap();
            assert!(read_msg(&mut &buf[..]).is_err(), "{bad_path:?}");
        }
        let mut buf = Vec::new();
        write_msg(
            &mut buf,
            &Message::Stream {
                name: "db/app/dump.sql".into(),
            },
        )
        .unwrap();
        assert!(read_msg(&mut &buf[..]).is_ok());
        let mut buf = Vec::new();
        write_msg(&mut buf, &Message::Stream { name: "../x".into() }).unwrap();
        assert!(read_msg(&mut &buf[..]).is_err());
        let mut big = ((MAX_FRAME + 1) as u32).to_be_bytes().to_vec();
        big.extend([0u8; 8]);
        assert!(read_msg(&mut &big[..]).is_err());
    }

    #[test]
    fn manifest_validation() {
        let m: Manifest = serde_json::from_value(serde_json::json!({
            "id": "postgresql", "name": "PostgreSQL", "version": "1.0.0", "publisher": "nexusbackup", "api": 1,
            "kinds": [{"kind": "postgresql", "title": "PostgreSQL server",
                       "config_schema": {"type": "object", "properties": {"host": {"type": "string"}, "port": {"type": "integer"}, "password": {"type": "string"}}},
                       "secret_fields": ["password"],
                       "endpoints": [{"host": "/host", "port": "/port", "default_port": 5432, "proto": "tcp"}],
                       "restores": [{"id": "download", "title": "Download"}, {"id": "to_target", "title": "Restore"}]}]
        }))
        .unwrap();
        assert_eq!(m.validate(), Ok(()));
        let k = &m.kinds[0];
        assert_eq!(k.tcp_ports(&serde_json::json!({"host": "db", "port": 6432})), [6432]);
        assert_eq!(k.tcp_ports(&serde_json::json!({"host": "db"})), [5432]);
        assert!(k.tcp_ports(&serde_json::json!({})).is_empty(), "unconfigured endpoint");
        let mut bad = m.clone();
        bad.id = "Bad_ID".into();
        assert!(bad.validate().is_err());
        let mut bad = m.clone();
        bad.kinds[0].restores.clear();
        assert!(bad.validate().is_err(), "download is mandatory");
        let mut bad = m.clone();
        bad.api = 2;
        assert!(bad.validate().is_err());
        assert!(newer("1.10.0", "1.9.9") && !newer("1.0.0", "1.0.0"));
        let mut bad = m.clone();
        bad.id = "pg-15".into();
        assert!(
            bad.validate().is_err(),
            "all-digit component makes source names ambiguous"
        );
        let mut bad = m.clone();
        bad.kinds[0].secret_fields.push("nope".into());
        assert!(bad.validate().is_err(), "secret fields must be config properties");
        assert_eq!(Manifest::source_kind("postgresql"), "plugin:postgresql");
    }
}
