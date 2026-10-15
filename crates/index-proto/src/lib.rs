//! nexus-index protocol (Phase 31b, docs/file-index-v2-plan.md): one JSON
//! request line per connection on a Unix socket, one JSON answer line
//! (`{"ok": …}` or `{"err": "…"}`). Used by the web-api (search, status), the
//! scheduler (nudges after commits and deletions, per-source rules, health)
//! and the service itself. No tantivy here: the web-api links only this.

#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

/// Socket path of the nexus-index service unless the configuration names another.
pub const DEFAULT_SOCKET: &str = "/run/nexus-index/index.sock";
/// Longest request / answer line.
pub const MAX_LINE: u64 = 16 << 20;
/// Longest search term `q`, in bytes.
pub const MAX_QUERY: usize = 256;
/// Largest page size (`limit`), in file versions.
pub const MAX_LIMIT: usize = 200;
/// Page size when the request has no `limit`.
pub const DEFAULT_LIMIT: usize = 50;

/// One request line, `{"op": "<variant>", ...fields}`.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Request {
    /// File search (web-api); answer: [`SearchResp`].
    Search(SearchReq),
    /// Something changed in the tenant's store (commit, deletion, hold): sync soon.
    /// Sent by the scheduler; answer: `{"queued": tenant}`.
    Sync {
        /// tenant whose store changed
        tenant: String,
    },
    /// The rules of the tenant's sources (scheduler, from the groups); answer:
    /// `{"changed": bool}`, changed sources are ingested again.
    Config {
        /// tenant the rules belong to
        tenant: String,
        /// rules per source name; a source missing here gets [`SourceRules::default`]
        sources: BTreeMap<String, SourceRules>,
    },
    /// Index health (web-api, scheduler); answer: [`Status`].
    Status {
        /// only this tenant; absent: every tenant with an index on disk
        #[serde(default)]
        tenant: Option<String>,
    },
    /// Drop the tenant's index and build it again from the name indexes (web-api, admin
    /// only); answer: `{"rebuilt": tenant}`.
    Rebuild {
        /// tenant whose index is rebuilt
        tenant: String,
    },
}

/// How the search term `q` is matched.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, Default, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    /// `/` in the query: path glob; `*?[`: name glob; else words
    #[default]
    Auto,
    /// glob (`*`, `?`) or substring on the file name, case-insensitive
    Name,
    /// glob on the whole guest path, case-insensitive
    Path,
    /// every word (up to 8) starts a word of the path
    Words,
}

/// Filter on whether a file version is still present.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, Default, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Deleted {
    /// every version
    #[default]
    Any,
    /// files no longer in the newest indexed snapshot of their source
    Only,
    /// files still present
    Exclude,
}

/// One search page (`op: search`); unknown fields are refused. Checked by [`SearchReq::validate`].
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SearchReq {
    /// tenant whose index is searched (the web-api sets the caller's tenant)
    pub tenant: String,
    /// name / path glob or words; may be empty when other filters are set
    #[serde(default)]
    pub q: String,
    /// how `q` is matched; absent: [`Mode::Auto`]
    #[serde(default)]
    pub mode: Mode,
    /// only these sources (the web-api resolves source and group filters)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sources: Option<Vec<String>>,
    /// source kinds: vm, ct, host, nas, share, plugin
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kinds: Option<Vec<String>>,
    /// file extensions without the dot, case-insensitive; absent or empty: any
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ext: Option<Vec<String>>,
    /// smallest file size in bytes (inclusive); absent: no lower bound
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size_min: Option<u64>,
    /// largest file size in bytes (inclusive); absent: no upper bound
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size_max: Option<u64>,
    /// earliest modification time, unix seconds (inclusive); absent: no lower bound
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtime_from: Option<i64>,
    /// latest modification time, unix seconds (inclusive); absent: no upper bound
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtime_to: Option<i64>,
    /// `file` | `dir`; absent: both
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entry: Option<String>,
    /// present / deleted filter; absent: [`Deleted::Any`]
    #[serde(default)]
    pub deleted: Deleted,
    /// page size in file versions, 1..=[`MAX_LIMIT`]; absent: [`DEFAULT_LIMIT`]
    #[serde(default = "default_limit")]
    pub limit: usize,
    /// `next` of the previous page (opaque, at most 64 bytes); absent: first page
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
}

fn default_limit() -> usize {
    DEFAULT_LIMIT
}

impl SearchReq {
    /// The checks both sides make (web-api before forwarding, the service again).
    pub fn validate(&self) -> Result<(), String> {
        if self.q.len() > MAX_QUERY || self.q.chars().any(char::is_control) {
            return Err(format!("q: at most {MAX_QUERY} characters, no control characters"));
        }
        let filtered = self.ext.as_ref().is_some_and(|e| !e.is_empty())
            || self.size_min.is_some()
            || self.size_max.is_some()
            || self.mtime_from.is_some()
            || self.mtime_to.is_some()
            || self.deleted == Deleted::Only;
        if self.q.trim().is_empty() && !filtered {
            return Err("q: a search term or a filter (extension, size, time, deleted) is needed".into());
        }
        if !(1..=MAX_LIMIT).contains(&self.limit) {
            return Err(format!("limit: 1..={MAX_LIMIT}"));
        }
        if let Some(e) = &self.entry {
            if e != "file" && e != "dir" {
                return Err("entry: file or dir".into());
            }
        }
        for e in self.ext.iter().flatten() {
            if e.is_empty() || e.len() > 32 || !e.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '-') {
                return Err("ext: letters, digits, - and _ (without the dot)".into());
            }
        }
        for k in self.kinds.iter().flatten() {
            if !KINDS.contains(&k.as_str()) {
                return Err(format!("kinds: one of {}", KINDS.join(", ")));
            }
        }
        if self.sources.as_ref().is_some_and(|s| s.len() > 10_000) {
            return Err("sources: too many".into());
        }
        if let (Some(a), Some(b)) = (self.size_min, self.size_max) {
            if a > b {
                return Err("size_min: above size_max".into());
            }
        }
        if let (Some(a), Some(b)) = (self.mtime_from, self.mtime_to) {
            if a > b {
                return Err("mtime_from: after mtime_to".into());
            }
        }
        if self.cursor.as_ref().is_some_and(|c| c.len() > 64) {
            return Err("cursor: invalid".into());
        }
        Ok(())
    }
}

/// Source kinds by source name prefix.
pub const KINDS: &[&str] = &["vm", "ct", "host", "nas", "share", "plugin"];

/// Kind of a source from its name prefix (`vm-100` is `vm`); `other` for an unknown prefix.
pub fn source_kind(source: &str) -> &'static str {
    for k in KINDS {
        if source.starts_with(&format!("{k}-")) {
            return k;
        }
    }
    "other"
}

/// One version of a file: present in the snapshots `first` ≤ t < `gone`.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Version {
    /// file size in bytes
    pub size: u64,
    /// modification time, unix seconds
    pub mtime: i64,
    /// first snapshot (time, unix seconds) holding this version
    pub first: u64,
    /// first later indexed snapshot (time) without it; `None`: still in the newest
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gone: Option<u64>,
    /// owner when the name index records one (Phase 31c: VM disks; Windows SID
    /// `S-1-5-21-…`, Linux `uid:gid`), as of the version's first snapshot
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
}

/// One file (or directory) of one source, with its versions, newest first.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Hit {
    /// source name (`vm-100`, `host-a1`, ...)
    pub source: String,
    /// guest path as shown (`/etc/hosts`, `C:/Users/ann/x.docx`, `share/x`)
    pub path: String,
    /// file-browser path (name index; open, download, restore)
    pub browse: String,
    /// `file` | `dir` | `symlink` | `other`
    pub kind: String,
    /// the matching versions, newest first
    pub versions: Vec<Version>,
}

/// Indexed / not indexed snapshot times of a source (timeline marks).
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct SourceSnaps {
    /// snapshot times (unix seconds) in the search index
    pub indexed: Vec<u64>,
    /// snapshots without a name index (yet) or excluded by the rules
    pub unindexed: Vec<u64>,
}

/// Answer to [`Request::Search`]: one page of hits.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct SearchResp {
    /// files of this page, each with its matching versions
    pub hits: Vec<Hit>,
    /// cursor of the next page; absent: last page
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next: Option<String>,
    /// time the service spent on the query, milliseconds
    pub elapsed_ms: u64,
    /// the sources of the hits
    pub sources: BTreeMap<String, SourceSnaps>,
    /// snapshots waiting to be ingested (the index is behind when not 0)
    pub pending: u64,
}

/// Which entries of a source go into the search index (the sealed name index
/// always holds everything). Rule syntax as Cohesity: `/` separators also for
/// Windows, `/C/…` one drive, `/…` every drive, `*` per component, the most
/// specific rule wins.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct SourceRules {
    /// index this source at all; absent: true
    #[serde(default = "yes")]
    pub enabled: bool,
    /// apply the built-in excludes ([`DEFAULT_EXCLUDES`]); absent: true
    #[serde(default = "yes")]
    pub defaults: bool,
    /// trees to index even inside an excluded one (rule syntax above)
    #[serde(default)]
    pub include: Vec<String>,
    /// trees to leave out of the search index (rule syntax above)
    #[serde(default)]
    pub exclude: Vec<String>,
}

fn yes() -> bool {
    true
}

impl Default for SourceRules {
    fn default() -> Self {
        SourceRules {
            enabled: true,
            defaults: true,
            include: Vec::new(),
            exclude: Vec::new(),
        }
    }
}

/// Windows excludes (Cohesity's list) and Linux system trees; `/var` stays
/// searchable (databases, web and mail data live there).
pub const DEFAULT_EXCLUDES: &[&str] = &[
    "/$Recycle.Bin",
    "/Windows",
    "/Program Files",
    "/Program Files (x86)",
    "/ProgramData",
    "/System Volume Information",
    "/Users/*/AppData",
    "/Recovery",
    "/proc",
    "/sys",
    "/dev",
    "/run",
    "/tmp",
    "/usr",
    "/lib",
    "/lib64",
    "/boot",
    "/var/cache",
    "/var/tmp",
    "/var/lib/docker",
    "/var/lib/containerd",
];

/// Checks a rule: absolute, `/`-separated, no `.`/`..`, at most 64 components.
pub fn valid_rule(r: &str) -> bool {
    r.starts_with('/')
        && r.len() <= 1024
        && !r.chars().any(char::is_control)
        && r.split('/').skip(1).count() <= 64
        && r.split('/').skip(1).all(|c| c != "." && c != "..")
}

/// Index state of one tenant (part of [`Status`]).
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct TenantStatus {
    /// tenant name
    pub tenant: String,
    /// file versions in the search index
    pub docs: u64,
    /// sealed index bytes on disk
    pub bytes: u64,
    /// sources of the tenant that have snapshots
    pub sources: u64,
    /// snapshots in the search index
    pub snapshots_indexed: u64,
    /// snapshots with a name index that is not in the search index yet
    pub snapshots_pending: u64,
    /// time (unix seconds) of the oldest such snapshot; absent: none pending
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oldest_pending: Option<u64>,
    /// snapshots without a name index (VM/CT not indexed, excluded)
    pub snapshots_unindexed: u64,
    /// time of the last sync (also a failed one), unix seconds; absent: none since the service started
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_sync: Option<u64>,
    /// error of the last sync; absent: it succeeded
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Answer to [`Request::Status`].
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct Status {
    /// the requested tenant, or every tenant with an index on disk
    pub tenants: Vec<TenantStatus>,
    /// free bytes on the index file system
    pub free_bytes: u64,
    /// ingestion pauses below this many free bytes
    pub floor_bytes: u64,
    /// ingestion is paused (free space below the floor)
    pub paused: bool,
    /// decrypted index blocks in memory
    pub cache_bytes: u64,
    /// upper bound of `cache_bytes`
    pub cache_limit: u64,
}

/// Sends one request and returns the `ok` value (blocking, with a timeout).
pub fn call(socket: &Path, req: &Request, timeout: Duration) -> io::Result<serde_json::Value> {
    let mut s = UnixStream::connect(socket)?;
    s.set_read_timeout(Some(timeout))?;
    s.set_write_timeout(Some(timeout))?;
    let mut line = serde_json::to_vec(req)?;
    line.push(b'\n');
    s.write_all(&line)?;
    s.shutdown(std::net::Shutdown::Write)?;
    let mut buf = Vec::new();
    BufReader::new(s).take(MAX_LINE).read_until(b'\n', &mut buf)?;
    let v: serde_json::Value = serde_json::from_slice(&buf)?;
    if let Some(e) = v.get("err") {
        return Err(io::Error::other(e.as_str().unwrap_or("nexus-index error").to_owned()));
    }
    v.get("ok")
        .cloned()
        .ok_or_else(|| io::Error::other("nexus-index: malformed answer"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_format() {
        let r: Request = serde_json::from_str(r#"{"op":"search","tenant":"t","q":"*.pdf","ext":["pdf"]}"#).unwrap();
        let Request::Search(s) = &r else { panic!() };
        assert_eq!((s.limit, s.mode, s.deleted), (DEFAULT_LIMIT, Mode::Auto, Deleted::Any));
        assert!(s.validate().is_ok());
        assert!(serde_json::from_str::<Request>(r#"{"op":"search","tenant":"t","bogus":1}"#).is_err());
        let r: Request =
            serde_json::from_str(r#"{"op":"config","tenant":"t","sources":{"vm-1":{"exclude":["/data"]}}}"#).unwrap();
        let Request::Config { sources, .. } = r else { panic!() };
        assert!(sources["vm-1"].enabled && sources["vm-1"].defaults);
    }

    #[test]
    fn validation() {
        let ok = SearchReq {
            tenant: "t".into(),
            q: "invoice".into(),
            limit: 10,
            ..Default::default()
        };
        assert!(ok.validate().is_ok());
        let bad = |f: &dyn Fn(&mut SearchReq)| {
            let mut r = ok.clone();
            f(&mut r);
            r.validate().is_err()
        };
        assert!(bad(&|r| r.q = String::new()));
        assert!(bad(&|r| r.q = "a\nb".into()));
        assert!(bad(&|r| r.limit = 0));
        assert!(bad(&|r| r.ext = Some(vec![".pdf".into()])));
        assert!(bad(&|r| r.kinds = Some(vec!["disk".into()])));
        assert!(bad(&|r| r.entry = Some("x".into())));
        assert!(bad(&|r| (r.size_min, r.size_max) = (Some(5), Some(1))));
        let mut only = ok.clone();
        only.q.clear();
        only.deleted = Deleted::Only;
        assert!(only.validate().is_ok(), "deleted files without a term");
        assert_eq!(source_kind("vm-100"), "vm");
        assert_eq!(source_kind("host-a1"), "host");
        assert!(valid_rule("/Users/*/AppData") && !valid_rule("Users") && !valid_rule("/a/../b"));
    }
}
