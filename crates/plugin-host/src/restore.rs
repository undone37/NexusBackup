//! Restore op: the plugin asks for snapshot content (`NeedFiles` / `NeedStreams`),
//! the host streams it from the store (`FileBegin`/`Data`/`FileEnd`,
//! `Stream`/`Data`/`StreamEnd`, then `NeedDone`); the plugin writes it to its
//! target system and ends with `Done` (or `Error`). The host never writes
//! anywhere itself and serves only the selected snapshot of this source.

use crate::backup::{msg_name, read_state, LogSink};
use crate::sandbox::Peer;
use crate::{escape, meta_of, FILES_INDEX, STREAMS_INDEX};
use anyhow::{bail, Result};
use chunkstore::{FileEntry, Index, Store, TreeEntry, TreeKind};
use plugin_proto::{BaseInfo, Message, Op, API, MAX_DATA};
use serde_json::{json, Value};

/// A plugin snapshot loaded for restore / mount / download.
pub struct Snapshot {
    pub source: String,
    pub time: u64,
    /// sorted by path (bytes)
    pub files: Vec<TreeEntry>,
    pub streams: Vec<FileEntry>,
    pub state: Option<Vec<u8>>,
}

impl Snapshot {
    pub fn load(store: &Store, source: &str, time: u64) -> Result<Snapshot> {
        let m = store.load_manifest(source, time)?;
        let mut files = match store.load_index(&m, FILES_INDEX)? {
            Index::Tree { entries } => entries,
            _ => bail!("{source}/{time} is not a plugin snapshot"),
        };
        files.sort_by(|a, b| a.path.cmp(&b.path));
        let streams = if m.indexes.iter().any(|i| i == STREAMS_INDEX) {
            match store.load_index(&m, STREAMS_INDEX)? {
                Index::Dynamic { entries } => entries,
                _ => bail!("{source}/{time}: `streams` is not a dynamic index"),
            }
        } else {
            Vec::new()
        };
        Ok(Snapshot {
            source: source.to_owned(),
            time,
            files,
            streams,
            state: read_state(store, &m)?,
        })
    }

    /// `path` itself and everything below it.
    pub fn subtree(&self, path: &[u8]) -> Vec<&TreeEntry> {
        let mut out: Vec<&TreeEntry> = self.file(path).into_iter().collect();
        // sorted by bytes: everything below `path/` lies in ["path/", "path0")
        let lo_key = [path, b"/"].concat();
        let hi_key = [path, b"0"].concat();
        let lo = self.files.partition_point(|e| e.path < lo_key);
        let hi = self.files.partition_point(|e| e.path < hi_key);
        out.extend(&self.files[lo..hi.max(lo)]);
        out
    }

    pub fn file(&self, path: &[u8]) -> Option<&TreeEntry> {
        self.files
            .binary_search_by(|e| e.path.as_slice().cmp(path))
            .ok()
            .map(|i| &self.files[i])
    }

    /// Top-level names (for the plugin: what it can ask for).
    pub fn top(&self) -> Vec<String> {
        let mut v: Vec<String> = self
            .files
            .iter()
            .filter(|e| !e.path.contains(&b'/'))
            .map(|e| String::from_utf8_lossy(&e.path).into_owned())
            .collect();
        v.truncate(10_000);
        v
    }

    /// Init params common to restore and mount.
    pub fn init_params(&self, extra: Value) -> Value {
        let mut p = json!({
            "snapshot": {"source": self.source, "time": self.time},
            "streams": self.streams.iter().take(100_000).map(|s| json!({"name": s.path, "size": s.size})).collect::<Vec<_>>(),
            "top": self.top(),
            "files": self.files.len(),
        });
        if let (Some(o), Some(e)) = (p.as_object_mut(), extra.as_object()) {
            o.extend(e.clone());
        }
        p
    }
}

/// Init params of a restore beyond the snapshot: the restore id, the user's
/// params and, for a restore into another source, `target_source_id`.
fn restore_extra(p: &Params) -> Value {
    let mut v = json!({"restore": p.restore, "params": p.params});
    if let Some(t) = p.target_source_id {
        v["target_source_id"] = json!(t);
    }
    v
}

/// Sends `chunks` as `Data` frames (≤ MAX_DATA each).
fn send_chunks(store: &Store, peer: &mut dyn Peer, chunks: &[chunkstore::ChunkId]) -> Result<u64> {
    let mut n = 0;
    for c in chunks {
        let data = store.read_chunk(c)?;
        for piece in data.chunks(MAX_DATA) {
            peer.send(&Message::Data { bytes: piece.to_vec() })?;
            n += piece.len() as u64;
        }
    }
    Ok(n)
}

pub struct Params<'a> {
    pub job: u64,
    pub kind: &'a str,
    pub config: &'a str,
    /// restore id from the manifest (`to_target`, `pitr`, …)
    pub restore: &'a str,
    /// user parameters (validated against the restore's params_schema by the web-api)
    pub params: Value,
    pub max_log_bytes: usize,
    /// restore with another source's config (`target_source` restores): its id
    pub target_source_id: Option<u64>,
}

#[derive(Debug, Default)]
pub struct Report {
    pub files_sent: u64,
    pub streams_sent: u64,
    pub bytes_sent: u64,
    pub summary: String,
    pub consistent: bool,
}

pub fn run(
    store: &Store,
    peer: &mut dyn Peer,
    snap: &Snapshot,
    p: &Params,
    out: &mut dyn FnMut(&str),
) -> Result<Report> {
    peer.send(&Message::Init {
        api: API,
        job: p.job,
        kind: p.kind.to_owned(),
        op: Op::Restore,
        config: p.config.to_owned(),
        params: snap
            .init_params(restore_extra(p))
            .to_string(),
        base: Some(BaseInfo { time: snap.time }),
        state: snap.state.clone(),
    })?;
    let mut log = LogSink {
        out,
        left: p.max_log_bytes,
        last_progress: None,
    };
    let mut r = Report::default();
    loop {
        match peer.recv()? {
            Message::Log { level, text } => log.log(level, &text),
            Message::Progress { done, total, text } => log.progress(done, total, &text),
            Message::NeedFiles { paths } => {
                for path in &paths {
                    for e in snap.subtree(path) {
                        peer.send(&Message::FileBegin {
                            path: e.path.clone(),
                            meta: meta_of(e),
                        })?;
                        if e.kind == TreeKind::File {
                            r.bytes_sent += send_chunks(store, peer, &e.chunks)?;
                            r.files_sent += 1;
                        }
                        peer.send(&Message::FileEnd)?;
                    }
                }
                peer.send(&Message::NeedDone)?;
            }
            Message::NeedStreams { names } => {
                for name in &names {
                    if let Some(s) = snap.streams.iter().find(|s| &s.path == name) {
                        peer.send(&Message::Stream { name: s.path.clone() })?;
                        r.bytes_sent += send_chunks(store, peer, &s.chunks)?;
                        peer.send(&Message::StreamEnd)?;
                        r.streams_sent += 1;
                    }
                }
                peer.send(&Message::NeedDone)?;
            }
            Message::Done {
                summary, consistent, ..
            } => {
                r.summary = summary;
                r.consistent = consistent;
                break;
            }
            Message::Error { code, message } => {
                peer.finish();
                bail!("plugin reported an error ({code}): {}", escape(&message, 2000));
            }
            other => return Err(peer.violation(&format!("unexpected message {} during restore", msg_name(&other)))),
        }
    }
    peer.finish();
    Ok(r)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn e(p: &str) -> TreeEntry {
        TreeEntry {
            path: p.as_bytes().to_vec(),
            kind: TreeKind::File,
            mode: 0o644,
            uid: 0,
            gid: 0,
            size: 0,
            mtime_ns: 0,
            ctime_ns: 0,
            inode: 0,
            rdev: 0,
            link_target: None,
            xattrs: vec![],
            chunks: vec![],
            inconsistent: false,
        }
    }

    #[test]
    fn subtree_selection() {
        let mut files: Vec<_> = ["a", "a-x", "a/b", "a/b/c", "a/d", "ab", "b", "b/x"]
            .iter()
            .map(|p| e(p))
            .collect();
        files.sort_by(|a, b| a.path.cmp(&b.path));
        let s = Snapshot {
            source: "s".into(),
            time: 1,
            files,
            streams: vec![],
            state: None,
        };
        let names = |p: &str| -> Vec<String> {
            s.subtree(p.as_bytes())
                .iter()
                .map(|e| String::from_utf8_lossy(&e.path).into_owned())
                .collect()
        };
        assert_eq!(names("a"), ["a", "a/b", "a/b/c", "a/d"]);
        assert_eq!(names("a/b"), ["a/b", "a/b/c"]);
        assert_eq!(names("b/x"), ["b/x"]);
        assert!(names("c").is_empty());
        assert_eq!(s.top(), ["a", "a-x", "ab", "b"]);
        assert!(s.file(b"a/d").is_some() && s.file(b"a/e").is_none());
    }
}
