//! The generic `download` restore (no plugin involved): the snapshot's files plus
//! its streams below `.nexus-streams/<name>`, listed and written as tar/zip with
//! the agents' file module (same JSON listing as the other connectors).

use crate::restore::Snapshot;
use anyhow::Result;
use chunkstore::{TreeEntry, TreeKind};
use plugin_proto::STREAMS_DIR;
use std::collections::BTreeSet;

fn dir_entry(path: Vec<u8>, mtime: i64) -> TreeEntry {
    TreeEntry {
        path,
        kind: TreeKind::Dir,
        mode: 0o40755,
        uid: 0,
        gid: 0,
        size: 0,
        mtime_ns: mtime * 1_000_000_000,
        ctime_ns: 0,
        inode: 0,
        rdev: 0,
        link_target: None,
        xattrs: Vec::new(),
        chunks: Vec::new(),
        inconsistent: false,
    }
}

/// Files + streams as one tree (streams as regular files, mode 0600, snapshot time).
pub fn view(s: &Snapshot) -> Vec<TreeEntry> {
    let mut out = s.files.clone();
    if s.streams.is_empty() {
        return out;
    }
    let mut dirs: BTreeSet<Vec<u8>> = BTreeSet::new();
    dirs.insert(STREAMS_DIR.as_bytes().to_vec());
    for st in &s.streams {
        let p = format!("{STREAMS_DIR}/{}", st.path);
        let mut i = 0;
        while let Some(k) = p[i..].find('/') {
            dirs.insert(p.as_bytes()[..i + k].to_vec());
            i += k + 1;
        }
    }
    out.extend(dirs.into_iter().map(|d| dir_entry(d, s.time as i64)));
    for st in &s.streams {
        out.push(TreeEntry {
            path: format!("{STREAMS_DIR}/{}", st.path).into_bytes(),
            kind: TreeKind::File,
            mode: 0o100600,
            size: st.size,
            mtime_ns: st.mtime * 1_000_000_000,
            chunks: st.chunks.clone(),
            ..dir_entry(Vec::new(), 0)
        });
    }
    out
}

pub fn list(s: &Snapshot, dir: &str) -> Result<Vec<agent_conn::files::ListEntry>> {
    agent_conn::files::list(&view(s), dir)
}
