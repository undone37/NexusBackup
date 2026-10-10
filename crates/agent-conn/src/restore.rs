//! Restore files of a tree snapshot to a path on an agent.
//!
//! `RestoreBegin` (target, overwrite, confirm token typed in the UI) →
//! `RestoreReady`; then batches: `RestoreEntries { batch }` followed by one
//! `RestoreChunk` per chunk of the batch's regular files, in entry order and
//! chunk order (repeated chunks are sent again, so the agent can write each
//! file sequentially); finally `RestoreEnd` → `RestoreDone { stats }`.
//! Entry chunk lists carry the plain BLAKE3 hashes (mapping index, or
//! recomputed from the chunk data).

use crate::map::MapDb;
use crate::tls::Session;
use crate::{name, source_name, valid_rel_path, TREE_INDEX};
use agent_proto::{Entry, Hash, Kind, Message, Overwrite, ScanStats};
use anyhow::{bail, Result};
use chunkstore::{Index, Store, TreeEntry, TreeKind};
use std::collections::HashSet;

pub struct Spec {
    pub job: u64,
    /// snapshot `host-<source_agent>/<time>`
    pub source_agent: String,
    pub time: u64,
    /// absolute paths inside the snapshot; `/` = everything
    pub paths: Vec<String>,
    pub target: String,
    pub overwrite: Overwrite,
    pub confirm: String,
}

pub fn parse_overwrite(s: &str) -> Result<Overwrite> {
    Ok(match s {
        "never" => Overwrite::Never,
        "if_older" => Overwrite::IfOlder,
        "always" => Overwrite::Always,
        _ => bail!("overwrite must be never, if_older or always"),
    })
}

/// `/etc/ssh/` → `etc/ssh`; `/` → empty (= everything).
pub fn request_path(p: &str) -> Result<Vec<u8>> {
    let t = p.trim_matches('/');
    if t.is_empty() {
        return Ok(Vec::new());
    }
    if !p.starts_with('/') || !valid_rel_path(t.as_bytes()) {
        bail!("invalid path {p:?} (absolute, no . or .. components)");
    }
    Ok(t.as_bytes().to_vec())
}

fn under(path: &[u8], sel: &[u8]) -> bool {
    sel.is_empty() || path == sel || (path.starts_with(sel) && path.get(sel.len()) == Some(&b'/'))
}

/// Entries selected by `paths` plus the directories above them (so parents are
/// created with their recorded metadata), in snapshot order.
pub fn select<'a>(entries: &'a [TreeEntry], paths: &[String]) -> Result<Vec<&'a TreeEntry>> {
    let sel: Vec<Vec<u8>> = paths.iter().map(|p| request_path(p)).collect::<Result<_>>()?;
    let mut parents: HashSet<&[u8]> = HashSet::new();
    for s in &sel {
        let mut i = 0;
        while let Some(k) = s[i..].iter().position(|b| *b == b'/') {
            parents.insert(&s[..i + k]);
            i += k + 1;
        }
    }
    let out: Vec<&TreeEntry> = entries
        .iter()
        .filter(|e| {
            sel.iter().any(|s| under(&e.path, s)) || (e.kind == TreeKind::Dir && parents.contains(e.path.as_slice()))
        })
        .collect();
    if out.is_empty() {
        bail!("no matching paths in the snapshot");
    }
    Ok(out)
}

pub fn load_tree(store: &Store, agent_id: &str, time: u64) -> Result<Vec<TreeEntry>> {
    let m = store.load_manifest(&source_name(agent_id), time)?;
    match store.load_index(&m, TREE_INDEX)? {
        Index::Tree { entries } => Ok(entries),
        _ => bail!("{}/{time} is not a file tree snapshot", m.source),
    }
}

fn proto_kind(k: &TreeKind) -> Kind {
    match k {
        TreeKind::File => Kind::File,
        TreeKind::Dir => Kind::Dir,
        TreeKind::Symlink => Kind::Symlink,
        TreeKind::Hardlink => Kind::Hardlink,
        TreeKind::Device => Kind::Device,
        TreeKind::Fifo => Kind::Fifo,
        TreeKind::Socket => Kind::Socket,
    }
}

const BATCH: usize = 1000;

pub fn restore(
    store: &Store,
    map: &MapDb,
    s: &mut Session,
    spec: &Spec,
    log: &mut dyn FnMut(&str),
) -> Result<ScanStats> {
    let tree = load_tree(store, &spec.source_agent, spec.time)?;
    let lz4 = s.has_cap(agent_proto::CAP_LZ4); // chunks compressed on the wire if the agent can decode them
    let sel = select(&tree, &spec.paths)?;
    s.send(&Message::RestoreBegin {
        job: spec.job,
        target: spec.target.clone(),
        overwrite: spec.overwrite,
        confirm: spec.confirm.clone(),
    })?;
    match s.recv()? {
        Message::RestoreReady => {}
        m => bail!("unexpected answer to RestoreBegin: {}", name(&m)),
    }
    let (mut files, mut bytes) = (0u64, 0u64);
    for batch in sel.chunks(BATCH) {
        let mut out = Vec::with_capacity(batch.len());
        for e in batch {
            let mut chunks: Vec<(Hash, u32)> = Vec::with_capacity(e.chunks.len());
            for id in &e.chunks {
                // the mapping index knows (almost) every chunk an agent sent; else recompute
                chunks.push(match map.plain_of(id)? {
                    Some(p) => p,
                    None => {
                        let d = store.read_chunk(id)?;
                        (*blake3::hash(&d).as_bytes(), d.len() as u32)
                    }
                });
            }
            out.push(Entry {
                path: e.path.clone(),
                kind: proto_kind(&e.kind),
                mode: e.mode,
                uid: e.uid,
                gid: e.gid,
                size: e.size,
                mtime_ns: e.mtime_ns,
                ctime_ns: e.ctime_ns,
                inode: e.inode,
                rdev: e.rdev,
                link_target: e.link_target.clone(),
                xattrs: e.xattrs.clone(),
                chunks,
                unchanged: false,
                inconsistent: e.inconsistent,
            });
        }
        s.send(&Message::RestoreEntries { batch: out })?;
        for e in batch.iter().filter(|e| e.kind == TreeKind::File) {
            files += 1;
            for id in &e.chunks {
                let data = store.read_chunk(id)?;
                bytes += data.len() as u64;
                let hash = *blake3::hash(&data).as_bytes();
                match lz4.then(|| agent_proto::lz4_pack(&data)).flatten() {
                    Some(c) => s.send(&Message::RestoreChunkLz4 {
                        hash,
                        raw_len: data.len() as u32,
                        data: c,
                    })?,
                    None => s.send(&Message::RestoreChunk { hash, data })?,
                }
            }
        }
    }
    s.send(&Message::RestoreEnd)?;
    let stats = match s.recv()? {
        Message::RestoreDone { stats } => stats,
        m => bail!("unexpected answer to RestoreEnd: {}", name(&m)),
    };
    log(&format!(
        "sent {} entries ({files} files, {bytes} bytes) to {}",
        sel.len(),
        spec.target
    ));
    for e in &stats.errors {
        log(&format!("agent: {e:?}")); // escaped: agent text never starts a log line
    }
    Ok(stats)
}
