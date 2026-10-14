//! Restore files of a tree snapshot to a path on an agent.
//!
//! `RestoreBegin` (target, overwrite, confirm token typed in the UI) →
//! `RestoreReady`; then batches: `RestoreEntries { batch }` followed by one
//! `RestoreChunk` per chunk of the batch's regular files, in entry order and
//! chunk order (repeated chunks are sent again, so the agent can write each
//! file sequentially); finally `RestoreEnd` → `RestoreDone { stats }`.
//! Entry chunk lists carry the plain BLAKE3 hashes (mapping index, or
//! recomputed from the chunk data).
//!
//! Sources: any file-tree snapshot of the tenant (`host-<agent>`, `nas-…`,
//! `share-…`, `plugin-…`), and VM/CT files through a tar (`crate::tarbridge`).
//! Restores onto another host than the snapshot's own get the metadata the
//! target can sensibly take ([`Target::adapt`]).

use crate::map::MapDb;
use crate::tls::Session;
use crate::{name, source_name, valid_rel_path, TREE_INDEX};
use agent_proto::{Entry, Hash, Kind, Message, Overwrite, ScanStats};
use anyhow::{bail, Result};
use chunkstore::{Index, Store, TreeEntry, TreeKind};
use std::collections::HashSet;

pub struct Spec {
    pub job: u64,
    /// snapshot `<source>/<time>`: a file tree (`host-<agent>`, `nas-…`, `share-…`,
    /// `plugin-…`), or `vm-`/`ct-` for the tar bridge (informational there)
    pub source: String,
    pub time: u64,
    /// absolute paths inside the snapshot; `/` = everything
    pub paths: Vec<String>,
    pub target: String,
    pub overwrite: Overwrite,
    pub confirm: String,
    /// id of the agent restored to (`host-<id>` = restore onto the snapshot's own host)
    pub target_agent: String,
}

impl Spec {
    pub fn same_host(&self) -> bool {
        self.source == source_name(&self.target_agent)
    }
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

/// Index holding the file tree of a snapshot source; None: no file-tree source.
/// Plugin snapshots keep their files in `files` (crate plugin-host); `streams` are not files.
pub fn tree_index(source: &str) -> Option<&'static str> {
    let ok = source.len() <= 255 && source.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b));
    if !ok {
        None
    } else if source.starts_with("plugin-") {
        Some("files")
    } else if ["host-", "nas-", "share-"].iter().any(|p| source.starts_with(p)) {
        Some(TREE_INDEX)
    } else {
        None
    }
}

/// File tree of `<source>/<time>` (any file-tree source, see [`tree_index`]); plugin
/// snapshots with their streams below `.nexus-streams/`, as the file browser shows them.
pub fn load_source_tree(store: &Store, source: &str, time: u64) -> Result<Vec<TreeEntry>> {
    let Some(index) = tree_index(source) else {
        bail!("{source:?} is not a file-tree snapshot source (host-, nas-, share-, plugin-)");
    };
    let m = store.load_manifest(source, time)?;
    let tree = match store.load_index(&m, index)? {
        Index::Tree { entries } => entries,
        _ => bail!("{}/{time} is not a file tree snapshot", m.source),
    };
    if !source.starts_with("plugin-") || !m.indexes.iter().any(|i| i == "streams") {
        return Ok(tree);
    }
    match store.load_index(&m, "streams")? {
        Index::Dynamic { entries } => Ok(crate::files::with_streams(tree, &entries, time)),
        _ => bail!("{}/{time}: `streams` is not a dynamic index", m.source),
    }
}

/// File tree of the host snapshot `host-<agent_id>/<time>`.
pub fn load_tree(store: &Store, agent_id: &str, time: u64) -> Result<Vec<TreeEntry>> {
    load_source_tree(store, &source_name(agent_id), time)
}

/// What the target agent can take of another host's metadata.
#[derive(Clone, Copy, Debug, Default)]
pub struct Target {
    /// restoring onto the snapshot's own host: everything as recorded
    pub same_host: bool,
    /// Windows agent (`win-sd`): `win.*` xattrs, alternate data streams
    pub windows: bool,
    /// Linux agent with xattr support: `user.*` xattrs
    pub xattrs: bool,
}

/// Entries and xattrs left out by [`Target::adapt`] (logged, not errors).
#[derive(Debug, Default, PartialEq)]
pub struct Skipped {
    pub entries: u64,
    pub xattrs: u64,
}

impl Target {
    pub fn of(s: &Session, same_host: bool) -> Target {
        Target {
            same_host,
            windows: s.has_cap("win-sd"),
            xattrs: s.has_cap("xattrs"),
        }
    }

    /// Adapts an entry for another host than the snapshot's (docs/agent-protocol.md
    /// "Restore to another host"): owners are not mapped (uid/gid -1: the agent's
    /// restore user stays the owner; Windows ignores them), setuid/setgid/sticky bits
    /// are cleared, device nodes and sockets (and FIFOs on Windows) are skipped, xattrs are kept only where the
    /// target can store them (`user.*` on Linux, `win.*` on Windows; ACLs and SELinux
    /// labels of another host are dropped), alternate data streams only on Windows.
    /// false = skip the entry.
    pub fn adapt(&self, e: &mut Entry, sk: &mut Skipped) -> bool {
        if self.same_host {
            return true;
        }
        let ads = e.xattrs.iter().any(|(k, _)| k == b"win.ads");
        // Windows agents cannot create FIFOs (an error there); devices/sockets make no sense elsewhere
        let windows_fifo = self.windows && e.kind == Kind::Fifo;
        if matches!(e.kind, Kind::Device | Kind::Socket) || windows_fifo || (ads && !self.windows) {
            sk.entries += 1;
            return false;
        }
        e.uid = u32::MAX;
        e.gid = u32::MAX;
        e.mode &= !0o7000;
        let before = e.xattrs.len();
        e.xattrs.retain(|(k, _)| {
            if self.windows {
                k.starts_with(b"win.")
            } else {
                self.xattrs && k.starts_with(b"user.")
            }
        });
        sk.xattrs += (before - e.xattrs.len()) as u64;
        true
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
/// chunk references per batch: keeps `RestoreEntries` well below `MAX_FRAME`
const BATCH_CHUNKS: usize = 100_000;

/// Splits `items` into batches of at most `BATCH` entries and `BATCH_CHUNKS` chunk
/// references (an entry with more chunks gets a batch of its own).
pub(crate) fn batches<T>(items: &[T], chunks: impl Fn(&T) -> usize) -> Vec<&[T]> {
    let mut out = Vec::new();
    let (mut start, mut n) = (0, 0);
    for (i, x) in items.iter().enumerate() {
        let c = chunks(x);
        if i > start && (i - start == BATCH || n + c > BATCH_CHUNKS) {
            out.push(&items[start..i]);
            (start, n) = (i, 0);
        }
        n += c;
    }
    if start < items.len() {
        out.push(&items[start..]);
    }
    out
}

pub(crate) fn begin(s: &mut Session, spec: &Spec) -> Result<()> {
    s.send(&Message::RestoreBegin {
        job: spec.job,
        target: spec.target.clone(),
        overwrite: spec.overwrite,
        confirm: spec.confirm.clone(),
    })?;
    match s.recv()? {
        Message::RestoreReady => Ok(()),
        m => bail!("unexpected answer to RestoreBegin: {}", name(&m)),
    }
}

/// One chunk, LZ4-compressed on the wire if the agent can decode it.
pub(crate) fn send_chunk(s: &mut Session, lz4: bool, data: Vec<u8>) -> Result<()> {
    let hash = *blake3::hash(&data).as_bytes();
    match lz4.then(|| agent_proto::lz4_pack(&data)).flatten() {
        Some(c) => s.send(&Message::RestoreChunkLz4 {
            hash,
            raw_len: data.len() as u32,
            data: c,
        }),
        None => s.send(&Message::RestoreChunk { hash, data }),
    }
}

pub(crate) fn end(s: &mut Session, sk: &Skipped, log: &mut dyn FnMut(&str)) -> Result<ScanStats> {
    s.send(&Message::RestoreEnd)?;
    let stats = match s.recv()? {
        Message::RestoreDone { stats } => stats,
        m => bail!("unexpected answer to RestoreEnd: {}", name(&m)),
    };
    if *sk != Skipped::default() {
        log(&format!(
            "restore to another host: skipped {} entries (devices, sockets, alternate data streams) and {} xattrs the target cannot take",
            sk.entries, sk.xattrs
        ));
    }
    for e in &stats.errors {
        log(&format!("agent: {e:?}")); // escaped: agent text never starts a log line
    }
    Ok(stats)
}

pub fn restore(
    store: &Store,
    map: &MapDb,
    s: &mut Session,
    spec: &Spec,
    log: &mut dyn FnMut(&str),
) -> Result<ScanStats> {
    let tree = load_source_tree(store, &spec.source, spec.time)?;
    restore_tree(store, map, s, spec, &tree, log)
}

/// [`restore`] of a tree composed elsewhere (Phase 33 synthetic restore:
/// `chunkstore::synthetic::compose`); `spec.paths` select from it.
pub fn restore_tree(
    store: &Store,
    map: &MapDb,
    s: &mut Session,
    spec: &Spec,
    tree: &[TreeEntry],
    log: &mut dyn FnMut(&str),
) -> Result<ScanStats> {
    let lz4 = s.has_cap(agent_proto::CAP_LZ4); // chunks compressed on the wire if the agent can decode them
    let target = Target::of(s, spec.same_host());
    let sel = select(tree, &spec.paths)?;
    begin(s, spec)?;
    let (mut files, mut bytes, mut sk) = (0u64, 0u64, Skipped::default());
    for batch in batches(&sel, |e| e.chunks.len()) {
        let mut out = Vec::with_capacity(batch.len());
        let mut sent = Vec::with_capacity(batch.len());
        for e in batch {
            let mut chunks: Vec<(Hash, u32)> = Vec::with_capacity(e.chunks.len());
            for id in &e.chunks {
                // the mapping index knows (almost) every chunk an agent sent; else recompute
                // ponytail: nas/share/plugin trees read each chunk twice (hash, then send)
                chunks.push(match map.plain_of(id)? {
                    Some(p) => p,
                    None => {
                        let d = store.read_chunk(id)?;
                        (*blake3::hash(&d).as_bytes(), d.len() as u32)
                    }
                });
            }
            let mut en = Entry {
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
            };
            if target.adapt(&mut en, &mut sk) {
                out.push(en);
                sent.push(*e);
            }
        }
        s.send(&Message::RestoreEntries { batch: out })?;
        for e in sent.iter().filter(|e| e.kind == TreeKind::File) {
            files += 1;
            for id in &e.chunks {
                let data = store.read_chunk(id)?;
                bytes += data.len() as u64;
                send_chunk(s, lz4, data)?;
            }
        }
    }
    let stats = end(s, &sk, log)?;
    log(&format!(
        "sent {} entries ({files} files, {bytes} bytes) of {}/{} to {}",
        sel.len() as u64 - sk.entries,
        spec.source,
        spec.time,
        spec.target
    ));
    Ok(stats)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(kind: Kind, mode: u32, xattrs: &[&str]) -> Entry {
        Entry {
            path: b"a".to_vec(),
            kind,
            mode,
            uid: 1000,
            gid: 100,
            size: 0,
            mtime_ns: 0,
            ctime_ns: 0,
            inode: 0,
            rdev: 0,
            link_target: None,
            xattrs: xattrs.iter().map(|k| (k.as_bytes().to_vec(), b"v".to_vec())).collect(),
            chunks: vec![],
            unchanged: false,
            inconsistent: false,
        }
    }

    #[test]
    fn other_hosts_get_adapted_metadata() {
        let linux = Target {
            xattrs: true,
            ..Default::default()
        };
        let mut sk = Skipped::default();
        let mut e = entry(
            Kind::File,
            0o104755,
            &["user.a", "security.selinux", "system.posix_acl_access", "win.sd"],
        );
        assert!(linux.adapt(&mut e, &mut sk));
        assert_eq!(
            (e.uid, e.gid, e.mode),
            (u32::MAX, u32::MAX, 0o100755),
            "no owner, no setuid"
        );
        assert_eq!(e.xattrs, vec![(b"user.a".to_vec(), b"v".to_vec())]);
        assert_eq!(sk, Skipped { entries: 0, xattrs: 3 });
        for k in [Kind::Device, Kind::Socket] {
            assert!(!linux.adapt(&mut entry(k, 0o20644, &[]), &mut sk));
        }
        assert!(
            !linux.adapt(&mut entry(Kind::File, 0o644, &["win.ads"]), &mut sk),
            "alternate data streams only on Windows"
        );
        assert_eq!(sk.entries, 3);

        let win = Target {
            windows: true,
            ..Default::default()
        };
        let mut e = entry(Kind::File, 0o644, &["win.ads", "win.sd", "user.a"]);
        assert!(win.adapt(&mut e, &mut sk));
        assert_eq!(e.xattrs.len(), 2);
        assert!(
            !win.adapt(&mut entry(Kind::Fifo, 0o10644, &[]), &mut sk),
            "no FIFOs on Windows"
        );
        assert!(linux.adapt(&mut entry(Kind::Fifo, 0o10644, &[]), &mut sk));

        // without xattr support nothing is kept; the own host keeps everything
        let mut e = entry(Kind::File, 0o4755, &["user.a"]);
        assert!(Target::default().adapt(&mut e, &mut sk) && e.xattrs.is_empty());
        let own = Target {
            same_host: true,
            ..Default::default()
        };
        let mut e = entry(Kind::Device, 0o4755, &["security.selinux"]);
        assert!(own.adapt(&mut e, &mut sk));
        assert_eq!((e.uid, e.mode, e.xattrs.len()), (1000, 0o4755, 1));
    }

    #[test]
    fn sources_and_batches() {
        assert_eq!(tree_index("host-0123456789abcdef"), Some("tree"));
        assert_eq!(tree_index("nas-3-tank.data"), Some("tree"));
        assert_eq!(tree_index("share-2"), Some("tree"));
        assert_eq!(tree_index("plugin-pgx-9-db1"), Some("files"));
        assert_eq!(tree_index("vm-100"), None);
        assert_eq!(tree_index("host-../x"), None);
        let v: Vec<usize> = vec![1; 2500];
        let b = batches(&v, |c| *c);
        assert_eq!(b.iter().map(|x| x.len()).collect::<Vec<_>>(), [1000, 1000, 500]);
        let v = vec![60_000, 60_000, 1, 200_000];
        let b = batches(&v, |c| *c);
        assert_eq!(
            b.iter().map(|x| x.len()).collect::<Vec<_>>(),
            [1, 2, 1],
            "a huge entry gets a batch of its own"
        );
        assert!(batches(&Vec::<usize>::new(), |c| *c).is_empty());
    }
}
