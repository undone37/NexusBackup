//! Per-snapshot file name index (docs/file-index.md): the names, sizes, mtimes
//! and kinds of a snapshot's files, sealed with the tenant keyring next to the
//! manifest (`snapshots/<source>/<time>/names`). It is written at commit for
//! file-tree snapshots (agents, NAS, plugins), later for VM/CT disks (opt-in,
//! nexus-pve `files … index`), and goes away with the snapshot directory.
//! File names never leave the tenant's sealed store; searching needs the key.
//!
//! Format versions (both postcard, sealed): v1 (context `names:<source>/<time>`)
//! has paths, sizes, mtimes and kinds; v2 (context `names2:<source>/<time>`,
//! Phase 28) adds the SHA-256 of regular files for the IOC hash hunt (sparse:
//! `(entry index, hash)`). An index without hashes is still written as v1, so
//! the previous release reads every snapshot taken without `file_hashes`.
//! Readers try v2, then v1. The name index never goes offsite (derived data).

use crate::crypto::invalid;
use crate::store::{write_atomic, Index, Manifest, Store, TreeEntry, TreeKind};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io;

pub const FILE: &str = "names";

/// SHA-256 of a regular file's content (IOC hash hunt, Phase 28).
pub type Sha256 = [u8; 32];

/// SHA-256 of the empty file (files without chunks need no read).
pub const EMPTY_SHA256: Sha256 = [
    0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24, 0x27, 0xae, 0x41,
    0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
];

/// Column layout: one NUL-separated string for all paths (decodes with one
/// copy instead of one allocation per name) plus parallel arrays.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct NameIndex {
    /// paths relative to the snapshot root, `/`-separated, NUL-terminated each
    pub paths: String,
    pub size: Vec<u64>,
    /// seconds
    pub mtime: Vec<i64>,
    pub kind: Vec<u8>,
    /// v2: `(entry index, SHA-256)` of regular files, ascending by index;
    /// empty = no hashes recorded (written as v1)
    #[serde(default)]
    pub sha256: Vec<(u32, Sha256)>,
}

/// On-disk layouts (postcard is positional: one struct per version).
#[derive(Serialize, Deserialize)]
struct V1 {
    paths: String,
    size: Vec<u64>,
    mtime: Vec<i64>,
    kind: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct V2 {
    paths: String,
    size: Vec<u64>,
    mtime: Vec<i64>,
    kind: Vec<u8>,
    sha256: Vec<(u32, Sha256)>,
}

pub const KIND_FILE: u8 = 0;
pub const KIND_DIR: u8 = 1;
pub const KIND_SYMLINK: u8 = 2;
pub const KIND_OTHER: u8 = 3;

/// A path as the index stores it: no leading `/`, NUL as U+FFFD.
pub fn normalise(path: &str) -> std::borrow::Cow<'_, str> {
    let path = path.trim_start_matches('/');
    if path.contains('\0') {
        path.replace('\0', "\u{FFFD}").into()
    } else {
        path.into()
    }
}

pub fn kind_name(k: u8) -> &'static str {
    match k {
        KIND_FILE => "file",
        KIND_DIR => "dir",
        KIND_SYMLINK => "symlink",
        _ => "other",
    }
}

/// The streams of a plugin snapshot appear below this directory in the file
/// browser (plugin_proto::STREAMS_DIR, crate plugin-host files.rs `view`).
const STREAMS_DIR: &str = ".nexus-streams";
const STREAMS_INDEX: &str = "streams";

impl NameIndex {
    pub fn len(&self) -> usize {
        self.size.len()
    }

    pub fn is_empty(&self) -> bool {
        self.size.is_empty()
    }

    /// Appends one entry. Leading `/` are dropped; NUL (impossible in file
    /// names, but hostile sources) becomes U+FFFD ([`normalise`]).
    pub fn push(&mut self, path: &str, size: u64, mtime: i64, kind: u8) {
        let path = normalise(path);
        if path.is_empty() {
            return;
        }
        self.paths.push_str(&path);
        self.paths.push('\0');
        self.size.push(size);
        self.mtime.push(mtime);
        self.kind.push(kind);
    }

    /// Records the SHA-256 of entry `i` (call in ascending `i`; a repeated or
    /// out-of-order index is ignored).
    pub fn set_hash(&mut self, i: usize, h: Sha256) {
        let i = i as u32;
        if (i as usize) < self.len() && self.sha256.last().is_none_or(|(l, _)| *l < i) {
            self.sha256.push((i, h));
        }
    }

    /// The SHA-256 of entry `i`, if recorded.
    pub fn hash(&self, i: usize) -> Option<&Sha256> {
        let i = i as u32;
        self.sha256
            .binary_search_by_key(&i, |(x, _)| *x)
            .ok()
            .map(|k| &self.sha256[k].1)
    }

    pub fn has_hashes(&self) -> bool {
        !self.sha256.is_empty()
    }

    /// `(path, size, sha256)` of every entry with a recorded hash.
    pub fn hashed(&self) -> impl Iterator<Item = (&str, u64, &Sha256)> + '_ {
        let mut want = self.sha256.iter().peekable();
        self.iter().enumerate().filter_map(move |(i, (p, s, _, _))| {
            while want.peek().is_some_and(|(x, _)| (*x as usize) < i) {
                want.next();
            }
            match want.peek() {
                Some((x, h)) if *x as usize == i => Some((p, s, h)),
                _ => None,
            }
        })
    }

    /// `(path, size, mtime, kind)` in insertion order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, u64, i64, u8)> + '_ {
        self.paths
            .split_terminator('\0')
            .zip(&self.size)
            .zip(&self.mtime)
            .zip(&self.kind)
            .map(|(((p, s), m), k)| (p, *s, *m, *k))
    }

    /// The index of a file-tree snapshot, `None` without a `Tree` index (VM
    /// disks, container tar streams: their names need the guest file systems).
    /// Plugin streams (`streams`) are listed below `.nexus-streams/`.
    pub fn from_indexes<'a>(indexes: impl IntoIterator<Item = (&'a str, &'a Index)>) -> Option<NameIndex> {
        Self::from_indexes_hashed(indexes, &mut |_| Ok(None)).ok().flatten()
    }

    /// [`Self::from_indexes`], asking `hash` for the SHA-256 of every regular
    /// file of the tree (Phase 28; `None` = not known).
    pub fn from_indexes_hashed<'a>(
        indexes: impl IntoIterator<Item = (&'a str, &'a Index)>,
        hash: &mut dyn FnMut(&TreeEntry) -> io::Result<Option<Sha256>>,
    ) -> io::Result<Option<NameIndex>> {
        let mut out = NameIndex::default();
        let (mut tree, mut streams) = (false, Vec::new());
        for (name, idx) in indexes {
            match idx {
                Index::Tree { entries } => {
                    tree = true;
                    for e in entries {
                        let kind = match e.kind {
                            TreeKind::File | TreeKind::Hardlink => KIND_FILE,
                            TreeKind::Dir => KIND_DIR,
                            TreeKind::Symlink => KIND_SYMLINK,
                            _ => KIND_OTHER,
                        };
                        let before = out.len();
                        out.push(
                            &String::from_utf8_lossy(&e.path),
                            e.size,
                            e.mtime_ns.div_euclid(1_000_000_000),
                            kind,
                        );
                        if out.len() > before && e.kind == TreeKind::File {
                            if let Some(h) = hash(e)? {
                                out.set_hash(before, h);
                            }
                        }
                    }
                }
                Index::Dynamic { entries } if name == STREAMS_INDEX => streams.extend(entries),
                _ => {}
            }
        }
        if !tree {
            return Ok(None);
        }
        if !streams.is_empty() {
            out.push(STREAMS_DIR, 0, 0, KIND_DIR);
        }
        for s in streams {
            out.push(&format!("{STREAMS_DIR}/{}", s.path), s.size, s.mtime, KIND_FILE);
        }
        Ok(Some(out))
    }
}

fn ctx(source: &str, time: u64) -> String {
    format!("names:{source}/{time}")
}

fn ctx2(source: &str, time: u64) -> String {
    format!("names2:{source}/{time}")
}

fn ser(e: postcard::Error) -> io::Error {
    invalid(format!("serialization: {e}"))
}

impl Store {
    /// Seals and writes the name index of `source/time` (replacing an older
    /// one): v2 when it carries hashes, else v1.
    pub fn write_names(&self, source: &str, time: u64, names: &NameIndex) -> io::Result<()> {
        let blob = if names.has_hashes() {
            let v = V2 {
                paths: names.paths.clone(),
                size: names.size.clone(),
                mtime: names.mtime.clone(),
                kind: names.kind.clone(),
                sha256: names.sha256.clone(),
            };
            self.keys()
                .seal(ctx2(source, time).as_bytes(), &postcard::to_stdvec(&v).map_err(ser)?)
        } else {
            let v = V1 {
                paths: names.paths.clone(),
                size: names.size.clone(),
                mtime: names.mtime.clone(),
                kind: names.kind.clone(),
            };
            self.keys()
                .seal(ctx(source, time).as_bytes(), &postcard::to_stdvec(&v).map_err(ser)?)
        };
        write_atomic(&self.snap_dir(source, time).join(FILE), &blob)
    }

    /// Decodes a sealed name index of `source/time`, v2 or v1 (wrong key or a
    /// file of another snapshot: error).
    pub fn decode_names(&self, source: &str, time: u64, sealed: &[u8]) -> io::Result<NameIndex> {
        if let Ok((_, plain)) = self.keys().open(ctx2(source, time).as_bytes(), sealed) {
            let v: V2 = postcard::from_bytes(&plain).map_err(ser)?;
            let n = NameIndex {
                paths: v.paths,
                size: v.size,
                mtime: v.mtime,
                kind: v.kind,
                sha256: v.sha256,
            };
            if n.sha256.windows(2).any(|w| w[0].0 >= w[1].0) || n.sha256.last().is_some_and(|l| l.0 as usize >= n.len())
            {
                return Err(invalid("name index: hash entries out of order"));
            }
            return Ok(n);
        }
        let v: V1 = postcard::from_bytes(&self.keys().open(ctx(source, time).as_bytes(), sealed)?.1).map_err(ser)?;
        Ok(NameIndex {
            paths: v.paths,
            size: v.size,
            mtime: v.mtime,
            kind: v.kind,
            sha256: Vec::new(),
        })
    }

    /// The stored name index of a committed snapshot, `None` if it has none.
    pub fn load_names(&self, m: &Manifest) -> io::Result<Option<NameIndex>> {
        match fs::read(self.snap_dir(&m.source, m.time).join(FILE)) {
            Ok(b) => self.decode_names(&m.source, m.time, &b).map(Some),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// The stored index, else one built from the snapshot's indexes (file
    /// trees only; not written). `None`: VM/CT snapshot without a name index.
    pub fn names_or_build(&self, m: &Manifest) -> io::Result<Option<NameIndex>> {
        if let Some(n) = self.load_names(m)? {
            return Ok(Some(n));
        }
        self.build_names(m)
    }

    fn build_names(&self, m: &Manifest) -> io::Result<Option<NameIndex>> {
        let mut idx = Vec::new();
        for name in &m.indexes {
            idx.push((name.as_str(), self.load_index(m, name)?));
        }
        Ok(NameIndex::from_indexes(idx.iter().map(|(n, i)| (*n, i))))
    }

    /// Writes the missing name indexes of file-tree snapshots (snapshots from
    /// before the index existed, offsite / replicated imports). Idempotent.
    /// Returns (written, already there or not a file tree).
    pub fn backfill_names(&self) -> io::Result<(usize, usize)> {
        let (mut built, mut skipped) = (0, 0);
        for m in self.list_snapshots()? {
            let path = self.snap_dir(&m.source, m.time).join(FILE);
            if path.exists() {
                skipped += 1;
                continue;
            }
            let Some(n) = self.build_names(&m)? else {
                skipped += 1;
                continue;
            };
            // under the metadata lock: a concurrent delete in this process
            // either removed the directory already or waits for us
            let _g = self.meta_lock();
            if !self.snap_dir(&m.source, m.time).join("manifest").exists() {
                continue;
            }
            self.write_names(&m.source, m.time, &n)?;
            built += 1;
        }
        Ok((built, skipped))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Keyring, Options, TreeEntry};

    fn keys(t: &str, k: u8) -> Keyring {
        Keyring::new(t, &[(1, [k; 32])])
    }

    pub fn entry(path: &str, kind: TreeKind, size: u64) -> TreeEntry {
        TreeEntry {
            path: path.as_bytes().to_vec(),
            kind,
            mode: 0o644,
            uid: 0,
            gid: 0,
            size,
            mtime_ns: 1_700_000_000_000_000_000,
            ctime_ns: 0,
            inode: 0,
            rdev: 0,
            link_target: None,
            xattrs: Vec::new(),
            chunks: Vec::new(),
            inconsistent: false,
        }
    }

    fn opts() -> Options {
        Options {
            min_lock_secs: 0,
            ..Options::default()
        }
    }

    #[test]
    fn written_at_commit_sealed_and_deleted_with_the_snapshot() {
        let d = tempfile::tempdir().unwrap();
        let s = Store::open(d.path(), keys("acme", 1), opts()).unwrap();
        let tree = Index::Tree {
            entries: vec![
                entry("etc", TreeKind::Dir, 0),
                entry("etc/passwd", TreeKind::File, 42),
                entry("etc/bad\0name", TreeKind::Symlink, 0),
            ],
        };
        let m = s.commit_snapshot("host-a1", 100, &[("tree", tree)]).unwrap();
        let n = s.load_names(&m).unwrap().unwrap();
        let v: Vec<_> = n.iter().collect();
        assert_eq!(
            v,
            vec![
                ("etc", 0, 1_700_000_000, KIND_DIR),
                ("etc/passwd", 42, 1_700_000_000, KIND_FILE),
                ("etc/bad\u{FFFD}name", 0, 1_700_000_000, KIND_SYMLINK)
            ]
        );
        // no file names in plaintext on disk
        let raw = fs::read(d.path().join("snapshots/host-a1/100/names")).unwrap();
        assert!(!raw.windows(6).any(|w| w == b"passwd"));
        // another tenant's key, or the file of another snapshot, cannot open it
        let other = Store::open(d.path().join("o"), keys("other", 2), opts()).unwrap();
        assert!(other.decode_names("host-a1", 100, &raw).is_err());
        assert!(s.decode_names("host-a1", 101, &raw).is_err());
        assert!(s.decode_names("host-a1", 100, &raw).is_ok());
        s.delete_snapshot("host-a1", 100).unwrap();
        assert!(!d.path().join("snapshots/host-a1/100").exists());
    }

    #[test]
    fn vm_snapshots_have_none_until_indexed_and_streams_are_listed() {
        let d = tempfile::tempdir().unwrap();
        let s = Store::open(d.path(), keys("acme", 1), opts()).unwrap();
        let disk = s.store_image(&[7u8; 1000][..], 4096).unwrap();
        let m = s.commit_snapshot("vm-100", 5, &[("drive-scsi0", disk)]).unwrap();
        assert_eq!(s.load_names(&m).unwrap(), None);
        assert_eq!(s.names_or_build(&m).unwrap(), None);
        let mut n = NameIndex::default();
        n.push("/sda1/etc/hosts", 9, 3, KIND_FILE);
        s.write_names("vm-100", 5, &n).unwrap();
        assert_eq!(
            s.load_names(&m).unwrap().unwrap().iter().next(),
            Some(("sda1/etc/hosts", 9, 3, KIND_FILE))
        );

        let files = Index::Tree {
            entries: vec![entry("mail/a.eml", TreeKind::File, 1)],
        };
        let streams = Index::Dynamic {
            entries: vec![crate::FileEntry {
                path: "db.dump".into(),
                mode: 0o600,
                size: 77,
                mtime: 9,
                chunks: Vec::new(),
            }],
        };
        let m = s
            .commit_snapshot("plugin-pg-1", 6, &[("files", files), ("streams", streams)])
            .unwrap();
        let paths: Vec<_> = s
            .load_names(&m)
            .unwrap()
            .unwrap()
            .iter()
            .map(|e| e.0.to_owned())
            .collect();
        assert_eq!(paths, ["mail/a.eml", ".nexus-streams", ".nexus-streams/db.dump"]);
    }

    #[test]
    fn backfill_is_idempotent() {
        let d = tempfile::tempdir().unwrap();
        let s = Store::open(d.path(), keys("acme", 1), opts()).unwrap();
        let tree = || Index::Tree {
            entries: vec![entry("a.txt", TreeKind::File, 1)],
        };
        s.commit_snapshot("nas-1-tank.data", 1, &[("tree", tree())]).unwrap();
        s.commit_snapshot("nas-1-tank.data", 2, &[("tree", tree())]).unwrap();
        let disk = s.store_image(&[1u8; 10][..], 4096).unwrap();
        s.commit_snapshot("vm-1", 3, &[("drive-scsi0", disk)]).unwrap();
        // snapshots from before the name index
        fs::remove_file(d.path().join("snapshots/nas-1-tank.data/1/names")).unwrap();
        assert_eq!(s.backfill_names().unwrap(), (1, 2));
        assert_eq!(s.backfill_names().unwrap(), (0, 3));
        let m = s.load_manifest("nas-1-tank.data", 1).unwrap();
        assert_eq!(s.load_names(&m).unwrap().unwrap().len(), 1);
    }

    fn sha(d: &[u8]) -> Sha256 {
        <sha2::Sha256 as sha2::Digest>::digest(d).into()
    }

    fn file(s: &Store, path: &str, data: &[u8]) -> TreeEntry {
        let st = s.store_file_stats(data).unwrap();
        TreeEntry {
            chunks: st.chunks,
            ..entry(path, TreeKind::File, data.len() as u64)
        }
    }

    /// Phase 28: v1 stays readable, v2 carries hashes; hashes come from the
    /// read, the previous snapshot or the store.
    #[test]
    fn file_hashes_fresh_carried_and_computed() {
        let d = tempfile::tempdir().unwrap();
        let s = Store::open(d.path(), keys("acme", 1), opts()).unwrap();
        // hashing off: v1, no hashes
        let a = file(&s, "a.txt", b"alpha");
        let m = s
            .commit_snapshot(
                "host-a1",
                1,
                &[(
                    "tree",
                    Index::Tree {
                        entries: vec![a.clone()],
                    },
                )],
            )
            .unwrap();
        assert!(!s.load_names(&m).unwrap().unwrap().has_hashes());
        assert_eq!(s.take_hash_stats(), None);
        // on: the old file's hash is read back from the store, a new one hashed while read
        s.enable_file_hashes();
        let b = file(&s, "dir/b.bin", &[7u8; 300_000]);
        let empty = entry("empty", TreeKind::File, 0);
        let tree = Index::Tree {
            entries: vec![entry("dir", TreeKind::Dir, 0), a.clone(), b.clone(), empty],
        };
        let m = s.commit_snapshot("host-a1", 2, &[("tree", tree)]).unwrap();
        let st = s.take_hash_stats().unwrap();
        assert_eq!((st.fresh, st.carried, st.computed, st.failed), (1, 0, 1, 0));
        let n = s.load_names(&m).unwrap().unwrap();
        let h: Vec<_> = n.hashed().map(|(p, sz, h)| (p.to_owned(), sz, *h)).collect();
        assert_eq!(
            h,
            vec![
                ("a.txt".into(), 5, sha(b"alpha")),
                ("dir/b.bin".into(), 300_000, sha(&[7u8; 300_000])),
                ("empty".into(), 0, EMPTY_SHA256),
            ]
        );
        assert_eq!(n.hash(0), None, "directories carry none");
        // the sealed file is v2: not readable as v1, the previous release fails instead of mis-reading
        let raw = fs::read(d.path().join("snapshots/host-a1/2/names")).unwrap();
        assert!(s.keys().open(b"names:host-a1/2", &raw).is_err());
        // next snapshot: unchanged files carry their hash over (also renamed), no read
        let moved = TreeEntry {
            path: b"moved.bin".to_vec(),
            ..b.clone()
        };
        let m = s
            .commit_snapshot(
                "host-a1",
                3,
                &[(
                    "tree",
                    Index::Tree {
                        entries: vec![a, moved],
                    },
                )],
            )
            .unwrap();
        let st = s.take_hash_stats().unwrap();
        assert_eq!((st.fresh, st.carried, st.computed), (0, 2, 0));
        let n = s.load_names(&m).unwrap().unwrap();
        assert_eq!(
            n.hashed().nth(1).map(|x| (x.0, *x.2)),
            Some(("moved.bin", sha(&[7u8; 300_000])))
        );
        // a hash recorded by an agent (keyed chunk list) wins over reading
        let c = file(&s, "c", b"gamma");
        s.record_file_hash(&c.chunks, [9; 32]);
        let m = s
            .commit_snapshot("host-a1", 4, &[("tree", Index::Tree { entries: vec![c] })])
            .unwrap();
        assert_eq!(s.load_names(&m).unwrap().unwrap().hash(0), Some(&[9; 32]));
        // VM snapshots have no tree: nothing to hash
        let disk = s.store_image(&[1u8; 10][..], 4096).unwrap();
        s.commit_snapshot("vm-1", 5, &[("drive-scsi0", disk)]).unwrap();
        assert_eq!(s.take_hash_stats(), None);
    }

    #[test]
    fn hash_entries_are_validated() {
        let d = tempfile::tempdir().unwrap();
        let s = Store::open(d.path(), keys("acme", 1), opts()).unwrap();
        s.commit_snapshot("host-a1", 1, &[("tree", Index::Tree { entries: vec![] })])
            .unwrap();
        let mut n = NameIndex::default();
        n.push("a", 1, 1, KIND_FILE);
        n.push("b", 1, 1, KIND_FILE);
        n.set_hash(1, [1; 32]);
        n.set_hash(0, [2; 32]); // out of order: ignored
        n.set_hash(5, [3; 32]); // beyond the entries: ignored
        assert_eq!(n.sha256, vec![(1, [1; 32])]);
        s.write_names("host-a1", 1, &n).unwrap();
        let m = s.load_manifest("host-a1", 1).unwrap();
        assert_eq!(s.load_names(&m).unwrap().unwrap(), n);
        // a forged out-of-range entry is refused on read
        let bad = postcard::to_stdvec(&V2 {
            paths: "a\0".into(),
            size: vec![1],
            mtime: vec![1],
            kind: vec![KIND_FILE],
            sha256: vec![(3, [0; 32])],
        })
        .unwrap();
        let sealed = s.keys().seal(b"names2:host-a1/1", &bad);
        assert!(s.decode_names("host-a1", 1, &sealed).is_err());
    }
}
