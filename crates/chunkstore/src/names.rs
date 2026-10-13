//! Per-snapshot file name index (docs/file-index.md): the names, sizes, mtimes
//! and kinds of a snapshot's files, sealed with the tenant keyring next to the
//! manifest (`snapshots/<source>/<time>/names`). It is written at commit for
//! file-tree snapshots (agents, NAS, plugins), later for VM/CT disks (opt-in,
//! nexus-pve `files … index`), and goes away with the snapshot directory.
//! File names never leave the tenant's sealed store; searching needs the key.

use crate::crypto::invalid;
use crate::store::{write_atomic, Index, Manifest, Store, TreeKind};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io;

pub const FILE: &str = "names";

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
}

pub const KIND_FILE: u8 = 0;
pub const KIND_DIR: u8 = 1;
pub const KIND_SYMLINK: u8 = 2;
pub const KIND_OTHER: u8 = 3;

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
    /// names, but hostile sources) becomes U+FFFD.
    pub fn push(&mut self, path: &str, size: u64, mtime: i64, kind: u8) {
        let path = path.trim_start_matches('/');
        if path.is_empty() {
            return;
        }
        if path.contains('\0') {
            self.paths.push_str(&path.replace('\0', "\u{FFFD}"));
        } else {
            self.paths.push_str(path);
        }
        self.paths.push('\0');
        self.size.push(size);
        self.mtime.push(mtime);
        self.kind.push(kind);
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
                        out.push(
                            &String::from_utf8_lossy(&e.path),
                            e.size,
                            e.mtime_ns.div_euclid(1_000_000_000),
                            kind,
                        );
                    }
                }
                Index::Dynamic { entries } if name == STREAMS_INDEX => streams.extend(entries),
                _ => {}
            }
        }
        if !tree {
            return None;
        }
        if !streams.is_empty() {
            out.push(STREAMS_DIR, 0, 0, KIND_DIR);
        }
        for s in streams {
            out.push(&format!("{STREAMS_DIR}/{}", s.path), s.size, s.mtime, KIND_FILE);
        }
        Some(out)
    }
}

pub(crate) fn ctx(source: &str, time: u64) -> String {
    format!("names:{source}/{time}")
}

impl Store {
    /// Seals and writes the name index of `source/time` (replacing an older one).
    pub fn write_names(&self, source: &str, time: u64, names: &NameIndex) -> io::Result<()> {
        let blob = self.keys().seal(
            ctx(source, time).as_bytes(),
            &postcard::to_stdvec(names).map_err(|e| invalid(format!("serialization: {e}")))?,
        );
        write_atomic(&self.snap_dir(source, time).join(FILE), &blob)
    }

    /// Decodes a sealed name index of `source/time` (wrong key or a file of
    /// another snapshot: error).
    pub fn decode_names(&self, source: &str, time: u64, sealed: &[u8]) -> io::Result<NameIndex> {
        postcard::from_bytes(&self.keys().open(ctx(source, time).as_bytes(), sealed)?.1)
            .map_err(|e| invalid(format!("serialization: {e}")))
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
}
