//! Small sealed per-snapshot side files next to the manifest
//! (`snapshots/<source>/<time>/<name>`), e.g. `fsindex`, the volume report of
//! the guest file index (Phase 31a, crate fsindex). Sealed with the tenant
//! keyring under the context `<name>:<source>/<time>`, written atomically, gone
//! with the snapshot directory. Derived data: offsite and replication do not
//! carry them.
//!
//! [`MetaReader`] reads snapshot lists, name indexes and side files without
//! opening a [`Store`] (which creates directories, syncs and keeps the
//! compliance clock): nexus-index has read-only access to the stores.

use crate::crypto::{invalid, Keyring};
use crate::names::{self, NameIndex};
use crate::store::{write_atomic, Store};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// Side files a caller may write (manifest and indexes are the store's own).
fn check(name: &str) -> io::Result<()> {
    let ok = !name.is_empty()
        && name.len() <= 32
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !matches!(name, "manifest" | "names")
        && !name.ends_with("idx");
    if ok {
        Ok(())
    } else {
        Err(invalid(format!("snapshot side file name {name:?}")))
    }
}

fn check_source(s: &str) -> io::Result<()> {
    let ok = !s.is_empty() && s != "." && s != ".." && !s.contains('/') && !s.contains('\0');
    if ok {
        Ok(())
    } else {
        Err(invalid(format!("source name {s:?}")))
    }
}

fn snap_dir(root: &Path, source: &str, time: u64) -> PathBuf {
    root.join("snapshots").join(source).join(time.to_string())
}

fn read_side(root: &Path, keys: &Keyring, source: &str, time: u64, name: &str) -> io::Result<Option<Vec<u8>>> {
    check(name)?;
    check_source(source)?;
    match fs::read(snap_dir(root, source, time).join(name)) {
        Ok(b) => Ok(Some(keys.open(format!("{name}:{source}/{time}").as_bytes(), &b)?.1)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

fn keys_of(root: &Path) -> io::Result<Vec<(String, u64)>> {
    let mut out = Vec::new();
    let dir = match fs::read_dir(root.join("snapshots")) {
        Ok(d) => d,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(out),
        Err(e) => return Err(e),
    };
    for src in dir.flatten() {
        let Some(source) = src.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let Ok(times) = fs::read_dir(src.path()) else { continue };
        for t in times.flatten() {
            let Some(time) = t.file_name().to_str().and_then(|s| s.parse::<u64>().ok()) else {
                continue;
            };
            if t.path().join("manifest").exists() {
                out.push((source.clone(), time));
            }
        }
    }
    out.sort();
    Ok(out)
}

impl Store {
    /// Seals and writes `name` of a committed snapshot (replacing an older one).
    pub fn write_snap_file(&self, source: &str, time: u64, name: &str, data: &[u8]) -> io::Result<()> {
        check(name)?;
        check_source(source)?;
        let dir = self.snap_dir(source, time);
        let _g = self.meta_lock();
        if !dir.join("manifest").exists() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("snapshot {source}/{time}"),
            ));
        }
        let blob = self.keys().seal(format!("{name}:{source}/{time}").as_bytes(), data);
        write_atomic(&dir.join(name), &blob)
    }

    /// The opened side file, `None` if the snapshot has none.
    pub fn read_snap_file(&self, source: &str, time: u64, name: &str) -> io::Result<Option<Vec<u8>>> {
        read_side(self.root(), self.keys(), source, time, name)
    }

    /// Whether the committed snapshot has a name index (`names`).
    pub fn has_names(&self, source: &str, time: u64) -> bool {
        self.snap_dir(source, time).join(names::FILE).exists()
    }

    /// (source, time) of every committed snapshot without opening the
    /// manifests (cheap; a snapshot deleted meanwhile is simply left out).
    pub fn snapshot_keys(&self) -> io::Result<Vec<(String, u64)>> {
        keys_of(self.root())
    }
}

/// Read-only access to a store's snapshot metadata (no writes at all).
pub struct MetaReader {
    root: PathBuf,
    keys: Keyring,
}

impl MetaReader {
    pub fn new(root: impl Into<PathBuf>, keys: Keyring) -> MetaReader {
        MetaReader {
            root: root.into(),
            keys,
        }
    }

    pub fn keys(&self) -> &Keyring {
        &self.keys
    }

    /// Fails unless the keyring is the store's (its `keycheck`).
    pub fn check_keys(&self) -> io::Result<()> {
        let b = fs::read(self.root.join("keycheck"))?;
        self.keys
            .open(b"keycheck", &b)
            .map(drop)
            .map_err(|_| invalid("keyring does not match this store"))
    }

    pub fn snapshot_keys(&self) -> io::Result<Vec<(String, u64)>> {
        keys_of(&self.root)
    }

    pub fn has_names(&self, source: &str, time: u64) -> bool {
        check_source(source).is_ok() && snap_dir(&self.root, source, time).join(names::FILE).exists()
    }

    /// The snapshot's name index, `None` if it has none (yet).
    pub fn load_names(&self, source: &str, time: u64) -> io::Result<Option<NameIndex>> {
        check_source(source)?;
        match fs::read(snap_dir(&self.root, source, time).join(names::FILE)) {
            Ok(b) => names::decode(&self.keys, source, time, &b).map(Some),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    pub fn read_snap_file(&self, source: &str, time: u64, name: &str) -> io::Result<Option<Vec<u8>>> {
        read_side(&self.root, &self.keys, source, time, name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Index, Options, TreeEntry, TreeKind};

    #[test]
    fn sealed_side_files() {
        let d = tempfile::tempdir().unwrap();
        let s = Store::open(
            d.path(),
            Keyring::new("t", &[(1, [4; 32])]),
            Options {
                min_lock_secs: 0,
                ..Options::default()
            },
        )
        .unwrap();
        assert!(s.write_snap_file("vm-1", 5, "fsindex", b"x").is_err(), "no snapshot");
        let disk = s.store_image(&[1u8; 100][..], 4096).unwrap();
        s.commit_snapshot("vm-1", 5, &[("drive-scsi0", disk)]).unwrap();
        s.write_snap_file("vm-1", 5, "fsindex", b"secret volume list").unwrap();
        assert_eq!(
            s.read_snap_file("vm-1", 5, "fsindex").unwrap().unwrap(),
            b"secret volume list"
        );
        assert_eq!(s.read_snap_file("vm-1", 5, "other").unwrap(), None);
        let raw = std::fs::read(d.path().join("snapshots/vm-1/5/fsindex")).unwrap();
        assert!(!raw.windows(6).any(|w| w == b"secret"));
        for bad in ["manifest", "names", "drive-scsi0.idx", "../x", "A"] {
            assert!(s.write_snap_file("vm-1", 5, bad, b"x").is_err(), "{bad}");
        }
        assert!(s.write_snap_file("..", 5, "fsindex", b"x").is_err());
        assert_eq!(s.snapshot_keys().unwrap(), vec![("vm-1".to_string(), 5)]);
        assert!(!s.has_names("vm-1", 5));

        // the read-only reader sees the same, with the same key only
        let tree = Index::Tree {
            entries: vec![TreeEntry {
                path: b"etc/hosts".to_vec(),
                kind: TreeKind::File,
                mode: 0o644,
                uid: 0,
                gid: 0,
                size: 9,
                mtime_ns: 0,
                ctime_ns: 0,
                inode: 0,
                rdev: 0,
                link_target: None,
                xattrs: Vec::new(),
                chunks: Vec::new(),
                inconsistent: false,
            }],
        };
        s.commit_snapshot("host-a", 6, &[("tree", tree)]).unwrap();
        let r = MetaReader::new(d.path(), Keyring::new("t", &[(1, [4; 32])]));
        r.check_keys().unwrap();
        assert_eq!(r.snapshot_keys().unwrap().len(), 2);
        assert!(r.has_names("host-a", 6) && !r.has_names("vm-1", 5));
        assert_eq!(
            r.load_names("host-a", 6).unwrap().unwrap().iter().next().unwrap().0,
            "etc/hosts"
        );
        assert_eq!(r.load_names("vm-1", 5).unwrap(), None);
        // a name index v2 (file hashes, Phase 28) reads too
        let mut n = NameIndex::default();
        n.push("vda1/bin/sh", 3, 0, names::KIND_FILE);
        n.set_hash(0, [7; 32]);
        s.write_names("vm-1", 5, &n).unwrap();
        assert_eq!(r.load_names("vm-1", 5).unwrap().unwrap().hash(0), Some(&[7; 32]));
        assert_eq!(
            r.read_snap_file("vm-1", 5, "fsindex").unwrap().unwrap(),
            b"secret volume list"
        );
        assert!(MetaReader::new(d.path(), Keyring::new("t", &[(1, [5; 32])]))
            .check_keys()
            .is_err());
        s.delete_snapshot("vm-1", 5).unwrap();
        assert_eq!(s.snapshot_keys().unwrap(), vec![("host-a".to_string(), 6)]);
    }
}
