//! Small sealed per-snapshot side files next to the manifest
//! (`snapshots/<source>/<time>/<name>`), e.g. `fsindex`, the volume report of
//! the guest file index (Phase 31a, crate fsindex). Sealed with the tenant
//! keyring under the context `<name>:<source>/<time>`, written atomically, gone
//! with the snapshot directory. Derived data: offsite and replication do not
//! carry them.

use crate::crypto::invalid;
use crate::store::{write_atomic, Store};
use std::fs;
use std::io;

/// Side files a caller may write (manifest and indexes are the store's own).
fn check(name: &str) -> io::Result<()> {
    let ok = !name.is_empty()
        && name.len() <= 32
        && name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !matches!(name, "manifest" | "names")
        && !name.ends_with("idx");
    if ok {
        Ok(())
    } else {
        Err(invalid(format!("snapshot side file name {name:?}")))
    }
}

impl Store {
    /// Seals and writes `name` of a committed snapshot (replacing an older one).
    pub fn write_snap_file(&self, source: &str, time: u64, name: &str, data: &[u8]) -> io::Result<()> {
        check(name)?;
        let dir = self.snap_dir(source, time);
        let _g = self.meta_lock();
        if !dir.join("manifest").exists() {
            return Err(io::Error::new(io::ErrorKind::NotFound, format!("snapshot {source}/{time}")));
        }
        let blob = self.keys().seal(format!("{name}:{source}/{time}").as_bytes(), data);
        write_atomic(&dir.join(name), &blob)
    }

    /// The opened side file, `None` if the snapshot has none.
    pub fn read_snap_file(&self, source: &str, time: u64, name: &str) -> io::Result<Option<Vec<u8>>> {
        check(name)?;
        match fs::read(self.snap_dir(source, time).join(name)) {
            Ok(b) => Ok(Some(self.keys().open(format!("{name}:{source}/{time}").as_bytes(), &b)?.1)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Whether the committed snapshot has a name index (`names`).
    pub fn has_names(&self, source: &str, time: u64) -> bool {
        self.snap_dir(source, time).join(crate::names::FILE).exists()
    }

    /// (source, time) of every committed snapshot without opening the
    /// manifests (cheap; a snapshot deleted meanwhile is simply left out).
    pub fn snapshot_keys(&self) -> io::Result<Vec<(String, u64)>> {
        let mut out = Vec::new();
        let dir = match fs::read_dir(self.root().join("snapshots")) {
            Ok(d) => d,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(out),
            Err(e) => return Err(e),
        };
        for src in dir.flatten() {
            let Some(source) = src.file_name().to_str().map(str::to_owned) else { continue };
            let Ok(times) = fs::read_dir(src.path()) else { continue };
            for t in times.flatten() {
                let Some(time) = t.file_name().to_str().and_then(|s| s.parse::<u64>().ok()) else { continue };
                if t.path().join("manifest").exists() {
                    out.push((source.clone(), time));
                }
            }
        }
        out.sort();
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use crate::{Keyring, Options, Store};

    #[test]
    fn sealed_side_files() {
        let d = tempfile::tempdir().unwrap();
        let s = Store::open(d.path(), Keyring::new("t", &[(1, [4; 32])]),
            Options {
                min_lock_secs: 0,
                ..Options::default()
            },
        ).unwrap();
        assert!(s.write_snap_file("vm-1", 5, "fsindex", b"x").is_err(), "no snapshot");
        let disk = s.store_image(&[1u8; 100][..], 4096).unwrap();
        s.commit_snapshot("vm-1", 5, &[("drive-scsi0", disk)]).unwrap();
        s.write_snap_file("vm-1", 5, "fsindex", b"secret volume list").unwrap();
        assert_eq!(s.read_snap_file("vm-1", 5, "fsindex").unwrap().unwrap(), b"secret volume list");
        assert_eq!(s.read_snap_file("vm-1", 5, "other").unwrap(), None);
        let raw = std::fs::read(d.path().join("snapshots/vm-1/5/fsindex")).unwrap();
        assert!(!raw.windows(6).any(|w| w == b"secret"));
        for bad in ["manifest", "names", "drive-scsi0.idx", "../x", "A"] {
            assert!(s.write_snap_file("vm-1", 5, bad, b"x").is_err(), "{bad}");
        }
        assert_eq!(s.snapshot_keys().unwrap(), vec![("vm-1".to_string(), 5)]);
        assert!(!s.has_names("vm-1", 5));
        s.delete_snapshot("vm-1", 5).unwrap();
        assert!(s.snapshot_keys().unwrap().is_empty());
    }
}
