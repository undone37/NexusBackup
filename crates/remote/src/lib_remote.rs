//! Dumb remote storage (Hetzner Storage Box via SFTP, S3). The remote only
//! stores files; all intelligence (inventory, retention, GC) is on the appliance.
//! Paths are relative to the tenant's root on the remote, `/`-separated.
//!
//! Retention locks (S3 Object Lock, compliance mode) are an optional
//! capability: `supports_locks()` says whether `put_locked` / `extend_lock`
//! make objects undeletable until a date. Backends without locks keep the
//! defaults (plain `put`, no-op extension) and rely on their own
//! immutability layer (Storage Box snapshots).

use std::fs;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::PathBuf;

pub trait Remote: Send + Sync {
    /// Creates `path` (and parent dirs) with `data`. Atomic (tmp + rename) and
    /// append-only: fails with `AlreadyExists` if `path` exists.
    fn put(&self, path: &str, data: &[u8]) -> io::Result<()>;
    /// Reads `len` bytes at `offset` (`None` = to the end).
    fn get(&self, path: &str, offset: u64, len: Option<u64>) -> io::Result<Vec<u8>>;
    /// Entries of a directory: `(name, size, is_dir)`; missing dir = empty.
    fn list(&self, dir: &str) -> io::Result<Vec<(String, u64, bool)>>;
    fn delete(&self, path: &str) -> io::Result<()>;
    /// Removes an empty directory (best effort; backends without directories may ignore it).
    fn remove_dir(&self, _dir: &str) -> io::Result<()> {
        Ok(())
    }
    /// True if the backend enforces retention locks: a locked object (version)
    /// cannot be deleted or overwritten by anyone until its date.
    fn supports_locks(&self) -> bool {
        false
    }
    /// `put` with a retention lock until `retain_until` (unix seconds). Dates
    /// in the past (or within a minute) store the object unlocked.
    fn put_locked(&self, path: &str, data: &[u8], _retain_until: u64) -> io::Result<()> {
        self.put(path, data)
    }
    /// Makes sure `path` stays locked at least until `until` (never shortens).
    fn extend_lock(&self, _path: &str, _until: u64) -> io::Result<()> {
        Ok(())
    }
    /// Current lock date of `path` (`None` = unlocked or no lock support).
    fn lock_of(&self, _path: &str) -> io::Result<Option<u64>> {
        Ok(None)
    }
}

/// A remote path is relative, `/`-separated, without empty, `.` or `..` components.
pub fn check(path: &str) -> io::Result<()> {
    let ok =
        !path.is_empty() && !path.starts_with('/') && path.split('/').all(|c| !c.is_empty() && c != "." && c != "..");
    if ok {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid remote path {path:?}"),
        ))
    }
}

/// Remote in a local directory (tests, USB/NFS targets).
pub struct LocalDir(pub PathBuf);

impl LocalDir {
    fn p(&self, path: &str) -> io::Result<PathBuf> {
        check(path)?;
        Ok(self.0.join(path))
    }
}

impl Remote for LocalDir {
    fn put(&self, path: &str, data: &[u8]) -> io::Result<()> {
        let p = self.p(path)?;
        fs::create_dir_all(p.parent().unwrap())?;
        let tmp = p.with_extension(format!("tmp{}", std::process::id()));
        let mut f = fs::File::create(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
        // hard_link fails if the target exists: append-only without a race
        let r = fs::hard_link(&tmp, &p);
        fs::remove_file(&tmp)?;
        r
    }

    fn get(&self, path: &str, offset: u64, len: Option<u64>) -> io::Result<Vec<u8>> {
        let mut f = fs::File::open(self.p(path)?)?;
        f.seek(SeekFrom::Start(offset))?;
        let mut out = Vec::new();
        match len {
            Some(n) => {
                out.resize(n as usize, 0);
                f.read_exact(&mut out)?;
            }
            None => {
                f.read_to_end(&mut out)?;
            }
        }
        Ok(out)
    }

    fn list(&self, dir: &str) -> io::Result<Vec<(String, u64, bool)>> {
        let p = if dir.is_empty() { self.0.clone() } else { self.p(dir)? };
        let rd = match fs::read_dir(&p) {
            Ok(rd) => rd,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(vec![]),
            Err(e) => return Err(e),
        };
        let mut out = Vec::new();
        for e in rd {
            let e = e?;
            let m = e.metadata()?;
            out.push((e.file_name().to_string_lossy().into_owned(), m.len(), m.is_dir()));
        }
        out.sort();
        Ok(out)
    }

    fn delete(&self, path: &str) -> io::Result<()> {
        fs::remove_file(self.p(path)?)
    }

    fn remove_dir(&self, dir: &str) -> io::Result<()> {
        fs::remove_dir(self.p(dir)?)
    }
}

/// Shared contract test for every `Remote` implementation.
pub fn conformance(r: &dyn Remote) {
    r.put("a/b/c.bin", b"0123456789").unwrap();
    assert_eq!(
        r.put("a/b/c.bin", b"x").unwrap_err().kind(),
        io::ErrorKind::AlreadyExists
    );
    assert_eq!(r.get("a/b/c.bin", 2, Some(3)).unwrap(), b"234");
    assert_eq!(r.get("a/b/c.bin", 7, None).unwrap(), b"789");
    assert_eq!(r.list("a/b").unwrap(), vec![("c.bin".into(), 10, false)]);
    let top: Vec<_> = r.list("a").unwrap().into_iter().map(|(n, _, d)| (n, d)).collect();
    assert_eq!(top, vec![("b".to_string(), true)]); // dir sizes are backend-specific
    assert!(r.list("nope").unwrap().is_empty());
    assert!(r.get("../x", 0, None).is_err() && r.put("/abs", b"").is_err());
    r.delete("a/b/c.bin").unwrap();
    assert!(r.get("a/b/c.bin", 0, None).is_err());
}

#[cfg(test)]
mod tests {
    #[test]
    fn local_dir_conformance() {
        let d = tempfile::tempdir().unwrap();
        super::conformance(&super::LocalDir(d.path().to_owned()));
    }
}
