//! Credential files of the mount helper (Kerberos keytab): created 0600 with
//! `O_EXCL | O_NOFOLLOW` in the helper's private runtime directory (systemd
//! `RuntimeDirectory=`, 0700, removed when the helper instance ends) and
//! deleted again by [`CredFile`]'s `Drop` as soon as they are no longer needed.
//! SMB passwords never touch a file: they go to the kernel as one `fsconfig`
//! value.

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

pub struct CredFile {
    path: PathBuf,
}

impl CredFile {
    /// Writes `data` to `<dir>/<name>`. `dir` must be a directory owned by us
    /// and not accessible to group/others; an existing file (or symlink) of
    /// that name is an error, never followed or overwritten.
    pub fn create(dir: &Path, name: &str, data: &[u8]) -> io::Result<CredFile> {
        if name.is_empty() || name.contains('/') || name.starts_with('.') {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid credential file name",
            ));
        }
        let md = fs::symlink_metadata(dir)?;
        // SAFETY: geteuid has no preconditions.
        let me = unsafe { libc::geteuid() };
        if !md.is_dir() || md.permissions().mode() & 0o077 != 0 || std::os::unix::fs::MetadataExt::uid(&md) != me {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("{}: not a private directory (0700, owned by us)", dir.display()),
            ));
        }
        let path = dir.join(name);
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)?;
        let c = CredFile { path };
        f.write_all(data)?;
        f.sync_all()?;
        Ok(c)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for CredFile {
    fn drop(&mut self) {
        // overwrite before unlinking (tmpfs: no copies elsewhere, but cheap)
        if let Ok(m) = fs::metadata(&self.path) {
            if let Ok(mut f) = OpenOptions::new()
                .write(true)
                .custom_flags(libc::O_NOFOLLOW)
                .open(&self.path)
            {
                let _ = f.write_all(&vec![0u8; m.len() as usize]);
            }
        }
        let _ = fs::remove_file(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::MetadataExt;

    #[test]
    fn private_file_removed_on_drop() {
        let d = tempfile::tempdir().unwrap();
        fs::set_permissions(d.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let c = CredFile::create(d.path(), "keytab", b"\x05\x02secret").unwrap();
        let m = fs::metadata(c.path()).unwrap();
        assert_eq!(m.mode() & 0o777, 0o600);
        assert_eq!(fs::read(c.path()).unwrap(), b"\x05\x02secret");
        // never overwritten or followed
        assert!(CredFile::create(d.path(), "keytab", b"x").is_err());
        std::os::unix::fs::symlink("/etc/passwd", d.path().join("link")).unwrap();
        assert!(CredFile::create(d.path(), "link", b"x").is_err());
        let p = c.path().to_owned();
        drop(c);
        assert!(!p.exists());
        for bad in ["", "a/b", ".hidden"] {
            assert!(CredFile::create(d.path(), bad, b"x").is_err());
        }
        // a directory others can read is refused
        fs::set_permissions(d.path(), fs::Permissions::from_mode(0o755)).unwrap();
        assert!(CredFile::create(d.path(), "k2", b"x").is_err());
    }
}
