//! Restore to a path (Linux file system side of `agent_core::restore`). Everything is
//! written strictly below `target`: every path component is opened with
//! `openat2(RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS)` + `O_NOFOLLOW`
//! relative to the previous one, entry paths with empty, `.` or `..` components are
//! refused, and new files are created under a temporary name (`O_EXCL`) and renamed
//! into place, so a symlink planted at the destination is replaced, never followed.
//!
//! Order and bookkeeping (chunk placement, overwrite policy, hard links and directory
//! metadata last) live in `agent_core::restore::Stream`.
//!
//! Restoring onto `/` is refused unless `overwrite = Always` and a confirmation token is
//! given; every restore logs its confirmation token to the journal.

use crate::sys::{self, openat_beneath};
use agent_core::restore::{parent_bytes, Existing, RestoreFs, Stream};
use agent_proto::{Entry, Hash, Kind, Overwrite, ScanStats};
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};

fn err(msg: impl Into<String>) -> io::Error {
    agent_core::restore::invalid(msg)
}

/// Split an entry path into validated components.
pub fn components(path: &[u8]) -> io::Result<Vec<&OsStr>> {
    Ok(agent_core::restore::components(path)?
        .into_iter()
        .map(OsStr::from_bytes)
        .collect())
}

/// A regular file being restored: parent directory (relative path bytes) and names.
pub struct Tmp {
    parent: Vec<u8>,
    name: OsString,
    tmp: OsString,
}

pub struct LinuxFs {
    root: OwnedFd,
    pub target: PathBuf,
    seq: u64,
}

/// A restore in progress (`agent_core::restore::Stream` over [`LinuxFs`]).
pub struct Restore(pub Stream<LinuxFs>);

impl Restore {
    /// Validate the target and open it. `/` (or anything resolving to it) needs
    /// `Overwrite::Always` and a non-empty confirmation token.
    pub fn begin(job: u64, target: &str, overwrite: Overwrite, confirm: &str) -> io::Result<Restore> {
        let norm = crate::volumes::normalize(target).map_err(err)?;
        if confirm.trim().is_empty() {
            return Err(err("restore needs the confirmation token from the UI"));
        }
        eprintln!(
            "nexus-agent: restore job {job} to {} (overwrite {overwrite:?}) confirmed with token {:?}",
            norm.display(),
            confirm.trim()
        );
        std::fs::create_dir_all(&norm)?;
        let canon = std::fs::canonicalize(&norm)?;
        if canon == Path::new("/") && overwrite != Overwrite::Always {
            return Err(err(
                "restore onto / requires overwrite = Always (and a confirmation token)",
            ));
        }
        let c = sys::cstr(&canon)?;
        // SAFETY: plain open of a directory path.
        let fd = unsafe { libc::open(c.as_ptr(), libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let fs = LinuxFs {
            // SAFETY: freshly opened fd.
            root: unsafe { std::os::fd::FromRawFd::from_raw_fd(fd) },
            target: canon,
            seq: 0,
        };
        Ok(Restore(Stream::new(fs, overwrite)))
    }

    pub fn target(&self) -> &Path {
        &self.0.fs.target
    }

    pub fn entries(&mut self, batch: Vec<Entry>) {
        self.0.entries(batch)
    }

    pub fn chunk(&mut self, hash: Hash, data: &[u8]) {
        self.0.chunk(hash, data)
    }

    pub fn end(self) -> ScanStats {
        self.0.end()
    }
}

impl agent_core::server::RestoreJob for Restore {
    fn entries(&mut self, batch: Vec<Entry>) {
        self.0.entries(batch)
    }
    fn chunk(&mut self, hash: Hash, data: &[u8]) {
        self.0.chunk(hash, data)
    }
    fn end(self) -> ScanStats {
        self.0.end()
    }
    fn target(&self) -> String {
        self.0.fs.target.display().to_string()
    }
}

fn not_root_eperm(x: &io::Error) -> bool {
    // unprivileged restores keep the restoring user's ownership
    x.raw_os_error() == Some(libc::EPERM) && sys::geteuid() != 0
}

impl LinuxFs {
    /// Open the directory `comps` below the target, creating missing directories (0700;
    /// their real metadata arrives with their own entries).
    fn open_dir(&self, comps: &[&OsStr], create: bool) -> io::Result<OwnedFd> {
        let mut cur = openat_beneath(
            self.root.as_raw_fd(),
            OsStr::new("."),
            libc::O_PATH | libc::O_DIRECTORY,
            0,
        )?;
        for c in comps {
            let next = match openat_beneath(cur.as_raw_fd(), c, libc::O_PATH | libc::O_DIRECTORY, 0) {
                Err(e) if create && e.raw_os_error() == Some(libc::ENOENT) => {
                    sys::mkdirat(cur.as_raw_fd(), c, 0o700)?;
                    openat_beneath(cur.as_raw_fd(), c, libc::O_PATH | libc::O_DIRECTORY, 0)?
                }
                r => r?,
            };
            cur = next;
        }
        Ok(cur)
    }

    fn parent_of(&self, path: &[u8]) -> io::Result<(OwnedFd, OsString)> {
        let comps = components(path)?;
        let (last, parents) = comps.split_last().expect("non-empty");
        Ok((self.open_dir(parents, true)?, last.to_os_string()))
    }

    fn tmp_name(&mut self) -> OsString {
        self.seq += 1;
        OsString::from(format!(".nexus-restore.{}.{}", std::process::id(), self.seq))
    }

    fn open_tmp_in(&self, t: &Tmp, flags: i32) -> io::Result<(OwnedFd, File)> {
        let comps = if t.parent.is_empty() {
            vec![]
        } else {
            components(&t.parent)?
        };
        let dir = self.open_dir(&comps, false)?;
        let f = openat_beneath(dir.as_raw_fd(), &t.tmp, flags, 0)?;
        Ok((dir, f.into()))
    }

    fn chown_at(&self, fd: i32, name: &OsStr, e: &Entry) -> io::Result<()> {
        match sys::fchownat_nofollow(fd, name, e.uid, e.gid) {
            Err(x) if not_root_eperm(&x) => Ok(()),
            r => r,
        }
    }

    /// Metadata on a freshly created non-regular node, then rename into place.
    fn place(&self, dir: &OwnedFd, tmp: &OsStr, name: &OsStr, e: &Entry, warn: &mut Vec<String>) -> io::Result<()> {
        let fd = dir.as_raw_fd();
        let r = (|| {
            self.chown_at(fd, tmp, e)?;
            if e.kind != Kind::Symlink {
                sys::fchmodat(fd, tmp, e.mode & 0o7777)?;
            }
            if !e.xattrs.is_empty() {
                let node = openat_beneath(fd, tmp, libc::O_PATH, 0)?;
                for (k, v) in &e.xattrs {
                    if let Err(x) = sys::setxattr_opath(node.as_raw_fd(), k, v) {
                        warn.push(format!("xattr {}: {x}", String::from_utf8_lossy(k)));
                    }
                }
            }
            sys::utimensat_nofollow(fd, tmp, e.mtime_ns)?;
            sys::renameat(fd, tmp, fd, name)
        })();
        if r.is_err() {
            let _ = sys::unlinkat(fd, tmp, false);
        }
        r
    }
}

impl RestoreFs for LinuxFs {
    type Tmp = Tmp;
    type Writer = File;

    fn target_display(&self) -> String {
        self.target.display().to_string()
    }

    fn check_entry(&self, e: &Entry) -> io::Result<()> {
        components(&e.path)?;
        if e.kind == Kind::Hardlink {
            components(e.link_target.as_deref().unwrap_or_default())?;
        }
        Ok(())
    }

    fn existing(&mut self, path: &[u8]) -> io::Result<Existing> {
        let (dir, name) = self.parent_of(path)?;
        let st = match sys::fstatat_nofollow(dir.as_raw_fd(), &name) {
            Err(x) if x.raw_os_error() == Some(libc::ENOENT) => return Ok(Existing::Missing),
            r => r?,
        };
        Ok(if st.st_mode & libc::S_IFMT == libc::S_IFDIR {
            Existing::Dir
        } else {
            Existing::Other {
                mtime_ns: st.st_mtime * 1_000_000_000 + st.st_mtime_nsec,
            }
        })
    }

    fn make_dir(&mut self, e: &Entry, existing: Existing) -> io::Result<()> {
        let (dir, name) = self.parent_of(&e.path)?;
        let fd = dir.as_raw_fd();
        match existing {
            Existing::Dir => Ok(()),
            Existing::Other { .. } => {
                sys::unlinkat(fd, &name, false)?;
                sys::mkdirat(fd, &name, 0o700)
            }
            Existing::Missing => sys::mkdirat(fd, &name, 0o700),
        }
    }

    fn create_file(&mut self, e: &Entry) -> io::Result<Tmp> {
        let (dir, name) = self.parent_of(&e.path)?;
        let tmp = self.tmp_name();
        let f: File = openat_beneath(
            dir.as_raw_fd(),
            &tmp,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
            0o600,
        )?
        .into();
        f.set_len(e.size)?;
        Ok(Tmp {
            parent: parent_bytes(&e.path).to_vec(),
            name,
            tmp,
        })
    }

    fn open_tmp(&mut self, t: &Tmp) -> io::Result<File> {
        Ok(self.open_tmp_in(t, libc::O_WRONLY)?.1)
    }

    fn write_at(&mut self, w: &File, off: u64, data: &[u8]) -> io::Result<()> {
        w.write_all_at(data, off)
    }

    /// Owner, mode, xattrs, times on the temp file, then rename over the destination.
    fn commit_file(&mut self, t: Tmp, e: &Entry, warn: &mut Vec<String>) -> io::Result<()> {
        let (dir, f) = self.open_tmp_in(&t, libc::O_WRONLY)?;
        let r = (|| {
            match std::os::unix::fs::fchown(&f, Some(e.uid), Some(e.gid)) {
                Err(x) if not_root_eperm(&x) => {}
                r => r?,
            }
            f.set_permissions(std::os::unix::fs::PermissionsExt::from_mode(e.mode & 0o7777))?;
            for (k, v) in &e.xattrs {
                if let Err(x) = sys::fsetxattr(f.as_raw_fd(), k, v) {
                    warn.push(format!("xattr {}: {x}", String::from_utf8_lossy(k)));
                }
            }
            set_times(&f, e.mtime_ns)?;
            sys::renameat(dir.as_raw_fd(), &t.tmp, dir.as_raw_fd(), &t.name)
        })();
        if r.is_err() {
            let _ = sys::unlinkat(dir.as_raw_fd(), &t.tmp, false);
        }
        r
    }

    fn discard(&mut self, t: Tmp) {
        if let Ok((dir, _)) = self.open_tmp_in(&t, libc::O_RDONLY) {
            let _ = sys::unlinkat(dir.as_raw_fd(), &t.tmp, false);
        }
    }

    fn create_other(&mut self, e: &Entry, warn: &mut Vec<String>) -> io::Result<()> {
        let (dir, name) = self.parent_of(&e.path)?;
        let fd = dir.as_raw_fd();
        let tmp = self.tmp_name();
        match e.kind {
            Kind::Symlink => {
                let target = e.link_target.clone().ok_or_else(|| err("symlink without target"))?;
                sys::symlinkat(&target, fd, &tmp)?;
            }
            Kind::Device | Kind::Fifo | Kind::Socket => {
                let t = match e.kind {
                    Kind::Fifo => libc::S_IFIFO,
                    Kind::Socket => libc::S_IFSOCK,
                    // devices keep their type bits in `mode` (see scan.rs)
                    _ if e.mode & libc::S_IFMT == libc::S_IFBLK => libc::S_IFBLK,
                    _ => libc::S_IFCHR,
                };
                sys::mknodat(fd, &tmp, t | (e.mode & 0o7777), e.rdev)?;
            }
            _ => return Err(err("unexpected entry kind")),
        }
        self.place(&dir, &tmp, &name, e, warn)
    }

    fn hardlink(&mut self, e: &Entry) -> io::Result<()> {
        let target = e.link_target.as_deref().unwrap_or_default();
        let (tdir, tname) = self.parent_of(target)?;
        let (dir, name) = self.parent_of(&e.path)?;
        let tmp = self.tmp_name();
        sys::linkat(tdir.as_raw_fd(), &tname, dir.as_raw_fd(), &tmp)?;
        sys::renameat(dir.as_raw_fd(), &tmp, dir.as_raw_fd(), &name).inspect_err(|_| {
            let _ = sys::unlinkat(dir.as_raw_fd(), &tmp, false);
        })
    }

    fn dir_metadata(&mut self, e: &Entry, _existed: bool, warn: &mut Vec<String>) -> io::Result<()> {
        let comps = components(&e.path)?;
        let d: File = {
            let (last, parents) = comps.split_last().expect("non-empty");
            let parent = self.open_dir(parents, false)?;
            openat_beneath(parent.as_raw_fd(), last, libc::O_RDONLY | libc::O_DIRECTORY, 0)?.into()
        };
        match std::os::unix::fs::fchown(&d, Some(e.uid), Some(e.gid)) {
            Err(x) if not_root_eperm(&x) => {}
            r => r?,
        }
        d.set_permissions(std::os::unix::fs::PermissionsExt::from_mode(e.mode & 0o7777))?;
        for (k, v) in &e.xattrs {
            if let Err(x) = sys::fsetxattr(d.as_raw_fd(), k, v) {
                warn.push(format!("xattr {}: {x}", String::from_utf8_lossy(k)));
            }
        }
        set_times(&d, e.mtime_ns)
    }

    fn finish(&mut self) {
        // SAFETY: syncfs on our own fd.
        unsafe { libc::syncfs(self.root.as_raw_fd()) };
    }
}

fn set_times(f: &File, mtime_ns: i64) -> io::Result<()> {
    let ts = libc::timespec {
        tv_sec: mtime_ns.div_euclid(1_000_000_000),
        tv_nsec: mtime_ns.rem_euclid(1_000_000_000),
    };
    // SAFETY: valid fd and timespec array.
    if unsafe { libc::futimens(f.as_raw_fd(), [ts, ts].as_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};

    fn entry(path: &str, kind: Kind, data: &[u8]) -> (Entry, Vec<(Hash, Vec<u8>)>) {
        let chunks: Vec<(Hash, Vec<u8>)> = data
            .chunks(1000)
            .map(|c| (*blake3::hash(c).as_bytes(), c.to_vec()))
            .collect();
        let e = Entry {
            path: path.as_bytes().to_vec(),
            kind,
            mode: 0o640,
            uid: sys::geteuid(),
            // SAFETY: trivial syscall
            gid: unsafe { libc::getegid() },
            size: data.len() as u64,
            mtime_ns: 1_600_000_000_123_456_789,
            ctime_ns: 0,
            inode: 1,
            rdev: 0,
            link_target: None,
            xattrs: vec![],
            chunks: chunks.iter().map(|(h, d)| (*h, d.len() as u32)).collect(),
            unchanged: false,
            inconsistent: false,
        };
        (e, chunks)
    }

    #[test]
    fn path_validation() {
        for bad in ["", "../x", "a/../b", "/abs", "a//b", "./a", "a/.", "a\0b"] {
            assert!(components(bad.as_bytes()).is_err(), "{bad}");
        }
        assert_eq!(components(b"a/b c/d").unwrap().len(), 3);
    }

    #[test]
    fn refuses_root_without_always_and_confirm() {
        assert!(Restore::begin(1, "/", Overwrite::Never, "tok").is_err());
        assert!(Restore::begin(1, "/", Overwrite::IfOlder, "tok").is_err());
        assert!(Restore::begin(1, "/", Overwrite::Always, "").is_err());
        let t = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink("/", t.path().join("rootlink")).unwrap();
        let via_link = t.path().join("rootlink");
        assert!(Restore::begin(1, via_link.to_str().unwrap(), Overwrite::IfOlder, "tok").is_err());
        assert!(Restore::begin(1, "relative/path", Overwrite::Always, "tok").is_err());
        assert!(Restore::begin(1, "/tmp/../etc", Overwrite::Always, "tok").is_err());
    }

    #[test]
    fn symlink_in_parent_path_is_not_followed() {
        let t = tempfile::tempdir().unwrap();
        let target = t.path().join("target");
        let outside = t.path().join("outside");
        fs::create_dir_all(&target).unwrap();
        fs::create_dir_all(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, target.join("evil")).unwrap();
        std::os::unix::fs::symlink("../outside", target.join("rel")).unwrap();
        let mut r = Restore::begin(1, target.to_str().unwrap(), Overwrite::Always, "tok").unwrap();
        let (e1, c1) = entry("evil/passwd", Kind::File, b"pwned");
        let (e2, c2) = entry("rel/passwd", Kind::File, b"pwned");
        let (e3, _) = entry("rel/sub", Kind::Dir, b"");
        r.entries(vec![e1, e2, e3]);
        for (h, d) in c1.into_iter().chain(c2) {
            r.chunk(h, &d);
        }
        let stats = r.end();
        assert_eq!(fs::read_dir(&outside).unwrap().count(), 0, "nothing written outside");
        assert_eq!(stats.errors.len(), 3, "{:?}", stats.errors);
    }

    #[test]
    fn symlink_at_destination_is_replaced_not_followed() {
        let t = tempfile::tempdir().unwrap();
        let target = t.path().join("target");
        fs::create_dir_all(&target).unwrap();
        let victim = t.path().join("victim");
        fs::write(&victim, b"original").unwrap();
        std::os::unix::fs::symlink(&victim, target.join("f")).unwrap();
        // Never keeps the existing symlink
        let mut r = Restore::begin(1, target.to_str().unwrap(), Overwrite::Never, "tok").unwrap();
        let (e, c) = entry("f", Kind::File, b"new content");
        r.entries(vec![e.clone()]);
        for (h, d) in &c {
            r.chunk(*h, d);
        }
        r.end();
        assert!(fs::symlink_metadata(target.join("f")).unwrap().file_type().is_symlink());
        // Always replaces the symlink itself
        let mut r = Restore::begin(1, target.to_str().unwrap(), Overwrite::Always, "tok").unwrap();
        r.entries(vec![e]);
        for (h, d) in &c {
            r.chunk(*h, d);
        }
        let s = r.end();
        assert!(s.errors.is_empty(), "{:?}", s.errors);
        assert_eq!(fs::read(&victim).unwrap(), b"original");
        assert_eq!(fs::read(target.join("f")).unwrap(), b"new content");
        assert!(fs::symlink_metadata(target.join("f")).unwrap().file_type().is_file());
    }

    #[test]
    fn restores_kinds_and_metadata() {
        let t = tempfile::tempdir().unwrap();
        let target = t.path().join("t");
        let mut r = Restore::begin(1, target.to_str().unwrap(), Overwrite::IfOlder, "tok").unwrap();
        let data: Vec<u8> = (0..5000u32).map(|i| i as u8).collect();
        let (mut d, _) = entry("a", Kind::Dir, b"");
        d.mode = 0o751;
        let (f, chunks) = entry("a/file", Kind::File, &data);
        let (mut l, _) = entry("a/sym", Kind::Symlink, b"");
        l.link_target = Some(b"/etc/shadow".to_vec());
        let (mut h, _) = entry("a/hard", Kind::Hardlink, b"");
        h.link_target = Some(b"a/file".to_vec());
        let (mut p, _) = entry("deep/er/fifo", Kind::Fifo, b"");
        p.mode = 0o600;
        let (empty, _) = entry("a/empty", Kind::File, b"");
        r.entries(vec![d, f, l, h, p, empty]);
        for (hh, dd) in chunks.iter().rev() {
            r.chunk(*hh, dd);
        }
        let s = r.end();
        assert!(s.errors.is_empty(), "{:?}", s.errors);
        let base = &target;
        assert_eq!(fs::read(base.join("a/file")).unwrap(), data);
        let md = fs::metadata(base.join("a/file")).unwrap();
        assert_eq!(md.permissions().mode() & 0o7777, 0o640);
        assert_eq!(md.mtime_nsec(), 123_456_789);
        assert_eq!(fs::read_link(base.join("a/sym")).unwrap(), Path::new("/etc/shadow"));
        assert_eq!(fs::metadata(base.join("a/hard")).unwrap().ino(), md.ino());
        assert!(fs::symlink_metadata(base.join("deep/er/fifo"))
            .unwrap()
            .file_type()
            .is_fifo());
        let dm = fs::metadata(base.join("a")).unwrap();
        assert_eq!(dm.permissions().mode() & 0o7777, 0o751);
        assert_eq!(dm.mtime(), 1_600_000_000);
        assert_eq!(fs::read(base.join("a/empty")).unwrap(), b"");
        let leftovers = fs::read_dir(base.join("a"))
            .unwrap()
            .filter(|e| e.as_ref().unwrap().file_name().to_string_lossy().starts_with(".nexus"))
            .count();
        assert_eq!(leftovers, 0);
        // IfOlder: the existing file has the same mtime -> kept
        let mut r = Restore::begin(1, target.to_str().unwrap(), Overwrite::IfOlder, "tok").unwrap();
        let (f2, _) = entry("a/file", Kind::File, b"other");
        r.entries(vec![f2]);
        let s = r.end();
        assert!(s.errors.is_empty(), "kept by policy is not an error: {:?}", s.errors);
        assert_eq!(fs::read(base.join("a/file")).unwrap(), data);
    }

    #[test]
    fn bad_chunks_are_rejected_and_incomplete_files_removed() {
        let t = tempfile::tempdir().unwrap();
        let mut r = Restore::begin(1, t.path().to_str().unwrap(), Overwrite::Always, "tok").unwrap();
        let (f, chunks) = entry("x", Kind::File, &[7u8; 2500]);
        r.entries(vec![f]);
        r.chunk(chunks[0].0, b"forged");
        r.chunk(chunks[1].0, &chunks[1].1);
        let s = r.end();
        assert!(s.errors.iter().any(|e| e.contains("hash mismatch")));
        assert!(s.errors.iter().any(|e| e.contains("incomplete")));
        assert_eq!(fs::read_dir(t.path()).unwrap().count(), 0, "temp file removed");
    }
}
