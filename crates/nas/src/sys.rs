//! Thin libc wrappers for the scan: `openat2` confined below a directory fd,
//! `statx` without automount, directory listing, xattrs by fd, `readlinkat`.
//! Everything works relative to fds, so it works inside the detached share
//! mount that no path names.

use std::ffi::{CStr, CString};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::atomic::{AtomicBool, Ordering};

pub const RESOLVE_NO_XDEV: u64 = 0x01;
pub const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
pub const RESOLVE_NO_SYMLINKS: u64 = 0x04;
pub const RESOLVE_BENEATH: u64 = 0x08;

/// Below the root, never via a symlink, never across a mount (nested exports,
/// automounted snapshot dirs, a server-side mount over a directory).
pub const CONFINED: u64 = RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS | RESOLVE_NO_XDEV;

/// Upper bound of one xattr value and of all xattrs of an entry.
pub const MAX_XATTR: usize = 64 << 10;

fn cvt(r: libc::c_int) -> io::Result<libc::c_int> {
    if r < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(r)
    }
}

pub fn cstr(b: &[u8]) -> io::Result<CString> {
    CString::new(b).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in path"))
}

#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

/// openat2 is unavailable: the kernel is older than 5.6, or a seccomp filter
/// refuses it (systemd's `RestrictSUIDSGID=` answers ENOSYS for openat2, whose
/// mode argument it cannot inspect — the scheduler's unit, inherited by jobs).
static NO_OPENAT2: AtomicBool = AtomicBool::new(false);

/// `openat2(dirfd, path, flags | O_NOFOLLOW | O_CLOEXEC, resolve)`; without
/// openat2 the same confinement component by component (see [`open_walk`]).
pub fn openat2(dirfd: RawFd, path: &[u8], flags: libc::c_int, resolve: u64) -> io::Result<OwnedFd> {
    if !NO_OPENAT2.load(Ordering::Relaxed) {
        match raw_openat2(dirfd, path, flags, resolve) {
            Err(e) if e.raw_os_error() == Some(libc::ENOSYS) => NO_OPENAT2.store(true, Ordering::Relaxed),
            r => return r,
        }
    }
    open_walk(dirfd, path, flags, resolve)
}

/// Tests: use the [`open_walk`] fallback from now on (as under a seccomp filter).
#[doc(hidden)]
pub fn disable_openat2() {
    NO_OPENAT2.store(true, Ordering::Relaxed);
}

/// The openat2 confinement with plain `openat`: the path is split into
/// components (no empty, `.` or `..` component: never above `dirfd`), each is
/// opened with `O_NOFOLLOW` (a symlink anywhere fails), and with
/// `RESOLVE_NO_XDEV` every opened component must be on `dirfd`'s mount.
pub fn open_walk(dirfd: RawFd, path: &[u8], flags: libc::c_int, resolve: u64) -> io::Result<OwnedFd> {
    let einval = || io::Error::from_raw_os_error(libc::EINVAL);
    let base = if resolve & RESOLVE_NO_XDEV != 0 {
        Some(fstatx(dirfd, false)?)
    } else {
        None
    };
    let comps: Vec<&[u8]> = if path == b"." {
        vec![b"."]
    } else {
        let c: Vec<&[u8]> = path.split(|b| *b == b'/').collect();
        if c.iter().any(|c| c.is_empty() || *c == b"." || *c == b"..") {
            return Err(einval());
        }
        c
    };
    let mut cur: Option<OwnedFd> = None;
    for (i, c) in comps.iter().enumerate() {
        let last = i + 1 == comps.len();
        let fl = if last {
            flags
        } else {
            libc::O_RDONLY | libc::O_DIRECTORY
        };
        let name = cstr(c)?;
        let at = cur.as_ref().map_or(dirfd, |f| f.as_raw_fd());
        // SAFETY: openat with a valid C string.
        let r = unsafe {
            libc::openat(
                at,
                name.as_ptr(),
                fl | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NOCTTY,
            )
        };
        if r < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: fresh fd owned by us.
        let fd = unsafe { OwnedFd::from_raw_fd(r) };
        if let Some(b) = &base {
            let s = fstatx(fd.as_raw_fd(), false)?;
            if s.dev != b.dev || s.mnt_id != b.mnt_id {
                return Err(io::Error::from_raw_os_error(libc::EXDEV));
            }
        }
        cur = Some(fd);
    }
    cur.ok_or_else(einval)
}

fn raw_openat2(dirfd: RawFd, path: &[u8], flags: libc::c_int, resolve: u64) -> io::Result<OwnedFd> {
    let p = cstr(path)?;
    let how = OpenHow {
        flags: (flags | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NOCTTY) as u64,
        mode: 0,
        resolve,
    };
    loop {
        // SAFETY: openat2 with a correctly sized open_how struct and a C string.
        let r = unsafe {
            libc::syscall(
                libc::SYS_openat2,
                dirfd,
                p.as_ptr(),
                &how as *const OpenHow,
                std::mem::size_of::<OpenHow>(),
            )
        };
        if r < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted || e.raw_os_error() == Some(libc::EAGAIN) {
                continue;
            }
            return Err(e);
        }
        // SAFETY: fresh fd owned by us.
        return Ok(unsafe { OwnedFd::from_raw_fd(r as RawFd) });
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    File,
    Dir,
    Symlink,
    Fifo,
    Socket,
    Device,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Stat {
    pub kind: Kind,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub size: u64,
    pub mtime_ns: i64,
    pub ctime_ns: i64,
    pub ino: u64,
    pub nlink: u32,
    pub dev: u64,
    pub rdev: u64,
    pub mnt_id: u64,
    /// automount point (nested export / snapshot dir not mounted yet)
    pub automount: bool,
}

fn ns(t: libc::statx_timestamp) -> i64 {
    t.tv_sec.saturating_mul(1_000_000_000).saturating_add(t.tv_nsec as i64)
}

fn from_statx(s: &libc::statx) -> io::Result<Stat> {
    let kind = match u32::from(s.stx_mode) & libc::S_IFMT {
        libc::S_IFREG => Kind::File,
        libc::S_IFDIR => Kind::Dir,
        libc::S_IFLNK => Kind::Symlink,
        libc::S_IFIFO => Kind::Fifo,
        libc::S_IFSOCK => Kind::Socket,
        libc::S_IFCHR | libc::S_IFBLK => Kind::Device,
        _ => return Err(io::Error::other("unknown file type")),
    };
    Ok(Stat {
        kind,
        mode: u32::from(s.stx_mode),
        uid: s.stx_uid,
        gid: s.stx_gid,
        size: s.stx_size,
        mtime_ns: ns(s.stx_mtime),
        ctime_ns: ns(s.stx_ctime),
        ino: s.stx_ino,
        nlink: s.stx_nlink,
        dev: libc::makedev(s.stx_dev_major, s.stx_dev_minor),
        rdev: libc::makedev(s.stx_rdev_major, s.stx_rdev_minor),
        mnt_id: s.stx_mnt_id,
        automount: s.stx_attributes & libc::STATX_ATTR_AUTOMOUNT as u64 != 0,
    })
}

const MASK: libc::c_uint = libc::STATX_BASIC_STATS | libc::STATX_MNT_ID;

/// `statx(dirfd, name, AT_SYMLINK_NOFOLLOW | AT_NO_AUTOMOUNT)` (never triggers an automount).
pub fn statx_at(dirfd: RawFd, name: &CStr) -> io::Result<Stat> {
    // SAFETY: zeroed statx is a valid out buffer.
    let mut s: libc::statx = unsafe { std::mem::zeroed() };
    cvt(unsafe {
        libc::statx(
            dirfd,
            name.as_ptr(),
            libc::AT_SYMLINK_NOFOLLOW | libc::AT_NO_AUTOMOUNT,
            MASK,
            &mut s,
        )
    })?;
    from_statx(&s)
}

/// `statx` of an open fd; `force_sync` asks the server (NFS/SMB: no cached attributes).
pub fn fstatx(fd: RawFd, force_sync: bool) -> io::Result<Stat> {
    let mut s: libc::statx = unsafe { std::mem::zeroed() };
    let flags = libc::AT_EMPTY_PATH | if force_sync { libc::AT_STATX_FORCE_SYNC } else { 0 };
    // SAFETY: empty C string with AT_EMPTY_PATH on a valid fd.
    cvt(unsafe { libc::statx(fd, c"".as_ptr(), flags, MASK, &mut s) })?;
    from_statx(&s)
}

/// Names in a directory (without `.` and `..`), sorted bytewise.
pub fn read_dir(fd: &OwnedFd) -> io::Result<Vec<Vec<u8>>> {
    // fdopendir takes ownership of the fd: give it a duplicate
    // SAFETY: dup of a valid fd.
    let d = cvt(unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) })?;
    // SAFETY: d is a fresh directory fd; on failure we close it ourselves.
    let dir = unsafe { libc::fdopendir(d) };
    if dir.is_null() {
        let e = io::Error::last_os_error();
        unsafe { libc::close(d) };
        return Err(e);
    }
    let mut out = Vec::new();
    let res = loop {
        // SAFETY: errno is thread-local; readdir64 on a valid DIR*.
        unsafe { *libc::__errno_location() = 0 };
        let e = unsafe { libc::readdir64(dir) };
        if e.is_null() {
            let errno = unsafe { *libc::__errno_location() };
            break if errno == 0 {
                Ok(())
            } else {
                Err(io::Error::from_raw_os_error(errno))
            };
        }
        // SAFETY: d_name is NUL-terminated inside the dirent.
        let name = unsafe { CStr::from_ptr((*e).d_name.as_ptr()) }.to_bytes();
        if name != b"." && name != b".." {
            out.push(name.to_vec());
        }
    };
    // SAFETY: closes the DIR* and its fd.
    unsafe { libc::closedir(dir) };
    res?;
    out.sort_unstable();
    Ok(out)
}

/// `readlinkat(dirfd, name)` (targets up to PATH_MAX).
pub fn readlinkat(dirfd: RawFd, name: &CStr) -> io::Result<Vec<u8>> {
    let mut buf = vec![0u8; crate::MAX_PATH + 1];
    // SAFETY: buffer of the given length.
    let n = unsafe { libc::readlinkat(dirfd, name.as_ptr(), buf.as_mut_ptr().cast(), buf.len()) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    let n = n as usize;
    if n > crate::MAX_PATH {
        return Err(io::Error::other("symlink target too long"));
    }
    buf.truncate(n);
    Ok(buf)
}

fn ignorable(e: &io::Error) -> bool {
    matches!(
        e.raw_os_error(),
        Some(libc::ENODATA) | Some(libc::EOPNOTSUPP) | Some(libc::EINVAL)
    )
}

/// Extended attributes of an open file/directory: every listed name plus the
/// `extra` names file systems do not list (`system.nfs4_acl`, `system.cifs_acl`,
/// `user.cifs.*`). `security.selinux` (the local label of the mount) is skipped.
/// Values above [`MAX_XATTR`] are an error; the total is bounded by the same limit.
pub fn fxattrs(fd: RawFd, extra: &[&str], buf: &mut Vec<u8>) -> io::Result<Vec<(Vec<u8>, Vec<u8>)>> {
    buf.resize(MAX_XATTR, 0);
    // SAFETY: buffer of the given size.
    let n = unsafe { libc::flistxattr(fd, buf.as_mut_ptr().cast(), buf.len()) };
    let mut names: Vec<Vec<u8>> = if n < 0 {
        let e = io::Error::last_os_error();
        if !ignorable(&e) {
            return Err(e);
        }
        Vec::new()
    } else {
        buf[..n as usize]
            .split(|b| *b == 0)
            .filter(|s| !s.is_empty())
            .map(<[u8]>::to_vec)
            .collect()
    };
    for x in extra {
        if !names.iter().any(|n| n == x.as_bytes()) {
            names.push(x.as_bytes().to_vec());
        }
    }
    names.retain(|n| n != b"security.selinux");
    names.sort();
    let mut out = Vec::new();
    let mut total = 0usize;
    for name in names {
        let c = cstr(&name)?;
        // SAFETY: buffer of the given size, valid C string.
        let n = unsafe { libc::fgetxattr(fd, c.as_ptr(), buf.as_mut_ptr().cast(), buf.len()) };
        if n < 0 {
            let e = io::Error::last_os_error();
            if ignorable(&e) {
                continue;
            }
            if e.raw_os_error() == Some(libc::ERANGE) {
                return Err(io::Error::other(format!(
                    "xattr {} larger than {MAX_XATTR} bytes",
                    String::from_utf8_lossy(&name)
                )));
            }
            return Err(e);
        }
        total += name.len() + n as usize;
        if total > MAX_XATTR {
            return Err(io::Error::other(format!(
                "xattrs larger than {MAX_XATTR} bytes in total"
            )));
        }
        out.push((name, buf[..n as usize].to_vec()));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn open_walk_is_confined_like_openat2() {
        let d = tempfile::tempdir().unwrap();
        fs::create_dir_all(d.path().join("a/b")).unwrap();
        fs::write(d.path().join("a/b/f"), "x").unwrap();
        std::os::unix::fs::symlink("b", d.path().join("a/lnk")).unwrap();
        std::os::unix::fs::symlink("/etc", d.path().join("etc")).unwrap();
        let root = crate::mount::open_local(d.path()).unwrap();
        let r = root.as_raw_fd();
        for f in [open_walk, openat2] {
            assert!(f(r, b"a/b/f", libc::O_RDONLY, CONFINED).is_ok());
            assert!(f(r, b".", libc::O_RDONLY | libc::O_DIRECTORY, CONFINED).is_ok());
            for bad in [&b"a/lnk/f"[..], b"etc/passwd", b"etc", b"../x", b"/etc/passwd"] {
                assert!(
                    f(r, bad, libc::O_RDONLY, CONFINED).is_err(),
                    "{}",
                    String::from_utf8_lossy(bad)
                );
            }
        }
        // stricter than openat2 (which allows `..` that stays beneath): no `..`, `.` or empty components
        for bad in [&b"a/../a/b/f"[..], b"a//b", b"a/./b"] {
            assert!(open_walk(r, bad, libc::O_RDONLY, CONFINED).is_err());
        }
    }
}
