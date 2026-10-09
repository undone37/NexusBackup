//! Thin libc wrappers for the scan: `openat2` confined below a directory fd,
//! `statx` without automount, directory listing, xattrs by fd, `readlinkat`.
//! Everything works relative to fds, so it works inside the detached share
//! mount that no path names.

use std::ffi::{CStr, CString};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

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

/// `openat2(dirfd, path, flags | O_NOFOLLOW | O_CLOEXEC, resolve)`.
pub fn openat2(dirfd: RawFd, path: &[u8], flags: libc::c_int, resolve: u64) -> io::Result<OwnedFd> {
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
