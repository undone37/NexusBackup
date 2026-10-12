//! Thin libc wrappers (xattrs, openat2, mounts, namespaces).

use std::ffi::{CString, OsStr};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

pub fn cstr(p: impl AsRef<OsStr>) -> io::Result<CString> {
    CString::new(p.as_ref().as_bytes()).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in path"))
}

fn cvt(r: libc::c_int) -> io::Result<libc::c_int> {
    if r < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(r)
    }
}

fn cvt_ssize(r: libc::ssize_t) -> io::Result<usize> {
    if r < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(r as usize)
    }
}

/// All xattrs of `path` without following a final symlink (includes `security.*`
/// and the POSIX ACLs `system.posix_acl_access` / `system.posix_acl_default`).
pub fn lxattrs(path: &Path) -> io::Result<Vec<(Vec<u8>, Vec<u8>)>> {
    let p = cstr(path)?;
    let mut names = vec![0u8; 1024];
    let len = loop {
        // SAFETY: buffer pointer/length are valid for the call.
        match cvt_ssize(unsafe { libc::llistxattr(p.as_ptr(), names.as_mut_ptr().cast(), names.len()) }) {
            Ok(n) => break n,
            Err(e) if e.raw_os_error() == Some(libc::ERANGE) => names.resize(names.len() * 4, 0),
            Err(e) if matches!(e.raw_os_error(), Some(libc::ENOTSUP) | Some(libc::ENODATA)) => return Ok(vec![]),
            Err(e) => return Err(e),
        }
        if names.len() > 1 << 20 {
            return Err(io::Error::other("xattr name list too large"));
        }
    };
    let mut out = Vec::new();
    for name in names[..len].split(|b| *b == 0).filter(|n| !n.is_empty()) {
        let cname = CString::new(name).expect("split on NUL");
        let mut val = vec![0u8; 256];
        loop {
            // SAFETY: as above.
            let r = unsafe { libc::lgetxattr(p.as_ptr(), cname.as_ptr(), val.as_mut_ptr().cast(), val.len()) };
            match cvt_ssize(r) {
                Ok(n) => {
                    val.truncate(n);
                    out.push((name.to_vec(), val));
                    break;
                }
                Err(e) if e.raw_os_error() == Some(libc::ERANGE) && val.len() < 1 << 20 => val.resize(val.len() * 8, 0),
                Err(e) if e.raw_os_error() == Some(libc::ENODATA) => break, // removed meanwhile
                Err(e) => return Err(e),
            }
        }
    }
    out.sort();
    Ok(out)
}

pub fn fsetxattr(fd: RawFd, name: &[u8], value: &[u8]) -> io::Result<()> {
    let n = CString::new(name).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in xattr name"))?;
    // SAFETY: valid fd, name and value buffers.
    cvt(unsafe { libc::fsetxattr(fd, n.as_ptr(), value.as_ptr().cast(), value.len(), 0) }).map(drop)
}

/// xattrs on an `O_PATH` fd (symlinks): via the `/proc/self/fd` magic link, which
/// resolves to the inode the fd refers to (never to a symlink's target).
pub fn setxattr_opath(fd: RawFd, name: &[u8], value: &[u8]) -> io::Result<()> {
    let p = cstr(format!("/proc/self/fd/{fd}"))?;
    let n = CString::new(name).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in xattr name"))?;
    // SAFETY: valid C strings and buffers.
    cvt(unsafe { libc::setxattr(p.as_ptr(), n.as_ptr(), value.as_ptr().cast(), value.len(), 0) }).map(drop)
}

pub const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
pub const RESOLVE_NO_SYMLINKS: u64 = 0x04;
pub const RESOLVE_BENEATH: u64 = 0x08;

#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

/// `openat2(dirfd, name, flags, mode, RESOLVE_BENEATH|RESOLVE_NO_MAGICLINKS|RESOLVE_NO_SYMLINKS)`.
/// Falls back to `openat(.., O_NOFOLLOW)` on kernels without openat2 (< 5.6); callers
/// only pass single path components, so the fallback is equally confined.
pub fn openat_beneath(dirfd: RawFd, name: &OsStr, flags: libc::c_int, mode: u32) -> io::Result<OwnedFd> {
    let n = cstr(name)?;
    let how = OpenHow {
        flags: (flags | libc::O_NOFOLLOW | libc::O_CLOEXEC) as u64,
        mode: if flags & libc::O_CREAT != 0 { mode as u64 } else { 0 },
        resolve: RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS,
    };
    // SAFETY: openat2 with a correctly sized open_how struct.
    let r = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            dirfd,
            n.as_ptr(),
            &how as *const OpenHow,
            std::mem::size_of::<OpenHow>(),
        )
    };
    let fd = if r < 0 {
        let e = io::Error::last_os_error();
        if e.raw_os_error() != Some(libc::ENOSYS) {
            return Err(e);
        }
        // SAFETY: plain openat.
        cvt(unsafe { libc::openat(dirfd, n.as_ptr(), flags | libc::O_NOFOLLOW | libc::O_CLOEXEC, mode) })?
    } else {
        r as RawFd
    };
    // SAFETY: fd is freshly opened and owned by us.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

pub fn fstatat_nofollow(dirfd: RawFd, name: &OsStr) -> io::Result<libc::stat> {
    let n = cstr(name)?;
    // SAFETY: zeroed stat is a valid out buffer.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    cvt(unsafe { libc::fstatat(dirfd, n.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) })?;
    Ok(st)
}

pub fn fstat(fd: &impl AsRawFd) -> io::Result<libc::stat> {
    // SAFETY: as above.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    cvt(unsafe { libc::fstat(fd.as_raw_fd(), &mut st) })?;
    Ok(st)
}

pub fn mkdirat(dirfd: RawFd, name: &OsStr, mode: u32) -> io::Result<()> {
    let n = cstr(name)?;
    // SAFETY: valid fd and C string.
    cvt(unsafe { libc::mkdirat(dirfd, n.as_ptr(), mode) }).map(drop)
}

pub fn symlinkat(target: &[u8], dirfd: RawFd, name: &OsStr) -> io::Result<()> {
    let t = CString::new(target).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in link target"))?;
    let n = cstr(name)?;
    // SAFETY: valid strings and fd.
    cvt(unsafe { libc::symlinkat(t.as_ptr(), dirfd, n.as_ptr()) }).map(drop)
}

pub fn mknodat(dirfd: RawFd, name: &OsStr, mode: u32, dev: u64) -> io::Result<()> {
    let n = cstr(name)?;
    // SAFETY: valid fd and C string.
    cvt(unsafe { libc::mknodat(dirfd, n.as_ptr(), mode as libc::mode_t, dev as libc::dev_t) }).map(drop)
}

pub fn linkat(olddir: RawFd, old: &OsStr, newdir: RawFd, new: &OsStr) -> io::Result<()> {
    let o = cstr(old)?;
    let n = cstr(new)?;
    // SAFETY: valid fds/strings; flags 0 = do not follow a symlink `old`.
    cvt(unsafe { libc::linkat(olddir, o.as_ptr(), newdir, n.as_ptr(), 0) }).map(drop)
}

pub fn renameat(olddir: RawFd, old: &OsStr, newdir: RawFd, new: &OsStr) -> io::Result<()> {
    let o = cstr(old)?;
    let n = cstr(new)?;
    // SAFETY: valid fds/strings.
    cvt(unsafe { libc::renameat(olddir, o.as_ptr(), newdir, n.as_ptr()) }).map(drop)
}

pub fn unlinkat(dirfd: RawFd, name: &OsStr, dir: bool) -> io::Result<()> {
    let n = cstr(name)?;
    // SAFETY: valid fd/string.
    cvt(unsafe { libc::unlinkat(dirfd, n.as_ptr(), if dir { libc::AT_REMOVEDIR } else { 0 }) }).map(drop)
}

pub fn fchownat_nofollow(dirfd: RawFd, name: &OsStr, uid: u32, gid: u32) -> io::Result<()> {
    let n = cstr(name)?;
    // SAFETY: valid fd/string.
    cvt(unsafe { libc::fchownat(dirfd, n.as_ptr(), uid, gid, libc::AT_SYMLINK_NOFOLLOW) }).map(drop)
}

pub fn fchmodat(dirfd: RawFd, name: &OsStr, mode: u32) -> io::Result<()> {
    let n = cstr(name)?;
    // SAFETY: valid fd/string (fchmodat never follows nothing but the final symlink; we
    // only call it for non-symlinks that were just created by us).
    cvt(unsafe { libc::fchmodat(dirfd, n.as_ptr(), mode as libc::mode_t, 0) }).map(drop)
}

pub fn utimensat_nofollow(dirfd: RawFd, name: &OsStr, mtime_ns: i64) -> io::Result<()> {
    let n = cstr(name)?;
    let ts = libc::timespec {
        tv_sec: mtime_ns.div_euclid(1_000_000_000),
        tv_nsec: mtime_ns.rem_euclid(1_000_000_000),
    };
    let times = [ts, ts];
    // SAFETY: valid fd/string and timespec array.
    cvt(unsafe { libc::utimensat(dirfd, n.as_ptr(), times.as_ptr(), libc::AT_SYMLINK_NOFOLLOW) }).map(drop)
}

pub fn geteuid() -> u32 {
    // SAFETY: trivial syscall.
    unsafe { libc::geteuid() }
}

/// Private mount namespace for this process; host mounts still propagate in
/// (`MS_SLAVE`), our snapshot mounts never propagate out. Must run before threads start.
pub fn private_mount_namespace() -> io::Result<()> {
    // SAFETY: plain syscalls with valid arguments.
    cvt(unsafe { libc::unshare(libc::CLONE_NEWNS) })?;
    let root = cstr("/")?;
    cvt(unsafe {
        libc::mount(
            std::ptr::null(),
            root.as_ptr(),
            std::ptr::null(),
            libc::MS_REC | libc::MS_SLAVE,
            std::ptr::null(),
        )
    })
    .map(drop)
}

pub fn mount_ro(dev: &Path, target: &Path, fstype: &str, data: &str) -> io::Result<()> {
    let (d, t, f, o) = (cstr(dev)?, cstr(target)?, cstr(fstype)?, cstr(data)?);
    let flags = libc::MS_RDONLY | libc::MS_NODEV | libc::MS_NOSUID | libc::MS_NOEXEC;
    // SAFETY: valid C strings.
    cvt(unsafe { libc::mount(d.as_ptr(), t.as_ptr(), f.as_ptr(), flags, o.as_ptr().cast()) }).map(drop)
}

pub fn umount(target: &Path) -> io::Result<()> {
    let t = cstr(target)?;
    // SAFETY: valid C string.
    cvt(unsafe { libc::umount2(t.as_ptr(), libc::MNT_DETACH) }).map(drop)
}

pub fn uname() -> (String, String) {
    // SAFETY: zeroed utsname is a valid out buffer.
    let mut u: libc::utsname = unsafe { std::mem::zeroed() };
    if unsafe { libc::uname(&mut u) } != 0 {
        return (String::new(), String::new());
    }
    let s = |f: &[libc::c_char]| {
        let b: Vec<u8> = f.iter().take_while(|c| **c != 0).map(|c| *c as u8).collect();
        String::from_utf8_lossy(&b).into_owned()
    };
    (s(&u.release), s(&u.nodename))
}

/// `Limits::nice` for the calling thread (Linux priorities are per thread; hooks
/// inherit them). Only ever lowers: CPU nice becomes `max(current, n)` (the unit
/// already runs with `Nice=10`, and raising needs CAP_SYS_NICE, which the agent does
/// not have); from 15 on the I/O class becomes idle (the unit's default is
/// best-effort 7). Returns (nice, idle I/O) as set.
pub fn lower_priority(n: u8) -> io::Result<(i32, bool)> {
    // SAFETY: plain syscalls on the calling thread.
    let tid = unsafe { libc::syscall(libc::SYS_gettid) } as libc::id_t;
    // getpriority may legitimately return -1: clear errno first
    unsafe { *libc::__errno_location() = 0 };
    let cur = unsafe { libc::getpriority(libc::PRIO_PROCESS, tid) };
    if cur == -1 && io::Error::last_os_error().raw_os_error().unwrap_or(0) != 0 {
        return Err(io::Error::last_os_error());
    }
    let nice = cur.max(i32::from(n.min(19)));
    if nice > cur {
        cvt(unsafe { libc::setpriority(libc::PRIO_PROCESS, tid, nice) })?;
    }
    let idle = n >= 15;
    if idle {
        const IOPRIO_WHO_PROCESS: libc::c_long = 1;
        const IOPRIO_CLASS_IDLE: libc::c_long = 3;
        // SAFETY: ioprio_set(which, who, ioprio) on the calling thread
        let r = unsafe {
            libc::syscall(
                libc::SYS_ioprio_set,
                IOPRIO_WHO_PROCESS,
                tid as libc::c_long,
                IOPRIO_CLASS_IDLE << 13,
            )
        };
        cvt(r as libc::c_int)?;
    }
    Ok((nice, idle))
}
