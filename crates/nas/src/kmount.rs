//! The new mount API (`fsopen` → `fsconfig` → `fsmount`): builds a
//! [`MountSpec`] as a detached mount and returns its fd. The mount is never
//! attached to any mount namespace a process lives in (`move_mount` is never
//! called); it lives in an anonymous namespace until the last fd is closed,
//! then the kernel unmounts it.

use crate::opts::{MountSpec, Param};
use std::ffi::CString;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

const FSOPEN_CLOEXEC: libc::c_uint = 1;
const FSMOUNT_CLOEXEC: libc::c_uint = 1;
const FSCONFIG_SET_FLAG: libc::c_uint = 0;
const FSCONFIG_SET_STRING: libc::c_uint = 1;
const FSCONFIG_CMD_CREATE: libc::c_uint = 6;

fn cstr(s: &str) -> io::Result<CString> {
    CString::new(s).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in mount option"))
}

/// Messages the file system left in the fs context (`e …`, `w …`, `i …`).
fn context_log(fs: &OwnedFd) -> String {
    let mut out = Vec::new();
    let mut buf = [0u8; 1024];
    for _ in 0..32 {
        // SAFETY: reading into a stack buffer of the given size.
        let n = unsafe { libc::read(fs.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
        if n <= 0 {
            break;
        }
        out.push(String::from_utf8_lossy(&buf[..n as usize]).trim_end().to_owned());
    }
    out.join("; ")
}

fn err_with_log(what: &str, e: io::Error, fs: &OwnedFd) -> io::Error {
    let log = context_log(fs);
    let msg = if log.is_empty() {
        format!("{what}: {e}")
    } else {
        format!("{what}: {e} ({log})")
    };
    io::Error::new(e.kind(), msg)
}

/// Creates the mount; returns the detached mount fd (`O_PATH`-like, close-on-exec).
pub fn mount(spec: &MountSpec) -> io::Result<OwnedFd> {
    let ty = cstr(spec.fstype)?;
    // SAFETY: fsopen with a valid C string.
    let r = unsafe { libc::syscall(libc::SYS_fsopen, ty.as_ptr(), FSOPEN_CLOEXEC) };
    if r < 0 {
        let e = io::Error::last_os_error();
        return Err(io::Error::new(e.kind(), format!("fsopen({}): {e}", spec.fstype)));
    }
    // SAFETY: fresh fd owned by us.
    let fs = unsafe { OwnedFd::from_raw_fd(r as i32) };
    for p in &spec.params {
        let (cmd, key, val) = match p {
            Param::Flag(k) => (FSCONFIG_SET_FLAG, cstr(k)?, None),
            Param::Str(k, v) => (FSCONFIG_SET_STRING, cstr(k)?, Some(cstr(v)?)),
        };
        let vptr = val.as_ref().map_or(std::ptr::null(), |v| v.as_ptr());
        // SAFETY: fsconfig with valid C strings (or NULL for flags).
        let r = unsafe { libc::syscall(libc::SYS_fsconfig, fs.as_raw_fd(), cmd, key.as_ptr(), vptr, 0) };
        if r < 0 {
            let k = key.to_string_lossy().into_owned();
            return Err(err_with_log(&format!("option {k}"), io::Error::last_os_error(), &fs));
        }
    }
    // SAFETY: fsconfig create command, no key/value.
    let r = unsafe {
        libc::syscall(
            libc::SYS_fsconfig,
            fs.as_raw_fd(),
            FSCONFIG_CMD_CREATE,
            std::ptr::null::<libc::c_char>(),
            std::ptr::null::<libc::c_char>(),
            0,
        )
    };
    if r < 0 {
        return Err(err_with_log("mount", io::Error::last_os_error(), &fs));
    }
    // SAFETY: fsmount on the configured context.
    let r = unsafe { libc::syscall(libc::SYS_fsmount, fs.as_raw_fd(), FSMOUNT_CLOEXEC, spec.attrs) };
    if r < 0 {
        return Err(err_with_log("fsmount", io::Error::last_os_error(), &fs));
    }
    // SAFETY: fresh fd owned by us.
    Ok(unsafe { OwnedFd::from_raw_fd(r as i32) })
}
