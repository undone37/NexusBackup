//! Minimal Landlock (Linux ≥ 5.13) via raw system calls: the ruleset is built in
//! the host before `fork`, the child only calls `landlock_restrict_self` (one
//! async-signal-safe system call) right before it executes the plugin.
//!
//! Rights are negotiated with the kernel's ABI version: everything the kernel can
//! restrict is handled (denied unless a rule allows it). ABI 4 adds TCP bind /
//! connect port rules, ABI 6 scoping of signals and abstract Unix sockets.

use std::ffi::CString;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

const CREATE_RULESET_VERSION: u32 = 1;
const RULE_PATH_BENEATH: u32 = 1;
const RULE_NET_PORT: u32 = 2;

/// Execute a file.
pub const FS_EXECUTE: u64 = 1 << 0;
/// Open a file for writing.
pub const FS_WRITE_FILE: u64 = 1 << 1;
/// Open a file for reading.
pub const FS_READ_FILE: u64 = 1 << 2;
/// List a directory.
pub const FS_READ_DIR: u64 = 1 << 3;
/// Remove an empty directory.
pub const FS_REMOVE_DIR: u64 = 1 << 4;
/// Unlink a file.
pub const FS_REMOVE_FILE: u64 = 1 << 5;
/// Create a character device.
pub const FS_MAKE_CHAR: u64 = 1 << 6;
/// Create a directory.
pub const FS_MAKE_DIR: u64 = 1 << 7;
/// Create a regular file.
pub const FS_MAKE_REG: u64 = 1 << 8;
/// Create a Unix socket file.
pub const FS_MAKE_SOCK: u64 = 1 << 9;
/// Create a named pipe.
pub const FS_MAKE_FIFO: u64 = 1 << 10;
/// Create a block device.
pub const FS_MAKE_BLOCK: u64 = 1 << 11;
/// Create a symlink.
pub const FS_MAKE_SYM: u64 = 1 << 12;
/// Link or rename a file into another directory (ABI 2).
pub const FS_REFER: u64 = 1 << 13; // ABI 2
/// Truncate a file (ABI 3).
pub const FS_TRUNCATE: u64 = 1 << 14; // ABI 3
/// `ioctl` on a device file (ABI 5).
pub const FS_IOCTL_DEV: u64 = 1 << 15; // ABI 5
const NET_BIND_TCP: u64 = 1 << 0;
const NET_CONNECT_TCP: u64 = 1 << 1;
const SCOPE_ABSTRACT_UNIX: u64 = 1 << 0;
const SCOPE_SIGNAL: u64 = 1 << 1;

/// Rights that apply to a regular file (a rule on a file may only carry these).
const FILE_RIGHTS: u64 = FS_EXECUTE | FS_WRITE_FILE | FS_READ_FILE | FS_TRUNCATE | FS_IOCTL_DEV;
/// Read files, list directories and execute: install dir and system paths.
pub const READ_EXEC: u64 = FS_READ_FILE | FS_READ_DIR | FS_EXECUTE;
/// Read files and list directories.
pub const READ: u64 = FS_READ_FILE | FS_READ_DIR;

#[repr(C)]
struct RulesetAttr {
    handled_access_fs: u64,
    handled_access_net: u64,
    scoped: u64,
}

#[repr(C, packed)]
struct PathBeneathAttr {
    allowed_access: u64,
    parent_fd: i32,
}

#[repr(C)]
struct NetPortAttr {
    allowed_access: u64,
    port: u64,
}

/// Landlock ABI of the running kernel (0 = unavailable or disabled).
pub fn abi() -> u32 {
    // SAFETY: a NULL attr with size 0 and LANDLOCK_CREATE_RULESET_VERSION is the documented ABI query;
    // the kernel reads no memory.
    let r = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<RulesetAttr>(),
            0usize,
            CREATE_RULESET_VERSION,
        )
    };
    if r < 0 {
        0
    } else {
        r as u32
    }
}

fn fs_rights(abi: u32) -> u64 {
    let mut r = (1 << 13) - 1; // EXECUTE .. MAKE_SYM (ABI 1)
    if abi >= 2 {
        r |= FS_REFER;
    }
    if abi >= 3 {
        r |= FS_TRUNCATE;
    }
    if abi >= 5 {
        r |= FS_IOCTL_DEV;
    }
    r
}

/// A created ruleset (the host keeps it until the child has restricted itself).
pub struct Ruleset {
    fd: OwnedFd,
    /// Landlock ABI version the ruleset was built for.
    pub abi: u32,
    handled_fs: u64,
    /// TCP bind/connect are restricted (asked for and ABI ≥ 4).
    pub net: bool,
    /// Signals and abstract Unix sockets are scoped to the sandbox (ABI ≥ 6).
    pub scoped: bool,
}

impl Ruleset {
    /// Handles every right the kernel knows; `restrict_net` adds TCP bind/connect (ABI ≥ 4).
    pub fn new(restrict_net: bool) -> io::Result<Ruleset> {
        let abi = abi();
        if abi == 0 {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Landlock is not available (kernel < 5.13 or not in the LSM list)",
            ));
        }
        let net = restrict_net && abi >= 4;
        let scoped = abi >= 6;
        let attr = RulesetAttr {
            handled_access_fs: fs_rights(abi),
            handled_access_net: if net { NET_BIND_TCP | NET_CONNECT_TCP } else { 0 },
            scoped: if scoped { SCOPE_ABSTRACT_UNIX | SCOPE_SIGNAL } else { 0 },
        };
        // the kernel accepts a shorter struct for older ABIs (fields it does not know)
        let size = match abi {
            1..=3 => 8,
            4 | 5 => 16,
            _ => std::mem::size_of::<RulesetAttr>(),
        };
        // SAFETY: `attr` is a live #[repr(C)] landlock_ruleset_attr and `size` never exceeds its size (shorter
        // prefixes for older ABIs); the kernel only reads it during the call.
        let fd = unsafe {
            libc::syscall(
                libc::SYS_landlock_create_ruleset,
                &attr as *const RulesetAttr,
                size,
                0u32,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Ruleset {
            // SAFETY: `fd` is a fresh ruleset descriptor (checked >= 0) that nothing else owns.
            fd: unsafe { OwnedFd::from_raw_fd(fd as i32) },
            abi,
            handled_fs: attr.handled_access_fs,
            net,
            scoped,
        })
    }

    /// Allows `access` below `path` (or on the file `path`). Missing paths are skipped
    /// (returns false); symlinks are followed (the rule applies to the target).
    pub fn allow_path(&mut self, path: &Path, access: u64) -> io::Result<bool> {
        let c = CString::new(path.as_os_str().as_bytes())?;
        // SAFETY: `c` is a NUL-terminated CString alive across the call.
        let fd = unsafe { libc::open(c.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
        if fd < 0 {
            let e = io::Error::last_os_error();
            return match e.kind() {
                io::ErrorKind::NotFound | io::ErrorKind::PermissionDenied => Ok(false),
                _ => Err(e),
            };
        }
        // SAFETY: `fd` is a fresh descriptor (checked >= 0) that nothing else owns.
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        // SAFETY: libc::stat is plain C data (integers only); all-zero is a valid value for the out buffer.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: `fd` is open (owned above) and `st` is a valid, exclusive out buffer.
        if unsafe { libc::fstat(fd.as_raw_fd(), &mut st) } != 0 {
            // O_PATH opens without permission checks; SELinux denies the getattr (e.g.
            // /dev/random for nexus_pluginhost_t): the plugin could not use it either
            let e = io::Error::last_os_error();
            return match e.kind() {
                io::ErrorKind::PermissionDenied => Ok(false),
                _ => Err(e),
            };
        }
        let mut access = access & self.handled_fs;
        if st.st_mode & libc::S_IFMT != libc::S_IFDIR {
            access &= FILE_RIGHTS;
        }
        if access == 0 {
            return Ok(false);
        }
        let attr = PathBeneathAttr {
            allowed_access: access,
            parent_fd: fd.as_raw_fd(),
        };
        // SAFETY: `self.fd` is our open ruleset and `attr` a live #[repr(C, packed)] landlock_path_beneath_attr
        // (the kernel's layout); `fd` in it stays open across the call.
        let r = unsafe {
            libc::syscall(
                libc::SYS_landlock_add_rule,
                self.fd.as_raw_fd(),
                RULE_PATH_BENEATH,
                &attr as *const PathBeneathAttr,
                0u32,
            )
        };
        if r < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(true)
    }

    /// Allows TCP connect to `port` (no-op without network restriction).
    pub fn allow_connect(&mut self, port: u16) -> io::Result<()> {
        if !self.net {
            return Ok(());
        }
        let attr = NetPortAttr {
            allowed_access: NET_CONNECT_TCP,
            port: u64::from(port),
        };
        // SAFETY: `self.fd` is our open ruleset and `attr` a live #[repr(C)] landlock_net_port_attr;
        // the kernel only reads it during the call.
        let r = unsafe {
            libc::syscall(
                libc::SYS_landlock_add_rule,
                self.fd.as_raw_fd(),
                RULE_NET_PORT,
                &attr as *const NetPortAttr,
                0u32,
            )
        };
        if r < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// The ruleset descriptor for [`restrict_self`] in the child.
    pub fn raw_fd(&self) -> i32 {
        self.fd.as_raw_fd()
    }
}

/// In the child, after `PR_SET_NO_NEW_PRIVS`: one system call, no allocation.
///
/// # Safety
/// `fd` must be a Landlock ruleset descriptor.
pub unsafe fn restrict_self(fd: i32) -> io::Result<()> {
    // SAFETY: the caller guarantees `fd` is a Landlock ruleset; the syscall takes no pointers and
    // last_os_error does not allocate (fine in pre_exec).
    unsafe {
        if libc::syscall(libc::SYS_landlock_restrict_self, fd, 0u32) != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}
