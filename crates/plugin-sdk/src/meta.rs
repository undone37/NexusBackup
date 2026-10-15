//! Local file metadata → protocol [`Meta`] (lstat + extended attributes).

use plugin_proto::{Kind, Meta, MAX_XATTR};
use std::ffi::CString;
use std::fs;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::Path;

/// Entry kind of local metadata (from `symlink_metadata`). Never [`Kind::Hardlink`]:
/// hard links are detected by [`crate::Sink::walk_dir`] from the inode.
pub fn kind_of(m: &fs::Metadata) -> Kind {
    let t = m.file_type();
    if t.is_dir() {
        Kind::Dir
    } else if t.is_symlink() {
        Kind::Symlink
    } else if t.is_fifo() {
        Kind::Fifo
    } else if t.is_socket() {
        Kind::Socket
    } else if t.is_block_device() || t.is_char_device() {
        Kind::Device
    } else {
        Kind::File
    }
}

/// Extended attributes of `p` (not following symlinks), bounded by the protocol limit.
pub fn xattrs(p: &Path) -> io::Result<Vec<(Vec<u8>, Vec<u8>)>> {
    let c = CString::new(p.as_os_str().as_bytes())?;
    // SAFETY: `c` is a NUL-terminated CString alive across the call; a NULL buffer with size 0 only queries
    // the needed length.
    let n = unsafe { libc::llistxattr(c.as_ptr(), std::ptr::null_mut(), 0) };
    if n < 0 {
        let e = io::Error::last_os_error();
        return match e.raw_os_error() {
            Some(libc::ENOTSUP) => Ok(Vec::new()),
            _ => Err(e),
        };
    }
    let mut names = vec![0u8; n as usize];
    // SAFETY: `names` is a writable buffer of exactly `names.len()` bytes and `c` a live C string.
    let n = unsafe { libc::llistxattr(c.as_ptr(), names.as_mut_ptr().cast(), names.len()) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    names.truncate(n as usize);
    let mut out = Vec::new();
    let mut total = 0;
    for name in names.split(|b| *b == 0).filter(|n| !n.is_empty()) {
        let cn = CString::new(name)?;
        // SAFETY: `c` and `cn` are NUL-terminated CStrings alive across the call; a NULL buffer with size 0 only
        // queries the value length.
        let len = unsafe { libc::lgetxattr(c.as_ptr(), cn.as_ptr(), std::ptr::null_mut(), 0) };
        if len < 0 {
            continue;
        }
        let mut v = vec![0u8; len as usize];
        // SAFETY: `v` is a writable buffer of exactly `v.len()` bytes; `c` and `cn` are live C strings.
        let len = unsafe { libc::lgetxattr(c.as_ptr(), cn.as_ptr(), v.as_mut_ptr().cast(), v.len()) };
        if len < 0 {
            continue;
        }
        v.truncate(len as usize);
        total += name.len() + v.len();
        if total > MAX_XATTR {
            break;
        }
        out.push((name.to_vec(), v));
    }
    Ok(out)
}

/// Metadata of `p` (lstat); `with_xattrs` reads extended attributes too.
pub fn meta_of(p: &Path, m: &fs::Metadata, with_xattrs: bool) -> io::Result<Meta> {
    let kind = kind_of(m);
    Ok(Meta {
        kind: Some(kind),
        mode: m.mode(),
        uid: m.uid(),
        gid: m.gid(),
        size: if kind == Kind::File { m.size() } else { 0 },
        mtime_ns: m.mtime() * 1_000_000_000 + m.mtime_nsec(),
        ctime_ns: m.ctime() * 1_000_000_000 + m.ctime_nsec(),
        inode: m.ino(),
        link_target: if kind == Kind::Symlink {
            Some(fs::read_link(p)?.as_os_str().as_bytes().to_vec())
        } else {
            None
        },
        xattrs: if with_xattrs { xattrs(p)? } else { Vec::new() },
    })
}
