//! Connector side of the mount: ask `nexus-nasmount` for the share (the fd of
//! a detached read-only mount comes back over the socket), or open a local
//! directory as the "share" (tests, no root); then optionally descend into the
//! newest NAS snapshot below a configured snapshot directory.

use crate::fdpass;
use crate::proto::{parse_response, Request};
use crate::sys::{self, CONFINED, RESOLVE_BENEATH, RESOLVE_NO_MAGICLINKS, RESOLVE_NO_SYMLINKS};
use anyhow::{bail, Context, Result};
use std::io::Write;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

/// Sends `req` to the helper; returns the mount fd. `timeout`: how long the
/// helper may take (the mount itself waits for the server).
pub fn mount_share(socket: &Path, req: &Request, timeout: Duration) -> Result<OwnedFd> {
    let mut s =
        UnixStream::connect(socket).with_context(|| format!("connecting to the mount helper {}", socket.display()))?;
    s.set_read_timeout(Some(timeout))?;
    s.set_write_timeout(Some(Duration::from_secs(10)))?;
    s.write_all(&req.encode()?)?;
    let (line, fd) = fdpass::recv_fd(&s, 4096).context("waiting for the mount helper")?;
    parse_response(&line)?;
    let fd = fd.context("mount helper answered ok without a mount fd")?;
    Ok(fd)
}

/// A readable directory fd of the mount root (the mount fd itself is `O_PATH`).
pub fn open_root(mnt: &OwnedFd) -> Result<OwnedFd> {
    sys::openat2(mnt.as_raw_fd(), b".", libc::O_RDONLY | libc::O_DIRECTORY, CONFINED).context("opening the share root")
}

/// A local directory as the share (tests and the dev lab without a helper).
pub fn open_local(path: &Path) -> Result<OwnedFd> {
    let c = sys::cstr(path.as_os_str().as_encoded_bytes())?;
    // SAFETY: plain open of a C string path.
    let fd = unsafe { libc::open(c.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error()).with_context(|| format!("{}", path.display()));
    }
    // SAFETY: fresh fd owned by us.
    Ok(unsafe { std::os::fd::FromRawFd::from_raw_fd(fd) })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Order {
    /// greatest name (time-stamped names: `auto-2026-10-09_0300`)
    Name,
    /// newest mtime of the snapshot directory (NetApp `hourly.0`), name as tie break
    Mtime,
}

impl Order {
    pub fn parse(s: &str) -> Result<Order> {
        match s {
            "name" => Ok(Order::Name),
            "mtime" => Ok(Order::Mtime),
            _ => bail!("snapshot_order: name or mtime"),
        }
    }
}

/// The newest snapshot below `<root>/<dir>` whose name starts with `prefix`:
/// (name, readable dir fd of it). None if the directory has no such snapshot.
/// The snapshot directory and the snapshot itself may be other (automounted)
/// file systems, so these two steps may cross mounts; the scan below the
/// snapshot never does.
pub fn newest_snapshot(root: &OwnedFd, dir: &str, prefix: &str, order: Order) -> Result<Option<(String, OwnedFd)>> {
    if !crate::valid_rel_dir(dir) {
        bail!("invalid snapshot directory {dir:?}");
    }
    let follow = RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS;
    let d = sys::openat2(
        root.as_raw_fd(),
        dir.as_bytes(),
        libc::O_RDONLY | libc::O_DIRECTORY,
        follow,
    )
    .with_context(|| format!("snapshot directory {dir}"))?;
    let mut best: Option<(i64, Vec<u8>)> = None;
    for name in sys::read_dir(&d)? {
        if !name.starts_with(prefix.as_bytes()) || std::str::from_utf8(&name).is_err() {
            continue;
        }
        let st = match sys::statx_at(d.as_raw_fd(), &sys::cstr(&name)?) {
            Ok(s) => s,
            Err(_) => continue,
        };
        if st.kind != sys::Kind::Dir {
            continue;
        }
        let key = match order {
            Order::Name => 0,
            Order::Mtime => st.mtime_ns,
        };
        if best.as_ref().is_none_or(|(k, n)| (key, &name) > (*k, n)) {
            best = Some((key, name));
        }
    }
    let Some((_, name)) = best else {
        return Ok(None);
    };
    let fd = sys::openat2(d.as_raw_fd(), &name, libc::O_RDONLY | libc::O_DIRECTORY, follow)
        .with_context(|| format!("opening snapshot {}", String::from_utf8_lossy(&name)))?;
    Ok(Some((String::from_utf8(name).expect("checked"), fd)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn picks_the_newest_snapshot() {
        let d = tempfile::tempdir().unwrap();
        let s = d.path().join(".zfs/snapshot");
        for (n, t) in [
            ("auto-2026-10-08", 300),
            ("auto-2026-10-09", 100),
            ("manual", 900),
            ("auto-2026-10-07", 200),
        ] {
            fs::create_dir_all(s.join(n)).unwrap();
            fs::write(s.join(n).join("f"), n).unwrap();
            let tv = [
                libc::timespec { tv_sec: t, tv_nsec: 0 },
                libc::timespec { tv_sec: t, tv_nsec: 0 },
            ];
            let c = sys::cstr(s.join(n).as_os_str().as_encoded_bytes()).unwrap();
            assert_eq!(
                unsafe { libc::utimensat(libc::AT_FDCWD, c.as_ptr(), tv.as_ptr(), 0) },
                0
            );
        }
        fs::write(s.join("auto-zzz-file"), "not a dir").unwrap();
        let root = open_local(d.path()).unwrap();
        let (n, _) = newest_snapshot(&root, ".zfs/snapshot", "auto-", Order::Name)
            .unwrap()
            .unwrap();
        assert_eq!(n, "auto-2026-10-09");
        let (n, fd) = newest_snapshot(&root, ".zfs/snapshot", "auto-", Order::Mtime)
            .unwrap()
            .unwrap();
        assert_eq!(n, "auto-2026-10-08");
        assert!(sys::read_dir(&fd).unwrap().contains(&b"f".to_vec()));
        let (n, _) = newest_snapshot(&root, ".zfs/snapshot", "", Order::Mtime)
            .unwrap()
            .unwrap();
        assert_eq!(n, "manual");
        assert!(newest_snapshot(&root, ".zfs/snapshot", "hourly.", Order::Name)
            .unwrap()
            .is_none());
        assert!(newest_snapshot(&root, "../x", "", Order::Name).is_err());
        // a symlinked snapshot dir is not followed
        std::os::unix::fs::symlink(&s, d.path().join("snaplink")).unwrap();
        assert!(newest_snapshot(&root, "snaplink", "", Order::Name).is_err());
    }
}
