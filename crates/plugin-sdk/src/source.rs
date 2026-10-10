//! Restore side: receiving snapshot content from the host, writing it safely to a
//! local directory, and the mount op.

use crate::{Result, Shared};
use anyhow::{anyhow, bail};
use plugin_proto::{Kind, Message, Meta};
use std::ffi::CString;
use std::io::{self, Read};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::Path;

/// One file of the snapshot as the host sends it.
#[derive(Debug, Clone)]
pub struct FileItem {
    pub path: Vec<u8>,
    pub meta: Meta,
}

pub struct Source {
    chan: Shared,
}

/// Reader over the `Data` frames of the current item (until FileEnd / StreamEnd).
struct DataReader<'a> {
    chan: &'a Shared,
    buf: Vec<u8>,
    pos: usize,
    end: bool,
}

impl Read for DataReader<'_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        while self.pos == self.buf.len() {
            if self.end {
                return Ok(0);
            }
            match self.chan.borrow_mut().recv()? {
                Message::Data { bytes } => {
                    self.buf = bytes;
                    self.pos = 0;
                }
                Message::FileEnd | Message::StreamEnd => self.end = true,
                m => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("unexpected host message {m:?}"),
                    ))
                }
            }
        }
        let n = out.len().min(self.buf.len() - self.pos);
        out[..n].copy_from_slice(&self.buf[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

impl Source {
    pub(crate) fn new(chan: Shared) -> Source {
        Source { chan }
    }

    fn items(
        &mut self,
        req: Message,
        f: &mut dyn FnMut(Option<&FileItem>, Option<&str>, &mut dyn Read) -> Result<()>,
    ) -> Result<()> {
        self.chan
            .borrow_mut()
            .send(&req)
            .map_err(|e| anyhow!("host connection: {e}"))?;
        loop {
            let m = self.chan.borrow_mut().recv()?;
            let mut r = DataReader {
                chan: &self.chan,
                buf: Vec::new(),
                pos: 0,
                end: false,
            };
            match m {
                Message::FileBegin { path, meta } => {
                    let item = FileItem { path, meta };
                    f(Some(&item), None, &mut r)?;
                }
                Message::Stream { name } => f(None, Some(&name), &mut r)?,
                Message::NeedDone => return Ok(()),
                m => bail!("unexpected host message {m:?}"),
            }
            // whatever the callback did not read
            io::copy(&mut r, &mut io::sink())?;
        }
    }

    /// Files at or below `paths` (relative), in snapshot order. Paths not in the snapshot are skipped.
    pub fn files(
        &mut self,
        paths: &[Vec<u8>],
        mut f: impl FnMut(&FileItem, &mut dyn Read) -> Result<()>,
    ) -> Result<()> {
        self.items(Message::NeedFiles { paths: paths.to_vec() }, &mut |i, _, r| {
            f(i.expect("file item"), r)
        })
    }

    /// Application streams by name (missing names are skipped).
    pub fn streams(&mut self, names: &[String], mut f: impl FnMut(&str, &mut dyn Read) -> Result<()>) -> Result<()> {
        self.items(Message::NeedStreams { names: names.to_vec() }, &mut |_, n, r| {
            f(n.expect("stream"), r)
        })
    }

    pub fn progress(&mut self, done: u64, total: u64, text: &str) {
        let _ = self.chan.borrow_mut().send(&Message::Progress {
            done,
            total,
            text: text.into(),
        });
    }

    /// Writes the files at/below `paths` into `target` with their metadata: no symlink
    /// in the target is ever followed (component-wise `openat` with `O_NOFOLLOW`),
    /// files are created exclusively (existing ones are replaced only with `overwrite`).
    pub fn restore_tree(&mut self, paths: &[Vec<u8>], target: &Path, opts: &RestoreOptions) -> Result<RestoreStats> {
        let root = open_dir(target)?;
        let mut st = RestoreStats::default();
        let mut dirs: Vec<(Vec<u8>, Meta)> = Vec::new();
        self.files(paths, |item, data| {
            if !plugin_proto::valid_path(&item.path) {
                bail!("invalid path from the host");
            }
            match write_item(&root, item, data, opts) {
                Ok(()) => {
                    match item.meta.kind.unwrap_or(Kind::File) {
                        Kind::File => {
                            st.files += 1;
                            st.bytes += item.meta.size;
                        }
                        Kind::Dir => {
                            st.dirs += 1;
                            dirs.push((item.path.clone(), item.meta.clone()));
                        }
                        _ => st.other += 1,
                    }
                    Ok(())
                }
                Err(e) => {
                    st.errors += 1;
                    if st.errors <= 20 {
                        st.messages
                            .push(format!("{}: {e:#}", String::from_utf8_lossy(&item.path)));
                    }
                    Ok(())
                }
            }
        })?;
        // directory times last (writing children changed them)
        for (p, m) in dirs.iter().rev() {
            if let Ok((parent, name)) = open_parent(&root, p, false) {
                let c = CString::new(name)?;
                let fd = unsafe {
                    libc::openat(
                        parent.as_raw_fd(),
                        c.as_ptr(),
                        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                    )
                };
                if fd >= 0 {
                    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
                    apply_meta(&fd, m, opts);
                }
            }
        }
        Ok(st)
    }
}

#[derive(Debug, Clone, Default)]
pub struct RestoreOptions {
    /// replace existing files (else they are left alone and counted as errors)
    pub overwrite: bool,
    /// set owner/group (needs privileges; failures are ignored)
    pub owners: bool,
    pub xattrs: bool,
}

#[derive(Debug, Clone, Default)]
pub struct RestoreStats {
    pub files: u64,
    pub dirs: u64,
    pub other: u64,
    pub bytes: u64,
    pub errors: u64,
    pub messages: Vec<String>,
}

fn last_err() -> anyhow::Error {
    io::Error::last_os_error().into()
}

fn open_dir(p: &Path) -> Result<OwnedFd> {
    use std::os::unix::ffi::OsStrExt;
    let c = CString::new(p.as_os_str().as_bytes())?;
    let fd = unsafe { libc::open(c.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(anyhow!("{}: {}", p.display(), io::Error::last_os_error()));
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// The directory containing `path` (created as needed, never through symlinks) and the last component.
fn open_parent<'a>(root: &OwnedFd, path: &'a [u8], create: bool) -> Result<(OwnedFd, &'a [u8])> {
    let comps: Vec<&[u8]> = path.split(|b| *b == b'/').collect();
    let (last, dirs) = comps.split_last().ok_or_else(|| anyhow!("empty path"))?;
    let mut cur = unsafe { OwnedFd::from_raw_fd(libc::dup(root.as_raw_fd())) };
    for d in dirs {
        let c = CString::new(*d)?;
        if create {
            unsafe { libc::mkdirat(cur.as_raw_fd(), c.as_ptr(), 0o700) };
        }
        let fd = unsafe {
            libc::openat(
                cur.as_raw_fd(),
                c.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(last_err());
        }
        cur = unsafe { OwnedFd::from_raw_fd(fd) };
    }
    Ok((cur, last))
}

fn apply_meta(fd: &OwnedFd, m: &Meta, opts: &RestoreOptions) {
    unsafe {
        if opts.owners {
            libc::fchown(fd.as_raw_fd(), m.uid, m.gid);
        }
        libc::fchmod(fd.as_raw_fd(), m.mode & 0o7777);
        if opts.xattrs {
            for (k, v) in &m.xattrs {
                if let Ok(k) = CString::new(k.clone()) {
                    libc::fsetxattr(fd.as_raw_fd(), k.as_ptr(), v.as_ptr().cast(), v.len(), 0);
                }
            }
        }
        let t = libc::timespec {
            tv_sec: m.mtime_ns.div_euclid(1_000_000_000),
            tv_nsec: m.mtime_ns.rem_euclid(1_000_000_000),
        };
        libc::futimens(fd.as_raw_fd(), [t, t].as_ptr());
    }
}

fn write_item(root: &OwnedFd, item: &FileItem, data: &mut dyn Read, opts: &RestoreOptions) -> Result<()> {
    let (parent, name) = open_parent(root, &item.path, true)?;
    let c = CString::new(name)?;
    let pfd = parent.as_raw_fd();
    let m = &item.meta;
    match m.kind.unwrap_or(Kind::File) {
        Kind::File => {
            if opts.overwrite {
                unsafe { libc::unlinkat(pfd, c.as_ptr(), 0) };
            }
            let fd = unsafe {
                libc::openat(
                    pfd,
                    c.as_ptr(),
                    libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                    0o600,
                )
            };
            if fd < 0 {
                return Err(last_err());
            }
            let fd = unsafe { OwnedFd::from_raw_fd(fd) };
            let mut f = std::fs::File::from(fd.try_clone()?);
            io::copy(data, &mut f)?;
            f.sync_all()?;
            apply_meta(&fd, m, opts);
        }
        Kind::Dir => {
            if unsafe { libc::mkdirat(pfd, c.as_ptr(), 0o700) } != 0
                && io::Error::last_os_error().kind() != io::ErrorKind::AlreadyExists
            {
                return Err(last_err());
            }
        }
        Kind::Symlink => {
            let t = CString::new(m.link_target.clone().unwrap_or_default())?;
            if opts.overwrite {
                unsafe { libc::unlinkat(pfd, c.as_ptr(), 0) };
            }
            if unsafe { libc::symlinkat(t.as_ptr(), pfd, c.as_ptr()) } != 0 {
                return Err(last_err());
            }
            let ts = libc::timespec {
                tv_sec: m.mtime_ns.div_euclid(1_000_000_000),
                tv_nsec: m.mtime_ns.rem_euclid(1_000_000_000),
            };
            unsafe { libc::utimensat(pfd, c.as_ptr(), [ts, ts].as_ptr(), libc::AT_SYMLINK_NOFOLLOW) };
        }
        Kind::Hardlink => {
            let target = m.link_target.clone().unwrap_or_default();
            if !plugin_proto::valid_path(&target) {
                bail!("invalid hard link target");
            }
            let (tp, tn) = open_parent(root, &target, false)?;
            let tc = CString::new(tn)?;
            if opts.overwrite {
                unsafe { libc::unlinkat(pfd, c.as_ptr(), 0) };
            }
            if unsafe { libc::linkat(tp.as_raw_fd(), tc.as_ptr(), pfd, c.as_ptr(), 0) } != 0 {
                return Err(last_err());
            }
        }
        Kind::Fifo => {
            if unsafe { libc::mkfifoat(pfd, c.as_ptr(), m.mode & 0o7777) } != 0 {
                return Err(last_err());
            }
        }
        Kind::Device | Kind::Socket => bail!("devices and sockets are not restored"),
    }
    Ok(())
}

/// Mount op: announce readiness, read snapshot files on demand, wait for `Unmount`.
pub struct Mount {
    chan: Shared,
    unmounted: bool,
}

impl Mount {
    pub(crate) fn new(chan: Shared) -> Mount {
        Mount { chan, unmounted: false }
    }

    pub fn ready(&mut self, info: &str) -> Result<()> {
        self.chan
            .borrow_mut()
            .send(&Message::MountReady { info: info.into() })
            .map_err(|e| anyhow!("host connection: {e}"))
    }

    /// `len` bytes at `offset` of a snapshot file; None if there is no such file,
    /// Err after the host sent `Unmount` (check [`Mount::unmounted`]).
    pub fn read_file(&mut self, path: &[u8], offset: u64, len: u32) -> Result<Option<Vec<u8>>> {
        if self.unmounted {
            bail!("unmounted");
        }
        self.chan.borrow_mut().send(&Message::ReadFile {
            path: path.to_vec(),
            offset,
            len: len.min(plugin_proto::MAX_DATA as u32),
        })?;
        loop {
            match self.chan.borrow_mut().recv()? {
                Message::FileData { bytes } => return Ok(Some(bytes)),
                Message::Error { .. } => return Ok(None),
                Message::Unmount => {
                    self.unmounted = true;
                    bail!("unmounted");
                }
                m => bail!("unexpected host message {m:?}"),
            }
        }
    }

    pub fn unmounted(&self) -> bool {
        self.unmounted
    }

    /// Blocks until the host ends the mount.
    pub fn wait_unmount(&mut self) -> Result<()> {
        while !self.unmounted {
            if let Message::Unmount = self.chan.borrow_mut().recv()? {
                self.unmounted = true;
            }
        }
        Ok(())
    }
}
