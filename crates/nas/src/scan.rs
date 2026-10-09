//! Parallel scan of a share (or any directory fd) into an `Index::Tree`.
//!
//! **Work items** (shared LIFO queue, a bounded pool of worker threads; idle
//! workers take the next item, so directories are distributed dynamically):
//! - `Dir`: open the directory (relative to the root fd, `openat2` confined:
//!   beneath the root, no symlinks, no mount crossing), read its xattrs, list
//!   and sort its names, then process them — inline for small directories, as
//!   `Batch` items of [`Options::batch`] names for large ones, so a directory
//!   with a million files is read by all workers at once;
//! - `Batch`: `statx` each name (never triggers an automount), files are reused
//!   from the previous snapshot or read and chunked into the store,
//!   subdirectories become new `Dir` items.
//!
//! **Determinism**: names are sorted per directory and every batch has a fixed
//! slot, so the assembled tree (pre-order, parents before children) is the
//! same for any number of threads.
//!
//! **Metadata cache**: a file reuses the previous snapshot's keyed chunk IDs
//! (and xattrs) if its path or inode matches a previous regular file with the
//! same inode, size, mtime and ctime, that file was consistent, and all its
//! chunks are still in the store. ctime is part of the key: it changes on every
//! content, xattr/ACL or owner change and cannot be set by users (mtime can).
//! Directories reuse their xattrs under the same rule (inode + ctime).
//!
//! **Change during read**: a read file's attributes are fetched again from the
//! server after the read (`AT_STATX_FORCE_SYNC`); size/mtime/ctime changes or a
//! short read mark it `inconsistent`.
//!
//! **Hard links**: the first name (tree order) is the file, later names are
//! `Hardlink` entries (as agent and TrueNAS snapshots); the content is read once.
//!
//! **Not descended**: nested mounts, automount points (nested exports,
//! snapshot directories), excluded names. Symlinks are recorded, never followed.

use crate::sys::{self, Kind, Stat, CONFINED};
use agent_core::glob::Excludes;
use anyhow::{anyhow, Result};
use chunkstore::{ChunkId, Store, TreeEntry, TreeKind};
use std::collections::{HashMap, HashSet};
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

const MAX_ERRORS: usize = 1000;

/// (name, value) pairs as in `TreeEntry::xattrs`.
pub type Xattrs = Vec<(Vec<u8>, Vec<u8>)>;
/// Test hook: called with the path of a file after it was opened, before it is read.
pub type ReadHook = Box<dyn Fn(&[u8]) + Send + Sync>;

pub struct Options {
    pub threads: usize,
    /// read xattrs (ACLs) of files and directories
    pub xattrs: bool,
    /// xattr names the file system does not list (`system.nfs4_acl`, `system.cifs_acl`, …)
    pub extra_xattrs: Vec<&'static str>,
    pub excludes: Excludes,
    /// names per work item in large directories
    pub batch: usize,
    /// tests: called with the path after a file was opened, before it is read
    #[doc(hidden)]
    pub before_read: Option<ReadHook>,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            threads: 16,
            xattrs: true,
            extra_xattrs: Vec::new(),
            excludes: Excludes::new(&[]),
            batch: 256,
            before_read: None,
        }
    }
}

/// The previous snapshot of the share, indexed for reuse.
pub struct Prev<'a> {
    by_path: HashMap<&'a [u8], &'a TreeEntry>,
    by_ino: HashMap<u64, &'a TreeEntry>,
}

impl<'a> Prev<'a> {
    pub fn new(entries: &'a [TreeEntry]) -> Prev<'a> {
        let mut p = Prev {
            by_path: HashMap::with_capacity(entries.len()),
            by_ino: HashMap::new(),
        };
        for e in entries {
            p.by_path.insert(&e.path, e);
            if e.kind == TreeKind::File {
                p.by_ino.insert(e.inode, e);
            }
        }
        p
    }
}

#[derive(Default, Debug)]
pub struct Stats {
    pub entries: AtomicU64,
    pub files: AtomicU64,
    pub dirs: AtomicU64,
    pub files_read: AtomicU64,
    pub bytes_read: AtomicU64,
    pub reused_files: AtomicU64,
    pub reused_bytes: AtomicU64,
    pub new_chunks: AtomicU64,
    pub new_bytes: AtomicU64,
    pub inconsistent: AtomicU64,
    /// entries that vanished between listing and reading (normal churn)
    pub vanished: AtomicU64,
    /// nested mounts / automount points not descended into
    pub skipped_mounts: AtomicU64,
}

#[derive(Debug, Default, Clone)]
pub struct Report {
    pub entries: u64,
    pub files: u64,
    pub dirs: u64,
    pub files_read: u64,
    pub bytes_read: u64,
    pub reused_files: u64,
    pub reused_bytes: u64,
    pub new_chunks: u64,
    pub new_bytes: u64,
    pub inconsistent: u64,
    pub vanished: u64,
    pub skipped_mounts: u64,
    /// entries that could not be read (omitted from the tree)
    pub errors: Vec<String>,
    pub error_count: u64,
    pub secs: f64,
}

struct Ent {
    e: TreeEntry,
    nlink: u32,
    /// regular file whose chunks are known (read or reused)
    content: bool,
}

#[derive(Default)]
struct DirResult {
    batches: Vec<Option<Vec<Ent>>>,
    xattrs: Vec<(Vec<u8>, Vec<u8>)>,
}

enum Work {
    Dir {
        path: Arc<[u8]>,
        st: Stat,
    },
    Batch {
        dir: Arc<[u8]>,
        idx: usize,
        names: Vec<Vec<u8>>,
    },
}

struct Queue {
    items: Vec<Work>,
    active: usize,
}

struct Scan<'a> {
    store: &'a Store,
    root: RawFd,
    root_st: Stat,
    opts: &'a Options,
    prev: Option<&'a Prev<'a>>,
    q: Mutex<Queue>,
    cv: Condvar,
    results: Mutex<HashMap<Arc<[u8]>, DirResult>>,
    claimed: Mutex<HashSet<u64>>,
    stats: Stats,
    errors: Mutex<(Vec<String>, u64)>,
    abort: AtomicBool,
    fatal: Mutex<Option<anyhow::Error>>,
}

fn join(dir: &[u8], name: &[u8]) -> Vec<u8> {
    if dir.is_empty() {
        name.to_vec()
    } else {
        let mut p = Vec::with_capacity(dir.len() + 1 + name.len());
        p.extend_from_slice(dir);
        p.push(b'/');
        p.extend_from_slice(name);
        p
    }
}

fn lossy(p: &[u8]) -> String {
    String::from_utf8_lossy(p).escape_debug().to_string()
}

fn tree_kind(k: Kind) -> TreeKind {
    match k {
        Kind::File => TreeKind::File,
        Kind::Dir => TreeKind::Dir,
        Kind::Symlink => TreeKind::Symlink,
        Kind::Fifo => TreeKind::Fifo,
        Kind::Socket => TreeKind::Socket,
        Kind::Device => TreeKind::Device,
    }
}

fn entry(path: Vec<u8>, st: &Stat) -> TreeEntry {
    TreeEntry {
        path,
        kind: tree_kind(st.kind),
        mode: st.mode & 0o7777,
        uid: st.uid,
        gid: st.gid,
        size: if st.kind == Kind::File { st.size } else { 0 },
        mtime_ns: st.mtime_ns,
        ctime_ns: st.ctime_ns,
        inode: st.ino,
        rdev: if st.kind == Kind::Device { st.rdev } else { 0 },
        link_target: None,
        xattrs: Vec::new(),
        chunks: Vec::new(),
        inconsistent: false,
    }
}

impl Scan<'_> {
    fn error(&self, msg: String) {
        let mut e = self.errors.lock().unwrap();
        e.1 += 1;
        if e.0.len() < MAX_ERRORS {
            e.0.push(msg);
        }
    }

    fn fail(&self, e: anyhow::Error) {
        let mut f = self.fatal.lock().unwrap();
        if f.is_none() {
            *f = Some(e);
        }
        self.abort.store(true, Relaxed);
        self.cv.notify_all();
    }

    fn push(&self, items: Vec<Work>) {
        if items.is_empty() {
            return;
        }
        let mut q = self.q.lock().unwrap();
        q.items.extend(items);
        drop(q);
        self.cv.notify_all();
    }

    fn worker(&self, xbuf: &mut Vec<u8>) {
        loop {
            let w = {
                let mut q = self.q.lock().unwrap();
                loop {
                    if self.abort.load(Relaxed) {
                        return;
                    }
                    if let Some(w) = q.items.pop() {
                        q.active += 1;
                        break w;
                    }
                    if q.active == 0 {
                        self.cv.notify_all();
                        return;
                    }
                    q = self.cv.wait(q).unwrap();
                }
            };
            match w {
                Work::Dir { path, st } => self.dir(path, st, xbuf),
                Work::Batch { dir, idx, names } => match self.open_dir(&dir) {
                    Ok(fd) => self.batch(&dir, fd.as_raw_fd(), idx, names, xbuf),
                    Err(e) => {
                        self.error(format!("{}: open: {e}", lossy(&dir)));
                        self.store_batch(&dir, idx, Vec::new());
                    }
                },
            }
            let mut q = self.q.lock().unwrap();
            q.active -= 1;
            if q.active == 0 && q.items.is_empty() {
                self.cv.notify_all();
            }
        }
    }

    fn open_dir(&self, path: &[u8]) -> std::io::Result<OwnedFd> {
        let p: &[u8] = if path.is_empty() { b"." } else { path };
        sys::openat2(self.root, p, libc::O_RDONLY | libc::O_DIRECTORY, CONFINED)
    }

    fn store_batch(&self, dir: &Arc<[u8]>, idx: usize, ents: Vec<Ent>) {
        let mut r = self.results.lock().unwrap();
        if let Some(d) = r.get_mut(dir) {
            d.batches[idx] = Some(ents);
        }
    }

    fn dir(&self, path: Arc<[u8]>, st: Stat, xbuf: &mut Vec<u8>) {
        let fd = match self.open_dir(&path) {
            Ok(f) => f,
            Err(e) if e.raw_os_error() == Some(libc::ENOENT) => {
                self.stats.vanished.fetch_add(1, Relaxed);
                return;
            }
            Err(e) => {
                self.error(format!("{}: open: {e}", lossy(&path)));
                return;
            }
        };
        // the directory must still be the one that was listed (no swap in between)
        match sys::fstatx(fd.as_raw_fd(), false) {
            Ok(now) if now.ino == st.ino && now.dev == self.root_st.dev => {}
            Ok(_) => {
                self.error(format!("{}: replaced during the scan", lossy(&path)));
                return;
            }
            Err(e) => {
                self.error(format!("{}: stat: {e}", lossy(&path)));
                return;
            }
        }
        let mut xattrs = Vec::new();
        if self.opts.xattrs && !path.is_empty() {
            let reuse = self
                .prev
                .and_then(|p| p.by_path.get(&path[..]))
                .filter(|o| o.kind == TreeKind::Dir && o.inode == st.ino && o.ctime_ns == st.ctime_ns);
            match reuse {
                Some(o) => xattrs = o.xattrs.clone(),
                None => match sys::fxattrs(fd.as_raw_fd(), &self.opts.extra_xattrs, xbuf) {
                    Ok(x) => xattrs = x,
                    Err(e) => self.error(format!("{}: xattrs: {e}", lossy(&path))),
                },
            }
        }
        let mut names = match sys::read_dir(&fd) {
            Ok(n) => n,
            Err(e) => {
                self.error(format!("{}: list: {e}", lossy(&path)));
                Vec::new()
            }
        };
        names.retain(|n| {
            let mut abs = Vec::with_capacity(path.len() + n.len() + 2);
            abs.push(b'/');
            abs.extend_from_slice(&join(&path, n));
            !self.opts.excludes.matches(&abs)
        });
        let nb = names.len().div_ceil(self.opts.batch.max(1));
        self.results.lock().unwrap().insert(
            path.clone(),
            DirResult {
                batches: (0..nb).map(|_| None).collect(),
                xattrs,
            },
        );
        if nb == 1 {
            self.batch(&path, fd.as_raw_fd(), 0, names, xbuf);
        } else if nb > 1 {
            drop(fd);
            let mut items = Vec::with_capacity(nb);
            let mut rest = names;
            let mut chunks = Vec::with_capacity(nb);
            while !rest.is_empty() {
                let tail = rest.split_off(rest.len().min(self.opts.batch));
                chunks.push(std::mem::replace(&mut rest, tail));
            }
            // LIFO queue: push the last batch first so batch 0 is taken next
            for (idx, names) in chunks.into_iter().enumerate().rev() {
                items.push(Work::Batch {
                    dir: path.clone(),
                    idx,
                    names,
                });
            }
            self.push(items);
        }
    }

    fn batch(&self, dir: &Arc<[u8]>, dirfd: RawFd, idx: usize, names: Vec<Vec<u8>>, xbuf: &mut Vec<u8>) {
        let mut out = Vec::with_capacity(names.len());
        let mut sub = Vec::new();
        for name in names {
            if self.abort.load(Relaxed) {
                return;
            }
            let path = join(dir, &name);
            if !crate::valid_rel_path(&path) {
                self.error(format!("{}: path too long or invalid", lossy(&path)));
                continue;
            }
            match self.one(dirfd, &name, path, xbuf) {
                Ok(Some((ent, descend))) => {
                    if let Some(st) = descend {
                        sub.push(Work::Dir {
                            path: Arc::from(ent.e.path.as_slice()),
                            st,
                        });
                    }
                    self.stats.entries.fetch_add(1, Relaxed);
                    out.push(ent);
                }
                Ok(None) => {}
                Err(Fatal(e)) => {
                    self.fail(e);
                    return;
                }
            }
        }
        self.store_batch(dir, idx, out);
        self.push(sub);
    }

    /// One directory entry. Ok(None): vanished or unreadable (error recorded).
    fn one(
        &self,
        dirfd: RawFd,
        name: &[u8],
        path: Vec<u8>,
        xbuf: &mut Vec<u8>,
    ) -> Result<Option<(Ent, Option<Stat>)>, Fatal> {
        let cname = match sys::cstr(name) {
            Ok(c) => c,
            Err(e) => {
                self.error(format!("{}: {e}", lossy(&path)));
                return Ok(None);
            }
        };
        let st = match sys::statx_at(dirfd, &cname) {
            Ok(s) => s,
            Err(e) if e.raw_os_error() == Some(libc::ENOENT) => {
                self.stats.vanished.fetch_add(1, Relaxed);
                return Ok(None);
            }
            Err(e) => {
                self.error(format!("{}: stat: {e}", lossy(&path)));
                return Ok(None);
            }
        };
        let mut e = entry(path, &st);
        match st.kind {
            Kind::Dir => {
                self.stats.dirs.fetch_add(1, Relaxed);
                let same_fs = !st.automount && st.dev == self.root_st.dev && st.mnt_id == self.root_st.mnt_id;
                if !same_fs {
                    self.stats.skipped_mounts.fetch_add(1, Relaxed);
                    self.error_note(format!(
                        "{}: nested mount / automount point, not descended",
                        lossy(&e.path)
                    ));
                }
                let descend = same_fs.then_some(st);
                return Ok(Some((
                    Ent {
                        e,
                        nlink: st.nlink,
                        content: false,
                    },
                    descend,
                )));
            }
            Kind::Symlink => match sys::readlinkat(dirfd, &cname) {
                Ok(t) => e.link_target = Some(t),
                Err(err) if err.raw_os_error() == Some(libc::ENOENT) => {
                    self.stats.vanished.fetch_add(1, Relaxed);
                    return Ok(None);
                }
                Err(err) => {
                    self.error(format!("{}: readlink: {err}", lossy(&e.path)));
                    return Ok(None);
                }
            },
            Kind::File => {
                self.stats.files.fetch_add(1, Relaxed);
                return self.file(dirfd, &cname, e, st, xbuf);
            }
            Kind::Fifo | Kind::Socket | Kind::Device => {}
        }
        Ok(Some((
            Ent {
                e,
                nlink: st.nlink,
                content: false,
            },
            None,
        )))
    }

    /// Notes that are not errors (nested mounts): logged with the errors, not counted.
    fn error_note(&self, msg: String) {
        let mut e = self.errors.lock().unwrap();
        if e.0.len() < MAX_ERRORS {
            e.0.push(format!("note: {msg}"));
        }
    }

    fn reusable(&self, path: &[u8], st: &Stat) -> Option<&TreeEntry> {
        let p = self.prev?;
        let same = |o: &&&TreeEntry| {
            o.kind == TreeKind::File
                && o.inode == st.ino
                && o.size == st.size
                && o.mtime_ns == st.mtime_ns
                && o.ctime_ns == st.ctime_ns
                && !o.inconsistent
        };
        let o = p
            .by_path
            .get(path)
            .filter(same)
            .or_else(|| p.by_ino.get(&st.ino).filter(same))?;
        o.chunks.iter().all(|c: &ChunkId| self.store.has_chunk(c)).then_some(*o)
    }

    fn file(
        &self,
        dirfd: RawFd,
        name: &std::ffi::CStr,
        mut e: TreeEntry,
        st: Stat,
        xbuf: &mut Vec<u8>,
    ) -> Result<Option<(Ent, Option<Stat>)>, Fatal> {
        if let Some(o) = self.reusable(&e.path, &st) {
            e.chunks = o.chunks.clone();
            e.xattrs = o.xattrs.clone();
            self.stats.reused_files.fetch_add(1, Relaxed);
            self.stats.reused_bytes.fetch_add(st.size, Relaxed);
            return Ok(Some((
                Ent {
                    e,
                    nlink: st.nlink,
                    content: true,
                },
                None,
            )));
        }
        if st.nlink > 1 && !self.claimed.lock().unwrap().insert(st.ino) {
            // another name of this inode is (being) read
            return Ok(Some((
                Ent {
                    e,
                    nlink: st.nlink,
                    content: false,
                },
                None,
            )));
        }
        let fd = match sys::openat2(dirfd, name.to_bytes(), libc::O_RDONLY | libc::O_NONBLOCK, CONFINED) {
            Ok(f) => f,
            Err(err) if err.raw_os_error() == Some(libc::ENOENT) => {
                self.stats.vanished.fetch_add(1, Relaxed);
                return Ok(None);
            }
            Err(err) => {
                self.error(format!("{}: open: {err}", lossy(&e.path)));
                return Ok(None);
            }
        };
        let before = match sys::fstatx(fd.as_raw_fd(), false) {
            Ok(b) => b,
            Err(err) => {
                self.error(format!("{}: stat: {err}", lossy(&e.path)));
                return Ok(None);
            }
        };
        if before.kind != Kind::File {
            self.error(format!("{}: replaced by a non-file during the scan", lossy(&e.path)));
            return Ok(None);
        }
        // replaced between listing and open: back up what was opened, flagged
        let mut inconsistent = before.ino != st.ino;
        let nlink = before.nlink;
        e = TreeEntry {
            path: e.path,
            ..entry(Vec::new(), &before)
        };
        if self.opts.xattrs {
            match sys::fxattrs(fd.as_raw_fd(), &self.opts.extra_xattrs, xbuf) {
                Ok(x) => e.xattrs = x,
                Err(err) => self.error_note(format!("{}: xattrs: {err}", lossy(&e.path))),
            }
        }
        if let Some(h) = &self.opts.before_read {
            h(&e.path);
        }
        let mut f = std::fs::File::from(fd);
        let s = match self.store.store_file_stats(&mut f) {
            Ok(s) => s,
            Err(err) => {
                // a read error of the share is per file; a store write error is fatal
                let msg = format!("{}: read: {err}", lossy(&e.path));
                if is_read_error(&err) {
                    self.error(msg);
                    return Ok(None);
                }
                return Err(Fatal(anyhow!("store: {msg}")));
            }
        };
        let after = sys::fstatx(f.as_raw_fd(), true);
        inconsistent |= s.size != before.size
            || after.as_ref().map_or(true, |a| {
                a.size != before.size || a.mtime_ns != before.mtime_ns || a.ctime_ns != before.ctime_ns
            });
        e.size = s.size;
        e.chunks = s.chunks;
        e.inconsistent = inconsistent;
        self.stats.files_read.fetch_add(1, Relaxed);
        self.stats.bytes_read.fetch_add(s.size, Relaxed);
        self.stats.new_chunks.fetch_add(s.new_chunks as u64, Relaxed);
        self.stats.new_bytes.fetch_add(s.new_bytes, Relaxed);
        if inconsistent {
            self.stats.inconsistent.fetch_add(1, Relaxed);
        }
        Ok(Some((
            Ent {
                e,
                nlink,
                content: true,
            },
            None,
        )))
    }
}

struct Fatal(anyhow::Error);

/// Store errors come from the local disk (ENOSPC, EROFS, EDQUOT, EIO on the
/// store); everything else while reading is the share's.
fn is_read_error(e: &std::io::Error) -> bool {
    !matches!(
        e.raw_os_error(),
        Some(libc::ENOSPC) | Some(libc::EDQUOT) | Some(libc::EROFS)
    )
}

/// Scans the directory `root` (a dir fd: the share root or a snapshot in it).
/// `log` gets progress lines every 30 s.
pub fn scan(
    store: &Store,
    root: &OwnedFd,
    opts: &Options,
    prev: Option<&Prev<'_>>,
    log: &(dyn Fn(&str) + Sync),
) -> Result<(Vec<TreeEntry>, Report)> {
    let t0 = Instant::now();
    let root_st = sys::fstatx(root.as_raw_fd(), false)?;
    if root_st.kind != Kind::Dir {
        anyhow::bail!("share root is not a directory");
    }
    let s = Scan {
        store,
        root: root.as_raw_fd(),
        root_st,
        opts,
        prev,
        q: Mutex::new(Queue {
            items: vec![Work::Dir {
                path: Arc::from(&b""[..]),
                st: root_st,
            }],
            active: 0,
        }),
        cv: Condvar::new(),
        results: Mutex::new(HashMap::new()),
        claimed: Mutex::new(HashSet::new()),
        stats: Stats::default(),
        errors: Mutex::new((Vec::new(), 0)),
        abort: AtomicBool::new(false),
        fatal: Mutex::new(None),
    };
    let done = AtomicBool::new(false);
    std::thread::scope(|sc| {
        let workers: Vec<_> = (0..opts.threads.clamp(1, 256))
            .map(|_| {
                sc.spawn(|| {
                    let mut xbuf = Vec::new();
                    s.worker(&mut xbuf)
                })
            })
            .collect();
        sc.spawn(|| {
            let mut last = Instant::now();
            while !done.load(Relaxed) {
                std::thread::sleep(Duration::from_millis(200));
                if last.elapsed() >= Duration::from_secs(30) {
                    last = Instant::now();
                    let st = &s.stats;
                    log(&format!(
                        "scan: {} entries, {} files read ({} bytes), {} reused, {:.0} entries/s",
                        st.entries.load(Relaxed),
                        st.files_read.load(Relaxed),
                        st.bytes_read.load(Relaxed),
                        st.reused_files.load(Relaxed),
                        st.entries.load(Relaxed) as f64 / t0.elapsed().as_secs_f64()
                    ));
                }
            }
        });
        for w in workers {
            if w.join().is_err() {
                s.fail(anyhow!("scan worker panicked"));
            }
        }
        done.store(true, Relaxed);
    });
    if let Some(e) = s.fatal.lock().unwrap().take() {
        return Err(e);
    }
    let results = s.results.into_inner().unwrap();
    let entries = assemble(results);
    let st = s.stats;
    let (errors, error_count) = s.errors.into_inner().unwrap();
    let r = Report {
        entries: entries.len() as u64,
        files: st.files.into_inner(),
        dirs: st.dirs.into_inner(),
        files_read: st.files_read.into_inner(),
        bytes_read: st.bytes_read.into_inner(),
        reused_files: st.reused_files.into_inner(),
        reused_bytes: st.reused_bytes.into_inner(),
        new_chunks: st.new_chunks.into_inner(),
        new_bytes: st.new_bytes.into_inner(),
        inconsistent: st.inconsistent.into_inner(),
        vanished: st.vanished.into_inner(),
        skipped_mounts: st.skipped_mounts.into_inner(),
        errors,
        error_count,
        secs: t0.elapsed().as_secs_f64(),
    };
    Ok((entries, r))
}

/// Pre-order tree from the per-directory results; hard links resolved.
fn assemble(mut results: HashMap<Arc<[u8]>, DirResult>) -> Vec<TreeEntry> {
    // content of multiply linked inodes (read by whichever name claimed it, or reused)
    let mut linked: HashMap<u64, &TreeEntry> = HashMap::new();
    for d in results.values() {
        for b in d.batches.iter().flatten() {
            for x in b {
                if x.nlink > 1 && x.content && x.e.kind == TreeKind::File {
                    linked.entry(x.e.inode).or_insert(&x.e);
                }
            }
        }
    }
    let linked: HashMap<u64, TreeEntry> = linked.into_iter().map(|(k, e)| (k, e.clone())).collect();
    let take = |results: &mut HashMap<Arc<[u8]>, DirResult>, path: &[u8]| -> Option<std::vec::IntoIter<Ent>> {
        let d = results.remove(path)?;
        Some(
            d.batches
                .into_iter()
                .flatten()
                .flatten()
                .collect::<Vec<_>>()
                .into_iter(),
        )
    };
    let mut out: Vec<TreeEntry> = Vec::new();
    let mut first_name: HashMap<u64, Vec<u8>> = HashMap::new();
    let mut dir_xattrs: HashMap<Arc<[u8]>, Xattrs> = results
        .iter_mut()
        .map(|(k, v)| (k.clone(), std::mem::take(&mut v.xattrs)))
        .collect();
    let mut stack: Vec<std::vec::IntoIter<Ent>> = Vec::new();
    if let Some(it) = take(&mut results, b"") {
        stack.push(it);
    }
    while let Some(top) = stack.last_mut() {
        let Some(mut x) = top.next() else {
            stack.pop();
            continue;
        };
        match x.e.kind {
            TreeKind::Dir => {
                if let Some(xa) = dir_xattrs.remove(&x.e.path[..]) {
                    x.e.xattrs = xa;
                }
                let path = x.e.path.clone();
                out.push(x.e);
                if let Some(it) = take(&mut results, &path) {
                    stack.push(it);
                }
            }
            TreeKind::File if x.nlink > 1 => {
                if let Some(first) = first_name.get(&x.e.inode) {
                    x.e.kind = TreeKind::Hardlink;
                    x.e.link_target = Some(first.clone());
                    x.e.size = 0;
                    x.e.chunks = Vec::new();
                    x.e.xattrs = Vec::new();
                    out.push(x.e);
                } else if let Some(l) = linked.get(&x.e.inode) {
                    if !x.content {
                        x.e.chunks = l.chunks.clone();
                        x.e.xattrs = l.xattrs.clone();
                        x.e.inconsistent = l.inconsistent;
                        x.e.size = l.size;
                    }
                    first_name.insert(x.e.inode, x.e.path.clone());
                    out.push(x.e);
                }
                // else: no name of this inode could be read (error recorded): omitted
            }
            _ => out.push(x.e),
        }
    }
    out
}

impl Report {
    pub fn files_per_sec(&self) -> f64 {
        if self.secs > 0.0 {
            self.entries as f64 / self.secs
        } else {
            0.0
        }
    }
}
