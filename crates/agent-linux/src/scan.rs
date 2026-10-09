//! Walk prepared roots, emit `Entry`s, chunk changed files (FastCDC + plain BLAKE3).
//!
//! Chunk data is not kept in memory: the [`Locator`] remembers where each chunk can be
//! read again (file + offset; in fallback mode a bounded spool file holds exactly the
//! bytes that were hashed). `Want` re-reads and verifies `blake3(data) == hash` before
//! sending. Memory per chunk ≈ 40 bytes (8-byte hash prefix key + location).

use crate::cache::{Cache, Cached};
use crate::glob::Excludes;
use crate::snapshot::BTRFS_DIR;
use crate::sys;
use agent_proto::{Entry, Hash, Kind, ScanStats, CDC_AVG, CDC_MAX, CDC_MIN, MAX_PATH, MAX_XATTR};
use std::collections::{HashMap, HashSet};
use std::fs::{self, File, Metadata};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileExt, FileTypeExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

const MAX_ERRORS: usize = 1000;
type ChunkList = Vec<(Hash, u32)>;
/// candidate locations kept per chunk hash (identical files share chunks)
const MAX_LOCS: usize = 4;

#[derive(Clone, Debug)]
pub struct Root {
    /// absolute host path (what the entry paths are named after)
    pub host: PathBuf,
    /// where it is read: inside the snapshot, or the live path in fallback mode
    pub src: PathBuf,
    /// fallback mode (no snapshot): detect changes during read, spool chunk data
    pub live: bool,
}

#[derive(Clone, Copy, Debug)]
struct Loc {
    file: u32,
    offset: u64,
    len: u32,
    spooled: Option<u64>,
}

struct Spool {
    f: File,
    used: u64,
    max: u64,
}

/// Where to find each chunk again for `Want`.
#[derive(Default)]
pub struct Locator {
    files: Vec<PathBuf>,
    map: HashMap<u64, Vec<(Hash, Loc)>>,
    spool: Option<Spool>,
    open: Option<(u32, File)>,
}

fn key(h: &Hash) -> u64 {
    u64::from_le_bytes(h[..8].try_into().expect("8 bytes"))
}

impl Locator {
    /// `spool_dir`: fallback chunk spool (unlinked right after creation, so a crash
    /// leaves nothing behind); `max` bytes at most.
    pub fn new(spool_dir: Option<&Path>, max: u64) -> io::Result<Locator> {
        let spool = match spool_dir {
            Some(d) if max > 0 => {
                crate::config::ensure_dir(d, 0o700)?;
                let p = d.join(format!("spool.{}.{}", std::process::id(), rand_u64()));
                let f = fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .custom_flags(libc::O_NOFOLLOW)
                    .open(&p)?;
                fs::remove_file(&p)?;
                Some(Spool { f, used: 0, max })
            }
            _ => None,
        };
        Ok(Locator {
            spool,
            ..Default::default()
        })
    }

    fn add_file(&mut self, p: PathBuf) -> u32 {
        self.files.push(p);
        (self.files.len() - 1) as u32
    }

    fn add(&mut self, h: &Hash, mut loc: Loc, spool_data: Option<&[u8]>) -> io::Result<()> {
        let locs = self.map.entry(key(h)).or_default();
        let same: Vec<&Loc> = locs.iter().filter(|(x, _)| x == h).map(|(_, l)| l).collect();
        if same.len() >= MAX_LOCS || same.iter().any(|l| l.spooled.is_some()) {
            return Ok(());
        }
        if let (Some(data), Some(s)) = (spool_data, self.spool.as_mut()) {
            if s.used + data.len() as u64 <= s.max {
                s.f.write_all_at(data, s.used)?;
                loc.spooled = Some(s.used);
                s.used += data.len() as u64;
            }
        }
        locs.push((*h, loc));
        Ok(())
    }

    pub fn chunks(&self) -> usize {
        self.map.values().map(|v| v.len()).sum()
    }

    pub fn spooled_bytes(&self) -> u64 {
        self.spool.as_ref().map_or(0, |s| s.used)
    }

    /// Read a chunk again and verify its hash. `None` if no location still holds it
    /// (unknown hash, or the live file changed since the scan).
    pub fn get(&mut self, h: &Hash) -> Option<Vec<u8>> {
        let locs: Vec<Loc> = self
            .map
            .get(&key(h))?
            .iter()
            .filter(|(x, _)| x == h)
            .map(|(_, l)| *l)
            .collect();
        for loc in locs {
            let mut buf = vec![0u8; loc.len as usize];
            let ok = match loc.spooled {
                Some(off) => self
                    .spool
                    .as_ref()
                    .is_some_and(|s| s.f.read_exact_at(&mut buf, off).is_ok()),
                None => self
                    .file(loc.file)
                    .is_some_and(|f| f.read_exact_at(&mut buf, loc.offset).is_ok()),
            };
            if ok && blake3::hash(&buf).as_bytes() == h {
                return Some(buf);
            }
        }
        None
    }

    fn file(&mut self, idx: u32) -> Option<&File> {
        if self.open.as_ref().map(|(i, _)| *i) != Some(idx) {
            let p = self.files.get(idx as usize)?;
            let f = open_nofollow(p).ok()?;
            self.open = Some((idx, f));
        }
        self.open.as_ref().map(|(_, f)| f)
    }
}

fn rand_u64() -> u64 {
    let mut b = [0u8; 8];
    let _ = ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut b);
    u64::from_le_bytes(b)
}

pub fn open_nofollow(p: &Path) -> io::Result<File> {
    let o = |noatime: bool| {
        fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | if noatime { libc::O_NOATIME } else { 0 })
            .open(p)
    };
    match o(true) {
        Err(e) if e.raw_os_error() == Some(libc::EPERM) => o(false),
        r => r,
    }
}

pub fn mtime_ns(m: &Metadata) -> i64 {
    m.mtime() * 1_000_000_000 + m.mtime_nsec()
}

pub fn ctime_ns(m: &Metadata) -> i64 {
    m.ctime() * 1_000_000_000 + m.ctime_nsec()
}

fn kind_of(m: &Metadata) -> Option<Kind> {
    let t = m.file_type();
    Some(if t.is_file() {
        Kind::File
    } else if t.is_dir() {
        Kind::Dir
    } else if t.is_symlink() {
        Kind::Symlink
    } else if t.is_block_device() || t.is_char_device() {
        Kind::Device
    } else if t.is_fifo() {
        Kind::Fifo
    } else if t.is_socket() {
        Kind::Socket
    } else {
        return None;
    })
}

pub struct Scanner<'a> {
    pub excludes: &'a Excludes,
    /// committed cache of the base backup (None = read everything)
    pub cache: Option<&'a Cache>,
    /// all host mount points: never descended into from a parent root
    pub mountpoints: HashSet<PathBuf>,
    pub locator: Locator,
    pub new_cache: Cache,
    pub stats: ScanStats,
    roots: HashSet<PathBuf>,
    links: HashMap<(u64, u64), Vec<u8>>,
}

impl<'a> Scanner<'a> {
    pub fn new(excludes: &'a Excludes, cache: Option<&'a Cache>, locator: Locator, new_cache: Cache) -> Self {
        Scanner {
            excludes,
            cache,
            mountpoints: HashSet::new(),
            locator,
            new_cache,
            stats: ScanStats::default(),
            roots: HashSet::new(),
            links: HashMap::new(),
        }
    }

    fn error(&mut self, msg: String) {
        if self.stats.errors.len() < MAX_ERRORS {
            self.stats.errors.push(msg);
        } else if self.stats.errors.len() == MAX_ERRORS {
            self.stats.errors.push("further errors suppressed".into());
        }
    }

    /// Walk all roots. `emit` errors (connection) abort; file errors are collected.
    pub fn run(&mut self, roots: &[Root], emit: &mut dyn FnMut(Entry) -> io::Result<()>) -> io::Result<()> {
        self.roots = roots.iter().map(|r| r.host.clone()).collect();
        for root in roots {
            let md = match fs::symlink_metadata(&root.src) {
                Ok(m) => m,
                Err(e) => {
                    self.error(format!("{}: {e}", root.host.display()));
                    continue;
                }
            };
            let dev = md.dev();
            if root.host != Path::new("/") {
                if let Some(e) = self.entry(root, &root.host, &root.src, &md) {
                    emit(e)?;
                }
            }
            if !md.is_dir() {
                continue;
            }
            let mut stack = vec![(root.host.clone(), root.src.clone())];
            while let Some((host, src)) = stack.pop() {
                let mut names: Vec<_> = match fs::read_dir(&src) {
                    Ok(rd) => rd.filter_map(|e| e.ok().map(|e| e.file_name())).collect(),
                    Err(e) => {
                        self.error(format!("{}: {e}", host.display()));
                        continue;
                    }
                };
                names.sort();
                let mut subdirs = vec![];
                for name in names {
                    if name == BTRFS_DIR && src == root.src {
                        continue;
                    }
                    let (h, s) = (host.join(&name), src.join(&name));
                    if self.excludes.matches(h.as_os_str().as_bytes()) {
                        continue;
                    }
                    let md = match fs::symlink_metadata(&s) {
                        Ok(m) => m,
                        Err(e) => {
                            self.error(format!("{}: {e}", h.display()));
                            continue;
                        }
                    };
                    let boundary = md.is_dir() && (md.dev() != dev || self.mountpoints.contains(&h));
                    if boundary && self.roots.contains(&h) {
                        continue; // another root covers it
                    }
                    if let Some(e) = self.entry(root, &h, &s, &md) {
                        emit(e)?;
                    }
                    if md.is_dir() && !boundary {
                        subdirs.push((h, s));
                    }
                }
                stack.extend(subdirs.into_iter().rev());
            }
        }
        Ok(())
    }

    fn entry(&mut self, root: &Root, host: &Path, src: &Path, md: &Metadata) -> Option<Entry> {
        let path = host
            .as_os_str()
            .as_bytes()
            .strip_prefix(b"/")
            .unwrap_or(host.as_os_str().as_bytes())
            .to_vec();
        if path.len() > MAX_PATH {
            self.error(format!(
                "{}: path longer than {MAX_PATH} bytes, skipped",
                host.display()
            ));
            return None;
        }
        let Some(mut kind) = kind_of(md) else {
            self.error(format!("{}: unknown file type", host.display()));
            return None;
        };
        let mut e = Entry {
            path,
            kind,
            // devices keep S_IFBLK/S_IFCHR so restore can tell them apart
            mode: if kind == Kind::Device {
                md.mode()
            } else {
                md.mode() & 0o7777
            },
            uid: md.uid(),
            gid: md.gid(),
            size: if kind == Kind::File { md.size() } else { 0 },
            mtime_ns: mtime_ns(md),
            ctime_ns: ctime_ns(md),
            inode: md.ino(),
            rdev: if kind == Kind::Device { md.rdev() } else { 0 },
            link_target: None,
            xattrs: vec![],
            chunks: vec![],
            unchanged: false,
            inconsistent: false,
        };
        match sys::lxattrs(src) {
            Ok(x) => {
                let mut total = 0;
                for (k, v) in x {
                    total += k.len() + v.len();
                    if total > MAX_XATTR {
                        self.error(format!(
                            "{}: xattrs exceed {MAX_XATTR} bytes, truncated",
                            host.display()
                        ));
                        break;
                    }
                    e.xattrs.push((k, v));
                }
            }
            Err(err) => self.error(format!("{}: xattrs: {err}", host.display())),
        }
        if kind != Kind::Dir && md.nlink() > 1 {
            match self.links.get(&(md.dev(), md.ino())) {
                Some(first) => {
                    kind = Kind::Hardlink;
                    e.kind = kind;
                    e.link_target = Some(first.clone());
                    e.size = 0;
                }
                None => {
                    self.links.insert((md.dev(), md.ino()), e.path.clone());
                }
            }
        }
        match kind {
            Kind::Dir => self.stats.dirs += 1,
            Kind::Symlink => match fs::read_link(src) {
                Ok(t) if t.as_os_str().len() <= MAX_PATH => e.link_target = Some(t.as_os_str().as_bytes().to_vec()),
                Ok(_) => {
                    self.error(format!("{}: symlink target too long, skipped", host.display()));
                    return None;
                }
                Err(err) => {
                    self.error(format!("{}: {err}", host.display()));
                    return None;
                }
            },
            Kind::File => {
                self.stats.files += 1;
                if !self.file(root, host, src, md, &mut e) {
                    return None;
                }
                self.stats.bytes += e.size;
            }
            Kind::Hardlink => self.stats.files += 1,
            _ => {}
        }
        Some(e)
    }

    /// Fill `e.chunks`: from the cache if unchanged, otherwise by reading the file.
    fn file(&mut self, root: &Root, host: &Path, src: &Path, md: &Metadata, e: &mut Entry) -> bool {
        let cached = self
            .cache
            .and_then(|c| c.lookup(&e.path, e.size, e.mtime_ns, e.ctime_ns, e.inode))
            .filter(|c| c.chunks.iter().map(|(_, l)| *l as u64).sum::<u64>() == c.size)
            .cloned();
        let idx = self.locator.add_file(src.to_path_buf());
        if let Some(c) = cached {
            let mut off = 0;
            for (h, l) in &c.chunks {
                let loc = Loc {
                    file: idx,
                    offset: off,
                    len: *l,
                    spooled: None,
                };
                if let Err(err) = self.locator.add(h, loc, None) {
                    self.error(format!("{}: {err}", host.display()));
                }
                off += *l as u64;
            }
            e.chunks = c.chunks.clone();
            e.unchanged = true;
            self.stats.unchanged += 1;
            self.new_cache.files.insert(e.path.clone(), c);
            return true;
        }
        match self.read(root, src, md, idx) {
            Ok((chunks, size, changed)) => {
                self.stats.read_bytes += size;
                e.size = size;
                e.chunks = chunks;
                if changed {
                    e.inconsistent = true;
                    self.stats.inconsistent += 1;
                } else {
                    let c = Cached {
                        size,
                        mtime_ns: e.mtime_ns,
                        ctime_ns: e.ctime_ns,
                        inode: e.inode,
                        chunks: e.chunks.clone(),
                    };
                    self.new_cache.files.insert(e.path.clone(), c);
                }
                true
            }
            Err(err) => {
                self.error(format!("{}: {err}", host.display()));
                false
            }
        }
    }

    /// Returns (chunks, bytes read, changed during read).
    fn read(&mut self, root: &Root, src: &Path, pre: &Metadata, idx: u32) -> io::Result<(ChunkList, u64, bool)> {
        let f = open_nofollow(src)?;
        let opened = f.metadata()?;
        if opened.dev() != pre.dev() || opened.ino() != pre.ino() {
            return Err(io::Error::other("replaced while scanning"));
        }
        let mut chunks = vec![];
        let mut total = 0u64;
        for c in fastcdc::v2020::StreamCDC::new(&f, CDC_MIN, CDC_AVG, CDC_MAX) {
            let c = c.map_err(io::Error::other)?;
            let h = *blake3::hash(&c.data).as_bytes();
            let loc = Loc {
                file: idx,
                offset: c.offset,
                len: c.length as u32,
                spooled: None,
            };
            self.locator.add(&h, loc, root.live.then_some(&c.data[..]))?;
            chunks.push((h, c.length as u32));
            total += c.length as u64;
        }
        let post = f.metadata()?;
        let changed = total != pre.size()
            || post.size() != pre.size()
            || mtime_ns(&post) != mtime_ns(pre)
            || ctime_ns(&post) != ctime_ns(pre);
        Ok((chunks, total, changed))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn scan_dir(dir: &Path, excludes: &[&str], cache: Option<&Cache>, live: bool) -> (Vec<Entry>, Scanner<'static>) {
        let ex: &'static Excludes = Box::leak(Box::new(Excludes::new(
            &excludes.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
        )));
        let cache: Option<&'static Cache> = cache.map(|c| &*Box::leak(Box::new(c.clone())));
        let mut s = Scanner::new(ex, cache, Locator::new(None, 0).unwrap(), Cache::new(1, None));
        let mut out = vec![];
        let root = Root {
            host: dir.to_path_buf(),
            src: dir.to_path_buf(),
            live,
        };
        s.run(&[root], &mut |e| {
            out.push(e);
            Ok(())
        })
        .unwrap();
        (out, s)
    }

    fn rel<'e>(es: &'e [Entry], dir: &Path, name: &str) -> &'e Entry {
        let p = dir.join(name);
        let p = p.as_os_str().as_bytes().strip_prefix(b"/").unwrap();
        es.iter()
            .find(|e| e.path == p)
            .unwrap_or_else(|| panic!("{name} missing"))
    }

    #[test]
    fn metadata_hardlinks_symlinks_xattrs_and_chunks() {
        let t = tempfile::tempdir().unwrap();
        let d = t.path();
        fs::create_dir(d.join("sub")).unwrap();
        let mut x = 0x9E3779B97F4A7C15u64;
        let big: Vec<u8> = (0..5_000_000)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                x as u8
            })
            .collect();
        fs::write(d.join("sub/big"), &big).unwrap();
        fs::write(d.join("small"), b"hello").unwrap();
        fs::set_permissions(d.join("small"), fs::Permissions::from_mode(0o4751)).unwrap();
        fs::hard_link(d.join("small"), d.join("sub/link")).unwrap();
        std::os::unix::fs::symlink("../small", d.join("sub/sym")).unwrap();
        let _ = xattr_set(&d.join("small"), "user.test", b"v1");
        let (es, s) = scan_dir(d, &[], None, false);
        let small = rel(&es, d, "small");
        assert_eq!(small.kind, Kind::File);
        assert_eq!(small.mode, 0o4751);
        assert_eq!(small.chunks, vec![(*blake3::hash(b"hello").as_bytes(), 5)]);
        if xattr_set(&d.join("sub/big"), "user.t2", b"x").is_ok() {
            assert!(small.xattrs.contains(&(b"user.test".to_vec(), b"v1".to_vec())));
        }
        let link = rel(&es, d, "sub/link");
        assert_eq!(link.kind, Kind::Hardlink);
        assert_eq!(link.link_target.as_ref(), Some(&small.path));
        assert_eq!(rel(&es, d, "sub/sym").link_target.as_deref(), Some(&b"../small"[..]));
        let bigc = &rel(&es, d, "sub/big").chunks;
        assert!(bigc.len() >= 2, "FastCDC splits 5 MB");
        assert_eq!(bigc.iter().map(|c| c.1 as usize).sum::<usize>(), big.len());
        // the parent dir is emitted before its children
        let pos = |n: &str| es.iter().position(|e| e.path.ends_with(n.as_bytes())).unwrap();
        assert!(pos("/sub") < pos("sub/big"));
        // locator returns verified data for every chunk
        let mut loc = s.locator;
        for (h, l) in bigc {
            assert_eq!(loc.get(h).unwrap().len(), *l as usize);
        }
        assert!(loc.get(&[9; 32]).is_none());
        assert_eq!(s.stats.files, 3);
        assert_eq!(s.stats.dirs, 2);
    }

    fn xattr_set(p: &Path, k: &str, v: &[u8]) -> io::Result<()> {
        let f = File::open(p)?;
        sys::fsetxattr(std::os::fd::AsRawFd::as_raw_fd(&f), k.as_bytes(), v)
    }

    #[test]
    fn excludes_skip_files_and_dirs() {
        let t = tempfile::tempdir().unwrap();
        let d = t.path();
        fs::create_dir_all(d.join("cache/deep")).unwrap();
        fs::write(d.join("cache/deep/x"), b"x").unwrap();
        fs::write(d.join("a.tmp"), b"x").unwrap();
        fs::write(d.join("keep"), b"x").unwrap();
        let pat = format!("{}/cache", d.display());
        let (es, _) = scan_dir(d, &["*.tmp", &pat], None, false);
        let names: Vec<String> = es
            .iter()
            .map(|e| String::from_utf8_lossy(&e.path).into_owned())
            .collect();
        assert!(names.iter().any(|n| n.ends_with("/keep")));
        assert!(
            !names.iter().any(|n| n.contains("a.tmp") || n.contains("cache")),
            "{names:?}"
        );
    }

    #[test]
    fn cache_marks_unchanged_without_reading() {
        let t = tempfile::tempdir().unwrap();
        let d = t.path();
        fs::write(d.join("a"), b"aaaa").unwrap();
        fs::write(d.join("b"), b"bbbb").unwrap();
        let (_, s1) = scan_dir(d, &[], None, false);
        assert_eq!(s1.stats.read_bytes, 8);
        let cache = s1.new_cache;
        std::thread::sleep(std::time::Duration::from_millis(20));
        fs::write(d.join("b"), b"bbbbb").unwrap();
        let (es, s2) = scan_dir(d, &[], Some(&cache), false);
        assert!(rel(&es, d, "a").unchanged);
        assert_eq!(
            rel(&es, d, "a").chunks,
            cache.files.values().find(|c| c.size == 4).unwrap().chunks
        );
        assert!(!rel(&es, d, "b").unchanged);
        assert_eq!(s2.stats.read_bytes, 5, "only the changed file is read");
        assert_eq!(s2.stats.unchanged, 1);
        // unchanged files' chunks can still be served
        let mut loc = s2.locator;
        assert_eq!(loc.get(blake3::hash(b"aaaa").as_bytes()).unwrap(), b"aaaa");
    }

    #[test]
    fn fallback_detects_change_during_read_and_spools() {
        let t = tempfile::tempdir().unwrap();
        let d = t.path().join("data");
        fs::create_dir(&d).unwrap();
        fs::write(d.join("stable"), b"stable").unwrap();
        fs::write(d.join("hot"), vec![1u8; 600_000]).unwrap();
        let pre = fs::symlink_metadata(d.join("hot")).unwrap();
        // simulate a writer between the walk's stat and the read
        let ex = Excludes::default();
        let spool = t.path().join("spool");
        let mut s = Scanner::new(
            &ex,
            None,
            Locator::new(Some(&spool), 1 << 20).unwrap(),
            Cache::new(1, None),
        );
        let root = Root {
            host: d.clone(),
            src: d.clone(),
            live: true,
        };
        std::thread::sleep(std::time::Duration::from_millis(20));
        fs::write(d.join("hot"), vec![2u8; 700_000]).unwrap();
        let idx = s.locator.add_file(d.join("hot"));
        let (chunks, size, changed) = s.read(&root, &d.join("hot"), &pre, idx).unwrap();
        assert!(changed, "size/mtime changed during read");
        assert_eq!(size, 700_000);
        assert_eq!(chunks.iter().map(|c| c.1 as u64).sum::<u64>(), 700_000);
        // the full scan marks a file inconsistent only if it changed while read
        let mut out = vec![];
        s.run(&[root], &mut |e| {
            out.push(e);
            Ok(())
        })
        .unwrap();
        assert!(out.iter().all(|e| !e.inconsistent));
        // spooled data survives later changes of the live file
        let h = chunks[0].0;
        fs::write(d.join("hot"), b"gone").unwrap();
        assert!(s.locator.spooled_bytes() > 0);
        assert_eq!(s.locator.get(&h).unwrap().len(), chunks[0].1 as usize);
        assert_eq!(fs::read_dir(&spool).unwrap().count(), 0, "spool file is unlinked");
    }

    #[test]
    fn does_not_cross_mount_points() {
        let t = tempfile::tempdir().unwrap();
        let d = t.path();
        fs::create_dir_all(d.join("mnt/inner")).unwrap();
        fs::write(d.join("mnt/inner/x"), b"x").unwrap();
        let ex = Excludes::default();
        let mut s = Scanner::new(&ex, None, Locator::default(), Cache::default());
        s.mountpoints.insert(d.join("mnt"));
        let mut out = vec![];
        s.run(
            &[Root {
                host: d.to_path_buf(),
                src: d.to_path_buf(),
                live: false,
            }],
            &mut |e| {
                out.push(e);
                Ok(())
            },
        )
        .unwrap();
        assert!(
            out.iter().any(|e| e.path.ends_with(b"/mnt")),
            "mount point dir itself is kept"
        );
        assert!(!out.iter().any(|e| e.path.ends_with(b"inner")));
    }
}
