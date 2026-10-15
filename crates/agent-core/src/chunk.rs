//! FastCDC (128/512/4096 KiB) + plain BLAKE3 chunking and the chunk [`Locator`].
//!
//! Chunk data is not kept in memory: the locator remembers where each chunk can be
//! read again (file + offset; in fallback mode a bounded spool file holds exactly the
//! bytes that were hashed). `Want` re-reads and verifies `blake3(data) == hash` before
//! sending. Memory per chunk ≈ 40 bytes (8-byte hash prefix key + location).

use crate::cache::{Cache, Cached};
use agent_proto::{Hash, CDC_AVG, CDC_MAX, CDC_MIN};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io;
use std::path::{Path, PathBuf};

pub type ChunkList = Vec<(Hash, u32)>;
/// candidate locations kept per chunk hash (identical files share chunks)
const MAX_LOCS: usize = 4;
/// SHA-256 of recently chunked files kept for [`take_file_hash`] (an entry is
/// emitted right after its file was read; Windows ADS are read in between)
const RECENT_HASHES: usize = 64;

/// (chunk list key, SHA-256) of the files chunked last
type Recent = std::collections::VecDeque<([u8; 16], Hash)>;

thread_local! {
    /// `Some` while a `ScanHashed` runs on this (session) thread
    static FILE_SHA: std::cell::RefCell<Option<Recent>> = const { std::cell::RefCell::new(None) };
}

/// Phase 28 (CAP_FILE_HASH): compute the SHA-256 of every file chunked on this
/// thread until switched off again.
pub fn set_file_hashing(on: bool) {
    FILE_SHA.with(|f| *f.borrow_mut() = on.then(std::collections::VecDeque::new));
}

fn list_key(chunks: &[(Hash, u32)]) -> [u8; 16] {
    let mut h = blake3::Hasher::new();
    for (c, l) in chunks {
        h.update(c);
        h.update(&l.to_le_bytes());
    }
    h.finalize().as_bytes()[..16].try_into().expect("16 bytes")
}

/// The SHA-256 of the file just chunked with exactly this chunk list, if hashing is on.
pub fn take_file_hash(chunks: &[(Hash, u32)]) -> Option<Hash> {
    let k = list_key(chunks);
    FILE_SHA.with(|f| {
        let mut f = f.borrow_mut();
        let q = f.as_mut()?;
        let i = q.iter().rposition(|(x, _)| *x == k)?;
        q.remove(i).map(|(_, h)| h)
    })
}

fn hashing() -> bool {
    FILE_SHA.with(|f| f.borrow().is_some())
}

fn remember_hash(chunks: &[(Hash, u32)], h: Hash) {
    let k = list_key(chunks);
    FILE_SHA.with(|f| {
        if let Some(q) = f.borrow_mut().as_mut() {
            if q.len() >= RECENT_HASHES {
                q.pop_front();
            }
            q.push_back((k, h));
        }
    });
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

pub fn rand_u64() -> u64 {
    let mut b = [0u8; 8];
    let _ = ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut b);
    u64::from_le_bytes(b)
}

/// A spool file that disappears when closed (unlinked right away on Unix,
/// delete-on-close on Windows), so a crash leaves nothing behind.
fn spool_file(dir: &Path) -> io::Result<File> {
    crate::config::ensure_dir(dir, 0o700)?;
    let p = dir.join(format!("spool.{}.{}", std::process::id(), rand_u64()));
    let mut o = fs::OpenOptions::new();
    o.read(true).write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600).custom_flags(libc::O_NOFOLLOW);
        let f = o.open(&p)?;
        fs::remove_file(&p)?;
        Ok(f)
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_FLAG_DELETE_ON_CLOSE: u32 = 0x0400_0000;
        const FILE_ATTRIBUTE_TEMPORARY: u32 = 0x100;
        o.custom_flags(FILE_FLAG_DELETE_ON_CLOSE)
            .attributes(FILE_ATTRIBUTE_TEMPORARY)
            .share_mode(0);
        o.open(&p)
    }
}

impl Locator {
    /// `spool_dir`: fallback chunk spool (gone when closed); `max` bytes at most.
    pub fn new(spool_dir: Option<&Path>, max: u64) -> io::Result<Locator> {
        let spool = match spool_dir {
            Some(d) if max > 0 => Some(Spool {
                f: spool_file(d)?,
                used: 0,
                max,
            }),
            _ => None,
        };
        Ok(Locator {
            spool,
            ..Default::default()
        })
    }

    pub fn add_file(&mut self, p: PathBuf) -> u32 {
        self.files.push(p);
        (self.files.len() - 1) as u32
    }

    /// Remember one chunk location; with `spool_data` (fallback mode) the bytes are
    /// also copied to the spool while it has room.
    pub fn add(&mut self, h: &Hash, file: u32, offset: u64, len: u32, spool_data: Option<&[u8]>) -> io::Result<()> {
        let mut loc = Loc {
            file,
            offset,
            len,
            spooled: None,
        };
        let locs = self.map.entry(key(h)).or_default();
        let same: Vec<&Loc> = locs.iter().filter(|(x, _)| x == h).map(|(_, l)| l).collect();
        if same.len() >= MAX_LOCS || same.iter().any(|l| l.spooled.is_some()) {
            return Ok(());
        }
        if let (Some(data), Some(s)) = (spool_data, self.spool.as_mut()) {
            if s.used + data.len() as u64 <= s.max {
                write_all_at(&s.f, data, s.used)?;
                loc.spooled = Some(s.used);
                s.used += data.len() as u64;
            }
        }
        locs.push((*h, loc));
        Ok(())
    }

    /// Locations of an unchanged file's cached chunk list (consecutive offsets).
    pub fn add_list(&mut self, file: u32, chunks: &[(Hash, u32)]) -> io::Result<()> {
        let mut off = 0;
        for (h, l) in chunks {
            self.add(h, file, off, *l, None)?;
            off += *l as u64;
        }
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
                    .is_some_and(|s| read_exact_at(&s.f, &mut buf, off).is_ok()),
                None => self
                    .file(loc.file)
                    .is_some_and(|f| read_exact_at(f, &mut buf, loc.offset).is_ok()),
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
            let f = open_read(p).ok()?;
            self.open = Some((idx, f));
        }
        self.open.as_ref().map(|(_, f)| f)
    }
}

/// Chunk an open file from its start: FastCDC + plain BLAKE3, each chunk registered
/// with the locator under file `idx` (and spooled when `spool`). Returns the chunk
/// list and the number of bytes read.
pub fn chunk_file(loc: &mut Locator, idx: u32, f: &File, spool: bool) -> io::Result<(ChunkList, u64)> {
    chunk_reader(loc, idx, f, spool)
}

/// [`chunk_file`] over any reader (tests, ADS handles).
pub fn chunk_reader(loc: &mut Locator, idx: u32, r: impl io::Read, spool: bool) -> io::Result<(ChunkList, u64)> {
    let mut chunks = vec![];
    let mut total = 0u64;
    let mut sha = hashing().then(<sha2::Sha256 as sha2::Digest>::new);
    for c in fastcdc::v2020::StreamCDC::new(r, CDC_MIN, CDC_AVG, CDC_MAX) {
        let c = c.map_err(io::Error::other)?;
        let h = *blake3::hash(&c.data).as_bytes();
        if let Some(s) = sha.as_mut() {
            sha2::Digest::update(s, &c.data);
        }
        loc.add(&h, idx, c.offset, c.length as u32, spool.then_some(&c.data[..]))?;
        chunks.push((h, c.length as u32));
        total += c.length as u64;
    }
    if let Some(s) = sha {
        remember_hash(&chunks, sha2::Digest::finalize(s).into());
    }
    Ok((chunks, total))
}

/// The metadata-cache decision shared by all agents: the cached chunk list of `path`
/// if size, mtime, ctime and inode (file id) all match and the list is consistent.
pub fn reuse(
    cache: Option<&Cache>,
    path: &[u8],
    size: u64,
    mtime_ns: i64,
    ctime_ns: i64,
    inode: u64,
) -> Option<Cached> {
    cache
        .and_then(|c| c.lookup(path, size, mtime_ns, ctime_ns, inode))
        .filter(|c| c.chunks.iter().map(|(_, l)| *l as u64).sum::<u64>() == c.size)
        .filter(|c| c.chunks.iter().all(|(_, l)| *l > 0))
        .cloned()
}

/// Open for reading without following a final symlink (`O_NOFOLLOW`, `O_NOATIME` when
/// permitted).
#[cfg(unix)]
pub fn open_read(p: &Path) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
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

/// Open for reading with backup semantics (needs SeBackupPrivilege to bypass ACLs),
/// sharing everything (live fallback mode reads files in use).
#[cfg(windows)]
pub fn open_read(p: &Path) -> io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    const FILE_FLAG_SEQUENTIAL_SCAN: u32 = 0x0800_0000;
    fs::OpenOptions::new()
        .read(true)
        .share_mode(7)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_SEQUENTIAL_SCAN)
        .open(p)
}

#[cfg(unix)]
pub fn read_exact_at(f: &File, buf: &mut [u8], off: u64) -> io::Result<()> {
    std::os::unix::fs::FileExt::read_exact_at(f, buf, off)
}

#[cfg(unix)]
pub fn write_all_at(f: &File, buf: &[u8], off: u64) -> io::Result<()> {
    std::os::unix::fs::FileExt::write_all_at(f, buf, off)
}

#[cfg(windows)]
pub fn read_exact_at(f: &File, mut buf: &mut [u8], mut off: u64) -> io::Result<()> {
    use std::os::windows::fs::FileExt;
    while !buf.is_empty() {
        match f.seek_read(buf, off) {
            Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(n) => {
                buf = &mut buf[n..];
                off += n as u64;
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

#[cfg(windows)]
pub fn write_all_at(f: &File, mut buf: &[u8], mut off: u64) -> io::Result<()> {
    use std::os::windows::fs::FileExt;
    while !buf.is_empty() {
        match f.seek_write(buf, off) {
            Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
            Ok(n) => {
                buf = &buf[n..];
                off += n as u64;
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunks_register_and_serve_verified_data() {
        let t = tempfile::tempdir().unwrap();
        let mut x = 0x9E3779B97F4A7C15u64;
        let data: Vec<u8> = (0..3_000_000)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                x as u8
            })
            .collect();
        let p = t.path().join("f");
        fs::write(&p, &data).unwrap();
        let mut loc = Locator::new(Some(&t.path().join("spool")), 1 << 30).unwrap();
        let idx = loc.add_file(p.clone());
        let (chunks, total) = chunk_file(&mut loc, idx, &File::open(&p).unwrap(), true).unwrap();
        assert_eq!(total, data.len() as u64);
        assert!(chunks.len() >= 2);
        assert_eq!(loc.spooled_bytes(), total);
        // spooled data survives the file changing
        fs::write(&p, b"changed").unwrap();
        for (h, l) in &chunks {
            assert_eq!(loc.get(h).unwrap().len(), *l as usize);
        }
        assert!(loc.get(&[1; 32]).is_none());
        // without spool, a changed file means the chunk is gone (hash verified)
        let mut l2 = Locator::default();
        let i2 = l2.add_file(p.clone());
        l2.add_list(i2, &chunks).unwrap();
        assert!(l2.get(&chunks[0].0).is_none());
    }

    #[test]
    fn file_hashes_only_while_switched_on() {
        let t = tempfile::tempdir().unwrap();
        let data = vec![5u8; 700_000];
        let mut loc = Locator::default();
        let (c, _) = chunk_reader(&mut loc, 0, &data[..], false).unwrap();
        assert_eq!(take_file_hash(&c), None, "off by default");
        set_file_hashing(true);
        let (c, _) = chunk_reader(&mut loc, 0, &data[..], false).unwrap();
        let (c2, _) = chunk_reader(&mut loc, 0, &b"other"[..], false).unwrap();
        let want: Hash = <sha2::Sha256 as sha2::Digest>::digest(&data).into();
        assert_eq!(take_file_hash(&c), Some(want));
        assert_eq!(take_file_hash(&c), None, "taken once");
        assert!(take_file_hash(&c2).is_some());
        // on another thread: off
        let d2 = data.clone();
        std::thread::spawn(move || {
            let mut l = Locator::default();
            let (c, _) = chunk_reader(&mut l, 0, &d2[..], false).unwrap();
            assert_eq!(take_file_hash(&c), None);
        })
        .join()
        .unwrap();
        set_file_hashing(false);
        let (c, _) = chunk_reader(&mut loc, 0, &data[..], false).unwrap();
        assert_eq!(take_file_hash(&c), None);
        drop(t);
    }

    #[test]
    fn reuse_requires_matching_metadata_and_consistent_list() {
        let mut c = Cache::new(1, None);
        c.files.insert(
            b"x".to_vec(),
            Cached {
                size: 4,
                mtime_ns: 1,
                ctime_ns: 2,
                inode: 3,
                chunks: vec![([1; 32], 4)],
            },
        );
        c.files.insert(
            b"bad".to_vec(),
            Cached {
                size: 5,
                mtime_ns: 1,
                ctime_ns: 2,
                inode: 3,
                chunks: vec![([1; 32], 4)],
            },
        );
        assert!(reuse(Some(&c), b"x", 4, 1, 2, 3).is_some());
        assert!(reuse(Some(&c), b"x", 4, 1, 2, 4).is_none());
        assert!(
            reuse(Some(&c), b"bad", 5, 1, 2, 3).is_none(),
            "inconsistent list = re-read"
        );
        assert!(reuse(None, b"x", 4, 1, 2, 3).is_none());
    }
}
