//! Tantivy `Directory` whose files are sealed with the tenant keyring
//! (XChaCha20-Poly1305 like every store object; docs/file-index-v2-plan.md).
//!
//! Segment files are written once (`open_write`) as a sequence of sealed
//! blocks of [`BLOCK`] plain bytes plus a sealed block table at the end:
//!
//! ```text
//! "NXIX1\0\0\0" | sealed block 0 | … | sealed block n-1 | sealed table | u64 LE table offset
//! ```
//!
//! Block `i` is sealed under the context `nexus-index:<file>:<i>`, the table
//! (offsets, lengths, plain length) under `nexus-index:<file>:table`, so blocks
//! cannot be swapped between files or positions and a file cannot be
//! truncated unnoticed. Reads decrypt only the blocks they touch, through a
//! cache of decrypted blocks shared by all tenants and bounded in bytes (LRU).
//! Small files written with `atomic_write` (`meta.json`, `.managed.json`) are
//! one sealed blob each. Locks are process-local: nexus-index is the only
//! process that opens these directories.

use chunkstore::Keyring;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;
use std::fs::{self, File};
use std::io::{self, BufWriter, Write};
use std::ops::Range;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tantivy::directory::error::{DeleteError, LockError, OpenReadError, OpenWriteError};
use tantivy::directory::{
    AntiCallToken, Directory, DirectoryLock, FileHandle, Lock, OwnedBytes, TerminatingWrite, WatchCallback,
    WatchHandle, WritePtr,
};
use tantivy::HasLen;

pub const BLOCK: usize = 256 << 10;
const MAGIC: &[u8; 8] = b"NXIX1\0\0\0";

/// (file, block number)
type BlockKey = (Arc<str>, usize);

/// Decrypted blocks of all open index files, bounded in bytes.
pub struct BlockCache {
    cap: usize,
    bytes: usize,
    tick: u64,
    map: HashMap<BlockKey, (u64, Arc<[u8]>)>,
    order: BTreeMap<u64, BlockKey>,
}

impl BlockCache {
    pub fn new(cap: usize) -> Arc<Mutex<BlockCache>> {
        Arc::new(Mutex::new(BlockCache {
            cap: cap.max(BLOCK * 8),
            bytes: 0,
            tick: 0,
            map: HashMap::new(),
            order: BTreeMap::new(),
        }))
    }

    fn get(&mut self, k: &(Arc<str>, usize)) -> Option<Arc<[u8]>> {
        self.tick += 1;
        let tick = self.tick;
        let (t, b) = self.map.get_mut(k)?;
        self.order.remove(t);
        *t = tick;
        self.order.insert(tick, k.clone());
        Some(b.clone())
    }

    fn put(&mut self, k: (Arc<str>, usize), b: Arc<[u8]>) {
        self.tick += 1;
        self.bytes += b.len();
        self.order.insert(self.tick, k.clone());
        if let Some((t, old)) = self.map.insert(k, (self.tick, b)) {
            self.order.remove(&t);
            self.bytes -= old.len();
        }
        while self.bytes > self.cap {
            let Some((_, k)) = self.order.pop_first() else { break };
            if let Some((_, b)) = self.map.remove(&k) {
                self.bytes -= b.len();
            }
        }
    }

    /// Drops the blocks of one file (deleted).
    fn forget(&mut self, file: &str) {
        let keys: Vec<_> = self.map.keys().filter(|k| &*k.0 == file).cloned().collect();
        for k in keys {
            if let Some((t, b)) = self.map.remove(&k) {
                self.order.remove(&t);
                self.bytes -= b.len();
            }
        }
    }

    pub fn bytes(&self) -> usize {
        self.bytes
    }
}

#[derive(Clone)]
pub struct SealedDir {
    root: PathBuf,
    /// cache key prefix: `<tenant>/`
    id: Arc<str>,
    keys: Arc<Keyring>,
    cache: Arc<Mutex<BlockCache>>,
    locks: Arc<Mutex<HashSet<PathBuf>>>,
}

impl fmt::Debug for SealedDir {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SealedDir({})", self.root.display())
    }
}

fn ctx(file: &str, part: &str) -> Vec<u8> {
    format!("nexus-index:{file}:{part}").into_bytes()
}

fn name(p: &Path) -> io::Result<String> {
    // tantivy only uses flat file names
    match p.to_str() {
        Some(s) if !s.is_empty() && !s.contains('/') && s != "." && s != ".." => Ok(s.to_owned()),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("index file name {p:?}"),
        )),
    }
}

impl SealedDir {
    pub fn open(root: &Path, keys: Arc<Keyring>, cache: Arc<Mutex<BlockCache>>) -> io::Result<SealedDir> {
        fs::create_dir_all(root)?;
        Ok(SealedDir {
            root: root.to_owned(),
            id: Arc::from(format!("{}/", keys.tenant())),
            keys,
            cache,
            locks: Arc::new(Mutex::new(HashSet::new())),
        })
    }

    fn path(&self, p: &Path) -> io::Result<(String, PathBuf)> {
        let n = name(p)?;
        let full = self.root.join(&n);
        Ok((n, full))
    }

    /// Removes every file of the index (damaged or another format: rebuilt).
    pub fn wipe(&self) -> io::Result<()> {
        for e in fs::read_dir(&self.root)?.flatten() {
            if e.file_type().is_ok_and(|t| t.is_file()) {
                fs::remove_file(e.path())?;
            }
        }
        let mut c = self.cache.lock().unwrap();
        let id = self.id.clone();
        let keys: Vec<_> = c.map.keys().filter(|k| k.0.starts_with(&*id)).cloned().collect();
        for k in keys {
            if let Some((t, b)) = c.map.remove(&k) {
                c.order.remove(&t);
                c.bytes -= b.len();
            }
        }
        Ok(())
    }

    /// Bytes on disk of the index (Storage page).
    pub fn disk_bytes(&self) -> u64 {
        Self::bytes_of(&self.root)
    }

    pub fn bytes_of(root: &Path) -> u64 {
        fs::read_dir(root)
            .map(|d| d.flatten().filter_map(|e| e.metadata().ok()).map(|m| m.len()).sum())
            .unwrap_or(0)
    }
}

/// An open segment file: block table + the sealed file.
struct Handle {
    file: File,
    name: String,
    cache_key: Arc<str>,
    keys: Arc<Keyring>,
    cache: Arc<Mutex<BlockCache>>,
    /// (offset, sealed length) per block
    blocks: Vec<(u64, u32)>,
    len: usize,
}

impl fmt::Debug for Handle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Handle({}, {} bytes)", self.name, self.len)
    }
}

impl HasLen for Handle {
    fn len(&self) -> usize {
        self.len
    }
}

impl Handle {
    fn block(&self, i: usize) -> io::Result<Arc<[u8]>> {
        let key = (self.cache_key.clone(), i);
        if let Some(b) = self.cache.lock().unwrap().get(&key) {
            return Ok(b);
        }
        let (off, n) = self.blocks[i];
        let mut sealed = vec![0u8; n as usize];
        self.file.read_exact_at(&mut sealed, off)?;
        let plain = self.keys.open(&ctx(&self.name, &i.to_string()), &sealed)?.1;
        let want = BLOCK.min(self.len - i * BLOCK);
        if plain.len() != want {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "index block length"));
        }
        let b: Arc<[u8]> = Arc::from(plain);
        self.cache.lock().unwrap().put(key, b.clone());
        Ok(b)
    }
}

/// `Arc<[u8]>` window for OwnedBytes without a copy.
struct ArcSlice(Arc<[u8]>);

impl std::ops::Deref for ArcSlice {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.0
    }
}

// SAFETY: the bytes live in the Arc's heap allocation; moving the wrapper does not move them
unsafe impl stable_deref_trait::StableDeref for ArcSlice {}

impl FileHandle for Handle {
    fn read_bytes(&self, range: Range<usize>) -> io::Result<OwnedBytes> {
        if range.start > range.end || range.end > self.len {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "read beyond the index file",
            ));
        }
        if range.is_empty() {
            return Ok(OwnedBytes::empty());
        }
        let (first, last) = (range.start / BLOCK, (range.end - 1) / BLOCK);
        if first == last {
            let b = self.block(first)?;
            let base = first * BLOCK;
            return Ok(OwnedBytes::new(ArcSlice(b)).slice(range.start - base..range.end - base));
        }
        let mut out = Vec::with_capacity(range.len());
        for i in first..=last {
            let b = self.block(i)?;
            let base = i * BLOCK;
            let a = range.start.max(base) - base;
            let e = range.end.min(base + b.len()) - base;
            out.extend_from_slice(&b[a..e]);
        }
        Ok(OwnedBytes::new(out))
    }
}

/// Seals blocks as they fill; the table is written on `terminate`.
struct Writer {
    out: BufWriter<File>,
    name: String,
    keys: Arc<Keyring>,
    buf: Vec<u8>,
    pos: u64,
    blocks: Vec<(u64, u32)>,
    plain: u64,
    done: bool,
}

impl Writer {
    fn seal_block(&mut self) -> io::Result<()> {
        if self.buf.is_empty() {
            return Ok(());
        }
        let i = self.blocks.len();
        let sealed = self.keys.seal(&ctx(&self.name, &i.to_string()), &self.buf);
        self.out.write_all(&sealed)?;
        self.blocks.push((self.pos, sealed.len() as u32));
        self.pos += sealed.len() as u64;
        self.plain += self.buf.len() as u64;
        self.buf.clear();
        Ok(())
    }
}

impl Write for Writer {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        if self.done {
            return Err(io::Error::other("index file already terminated"));
        }
        let mut rest = data;
        while !rest.is_empty() {
            let k = (BLOCK - self.buf.len()).min(rest.len());
            self.buf.extend_from_slice(&rest[..k]);
            rest = &rest[k..];
            if self.buf.len() == BLOCK {
                self.seal_block()?;
            }
        }
        Ok(data.len())
    }

    /// Full blocks are on disk already; a partial block waits for terminate
    /// (tantivy reads a file only after terminating it).
    fn flush(&mut self) -> io::Result<()> {
        self.out.flush()
    }
}

impl TerminatingWrite for Writer {
    fn terminate_ref(&mut self, _: AntiCallToken) -> io::Result<()> {
        if self.done {
            return Ok(());
        }
        self.seal_block()?;
        let mut table = Vec::with_capacity(8 + self.blocks.len() * 12);
        table.extend_from_slice(&self.plain.to_le_bytes());
        for (o, n) in &self.blocks {
            table.extend_from_slice(&o.to_le_bytes());
            table.extend_from_slice(&n.to_le_bytes());
        }
        let sealed = self.keys.seal(&ctx(&self.name, "table"), &table);
        self.out.write_all(&sealed)?;
        self.out.write_all(&self.pos.to_le_bytes())?;
        self.out.flush()?;
        self.out.get_ref().sync_all()?;
        self.done = true;
        Ok(())
    }
}

fn read_table(file: &File, name: &str, keys: &Keyring) -> io::Result<(Vec<(u64, u32)>, usize)> {
    let bad = |m: &str| io::Error::new(io::ErrorKind::InvalidData, format!("index file {name}: {m}"));
    let size = file.metadata()?.len();
    if size < MAGIC.len() as u64 + 8 {
        return Err(bad("truncated"));
    }
    let mut m = [0u8; 8];
    file.read_exact_at(&mut m, 0)?;
    if &m != MAGIC {
        return Err(bad("not a sealed index file"));
    }
    let mut t = [0u8; 8];
    file.read_exact_at(&mut t, size - 8)?;
    let toff = u64::from_le_bytes(t);
    if toff < MAGIC.len() as u64 || toff >= size - 8 || size - 8 - toff > 64 << 20 {
        return Err(bad("table offset"));
    }
    let mut sealed = vec![0u8; (size - 8 - toff) as usize];
    file.read_exact_at(&mut sealed, toff)?;
    let table = keys.open(&ctx(name, "table"), &sealed)?.1;
    if table.len() < 8 || (table.len() - 8) % 12 != 0 {
        return Err(bad("table"));
    }
    let plain = u64::from_le_bytes(table[..8].try_into().unwrap());
    let blocks: Vec<(u64, u32)> = table[8..]
        .chunks(12)
        .map(|c| {
            (
                u64::from_le_bytes(c[..8].try_into().unwrap()),
                u32::from_le_bytes(c[8..].try_into().unwrap()),
            )
        })
        .collect();
    let ok = plain.div_ceil(BLOCK as u64) == blocks.len() as u64
        && blocks
            .iter()
            .all(|(o, n)| *o >= MAGIC.len() as u64 && o + *n as u64 <= toff);
    if !ok {
        return Err(bad("table"));
    }
    Ok((blocks, plain as usize))
}

struct LockGuard {
    locks: Arc<Mutex<HashSet<PathBuf>>>,
    path: PathBuf,
}

impl Drop for LockGuard {
    fn drop(&mut self) {
        self.locks.lock().unwrap().remove(&self.path);
    }
}

impl Directory for SealedDir {
    fn get_file_handle(&self, path: &Path) -> Result<Arc<dyn FileHandle>, OpenReadError> {
        let (n, full) = self
            .path(path)
            .map_err(|e| OpenReadError::wrap_io_error(e, path.to_owned()))?;
        let file = match File::open(&full) {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                return Err(OpenReadError::FileDoesNotExist(path.to_owned()))
            }
            Err(e) => return Err(OpenReadError::wrap_io_error(e, path.to_owned())),
        };
        let (blocks, len) =
            read_table(&file, &n, &self.keys).map_err(|e| OpenReadError::wrap_io_error(e, path.to_owned()))?;
        Ok(Arc::new(Handle {
            file,
            cache_key: Arc::from(format!("{}{n}", self.id)),
            name: n,
            keys: self.keys.clone(),
            cache: self.cache.clone(),
            blocks,
            len,
        }))
    }

    fn delete(&self, path: &Path) -> Result<(), DeleteError> {
        let (n, full) = self.path(path).map_err(|e| DeleteError::IoError {
            io_error: Arc::new(e),
            filepath: path.to_owned(),
        })?;
        self.cache.lock().unwrap().forget(&format!("{}{n}", self.id));
        match fs::remove_file(full) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Err(DeleteError::FileDoesNotExist(path.to_owned())),
            Err(e) => Err(DeleteError::IoError {
                io_error: Arc::new(e),
                filepath: path.to_owned(),
            }),
        }
    }

    fn exists(&self, path: &Path) -> Result<bool, OpenReadError> {
        let (_, full) = self
            .path(path)
            .map_err(|e| OpenReadError::wrap_io_error(e, path.to_owned()))?;
        Ok(full.exists())
    }

    fn open_write(&self, path: &Path) -> Result<WritePtr, OpenWriteError> {
        let (n, full) = self
            .path(path)
            .map_err(|e| OpenWriteError::wrap_io_error(e, path.to_owned()))?;
        let mut f = match File::options().write(true).create_new(true).open(&full) {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                return Err(OpenWriteError::FileAlreadyExists(path.to_owned()))
            }
            Err(e) => return Err(OpenWriteError::wrap_io_error(e, path.to_owned())),
        };
        f.write_all(MAGIC)
            .map_err(|e| OpenWriteError::wrap_io_error(e, path.to_owned()))?;
        let w = Writer {
            out: BufWriter::with_capacity(1 << 20, f),
            name: n,
            keys: self.keys.clone(),
            buf: Vec::with_capacity(BLOCK),
            pos: MAGIC.len() as u64,
            blocks: Vec::new(),
            plain: 0,
            done: false,
        };
        Ok(BufWriter::new(Box::new(w)))
    }

    fn atomic_read(&self, path: &Path) -> Result<Vec<u8>, OpenReadError> {
        let (n, full) = self
            .path(path)
            .map_err(|e| OpenReadError::wrap_io_error(e, path.to_owned()))?;
        let b = match fs::read(&full) {
            Ok(b) => b,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                return Err(OpenReadError::FileDoesNotExist(path.to_owned()))
            }
            Err(e) => return Err(OpenReadError::wrap_io_error(e, path.to_owned())),
        };
        self.keys
            .open(&ctx(&n, "atomic"), &b)
            .map(|x| x.1)
            .map_err(|e| OpenReadError::wrap_io_error(e, path.to_owned()))
    }

    fn atomic_write(&self, path: &Path, data: &[u8]) -> io::Result<()> {
        let (n, full) = self.path(path)?;
        chunkstore::store::write_atomic(&full, &self.keys.seal(&ctx(&n, "atomic"), data))
    }

    fn sync_directory(&self) -> io::Result<()> {
        File::open(&self.root)?.sync_all()
    }

    fn acquire_lock(&self, lock: &Lock) -> Result<DirectoryLock, LockError> {
        let p = self.root.join(&lock.filepath);
        loop {
            if self.locks.lock().unwrap().insert(p.clone()) {
                return Ok(DirectoryLock::from(Box::new(LockGuard {
                    locks: self.locks.clone(),
                    path: p,
                })));
            }
            if !lock.is_blocking {
                return Err(LockError::LockBusy);
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    }

    fn watch(&self, _: WatchCallback) -> tantivy::Result<WatchHandle> {
        Ok(WatchHandle::empty())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir(d: &Path, key: u8, cache: usize) -> SealedDir {
        let keys = Arc::new(Keyring::new("acme", &[(1, [key; 32])]));
        SealedDir::open(d, keys, BlockCache::new(cache)).unwrap()
    }

    #[test]
    fn blocks_are_sealed_and_bound_to_their_place() {
        let t = tempfile::tempdir().unwrap();
        let d = dir(t.path(), 1, 0);
        let data: Vec<u8> = (0..(BLOCK * 2 + 777)).map(|i| (i % 251) as u8).collect();
        let mut w = d.open_write(Path::new("seg.idx")).unwrap();
        w.write_all(b"secret-term ").unwrap();
        w.write_all(&data).unwrap();
        w.flush().unwrap();
        w.terminate().unwrap();
        let mut want = b"secret-term ".to_vec();
        want.extend_from_slice(&data);
        let f = d.open_read(Path::new("seg.idx")).unwrap();
        assert_eq!(f.len(), want.len());
        assert_eq!(f.read_bytes().unwrap().as_slice(), &want[..]);
        let mid = f.slice(BLOCK - 3..BLOCK + 5).read_bytes().unwrap();
        assert_eq!(mid.as_slice(), &want[BLOCK - 3..BLOCK + 5]);
        // no plaintext on disk
        let raw = fs::read(t.path().join("seg.idx")).unwrap();
        assert!(!raw.windows(11).any(|w| w == b"secret-term"));
        // another tenant key / a renamed file / a truncated file do not open
        assert!(dir(t.path(), 2, 0).open_read(Path::new("seg.idx")).is_err());
        fs::copy(t.path().join("seg.idx"), t.path().join("other.idx")).unwrap();
        assert!(d.open_read(Path::new("other.idx")).is_err());
        fs::write(t.path().join("cut.idx"), &raw[..raw.len() - 20]).unwrap();
        assert!(d.open_read(Path::new("cut.idx")).is_err());
        // atomic files
        d.atomic_write(Path::new("meta.json"), b"{\"segments\":[]}").unwrap();
        assert_eq!(d.atomic_read(Path::new("meta.json")).unwrap(), b"{\"segments\":[]}");
        assert!(!fs::read(t.path().join("meta.json"))
            .unwrap()
            .windows(8)
            .any(|w| w == b"segments"));
        assert!(d.open_write(Path::new("seg.idx")).is_err(), "write once");
        d.delete(Path::new("seg.idx")).unwrap();
        assert!(!d.exists(Path::new("seg.idx")).unwrap());
        assert!(d.open_write(Path::new("../x")).is_err());
    }

    #[test]
    fn cache_is_bounded() {
        let t = tempfile::tempdir().unwrap();
        let d = dir(t.path(), 1, BLOCK * 8);
        let mut w = d.open_write(Path::new("big")).unwrap();
        w.write_all(&vec![7u8; BLOCK * 20]).unwrap();
        w.terminate().unwrap();
        let f = d.open_read(Path::new("big")).unwrap();
        for i in 0..20 {
            f.slice(i * BLOCK..i * BLOCK + 10).read_bytes().unwrap();
        }
        assert!(d.cache.lock().unwrap().bytes() <= BLOCK * 8);
    }
}
