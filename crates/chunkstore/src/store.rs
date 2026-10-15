//! Local chunk store (plan §5): one file per chunk, sealed indexes and
//! manifests, retention locks, mark-and-sweep GC, verify.
//!
//! Layout under `root`:
//! ```text
//! keycheck                         sealed marker, rejects a wrong keyring
//! clock                            compliance clock state
//! chunks/<hex[..4]>/<hex>          sealed chunks
//! snapshots/<source>/<time>/<name>.idx
//! snapshots/<source>/<time>/names      sealed file name index (names.rs; file trees)
//! snapshots/<source>/<time>/manifest   written last = commit point
//! badchunks                        chunks that failed verify (health.rs)
//! chunks/<hex[..4]>/<hex>.bad      a corrupt chunk moved aside
//! ```

use crate::clock::ComplianceClock;
use crate::crypto::{hex, invalid, parse_hex, ChunkId, Keyring};
use crate::names::{NameIndex, Sha256};
use crate::pipeline::{ChunkSink, Job};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, SystemTime};

/// Chunk size of fixed-size (block device) indexes: 4 MiB.
pub const IMAGE_CHUNK_SIZE: usize = 4 << 20;
/// Content-defined chunking (FastCDC) of file data: minimum chunk size, bytes.
pub const CDC_MIN: u32 = 128 << 10;
/// FastCDC average chunk size, bytes.
pub const CDC_AVG: u32 = 512 << 10;
/// FastCDC maximum chunk size, bytes.
pub const CDC_MAX: u32 = 4 << 20;
/// Longest backup duration `stats_line` reports (`secs`): 7 days.
pub const STATS_MAX_SECS: u64 = 7 * 86_400;

/// Tunables of a [`Store`], fixed at [`Store::open`].
pub struct Options {
    /// Lock every new snapshot gets (plan: 14 days).
    pub min_lock_secs: u64,
    /// Unreferenced chunks younger than this survive GC. Backups must commit
    /// within this window, otherwise their reused chunks can be swept.
    pub gc_grace_secs: u64,
    /// Above this share of deleted chunks a GC needs quorum approval.
    pub gc_max_delete_fraction: f64,
    /// Compliance clock forward slew (calibration knob, see clock.rs).
    pub clock_slew: f64,
    /// Threads that hash, compress, seal and write chunks while the caller
    /// reads the next ones (`store_image*`, `store_file*`, `insert_chunks_parallel`).
    /// 0 = `NEXUS_CHUNK_WORKERS` if set, else min(available cores, 8).
    pub chunk_workers: usize,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            min_lock_secs: 14 * 86400,
            gc_grace_secs: 86400,
            gc_max_delete_fraction: 0.2,
            clock_slew: crate::clock::DEFAULT_SLEW,
            chunk_workers: 0,
        }
    }
}

/// Chunk list of one stored object (a disk image or a file tree), sealed as
/// `snapshots/<source>/<time>/<name>.idx`. Variant order is part of the format.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum Index {
    /// Block device: chunk N covers offset `N * chunk_size`.
    Fixed {
        /// bytes per chunk (the last chunk may be shorter)
        chunk_size: u32,
        /// image size, bytes
        size: u64,
        /// chunk ids in offset order
        chunks: Vec<ChunkId>,
    },
    /// File tree.
    Dynamic {
        /// one entry per file
        entries: Vec<FileEntry>,
    },
    /// Host file tree with full metadata (agents, docs/agent-protocol.md). Appended
    /// last: postcard encodes the variant index, so older indexes still decode.
    Tree {
        /// one entry per path
        entries: Vec<TreeEntry>,
    },
}

/// Type of a [`TreeEntry`].
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum TreeKind {
    /// Regular file.
    File,
    /// Directory.
    Dir,
    /// Symbolic link (`link_target` holds the target).
    Symlink,
    /// Further name of an inode stored earlier in the tree (`link_target` holds that path; no chunks).
    Hardlink,
    /// Block or character device (`rdev`).
    Device,
    /// Named pipe.
    Fifo,
    /// Unix socket.
    Socket,
}

/// One entry of an [`Index::Tree`]: path, POSIX metadata and chunk list.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct TreeEntry {
    /// relative to the backed-up root, raw bytes
    pub path: Vec<u8>,
    /// entry type
    pub kind: TreeKind,
    /// POSIX mode bits (`st_mode`)
    pub mode: u32,
    /// numeric owner user id
    pub uid: u32,
    /// numeric owner group id
    pub gid: u32,
    /// plain bytes (0 for directories and hardlinks)
    pub size: u64,
    /// modification time, nanoseconds since the unix epoch
    pub mtime_ns: i64,
    /// inode change time, nanoseconds since the unix epoch
    pub ctime_ns: i64,
    /// inode number on the source (change detection, hardlinks)
    pub inode: u64,
    /// device number of device nodes
    pub rdev: u64,
    /// symlink target, or for a hardlink the path of the first name (raw bytes)
    pub link_target: Option<Vec<u8>>,
    /// extended attributes as (name, value), raw bytes
    pub xattrs: Vec<(Vec<u8>, Vec<u8>)>,
    /// keyed chunk IDs (the appliance maps the agent's plain hashes)
    pub chunks: Vec<ChunkId>,
    /// changed while read without a snapshot (fallback mode)
    pub inconsistent: bool,
}

/// One file of an [`Index::Dynamic`] tree.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct FileEntry {
    /// path relative to the backed-up root, `/`-separated
    pub path: String,
    /// POSIX mode bits
    pub mode: u32,
    /// plain bytes
    pub size: u64,
    /// modification time, unix seconds
    pub mtime: i64,
    /// chunk ids of the content, in order
    pub chunks: Vec<ChunkId>,
}

impl Index {
    /// Logical (plain) size: the image size, or the sum of the file sizes.
    pub fn size(&self) -> u64 {
        match self {
            Index::Fixed { size, .. } => *size,
            Index::Dynamic { entries } => entries.iter().map(|e| e.size).sum(),
            Index::Tree { entries } => entries.iter().map(|e| e.size).sum(),
        }
    }

    /// All chunk ids the index references, in order (duplicates included).
    pub fn chunk_ids(&self) -> Vec<&ChunkId> {
        match self {
            Index::Fixed { chunks, .. } => chunks.iter().collect(),
            Index::Dynamic { entries } => entries.iter().flat_map(|e| &e.chunks).collect(),
            Index::Tree { entries } => entries.iter().flat_map(|e| &e.chunks).collect(),
        }
    }
}

// ponytail: offsite/verify status live in the catalog, not in the immutable manifest.
/// Commit record of a snapshot (`snapshots/<source>/<time>/manifest`, sealed,
/// written last): which indexes exist and how long the snapshot is locked.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Manifest {
    /// tenant of the keyring that wrote it
    pub tenant: String,
    /// source name (a guest, agent, share, ...)
    pub source: String,
    /// snapshot time, unix seconds (also the directory name)
    pub time: u64,
    /// index names (`<name>.idx` files) in the snapshot
    pub indexes: Vec<String>,
    /// compliance clock time (unix seconds) before which the snapshot cannot be deleted;
    /// only ever extended
    pub lock_until: u64,
}

/// Result of `Store::store_file_stats`.
#[derive(Debug, Default)]
pub struct FileStats {
    /// chunk ids of the stream, in order
    pub chunks: Vec<ChunkId>,
    /// bytes read from the stream
    pub size: u64,
    /// chunks (and their plain bytes) that were not in the store before
    pub new_chunks: usize,
    /// plain bytes of the new chunks
    pub new_bytes: u64,
    /// sealed (compressed + encrypted) bytes written for those new chunks
    pub new_stored: u64,
}

/// Chunks new to the store, written through one `Store` handle since it was
/// opened (`Store::written`). A connector backs up one snapshot at a time, so
/// the difference before/after a snapshot is that snapshot's new data.
#[derive(Debug, Default, Clone, Copy, PartialEq)]
pub struct Written {
    /// number of new chunks
    pub chunks: u64,
    /// plain bytes of the new chunks
    pub plain: u64,
    /// sealed bytes on disk of the new chunks (after zstd + AEAD)
    pub stored: u64,
}

impl Written {
    /// Difference to an earlier reading of the same handle (`self - before`).
    pub fn since(self, before: Written) -> Written {
        Written {
            chunks: self.chunks - before.chunks,
            plain: self.plain - before.plain,
            stored: self.stored - before.stored,
        }
    }
}

/// Result of a [`Store::gc`] run.
#[derive(Debug, Default)]
pub struct GcStats {
    /// chunk files scanned
    pub total: usize,
    /// distinct chunks referenced by committed snapshots
    pub marked: usize,
    /// unreferenced chunks deleted
    pub deleted: usize,
    /// unreferenced chunks kept because they are younger than `gc_grace_secs`
    pub kept_grace: usize,
}

/// Result of [`Store::verify`].
#[derive(Debug, Default)]
pub struct VerifyReport {
    /// chunk files selected and fully re-read
    pub checked: usize,
    /// selected chunks that failed decryption or the hash check
    pub corrupt: Vec<ChunkId>,
    /// chunks referenced by a snapshot but without a file
    pub missing: Vec<ChunkId>,
}

/// Random access into a fixed index (restore / instant recovery), caching the last chunk.
pub struct ImageReader<'a> {
    store: &'a Store,
    chunk_size: u64,
    size: u64,
    chunks: &'a [ChunkId],
    cached: Option<(usize, Vec<u8>)>,
}

impl ImageReader<'_> {
    /// Image size, bytes.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Fills `buf` from image offset `off` (bytes). Fails with `InvalidInput` when
    /// the range ends beyond the image, or on an unreadable chunk.
    pub fn read_at(&mut self, off: u64, buf: &mut [u8]) -> io::Result<()> {
        if off.checked_add(buf.len() as u64).is_none_or(|e| e > self.size) {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "read beyond image end"));
        }
        let mut done = 0;
        while done < buf.len() {
            let pos = off + done as u64;
            let n = (pos / self.chunk_size) as usize;
            if self.cached.as_ref().is_none_or(|(c, _)| *c != n) {
                self.cached = Some((n, self.store.read_chunk(&self.chunks[n])?));
            }
            let data = &self.cached.as_ref().unwrap().1;
            let at = (pos % self.chunk_size) as usize;
            let k = (data.len() - at).min(buf.len() - done);
            buf[done..done + k].copy_from_slice(&data[at..at + k]);
            done += k;
        }
        Ok(())
    }
}

/// Streaming `Read` over a chunk list ([`Store::chunk_reader`]).
pub struct ChunkReader<'a> {
    store: &'a Store,
    ids: &'a [ChunkId],
    next: usize,
    buf: Vec<u8>,
    pos: usize,
}

impl Read for ChunkReader<'_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        while self.pos == self.buf.len() {
            let Some(id) = self.ids.get(self.next) else {
                return Ok(0);
            };
            self.buf = self.store.read_chunk(id)?;
            self.pos = 0;
            self.next += 1;
        }
        let n = out.len().min(self.buf.len() - self.pos);
        out[..n].copy_from_slice(&self.buf[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

/// One tenant's chunk store at `root` (layout in the module doc). Thread-safe;
/// open one per tenant and process.
pub struct Store {
    root: PathBuf,
    keys: Keyring,
    clock: std::sync::Arc<ComplianceClock>,
    opts: Options,
    // ponytail: one lock for exists/touch vs. sweep/unlink; per-prefix locks if contention shows.
    chunk_lock: Mutex<()>,
    meta_lock: Mutex<()>,
    dirty_dirs: Mutex<HashSet<PathBuf>>,
    written: Mutex<Written>,
    workers: usize,
    /// Phase 28 (`enable_file_hashes`): SHA-256 of files stored through this
    /// handle, by their chunk list; consumed by the next commit
    file_hashes: Mutex<Option<HashMap<[u8; 16], Sha256>>>,
    hash_stats: Mutex<Option<HashStats>>,
}

/// Where the file hashes of the last committed snapshot came from (`Store::take_hash_stats`).
#[derive(Debug, Default, Clone, Copy, PartialEq)]
pub struct HashStats {
    /// computed while the data was read (connector or agent)
    pub fresh: u64,
    /// same chunk list as in the previous snapshot of the source
    pub carried: u64,
    /// read back from the store (old agents, the first run with hashes)
    pub computed: u64,
    /// unreadable chunks: no hash recorded
    pub failed: u64,
}

impl std::fmt::Display for HashStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "file hashes: {} while reading, {} from the previous snapshot, {} read back from the store, {} failed",
            self.fresh, self.carried, self.computed, self.failed
        )
    }
}

/// Key of a file's chunk list in the hash cache (128-bit BLAKE3 prefix).
pub fn chunk_list_key(chunks: &[ChunkId]) -> [u8; 16] {
    let mut h = blake3::Hasher::new();
    h.update(&(chunks.len() as u64).to_le_bytes());
    for c in chunks {
        h.update(c);
    }
    h.finalize().as_bytes()[..16].try_into().expect("16 bytes")
}

/// A reader that hashes what passes through it (SHA-256).
struct ShaRead<R> {
    inner: R,
    h: Option<sha2::Sha256>,
}

impl<R: Read> Read for ShaRead<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        if let Some(h) = self.h.as_mut() {
            sha2::Digest::update(h, &buf[..n]);
        }
        Ok(n)
    }
}

pub(crate) fn sync_dir(dir: &Path) -> io::Result<()> {
    File::open(dir)?.sync_all()
}

/// tmp + fsync + rename + fsync(dir): the file is either old or new, never torn.
pub fn write_atomic(path: &Path, data: &[u8]) -> io::Result<()> {
    let tmp = path.with_extension(format!("tmp{}", rand::random::<u32>()));
    let mut f = File::create(&tmp)?;
    f.write_all(data)?;
    f.sync_all()?;
    fs::rename(&tmp, path)?;
    sync_dir(path.parent().unwrap())
}

/// Names become path components: allow only a safe charset.
fn check_name(s: &str) -> io::Result<()> {
    let ok = !s.is_empty()
        && s.len() <= 128
        && !s.starts_with('.')
        && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b));
    if ok {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid name {s:?}"),
        ))
    }
}

fn read_full(r: &mut impl Read, buf: &mut [u8]) -> io::Result<usize> {
    let mut n = 0;
    while n < buf.len() {
        match r.read(&mut buf[n..]) {
            Ok(0) => break,
            Ok(k) => n += k,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(n)
}

impl Store {
    /// Opens (creates if needed) the store at `root`. Fails if `keys` is not the
    /// keyring the store was created with (`keycheck`).
    pub fn open(root: impl Into<PathBuf>, keys: Keyring, opts: Options) -> io::Result<Self> {
        let root = root.into();
        fs::create_dir_all(root.join("chunks"))?;
        fs::create_dir_all(root.join("snapshots"))?;
        let check = root.join("keycheck");
        match fs::read(&check) {
            Ok(b) => {
                keys.open(b"keycheck", &b)
                    .map_err(|_| invalid("keyring does not match this store"))?;
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => write_atomic(&check, &keys.seal(b"keycheck", b"ok"))?,
            Err(e) => return Err(e),
        }
        // A crashed predecessor may have renamed chunks into place without syncing
        // their directories; we reuse such chunks without re-syncing, so flush once here.
        if unsafe { libc::syncfs(File::open(&root)?.as_raw_fd()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let clock = ComplianceClock::shared(root.join("clock"), opts.clock_slew)?;
        let workers = crate::pipeline::resolve_workers(opts.chunk_workers);
        Ok(Store {
            root,
            keys,
            clock,
            opts,
            chunk_lock: Mutex::new(()),
            meta_lock: Mutex::new(()),
            dirty_dirs: Mutex::new(HashSet::new()),
            written: Mutex::new(Written::default()),
            workers,
            file_hashes: Mutex::new(None),
            hash_stats: Mutex::new(None),
        })
    }

    /// Insert threads used per pipeline (`Options::chunk_workers`, resolved).
    pub fn chunk_workers(&self) -> usize {
        self.workers
    }

    /// Inserts chunks on `chunk_workers()` threads while `produce` keeps
    /// reading on the calling thread: it pushes each chunk's data in order into
    /// the sink. Returns (id, sealed bytes written or 0 if the chunk existed)
    /// per chunk in push order; the first error (of `produce` or a worker)
    /// stops the pipeline and is returned. See pipeline.rs.
    pub fn insert_chunks_parallel<E: From<io::Error> + Send>(
        &self,
        produce: impl FnOnce(&mut ChunkSink<'_, '_, E>) -> Result<(), E>,
    ) -> Result<Vec<(ChunkId, u64)>, E> {
        crate::pipeline::run(self, self.workers, produce)
    }

    /// The tenant keyring of this store.
    pub fn keys(&self) -> &Keyring {
        &self.keys
    }

    /// Decodes a sealed manifest / index file of `source/time` (offsite copies).
    pub fn decode_manifest(&self, source: &str, time: u64, sealed: &[u8]) -> io::Result<Manifest> {
        let ctx = format!("manifest:{source}/{time}");
        postcard::from_bytes(&self.keys.open(ctx.as_bytes(), sealed)?.1).map_err(invalid_ser)
    }

    /// Decodes a sealed index file `name` of `source/time` (offsite copies).
    pub fn decode_index(&self, source: &str, time: u64, name: &str, sealed: &[u8]) -> io::Result<Index> {
        let ctx = format!("index:{source}/{time}/{name}");
        postcard::from_bytes(&self.keys.open(ctx.as_bytes(), sealed)?.1).map_err(invalid_ser)
    }

    /// Current compliance clock time, unix seconds (retention locks).
    pub fn compliance_now(&self) -> io::Result<u64> {
        self.clock.now()
    }

    pub(crate) fn root(&self) -> &Path {
        &self.root
    }

    pub(crate) fn chunk_lock(&self) -> std::sync::MutexGuard<'_, ()> {
        self.chunk_lock.lock().unwrap()
    }

    pub(crate) fn chunk_path(&self, id: &ChunkId) -> PathBuf {
        let h = hex(id);
        self.root.join("chunks").join(&h[..4]).join(h)
    }

    /// Bumps mtime so a running GC sees the chunk as fresh. Caller holds chunk_lock.
    fn touch(path: &Path) -> io::Result<bool> {
        match File::options().write(true).open(path) {
            Ok(f) => f.set_modified(SystemTime::now()).map(|_| true),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// Returns (chunk id, newly stored).
    pub fn insert_chunk(&self, data: &[u8]) -> io::Result<(ChunkId, bool)> {
        let (id, stored) = self.insert_chunk_stored(data)?;
        Ok((id, stored > 0))
    }

    /// Like `insert_chunk`; returns the sealed size written, 0 if the chunk existed.
    pub fn insert_chunk_stored(&self, data: &[u8]) -> io::Result<(ChunkId, u64)> {
        let id = self.keys.chunk_id(data);
        let mut stored = 0;
        let new = self.store_sealed(&id, || {
            let s = self.keys.seal_chunk(&id, data);
            stored = s.len() as u64;
            Ok(s)
        })?;
        if !new {
            return Ok((id, 0));
        }
        let mut w = self.written.lock().unwrap();
        w.chunks += 1;
        w.plain += data.len() as u64;
        w.stored += stored;
        Ok((id, stored))
    }

    /// Totals of the chunks this handle added to the store (see `Written`).
    pub fn written(&self) -> Written {
        *self.written.lock().unwrap()
    }

    /// The connectors' machine-readable per-snapshot line (docs/storage-accounting.md):
    /// `nexus-stats {"source","time","read","logical","new_chunks","new_plain","new_stored"}`.
    /// `read` = bytes read from the source, `logical` = the snapshot's size (sum of
    /// its indexes), `new` = `written().since(<before the snapshot>)`. Phase 30:
    /// `secs` = seconds from the snapshot time (taken when the backup started) to
    /// this line, the backup's duration; left out when the snapshot time lies in
    /// the future or more than [`STATS_MAX_SECS`] back (imports, tests).
    pub fn stats_line(&self, m: &Manifest, read: u64, new: Written) -> io::Result<String> {
        let mut logical = 0;
        for i in &m.indexes {
            logical += self.load_index(m, i)?.size();
        }
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let secs = now
            .checked_sub(m.time)
            .filter(|s| *s <= STATS_MAX_SECS)
            .map_or_else(String::new, |s| format!(",\"secs\":{s}"));
        // source names pass check_name(): no JSON escaping needed
        Ok(format!(
            "nexus-stats {{\"source\":\"{}\",\"time\":{},\"read\":{read},\"logical\":{logical},\"new_chunks\":{},\"new_plain\":{},\"new_stored\":{}{secs}}}",
            m.source, m.time, new.chunks, new.plain, new.stored
        ))
    }

    /// Inserts an already sealed chunk (offsite restore / DR). It is fully
    /// verified (AEAD + keyed hash) before it is accepted.
    pub fn insert_chunk_raw(&self, id: &ChunkId, sealed: &[u8]) -> io::Result<bool> {
        self.store_sealed(id, || {
            self.keys.open_chunk(id, sealed)?;
            Ok(sealed.to_vec())
        })
    }

    /// The sealed bytes of a chunk exactly as stored (offsite packs).
    pub fn read_chunk_raw(&self, id: &ChunkId) -> io::Result<Vec<u8>> {
        fs::read(self.chunk_path(id))
    }

    fn store_sealed(&self, id: &ChunkId, sealed: impl FnOnce() -> io::Result<Vec<u8>>) -> io::Result<bool> {
        let path = self.chunk_path(id);
        {
            let _g = self.chunk_lock.lock().unwrap();
            if Self::touch(&path)? {
                return Ok(false);
            }
        }
        // seal + write outside the lock; only the rename is serialized against GC
        let sealed = sealed()?;
        let dir = path.parent().unwrap();
        fs::create_dir_all(dir)?;
        // create_new: two workers storing the same chunk never share a temp file
        let (tmp, mut f) = loop {
            let tmp = dir.join(format!("{}.tmp{}", hex(id), rand::random::<u32>()));
            match File::options().write(true).create_new(true).open(&tmp) {
                Ok(f) => break (tmp, f),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e),
            }
        };
        f.write_all(&sealed)?;
        f.sync_all()?;
        let _g = self.chunk_lock.lock().unwrap();
        if Self::touch(&path)? {
            fs::remove_file(&tmp)?;
            return Ok(false);
        }
        fs::rename(&tmp, &path)?;
        self.dirty_dirs.lock().unwrap().insert(dir.to_owned());
        Ok(true)
    }

    /// Whether the chunk file exists (no verification).
    pub fn has_chunk(&self, id: &ChunkId) -> bool {
        self.chunk_path(id).exists()
    }

    /// Reuse of a chunk that is referenced only by ID (e.g. via the agent mapping
    /// index): true if it exists, and its mtime is bumped under the chunk lock so
    /// a concurrent GC treats it as fresh until the referencing snapshot commits.
    pub fn touch_chunk(&self, id: &ChunkId) -> io::Result<bool> {
        let _g = self.chunk_lock.lock().unwrap();
        Self::touch(&self.chunk_path(id))
    }

    /// Random-access reader over a fixed index; fails for other index kinds.
    pub fn image_reader<'a>(&'a self, index: &'a Index) -> io::Result<ImageReader<'a>> {
        let Index::Fixed {
            chunk_size,
            size,
            chunks,
        } = index
        else {
            return Err(invalid("not a fixed index"));
        };
        Ok(ImageReader {
            store: self,
            chunk_size: *chunk_size as u64,
            size: *size,
            chunks,
            cached: None,
        })
    }

    /// Reads, decrypts and verifies one chunk.
    pub fn read_chunk(&self, id: &ChunkId) -> io::Result<Vec<u8>> {
        self.keys.open_chunk(id, &fs::read(self.chunk_path(id))?)
    }

    /// Fixed-size chunking of a block device / image.
    pub fn store_image(&self, mut r: impl Read, chunk_size: usize) -> io::Result<Index> {
        let mut size = 0u64;
        let chunks = self.insert_chunks_parallel::<io::Error>(|sink| loop {
            let mut buf = sink.buffer(chunk_size);
            let n = read_full(&mut r, &mut buf)?;
            if n == 0 {
                return Ok(());
            }
            buf.truncate(n);
            sink.push(buf)?;
            size += n as u64;
        })?;
        Ok(Index::Fixed {
            chunk_size: chunk_size as u32,
            size,
            chunks: chunks.into_iter().map(|(id, _)| id).collect(),
        })
    }

    /// Incremental-forever for block devices. `dirty` = sorted, non-overlapping
    /// `(offset, len)` extents of the QEMU dirty bitmap. Only dirty bytes (plus any
    /// area beyond the previous size) are read via `read_at`: PVE snapshot-access
    /// exports refuse reads of clean areas. Clean parts of a partly dirty chunk are
    /// taken from the previous snapshot's chunk. `prev = None` reads everything.
    ///
    /// `read_at` runs on the calling thread, in offset order, one call per read
    /// range; the chunks go to `chunk_workers()` threads (pipeline.rs) that also
    /// do the merge with the previous chunk (decrypt + verify of the base), so
    /// the reads keep streaming while earlier chunks are sealed and written.
    pub fn store_image_extents(
        &self,
        prev: Option<&Index>,
        chunk_size: usize,
        size: u64,
        dirty: &[(u64, u64)],
        mut read_at: impl FnMut(u64, &mut [u8]) -> io::Result<()>,
    ) -> io::Result<Index> {
        let (prev_size, prev_chunks) = match prev {
            Some(Index::Fixed {
                chunk_size: c,
                size,
                chunks,
            }) if *c as usize == chunk_size => (*size, chunks.as_slice()),
            Some(_) => return Err(invalid("previous index is not a fixed index with the same chunk size")),
            None => (0, &[][..]),
        };
        let cs = chunk_size as u64;
        // Ok(id): reused from the previous index; Err(n): n-th chunk handed to the workers
        let mut plan: Vec<Result<ChunkId, usize>> = Vec::with_capacity(size.div_ceil(cs) as usize);
        let stored = self.insert_chunks_parallel::<io::Error>(|sink| {
            let mut i = 0;
            for n in 0..size.div_ceil(cs) {
                let (start, end) = (n * cs, ((n + 1) * cs).min(size));
                let reads = chunk_reads(dirty, &mut i, start, end, prev_size);
                let base = prev_chunks.get(n as usize);
                if reads.is_empty() && ((n + 1) * cs).min(prev_size) == end {
                    plan.push(Ok(*base.unwrap()));
                    continue;
                }
                let len = (end - start) as usize;
                let mut buf = sink.buffer(len);
                let (mut holes, mut at) = (Vec::new(), 0);
                for (a, b) in reads {
                    let (a, b) = ((a - start) as usize, (b - start) as usize);
                    read_at(start + a as u64, &mut buf[a..b])?;
                    if at < a {
                        holes.push((at, a));
                    }
                    at = b;
                }
                if at < len {
                    holes.push((at, len));
                }
                plan.push(Err(sink.feed(Job {
                    buf,
                    holes,
                    base: base.copied(),
                })?));
            }
            Ok(())
        })?;
        Ok(Index::Fixed {
            chunk_size: chunk_size as u32,
            size,
            chunks: plan.into_iter().map(|c| c.unwrap_or_else(|k| stored[k].0)).collect(),
        })
    }

    /// Bytes [`Store::store_image_extents`] reads through `read_at` for these
    /// arguments (live progress: the total of a disk before it is read).
    pub fn image_extents_bytes(prev: Option<&Index>, chunk_size: usize, size: u64, dirty: &[(u64, u64)]) -> u64 {
        Self::image_extents_reads(prev, chunk_size, size, dirty)
            .iter()
            .map(|(a, b)| b - a)
            .sum()
    }

    /// The `(start, end)` ranges [`Store::store_image_extents`] passes to `read_at`, in
    /// call order (a reader can fetch them ahead, e.g. pipelined NBD requests).
    pub fn image_extents_reads(
        prev: Option<&Index>,
        chunk_size: usize,
        size: u64,
        dirty: &[(u64, u64)],
    ) -> Vec<(u64, u64)> {
        let prev_size = match prev {
            Some(Index::Fixed { size, .. }) => *size,
            _ => 0,
        };
        let cs = chunk_size.max(1) as u64;
        let mut i = 0;
        (0..size.div_ceil(cs))
            .flat_map(|n| chunk_reads(dirty, &mut i, n * cs, ((n + 1) * cs).min(size), prev_size))
            .collect()
    }

    /// FastCDC chunking of one file; returns (chunks, size).
    pub fn store_file(&self, r: impl Read) -> io::Result<(Vec<ChunkId>, u64)> {
        let s = self.store_file_stats(r)?;
        Ok((s.chunks, s.size))
    }

    /// Like `store_file`, also counting the chunks that were not in the store yet.
    /// A file of more than one chunk is inserted on `chunk_workers()` threads
    /// while the next chunks are read (pipeline.rs); a one-chunk file inline.
    pub fn store_file_stats(&self, r: impl Read) -> io::Result<FileStats> {
        let hashing = self.file_hashes.lock().unwrap().is_some();
        let mut r = ShaRead {
            inner: r,
            h: hashing.then(<sha2::Sha256 as sha2::Digest>::new),
        };
        let s = self.store_file_inner(&mut r)?;
        if let Some(h) = r.h.take() {
            self.record_file_hash(&s.chunks, sha2::Digest::finalize(h).into());
        }
        Ok(s)
    }

    fn store_file_inner(&self, r: impl Read) -> io::Result<FileStats> {
        let mut cdc = fastcdc::v2020::StreamCDC::new(r, CDC_MIN, CDC_AVG, CDC_MAX);
        let mut next = || cdc.next().transpose().map_err(io::Error::other);
        let mut lens = Vec::new();
        let ids = match (next()?, next()?) {
            (None, _) => Vec::new(),
            (Some(c), None) => {
                lens.push(c.length);
                vec![self.insert_chunk_stored(&c.data)?]
            }
            (Some(a), Some(b)) => self.insert_chunks_parallel::<io::Error>(|sink| {
                let mut c = Some(a);
                let mut pending = Some(b);
                while let Some(chunk) = c {
                    lens.push(chunk.length);
                    sink.push(chunk.data)?;
                    c = match pending.take() {
                        Some(p) => Some(p),
                        None => next()?,
                    };
                }
                Ok(())
            })?,
        };
        let mut s = FileStats::default();
        for ((id, stored), len) in ids.into_iter().zip(lens) {
            s.chunks.push(id);
            s.size += len as u64;
            if stored > 0 {
                s.new_chunks += 1;
                s.new_bytes += len as u64;
                s.new_stored += stored;
            }
        }
        Ok(s)
    }

    /// Writes the plaintext of `ids` to `w` in order (each chunk verified).
    pub fn write_chunks<'a>(&self, ids: impl IntoIterator<Item = &'a ChunkId>, mut w: impl Write) -> io::Result<()> {
        for id in ids {
            w.write_all(&self.read_chunk(id)?)?;
        }
        Ok(())
    }

    /// Streaming `Read` over a chunk list (one decrypted chunk in memory at a time).
    pub fn chunk_reader<'a>(&'a self, ids: &'a [ChunkId]) -> ChunkReader<'a> {
        ChunkReader {
            store: self,
            ids,
            next: 0,
            buf: Vec::new(),
            pos: 0,
        }
    }

    pub(crate) fn meta_lock(&self) -> std::sync::MutexGuard<'_, ()> {
        self.meta_lock.lock().unwrap()
    }

    pub(crate) fn snap_dir(&self, source: &str, time: u64) -> PathBuf {
        self.root.join("snapshots").join(source).join(time.to_string())
    }

    fn write_manifest(&self, m: &Manifest) -> io::Result<()> {
        let ctx = format!("manifest:{}/{}", m.source, m.time);
        let blob = self
            .keys
            .seal(ctx.as_bytes(), &postcard::to_stdvec(m).map_err(invalid_ser)?);
        write_atomic(&self.snap_dir(&m.source, m.time).join("manifest"), &blob)
    }

    /// Phase 28: record the SHA-256 of every regular file in the name index of
    /// the snapshots committed through this handle (group option
    /// `file_hashes`). Files stored with `store_file*` are hashed while read;
    /// [`Self::record_file_hash`] adds hashes computed elsewhere (agents); the
    /// rest come from the previous snapshot of the source (same chunk list) or
    /// are read back from the store.
    pub fn enable_file_hashes(&self) {
        self.file_hashes.lock().unwrap().get_or_insert_with(HashMap::new);
    }

    /// Whether [`Self::enable_file_hashes`] was called on this handle.
    pub fn file_hashes_enabled(&self) -> bool {
        self.file_hashes.lock().unwrap().is_some()
    }

    /// The SHA-256 of a file with these (keyed) chunks, for the next commit.
    /// Ignored unless hashing is enabled.
    pub fn record_file_hash(&self, chunks: &[ChunkId], sha: Sha256) {
        if let Some(m) = self.file_hashes.lock().unwrap().as_mut() {
            m.insert(chunk_list_key(chunks), sha);
        }
    }

    /// Where the hashes of the last commit came from (`None`: hashing off or no file tree).
    pub fn take_hash_stats(&self) -> Option<HashStats> {
        self.hash_stats.lock().unwrap().take()
    }

    /// Hashes of the newest earlier snapshot of `source`, by chunk list.
    fn previous_hashes(&self, source: &str, time: u64) -> io::Result<HashMap<[u8; 16], Sha256>> {
        let mut out = HashMap::new();
        let prev = match fs::read_dir(self.root.join("snapshots").join(source)) {
            Ok(rd) => rd
                .filter_map(|e| e.ok()?.file_name().to_str()?.parse::<u64>().ok())
                .filter(|t| *t < time && self.snap_dir(source, *t).join("manifest").exists())
                .max(),
            Err(e) if e.kind() == io::ErrorKind::NotFound => None,
            Err(e) => return Err(e),
        };
        let Some(t) = prev else { return Ok(out) };
        let m = self.load_manifest(source, t)?;
        let Some(names) = self.load_names(&m)?.filter(super::names::NameIndex::has_hashes) else {
            return Ok(out);
        };
        let by_path: HashMap<&str, &Sha256> = names.hashed().map(|(p, _, h)| (p, h)).collect();
        for name in &m.indexes {
            if let Index::Tree { entries } = self.load_index(&m, name)? {
                for e in entries.iter().filter(|e| e.kind == TreeKind::File) {
                    let raw = String::from_utf8_lossy(&e.path);
                    let p = crate::names::normalise(&raw);
                    if let Some(h) = by_path.get(&*p) {
                        out.insert(chunk_list_key(&e.chunks), **h);
                    }
                }
            }
        }
        Ok(out)
    }

    /// The name index of a new snapshot, with file hashes when enabled.
    fn names_for_commit(&self, source: &str, time: u64, indexes: &[(&str, Index)]) -> io::Result<Option<NameIndex>> {
        let plain = || NameIndex::from_indexes(indexes.iter().map(|(n, i)| (*n, i)));
        *self.hash_stats.lock().unwrap() = None;
        let Some(fresh) = self.file_hashes.lock().unwrap().as_mut().map(std::mem::take) else {
            return Ok(plain());
        };
        if !indexes.iter().any(|(_, i)| matches!(i, Index::Tree { .. })) {
            return Ok(plain());
        }
        let prev = self.previous_hashes(source, time)?;
        let mut st = HashStats::default();
        let names = NameIndex::from_indexes_hashed(indexes.iter().map(|(n, i)| (*n, i)), &mut |e| {
            if e.chunks.is_empty() {
                return Ok((e.size == 0).then_some(crate::names::EMPTY_SHA256));
            }
            let k = chunk_list_key(&e.chunks);
            if let Some(h) = fresh.get(&k) {
                st.fresh += 1;
                return Ok(Some(*h));
            }
            if let Some(h) = prev.get(&k) {
                st.carried += 1;
                return Ok(Some(*h));
            }
            let mut h = <sha2::Sha256 as sha2::Digest>::new();
            for id in &e.chunks {
                match self.read_chunk(id) {
                    Ok(d) => sha2::Digest::update(&mut h, &d),
                    Err(_) => {
                        st.failed += 1;
                        return Ok(None);
                    }
                }
            }
            st.computed += 1;
            Ok(Some(sha2::Digest::finalize(h).into()))
        })?;
        *self.hash_stats.lock().unwrap() = Some(st);
        Ok(names)
    }

    /// Commits a snapshot. All chunks were inserted before; their directory
    /// entries are made durable first, then indexes, then the manifest.
    pub fn commit_snapshot(&self, source: &str, time: u64, indexes: &[(&str, Index)]) -> io::Result<Manifest> {
        check_name(source)?;
        indexes.iter().try_for_each(|(n, _)| check_name(n))?;
        let dir = self.snap_dir(source, time);
        if dir.join("manifest").exists() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("snapshot {source}/{time} exists"),
            ));
        }
        fs::create_dir_all(&dir)?;
        sync_dir(&self.root.join("snapshots"))?; // entry of a new <source> dir
        let dirty: Vec<_> = self.dirty_dirs.lock().unwrap().drain().collect();
        dirty.iter().try_for_each(|d| sync_dir(d))?;
        sync_dir(&self.root.join("chunks"))?;
        for (name, idx) in indexes {
            let ctx = format!("index:{source}/{time}/{name}");
            let blob = self
                .keys
                .seal(ctx.as_bytes(), &postcard::to_stdvec(idx).map_err(invalid_ser)?);
            write_atomic(&dir.join(format!("{name}.idx")), &blob)?;
        }
        if let Some(names) = self.names_for_commit(source, time, indexes)? {
            self.write_names(source, time, &names)?;
        }
        let m = Manifest {
            tenant: self.keys.tenant().to_owned(),
            source: source.to_owned(),
            time,
            indexes: indexes.iter().map(|(n, _)| n.to_string()).collect(),
            lock_until: self.clock.now()? + self.opts.min_lock_secs,
        };
        self.write_manifest(&m)?;
        sync_dir(dir.parent().unwrap())?;
        Ok(m)
    }

    /// Sealed files of a committed snapshot, manifest last: `(file name, bytes)`.
    pub fn snapshot_raw_files(&self, m: &Manifest) -> io::Result<Vec<(String, Vec<u8>)>> {
        let dir = self.snap_dir(&m.source, m.time);
        let mut out = Vec::new();
        for name in &m.indexes {
            let f = format!("{name}.idx");
            out.push((f.clone(), fs::read(dir.join(&f))?));
        }
        out.push(("manifest".into(), fs::read(dir.join("manifest"))?));
        Ok(out)
    }

    /// Imports a snapshot from sealed files (offsite restore / DR). Every file
    /// is verified before anything is written; the manifest is written last.
    /// The imported manifest keeps its lock; chunks must be inserted separately.
    pub fn import_snapshot_raw(&self, source: &str, time: u64, files: &[(String, Vec<u8>)]) -> io::Result<Manifest> {
        check_name(source)?;
        let raw = |name: &str| {
            files
                .iter()
                .find(|(n, _)| n == name)
                .map(|(_, b)| b)
                .ok_or_else(|| invalid(format!("snapshot file {name} missing")))
        };
        let ctx = format!("manifest:{source}/{time}");
        let m: Manifest =
            postcard::from_bytes(&self.keys.open(ctx.as_bytes(), raw("manifest")?)?.1).map_err(invalid_ser)?;
        for name in &m.indexes {
            check_name(name)?;
            let ctx = format!("index:{source}/{time}/{name}");
            self.keys.open(ctx.as_bytes(), raw(&format!("{name}.idx"))?)?;
        }
        let dir = self.snap_dir(source, time);
        if dir.join("manifest").exists() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("snapshot {source}/{time} exists"),
            ));
        }
        fs::create_dir_all(&dir)?;
        sync_dir(&self.root.join("snapshots"))?;
        for name in &m.indexes {
            write_atomic(&dir.join(format!("{name}.idx")), raw(&format!("{name}.idx"))?)?;
        }
        write_atomic(&dir.join("manifest"), raw("manifest")?)?;
        sync_dir(dir.parent().unwrap())?;
        Ok(m)
    }

    /// Loads and opens the manifest of `source/time`.
    pub fn load_manifest(&self, source: &str, time: u64) -> io::Result<Manifest> {
        check_name(source)?;
        let ctx = format!("manifest:{source}/{time}");
        let blob = fs::read(self.snap_dir(source, time).join("manifest"))?;
        postcard::from_bytes(&self.keys.open(ctx.as_bytes(), &blob)?.1).map_err(invalid_ser)
    }

    /// Loads and opens index `name` of the snapshot `m`.
    pub fn load_index(&self, m: &Manifest, name: &str) -> io::Result<Index> {
        check_name(name)?;
        let ctx = format!("index:{}/{}/{name}", m.source, m.time);
        let blob = fs::read(self.snap_dir(&m.source, m.time).join(format!("{name}.idx")))?;
        postcard::from_bytes(&self.keys.open(ctx.as_bytes(), &blob)?.1).map_err(invalid_ser)
    }

    /// Committed snapshots only (directories without manifest are aborted backups).
    pub fn list_snapshots(&self) -> io::Result<Vec<Manifest>> {
        let mut out = Vec::new();
        for src in fs::read_dir(self.root.join("snapshots"))? {
            let src = src?;
            let Some(source) = src.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            for t in fs::read_dir(src.path())? {
                let t = t?;
                let Some(time) = t.file_name().to_str().and_then(|s| s.parse().ok()) else {
                    continue;
                };
                if t.path().join("manifest").exists() {
                    out.push(self.load_manifest(&source, time)?);
                }
            }
        }
        out.sort_by(|a, b| (&a.source, a.time).cmp(&(&b.source, b.time)));
        Ok(out)
    }

    /// Locks can only grow. Returns the effective lock.
    pub fn extend_lock(&self, source: &str, time: u64, until: u64) -> io::Result<u64> {
        let _g = self.meta_lock.lock().unwrap();
        let mut m = self.load_manifest(source, time)?;
        if until > m.lock_until {
            m.lock_until = until;
            self.write_manifest(&m)?;
        }
        Ok(m.lock_until)
    }

    /// Refused while the compliance clock is before `lock_until`, for everyone.
    pub fn delete_snapshot(&self, source: &str, time: u64) -> io::Result<()> {
        let _g = self.meta_lock.lock().unwrap();
        let m = self.load_manifest(source, time)?;
        let now = self.clock.now()?;
        if now < m.lock_until {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "snapshot {source}/{time} locked for {} more seconds",
                    m.lock_until - now
                ),
            ));
        }
        let dir = self.snap_dir(source, time);
        fs::remove_file(dir.join("manifest"))?;
        sync_dir(&dir)?;
        fs::remove_dir_all(&dir)
    }

    /// Applies GFS retention to one source: kept snapshots get their locks
    /// extended per class, the rest are deleted unless still locked.
    /// Returns (kept, deleted, still_locked).
    pub fn apply_retention(&self, source: &str, gfs: &crate::retention::Gfs) -> io::Result<(usize, usize, usize)> {
        self.apply_retention_held(source, gfs, &BTreeSet::new())
    }

    /// [`Self::apply_retention`] that never deletes the snapshots at `held`
    /// times (legal holds, kept in the catalog): they count as kept, their
    /// locks are only extended when GFS keeps them anyway, and they still take
    /// part in the GFS selection (a held snapshot may be the daily one).
    pub fn apply_retention_held(
        &self,
        source: &str,
        gfs: &crate::retention::Gfs,
        held: &BTreeSet<u64>,
    ) -> io::Result<(usize, usize, usize)> {
        let snaps: Vec<Manifest> = self
            .list_snapshots()?
            .into_iter()
            .filter(|m| m.source == source)
            .collect();
        let keep = crate::retention::keep(&snaps.iter().map(|m| m.time).collect::<Vec<_>>(), gfs);
        let (mut deleted, mut locked, mut held_only) = (0, 0, 0);
        for m in &snaps {
            match keep.get(&m.time) {
                Some(classes) => {
                    self.extend_lock(source, m.time, crate::retention::lock_until(m.time, classes))?;
                }
                None if held.contains(&m.time) => held_only += 1,
                None => match self.delete_snapshot(source, m.time) {
                    Ok(()) => deleted += 1,
                    Err(e) if e.kind() == io::ErrorKind::PermissionDenied => locked += 1,
                    Err(e) => return Err(e),
                },
            }
        }
        Ok((keep.len() + held_only, deleted, locked))
    }

    /// All chunk IDs referenced by committed snapshots. Any unreadable
    /// manifest or index is an error: never sweep on an incomplete mark.
    pub(crate) fn mark(&self) -> io::Result<HashSet<ChunkId>> {
        let mut marked = HashSet::new();
        for m in self.list_snapshots()? {
            for name in &m.indexes {
                marked.extend(self.load_index(&m, name)?.chunk_ids().into_iter().copied());
            }
        }
        Ok(marked)
    }

    fn for_each_chunk_file(&self, mut f: impl FnMut(PathBuf, &str, SystemTime) -> io::Result<()>) -> io::Result<()> {
        for d in fs::read_dir(self.root.join("chunks"))? {
            for e in fs::read_dir(d?.path())? {
                let e = e?;
                let Some(name) = e.file_name().to_str().map(str::to_owned) else {
                    continue;
                };
                f(e.path(), &name, e.metadata()?.modified()?)?;
            }
        }
        Ok(())
    }

    /// Mark-and-sweep with grace period. `approved` = quorum approval for
    /// deleting more than `gc_max_delete_fraction` of all chunks.
    pub fn gc(&self, approved: bool) -> io::Result<GcStats> {
        let cutoff = SystemTime::now() - Duration::from_secs(self.opts.gc_grace_secs);
        let marked = self.mark()?;
        let mut st = GcStats {
            marked: marked.len(),
            ..Default::default()
        };
        let mut candidates = Vec::new();
        self.for_each_chunk_file(|path, name, mtime| {
            if name.contains(".tmp") {
                if mtime < cutoff {
                    fs::remove_file(&path)?; // leftover of a crashed write
                }
                return Ok(());
            }
            let Some(id) = parse_hex(name) else { return Ok(()) };
            st.total += 1;
            if !marked.contains(&id) {
                if mtime < cutoff {
                    candidates.push(path);
                } else {
                    st.kept_grace += 1;
                }
            }
            Ok(())
        })?;
        if !approved && candidates.len() as f64 > st.total as f64 * self.opts.gc_max_delete_fraction {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "GC would delete {} of {} chunks: quorum approval required",
                    candidates.len(),
                    st.total
                ),
            ));
        }
        for path in candidates {
            let _g = self.chunk_lock.lock().unwrap();
            // re-check: a backup may have reused (touched) it since the scan
            match fs::metadata(&path).and_then(|m| m.modified()) {
                Ok(mtime) if mtime < cutoff => {
                    fs::remove_file(&path)?;
                    st.deleted += 1;
                }
                Ok(_) => st.kept_grace += 1,
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
        }
        Ok(st)
    }

    /// Reports referenced-but-missing chunks and fully re-reads the chunks
    /// selected by `select` (e.g. `|id| id[0] % weeks == week` for rolling verify).
    pub fn verify(&self, select: impl Fn(&ChunkId) -> bool) -> io::Result<VerifyReport> {
        let mut r = VerifyReport::default();
        for id in self.mark()? {
            if !self.chunk_path(&id).exists() {
                r.missing.push(id);
            }
        }
        self.for_each_chunk_file(|_, name, _| {
            if let Some(id) = parse_hex(name).filter(|id| select(id)) {
                r.checked += 1;
                if self.read_chunk(&id).is_err() {
                    r.corrupt.push(id);
                }
            }
            Ok(())
        })?;
        Ok(r)
    }
}

fn invalid_ser(e: postcard::Error) -> io::Error {
    invalid(format!("serialization: {e}"))
}

/// The ranges of chunk `start..end` read from the source: its dirty extents
/// below the previous size plus everything beyond it (grown disk / no base),
/// without overlap. `i` = first extent that may touch the chunk (advanced).
fn chunk_reads(dirty: &[(u64, u64)], i: &mut usize, start: u64, end: u64, prev_size: u64) -> Vec<(u64, u64)> {
    while *i < dirty.len() && dirty[*i].0 + dirty[*i].1 <= start {
        *i += 1;
    }
    let grown = prev_size.clamp(start, end);
    let mut reads: Vec<(u64, u64)> = dirty[*i..]
        .iter()
        .take_while(|e| e.0 < grown)
        .map(|&(o, l)| (o.max(start), (o + l).min(grown)))
        .filter(|(a, b)| a < b)
        .collect();
    if grown < end {
        reads.push((grown, end));
    }
    reads
}
