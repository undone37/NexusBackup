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
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashSet};
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, SystemTime};

pub const IMAGE_CHUNK_SIZE: usize = 4 << 20;
pub const CDC_MIN: u32 = 128 << 10;
pub const CDC_AVG: u32 = 512 << 10;
pub const CDC_MAX: u32 = 4 << 20;

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
}

impl Default for Options {
    fn default() -> Self {
        Options {
            min_lock_secs: 14 * 86400,
            gc_grace_secs: 86400,
            gc_max_delete_fraction: 0.2,
            clock_slew: crate::clock::DEFAULT_SLEW,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum Index {
    /// Block device: chunk N covers offset `N * chunk_size`.
    Fixed {
        chunk_size: u32,
        size: u64,
        chunks: Vec<ChunkId>,
    },
    /// File tree.
    Dynamic { entries: Vec<FileEntry> },
    /// Host file tree with full metadata (agents, docs/agent-protocol.md). Appended
    /// last: postcard encodes the variant index, so older indexes still decode.
    Tree { entries: Vec<TreeEntry> },
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum TreeKind {
    File,
    Dir,
    Symlink,
    Hardlink,
    Device,
    Fifo,
    Socket,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct TreeEntry {
    /// relative to the backed-up root, raw bytes
    pub path: Vec<u8>,
    pub kind: TreeKind,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub size: u64,
    pub mtime_ns: i64,
    pub ctime_ns: i64,
    pub inode: u64,
    pub rdev: u64,
    pub link_target: Option<Vec<u8>>,
    pub xattrs: Vec<(Vec<u8>, Vec<u8>)>,
    /// keyed chunk IDs (the appliance maps the agent's plain hashes)
    pub chunks: Vec<ChunkId>,
    /// changed while read without a snapshot (fallback mode)
    pub inconsistent: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct FileEntry {
    pub path: String,
    pub mode: u32,
    pub size: u64,
    pub mtime: i64,
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

    pub fn chunk_ids(&self) -> Vec<&ChunkId> {
        match self {
            Index::Fixed { chunks, .. } => chunks.iter().collect(),
            Index::Dynamic { entries } => entries.iter().flat_map(|e| &e.chunks).collect(),
            Index::Tree { entries } => entries.iter().flat_map(|e| &e.chunks).collect(),
        }
    }
}

// ponytail: offsite/verify status live in the catalog, not in the immutable manifest.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Manifest {
    pub tenant: String,
    pub source: String,
    pub time: u64,
    pub indexes: Vec<String>,
    pub lock_until: u64,
}

/// Result of `Store::store_file_stats`.
#[derive(Debug, Default)]
pub struct FileStats {
    pub chunks: Vec<ChunkId>,
    /// bytes read from the stream
    pub size: u64,
    /// chunks (and their plain bytes) that were not in the store before
    pub new_chunks: usize,
    pub new_bytes: u64,
    /// sealed (compressed + encrypted) bytes written for those new chunks
    pub new_stored: u64,
}

/// Chunks new to the store, written through one `Store` handle since it was
/// opened (`Store::written`). A connector backs up one snapshot at a time, so
/// the difference before/after a snapshot is that snapshot's new data.
#[derive(Debug, Default, Clone, Copy, PartialEq)]
pub struct Written {
    pub chunks: u64,
    /// plain bytes of the new chunks
    pub plain: u64,
    /// sealed bytes on disk of the new chunks (after zstd + AEAD)
    pub stored: u64,
}

impl Written {
    pub fn since(self, before: Written) -> Written {
        Written {
            chunks: self.chunks - before.chunks,
            plain: self.plain - before.plain,
            stored: self.stored - before.stored,
        }
    }
}

#[derive(Debug, Default)]
pub struct GcStats {
    pub total: usize,
    pub marked: usize,
    pub deleted: usize,
    pub kept_grace: usize,
}

#[derive(Debug, Default)]
pub struct VerifyReport {
    pub checked: usize,
    pub corrupt: Vec<ChunkId>,
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
    pub fn size(&self) -> u64 {
        self.size
    }

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
        Ok(Store {
            root,
            keys,
            clock,
            opts,
            chunk_lock: Mutex::new(()),
            meta_lock: Mutex::new(()),
            dirty_dirs: Mutex::new(HashSet::new()),
            written: Mutex::new(Written::default()),
        })
    }

    pub fn keys(&self) -> &Keyring {
        &self.keys
    }

    /// Decodes a sealed manifest / index file of `source/time` (offsite copies).
    pub fn decode_manifest(&self, source: &str, time: u64, sealed: &[u8]) -> io::Result<Manifest> {
        let ctx = format!("manifest:{source}/{time}");
        postcard::from_bytes(&self.keys.open(ctx.as_bytes(), sealed)?.1).map_err(invalid_ser)
    }

    pub fn decode_index(&self, source: &str, time: u64, name: &str, sealed: &[u8]) -> io::Result<Index> {
        let ctx = format!("index:{source}/{time}/{name}");
        postcard::from_bytes(&self.keys.open(ctx.as_bytes(), sealed)?.1).map_err(invalid_ser)
    }

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
    /// its indexes), `new` = `written().since(<before the snapshot>)`.
    pub fn stats_line(&self, m: &Manifest, read: u64, new: Written) -> io::Result<String> {
        let mut logical = 0;
        for i in &m.indexes {
            logical += self.load_index(m, i)?.size();
        }
        // source names pass check_name(): no JSON escaping needed
        Ok(format!(
            "nexus-stats {{\"source\":\"{}\",\"time\":{},\"read\":{read},\"logical\":{logical},\"new_chunks\":{},\"new_plain\":{},\"new_stored\":{}}}",
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
        let tmp = dir.join(format!("{}.tmp{}", hex(id), rand::random::<u32>()));
        let mut f = File::create(&tmp)?;
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

    pub fn read_chunk(&self, id: &ChunkId) -> io::Result<Vec<u8>> {
        self.keys.open_chunk(id, &fs::read(self.chunk_path(id))?)
    }

    /// Fixed-size chunking of a block device / image.
    pub fn store_image(&self, mut r: impl Read, chunk_size: usize) -> io::Result<Index> {
        let mut buf = vec![0u8; chunk_size];
        let (mut size, mut chunks) = (0u64, Vec::new());
        loop {
            let n = read_full(&mut r, &mut buf)?;
            if n == 0 {
                break;
            }
            chunks.push(self.insert_chunk(&buf[..n])?.0);
            size += n as u64;
        }
        Ok(Index::Fixed {
            chunk_size: chunk_size as u32,
            size,
            chunks,
        })
    }

    /// Incremental-forever for block devices. `dirty` = sorted, non-overlapping
    /// `(offset, len)` extents of the QEMU dirty bitmap. Only dirty bytes (plus any
    /// area beyond the previous size) are read via `read_at`: PVE snapshot-access
    /// exports refuse reads of clean areas. Clean parts of a partly dirty chunk are
    /// taken from the previous snapshot's chunk. `prev = None` reads everything.
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
        let mut buf = vec![0u8; chunk_size];
        let mut chunks = Vec::with_capacity(size.div_ceil(cs) as usize);
        let mut i = 0;
        for n in 0..size.div_ceil(cs) {
            let (start, end) = (n * cs, ((n + 1) * cs).min(size));
            while i < dirty.len() && dirty[i].0 + dirty[i].1 <= start {
                i += 1;
            }
            let mut reads: Vec<(u64, u64)> = dirty[i..]
                .iter()
                .take_while(|e| e.0 < end)
                .map(|&(o, l)| (o.max(start), (o + l).min(end)))
                .collect();
            if prev_size < end {
                reads.push((prev_size.max(start), end)); // grown disk / no base
                                                         // merge with the dirty extents: a full backup (fresh bitmap: everything dirty,
                                                         // no base) read every chunk twice before
                reads.sort_unstable();
                let mut merged: Vec<(u64, u64)> = Vec::with_capacity(reads.len());
                for (a, b) in reads {
                    match merged.last_mut() {
                        Some(last) if a <= last.1 => last.1 = last.1.max(b),
                        _ => merged.push((a, b)),
                    }
                }
                reads = merged;
            }
            let base = prev_chunks.get(n as usize);
            if reads.is_empty() && ((n + 1) * cs).min(prev_size) == end {
                chunks.push(*base.unwrap());
                continue;
            }
            let chunk = &mut buf[..(end - start) as usize];
            chunk.fill(0);
            if let Some(id) = base {
                let old = self.read_chunk(id)?;
                let k = old.len().min(chunk.len());
                chunk[..k].copy_from_slice(&old[..k]);
            }
            for (a, b) in reads {
                read_at(a, &mut chunk[(a - start) as usize..(b - start) as usize])?;
            }
            chunks.push(self.insert_chunk(chunk)?.0);
        }
        Ok(Index::Fixed {
            chunk_size: chunk_size as u32,
            size,
            chunks,
        })
    }

    /// FastCDC chunking of one file; returns (chunks, size).
    pub fn store_file(&self, r: impl Read) -> io::Result<(Vec<ChunkId>, u64)> {
        let s = self.store_file_stats(r)?;
        Ok((s.chunks, s.size))
    }

    /// Like `store_file`, also counting the chunks that were not in the store yet.
    pub fn store_file_stats(&self, r: impl Read) -> io::Result<FileStats> {
        let mut s = FileStats::default();
        for c in fastcdc::v2020::StreamCDC::new(r, CDC_MIN, CDC_AVG, CDC_MAX) {
            let c = c.map_err(io::Error::other)?;
            let (id, stored) = self.insert_chunk_stored(&c.data)?;
            s.chunks.push(id);
            s.size += c.length as u64;
            if stored > 0 {
                s.new_chunks += 1;
                s.new_bytes += c.length as u64;
                s.new_stored += stored;
            }
        }
        Ok(s)
    }

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
        if let Some(names) = crate::names::NameIndex::from_indexes(indexes.iter().map(|(n, i)| (*n, i))) {
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

    pub fn load_manifest(&self, source: &str, time: u64) -> io::Result<Manifest> {
        check_name(source)?;
        let ctx = format!("manifest:{source}/{time}");
        let blob = fs::read(self.snap_dir(source, time).join("manifest"))?;
        postcard::from_bytes(&self.keys.open(ctx.as_bytes(), &blob)?.1).map_err(invalid_ser)
    }

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
