//! Local chunk store (plan §5): one file per chunk, sealed indexes and
//! manifests, retention locks, mark-and-sweep GC, verify.
//!
//! Layout under `root`:
//! ```text
//! keycheck                         sealed marker, rejects a wrong keyring
//! clock                            compliance clock state
//! chunks/<hex[..4]>/<hex>          sealed chunks
//! snapshots/<source>/<time>/<name>.idx
//! snapshots/<source>/<time>/manifest   written last = commit point
//! ```

use crate::clock::ComplianceClock;
use crate::crypto::{hex, invalid, parse_hex, ChunkId, Keyring};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom, Write};
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
            clock_slew: 0.01,
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
    pub fn chunk_ids(&self) -> Vec<&ChunkId> {
        match self {
            Index::Fixed { chunks, .. } => chunks.iter().collect(),
            Index::Dynamic { entries } => entries.iter().flat_map(|e| &e.chunks).collect(),
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

pub struct Store {
    root: PathBuf,
    keys: Keyring,
    clock: ComplianceClock,
    opts: Options,
    // ponytail: one lock for exists/touch vs. sweep/unlink; per-prefix locks if contention shows.
    chunk_lock: Mutex<()>,
    meta_lock: Mutex<()>,
    dirty_dirs: Mutex<HashSet<PathBuf>>,
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
        let clock = ComplianceClock::open(root.join("clock"), opts.clock_slew)?;
        Ok(Store {
            root,
            keys,
            clock,
            opts,
            chunk_lock: Mutex::new(()),
            meta_lock: Mutex::new(()),
            dirty_dirs: Mutex::new(HashSet::new()),
        })
    }

    pub fn compliance_now(&self) -> io::Result<u64> {
        self.clock.now()
    }

    fn chunk_path(&self, id: &ChunkId) -> PathBuf {
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
        let id = self.keys.chunk_id(data);
        let path = self.chunk_path(&id);
        {
            let _g = self.chunk_lock.lock().unwrap();
            if Self::touch(&path)? {
                return Ok((id, false));
            }
        }
        // seal + write outside the lock; only the rename is serialized against GC
        let sealed = self.keys.seal_chunk(&id, data);
        let dir = path.parent().unwrap();
        fs::create_dir_all(dir)?;
        let tmp = dir.join(format!("{}.tmp{}", hex(&id), rand::random::<u32>()));
        let mut f = File::create(&tmp)?;
        f.write_all(&sealed)?;
        f.sync_all()?;
        let _g = self.chunk_lock.lock().unwrap();
        if Self::touch(&path)? {
            fs::remove_file(&tmp)?;
            return Ok((id, false));
        }
        fs::rename(&tmp, &path)?;
        self.dirty_dirs.lock().unwrap().insert(dir.to_owned());
        Ok((id, true))
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

    /// Incremental-forever for block devices: only chunks flagged by `dirty`
    /// (QEMU dirty bitmap, in chunk units) are read; the rest come from `prev`.
    /// After bitmap loss use `store_image` (full read, still only new chunks stored).
    pub fn store_image_dirty(
        &self,
        prev: &Index,
        mut r: impl Read + Seek,
        size: u64,
        dirty: impl Fn(u64) -> bool,
    ) -> io::Result<Index> {
        let Index::Fixed {
            chunk_size,
            size: prev_size,
            chunks: prev_chunks,
        } = prev
        else {
            return Err(invalid("previous index is not a fixed index"));
        };
        let cs = *chunk_size as u64;
        let mut buf = vec![0u8; cs as usize];
        let mut chunks = Vec::with_capacity(size.div_ceil(cs) as usize);
        for n in 0..size.div_ceil(cs) {
            let end = ((n + 1) * cs).min(size);
            let same_range = n < prev_chunks.len() as u64 && end == ((n + 1) * cs).min(*prev_size);
            if same_range && !dirty(n) {
                chunks.push(prev_chunks[n as usize]);
                continue;
            }
            let len = (end - n * cs) as usize;
            r.seek(SeekFrom::Start(n * cs))?;
            if read_full(&mut r, &mut buf[..len])? != len {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "device shorter than size"));
            }
            chunks.push(self.insert_chunk(&buf[..len])?.0);
        }
        Ok(Index::Fixed {
            chunk_size: *chunk_size,
            size,
            chunks,
        })
    }

    /// FastCDC chunking of one file; returns (chunks, size).
    pub fn store_file(&self, r: impl Read) -> io::Result<(Vec<ChunkId>, u64)> {
        let (mut chunks, mut size) = (Vec::new(), 0u64);
        for c in fastcdc::v2020::StreamCDC::new(r, CDC_MIN, CDC_AVG, CDC_MAX) {
            let c = c.map_err(io::Error::other)?;
            chunks.push(self.insert_chunk(&c.data)?.0);
            size += c.length as u64;
        }
        Ok((chunks, size))
    }

    pub fn write_chunks<'a>(&self, ids: impl IntoIterator<Item = &'a ChunkId>, mut w: impl Write) -> io::Result<()> {
        for id in ids {
            w.write_all(&self.read_chunk(id)?)?;
        }
        Ok(())
    }

    fn snap_dir(&self, source: &str, time: u64) -> PathBuf {
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

    /// All chunk IDs referenced by committed snapshots. Any unreadable
    /// manifest or index is an error: never sweep on an incomplete mark.
    fn mark(&self) -> io::Result<HashSet<ChunkId>> {
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
