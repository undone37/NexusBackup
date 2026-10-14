//! Wire protocol between the parent (nexus-pve) and the helper
//! (`nexus-fsindex --helper`) over the helper's stdin/stdout.
//!
//! Frames: `[u8 tag][u32 LE length][payload]`, at most 16 MiB.
//!
//! Parent → helper: `C` config (JSON [`Config`]), then answers: `D` disk bytes
//! (exactly the requested length) or `F` read error (UTF-8 message) for each
//! `R`; `A` (one byte, 1 = parse, 0 = skip) for each `B`.
//!
//! Helper → parent: `R` read request (`u32 disk, u64 offset, u32 length`, at
//! most 1 MiB), `B` volume begins (JSON [`Volume`]), `E` entries
//! (`[u8 kind][u64 size][i64 mtime][u16 len][path][u8 extra]`, then with bit 0
//! of `extra` `[u8 len][owner]`, with bit 1 `[32 bytes SHA-256]`…), `Z` volume done (JSON
//! [`Volume`]), `Q` finished, `X` fatal error (UTF-8 message).

use crate::disk::{invalid, DiskIo};
use crate::walk::Driver;
use crate::{Entry, Limits, Volume};
use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap};
use std::io::{self, Read, Write};
use std::rc::Rc;

pub const MAX_FRAME: u32 = 16 << 20;
pub const MAX_READ: u32 = 1 << 20;
/// Bytes per block of the helper's cache (and of the per-directory read sets).
pub const BLOCK: u64 = 64 << 10;
const BATCH: usize = 64 << 10;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Config {
    /// (index name, size) per disk, in micro-VM attach order
    pub disks: Vec<(String, u64)>,
    pub limits: Limits,
    /// bytes of disk data the helper caches
    #[serde(default = "default_cache")]
    pub cache_bytes: u64,
}

fn default_cache() -> u64 {
    128 << 20
}

pub fn write_frame(w: &mut dyn Write, tag: u8, payload: &[u8]) -> io::Result<()> {
    if payload.len() > MAX_FRAME as usize {
        return Err(invalid("frame too large"));
    }
    w.write_all(&[tag])?;
    w.write_all(&(payload.len() as u32).to_le_bytes())?;
    w.write_all(payload)
}

pub fn read_frame(r: &mut dyn Read) -> io::Result<(u8, Vec<u8>)> {
    let mut h = [0u8; 5];
    r.read_exact(&mut h)?;
    let n = u32::from_le_bytes([h[1], h[2], h[3], h[4]]);
    if n > MAX_FRAME {
        return Err(invalid("frame too large"));
    }
    let mut p = vec![0u8; n as usize];
    r.read_exact(&mut p)?;
    Ok((h[0], p))
}

#[allow(clippy::too_many_arguments)]
pub fn encode_entry(
    buf: &mut Vec<u8>,
    path: &str,
    size: u64,
    mtime: i64,
    kind: u8,
    owner: Option<&str>,
    sha256: Option<&[u8; 32]>,
) {
    let p = &path.as_bytes()[..path.len().min(u16::MAX as usize)];
    buf.push(kind);
    buf.extend_from_slice(&size.to_le_bytes());
    buf.extend_from_slice(&mtime.to_le_bytes());
    buf.extend_from_slice(&(p.len() as u16).to_le_bytes());
    buf.extend_from_slice(p);
    let owner = owner.filter(|o| o.len() <= u8::MAX as usize);
    buf.push(u8::from(owner.is_some()) | u8::from(sha256.is_some()) << 1);
    if let Some(o) = owner {
        buf.push(o.len() as u8);
        buf.extend_from_slice(o.as_bytes());
    }
    if let Some(h) = sha256 {
        buf.extend_from_slice(h);
    }
}

/// Decodes an `E` payload (hostile input on the parent side).
pub fn decode_entries(mut b: &[u8], out: &mut Vec<Entry>) -> io::Result<()> {
    while !b.is_empty() {
        if b.len() < 19 {
            return Err(invalid("truncated entry"));
        }
        let kind = b[0];
        let size = u64::from_le_bytes(b[1..9].try_into().unwrap());
        let mtime = i64::from_le_bytes(b[9..17].try_into().unwrap());
        let n = u16::from_le_bytes([b[17], b[18]]) as usize;
        let p = b.get(19..19 + n).ok_or_else(|| invalid("truncated entry"))?;
        let path = String::from_utf8_lossy(p).into_owned();
        if kind > crate::KIND_OTHER
            || path.is_empty()
            || path.starts_with('/')
            || path.split('/').any(|c| c.is_empty() || c == "." || c == "..")
        {
            return Err(invalid("malformed entry"));
        }
        let extra = *b.get(19 + n).ok_or_else(|| invalid("truncated entry"))?;
        let mut at = 20 + n;
        if extra & !3 != 0 {
            return Err(invalid("malformed entry"));
        }
        let mut owner = None;
        if extra & 1 != 0 {
            let k = *b.get(at).ok_or_else(|| invalid("truncated entry"))? as usize;
            let o = b.get(at + 1..at + 1 + k).ok_or_else(|| invalid("truncated entry"))?;
            let o = std::str::from_utf8(o).ok().filter(|o| crate::valid_owner(o));
            owner = Some(o.ok_or_else(|| invalid("malformed owner"))?.to_owned());
            at += 1 + k;
        }
        let mut sha256 = None;
        if extra & 2 != 0 {
            let h = b.get(at..at + 32).ok_or_else(|| invalid("truncated entry"))?;
            sha256 = Some(h.try_into().unwrap());
            at += 32;
            if kind != crate::KIND_FILE {
                return Err(invalid("a hash for an entry that is not a file"));
            }
        }
        out.push(Entry {
            path,
            size,
            mtime,
            kind,
            owner,
            sha256,
        });
        b = &b[at..];
    }
    Ok(())
}

/// A `B` / `Z` payload from the helper (hostile on the parent side): the
/// browse path becomes a prefix of name-index paths, so it must be relative
/// and without `.`/`..`/empty components.
pub fn parse_volume(p: &[u8]) -> io::Result<Volume> {
    let v: Volume = serde_json::from_slice(p)?;
    let ok = !v.browse.is_empty()
        && v.browse.len() <= 512
        && v.key.len() <= 1024
        && !v.browse.contains('\0')
        && v.browse.split('/').all(|c| !c.is_empty() && c != "." && c != "..");
    if !ok {
        return Err(invalid("malformed volume"));
    }
    Ok(v)
}

/// The helper's end of the pipe.
pub struct Chan<R, W> {
    pub r: R,
    pub w: W,
}

pub type Shared<R, W> = Rc<RefCell<Chan<R, W>>>;

/// Disk bytes from the parent, with a block cache (LRU, 64 KiB blocks).
pub struct Remote<R, W> {
    chan: Shared<R, W>,
    sizes: Vec<u64>,
    cache: HashMap<(usize, u64), (u64, Vec<u8>)>,
    order: BTreeMap<u64, (usize, u64)>,
    tick: u64,
    bytes: u64,
    cap: u64,
    /// blocks accessed since the last `take_accessed`
    accessed: std::collections::HashSet<(usize, u64)>,
}

impl<R: Read, W: Write> Remote<R, W> {
    pub fn new(chan: Shared<R, W>, sizes: Vec<u64>, cap: u64) -> Self {
        Remote {
            chan,
            sizes,
            cache: HashMap::new(),
            order: BTreeMap::new(),
            tick: 0,
            bytes: 0,
            cap: cap.max(BLOCK * 16),
            accessed: std::collections::HashSet::new(),
        }
    }

    fn fetch(&mut self, disk: usize, off: u64, len: u64) -> io::Result<Vec<u8>> {
        let mut c = self.chan.borrow_mut();
        let mut req = Vec::with_capacity(16);
        req.extend_from_slice(&(disk as u32).to_le_bytes());
        req.extend_from_slice(&off.to_le_bytes());
        req.extend_from_slice(&(len as u32).to_le_bytes());
        write_frame(&mut c.w, b'R', &req)?;
        c.w.flush()?;
        match read_frame(&mut c.r)? {
            (b'D', d) if d.len() as u64 == len => Ok(d),
            (b'F', m) => Err(io::Error::other(String::from_utf8_lossy(&m).into_owned())),
            _ => Err(invalid("unexpected answer to a read")),
        }
    }

    fn insert(&mut self, k: (usize, u64), d: Vec<u8>) {
        self.tick += 1;
        self.bytes += d.len() as u64;
        self.order.insert(self.tick, k);
        if let Some((t, old)) = self.cache.insert(k, (self.tick, d)) {
            self.order.remove(&t);
            self.bytes -= old.len() as u64;
        }
        while self.bytes > self.cap {
            let Some((_, k)) = self.order.pop_first() else { break };
            if let Some((_, d)) = self.cache.remove(&k) {
                self.bytes -= d.len() as u64;
            }
        }
    }
}

impl<R: Read, W: Write> DiskIo for Remote<R, W> {
    fn disks(&self) -> usize {
        self.sizes.len()
    }

    fn disk_size(&self, d: usize) -> u64 {
        self.sizes.get(d).copied().unwrap_or(0)
    }

    fn read(&mut self, disk: usize, off: u64, buf: &mut [u8]) -> io::Result<()> {
        let size = self.disk_size(disk);
        if disk >= self.sizes.len() || off.checked_add(buf.len() as u64).is_none_or(|e| e > size) {
            return Err(invalid("read beyond the end of the disk"));
        }
        let mut done = 0usize;
        while done < buf.len() {
            let pos = off + done as u64;
            let b = pos / BLOCK;
            self.accessed.insert((disk, b));
            if let Some((t, d)) = self.cache.get_mut(&(disk, b)) {
                self.tick += 1;
                let old = *t;
                *t = self.tick;
                let at = (pos - b * BLOCK) as usize;
                let k = (d.len() - at).min(buf.len() - done);
                buf[done..done + k].copy_from_slice(&d[at..at + k]);
                done += k;
                let tick = self.tick;
                self.order.remove(&old);
                self.order.insert(tick, (disk, b));
                continue;
            }
            // a run of missing blocks, at most 1 MiB, up to the end of the request
            let last = (off + buf.len() as u64 - 1) / BLOCK;
            let mut n = 1;
            while b + n <= last && n < MAX_READ as u64 / BLOCK && !self.cache.contains_key(&(disk, b + n)) {
                n += 1;
            }
            let start = b * BLOCK;
            let len = (n * BLOCK).min(size - start);
            let data = self.fetch(disk, start, len)?;
            for (i, blk) in data.chunks(BLOCK as usize).enumerate() {
                self.insert((disk, b + i as u64), blk.to_vec());
            }
        }
        Ok(())
    }

    fn take_accessed(&mut self) -> Vec<(usize, u64)> {
        self.accessed.drain().collect()
    }

    fn forget(&mut self) {
        self.cache.clear();
        self.order.clear();
        self.bytes = 0;
    }
}

/// Sends a walk's volumes and entries to the parent.
pub struct HelperDriver<R, W> {
    pub chan: Shared<R, W>,
    batch: Vec<u8>,
}

impl<R: Read, W: Write> HelperDriver<R, W> {
    pub fn new(chan: Shared<R, W>) -> Self {
        HelperDriver {
            chan,
            batch: Vec::with_capacity(BATCH + 4096),
        }
    }

    fn flush_batch(&mut self) -> io::Result<()> {
        if !self.batch.is_empty() {
            write_frame(&mut self.chan.borrow_mut().w, b'E', &self.batch)?;
            self.batch.clear();
        }
        Ok(())
    }
}

impl<R: Read, W: Write> Driver for HelperDriver<R, W> {
    fn begin(&mut self, v: &Volume) -> io::Result<bool> {
        self.flush_batch()?;
        let mut c = self.chan.borrow_mut();
        write_frame(&mut c.w, b'B', &serde_json::to_vec(v)?)?;
        c.w.flush()?;
        match read_frame(&mut c.r)? {
            (b'A', a) if a.len() == 1 => Ok(a[0] == 1),
            _ => Err(invalid("unexpected answer to a volume")),
        }
    }

    fn entry(&mut self, path: &str, size: u64, mtime: i64, kind: u8) -> io::Result<()> {
        self.entry_ext(path, size, mtime, kind, None, None)
    }

    fn entry_ext(
        &mut self,
        path: &str,
        size: u64,
        mtime: i64,
        kind: u8,
        owner: Option<&str>,
        sha256: Option<&[u8; 32]>,
    ) -> io::Result<()> {
        encode_entry(&mut self.batch, path, size, mtime, kind, owner, sha256);
        if self.batch.len() >= BATCH {
            self.flush_batch()?;
        }
        Ok(())
    }

    fn end(&mut self, v: &Volume) -> io::Result<()> {
        self.flush_batch()?;
        let mut c = self.chan.borrow_mut();
        write_frame(&mut c.w, b'Z', &serde_json::to_vec(v)?)?;
        c.w.flush()
    }

    fn expect(&mut self, entries: u64) -> io::Result<()> {
        write_frame(&mut self.chan.borrow_mut().w, b'P', &entries.to_le_bytes())
    }

    fn reuse_dir(&mut self, rel: &str, own: bool, layout: &str) -> io::Result<Option<Vec<(u64, String)>>> {
        self.flush_batch()?;
        let mut c = self.chan.borrow_mut();
        let q = serde_json::json!({"rel": rel, "own": own, "layout": layout});
        write_frame(&mut c.w, b'U', &serde_json::to_vec(&q)?)?;
        c.w.flush()?;
        match read_frame(&mut c.r)? {
            (b'Y', s) => Ok(Some(serde_json::from_slice(&s)?)),
            (b'N', _) => Ok(None),
            _ => Err(invalid("unexpected answer to a directory query")),
        }
    }

    fn dir_listed(&mut self, rec: &crate::DirRec, blocks: &[(usize, u64)]) -> io::Result<()> {
        let body = serde_json::json!({"rec": rec, "blocks": blocks});
        write_frame(&mut self.chan.borrow_mut().w, b'L', &serde_json::to_vec(&body)?)
    }
}

/// The helper's main loop: config, walk, `Q` (or `X` with the error).
pub fn serve<R: Read + 'static, W: Write + 'static>(r: R, w: W) -> io::Result<()> {
    let chan = Rc::new(RefCell::new(Chan { r, w }));
    let res = (|| {
        let cfg: Config = match read_frame(&mut chan.borrow_mut().r)? {
            (b'C', c) => serde_json::from_slice(&c)?,
            _ => return Err(invalid("expected the configuration")),
        };
        let names: Vec<String> = cfg.disks.iter().map(|d| d.0.clone()).collect();
        let sizes = cfg.disks.iter().map(|d| d.1).collect();
        let io: crate::disk::Io = Rc::new(RefCell::new(Remote::new(chan.clone(), sizes, cfg.cache_bytes)));
        let mut drv = HelperDriver::new(chan.clone());
        crate::walk::run(io, &names, cfg.limits, &mut drv)
    })();
    let mut c = chan.borrow_mut();
    match res {
        Ok(()) => write_frame(&mut c.w, b'Q', &[])?,
        Err(e) => write_frame(&mut c.w, b'X', e.to_string().as_bytes())?,
    }
    c.w.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entries_with_owner_and_hash() {
        let mut b = Vec::new();
        encode_entry(
            &mut b,
            "a/b.txt",
            5,
            7,
            crate::KIND_FILE,
            Some("S-1-5-21-1-1001"),
            Some(&[3; 32]),
        );
        encode_entry(&mut b, "a", 0, 7, crate::KIND_DIR, Some("0:0"), None);
        encode_entry(&mut b, "a/c", 1, 7, crate::KIND_FILE, None, None);
        let mut out = Vec::new();
        decode_entries(&b, &mut out).unwrap();
        assert_eq!(out[0].owner.as_deref(), Some("S-1-5-21-1-1001"));
        assert_eq!(out[0].sha256, Some([3; 32]));
        assert_eq!((out[1].owner.as_deref(), out[2].owner.as_deref()), (Some("0:0"), None));
        // hostile: an owner with other characters, a hash on a directory, unknown extra bits
        for (owner, kind, extra) in [
            ("../x", crate::KIND_FILE, None),
            ("0:0", crate::KIND_DIR, None),
            ("0:0", 0, Some(4u8)),
        ] {
            let mut b = Vec::new();
            encode_entry(&mut b, "x", 1, 1, kind, Some(owner), Some(&[0; 32]));
            if let Some(x) = extra {
                b[1 + 8 + 8 + 2 + 1] |= x;
            }
            assert!(decode_entries(&b, &mut Vec::new()).is_err(), "{owner} {kind}");
        }
        // truncated anywhere: an error, never a panic
        for n in 0..b.len() {
            let _ = decode_entries(&b[..n], &mut Vec::new());
        }
    }
}
