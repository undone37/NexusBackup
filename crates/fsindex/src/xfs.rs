//! XFS, own minimal read-only parser (Phase 31c; no maintained crate exists):
//! superblock (v4 and v5, CRC checked), inodes by number (v1-v3, CRC and
//! number checked on v5; big time stamps, 64-bit extent counters), data forks
//! in local, extent and B+tree format, directories in every format (short
//! form, block, leaf, node and B+tree: the data blocks below 32 GiB are read,
//! leaf and free index blocks are not needed for a listing). The XFS log is
//! never replayed. The AG inode B+trees are not needed: inode numbers encode
//! where an inode lies.
//!
//! Every block goes through the volume (the helper's logged block cache), so a
//! directory's listing has a complete read set and can be taken over unread in
//! the next snapshot (Phase 31c, as NTFS). Hostile input: every offset and
//! count is checked, B+trees are depth- and size-bounded, a directory is read
//! up to `MAX_DIR` bytes, directories are entered once.

use crate::disk::Vol;
use crate::walk::Out;
use crate::{Volume, KIND_DIR, KIND_FILE, KIND_OTHER, KIND_SYMLINK, MAX_DEPTH, MAX_PATH};
use std::collections::{BTreeSet, HashSet};

/// Directory data below this logical offset; leaf / free index blocks above.
const LEAF_OFFSET: u64 = 32 << 30;
/// Bytes of directory data read per directory.
const MAX_DIR: u64 = 1 << 30;
/// Extents per fork looked at.
const MAX_EXTENTS: usize = 1 << 20;
const MAX_BTREE_DEPTH: usize = 10;

fn be16(b: &[u8], at: usize) -> u16 {
    b.get(at..at + 2).map_or(0, |s| u16::from_be_bytes([s[0], s[1]]))
}

fn be32(b: &[u8], at: usize) -> u32 {
    b.get(at..at + 4)
        .map_or(0, |s| u32::from_be_bytes(s.try_into().unwrap()))
}

fn be64(b: &[u8], at: usize) -> u64 {
    b.get(at..at + 8)
        .map_or(0, |s| u64::from_be_bytes(s.try_into().unwrap()))
}

/// CRC-32C (Castagnoli) as XFS stores it: of the buffer with the CRC field
/// (at `at`) taken as zero.
fn crc_ok(b: &[u8], at: usize) -> bool {
    if b.len() < at + 4 {
        return false;
    }
    if cfg!(fuzzing) {
        return true; // the fuzzer cannot forge checksums; let it reach the parsers behind them
    }
    let mut c = !0u32;
    for (i, &x) in b.iter().enumerate() {
        let x = if (at..at + 4).contains(&i) { 0 } else { x };
        c ^= u32::from(x);
        for _ in 0..8 {
            c = if c & 1 != 0 { (c >> 1) ^ 0x82F6_3B78 } else { c >> 1 };
        }
    }
    !c == u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
}

/// A directory entry: name, inode number, file type if the file system records it.
pub type DirEntry = (Vec<u8>, u64, Option<u8>);

/// One extent of a fork: logical block, disk block (fs block number), count.
#[derive(Clone, Copy, Debug, PartialEq)]
struct Ext {
    off: u64,
    fsb: u64,
    len: u64,
    unwritten: bool,
}

fn ext(rec: &[u8]) -> Ext {
    let (l0, l1) = (be64(rec, 0), be64(rec, 8));
    Ext {
        unwritten: l0 >> 63 != 0,
        off: (l0 & ((1 << 63) - 1)) >> 9,
        fsb: ((l0 & 0x1ff) << 43) | (l1 >> 21),
        len: l1 & ((1 << 21) - 1),
    }
}

pub struct Xfs {
    v: Vol,
    bs: u64,
    /// fs blocks per directory block (log2)
    dirblklog: u32,
    agblocks: u64,
    agblklog: u32,
    agcount: u64,
    inodesize: u64,
    inopblog: u32,
    v5: bool,
    ftype: bool,
    pub root: u64,
}

/// What an inode says about itself.
#[derive(Clone, Debug)]
pub struct Inode {
    pub mode: u16,
    pub size: u64,
    pub mtime: i64,
    pub uid: u32,
    pub gid: u32,
    format: u8,
    nextents: u64,
    /// the data fork
    fork: Vec<u8>,
}

impl Inode {
    pub fn kind(&self) -> u8 {
        match self.mode & 0o170000 {
            0o040000 => KIND_DIR,
            0o100000 => KIND_FILE,
            0o120000 => KIND_SYMLINK,
            _ => KIND_OTHER,
        }
    }
}

impl Xfs {
    pub fn open(v: &Vol) -> Result<Xfs, String> {
        let sb = v.read_vec(0, 512).map_err(|e| e.to_string())?;
        if sb.len() < 512 || &sb[0..4] != b"XFSB" {
            return Err("xfs: no superblock".into());
        }
        let bs = u64::from(be32(&sb, 4));
        let version = be16(&sb, 100) & 0xf;
        let v5 = version == 5;
        if !(4..=5).contains(&version) {
            return Err(format!("xfs: version {version}"));
        }
        let sectsize = be16(&sb, 102) as usize;
        if v5 {
            let s = v.read_vec(0, sectsize.clamp(512, 32768)).map_err(|e| e.to_string())?;
            if !crc_ok(&s, 224) {
                return Err("xfs: superblock checksum".into());
            }
            // incompat features this parser reads around: ftype, sparse inodes, meta uuid,
            // big time stamps, needs-repair, 64-bit extent counters, exchange-range, parent
            // pointers, metadata directory tree
            let unknown = be32(&sb, 216) & !0x1ff;
            if unknown != 0 {
                return Err(format!("xfs: unknown incompatible features {unknown:#x}"));
            }
        }
        let (blocklog, inodelog, inopblog, agblklog) = (sb[120], sb[122], sb[123], sb[124]);
        let x = Xfs {
            v: v.clone(),
            bs,
            dirblklog: u32::from(sb[192]),
            agblocks: u64::from(be32(&sb, 84)),
            agblklog: u32::from(agblklog),
            agcount: u64::from(be32(&sb, 88)),
            inodesize: u64::from(be16(&sb, 104)),
            inopblog: u32::from(inopblog),
            v5,
            ftype: if v5 {
                be32(&sb, 216) & 1 != 0
            } else {
                be32(&sb, 200) & 0x200 != 0
            },
            root: be64(&sb, 56),
        };
        let ok = (9..=16).contains(&blocklog)
            && bs == 1 << blocklog
            && (8..=11).contains(&inodelog)
            && x.inodesize == 1 << inodelog
            && u32::from(blocklog) == u32::from(inodelog) + x.inopblog
            && x.dirblklog <= 16 - u32::from(blocklog).min(16)
            && x.agblocks > 0
            && x.agblklog < 32
            && x.agblocks <= 1 << x.agblklog
            && x.agcount > 0
            && x.agcount
                .checked_mul(x.agblocks)
                .is_some_and(|b| b.checked_mul(bs).is_some());
        if !ok {
            return Err("xfs: superblock geometry".into());
        }
        Ok(x)
    }

    /// Byte offset of fs block `fsb` (AG number in the high bits).
    fn fsb_off(&self, fsb: u64) -> Result<u64, String> {
        let (ag, agbno) = (fsb >> self.agblklog, fsb & ((1 << self.agblklog) - 1));
        if ag >= self.agcount || agbno >= self.agblocks {
            return Err(format!("xfs: block {fsb} outside the file system"));
        }
        Ok((ag * self.agblocks + agbno) * self.bs)
    }

    fn read(&self, off: u64, n: u64) -> Result<Vec<u8>, String> {
        let mut b = vec![0u8; n as usize];
        self.v.read_at(off, &mut b).map_err(|e| e.to_string())?;
        Ok(b)
    }

    pub fn inode(&self, ino: u64) -> Result<Inode, String> {
        let shift = self.agblklog + self.inopblog;
        if shift >= 64 {
            return Err("xfs: inode geometry".into());
        }
        let ag = ino >> shift;
        let agbno = (ino >> self.inopblog) & ((1 << self.agblklog) - 1);
        let idx = ino & ((1 << self.inopblog) - 1);
        if ag >= self.agcount || agbno >= self.agblocks {
            return Err(format!("xfs: inode {ino} outside the file system"));
        }
        let off = (ag * self.agblocks + agbno) * self.bs + idx * self.inodesize;
        let b = self.read(off, self.inodesize)?;
        if &b[0..2] != b"IN" {
            return Err(format!("xfs: inode {ino}: no inode"));
        }
        let version = b[4];
        let core = match version {
            1 | 2 if !self.v5 => 100,
            3 if self.v5 => 176,
            _ => return Err(format!("xfs: inode {ino}: version {version}")),
        };
        if version == 3 && (!crc_ok(&b, 100) || be64(&b, 152) != ino) {
            return Err(format!("xfs: inode {ino}: checksum"));
        }
        let flags2 = if version == 3 { be64(&b, 120) } else { 0 };
        let ts = |at: usize| -> i64 {
            if flags2 & (1 << 3) != 0 {
                // big time stamps: nanoseconds since 1901-12-13
                (be64(&b, at) / 1_000_000_000) as i64 - (1i64 << 31)
            } else {
                i64::from(be32(&b, at) as i32)
            }
        };
        let nextents = if flags2 & (1 << 4) != 0 {
            be64(&b, 24)
        } else {
            u64::from(be32(&b, 76))
        };
        let forkoff = u64::from(b[82]) * 8;
        let room = self.inodesize - core;
        let fork_len = if forkoff == 0 { room } else { forkoff.min(room) };
        Ok(Inode {
            mode: be16(&b, 2),
            size: be64(&b, 56),
            mtime: ts(40),
            uid: be32(&b, 8),
            gid: be32(&b, 12),
            format: b[5],
            nextents,
            fork: b[core as usize..(core + fork_len) as usize].to_vec(),
        })
    }

    /// The extents of a data fork in extent or B+tree format, sorted by logical block.
    fn extents(&self, ino: &Inode) -> Result<Vec<Ext>, String> {
        let mut out = Vec::new();
        match ino.format {
            2 => {
                let n = ino.nextents.min(MAX_EXTENTS as u64) as usize;
                if n * 16 > ino.fork.len() {
                    return Err("xfs: extent list larger than the inode".into());
                }
                out.extend(ino.fork.as_chunks::<16>().0.iter().take(n).map(|c| ext(c)));
            }
            3 => {
                // root in the inode: level, records; keys, then pointers at the fork's maxrecs
                let (level, n) = (be16(&ino.fork, 0) as usize, be16(&ino.fork, 2) as usize);
                let maxrecs = ino.fork.len().saturating_sub(4) / 16;
                if level == 0 || level > MAX_BTREE_DEPTH || n == 0 || n > maxrecs {
                    return Err("xfs: extent tree root".into());
                }
                for i in 0..n {
                    let ptr = be64(&ino.fork, 4 + maxrecs * 8 + i * 8);
                    self.bmbt(ptr, level - 1, &mut out, &mut HashSet::new())?;
                }
            }
            1 => {}
            f => return Err(format!("xfs: data fork format {f}")),
        }
        out.sort_by_key(|e| e.off);
        Ok(out)
    }

    /// A block of the extent B+tree at `level` (0: records).
    fn bmbt(&self, fsb: u64, level: usize, out: &mut Vec<Ext>, seen: &mut HashSet<u64>) -> Result<(), String> {
        if !seen.insert(fsb) || seen.len() > MAX_EXTENTS {
            return Err("xfs: extent tree loops".into());
        }
        let b = self.read(self.fsb_off(fsb)?, self.bs)?;
        let (magic, hdr) = if self.v5 { (b"BMA3", 72) } else { (b"BMAP", 24) };
        if &b[0..4] != magic || (self.v5 && !crc_ok(&b, 64)) {
            return Err("xfs: extent tree block".into());
        }
        if usize::from(be16(&b, 4)) != level {
            return Err("xfs: extent tree level".into());
        }
        let n = be16(&b, 6) as usize;
        let maxrecs = (b.len() - hdr) / 16;
        if n > maxrecs {
            return Err("xfs: extent tree block records".into());
        }
        if level == 0 {
            for i in 0..n {
                out.push(ext(&b[hdr + i * 16..hdr + i * 16 + 16]));
                if out.len() > MAX_EXTENTS {
                    return Err("xfs: too many extents".into());
                }
            }
        } else {
            for i in 0..n {
                let ptr = be64(&b, hdr + maxrecs * 8 + i * 8);
                self.bmbt(ptr, level - 1, out, seen)?;
            }
        }
        Ok(())
    }

    /// Up to `max` bytes of a file's content (holes and unwritten extents read zeros).
    pub fn read_file(&self, ino: &Inode, max: u64) -> Result<Vec<u8>, String> {
        let size = ino.size.min(max);
        if ino.format == 1 {
            return Ok(ino.fork[..(size as usize).min(ino.fork.len())].to_vec());
        }
        let mut out = vec![0u8; size as usize];
        for e in self.extents(ino)? {
            let start = e.off.saturating_mul(self.bs);
            if start >= size || e.unwritten {
                continue;
            }
            let n = (e.len * self.bs).min(size - start);
            let d = self.read(self.fsb_off(e.fsb)?, n)?;
            out[start as usize..(start + n) as usize].copy_from_slice(&d);
        }
        Ok(out)
    }

    /// SHA-256 of a regular file's content (holes and unwritten extents are zeros).
    pub fn hash_file(&self, ino: &Inode) -> Result<[u8; 32], String> {
        use sha2::Digest;
        let mut h = sha2::Sha256::new();
        let size = ino.size;
        if ino.format == 1 {
            let d = ino.fork.get(..size as usize).ok_or("xfs: inline data")?;
            h.update(d);
            return Ok(h.finalize().into());
        }
        let zeros = vec![0u8; crate::walk::HASH_READ];
        let feed_zeros = |h: &mut sha2::Sha256, mut n: u64| {
            while n > 0 {
                let k = n.min(zeros.len() as u64) as usize;
                h.update(&zeros[..k]);
                n -= k as u64;
            }
        };
        let mut pos = 0u64;
        for e in self.extents(ino)? {
            let start = e.off.saturating_mul(self.bs);
            if start >= size {
                break;
            }
            if start < pos {
                return Err("xfs: overlapping extents".into());
            }
            feed_zeros(&mut h, start - pos);
            let len = (e.len * self.bs).min(size - start);
            if e.unwritten {
                feed_zeros(&mut h, len);
            } else {
                let base = self.fsb_off(e.fsb)?;
                let mut done = 0;
                while done < len {
                    let k = (len - done).min(crate::walk::HASH_READ as u64);
                    h.update(&self.read(base + done, k)?);
                    done += k;
                }
            }
            pos = start + len;
        }
        feed_zeros(&mut h, size.saturating_sub(pos));
        Ok(h.finalize().into())
    }

    /// The entries of directory `ino`: (name, inode number, file type from the entry
    /// if the file system records it). `Err` for an unreadable directory; damaged
    /// blocks inside it are skipped and counted in `bad`.
    pub fn dir(&self, ino: &Inode, bad: &mut u64) -> Result<Vec<DirEntry>, String> {
        let mut out = Vec::new();
        if ino.format == 1 {
            self.shortform(&ino.fork[..(ino.size as usize).min(ino.fork.len())], &mut out)?;
            return Ok(out);
        }
        let exts = self.extents(ino)?;
        let dbs = self.bs << self.dirblklog;
        let per = 1u64 << self.dirblklog;
        // the directory blocks with data (logical directory block numbers)
        let mut blocks = BTreeSet::new();
        let mut steps = 0u64;
        for e in &exts {
            let end = e.off.saturating_add(e.len).min(LEAF_OFFSET / self.bs);
            let mut b = e.off;
            while b < end {
                blocks.insert(b >> self.dirblklog);
                steps += 1;
                if (blocks.len() as u64).max(steps / 4) * dbs > MAX_DIR {
                    return Err("xfs: directory too large".into());
                }
                b = ((b >> self.dirblklog) + 1) << self.dirblklog;
            }
        }
        // the extent holding logical block `lb` (sorted by `off`; overlaps: the last one starting before)
        let find = |lb: u64| {
            let i = exts.partition_point(|e| e.off <= lb);
            exts[..i].last().filter(|e| lb < e.off + e.len && !e.unwritten)
        };
        let single = exts.len() == 1 && blocks.len() == 1;
        for db in blocks {
            let mut buf = Vec::with_capacity(dbs as usize);
            for i in 0..per {
                let lb = (db << self.dirblklog) + i;
                let Some(e) = find(lb) else { break };
                buf.extend(self.read(self.fsb_off(e.fsb + (lb - e.off))?, self.bs)?);
            }
            if buf.len() as u64 != dbs || self.data_block(&buf, single, &mut out).is_err() {
                *bad += 1;
            }
        }
        Ok(out)
    }

    fn shortform(&self, f: &[u8], out: &mut Vec<DirEntry>) -> Result<(), String> {
        if f.len() < 2 {
            return Err("xfs: short form directory".into());
        }
        let count = f[0] as usize;
        let isz = if f[1] > 0 { 8 } else { 4 };
        let mut at = 2 + isz;
        for _ in 0..count {
            let n = *f.get(at).ok_or("xfs: short form entry")? as usize;
            let name = f.get(at + 3..at + 3 + n).ok_or("xfs: short form entry")?.to_vec();
            let mut p = at + 3 + n;
            let ft = if self.ftype {
                p += 1;
                Some(*f.get(p - 1).ok_or("xfs: short form entry")?)
            } else {
                None
            };
            let num = f.get(p..p + isz).ok_or("xfs: short form entry")?;
            let num = if isz == 8 {
                be64(num, 0)
            } else {
                u64::from(be32(num, 0))
            };
            out.push((name, num, ft));
            at = p + isz;
        }
        Ok(())
    }

    /// The entries of one directory data block (block format: `single`).
    fn data_block(&self, b: &[u8], single: bool, out: &mut Vec<DirEntry>) -> Result<(), String> {
        let (data, block, hdr) = if self.v5 {
            (b"XDD3", b"XDB3", 64)
        } else {
            (b"XD2D", b"XD2B", 16)
        };
        let magic = b.get(0..4).ok_or("xfs: directory block")?;
        let end = if magic == block {
            // block format: leaf entries and a tail at the end
            let count = u64::from(be32(b, b.len() - 8));
            (b.len() as u64)
                .checked_sub(8 + count * 8)
                .filter(|e| *e >= hdr as u64)
                .ok_or("xfs: directory block tail")? as usize
        } else if magic == data && !single {
            b.len()
        } else {
            return Err("xfs: directory block magic".into());
        };
        if self.v5 && !crc_ok(b, 4) {
            return Err("xfs: directory block checksum".into());
        }
        let mut at = hdr;
        while at + 8 <= end {
            if be16(b, at) == 0xffff {
                // unused space: its length, a multiple of 8
                let n = be16(b, at + 2) as usize;
                if n < 8 || !n.is_multiple_of(8) {
                    return Err("xfs: directory free space".into());
                }
                at += n;
                continue;
            }
            let num = be64(b, at);
            let n = *b.get(at + 8).ok_or("xfs: directory entry")? as usize;
            let name = b.get(at + 9..at + 9 + n).ok_or("xfs: directory entry")?;
            let ft = if self.ftype { b.get(at + 9 + n).copied() } else { None };
            let size = (8 + 1 + n + usize::from(self.ftype) + 2).div_ceil(8) * 8;
            if n == 0 || at + size > end {
                return Err("xfs: directory entry".into());
            }
            out.push((name.to_vec(), num, ft));
            at += size;
        }
        Ok(())
    }

    /// The inode of `path` below the root (`/`-separated).
    pub fn lookup(&self, path: &str) -> Result<Option<(u64, Inode)>, String> {
        let mut at = self.root;
        let mut ino = self.inode(at)?;
        for c in path.split('/').filter(|c| !c.is_empty()) {
            if ino.kind() != KIND_DIR {
                return Ok(None);
            }
            let mut bad = 0;
            let Some(n) = self
                .dir(&ino, &mut bad)?
                .into_iter()
                .find(|e| e.0 == c.as_bytes())
                .map(|e| e.1)
            else {
                return Ok(None);
            };
            at = n;
            ino = self.inode(at)?;
        }
        Ok(Some((at, ino)))
    }

    pub fn label_uuid(&self) -> Result<(Option<String>, String), String> {
        let sb = self.read(0, 512)?;
        let l = String::from_utf8_lossy(sb[108..120].split(|b| *b == 0).next().unwrap_or(&[])).into_owned();
        let u = crate::hex(&sb[32..48]);
        let uuid = format!(
            "{}-{}-{}-{}-{}",
            &u[0..8],
            &u[8..12],
            &u[12..16],
            &u[16..20],
            &u[20..32]
        );
        Ok((Some(l).filter(|l| !l.is_empty()), uuid))
    }

    /// Used inodes (superblock counters; the estimate for live progress).
    pub fn used_inodes(&self) -> u64 {
        self.read(0, 512)
            .map_or(0, |sb| be64(&sb, 128).saturating_sub(be64(&sb, 136)))
    }
}

/// The file type byte of a directory entry (XFS_DIR3_FT_*) as an entry kind.
fn ftype_kind(ft: u8) -> u8 {
    match ft {
        1 => KIND_FILE,
        2 => KIND_DIR,
        7 => KIND_SYMLINK,
        _ => KIND_OTHER,
    }
}

pub fn walk(v: &Vol, out: &mut Out, info: &mut Volume) -> Result<(), String> {
    let fs = Xfs::open(v)?;
    let (label, uuid) = fs.label_uuid()?;
    info.label = label;
    info.uuid = Some(uuid);
    out.expect(fs.used_inodes().saturating_sub(1));
    if let Ok(Some((_, f))) = fs.lookup("etc/fstab") {
        if f.kind() == KIND_FILE && f.size <= 64 << 10 {
            if let Ok(t) = fs.read_file(&f, 64 << 10) {
                info.fstab = Some(String::from_utf8_lossy(&t).into_owned());
            }
        }
    }
    // Phase 39 C2: account names for the owner column (helper 0 alone)
    if out.owns("", 0) {
        if let Ok(Some((_, f))) = fs.lookup("etc/passwd") {
            if f.kind() == KIND_FILE && f.size <= crate::PASSWD_MAX {
                if let Ok(t) = fs.read_file(&f, crate::PASSWD_MAX) {
                    info.accounts = crate::passwd_accounts(&String::from_utf8_lossy(&t));
                }
            }
        }
    }
    // directory records: inodes sit where the AG geometry puts them (no shared lookup
    // structure as NTFS's $MFT record), a grown volume changes the geometry
    out.dir_basis(
        format!(
            "xfs-{}-{}-{}-{}-{}",
            fs.bs, fs.agblocks, fs.agcount, fs.inodesize, fs.dirblklog
        ),
        Vec::new(),
    );
    let mut stack: Vec<(u64, String, usize)> = vec![(fs.root, String::new(), 0)];
    let mut visited = HashSet::from([fs.root]);
    while let Some((num, rel, depth)) = stack.pop() {
        if !out.walks(&rel, depth) {
            continue; // another helper's share
        }
        if out.out_of_time() {
            return Ok(());
        }
        let own = out.owns(&rel, depth);
        if let Some(subs) = out.reuse_dir(&rel, own) {
            // Phase 31c: listed in the previous snapshot and nothing that listing read changed
            for (n, name) in subs {
                let path = if rel.is_empty() { name } else { format!("{rel}/{name}") };
                if depth + 1 < MAX_DEPTH && out.walks(&path, depth + 1) && visited.insert(n) {
                    stack.push((n, path, depth + 1));
                }
            }
            continue;
        }
        if own {
            out.dir_start();
        }
        let skipped0 = info.skipped_entries;
        let mut bad = 0;
        let dir = fs.inode(num).and_then(|d| {
            if d.kind() == KIND_DIR {
                Ok(d)
            } else {
                Err("not a directory".into())
            }
        });
        let entries = match dir.and_then(|d| fs.dir(&d, &mut bad)) {
            Ok(e) => e,
            Err(e) => {
                if own {
                    out.note(info, format!("/{rel}: {e}"));
                }
                continue;
            }
        };
        if bad > 0 && own {
            out.note(info, format!("/{rel}: {bad} damaged directory block(s)"));
        }
        let mut subdirs = Vec::new();
        let mut seen = HashSet::new();
        let mut budget_miss = false;
        for (name, n, ft) in entries {
            if name == b"." || name == b".." {
                continue;
            }
            let name = String::from_utf8_lossy(&name).into_owned();
            let path = if rel.is_empty() {
                name.clone()
            } else {
                format!("{rel}/{name}")
            };
            if !own {
                // another helper's entries: only the subdirectories (type from the entry when recorded)
                let is_dir = match ft {
                    Some(ft) => ftype_kind(ft) == KIND_DIR,
                    None => fs.inode(n).is_ok_and(|i| i.kind() == KIND_DIR),
                };
                if is_dir
                    && !name.contains('/')
                    && path.len() <= MAX_PATH
                    && depth + 1 < MAX_DEPTH
                    && out.walks(&path, depth + 1)
                    && visited.insert(n)
                {
                    stack.push((n, path, depth + 1));
                }
                continue;
            }
            if name.contains('/') || path.len() > MAX_PATH || !seen.insert(name.clone()) {
                info.skipped_entries += 1;
                continue;
            }
            let Ok(ino) = fs.inode(n) else {
                info.skipped_entries += 1;
                continue;
            };
            let kind = ino.kind();
            let size = if kind == KIND_FILE { ino.size } else { 0 };
            let owner = format!("{}:{}", ino.uid, ino.gid);
            // Phase 31c: the content's SHA-256 (budgeted)
            let mut sha = None;
            if kind == KIND_FILE && out.hashing() {
                if !out.hash_budget(size) {
                    info.unhashed_files += 1;
                    budget_miss = true;
                } else {
                    match fs.hash_file(&ino) {
                        Ok(h) => {
                            sha = Some(h);
                            info.hashed_files += 1;
                        }
                        Err(_) => info.unhashed_files += 1,
                    }
                }
            }
            if !out.emit_ext(info, &path, size, ino.mtime, kind, Some(&owner), sha.as_ref())? {
                return Ok(());
            }
            if kind == KIND_DIR {
                subdirs.push((n, name));
                if out.walks(&path, depth + 1) {
                    if depth + 1 >= MAX_DEPTH {
                        out.note(info, format!("/{path}: nested too deeply"));
                        continue;
                    }
                    if visited.insert(n) {
                        stack.push((n, path, depth + 1));
                    }
                }
            }
        }
        if own && bad == 0 {
            out.dir_listed(&crate::DirRec {
                rel,
                subdirs,
                skipped: info.skipped_entries - skipped0,
                hashed: out.hashing() && !budget_miss,
                ..Default::default()
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extent_records_and_crc() {
        // startoff 5, startblock 0x123456789, count 7, unwritten
        let (off, fsb, len) = (5u64, 0x1_2345_6789u64, 7u64);
        let l0 = (1u64 << 63) | (off << 9) | (fsb >> 43);
        let l1 = ((fsb & ((1 << 43) - 1)) << 21) | len;
        let mut r = l0.to_be_bytes().to_vec();
        r.extend(l1.to_be_bytes());
        assert_eq!(
            ext(&r),
            Ext {
                off,
                fsb,
                len,
                unwritten: true
            }
        );
        // CRC-32C check value of "123456789" is 0xe3069283
        let mut b = b"123456789\0\0\0\0".to_vec();
        b[9..13].copy_from_slice(&0u32.to_le_bytes());
        let mut c = !0u32;
        for &x in b"123456789\0\0\0\0" {
            c ^= u32::from(x);
            for _ in 0..8 {
                c = if c & 1 != 0 { (c >> 1) ^ 0x82F6_3B78 } else { c >> 1 };
            }
        }
        b[9..13].copy_from_slice(&(!c).to_le_bytes());
        assert!(crc_ok(&b, 9));
        b[0] ^= 1;
        assert!(!crc_ok(&b, 9));
    }
}
