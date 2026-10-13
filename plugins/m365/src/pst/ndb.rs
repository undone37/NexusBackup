//! NDB layer of a Unicode PST ([MS-PST] 2.2): header, allocation maps, blocks
//! (data blocks, XBLOCK / XXBLOCK data trees, SLBLOCK / SIBLOCK subnode trees) and
//! the two B-trees (NBT, BBT). Write-once: blocks are appended in file order as the
//! caller produces them (no encryption, `bCryptMethod` = none); the maps, the B-tree
//! pages, the density list and the header are written by [`Ndb::finish`], which
//! seeks back. Only metadata is kept in memory (24–32 bytes per block / node).

use std::io::{self, Seek, SeekFrom, Write};

pub const PAGE: u64 = 512;
/// Data bytes of one block (8 KiB minus the 16-byte trailer).
pub const BLOCK_DATA: usize = 8176;
const TRAILER: usize = 16;
const AMAP_FIRST: u64 = 0x4400;
/// Bytes one AMap page maps (496 bytes × 8 bits × 64 bytes).
pub const AMAP_SPAN: u64 = 496 * 8 * 64;
const DLIST_AT: u64 = 0x4200;
/// XBLOCK / XXBLOCK entries per block, SLBLOCK and SIBLOCK entries per block.
const X_MAX: usize = (BLOCK_DATA - 8) / 8;
const SL_MAX: usize = (BLOCK_DATA - 8) / 24;
const SI_MAX: usize = (BLOCK_DATA - 8) / 16;

const PT_BBT: u8 = 0x80;
const PT_NBT: u8 = 0x81;
const PT_FMAP: u8 = 0x82;
const PT_PMAP: u8 = 0x83;
const PT_AMAP: u8 = 0x84;
const PT_FPMAP: u8 = 0x85;
const PT_DL: u8 = 0x86;

/// [MS-PST] 5.3: CRC-32 (reflected, polynomial 0xEDB88320) without pre/post inversion.
pub fn crc(data: &[u8]) -> u32 {
    static TABLE: std::sync::OnceLock<[u32; 256]> = std::sync::OnceLock::new();
    let t = TABLE.get_or_init(|| {
        let mut t = [0u32; 256];
        for (i, e) in t.iter_mut().enumerate() {
            let mut c = i as u32;
            for _ in 0..8 {
                c = if c & 1 != 0 { 0xEDB8_8320 ^ (c >> 1) } else { c >> 1 };
            }
            *e = c;
        }
        t
    });
    data.iter()
        .fold(0u32, |c, &b| t[((c ^ u32::from(b)) & 0xFF) as usize] ^ (c >> 8))
}

/// [MS-PST] 5.5: block / page signature.
pub fn sig(ib: u64, bid: u64) -> u16 {
    let v = (ib as u32) ^ (bid as u32);
    ((v >> 16) as u16) ^ (v as u16)
}

/// Reserved pages at the start of AMap region `i`: the AMap itself, a PMap every
/// 8th region, an FMap every 496th region from 128 on, an FPMap every 31744th from 8192 on.
fn reserved(i: u64) -> (bool, bool, bool) {
    let pmap = i.is_multiple_of(8);
    let fmap = pmap && i >= 128 && (i - 128).is_multiple_of(496);
    let fpmap = pmap && i >= 8192 && (i - 8192).is_multiple_of(496 * 64);
    (pmap, fmap, fpmap)
}

fn region_start(i: u64) -> u64 {
    AMAP_FIRST + i * AMAP_SPAN
}

fn data_start(i: u64) -> u64 {
    let (p, f, fp) = reserved(i);
    region_start(i) + PAGE * (1 + u64::from(p) + u64::from(f) + u64::from(fp))
}

#[derive(Clone, Copy)]
struct BbtEntry {
    bid: u64,
    ib: u64,
    cb: u16,
}

#[derive(Clone, Copy)]
pub struct NbtEntry {
    pub nid: u32,
    pub data: u64,
    pub sub: u64,
    pub parent: u32,
}

/// Subnode of a node ([MS-PST] 2.2.2.8.3.3): its NID (unique within the parent) and
/// its own data / subnode blocks.
pub struct SubEntry {
    pub nid: u32,
    pub data: u64,
    pub sub: u64,
}

pub struct Ndb<W: Write + Seek> {
    w: W,
    /// next free byte (allocation cursor)
    pos: u64,
    next_bid: u64,
    next_page: u64,
    bbt: Vec<BbtEntry>,
    nbt: Vec<NbtEntry>,
    /// allocation bitmap per AMap region
    amaps: Vec<[u8; 496]>,
    pub nid_max: [u32; 32],
}

impl<W: Write + Seek> Ndb<W> {
    pub fn new(w: W) -> io::Result<Ndb<W>> {
        let mut n = Ndb {
            w,
            pos: data_start(0),
            next_bid: 4,
            next_page: 1,
            bbt: Vec::new(),
            nbt: Vec::new(),
            amaps: Vec::new(),
            nid_max: [0x400; 32],
        };
        n.nid_max[3] = 0x4000; // NID_TYPE_SEARCH_FOLDER
        n.nid_max[4] = 0x10000; // NID_TYPE_NORMAL_MESSAGE
        n.nid_max[8] = 0x8000; // NID_TYPE_ASSOC_MESSAGE
        n.region(0);
        // the header area up to the first AMap: written by finish, zero now
        n.w.seek(SeekFrom::Start(0))?;
        n.w.write_all(&vec![0; AMAP_FIRST as usize])?;
        Ok(n)
    }

    /// Bytes written so far (the file size if it were finished now, roughly).
    pub fn size(&self) -> u64 {
        self.pos
    }

    /// The NBT entry of a top-level node.
    pub fn add_node(&mut self, e: NbtEntry) {
        let t = (e.nid & 0x1F) as usize;
        self.nid_max[t] = self.nid_max[t].max(e.nid >> 5);
        self.nbt.push(e);
    }

    fn region(&mut self, i: u64) -> &mut [u8; 496] {
        while self.amaps.len() as u64 <= i {
            let k = self.amaps.len() as u64;
            let mut m = [0u8; 496];
            let pages = (data_start(k) - region_start(k)) / PAGE;
            m[..pages as usize].fill(0xFF);
            self.amaps.push(m);
        }
        &mut self.amaps[i as usize]
    }

    /// Reserves `size` bytes (multiple of 64) aligned to `align` within one AMap region.
    fn alloc(&mut self, size: u64, align: u64) -> u64 {
        let mut at = self.pos.div_ceil(align) * align;
        let i = (at - AMAP_FIRST) / AMAP_SPAN;
        if at + size > region_start(i + 1) {
            at = data_start(i + 1);
        } else if at < data_start(i) {
            at = data_start(i);
        }
        let i = (at - AMAP_FIRST) / AMAP_SPAN;
        let first = ((at - region_start(i)) / 64) as usize;
        let m = self.region(i);
        for bit in first..first + (size / 64) as usize {
            m[bit / 8] |= 0x80 >> (bit % 8);
        }
        self.pos = at + size;
        at
    }

    fn put(&mut self, at: u64, data: &[u8]) -> io::Result<()> {
        self.w.seek(SeekFrom::Start(at))?;
        self.w.write_all(data)
    }

    fn bid(&mut self, internal: bool) -> u64 {
        let b = self.next_bid | if internal { 2 } else { 0 };
        self.next_bid += 4;
        b
    }

    /// One block (≤ 8176 bytes of data) → its BID.
    pub fn block(&mut self, data: &[u8], internal: bool) -> io::Result<u64> {
        assert!(data.len() <= BLOCK_DATA, "block of {} bytes", data.len());
        let size = (data.len() + TRAILER).div_ceil(64) as u64 * 64;
        let at = self.alloc(size, 64);
        let bid = self.bid(internal);
        let mut b = Vec::with_capacity(size as usize);
        b.extend_from_slice(data);
        b.resize(size as usize - TRAILER, 0);
        b.extend_from_slice(&(data.len() as u16).to_le_bytes());
        b.extend_from_slice(&sig(at, bid).to_le_bytes());
        b.extend_from_slice(&crc(data).to_le_bytes());
        b.extend_from_slice(&bid.to_le_bytes());
        self.put(at, &b)?;
        self.bbt.push(BbtEntry {
            bid,
            ib: at,
            cb: data.len() as u16,
        });
        Ok(bid)
    }

    /// A node's data stream given as its data blocks (each ≤ 8176 bytes; heap pages
    /// and row-matrix blocks keep their boundaries): one block, or a data tree.
    pub fn data_blocks(&mut self, blocks: &[Vec<u8>]) -> io::Result<u64> {
        if blocks.is_empty() {
            return Ok(0);
        }
        if blocks.len() == 1 {
            return self.block(&blocks[0], false);
        }
        let mut leaves = Vec::with_capacity(blocks.len());
        for b in blocks {
            leaves.push((self.block(b, false)?, b.len() as u64));
        }
        self.tree(&leaves)
    }

    /// Raw bytes as a data stream (cut into 8176-byte blocks).
    pub fn data(&mut self, bytes: &[u8]) -> io::Result<u64> {
        if bytes.len() <= BLOCK_DATA {
            return self.block(bytes, false);
        }
        let mut leaves = Vec::with_capacity(bytes.len() / BLOCK_DATA + 1);
        for b in bytes.chunks(BLOCK_DATA) {
            leaves.push((self.block(b, false)?, b.len() as u64));
        }
        self.tree(&leaves)
    }

    /// XBLOCKs over the data blocks, an XXBLOCK over several XBLOCKs.
    fn tree(&mut self, leaves: &[(u64, u64)]) -> io::Result<u64> {
        let total: u64 = leaves.iter().map(|l| l.1).sum();
        if total > u64::from(u32::MAX) {
            return Err(io::Error::other("node data larger than 4 GiB"));
        }
        let mut xs = Vec::new();
        for group in leaves.chunks(X_MAX) {
            let lcb: u64 = group.iter().map(|l| l.1).sum();
            let bid = self.xblock(1, group.iter().map(|l| l.0), group.len(), lcb)?;
            xs.push((bid, lcb));
        }
        if xs.len() == 1 {
            return Ok(xs[0].0);
        }
        if xs.len() > X_MAX {
            return Err(io::Error::other("node data too large for an XXBLOCK"));
        }
        self.xblock(2, xs.iter().map(|x| x.0), xs.len(), total)
    }

    fn xblock(&mut self, level: u8, bids: impl Iterator<Item = u64>, n: usize, lcb: u64) -> io::Result<u64> {
        let mut b = vec![0x01, level];
        b.extend_from_slice(&(n as u16).to_le_bytes());
        b.extend_from_slice(&(lcb as u32).to_le_bytes());
        for bid in bids {
            b.extend_from_slice(&bid.to_le_bytes());
        }
        self.block(&b, true)
    }

    /// Subnode B-tree (SLBLOCK, SIBLOCK above 340 entries) → its BID (0: none).
    pub fn subnodes(&mut self, mut subs: Vec<SubEntry>) -> io::Result<u64> {
        if subs.is_empty() {
            return Ok(0);
        }
        subs.sort_by_key(|s| s.nid);
        let mut leaves = Vec::new();
        for group in subs.chunks(SL_MAX) {
            let mut b = vec![0x02, 0x00];
            b.extend_from_slice(&(group.len() as u16).to_le_bytes());
            b.extend_from_slice(&[0; 4]);
            for s in group {
                b.extend_from_slice(&u64::from(s.nid).to_le_bytes());
                b.extend_from_slice(&s.data.to_le_bytes());
                b.extend_from_slice(&s.sub.to_le_bytes());
            }
            leaves.push((group[0].nid, self.block(&b, true)?));
        }
        if leaves.len() == 1 {
            return Ok(leaves[0].1);
        }
        if leaves.len() > SI_MAX {
            return Err(io::Error::other("too many subnodes"));
        }
        let mut b = vec![0x02, 0x01];
        b.extend_from_slice(&(leaves.len() as u16).to_le_bytes());
        b.extend_from_slice(&[0; 4]);
        for (nid, bid) in &leaves {
            b.extend_from_slice(&u64::from(*nid).to_le_bytes());
            b.extend_from_slice(&bid.to_le_bytes());
        }
        self.block(&b, true)
    }

    /// One B-tree page at a fresh 512-byte slot → (page BID, offset).
    fn page(&mut self, ptype: u8, entries: &[u8], n: usize, max: u8, cb: u8, level: u8) -> io::Result<(u64, u64)> {
        let at = self.alloc(PAGE, PAGE);
        let bid = self.next_page;
        self.next_page += 1;
        let mut p = vec![0u8; 512];
        p[..entries.len()].copy_from_slice(entries);
        p[488] = n as u8;
        p[489] = max;
        p[490] = cb;
        p[491] = level;
        self.trailer(&mut p, ptype, sig(at, bid), bid);
        self.put(at, &p)?;
        Ok((bid, at))
    }

    fn trailer(&self, p: &mut [u8], ptype: u8, wsig: u16, bid: u64) {
        let c = crc(&p[..496]);
        p[496] = ptype;
        p[497] = ptype;
        p[498..500].copy_from_slice(&wsig.to_le_bytes());
        p[500..504].copy_from_slice(&c.to_le_bytes());
        p[504..512].copy_from_slice(&bid.to_le_bytes());
    }

    /// Builds a B-tree from sorted (key, leaf entry bytes) → root BREF (bid, ib).
    fn btree(&mut self, ptype: u8, leaves: Vec<(u64, Vec<u8>)>, cb_leaf: u8) -> io::Result<(u64, u64)> {
        let per_leaf = 488 / cb_leaf as usize;
        let mut level: Vec<(u64, u64, u64)> = Vec::new(); // (first key, bid, ib)
        if leaves.is_empty() {
            let (bid, ib) = self.page(ptype, &[], 0, per_leaf as u8, cb_leaf, 0)?;
            return Ok((bid, ib));
        }
        for group in leaves.chunks(per_leaf) {
            let bytes: Vec<u8> = group.iter().flat_map(|(_, e)| e.iter().copied()).collect();
            let (bid, ib) = self.page(ptype, &bytes, group.len(), per_leaf as u8, cb_leaf, 0)?;
            level.push((group[0].0, bid, ib));
        }
        let mut depth = 1u8;
        while level.len() > 1 {
            let mut up = Vec::new();
            for group in level.chunks(20) {
                let mut bytes = Vec::with_capacity(group.len() * 24);
                for (key, bid, ib) in group {
                    bytes.extend_from_slice(&key.to_le_bytes());
                    bytes.extend_from_slice(&bid.to_le_bytes());
                    bytes.extend_from_slice(&ib.to_le_bytes());
                }
                let (bid, ib) = self.page(ptype, &bytes, group.len(), 20, 24, depth)?;
                up.push((group[0].0, bid, ib));
            }
            level = up;
            depth += 1;
        }
        Ok((level[0].1, level[0].2))
    }

    /// Writes the B-trees, the maps, the density list and the header; returns the writer.
    pub fn finish(mut self) -> io::Result<W> {
        let mut nbt = std::mem::take(&mut self.nbt);
        nbt.sort_by_key(|e| e.nid);
        let nbt: Vec<(u64, Vec<u8>)> = nbt
            .iter()
            .map(|e| {
                let mut b = Vec::with_capacity(32);
                b.extend_from_slice(&u64::from(e.nid).to_le_bytes());
                b.extend_from_slice(&e.data.to_le_bytes());
                b.extend_from_slice(&e.sub.to_le_bytes());
                b.extend_from_slice(&e.parent.to_le_bytes());
                b.extend_from_slice(&[0; 4]);
                (u64::from(e.nid), b)
            })
            .collect();
        let nbt_root = self.btree(PT_NBT, nbt, 32)?;
        let mut bbt = std::mem::take(&mut self.bbt);
        bbt.sort_by_key(|e| e.bid);
        let bbt: Vec<(u64, Vec<u8>)> = bbt
            .iter()
            .map(|e| {
                let mut b = Vec::with_capacity(24);
                b.extend_from_slice(&e.bid.to_le_bytes());
                b.extend_from_slice(&e.ib.to_le_bytes());
                b.extend_from_slice(&e.cb.to_le_bytes());
                b.extend_from_slice(&2u16.to_le_bytes()); // cRef: the BBT entry + one reference
                b.extend_from_slice(&[0; 4]);
                (e.bid, b)
            })
            .collect();
        let bbt_root = self.btree(PT_BBT, bbt, 24)?;
        // the file ends at an AMap region boundary
        let regions = ((self.pos - AMAP_FIRST).div_ceil(AMAP_SPAN)).max(1);
        self.region(regions - 1);
        let eof = region_start(regions);
        let mut free_total = 0u64;
        let mut free_slots = Vec::with_capacity(regions as usize);
        for i in 0..regions {
            let m = self.amaps[i as usize];
            let mut p = vec![0u8; 512];
            p[..496].copy_from_slice(&m);
            let at = region_start(i);
            self.trailer(&mut p, PT_AMAP, 0, at);
            self.put(at, &p)?;
            let free: u64 = m.iter().map(|b| u64::from(b.count_zeros())).sum();
            free_total += free * 64;
            free_slots.push(free);
            let (pmap, _, _) = reserved(i);
            if pmap {
                let mut p = vec![0xFFu8; 512];
                self.trailer(&mut p, PT_PMAP, 0, at + PAGE);
                self.put(at + PAGE, &p)?;
            }
        }
        // FMaps (one byte per region: longest free run, capped at 255) and FPMaps
        for i in 0..regions {
            let (_, fmap, fpmap) = reserved(i);
            let mut at = region_start(i) + 2 * PAGE;
            if fmap {
                let mut p = vec![0u8; 512];
                for (k, slot) in p[..496].iter_mut().enumerate() {
                    if let Some(m) = self.amaps.get(i as usize + k) {
                        *slot = longest_free(m).min(255) as u8;
                    }
                }
                self.trailer(&mut p, PT_FMAP, 0, at);
                self.put(at, &p)?;
                at += PAGE;
            }
            if fpmap {
                let mut p = vec![0xFFu8; 512];
                self.trailer(&mut p, PT_FPMAP, 0, at);
                self.put(at, &p)?;
            }
        }
        self.put(eof - 1, &[0])?;
        // density list: the emptiest regions first
        let mut order: Vec<u64> = (0..regions).collect();
        order.sort_by_key(|&i| std::cmp::Reverse(free_slots[i as usize]));
        order.truncate(119);
        let mut dl = vec![0u8; 512];
        dl[0] = 0x01; // DFL_BACKFILL_COMPLETE
        dl[1] = order.len() as u8;
        dl[4..8].copy_from_slice(&(order[0] as u32).to_le_bytes());
        for (k, &i) in order.iter().enumerate() {
            let e = (i as u32 & 0xF_FFFF) | ((free_slots[i as usize].min(0xFFF) as u32) << 20);
            dl[8 + 4 * k..12 + 4 * k].copy_from_slice(&e.to_le_bytes());
        }
        let page_bid = self.next_page;
        self.trailer(&mut dl, PT_DL, sig(DLIST_AT, page_bid), page_bid);
        self.put(DLIST_AT, &dl)?;
        let hdr = self.header(eof, region_start(regions - 1), free_total, nbt_root, bbt_root);
        self.put(0, &hdr)?;
        self.w.flush()?;
        Ok(self.w)
    }

    fn header(&self, eof: u64, amap_last: u64, free: u64, nbt: (u64, u64), bbt: (u64, u64)) -> Vec<u8> {
        let mut h = vec![0u8; 564];
        h[0..4].copy_from_slice(b"!BDN");
        h[8..10].copy_from_slice(b"SM");
        h[10..12].copy_from_slice(&23u16.to_le_bytes()); // Unicode
        h[12..14].copy_from_slice(&19u16.to_le_bytes());
        h[14] = 1;
        h[15] = 1;
        h[32..40].copy_from_slice(&self.next_page.to_le_bytes());
        h[40..44].copy_from_slice(&1u32.to_le_bytes()); // dwUnique
        for (k, n) in self.nid_max.iter().enumerate() {
            h[44 + 4 * k..48 + 4 * k].copy_from_slice(&n.to_le_bytes());
        }
        // ROOT at 180
        let r = 180;
        h[r + 4..r + 12].copy_from_slice(&eof.to_le_bytes());
        h[r + 12..r + 20].copy_from_slice(&amap_last.to_le_bytes());
        h[r + 20..r + 28].copy_from_slice(&free.to_le_bytes());
        h[r + 36..r + 44].copy_from_slice(&nbt.0.to_le_bytes());
        h[r + 44..r + 52].copy_from_slice(&nbt.1.to_le_bytes());
        h[r + 52..r + 60].copy_from_slice(&bbt.0.to_le_bytes());
        h[r + 60..r + 68].copy_from_slice(&bbt.1.to_le_bytes());
        h[r + 68] = 0x02; // VALID_AMAP2
        h[256..512].fill(0xFF); // rgbFM, rgbFP (deprecated)
        h[512] = 0x80;
        h[513] = 0; // NDB_CRYPT_NONE
        h[516..524].copy_from_slice(&self.next_bid.to_le_bytes());
        let partial = crc(&h[8..8 + 471]);
        h[4..8].copy_from_slice(&partial.to_le_bytes());
        let full = crc(&h[8..524]);
        h[524..528].copy_from_slice(&full.to_le_bytes());
        h
    }
}

/// Longest run of free 64-byte slots in an AMap.
fn longest_free(m: &[u8; 496]) -> u32 {
    let (mut best, mut run) = (0, 0);
    for byte in m {
        for k in 0..8 {
            if byte & (0x80 >> k) == 0 {
                run += 1;
                best = best.max(run);
            } else {
                run = 0;
            }
        }
    }
    best
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// The sample intermediate NBT page of [MS-PST] 3.3: its CRC and signature.
    #[test]
    fn crc_and_signature_match_the_spec() {
        let mut p = vec![0u8; 496];
        let entries: [u64; 9] = [0x21, 0x205, 0x7E00, 0x60F, 0x141, 0x7000, 0x8022, 0xFD, 0x8400];
        for (k, v) in entries.iter().enumerate() {
            p[8 * k..8 * k + 8].copy_from_slice(&v.to_le_bytes());
        }
        p[488..492].copy_from_slice(&[0x03, 0x14, 0x18, 0x01]);
        assert_eq!(crc(&p), 0x02E8_B164);
        assert_eq!(sig(0x8200, 0x206), 0x8006);
        assert_eq!(crc(b""), 0);
    }

    #[test]
    fn reserved_pages() {
        assert_eq!(reserved(0), (true, false, false));
        assert_eq!(reserved(1), (false, false, false));
        assert_eq!(reserved(128), (true, true, false));
        assert_eq!(reserved(128 + 496), (true, true, false));
        assert_eq!(reserved(8192), (true, false, true));
        assert_eq!(data_start(0), 0x4800);
        assert_eq!(data_start(1), 0x4400 + AMAP_SPAN + 512);
    }

    #[test]
    fn blocks_and_allocation() {
        let mut n = Ndb::new(Cursor::new(Vec::new())).unwrap();
        let b1 = n.block(b"hello", false).unwrap();
        let b2 = n.data(&vec![7u8; 3 * BLOCK_DATA + 5]).unwrap();
        assert_eq!(b1, 4);
        assert_eq!(b2 & 2, 2, "an XBLOCK is internal");
        // block layout: data, padding, trailer (cb, sig, crc, bid) at the end of 64 bytes
        let first = &n.amaps[0];
        assert_eq!(first[0], 0xFF, "AMap + PMap pages");
        assert_eq!(first[1], 0xFF, "...");
        assert_eq!(first[2] & 0x80, 0x80, "the first block");
        let w = n.finish().unwrap().into_inner();
        let at = 0x4800usize;
        assert_eq!(&w[at..at + 5], b"hello");
        assert_eq!(u16::from_le_bytes([w[at + 48], w[at + 49]]), 5);
        assert_eq!(
            u32::from_le_bytes(w[at + 52..at + 56].try_into().unwrap()),
            crc(b"hello")
        );
        assert_eq!(u64::from_le_bytes(w[at + 56..at + 64].try_into().unwrap()), 4);
        assert_eq!(w.len() as u64, 0x4400 + AMAP_SPAN, "one AMap region");
        assert_eq!(&w[..4], b"!BDN");
        assert_eq!(u32::from_le_bytes(w[524..528].try_into().unwrap()), crc(&w[8..524]));
        // AMap page CRC
        let am = &w[0x4400..0x4600];
        assert_eq!(am[496], PT_AMAP);
        assert_eq!(u32::from_le_bytes(am[500..504].try_into().unwrap()), crc(&am[..496]));
    }

    #[test]
    fn allocation_skips_the_next_regions_maps() {
        let mut n = Ndb::new(Cursor::new(Vec::new())).unwrap();
        let big = vec![1u8; BLOCK_DATA];
        let mut last = 0;
        while n.pos < data_start(1) + 10 * 8192 {
            n.block(&big, false).unwrap();
            last = n.bbt.last().unwrap().ib;
            let i = (last - AMAP_FIRST) / AMAP_SPAN;
            assert!(last >= data_start(i) && last + 8192 <= region_start(i + 1), "{last:#x}");
        }
        assert!(last > data_start(1));
    }
}
