//! LTP layer ([MS-PST] 2.3): heap-on-node (HN), BTree-on-heap (BTH), property
//! contexts (PC) and table contexts (TC), built in memory as the node's data blocks
//! plus its subnodes (values over 3580 bytes, large row matrices).

use super::ndb::BLOCK_DATA;

/// Largest heap allocation; bigger values go to a subnode.
pub const MAX_ITEM: usize = 3580;
const MAX_ALLOCS: usize = 2047;
pub const SIG_TC: u8 = 0x7C;
pub const SIG_BTH: u8 = 0xB5;
pub const SIG_PC: u8 = 0xBC;
/// NID type of subnodes holding property values / row matrices.
const NID_TYPE_LTP: u32 = 0x1F;

pub const PT_BOOL: u16 = 0x000B;
pub const PT_I32: u16 = 0x0003;
pub const PT_I64: u16 = 0x0014;
pub const PT_TIME: u16 = 0x0040;
pub const PT_STR: u16 = 0x001F;
pub const PT_BIN: u16 = 0x0102;

/// A property value.
#[derive(Clone, Debug, PartialEq)]
pub enum Val {
    Bool(bool),
    I32(i32),
    I64(i64),
    /// FILETIME (100 ns since 1601)
    Time(u64),
    Str(String),
    Bin(Vec<u8>),
}

impl Val {
    pub fn ptype(&self) -> u16 {
        match self {
            Val::Bool(_) => PT_BOOL,
            Val::I32(_) => PT_I32,
            Val::I64(_) => PT_I64,
            Val::Time(_) => PT_TIME,
            Val::Str(_) => PT_STR,
            Val::Bin(_) => PT_BIN,
        }
    }

    /// The value's bytes (strings: UTF-16LE without terminator).
    fn bytes(&self) -> Vec<u8> {
        match self {
            Val::Bool(b) => vec![u8::from(*b)],
            Val::I32(v) => v.to_le_bytes().to_vec(),
            Val::I64(v) => v.to_le_bytes().to_vec(),
            Val::Time(v) => v.to_le_bytes().to_vec(),
            Val::Str(s) => s.encode_utf16().flat_map(u16::to_le_bytes).collect(),
            Val::Bin(b) => b.clone(),
        }
    }
}

/// Data of a subnode: heap pages / row-matrix blocks (boundaries kept) or raw bytes.
pub enum SubData {
    Blocks(Vec<Vec<u8>>),
    Raw(Vec<u8>),
}

pub struct SubNode {
    pub nid: u32,
    pub data: SubData,
    pub subs: Vec<SubNode>,
}

/// A node's content: its data blocks and its subnodes.
pub struct Built {
    pub blocks: Vec<Vec<u8>>,
    pub subs: Vec<SubNode>,
}

/// Local NIDs for value subnodes of one node.
#[derive(Default)]
pub struct SubIds(u32);

impl SubIds {
    pub fn alloc(&mut self) -> u32 {
        self.0 += 1;
        (self.0 << 5) | NID_TYPE_LTP
    }
}

fn page_header(i: usize) -> usize {
    match i {
        0 => 12,
        8 => 66,
        i if i > 8 && (i - 8) % 128 == 0 => 66,
        _ => 2,
    }
}

/// [MS-PST] 2.3.1.2 fill level of a heap block with `free` bytes left.
fn fill_level(free: usize) -> u8 {
    const BOUNDS: [usize; 15] = [
        3584, 2560, 2048, 1792, 1536, 1280, 1024, 768, 512, 256, 128, 64, 32, 16, 8,
    ];
    BOUNDS.iter().position(|&b| free >= b).unwrap_or(15) as u8
}

#[derive(Default)]
struct HeapPage {
    items: Vec<Vec<u8>>,
    used: usize,
}

/// Heap-on-node builder.
pub struct Heap {
    client_sig: u8,
    pages: Vec<HeapPage>,
}

impl Heap {
    pub fn new(client_sig: u8) -> Heap {
        Heap {
            client_sig,
            pages: vec![HeapPage::default()],
        }
    }

    fn fits(&self, i: usize, p: &HeapPage, len: usize) -> bool {
        let n = p.items.len() + 1;
        let bytes = page_header(i) + p.used + len;
        n <= MAX_ALLOCS && bytes.div_ceil(2) * 2 + 4 + 2 * (n + 1) <= BLOCK_DATA
    }

    /// Allocates `data` (≤ 3580 bytes) → its HID.
    pub fn alloc(&mut self, data: Vec<u8>) -> u32 {
        assert!(data.len() <= MAX_ITEM);
        let last = self.pages.len() - 1;
        if !self.fits(last, &self.pages[last], data.len()) {
            self.pages.push(HeapPage::default());
        }
        let i = self.pages.len() - 1;
        let p = &mut self.pages[i];
        p.used += data.len();
        p.items.push(data);
        ((i as u32) << 16) | ((p.items.len() as u32) << 5)
    }

    /// Replaces an allocation by data of the same size.
    pub fn set(&mut self, hid: u32, data: Vec<u8>) {
        let item = &mut self.pages[(hid >> 16) as usize].items[((hid >> 5) & 0x7FF) as usize - 1];
        assert_eq!(item.len(), data.len());
        *item = data;
    }

    /// The heap's data blocks (one per page).
    pub fn blocks(self, user_root: u32) -> Vec<Vec<u8>> {
        let n = self.pages.len();
        let mut out: Vec<Vec<u8>> = Vec::with_capacity(n);
        let mut levels = Vec::with_capacity(n);
        for (i, p) in self.pages.iter().enumerate() {
            let mut b = vec![0u8; page_header(i)];
            let mut offs = Vec::with_capacity(p.items.len() + 1);
            for it in &p.items {
                offs.push(b.len() as u16);
                b.extend_from_slice(it);
            }
            offs.push(b.len() as u16);
            if b.len() % 2 == 1 {
                b.push(0);
            }
            let hnpm = b.len() as u16;
            b.extend_from_slice(&(p.items.len() as u16).to_le_bytes());
            b.extend_from_slice(&0u16.to_le_bytes());
            for o in offs {
                b.extend_from_slice(&o.to_le_bytes());
            }
            b[0..2].copy_from_slice(&hnpm.to_le_bytes());
            levels.push(fill_level(BLOCK_DATA - b.len()));
            out.push(b);
        }
        let pack = |levels: &[u8], dst: &mut [u8]| {
            for (k, l) in levels.iter().enumerate() {
                dst[k / 2] |= l << (4 * (k % 2));
            }
        };
        out[0][2] = 0xEC;
        out[0][3] = self.client_sig;
        out[0][4..8].copy_from_slice(&user_root.to_le_bytes());
        pack(&levels[..n.min(8)], &mut out[0][8..12]);
        for i in (8..n).step_by(128).collect::<Vec<_>>() {
            let (lv, b) = (&levels[i..n.min(i + 128)], &mut out[i]);
            pack(lv, &mut b[2..66]);
        }
        out
    }
}

/// BTree-on-heap over sorted records → HID of its BTHHEADER.
pub fn bth(heap: &mut Heap, cb_key: u8, cb_ent: u8, records: &[(Vec<u8>, Vec<u8>)]) -> u32 {
    let hdr = heap.alloc(vec![0; 8]);
    bth_at(heap, hdr, cb_key, cb_ent, records)
}

/// Like [`bth`] with the header allocated already (`hdr`, 8 bytes).
fn bth_at(heap: &mut Heap, hdr: u32, cb_key: u8, cb_ent: u8, records: &[(Vec<u8>, Vec<u8>)]) -> u32 {
    let mut root = 0u32;
    let mut levels = 0u8;
    if !records.is_empty() {
        let rec = (cb_key + cb_ent) as usize;
        let mut level: Vec<(Vec<u8>, u32)> = records
            .chunks(MAX_ITEM / rec)
            .map(|c| {
                let bytes: Vec<u8> = c.iter().flat_map(|(k, e)| k.iter().chain(e).copied()).collect();
                (c[0].0.clone(), heap.alloc(bytes))
            })
            .collect();
        while level.len() > 1 {
            levels += 1;
            let rec = cb_key as usize + 4;
            level = level
                .chunks(MAX_ITEM / rec)
                .map(|c| {
                    let bytes: Vec<u8> = c
                        .iter()
                        .flat_map(|(k, h)| k.iter().copied().chain(h.to_le_bytes()))
                        .collect();
                    (c[0].0.clone(), heap.alloc(bytes))
                })
                .collect();
        }
        root = level[0].1;
    }
    let mut h = vec![SIG_BTH, cb_key, cb_ent, levels];
    h.extend_from_slice(&root.to_le_bytes());
    heap.set(hdr, h);
    hdr
}

/// A variable-size value: in the heap or (over 3580 bytes) in a new subnode → its HNID.
fn var(heap: &mut Heap, subs: &mut Vec<SubNode>, ids: &mut SubIds, bytes: Vec<u8>) -> u32 {
    if bytes.is_empty() {
        return 0; // an empty value, as Outlook writes it
    }
    if bytes.len() <= MAX_ITEM {
        return heap.alloc(bytes);
    }
    let nid = ids.alloc();
    subs.push(SubNode {
        nid,
        data: SubData::Raw(bytes),
        subs: Vec::new(),
    });
    nid
}

/// Property context of `props` (unique property ids; sorted here).
pub fn pc(props: &[(u16, Val)], ids: &mut SubIds) -> Built {
    let mut heap = Heap::new(SIG_PC);
    let hdr = heap.alloc(vec![0; 8]); // the BTH header first (HID 0x20 as Outlook does)
    let mut subs = Vec::new();
    let mut sorted: Vec<&(u16, Val)> = props.iter().collect();
    sorted.sort_by_key(|p| p.0);
    let mut records = Vec::with_capacity(sorted.len());
    for (id, v) in sorted {
        let value = match v {
            Val::Bool(_) | Val::I32(_) => {
                let mut b = v.bytes();
                b.resize(4, 0);
                u32::from_le_bytes(b.try_into().unwrap())
            }
            _ => var(&mut heap, &mut subs, ids, v.bytes()),
        };
        let mut e = v.ptype().to_le_bytes().to_vec();
        e.extend_from_slice(&value.to_le_bytes());
        records.push((id.to_le_bytes().to_vec(), e));
    }
    bth_at(&mut heap, hdr, 2, 6, &records);
    Built {
        blocks: heap.blocks(hdr),
        subs,
    }
}

fn col_size(ptype: u16) -> usize {
    match ptype {
        PT_BOOL => 1,
        0x0002 => 2,
        PT_I64 | PT_TIME | 0x0005 => 8,
        _ => 4, // PtypInteger32, and the HNID of variable-size types
    }
}

pub const TAG_ROW_ID: u32 = 0x67F2_0003;
pub const TAG_ROW_VER: u32 = 0x67F3_0003;

/// Table context with `cols` (property tags; row id / version are added) and `rows`
/// (row id, values; values of tags not in `cols` are ignored).
pub fn tc(cols: &[u32], rows: &[(u32, Vec<(u32, Val)>)], ids: &mut SubIds) -> Built {
    let mut tags: Vec<u32> = cols
        .iter()
        .copied()
        .filter(|t| *t != TAG_ROW_ID && *t != TAG_ROW_VER)
        .collect();
    tags.sort_unstable();
    tags.dedup();
    // layout: row id @0, row version @4, then 8-, 4-, 2-, 1-byte columns, then the CEB
    let mut layout: Vec<(u32, u16, u8, u8)> = vec![(TAG_ROW_ID, 0, 4, 0), (TAG_ROW_VER, 4, 4, 1)];
    let ibit = |t: u32| 2 + tags.iter().position(|x| *x == t).unwrap() as u8;
    let mut off = 8u16;
    let mut ends = [0u16; 3];
    for (k, size) in [(0, 8usize), (0, 4), (1, 2), (2, 1)] {
        for &t in tags.iter().filter(|t| col_size(**t as u16) == size) {
            layout.push((t, off, size as u8, ibit(t)));
            off += size as u16;
        }
        ends[k] = off;
    }
    let ncols = tags.len() + 2;
    let row_size = off as usize + ncols.div_ceil(8);
    let mut heap = Heap::new(SIG_TC);
    let mut subs = Vec::new();
    // RowIndex (row id → row number), keys sorted numerically
    let mut index: Vec<(u32, u32)> = rows.iter().enumerate().map(|(i, r)| (r.0, i as u32)).collect();
    index.sort_unstable();
    let records: Vec<(Vec<u8>, Vec<u8>)> = index
        .iter()
        .map(|(id, i)| (id.to_le_bytes().to_vec(), i.to_le_bytes().to_vec()))
        .collect();
    let row_index = bth(&mut heap, 4, 4, &records);
    let info = heap.alloc(vec![0; 22 + 8 * ncols]);
    let mut matrix = Vec::with_capacity(rows.len() * row_size);
    for (id, vals) in rows {
        let mut r = vec![0u8; row_size];
        let ceb = off as usize;
        let set = |r: &mut Vec<u8>, bit: u8| r[ceb + bit as usize / 8] |= 0x80 >> (bit % 8);
        r[0..4].copy_from_slice(&id.to_le_bytes());
        r[4..8].copy_from_slice(&1u32.to_le_bytes());
        set(&mut r, 0);
        set(&mut r, 1);
        for (tag, v) in vals {
            let Some(&(_, ib, cb, bit)) = layout.iter().find(|c| c.0 == *tag) else {
                continue;
            };
            if v.ptype() != *tag as u16 {
                continue;
            }
            let bytes = match v {
                Val::Str(_) | Val::Bin(_) => var(&mut heap, &mut subs, ids, v.bytes()).to_le_bytes().to_vec(),
                _ => v.bytes(),
            };
            r[ib as usize..ib as usize + cb as usize].copy_from_slice(&bytes[..cb as usize]);
            set(&mut r, bit);
        }
        matrix.extend_from_slice(&r);
    }
    let rows_hnid = if rows.is_empty() {
        0
    } else if matrix.len() <= MAX_ITEM {
        heap.alloc(matrix)
    } else {
        // whole rows per block; every block but the last is full size
        let per = BLOCK_DATA / row_size;
        let mut blocks: Vec<Vec<u8>> = matrix.chunks(per * row_size).map(<[u8]>::to_vec).collect();
        let last = blocks.len() - 1;
        for b in &mut blocks[..last] {
            b.resize(BLOCK_DATA, 0);
        }
        let nid = ids.alloc();
        subs.push(SubNode {
            nid,
            data: SubData::Blocks(blocks),
            subs: Vec::new(),
        });
        nid
    };
    let mut t = vec![SIG_TC, ncols as u8];
    for e in [ends[0], ends[1], ends[2], row_size as u16] {
        t.extend_from_slice(&e.to_le_bytes());
    }
    t.extend_from_slice(&row_index.to_le_bytes());
    t.extend_from_slice(&rows_hnid.to_le_bytes());
    t.extend_from_slice(&0u32.to_le_bytes());
    layout.sort_by_key(|c| c.0);
    for (tag, ib, cb, bit) in layout {
        t.extend_from_slice(&tag.to_le_bytes());
        t.extend_from_slice(&ib.to_le_bytes());
        t.push(cb);
        t.push(bit);
    }
    heap.set(info, t);
    Built {
        blocks: heap.blocks(info),
        subs,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn u16at(b: &[u8], o: usize) -> usize {
        u16::from_le_bytes([b[o], b[o + 1]]) as usize
    }

    /// Heap item `hid` of single- or multi-page heap blocks.
    pub fn item(blocks: &[Vec<u8>], hid: u32) -> Vec<u8> {
        let b = &blocks[(hid >> 16) as usize];
        let map = u16at(b, 0);
        let k = ((hid >> 5) & 0x7FF) as usize;
        let (a, z) = (u16at(b, map + 4 + 2 * (k - 1)), u16at(b, map + 4 + 2 * k));
        b[a..z].to_vec()
    }

    #[test]
    fn heap_layout() {
        let mut h = Heap::new(SIG_PC);
        let a = h.alloc(vec![1, 2, 3]);
        let b = h.alloc(vec![9; 8]);
        assert_eq!((a, b), (0x20, 0x40));
        let blocks = h.blocks(a);
        assert_eq!(blocks.len(), 1);
        let p = &blocks[0];
        assert_eq!((p[2], p[3]), (0xEC, SIG_PC));
        assert_eq!(u32::from_le_bytes(p[4..8].try_into().unwrap()), 0x20);
        let map = u16at(p, 0);
        assert_eq!(map % 2, 0);
        assert_eq!((u16at(p, map), u16at(p, map + 2)), (2, 0), "cAlloc, cFree");
        assert_eq!(item(&blocks, a), [1, 2, 3]);
        assert_eq!(item(&blocks, b), [9; 8]);
    }

    #[test]
    fn heap_spills_into_more_pages() {
        let mut h = Heap::new(SIG_TC);
        let hids: Vec<u32> = (0..30).map(|i| h.alloc(vec![i as u8; 3000])).collect();
        assert!(hids.iter().any(|h| h >> 16 == 9));
        let blocks = h.blocks(hids[0]);
        assert!(blocks.iter().all(|b| b.len() <= BLOCK_DATA));
        assert_eq!(u16at(&blocks[1], 0) % 2, 0);
        for (i, hid) in hids.iter().enumerate() {
            assert_eq!(item(&blocks, *hid), vec![i as u8; 3000]);
        }
        // a bitmap header (66 bytes) in block 8
        let first = u16at(&blocks[8], u16at(&blocks[8], 0) + 4);
        assert_eq!(first, 66);
    }

    #[test]
    fn bth_levels() {
        let mut h = Heap::new(SIG_BTH);
        let recs: Vec<(Vec<u8>, Vec<u8>)> = (0u32..2000)
            .map(|i| (i.to_le_bytes().to_vec(), (i * 2).to_le_bytes().to_vec()))
            .collect();
        let hdr = bth(&mut h, 4, 4, &recs);
        let blocks = h.blocks(hdr);
        let head = item(&blocks, hdr);
        assert_eq!(&head[..4], &[SIG_BTH, 4, 4, 1]);
        let root = u32::from_le_bytes(head[4..8].try_into().unwrap());
        let idx = item(&blocks, root);
        assert_eq!(idx.len(), 8 * 2000usize.div_ceil(447));
        let leaf2 = u32::from_le_bytes(idx[12..16].try_into().unwrap());
        assert_eq!(
            &item(&blocks, leaf2)[..8],
            &[0xBF, 1, 0, 0, 0x7E, 3, 0, 0],
            "record 447"
        );
    }

    #[test]
    fn property_context() {
        let mut ids = SubIds::default();
        let big = "x".repeat(2000); // 4000 bytes as UTF-16: a subnode
        let b = pc(
            &[
                (0x3001, Val::Str("Inbox".into())),
                (0x3602, Val::I32(7)),
                (0x360A, Val::Bool(true)),
                (0x1000, Val::Str(big.clone())),
                (0x3007, Val::Time(42)),
            ],
            &mut ids,
        );
        assert_eq!(b.subs.len(), 1);
        let hdr = item(&b.blocks, 0x20);
        assert_eq!(&hdr[..4], &[SIG_BTH, 2, 6, 0]);
        let recs = item(&b.blocks, u32::from_le_bytes(hdr[4..8].try_into().unwrap()));
        let ids_sorted: Vec<u16> = recs.chunks(8).map(|r| u16::from_le_bytes([r[0], r[1]])).collect();
        assert_eq!(ids_sorted, [0x1000, 0x3001, 0x3007, 0x3602, 0x360A]);
        let rec = |k: usize| u32::from_le_bytes(recs[8 * k + 4..8 * k + 8].try_into().unwrap());
        assert_eq!(rec(0), b.subs[0].nid);
        assert_eq!(rec(0) & 0x1F, 0x1F);
        assert_eq!(
            item(&b.blocks, rec(1)),
            "Inbox".encode_utf16().flat_map(u16::to_le_bytes).collect::<Vec<_>>()
        );
        assert_eq!(item(&b.blocks, rec(2)), 42u64.to_le_bytes());
        assert_eq!((rec(3), rec(4)), (7, 1));
    }

    #[test]
    fn table_context() {
        let mut ids = SubIds::default();
        let cols = [0x3001_001F, 0x3602_0003, 0x360A_000B, 0x0E06_0040];
        let rows: Vec<(u32, Vec<(u32, Val)>)> = (0..300u32)
            .map(|i| {
                (
                    0x8022 + 32 * (299 - i),
                    vec![
                        (0x3001_001F, Val::Str(format!("folder {i}"))),
                        (0x3602_0003, Val::I32(i as i32)),
                    ],
                )
            })
            .collect();
        let b = tc(&cols, &rows, &mut ids);
        let info = item(&b.blocks, u32::from_le_bytes(b.blocks[0][4..8].try_into().unwrap()));
        assert_eq!((info[0], info[1]), (SIG_TC, 6));
        let rgib: Vec<usize> = (0..4).map(|k| u16at(&info, 2 + 2 * k)).collect();
        assert_eq!(
            rgib,
            [8 + 8 + 4 + 4, 24, 25, 26],
            "8-byte, 4-byte, (no 2-byte), 1-byte, CEB"
        );
        let rows_nid = u32::from_le_bytes(info[14..18].try_into().unwrap());
        assert_eq!(rows_nid & 0x1F, 0x1F, "300 rows of 26 bytes: a subnode");
        let SubData::Blocks(m) = &b.subs.iter().find(|s| s.nid == rows_nid).unwrap().data else {
            panic!()
        };
        assert_eq!(m.len(), 1);
        let r0 = &m[0][..26];
        assert_eq!(u32::from_le_bytes(r0[0..4].try_into().unwrap()), 0x8022 + 32 * 299);
        assert_eq!(
            r0[25], 0b1101_1000,
            "row id, version, display name, content count exist"
        );
        // descriptors sorted by tag
        let tags: Vec<u32> = (0..6)
            .map(|k| u32::from_le_bytes(info[22 + 8 * k..26 + 8 * k].try_into().unwrap()))
            .collect();
        let mut sorted = tags.clone();
        sorted.sort();
        assert_eq!(tags, sorted);
    }

    #[test]
    fn row_matrix_blocks_hold_whole_rows() {
        let mut ids = SubIds::default();
        let rows: Vec<(u32, Vec<(u32, Val)>)> = (0..2000u32).map(|i| (i, vec![(0x0E08_0003, Val::I32(1))])).collect();
        let b = tc(&[0x0E08_0003], &rows, &mut ids);
        let SubData::Blocks(m) = &b.subs[0].data else { panic!() };
        let row = 4 + 4 + 4 + 1;
        assert_eq!(m.len(), (2000usize).div_ceil(BLOCK_DATA / row));
        assert!(m[..m.len() - 1].iter().all(|b| b.len() == BLOCK_DATA));
        assert_eq!(m.last().unwrap().len() % row, 0);
    }

    #[test]
    fn fill_levels() {
        assert_eq!(fill_level(8000), 0);
        assert_eq!(fill_level(3000), 1);
        assert_eq!(fill_level(100), 11);
        assert_eq!(fill_level(3), 15);
    }
}
