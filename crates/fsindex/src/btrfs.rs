//! btrfs, own minimal read-only parser (Phase 31c): superblock, the system
//! chunk array and the chunk tree (logical -> physical addresses on the one
//! device), the root tree (subvolume roots, the default subvolume) and the
//! file system trees (directory index items, inode items, inline / regular
//! file extents for `/etc/fstab`). Single-device file systems only (a
//! multi-device btrfs is reported by the probe and goes to the micro-VM).
//!
//! The listing starts at the default subvolume, as the micro-VM mounts it (no
//! `subvol=`), so browse paths match the file browser; subvolumes and
//! snapshots below it appear as directories with their contents. The log tree
//! is not replayed (`dirty` when there is one). Tree nodes are checked
//! (logical address, fsid, level, item bounds, CRC-32C when that is the
//! checksum type; other checksum types are not verified). Every B+tree descent
//! is depth-bounded (levels strictly decrease), directories are entered once.
//!
//! No per-directory records (Phase 31c): btrfs is copy-on-write, every change
//! rewrites the path up to the tree root, so a directory's read set would
//! always change; unchanged volumes are still reused as a whole. Decoded nodes
//! are cached in the walker for speed, which is allowed only because of that.

use crate::disk::{le16, le32, le64, Vol};
use crate::walk::Out;
use crate::{Volume, KIND_DIR, KIND_FILE, KIND_OTHER, KIND_SYMLINK, MAX_DEPTH, MAX_PATH};
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::rc::Rc;

const SUPER: u64 = 0x10000;
const MAGIC: &[u8] = b"_BHRfS_M";
const HDR: usize = 0x65;
const ITEM: usize = 25;
const KEY_PTR: usize = 33;
const MAX_LEVEL: u8 = 8;
/// Decoded tree nodes kept (bytes, roughly).
const NODE_CACHE: usize = 64 << 20;

const INODE_ITEM: u8 = 1;
const DIR_INDEX: u8 = 96;
const EXTENT_DATA: u8 = 108;
const ROOT_ITEM: u8 = 132;
const DIR_ITEM: u8 = 84;
const CHUNK_ITEM: u8 = 228;

const FS_TREE: u64 = 5;
/// the empty directory a snapshot holds where its source had a subvolume
const EMPTY_SUBVOL_DIR: u64 = 2;
const ROOT_TREE_DIR: u64 = 6;

/// incompat features this parser does not read: extent tree v2, RAID stripe tree
const INCOMPAT_UNKNOWN: u64 = 0x2000 | 0x4000 | !0x1_ffff;

/// A btrfs key: (object id, type, offset), ordered as the trees order them.
pub type Key = (u64, u8, u64);

/// Called per item of a scan: `Ok(false)` stops it.
type Visit<'a> = dyn FnMut(Key, &[u8]) -> Result<bool, String> + 'a;

fn key(b: &[u8], at: usize) -> Key {
    (le64(b, at), b.get(at + 8).copied().unwrap_or(0), le64(b, at + 9))
}

fn crc32c(b: &[u8]) -> u32 {
    let mut c = !0u32;
    for &x in b {
        c ^= u32::from(x);
        for _ in 0..8 {
            c = if c & 1 != 0 { (c >> 1) ^ 0x82F6_3B78 } else { c >> 1 };
        }
    }
    !c
}

/// A chunk: logical start, length, physical offset of its first stripe.
#[derive(Clone, Copy, Debug)]
struct Chunk {
    logical: u64,
    len: u64,
    phys: u64,
}

/// A tree node: its level and its items (leaf: key and data; node: key and child).
enum Node {
    Leaf(Vec<(Key, Vec<u8>)>),
    Inner(u8, Vec<(Key, u64)>),
}

pub struct Btrfs {
    v: Vol,
    nodesize: u64,
    fsid: [u8; 16],
    devid: u64,
    crc: bool,
    chunks: Vec<Chunk>,
    root_tree: (u64, u8),
    cache: RefCell<(HashMap<u64, Rc<Node>>, usize)>,
    pub label: Option<String>,
    pub uuid: String,
    pub dirty: bool,
}

/// What an inode item says.
#[derive(Clone, Debug)]
pub struct Inode {
    pub size: u64,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub mtime: i64,
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

fn chunk_item(b: &[u8], logical: u64, devid: u64) -> Result<Chunk, String> {
    let len = le64(b, 0);
    let n = le16(b, 44) as usize;
    let ty = le64(b, 24);
    if b.len() < 48 + n * 32 || n == 0 || len == 0 || logical.checked_add(len).is_none() {
        return Err("btrfs: chunk item".into());
    }
    // single, DUP, RAID1/1C3/1C4: every stripe holds all of it; striped profiles only with one stripe
    let striped = ty & ((1 << 3) | (1 << 6) | (1 << 7) | (1 << 8)) != 0;
    if striped && n > 1 {
        return Err("btrfs: striped RAID profile is not indexed".into());
    }
    if le64(b, 48) != devid {
        return Err("btrfs: chunk on another device (multi-device file system)".into());
    }
    Ok(Chunk {
        logical,
        len,
        phys: le64(b, 56),
    })
}

impl Btrfs {
    pub fn open(v: &Vol) -> Result<Btrfs, String> {
        let sb = v.read_vec(SUPER, 4096).map_err(|e| e.to_string())?;
        if sb.len() < 4096 || &sb[0x40..0x48] != MAGIC {
            return Err("btrfs: no superblock".into());
        }
        let csum_type = le16(&sb, 0xc4);
        if csum_type == 0 && !cfg!(fuzzing) && crc32c(&sb[0x20..]) != le32(&sb, 0) {
            return Err("btrfs: superblock checksum".into());
        }
        let incompat = le64(&sb, 0xbc);
        if incompat & INCOMPAT_UNKNOWN != 0 {
            return Err(format!("btrfs: unsupported incompatible features {incompat:#x}"));
        }
        if le64(&sb, 0x88) != 1 {
            return Err("btrfs: multi-device file system".into());
        }
        let nodesize = u64::from(le32(&sb, 0x94));
        if !(4096..=65536).contains(&nodesize) || !nodesize.is_power_of_two() {
            return Err("btrfs: node size".into());
        }
        let mut fsid = [0u8; 16];
        // METADATA_UUID: the nodes carry the metadata UUID instead of the fsid
        let at = if incompat & 0x400 != 0 { 0x23b } else { 0x20 };
        fsid.copy_from_slice(&sb[at..at + 16]);
        let label = String::from_utf8_lossy(sb[0x12b..0x22b].split(|b| *b == 0).next().unwrap_or(&[])).into_owned();
        let u = crate::hex(&sb[0x20..0x30]);
        let mut fs = Btrfs {
            v: v.clone(),
            nodesize,
            fsid,
            devid: le64(&sb, 0xc9),
            crc: csum_type == 0,
            chunks: Vec::new(),
            root_tree: (le64(&sb, 0x50), sb[0xc6]),
            cache: RefCell::new((HashMap::new(), 0)),
            label: Some(label).filter(|l| !l.is_empty()),
            uuid: format!(
                "{}-{}-{}-{}-{}",
                &u[0..8],
                &u[8..12],
                &u[12..16],
                &u[16..20],
                &u[20..32]
            ),
            dirty: le64(&sb, 0x60) != 0,
        };
        // bootstrap: the system chunk array, then the whole chunk tree
        let n = (le32(&sb, 0xa0) as usize).min(2048);
        let arr = &sb[0x32b..0x32b + n];
        let mut at = 0;
        while at + 17 + 48 <= arr.len() {
            let k = key(arr, at);
            let stripes = le16(arr, at + 17 + 44) as usize;
            let size = 48 + stripes * 32;
            let item = arr.get(at + 17..at + 17 + size).ok_or("btrfs: system chunk array")?;
            if k.1 != CHUNK_ITEM {
                return Err("btrfs: system chunk array".into());
            }
            fs.chunks.push(chunk_item(item, k.2, fs.devid)?);
            at += 17 + size;
        }
        fs.sort_chunks();
        let mut chunks = Vec::new();
        let devid = fs.devid;
        fs.scan(
            (le64(&sb, 0x58), sb[0xc7]),
            (0, 0, 0),
            (u64::MAX, u8::MAX, u64::MAX),
            &mut |k, d| {
                if k.1 == CHUNK_ITEM {
                    chunks.push(chunk_item(d, k.2, devid)?);
                    if chunks.len() > 1 << 20 {
                        return Err("btrfs: too many chunks".into());
                    }
                }
                Ok(true)
            },
        )?;
        fs.chunks.extend(chunks);
        fs.sort_chunks();
        Ok(fs)
    }

    fn sort_chunks(&mut self) {
        self.chunks.sort_by_key(|c| c.logical);
        self.chunks.dedup_by_key(|c| c.logical);
    }

    /// Physical offset of logical address `l` with `n` bytes from there in one chunk.
    fn phys(&self, l: u64, n: u64) -> Result<u64, String> {
        let i = self.chunks.partition_point(|c| c.logical <= l);
        let c = self.chunks[..i]
            .last()
            .filter(|c| l.checked_add(n).is_some_and(|e| e <= c.logical + c.len))
            .ok_or_else(|| format!("btrfs: address {l:#x} not in a chunk"))?;
        c.phys
            .checked_add(l - c.logical)
            .ok_or_else(|| "btrfs: chunk offset".into())
    }

    fn node(&self, l: u64, level: u8) -> Result<Rc<Node>, String> {
        if let Some(n) = self.cache.borrow().0.get(&l) {
            return Ok(n.clone());
        }
        let b = self
            .v
            .read_vec(self.phys(l, self.nodesize)?, self.nodesize as usize)
            .map_err(|e| e.to_string())?;
        if b.len() as u64 != self.nodesize
            || le64(&b, 0x30) != l
            || b[0x20..0x30] != self.fsid
            || b[0x64] != level
            || (self.crc && !cfg!(fuzzing) && crc32c(&b[0x20..]) != le32(&b, 0))
        {
            return Err(format!("btrfs: tree node {l:#x} damaged"));
        }
        let n = le32(&b, 0x60) as usize;
        let node = if level == 0 {
            if HDR + n * ITEM > b.len() {
                return Err(format!("btrfs: tree node {l:#x} items"));
            }
            let mut items = Vec::with_capacity(n);
            for i in 0..n {
                let at = HDR + i * ITEM;
                let (off, size) = (le32(&b, at + 17) as usize, le32(&b, at + 21) as usize);
                let data = off
                    .checked_add(HDR)
                    .and_then(|s| b.get(s..s.checked_add(size)?))
                    .ok_or_else(|| format!("btrfs: tree node {l:#x} item data"))?;
                items.push((key(&b, at), data.to_vec()));
            }
            Node::Leaf(items)
        } else {
            if HDR + n * KEY_PTR > b.len() {
                return Err(format!("btrfs: tree node {l:#x} pointers"));
            }
            Node::Inner(
                level,
                (0..n)
                    .map(|i| (key(&b, HDR + i * KEY_PTR), le64(&b, HDR + i * KEY_PTR + 17)))
                    .collect(),
            )
        };
        let node = Rc::new(node);
        let mut c = self.cache.borrow_mut();
        if c.1 > NODE_CACHE {
            c.0.clear();
            c.1 = 0;
        }
        c.1 += self.nodesize as usize;
        c.0.insert(l, node.clone());
        Ok(node)
    }

    /// Every item with `lo <= key <= hi` of the tree at (root, level), in key order,
    /// to `f` (`false`: stop). Returns whether it went through.
    fn scan(&self, root: (u64, u8), lo: Key, hi: Key, f: &mut Visit) -> Result<bool, String> {
        if root.1 >= MAX_LEVEL {
            return Err("btrfs: tree too deep".into());
        }
        match &*self.node(root.0, root.1)? {
            Node::Leaf(items) => {
                for (k, d) in items {
                    if *k > hi {
                        return Ok(false);
                    }
                    if *k >= lo && !f(*k, d)? {
                        return Ok(false);
                    }
                }
                Ok(true)
            }
            Node::Inner(level, ptrs) => {
                for (i, (k, child)) in ptrs.iter().enumerate() {
                    if *k > hi {
                        return Ok(false);
                    }
                    // child i holds keys from k up to (not including) the next pointer's key
                    if ptrs.get(i + 1).is_some_and(|n| n.0 <= lo) {
                        continue;
                    }
                    if !self.scan((*child, level - 1), lo, hi, f)? {
                        return Ok(false);
                    }
                }
                Ok(true)
            }
        }
    }

    /// The first item with key `k` exactly.
    fn get(&self, root: (u64, u8), k: Key) -> Result<Option<Vec<u8>>, String> {
        let mut out = None;
        self.scan(root, k, k, &mut |_, d| {
            out = Some(d.to_vec());
            Ok(false)
        })?;
        Ok(out)
    }

    /// Root (node, level) and root directory of subvolume `id`.
    fn subvol(&self, id: u64) -> Result<((u64, u8), u64), String> {
        let mut out = None;
        self.scan(
            self.root_tree,
            (id, ROOT_ITEM, 0),
            (id, ROOT_ITEM, u64::MAX),
            &mut |_, d| {
                out = Some(d.to_vec());
                Ok(false)
            },
        )?;
        let d = out.ok_or_else(|| format!("btrfs: subvolume {id} not found"))?;
        if d.len() < 239 {
            return Err(format!("btrfs: root item of subvolume {id}"));
        }
        Ok(((le64(&d, 176), d[238]), le64(&d, 168)))
    }

    /// The default subvolume (`default` in the root tree directory), else the top level.
    fn default_subvol(&self) -> Result<u64, String> {
        let mut id = FS_TREE;
        self.scan(
            self.root_tree,
            (ROOT_TREE_DIR, DIR_ITEM, 0),
            (ROOT_TREE_DIR, DIR_ITEM, u64::MAX),
            &mut |_, d| {
                for (name, loc, _) in dir_items(d) {
                    if name == b"default" && loc.1 == ROOT_ITEM {
                        id = loc.0;
                    }
                }
                Ok(true)
            },
        )?;
        Ok(id)
    }

    fn inode(&self, tree: (u64, u8), ino: u64) -> Result<Inode, String> {
        let d = self
            .get(tree, (ino, INODE_ITEM, 0))?
            .filter(|d| d.len() >= 160)
            .ok_or_else(|| format!("btrfs: inode {ino} not found"))?;
        Ok(Inode {
            size: le64(&d, 16),
            uid: le32(&d, 44),
            gid: le32(&d, 48),
            mode: le32(&d, 52),
            mtime: le64(&d, 136) as i64,
        })
    }

    /// The entries of directory `ino`: (name, location key, type).
    fn dir(&self, tree: (u64, u8), ino: u64) -> Result<Vec<(Vec<u8>, Key, u8)>, String> {
        let mut out = Vec::new();
        self.scan(tree, (ino, DIR_INDEX, 0), (ino, DIR_INDEX, u64::MAX), &mut |_, d| {
            out.extend(dir_items(d).into_iter().take(1));
            Ok(true)
        })?;
        Ok(out)
    }

    /// Up to `max` bytes of a file (uncompressed inline and regular extents; holes read zeros).
    fn read_file(&self, tree: (u64, u8), ino: u64, size: u64, max: u64) -> Result<Vec<u8>, String> {
        let size = size.min(max);
        let mut out = vec![0u8; size as usize];
        let mut err = None;
        self.scan(
            tree,
            (ino, EXTENT_DATA, 0),
            (ino, EXTENT_DATA, size.saturating_sub(1)),
            &mut |k, d| {
                let at = k.2;
                if d.len() < 21 || d[16] != 0 || d[17] != 0 {
                    err = Some("btrfs: compressed or encrypted extent".to_string());
                    return Ok(false);
                }
                let data = match d[20] {
                    0 => d[21..].to_vec(),
                    1 if d.len() >= 53 => {
                        let (bytenr, off, n) = (le64(d, 21), le64(d, 37), le64(d, 45));
                        if bytenr == 0 {
                            return Ok(true); // a hole
                        }
                        let n = n.min(size.saturating_sub(at));
                        let p = self.phys(bytenr.checked_add(off).ok_or("btrfs: extent")?, n)?;
                        self.v.read_vec(p, n as usize).map_err(|e| e.to_string())?
                    }
                    _ => return Ok(true), // preallocated: zeros
                };
                let n = (data.len() as u64).min(size.saturating_sub(at)) as usize;
                out[at as usize..at as usize + n].copy_from_slice(&data[..n]);
                Ok(true)
            },
        )?;
        match err {
            Some(e) => Err(e),
            None => Ok(out),
        }
    }

    /// Inode of `path` (below the root directory of subvolume tree `tree`).
    fn lookup(&self, tree: (u64, u8), dir: u64, path: &str) -> Result<Option<(u64, Inode)>, String> {
        let (mut tree, mut at) = (tree, dir);
        for c in path.split('/').filter(|c| !c.is_empty()) {
            let Some((_, loc, _)) = self.dir(tree, at)?.into_iter().find(|e| e.0 == c.as_bytes()) else {
                return Ok(None);
            };
            if loc.1 == ROOT_ITEM {
                let (t, d) = self.subvol(loc.0)?;
                (tree, at) = (t, d);
            } else {
                at = loc.0;
            }
        }
        Ok(Some((at, self.inode(tree, at)?)))
    }
}

/// The `btrfs_dir_item`s of one item: (name, location key, type).
fn dir_items(mut d: &[u8]) -> Vec<(Vec<u8>, Key, u8)> {
    let mut out = Vec::new();
    while d.len() >= 30 {
        let loc = key(d, 0);
        let (data_len, name_len, ty) = (le16(d, 25) as usize, le16(d, 27) as usize, d[29]);
        let Some(name) = d.get(30..30 + name_len) else { break };
        out.push((name.to_vec(), loc, ty));
        d = d.get(30 + name_len + data_len..).unwrap_or_default();
    }
    out
}

fn type_kind(t: u8) -> u8 {
    match t {
        1 => KIND_FILE,
        2 => KIND_DIR,
        7 => KIND_SYMLINK,
        _ => KIND_OTHER,
    }
}

pub fn walk(v: &Vol, out: &mut Out, info: &mut Volume) -> Result<(), String> {
    let fs = Btrfs::open(v)?;
    info.label = fs.label.clone();
    info.uuid = Some(fs.uuid.clone());
    info.dirty = fs.dirty;
    let (tree, root_dir) = fs.subvol(fs.default_subvol()?)?;
    if let Ok(Some((ino, f))) = fs.lookup(tree, root_dir, "etc/fstab") {
        if f.kind() == KIND_FILE && f.size <= 64 << 10 {
            if let Ok(t) = fs.read_file(tree, ino, f.size, 64 << 10) {
                info.fstab = Some(String::from_utf8_lossy(&t).into_owned());
            }
        }
    }
    // (tree, directory inode, path, depth)
    let mut stack: Vec<((u64, u8), u64, String, usize)> = vec![(tree, root_dir, String::new(), 0)];
    let mut visited = HashSet::from([(tree.0, root_dir)]);
    while let Some((tree, dir, rel, depth)) = stack.pop() {
        if !out.walks(&rel, depth) {
            continue; // another helper's share
        }
        if out.out_of_time() {
            return Ok(());
        }
        let own = out.owns(&rel, depth);
        let entries = match fs.dir(tree, dir) {
            Ok(e) => e,
            Err(e) => {
                if own {
                    out.note(info, format!("/{rel}: {e}"));
                }
                continue;
            }
        };
        let mut seen = HashSet::new();
        for (name, loc, ty) in entries {
            let name = String::from_utf8_lossy(&name).into_owned();
            let path = if rel.is_empty() {
                name.clone()
            } else {
                format!("{rel}/{name}")
            };
            if name.is_empty() || name.contains('/') || path.len() > MAX_PATH || !seen.insert(name.clone()) {
                info.skipped_entries += u64::from(own);
                continue;
            }
            if loc.1 == INODE_ITEM && loc.0 == EMPTY_SUBVOL_DIR {
                // a subvolume that was not part of a snapshot: an empty directory
                if own && !out.emit(info, &path, 0, 0, KIND_DIR)? {
                    return Ok(());
                }
                continue;
            }
            // a subvolume (or snapshot) inside: a directory, its contents from its own tree
            let sub = (loc.1 == ROOT_ITEM).then(|| fs.subvol(loc.0));
            let target = match sub {
                Some(Ok((t, d))) => Some((t, d)),
                Some(Err(_)) => {
                    info.skipped_entries += u64::from(own);
                    continue;
                }
                None => (ty == 2).then_some((tree, loc.0)),
            };
            if own {
                let (kind, size, mtime, owner) = match target {
                    Some((t, d)) => match fs.inode(t, d) {
                        Ok(i) => (KIND_DIR, 0, i.mtime, format!("{}:{}", i.uid, i.gid)),
                        Err(_) => {
                            info.skipped_entries += 1;
                            continue;
                        }
                    },
                    None => match fs.inode(tree, loc.0) {
                        Ok(i) => {
                            let k = i.kind();
                            let o = format!("{}:{}", i.uid, i.gid);
                            (k, if k == KIND_FILE { i.size } else { 0 }, i.mtime, o)
                        }
                        Err(_) => {
                            info.skipped_entries += 1;
                            continue;
                        }
                    },
                };
                if !out.emit_ext(info, &path, size, mtime, kind, Some(&owner), None)? {
                    return Ok(());
                }
            } else if type_kind(ty) != KIND_DIR && target.is_none() {
                continue;
            }
            if let Some((t, d)) = target {
                if !out.walks(&path, depth + 1) {
                    continue;
                }
                if depth + 1 >= MAX_DEPTH {
                    if own {
                        out.note(info, format!("/{path}: nested too deeply"));
                    }
                    continue;
                }
                if visited.insert((t.0, d)) {
                    stack.push((t, d, path, depth + 1));
                }
            }
        }
    }
    Ok(())
}
