//! Windows dynamic disks (LDM, Phase 31c), read-only: the private header
//! (`PRIVHEAD`: MBR disks at sector 6, GPT disks at the last sector of the LDM
//! metadata partition), the table of contents and the database (`VMDB` and its
//! `VBLK` records, fragmented records joined) as the Linux kernel's
//! `block/partitions/ldm.c` reads them: disks, volumes, components and
//! partitions (subdisks). Simple and spanned volumes are mapped to segments
//! on the disks (mirrors by their first plex); striped and RAID-5 volumes are
//! reported. All fields are big-endian; every variable-length field and record
//! size is checked the way the kernel checks it.

use crate::disk::{Io, Segment, Vol};
use std::collections::{BTreeMap, HashMap};

const SECTOR: u64 = 512;
/// The database starts with the TOCBLOCK one sector after `config_start`, the VMDB 17 sectors after.
const OFF_TOCB: u64 = 1;
const OFF_VMDB: u64 = 17;
const MAX_VBLKS: u64 = 1 << 16;

const VBLK_CMP3: u8 = 0x32;
const VBLK_PRT3: u8 = 0x33;
const VBLK_DSK3: u8 = 0x34;
const VBLK_DSK4: u8 = 0x44;
const VBLK_VOL5: u8 = 0x51;

const COMP_STRIPE: u8 = 1;
const COMP_RAID: u8 = 3;

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

/// Where a disk's private header lies: (disk, byte offset).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Member {
    pub disk: usize,
    pub privhead: u64,
}

/// One dynamic volume.
#[derive(Clone, Debug, PartialEq)]
pub struct DynVol {
    pub name: String,
    /// the volume GUID (as `MountedDevices` names it: `DMIO:ID:` + these bytes), text
    pub guid: String,
    pub size: u64,
    /// segments on the disks, or why it is not read
    pub map: Result<Vec<Segment>, String>,
    /// mirrored: only the first plex is read
    pub mirrored: bool,
}

/// A disk's private header: its GUID and where its data and database are (sectors).
struct Privhead {
    guid: Vec<u8>,
    start: u64,
    config_start: u64,
    config_size: u64,
}

/// A GUID written as text (`xxxxxxxx-xxxx-…`) as bytes in text order.
fn text_guid(s: &[u8]) -> Option<Vec<u8>> {
    let s = std::str::from_utf8(s.get(..36)?).ok()?;
    let h: String = s.chars().filter(|c| *c != '-').collect();
    if h.len() != 32 || s.chars().filter(|c| *c == '-').count() != 4 {
        return None;
    }
    (0..16)
        .map(|i| u8::from_str_radix(&h[i * 2..i * 2 + 2], 16).ok())
        .collect()
}

fn privhead(v: &Vol, at: u64) -> Result<Privhead, String> {
    let b = v.read_vec(at, 512).map_err(|e| e.to_string())?;
    if b.get(0..8) != Some(b"PRIVHEAD") {
        return Err("LDM: no private header".into());
    }
    let (major, minor) = (be16(&b, 0x0c), be16(&b, 0x0e));
    if major != 2 || !(11..=12).contains(&minor) {
        return Err(format!("LDM: private header version {major}.{minor}"));
    }
    let p = Privhead {
        guid: text_guid(&b[0x30..]).ok_or("LDM: disk GUID")?,
        start: be64(&b, 0x11b),
        config_start: be64(&b, 0x12b),
        config_size: be64(&b, 0x133),
    };
    let sectors = v.size() / SECTOR;
    let ok = p.config_size > OFF_VMDB + 1
        && p.config_start.checked_add(p.config_size).is_some_and(|e| e <= sectors)
        && p.start < sectors;
    if !ok {
        return Err("LDM: private header layout".into());
    }
    Ok(p)
}

/// A variable-length number: length byte, big-endian value.
fn vnum(b: &[u8], at: usize) -> Result<u64, String> {
    let n = *b.get(at).ok_or("LDM: record truncated")? as usize;
    if n == 0 || n > 8 {
        return Err("LDM: number field".into());
    }
    let s = b.get(at + 1..at + 1 + n).ok_or("LDM: record truncated")?;
    Ok(s.iter().fold(0u64, |a, x| a << 8 | u64::from(*x)))
}

/// A variable-length string: length byte, bytes.
fn vstr(b: &[u8], at: usize) -> Result<String, String> {
    let n = *b.get(at).ok_or("LDM: record truncated")? as usize;
    let s = b.get(at + 1..at + 1 + n).ok_or("LDM: record truncated")?;
    Ok(String::from_utf8_lossy(s).into_owned())
}

/// The kernel's `ldm_relative`: the offset (from `base`) behind the field at
/// `base + offset`, whose first byte is its length.
fn rel(b: &[u8], base: usize, offset: usize) -> Result<usize, String> {
    let at = base + offset;
    let n = *b.get(at).ok_or("LDM: record truncated")? as usize;
    if at + n >= b.len() {
        return Err("LDM: record field beyond its end".into());
    }
    Ok(n + offset + 1)
}

#[derive(Debug)]
enum Rec {
    Disk {
        guid: Vec<u8>,
    },
    Vol {
        name: String,
        kind: String,
        size: u64,
        guid: Vec<u8>,
    },
    Comp {
        kind: u8,
        parent: u64,
    },
    Part {
        start: u64,
        offset: u64,
        size: u64,
        parent: u64,
        disk: u64,
    },
}

/// One VBLK record (joined fragments): (object id, record).
fn parse_vblk(b: &[u8]) -> Result<Option<(u64, Rec)>, String> {
    if b.len() < 0x19 {
        return Err("LDM: record truncated".into());
    }
    let (flags, ty, size) = (b[0x12], b[0x13], be32(b, 0x14) as usize);
    let id = vnum(b, 0x18)?;
    let r_objid = rel(b, 0x18, 0)?;
    let r_name = rel(b, 0x18, r_objid)?;
    let check = |len: usize| {
        if len == size {
            Ok(())
        } else {
            Err("LDM: record size".to_string())
        }
    };
    let rec = match ty {
        VBLK_DSK3 => {
            let r_diskid = rel(b, 0x18, r_name)?;
            let r_alt = rel(b, 0x18, r_diskid)?;
            check(r_alt + 12)?;
            Rec::Disk {
                guid: text_guid(b.get(0x19 + r_name..).unwrap_or_default()).ok_or("LDM: disk GUID")?,
            }
        }
        VBLK_DSK4 => {
            check(r_name + 45)?;
            Rec::Disk {
                guid: b.get(0x18 + r_name..0x28 + r_name).ok_or("LDM: disk GUID")?.to_vec(),
            }
        }
        VBLK_VOL5 => {
            let r_vtype = rel(b, 0x18, r_name)?;
            let r_dis = rel(b, 0x18, r_vtype)?;
            let r_child = rel(b, 0x2d, r_dis)?;
            let r_size = rel(b, 0x3d, r_child)?;
            let mut r = r_size;
            for bit in [0x08u8, 0x20, 0x80, 0x02] {
                // id1, id2, size2, drive hint
                if flags & bit != 0 {
                    r = rel(b, 0x52, r)?;
                }
            }
            if r + 58 > size {
                return Err("LDM: record size".into());
            }
            Rec::Vol {
                name: vstr(b, 0x18 + r_objid)?,
                kind: vstr(b, 0x18 + r_name)?,
                size: vnum(b, 0x3d + r_child)?,
                guid: b.get(0x42 + r_size..0x52 + r_size).ok_or("LDM: volume GUID")?.to_vec(),
            }
        }
        VBLK_CMP3 => {
            let r_vstate = rel(b, 0x18, r_name)?;
            let r_child = rel(b, 0x1d, r_vstate)?;
            let r_parent = rel(b, 0x2d, r_child)?;
            let len = if flags & 0x10 != 0 {
                let r_stripe = rel(b, 0x2e, r_parent)?;
                rel(b, 0x2e, r_stripe)?
            } else {
                r_parent
            };
            check(len + 22)?;
            Rec::Comp {
                kind: *b.get(0x18 + r_vstate).ok_or("LDM: record truncated")?,
                parent: vnum(b, 0x2d + r_child)?,
            }
        }
        VBLK_PRT3 => {
            let r_size = rel(b, 0x34, r_name)?;
            let r_parent = rel(b, 0x34, r_size)?;
            let r_diskid = rel(b, 0x34, r_parent)?;
            let len = if flags & 0x08 != 0 {
                rel(b, 0x34, r_diskid)?
            } else {
                r_diskid
            };
            check(len + 28)?;
            Rec::Part {
                start: be64(b, 0x24 + r_name),
                offset: be64(b, 0x2c + r_name),
                size: vnum(b, 0x34 + r_name)?,
                parent: vnum(b, 0x34 + r_size)?,
                disk: vnum(b, 0x34 + r_parent)?,
            }
        }
        _ => return Ok(None), // disk groups and others: not needed
    };
    Ok(Some((id, rec)))
}

/// The records of one disk's database.
fn database(v: &Vol, ph: &Privhead) -> Result<(u32, Vec<(u64, Rec)>), String> {
    let base = ph.config_start * SECTOR;
    let toc = v.read_vec(base + OFF_TOCB * SECTOR, 512).map_err(|e| e.to_string())?;
    if toc.get(0..8) != Some(b"TOCBLOCK") {
        return Err("LDM: no table of contents".into());
    }
    let vm = v.read_vec(base + OFF_VMDB * SECTOR, 512).map_err(|e| e.to_string())?;
    if vm.get(0..4) != Some(b"VMDB") || be16(&vm, 0x12) != 4 || be16(&vm, 0x14) != 10 {
        return Err("LDM: no database header".into());
    }
    let (last, size, offset) = (
        u64::from(be32(&vm, 4)),
        u64::from(be32(&vm, 8)),
        u64::from(be32(&vm, 12)),
    );
    if !(32..=512).contains(&size) || 512 % size != 0 || last > MAX_VBLKS {
        return Err("LDM: database layout".into());
    }
    let (skip, finish) = (offset / SECTOR, size * last / SECTOR);
    if (OFF_VMDB + finish) > ph.config_size {
        return Err("LDM: database beyond its area".into());
    }
    // group -> (fragments expected, fragments by number)
    let mut frags: BTreeMap<u32, (u16, BTreeMap<u16, Vec<u8>>)> = BTreeMap::new();
    let mut out = Vec::new();
    if finish > skip {
        let all = v
            .read_vec(base + (OFF_VMDB + skip) * SECTOR, ((finish - skip) * SECTOR) as usize)
            .map_err(|e| e.to_string())?;
        for b in all.chunks_exact(size as usize) {
            if b.get(0..4) != Some(b"VBLK") {
                return Err("LDM: damaged record".into());
            }
            let (group, rec, num) = (be32(b, 8), be16(b, 0x0c), be16(b, 0x0e));
            match num {
                0 => {}
                1 => out.extend(parse_vblk(b)?),
                2..=4 if rec < num => {
                    let f = frags.entry(group).or_insert((num, BTreeMap::new()));
                    if f.0 != num {
                        return Err("LDM: fragments disagree".into());
                    }
                    f.1.insert(rec, b.to_vec());
                }
                _ => return Err("LDM: fragmented record".into()),
            }
        }
    }
    for (_, (num, parts)) in frags {
        if parts.len() != num as usize {
            continue; // incomplete (the kernel skips them too)
        }
        let mut joined = Vec::new();
        for (i, p) in parts.values().enumerate() {
            joined.extend_from_slice(if i == 0 { p } else { &p[16..] });
        }
        out.extend(parse_vblk(&joined)?);
    }
    Ok((last as u32, out))
}

fn guid_text(b: &[u8]) -> String {
    crate::part::guid(b)
}

/// The dynamic volumes of the disk group on `members`; `Err` when no database is readable.
pub fn volumes(io: &Io, members: &[Member]) -> Result<Vec<DynVol>, String> {
    let mut heads = Vec::new();
    let mut best: Option<(u32, Vec<(u64, Rec)>)> = None;
    let mut first_err = None;
    for m in members {
        let size = io.borrow().disk_size(m.disk);
        let v = Vol::region(io.clone(), m.disk, 0, size);
        let ph = match privhead(&v, m.privhead) {
            Ok(p) => p,
            Err(e) => {
                first_err.get_or_insert(e);
                continue;
            }
        };
        match database(&v, &ph) {
            Ok(db) if best.as_ref().is_none_or(|b| db.0 > b.0) => best = Some(db),
            Ok(_) => {}
            Err(e) => {
                first_err.get_or_insert(e);
            }
        }
        heads.push((m.disk, ph));
    }
    let Some((_, recs)) = best else {
        return Err(first_err.unwrap_or_else(|| "LDM: no database".into()));
    };
    // disk object -> (snapshot disk, its data start in sectors)
    let mut disks: HashMap<u64, Option<(usize, u64)>> = HashMap::new();
    let mut vols = Vec::new();
    let mut comps: Vec<(u64, u8, u64)> = Vec::new();
    let mut parts: Vec<(u64, u64, u64, u64, u64)> = Vec::new();
    for (id, r) in recs {
        match r {
            Rec::Disk { guid } => {
                let at = heads
                    .iter()
                    .find(|(_, ph)| ph.guid == guid)
                    .map(|(d, ph)| (*d, ph.start));
                disks.insert(id, at);
            }
            Rec::Vol { name, kind, size, guid } => vols.push((id, name, kind, size, guid)),
            Rec::Comp { kind, parent } => comps.push((id, kind, parent)),
            Rec::Part {
                start,
                offset,
                size,
                parent,
                disk,
            } => parts.push((parent, offset, size, start, disk)),
        }
    }
    let mut out = Vec::new();
    for (id, name, kind, size, guid) in vols {
        let mine: Vec<&(u64, u8, u64)> = comps.iter().filter(|c| c.2 == id).collect();
        let map = (|| {
            if kind.eq_ignore_ascii_case("raid5") || mine.iter().any(|c| c.1 == COMP_RAID) {
                return Err("RAID-5 dynamic volume is not indexed".to_string());
            }
            if mine.iter().any(|c| c.1 == COMP_STRIPE) {
                return Err("striped dynamic volume is not indexed".to_string());
            }
            let comp = mine.first().ok_or("dynamic volume without a component")?;
            let mut ps: Vec<_> = parts.iter().filter(|p| p.0 == comp.0).collect();
            ps.sort_by_key(|p| p.1);
            let mut segs = Vec::new();
            let mut at = 0u64;
            for (_, offset, n, start, disk) in ps {
                let (d, data) = disks
                    .get(disk)
                    .copied()
                    .flatten()
                    .ok_or("a disk of the dynamic volume is missing")?;
                if *offset != at || *n == 0 {
                    return Err("dynamic volume has gaps".to_string());
                }
                let phys = data
                    .checked_add(*start)
                    .and_then(|s| s.checked_mul(SECTOR))
                    .ok_or("dynamic volume extent")?;
                let len = n.checked_mul(SECTOR).ok_or("dynamic volume extent")?;
                if phys.checked_add(len).is_none_or(|e| e > io.borrow().disk_size(d)) {
                    return Err("dynamic volume extent beyond its disk".to_string());
                }
                segs.push(Segment {
                    start: at * SECTOR,
                    len,
                    legs: vec![(d, phys)],
                    stripe: 0,
                });
                at += n;
                if segs.len() > 4096 {
                    return Err("dynamic volume with too many extents".to_string());
                }
            }
            if segs.is_empty() || at != size {
                return Err("dynamic volume extents do not add up to its size".to_string());
            }
            Ok(segs)
        })();
        out.push(DynVol {
            name,
            guid: guid_text(&guid),
            size: size.saturating_mul(SECTOR),
            map,
            mirrored: mine.len() > 1,
        });
    }
    Ok(out)
}

/// Builds VBLK records and a database (tests and fuzz seeds): `recs` are complete
/// records (header filled in here), placed from slot 4 on; `last` slots in all.
#[doc(hidden)]
pub mod build {
    /// A variable-length number.
    pub fn num(v: u64) -> Vec<u8> {
        let b: Vec<u8> = v.to_be_bytes().into_iter().skip_while(|x| *x == 0).collect();
        let b = if b.is_empty() { vec![0] } else { b };
        let mut out = vec![b.len() as u8];
        out.extend(b);
        out
    }

    pub fn text(s: &str) -> Vec<u8> {
        let mut out = vec![s.len() as u8];
        out.extend(s.as_bytes());
        out
    }

    /// A record of `ty` with `flags` whose fields from 0x18 on are `body`; `size` as the
    /// kernel computes it (`body` length less the trailing bytes it does not count).
    pub fn rec(ty: u8, flags: u8, body: &[u8], size: usize) -> Vec<u8> {
        let mut r = vec![0u8; 0x18];
        r[0..4].copy_from_slice(b"VBLK");
        r[0x12] = flags;
        r[0x13] = ty;
        r[0x14..0x18].copy_from_slice(&(size as u32).to_be_bytes());
        r.extend(body);
        r
    }

    pub fn disk4(id: u64, name: &str, guid: &[u8; 16]) -> Vec<u8> {
        let mut b = num(id);
        b.extend(text(name));
        let r_name = b.len();
        b.extend(guid);
        b.resize(r_name + 45, 0);
        rec(0x44, 0, &b, r_name + 45)
    }

    pub fn volume(id: u64, name: &str, kind: &str, children: u64, size: u64, guid: &[u8; 16]) -> Vec<u8> {
        let mut b = num(id);
        b.extend(text(name));
        b.extend(text(kind));
        b.extend(text("")); // disable drive letter
        let r_dis = b.len();
        // state, then children at 0x2d (0x15 bytes after the 0x18 base)
        b.extend(b"ACTIVE");
        b.resize(r_dis + 0x15, 0);
        b.extend(num(children));
        let r_child = b.len() - 0x15;
        b.resize(r_child + 0x25, 0); // size at 0x3d
        b.extend(num(size));
        let r_size = b.len() - 0x25;
        b.resize(r_size + 0x29, 0);
        b.push(0x07); // partition type
        b.extend(guid);
        let len = r_size + 58;
        b.resize(len, 0);
        rec(0x51, 0, &b, len)
    }

    pub fn component(id: u64, name: &str, kind: u8, children: u64, parent: u64) -> Vec<u8> {
        let mut b = num(id);
        b.extend(text(name));
        b.extend(text("ACTIVE"));
        let r_vstate = b.len();
        b.push(kind);
        b.resize(r_vstate + 5, 0); // children at 0x1d
        b.extend(num(children));
        let r_child = b.len() - 5;
        b.resize(r_child + 0x15, 0); // parent at 0x2d
        b.extend(num(parent));
        let r_parent = b.len() - 0x15;
        b.resize(r_parent + 22, 0);
        rec(0x32, 0, &b, r_parent + 22)
    }

    pub fn partition(id: u64, name: &str, start: u64, offset: u64, size: u64, parent: u64, disk: u64) -> Vec<u8> {
        let mut b = num(id);
        b.extend(text(name));
        let r_name = b.len();
        b.resize(r_name + 12, 0);
        b.extend(start.to_be_bytes());
        b.extend(offset.to_be_bytes());
        b.extend(num(size));
        b.extend(num(parent));
        b.extend(num(disk));
        let r_diskid = b.len() - 0x1c;
        b.resize(r_diskid + 28, 0);
        rec(0x33, 0, &b, r_diskid + 28)
    }

    /// The LDM area of a disk (`config_size` sectors from `config_start`): TOCBLOCK,
    /// VMDB, the records (each split into fragments of `slot` bytes as needed).
    pub fn database(recs: &[Vec<u8>], slot: usize, config_size: usize) -> Vec<u8> {
        let mut area = vec![0u8; config_size * 512];
        area[512..520].copy_from_slice(b"TOCBLOCK");
        let vm = 17 * 512;
        area[vm..vm + 4].copy_from_slice(b"VMDB");
        let mut slots: Vec<Vec<u8>> = (0..4).map(|_| Vec::new()).collect();
        for (g, r) in recs.iter().enumerate() {
            let pay = slot - 16;
            let body = &r[16..];
            let n = body.len().div_ceil(pay).max(1);
            for (i, c) in body.chunks(pay).enumerate() {
                let mut s = r[..16].to_vec();
                s[8..12].copy_from_slice(&(g as u32 + 1).to_be_bytes());
                s[12..14].copy_from_slice(&(i as u16).to_be_bytes());
                s[14..16].copy_from_slice(&(n as u16).to_be_bytes());
                s.extend(c);
                slots.push(s);
            }
        }
        let last = slots.len() as u32 + 4;
        area[vm + 4..vm + 8].copy_from_slice(&last.to_be_bytes());
        area[vm + 8..vm + 12].copy_from_slice(&(slot as u32).to_be_bytes());
        area[vm + 12..vm + 16].copy_from_slice(&512u32.to_be_bytes());
        area[vm + 0x12..vm + 0x14].copy_from_slice(&4u16.to_be_bytes());
        area[vm + 0x14..vm + 0x16].copy_from_slice(&10u16.to_be_bytes());
        // slot k at VMDB + k * slot; slots 0..4 hold the VMDB itself (offset 512)
        for k in 0..last as usize {
            let at = vm + k * slot;
            if k < 512 / slot {
                continue;
            }
            area[at..at + 4].copy_from_slice(b"VBLK");
            if let Some(s) = slots.get(k).filter(|s| !s.is_empty()) {
                area[at..at + s.len()].copy_from_slice(s);
            }
        }
        area
    }

    /// A private header: disk GUID (text), data start, database start and size (sectors).
    pub fn privhead(guid: &str, start: u64, config_start: u64, config_size: u64) -> Vec<u8> {
        let mut b = vec![0u8; 512];
        b[0..8].copy_from_slice(b"PRIVHEAD");
        b[0x0c..0x0e].copy_from_slice(&2u16.to_be_bytes());
        b[0x0e..0x10].copy_from_slice(&12u16.to_be_bytes());
        b[0x30..0x30 + guid.len()].copy_from_slice(guid.as_bytes());
        b[0x11b..0x123].copy_from_slice(&start.to_be_bytes());
        b[0x12b..0x133].copy_from_slice(&config_start.to_be_bytes());
        b[0x133..0x13b].copy_from_slice(&config_size.to_be_bytes());
        b
    }
}

#[cfg(test)]
mod tests {
    use super::build::{component, disk4, partition, volume};
    use super::*;
    use crate::disk::Local;
    use std::cell::RefCell;
    use std::rc::Rc;

    #[test]
    fn records_parse_back() {
        let g = [7u8; 16];
        let (_, r) = parse_vblk(&volume(9, "Volume1", "gen", 1, 2048, &g)).unwrap().unwrap();
        assert!(matches!(r, Rec::Vol { ref name, size: 2048, ref guid, .. } if name == "Volume1" && guid == &g));
        let (_, r) = parse_vblk(&component(10, "Volume1-01", 2, 1, 9)).unwrap().unwrap();
        assert!(matches!(r, Rec::Comp { kind: 2, parent: 9 }));
        let (id, r) = parse_vblk(&partition(11, "Disk1-01", 100, 0, 2048, 10, 3))
            .unwrap()
            .unwrap();
        assert_eq!(id, 11);
        assert!(matches!(
            r,
            Rec::Part {
                start: 100,
                offset: 0,
                size: 2048,
                parent: 10,
                disk: 3
            }
        ));
        let (_, r) = parse_vblk(&disk4(3, "Disk1", &g)).unwrap().unwrap();
        assert!(matches!(r, Rec::Disk { ref guid } if guid == &g));
        // a wrong size field, a length byte beyond the record: errors
        let mut p = partition(11, "Disk1-01", 100, 0, 2048, 10, 3);
        p[0x17] ^= 1;
        assert!(parse_vblk(&p).is_err());
        let mut p = partition(11, "Disk1-01", 100, 0, 2048, 10, 3);
        p[0x18 + 2] = 0xff;
        assert!(parse_vblk(&p).is_err());
        assert!(parse_vblk(&p[..0x1a]).is_err());
    }

    #[test]
    fn hostile_databases() {
        let g = "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0";
        let mut disk = vec![0u8; 4 << 20];
        let cs = (disk.len() / 512 - 2048) as u64;
        disk[6 * 512..7 * 512].copy_from_slice(&build::privhead(g, 63, cs, 2048));
        let gb: [u8; 16] = text_guid(g.as_bytes()).unwrap().try_into().unwrap();
        let recs = vec![
            disk4(1, "Disk1", &gb),
            volume(2, "Volume1", "gen", 1, 100, &[1; 16]),
            component(3, "Volume1-01", 2, 1, 2),
            partition(4, "Disk1-01", 0, 0, 100, 3, 1),
        ];
        let db = build::database(&recs, 128, 2048);
        let at = cs as usize * 512;
        disk[at..at + db.len()].copy_from_slice(&db);
        let io = |d: Vec<u8>| -> Io { Rc::new(RefCell::new(Local { disks: vec![d] })) };
        let m = [Member {
            disk: 0,
            privhead: 6 * 512,
        }];
        let v = volumes(&io(disk.clone()), &m).unwrap();
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].map.as_ref().unwrap()[0].legs, [(0, 63 * 512)]);
        // every single-byte change of the database: an answer or an error, never a panic
        for i in (at + 17 * 512..at + 17 * 512 + 1200).step_by(3) {
            for x in [0u8, 0xff, 0x08] {
                let mut d = disk.clone();
                d[i] = x;
                let _ = volumes(&io(d), &m);
            }
        }
        // a record count far beyond the area
        let mut d = disk.clone();
        d[at + 17 * 512 + 4..at + 17 * 512 + 8].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(volumes(&io(d), &m).is_err());
    }
}
