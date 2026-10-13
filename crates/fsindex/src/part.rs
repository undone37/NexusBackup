//! Partition tables: GPT (primary, else backup header; CRCs checked) and MBR
//! with extended / logical partitions. Read-only, bounded (at most 256
//! partitions per disk, EBR chains checked for loops).

use crate::disk::{le16, le32, le64, Vol};
use std::io;

pub const SECTOR: u64 = 512;
const MAX_PARTS: usize = 256;

#[derive(Clone, Debug, PartialEq)]
pub enum PType {
    /// a file system is expected (probed by content)
    Data,
    Lvm,
    Swap,
    /// Windows dynamic disk (LDM): not indexed (31c)
    Ldm,
    StorageSpaces,
    /// Microsoft reserved, BIOS boot: no file system, not reported
    Reserved,
    LinuxRaid,
    Zfs,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Part {
    /// partition number as Linux numbers it (GPT slot + 1; MBR 1-4, logical from 5)
    pub number: u32,
    pub start: u64,
    pub len: u64,
    pub ptype: PType,
    /// GPT unique partition GUID (lowercase), `PARTUUID=`
    pub guid: Option<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Table {
    /// no partition table: the whole disk is one volume
    None,
    Mbr(Vec<Part>),
    Gpt(Vec<Part>),
    /// a table was found but cannot be used
    Corrupt(String),
}

fn crc32_raw(mut c: u32, data: &[u8]) -> u32 {
    for &b in data {
        c ^= b as u32;
        for _ in 0..8 {
            c = if c & 1 != 0 { (c >> 1) ^ 0xEDB8_8320 } else { c >> 1 };
        }
    }
    c
}

/// CRC-32 (IEEE, as GPT uses it).
pub fn crc32(data: &[u8]) -> u32 {
    !crc32_raw(!0, data)
}

/// LVM2's `calc_crc(INITIAL_CRC, …)`: same polynomial, seed 0xf597a6cf, no final inversion.
pub fn crc32_lvm(data: &[u8]) -> u32 {
    crc32_raw(0xf597_a6cf, data)
}

/// Mixed-endian GUID as text (`xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`, lowercase).
pub fn guid(b: &[u8]) -> String {
    if b.len() < 16 {
        return String::new();
    }
    format!(
        "{:08x}-{:04x}-{:04x}-{}-{}",
        le32(b, 0),
        le16(b, 4),
        le16(b, 6),
        crate::hex(&b[8..10]),
        crate::hex(&b[10..16])
    )
}

fn gpt_type(g: &str) -> Option<PType> {
    Some(match g {
        "00000000-0000-0000-0000-000000000000" => return None,
        "e6d6d379-f507-44c2-a23c-238f2a3df928" => PType::Lvm,
        "0657fd6d-a4ab-43c4-84e5-0933c84b4f4f" => PType::Swap,
        "5808c8aa-7e8f-42e0-85d2-e1e90434cfb3" | "af9b60a0-1431-4f62-bc68-3311714a69ad" => PType::Ldm,
        "e75caf8f-f680-4cee-afa3-b001e56efc2d" => PType::StorageSpaces,
        "e3c9e316-0b5c-4db8-817d-f92df00215ae" | "21686148-6449-6e6f-744e-656564454649" => PType::Reserved,
        "a19d880f-05fc-4d3b-a006-743f0f84911e" => PType::LinuxRaid,
        "6a898cc3-1dd2-11b2-99a6-080020736631" => PType::Zfs,
        _ => PType::Data,
    })
}

fn mbr_type(t: u8) -> Option<PType> {
    Some(match t {
        0x00 | 0x05 | 0x0f | 0x85 | 0xee => return None,
        0x8e => PType::Lvm,
        0x82 => PType::Swap,
        0x42 => PType::Ldm,
        0xfd => PType::LinuxRaid,
        _ => PType::Data,
    })
}

/// GPT header at `lba` with sector size `ss`: the partitions, or why not.
fn gpt_at(v: &Vol, lba: u64, ss: u64) -> Result<Vec<Part>, String> {
    let h = v.read_vec(lba * ss, ss as usize).map_err(|e| e.to_string())?;
    if h.get(0..8) != Some(b"EFI PART") {
        return Err("no GPT header".into());
    }
    let hsize = le32(&h, 12) as usize;
    if !(92..=ss as usize).contains(&hsize) {
        return Err("GPT header size".into());
    }
    let mut hc = h[..hsize].to_vec();
    hc[16..20].fill(0);
    if crc32(&hc) != le32(&h, 16) {
        return Err("GPT header checksum".into());
    }
    let (first_use, last_use) = (le64(&h, 40), le64(&h, 48));
    let (entries_lba, count, esize) = (le64(&h, 72), le32(&h, 80) as u64, le32(&h, 84) as u64);
    if count > 1024 || !(128..=4096).contains(&esize) || esize % 8 != 0 {
        return Err("GPT entry array".into());
    }
    let arr = v
        .read_vec(entries_lba.checked_mul(ss).ok_or("GPT entry array")?, (count * esize) as usize)
        .map_err(|e| e.to_string())?;
    if arr.len() as u64 != count * esize || crc32(&arr) != le32(&h, 88) {
        return Err("GPT entry array checksum".into());
    }
    let disk_sectors = v.size() / ss;
    let mut out = Vec::new();
    for i in 0..count as usize {
        let e = &arr[i * esize as usize..(i + 1) * esize as usize];
        let Some(pt) = gpt_type(&guid(&e[0..16])) else { continue };
        let (first, last) = (le64(e, 32), le64(e, 40));
        if first > last || first < first_use.min(2) || last >= disk_sectors || (last_use > 0 && last > last_use) {
            return Err(format!("GPT partition {} outside the disk", i + 1));
        }
        out.push(Part {
            number: i as u32 + 1,
            start: first * ss,
            len: (last - first + 1) * ss,
            ptype: pt,
            guid: Some(guid(&e[16..32])),
        });
        if out.len() > MAX_PARTS {
            return Err("too many partitions".into());
        }
    }
    Ok(out)
}

fn mbr_entries(s: &[u8]) -> Vec<(u8, u8, u64, u64)> {
    (0..4)
        .map(|i| {
            let e = &s[446 + i * 16..462 + i * 16];
            (e[0], e[4], le32(e, 8) as u64, le32(e, 12) as u64)
        })
        .collect()
}

/// A plausible MBR: signature, status bytes 0x00/0x80, entries inside the disk.
fn mbr_ok(s: &[u8], disk: u64) -> bool {
    s.len() >= 512
        && s[510] == 0x55
        && s[511] == 0xaa
        && mbr_entries(s).iter().all(|(st, t, lba, n)| {
            (*st == 0 || *st == 0x80) && (*t == 0 || (*lba > 0 && (*lba + *n) * SECTOR <= disk + SECTOR))
        })
        && mbr_entries(s).iter().any(|(_, t, _, n)| *t != 0 && *n > 0)
}

/// Reads the partition table of a disk. A boot sector of a file system at
/// sector 0 (whole-disk FAT/NTFS/exFAT) is not taken for an MBR.
pub fn parse(v: &Vol) -> io::Result<Table> {
    let s0 = v.read_vec(0, SECTOR as usize)?;
    if s0.len() < 512 || crate::probe::is_boot_sector_fs(&s0) {
        return Ok(Table::None);
    }
    let size = v.size();
    let protective = mbr_ok(&s0, size) && mbr_entries(&s0).iter().any(|e| e.1 == 0xee);
    // GPT: 512-byte sectors, then 4 KiB; primary header, then the backup at the last sector
    let mut gpt_err = None;
    for ss in [SECTOR, 4096] {
        if size < ss * 3 {
            continue;
        }
        match gpt_at(v, 1, ss).or_else(|e| gpt_at(v, size / ss - 1, ss).map_err(|_| e)) {
            Ok(p) => return Ok(Table::Gpt(p)),
            Err(e) if e != "no GPT header" => gpt_err = Some(e),
            Err(_) => {}
        }
    }
    if protective {
        return Ok(Table::Corrupt(gpt_err.unwrap_or_else(|| "protective MBR without a GPT".into())));
    }
    if let Some(e) = gpt_err {
        return Ok(Table::Corrupt(e));
    }
    if !mbr_ok(&s0, size) {
        return Ok(Table::None);
    }
    let mut out = Vec::new();
    for (i, (_, t, lba, n)) in mbr_entries(&s0).into_iter().enumerate() {
        if n == 0 {
            continue;
        }
        if matches!(t, 0x05 | 0x0f | 0x85) {
            if let Err(e) = logical(v, lba, &mut out) {
                return Ok(Table::Corrupt(e));
            }
            continue;
        }
        if let Some(pt) = mbr_type(t) {
            out.push(Part {
                number: i as u32 + 1,
                start: lba * SECTOR,
                len: n * SECTOR,
                ptype: pt,
                guid: None,
            });
        }
    }
    Ok(Table::Mbr(out))
}

/// Logical partitions of the extended partition at `ext` (sectors): a chain of
/// EBRs, each with the logical partition (relative to the EBR) and the link
/// to the next EBR (relative to the extended partition).
fn logical(v: &Vol, ext: u64, out: &mut Vec<Part>) -> Result<(), String> {
    let mut at = ext;
    let mut seen = std::collections::HashSet::new();
    let mut number = 5;
    loop {
        if !seen.insert(at) || seen.len() > MAX_PARTS {
            return Err("extended partition chain loops".into());
        }
        let s = v.read_vec(at * SECTOR, SECTOR as usize).map_err(|e| e.to_string())?;
        if s.len() < 512 || s[510] != 0x55 || s[511] != 0xaa {
            return Err("extended boot record without signature".into());
        }
        let e = mbr_entries(&s);
        let (_, t, rel, n) = e[0];
        if n > 0 {
            if let Some(pt) = mbr_type(t) {
                let start = (at + rel) * SECTOR;
                if start + n * SECTOR > v.size() {
                    return Err(format!("logical partition {number} outside the disk"));
                }
                out.push(Part {
                    number,
                    start,
                    len: n * SECTOR,
                    ptype: pt,
                    guid: None,
                });
            }
            number += 1;
        }
        let (_, t2, next, _) = e[1];
        if t2 == 0 || next == 0 {
            return Ok(());
        }
        at = ext + next;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::disk::{Io, Local};
    use std::cell::RefCell;
    use std::rc::Rc;

    pub fn vol(d: Vec<u8>) -> Vol {
        let n = d.len() as u64;
        let io: Io = Rc::new(RefCell::new(Local { disks: vec![d] }));
        Vol::region(io, 0, 0, n)
    }

    fn mbr_entry(s: &mut [u8], i: usize, t: u8, lba: u32, n: u32) {
        let e = &mut s[446 + i * 16..462 + i * 16];
        e[4] = t;
        e[8..12].copy_from_slice(&lba.to_le_bytes());
        e[12..16].copy_from_slice(&n.to_le_bytes());
    }

    #[test]
    fn crc() {
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    }

    #[test]
    fn mbr_with_logical_partitions() {
        let mut d = vec![0u8; 4096 * 512];
        mbr_entry(&mut d, 0, 0x83, 2048, 1000);
        mbr_entry(&mut d, 1, 0x05, 3100, 900);
        d[510] = 0x55;
        d[511] = 0xaa;
        // EBR 1 at 3100: logical at +10 (100 sectors), next EBR at ext+200
        let e1 = 3100 * 512;
        {
            let s = &mut d[e1..e1 + 512];
            mbr_entry(s, 0, 0x8e, 10, 100);
            mbr_entry(s, 1, 0x05, 200, 300);
            s[510] = 0x55;
            s[511] = 0xaa;
        }
        let e2 = 3300 * 512;
        {
            let s = &mut d[e2..e2 + 512];
            mbr_entry(s, 0, 0x07, 10, 50);
            s[510] = 0x55;
            s[511] = 0xaa;
        }
        let Table::Mbr(p) = parse(&vol(d.clone())).unwrap() else { panic!() };
        let got: Vec<_> = p.iter().map(|p| (p.number, p.start / 512, p.len / 512, p.ptype.clone())).collect();
        assert_eq!(
            got,
            [(1, 2048, 1000, PType::Data), (5, 3110, 100, PType::Lvm), (6, 3310, 50, PType::Data)]
        );
        // a loop in the EBR chain
        {
            let s = &mut d[e2..e2 + 512];
            mbr_entry(s, 1, 0x05, 0, 300);
        }
        let s = &mut d[e2..e2 + 512];
        mbr_entry(s, 1, 0x05, 200, 300); // points back to itself (ext + 200)
        assert!(matches!(parse(&vol(d)).unwrap(), Table::Corrupt(_)));
    }

    #[test]
    fn gpt_and_corruption() {
        let sectors = 8192u64;
        let mut d = vec![0u8; (sectors * 512) as usize];
        mbr_entry(&mut d, 0, 0xee, 1, (sectors - 1) as u32);
        d[510] = 0x55;
        d[511] = 0xaa;
        let mut arr = vec![0u8; 128 * 128];
        let lvm = [
            0x79, 0xd3, 0xd6, 0xe6, 0x07, 0xf5, 0xc2, 0x44, 0xa2, 0x3c, 0x23, 0x8f, 0x2a, 0x3d, 0xf9, 0x28,
        ];
        arr[0..16].copy_from_slice(&lvm);
        arr[16..32].copy_from_slice(&[0x11; 16]);
        arr[32..40].copy_from_slice(&2048u64.to_le_bytes());
        arr[40..48].copy_from_slice(&4095u64.to_le_bytes());
        let mut h = vec![0u8; 92];
        h[0..8].copy_from_slice(b"EFI PART");
        h[12..16].copy_from_slice(&92u32.to_le_bytes());
        h[40..48].copy_from_slice(&34u64.to_le_bytes());
        h[48..56].copy_from_slice(&(sectors - 34).to_le_bytes());
        h[72..80].copy_from_slice(&2u64.to_le_bytes());
        h[80..84].copy_from_slice(&128u32.to_le_bytes());
        h[84..88].copy_from_slice(&128u32.to_le_bytes());
        h[88..92].copy_from_slice(&crc32(&arr).to_le_bytes());
        let c = crc32(&h);
        h[16..20].copy_from_slice(&c.to_le_bytes());
        d[512..604].copy_from_slice(&h);
        d[1024..1024 + arr.len()].copy_from_slice(&arr);
        let Table::Gpt(p) = parse(&vol(d.clone())).unwrap() else { panic!() };
        assert_eq!(p.len(), 1);
        assert_eq!((p[0].number, p[0].start, p[0].ptype.clone()), (1, 2048 * 512, PType::Lvm));
        assert_eq!(p[0].guid.as_deref(), Some("11111111-1111-1111-1111-111111111111"));
        d[1024 + 33] ^= 1; // entry array checksum no longer matches
        assert_eq!(
            parse(&vol(d)).unwrap(),
            Table::Corrupt("GPT entry array checksum".into())
        );
    }
}
