//! Windows registry hives (regf), read-only and minimal (Phase 31c): enough to
//! read the drive letters from `MountedDevices` in the SYSTEM hive of a
//! Windows system volume. Base block (checksum), key nodes (`nk`), subkey
//! lists (`lf`, `lh`, `li`, `ri`), value lists and values (`vk`, data up to
//! one cell; big data `db` is not read). Every offset is checked against the
//! hive's size, lists are bounded, `ri` nesting is limited; hostile input
//! gives an error, never a panic or an endless loop. Transaction logs
//! (`SYSTEM.LOG1/2`) are not replayed: a value written in the last minutes
//! before the snapshot may be missing (drive letters rarely change).

use crate::disk::{le16, le32};

/// Hive bins start after the 4 KiB base block.
const BINS: u64 = 4096;
/// Subkeys / values per key that are looked at.
const MAX_LIST: usize = 1 << 16;
/// Largest cell read (value data, lists).
const MAX_CELL: usize = 1 << 20;

/// Random access to the hive file.
pub trait HiveRead {
    /// bytes in the hive file
    fn size(&self) -> u64;
    /// Exactly `buf.len()` bytes at `off`.
    fn read_at(&mut self, off: u64, buf: &mut [u8]) -> Result<(), String>;
}

impl HiveRead for &[u8] {
    fn size(&self) -> u64 {
        <[u8]>::len(self) as u64
    }
    fn read_at(&mut self, off: u64, buf: &mut [u8]) -> Result<(), String> {
        let s = usize::try_from(off).ok().ok_or("hive: offset")?;
        let src = self
            .get(s..s.checked_add(buf.len()).ok_or("hive: offset")?)
            .ok_or("hive: read beyond the end")?;
        buf.copy_from_slice(src);
        Ok(())
    }
}

pub struct Hive<R> {
    r: R,
    /// bytes of hive bins (base block field, cut to the file)
    bins: u64,
    root: u32,
}

/// A value: name, type, data.
#[derive(Clone, Debug, PartialEq)]
pub struct Value {
    pub name: String,
    pub ty: u32,
    pub data: Vec<u8>,
}

impl<R: HiveRead> Hive<R> {
    pub fn open(mut r: R) -> Result<Hive<R>, String> {
        let mut b = vec![0u8; 512];
        r.read_at(0, &mut b)?;
        if &b[0..4] != b"regf" {
            return Err("hive: no regf signature".into());
        }
        let mut x = 0u32;
        for i in 0..127 {
            x ^= le32(&b, i * 4);
        }
        let x = match x {
            0 => 1,
            0xffff_ffff => 0xffff_fffe,
            x => x,
        };
        if x != le32(&b, 508) {
            return Err("hive: base block checksum".into());
        }
        let bins = u64::from(le32(&b, 40)).min(r.size().saturating_sub(BINS));
        let root = le32(&b, 36);
        if bins == 0 {
            return Err("hive: no hive bins".into());
        }
        Ok(Hive { r, bins, root })
    }

    /// The data of the allocated cell at `off` (relative to the bins), at least `min` bytes.
    fn cell(&mut self, off: u32, min: usize) -> Result<Vec<u8>, String> {
        let off = u64::from(off);
        if off.checked_add(4).is_none_or(|e| e > self.bins) {
            return Err("hive: cell outside the bins".into());
        }
        let mut h = [0u8; 4];
        self.r.read_at(BINS + off, &mut h)?;
        let size = i32::from_le_bytes(h);
        // allocated cells have a negative size (header included)
        let len = (size
            .checked_neg()
            .filter(|s| *s >= 4)
            .ok_or("hive: cell not allocated")?
            - 4) as usize;
        if len < min || len > MAX_CELL || off + 4 + len as u64 > self.bins {
            return Err("hive: cell size".into());
        }
        let mut d = vec![0u8; len];
        self.r.read_at(BINS + off + 4, &mut d)?;
        Ok(d)
    }

    fn key(&mut self, off: u32) -> Result<Key, String> {
        let d = self.cell(off, 0x4c)?;
        if &d[0..2] != b"nk" {
            return Err("hive: not a key node".into());
        }
        let n = le16(&d, 0x48) as usize;
        let raw = d.get(0x4c..0x4c + n).ok_or("hive: key name")?;
        Ok(Key {
            name: name(raw, le16(&d, 2) & 0x20 != 0),
            subkeys: le32(&d, 0x14),
            subkey_list: le32(&d, 0x1c),
            values: le32(&d, 0x24),
            value_list: le32(&d, 0x28),
        })
    }

    /// The cell offsets of the subkeys listed at `off`.
    fn subkey_offsets(&mut self, off: u32, depth: usize, out: &mut Vec<u32>) -> Result<(), String> {
        if depth > 4 {
            return Err("hive: subkey index nested too deeply".into());
        }
        let d = self.cell(off, 4)?;
        let n = le16(&d, 2) as usize;
        let (step, sig) = (
            match &d[0..2] {
                b"lf" | b"lh" => 8,
                b"li" | b"ri" => 4,
                _ => return Err("hive: unknown subkey list".into()),
            },
            [d[0], d[1]],
        );
        if 4 + n * step > d.len() {
            return Err("hive: subkey list truncated".into());
        }
        for i in 0..n {
            let o = le32(&d, 4 + i * step);
            if &sig == b"ri" {
                self.subkey_offsets(o, depth + 1, out)?;
            } else {
                out.push(o);
            }
            if out.len() > MAX_LIST {
                return Err("hive: too many subkeys".into());
            }
        }
        Ok(())
    }

    /// The subkey `name` (case-insensitive) of the key at `off`.
    fn subkey(&mut self, off: u32, want: &str) -> Result<Option<u32>, String> {
        let k = self.key(off)?;
        if k.subkeys == 0 {
            return Ok(None);
        }
        let mut offs = Vec::new();
        self.subkey_offsets(k.subkey_list, 0, &mut offs)?;
        for o in offs {
            if self.key(o)?.name.eq_ignore_ascii_case(want) {
                return Ok(Some(o));
            }
        }
        Ok(None)
    }

    /// The key at `path` (`\`-separated, below the root key); `None`: not there.
    pub fn find(&mut self, path: &str) -> Result<Option<u32>, String> {
        let mut at = self.root;
        self.key(at)?;
        for c in path.split('\\').filter(|c| !c.is_empty()) {
            match self.subkey(at, c)? {
                Some(o) => at = o,
                None => return Ok(None),
            }
        }
        Ok(Some(at))
    }

    /// The values of the key at `off` (data of more than one cell is left empty).
    pub fn values(&mut self, off: u32) -> Result<Vec<Value>, String> {
        let k = self.key(off)?;
        let n = k.values as usize;
        if n == 0 {
            return Ok(Vec::new());
        }
        if n > MAX_LIST {
            return Err("hive: too many values".into());
        }
        let list = self.cell(k.value_list, n * 4)?;
        let mut out = Vec::with_capacity(n);
        for i in 0..n {
            let d = self.cell(le32(&list, i * 4), 0x14)?;
            if &d[0..2] != b"vk" {
                return Err("hive: not a value".into());
            }
            let nlen = le16(&d, 2) as usize;
            let raw = d.get(0x14..0x14 + nlen).ok_or("hive: value name")?;
            let name = name(raw, le16(&d, 0x10) & 1 != 0);
            let (size, at, ty) = (le32(&d, 4), le32(&d, 8), le32(&d, 12));
            let data = if size & 0x8000_0000 != 0 {
                // up to 4 bytes kept in the offset field
                let n = (size & 0x7fff_ffff).min(4) as usize;
                at.to_le_bytes()[..n].to_vec()
            } else if size as usize > MAX_CELL - 4 {
                Vec::new()
            } else {
                let c = self.cell(at, 0)?;
                if c.len() < size as usize || c.starts_with(b"db") && size > 16344 {
                    Vec::new()
                } else {
                    c[..size as usize].to_vec()
                }
            };
            out.push(Value { name, ty, data });
        }
        Ok(out)
    }
}

struct Key {
    name: String,
    subkeys: u32,
    subkey_list: u32,
    values: u32,
    value_list: u32,
}

/// A key or value name: Latin-1 (compressed) or UTF-16LE.
fn name(raw: &[u8], compressed: bool) -> String {
    if compressed {
        raw.iter().map(|&b| b as char).collect()
    } else {
        let u: Vec<u16> = raw.as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes(*c)).collect();
        String::from_utf16_lossy(&u)
    }
}

/// The drive letters of `MountedDevices` in a SYSTEM hive: (`D:`, volume id as
/// [`crate::Volume::win_id`] writes it), sorted by letter. GPT partitions and
/// dynamic volumes: `DMIO:ID:` + GUID; MBR partitions: disk signature + offset.
pub fn drive_letters<R: HiveRead>(r: R) -> Result<Vec<(String, String)>, String> {
    let mut h = Hive::open(r)?;
    let Some(k) = h.find("MountedDevices")? else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    for v in h.values(k)? {
        let Some(l) = v.name.strip_prefix("\\DosDevices\\") else {
            continue;
        };
        let b = l.as_bytes();
        if b.len() != 2 || !b[0].is_ascii_alphabetic() || b[1] != b':' {
            continue;
        }
        let id = match v.data.len() {
            12 => format!("mbr:{:08x}:{}", le32(&v.data, 0), crate::disk::le64(&v.data, 4)),
            24 if v.data.starts_with(b"DMIO:ID:") => format!("guid:{}", crate::part::guid(&v.data[8..])),
            _ => continue,
        };
        out.push((l.to_ascii_uppercase(), id));
    }
    out.sort();
    out.dedup_by(|a, b| a.0 == b.0);
    Ok(out)
}

/// (name, type, data) of a value for [`build`].
#[doc(hidden)]
pub type TestValue<'a> = (&'a str, u32, Vec<u8>);

/// Builds a minimal hive (tests, fuzz seeds): the root key with one subkey
/// per `(path, values)`, values as `(name, type, data)`.
#[doc(hidden)]
pub fn build(keys: &[(&str, Vec<TestValue>)]) -> Vec<u8> {
    struct B {
        bins: Vec<u8>,
    }
    impl B {
        fn cell(&mut self, data: &[u8]) -> u32 {
            let off = self.bins.len() as u32;
            let len = (data.len() + 4).div_ceil(8) * 8;
            self.bins.extend_from_slice(&(-(len as i32)).to_le_bytes());
            self.bins.extend_from_slice(data);
            self.bins.resize(off as usize + len, 0);
            off
        }
        fn key(&mut self, name: &str, subs: &[u32], values: &[u32]) -> u32 {
            let mut lst = 0;
            if !subs.is_empty() {
                let mut l = b"lf".to_vec();
                l.extend_from_slice(&(subs.len() as u16).to_le_bytes());
                for s in subs {
                    l.extend_from_slice(&s.to_le_bytes());
                    l.extend_from_slice(&[0; 4]);
                }
                lst = self.cell(&l);
            }
            let mut vl = 0;
            if !values.is_empty() {
                let l: Vec<u8> = values.iter().flat_map(|v| v.to_le_bytes()).collect();
                vl = self.cell(&l);
            }
            let mut k = vec![0u8; 0x4c];
            k[0..2].copy_from_slice(b"nk");
            k[2..4].copy_from_slice(&0x20u16.to_le_bytes());
            k[0x14..0x18].copy_from_slice(&(subs.len() as u32).to_le_bytes());
            k[0x1c..0x20].copy_from_slice(&lst.to_le_bytes());
            k[0x24..0x28].copy_from_slice(&(values.len() as u32).to_le_bytes());
            k[0x28..0x2c].copy_from_slice(&vl.to_le_bytes());
            k[0x48..0x4a].copy_from_slice(&(name.len() as u16).to_le_bytes());
            k.extend_from_slice(name.as_bytes());
            self.cell(&k)
        }
        fn value(&mut self, name: &str, ty: u32, data: &[u8]) -> u32 {
            let (size, at) = if data.len() <= 4 {
                let mut x = [0u8; 4];
                x[..data.len()].copy_from_slice(data);
                (data.len() as u32 | 0x8000_0000, u32::from_le_bytes(x))
            } else {
                (data.len() as u32, self.cell(data))
            };
            let mut v = vec![0u8; 0x14];
            v[0..2].copy_from_slice(b"vk");
            v[2..4].copy_from_slice(&(name.len() as u16).to_le_bytes());
            v[4..8].copy_from_slice(&size.to_le_bytes());
            v[8..12].copy_from_slice(&at.to_le_bytes());
            v[12..16].copy_from_slice(&ty.to_le_bytes());
            v[0x10..0x12].copy_from_slice(&1u16.to_le_bytes());
            v.extend_from_slice(name.as_bytes());
            self.cell(&v)
        }
    }
    let mut b = B { bins: b"hbin".to_vec() };
    b.bins.resize(32, 0);
    let mut subs = Vec::new();
    for (name, vals) in keys {
        let vs: Vec<u32> = vals.iter().map(|(n, t, d)| b.value(n, *t, d)).collect();
        subs.push(b.key(name, &[], &vs));
    }
    let root = b.key("ROOT", &subs, &[]);
    let size = b.bins.len().div_ceil(4096) * 4096;
    b.bins.resize(size, 0);
    b.bins[8..12].copy_from_slice(&(size as u32).to_le_bytes());
    let mut base = vec![0u8; 4096];
    base[0..4].copy_from_slice(b"regf");
    base[4..8].copy_from_slice(&1u32.to_le_bytes());
    base[8..12].copy_from_slice(&1u32.to_le_bytes());
    base[20..24].copy_from_slice(&1u32.to_le_bytes());
    base[24..28].copy_from_slice(&5u32.to_le_bytes());
    base[36..40].copy_from_slice(&root.to_le_bytes());
    base[40..44].copy_from_slice(&(size as u32).to_le_bytes());
    let x = match (0..127).fold(0u32, |x, i| x ^ le32(&base, i * 4)) {
        0 => 1,
        0xffff_ffff => 0xffff_fffe,
        x => x,
    };
    base[508..512].copy_from_slice(&x.to_le_bytes());
    base.extend(b.bins);
    base
}

/// `MountedDevices` data of a GPT partition / dynamic volume (`guid` as text).
#[doc(hidden)]
pub fn dmio(guid: &str) -> Vec<u8> {
    let h: Vec<u8> = guid
        .split('-')
        .flat_map(|p| (0..p.len() / 2).map(move |i| u8::from_str_radix(&p[i * 2..i * 2 + 2], 16).unwrap_or(0)))
        .collect();
    let mut g: Vec<u8> = Vec::with_capacity(16);
    if h.len() == 16 {
        g.extend(h[0..4].iter().rev());
        g.extend(h[4..6].iter().rev());
        g.extend(h[6..8].iter().rev());
        g.extend(&h[8..16]);
    }
    let mut d = b"DMIO:ID:".to_vec();
    d.extend(g);
    d
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mbr(sig: u32, off: u64) -> Vec<u8> {
        let mut d = sig.to_le_bytes().to_vec();
        d.extend(off.to_le_bytes());
        d
    }

    fn utf16(s: &str) -> Vec<u8> {
        s.encode_utf16().flat_map(u16::to_le_bytes).collect()
    }

    #[test]
    fn drive_letters_from_mounted_devices() {
        let g = "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0";
        let hive = build(&[
            ("Select", vec![("Current", 4, 1u32.to_le_bytes().to_vec())]),
            (
                "MountedDevices",
                vec![
                    ("\\DosDevices\\C:", 3, dmio(g)),
                    ("\\DosDevices\\E:", 3, mbr(0xdead_beef, 1 << 20)),
                    ("\\DosDevices\\D:", 3, utf16("\\??\\SCSI#CdRom&Ven_QEMU")),
                    ("\\??\\Volume{1234}", 3, dmio(g)),
                ],
            ),
        ]);
        let d = drive_letters(hive.as_slice()).unwrap();
        assert_eq!(
            d,
            [
                ("C:".to_string(), format!("guid:{g}")),
                ("E:".to_string(), "mbr:deadbeef:1048576".to_string())
            ]
        );
        let mut h = Hive::open(hive.as_slice()).unwrap();
        let k = h.find("select").unwrap().unwrap();
        assert_eq!(h.values(k).unwrap()[0].data, 1u32.to_le_bytes());
        assert_eq!(h.find("Nope\\x").unwrap(), None);
        // no MountedDevices: no letters
        assert!(drive_letters(build(&[("Select", vec![])]).as_slice())
            .unwrap()
            .is_empty());
    }

    #[test]
    fn hostile_hives() {
        let good = build(&[("MountedDevices", vec![("\\DosDevices\\C:", 3, mbr(1, 2))])]);
        // checksum, signature
        let mut b = good.clone();
        b[100] ^= 1;
        assert!(drive_letters(b.as_slice()).is_err());
        assert!(drive_letters(&b"regf"[..]).is_err());
        // every single-byte change of the bins: an error or an answer, never a panic
        for i in 4096..good.len().min(4096 + 600) {
            for x in [0x00u8, 0xff, 0x80, 0x7f] {
                let mut b = good.clone();
                b[i] = x;
                let _ = drive_letters(b.as_slice());
            }
        }
        // a subkey index that points at itself (ri loop): bounded
        let mut b = good.clone();
        let root = le32(&b, 36) as usize;
        let list = le32(&b, 4096 + root + 4 + 0x1c) as usize;
        b[4096 + list + 4..4096 + list + 6].copy_from_slice(b"ri");
        b[4096 + list + 8..4096 + list + 12].copy_from_slice(&(list as u32).to_le_bytes());
        assert!(drive_letters(b.as_slice()).is_err());
        // truncated file
        assert!(drive_letters(&good[..4200]).is_err());
    }
}
