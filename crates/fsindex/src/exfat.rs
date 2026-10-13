//! exFAT, own minimal read-only parser (no maintained read-only crate): boot
//! sector, FAT chains, directory entry sets (file, stream extension, names).
//! Bounded: cluster chains are cut at the cluster count, directories at
//! 64 MiB, names at 255 characters.

use crate::disk::{le16, le32, le64, Vol};
use crate::walk::Out;
use crate::{Volume, KIND_DIR, KIND_FILE, MAX_DEPTH, MAX_PATH};

const MAX_DIR: u64 = 64 << 20;

struct Ex {
    v: Vol,
    fat: u64,
    heap: u64,
    cs: u64,
    count: u32,
}

/// exFAT time stamp (local time, taken as UTC) to unix seconds.
fn ts(t: u32) -> i64 {
    let (sec, min, hour) = ((t & 0x1f) * 2, (t >> 5) & 0x3f, (t >> 11) & 0x1f);
    let (day, month, year) = ((t >> 16) & 0x1f, (t >> 21) & 0xf, 1980 + (t >> 25));
    crate::fat::days_from_civil(year as i64, month.max(1) as i64, day.max(1) as i64) * 86400
        + hour as i64 * 3600
        + min as i64 * 60
        + sec as i64
}

impl Ex {
    fn open(v: &Vol) -> Result<Ex, String> {
        let b = v.read_vec(0, 512).map_err(|e| e.to_string())?;
        if b.len() < 512 || b.get(3..11) != Some(b"EXFAT   ") || b[510] != 0x55 || b[511] != 0xaa {
            return Err("exfat: no boot sector".into());
        }
        let (bps_shift, spc_shift) = (b[108] as u32, b[109] as u32);
        if !(9..=12).contains(&bps_shift) || bps_shift + spc_shift > 25 {
            return Err("exfat: sector / cluster size".into());
        }
        let bps = 1u64 << bps_shift;
        let ex = Ex {
            v: v.clone(),
            fat: le32(&b, 80) as u64 * bps,
            heap: le32(&b, 88) as u64 * bps,
            cs: 1u64 << (bps_shift + spc_shift),
            count: le32(&b, 92),
        };
        if ex.fat == 0 || ex.heap == 0 || ex.count == 0 || ex.heap >= v.size() {
            return Err("exfat: layout".into());
        }
        Ok(ex)
    }

    fn cluster_off(&self, c: u32) -> Result<u64, String> {
        if c < 2 || c - 2 >= self.count {
            return Err(format!("exfat: cluster {c} outside the heap"));
        }
        Ok(self.heap + (c as u64 - 2) * self.cs)
    }

    fn next(&self, c: u32) -> Result<u32, String> {
        let mut b = [0u8; 4];
        self.v.read_at(self.fat + c as u64 * 4, &mut b).map_err(|e| e.to_string())?;
        Ok(u32::from_le_bytes(b))
    }

    /// The bytes of a cluster chain: contiguous (`nofat`, `len` bytes) or
    /// through the FAT (`len` = 0: to the end of the chain).
    fn read_chain(&self, first: u32, nofat: bool, len: u64) -> Result<Vec<u8>, String> {
        let limit = if len == 0 { MAX_DIR } else { len.min(MAX_DIR) };
        let mut out = Vec::new();
        let mut c = first;
        let mut steps = 0u64;
        while (out.len() as u64) < limit {
            let off = self.cluster_off(c)?;
            let n = self.cs.min(limit - out.len() as u64) as usize;
            out.extend(self.v.read_vec(off, n).map_err(|e| e.to_string())?);
            steps += 1;
            if steps > self.count as u64 {
                return Err("exfat: cluster chain loops".into());
            }
            c = if nofat {
                c.checked_add(1).ok_or("exfat: cluster chain")?
            } else {
                match self.next(c)? {
                    0xffff_ffff => break,
                    n if n < 2 || n >= 0xffff_fff7 => return Err("exfat: broken cluster chain".into()),
                    n => n,
                }
            };
        }
        Ok(out)
    }
}

/// One directory: (name, is_dir, size, mtime, first cluster, no FAT chain, data length).
type Item = (String, bool, u64, i64, u32, bool, u64);

fn entries(data: &[u8], label: &mut Option<String>) -> (Vec<Item>, u64) {
    let mut out = Vec::new();
    let mut bad = 0;
    let mut i = 0;
    while i + 32 <= data.len() {
        let e = &data[i..i + 32];
        match e[0] {
            0x00 => break,
            0x83 => {
                let n = (e[1] as usize).min(11);
                let u: Vec<u16> = (0..n).map(|k| le16(e, 2 + 2 * k)).collect();
                *label = Some(String::from_utf16_lossy(&u));
            }
            0x85 => {
                let sec = e[1] as usize;
                let attrs = le16(e, 4);
                let mtime = ts(le32(e, 12));
                if sec < 2 || i + 32 * (sec + 1) > data.len() {
                    bad += 1;
                    i += 32;
                    continue;
                }
                let st = &data[i + 32..i + 64];
                if st[0] != 0xc0 {
                    bad += 1;
                    i += 32;
                    continue;
                }
                let name_len = st[3] as usize;
                let mut name = Vec::new();
                for k in 2..=sec {
                    let n = &data[i + 32 * k..i + 32 * (k + 1)];
                    if n[0] != 0xc1 {
                        break;
                    }
                    for j in 0..15 {
                        name.push(le16(n, 2 + 2 * j));
                    }
                }
                name.truncate(name_len);
                let size = le64(st, 24);
                out.push((
                    String::from_utf16_lossy(&name),
                    attrs & 0x10 != 0,
                    size,
                    mtime,
                    le32(st, 20),
                    st[1] & 2 != 0,
                    size,
                ));
                i += 32 * (sec + 1);
                continue;
            }
            _ => {}
        }
        i += 32;
    }
    (out, bad)
}

pub fn walk(v: &Vol, out: &mut Out, info: &mut Volume) -> Result<(), String> {
    let ex = Ex::open(v)?;
    let b = v.read_vec(0, 512).map_err(|e| e.to_string())?;
    let serial = le32(&b, 100);
    info.uuid = Some(format!("{:04X}-{:04X}", serial >> 16, serial & 0xffff));
    info.dirty = le16(&b, 106) & 2 != 0;
    // (first cluster, contiguous, length, path, depth): read when popped
    let mut stack = vec![(le32(&b, 96), false, 0u64, String::new(), 0usize)];
    let mut first = true;
    let mut visited = std::collections::HashSet::new();
    while let Some((cl, nofat, len, rel, depth)) = stack.pop() {
        let data = match ex.read_chain(cl, nofat, len) {
            Ok(d) => d,
            Err(e) if first => return Err(e),
            Err(e) => {
                out.note(info, format!("/{rel}: {e}"));
                continue;
            }
        };
        let mut label = None;
        let (items, bad) = entries(&data, &mut label);
        if first {
            info.label = label.filter(|l| !l.is_empty());
            first = false;
        }
        info.skipped_entries += bad;
        for (name, dir, size, mtime, cl, nofat, len) in items {
            if name.is_empty() || name.contains('/') || name == "." || name == ".." {
                info.skipped_entries += 1;
                continue;
            }
            let path = if rel.is_empty() { name } else { format!("{rel}/{name}") };
            if path.len() > MAX_PATH {
                info.skipped_entries += 1;
                continue;
            }
            let kind = if dir { KIND_DIR } else { KIND_FILE };
            if !out.emit(info, &path, if dir { 0 } else { size }, mtime, kind)? {
                return Ok(());
            }
            if dir && cl != 0 {
                if depth + 1 >= MAX_DEPTH {
                    out.note(info, format!("/{path}: nested too deeply"));
                    continue;
                }
                if visited.insert(cl) {
                    stack.push((cl, nofat, if nofat { len } else { 0 }, path, depth + 1));
                }
            }
        }
    }
    Ok(())
}
