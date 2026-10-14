//! NTFS through the crate `ntfs` (read-only). Directories are walked through
//! their `$I30` indexes; size and modification time come from each file's own
//! record (`$DATA` length, `$STANDARD_INFORMATION`), not from the index copy
//! of `$FILE_NAME` (Windows updates that lazily). DOS 8.3 aliases and the NTFS
//! metadata files are left out. `$LogFile` is never replayed. Owners (Phase
//! 31c): the security id of `$STANDARD_INFORMATION` names a descriptor in
//! `$Secure:$SDS`, read once per volume, whose owner SID is the entry's owner.

use crate::disk::{le16, le32, le64, Padded, Vol};
use crate::walk::Out;
use crate::{nt_to_unix, Volume, KIND_DIR, KIND_FILE, KIND_SYMLINK, MAX_DEPTH, MAX_PATH};
use ntfs::structured_values::{NtfsFileAttributeFlags, NtfsFileNamespace, NtfsStandardInformation, NtfsVolumeFlags};
use ntfs::{Ntfs, NtfsAttributeType, NtfsFile, NtfsReadSeek};
use std::collections::HashMap;

const TAG_DEDUP: u32 = 0x8000_0013;
const TAG_SYMLINK: u32 = 0xA000_000C;
const TAG_MOUNT_POINT: u32 = 0xA000_0003;
/// records 0-15: $MFT, $MFTMirr, $LogFile, $Volume, $AttrDef, ., $Bitmap, $Boot,
/// $BadClus, $Secure, $UpCase, $Extend, reserved
const FIRST_USER_RECORD: u64 = 16;
const ROOT: u64 = 5;
/// `$Secure`, whose `$SDS` stream holds the security descriptors.
const SECURE: u64 = 9;
/// Bytes of `$SDS` read for the owner table.
const MAX_SDS: u64 = 32 << 20;
/// `$SDS` is written in 256 KiB blocks, each followed by its mirror copy.
const SDS_BLOCK: usize = 256 << 10;

/// A SID as text (`S-1-5-21-…`), from its binary form.
pub fn sid_text(b: &[u8]) -> Option<String> {
    let (rev, n) = (*b.first()?, *b.get(1)? as usize);
    if rev != 1 || n > 15 {
        return None;
    }
    let auth = b.get(2..8)?.iter().fold(0u64, |a, x| a << 8 | u64::from(*x));
    let mut s = format!("S-1-{auth}");
    for i in 0..n {
        s.push_str(&format!("-{}", crate::disk::le32(b.get(8 + i * 4..12 + i * 4)?, 0)));
    }
    Some(s)
}

/// The owner SIDs of the security descriptors in a `$SDS` stream, by security id.
pub fn parse_sds(d: &[u8], out: &mut HashMap<u32, String>) {
    let mut block = 0;
    while block < d.len() {
        let end = (block + SDS_BLOCK).min(d.len());
        let mut at = block;
        // entry: hash, security id, its own offset, length, then the self-relative descriptor
        while at + 20 <= end {
            let (id, off, len) = (le32(d, at + 4), le64(d, at + 8), le32(d, at + 16) as usize);
            if len < 20 + 20 || off != at as u64 || at + len > end {
                break;
            }
            let sd = &d[at + 20..at + len];
            // revision 1, self-relative (control 0x8000), owner offset
            let owner = le32(sd, 4) as usize;
            if sd[0] == 1 && le16(sd, 2) & 0x8000 != 0 && owner >= 20 {
                if let Some(s) = sd.get(owner..).and_then(sid_text) {
                    out.insert(id, s);
                }
            }
            if out.len() > 1 << 20 {
                return;
            }
            at += len.div_ceil(16) * 16;
        }
        block += 2 * SDS_BLOCK; // skip the mirror copy
    }
}

/// security id -> owner SID of the volume (`$Secure:$SDS`); empty when it cannot be read.
fn owners(ntfs: &Ntfs, fs: &mut Padded) -> HashMap<u32, String> {
    let mut out = HashMap::new();
    let Ok(f) = ntfs.file(fs, SECURE) else { return out };
    // the named $DATA stream "$SDS" (looked up by hand: the crate's name lookup needs $UpCase)
    let mut attrs = f.attributes();
    while let Some(item) = attrs.next(fs) {
        let Ok(item) = item else { break };
        let Ok(a) = item.to_attribute() else { continue };
        let named = a.name().is_ok_and(|n| n.to_string_lossy() == "$SDS");
        if a.ty().ok() != Some(NtfsAttributeType::Data) || !named {
            continue;
        }
        let Ok(mut v) = a.value(fs) else { break };
        let mut d = vec![0u8; v.len().min(MAX_SDS) as usize];
        let mut done = 0;
        while done < d.len() {
            match v.read(fs, &mut d[done..]) {
                Ok(n) if n > 0 => done += n,
                _ => break,
            }
        }
        d.truncate(done);
        parse_sds(&d, &mut out);
        break;
    }
    out
}

fn reparse_tag(f: &NtfsFile, fs: &mut Padded) -> Option<u32> {
    let mut attrs = f.attributes();
    while let Some(item) = attrs.next(fs) {
        let item = item.ok()?;
        let a = item.to_attribute().ok()?;
        if a.ty().ok()? == NtfsAttributeType::ReparsePoint {
            let mut v = a.value(fs).ok()?;
            let mut b = [0u8; 4];
            return (v.read(fs, &mut b).ok()? == 4).then(|| u32::from_le_bytes(b));
        }
    }
    None
}

pub fn walk(v: &Vol, out: &mut Out, info: &mut Volume) -> Result<(), String> {
    let mut fs = Padded(v.clone());
    let ntfs = Ntfs::new(&mut fs).map_err(|e| format!("ntfs: {e}"))?;
    info.uuid = Some(format!("{:016X}", ntfs.serial_number()));
    if let Some(Ok(n)) = ntfs.volume_name(&mut fs) {
        info.label = Some(n.name().to_string_lossy()).filter(|s| !s.is_empty());
    }
    if let Ok(vi) = ntfs.volume_info(&mut fs) {
        info.dirty = vi.flags().contains(NtfsVolumeFlags::IS_DIRTY);
    }
    // MFT records (in use or free): an upper estimate of the entries; the MFT's data runs:
    // the layout signature of the directory records (Phase 31c)
    let mut layout = String::new();
    if let Some(Ok(d)) = ntfs.file(&mut fs, 0).ok().as_ref().and_then(|m| m.data(&mut fs, "")) {
        if let Ok(a) = d.to_attribute() {
            let records = a.value_length() / u64::from(ntfs.file_record_size().max(1));
            out.expect(records.saturating_sub(FIRST_USER_RECORD));
            if let Ok(ntfs::attribute_value::NtfsAttributeValue::NonResident(nr)) = a.value(&mut fs) {
                let mut h: u64 = 0xcbf2_9ce4_8422_2325;
                let mut ok = true;
                for run in nr.data_runs() {
                    let Ok(run) = run else {
                        ok = false;
                        break;
                    };
                    let pos = run.data_position().value().map_or(0, |p| p.get());
                    for b in pos.to_le_bytes().into_iter().chain(run.allocated_size().to_le_bytes()) {
                        h = (h ^ u64::from(b)).wrapping_mul(0x0100_0000_01b3);
                    }
                }
                if ok {
                    layout = format!("ntfs-mft-{h:016x}");
                }
            }
        }
    }
    // every lookup reads the $MFT record (crate ntfs finds the records through its data
    // runs): its blocks change with their neighbours in every snapshot, the layout above
    // stands for what matters in it
    let mft = ntfs.mft_position().value().map(|p| p.get());
    let ignore = mft
        .map(|p| v.disk_blocks(p, u64::from(ntfs.file_record_size())))
        .unwrap_or_default();
    out.dir_basis(layout, ignore);
    // Phase 31c: owners (security id in $STANDARD_INFORMATION -> descriptor in $Secure)
    let owner_of = owners(&ntfs, &mut fs);
    let mut stack: Vec<(u64, String, usize)> = vec![(ROOT, String::new(), 0)];
    // NTFS has no directory hard links: a directory seen twice is a loop
    let mut visited = std::collections::HashSet::from([ROOT]);
    while let Some((rec, rel, depth)) = stack.pop() {
        if !out.walks(&rel, depth) {
            continue; // another helper's share
        }
        // emits this directory's entries (else only looks for its subdirectories)
        let own = out.owns(&rel, depth);
        if let Some(subs) = out.reuse_dir(&rel, own) {
            // Phase 31c: listed in the previous snapshot and nothing that listing read changed
            if depth == 1
                && rel.eq_ignore_ascii_case("Windows")
                && subs.iter().any(|(_, n)| n.eq_ignore_ascii_case("System32"))
            {
                info.windows = true;
            }
            for (num, name) in subs {
                let path = if rel.is_empty() { name } else { format!("{rel}/{name}") };
                if depth + 1 < MAX_DEPTH && out.walks(&path, depth + 1) && visited.insert(num) {
                    stack.push((num, path, depth + 1));
                }
            }
            continue;
        }
        if own {
            out.dir_start();
        }
        // for this directory's record (Phase 31c): its subdirectories, complete or not, its counters
        let mut subdirs: Vec<(u64, String)> = Vec::new();
        let mut complete = true;
        let mut budget_miss = false;
        let (dedup0, skipped0) = (info.dedup_files, info.skipped_entries);
        let dir = match ntfs.file(&mut fs, rec) {
            Ok(d) => d,
            Err(e) => {
                if own {
                    out.note(info, format!("/{rel}: {e}"));
                }
                continue;
            }
        };
        let idx =
            match index_root_ok(&dir, &mut fs).and_then(|()| dir.directory_index(&mut fs).map_err(|e| e.to_string())) {
                Ok(i) => i,
                Err(e) => {
                    if own {
                        out.note(info, format!("/{rel}: {e}"));
                    }
                    continue;
                }
            };
        let mut it = idx.entries();
        let mut seen = std::collections::HashSet::new();
        while let Some(e) = it.next(&mut fs) {
            let e = match e {
                Ok(e) => e,
                Err(err) => {
                    if own {
                        out.note(info, format!("/{rel}: {err}"));
                    }
                    complete = false;
                    break;
                }
            };
            let Some(Ok(key)) = e.key() else { continue };
            if key.namespace() == NtfsFileNamespace::Dos {
                continue;
            }
            let num = e.file_reference().file_record_number();
            if num == rec || num < FIRST_USER_RECORD {
                continue;
            }
            let name = key.name().to_string_lossy();
            if !own && !key.file_attributes().contains(NtfsFileAttributeFlags::REPARSE_POINT) {
                // another helper's entries: only the subdirectories, from the index entry (no
                // MFT record read); reparse points go the full way (junctions are not entered)
                if key.is_directory() && !name.is_empty() && !name.contains('/') && seen.insert(name.clone()) {
                    let path = if rel.is_empty() {
                        name.clone()
                    } else {
                        format!("{rel}/{name}")
                    };
                    if path.len() <= MAX_PATH
                        && depth + 1 < MAX_DEPTH
                        && out.walks(&path, depth + 1)
                        && visited.insert(num)
                    {
                        stack.push((num, path, depth + 1));
                    }
                }
                continue;
            }
            // a hard link may show up once per name; the same name twice is a broken index
            if !seen.insert(name.clone()) || name.is_empty() || name.contains('/') {
                info.skipped_entries += u64::from(own);
                continue;
            }
            let path = if rel.is_empty() {
                name.clone()
            } else {
                format!("{rel}/{name}")
            };
            if path.len() > MAX_PATH {
                info.skipped_entries += u64::from(own);
                continue;
            }
            let file = match ntfs.file(&mut fs, num) {
                Ok(f) => f,
                Err(_) => {
                    info.skipped_entries += u64::from(own);
                    continue;
                }
            };
            let si: Option<NtfsStandardInformation> = file.info().ok();
            let mtime = si
                .as_ref()
                .map_or(key.modification_time(), |s| s.modification_time())
                .nt_timestamp();
            let attrs = si.as_ref().map_or(key.file_attributes(), |s| s.file_attributes());
            let is_dir = file.is_directory();
            let tag = if attrs.contains(ntfs::structured_values::NtfsFileAttributeFlags::REPARSE_POINT) {
                reparse_tag(&file, &mut fs)
            } else {
                None
            };
            let kind = match tag {
                Some(TAG_SYMLINK | TAG_MOUNT_POINT) => KIND_SYMLINK,
                _ if is_dir => KIND_DIR,
                _ => KIND_FILE,
            };
            if tag == Some(TAG_DEDUP) {
                info.dedup_files += u64::from(own);
            }
            let size = if kind == KIND_FILE && own {
                match file.data(&mut fs, "") {
                    Some(Ok(item)) => item.to_attribute().map_or(key.data_size(), |a| a.value_length()),
                    _ => 0,
                }
            } else {
                0
            };
            if depth == 1
                && kind == KIND_DIR
                && name.eq_ignore_ascii_case("System32")
                && rel.eq_ignore_ascii_case("Windows")
            {
                info.windows = true;
            }
            let owner = si
                .as_ref()
                .and_then(|s| s.security_id())
                .and_then(|id| owner_of.get(&id))
                .map(String::as_str);
            // Phase 31c: the content's SHA-256 (not of deduplicated stubs; budgeted)
            let mut sha = None;
            if kind == KIND_FILE && own && out.hashing() {
                if tag == Some(TAG_DEDUP) {
                    info.unhashed_files += 1;
                } else if !out.hash_budget(size) {
                    info.unhashed_files += 1;
                    budget_miss = true;
                } else {
                    match hash_data(&file, &mut fs, size) {
                        Ok(h) => {
                            sha = Some(h);
                            info.hashed_files += 1;
                        }
                        Err(_) => info.unhashed_files += 1,
                    }
                }
            }
            if own && !out.emit_ext(info, &path, size, nt_to_unix(mtime), kind, owner, sha.as_ref())? {
                return Ok(());
            }
            if kind == KIND_DIR {
                subdirs.push((num, name.clone()));
            }
            if kind == KIND_DIR && out.walks(&path, depth + 1) {
                if depth + 1 >= MAX_DEPTH {
                    out.note(info, format!("/{path}: nested too deeply"));
                    continue;
                }
                if visited.insert(num) {
                    stack.push((num, path, depth + 1));
                }
            }
        }
        if own && complete {
            out.dir_listed(&crate::DirRec {
                rel,
                subdirs,
                dedup: info.dedup_files - dedup0,
                skipped: info.skipped_entries - skipped0,
                hashed: out.hashing() && !budget_miss,
                ..Default::default()
            });
        }
    }
    // Phase 31c: the drive letters of the system volume (helper 0 alone; a broken or
    // missing hive leaves the letters out, the volume is still `C:`)
    if info.windows && out.owns("", 0) {
        info.drives = drives(&ntfs, &mut fs).unwrap_or_default();
    }
    Ok(())
}

/// The index record size a directory's `$INDEX_ROOT` names: the crate allocates a
/// record of it for every index block it reads, so a hostile size is refused first.
fn index_root_ok(dir: &NtfsFile, fs: &mut Padded) -> Result<(), String> {
    let mut attrs = dir.attributes();
    while let Some(item) = attrs.next(fs) {
        let item = item.map_err(|e| e.to_string())?;
        let a = item.to_attribute().map_err(|e| e.to_string())?;
        if a.ty().ok() != Some(NtfsAttributeType::IndexRoot) {
            continue;
        }
        let r = a
            .resident_structured_value::<ntfs::structured_values::NtfsIndexRoot>()
            .map_err(|e| e.to_string())?;
        let n = r.index_record_size();
        if !(512..=65536).contains(&n) || !n.is_power_of_two() {
            return Err(format!("index record size {n}"));
        }
    }
    Ok(())
}

/// SHA-256 of a file's unnamed `$DATA` (`size` bytes); compressed or encrypted data
/// (the crate would return it raw) is an error.
fn hash_data(f: &NtfsFile, fs: &mut Padded, size: u64) -> Result<[u8; 32], String> {
    use ntfs::NtfsAttributeFlags as F;
    use sha2::Digest;
    let item = f.data(fs, "").ok_or("no data")?.map_err(|e| e.to_string())?;
    let a = item.to_attribute().map_err(|e| e.to_string())?;
    if a.flags().intersects(F::COMPRESSED | F::ENCRYPTED) || a.value_length() != size {
        return Err("compressed or encrypted".into());
    }
    let mut v = a.value(fs).map_err(|e| e.to_string())?;
    let mut h = sha2::Sha256::new();
    let mut buf = vec![0u8; crate::walk::HASH_READ];
    let mut done = 0u64;
    while done < size {
        let n = v.read(fs, &mut buf).map_err(|e| e.to_string())?;
        if n == 0 {
            return Err("short read".into());
        }
        let n = (n as u64).min(size - done) as usize;
        h.update(&buf[..n]);
        done += n as u64;
    }
    Ok(h.finalize().into())
}

/// The SYSTEM hive of the volume, read in place through the file's `$DATA`.
struct HiveFile<'a, 'n, 'f> {
    v: ntfs::attribute_value::NtfsAttributeValue<'n, 'f>,
    fs: &'a mut Padded,
}

impl crate::regf::HiveRead for HiveFile<'_, '_, '_> {
    fn size(&self) -> u64 {
        self.v.len()
    }
    fn read_at(&mut self, off: u64, buf: &mut [u8]) -> Result<(), String> {
        if off.checked_add(buf.len() as u64).is_none_or(|e| e > self.v.len()) {
            return Err("hive: read beyond the end".into());
        }
        self.v
            .seek(self.fs, std::io::SeekFrom::Start(off))
            .map_err(|e| e.to_string())?;
        let mut done = 0;
        while done < buf.len() {
            let n = self.v.read(self.fs, &mut buf[done..]).map_err(|e| e.to_string())?;
            if n == 0 {
                return Err("hive: short read".into());
            }
            done += n;
        }
        Ok(())
    }
}

/// `MountedDevices` of `Windows/System32/config/SYSTEM` ([`crate::regf::drive_letters`]).
fn drives(ntfs: &Ntfs, fs: &mut Padded) -> Result<Vec<(String, String)>, String> {
    let e = |e: ntfs::NtfsError| e.to_string();
    // the index is sorted by NTFS' upcase table; for these ASCII names (and nearly all others)
    // simple uppercasing orders the same, without reading the 128 KiB $UpCase
    let up = |s: &str| s.chars().flat_map(char::to_uppercase).collect::<String>();
    let mut rec = ROOT;
    for name in ["WINDOWS", "SYSTEM32", "CONFIG", "SYSTEM"] {
        let dir = ntfs.file(fs, rec).map_err(e)?;
        index_root_ok(&dir, fs)?;
        let idx = dir.directory_index(fs).map_err(e)?;
        let mut finder = idx.finder();
        let hit = finder
            .find(fs, |k| {
                let k = k.name().to_string_lossy();
                name.encode_utf16().cmp(up(&k).encode_utf16())
            })
            .ok_or_else(|| format!("{name} not found"))?
            .map_err(e)?;
        rec = hit.file_reference().file_record_number();
    }
    let f = ntfs.file(fs, rec).map_err(e)?;
    let item = f.data(fs, "").ok_or("SYSTEM hive without data")?.map_err(e)?;
    let attr = item.to_attribute().map_err(e)?;
    let v = attr.value(fs).map_err(e)?;
    crate::regf::drive_letters(HiveFile { v, fs })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A `$SDS` entry for security id `id` at `at` whose descriptor's owner is `sid`.
    fn entry(id: u32, at: usize, sid: &[u8]) -> Vec<u8> {
        let mut sd = vec![1u8, 0, 0, 0x80];
        sd.extend(20u32.to_le_bytes()); // owner offset
        sd.extend([0u8; 12]);
        sd.extend(sid);
        let mut e = vec![0u8; 4];
        e.extend(id.to_le_bytes());
        e.extend((at as u64).to_le_bytes());
        e.extend(((20 + sd.len()) as u32).to_le_bytes());
        e.extend(sd);
        e.resize(e.len().div_ceil(16) * 16, 0);
        e
    }

    #[test]
    fn owners_from_sds() {
        // S-1-5-21-1-2-3-1001
        let mut sid = vec![1u8, 5, 0, 0, 0, 0, 0, 5];
        for x in [21u32, 1, 2, 3, 1001] {
            sid.extend(x.to_le_bytes());
        }
        assert_eq!(sid_text(&sid).as_deref(), Some("S-1-5-21-1-2-3-1001"));
        assert_eq!(sid_text(&[1, 9, 0]), None);
        let admins = [1u8, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 0x20, 2, 0, 0];
        let mut d = entry(0x100, 0, &admins);
        let n = d.len();
        d.extend(entry(0x101, n, &sid));
        // the mirror copy of the first block, then the next block
        d.resize(2 * SDS_BLOCK, 0);
        d.extend(entry(0x102, 2 * SDS_BLOCK, &sid));
        let mut m = HashMap::new();
        parse_sds(&d, &mut m);
        assert_eq!(m.len(), 3, "{m:?}");
        assert_eq!(m[&0x100], "S-1-5-32-544");
        assert_eq!(m[&0x102], "S-1-5-21-1-2-3-1001");
        // hostile: wrong self offsets, lengths beyond the block, truncation
        for i in 0..d.len().min(200) {
            for x in [0u8, 0xff, 0x7f] {
                let mut h = d.clone();
                h[i] = x;
                let mut m = HashMap::new();
                parse_sds(&h, &mut m);
                parse_sds(&h[..i], &mut m);
            }
        }
    }
}
