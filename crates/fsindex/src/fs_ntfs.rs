//! NTFS through the crate `ntfs` (read-only). Directories are walked through
//! their `$I30` indexes; size and modification time come from each file's own
//! record (`$DATA` length, `$STANDARD_INFORMATION`), not from the index copy
//! of `$FILE_NAME` (Windows updates that lazily). DOS 8.3 aliases and the NTFS
//! metadata files are left out. `$LogFile` is never replayed.

use crate::disk::{Padded, Vol};
use crate::walk::Out;
use crate::{nt_to_unix, Volume, KIND_DIR, KIND_FILE, KIND_SYMLINK, MAX_DEPTH, MAX_PATH};
use ntfs::structured_values::{NtfsFileAttributeFlags, NtfsFileNamespace, NtfsStandardInformation, NtfsVolumeFlags};
use ntfs::{Ntfs, NtfsAttributeType, NtfsFile, NtfsReadSeek};

const TAG_DEDUP: u32 = 0x8000_0013;
const TAG_SYMLINK: u32 = 0xA000_000C;
const TAG_MOUNT_POINT: u32 = 0xA000_0003;
/// records 0-15: $MFT, $MFTMirr, $LogFile, $Volume, $AttrDef, ., $Bitmap, $Boot,
/// $BadClus, $Secure, $UpCase, $Extend, reserved
const FIRST_USER_RECORD: u64 = 16;
const ROOT: u64 = 5;

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
    // MFT records (in use or free): an upper estimate of the entries
    if let Some(Ok(d)) = ntfs.file(&mut fs, 0).ok().as_ref().and_then(|m| m.data(&mut fs, "")) {
        if let Ok(a) = d.to_attribute() {
            let records = a.value_length() / u64::from(ntfs.file_record_size().max(1));
            out.expect(records.saturating_sub(FIRST_USER_RECORD));
        }
    }
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
        let idx = match dir.directory_index(&mut fs) {
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
            if own && !out.emit(info, &path, size, nt_to_unix(mtime), kind)? {
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
