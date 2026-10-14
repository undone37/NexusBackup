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
    Ok(())
}
