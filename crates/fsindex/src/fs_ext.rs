//! ext2/3/4 through the crate `ext4-view` (read-only; a jbd2 journal is
//! applied in memory by the crate, nothing is written).

use crate::disk::{le32, Vol};
use crate::walk::Out;
use crate::{Volume, KIND_DIR, KIND_FILE, KIND_OTHER, KIND_SYMLINK, MAX_DEPTH, MAX_PATH};
use ext4_view::{Ext4, PathBuf};

pub fn walk(v: &Vol, out: &mut Out, info: &mut Volume) -> Result<(), String> {
    // needs_recovery (incompat 0x4): mounted when the snapshot was taken
    let sb = v.read_vec(1024, 1024).map_err(|e| e.to_string())?;
    info.dirty = le32(&sb, 0x60) & 0x4 != 0;
    // used inodes (s_inodes_count - s_free_inodes_count) less the reserved ones below
    // s_first_ino: about one entry each
    let used = le32(&sb, 0).saturating_sub(le32(&sb, 0x10));
    out.expect(u64::from(used.saturating_sub(le32(&sb, 0x54).saturating_sub(1))));
    let fs = Ext4::load(Box::new(v.clone())).map_err(|e| format!("ext4: {e}"))?;
    info.label = fs.label().to_str().ok().filter(|s| !s.is_empty()).map(str::to_owned);
    info.uuid = Some(fs.uuid().to_string().to_lowercase());
    if let Ok(t) = fs.read("/etc/fstab") {
        if t.len() <= 64 << 10 {
            info.fstab = Some(String::from_utf8_lossy(&t).into_owned());
        }
    }
    let mut stack: Vec<(PathBuf, String, usize)> = vec![(PathBuf::new("/"), String::new(), 0)];
    while let Some((dir, rel, depth)) = stack.pop() {
        if !out.walks(&rel, depth) {
            continue; // another helper's share
        }
        // emits this directory's entries (else only looks for its subdirectories)
        let own = out.owns(&rel, depth);
        let rd = match fs.read_dir(&dir) {
            Ok(r) => r,
            Err(e) => {
                if own {
                    out.note(info, format!("/{rel}: {e}"));
                }
                continue;
            }
        };
        for e in rd {
            let e = match e {
                Ok(e) => e,
                Err(err) => {
                    if own {
                        out.note(info, format!("/{rel}: {err}"));
                    }
                    break;
                }
            };
            let name = e.file_name();
            let name_b: &[u8] = name.as_ref();
            if name_b == b"." || name_b == b".." {
                continue;
            }
            let name = String::from_utf8_lossy(name_b);
            let path = if rel.is_empty() {
                name.into_owned()
            } else {
                format!("{rel}/{name}")
            };
            if !own {
                // another helper's entries: only the subdirectories (type from the directory entry)
                if e.file_type().is_ok_and(|t| t.is_dir())
                    && path.len() <= MAX_PATH
                    && depth + 1 < MAX_DEPTH
                    && out.walks(&path, depth + 1)
                {
                    stack.push((e.path(), path, depth + 1));
                }
                continue;
            }
            if path.len() > MAX_PATH {
                info.skipped_entries += u64::from(own);
                continue;
            }
            let (kind, size, mtime) = match e.metadata() {
                Ok(m) => {
                    let ft = m.file_type();
                    let k = if ft.is_dir() {
                        KIND_DIR
                    } else if ft.is_symlink() {
                        KIND_SYMLINK
                    } else if ft.is_regular_file() {
                        KIND_FILE
                    } else {
                        KIND_OTHER
                    };
                    (k, if k == KIND_FILE { m.len() } else { 0 }, m.modified().seconds())
                }
                Err(_) => {
                    info.skipped_entries += u64::from(own);
                    continue;
                }
            };
            if own && !out.emit(info, &path, size, mtime, kind)? {
                return Ok(());
            }
            if kind == KIND_DIR && out.walks(&path, depth + 1) {
                if depth + 1 >= MAX_DEPTH {
                    out.note(info, format!("/{path}: nested too deeply"));
                    continue;
                }
                stack.push((e.path(), path, depth + 1));
            }
        }
    }
    Ok(())
}
