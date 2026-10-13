//! FAT12/16/32 with long names through the crate `fatfs`. The device it gets
//! refuses every write ([`Vol`]'s `Write`), so nothing is ever changed.

use crate::disk::Vol;
use crate::walk::Out;
use crate::{Volume, KIND_DIR, KIND_FILE, MAX_DEPTH, MAX_PATH};

/// Days since 1970-01-01 of a proleptic Gregorian date (H. Hinnant's algorithm).
pub fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// FAT time stamps are local time without a zone; taken as UTC.
fn unix(dt: fatfs::DateTime) -> i64 {
    days_from_civil(dt.date.year as i64, dt.date.month as i64, dt.date.day as i64) * 86400
        + dt.time.hour as i64 * 3600
        + dt.time.min as i64 * 60
        + dt.time.sec as i64
}

pub fn walk(v: &Vol, out: &mut Out, info: &mut Volume) -> Result<(), String> {
    let fs = fatfs::FileSystem::new(v.clone(), fatfs::FsOptions::new()).map_err(|e| format!("fat: {e}"))?;
    let id = fs.volume_id();
    info.uuid = Some(format!("{:04X}-{:04X}", id >> 16, id & 0xffff));
    let label = fs.volume_label().trim().to_owned();
    info.label = Some(label).filter(|l| !l.is_empty() && l != "NO NAME");
    info.dirty = fs.read_status_flags().is_ok_and(|f| f.dirty());
    let mut stack = vec![(fs.root_dir(), String::new(), 0usize)];
    while let Some((dir, rel, depth)) = stack.pop() {
        for e in dir.iter() {
            let e = match e {
                Ok(e) => e,
                Err(err) => {
                    out.note(info, format!("/{rel}: {err}"));
                    break;
                }
            };
            let name = e.file_name();
            if name == "." || name == ".." || name.is_empty() || name.contains('/') {
                continue;
            }
            let path = if rel.is_empty() { name } else { format!("{rel}/{name}") };
            if path.len() > MAX_PATH {
                info.skipped_entries += 1;
                continue;
            }
            let kind = if e.is_dir() { KIND_DIR } else { KIND_FILE };
            let size = if kind == KIND_FILE { e.len() } else { 0 };
            if !out.emit(info, &path, size, unix(e.modified()), kind)? {
                return Ok(());
            }
            if kind == KIND_DIR {
                if depth + 1 >= MAX_DEPTH {
                    out.note(info, format!("/{path}: nested too deeply"));
                    continue;
                }
                stack.push((e.to_dir(), path, depth + 1));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn civil() {
        assert_eq!(super::days_from_civil(1970, 1, 1), 0);
        assert_eq!(super::days_from_civil(2000, 3, 1), 11017);
        assert_eq!(super::days_from_civil(1980, 1, 1), 3652);
    }
}
