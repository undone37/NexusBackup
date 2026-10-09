//! File-level downloads from tree snapshots: list one directory (same JSON as
//! `nexus-pve … ls`), write selected paths as tar or zip. Tar keeps owners,
//! modes, mtimes, symlinks, hard links, devices/fifos and xattrs (PAX
//! `SCHILY.xattr.*`, as GNU tar --xattrs); zip keeps modes and mtimes only.

use crate::restore::{request_path, select};
use anyhow::{bail, Result};
use chunkstore::{Store, TreeEntry, TreeKind};
use serde::Serialize;
use std::ffi::OsStr;
use std::fs::File;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use zip::write::SimpleFileOptions;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Format {
    Tar,
    Zip,
}

impl Format {
    pub fn from_path(p: &Path) -> Result<Self> {
        match p.extension().and_then(|e| e.to_str()) {
            Some("tar") => Ok(Format::Tar),
            Some("zip") => Ok(Format::Zip),
            _ => bail!("output must end in .tar or .zip"),
        }
    }
}

#[derive(Serialize, Debug, PartialEq)]
pub struct ListEntry {
    pub name: String,
    pub kind: &'static str,
    pub size: u64,
    pub mode: u32,
    pub mtime: i64,
    pub uid: u32,
    pub gid: u32,
    pub link: Option<String>,
}

fn kind(k: &TreeKind) -> &'static str {
    match k {
        TreeKind::File => "file",
        TreeKind::Dir => "dir",
        TreeKind::Symlink => "symlink",
        TreeKind::Hardlink => "hardlink",
        _ => "other",
    }
}

/// Entries directly inside `dir` (absolute, `/` = root).
pub fn list(entries: &[TreeEntry], dir: &str) -> Result<Vec<ListEntry>> {
    let d = request_path(dir)?;
    let mut out = Vec::new();
    for e in entries {
        let parent = match e.path.iter().rposition(|b| *b == b'/') {
            Some(i) => &e.path[..i],
            None => &[][..],
        };
        if parent != d.as_slice() {
            continue;
        }
        let name = &e.path[parent.len() + usize::from(!parent.is_empty())..];
        out.push(ListEntry {
            name: String::from_utf8_lossy(name).into_owned(),
            kind: kind(&e.kind),
            size: e.size,
            mode: e.mode & 0o7777,
            mtime: e.mtime_ns.div_euclid(1_000_000_000),
            uid: e.uid,
            gid: e.gid,
            link: e.link_target.as_ref().map(|l| String::from_utf8_lossy(l).into_owned()),
        });
    }
    Ok(out)
}

/// Unix seconds -> zip DOS time (UTC); out-of-range dates fall back to the default.
fn zip_time(unix: i64) -> zip::DateTime {
    let (days, secs) = (unix.div_euclid(86400), unix.rem_euclid(86400));
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u8;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u8;
    let y = yoe + era * 400 + i64::from(m <= 2);
    let Ok(y) = u16::try_from(y) else {
        return zip::DateTime::default();
    };
    let (h, mi, se) = ((secs / 3600) as u8, (secs / 60 % 60) as u8, (secs % 60) as u8);
    zip::DateTime::from_date_and_time(y, m, d, h, mi, se).unwrap_or_default()
}

/// Writes the selected paths (and everything below them, plus parent
/// directories) to `out`. Returns the number of entries written.
pub fn extract(store: &Store, entries: &[TreeEntry], paths: &[String], fmt: Format, out: File) -> Result<usize> {
    let sel = select(entries, paths)?;
    match fmt {
        Format::Tar => {
            let mut b = tar::Builder::new(io::BufWriter::new(out));
            for e in &sel {
                let path = Path::new(OsStr::from_bytes(&e.path));
                let mut h = tar::Header::new_gnu();
                h.set_mode(e.mode & 0o7777);
                h.set_uid(u64::from(e.uid));
                h.set_gid(u64::from(e.gid));
                h.set_mtime(e.mtime_ns.div_euclid(1_000_000_000).max(0) as u64);
                h.set_size(0);
                if !e.xattrs.is_empty() {
                    let keys: Vec<(String, &[u8])> = e
                        .xattrs
                        .iter()
                        .map(|(k, v)| (format!("SCHILY.xattr.{}", String::from_utf8_lossy(k)), v.as_slice()))
                        .collect();
                    b.append_pax_extensions(keys.iter().map(|(k, v)| (k.as_str(), *v)))?;
                }
                match e.kind {
                    TreeKind::File => {
                        h.set_entry_type(tar::EntryType::Regular);
                        h.set_size(e.size);
                        b.append_data(&mut h, path, store.chunk_reader(&e.chunks))?;
                    }
                    TreeKind::Dir => {
                        h.set_entry_type(tar::EntryType::Directory);
                        b.append_data(&mut h, path, io::empty())?;
                    }
                    TreeKind::Symlink | TreeKind::Hardlink => {
                        h.set_entry_type(if e.kind == TreeKind::Symlink {
                            tar::EntryType::Symlink
                        } else {
                            tar::EntryType::Link
                        });
                        let target = Path::new(OsStr::from_bytes(e.link_target.as_deref().unwrap_or_default()));
                        b.append_link(&mut h, path, target)?;
                    }
                    TreeKind::Device | TreeKind::Fifo => {
                        let t = if e.kind == TreeKind::Fifo {
                            tar::EntryType::Fifo
                        } else if e.mode & libc::S_IFMT == libc::S_IFBLK {
                            tar::EntryType::Block
                        } else {
                            tar::EntryType::Char
                        };
                        h.set_entry_type(t);
                        h.set_device_major(libc::major(e.rdev))?;
                        h.set_device_minor(libc::minor(e.rdev))?;
                        b.append_data(&mut h, path, io::empty())?;
                    }
                    TreeKind::Socket => continue, // not representable
                }
            }
            b.into_inner()?.into_inner().map_err(|e| e.into_error())?.sync_all()?;
        }
        Format::Zip => {
            let mut z = zip::ZipWriter::new(out);
            for e in &sel {
                let name = String::from_utf8_lossy(&e.path).into_owned();
                let opts = SimpleFileOptions::default()
                    .compression_method(zip::CompressionMethod::Deflated)
                    .unix_permissions(e.mode & 0o7777)
                    .last_modified_time(zip_time(e.mtime_ns.div_euclid(1_000_000_000)))
                    .large_file(e.size >= u32::MAX as u64);
                match e.kind {
                    TreeKind::Dir => z.add_directory(name, opts)?,
                    TreeKind::Symlink | TreeKind::Hardlink => z.add_symlink(
                        name,
                        String::from_utf8_lossy(e.link_target.as_deref().unwrap_or_default()),
                        opts,
                    )?,
                    TreeKind::File => {
                        z.start_file(name, opts)?;
                        io::copy(&mut store.chunk_reader(&e.chunks), &mut z)?;
                    }
                    _ => continue, // devices, fifos, sockets: meaningless in a download
                }
            }
            z.finish()?.sync_all()?;
        }
    }
    Ok(sel.len())
}
