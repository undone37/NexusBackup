//! File-level restore from tar streams (container snapshots, restore micro-VM):
//! list one directory, extract selected paths as tar or zip.

use anyhow::{bail, Context, Result};
use serde::Serialize;
use std::fs::File;
use std::io::{self, Read};
use std::path::{Component, Path};
use tar::EntryType;
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
pub struct Entry {
    pub name: String,
    pub kind: &'static str,
    pub size: u64,
    pub mode: u32,
    pub mtime: u64,
    pub uid: u64,
    pub gid: u64,
    pub link: Option<String>,
}

/// `./etc/passwd`, `etc/passwd/` -> `etc/passwd`; root -> "".
fn norm(p: &Path) -> String {
    let s = p.to_string_lossy();
    s.trim_start_matches("./").trim_matches('/').to_owned()
}

/// Archive-relative form of an entry name for the download: absolute names
/// become relative, `.` is dropped; `None` for names with `..` (they would
/// escape the directory the user extracts into) or NUL bytes (no file system
/// has them; extractors would truncate the name).
fn safe_rel(p: &Path) -> Option<String> {
    let mut parts = Vec::new();
    for c in p.components() {
        match c {
            Component::Normal(s) if !s.as_encoded_bytes().contains(&0) => parts.push(s.to_string_lossy()),
            Component::RootDir | Component::CurDir => {}
            Component::Normal(_) | Component::ParentDir | Component::Prefix(_) => return None,
        }
    }
    Some(parts.join("/"))
}

/// Entry names and hard-link targets of a hostile stream (compromised container
/// or restore VM) are sanitized: names with `..` are skipped, and so is anything
/// below an earlier symlink entry (it would be written through the link).
#[derive(Default)]
struct Guard {
    links: Vec<String>,
}

impl Guard {
    fn admit(&mut self, e: &tar::Entry<impl Read>) -> Result<Option<(String, Option<String>)>> {
        let Some(path) = safe_rel(&e.path()?) else {
            eprintln!("files: skipping unsafe entry {:?}", e.path()?);
            return Ok(None);
        };
        if self
            .links
            .iter()
            .any(|l| path.strip_prefix(l.as_str()).is_some_and(|r| r.starts_with('/')))
        {
            eprintln!("files: skipping {path:?} below a symlink");
            return Ok(None);
        }
        let link = match (e.header().entry_type(), e.link_name()?) {
            (EntryType::Link, Some(l)) => match safe_rel(&l) {
                Some(l) => Some(l),
                None => {
                    eprintln!("files: skipping hard link {path:?} to {l:?}");
                    return Ok(None);
                }
            },
            (_, l) => l.map(|l| l.to_string_lossy().into_owned()),
        };
        if e.header().entry_type() == EntryType::Symlink {
            self.links.push(path.clone());
        }
        Ok(Some((path, link)))
    }
}

/// Requested paths are relative to the archive root; `..` is rejected.
pub fn clean_request(p: &str) -> Result<String> {
    let p = p.trim_matches('/');
    if p.split('/').any(|c| c == "..") {
        bail!("invalid path {p:?}");
    }
    Ok(p.to_owned())
}

fn kind(t: EntryType) -> &'static str {
    match t {
        EntryType::Regular | EntryType::Continuous => "file",
        EntryType::Directory => "dir",
        EntryType::Symlink => "symlink",
        EntryType::Link => "hardlink",
        _ => "other",
    }
}

/// Entries directly inside `dir` ("" = archive root).
// ponytail: reads the whole stream per call; an entry offset index if browsing big CTs is slow.
pub fn list(r: impl Read, dir: &str) -> Result<Vec<Entry>> {
    let dir = clean_request(dir)?;
    let mut out = Vec::new();
    for e in tar::Archive::new(r).entries()? {
        let e = e?;
        let path = norm(&e.path()?);
        let parent = path.rsplit_once('/').map_or("", |(p, _)| p);
        if path.is_empty() || parent != dir {
            continue;
        }
        let h = e.header();
        out.push(Entry {
            name: path.rsplit('/').next().unwrap_or_default().to_owned(),
            kind: kind(h.entry_type()),
            size: h.size()?,
            mode: h.mode()?,
            mtime: h.mtime()?,
            uid: h.uid()?,
            gid: h.gid()?,
            link: e.link_name()?.map(|l| l.to_string_lossy().into_owned()),
        });
    }
    Ok(out)
}

/// Unix seconds -> zip DOS time (UTC; zip has no time zone). Days-to-civil after
/// H. Hinnant; out-of-range dates (before 1980) fall back to the zip default.
fn zip_time(unix: u64) -> zip::DateTime {
    let (days, secs) = ((unix / 86400) as i64, unix % 86400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u8;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u8;
    let y = (yoe + era * 400 + i64::from(m <= 2)) as u16;
    let (h, mi, se) = ((secs / 3600) as u8, (secs / 60 % 60) as u8, (secs % 60) as u8);
    zip::DateTime::from_date_and_time(y, m, d, h, mi, se).unwrap_or_default()
}

fn selected(path: &str, sel: &[String]) -> bool {
    sel.iter()
        .any(|s| s.is_empty() || path == s || path.strip_prefix(s.as_str()).is_some_and(|r| r.starts_with('/')))
}

/// Copies the selected paths (and everything below them) into `out`.
/// Returns the number of entries written. Zip keeps permissions but not owners,
/// mtimes or xattrs; tar keeps owners/modes/mtimes (no xattrs/ACLs).
pub fn extract(r: impl Read, paths: &[String], fmt: Format, out: File) -> Result<usize> {
    let sel: Vec<String> = paths.iter().map(|p| clean_request(p)).collect::<Result<_>>()?;
    let mut n = 0;
    let mut archive = tar::Archive::new(r);
    match fmt {
        Format::Tar => {
            let mut b = tar::Builder::new(out);
            let mut guard = Guard::default();
            for e in archive.entries()? {
                let mut e = e?;
                let Some((path, link)) = guard.admit(&e)? else { continue };
                if path.is_empty() || !selected(&path, &sel) {
                    continue;
                }
                let mut h = e.header().clone();
                match link {
                    Some(link) => b.append_link(&mut h, &path, link)?,
                    None => b.append_data(&mut h, &path, &mut e)?,
                }
                n += 1;
            }
            b.into_inner()?.sync_all()?;
        }
        Format::Zip => {
            let mut z = zip::ZipWriter::new(out);
            let mut guard = Guard::default();
            for e in archive.entries()? {
                let mut e = e?;
                let Some((path, link)) = guard.admit(&e)? else { continue };
                if path.is_empty() || !selected(&path, &sel) {
                    continue;
                }
                let h = e.header();
                let size = h.size()?;
                let opts = SimpleFileOptions::default()
                    .compression_method(zip::CompressionMethod::Deflated)
                    .unix_permissions(h.mode()? & 0o7777)
                    .last_modified_time(zip_time(h.mtime()?))
                    .large_file(size >= u32::MAX as u64);
                match h.entry_type() {
                    EntryType::Directory => z.add_directory(path, opts)?,
                    EntryType::Symlink | EntryType::Link => {
                        z.add_symlink(path, link.context("link without target")?, opts)?
                    }
                    EntryType::Regular | EntryType::Continuous => {
                        z.start_file(path, opts)?;
                        io::copy(&mut e, &mut z)?;
                    }
                    _ => continue, // devices, fifos: meaningless in a download
                }
                n += 1;
            }
            z.finish()?.sync_all()?;
        }
    }
    if n == 0 {
        bail!("no matching paths in archive");
    }
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Seek;

    fn sample() -> Vec<u8> {
        let mut b = tar::Builder::new(Vec::new());
        let mut add = |path: &str, t: EntryType, data: &[u8], link: Option<&str>| {
            let mut h = tar::Header::new_gnu();
            h.set_entry_type(t);
            h.set_mode(if t == EntryType::Directory { 0o755 } else { 0o640 });
            h.set_uid(1000);
            h.set_gid(1000);
            h.set_mtime(1_760_000_000);
            h.set_size(data.len() as u64);
            match link {
                Some(l) => b.append_link(&mut h, path, l).unwrap(),
                None => b.append_data(&mut h, path, data).unwrap(),
            }
        };
        add("./", EntryType::Directory, b"", None);
        add("./etc/", EntryType::Directory, b"", None);
        add("./etc/hostname", EntryType::Regular, b"ct200\n", None);
        add(
            "./etc/localtime",
            EntryType::Symlink,
            b"",
            Some("/usr/share/zoneinfo/UTC"),
        );
        add("./etcetera", EntryType::Regular, b"not etc", None);
        add(
            "./home/u/über langer name.txt",
            EntryType::Regular,
            &vec![7u8; 300_000],
            None,
        );
        b.into_inner().unwrap()
    }

    #[test]
    fn lists_one_level() {
        let names: Vec<_> = list(&sample()[..], "/")
            .unwrap()
            .into_iter()
            .map(|e| (e.name, e.kind))
            .collect();
        assert_eq!(names, [("etc".into(), "dir"), ("etcetera".to_string(), "file")]);
        let etc = list(&sample()[..], "etc").unwrap();
        assert_eq!(etc[1].link.as_deref(), Some("/usr/share/zoneinfo/UTC"));
        assert_eq!((etc[0].size, etc[0].uid), (6, 1000));
        assert!(list(&sample()[..], "../x").is_err());
    }

    /// Raw tar entry; the name bytes bypass the tar crate's own path checks.
    fn raw(b: &mut tar::Builder<Vec<u8>>, name: &str, t: EntryType, data: &[u8], link: Option<&str>) {
        let mut h = tar::Header::new_gnu();
        h.as_old_mut().name[..name.len()].copy_from_slice(name.as_bytes());
        if let Some(l) = link {
            h.as_old_mut().linkname[..l.len()].copy_from_slice(l.as_bytes());
        }
        h.set_entry_type(t);
        h.set_mode(0o644);
        h.set_size(data.len() as u64);
        h.set_cksum();
        b.append(&h, data).unwrap();
    }

    /// Regression (fuzzing, tar_files): a hostile stream (compromised CT or
    /// restore VM) put `../` names and write-through-symlink entries into the
    /// user's download (zip slip on the machine that extracts it).
    #[test]
    fn hostile_names_are_dropped() {
        let mut b = tar::Builder::new(Vec::new());
        raw(&mut b, "../../etc/cron.d/evil", EntryType::Regular, b"x", None);
        raw(&mut b, "a/../../b", EntryType::Regular, b"x", None);
        raw(&mut b, "/abs/ok", EntryType::Regular, b"abs", None);
        raw(&mut b, "lnk", EntryType::Symlink, b"", Some("/etc"));
        raw(&mut b, "lnk/passwd", EntryType::Regular, b"pw", None);
        raw(&mut b, "hl", EntryType::Link, b"", Some("../../etc/shadow"));
        // GNU long name with NUL bytes inside (fuzzing found it in a zip name)
        raw(&mut b, "././@LongLink", EntryType::GNULongName, b"a\0b/c\0", None);
        raw(&mut b, "short", EntryType::Regular, b"x", None);
        raw(&mut b, "keep/me", EntryType::Regular, b"ok", None);
        let tar = b.into_inner().unwrap();
        let d = tempfile::tempdir().unwrap();
        for fmt in [Format::Tar, Format::Zip] {
            let p = d.path().join("o");
            let n = extract(&tar[..], &[String::new()], fmt, File::create(&p).unwrap()).unwrap();
            assert_eq!(n, 3, "abs/ok, lnk, keep/me");
            let names: Vec<String> = match fmt {
                Format::Tar => tar::Archive::new(File::open(&p).unwrap())
                    .entries()
                    .unwrap()
                    .map(|e| e.unwrap().path().unwrap().to_string_lossy().into_owned())
                    .collect(),
                Format::Zip => {
                    let z = zip::ZipArchive::new(File::open(&p).unwrap()).unwrap();
                    z.file_names().map(str::to_owned).collect()
                }
            };
            let mut names = names;
            names.sort();
            assert_eq!(names, ["abs/ok", "keep/me", "lnk"]);
        }
    }

    #[test]
    fn extracts_tar_and_zip() {
        let d = tempfile::tempdir().unwrap();
        let t = d.path().join("o.tar");
        let n = extract(&sample()[..], &["etc".into()], Format::Tar, File::create(&t).unwrap()).unwrap();
        assert_eq!(n, 3, "etc, hostname, localtime; not etcetera");
        let back: Vec<_> = list(File::open(&t).unwrap(), "etc")
            .unwrap()
            .into_iter()
            .map(|e| e.name)
            .collect();
        assert_eq!(back, ["hostname", "localtime"]);

        let z = d.path().join("o.zip");
        extract(
            &sample()[..],
            &["home".into(), "/etc/hostname".into()],
            Format::Zip,
            File::create(&z).unwrap(),
        )
        .unwrap();
        let mut f = File::open(&z).unwrap();
        f.rewind().unwrap();
        let mut zr = zip::ZipArchive::new(f).unwrap();
        let mut s = String::new();
        zr.by_name("etc/hostname").unwrap().read_to_string(&mut s).unwrap();
        assert_eq!(s, "ct200\n");
        assert_eq!(zr.by_name("home/u/über langer name.txt").unwrap().size(), 300_000);
        assert_eq!(
            zr.by_name("etc/hostname").unwrap().unix_mode().map(|m| m & 0o777),
            Some(0o640)
        );
        let lm = zr.by_name("etc/hostname").unwrap().last_modified().unwrap();
        assert_eq!(
            (lm.year(), lm.month(), lm.day(), lm.hour(), lm.minute()),
            (2025, 10, 9, 8, 53)
        ); // 1760000000
        assert!(extract(&sample()[..], &["nope".into()], Format::Tar, File::create(&t).unwrap()).is_err());
    }
}
