//! Restore on Windows: `agent_core::restore::RestoreFs` with confinement per
//! `crate::confine` (component walk, `FILE_FLAG_OPEN_REPARSE_POINT`, held handles
//! without `FILE_SHARE_DELETE`, final-path check of everything written).
//!
//! Files are written to `.nexus-restore.<pid>.<n>` next to the destination, get their
//! attributes, times and (policy permitting) security descriptor, and are renamed
//! over the destination by handle (a symlink/junction at the destination is replaced,
//! never followed). Alternate data streams are written into the restored (or kept)
//! base file after it is in place; the base's times are re-applied afterwards.

use super::sys::{self, Handle};
use crate::confine::{self, Namespace, Node};
use crate::meta::{self, Reparse, SdInfo};
use crate::paths::{self, wtf8_to_utf16};
use agent_core::restore::{invalid, Existing, RestoreFs, Stream};
use agent_proto::{Entry, Kind, Overwrite};
use std::collections::HashMap;
use std::ffi::OsString;
use std::fs::File;
use std::io;
use std::os::windows::ffi::OsStringExt;
use std::os::windows::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

const FILE_ATTRIBUTE_READONLY: u32 = meta::FILE_ATTRIBUTE_READONLY;

fn os(name: &[u8]) -> io::Result<OsString> {
    wtf8_to_utf16(name)
        .map(|w| OsString::from_wide(&w))
        .ok_or_else(|| invalid("name is not valid WTF-8"))
}

/// A held directory: its path and the open handle that pins it.
pub struct Held {
    pub path: PathBuf,
    _h: Option<Handle>,
}

struct Ns<'a> {
    root: &'a Path,
}

impl Namespace for Ns<'_> {
    type Handle = Held;

    fn root(&mut self) -> io::Result<Held> {
        let h = sys::open(
            self.root,
            sys::FILE_READ_ATTRIBUTES,
            sys::SHARE_NO_DELETE,
            sys::OPEN_EXISTING,
            sys::FLAG_BACKUP | sys::FLAG_OPEN_REPARSE,
        )?;
        Ok(Held {
            path: self.root.to_path_buf(),
            _h: Some(h),
        })
    }

    fn open(&mut self, parent: &Held, name: &[u8]) -> io::Result<Option<(Held, Node)>> {
        let p = parent.path.join(os(name)?);
        let h = match sys::open(
            &p,
            sys::FILE_READ_ATTRIBUTES,
            sys::SHARE_NO_DELETE,
            sys::OPEN_EXISTING,
            sys::FLAG_BACKUP | sys::FLAG_OPEN_REPARSE,
        ) {
            Ok(h) => h,
            Err(e) if sys::is_not_found(&e) => return Ok(None),
            Err(e) => return Err(e),
        };
        let t = sys::tag_info(&h)?;
        let node = if t.FileAttributes & meta::FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            Node::Reparse
        } else if t.FileAttributes & meta::FILE_ATTRIBUTE_DIRECTORY != 0 {
            Node::Dir
        } else {
            Node::File
        };
        Ok(Some((Held { path: p, _h: Some(h) }, node)))
    }

    fn mkdir(&mut self, parent: &Held, name: &[u8]) -> io::Result<()> {
        sys::create_dir(&parent.path.join(os(name)?))
    }
}

pub struct Tmp {
    dir: Vec<Vec<u8>>,
    tmp: OsString,
    name: OsString,
    stream: Option<OsString>,
}

pub struct WinFs {
    /// verbatim target (`\\?\D:\restore`)
    root: PathBuf,
    root_final: String,
    overwrite: Overwrite,
    seq: u64,
    sacl_ok: bool,
    /// base files restored in this run: path → (created, written, attrs)
    bases: HashMap<Vec<u8>, (i64, i64, u32)>,
}

pub type Restore = Stream<WinFs>;

/// Validate and open the target. A drive root needs `Overwrite::Always`.
pub fn begin(job: u64, target: &str, overwrite: Overwrite, confirm: &str, sacl_ok: bool) -> io::Result<Restore> {
    let t = paths::WinPath::parse(target).map_err(invalid)?;
    if confirm.trim().is_empty() {
        return Err(invalid("restore needs the confirmation token from the UI"));
    }
    eprintln!(
        "nexus-agent: restore job {job} to {} (overwrite {overwrite:?}) confirmed with token {:?}",
        t.win32(),
        confirm.trim()
    );
    if t.comps.is_empty() && overwrite != Overwrite::Always {
        return Err(invalid("restore onto a drive root requires overwrite = Always"));
    }
    std::fs::create_dir_all(t.verbatim())?;
    let h = sys::open(
        Path::new(&t.verbatim()),
        sys::FILE_READ_ATTRIBUTES,
        sys::SHARE_ALL,
        sys::OPEN_EXISTING,
        sys::FLAG_BACKUP,
    )?;
    let root_final = sys::final_path(&h)?;
    let fin = paths::WinPath::parse(root_final.trim_start_matches(r"\\?\")).map_err(invalid)?;
    if fin.comps.is_empty() && overwrite != Overwrite::Always {
        return Err(invalid("target resolves to a drive root; requires overwrite = Always"));
    }
    Ok(Stream::new(
        WinFs {
            root: PathBuf::from(fin.verbatim()),
            root_final,
            overwrite,
            seq: 0,
            sacl_ok,
            bases: HashMap::new(),
        },
        overwrite,
    ))
}

fn split(path: &[u8]) -> (Vec<Vec<u8>>, Vec<u8>, Option<Vec<u8>>) {
    let mut comps: Vec<Vec<u8>> = path.split(|b| *b == b'/').map(<[u8]>::to_vec).collect();
    let last = comps.pop().unwrap_or_default();
    match last.iter().position(|b| *b == b':') {
        Some(i) => (comps, last[..i].to_vec(), Some(last[i + 1..].to_vec())),
        None => (comps, last, None),
    }
}

impl WinFs {
    fn dirs(&self, comps: &[Vec<u8>], create: bool) -> io::Result<Vec<Held>> {
        let refs: Vec<&[u8]> = comps.iter().map(Vec::as_slice).collect();
        confine::open_dirs(&mut Ns { root: &self.root }, &refs, create)
    }

    fn tmp_name(&mut self) -> OsString {
        self.seq += 1;
        OsString::from(format!(".nexus-restore.{}.{}", std::process::id(), self.seq))
    }

    fn check_beneath(&self, h: &Handle) -> io::Result<()> {
        let f = sys::final_path(h)?;
        if paths::is_beneath(&f, &self.root_final) {
            Ok(())
        } else {
            Err(invalid(format!("{f} is outside the restore target")))
        }
    }

    /// Open an existing object (not following it) below the held directory.
    fn open_in(&self, dir: &Held, name: &OsString, access: u32) -> io::Result<Handle> {
        let h = sys::open(
            &dir.path.join(name),
            access,
            sys::SHARE_ALL,
            sys::OPEN_EXISTING,
            sys::FLAG_BACKUP | sys::FLAG_OPEN_REPARSE,
        )?;
        self.check_beneath(&h)?;
        Ok(h)
    }

    /// Security descriptor, attributes, times on an open object.
    fn apply_meta(&self, h: &Handle, e: &Entry, with_sd: bool, warn: &mut Vec<String>) -> io::Result<()> {
        if with_sd {
            if let Some(sd) = meta::xattr(&e.xattrs, meta::X_SD) {
                match SdInfo::parse(sd) {
                    Ok(info) => {
                        if let Err(x) = sys::set_security(h, info.apply_flags(self.sacl_ok), sd) {
                            // retry without owner/SACL (e.g. foreign SIDs or missing privilege)
                            let f = info.apply_flags(false)
                                & !(meta::OWNER_SECURITY_INFORMATION | meta::GROUP_SECURITY_INFORMATION);
                            match sys::set_security(h, f, sd) {
                                Ok(()) => warn.push(format!("security descriptor applied without owner/SACL: {x}")),
                                Err(y) => warn.push(format!("security descriptor: {y}")),
                            }
                        }
                    }
                    Err(x) => warn.push(x),
                }
            }
        }
        let attrs = meta::attrs_of(&e.xattrs).unwrap_or(meta::FILE_ATTRIBUTE_ARCHIVE) & meta::RESTORABLE_ATTRS;
        let created = meta::created_of(&e.xattrs).unwrap_or(0);
        let written = meta::unix_ns_to_filetime(e.mtime_ns);
        // FILE_ATTRIBUTE_NORMAL if nothing else is set (0 = "leave unchanged")
        let attrs = if attrs == 0 { meta::FILE_ATTRIBUTE_NORMAL } else { attrs };
        sys::set_basic(h, created, written, attrs)
    }

    fn write_stream(&mut self, t: &Tmp, e: &Entry) -> io::Result<()> {
        let held = self.dirs(&t.dir, false)?;
        let dir = held.last().expect("root");
        let base_key = e.path[..e.path.iter().rposition(|b| *b == b':').unwrap_or(e.path.len())].to_vec();
        let base = dir.path.join(&t.name);
        let bh = self.open_in(dir, &t.name, sys::FILE_READ_ATTRIBUTES | sys::FILE_WRITE_ATTRIBUTES)?;
        let tag = sys::tag_info(&bh)?;
        if tag.FileAttributes & meta::FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(invalid("base of the stream is a reparse point"));
        }
        let b = sys::basic_info(&bh)?;
        if b.FileAttributes & FILE_ATTRIBUTE_READONLY != 0 {
            sys::set_basic(&bh, 0, 0, b.FileAttributes & !FILE_ATTRIBUTE_READONLY)?;
        }
        let mut sp = base.into_os_string();
        sp.push(":");
        sp.push(t.stream.as_ref().expect("stream"));
        let r = (|| {
            let mut src = File::open(dir.path.join(&t.tmp))?;
            let mut dst = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .custom_flags(sys::FLAG_BACKUP | sys::FLAG_OPEN_REPARSE)
                .open(&sp)?;
            io::copy(&mut src, &mut dst).map(drop)
        })();
        // writing a stream touches the base file's times: put them back
        let (created, written, attrs) =
            self.bases
                .get(&base_key)
                .copied()
                .unwrap_or((b.CreationTime, b.LastWriteTime, b.FileAttributes));
        let _ = sys::set_basic(&bh, created, written, attrs);
        let _ = std::fs::remove_file(dir.path.join(&t.tmp));
        r
    }
}

impl RestoreFs for WinFs {
    type Tmp = Tmp;
    type Writer = File;

    fn target_display(&self) -> String {
        self.root.display().to_string()
    }

    fn check_entry(&self, e: &Entry) -> io::Result<()> {
        paths::check_entry_path(&e.path, meta::is_ads(&e.xattrs)).map_err(invalid)?;
        if e.kind == Kind::Hardlink {
            paths::check_entry_path(e.link_target.as_deref().unwrap_or_default(), false).map_err(invalid)?;
        }
        if meta::is_ads(&e.xattrs) && e.kind != Kind::File {
            return Err(invalid("alternate data stream entry that is not a file"));
        }
        Ok(())
    }

    fn existing(&mut self, path: &[u8]) -> io::Result<Existing> {
        let (dir, name, stream) = split(path);
        let held = self.dirs(&dir, true)?;
        let d = held.last().expect("root");
        if stream.is_some() {
            let base_key = path[..path.iter().rposition(|b| *b == b':').unwrap_or(path.len())].to_vec();
            if self.bases.contains_key(&base_key) {
                return Ok(Existing::Missing); // its file was just restored
            }
        }
        let name = os(&name)?;
        match sys::open(
            &d.path.join(&name),
            sys::FILE_READ_ATTRIBUTES,
            sys::SHARE_ALL,
            sys::OPEN_EXISTING,
            sys::FLAG_BACKUP | sys::FLAG_OPEN_REPARSE,
        ) {
            Err(e) if sys::is_not_found(&e) => Ok(Existing::Missing),
            Err(e) => Err(e),
            Ok(h) => {
                let b = sys::basic_info(&h)?;
                Ok(
                    if b.FileAttributes & meta::FILE_ATTRIBUTE_DIRECTORY != 0
                        && b.FileAttributes & meta::FILE_ATTRIBUTE_REPARSE_POINT == 0
                    {
                        Existing::Dir
                    } else {
                        Existing::Other {
                            mtime_ns: meta::filetime_to_unix_ns(b.LastWriteTime),
                        }
                    },
                )
            }
        }
    }

    fn make_dir(&mut self, e: &Entry, existing: Existing) -> io::Result<()> {
        let (dir, name, _) = split(&e.path);
        let held = self.dirs(&dir, true)?;
        let d = held.last().expect("root");
        let name = os(&name)?;
        match existing {
            Existing::Dir => Ok(()),
            Existing::Other { .. } => {
                let h = self.open_in(d, &name, sys::DELETE)?;
                sys::delete_by_handle(&h)?;
                drop(h);
                sys::create_dir(&d.path.join(&name))
            }
            Existing::Missing => sys::create_dir(&d.path.join(&name)),
        }
    }

    fn create_file(&mut self, e: &Entry) -> io::Result<Tmp> {
        let (dir, name, stream) = split(&e.path);
        let held = self.dirs(&dir, true)?;
        let tmp = self.tmp_name();
        let p = held.last().expect("root").path.join(&tmp);
        let f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .custom_flags(sys::FLAG_BACKUP)
            .open(&p)?;
        f.set_len(e.size)?;
        Ok(Tmp {
            dir,
            tmp,
            name: os(&name)?,
            stream: stream.map(|s| os(&s)).transpose()?,
        })
    }

    fn open_tmp(&mut self, t: &Tmp) -> io::Result<File> {
        let held = self.dirs(&t.dir, false)?;
        std::fs::OpenOptions::new()
            .write(true)
            .custom_flags(sys::FLAG_BACKUP | sys::FLAG_OPEN_REPARSE)
            .open(held.last().expect("root").path.join(&t.tmp))
    }

    fn write_at(&mut self, w: &File, off: u64, data: &[u8]) -> io::Result<()> {
        agent_core::chunk::write_all_at(w, data, off)
    }

    fn commit_file(&mut self, t: Tmp, e: &Entry, warn: &mut Vec<String>) -> io::Result<()> {
        if t.stream.is_some() {
            return self.write_stream(&t, e);
        }
        let held = self.dirs(&t.dir, false)?;
        let d = held.last().expect("root");
        let access = sys::FILE_READ_ATTRIBUTES
            | sys::FILE_WRITE_ATTRIBUTES
            | sys::DELETE
            | sys::WRITE_DAC
            | sys::WRITE_OWNER
            | if self.sacl_ok { sys::ACCESS_SYSTEM_SECURITY } else { 0 };
        let h = self.open_in(d, &t.tmp, access)?;
        let r = (|| {
            self.apply_meta(&h, e, true, warn)?;
            sys::rename_replace(&h, &d.path.join(&t.name))?;
            self.check_beneath(&h)
        })();
        if r.is_err() {
            let _ = sys::delete_by_handle(&h);
        } else {
            let attrs = meta::attrs_of(&e.xattrs).unwrap_or(0) & meta::RESTORABLE_ATTRS;
            self.bases.insert(
                e.path.clone(),
                (
                    meta::created_of(&e.xattrs).unwrap_or(0),
                    meta::unix_ns_to_filetime(e.mtime_ns),
                    if attrs == 0 { meta::FILE_ATTRIBUTE_NORMAL } else { attrs },
                ),
            );
        }
        r
    }

    fn discard(&mut self, t: Tmp) {
        if let Ok(held) = self.dirs(&t.dir, false) {
            let _ = std::fs::remove_file(held.last().expect("root").path.join(&t.tmp));
        }
    }

    fn create_other(&mut self, e: &Entry, warn: &mut Vec<String>) -> io::Result<()> {
        if e.kind != Kind::Symlink {
            return Err(invalid(format!("{:?} entries cannot be restored on Windows", e.kind)));
        }
        let reparse = match meta::xattr(&e.xattrs, meta::X_REPARSE) {
            Some(raw) => {
                Reparse::parse(raw).map_err(invalid)?; // validated, then used as stored
                raw.to_vec()
            }
            None => Reparse::symlink_for(e.link_target.as_deref().unwrap_or_default())
                .ok_or_else(|| invalid("symlink without target"))?
                .build(),
        };
        let is_dir = meta::attrs_of(&e.xattrs).is_some_and(|a| a & meta::FILE_ATTRIBUTE_DIRECTORY != 0)
            || reparse[..4] == meta::IO_REPARSE_TAG_MOUNT_POINT.to_le_bytes();
        let (dir, name, _) = split(&e.path);
        let held = self.dirs(&dir, true)?;
        let d = held.last().expect("root");
        let tmp = self.tmp_name();
        let tp = d.path.join(&tmp);
        if is_dir {
            sys::create_dir(&tp)?;
        } else {
            drop(std::fs::OpenOptions::new().write(true).create_new(true).open(&tp)?);
        }
        let access = sys::GENERIC_WRITE
            | sys::FILE_READ_ATTRIBUTES
            | sys::FILE_WRITE_ATTRIBUTES
            | sys::DELETE
            | sys::WRITE_DAC
            | sys::WRITE_OWNER;
        let h = self.open_in(d, &tmp, access)?;
        let r = (|| {
            sys::set_reparse(&h, &reparse)?;
            self.apply_meta(&h, e, true, warn)?;
            sys::rename_replace(&h, &d.path.join(os(&name)?))
        })();
        if r.is_err() {
            let _ = sys::delete_by_handle(&h);
        }
        r
    }

    fn hardlink(&mut self, e: &Entry) -> io::Result<()> {
        let (tdir, tname, _) = split(e.link_target.as_deref().unwrap_or_default());
        let theld = self.dirs(&tdir, false)?;
        let target = theld.last().expect("root").path.join(os(&tname)?);
        let th = sys::open(
            &target,
            sys::FILE_READ_ATTRIBUTES,
            sys::SHARE_ALL,
            sys::OPEN_EXISTING,
            sys::FLAG_BACKUP | sys::FLAG_OPEN_REPARSE,
        )?;
        self.check_beneath(&th)?;
        if sys::tag_info(&th)?.FileAttributes & (meta::FILE_ATTRIBUTE_REPARSE_POINT | meta::FILE_ATTRIBUTE_DIRECTORY)
            != 0
        {
            return Err(invalid("hard link target is not a regular file"));
        }
        let (dir, name, _) = split(&e.path);
        let held = self.dirs(&dir, true)?;
        let d = held.last().expect("root");
        let tmp = self.tmp_name();
        sys::hard_link(&d.path.join(&tmp), &target)?;
        let h = self.open_in(d, &tmp, sys::FILE_READ_ATTRIBUTES | sys::DELETE)?;
        sys::rename_replace(&h, &d.path.join(os(&name)?)).inspect_err(|_| {
            let _ = sys::delete_by_handle(&h);
        })
    }

    fn dir_metadata(&mut self, e: &Entry, existed: bool, warn: &mut Vec<String>) -> io::Result<()> {
        let (dir, name, _) = split(&e.path);
        let held = self.dirs(&dir, false)?;
        let d = held.last().expect("root");
        let access = sys::FILE_READ_ATTRIBUTES
            | sys::FILE_WRITE_ATTRIBUTES
            | sys::WRITE_DAC
            | sys::WRITE_OWNER
            | if self.sacl_ok { sys::ACCESS_SYSTEM_SECURITY } else { 0 };
        let h = self.open_in(d, &os(&name)?, access)?;
        if sys::tag_info(&h)?.FileAttributes & meta::FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(invalid("directory was replaced by a reparse point"));
        }
        // the security of a directory that was already there changes only with Always
        let with_sd = !existed || self.overwrite == Overwrite::Always;
        self.apply_meta(&h, e, with_sd, warn)
    }

    fn finish(&mut self) {}
}
