//! `scan::Source` over Win32: reads a VSS shadow copy (or the live volume in fallback
//! mode) with backup semantics, never following reparse points.

use super::sys::{self, Handle};
use crate::meta;
use crate::scan::{Facts, Source};
use std::ffi::OsString;
use std::io;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};

pub struct WinSource {
    /// SeSecurityPrivilege is held: read SACLs too
    pub sacl: bool,
}

impl WinSource {
    fn open_meta(&self, p: &Path) -> io::Result<Handle> {
        if self.sacl {
            if let Ok(h) = sys::open_meta(p, sys::ACCESS_SYSTEM_SECURITY) {
                return Ok(h);
            }
        }
        sys::open_meta(p, 0)
    }
}

impl Source for WinSource {
    fn stat(&mut self, p: &Path) -> io::Result<Facts> {
        let h = self.open_meta(p)?;
        let basic = sys::basic_info(&h)?;
        let std_info = sys::standard_info(&h)?;
        let (volume, file_id) = sys::file_id(&h)?;
        let attrs = basic.FileAttributes;
        let tag = if attrs & meta::FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            sys::tag_info(&h)?.ReparseTag
        } else {
            0
        };
        let link = meta::is_link_tag(tag) && attrs & meta::FILE_ATTRIBUTE_REPARSE_POINT != 0;
        let reparse = if link { Some(sys::get_reparse(&h)?) } else { None };
        let mut flags =
            meta::OWNER_SECURITY_INFORMATION | meta::GROUP_SECURITY_INFORMATION | meta::DACL_SECURITY_INFORMATION;
        if self.sacl {
            flags |= meta::SACL_SECURITY_INFORMATION;
        }
        let sd = sys::get_security(&h, flags)
            .or_else(|_| sys::get_security(&h, flags & !meta::SACL_SECURITY_INFORMATION))
            .ok();
        let streams = if link {
            vec![]
        } else {
            sys::streams(&h)?
                .into_iter()
                .filter_map(|(raw, size)| meta::stream_name(&raw).map(|n| (n, size)))
                .collect()
        };
        Ok(Facts {
            attrs,
            size: std_info.EndOfFile as u64,
            created: basic.CreationTime,
            written: basic.LastWriteTime,
            changed: basic.ChangeTime,
            file_id,
            volume,
            links: std_info.NumberOfLinks,
            reparse,
            reparse_tag: tag,
            sd,
            streams,
        })
    }

    fn list(&mut self, dir: &Path) -> io::Result<Vec<Vec<u16>>> {
        let mut out = vec![];
        for e in std::fs::read_dir(dir)? {
            out.push(e?.file_name().encode_wide().collect());
        }
        Ok(out)
    }

    fn child(&self, dir: &Path, name: &[u16]) -> PathBuf {
        dir.join(OsString::from_wide(name))
    }

    fn stream(&self, file: &Path, name: &[u16]) -> PathBuf {
        let mut s = file.as_os_str().to_owned();
        s.push(":");
        s.push(OsString::from_wide(name));
        PathBuf::from(s)
    }

    fn open(&mut self, p: &Path) -> io::Result<std::fs::File> {
        agent_core::chunk::open_read(p)
    }
}
