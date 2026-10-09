//! Volumes: enumeration (`ListVolumes`) and path → volume mapping (`Prepare`).

use super::sys::{from_wide, io_err, wide};
use crate::paths::WinPath;
use agent_proto::{SnapshotKind, Volume};
use std::io;
use windows::core::PCWSTR;
use windows::Win32::Storage::FileSystem::{
    FindFirstVolumeW, FindNextVolumeW, FindVolumeClose, GetDriveTypeW, GetVolumeInformationW,
    GetVolumeNameForVolumeMountPointW, GetVolumePathNameW, GetVolumePathNamesForVolumeNameW,
};

const DRIVE_FIXED: u32 = 3;

/// A mounted volume and where it is mounted.
#[derive(Clone, Debug, PartialEq)]
pub struct Vol {
    /// `\\?\Volume{...}\`
    pub guid: String,
    pub mount: WinPath,
    pub fstype: String,
}

impl Vol {
    pub fn snapshot_kind(&self) -> SnapshotKind {
        if vss_capable(&self.fstype) {
            SnapshotKind::Vss
        } else {
            SnapshotKind::None
        }
    }
}

pub fn vss_capable(fstype: &str) -> bool {
    fstype.eq_ignore_ascii_case("NTFS") || fstype.eq_ignore_ascii_case("ReFS")
}

pub fn fs_type(mount: &str) -> String {
    let w = wide(mount);
    let mut name = [0u16; 64];
    // SAFETY: valid root path and buffers.
    match unsafe { GetVolumeInformationW(PCWSTR(w.as_ptr()), None, None, None, None, Some(&mut name)) } {
        Ok(()) => from_wide(&name).to_string_lossy().into_owned(),
        Err(_) => String::new(),
    }
}

/// The volume containing `p` (which need not exist below its volume's mount point).
pub fn containing(p: &WinPath) -> io::Result<Vol> {
    let w = wide(p.win32());
    let mut mount = [0u16; 1024];
    // SAFETY: valid buffers.
    unsafe { GetVolumePathNameW(PCWSTR(w.as_ptr()), &mut mount) }.map_err(io_err)?;
    let mount = from_wide(&mount).to_string_lossy().into_owned();
    let mw = wide(&mount);
    let mut guid = [0u16; 128];
    // SAFETY: valid buffers.
    unsafe { GetVolumeNameForVolumeMountPointW(PCWSTR(mw.as_ptr()), &mut guid) }.map_err(io_err)?;
    Ok(Vol {
        guid: from_wide(&guid).to_string_lossy().into_owned(),
        mount: WinPath::parse(&mount).map_err(io::Error::other)?,
        fstype: fs_type(&mount),
    })
}

/// All fixed volumes with at least one drive-letter or folder mount point.
pub fn list() -> Vec<Vol> {
    let mut out = vec![];
    let mut name = [0u16; 128];
    // SAFETY: valid buffer; the find handle is closed below.
    let Ok(h) = (unsafe { FindFirstVolumeW(&mut name) }) else {
        return out;
    };
    loop {
        let guid = from_wide(&name).to_string_lossy().into_owned();
        let gw = wide(&guid);
        // SAFETY: valid path.
        if unsafe { GetDriveTypeW(PCWSTR(gw.as_ptr())) } == DRIVE_FIXED {
            let mut paths = vec![0u16; 4096];
            let mut len = 0u32;
            // SAFETY: valid buffers.
            if unsafe { GetVolumePathNamesForVolumeNameW(PCWSTR(gw.as_ptr()), Some(&mut paths), &mut len) }.is_ok() {
                let fstype = fs_type(&guid);
                for m in paths[..(len as usize).min(paths.len())]
                    .split(|c| *c == 0)
                    .filter(|s| !s.is_empty())
                {
                    if let Ok(mount) = WinPath::parse(&String::from_utf16_lossy(m)) {
                        out.push(Vol {
                            guid: guid.clone(),
                            mount,
                            fstype: fstype.clone(),
                        });
                    }
                }
            }
        }
        // SAFETY: valid handle and buffer.
        if unsafe { FindNextVolumeW(h, &mut name) }.is_err() {
            break;
        }
    }
    // SAFETY: handle from FindFirstVolumeW.
    let _ = unsafe { FindVolumeClose(h) };
    out.sort_by(|a, b| a.mount.cmp(&b.mount));
    out
}

pub fn list_volumes() -> Vec<Volume> {
    list()
        .into_iter()
        .map(|v| Volume {
            mountpoint: v.mount.slash(),
            snapshot: v.snapshot_kind(),
            device: v.guid,
            fstype: v.fstype,
        })
        .collect()
}
