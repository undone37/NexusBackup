//! #19 volume images (CAP_VOLUME_IMAGE, docs/bmr.md "Windows"): the machine layout (with the MBR boot code) and the
//! partitions to read for a bare-metal backup: NTFS / ReFS volumes from a VSS snapshot (the shadow copy device,
//! consistent), the others (EFI system partition, MSR, a FAT recovery partition) raw from the partition device
//! (small and seldom written). The VSS set stays open until `ImgFinish`.

use super::vss;
use crate::winlayout::{build, images, Facts};
use base64::Engine;
use std::collections::HashMap;
use std::io::Read;
use std::path::PathBuf;
use std::process::Command;
use std::sync::{Mutex, OnceLock};

const SCRIPT: &str = include_str!("layout.ps1");

fn sets() -> &'static Mutex<HashMap<String, vss::SnapshotSet>> {
    static S: OnceLock<Mutex<HashMap<String, vss::SnapshotSet>>> = OnceLock::new();
    S.get_or_init(|| Mutex::new(HashMap::new()))
}

fn facts() -> Result<Facts, String> {
    let utf16: Vec<u8> = SCRIPT.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let encoded = base64::engine::general_purpose::STANDARD.encode(utf16);
    let out = Command::new(super::hyperv::system32().join("WindowsPowerShell\\v1.0\\powershell.exe"))
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-EncodedCommand",
        ])
        .arg(encoded)
        .output()
        .map_err(|e| format!("powershell.exe: {e}"))?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        return Err(format!("layout: {}", err.lines().next().unwrap_or("no message")));
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    let line = stdout.lines().rev().find(|l| !l.trim().is_empty()).unwrap_or_default();
    serde_json::from_str(line.trim()).map_err(|e| format!("layout facts: {e}"))
}

/// The first 440 bytes of disk `n` (the MBR boot code).
fn boot_code(n: u32) -> Option<Vec<u8>> {
    let mut f = std::fs::File::open(format!("\\\\.\\PhysicalDrive{n}")).ok()?;
    let mut buf = vec![0u8; 512];
    f.read_exact(&mut buf).ok()?;
    buf.truncate(440);
    Some(buf)
}

/// `GetLayout`: the layout as JSON.
pub fn layout() -> Result<String, String> {
    let l = build(&facts()?, boot_code);
    serde_json::to_string(&l).map_err(|e| e.to_string())
}

fn size_of(path: &str) -> Option<u64> {
    let f = std::fs::File::open(path).ok()?;
    super::hyperv::device_size(&f).ok()
}

/// `ImgPrepare`: (`{"set", "images": [{name, target, size, vss}]}`, the devices in target order).
pub fn prepare() -> Result<(String, Vec<PathBuf>), String> {
    let im = images(&facts()?);
    if im.is_empty() {
        return Err("no partitions to image (no boot or system disk found)".into());
    }
    let mut set = None;
    let mut member = vec![None; im.len()];
    if im.iter().any(|i| i.2.is_some()) {
        let mut s = vss::SnapshotSet::begin(&[])?;
        for (k, i) in im.iter().enumerate() {
            if let Some(v) = &i.2 {
                s.add(v).map_err(|e| format!("{}: {e}", i.0))?;
                member[k] = Some(s.members.len() - 1);
            }
        }
        s.create(&[])?;
        set = Some(s);
    }
    let mut out = Vec::new();
    let mut paths = Vec::new();
    for (k, (name, dev, _, size)) in im.iter().enumerate() {
        let path = match (member[k], &set) {
            (Some(m), Some(s)) => s.device(m)?,
            _ => dev.clone(),
        };
        // what the device reads as: a shadow copy is its volume, which can end before its partition (lab
        // 2026-11-02: 4 MiB short of a 40 GiB partition); the shadow device does not answer the length IOCTL, its
        // live volume does (`\\?\Volume{...}` without the trailing backslash opens the volume, not its root)
        let len = match &im[k].2 {
            Some(v) if member[k].is_some() => size_of(v.trim_end_matches('\\')).or_else(|| size_of(&path)),
            _ => size_of(&path),
        }
        .unwrap_or(*size)
        .min(*size);
        out.push(serde_json::json!({"name": name, "target": k + 1, "size": len, "vss": member[k].is_some()}));
        paths.push(PathBuf::from(path));
    }
    let id = set.as_ref().map(vss::SnapshotSet::set_id).unwrap_or_default();
    if let Some(s) = set {
        sets().lock().map_err(|_| "poisoned".to_string())?.insert(id.clone(), s);
    }
    Ok((serde_json::json!({"set": id, "images": out}).to_string(), paths))
}

/// `ImgFinish`: the VSS set released.
pub fn finish(prepared: &str) -> Result<(), String> {
    let v: serde_json::Value = serde_json::from_str(prepared).unwrap_or_default();
    let id = v["set"].as_str().unwrap_or_default();
    if let Some(s) = sets().lock().map_err(|_| "poisoned".to_string())?.remove(id) {
        drop(s.finish(true));
    }
    Ok(())
}

/// One `DeviceIoControl` with input and output buffers; the bytes returned. ERROR_MORE_DATA counts as success
/// (the output is then full).
fn ioctl(f: &std::fs::File, code: u32, input: &[u8], out: &mut [u8]) -> std::io::Result<usize> {
    use std::os::windows::io::AsRawHandle;
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::System::IO::DeviceIoControl;
    let mut got = 0u32;
    // SAFETY: the handle is open for the call; both buffers are valid for their lengths.
    let r = unsafe {
        DeviceIoControl(
            HANDLE(f.as_raw_handle()),
            code,
            (!input.is_empty()).then_some(input.as_ptr().cast()),
            input.len() as u32,
            Some(out.as_mut_ptr().cast()),
            out.len() as u32,
            Some(&mut got),
            None,
        )
    };
    match r {
        Ok(()) => Ok(got as usize),
        Err(e) if e.code().0 as u32 == 0x8007_00EA => Ok(got as usize), // ERROR_MORE_DATA
        Err(e) => Err(std::io::Error::other(e.to_string())),
    }
}

/// The free clusters of the NTFS volume on `path` (a shadow copy device) as sorted byte ranges, from its cluster
/// bitmap. Empty when the volume is not NTFS or the bitmap cannot be read (the image is then read in full).
pub fn free_ranges(path: &std::path::Path) -> Vec<(u64, u64)> {
    const FSCTL_GET_NTFS_VOLUME_DATA: u32 = 0x0009_0064;
    const FSCTL_GET_VOLUME_BITMAP: u32 = 0x0009_006F;
    let Ok(f) = std::fs::File::open(path) else {
        return Vec::new();
    };
    let mut vd = [0u8; 128];
    if ioctl(&f, FSCTL_GET_NTFS_VOLUME_DATA, &[], &mut vd).is_err() {
        return Vec::new();
    }
    let i64_at = |b: &[u8], o: usize| i64::from_le_bytes(b[o..o + 8].try_into().unwrap_or_default());
    let total = i64_at(&vd, 16).max(0) as u64; // TotalClusters
    let bpc = u64::from(u32::from_le_bytes(vd[44..48].try_into().unwrap_or_default())); // BytesPerCluster
    if total == 0 || bpc == 0 {
        return Vec::new();
    }
    let mut out = vec![0u8; 16 + total.div_ceil(8) as usize];
    let start = 0i64.to_le_bytes(); // STARTING_LCN_INPUT_BUFFER
    let Ok(n) = ioctl(&f, FSCTL_GET_VOLUME_BITMAP, &start, &mut out) else {
        return Vec::new();
    };
    if n < 16 || i64_at(&out, 0) != 0 {
        return Vec::new();
    }
    let clusters = (i64_at(&out, 8).max(0) as u64).min(((n - 16) as u64) * 8);
    crate::winlayout::free_from_bitmap(&out[16..], clusters, bpc)
}
