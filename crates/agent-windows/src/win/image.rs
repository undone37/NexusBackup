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
        // what the device reads as (a shadow copy can be a little shorter than its partition)
        let len = size_of(&path).unwrap_or(*size);
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
