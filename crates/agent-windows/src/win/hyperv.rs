//! Hyper-V host backups (#39, docs/hyperv-design.md M1, agent protocol v1.10): the WMI steps run in Windows
//! PowerShell (`hyperv.ps1`, embedded) with the Hyper-V module; the agent reads the mounted frozen disks itself
//! (`\\.\PhysicalDriveN`, block reads).
//! ponytail: PowerShell instead of native COM/WMI calls: one process per step (a second or two, per backup, not per
//! block); native IWbemServices when that cost matters (M2's change query goes through virtdisk.dll anyway).

use base64::Engine;
use std::path::PathBuf;
use std::process::Command;

const SCRIPT: &str = include_str!("hyperv.ps1");

/// Whether this host runs Hyper-V (the Virtual Machine Management service is installed).
pub fn available() -> bool {
    system32().join("vmms.exe").is_file()
}

fn system32() -> PathBuf {
    let root = std::env::var_os("SystemRoot").unwrap_or_else(|| "C:\\Windows".into());
    PathBuf::from(root).join("System32")
}

/// Runs one action of the script with `args` (JSON object) and returns its JSON line.
fn run(args: &serde_json::Value) -> Result<String, String> {
    let utf16: Vec<u8> = SCRIPT.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let encoded = base64::engine::general_purpose::STANDARD.encode(utf16);
    let out = Command::new(system32().join("WindowsPowerShell\\v1.0\\powershell.exe"))
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-EncodedCommand",
        ])
        .arg(encoded)
        .env("NEXUS_HV", args.to_string())
        .output()
        .map_err(|e| format!("powershell.exe: {e}"))?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        let err = err.trim();
        // PowerShell's error record: the message is the first line
        let first = err.lines().next().unwrap_or("no message");
        return Err(format!("Hyper-V {}: {first}", args["action"].as_str().unwrap_or("?")));
    }
    stdout
        .lines()
        .rev()
        .find(|l| !l.trim().is_empty())
        .map(|l| l.trim().to_owned())
        .ok_or_else(|| "Hyper-V: no answer from the script".into())
}

pub fn list() -> Result<String, String> {
    run(&serde_json::json!({"action": "list"}))
}

/// The `HvPrepared` JSON and the device of each disk in target order.
pub fn prepare(vm: &str, base: Option<&serde_json::Value>) -> Result<(String, Vec<PathBuf>), String> {
    if vm.len() != 36 || !vm.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-') {
        return Err(format!("invalid VM id {vm:?}"));
    }
    // #39 M2: the base reference point's RCT ids, one per disk (strings only; the script checks their form)
    let rct: Vec<&str> = base
        .and_then(|b| b["rct"].as_array())
        .into_iter()
        .flatten()
        .filter_map(|v| v.as_str())
        .filter(|s| s.len() <= 200 && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b':' || b == b'-'))
        .collect();
    let json = run(&serde_json::json!({"action": "prepare", "vm": vm, "rct": rct}))?;
    let v: serde_json::Value = serde_json::from_str(&json).map_err(|e| format!("Hyper-V prepare: {e}"))?;
    let mut disks: Vec<(u64, PathBuf)> = v["disks"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|d| Some((d["target"].as_u64()?, PathBuf::from(d["device"].as_str()?))))
        .collect();
    disks.sort_by_key(|(t, _)| *t);
    Ok((json, disks.into_iter().map(|(_, p)| p).collect()))
}

/// #39 M4: the `HvRestoreReady` JSON and the device of each new disk in target order.
pub fn restore_begin(spec: &serde_json::Value) -> Result<(String, Vec<PathBuf>), String> {
    let json = run(&serde_json::json!({"action": "restore_begin", "spec": spec}))?;
    let v: serde_json::Value = serde_json::from_str(&json).map_err(|e| format!("Hyper-V restore: {e}"))?;
    let mut disks: Vec<(u64, PathBuf)> = v["disks"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|d| Some((d["target"].as_u64()?, PathBuf::from(d["device"].as_str()?))))
        .collect();
    disks.sort_by_key(|(t, _)| *t);
    Ok((json, disks.into_iter().map(|(_, p)| p).collect()))
}

pub fn restore_finish(begun: &str, keep: bool) -> Result<String, String> {
    let b: serde_json::Value = serde_json::from_str(begun).map_err(|e| format!("Hyper-V restore: {e}"))?;
    run(&serde_json::json!({"action": "restore_finish", "begun": b, "keep": keep}))
}

pub fn finish(prepared: &str, keep: bool) -> Result<String, String> {
    let p: serde_json::Value = serde_json::from_str(prepared).map_err(|e| format!("Hyper-V finish: {e}"))?;
    run(&serde_json::json!({"action": "finish", "prepared": p, "keep": keep}))
}

/// Size of an opened disk (`\\.\PhysicalDriveN` has no end to seek to): IOCTL_DISK_GET_LENGTH_INFO, else the end of a plain file.
pub fn device_size(f: &std::fs::File) -> std::io::Result<u64> {
    use std::os::windows::io::AsRawHandle;
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::System::IO::DeviceIoControl;
    const IOCTL_DISK_GET_LENGTH_INFO: u32 = 0x0007_405C;
    let mut len = 0i64;
    let mut got = 0u32;
    // SAFETY: the handle is open for the call; the output buffer is one i64 (GET_LENGTH_INFORMATION).
    unsafe {
        DeviceIoControl(
            HANDLE(f.as_raw_handle()),
            IOCTL_DISK_GET_LENGTH_INFO,
            None,
            0,
            Some((&mut len as *mut i64).cast()),
            8,
            Some(&mut got),
            None,
        )
    }
    // a plain file has no disk length (and `metadata()` fails on a raw disk handle: "Incorrect function")
    .map_or_else(
        |_| std::io::Seek::seek(&mut &*f, std::io::SeekFrom::End(0)),
        |()| Ok(len as u64),
    )
}
