//! Signed self-update for Windows. Signature and version checks are shared
//! (`agent_core::update::check_candidate`: cosign blob signature with the pinned keys
//! in `config\release-keys\*.pub`, embedded version strictly newer). Authenticode is
//! not required.
//!
//! Installing: a running `.exe` cannot be overwritten but can be renamed, so the new
//! binary is written to `<exe>.new`, the running one is renamed to `<exe>.prev`, and
//! `<exe>.new` is renamed to `<exe>`; then the process exits with
//! [`RESTART_EXIT_CODE`] and the service control manager restarts it (failure actions
//! set by `nexus-agent install`). If the running binary cannot be renamed, the
//! replacement is scheduled with `MoveFileEx(MOVEFILE_DELAY_UNTIL_REBOOT)` and the
//! update takes effect at the next reboot (the agent reports that).

use std::fs;
use std::io::{self, Write};
use std::path::Path;

/// Embedded in every build; found in update candidates to learn their real version.
#[used]
pub static VERSION_MARKER: &[u8] = concat!("\0NEXUS-AGENT-VERSION=", env!("CARGO_PKG_VERSION"), "\0").as_bytes();
pub const RESTART_EXIT_CODE: i32 = 75;

/// PE32+ image for x86-64 (`MZ`, `PE\0\0`, machine 0x8664, optional header magic 0x20b).
pub fn is_pe_x64(b: &[u8]) -> bool {
    if b.len() < 0x40 || &b[..2] != b"MZ" {
        return false;
    }
    let pe = u32::from_le_bytes(b[0x3C..0x40].try_into().expect("4")) as usize;
    let Some(h) = b.get(pe..pe + 26) else { return false };
    &h[..4] == b"PE\0\0" && u16::from_le_bytes([h[4], h[5]]) == 0x8664 && u16::from_le_bytes([h[24], h[25]]) == 0x20B
}

/// How the new binary was put in place.
#[derive(Debug, PartialEq, Eq)]
pub enum Installed {
    /// in place now; restart the service
    Now,
    /// scheduled for the next reboot
    AtReboot,
}

/// Write `binary` next to `exe` and swap it in (see module docs). `delay_rename` is
/// the rename-on-reboot fallback (`MoveFileExW(.., MOVEFILE_DELAY_UNTIL_REBOOT |
/// MOVEFILE_REPLACE_EXISTING)` on Windows).
pub fn install(exe: &Path, binary: &[u8], delay_rename: fn(&Path, &Path) -> io::Result<()>) -> io::Result<Installed> {
    let name = exe
        .file_name()
        .ok_or_else(|| io::Error::other("executable has no name"))?
        .to_string_lossy()
        .into_owned();
    let dir = exe
        .parent()
        .ok_or_else(|| io::Error::other("executable has no directory"))?;
    let new = dir.join(format!("{name}.new"));
    let prev = dir.join(format!("{name}.prev"));
    let _ = fs::remove_file(&new);
    {
        let mut f = fs::OpenOptions::new().write(true).create_new(true).open(&new)?;
        f.write_all(binary)?;
        f.sync_all()?;
    }
    let _ = fs::remove_file(&prev);
    if let Err(e) = fs::rename(exe, &prev) {
        // the running image could not be moved aside: replace it at the next boot
        return match delay_rename(&new, exe) {
            Ok(()) => Ok(Installed::AtReboot),
            Err(e2) => {
                let _ = fs::remove_file(&new);
                Err(io::Error::other(format!(
                    "rename running binary: {e}; delayed rename: {e2}"
                )))
            }
        };
    }
    if let Err(e) = fs::rename(&new, exe) {
        let _ = fs::rename(&prev, exe);
        let _ = fs::remove_file(&new);
        return Err(e);
    }
    Ok(Installed::Now)
}

// ------------------------------------------------------------- Phase 27 (protocol v1.8)

use agent_core::update::InstallResult;
use std::ffi::OsString;
use std::path::PathBuf;

/// Verbose log of an in-band MSI update, below the state directory.
pub const MSI_LOG: &str = "update-msi.log";

/// `CreateProcess` flags for msiexec: no console, its own process group and outside
/// the service's job object, so stopping and replacing the service does not kill it.
pub const DETACHED_PROCESS: u32 = 0x0000_0008;
pub const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
pub const CREATE_BREAKAWAY_FROM_JOB: u32 = 0x0100_0000;
pub const DETACHED_FLAGS: u32 = DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | CREATE_BREAKAWAY_FROM_JOB;

/// `%SystemRoot%\System32\msiexec.exe`.
pub fn msiexec(system_root: Option<OsString>) -> PathBuf {
    PathBuf::from(system_root.unwrap_or_else(|| "C:\\Windows".into()))
        .join("System32")
        .join("msiexec.exe")
}

/// The msiexec arguments of an MSI update: install the verified package quietly,
/// never reboot, verbose log. Fixed arguments; the only variable parts are the
/// staged file (below `staging`) and the log path. The MSI's major upgrade replaces
/// the previous version and keeps `%ProgramData%\NexusAgent` (enrollment, state).
pub fn msiexec_args(msi: &Path, log: &Path, staging: &Path) -> Result<Vec<OsString>, String> {
    let s = msi.to_str().ok_or("staged file name is not UTF-8")?;
    if msi.parent() != Some(staging) || !s.to_ascii_lowercase().ends_with(".msi") || s.contains(['"', '\n', '\0']) {
        return Err(format!("{s}: not a staged MSI"));
    }
    Ok(vec![
        "/i".into(),
        msi.as_os_str().to_owned(),
        "/qn".into(),
        "/norestart".into(),
        "/l*v".into(),
        log.as_os_str().to_owned(),
    ])
}

/// Text of an msiexec log: UTF-16LE (with BOM, as msiexec writes it) or 8-bit.
pub fn decode_log(b: &[u8]) -> String {
    let utf16 = b.starts_with(&[0xFF, 0xFE]) || (b.len() >= 4 && b[1] == 0 && b[3] == 0);
    if utf16 {
        let start = if b.starts_with(&[0xFF, 0xFE]) { 2 } else { 0 };
        let u: Vec<u16> = b[start..]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes(*c))
            .collect();
        String::from_utf16_lossy(&u)
    } else {
        String::from_utf8_lossy(b).into_owned()
    }
}

/// Outcome of an MSI install from its verbose log: `MainEngineThread is returning
/// <code>` ends every run (0 = success, 3010 = success, reboot required; 1641 = a
/// restart was started). No such line yet: still running.
pub fn parse_msi_log(b: Option<&[u8]>) -> InstallResult {
    let Some(b) = b else {
        return InstallResult::Unknown;
    };
    let text = decode_log(b);
    let code = text.lines().rev().find_map(|l| {
        l.split("MainEngineThread is returning ")
            .nth(1)
            .and_then(|r| r.trim().trim_end_matches('.').trim().parse::<u32>().ok())
    });
    match code {
        None => InstallResult::Running,
        Some(0 | 3010 | 1641) => InstallResult::Succeeded,
        Some(c) => {
            // the lines around the first failing action are the useful part
            let lines: Vec<&str> = text.lines().collect();
            let at = lines
                .iter()
                .position(|l| l.contains("Return value 3"))
                .unwrap_or(lines.len());
            let from = at.saturating_sub(15);
            let tail = agent_core::update::tail_lines(&lines[from..lines.len().min(at + 1)].join("\n"), 20);
            let why = match c {
                1603 => "fatal error during installation",
                1618 => "another installation is in progress",
                1638 => "another version of this product is already installed (downgrade refused)",
                1925 | 1625 => "not allowed by policy",
                _ => "installation failed",
            };
            // `Action ended 12:00:05: StartServices. Return value 3.`: the action that failed, in the message itself
            let action = lines.get(at).and_then(|l| {
                let a = l.split("Action ended ").nth(1)?.split_once(": ")?.1;
                let a = a.split(". Return value").next()?.trim();
                (!a.is_empty() && a.len() <= 64 && a.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'))
                    .then_some(a)
            });
            let at_action = action.map(|a| format!(" (failed action: {a})")).unwrap_or_default();
            InstallResult::Failed(format!("msiexec exit code {c}: {why}{at_action}"), tail)
        }
    }
}

/// Start watchdog on Windows: the running (new) image cannot be overwritten but can
/// be renamed: it goes aside as `<exe>.failed`, `<exe>.prev` takes its place; the
/// service control manager restarts the previous version.
pub fn restore_prev(exe: &Path) -> Result<(), String> {
    let name = exe
        .file_name()
        .ok_or("executable has no name")?
        .to_string_lossy()
        .into_owned();
    let dir = exe.parent().ok_or("executable has no directory")?;
    let prev = dir.join(format!("{name}.prev"));
    let failed = dir.join(format!("{name}.failed"));
    if !prev.is_file() {
        return Err(format!("{} not found", prev.display()));
    }
    let _ = fs::remove_file(&failed);
    fs::rename(exe, &failed).map_err(|e| format!("{} -> {}: {e}", exe.display(), failed.display()))?;
    if let Err(e) = fs::rename(&prev, exe) {
        let _ = fs::rename(&failed, exe);
        return Err(format!("{} -> {}: {e}", prev.display(), exe.display()));
    }
    Ok(())
}

#[cfg(test)]
mod update2_tests {
    use super::*;

    #[test]
    fn msiexec_arguments_are_fixed() {
        let staging = Path::new("C:/ProgramData/NexusAgent/state/update");
        let msi = staging.join("nexus-agent-0.2.0-x64.msi");
        let log = Path::new("C:/ProgramData/NexusAgent/state/update-msi.log");
        let a = msiexec_args(&msi, log, staging).unwrap();
        let a: Vec<String> = a.iter().map(|x| x.to_string_lossy().into_owned()).collect();
        assert_eq!(
            a,
            [
                "/i",
                "C:/ProgramData/NexusAgent/state/update/nexus-agent-0.2.0-x64.msi",
                "/qn",
                "/norestart",
                "/l*v",
                "C:/ProgramData/NexusAgent/state/update-msi.log"
            ]
        );
        for bad in [
            Path::new("C:/Temp/x.msi").to_path_buf(),
            staging.join("x.exe"),
            staging.join("a\"b.msi"),
        ] {
            assert!(msiexec_args(&bad, log, staging).is_err(), "{bad:?}");
        }
        assert_eq!(
            msiexec(Some("D:\\Win".into())),
            PathBuf::from("D:\\Win").join("System32").join("msiexec.exe")
        );
        assert_eq!(DETACHED_FLAGS, 0x0100_0208);
    }

    fn utf16(s: &str) -> Vec<u8> {
        let mut b = vec![0xFF, 0xFE];
        for u in s.encode_utf16() {
            b.extend(u.to_le_bytes());
        }
        b
    }

    #[test]
    fn msi_log_outcomes() {
        assert_eq!(parse_msi_log(None), InstallResult::Unknown);
        let running = "=== Verbose logging started ===\r\nAction start 12:00:01: InstallInitialize.\r\n";
        assert_eq!(parse_msi_log(Some(&utf16(running))), InstallResult::Running);
        let ok = format!("{running}MSI (s) (A0:B4) [12:00:09:123]: MainEngineThread is returning 0\r\n");
        assert_eq!(parse_msi_log(Some(&utf16(&ok))), InstallResult::Succeeded);
        let reboot = format!("{running}MainEngineThread is returning 3010\r\n");
        assert_eq!(parse_msi_log(Some(reboot.as_bytes())), InstallResult::Succeeded);
        let failed = format!(
            "{running}Action ended 12:00:05: StartServices. Return value 3.\r\nMSI (s) (A0:B4) [12:00:09:123]: MainEngineThread is returning 1603\r\n"
        );
        match parse_msi_log(Some(&utf16(&failed))) {
            InstallResult::Failed(e, tail) => {
                assert!(
                    e.contains("1603") && e.ends_with("(failed action: StartServices)"),
                    "{e}"
                );
                assert!(tail.iter().any(|l| l.contains("StartServices")), "{tail:?}");
            }
            r => panic!("{r:?}"),
        }
        let down = "MainEngineThread is returning 1638\r\n";
        match parse_msi_log(Some(down.as_bytes())) {
            InstallResult::Failed(e, _) => assert!(e.contains("downgrade"), "{e}"),
            r => panic!("{r:?}"),
        }
        assert_eq!(decode_log(&utf16("abc")), "abc");
        assert_eq!(decode_log(b"abc"), "abc");
    }

    #[test]
    fn watchdog_restore_puts_prev_back() {
        let t = tempfile::tempdir().unwrap();
        let exe = t.path().join("nexus-agent.exe");
        fs::write(&exe, b"new").unwrap();
        assert!(restore_prev(&exe).is_err());
        fs::write(t.path().join("nexus-agent.exe.prev"), b"old").unwrap();
        restore_prev(&exe).unwrap();
        assert_eq!(fs::read(&exe).unwrap(), b"old");
        assert_eq!(fs::read(t.path().join("nexus-agent.exe.failed")).unwrap(), b"new");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub fn fake_pe(version: &str) -> Vec<u8> {
        let mut b = vec![0u8; 0x200];
        b[..2].copy_from_slice(b"MZ");
        b[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        b[0x80..0x84].copy_from_slice(b"PE\0\0");
        b[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes());
        b[0x98..0x9A].copy_from_slice(&0x20Bu16.to_le_bytes());
        b.extend_from_slice(format!("\0NEXUS-AGENT-VERSION={version}\0").as_bytes());
        b
    }

    #[test]
    fn pe_detection() {
        assert!(is_pe_x64(&fake_pe("1.0.0")));
        let mut x86 = fake_pe("1.0.0");
        x86[0x84..0x86].copy_from_slice(&0x14Cu16.to_le_bytes());
        assert!(!is_pe_x64(&x86));
        let mut pe32 = fake_pe("1.0.0");
        pe32[0x98..0x9A].copy_from_slice(&0x10Bu16.to_le_bytes());
        assert!(!is_pe_x64(&pe32));
        let mut far = fake_pe("1.0.0");
        far[0x3C..0x40].copy_from_slice(&0xFFFF_FFF0u32.to_le_bytes());
        assert!(!is_pe_x64(&far));
        assert!(!is_pe_x64(b"\x7fELF"));
        assert_eq!(
            agent_core::update::embedded_version(VERSION_MARKER).unwrap(),
            env!("CARGO_PKG_VERSION")
        );
    }

    #[test]
    fn candidate_checks_use_the_pe_format() {
        // signature checks are covered in agent-core; here: an ELF is refused, a PE passes
        // the format gate (and fails later only on the signature)
        let keys = vec![("k".to_string(), vec![4u8; 65])];
        let e = agent_core::update::check_candidate("9.9.9", &fake_pe("9.9.9"), b"sig", &keys, "0.1.0", is_pe_x64)
            .unwrap_err();
        assert!(e.contains("signature"), "{e}");
    }

    #[test]
    fn install_swaps_and_keeps_prev() {
        let t = tempfile::tempdir().unwrap();
        let exe = t.path().join("nexus-agent.exe");
        fs::write(&exe, b"old").unwrap();
        fn no_delay(_: &Path, _: &Path) -> io::Result<()> {
            panic!("not needed")
        }
        assert_eq!(install(&exe, b"new", no_delay).unwrap(), Installed::Now);
        assert_eq!(fs::read(&exe).unwrap(), b"new");
        assert_eq!(fs::read(t.path().join("nexus-agent.exe.prev")).unwrap(), b"old");
        assert!(!t.path().join("nexus-agent.exe.new").exists());
        // second update replaces .prev
        assert_eq!(install(&exe, b"newer", no_delay).unwrap(), Installed::Now);
        assert_eq!(fs::read(t.path().join("nexus-agent.exe.prev")).unwrap(), b"new");
    }

    #[test]
    fn install_falls_back_to_rename_at_reboot() {
        let t = tempfile::tempdir().unwrap();
        let exe = t.path().join("missing.exe"); // cannot be renamed aside
        fn delay(new: &Path, _exe: &Path) -> io::Result<()> {
            assert!(new.exists());
            Ok(())
        }
        assert_eq!(install(&exe, b"new", delay).unwrap(), Installed::AtReboot);
        fn fail(_: &Path, _: &Path) -> io::Result<()> {
            Err(io::Error::other("no"))
        }
        assert!(install(&exe, b"new", fail).is_err());
        assert!(!t.path().join("missing.exe.new").exists(), "cleaned up");
    }
}
