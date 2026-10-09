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
