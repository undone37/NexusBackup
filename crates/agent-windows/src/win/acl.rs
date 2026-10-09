//! Restrictive ACL on `%ProgramData%\NexusAgent` (config: private key, token digest,
//! certificates, release keys; state: cache, spool): owner Administrators, protected
//! DACL with full control for SYSTEM and Administrators only, inherited by everything
//! below. Applied by `init`, `install` and at every service start.

use super::sys::{io_err, wide};
use std::io;
use std::path::Path;
use windows::core::PCWSTR;
use windows::Win32::Foundation::{LocalFree, HLOCAL};
use windows::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
use windows::Win32::Security::{SetFileSecurityW, OBJECT_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR};

/// Owner Administrators, group SYSTEM, protected DACL: SYSTEM + Administrators full
/// control, inherited by files and subdirectories.
pub const SDDL: &str = "O:BAG:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";

const OWNER: u32 = 0x1;
const DACL: u32 = 0x4;
const PROTECTED_DACL: u32 = 0x8000_0000;
const SDDL_REVISION_1: u32 = 1;

fn apply(path: &Path, sd: PSECURITY_DESCRIPTOR) -> io::Result<()> {
    let w = wide(path);
    // SAFETY: valid path and descriptor.
    let ok = unsafe {
        SetFileSecurityW(
            PCWSTR(w.as_ptr()),
            OBJECT_SECURITY_INFORMATION(OWNER | DACL | PROTECTED_DACL),
            sd,
        )
    };
    if ok.as_bool() {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Create `base` (and `dirs` below it) and set the ACL on it and on everything that
/// already exists below it.
pub fn secure(base: &Path, dirs: &[&Path]) -> io::Result<()> {
    std::fs::create_dir_all(base)?;
    for d in dirs {
        std::fs::create_dir_all(d)?;
    }
    let s = wide(SDDL);
    let mut sd = PSECURITY_DESCRIPTOR::default();
    // SAFETY: valid SDDL; the descriptor is freed with LocalFree.
    unsafe { ConvertStringSecurityDescriptorToSecurityDescriptorW(PCWSTR(s.as_ptr()), SDDL_REVISION_1, &mut sd, None) }
        .map_err(io_err)?;
    let r = (|| {
        apply(base, sd)?;
        let mut stack = vec![base.to_path_buf()];
        while let Some(d) = stack.pop() {
            for e in std::fs::read_dir(&d)? {
                let e = e?;
                let p = e.path();
                // children inherit; resetting them removes any explicit, looser ACEs
                apply(&p, sd)?;
                if e.file_type()?.is_dir() {
                    stack.push(p);
                }
            }
        }
        Ok(())
    })();
    // SAFETY: allocated by ConvertStringSecurityDescriptorToSecurityDescriptorW.
    unsafe {
        let _ = LocalFree(Some(HLOCAL(sd.0)));
    }
    r
}
