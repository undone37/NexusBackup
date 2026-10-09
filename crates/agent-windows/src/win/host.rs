//! `HelloReply` host information: Windows edition and build (registry), DNS host name.

use super::sys::{from_wide, wide};
use agent_core::server::HostInfo;
use windows::core::{PCWSTR, PWSTR};
use windows::Win32::System::Registry::{RegGetValueW, HKEY_LOCAL_MACHINE, RRF_RT_REG_DWORD, RRF_RT_REG_SZ};
use windows::Win32::System::SystemInformation::{ComputerNameDnsHostname, GetComputerNameExW};

const CURRENT_VERSION: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion";

fn reg_string(name: &str) -> Option<String> {
    let (k, v) = (wide(CURRENT_VERSION), wide(name));
    let mut buf = vec![0u16; 256];
    let mut len = (buf.len() * 2) as u32;
    // SAFETY: valid key/value names and buffer.
    let r = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(k.as_ptr()),
            PCWSTR(v.as_ptr()),
            RRF_RT_REG_SZ,
            None,
            Some(buf.as_mut_ptr().cast()),
            Some(&mut len),
        )
    };
    r.is_ok().then(|| from_wide(&buf).to_string_lossy().into_owned())
}

fn reg_dword(name: &str) -> Option<u32> {
    let (k, v) = (wide(CURRENT_VERSION), wide(name));
    let mut val = 0u32;
    let mut len = 4u32;
    // SAFETY: valid names and a 4-byte buffer.
    let r = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(k.as_ptr()),
            PCWSTR(v.as_ptr()),
            RRF_RT_REG_DWORD,
            None,
            Some((&mut val as *mut u32).cast()),
            Some(&mut len),
        )
    };
    r.is_ok().then_some(val)
}

pub fn hostname() -> String {
    let mut buf = vec![0u16; 256];
    let mut n = buf.len() as u32;
    // SAFETY: valid buffer and size.
    match unsafe { GetComputerNameExW(ComputerNameDnsHostname, Some(PWSTR(buf.as_mut_ptr())), &mut n) } {
        Ok(()) => String::from_utf16_lossy(&buf[..n as usize]),
        Err(_) => String::new(),
    }
}

/// e.g. ("Windows Server 2022 Standard (21H2)", "10.0.20348.2340")
pub fn os_version() -> (String, String) {
    let product = reg_string("ProductName").unwrap_or_else(|| "Windows".into());
    let display = reg_string("DisplayVersion").or_else(|| reg_string("ReleaseId"));
    let build = reg_string("CurrentBuild").unwrap_or_default();
    let ubr = reg_dword("UBR").map(|u| format!(".{u}")).unwrap_or_default();
    let os = match display {
        Some(d) => format!("{product} ({d})"),
        None => product,
    };
    (os, format!("10.0.{build}{ubr}"))
}

pub fn info() -> HostInfo {
    let (os, kernel) = os_version();
    HostInfo {
        os,
        kernel,
        hostname: hostname(),
        caps: [
            "vss",
            "vss-writers",
            "usn",
            "ads",
            "win-sd",
            "hardlinks",
            "fallback",
            "restore",
            "update",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect(),
        agent_version: env!("CARGO_PKG_VERSION").into(),
    }
}
