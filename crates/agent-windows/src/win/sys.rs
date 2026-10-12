//! Thin Win32 wrappers (handles, file information classes, security descriptors,
//! reparse points, privileges). Everything returns `io::Result`.

use std::ffi::{OsStr, OsString};
use std::io;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::path::Path;
use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, HANDLE, LUID};
use windows::Win32::Security::{
    AdjustTokenPrivileges, GetKernelObjectSecurity, GetSecurityDescriptorLength, LookupPrivilegeValueW,
    SetKernelObjectSecurity, LUID_AND_ATTRIBUTES, OBJECT_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
    SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY,
};
use windows::Win32::Storage::FileSystem::*;
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows::Win32::System::IO::DeviceIoControl;

pub const GENERIC_READ: u32 = 0x8000_0000;
pub const GENERIC_WRITE: u32 = 0x4000_0000;
pub const ACCESS_SYSTEM_SECURITY: u32 = 0x0100_0000;
pub const FILE_READ_ATTRIBUTES: u32 = 0x80;
pub const FILE_WRITE_ATTRIBUTES: u32 = 0x100;
pub const DELETE: u32 = 0x1_0000;
pub const WRITE_DAC: u32 = 0x4_0000;
pub const WRITE_OWNER: u32 = 0x8_0000;
pub const OPEN_EXISTING: u32 = 3;
/// FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES: attribute-only opens do not take part in
/// share-mode checks, so a pinning handle must request data access
pub const PIN_DIR_ACCESS: u32 = 0x1 | 0x80;
pub const SHARE_ALL: u32 = 7;
/// read + write, never delete: a held directory cannot be renamed or replaced
pub const SHARE_NO_DELETE: u32 = 3;
pub const FLAG_BACKUP: u32 = 0x0200_0000;
pub const FLAG_OPEN_REPARSE: u32 = 0x0020_0000;

pub const FSCTL_GET_REPARSE_POINT: u32 = 0x0009_00A8;
pub const FSCTL_SET_REPARSE_POINT: u32 = 0x0009_00A4;
pub const FSCTL_QUERY_USN_JOURNAL: u32 = 0x0009_00F4;
pub const FSCTL_READ_USN_JOURNAL: u32 = 0x0009_00BB;
pub const FSCTL_CREATE_USN_JOURNAL: u32 = 0x0009_00E7;

pub const ERROR_FILE_NOT_FOUND: i32 = 2;
pub const ERROR_PATH_NOT_FOUND: i32 = 3;
pub const ERROR_JOURNAL_NOT_ACTIVE: i32 = 1179;
pub const ERROR_JOURNAL_DELETE_IN_PROGRESS: i32 = 1178;
pub const ERROR_JOURNAL_ENTRY_DELETED: i32 = 1181;
pub const ERROR_INVALID_FUNCTION: i32 = 1;
pub const ERROR_HANDLE_EOF: i32 = 38;
pub const ERROR_MORE_DATA: i32 = 234;
pub const ERROR_INSUFFICIENT_BUFFER: i32 = 122;
pub const ERROR_NOT_A_REPARSE_POINT: i32 = 4390;

/// `windows::core::Error` → `io::Error` (Win32 codes keep their `raw_os_error`).
pub fn io_err(e: windows::core::Error) -> io::Error {
    let hr = e.code().0 as u32;
    if hr & 0xFFFF_0000 == 0x8007_0000 {
        io::Error::from_raw_os_error((hr & 0xFFFF) as i32)
    } else {
        io::Error::other(format!("{e} ({hr:#010x})"))
    }
}

pub fn is_not_found(e: &io::Error) -> bool {
    matches!(
        e.raw_os_error(),
        Some(ERROR_FILE_NOT_FOUND) | Some(ERROR_PATH_NOT_FOUND)
    )
}

/// NUL-terminated UTF-16.
pub fn wide(s: impl AsRef<OsStr>) -> Vec<u16> {
    s.as_ref().encode_wide().chain(Some(0)).collect()
}

pub fn from_wide(w: &[u16]) -> OsString {
    let end = w.iter().position(|c| *c == 0).unwrap_or(w.len());
    OsString::from_wide(&w[..end])
}

/// Owned handle, closed on drop.
pub struct Handle(pub HANDLE);

impl Drop for Handle {
    fn drop(&mut self) {
        // SAFETY: we own the handle.
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

// SAFETY: kernel handles may be used from any thread.
unsafe impl Send for Handle {}

pub fn open(path: &Path, access: u32, share: u32, disposition: u32, flags: u32) -> io::Result<Handle> {
    let w = wide(path);
    // SAFETY: valid NUL-terminated path.
    let h = unsafe {
        CreateFileW(
            PCWSTR(w.as_ptr()),
            access,
            FILE_SHARE_MODE(share),
            None,
            FILE_CREATION_DISPOSITION(disposition),
            FILE_FLAGS_AND_ATTRIBUTES(flags),
            None,
        )
    }
    .map_err(io_err)?;
    Ok(Handle(h))
}

/// Open an object itself (never what a reparse point points to) for metadata.
pub fn open_meta(path: &Path, extra_access: u32) -> io::Result<Handle> {
    open(
        path,
        FILE_READ_ATTRIBUTES | READ_CONTROL.0 | extra_access,
        SHARE_ALL,
        OPEN_EXISTING,
        FLAG_BACKUP | FLAG_OPEN_REPARSE,
    )
}

fn info<T: Default>(h: &Handle, class: FILE_INFO_BY_HANDLE_CLASS) -> io::Result<T> {
    let mut v = T::default();
    // SAFETY: buffer of the right size for the class.
    unsafe { GetFileInformationByHandleEx(h.0, class, &mut v as *mut T as *mut _, std::mem::size_of::<T>() as u32) }
        .map_err(io_err)?;
    Ok(v)
}

pub fn basic_info(h: &Handle) -> io::Result<FILE_BASIC_INFO> {
    info(h, FileBasicInfo)
}

pub fn standard_info(h: &Handle) -> io::Result<FILE_STANDARD_INFO> {
    info(h, FileStandardInfo)
}

pub fn tag_info(h: &Handle) -> io::Result<FILE_ATTRIBUTE_TAG_INFO> {
    info(h, FileAttributeTagInfo)
}

/// (volume serial, 128-bit file id)
pub fn file_id(h: &Handle) -> io::Result<(u64, u128)> {
    let i: FILE_ID_INFO = info(h, FileIdInfo)?;
    Ok((i.VolumeSerialNumber, u128::from_le_bytes(i.FileId.Identifier)))
}

/// Named streams: (raw `:name:$DATA`, size).
pub fn streams(h: &Handle) -> io::Result<Vec<(Vec<u16>, u64)>> {
    let mut buf = vec![0u64; 8192];
    loop {
        let bytes = buf.len() * 8;
        // SAFETY: u64-aligned buffer of `bytes` bytes.
        let r = unsafe { GetFileInformationByHandleEx(h.0, FileStreamInfo, buf.as_mut_ptr().cast(), bytes as u32) };
        match r.map_err(io_err) {
            Ok(()) => break,
            Err(e) if e.raw_os_error() == Some(ERROR_HANDLE_EOF) => return Ok(vec![]), // no streams (directories)
            Err(e)
                if matches!(
                    e.raw_os_error(),
                    Some(ERROR_MORE_DATA) | Some(ERROR_INSUFFICIENT_BUFFER)
                ) && bytes < 1 << 24 =>
            {
                buf.resize(buf.len() * 4, 0)
            }
            Err(e) => return Err(e),
        }
    }
    // SAFETY: the buffer holds a chain of FILE_STREAM_INFO records written by the OS.
    let b: &[u8] = unsafe { std::slice::from_raw_parts(buf.as_ptr().cast(), buf.len() * 8) };
    let mut out = vec![];
    let mut o = 0usize;
    loop {
        let rec = b
            .get(o..o + 24)
            .ok_or_else(|| io::Error::other("stream info out of range"))?;
        let next = u32::from_le_bytes(rec[0..4].try_into().expect("4")) as usize;
        let name_len = u32::from_le_bytes(rec[4..8].try_into().expect("4")) as usize;
        let size = i64::from_le_bytes(rec[8..16].try_into().expect("8")) as u64;
        let name = b
            .get(o + 24..o + 24 + name_len)
            .ok_or_else(|| io::Error::other("stream name out of range"))?
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes(*c))
            .collect();
        out.push((name, size));
        if next == 0 {
            break;
        }
        o += next;
    }
    Ok(out)
}

/// Self-relative security descriptor (`flags` = *_SECURITY_INFORMATION).
pub fn get_security(h: &Handle, flags: u32) -> io::Result<Vec<u8>> {
    let mut need = 0u32;
    let mut buf = vec![0u8; 512];
    for _ in 0..4 {
        // SAFETY: buffer and length agree.
        let r = unsafe {
            GetKernelObjectSecurity(
                h.0,
                flags,
                Some(PSECURITY_DESCRIPTOR(buf.as_mut_ptr().cast())),
                buf.len() as u32,
                &mut need,
            )
        };
        match r.map_err(io_err) {
            Ok(()) => {
                // SAFETY: the buffer now holds a valid self-relative descriptor.
                let len = unsafe { GetSecurityDescriptorLength(PSECURITY_DESCRIPTOR(buf.as_mut_ptr().cast())) };
                buf.truncate((len as usize).min(buf.len()));
                return Ok(buf);
            }
            Err(e) if e.raw_os_error() == Some(ERROR_INSUFFICIENT_BUFFER) => buf.resize(need as usize, 0),
            Err(e) => return Err(e),
        }
    }
    Err(io::Error::other("security descriptor keeps growing"))
}

pub fn set_security(h: &Handle, flags: u32, sd: &[u8]) -> io::Result<()> {
    // SAFETY: `sd` was validated by meta::SdInfo::parse; the API copies it.
    unsafe {
        SetKernelObjectSecurity(
            h.0,
            OBJECT_SECURITY_INFORMATION(flags),
            PSECURITY_DESCRIPTOR(sd.as_ptr() as *mut _),
        )
    }
    .map_err(io_err)
}

pub fn ioctl(h: &Handle, code: u32, input: &[u8], out_len: usize) -> io::Result<Vec<u8>> {
    let mut out = vec![0u8; out_len];
    let mut got = 0u32;
    // SAFETY: buffers and lengths agree.
    unsafe {
        DeviceIoControl(
            h.0,
            code,
            (!input.is_empty()).then_some(input.as_ptr().cast()),
            input.len() as u32,
            (out_len > 0).then_some(out.as_mut_ptr().cast()),
            out_len as u32,
            Some(&mut got),
            None,
        )
    }
    .map_err(io_err)?;
    out.truncate(got as usize);
    Ok(out)
}

pub fn get_reparse(h: &Handle) -> io::Result<Vec<u8>> {
    ioctl(h, FSCTL_GET_REPARSE_POINT, &[], 16 * 1024)
}

pub fn set_reparse(h: &Handle, buf: &[u8]) -> io::Result<()> {
    ioctl(h, FSCTL_SET_REPARSE_POINT, buf, 0).map(drop)
}

pub fn set_basic(h: &Handle, created: i64, written: i64, attrs: u32) -> io::Result<()> {
    let i = FILE_BASIC_INFO {
        CreationTime: created,
        LastAccessTime: 0, // 0 = leave unchanged
        LastWriteTime: written,
        ChangeTime: 0,
        FileAttributes: attrs,
    };
    // SAFETY: correctly sized struct for the class.
    unsafe {
        SetFileInformationByHandle(
            h.0,
            FileBasicInfo,
            &i as *const FILE_BASIC_INFO as *const _,
            std::mem::size_of::<FILE_BASIC_INFO>() as u32,
        )
    }
    .map_err(io_err)
}

/// Rename the object behind `h` to the absolute `target`, replacing an existing
/// non-directory there (a symlink at `target` is replaced, not followed).
pub fn rename_replace(h: &Handle, target: &Path) -> io::Result<()> {
    let name: Vec<u16> = target.as_os_str().encode_wide().collect();
    let size = std::mem::size_of::<FILE_RENAME_INFO>() + name.len() * 2;
    let mut buf = vec![0u64; size.div_ceil(8)];
    let p = buf.as_mut_ptr() as *mut FILE_RENAME_INFO;
    // SAFETY: the buffer is large enough for the header plus the name.
    unsafe {
        (*p).Anonymous.ReplaceIfExists = true;
        (*p).RootDirectory = HANDLE::default();
        (*p).FileNameLength = (name.len() * 2) as u32;
        std::ptr::copy_nonoverlapping(name.as_ptr(), (*p).FileName.as_mut_ptr(), name.len());
        SetFileInformationByHandle(h.0, FileRenameInfo, p as *const _, size as u32)
    }
    .map_err(io_err)
}

pub fn delete_by_handle(h: &Handle) -> io::Result<()> {
    let i = FILE_DISPOSITION_INFO { DeleteFile: true };
    // SAFETY: correctly sized struct.
    unsafe {
        SetFileInformationByHandle(
            h.0,
            FileDispositionInfo,
            &i as *const FILE_DISPOSITION_INFO as *const _,
            std::mem::size_of::<FILE_DISPOSITION_INFO>() as u32,
        )
    }
    .map_err(io_err)
}

pub fn final_path(h: &Handle) -> io::Result<String> {
    let mut buf = vec![0u16; 1024];
    loop {
        // SAFETY: buffer slice passed with its length.
        let n = unsafe { GetFinalPathNameByHandleW(h.0, &mut buf, FILE_NAME_NORMALIZED) } as usize;
        if n == 0 {
            return Err(io::Error::last_os_error());
        }
        if n < buf.len() {
            return Ok(String::from_utf16_lossy(&buf[..n]));
        }
        buf.resize(n + 1, 0);
    }
}

pub fn create_dir(path: &Path) -> io::Result<()> {
    let w = wide(path);
    // SAFETY: valid path.
    unsafe { CreateDirectoryW(PCWSTR(w.as_ptr()), None) }.map_err(io_err)
}

pub fn hard_link(new: &Path, existing: &Path) -> io::Result<()> {
    let (n, e) = (wide(new), wide(existing));
    // SAFETY: valid paths.
    unsafe { CreateHardLinkW(PCWSTR(n.as_ptr()), PCWSTR(e.as_ptr()), None) }.map_err(io_err)
}

pub fn move_at_reboot(from: &Path, to: &Path) -> io::Result<()> {
    let (f, t) = (wide(from), wide(to));
    // SAFETY: valid paths.
    unsafe {
        MoveFileExW(
            PCWSTR(f.as_ptr()),
            PCWSTR(t.as_ptr()),
            MOVEFILE_DELAY_UNTIL_REBOOT | MOVEFILE_REPLACE_EXISTING,
        )
    }
    .map_err(io_err)
}

/// Enable privileges in the process token (backup/restore semantics, SACLs, owners).
/// Returns those that could not be enabled.
pub fn enable_privileges(names: &[&str]) -> Vec<String> {
    let mut failed = vec![];
    let mut token = HANDLE::default();
    // SAFETY: plain token calls with valid out pointers.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &mut token) }.is_err() {
        return names.iter().map(|s| s.to_string()).collect();
    }
    let token = Handle(token);
    for n in names {
        let w = wide(n);
        let mut luid = LUID::default();
        // SAFETY: valid name and out pointer.
        let ok = unsafe { LookupPrivilegeValueW(PCWSTR::null(), PCWSTR(w.as_ptr()), &mut luid) }.is_ok() && {
            let tp = TOKEN_PRIVILEGES {
                PrivilegeCount: 1,
                Privileges: [LUID_AND_ATTRIBUTES {
                    Luid: luid,
                    Attributes: SE_PRIVILEGE_ENABLED,
                }],
            };
            // SAFETY: valid token and struct; ERROR_NOT_ALL_ASSIGNED is reported via GetLastError.
            unsafe { AdjustTokenPrivileges(token.0, false, Some(&tp), 0, None, None) }.is_ok()
                && io::Error::last_os_error().raw_os_error() != Some(1300)
        };
        if !ok {
            failed.push(n.to_string());
        }
    }
    failed
}

/// `Limits::nice`: background processing mode for the calling (session) thread:
/// lowest CPU scheduling, very low I/O and memory priority.
pub fn background_mode() -> io::Result<()> {
    use windows::Win32::System::Threading::{GetCurrentThread, SetThreadPriority, THREAD_MODE_BACKGROUND_BEGIN};
    // SAFETY: pseudo handle of the calling thread.
    unsafe { SetThreadPriority(GetCurrentThread(), THREAD_MODE_BACKGROUND_BEGIN) }.map_err(io_err)
}
