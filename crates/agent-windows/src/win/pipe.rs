//! Local IPC for the endpoint UIs on Windows: the named pipe `\\.\pipe\nexus-agent-ui`
//! (docs/endpoint-ui.md) with the ACL of [`crate::endpoint::PIPE_SDDL`]. One server
//! instance waits at a time; each connected client is served on its own thread
//! (at most [`MAX_CLIENTS`]), newline-delimited JSON (`agent_ui_proto`).

use super::sys::{io_err, wide};
use super::Agent;
use std::io::{self, BufReader, Write};
use std::os::windows::io::{FromRawHandle, OwnedHandle};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use windows::core::PCWSTR;
use windows::Win32::Foundation::{LocalFree, ERROR_PIPE_CONNECTED, HLOCAL, INVALID_HANDLE_VALUE};
use windows::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
use windows::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
use windows::Win32::Storage::FileSystem::{FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_ACCESS_DUPLEX};
use windows::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE,
    PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
};

pub const MAX_CLIENTS: usize = 8;

/// Owned security descriptor from SDDL (freed on drop).
struct Sd(PSECURITY_DESCRIPTOR);

impl Sd {
    fn new(sddl: &str) -> io::Result<Sd> {
        let s = wide(sddl);
        let mut sd = PSECURITY_DESCRIPTOR::default();
        // SAFETY: valid SDDL string; freed in Drop.
        unsafe { ConvertStringSecurityDescriptorToSecurityDescriptorW(PCWSTR(s.as_ptr()), 1, &mut sd, None) }
            .map_err(io_err)?;
        Ok(Sd(sd))
    }
}

impl Drop for Sd {
    fn drop(&mut self) {
        // SAFETY: allocated by ConvertStringSecurityDescriptorToSecurityDescriptorW.
        unsafe {
            let _ = LocalFree(Some(HLOCAL(self.0 .0)));
        }
    }
}

fn instance(sd: &Sd, first: bool) -> io::Result<OwnedHandle> {
    let sa = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd.0 .0,
        bInheritHandle: false.into(),
    };
    let name = wide(agent_ui_proto::PIPE_NAME);
    // the first instance must not exist yet: nobody can squat the name before us
    let mut mode = PIPE_ACCESS_DUPLEX;
    if first {
        mode |= FILE_FLAG_FIRST_PIPE_INSTANCE;
    }
    // SAFETY: valid name and security attributes for the duration of the call.
    let h = unsafe {
        CreateNamedPipeW(
            PCWSTR(name.as_ptr()),
            mode,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            PIPE_UNLIMITED_INSTANCES,
            64 << 10,
            64 << 10,
            0,
            Some(&sa),
        )
    };
    if h == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a fresh handle we own.
    Ok(unsafe { OwnedHandle::from_raw_handle(h.0 as _) })
}

/// Serves the pipe until the process ends (run it on its own thread).
pub fn serve(agent: Arc<Agent>) -> io::Result<()> {
    let sd = Sd::new(crate::endpoint::PIPE_SDDL)?;
    let active = Arc::new(AtomicUsize::new(0));
    let mut first = true;
    loop {
        let h = instance(&sd, first)?;
        first = false;
        let raw = windows::Win32::Foundation::HANDLE(std::os::windows::io::AsRawHandle::as_raw_handle(&h) as _);
        // SAFETY: valid pipe handle, synchronous connect.
        match unsafe { ConnectNamedPipe(raw, None) } {
            Ok(()) => {}
            Err(e) if e.code() == ERROR_PIPE_CONNECTED.to_hresult() => {}
            Err(_) => continue,
        }
        if active.fetch_add(1, Ordering::SeqCst) >= MAX_CLIENTS {
            active.fetch_sub(1, Ordering::SeqCst);
            continue; // dropping the handle disconnects the client
        }
        let (agent, active) = (agent.clone(), active.clone());
        std::thread::spawn(move || {
            let _ = handle(&agent, std::fs::File::from(h));
            active.fetch_sub(1, Ordering::SeqCst);
        });
    }
}

fn handle(agent: &Agent, f: std::fs::File) -> io::Result<()> {
    let mut r = BufReader::new(f.try_clone()?);
    let mut w = f;
    while let Some(line) = agent_ui_proto::read_line(&mut r)? {
        w.write_all(agent.ui_request(&line).as_bytes())?;
        w.flush()?;
    }
    Ok(())
}
