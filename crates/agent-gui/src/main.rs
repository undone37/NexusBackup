// no console window on Windows
#![cfg_attr(windows, windows_subsystem = "windows")]

//! nexus-agent-gui [--open] [--socket PATH]
//!
//!   --open         open the Control Panel window (application menu entry); without it the
//!                  program starts in the tray (autostart at login)
//!   --socket PATH  agent service socket / named pipe (default: the platform default)
//!
//! One instance per user session: a second start asks the running one to open its window.

use nexus_agent_gui::app::{self, Options};
use nexus_agent_gui::ipc::Endpoint;
use std::sync::{mpsc, Arc, Mutex};

fn main() {
    let mut opts = Options::default();
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--open" => opts.open = true,
            "--socket" => opts.endpoint = Endpoint(args.next().map(Into::into)),
            "--version" => {
                println!("nexus-agent-gui {}", env!("CARGO_PKG_VERSION"));
                return;
            }
            _ => {
                eprintln!("usage: nexus-agent-gui [--open] [--socket PATH] [--version]");
                std::process::exit(2);
            }
        }
    }
    let (tx, rx) = mpsc::channel();
    if !single_instance(tx) {
        return;
    }
    opts.wakeups = Some(Arc::new(Mutex::new(rx)));
    opts.settings_path = nexus_agent_gui::settings::default_path();
    if let Err(e) = app::run(opts) {
        eprintln!("nexus-agent-gui: {e}");
        std::process::exit(1);
    }
}

/// Linux: abstract unix socket per user; a second instance sends "open" and exits.
#[cfg(target_os = "linux")]
fn single_instance(wake: mpsc::Sender<()>) -> bool {
    use std::io::{Read, Write};
    use std::os::linux::net::SocketAddrExt;
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::net::{SocketAddr, UnixListener, UnixStream};
    let uid = std::fs::metadata("/proc/self").map(|m| m.uid()).unwrap_or(0);
    let Ok(addr) = SocketAddr::from_abstract_name(format!("nexus-agent-gui-{uid}")) else {
        return true;
    };
    match UnixListener::bind_addr(&addr) {
        Ok(l) => {
            std::thread::spawn(move || {
                for mut s in l.incoming().flatten() {
                    // anyone on the host could connect (abstract sockets have no file mode);
                    // all they can do is open this window
                    let mut buf = [0u8; 4];
                    if s.read(&mut buf).is_ok_and(|n| &buf[..n] == b"open") && wake.send(()).is_err() {
                        break;
                    }
                }
            });
            true
        }
        Err(_) => {
            if let Ok(mut s) = UnixStream::connect_addr(&addr) {
                let _ = s.write_all(b"open");
            }
            false
        }
    }
}

/// Windows: one instance per logon session (named mutex). A second start (the Start menu entry) sets the
/// session's named event and exits; the running instance opens its window (#67: before, the second start did
/// nothing while the tray icon ran).
#[cfg(windows)]
fn single_instance(wake: mpsc::Sender<()>) -> bool {
    use windows_sys::Win32::Foundation::{GetLastError, ERROR_ALREADY_EXISTS};
    use windows_sys::Win32::System::Threading::{
        CreateEventW, CreateMutexW, OpenEventW, SetEvent, WaitForSingleObject, EVENT_MODIFY_STATE, INFINITE,
    };
    let wide = |s: &str| -> Vec<u16> { s.encode_utf16().chain(Some(0)).collect() };
    let (mutex, event) = (wide("Local\\NexusAgentGui"), wide("Local\\NexusAgentGuiOpen"));
    // SAFETY: valid NUL-terminated name; the handle lives until the process exits
    let h = unsafe { CreateMutexW(std::ptr::null(), 0, mutex.as_ptr()) };
    // SAFETY: GetLastError has no preconditions; it reads the calling thread's last error, set by CreateMutexW above.
    let first = h.is_null() || unsafe { GetLastError() } != ERROR_ALREADY_EXISTS;
    if first {
        // auto-reset, not signalled; anyone in this logon session can set it: all it does is open this window
        // SAFETY: valid NUL-terminated name, default security; the handle lives until the process exits
        let ev = unsafe { CreateEventW(std::ptr::null(), 0, 0, event.as_ptr()) };
        if !ev.is_null() {
            let ev = ev as usize; // a HANDLE is not Send; the thread only waits on it
            std::thread::spawn(move || loop {
                // SAFETY: a valid event handle that is never closed
                unsafe { WaitForSingleObject(ev as _, INFINITE) };
                if wake.send(()).is_err() {
                    break;
                }
            });
        }
    } else {
        // SAFETY: valid NUL-terminated name; a null handle (no running instance yet) is not used
        let ev = unsafe { OpenEventW(EVENT_MODIFY_STATE, 0, event.as_ptr()) };
        if !ev.is_null() {
            // SAFETY: a valid event handle with EVENT_MODIFY_STATE; the process exits right after
            unsafe { SetEvent(ev) };
        }
    }
    first
}

#[cfg(not(any(target_os = "linux", windows)))]
fn single_instance(_wake: mpsc::Sender<()>) -> bool {
    true
}
