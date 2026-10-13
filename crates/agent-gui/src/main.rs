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

/// Windows: one instance per logon session (named mutex); the tray icon of the running
/// instance opens the window.
#[cfg(windows)]
fn single_instance(_wake: mpsc::Sender<()>) -> bool {
    use windows_sys::Win32::Foundation::{GetLastError, ERROR_ALREADY_EXISTS};
    use windows_sys::Win32::System::Threading::CreateMutexW;
    let name: Vec<u16> = "Local\\NexusAgentGui\0".encode_utf16().collect();
    // SAFETY: valid NUL-terminated name; the handle lives until the process exits
    let h = unsafe { CreateMutexW(std::ptr::null(), 0, name.as_ptr()) };
    h.is_null() || unsafe { GetLastError() } != ERROR_ALREADY_EXISTS
}

#[cfg(not(any(target_os = "linux", windows)))]
fn single_instance(_wake: mpsc::Sender<()>) -> bool {
    true
}
