//! `nexus-index [config.json]`: the file search service (crate docs).
//! Config: `/etc/nexus/index.json` if present, else the defaults
//! (`service::Config`). Socket: one JSON request line per connection
//! (crate index-proto); peers are checked by uid (SO_PEERCRED).

use fileindex::service::{Config, Service};
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

const MAX_CONNS: usize = 32;

fn peer_uid(s: &UnixStream) -> std::io::Result<u32> {
    let mut cred = libc::ucred { pid: 0, uid: 0, gid: 0 };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: getsockopt into a correctly sized ucred
    let r = unsafe {
        libc::getsockopt(
            std::os::fd::AsRawFd::as_raw_fd(s),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if r != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(cred.uid)
}

fn uid_of(name: &str) -> Option<u32> {
    let c = std::ffi::CString::new(name).ok()?;
    // SAFETY: getpwnam at start (single thread), the entry is copied out at once
    let p = unsafe { libc::getpwnam(c.as_ptr()) };
    (!p.is_null()).then(|| unsafe { (*p).pw_uid })
}

fn serve(svc: &Service, mut s: UnixStream) {
    let _ = s.set_read_timeout(Some(Duration::from_secs(30)));
    let mut line = Vec::new();
    let res = BufReader::new(&s)
        .take(index_proto::MAX_LINE)
        .read_until(b'\n', &mut line)
        .map_err(anyhow::Error::from)
        .and_then(|_| Ok(serde_json::from_slice::<index_proto::Request>(&line)?))
        .and_then(|r| svc.handle(r));
    let out = match res {
        Ok(v) => serde_json::json!({"ok": v}),
        Err(e) => serde_json::json!({"err": format!("{e:#}")}),
    };
    let mut b = serde_json::to_vec(&out).unwrap_or_default();
    b.push(b'\n');
    let _ = s.write_all(&b);
}

fn main() -> anyhow::Result<()> {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "/etc/nexus/index.json".into());
    let cfg: Config = match std::fs::read(&path) {
        Ok(b) => serde_json::from_slice(&b)?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Config::default(),
        Err(e) => return Err(e.into()),
    };
    // decrypted names in memory: no core dumps, no ptrace by same-uid processes;
    // no mlockall (the index cache is large; swap is encrypted on the appliance)
    // SAFETY: plain system calls
    unsafe {
        libc::umask(0o077);
        libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
    }
    let sock = cfg.socket.clone();
    let keyd_socket = cfg.keyd_socket.clone();
    // SAFETY: getuid cannot fail
    let me = unsafe { libc::getuid() };
    let mut allowed = vec![me];
    for u in &cfg.allowed_users {
        match uid_of(u) {
            Some(id) => allowed.push(id),
            None => eprintln!("nexus-index: user {u} not found (not allowed on the socket)"),
        }
    }
    std::fs::create_dir_all(&cfg.index_base)?;
    let svc = Service::new(cfg, Arc::new(move |t: &str| keyd::fetch_keyring(&keyd_socket, t)));
    let _ = std::fs::remove_file(&sock);
    let l = UnixListener::bind(&sock)?;
    // access through the directory's group (RuntimeDirectory 0750) + the uid check
    std::fs::set_permissions(&sock, std::fs::Permissions::from_mode(0o660))?;
    eprintln!("nexus-index: listening on {}", sock.display());
    let s2 = svc.clone();
    std::thread::Builder::new()
        .name("sync".into())
        .spawn(move || s2.run_sync())?;
    let conns = Arc::new(AtomicUsize::new(0));
    for c in l.incoming() {
        let Ok(c) = c else { continue };
        match peer_uid(&c) {
            Ok(u) if allowed.contains(&u) => {}
            Ok(u) => {
                eprintln!("nexus-index: peer uid {u} not allowed");
                continue;
            }
            Err(_) => continue,
        }
        if conns.fetch_add(1, Ordering::SeqCst) >= MAX_CONNS {
            conns.fetch_sub(1, Ordering::SeqCst);
            continue;
        }
        let (svc, conns) = (svc.clone(), conns.clone());
        std::thread::spawn(move || {
            serve(&svc, c);
            conns.fetch_sub(1, Ordering::SeqCst);
        });
    }
    Ok(())
}
