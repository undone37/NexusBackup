//! `nexus-replicad <state-dir> <socket> <store-base> <allow-user>` (primary,
//! docs/replication.md §2): serves sealed snapshot files and chunks read-only to
//! the web-api (only `allow-user` may connect) and signs enrolled secondaries'
//! certificates. Publishes `ca.pem` and `seal.pub` next to the socket.

use anyhow::{bail, Context, Result};
use replication::replicad::Replicad;
use std::ffi::CString;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::sync::Arc;

fn resolve_uid(user: &str) -> Result<u32> {
    if let Ok(uid) = user.parse() {
        return Ok(uid);
    }
    let name = CString::new(user)?;
    let pw = unsafe { libc::getpwnam(name.as_ptr()) };
    if pw.is_null() {
        bail!("unknown user {user}");
    }
    Ok(unsafe { (*pw).pw_uid })
}

fn main() -> Result<()> {
    keyd::deny_dumps();
    unsafe { libc::umask(0o027) };
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [state, socket, store, user] = args.as_slice() else {
        bail!("usage: nexus-replicad <state-dir> <socket> <store-base> <allow-user>");
    };
    let uid = resolve_uid(user)?;
    let r = Arc::new(Replicad::open(Path::new(state), Path::new(store))?);
    let sock = Path::new(socket);
    let dir = sock.parent().context("socket path")?;
    // published files keep the runtime dir's group (nexus-replicad: the web-api)
    // (no chown when it is our own group already: the unit's syscall filter has no @chown)
    let gid = std::fs::metadata(dir)
        .ok()
        .map(|m| m.gid())
        .filter(|g| *g != unsafe { libc::getegid() });
    r.publish(dir, gid).context("publishing ca.pem / seal.pub")?;
    let _ = std::fs::remove_file(sock);
    let l = UnixListener::bind(sock)?;
    std::fs::set_permissions(sock, std::fs::Permissions::from_mode(0o660))?;
    eprintln!("<6>replicad: serving {} on {}", store, socket);
    r.serve(l, uid)?;
    Ok(())
}
