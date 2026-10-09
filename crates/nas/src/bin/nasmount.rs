//! `nexus-nasmount`: the privileged NAS mount helper (docs/nas-connector.md).
//!
//! Socket-activated per connection (`nexus-nasmount.socket`, `Accept=yes`):
//! fd 0 is the connection from the connector. Runs as root with
//! `CAP_SYS_ADMIN` only (unit) in the SELinux domain `nexus_nasmount_t`.
//!
//! 1. peer credentials (`SO_PEERCRED`): only the configured user
//!    (`NEXUS_NASMOUNT_ALLOW_USER`, the scheduler/connector user) is served;
//! 2. one request (bounded, 10 s), strictly parsed and validated
//!    ([`nas::proto::Request`]);
//! 3. Kerberos (SMB `sec=krb5`): keytab to a 0600 file in the private runtime
//!    dir, `kinit` into the ticket cache named by `KRB5CCNAME` (set by the unit,
//!    so the kernel's cifs.upcall finds it in this process's environment);
//! 4. `fsopen`/`fsconfig`/`fsmount` ([`nas::kmount`]): a detached, read-only
//!    `nosuid,nodev,noexec,nosymfollow` mount that no namespace contains;
//! 5. `ok` + the mount fd (`SCM_RIGHTS`) to the connector, exit. The mount
//!    disappears when the connector closes the fd (or dies).
//!
//! `nexus-nasmount --version` prints the version.

use anyhow::{bail, Context, Result};
use nas::cred::CredFile;
use nas::proto::{Request, Sec, MAX_REQUEST};
use nas::{fdpass, kmount, opts};
use std::ffi::CString;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn peer(sock: &UnixStream) -> Result<libc::ucred> {
    // SAFETY: zeroed ucred is a valid out buffer of the given length.
    let mut c: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let r = unsafe {
        libc::getsockopt(
            sock.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut c as *mut libc::ucred).cast(),
            &mut len,
        )
    };
    if r != 0 {
        bail!("SO_PEERCRED: {}", std::io::Error::last_os_error());
    }
    Ok(c)
}

fn uid_of(user: &str) -> Result<u32> {
    let n = CString::new(user)?;
    // SAFETY: getpwnam with a valid C string; the result is read immediately.
    let p = unsafe { libc::getpwnam(n.as_ptr()) };
    if p.is_null() {
        bail!("unknown user {user:?}");
    }
    Ok(unsafe { (*p).pw_uid })
}

fn read_request(sock: &mut UnixStream) -> Result<Vec<u8>> {
    sock.set_read_timeout(Some(Duration::from_secs(10)))?;
    let mut buf = Vec::new();
    let mut chunk = [0u8; 8192];
    while !buf.ends_with(b"\nend\n") {
        let n = sock.read(&mut chunk).context("reading the request")?;
        if n == 0 {
            bail!("connection closed before the end of the request");
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.len() > MAX_REQUEST {
            bail!("request too large");
        }
    }
    Ok(buf)
}

/// `kinit -k -t <keytab> <principal>` into `KRB5CCNAME` (a FILE: cache in the
/// private runtime dir), 30 s at most.
fn kinit(req: &Request) -> Result<CredFile> {
    let dir = PathBuf::from(std::env::var_os("RUNTIME_DIRECTORY").context("RUNTIME_DIRECTORY not set (unit)")?);
    let cc = std::env::var("KRB5CCNAME").context("KRB5CCNAME not set (unit)")?;
    let ccpath = cc.strip_prefix("FILE:").context("KRB5CCNAME must be a FILE: cache")?;
    if !std::path::Path::new(ccpath).starts_with(&dir) {
        bail!("KRB5CCNAME must be inside RUNTIME_DIRECTORY");
    }
    let kt = CredFile::create(&dir, "keytab", req.keytab.as_deref().unwrap_or_default())?;
    let mut child = Command::new("/usr/bin/kinit")
        .env_clear()
        .env("PATH", "/usr/bin:/usr/sbin")
        .env("KRB5CCNAME", &cc)
        .arg("-k")
        .arg("-t")
        .arg(kt.path())
        .arg("--")
        .arg(req.principal.as_deref().unwrap_or_default())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("kinit")?;
    let t0 = Instant::now();
    loop {
        if let Some(st) = child.try_wait()? {
            let mut err = String::new();
            if let Some(mut e) = child.stderr.take() {
                let _ = e.read_to_string(&mut err);
            }
            if !st.success() {
                bail!("kinit failed ({st}): {}", err.trim());
            }
            return Ok(kt);
        }
        if t0.elapsed() > Duration::from_secs(30) {
            let _ = child.kill();
            bail!("kinit timed out");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn serve(sock: &mut UnixStream) -> Result<std::os::fd::OwnedFd> {
    let cred = peer(sock)?;
    if let Ok(user) = std::env::var("NEXUS_NASMOUNT_ALLOW_USER") {
        if cred.uid != uid_of(&user)? {
            bail!("peer uid {} is not {user}", cred.uid);
        }
    }
    let req = Request::parse(&read_request(sock)?)?;
    let spec = opts::build(&req, cred.uid)?;
    eprintln!(
        "nexus-nasmount: peer uid {} pid {}: {} {}",
        cred.uid,
        cred.pid,
        req.addr,
        spec.describe()
    );
    // the keytab file is removed again right after the mount (the ticket cache stays
    // until the instance's runtime dir is removed)
    let _kt = match req.sec {
        Sec::Krb5 => Some(kinit(&req)?),
        _ => None,
    };
    Ok(kmount::mount(&spec)?)
}

fn main() {
    if std::env::args().nth(1).as_deref() == Some("--version") {
        println!("nexus-nasmount {}", env!("CARGO_PKG_VERSION"));
        return;
    }
    // SAFETY: process-wide settings without preconditions.
    unsafe {
        libc::umask(0o077);
        libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
    }
    // fd 0: the accepted connection (StandardInput=socket)
    // SAFETY: fd 0 is owned by this process; it must be a Unix stream socket.
    let mut sock = unsafe { UnixStream::from_raw_fd(0) };
    if sock.peer_addr().is_err() && peer(&sock).is_err() {
        eprintln!("nexus-nasmount: stdin is not a Unix socket connection (socket-activated only)");
        std::process::exit(2);
    }
    match serve(&mut sock) {
        Ok(fd) => {
            if let Err(e) = fdpass::send_fd(&sock, b"ok\n", fd.as_raw_fd()) {
                eprintln!("nexus-nasmount: sending the mount fd: {e}");
                std::process::exit(1);
            }
            // our copy of the fd closes on exit; the connector's copy keeps the mount
        }
        Err(e) => {
            let msg = format!("{e:#}").replace(['\n', '\r'], " ");
            eprintln!("nexus-nasmount: {msg}");
            let _ = sock.write_all(format!("error {msg}\n").as_bytes());
            // drain what the peer still sends: closing with unread data would
            // reset the connection and the answer could be lost
            let _ = sock.shutdown(std::net::Shutdown::Write);
            let _ = sock.set_read_timeout(Some(Duration::from_secs(1)));
            let _ = std::io::copy(&mut (&mut sock).take(MAX_REQUEST as u64), &mut std::io::sink());
            std::process::exit(1);
        }
    }
}
