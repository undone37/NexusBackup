//! nexus-nasmount as socket-activated (fd 0 = the connection), without root:
//! request validation, peer check, and the mount refused by the kernel come
//! back as `error …` lines; the connector side reports them.

use nas::proto::Request;
use std::io::{Read, Write};
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::process::{Command, Stdio};

fn run(req: &[u8], env: &[(&str, &str)]) -> (String, bool) {
    let (mut a, b) = UnixStream::pair().unwrap();
    let mut c = Command::new(env!("CARGO_BIN_EXE_nexus-nasmount"));
    c.stdin(Stdio::from(OwnedFd::from(b)))
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .env_clear();
    for (k, v) in env {
        c.env(k, v);
    }
    let mut child = c.spawn().unwrap();
    drop(c); // the Command holds our copy of the helper's end of the socket
    a.write_all(req).unwrap();
    let mut out = String::new();
    a.read_to_string(&mut out).unwrap();
    let st = child.wait().unwrap();
    (out, st.success())
}

fn root() -> bool {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() == 0 }
}

#[test]
fn refuses_invalid_requests() {
    let (out, ok) = run(b"nexus-nasmount 1\nfs nfs\nhost x\nend\n", &[]);
    assert!(!ok && out.starts_with("error ") && out.contains("missing"), "{out}");
    let (out, ok) = run(b"GET / HTTP/1.0\n\nend\n", &[]);
    assert!(!ok && out.starts_with("error "), "{out}");
}

#[test]
fn peer_check_and_kernel_refusal() {
    let req = Request::nfs("127.0.0.1", "127.0.0.1".parse().unwrap(), "/srv/share")
        .encode()
        .unwrap();
    // only the configured user is served
    let (out, ok) = run(&req, &[("NEXUS_NASMOUNT_ALLOW_USER", "root")]);
    if !root() {
        assert!(!ok && out.contains("is not root"), "{out}");
        // without CAP_SYS_ADMIN the kernel refuses fsopen
        let (out, ok) = run(&req, &[]);
        assert!(!ok && out.starts_with("error ") && out.contains("fsopen"), "{out}");
    }
}

#[test]
fn connector_reports_helper_errors() {
    if root() {
        return;
    }
    let d = tempfile::tempdir().unwrap();
    let sock = d.path().join("mount.sock");
    let l = std::os::unix::net::UnixListener::bind(&sock).unwrap();
    let t = std::thread::spawn(move || {
        let (c, _) = l.accept().unwrap();
        let mut child = Command::new(env!("CARGO_BIN_EXE_nexus-nasmount"))
            .stdin(Stdio::from(OwnedFd::from(c)))
            .stderr(Stdio::null())
            .env_clear()
            .spawn()
            .unwrap();
        child.wait().unwrap();
    });
    let req = Request::smb("nas", "127.0.0.1".parse().unwrap(), "share", "u", "pw");
    let e = nas::mount::mount_share(&sock, &req, std::time::Duration::from_secs(10)).unwrap_err();
    assert!(format!("{e:#}").contains("mount helper: fsopen(cifs)"), "{e:#}");
    t.join().unwrap();
}
