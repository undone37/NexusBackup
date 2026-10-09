//! keyd: the only process holding the appliance KEK. Unwraps tenant DEKs and
//! hands them to chunkstore over a Unix socket (peer uid checked).
//!
//! Layout under `dir`:
//! ```text
//! kek.local             KEK sealed to this machine (see `seal`)
//! kek.recovery          KEK wrapped under the offline recovery key (escrow, copied offsite)
//! tenants/<t>/dek.<v>   tenant DEK version v wrapped under the KEK
//! ```
//! DR: new machine + `kek.recovery` + `tenants/` + recovery key -> `recover()`.

use chunkstore::crypto::{generate_key, hex, parse_hex, unwrap_key, wrap_key};
use chunkstore::store::write_atomic;
use chunkstore::Keyring;
use std::fs;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::time::Duration;
use zeroize::{Zeroize, Zeroizing};

pub type Key = Zeroizing<[u8; 32]>;

fn err(kind: io::ErrorKind, msg: impl Into<String>) -> io::Error {
    io::Error::new(kind, msg.into())
}

// ponytail: file-based sealing (0600 via umask, root-only dir). TPM2 sealing bound
// to Secure Boot PCRs replaces seal/unseal once libtss2-dev is available.
fn seal(dir: &Path, kek: &[u8; 32]) -> io::Result<()> {
    write_atomic(&dir.join("kek.local"), kek)
}

fn unseal(dir: &Path) -> io::Result<Key> {
    let b = Zeroizing::new(fs::read(dir.join("kek.local"))?);
    let mut k = Zeroizing::new([0u8; 32]);
    if b.len() != 32 {
        return Err(err(io::ErrorKind::InvalidData, "kek.local corrupt"));
    }
    k.copy_from_slice(&b);
    Ok(k)
}

/// 16 groups of 4 hex digits, e.g. `1a2b-3c4d-…`.
pub fn format_recovery_key(k: &[u8; 32]) -> String {
    let h = hex(k);
    (0..16).map(|i| &h[i * 4..i * 4 + 4]).collect::<Vec<_>>().join("-")
}

pub fn parse_recovery_key(s: &str) -> io::Result<Key> {
    let h: String = s.chars().filter(|c| c.is_ascii_alphanumeric()).collect();
    parse_hex(&h.to_ascii_lowercase())
        .map(Zeroizing::new)
        .ok_or_else(|| err(io::ErrorKind::InvalidInput, "recovery key must be 64 hex digits"))
}

/// First boot: creates KEK and recovery key. The returned recovery key is
/// shown exactly once and never stored on the appliance.
pub fn init(dir: &Path) -> io::Result<String> {
    if dir.join("kek.recovery").exists() {
        return Err(err(io::ErrorKind::AlreadyExists, "keyd already initialized"));
    }
    fs::create_dir_all(dir.join("tenants"))?;
    let kek = Zeroizing::new(generate_key());
    let rk = Zeroizing::new(generate_key());
    write_atomic(&dir.join("kek.recovery"), &wrap_key(&rk, &kek, "kek-recovery"))?;
    seal(dir, &kek)?;
    Ok(format_recovery_key(&rk))
}

fn kek_from_recovery(dir: &Path, recovery_key: &str) -> io::Result<Key> {
    let rk = parse_recovery_key(recovery_key)?;
    let blob = fs::read(dir.join("kek.recovery"))?;
    Ok(Zeroizing::new(unwrap_key(&rk, &blob, "kek-recovery")?))
}

/// Proves the recovery key was recorded correctly (first-boot wizard).
pub fn check_recovery_key(dir: &Path, recovery_key: &str) -> io::Result<()> {
    if *kek_from_recovery(dir, recovery_key)? == *unseal(dir)? {
        Ok(())
    } else {
        Err(err(io::ErrorKind::InvalidData, "recovery key does not match KEK"))
    }
}

/// New hardware: re-seal the KEK from the escrow blob.
pub fn recover(dir: &Path, recovery_key: &str) -> io::Result<()> {
    seal(dir, &*kek_from_recovery(dir, recovery_key)?)
}

fn tenant_dir(dir: &Path, tenant: &str) -> io::Result<PathBuf> {
    let ok = !tenant.is_empty()
        && tenant.len() <= 64
        && !tenant.starts_with('.')
        && tenant.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b));
    if !ok {
        return Err(err(io::ErrorKind::InvalidInput, format!("invalid tenant {tenant:?}")));
    }
    Ok(dir.join("tenants").join(tenant))
}

fn versions(dir: &Path, tenant: &str) -> io::Result<Vec<u32>> {
    let mut v: Vec<u32> = match fs::read_dir(tenant_dir(dir, tenant)?) {
        Ok(rd) => rd
            .filter_map(|e| e.ok()?.file_name().to_str()?.strip_prefix("dek.")?.parse().ok())
            .collect(),
        Err(e) if e.kind() == io::ErrorKind::NotFound => vec![],
        Err(e) => return Err(e),
    };
    v.sort();
    Ok(v)
}

fn label(tenant: &str, v: u32) -> String {
    format!("tenant-dek:{tenant}:v{v}")
}

fn add_dek(dir: &Path, tenant: &str, v: u32) -> io::Result<u32> {
    let kek = unseal(dir)?;
    let dek = Zeroizing::new(generate_key());
    let td = tenant_dir(dir, tenant)?;
    fs::create_dir_all(&td)?;
    write_atomic(&td.join(format!("dek.{v}")), &wrap_key(&kek, &dek, &label(tenant, v)))?;
    Ok(v)
}

pub fn create_tenant(dir: &Path, tenant: &str) -> io::Result<u32> {
    if !versions(dir, tenant)?.is_empty() {
        return Err(err(io::ErrorKind::AlreadyExists, format!("tenant {tenant} exists")));
    }
    add_dek(dir, tenant, 1)
}

/// New DEK version; older versions stay available for reading.
pub fn rotate_tenant(dir: &Path, tenant: &str) -> io::Result<u32> {
    let last = *versions(dir, tenant)?
        .last()
        .ok_or_else(|| err(io::ErrorKind::NotFound, format!("no tenant {tenant}")))?;
    add_dek(dir, tenant, last + 1)
}

pub fn tenant_deks(dir: &Path, tenant: &str) -> io::Result<Vec<(u32, Key)>> {
    let kek = unseal(dir)?;
    let td = tenant_dir(dir, tenant)?;
    let vs = versions(dir, tenant)?;
    if vs.is_empty() {
        return Err(err(io::ErrorKind::NotFound, format!("no tenant {tenant}")));
    }
    vs.into_iter()
        .map(|v| {
            let blob = fs::read(td.join(format!("dek.{v}")))?;
            Ok((v, Zeroizing::new(unwrap_key(&kek, &blob, &label(tenant, v))?)))
        })
        .collect()
}

/// Escrow files for the offsite copy: `kek.recovery` (KEK under the offline
/// recovery key) and the tenant's DEKs (under the KEK). All wrapped, no secret in clear.
pub fn export_escrow(dir: &Path, tenant: &str) -> io::Result<Vec<(String, Vec<u8>)>> {
    let mut out = vec![("kek.recovery".to_owned(), fs::read(dir.join("kek.recovery"))?)];
    let td = tenant_dir(dir, tenant)?;
    for v in versions(dir, tenant)? {
        out.push((
            format!("tenants/{tenant}/dek.{v}"),
            fs::read(td.join(format!("dek.{v}")))?,
        ));
    }
    Ok(out)
}

/// DR on a fresh appliance: installs escrow files; follow with `recover()`.
/// Refuses to replace an existing, different `kek.recovery`.
pub fn import_escrow(dir: &Path, files: &[(String, Vec<u8>)]) -> io::Result<()> {
    fs::create_dir_all(dir.join("tenants"))?;
    for (name, bytes) in files {
        let target = match name.split('/').collect::<Vec<_>>().as_slice() {
            ["kek.recovery"] => dir.join("kek.recovery"),
            ["tenants", t, f] if f.strip_prefix("dek.").is_some_and(|v| v.parse::<u32>().is_ok()) => {
                let td = tenant_dir(dir, t)?;
                fs::create_dir_all(&td)?;
                td.join(f)
            }
            _ => {
                return Err(err(
                    io::ErrorKind::InvalidInput,
                    format!("unexpected escrow file {name:?}"),
                ))
            }
        };
        match fs::read(&target) {
            Ok(existing) if existing == *bytes => continue,
            Ok(_) => {
                return Err(err(
                    io::ErrorKind::AlreadyExists,
                    format!("{name} exists with different content"),
                ))
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => write_atomic(&target, bytes)?,
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// For every process that holds tenant DEKs (scheduler, nexus-pve,
/// nexus-offsite): no core dumps and no ptrace / `/proc/<pid>/mem` access by
/// other processes of the same uid (e.g. a restore-VM QEMU after an escape).
pub fn deny_dumps() {
    unsafe {
        libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
    }
}

/// Below this RLIMIT_MEMLOCK, `MCL_FUTURE` would turn larger allocations (argon2
/// in nexus-setup needs ~19 MiB) into aborts, so only current pages are locked.
const MIN_MEMLOCK_FOR_FUTURE: u64 = 64 << 20;

/// umask 077, no core dumps / ptrace by same uid, keys never swapped (best effort).
pub fn harden_process() {
    unsafe {
        libc::umask(0o077);
        libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
        let mut lim: libc::rlimit = std::mem::zeroed();
        let enough = libc::geteuid() == 0
            || (libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut lim) == 0
                && (lim.rlim_cur == libc::RLIM_INFINITY || lim.rlim_cur >= MIN_MEMLOCK_FOR_FUTURE));
        let flags = if enough {
            libc::MCL_CURRENT | libc::MCL_FUTURE
        } else {
            eprintln!("keyd: warning: RLIMIT_MEMLOCK below 64 MiB, locking current pages only; raise LimitMEMLOCK");
            libc::MCL_CURRENT
        };
        if libc::mlockall(flags) != 0 {
            eprintln!(
                "keyd: warning: mlockall failed ({}), raise LimitMEMLOCK",
                io::Error::last_os_error()
            );
        }
    }
}

fn peer_uid(s: &UnixStream) -> io::Result<u32> {
    let mut cred = libc::ucred { pid: 0, uid: 0, gid: 0 };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            std::os::fd::AsRawFd::as_raw_fd(s),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(cred.uid)
}

/// Protocol (one request per connection, only the allowed uid):
/// - `<tenant>\n` → N x (u32 LE version, 32-byte DEK)
/// - `ensure <tenant>\n` → same, creating DEK v1 first if the tenant has none
/// - `escrow <tenant>\n` → wrapped escrow files: N x (u16 BE name len, name, u32 BE len, bytes)
///
/// Any error closes the connection without an answer.
// ponytail: sequential accept loop; requests only happen at chunkstore start.
pub fn serve(listener: UnixListener, dir: &Path, allow_uid: u32) -> io::Result<()> {
    for conn in listener.incoming() {
        if let Err(e) = handle(conn?, dir, allow_uid) {
            eprintln!("keyd: request rejected: {e}");
        }
    }
    Ok(())
}

fn handle(mut s: UnixStream, dir: &Path, allow_uid: u32) -> io::Result<()> {
    let uid = peer_uid(&s)?;
    if uid != allow_uid {
        return Err(err(
            io::ErrorKind::PermissionDenied,
            format!("peer uid {uid} not allowed"),
        ));
    }
    s.set_read_timeout(Some(Duration::from_secs(5)))?;
    s.set_write_timeout(Some(Duration::from_secs(5)))?;
    let mut line = String::new();
    BufReader::new(&s).take(128).read_line(&mut line)?;
    s.write_all(&answer(dir, &line)?)
}

/// The answer to one request line (see `serve`); errors mean "no answer".
pub fn answer(dir: &Path, line: &str) -> io::Result<Zeroizing<Vec<u8>>> {
    let line = line.trim_end_matches('\n');
    let tenant = match line.split_once(' ') {
        Some(("escrow", t)) => {
            let mut out = Zeroizing::new(Vec::new());
            for (name, bytes) in export_escrow(dir, t)? {
                out.extend_from_slice(&(name.len() as u16).to_be_bytes());
                out.extend_from_slice(name.as_bytes());
                out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
                out.extend_from_slice(&bytes);
            }
            return Ok(out);
        }
        Some(("ensure", t)) => {
            if versions(dir, t)?.is_empty() {
                create_tenant(dir, t)?;
                eprintln!("keyd: created DEK v1 for tenant {t}");
            }
            t
        }
        Some(_) => return Err(err(io::ErrorKind::InvalidInput, "unknown request")),
        None => line,
    };
    let deks = tenant_deks(dir, tenant)?;
    let mut out = Zeroizing::new(Vec::with_capacity(deks.len() * 36));
    for (v, k) in &deks {
        out.extend_from_slice(&v.to_le_bytes());
        out.extend_from_slice(&k[..]);
    }
    Ok(out)
}

/// chunkstore side: fetch all DEK versions of a tenant and build its keyring.
pub fn fetch_keyring(socket: &Path, tenant: &str) -> io::Result<Keyring> {
    request_keyring(socket, tenant, tenant)
}

/// Like `fetch_keyring`, but keyd creates the tenant's first DEK if it has none
/// (scheduler: tenants are created in the UI, keys appear on first use).
pub fn ensure_keyring(socket: &Path, tenant: &str) -> io::Result<Keyring> {
    request_keyring(socket, &format!("ensure {tenant}"), tenant)
}

/// Wrapped escrow files of a tenant (see `export_escrow`), for the offsite copy.
pub fn fetch_escrow(socket: &Path, tenant: &str) -> io::Result<Vec<(String, Vec<u8>)>> {
    let mut s = UnixStream::connect(socket)?;
    s.write_all(format!("escrow {tenant}\n").as_bytes())?;
    let mut buf = Vec::new();
    s.read_to_end(&mut buf)?;
    if buf.is_empty() {
        return Err(err(io::ErrorKind::PermissionDenied, "keyd refused the request"));
    }
    parse_escrow(&buf)
}

/// Decodes an `escrow` answer: N x (u16 BE name len, name, u32 BE len, bytes).
pub fn parse_escrow(buf: &[u8]) -> io::Result<Vec<(String, Vec<u8>)>> {
    let (mut out, mut r) = (Vec::new(), buf);
    let bad = || err(io::ErrorKind::InvalidData, "malformed escrow answer");
    while !r.is_empty() {
        let n = u16::from_be_bytes(r.get(..2).ok_or_else(bad)?.try_into().unwrap()) as usize;
        let name = String::from_utf8(r.get(2..2 + n).ok_or_else(bad)?.to_vec()).map_err(|_| bad())?;
        r = &r[2 + n..];
        let len = u32::from_be_bytes(r.get(..4).ok_or_else(bad)?.try_into().unwrap()) as usize;
        out.push((name, r.get(4..4 + len).ok_or_else(bad)?.to_vec()));
        r = &r[4 + len..];
    }
    Ok(out)
}

fn request_keyring(socket: &Path, request: &str, tenant: &str) -> io::Result<Keyring> {
    let mut s = UnixStream::connect(socket)?;
    s.write_all(format!("{request}\n").as_bytes())?;
    let mut buf = Zeroizing::new(Vec::new());
    s.read_to_end(&mut buf)?;
    if buf.is_empty() || buf.len() % 36 != 0 {
        return Err(err(io::ErrorKind::PermissionDenied, "keyd refused the request"));
    }
    let mut deks: Vec<(u32, [u8; 32])> = buf
        .chunks(36)
        .map(|c| {
            (
                u32::from_le_bytes(c[..4].try_into().unwrap()),
                c[4..].try_into().unwrap(),
            )
        })
        .collect();
    let ring = Keyring::new(tenant, &deks);
    deks.iter_mut().for_each(|(_, k)| k.zeroize());
    Ok(ring)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lifecycle_rotation_and_recovery() {
        let d = tempfile::tempdir().unwrap();
        let rk = init(d.path()).unwrap();
        assert!(init(d.path()).is_err(), "init only once");
        check_recovery_key(d.path(), &rk.to_uppercase()).unwrap();
        assert!(check_recovery_key(d.path(), &format_recovery_key(&[0; 32])).is_err());
        assert_eq!(create_tenant(d.path(), "acme").unwrap(), 1);
        assert!(create_tenant(d.path(), "acme").is_err());
        assert_eq!(rotate_tenant(d.path(), "acme").unwrap(), 2);
        assert!(create_tenant(d.path(), "../x").is_err());
        let before: Vec<_> = tenant_deks(d.path(), "acme")
            .unwrap()
            .into_iter()
            .map(|(v, k)| (v, *k))
            .collect();
        assert_eq!(before.len(), 2);

        // DR: machine-sealed KEK lost, rebuilt from escrow + recovery key
        fs::remove_file(d.path().join("kek.local")).unwrap();
        assert!(tenant_deks(d.path(), "acme").is_err());
        assert!(recover(d.path(), &format_recovery_key(&[1; 32])).is_err());
        recover(d.path(), &rk).unwrap();
        let after: Vec<_> = tenant_deks(d.path(), "acme")
            .unwrap()
            .into_iter()
            .map(|(v, k)| (v, *k))
            .collect();
        assert_eq!(before, after);
    }

    #[test]
    fn socket_ensure_and_escrow() {
        let d = tempfile::tempdir().unwrap();
        init(d.path()).unwrap();
        let sock = d.path().join("k.sock");
        let me = unsafe { libc::getuid() };
        let l = UnixListener::bind(&sock).unwrap();
        let dir = d.path().to_owned();
        let srv = std::thread::spawn(move || {
            for _ in 0..4 {
                let _ = handle(l.accept().unwrap().0, &dir, me);
            }
        });
        assert!(fetch_keyring(&sock, "newco").is_err(), "plain get does not create");
        let a = ensure_keyring(&sock, "newco").unwrap();
        let b = ensure_keyring(&sock, "newco").unwrap();
        assert_eq!(a.chunk_id(b"x"), b.chunk_id(b"x"), "ensure is idempotent");
        let esc = fetch_escrow(&sock, "newco").unwrap();
        assert_eq!(esc, export_escrow(d.path(), "newco").unwrap());
        srv.join().unwrap();
    }

    #[test]
    fn escrow_roundtrip_dr() {
        let a = tempfile::tempdir().unwrap();
        let rk = init(a.path()).unwrap();
        create_tenant(a.path(), "acme").unwrap();
        rotate_tenant(a.path(), "acme").unwrap();
        let esc = export_escrow(a.path(), "acme").unwrap();
        assert_eq!(esc.len(), 3);
        let b = tempfile::tempdir().unwrap();
        import_escrow(b.path(), &esc).unwrap();
        import_escrow(b.path(), &esc).unwrap(); // idempotent
        assert!(tenant_deks(b.path(), "acme").is_err(), "no KEK before recover");
        recover(b.path(), &rk).unwrap();
        let k = |d: &Path| {
            tenant_deks(d, "acme")
                .unwrap()
                .into_iter()
                .map(|(v, k)| (v, *k))
                .collect::<Vec<_>>()
        };
        assert_eq!(k(a.path()), k(b.path()));
        assert!(import_escrow(b.path(), &[("../x".into(), vec![])]).is_err());
        assert!(import_escrow(b.path(), &[("kek.recovery".into(), vec![1])]).is_err());
    }

    #[test]
    fn socket_checks_peer_uid() {
        let d = tempfile::tempdir().unwrap();
        init(d.path()).unwrap();
        create_tenant(d.path(), "acme").unwrap();
        let sock = d.path().join("keyd.sock");
        let me = unsafe { libc::getuid() };
        for (allow, ok) in [(me, true), (me + 1, false)] {
            let l = UnixListener::bind(&sock).unwrap();
            let dir = d.path().to_owned();
            let t = std::thread::spawn(move || handle(l.accept().unwrap().0, &dir, allow));
            let r = fetch_keyring(&sock, "acme");
            assert_eq!(r.is_ok(), ok);
            assert_eq!(t.join().unwrap().is_ok(), ok);
            if let Ok(ring) = r {
                let deks: Vec<_> = tenant_deks(d.path(), "acme")
                    .unwrap()
                    .into_iter()
                    .map(|(v, k)| (v, *k))
                    .collect();
                assert_eq!(ring.chunk_id(b"x"), Keyring::new("acme", &deks).chunk_id(b"x"));
            }
            fs::remove_file(&sock).unwrap();
        }
    }
}
