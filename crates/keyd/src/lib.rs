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

/// New DEK version; older versions stay available for reading. Refused for
/// tenants whose keys were imported from a replication primary (their DEKs are
/// the primary's; a local version would be unknown there and break replication).
pub fn rotate_tenant(dir: &Path, tenant: &str) -> io::Result<u32> {
    if tenant_dir(dir, tenant)?.join(ORIGIN).exists() {
        return Err(err(
            io::ErrorKind::PermissionDenied,
            format!("tenant {tenant} is replicated from a primary: rotate there and re-export the keys"),
        ));
    }
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

/// Upper bound for an `attach-escrow` body (recovery key + escrow files).
pub const MAX_ATTACH: usize = 256 << 10;

/// Attach an offsite copy to a running appliance (web UI, docs/control-plane.md
/// "Attach an offsite copy"): the escrowed `kek.recovery` of the *old*
/// appliance is opened with its recovery key, which unwraps the tenant's DEKs;
/// they are re-wrapped under this appliance's KEK. Nothing of the old KEK or
/// the recovery key is stored. Refused if the tenant already has other keys
/// here or was replicated; idempotent for the same keys. Returns the versions.
pub fn attach_escrow(
    dir: &Path,
    tenant: &str,
    recovery_key: &str,
    files: &[(String, Vec<u8>)],
) -> io::Result<Vec<u32>> {
    let td = tenant_dir(dir, tenant)?;
    let blob = files
        .iter()
        .find(|(n, _)| n == "kek.recovery")
        .ok_or_else(|| err(io::ErrorKind::InvalidInput, "escrow has no kek.recovery"))?;
    let rk = parse_recovery_key(recovery_key)?;
    let old_kek = Zeroizing::new(unwrap_key(&rk, &blob.1, "kek-recovery").map_err(|_| {
        err(
            io::ErrorKind::PermissionDenied,
            "the recovery key does not open the escrowed KEK",
        )
    })?);
    let prefix = format!("tenants/{tenant}/dek.");
    let mut deks = Vec::new();
    for (name, bytes) in files.iter().filter(|(n, _)| n != "kek.recovery") {
        let v: u32 = name
            .strip_prefix(&prefix)
            .and_then(|v| v.parse().ok())
            .ok_or_else(|| err(io::ErrorKind::InvalidInput, format!("unexpected escrow file {name:?}")))?;
        deks.push((v, Zeroizing::new(unwrap_key(&old_kek, bytes, &label(tenant, v))?)));
    }
    if deks.is_empty() {
        return Err(err(
            io::ErrorKind::NotFound,
            format!("escrow has no keys of tenant {tenant}"),
        ));
    }
    if td.join(ORIGIN).exists() {
        return Err(err(
            io::ErrorKind::PermissionDenied,
            format!("tenant {tenant} is replicated from a primary"),
        ));
    }
    let have = versions(dir, tenant)?;
    let existing = if have.is_empty() {
        vec![]
    } else {
        tenant_deks(dir, tenant)?
    };
    for (v, k) in &existing {
        if !deks.iter().any(|(x, n)| x == v && n[..] == k[..]) {
            return Err(err(
                io::ErrorKind::AlreadyExists,
                format!("tenant {tenant} has other keys on this appliance (DEK v{v})"),
            ));
        }
    }
    let kek = unseal(dir)?;
    fs::create_dir_all(&td)?;
    for (v, k) in &deks {
        if !have.contains(v) {
            write_atomic(&td.join(format!("dek.{v}")), &wrap_key(&kek, k, &label(tenant, *v)))?;
        }
    }
    versions(dir, tenant)
}

/// Encodes escrow files like the `escrow` answer (see [`parse_escrow`]).
pub fn encode_escrow(files: &[(String, Vec<u8>)]) -> Vec<u8> {
    let mut out = Vec::new();
    for (name, bytes) in files {
        out.extend_from_slice(&(name.len() as u16).to_be_bytes());
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        out.extend_from_slice(bytes);
    }
    out
}

// ---------------------------------------------------------------- replication (docs/replication.md §5)

/// X25519 secret key of this keyd for receiving DEK exports, wrapped under the KEK.
const REPLICA_KEY: &str = "replica-x25519";
/// `tenants/<t>/origin`: the tenant's DEKs were imported from this primary.
const ORIGIN: &str = "origin";
const EXPORT_MAGIC: &[u8; 8] = b"NXDEKX1\0";
/// Upper bound for an export blob (a tenant with ~1000 key versions).
pub const MAX_EXPORT: usize = 64 << 10;

fn replica_secret(dir: &Path) -> io::Result<crypto_box::SecretKey> {
    let kek = unseal(dir)?;
    let path = dir.join(REPLICA_KEY);
    let sk = match fs::read(&path) {
        Ok(blob) => Zeroizing::new(unwrap_key(&kek, &blob, REPLICA_KEY)?),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            let k = Zeroizing::new(generate_key());
            write_atomic(&path, &wrap_key(&kek, &k, REPLICA_KEY))?;
            k
        }
        Err(e) => return Err(e),
    };
    Ok(crypto_box::SecretKey::from_bytes(*sk))
}

/// Public key a primary seals DEK exports to (created on first use).
pub fn replica_pubkey(dir: &Path) -> io::Result<[u8; 32]> {
    Ok(*replica_secret(dir)?.public_key().as_bytes())
}

/// All DEK versions of `tenant`, sealed (anonymous X25519 box) to a secondary
/// keyd's public key: `NXDEKX1\0 | u8 len | tenant | N x (u32 LE version, DEK)`.
/// The caller (the scheduler) has checked the approved quorum request.
pub fn export_for(dir: &Path, tenant: &str, peer_pub: &[u8; 32]) -> io::Result<Vec<u8>> {
    let deks = tenant_deks(dir, tenant)?;
    let mut pt = Zeroizing::new(Vec::with_capacity(9 + tenant.len() + deks.len() * 36));
    pt.extend_from_slice(EXPORT_MAGIC);
    pt.push(tenant.len() as u8);
    pt.extend_from_slice(tenant.as_bytes());
    for (v, k) in &deks {
        pt.extend_from_slice(&v.to_le_bytes());
        pt.extend_from_slice(&k[..]);
    }
    crypto_box::PublicKey::from_bytes(*peer_pub)
        .seal(&mut rand::rngs::OsRng, &pt)
        .map_err(|_| err(io::ErrorKind::Other, "sealing failed"))
}

/// Opens an export with this keyd's replication key: (tenant, DEKs).
fn open_export(dir: &Path, blob: &[u8]) -> io::Result<(String, Vec<(u32, Key)>)> {
    let bad = || err(io::ErrorKind::InvalidData, "malformed key export");
    if blob.len() > MAX_EXPORT {
        return Err(bad());
    }
    let pt = Zeroizing::new(
        replica_secret(dir)?
            .unseal(blob)
            .map_err(|_| err(io::ErrorKind::InvalidData, "key export not sealed to this appliance"))?,
    );
    let rest = pt.strip_prefix(EXPORT_MAGIC.as_slice()).ok_or_else(bad)?;
    let (&n, rest) = rest.split_first().ok_or_else(bad)?;
    let tenant = std::str::from_utf8(rest.get(..n as usize).ok_or_else(bad)?).map_err(|_| bad())?;
    let recs = &rest[n as usize..];
    if recs.is_empty() || recs.len() % 36 != 0 {
        return Err(bad());
    }
    let deks = recs
        .chunks(36)
        .map(|c| {
            let mut k = Zeroizing::new([0u8; 32]);
            k.copy_from_slice(&c[4..]);
            (u32::from_le_bytes(c[..4].try_into().unwrap()), k)
        })
        .collect();
    Ok((tenant.to_owned(), deks))
}

/// Imports a DEK export for `tenant` from the primary `origin` (its certificate
/// fingerprint): every version is stored wrapped under this keyd's KEK. Refused
/// if the tenant has local keys, keys from another origin, or a version with a
/// different key; idempotent otherwise. Returns all versions now present.
pub fn import_sealed(dir: &Path, tenant: &str, origin: &str, blob: &[u8]) -> io::Result<Vec<u32>> {
    if origin.is_empty() || origin.len() > 128 || !origin.bytes().all(|b| b.is_ascii_alphanumeric() || b == b':') {
        return Err(err(io::ErrorKind::InvalidInput, "invalid origin"));
    }
    let td = tenant_dir(dir, tenant)?;
    let (t, deks) = open_export(dir, blob)?;
    if t != tenant {
        return Err(err(
            io::ErrorKind::InvalidData,
            format!("key export is for tenant {t:?}, not {tenant:?}"),
        ));
    }
    let have = versions(dir, tenant)?;
    match fs::read_to_string(td.join(ORIGIN)) {
        Ok(o) if o.trim() == origin => {}
        Ok(o) => {
            return Err(err(
                io::ErrorKind::PermissionDenied,
                format!("tenant {tenant} is replicated from another primary ({})", o.trim()),
            ))
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound && have.is_empty() => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            return Err(err(
                io::ErrorKind::PermissionDenied,
                format!("tenant {tenant} has local keys: it cannot be replicated into"),
            ))
        }
        Err(e) => return Err(e),
    }
    let kek = unseal(dir)?;
    let existing: Vec<(u32, Key)> = if have.is_empty() {
        vec![]
    } else {
        tenant_deks(dir, tenant)?
    };
    for (v, k) in &deks {
        if let Some((_, old)) = existing.iter().find(|(x, _)| x == v) {
            if old[..] != k[..] {
                return Err(err(
                    io::ErrorKind::AlreadyExists,
                    format!("tenant {tenant}: DEK v{v} differs from the imported one"),
                ));
            }
        }
    }
    fs::create_dir_all(&td)?;
    if have.is_empty() {
        write_atomic(&td.join(ORIGIN), format!("{origin}\n").as_bytes())?;
    }
    for (v, k) in &deks {
        if !have.contains(v) {
            write_atomic(&td.join(format!("dek.{v}")), &wrap_key(&kek, k, &label(tenant, *v)))?;
        }
    }
    versions(dir, tenant)
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
/// - `replica-pubkey\n` → 32-byte X25519 public key for DEK exports (docs/replication.md)
/// - `export-for <tenant> <peer-pubkey hex> <quorum id>\n` → DEK export sealed to that key
/// - `import-sealed <tenant> <origin> <len>\n` + `len` bytes → N x u32 LE versions now present
/// - `attach-escrow <tenant> <len>\n` + `len` bytes (recovery key line, then escrow files
///   encoded like the `escrow` answer) → N x u32 LE versions now present ([`attach_escrow`])
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
    let mut r = BufReader::new(&s);
    let mut line = String::new();
    (&mut r).take(256).read_line(&mut line)?;
    // zeroized: an `attach-escrow` body carries the recovery key
    let body = Zeroizing::new(match body_len(&line)? {
        Some(n) => {
            let mut b = vec![0u8; n];
            r.read_exact(&mut b)?;
            b
        }
        None => Vec::new(),
    });
    s.write_all(&answer_with_body(dir, &line, &body)?)
}

/// `import-sealed …` and `attach-escrow …` carry a body of the length given last on the line.
fn body_len(line: &str) -> io::Result<Option<usize>> {
    let line = line.trim_end_matches('\n');
    let (rest, max) = match (line.strip_prefix("import-sealed "), line.strip_prefix("attach-escrow ")) {
        (Some(r), _) => (Some(r), MAX_EXPORT),
        (_, Some(r)) => (Some(r), MAX_ATTACH),
        _ => (None, 0),
    };
    match rest {
        Some(rest) => {
            let n: usize = rest
                .rsplit(' ')
                .next()
                .and_then(|n| n.parse().ok())
                .filter(|n| (1..=max).contains(n))
                .ok_or_else(|| err(io::ErrorKind::InvalidInput, "invalid body length"))?;
            Ok(Some(n))
        }
        None => Ok(None),
    }
}

/// The answer to one request line without a body (see `serve`); errors mean "no answer".
pub fn answer(dir: &Path, line: &str) -> io::Result<Zeroizing<Vec<u8>>> {
    answer_with_body(dir, line, &[])
}

/// The answer to one request line and its body (`import-sealed`).
pub fn answer_with_body(dir: &Path, line: &str, body: &[u8]) -> io::Result<Zeroizing<Vec<u8>>> {
    let line = line.trim_end_matches('\n');
    if line == "replica-pubkey" {
        return Ok(Zeroizing::new(replica_pubkey(dir)?.to_vec()));
    }
    if let Some(rest) = line.strip_prefix("export-for ") {
        let [tenant, pk, quorum] = rest.split(' ').collect::<Vec<_>>()[..] else {
            return Err(err(
                io::ErrorKind::InvalidInput,
                "export-for <tenant> <pubkey> <quorum>",
            ));
        };
        let pk: [u8; 32] = parse_hex(pk).ok_or_else(|| err(io::ErrorKind::InvalidInput, "invalid public key"))?;
        let q: u64 = quorum
            .parse()
            .map_err(|_| err(io::ErrorKind::InvalidInput, "invalid quorum id"))?;
        let blob = export_for(dir, tenant, &pk)?;
        eprintln!(
            "keyd: exported DEKs of tenant {tenant} to replication peer key {} (quorum {q})",
            hex(&pk)
        );
        return Ok(Zeroizing::new(blob));
    }
    if let Some(rest) = line.strip_prefix("import-sealed ") {
        let [tenant, origin, _len] = rest.split(' ').collect::<Vec<_>>()[..] else {
            return Err(err(
                io::ErrorKind::InvalidInput,
                "import-sealed <tenant> <origin> <len>",
            ));
        };
        let vs = import_sealed(dir, tenant, origin, body)?;
        eprintln!("keyd: imported DEKs of tenant {tenant} from {origin}: versions {vs:?}");
        return Ok(Zeroizing::new(vs.iter().flat_map(|v| v.to_le_bytes()).collect()));
    }
    if let Some(rest) = line.strip_prefix("attach-escrow ") {
        let [tenant, _len] = rest.split(' ').collect::<Vec<_>>()[..] else {
            return Err(err(io::ErrorKind::InvalidInput, "attach-escrow <tenant> <len>"));
        };
        let nl = body
            .iter()
            .position(|b| *b == b'\n')
            .ok_or_else(|| err(io::ErrorKind::InvalidInput, "attach-escrow: no recovery key line"))?;
        let rk = Zeroizing::new(String::from_utf8_lossy(&body[..nl]).into_owned());
        let vs = attach_escrow(dir, tenant, &rk, &parse_escrow(&body[nl + 1..])?)?;
        eprintln!("keyd: attached DEKs of tenant {tenant} from an offsite escrow: versions {vs:?}");
        return Ok(Zeroizing::new(vs.iter().flat_map(|v| v.to_le_bytes()).collect()));
    }
    let tenant = match line.split_once(' ') {
        Some(("escrow", t)) => {
            return Ok(Zeroizing::new(encode_escrow(&export_escrow(dir, t)?)));
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

fn request_raw(socket: &Path, line: &str, body: &[u8]) -> io::Result<Vec<u8>> {
    let mut s = UnixStream::connect(socket)?;
    s.write_all(format!("{line}\n").as_bytes())?;
    s.write_all(body)?;
    let mut buf = Vec::new();
    s.read_to_end(&mut buf)?;
    if buf.is_empty() {
        return Err(err(io::ErrorKind::PermissionDenied, "keyd refused the request"));
    }
    Ok(buf)
}

/// Secondary: this appliance's X25519 public key for DEK exports.
pub fn fetch_replica_pubkey(socket: &Path) -> io::Result<[u8; 32]> {
    request_raw(socket, "replica-pubkey", &[])?
        .try_into()
        .map_err(|_| err(io::ErrorKind::InvalidData, "malformed keyd answer"))
}

/// Primary (scheduler, after an approved quorum request): DEKs of `tenant`
/// sealed to a secondary keyd's public key.
pub fn request_export(socket: &Path, tenant: &str, peer_pub: &[u8; 32], quorum_id: i64) -> io::Result<Vec<u8>> {
    request_raw(
        socket,
        &format!("export-for {tenant} {} {quorum_id}", hex(peer_pub)),
        &[],
    )
}

/// nexus-offsite `attach`: hands the escrow fetched from the offsite target and
/// the recovery key typed in the web UI to keyd ([`attach_escrow`]).
pub fn request_attach(
    socket: &Path,
    tenant: &str,
    recovery_key: &str,
    files: &[(String, Vec<u8>)],
) -> io::Result<Vec<u32>> {
    let mut body = Zeroizing::new(format!("{}\n", recovery_key.trim()).into_bytes());
    body.extend_from_slice(&encode_escrow(files));
    let b = request_raw(socket, &format!("attach-escrow {tenant} {}", body.len()), &body)?;
    if b.len() % 4 != 0 {
        return Err(err(io::ErrorKind::InvalidData, "malformed keyd answer"));
    }
    Ok(b.chunks(4).map(|c| u32::from_le_bytes(c.try_into().unwrap())).collect())
}

/// Secondary (nexus-replica): import a DEK export received from the primary.
pub fn request_import(socket: &Path, tenant: &str, origin: &str, blob: &[u8]) -> io::Result<Vec<u32>> {
    let b = request_raw(socket, &format!("import-sealed {tenant} {origin} {}", blob.len()), blob)?;
    if b.len() % 4 != 0 {
        return Err(err(io::ErrorKind::InvalidData, "malformed keyd answer"));
    }
    Ok(b.chunks(4).map(|c| u32::from_le_bytes(c.try_into().unwrap())).collect())
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

    /// Attach (web UI DR): the old appliance's escrow + its recovery key into a
    /// running appliance with its own KEK, over the socket.
    #[test]
    fn attach_escrow_rewraps_under_local_kek() {
        let a = tempfile::tempdir().unwrap();
        let rk = init(a.path()).unwrap();
        create_tenant(a.path(), "acme").unwrap();
        rotate_tenant(a.path(), "acme").unwrap();
        let deks = |d: &Path| -> Vec<(u32, [u8; 32])> {
            tenant_deks(d, "acme")
                .unwrap()
                .into_iter()
                .map(|(v, k)| (v, *k))
                .collect()
        };
        let old = deks(a.path());
        let esc = export_escrow(a.path(), "acme").unwrap();

        let b = tempfile::tempdir().unwrap();
        init(b.path()).unwrap();
        create_tenant(b.path(), "other").unwrap();
        let sock = b.path().join("k.sock");
        let me = unsafe { libc::getuid() };
        let l = UnixListener::bind(&sock).unwrap();
        let dir = b.path().to_owned();
        let srv = std::thread::spawn(move || {
            for _ in 0..4 {
                let _ = handle(l.accept().unwrap().0, &dir, me);
            }
        });
        assert!(
            request_attach(&sock, "acme", &format_recovery_key(&[9; 32]), &esc).is_err(),
            "wrong recovery key"
        );
        assert!(
            request_attach(&sock, "other", &rk, &esc).is_err(),
            "files of another tenant"
        );
        assert_eq!(request_attach(&sock, "acme", &rk, &esc).unwrap(), vec![1, 2]);
        assert_eq!(
            request_attach(&sock, "acme", &rk, &esc).unwrap(),
            vec![1, 2],
            "idempotent"
        );
        srv.join().unwrap();
        assert_eq!(old, deks(b.path()), "same DEKs, wrapped under b's KEK");
        assert_ne!(
            fs::read(a.path().join("kek.recovery")).unwrap(),
            fs::read(b.path().join("kek.recovery")).unwrap(),
            "b keeps its own recovery escrow"
        );
        // a tenant with different local keys is refused
        let c = tempfile::tempdir().unwrap();
        init(c.path()).unwrap();
        create_tenant(c.path(), "acme").unwrap();
        assert!(attach_escrow(c.path(), "acme", &rk, &esc).is_err());
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

    fn deks(d: &Path, t: &str) -> Vec<(u32, [u8; 32])> {
        tenant_deks(d, t).unwrap().into_iter().map(|(v, k)| (v, *k)).collect()
    }

    /// docs/replication.md §5: DEKs travel only sealed to the secondary keyd and
    /// end up wrapped under the secondary's own KEK.
    #[test]
    fn replication_export_import() {
        let (p, s) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        init(p.path()).unwrap();
        init(s.path()).unwrap();
        create_tenant(p.path(), "acme").unwrap();
        create_tenant(p.path(), "other").unwrap();
        create_tenant(s.path(), "local").unwrap();
        let spk = replica_pubkey(s.path()).unwrap();
        assert_eq!(spk, replica_pubkey(s.path()).unwrap(), "key pair is persistent");
        let blob = export_for(p.path(), "acme", &spk).unwrap();
        let raw: Vec<u8> = deks(p.path(), "acme").iter().flat_map(|(_, k)| k.to_vec()).collect();
        assert!(!blob.windows(32).any(|w| w == &raw[..32]), "no DEK in clear");
        // another keyd cannot open it
        let x = tempfile::tempdir().unwrap();
        init(x.path()).unwrap();
        assert!(import_sealed(x.path(), "acme", "fp1", &blob).is_err());
        // wrong tenant name, local tenant, invalid origin
        assert!(import_sealed(s.path(), "other", "fp1", &blob).is_err());
        assert!(import_sealed(s.path(), "local", "fp1", &export_for(p.path(), "acme", &spk).unwrap()).is_err());
        assert!(import_sealed(s.path(), "acme", "../x", &blob).is_err());
        assert_eq!(import_sealed(s.path(), "acme", "fp1", &blob).unwrap(), vec![1]);
        assert_eq!(
            import_sealed(s.path(), "acme", "fp1", &blob).unwrap(),
            vec![1],
            "idempotent"
        );
        assert_eq!(deks(s.path(), "acme"), deks(p.path(), "acme"));
        assert!(
            import_sealed(s.path(), "acme", "fp2", &blob).is_err(),
            "another primary cannot take over"
        );
        assert!(
            rotate_tenant(s.path(), "acme").is_err(),
            "no local rotation of a replicated tenant"
        );
        // primary rotates: the re-export adds v2
        rotate_tenant(p.path(), "acme").unwrap();
        let blob2 = export_for(p.path(), "acme", &spk).unwrap();
        assert_eq!(import_sealed(s.path(), "acme", "fp1", &blob2).unwrap(), vec![1, 2]);
        assert_eq!(deks(s.path(), "acme"), deks(p.path(), "acme"));
        // a primary that changed v1 under the same origin is refused
        let p2 = tempfile::tempdir().unwrap();
        init(p2.path()).unwrap();
        create_tenant(p2.path(), "acme").unwrap();
        assert!(import_sealed(s.path(), "acme", "fp1", &export_for(p2.path(), "acme", &spk).unwrap()).is_err());
        // the wrapped files are under the secondary KEK, not the primary's
        assert_ne!(
            fs::read(s.path().join("tenants/acme/dek.1")).unwrap(),
            fs::read(p.path().join("tenants/acme/dek.1")).unwrap()
        );
        assert!(import_sealed(s.path(), "acme", "fp1", &[0u8; 100]).is_err());
    }

    #[test]
    fn replication_socket_verbs() {
        let (p, s) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        init(p.path()).unwrap();
        init(s.path()).unwrap();
        create_tenant(p.path(), "acme").unwrap();
        let me = unsafe { libc::getuid() };
        let start = |dir: &Path, n: usize| {
            let sock = dir.join("k.sock");
            let l = UnixListener::bind(&sock).unwrap();
            let dir = dir.to_owned();
            let t = std::thread::spawn(move || {
                for _ in 0..n {
                    let _ = handle(l.accept().unwrap().0, &dir, me);
                }
            });
            (sock, t)
        };
        let (ss, st) = start(s.path(), 3);
        let (ps, pt) = start(p.path(), 2);
        let spk = fetch_replica_pubkey(&ss).unwrap();
        let blob = request_export(&ps, "acme", &spk, 7).unwrap();
        assert!(request_export(&ps, "nope", &spk, 7).is_err());
        assert_eq!(request_import(&ss, "acme", "fp1", &blob).unwrap(), vec![1]);
        let ring = fetch_keyring(&ss, "acme").unwrap();
        assert_eq!(
            ring.chunk_id(b"x"),
            Keyring::new("acme", &deks(p.path(), "acme")).chunk_id(b"x")
        );
        st.join().unwrap();
        pt.join().unwrap();
        assert!(body_len("import-sealed a b 0\n").is_err());
        assert!(body_len(&format!("import-sealed a b {}\n", MAX_EXPORT + 1)).is_err());
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
