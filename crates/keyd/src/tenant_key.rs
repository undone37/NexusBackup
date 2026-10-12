//! Optional per-tenant recovery key (Phase 17e, docs/control-plane.md
//! "Tenant recovery key"). Lets one tenant rebuild its data from its offsite
//! copy without the appliance-wide recovery key.
//!
//! The tenant recovery key is 32 random bytes, written like the appliance
//! recovery key (16 groups of 4 hex digits). It is the X25519 secret key of a
//! key pair; the appliance keeps only the public key (`tenants/<t>/tenant-recovery.pub`,
//! set by the scheduler from the catalog), so every DEK version, including
//! versions created later by a rotation, is sealed to it without the secret:
//! ```text
//! tenants/<t>/tenant-escrow.<kid>.<v>   sealed box (X25519 + XSalsa20-Poly1305, as for replication exports)
//!                                       of  NXTRK1\0\0 | u8 len | tenant | u32 LE v | DEK v
//! ```
//! `kid` = the first 16 hex digits of the public key: a replaced key gets new
//! file names, so the offsite copy (append-only uploads) never mixes keys.
//! The plaintext names the tenant and the version, so a file renamed to
//! another tenant or version is refused.

use crate::{err, label, tenant_dir, versions, Key};
use chunkstore::crypto::{generate_key, hex, unwrap_key, wrap_key};
use chunkstore::store::write_atomic;
use std::fs;
use std::io;
use std::path::Path;
use zeroize::Zeroizing;

pub(crate) const PUB: &str = "tenant-recovery.pub";
const PREFIX: &str = "tenant-escrow.";
const MAGIC: &[u8; 8] = b"NXTRK1\0\0";

/// Short id of a tenant recovery key (its public key's first 16 hex digits).
pub fn key_id(public: &[u8; 32]) -> String {
    hex(public)[..16].to_owned()
}

/// X25519 public key of a tenant recovery key as typed (see `crate::parse_recovery_key`).
pub fn public_of(recovery_key: &str) -> io::Result<[u8; 32]> {
    let sk = crate::parse_recovery_key(recovery_key)?;
    Ok(*crypto_box::SecretKey::from_bytes(*sk).public_key().as_bytes())
}

/// A new tenant recovery key and its public key (the web-api generates its own
/// with `catalog::tenant_key::generate`, same format; this one is for tests and tools).
pub fn generate() -> (String, [u8; 32]) {
    let k = Zeroizing::new(generate_key());
    let s = crate::format_recovery_key(&k);
    let p = public_of(&s).expect("generated keys parse");
    (s, p)
}

fn file_name(kid: &str, v: u32) -> String {
    format!("{PREFIX}{kid}.{v}")
}

fn seal(public: &[u8; 32], tenant: &str, v: u32, dek: &[u8; 32]) -> io::Result<Vec<u8>> {
    let mut pt = Zeroizing::new(Vec::with_capacity(8 + 1 + tenant.len() + 36));
    pt.extend_from_slice(MAGIC);
    pt.push(tenant.len() as u8);
    pt.extend_from_slice(tenant.as_bytes());
    pt.extend_from_slice(&v.to_le_bytes());
    pt.extend_from_slice(dek);
    crypto_box::PublicKey::from_bytes(*public)
        .seal(&mut rand::rngs::OsRng, &pt)
        .map_err(|_| err(io::ErrorKind::Other, "sealing failed"))
}

/// The tenant's recovery public key, if one is set.
pub fn current(dir: &Path, tenant: &str) -> io::Result<Option<[u8; 32]>> {
    match fs::read(tenant_dir(dir, tenant)?.join(PUB)) {
        Ok(b) => b
            .try_into()
            .map(Some)
            .map_err(|_| err(io::ErrorKind::InvalidData, "tenant-recovery.pub corrupt")),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// Called whenever DEK `v` of `tenant` is stored (creation, rotation, replica
/// import): seals it to the tenant recovery key, if one is set.
pub(crate) fn on_new_dek(dir: &Path, tenant: &str, v: u32, dek: &[u8; 32]) -> io::Result<()> {
    if let Some(p) = current(dir, tenant)? {
        let td = tenant_dir(dir, tenant)?;
        write_atomic(&td.join(file_name(&key_id(&p), v)), &seal(&p, tenant, v, dek)?)?;
    }
    Ok(())
}

/// Sets (`Some`), replaces or removes (`None`) the tenant recovery key: the
/// old escrow files go, every DEK version is sealed to the new public key.
/// Idempotent (also repairs missing files). Returns whether the key changed.
pub fn set(dir: &Path, tenant: &str, public: Option<&[u8; 32]>) -> io::Result<bool> {
    let td = tenant_dir(dir, tenant)?;
    let vs = versions(dir, tenant)?;
    if vs.is_empty() {
        return Err(err(io::ErrorKind::NotFound, format!("no tenant {tenant}")));
    }
    let old = current(dir, tenant)?;
    let changed = old.as_ref() != public;
    if changed {
        for e in fs::read_dir(&td)? {
            let n = e?.file_name();
            if n.to_str().is_some_and(|n| n.starts_with(PREFIX)) {
                fs::remove_file(td.join(n))?;
            }
        }
        match public {
            Some(p) => write_atomic(&td.join(PUB), p)?,
            None => fs::remove_file(td.join(PUB))?,
        }
    }
    let Some(p) = public else { return Ok(changed) };
    let kid = key_id(p);
    let missing: Vec<u32> = vs
        .into_iter()
        .filter(|v| !td.join(file_name(&kid, *v)).exists())
        .collect();
    if !missing.is_empty() {
        for (v, dek) in crate::tenant_deks(dir, tenant)? {
            if missing.contains(&v) {
                write_atomic(&td.join(file_name(&kid, v)), &seal(p, tenant, v, &dek)?)?;
            }
        }
    }
    Ok(changed)
}

/// Escrow files of the current tenant recovery key: (`tenant-escrow.<kid>.<v>`, bytes).
pub(crate) fn escrow_files(dir: &Path, tenant: &str) -> io::Result<Vec<(String, Vec<u8>)>> {
    let Some(p) = current(dir, tenant)? else {
        return Ok(vec![]);
    };
    let td = tenant_dir(dir, tenant)?;
    let kid = key_id(&p);
    let mut out = Vec::new();
    for v in versions(dir, tenant)? {
        match fs::read(td.join(file_name(&kid, v))) {
            Ok(b) => out.push((file_name(&kid, v), b)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {} // sealed on the next `set`
            Err(e) => return Err(e),
        }
    }
    Ok(out)
}

/// True for names of tenant escrow files (`tenant-escrow.<kid>.<v>`).
pub fn is_escrow_file(name: &str) -> bool {
    name.starts_with(PREFIX)
}

/// Tenant-level DR: opens the escrow files (`(file name, bytes)`, e.g. as
/// listed in `keys/tenants/<t>/` offsite) that belong to `recovery_key`.
/// Files of other keys are ignored; a file that does not open or names another
/// tenant or version is an error. Never touches the appliance escrow.
pub fn open(tenant: &str, recovery_key: &str, files: &[(String, Vec<u8>)]) -> io::Result<Vec<(u32, Key)>> {
    let sk = crypto_box::SecretKey::from_bytes(*crate::parse_recovery_key(recovery_key)?);
    let kid = key_id(sk.public_key().as_bytes());
    let bad = |n: &str| {
        err(
            io::ErrorKind::InvalidData,
            format!("tenant escrow file {n} is not valid"),
        )
    };
    let mut out: Vec<(u32, Key)> = Vec::new();
    for (name, blob) in files {
        let Some(v) = name
            .strip_prefix(PREFIX)
            .and_then(|r| r.strip_prefix(kid.as_str()))
            .and_then(|r| r.strip_prefix('.'))
            .and_then(|v| v.parse::<u32>().ok())
        else {
            continue;
        };
        let pt = Zeroizing::new(sk.unseal(blob).map_err(|_| bad(name))?);
        let rest = pt.strip_prefix(MAGIC.as_slice()).ok_or_else(|| bad(name))?;
        let (&n, rest) = rest.split_first().ok_or_else(|| bad(name))?;
        let n = n as usize;
        if rest.len() != n + 36 || &rest[..n] != tenant.as_bytes() || rest[n..n + 4] != v.to_le_bytes() {
            return Err(bad(name));
        }
        let mut k = Zeroizing::new([0u8; 32]);
        k.copy_from_slice(&rest[n + 4..]);
        out.push((v, k));
    }
    if out.is_empty() {
        return Err(err(
            io::ErrorKind::NotFound,
            format!("no escrow of tenant {tenant} for this tenant recovery key"),
        ));
    }
    out.sort_by_key(|(v, _)| *v);
    Ok(out)
}

/// Tenant-level DR on an initialized appliance (its own KEK): stores the DEKs
/// opened with [`open`] wrapped under this keyd's KEK. Refused if the tenant
/// already has a version with a different key; idempotent otherwise.
pub fn install(dir: &Path, tenant: &str, deks: &[(u32, Key)]) -> io::Result<Vec<u32>> {
    let kek = crate::unseal(dir)?;
    let td = tenant_dir(dir, tenant)?;
    fs::create_dir_all(&td)?;
    for (v, k) in deks {
        let path = td.join(format!("dek.{v}"));
        match fs::read(&path) {
            Ok(blob) => {
                if *Zeroizing::new(unwrap_key(&kek, &blob, &label(tenant, *v))?) != **k {
                    return Err(err(
                        io::ErrorKind::AlreadyExists,
                        format!("tenant {tenant}: DEK v{v} exists with a different key"),
                    ));
                }
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                write_atomic(&path, &wrap_key(&kek, k, &label(tenant, *v)))?;
                on_new_dek(dir, tenant, *v, k)?;
            }
            Err(e) => return Err(e),
        }
    }
    versions(dir, tenant)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{create_tenant, export_escrow, init, rotate_tenant, tenant_deks};

    fn deks(d: &Path, t: &str) -> Vec<(u32, [u8; 32])> {
        tenant_deks(d, t).unwrap().into_iter().map(|(v, k)| (v, *k)).collect()
    }

    fn plain(v: Vec<(u32, Key)>) -> Vec<(u32, [u8; 32])> {
        v.into_iter().map(|(v, k)| (v, *k)).collect()
    }

    fn tenant_files(d: &Path, t: &str) -> Vec<(String, Vec<u8>)> {
        export_escrow(d, t)
            .unwrap()
            .into_iter()
            .filter_map(|(n, b)| Some((n.strip_prefix(&format!("tenants/{t}/"))?.to_owned(), b)))
            .collect()
    }

    #[test]
    fn wrap_unwrap_rotation_and_isolation() {
        let d = tempfile::tempdir().unwrap();
        init(d.path()).unwrap();
        create_tenant(d.path(), "acme").unwrap();
        create_tenant(d.path(), "other").unwrap();
        let (key, public) = generate();
        assert_eq!(public_of(&key.to_uppercase()).unwrap(), public);
        assert!(set(d.path(), "nope", Some(&public)).is_err());
        assert!(set(d.path(), "acme", Some(&public)).unwrap());
        assert!(!set(d.path(), "acme", Some(&public)).unwrap(), "idempotent");
        // the appliance never holds the secret: only the public key is on disk
        let td = d.path().join("tenants/acme");
        assert_eq!(fs::read(td.join(PUB)).unwrap(), public);
        let secret = crate::parse_recovery_key(&key).unwrap();
        for e in fs::read_dir(&td).unwrap() {
            let b = fs::read(e.unwrap().path()).unwrap();
            assert!(!b.windows(32).any(|w| w == &secret[..]), "secret never stored");
        }

        // rotation seals the new version with the public key only
        rotate_tenant(d.path(), "acme").unwrap();
        let files = tenant_files(d.path(), "acme");
        assert_eq!(
            files.iter().filter(|(n, _)| is_escrow_file(n)).count(),
            2,
            "v1 and v2 escrowed"
        );
        assert_eq!(plain(open("acme", &key, &files).unwrap()), deks(d.path(), "acme"));
        for (_, b) in &files {
            for (_, k) in deks(d.path(), "acme") {
                assert!(!b.windows(32).any(|w| w == k), "no DEK in clear");
            }
        }

        // other tenants: no escrow for this key, and a file copied over is refused
        assert!(tenant_files(d.path(), "other").iter().all(|(n, _)| !is_escrow_file(n)));
        assert!(open("other", &key, &tenant_files(d.path(), "other")).is_err());
        assert!(open("other", &key, &files).is_err(), "tenant name is sealed in");
        let (k2, p2) = generate();
        set(d.path(), "other", Some(&p2)).unwrap();
        assert!(open("other", &key, &tenant_files(d.path(), "other")).is_err());
        assert!(open("acme", &k2, &files).is_err());
        assert!(open("acme", &crate::format_recovery_key(&[7; 32]), &files).is_err());
        // renamed version is refused
        let esc: Vec<_> = files.iter().filter(|(n, _)| is_escrow_file(n)).cloned().collect();
        let swapped = vec![
            (esc[0].0.clone(), esc[1].1.clone()),
            (esc[1].0.clone(), esc[0].1.clone()),
        ];
        assert!(open("acme", &key, &swapped).is_err());

        // replacing removes the old escrow; the old key no longer opens anything new
        let (k3, p3) = generate();
        assert!(set(d.path(), "acme", Some(&p3)).unwrap());
        let files3 = tenant_files(d.path(), "acme");
        assert!(open("acme", &key, &files3).is_err());
        assert_eq!(plain(open("acme", &k3, &files3).unwrap()), deks(d.path(), "acme"));
        // removing
        assert!(set(d.path(), "acme", None).unwrap());
        assert!(tenant_files(d.path(), "acme").iter().all(|(n, _)| !is_escrow_file(n)));
        assert!(!td.join(PUB).exists());
    }

    #[test]
    fn install_on_fresh_appliance() {
        let (a, b) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        init(a.path()).unwrap();
        init(b.path()).unwrap();
        create_tenant(a.path(), "acme").unwrap();
        rotate_tenant(a.path(), "acme").unwrap();
        let (key, public) = generate();
        set(a.path(), "acme", Some(&public)).unwrap();
        let opened = open("acme", &key, &tenant_files(a.path(), "acme")).unwrap();
        assert_eq!(install(b.path(), "acme", &opened).unwrap(), vec![1, 2]);
        assert_eq!(install(b.path(), "acme", &opened).unwrap(), vec![1, 2], "idempotent");
        assert_eq!(deks(a.path(), "acme"), deks(b.path(), "acme"));
        // wrapped under b's own KEK, nothing of a's appliance escrow
        assert_ne!(
            fs::read(a.path().join("tenants/acme/dek.1")).unwrap(),
            fs::read(b.path().join("tenants/acme/dek.1")).unwrap()
        );
        // a different tenant with the same name already present is refused
        let c = tempfile::tempdir().unwrap();
        init(c.path()).unwrap();
        create_tenant(c.path(), "acme").unwrap();
        assert!(install(c.path(), "acme", &opened).is_err());
        // no KEK: refused
        let e = tempfile::tempdir().unwrap();
        assert!(install(e.path(), "acme", &opened).is_err());
    }
}
