//! Appliance configuration backup bundles (docs/control-plane.md "Configuration
//! backup", manual/14). The bundle is sealed so that the appliance can create
//! it without the recovery key and only the recovery key opens it:
//!
//! - keyd derives an X25519 key pair from the KEK (`config_secret`); the
//!   public key and the already wrapped `kek.recovery` are published next to the
//!   socket ([`publish`]) for the root helper `nexus-config-backup`;
//! - the helper seals a random bundle key to that public key (anonymous box, as
//!   for tenant recovery escrow and replication exports) and encrypts the files
//!   with it;
//! - restore: recovery key → `kek.recovery` (in the bundle) → KEK → X25519
//!   secret → bundle key → files.
//!
//! ```text
//! NXCFGB1\0 | u32 LE n | header (n bytes, clear: JSON written by the helper)
//!           | u32 LE n | kek.recovery | u32 LE n | bundle key sealed to the public key
//!           | nonce(24) | XChaCha20-Poly1305(bundle key, zstd(entries), aad = all bytes before the nonce)
//! entries: N x (u8 kind 0 file / 1 dir | u16 BE path len | path | u32 BE mode
//!              | u8 len | user | u8 len | group | u64 BE len | data)
//! ```
//! Paths are relative to `/` (never absolute, no `..`).
//!
//! Phase 30 (ADR-014): keyd publishes a hybrid public key (X25519 | ML-KEM-768,
//! the ML-KEM seed derived from the same KEK-derived secret, `PQ_CONTEXT`) and
//! bundles are `NXCFGB2\0` with the bundle key in a hybrid box (`crate::hybrid`,
//! label `config-bundle`); the layout is otherwise v1's. v1 bundles still open.

use crate::{err, parse_recovery_key, unseal, Key};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use chunkstore::crypto::{generate_key, unwrap_key};
use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use zeroize::Zeroizing;

/// magic of v1 bundles: the bundle key in an X25519-only sealed box (written for a 32-byte public key)
pub const MAGIC: &[u8; 8] = b"NXCFGB1\0";
/// Phase 30: the bundle key in a hybrid (X25519 + ML-KEM-768) box
pub const MAGIC2: &[u8; 8] = b"NXCFGB2\0";
const PQ_CONTEXT: &str = "NexusBackup 2026 config-backup ml-kem-768 v1";
const LABEL: &[u8] = b"config-bundle";
/// published next to the keyd socket (0644): the X25519 public key and `kek.recovery`
pub const PUB_FILE: &str = "config-backup.pub";
/// file name of the KEK escrow blob, in the keyd dir and published next to [`PUB_FILE`]
pub const KEK_RECOVERY_FILE: &str = "kek.recovery";
/// bundles larger than this are refused when opened
pub const MAX_BUNDLE: usize = 2 << 30;
const CONTEXT: &str = "NexusBackup 2026 config-backup x25519 v1";

/// One file or directory in a bundle, restored with its owner and mode.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    /// relative to `/` (see [`valid_path`])
    pub path: String,
    /// a directory (no data) instead of a file
    pub dir: bool,
    /// permission bits (`st_mode & 0o7777`)
    pub mode: u32,
    /// owner user name (not uid: uids may differ on the restored appliance), at most 255 bytes
    pub user: String,
    /// owner group name, at most 255 bytes
    pub group: String,
    /// file content; empty for directories
    pub data: Vec<u8>,
}

/// A bundle decrypted with the recovery key ([`open`]).
pub struct Opened {
    /// the clear JSON header written by the helper (same bytes as [`header`] returns)
    pub header: Vec<u8>,
    /// `kek.recovery` of the appliance that made the bundle
    pub kek_recovery: Vec<u8>,
    /// files and directories in the order they were sealed
    pub entries: Vec<Entry>,
}

fn secret_of(kek: &[u8; 32]) -> crypto_box::SecretKey {
    crypto_box::SecretKey::from_bytes(blake3::derive_key(CONTEXT, kek))
}

fn hybrid_of(kek: &[u8; 32]) -> crate::hybrid::Secret {
    crate::hybrid::Secret::derive(&Zeroizing::new(blake3::derive_key(CONTEXT, kek)), PQ_CONTEXT)
}

fn config_secret(dir: &Path) -> io::Result<crypto_box::SecretKey> {
    Ok(secret_of(&*unseal(dir)?))
}

/// Public key the configuration bundles are sealed to.
pub fn config_pubkey(dir: &Path) -> io::Result<[u8; 32]> {
    Ok(*config_secret(dir)?.public_key().as_bytes())
}

/// Phase 30: the hybrid public key bundles are sealed to (its X25519 half is
/// [`config_pubkey`]).
pub fn config_pubkey_pq(dir: &Path) -> io::Result<Vec<u8>> {
    Ok(hybrid_of(&*unseal(dir)?).public().to_bytes())
}

/// keyd serve: writes [`PUB_FILE`] (the hybrid public key since Phase 30) and
/// [`KEK_RECOVERY_FILE`] (both public: the latter is wrapped under the recovery
/// key and copied offsite anyway) into `out` (keyd's runtime dir, writable only by keyd).
pub fn publish(dir: &Path, out: &Path) -> io::Result<()> {
    for (name, bytes) in [
        (PUB_FILE, config_pubkey_pq(dir)?),
        (KEK_RECOVERY_FILE, fs::read(dir.join("kek.recovery"))?),
    ] {
        let p = out.join(name);
        chunkstore::store::write_atomic(&p, &bytes)?;
        fs::set_permissions(&p, fs::Permissions::from_mode(0o644))?;
    }
    Ok(())
}

/// Whether a bundle path is acceptable (relative, normal components only).
pub fn valid_path(p: &str) -> bool {
    !p.is_empty()
        && p.len() < 4096
        && !p.starts_with('/')
        && p.split('/')
            .all(|c| !c.is_empty() && c != "." && c != ".." && !c.contains('\0'))
}

fn encode(entries: &[Entry]) -> io::Result<Zeroizing<Vec<u8>>> {
    let mut out = Zeroizing::new(Vec::new());
    for e in entries {
        if !valid_path(&e.path) || e.user.len() > 255 || e.group.len() > 255 {
            return Err(err(io::ErrorKind::InvalidInput, format!("invalid entry {:?}", e.path)));
        }
        out.push(u8::from(e.dir));
        out.extend_from_slice(&(e.path.len() as u16).to_be_bytes());
        out.extend_from_slice(e.path.as_bytes());
        out.extend_from_slice(&e.mode.to_be_bytes());
        for s in [&e.user, &e.group] {
            out.push(s.len() as u8);
            out.extend_from_slice(s.as_bytes());
        }
        out.extend_from_slice(&(e.data.len() as u64).to_be_bytes());
        out.extend_from_slice(&e.data);
    }
    Ok(out)
}

fn decode(mut b: &[u8]) -> io::Result<Vec<Entry>> {
    let bad = || err(io::ErrorKind::InvalidData, "malformed configuration bundle");
    fn take<'a>(b: &mut &'a [u8], n: usize) -> Option<&'a [u8]> {
        let (h, t) = (b.len() >= n).then(|| b.split_at(n))?;
        *b = t;
        Some(h)
    }
    let mut out = Vec::new();
    while !b.is_empty() {
        let dir = take(&mut b, 1).ok_or_else(bad)?[0] == 1;
        let n = u16::from_be_bytes(take(&mut b, 2).ok_or_else(bad)?.try_into().unwrap()) as usize;
        let path = String::from_utf8(take(&mut b, n).ok_or_else(bad)?.to_vec()).map_err(|_| bad())?;
        let mode = u32::from_be_bytes(take(&mut b, 4).ok_or_else(bad)?.try_into().unwrap());
        let mut names = [String::new(), String::new()];
        for s in &mut names {
            let n = take(&mut b, 1).ok_or_else(bad)?[0] as usize;
            *s = String::from_utf8(take(&mut b, n).ok_or_else(bad)?.to_vec()).map_err(|_| bad())?;
        }
        let n = u64::from_be_bytes(take(&mut b, 8).ok_or_else(bad)?.try_into().unwrap());
        let data = take(&mut b, usize::try_from(n).map_err(|_| bad())?)
            .ok_or_else(bad)?
            .to_vec();
        if !valid_path(&path) {
            return Err(err(io::ErrorKind::InvalidData, format!("bundle path {path:?} refused")));
        }
        let [user, group] = names;
        out.push(Entry {
            path,
            dir,
            mode,
            user,
            group,
            data,
        });
    }
    Ok(out)
}

fn put(out: &mut Vec<u8>, b: &[u8]) {
    out.extend_from_slice(&(b.len() as u32).to_le_bytes());
    out.extend_from_slice(b);
}

/// Seals `entries` to `pubkey` (see [`publish`]); no secret of keyd is needed.
/// A hybrid public key makes a v2 bundle, a 32-byte X25519 key a v1 bundle.
pub fn seal(pubkey: &[u8], kek_recovery: &[u8], header: &[u8], entries: &[Entry]) -> io::Result<Vec<u8>> {
    let key = Zeroizing::new(generate_key());
    let (magic, sealed_key) = match <[u8; 32]>::try_from(pubkey) {
        Ok(x) => (
            MAGIC,
            crypto_box::PublicKey::from_bytes(x)
                .seal(&mut rand::rngs::OsRng, &key[..])
                .map_err(|_| err(io::ErrorKind::Other, "sealing failed"))?,
        ),
        Err(_) => (
            MAGIC2,
            crate::hybrid::seal(&crate::hybrid::Public::from_bytes(pubkey)?, LABEL, &key[..])?,
        ),
    };
    let mut out = magic.to_vec();
    put(&mut out, header);
    put(&mut out, kek_recovery);
    put(&mut out, &sealed_key);
    let plain = Zeroizing::new(zstd::encode_all(&encode(entries)?[..], 3)?);
    let nonce: [u8; 24] = rand::random();
    let ct = XChaCha20Poly1305::new((&*key).into())
        .encrypt(
            &XNonce::try_from(&nonce[..]).expect("24-byte nonce"),
            Payload { msg: &plain, aad: &out },
        )
        .map_err(|_| err(io::ErrorKind::Other, "encryption failed"))?;
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

struct Parts<'a> {
    hybrid: bool,
    header: &'a [u8],
    kek_recovery: &'a [u8],
    sealed_key: &'a [u8],
    aad: &'a [u8],
    rest: &'a [u8],
}

fn split(b: &[u8]) -> io::Result<Parts<'_>> {
    let bad = || err(io::ErrorKind::InvalidData, "not a NexusBackup configuration bundle");
    let hybrid = b.starts_with(MAGIC2);
    if !b.starts_with(MAGIC) && !hybrid {
        return Err(bad());
    }
    let mut pos = MAGIC.len();
    let mut field = || -> io::Result<&[u8]> {
        let n = u32::from_le_bytes(b.get(pos..pos + 4).ok_or_else(bad)?.try_into().unwrap()) as usize;
        let f = b.get(pos + 4..pos + 4 + n).ok_or_else(bad)?;
        pos += 4 + n;
        Ok(f)
    };
    let (header, kek_recovery, sealed_key) = (field()?, field()?, field()?);
    if b.len() < pos + 24 + 16 {
        return Err(bad());
    }
    Ok(Parts {
        hybrid,
        header,
        kek_recovery,
        sealed_key,
        aad: &b[..pos],
        rest: &b[pos..],
    })
}

/// The clear header (no key needed: listing, choosing a bundle).
pub fn header(bundle: &[u8]) -> io::Result<Vec<u8>> {
    Ok(split(bundle)?.header.to_vec())
}

/// Opens a bundle with the recovery key of the appliance that made it.
pub fn open(bundle: &[u8], recovery_key: &str) -> io::Result<Opened> {
    let p = split(bundle)?;
    let rk = parse_recovery_key(recovery_key)?;
    let kek: Key = Zeroizing::new(unwrap_key(&rk, p.kek_recovery, "kek-recovery").map_err(|_| {
        err(
            io::ErrorKind::PermissionDenied,
            "the recovery key does not open this bundle (it belongs to another appliance, or the key is mistyped)",
        )
    })?);
    open_with_kek(&p, &kek)
}

fn open_with_kek(p: &Parts<'_>, kek: &[u8; 32]) -> io::Result<Opened> {
    let bad = || {
        err(
            io::ErrorKind::InvalidData,
            "configuration bundle damaged or tampered with",
        )
    };
    let key = if p.hybrid {
        crate::hybrid::open(&hybrid_of(kek), LABEL, p.sealed_key).map_err(|_| bad())?
    } else {
        Zeroizing::new(secret_of(kek).unseal(p.sealed_key).map_err(|_| bad())?)
    };
    let key: &[u8; 32] = key[..].try_into().map_err(|_| bad())?;
    let (nonce, ct) = p.rest.split_at(24);
    let plain = Zeroizing::new(
        XChaCha20Poly1305::new(key.into())
            .decrypt(
                &XNonce::try_from(nonce).expect("24-byte nonce"),
                Payload { msg: ct, aad: p.aad },
            )
            .map_err(|_| bad())?,
    );
    let raw = Zeroizing::new(zstd::decode_all(&plain[..]).map_err(|_| bad())?);
    Ok(Opened {
        header: p.header.to_vec(),
        kek_recovery: p.kek_recovery.to_vec(),
        entries: decode(&raw)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entries() -> Vec<Entry> {
        vec![
            Entry {
                path: "etc/nexus/ssh".into(),
                dir: true,
                mode: 0o750,
                user: "nexus-chunkstore".into(),
                group: "nexus-chunkstore".into(),
                data: vec![],
            },
            Entry {
                path: "var/lib/nexus/webapi/totp.key".into(),
                dir: false,
                mode: 0o600,
                user: "nexus-webapi".into(),
                group: "nexus-webapi".into(),
                data: vec![7; 32],
            },
        ]
    }

    /// Created with the published public key only (no keyd secret, no recovery
    /// key); opened with the recovery key; a wrong key and tampering are refused.
    #[test]
    fn roundtrip_without_recovery_key() {
        let d = tempfile::tempdir().unwrap();
        let rk = crate::init(d.path()).unwrap();
        let run = tempfile::tempdir().unwrap();
        publish(d.path(), run.path()).unwrap();
        let pk = fs::read(run.path().join(PUB_FILE)).unwrap();
        assert_eq!(pk.len(), crate::hybrid::PUBLIC_LEN);
        assert_eq!(pk[..32], config_pubkey(d.path()).unwrap());
        let kr = fs::read(run.path().join(KEK_RECOVERY_FILE)).unwrap();
        assert_eq!(kr, fs::read(d.path().join("kek.recovery")).unwrap());
        let b = seal(&pk, &kr, br#"{"appliance":"x"}"#, &entries()).unwrap();
        assert!(b.starts_with(MAGIC2), "Phase 30: hybrid");
        // a v1 bundle (X25519 only, earlier releases) still opens
        let v1 = seal(&pk[..32], &kr, b"{}", &entries()).unwrap();
        assert!(v1.starts_with(MAGIC));
        assert_eq!(open(&v1, &rk).unwrap().entries, entries());
        assert_eq!(header(&b).unwrap(), br#"{"appliance":"x"}"#);
        let o = open(&b, &rk).unwrap();
        assert_eq!(o.entries, entries());
        assert_eq!(o.kek_recovery, kr);

        let wrong = crate::format_recovery_key(&[3; 32]);
        assert_eq!(open(&b, &wrong).err().unwrap().kind(), io::ErrorKind::PermissionDenied);
        // the clear header is authenticated, as is every payload byte
        let mut t = b.clone();
        t[12] ^= 1;
        assert!(open(&t, &rk).is_err());
        let mut t = b.clone();
        let n = t.len();
        t[n - 1] ^= 1;
        assert!(open(&t, &rk).is_err());
        assert!(open(b"garbage", &rk).is_err());
    }

    #[test]
    fn paths_and_entries_checked() {
        for ok in ["etc/nexus/ssh/id", "var/lib/nexus/catalog/catalog.db"] {
            assert!(valid_path(ok), "{ok}");
        }
        for bad in ["", "/etc/passwd", "etc/../x", "./x", "a//b", "a/"] {
            assert!(!valid_path(bad), "{bad}");
        }
        let mut e = entries();
        e[0].path = "../etc".into();
        assert!(seal(&[9; 32], &[], b"", &e).is_err());
    }
}
