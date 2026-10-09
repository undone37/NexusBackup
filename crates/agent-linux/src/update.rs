//! Signed self-update.
//!
//! `signature` is what `cosign sign-blob --key <release key>` prints: base64 of an
//! ASN.1/DER ECDSA P-256 signature over SHA-256 of the binary. It is verified against
//! the pinned keys in `/etc/nexus-agent/release-keys/*.pub` (PEM SPKI, as written by
//! `cosign generate-key-pair`; lab builds pin `release/testkey/TEST-cosign.pub`).
//!
//! The version the appliance claims is not covered by the signature, so the agent
//! reads the version embedded in the signed binary itself ([`VERSION_MARKER`]) and
//! refuses anything that is not strictly newer (no downgrade / replay of an older
//! signed build). The binary is written next to the running one, fsynced and renamed
//! over it atomically (the previous binary is kept as `<exe>.prev`); the service then
//! exits with [`RESTART_EXIT_CODE`] and systemd restarts it.

use base64::Engine;
use ring::signature::{UnparsedPublicKey, ECDSA_P256_SHA256_ASN1};
use std::fs;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

/// Embedded in every build; found in update candidates to learn their real version.
#[used]
pub static VERSION_MARKER: &[u8] = concat!("\0NEXUS-AGENT-VERSION=", env!("CARGO_PKG_VERSION"), "\0").as_bytes();
const MARKER_PREFIX: &[u8] = b"\0NEXUS-AGENT-VERSION=";
pub const RESTART_EXIT_CODE: i32 = 75;

/// DER prefix of a P-256 SubjectPublicKeyInfo (id-ecPublicKey, prime256v1).
const P256_SPKI_PREFIX: [u8; 26] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce,
    0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
];

/// Parse a PEM `PUBLIC KEY` (P-256) into the uncompressed point ring expects.
pub fn parse_public_key(pem: &str) -> Result<Vec<u8>, String> {
    let b64: String = pem
        .lines()
        .skip_while(|l| !l.starts_with("-----BEGIN PUBLIC KEY-----"))
        .skip(1)
        .take_while(|l| !l.starts_with("-----END"))
        .collect();
    let der = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .map_err(|e| format!("public key: {e}"))?;
    match der.strip_prefix(&P256_SPKI_PREFIX[..]) {
        Some(point) if point.len() == 65 && point[0] == 4 => Ok(point.to_vec()),
        _ => Err("public key is not an ECDSA P-256 key".into()),
    }
}

/// All pinned keys (file name, point). Unreadable / foreign keys are skipped.
pub fn load_keys(dir: &Path) -> Vec<(String, Vec<u8>)> {
    let mut out = vec![];
    let Ok(rd) = fs::read_dir(dir) else { return out };
    let mut names: Vec<PathBuf> = rd
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "pub"))
        .collect();
    names.sort();
    for p in names {
        match fs::read_to_string(&p)
            .map_err(|e| e.to_string())
            .and_then(|t| parse_public_key(&t))
        {
            Ok(k) => out.push((p.file_name().unwrap_or_default().to_string_lossy().into_owned(), k)),
            Err(e) => eprintln!("nexus-agent: release key {}: {e}", p.display()),
        }
    }
    out
}

/// Verify a cosign blob signature; returns the name of the key that matched.
pub fn verify(binary: &[u8], signature: &[u8], keys: &[(String, Vec<u8>)]) -> Result<String, String> {
    if keys.is_empty() {
        return Err("no pinned release keys".into());
    }
    let text = std::str::from_utf8(signature).ok().map(|s| s.trim().to_string());
    let der = match text.and_then(|t| base64::engine::general_purpose::STANDARD.decode(t).ok()) {
        Some(d) => d,
        None if signature.first() == Some(&0x30) => signature.to_vec(),
        None => return Err("signature is neither base64 nor DER".into()),
    };
    keys.iter()
        .find(|(_, k)| {
            UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, k)
                .verify(binary, &der)
                .is_ok()
        })
        .map(|(n, _)| n.clone())
        .ok_or_else(|| "signature does not verify with any pinned release key".into())
}

pub fn parse_version(v: &str) -> Option<(u64, u64, u64)> {
    let mut it = v.trim().split('.').map(|p| p.parse::<u64>().ok());
    let r = (it.next()??, it.next()??, it.next()??);
    it.next().is_none().then_some(r)
}

/// The version embedded in a candidate binary (exactly one distinct marker).
pub fn embedded_version(binary: &[u8]) -> Result<String, String> {
    let mut found: Vec<String> = vec![];
    let mut i = 0;
    while let Some(pos) = binary[i..]
        .windows(MARKER_PREFIX.len())
        .position(|w| w == MARKER_PREFIX)
    {
        let start = i + pos + MARKER_PREFIX.len();
        let end = binary[start..].iter().take(32).position(|b| *b == 0).map(|e| start + e);
        if let Some(v) = end.and_then(|e| std::str::from_utf8(&binary[start..e]).ok()) {
            if parse_version(v).is_some() && !found.iter().any(|f| f == v) {
                found.push(v.to_string());
            }
        }
        i = start;
    }
    match found.len() {
        1 => Ok(found.remove(0)),
        0 => Err("binary carries no version marker".into()),
        _ => Err("binary carries several version markers".into()),
    }
}

fn is_native_elf(b: &[u8]) -> bool {
    #[cfg(target_arch = "x86_64")]
    const MACHINE: u16 = 62;
    #[cfg(target_arch = "aarch64")]
    const MACHINE: u16 = 183;
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    const MACHINE: u16 = 0;
    b.len() > 64 && b[..4] == *b"\x7fELF" && b[4] == 2 && u16::from_le_bytes([b[18], b[19]]) == MACHINE
}

/// Check everything; on success atomically replace `exe`. Returns a summary.
pub fn apply(
    claimed: &str,
    binary: &[u8],
    signature: &[u8],
    keys: &[(String, Vec<u8>)],
    current: &str,
    exe: &Path,
) -> Result<String, String> {
    let key = verify(binary, signature, keys)?;
    let embedded = embedded_version(binary)?;
    if embedded != claimed.trim() {
        return Err(format!("claimed version {claimed} but the signed binary is {embedded}"));
    }
    let (new, cur) = (
        parse_version(&embedded).ok_or("bad version")?,
        parse_version(current).ok_or("bad current version")?,
    );
    if new <= cur {
        return Err(format!(
            "refusing downgrade/reinstall: {embedded} is not newer than {current}"
        ));
    }
    if !is_native_elf(binary) {
        return Err("not an ELF executable for this architecture".into());
    }
    let dir = exe.parent().ok_or("executable has no directory")?;
    let name = exe
        .file_name()
        .ok_or("executable has no name")?
        .to_string_lossy()
        .into_owned();
    let tmp = dir.join(format!(".{name}.update"));
    let _ = fs::remove_file(&tmp);
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o755)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&tmp)
        .map_err(|e| format!("{}: {e}", tmp.display()))?;
    let res = f
        .write_all(binary)
        .and_then(|_| f.set_permissions(fs::Permissions::from_mode(0o755)))
        .and_then(|_| f.sync_all())
        .and_then(|_| {
            let prev = dir.join(format!("{name}.prev"));
            let _ = fs::remove_file(&prev);
            let _ = fs::hard_link(exe, &prev);
            fs::rename(&tmp, exe)
        })
        .and_then(|_| fs::File::open(dir)?.sync_all());
    if let Err(e) = res {
        let _ = fs::remove_file(&tmp);
        return Err(format!("installing update: {e}"));
    }
    Ok(format!("updated {current} -> {embedded} (signed by {key})"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::rand::SystemRandom;
    use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};

    const TEST_PUB: &str = include_str!("../../../release/testkey/TEST-cosign.pub");
    const BLOB: &[u8] = include_bytes!("../tests/fixtures/cosign-blob.bin");
    const BLOB_SIG: &[u8] = include_bytes!("../tests/fixtures/cosign-blob.bin.sig");

    fn keypair() -> (EcdsaKeyPair, Vec<u8>) {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
        let kp = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng).unwrap();
        let point = kp.public_key().as_ref().to_vec();
        (kp, point)
    }

    fn sign(kp: &EcdsaKeyPair, data: &[u8]) -> Vec<u8> {
        let sig = kp.sign(&SystemRandom::new(), data).unwrap();
        base64::engine::general_purpose::STANDARD
            .encode(sig.as_ref())
            .into_bytes()
    }

    fn fake_binary(version: &str) -> Vec<u8> {
        let mut b = vec![0u8; 128];
        b[..4].copy_from_slice(b"\x7fELF");
        b[4] = 2;
        b[18..20].copy_from_slice(&62u16.to_le_bytes());
        b.extend_from_slice(format!("\0NEXUS-AGENT-VERSION={version}\0").as_bytes());
        b.extend_from_slice(MARKER_PREFIX); // a bare needle elsewhere must not confuse the parser
        b.extend_from_slice(b"junk");
        b
    }

    #[test]
    fn verifies_real_cosign_sign_blob_output_with_the_test_key() {
        // fixture made with: cosign sign-blob --key release/testkey/TEST-cosign.key blob
        let keys = vec![("TEST-cosign.pub".to_string(), parse_public_key(TEST_PUB).unwrap())];
        assert_eq!(verify(BLOB, BLOB_SIG, &keys).unwrap(), "TEST-cosign.pub");
        let mut tampered = BLOB.to_vec();
        tampered[0] ^= 1;
        assert!(verify(&tampered, BLOB_SIG, &keys).is_err());
        let (_, other) = keypair();
        assert!(verify(BLOB, BLOB_SIG, &[("other".into(), other)]).is_err());
        assert!(verify(BLOB, BLOB_SIG, &[]).is_err());
    }

    #[test]
    fn apply_checks_signature_version_and_replaces_atomically() {
        let t = tempfile::tempdir().unwrap();
        let exe = t.path().join("nexus-agent");
        fs::write(&exe, b"old").unwrap();
        let (kp, point) = keypair();
        let keys = vec![("k.pub".to_string(), point)];
        let new = fake_binary("0.2.0");
        let sig = sign(&kp, &new);
        // unsigned / wrong signature
        assert!(apply("0.2.0", &new, &sign(&kp, b"x"), &keys, "0.1.0", &exe).is_err());
        // claimed version differs from the embedded one
        assert!(apply("0.3.0", &new, &sig, &keys, "0.1.0", &exe)
            .unwrap_err()
            .contains("claimed"));
        // downgrade and reinstall
        assert!(apply("0.2.0", &new, &sig, &keys, "0.2.0", &exe)
            .unwrap_err()
            .contains("downgrade"));
        assert!(apply("0.2.0", &new, &sig, &keys, "0.10.0", &exe)
            .unwrap_err()
            .contains("downgrade"));
        // not an ELF
        let mut notelf = new.clone();
        notelf[0] = b'#';
        assert!(apply("0.2.0", &notelf, &sign(&kp, &notelf), &keys, "0.1.0", &exe).is_err());
        assert_eq!(fs::read(&exe).unwrap(), b"old");
        let msg = apply("0.2.0", &new, &sig, &keys, "0.1.0", &exe).unwrap();
        assert!(msg.contains("0.2.0"), "{msg}");
        assert_eq!(fs::read(&exe).unwrap(), new);
        assert_eq!(fs::read(t.path().join("nexus-agent.prev")).unwrap(), b"old");
        assert_eq!(fs::read_dir(t.path()).unwrap().count(), 2, "no temp files left");
    }

    #[test]
    fn key_parsing_and_versions() {
        let t = tempfile::tempdir().unwrap();
        fs::write(t.path().join("a.pub"), TEST_PUB).unwrap();
        fs::write(
            t.path().join("bad.pub"),
            "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n",
        )
        .unwrap();
        fs::write(t.path().join("ignored.txt"), TEST_PUB).unwrap();
        assert_eq!(load_keys(t.path()).len(), 1);
        assert_eq!(parse_version("1.2.3"), Some((1, 2, 3)));
        assert_eq!(parse_version("1.2"), None);
        assert_eq!(parse_version("1.2.3-rc1"), None);
        assert!(parse_version("0.10.0") > parse_version("0.9.9"));
        assert_eq!(embedded_version(VERSION_MARKER).unwrap(), env!("CARGO_PKG_VERSION"));
        // a real build (this test binary) carries exactly one parsable marker
        let me = fs::read(std::env::current_exe().unwrap()).unwrap();
        assert_eq!(embedded_version(&me).unwrap(), env!("CARGO_PKG_VERSION"));
        let mut two = fake_binary("1.0.0");
        two.extend(fake_binary("2.0.0"));
        assert!(embedded_version(&two).is_err());
    }
}
