//! Signed self-update (signature/version checks: `agent_core::update`).
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

use std::fs;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

/// Embedded in every build; found in update candidates to learn their real version.
#[used]
pub static VERSION_MARKER: &[u8] = concat!("\0NEXUS-AGENT-VERSION=", env!("CARGO_PKG_VERSION"), "\0").as_bytes();
pub const RESTART_EXIT_CODE: i32 = 75;

pub use agent_core::update::{embedded_version, load_keys, parse_public_key, parse_version, verify, MARKER_PREFIX};

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
    let (key, embedded) =
        agent_core::update::check_candidate(claimed, binary, signature, keys, current, is_native_elf)?;
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
    use base64::Engine;
    use ring::rand::SystemRandom;
    use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};

    const TEST_PUB: &str = include_str!("../../../release/testkey/TEST-cosign.pub");
    const BLOB: &[u8] = include_bytes!("../../agent-core/tests/fixtures/cosign-blob.bin");
    const BLOB_SIG: &[u8] = include_bytes!("../../agent-core/tests/fixtures/cosign-blob.bin.sig");

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
