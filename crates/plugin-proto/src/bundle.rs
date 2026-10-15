//! Plugin bundles (`<id>-<version>.nxplugin`, docs/plugin-system.md "Package"):
//! an uncompressed tar with `manifest.json`, `bin/plugin` and optional `assets/…`,
//! plus a detached signature as printed by `cosign sign-blob` (base64 of an
//! ASN.1/DER ECDSA P-256 signature over SHA-256 of the bundle file) — the format of
//! `release/sign.sh sign-blob` and of the agents' self-update.
//!
//! Reading is strict: regular files and directories only, normal relative paths,
//! no duplicates, bounded sizes. Packing is deterministic (sorted, mtime 0, root
//! owner), so the same inputs give the same bundle digest.

use crate::Manifest;
use base64::Engine;
use ring::rand::SystemRandom;
use ring::signature::{
    EcdsaKeyPair, KeyPair, UnparsedPublicKey, ECDSA_P256_SHA256_ASN1, ECDSA_P256_SHA256_ASN1_SIGNING,
};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::path::Path;

/// Bundles larger than this are refused (upload limit of the web-api).
pub const MAX_BUNDLE: usize = 128 << 20;
/// Largest `manifest.json` in bytes (1 MiB).
pub const MAX_MANIFEST: usize = 1 << 20;
/// Most files below `assets/`.
pub const MAX_ASSETS: usize = 256;
/// Publisher name of plugins signed with a project (release) key.
pub const PROJECT_PUBLISHER: &str = "nexusbackup";

/// DER prefix of a P-256 SubjectPublicKeyInfo (id-ecPublicKey, prime256v1).
const P256_SPKI_PREFIX: [u8; 26] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce,
    0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
];

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

/// SHA-256 of `b` as 64 lowercase hex digits.
pub fn sha256_hex(b: &[u8]) -> String {
    Sha256::digest(b).iter().map(|x| format!("{x:02x}")).collect()
}

/// A parsed bundle (see [`read`]).
#[derive(Debug, Clone, PartialEq)]
pub struct Bundle {
    /// `manifest.json` exactly as signed
    pub manifest_raw: Vec<u8>,
    /// `manifest_raw` parsed and validated ([`Manifest::validate`]).
    pub manifest: Manifest,
    /// `bin/plugin`
    pub bin: Vec<u8>,
    /// `assets/<path>` (path below `assets/`)
    pub assets: BTreeMap<String, Vec<u8>>,
}

impl Bundle {
    /// SHA-256 (hex) of `bin/plugin`; the host checks the installed binary against it.
    pub fn bin_sha256(&self) -> String {
        sha256_hex(&self.bin)
    }
}

fn normal_path(p: &str) -> bool {
    !p.is_empty()
        && p.len() <= 255
        && !p.starts_with('/')
        && p.split('/')
            .all(|c| !c.is_empty() && c != "." && c != ".." && c.bytes().all(|b| b.is_ascii_graphic()))
}

/// Parses and checks a bundle (structure + manifest validation; no signature).
pub fn read(bytes: &[u8]) -> Result<Bundle, String> {
    if bytes.len() > MAX_BUNDLE {
        return Err(format!("bundle exceeds {} MiB", MAX_BUNDLE >> 20));
    }
    let mut ar = tar::Archive::new(bytes);
    let mut files: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    for e in ar.entries().map_err(|e| format!("not a tar archive: {e}"))? {
        let mut e = e.map_err(|e| format!("tar: {e}"))?;
        let path = e
            .path()
            .map_err(|e| format!("tar path: {e}"))?
            .to_str()
            .ok_or("tar: non-UTF-8 path")?
            .trim_end_matches('/')
            .to_owned();
        if !normal_path(&path) {
            return Err(format!("bundle: invalid path {path:?}"));
        }
        match e.header().entry_type() {
            tar::EntryType::Directory => {
                if !["bin", "assets"].contains(&path.as_str()) && !path.starts_with("assets/") {
                    return Err(format!("bundle: unexpected directory {path:?}"));
                }
                continue;
            }
            tar::EntryType::Regular | tar::EntryType::Continuous => {}
            t => return Err(format!("bundle: {path:?} is not a regular file ({t:?})")),
        }
        if path != "manifest.json" && path != "bin/plugin" && !path.starts_with("assets/") {
            return Err(format!("bundle: unexpected file {path:?}"));
        }
        if files.len() >= MAX_ASSETS + 2 {
            return Err("bundle: too many files".into());
        }
        let mut data = Vec::with_capacity(e.size().min(MAX_BUNDLE as u64) as usize);
        e.read_to_end(&mut data).map_err(|e| format!("tar: {e}"))?;
        if files.insert(path.clone(), data).is_some() {
            return Err(format!("bundle: {path:?} appears twice"));
        }
    }
    let manifest_raw = files.remove("manifest.json").ok_or("bundle: manifest.json missing")?;
    if manifest_raw.len() > MAX_MANIFEST {
        return Err("bundle: manifest.json too large".into());
    }
    let manifest: Manifest = serde_json::from_slice(&manifest_raw).map_err(|e| format!("manifest.json: {e}"))?;
    manifest.validate().map_err(|e| format!("manifest.json: {e}"))?;
    let bin = files.remove("bin/plugin").ok_or("bundle: bin/plugin missing")?;
    if !bin.starts_with(b"\x7fELF") {
        return Err("bundle: bin/plugin is not an ELF executable".into());
    }
    let assets = files
        .into_iter()
        .map(|(k, v)| (k.trim_start_matches("assets/").to_owned(), v))
        .collect();
    Ok(Bundle {
        manifest_raw,
        manifest,
        bin,
        assets,
    })
}

/// Deterministic bundle: `manifest.json`, `bin/plugin` (0755), `assets/…` (0644), sorted.
pub fn pack(manifest_raw: &[u8], bin: &[u8], assets: &BTreeMap<String, Vec<u8>>) -> Result<Vec<u8>, String> {
    let m: Manifest = serde_json::from_slice(manifest_raw).map_err(|e| format!("manifest: {e}"))?;
    m.validate().map_err(|e| format!("manifest: {e}"))?;
    let mut b = tar::Builder::new(Vec::new());
    let mut add = |path: &str, data: &[u8], mode: u32, dir: bool| -> Result<(), String> {
        let mut h = tar::Header::new_ustar();
        h.set_mode(mode);
        h.set_uid(0);
        h.set_gid(0);
        h.set_mtime(0);
        h.set_size(if dir { 0 } else { data.len() as u64 });
        h.set_entry_type(if dir {
            tar::EntryType::Directory
        } else {
            tar::EntryType::Regular
        });
        b.append_data(&mut h, path, data).map_err(|e| format!("tar: {e}"))
    };
    add("manifest.json", manifest_raw, 0o644, false)?;
    add("bin", &[], 0o755, true)?;
    add("bin/plugin", bin, 0o755, false)?;
    for (k, v) in assets {
        if !normal_path(k) {
            return Err(format!("asset path {k:?} invalid"));
        }
        add(&format!("assets/{k}"), v, 0o644, false)?;
    }
    let out = b.into_inner().map_err(|e| format!("tar: {e}"))?;
    read(&out)?; // what we write must pass our own reader
    Ok(out)
}

// ---- keys and signatures ---------------------------------------------------------

/// A trusted signing key: a project key (from the image) or a publisher key (catalog).
#[derive(Debug, Clone, PartialEq)]
pub struct TrustedKey {
    /// file name (project keys) or `publisher/<fingerprint prefix>`
    pub name: String,
    /// the publisher this key may sign for ([`PROJECT_PUBLISHER`] for project keys)
    pub publisher: String,
    /// uncompressed P-256 point (65 bytes)
    pub point: Vec<u8>,
    /// A project key from the image (`true`) or a publisher key from the catalog.
    pub builtin: bool,
}

impl TrustedKey {
    /// [`fingerprint`] of this key.
    pub fn fingerprint(&self) -> String {
        fingerprint(&self.point)
    }
}

/// PEM `PUBLIC KEY` (P-256 SPKI, as written by `cosign generate-key-pair`) → point.
pub fn parse_public_key(pem: &str) -> Result<Vec<u8>, String> {
    let b64: String = pem
        .lines()
        .map(str::trim)
        .skip_while(|l| !l.starts_with("-----BEGIN PUBLIC KEY-----"))
        .skip(1)
        .take_while(|l| !l.starts_with("-----END"))
        .collect();
    let der = B64.decode(b64.trim()).map_err(|e| format!("public key: {e}"))?;
    match der.strip_prefix(&P256_SPKI_PREFIX[..]) {
        Some(point) if point.len() == 65 && point[0] == 4 => Ok(point.to_vec()),
        _ => Err("public key is not an ECDSA P-256 key".into()),
    }
}

/// sha256 (hex) of the SPKI DER: stable key id.
pub fn fingerprint(point: &[u8]) -> String {
    sha256_hex(&[&P256_SPKI_PREFIX[..], point].concat())
}

/// PEM `PUBLIC KEY` (P-256 SPKI) of an uncompressed point; inverse of [`parse_public_key`].
pub fn public_key_pem(point: &[u8]) -> String {
    pem_wrap("PUBLIC KEY", &[&P256_SPKI_PREFIX[..], point].concat())
}

fn pem_wrap(label: &str, der: &[u8]) -> String {
    let b = B64.encode(der);
    let mut s = format!("-----BEGIN {label}-----\n");
    for l in b.as_bytes().chunks(64) {
        s.push_str(std::str::from_utf8(l).unwrap_or_default());
        s.push('\n');
    }
    s.push_str(&format!("-----END {label}-----\n"));
    s
}

/// Project keys: every `*.pub` in `dir` (sorted); unreadable / foreign keys are skipped.
pub fn load_project_keys(dir: &Path) -> Vec<TrustedKey> {
    let Ok(rd) = fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut paths: Vec<_> = rd
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "pub"))
        .collect();
    paths.sort();
    paths
        .into_iter()
        .filter_map(|p| {
            let point = fs::read_to_string(&p).ok().and_then(|t| parse_public_key(&t).ok())?;
            Some(TrustedKey {
                name: p.file_name()?.to_string_lossy().into_owned(),
                publisher: PROJECT_PUBLISHER.into(),
                point,
                builtin: true,
            })
        })
        .collect()
}

/// Verifies a detached signature (base64 text or raw DER) over `bundle`; returns the key that matched.
pub fn verify<'a>(bundle: &[u8], signature: &[u8], keys: &'a [TrustedKey]) -> Result<&'a TrustedKey, String> {
    if keys.is_empty() {
        return Err("no trusted plugin signing keys".into());
    }
    let text = std::str::from_utf8(signature).ok().map(|s| s.trim().to_owned());
    let der = match text.and_then(|t| B64.decode(t).ok()) {
        Some(d) => d,
        None if signature.first() == Some(&0x30) => signature.to_vec(),
        None => return Err("signature is neither base64 nor DER".into()),
    };
    keys.iter()
        .find(|k| {
            UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, &k.point)
                .verify(bundle, &der)
                .is_ok()
        })
        .ok_or_else(|| "signature does not verify with any trusted key (unknown publisher?)".into())
}

/// New P-256 key pair: (PKCS#8 private key PEM, public key PEM).
pub fn generate_key() -> Result<(String, String), String> {
    let rng = SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).map_err(|_| "keygen failed")?;
    let kp =
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng).map_err(|_| "keygen failed")?;
    Ok((
        pem_wrap("PRIVATE KEY", pkcs8.as_ref()),
        public_key_pem(kp.public_key().as_ref()),
    ))
}

/// Signs `data` with a PKCS#8 PEM P-256 key; base64 DER signature (cosign sign-blob format).
pub fn sign(data: &[u8], private_pem: &str) -> Result<String, String> {
    if private_pem.contains("ENCRYPTED") {
        return Err("encrypted (cosign) keys: sign with `release/sign.sh sign-blob` or `cosign sign-blob`".into());
    }
    let b64: String = private_pem
        .lines()
        .map(str::trim)
        .skip_while(|l| !l.starts_with("-----BEGIN PRIVATE KEY-----"))
        .skip(1)
        .take_while(|l| !l.starts_with("-----END"))
        .collect();
    let der = B64.decode(b64).map_err(|e| format!("private key: {e}"))?;
    let rng = SystemRandom::new();
    let kp = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &der, &rng)
        .map_err(|_| "private key is not a PKCS#8 ECDSA P-256 key")?;
    let sig = kp.sign(&rng, data).map_err(|_| "signing failed")?;
    Ok(B64.encode(sig.as_ref()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest() -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "id": "example-files", "name": "Example", "version": "1.0.0", "publisher": "nexusbackup", "api": 1,
            "kinds": [{"kind": "files", "title": "Directory", "config_schema": {"type": "object", "properties": {"path": {"type": "string"}}},
                       "restores": [{"id": "download", "title": "Download"}]}]
        }))
        .unwrap()
    }

    #[test]
    fn pack_read_sign_verify() {
        let bin = b"\x7fELF fake".to_vec();
        let mut assets = BTreeMap::new();
        assets.insert("icon.svg".to_string(), b"<svg/>".to_vec());
        let b = pack(&manifest(), &bin, &assets).unwrap();
        assert_eq!(b, pack(&manifest(), &bin, &assets).unwrap(), "deterministic");
        let r = read(&b).unwrap();
        assert_eq!((r.bin.as_slice(), r.manifest.id.as_str()), (&bin[..], "example-files"));
        assert_eq!(r.assets["icon.svg"], b"<svg/>");
        let (sk, pk) = generate_key().unwrap();
        let sig = sign(&b, &sk).unwrap();
        let keys = vec![TrustedKey {
            name: "k".into(),
            publisher: "acme".into(),
            point: parse_public_key(&pk).unwrap(),
            builtin: false,
        }];
        assert_eq!(verify(&b, sig.as_bytes(), &keys).unwrap().name, "k");
        let mut tampered = b.clone();
        let n = tampered.len() - 600;
        tampered[n] ^= 1;
        assert!(verify(&tampered, sig.as_bytes(), &keys).is_err());
        let (_, other) = generate_key().unwrap();
        let keys2 = vec![TrustedKey {
            point: parse_public_key(&other).unwrap(),
            ..keys[0].clone()
        }];
        assert!(verify(&b, sig.as_bytes(), &keys2).is_err());
        assert_eq!(fingerprint(&keys[0].point).len(), 64);
        assert_eq!(
            parse_public_key(&public_key_pem(&keys[0].point)).unwrap(),
            keys[0].point
        );
    }

    #[test]
    fn verifies_cosign_test_key_signature() {
        // fixture of agent-core: `cosign sign-blob --key release/testkey/TEST-cosign.key blob`
        let pem = include_str!("../../../release/testkey/TEST-cosign.pub");
        let blob = include_bytes!("../../agent-core/tests/fixtures/cosign-blob.bin");
        let sig = include_bytes!("../../agent-core/tests/fixtures/cosign-blob.bin.sig");
        let keys = vec![TrustedKey {
            name: "TEST".into(),
            publisher: PROJECT_PUBLISHER.into(),
            point: parse_public_key(pem).unwrap(),
            builtin: true,
        }];
        assert!(verify(blob, sig, &keys).is_ok());
    }

    #[test]
    fn hostile_bundles_refused() {
        let tar_of = |entries: &[(&str, &[u8], tar::EntryType)]| {
            let mut b = tar::Builder::new(Vec::new());
            for (p, d, t) in entries {
                let mut h = tar::Header::new_gnu();
                h.set_entry_type(*t);
                h.set_size(d.len() as u64);
                h.set_mode(0o644);
                if *t == tar::EntryType::Symlink {
                    h.set_size(0);
                    b.append_link(&mut h, p, "/etc/passwd").unwrap();
                } else {
                    // bypass the tar crate's own path checks for `..`
                    h.as_mut_bytes()[..p.len()].copy_from_slice(p.as_bytes());
                    h.set_cksum();
                    b.append(&h, *d).unwrap();
                }
            }
            b.into_inner().unwrap()
        };
        let m = manifest();
        let reg = tar::EntryType::Regular;
        let elf: &[u8] = b"\x7fELF";
        for (bad, why) in [
            (tar_of(&[("manifest.json", &m, reg)]), "no binary"),
            (tar_of(&[("bin/plugin", elf, reg)]), "no manifest"),
            (
                tar_of(&[("manifest.json", &m, reg), ("bin/plugin", b"#!/bin/sh", reg)]),
                "not ELF",
            ),
            (
                tar_of(&[("manifest.json", &m, reg), ("bin/plugin", elf, reg), ("../x", b"", reg)]),
                "dotdot",
            ),
            (
                tar_of(&[
                    ("manifest.json", &m, reg),
                    ("bin/plugin", elf, reg),
                    ("etc/x", b"", reg),
                ]),
                "foreign file",
            ),
            (
                tar_of(&[
                    ("manifest.json", &m, reg),
                    ("bin/plugin", elf, reg),
                    ("assets/l", b"", tar::EntryType::Symlink),
                ]),
                "symlink",
            ),
            (
                tar_of(&[
                    ("manifest.json", &m, reg),
                    ("bin/plugin", elf, reg),
                    ("bin/plugin", elf, reg),
                ]),
                "duplicate",
            ),
            (b"garbage".to_vec(), "not tar"),
        ] {
            assert!(read(&bad).is_err(), "{why}");
        }
        assert!(read(&tar_of(&[("manifest.json", &m, reg), ("bin/plugin", elf, reg)])).is_ok());
    }
}
