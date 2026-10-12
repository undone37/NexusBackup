//! Appliance CA for agents (docs/agent-protocol.md "Transport"): created on
//! first use in `ca_dir` (under the scheduler state dir), keys 0600.
//!
//! ```text
//! appliance-id      random id, part of the appliance client cert CN
//! ca.key / ca.pem   ECDSA P-256 CA (path length 0), 20 years
//! client.key / client.pem   CN=nexus-appliance:<appliance-id>, EKU clientAuth, 10 years
//! ```
//! Agent certificates: CN=nexus-agent:<agent-id>, EKU serverAuth, 10 years; the
//! CSR only contributes its (signature-checked) public key, every other field
//! is chosen here.

use anyhow::{bail, Context, Result};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose, SerialNumber, SubjectPublicKeyInfo,
};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use time::{Duration, OffsetDateTime};

pub const AGENT_CN_PREFIX: &str = "nexus-agent:";
pub const APPLIANCE_CN_PREFIX: &str = "nexus-appliance:";

pub struct Ca {
    pub dir: PathBuf,
    pub appliance_id: String,
    pub ca_pem: String,
    ca_key: KeyPair,
    pub client_pem: String,
    pub client_key_der: Vec<u8>,
}

pub fn sha256_hex(b: &[u8]) -> String {
    Sha256::digest(b).iter().map(|b| format!("{b:02x}")).collect()
}

pub fn random_hex(bytes: usize) -> String {
    let mut b = vec![0u8; bytes];
    getrandom(&mut b);
    b.iter().map(|b| format!("{b:02x}")).collect()
}

fn getrandom(buf: &mut [u8]) {
    rustls::crypto::ring::default_provider()
        .secure_random
        .fill(buf)
        .expect("system random");
}

/// DER of the first certificate in a PEM string.
pub fn pem_to_der(pem: &str) -> Result<Vec<u8>> {
    let p = pem::parse(pem).context("PEM")?;
    Ok(p.contents().to_vec())
}

fn write_private(path: &Path, data: &[u8]) -> Result<()> {
    let tmp = path.with_extension("tmp");
    let _ = fs::remove_file(&tmp);
    let mut f = OpenOptions::new().write(true).create_new(true).mode(0o600).open(&tmp)?;
    f.write_all(data)?;
    f.sync_all()?;
    fs::rename(&tmp, path)?;
    Ok(())
}

fn validity(p: &mut CertificateParams, years: i64) {
    let now = OffsetDateTime::now_utc();
    p.not_before = now - Duration::days(1);
    p.not_after = now + Duration::days(365 * years);
    let mut serial = [0u8; 16];
    getrandom(&mut serial);
    serial[0] &= 0x7f; // positive
    p.serial_number = Some(SerialNumber::from(serial.to_vec()));
}

fn dn(cn: &str) -> DistinguishedName {
    let mut d = DistinguishedName::new();
    d.push(DnType::CommonName, cn);
    d
}

impl Ca {
    /// Loads the CA, creating it (and the appliance client cert) on first use.
    /// Concurrent callers are serialized with a lock file.
    pub fn load_or_create(dir: &Path) -> Result<Ca> {
        fs::DirBuilder::new().recursive(true).mode(0o700).create(dir)?;
        let lock = File::create(dir.join(".lock"))?;
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) } != 0 {
            return Err(std::io::Error::last_os_error()).context("lock CA dir");
        }
        if !dir.join("ca.pem").exists() {
            Self::create(dir)?;
        }
        Self::load(dir)
    }

    fn create(dir: &Path) -> Result<()> {
        let id = random_hex(8);
        let ca_key = KeyPair::generate()?;
        let mut p = CertificateParams::default();
        p.distinguished_name = dn(&format!("NexusBackup agent CA {id}"));
        p.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        p.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        validity(&mut p, 20);
        let ca = p.self_signed(&ca_key)?;
        let client_key = KeyPair::generate()?;
        let mut c = CertificateParams::default();
        c.distinguished_name = dn(&format!("{APPLIANCE_CN_PREFIX}{id}"));
        c.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        c.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        validity(&mut c, 10);
        let client = c.signed_by(&client_key, &ca, &ca_key)?;
        // keys first, the CA cert last: its presence marks a complete CA
        write_private(&dir.join("ca.key"), ca_key.serialize_pem().as_bytes())?;
        write_private(&dir.join("client.key"), client_key.serialize_pem().as_bytes())?;
        write_private(&dir.join("client.pem"), client.pem().as_bytes())?;
        write_private(&dir.join("appliance-id"), format!("{id}\n").as_bytes())?;
        write_private(&dir.join("ca.pem"), ca.pem().as_bytes())?;
        File::open(dir)?.sync_all()?;
        eprintln!("agent CA created in {} (appliance id {id})", dir.display());
        Ok(())
    }

    fn load(dir: &Path) -> Result<Ca> {
        for k in ["ca.key", "client.key"] {
            let m = fs::metadata(dir.join(k))?;
            if m.permissions().mode() & 0o077 != 0 {
                bail!("{}: must not be readable by group or others", dir.join(k).display());
            }
        }
        let rd = |n: &str| fs::read_to_string(dir.join(n)).with_context(|| format!("{}", dir.join(n).display()));
        let client_key = KeyPair::from_pem(&rd("client.key")?)?;
        Ok(Ca {
            dir: dir.to_owned(),
            appliance_id: rd("appliance-id")?.trim().to_owned(),
            ca_pem: rd("ca.pem")?,
            ca_key: KeyPair::from_pem(&rd("ca.key")?)?,
            client_pem: rd("client.pem")?,
            client_key_der: client_key.serialize_der(),
        })
    }

    /// Signs an agent CSR (PKCS#10 PEM). Only the CSR's public key is used,
    /// after its self-signature is checked. Returns (cert PEM, SHA-256 of the DER).
    pub fn sign_agent(&self, csr_pem: &str, agent_id: &str) -> Result<(String, String)> {
        use x509_parser::prelude::FromDer;
        if !crate::valid_agent_id(agent_id) {
            bail!("invalid agent id {agent_id:?}");
        }
        let der = pem_to_der(csr_pem).context("CSR")?;
        let (_, csr) = x509_parser::certification_request::X509CertificationRequest::from_der(&der)
            .map_err(|e| anyhow::anyhow!("CSR: {e}"))?;
        csr.verify_signature()
            .map_err(|e| anyhow::anyhow!("CSR signature invalid: {e}"))?;
        let spki = SubjectPublicKeyInfo::from_der(csr.certification_request_info.subject_pki.raw)
            .context("CSR public key (supported: ECDSA P-256/P-384, Ed25519, RSA)")?;
        let issuer = CertificateParams::from_ca_cert_pem(&self.ca_pem)?.self_signed(&self.ca_key)?;
        let mut p = CertificateParams::default();
        p.distinguished_name = dn(&format!("{AGENT_CN_PREFIX}{agent_id}"));
        p.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        validity(&mut p, 10);
        let cert = p.signed_by(&spki, &issuer, &self.ca_key)?;
        Ok((cert.pem(), sha256_hex(cert.der())))
    }

    /// Issues a certificate for a key pair generated here (tests, fake agents).
    pub fn issue(&self, key: &KeyPair, cn: &str, eku: ExtendedKeyUsagePurpose) -> Result<String> {
        let issuer = CertificateParams::from_ca_cert_pem(&self.ca_pem)?.self_signed(&self.ca_key)?;
        let mut p = CertificateParams::default();
        p.distinguished_name = dn(cn);
        p.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        p.extended_key_usages = vec![eku];
        validity(&mut p, 1);
        Ok(p.signed_by(key, &issuer, &self.ca_key)?.pem())
    }
}

/// (not_before, not_after) of a DER certificate, Unix seconds.
pub fn cert_validity(der: &[u8]) -> Option<(i64, i64)> {
    let (_, c) = x509_parser::parse_x509_certificate(der).ok()?;
    Some((c.validity().not_before.timestamp(), c.validity().not_after.timestamp()))
}

/// CN of a DER certificate.
pub fn common_name(der: &[u8]) -> Option<String> {
    let (_, c) = x509_parser::parse_x509_certificate(der).ok()?;
    let cn = c.subject().iter_common_name().next()?.as_str().ok()?.to_owned();
    Some(cn)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_once_and_signs_csrs() {
        let d = tempfile::tempdir().unwrap();
        let dir = d.path().join("ca");
        let a = Ca::load_or_create(&dir).unwrap();
        let b = Ca::load_or_create(&dir).unwrap();
        assert_eq!(a.appliance_id, b.appliance_id);
        assert_eq!(a.ca_pem, b.ca_pem);
        for k in ["ca.key", "client.key"] {
            assert_eq!(fs::metadata(dir.join(k)).unwrap().permissions().mode() & 0o777, 0o600);
        }
        assert_eq!(
            common_name(&pem_to_der(&a.client_pem).unwrap()).unwrap(),
            format!("nexus-appliance:{}", a.appliance_id)
        );
        let key = KeyPair::generate().unwrap();
        let mut p = CertificateParams::default();
        p.distinguished_name = dn("whatever-the-agent-asks-for");
        let csr = p.serialize_request(&key).unwrap().pem().unwrap();
        let (cert, fp) = a.sign_agent(&csr, "0123456789abcdef").unwrap();
        let der = pem_to_der(&cert).unwrap();
        assert_eq!(fp, sha256_hex(&der));
        assert_eq!(common_name(&der).unwrap(), "nexus-agent:0123456789abcdef");
        // tampered CSR: signature check fails
        let mut bad = pem_to_der(&csr).unwrap();
        let n = bad.len();
        bad[n - 5] ^= 1;
        let bad = pem::encode(&pem::Pem::new("CERTIFICATE REQUEST", bad));
        assert!(a.sign_agent(&bad, "0123456789abcdef").is_err());
        assert!(a.sign_agent(&csr, "../x").is_err());
        // group-readable key refused
        fs::set_permissions(dir.join("ca.key"), fs::Permissions::from_mode(0o640)).unwrap();
        assert!(Ca::load_or_create(&dir).is_err());
    }
}
