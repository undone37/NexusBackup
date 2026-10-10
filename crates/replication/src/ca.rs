//! Replication CA of the primary (docs/replication.md §4), held by
//! nexus-replicad only (`/var/lib/nexus/replicad`, keys 0600). It signs the
//! client certificates of enrolled secondaries; the web-api gets the CA
//! certificate (public) to verify them.
//!
//! ```text
//! ca.key / ca.pem   ECDSA P-256 CA (path length 0), 20 years
//! ```
//! Peer certificates: `CN=nexus-replica:<peer-id>`, EKU clientAuth, 10 years;
//! the CSR only contributes its (signature-checked) public key.

use crate::{sha256_hex, valid_peer_id, CN_PREFIX};
use anyhow::{bail, Context, Result};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose, SerialNumber, SubjectPublicKeyInfo,
};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;
use time::{Duration, OffsetDateTime};

pub struct Ca {
    pub ca_pem: String,
    ca_key: KeyPair,
}

pub fn random_bytes(buf: &mut [u8]) {
    rustls::crypto::ring::default_provider()
        .secure_random
        .fill(buf)
        .expect("system random");
}

/// DER of the first PEM block.
pub fn pem_to_der(pem: &str) -> Result<Vec<u8>> {
    Ok(pem::parse(pem).context("PEM")?.contents().to_vec())
}

pub(crate) fn write_private(path: &Path, data: &[u8]) -> Result<()> {
    let tmp = path.with_extension("tmp");
    let _ = fs::remove_file(&tmp);
    let mut f = OpenOptions::new().write(true).create_new(true).mode(0o600).open(&tmp)?;
    f.write_all(data)?;
    f.sync_all()?;
    fs::rename(&tmp, path)?;
    if let Some(d) = path.parent() {
        File::open(d)?.sync_all()?;
    }
    Ok(())
}

fn validity(p: &mut CertificateParams, years: i64) {
    let now = OffsetDateTime::now_utc();
    p.not_before = now - Duration::days(1);
    p.not_after = now + Duration::days(365 * years);
    let mut serial = [0u8; 16];
    random_bytes(&mut serial);
    serial[0] &= 0x7f;
    p.serial_number = Some(SerialNumber::from(serial.to_vec()));
}

fn dn(cn: &str) -> DistinguishedName {
    let mut d = DistinguishedName::new();
    d.push(DnType::CommonName, cn);
    d
}

impl Ca {
    /// Loads the CA in `dir`, creating it on first use (under a lock).
    pub fn load_or_create(dir: &Path) -> Result<Ca> {
        fs::DirBuilder::new().recursive(true).mode(0o700).create(dir)?;
        let lock = File::create(dir.join(".ca.lock"))?;
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) } != 0 {
            return Err(std::io::Error::last_os_error()).context("lock CA dir");
        }
        if !dir.join("ca.pem").exists() {
            let mut id = [0u8; 8];
            random_bytes(&mut id);
            let key = KeyPair::generate()?;
            let mut p = CertificateParams::default();
            p.distinguished_name = dn(&format!("NexusBackup replication CA {}", crate::hex(&id)));
            p.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
            p.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
            validity(&mut p, 20);
            let ca = p.self_signed(&key)?;
            write_private(&dir.join("ca.key"), key.serialize_pem().as_bytes())?;
            write_private(&dir.join("ca.pem"), ca.pem().as_bytes())?;
            eprintln!("replication CA created in {}", dir.display());
        }
        let m = fs::metadata(dir.join("ca.key"))?;
        if m.permissions().mode() & 0o077 != 0 {
            bail!(
                "{}: must not be readable by group or others",
                dir.join("ca.key").display()
            );
        }
        let rd = |n: &str| fs::read_to_string(dir.join(n)).with_context(|| format!("{}", dir.join(n).display()));
        Ok(Ca {
            ca_pem: rd("ca.pem")?,
            ca_key: KeyPair::from_pem(&rd("ca.key")?)?,
        })
    }

    /// Signs a secondary's CSR (PKCS#10 PEM): only its public key is used, after
    /// the self-signature is checked. Returns (cert PEM, SHA-256 of the DER).
    pub fn sign_peer(&self, csr_pem: &str, peer_id: &str) -> Result<(String, String)> {
        use x509_parser::prelude::FromDer;
        if !valid_peer_id(peer_id) {
            bail!("invalid peer id {peer_id:?}");
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
        p.distinguished_name = dn(&format!("{CN_PREFIX}{peer_id}"));
        p.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        validity(&mut p, 10);
        let cert = p.signed_by(&spki, &issuer, &self.ca_key)?;
        Ok((cert.pem(), sha256_hex(cert.der())))
    }
}

/// A fresh ECDSA P-256 key and a CSR for it (secondary side): (key PEM, CSR PEM).
pub fn new_key_and_csr(cn: &str) -> Result<(String, String)> {
    let key = KeyPair::generate()?;
    let mut p = CertificateParams::default();
    p.distinguished_name = dn(cn);
    let csr = p.serialize_request(&key)?.pem()?;
    Ok((key.serialize_pem(), csr))
}

/// Subject CN of a DER certificate.
pub fn common_name(der: &[u8]) -> Option<String> {
    let (_, c) = x509_parser::parse_x509_certificate(der).ok()?;
    let cn = c.subject().iter_common_name().next()?.as_str().ok()?.to_owned();
    Some(cn)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signs_client_certs_only_for_valid_csrs() {
        let d = tempfile::tempdir().unwrap();
        let a = Ca::load_or_create(d.path()).unwrap();
        assert_eq!(a.ca_pem, Ca::load_or_create(d.path()).unwrap().ca_pem);
        assert_eq!(
            fs::metadata(d.path().join("ca.key")).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let (_, csr) = new_key_and_csr("whatever").unwrap();
        let (cert, fp) = a.sign_peer(&csr, "0123456789abcdef").unwrap();
        let der = pem_to_der(&cert).unwrap();
        assert_eq!(fp, sha256_hex(&der));
        assert_eq!(common_name(&der).unwrap(), "nexus-replica:0123456789abcdef");
        let (_, c) = x509_parser::parse_x509_certificate(&der).unwrap();
        let eku = c.extended_key_usage().unwrap().unwrap().value;
        assert!(eku.client_auth && !eku.server_auth);
        let mut bad = pem_to_der(&csr).unwrap();
        let n = bad.len();
        bad[n - 5] ^= 1;
        let bad = pem::encode(&pem::Pem::new("CERTIFICATE REQUEST", bad));
        assert!(a.sign_peer(&bad, "0123456789abcdef").is_err());
        assert!(a.sign_peer(&csr, "../x").is_err());
    }
}
