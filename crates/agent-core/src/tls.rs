//! TLS configuration (rustls, ring provider, TLS 1.3 only, ALPN `nexus-agent/1`).
//!
//! - Enrollment mode: self-signed server certificate, no client certificate; trust is
//!   established by the token proofs bound to the TLS exporter (see `enroll.rs`).
//! - mTLS mode: server certificate = the agent certificate issued by the appliance CA;
//!   the client must present a certificate chained to that CA, with the clientAuth EKU
//!   and `CN=nexus-appliance:<id>` (optionally pinned to one id in agent.conf).

use rustls::client::danger::HandshakeSignatureValid;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::server::WebPkiClientVerifier;
use rustls::{DigitallySignedStruct, DistinguishedName, RootCertStore, ServerConfig, SignatureScheme};
use sha2::{Digest, Sha256};
use std::sync::Arc;

pub const APPLIANCE_CN_PREFIX: &str = "nexus-appliance:";
pub const AGENT_CN_PREFIX: &str = "nexus-agent:";

pub fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

pub fn fingerprint(der: &[u8]) -> String {
    hex::encode(Sha256::digest(der))
}

pub fn certs_from_pem(pem: &str) -> Result<Vec<CertificateDer<'static>>, String> {
    let v: Result<Vec<_>, _> = CertificateDer::pem_slice_iter(pem.as_bytes()).collect();
    let v = v.map_err(|e| format!("certificate PEM: {e}"))?;
    if v.is_empty() {
        return Err("no certificate in PEM".into());
    }
    Ok(v)
}

fn key_from_pem(pem: &str) -> Result<PrivateKeyDer<'static>, String> {
    let kp = rcgen::KeyPair::from_pem(pem).map_err(|e| format!("private key: {e}"))?;
    Ok(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(kp.serialize_der())))
}

fn base(provider: Arc<CryptoProvider>) -> Result<rustls::ConfigBuilder<ServerConfig, rustls::WantsVerifier>, String> {
    ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| e.to_string())
}

fn finish(mut c: ServerConfig) -> Arc<ServerConfig> {
    c.alpn_protocols = vec![agent_proto::ALPN.to_vec()];
    c.max_early_data_size = 0;
    Arc::new(c)
}

/// Enrollment mode: self-signed certificate, no client authentication.
pub fn enroll_config(key_pem: &str, cert_pem: &str) -> Result<Arc<ServerConfig>, String> {
    let c = base(provider())?
        .with_no_client_auth()
        .with_single_cert(certs_from_pem(cert_pem)?, key_from_pem(key_pem)?)
        .map_err(|e| format!("enrollment certificate: {e}"))?;
    Ok(finish(c))
}

/// mTLS mode.
pub fn mtls_config(
    key_pem: &str,
    cert_pem: &str,
    ca_pem: &str,
    pinned: Option<String>,
) -> Result<Arc<ServerConfig>, String> {
    let p = provider();
    let mut roots = RootCertStore::empty();
    for c in certs_from_pem(ca_pem)? {
        roots.add(c).map_err(|e| format!("CA certificate: {e}"))?;
    }
    let inner = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), p.clone())
        .build()
        .map_err(|e| format!("client verifier: {e}"))?;
    let verifier = Arc::new(ApplianceVerifier { inner, pinned });
    let c = base(p)?
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs_from_pem(cert_pem)?, key_from_pem(key_pem)?)
        .map_err(|e| format!("agent certificate: {e}"))?;
    Ok(finish(c))
}

/// CN of a certificate.
pub fn common_name(der: &[u8]) -> Result<String, String> {
    let (_, c) = x509_parser::parse_x509_certificate(der).map_err(|e| format!("certificate: {e}"))?;
    let cn = c.subject().iter_common_name().next().ok_or("certificate has no CN")?;
    cn.as_str().map(str::to_string).map_err(|e| format!("CN: {e}"))
}

/// Appliance id from a client certificate: CN `nexus-appliance:<id>` and an explicit
/// clientAuth EKU (webpki accepts a missing EKU extension; we do not).
pub fn appliance_id(der: &[u8], pinned: Option<&str>) -> Result<String, String> {
    let (_, c) = x509_parser::parse_x509_certificate(der).map_err(|e| format!("certificate: {e}"))?;
    let eku = c
        .extended_key_usage()
        .map_err(|e| format!("EKU: {e}"))?
        .ok_or("client certificate has no EKU")?;
    if !eku.value.client_auth {
        return Err("client certificate lacks the clientAuth EKU".into());
    }
    let cn = common_name(der)?;
    let id = cn
        .strip_prefix(APPLIANCE_CN_PREFIX)
        .filter(|id| valid_id(id))
        .ok_or_else(|| format!("client CN {cn:?} is not nexus-appliance:<id>"))?;
    if let Some(p) = pinned {
        if p != id {
            return Err(format!("appliance id {id} is not the pinned id {p}"));
        }
    }
    Ok(id.to_string())
}

pub fn valid_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 128 && id.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}

#[derive(Debug)]
struct ApplianceVerifier {
    inner: Arc<dyn ClientCertVerifier>,
    pinned: Option<String>,
}

impl ClientCertVerifier for ApplianceVerifier {
    fn client_auth_mandatory(&self) -> bool {
        true
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        self.inner.root_hint_subjects()
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        let ok = self.inner.verify_client_cert(end_entity, intermediates, now)?;
        appliance_id(end_entity, self.pinned.as_deref()).map_err(rustls::Error::General)?;
        Ok(ok)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

/// Key pair + self-signed enrollment certificate (`init`).
pub fn new_identity(hostname: &str) -> Result<(String, String), String> {
    let kp = rcgen::KeyPair::generate().map_err(|e| e.to_string())?;
    let mut params = rcgen::CertificateParams::new(vec![hostname.to_string()]).map_err(|e| e.to_string())?;
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "nexus-agent enrollment");
    let cert = params.self_signed(&kp).map_err(|e| e.to_string())?;
    Ok((kp.serialize_pem(), cert.pem()))
}

/// A new key pair (PEM), certificate renewal.
pub fn new_key() -> Result<String, String> {
    Ok(rcgen::KeyPair::generate().map_err(|e| e.to_string())?.serialize_pem())
}

/// CSR for the existing key (the appliance sets CN, EKU and validity).
pub fn csr(key_pem: &str) -> Result<String, String> {
    let kp = rcgen::KeyPair::from_pem(key_pem).map_err(|e| e.to_string())?;
    let mut params = rcgen::CertificateParams::new(vec![]).map_err(|e| e.to_string())?;
    params.distinguished_name.push(rcgen::DnType::CommonName, "nexus-agent");
    params
        .serialize_request(&kp)
        .and_then(|r| r.pem())
        .map_err(|e| e.to_string())
}

/// Validate what `EnrollDone` delivers: the certificate is for our key, names
/// `nexus-agent:<agent_id>`, is signed by the delivered CA certificate, and the CA is
/// a CA. Returns nothing; the caller stores the PEMs.
pub fn check_issued(key_pem: &str, cert_pem: &str, ca_pem: &str, agent_id: &str) -> Result<(), String> {
    if !valid_id(agent_id) {
        return Err("invalid agent id".into());
    }
    let kp = rcgen::KeyPair::from_pem(key_pem).map_err(|e| e.to_string())?;
    let cert_der = certs_from_pem(cert_pem)?.remove(0);
    let ca_der = certs_from_pem(ca_pem)?.remove(0);
    let (_, cert) = x509_parser::parse_x509_certificate(&cert_der).map_err(|e| format!("agent certificate: {e}"))?;
    let (_, ca) = x509_parser::parse_x509_certificate(&ca_der).map_err(|e| format!("CA certificate: {e}"))?;
    if cert.public_key().raw != kp.public_key_der().as_slice() {
        return Err("issued certificate is not for this agent's key".into());
    }
    let cn = common_name(&cert_der)?;
    if cn != format!("{AGENT_CN_PREFIX}{agent_id}") {
        return Err(format!(
            "issued certificate CN {cn:?} does not match agent id {agent_id}"
        ));
    }
    if !ca.is_ca() {
        return Err("CA certificate is not a CA".into());
    }
    cert.verify_signature(Some(ca.public_key()))
        .map_err(|e| format!("certificate not signed by the CA: {e}"))?;
    // the result must be usable as a server identity
    mtls_config(key_pem, cert_pem, ca_pem, None).map(drop)
}
