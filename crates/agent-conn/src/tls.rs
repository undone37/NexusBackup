//! TLS 1.3 client side of the agent protocol (rustls, ring): enrollment
//! connections (no certificate validation; the token proofs bind the session)
//! and mTLS sessions (agent cert must chain to the appliance CA, carry EKU
//! serverAuth, `CN=nexus-agent:<agent-id>` and, once enrolled, match the
//! fingerprint recorded at enrollment).

use crate::ca::{common_name, pem_to_der, sha256_hex, Ca, AGENT_CN_PREFIX};
use agent_proto::{read_msg, write_msg, Message, ALPN, EXPORTER_LABEL, VERSION};
use anyhow::{bail, Context, Result};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::verify_server_cert_signed_by_trust_anchor;
use rustls::crypto::{verify_tls13_signature, CryptoProvider};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::server::ParsedCertificate;
use rustls::{
    CertificateError, ClientConfig, ClientConnection, DigitallySignedStruct, Error, RootCertStore, SignatureScheme,
    StreamOwned,
};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

pub fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// Enrollment: any certificate (the agent is self-signed in enrollment mode),
/// but the handshake signature must be made with the presented key.
#[derive(Debug)]
struct EnrollVerifier(Arc<CryptoProvider>);

impl ServerCertVerifier for EnrollVerifier {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Err(Error::PeerIncompatible(rustls::PeerIncompatible::Tls12NotOffered))
    }
    fn verify_tls13_signature(
        &self,
        msg: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls13_signature(msg, cert, dss, &self.0.signature_verification_algorithms)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// mTLS: chain to the appliance CA (EKU serverAuth), expected CN, optional pin.
#[derive(Debug)]
pub struct AgentVerifier {
    provider: Arc<CryptoProvider>,
    roots: RootCertStore,
    expected_cn: String,
    /// accepted fingerprints (empty = any certificate of the CA): the recorded
    /// one, plus a renewed one not yet confirmed
    pins: Vec<String>,
}

impl ServerCertVerifier for AgentVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        let cert = ParsedCertificate::try_from(end_entity)?;
        verify_server_cert_signed_by_trust_anchor(
            &cert,
            &self.roots,
            intermediates,
            now,
            self.provider.signature_verification_algorithms.all,
        )?;
        if common_name(end_entity).as_deref() != Some(self.expected_cn.as_str()) {
            return Err(Error::InvalidCertificate(CertificateError::NotValidForName));
        }
        let fp = sha256_hex(end_entity);
        if !self.pins.is_empty() && !self.pins.iter().any(|p| p.eq_ignore_ascii_case(&fp)) {
            return Err(Error::InvalidCertificate(
                CertificateError::ApplicationVerificationFailure,
            ));
        }
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Err(Error::PeerIncompatible(rustls::PeerIncompatible::Tls12NotOffered))
    }
    fn verify_tls13_signature(
        &self,
        msg: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls13_signature(msg, cert, dss, &self.provider.signature_verification_algorithms)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

fn client_config(ca: &Ca, verifier: Arc<dyn ServerCertVerifier>) -> Result<Arc<ClientConfig>> {
    let chain = vec![CertificateDer::from(pem_to_der(&ca.client_pem)?)];
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ca.client_key_der.clone()));
    let mut cfg = ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_auth_cert(chain, key)?;
    cfg.alpn_protocols = vec![ALPN.to_vec()];
    cfg.enable_sni = false;
    Ok(Arc::new(cfg))
}

/// Client config for the enrollment connection. The appliance client cert is
/// offered too (an agent in enrollment mode may ignore it).
pub fn enroll_config(ca: &Ca) -> Result<Arc<ClientConfig>> {
    client_config(ca, Arc::new(EnrollVerifier(provider())))
}

/// Client config for an mTLS session with agent `agent_id`; `pin` = the
/// SHA-256 (hex) of the agent certificate recorded at enrollment.
pub fn session_config(ca: &Ca, agent_id: &str, pin: Option<&str>) -> Result<Arc<ClientConfig>> {
    session_config_pins(ca, agent_id, pin.as_slice())
}

/// Like [`session_config`], accepting any of `pins` (certificate renewal).
pub fn session_config_pins(ca: &Ca, agent_id: &str, pins: &[&str]) -> Result<Arc<ClientConfig>> {
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(pem_to_der(&ca.ca_pem)?))?;
    let v = AgentVerifier {
        provider: provider(),
        roots,
        expected_cn: format!("{AGENT_CN_PREFIX}{agent_id}"),
        pins: pins.iter().map(|p| p.to_string()).collect(),
    };
    client_config(ca, Arc::new(v))
}

/// One TLS connection to an agent; framing per agent-proto.
pub struct Session {
    pub s: StreamOwned<ClientConnection, TcpStream>,
    /// capabilities from `HelloReply` (empty until `hello`)
    pub caps: Vec<String>,
}

impl Session {
    pub fn has_cap(&self, cap: &str) -> bool {
        self.caps.iter().any(|c| c == cap)
    }
}

impl Session {
    pub fn connect(host: &str, port: u16, cfg: Arc<ClientConfig>, timeout: Duration) -> Result<Session> {
        let addrs: Vec<_> = (host.trim_matches(['[', ']']), port)
            .to_socket_addrs()
            .with_context(|| format!("resolve {host}"))?
            .collect();
        let mut last = None;
        let mut tcp = None;
        for a in addrs {
            match TcpStream::connect_timeout(&a, Duration::from_secs(15)) {
                Ok(t) => {
                    tcp = Some(t);
                    break;
                }
                Err(e) => last = Some(e),
            }
        }
        let tcp = match (tcp, last) {
            (Some(t), _) => t,
            (None, Some(e)) => return Err(e).with_context(|| format!("connect {host}:{port}")),
            (None, None) => bail!("{host}: no address"),
        };
        tcp.set_read_timeout(Some(timeout))?;
        tcp.set_write_timeout(Some(timeout))?;
        tcp.set_nodelay(true)?;
        let conn = ClientConnection::new(cfg, ServerName::try_from("nexus-agent").unwrap())?;
        let mut s = StreamOwned::new(conn, tcp);
        while s.conn.is_handshaking() {
            s.conn
                .complete_io(&mut s.sock)
                .with_context(|| format!("TLS handshake with {host}:{port}"))?;
        }
        if s.conn.alpn_protocol() != Some(ALPN) {
            bail!("{host}:{port}: agent did not negotiate ALPN nexus-agent/1");
        }
        Ok(Session { s, caps: Vec::new() })
    }

    /// TLS exporter bound to this session (enrollment proofs).
    pub fn exporter(&self) -> Result<[u8; 32]> {
        Ok(self.s.conn.export_keying_material([0u8; 32], EXPORTER_LABEL, None)?)
    }

    pub fn send(&mut self, m: &Message) -> Result<()> {
        write_msg(&mut self.s, m).context("send to agent")
    }

    /// Next message; an agent `Error` becomes an error.
    pub fn recv(&mut self) -> Result<Message> {
        match read_msg(&mut self.s).context("receive from agent")? {
            Message::Error { code, message } => bail!("agent error {code}: {message:?}"),
            m => Ok(m),
        }
    }

    /// The agent's certificate of this session: (SHA-256 hex, not_before, not_after).
    pub fn peer_cert(&self) -> Option<(String, i64, i64)> {
        let der = self.s.conn.peer_certificates()?.first()?;
        let (nb, na) = crate::ca::cert_validity(der)?;
        Some((sha256_hex(der), nb, na))
    }

    pub fn set_timeout(&mut self, t: Duration) {
        let _ = self.s.sock.set_read_timeout(Some(t));
    }

    /// `Hello`: version must match, the agent must report the expected id.
    pub fn hello(&mut self, agent_id: &str) -> Result<AgentInfo> {
        self.send(&Message::Hello { version: VERSION })?;
        match self.recv()? {
            Message::HelloReply {
                version,
                agent_id: id,
                os,
                kernel,
                hostname,
                agent_version,
                caps,
            } => {
                if version != VERSION {
                    bail!("agent speaks protocol version {version}, appliance {VERSION}");
                }
                if id != agent_id {
                    bail!("agent reports id {id:?}, expected {agent_id:?}");
                }
                self.caps = caps.clone();
                Ok(AgentInfo {
                    agent_id: id,
                    os,
                    kernel,
                    hostname,
                    version: agent_version,
                    caps,
                })
            }
            m => bail!("unexpected answer to Hello: {}", crate::name(&m)),
        }
    }

    pub fn close(mut self) {
        self.s.conn.send_close_notify();
        let _ = self.s.conn.complete_io(&mut self.s.sock);
    }
}

#[derive(serde::Serialize, Debug, Clone)]
pub struct AgentInfo {
    pub agent_id: String,
    pub os: String,
    pub kernel: String,
    pub hostname: String,
    pub version: String,
    pub caps: Vec<String>,
}
