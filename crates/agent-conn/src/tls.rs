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
use std::io::{Read, Write};
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
        pins: pins.iter().map(std::string::ToString::to_string).collect(),
    };
    client_config(ca, Arc::new(v))
}

/// What a session runs over: a TCP connection to the agent, or a stream relayed by
/// an edge proxy (crate::edge; the agent session's TLS runs inside it).
pub trait Transport: Read + Write + Send {
    fn set_read_timeout(&self, t: Option<Duration>) -> std::io::Result<()>;
}

impl Transport for TcpStream {
    fn set_read_timeout(&self, t: Option<Duration>) -> std::io::Result<()> {
        TcpStream::set_read_timeout(self, t)
    }
}

impl Transport for StreamOwned<ClientConnection, TcpStream> {
    fn set_read_timeout(&self, t: Option<Duration>) -> std::io::Result<()> {
        self.sock.set_read_timeout(t)
    }
}

/// One TLS connection to an agent; framing per agent-proto.
pub struct Session {
    pub s: StreamOwned<ClientConnection, Box<dyn Transport>>,
    /// capabilities from `HelloReply` (empty until `hello`)
    pub caps: Vec<String>,
    /// `direct` or `edge`
    pub via: &'static str,
}

impl Session {
    pub fn has_cap(&self, cap: &str) -> bool {
        self.caps.iter().any(|c| c == cap)
    }
}

/// What a failed connect to an agent most likely means, and what to do (shown in the job log).
fn connect_hint(e: &std::io::Error, port: u16) -> String {
    use std::io::ErrorKind::*;
    match e.kind() {
        // firewalld and iptables REJECT answer with ICMP host-prohibited (EHOSTUNREACH)
        HostUnreachable | NetworkUnreachable => format!(
            "a firewall on the agent host rejects the connection, or the host is down: allow TCP {port} from \
             this appliance"
        ),
        ConnectionRefused => {
            format!("nothing listens on {port}: is the agent service running? It starts only after `nexus-agent init`")
        }
        TimedOut | WouldBlock => format!(
            "no answer: the host is off, the address is wrong, or a firewall drops the packets (allow TCP {port} \
             from this appliance)"
        ),
        _ => "see the error below".into(),
    }
}

/// TCP connection with timeouts (`connect` ≤ `connect_timeout`).
pub fn tcp(host: &str, port: u16, connect_timeout: Duration, timeout: Duration) -> Result<TcpStream> {
    let addrs: Vec<_> = (host.trim_matches(['[', ']']), port)
        .to_socket_addrs()
        .with_context(|| format!("resolve {host}"))?
        .collect();
    let mut last = None;
    let mut tcp = None;
    for a in addrs {
        match TcpStream::connect_timeout(&a, connect_timeout) {
            Ok(t) => {
                tcp = Some(t);
                break;
            }
            Err(e) => last = Some(e),
        }
    }
    let tcp = match (tcp, last) {
        (Some(t), _) => t,
        (None, Some(e)) => {
            let hint = connect_hint(&e, port);
            return Err(e).with_context(|| format!("connect {host}:{port} ({hint})"));
        }
        (None, None) => bail!("{host}: no address"),
    };
    tcp.set_read_timeout(Some(timeout))?;
    tcp.set_write_timeout(Some(timeout))?;
    tcp.set_nodelay(true)?;
    Ok(tcp)
}

/// How to reach an agent: its address, and optionally an edge proxy (tried when the
/// direct connection fails).
pub struct Route<'a> {
    pub host: &'a str,
    pub port: u16,
    pub edge: Option<&'a crate::edge::EdgeTarget>,
}

impl Session {
    pub fn connect(host: &str, port: u16, cfg: Arc<ClientConfig>, timeout: Duration) -> Result<Session> {
        let t = tcp(host, port, timeout.min(Duration::from_secs(15)), timeout)?;
        Session::over(Box::new(t), cfg, &format!("{host}:{port}"), "direct")
    }

    /// Direct first (3 s to connect when an edge is set), then through the edge.
    pub fn connect_route(
        r: &Route,
        ca: &Ca,
        agent_id: &str,
        cfg: Arc<ClientConfig>,
        timeout: Duration,
    ) -> Result<Session> {
        let Some(edge) = r.edge else {
            return Session::connect(r.host, r.port, cfg, timeout);
        };
        let direct = tcp(r.host, r.port, Duration::from_secs(3), timeout)
            .and_then(|t| Session::over(Box::new(t), cfg.clone(), &format!("{}:{}", r.host, r.port), "direct"));
        match direct {
            Ok(s) => Ok(s),
            Err(d) => {
                let t = crate::edge::open(ca, edge, agent_id, timeout)
                    .with_context(|| format!("direct: {d:#}; via edge {}:{}", edge.host, edge.port))?;
                Session::over(
                    t,
                    cfg,
                    &format!("agent {agent_id} via edge {}:{}", edge.host, edge.port),
                    "edge",
                )
            }
        }
    }

    /// The agent-protocol TLS session over `t`.
    pub fn over(t: Box<dyn Transport>, cfg: Arc<ClientConfig>, label: &str, via: &'static str) -> Result<Session> {
        let conn = ClientConnection::new(cfg, ServerName::try_from("nexus-agent").unwrap())?;
        let mut s = StreamOwned::new(conn, t);
        while s.conn.is_handshaking() {
            s.conn
                .complete_io(&mut s.sock)
                .with_context(|| format!("TLS handshake with {label}"))?;
        }
        if s.conn.alpn_protocol() != Some(ALPN) {
            bail!("{label}: agent did not negotiate ALPN nexus-agent/1");
        }
        Ok(Session {
            s,
            caps: Vec::new(),
            via,
        })
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
                let facts = agent_proto::release::HostFacts::from_caps(&os, &caps);
                Ok(AgentInfo {
                    agent_id: id,
                    kernel,
                    hostname,
                    version: agent_version,
                    protocol: agent_proto::release::protocol_of(&caps).into(),
                    arch: facts.arch,
                    install: facts.install,
                    gui_version: facts.gui_version,
                    os,
                    caps,
                    via: self.via.into(),
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
    /// route of this session: `direct` or `edge`
    pub via: String,
    /// v1.8 host facts (older agents: derived, see `HostFacts::from_caps`)
    pub arch: String,
    pub install: String,
    pub gui_version: Option<String>,
    /// "1.8" with chunked updates, else "1.7"
    pub protocol: String,
}

impl AgentInfo {
    pub fn facts(&self) -> agent_proto::release::HostFacts {
        agent_proto::release::HostFacts::from_caps(&self.os, &self.caps)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connect_hints_name_the_likely_cause() {
        use std::io::{Error, ErrorKind};
        let h = |k| connect_hint(&Error::from(k), 7444);
        assert!(h(ErrorKind::HostUnreachable).contains("firewall on the agent host rejects"));
        assert!(h(ErrorKind::ConnectionRefused).contains("nothing listens on 7444"));
        assert!(h(ErrorKind::TimedOut).contains("allow TCP 7444"));
        // EHOSTUNREACH as the OS reports it (firewalld REJECT)
        assert!(connect_hint(&Error::from_raw_os_error(113), 7444).contains("firewall"));
    }
}
