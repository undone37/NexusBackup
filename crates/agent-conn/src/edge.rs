//! Appliance side of the edge proxy (docs/edge.md, `agent_proto::edge`). The
//! appliance connects *out* to the edge's control port with its client certificate
//! (`CN=nexus-appliance:<id>`, the one agents trust) and pins the edge certificate
//! learned at enrollment:
//!
//! - **enroll** (`nexus-agentctl … edge-enroll`): one-time token proofs bound to the
//!   TLS exporter (roles `edge-appliance` / `edge`); the edge pins our client
//!   certificate, we record its certificate fingerprint.
//! - **link** (`edge-link`, kept running by the scheduler): `Configure` (agent CA +
//!   pins of the agents assigned to this edge), a signed update if the appliance
//!   ships a newer edge binary, then `Wait` long polls for health, wakes and log lines.
//! - **open**: a stream to an agent; the agent session ([`crate::tls::Session`]) runs
//!   its own TLS inside it, end to end with the agent.

use crate::ca::{pem_to_der, sha256_hex, Ca};
use crate::tls::{provider, Transport};
use agent_proto::edge::{self as proto, EdgeAgent, EdgeLimits, EdgeMsg, MAX_CONTROL_FRAME};
use agent_proto::{enroll_proof, proof_eq};
use anyhow::{bail, Context, Result};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{verify_tls13_signature, CryptoProvider};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{ClientConfig, ClientConnection, DigitallySignedStruct, Error, SignatureScheme, StreamOwned};
use serde::Deserialize;
use serde_json::json;
use std::fs;
use std::net::TcpStream;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

type Conn = StreamOwned<ClientConnection, TcpStream>;

/// An edge as the appliance dials it (control port).
#[derive(Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct EdgeTarget {
    pub host: String,
    pub port: u16,
    /// pinned edge certificate (absent only for enrollment)
    #[serde(default)]
    pub cert_sha256: Option<String>,
}

/// Edge certificate: the pinned one; any (signature still checked) when enrolling.
#[derive(Debug)]
struct EdgeVerifier {
    provider: Arc<CryptoProvider>,
    pin: Option<String>,
}

impl ServerCertVerifier for EdgeVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        match &self.pin {
            Some(p) if !p.eq_ignore_ascii_case(&sha256_hex(end_entity)) => Err(Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            )),
            _ => Ok(ServerCertVerified::assertion()),
        }
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
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls13_signature(m, c, d, &self.provider.signature_verification_algorithms)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

/// TLS to the control port with the appliance client certificate.
fn connect(ca: &Ca, host: &str, port: u16, pin: Option<&str>, timeout: Duration) -> Result<Conn> {
    let chain = vec![CertificateDer::from(pem_to_der(&ca.client_pem)?)];
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ca.client_key_der.clone()));
    let mut cfg = ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(EdgeVerifier {
            provider: provider(),
            pin: pin.map(str::to_owned),
        }))
        .with_client_auth_cert(chain, key)?;
    cfg.alpn_protocols = vec![proto::ALPN.to_vec()];
    cfg.enable_sni = false;
    let tcp = crate::tls::tcp(host, port, timeout.min(Duration::from_secs(15)), timeout)?;
    let conn = ClientConnection::new(Arc::new(cfg), ServerName::try_from("nexus-edge").unwrap())?;
    let mut s = StreamOwned::new(conn, tcp);
    while s.conn.is_handshaking() {
        s.conn
            .complete_io(&mut s.sock)
            .with_context(|| format!("TLS handshake with edge {host}:{port}"))?;
    }
    if s.conn.alpn_protocol() != Some(proto::ALPN) {
        bail!("edge {host}:{port} did not negotiate ALPN nexus-edge/1");
    }
    Ok(s)
}

fn control(ca: &Ca, e: &EdgeTarget, timeout: Duration) -> Result<Conn> {
    let pin = e.cert_sha256.as_deref().context("edge is not enrolled")?;
    connect(ca, &e.host, e.port, Some(pin), timeout)
}

fn request(c: &mut Conn, m: &EdgeMsg) -> Result<EdgeMsg> {
    proto::write(c, m, MAX_CONTROL_FRAME).context("send to edge")?;
    match proto::read(c, MAX_CONTROL_FRAME).context("receive from edge")? {
        EdgeMsg::Error { code, message } => bail!("edge error {code}: {message:?}"),
        m => Ok(m),
    }
}

/// A stream to `agent_id` through the edge (the edge asks the agent to open it).
pub fn open(ca: &Ca, e: &EdgeTarget, agent_id: &str, timeout: Duration) -> Result<Box<dyn Transport>> {
    let mut c = control(ca, e, timeout)?;
    match request(
        &mut c,
        &EdgeMsg::Open {
            agent_id: agent_id.to_owned(),
        },
    )? {
        EdgeMsg::Opened => Ok(Box::new(c)),
        _ => bail!("unexpected answer to Open"),
    }
}

pub struct Enrolled {
    pub cert_sha256: String,
    pub version: String,
}

/// Enrollment with the token digest; both sides prove it bound to this TLS session.
pub fn enroll(ca: &Ca, host: &str, port: u16, digest: &str, timeout: Duration) -> Result<Enrolled> {
    let mut c = connect(ca, host, port, None, timeout)?;
    let ex = c.conn.export_keying_material([0u8; 32], proto::EXPORTER_LABEL, None)?;
    let fp = c
        .conn
        .peer_certificates()
        .and_then(|c| c.first())
        .map(|d| sha256_hex(d))
        .context("edge presented no certificate")?;
    let reply = request(
        &mut c,
        &EdgeMsg::Enroll {
            proof: enroll_proof(digest, "edge-appliance", &ex),
        },
    )?;
    let EdgeMsg::Enrolled { proof, version } = reply else {
        bail!("unexpected answer to Enroll");
    };
    if !proof_eq(&proof, &enroll_proof(digest, "edge", &ex)) {
        bail!("the edge's enrollment proof is wrong (wrong token or a man in the middle)");
    }
    Ok(Enrolled {
        cert_sha256: fp,
        version: version.chars().take(64).collect(),
    })
}

/// What the link pushes.
#[derive(Deserialize, Clone, Debug, Default)]
#[serde(deny_unknown_fields)]
pub struct LinkSpec {
    pub agents: Vec<EdgeAgent>,
    #[serde(default)]
    pub limits: EdgeLimits,
    /// `nexus-edge`, `nexus-edge.sig`, `nexus-edge.version` (pushed when newer)
    #[serde(default)]
    pub update_dir: Option<std::path::PathBuf>,
    /// end the link after this long (the scheduler starts a fresh one)
    #[serde(default = "max_secs")]
    pub max_secs: u64,
    #[serde(default = "wait_secs")]
    pub wait_secs: u32,
}

fn max_secs() -> u64 {
    3600
}
fn wait_secs() -> u32 {
    25
}

/// Signed edge binary from the appliance image, if any.
fn bundle(dir: &Path) -> Option<(String, Vec<u8>, Vec<u8>)> {
    let v = fs::read_to_string(dir.join("nexus-edge.version"))
        .ok()?
        .trim()
        .to_owned();
    let b = fs::read(dir.join("nexus-edge")).ok()?;
    let s = fs::read(dir.join("nexus-edge.sig")).ok()?;
    (!v.is_empty() && v.len() <= 64 && b.len() + s.len() + 1024 < MAX_CONTROL_FRAME).then_some((v, b, s))
}

fn newer(a: &str, b: &str) -> bool {
    let p = |v: &str| -> Option<(u64, u64, u64)> {
        let mut it = v.trim().split('.').map(|x| x.parse().ok());
        Some((it.next()??, it.next()??, it.next()??))
    };
    matches!((p(a), p(b)), (Some(a), Some(b)) if a > b)
}

/// The control link: lines `edge-health {json}`, `edge-wake {"agent_id"}`,
/// `edge-log {"line"}`, `edge-updated {"version"}` go to `out`. Returns after
/// `max_secs`, after an update (the edge restarts), or with the first error.
pub fn link(ca: &Ca, e: &EdgeTarget, spec: &LinkSpec, out: &mut dyn FnMut(String)) -> Result<()> {
    let t0 = Instant::now();
    let mut c = control(ca, e, Duration::from_secs(u64::from(spec.wait_secs) + 30))?;
    let configure = EdgeMsg::Configure {
        ca_pem: ca.ca_pem.clone(),
        agents: spec.agents.clone(),
        limits: spec.limits,
    };
    match request(&mut c, &configure)? {
        EdgeMsg::Ok => {}
        _ => bail!("unexpected answer to Configure"),
    }
    let mut wait = 0;
    loop {
        let EdgeMsg::Events { health, wakes, log } = request(&mut c, &EdgeMsg::Wait { secs: wait })? else {
            bail!("unexpected answer to Wait");
        };
        out(format!("edge-health {}", serde_json::to_string(&health)?));
        for l in log {
            out(format!(
                "edge-log {}",
                json!({ "line": l.chars().take(1024).collect::<String>() })
            ));
        }
        for a in wakes.into_iter().filter(|a| crate::valid_agent_id(a)) {
            out(format!("edge-wake {}", json!({ "agent_id": a })));
        }
        if wait == 0 {
            // first round: bring the edge up to the appliance's release
            if let Some((v, binary, signature)) = spec.update_dir.as_deref().and_then(bundle) {
                if newer(&v, &health.version) {
                    let r = request(
                        &mut c,
                        &EdgeMsg::Update {
                            version: v.clone(),
                            binary,
                            signature,
                        },
                    );
                    match r {
                        Ok(EdgeMsg::Ok) => {
                            out(format!(
                                "edge-updated {}",
                                json!({"from": health.version, "version": v})
                            ));
                            return Ok(());
                        }
                        Ok(_) => bail!("unexpected answer to Update"),
                        Err(err) => out(format!(
                            "edge-log {}",
                            json!({ "line": format!("update to {v} refused: {err:#}") })
                        )),
                    }
                }
            }
        }
        if t0.elapsed().as_secs() >= spec.max_secs {
            return Ok(());
        }
        wait = spec.wait_secs.min(proto::MAX_WAIT_SECS);
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn versions() {
        assert!(super::newer("0.2.0", "0.1.9"));
        assert!(!super::newer("0.1.0", "0.1.0"));
        assert!(!super::newer("x", "0.1.0"));
    }
}
