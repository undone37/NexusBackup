//! Edge rendezvous (docs/edge.md, `agent_proto::edge`): an enrolled agent with an
//! edge proxy (`agent.conf` `edge` + `edge_sha256`, or pushed by the appliance with
//! `SetEdge`) keeps one outbound TLS connection to the edge, authenticated with its
//! agent certificate; the edge certificate is pinned. When the appliance opens a
//! stream, the edge sends `Connect { nonce }`; the agent opens a second connection,
//! names the nonce and then serves the normal session over it with the same mTLS
//! server code ([`Agent::handle_transport`]): TLS end to end, the edge relays records
//! only. A local "back up now" request is passed on at once (`Wake`), so the
//! appliance polls within seconds. The agent keeps listening on its port as well.

use crate::config::{write_atomic, Paths};
use crate::server::{log, Agent, Mode, Platform};
use agent_proto::edge::{self as proto, EdgeMsg, MAX_PUBLIC_FRAME};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{verify_tls13_signature, CryptoProvider};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, ClientConnection, DigitallySignedStruct, Error, SignatureScheme, StreamOwned};
use serde::{Deserialize, Serialize};
use std::fs;
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

/// The edge sends `Ping` every 30 s: silence for this long means the connection is gone.
const READ_TIMEOUT: Duration = Duration::from_secs(90);
const MAX_BACKOFF: u64 = 300;

type Conn = StreamOwned<ClientConnection, TcpStream>;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct EdgeConf {
    /// `host:port`
    pub addr: String,
    /// pinned edge certificate (SHA-256 hex)
    pub cert_sha256: String,
}

/// `host:port` with a port, and a SHA-256 hex fingerprint.
pub fn validate(addr: &str, fp: &str) -> Result<(), String> {
    let port = addr.rsplit_once(':').and_then(|(h, p)| {
        let h = h.trim_matches(['[', ']']);
        (!h.is_empty() && !h.contains(char::is_whitespace))
            .then(|| p.parse::<u16>().ok())
            .flatten()
    });
    if port.is_none_or(|p| p == 0) || addr.len() > agent_proto::MAX_TEXT {
        return Err(format!("edge address {addr:?} is not host:port"));
    }
    if fp.len() != 64 || !fp.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("edge certificate fingerprint must be 64 hex characters".into());
    }
    Ok(())
}

/// The edge to use: agent.conf wins over the one the appliance pushed.
pub fn current(paths: &Paths, settings: &crate::config::Settings) -> Option<EdgeConf> {
    if let (Some(addr), Some(fp)) = (&settings.edge, &settings.edge_sha256) {
        return Some(EdgeConf {
            addr: addr.clone(),
            cert_sha256: fp.clone(),
        });
    }
    let c: EdgeConf = serde_json::from_slice(&fs::read(paths.edge()).ok()?).ok()?;
    validate(&c.addr, &c.cert_sha256).ok().map(|_| c)
}

/// `SetEdge` from the appliance (empty `addr` = none).
pub fn set(paths: &Paths, addr: &str, fp: &str) -> Result<(), String> {
    if addr.is_empty() {
        return match fs::remove_file(paths.edge()) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e.to_string()),
            _ => Ok(()),
        };
    }
    validate(addr, fp)?;
    let c = EdgeConf {
        addr: addr.to_string(),
        cert_sha256: fp.to_ascii_lowercase(),
    };
    let old: Option<EdgeConf> = fs::read(paths.edge())
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok());
    if old.as_ref() != Some(&c) {
        let body = serde_json::to_vec(&c).map_err(|e| e.to_string())?;
        write_atomic(&paths.edge(), &body, 0o600).map_err(|e| e.to_string())?;
        log(format!("edge proxy set by the appliance: {addr}"));
    }
    Ok(())
}

/// The edge certificate must be the pinned one (self-signed; no CA involved).
#[derive(Debug)]
struct Pinned {
    provider: Arc<CryptoProvider>,
    fp: String,
}

impl ServerCertVerifier for Pinned {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        if crate::tls::fingerprint(end_entity).eq_ignore_ascii_case(&self.fp) {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ))
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

/// TLS to the edge with the agent certificate (read fresh: renewals take effect).
fn connect(paths: &Paths, c: &EdgeConf) -> Result<Conn, String> {
    let read = |p: std::path::PathBuf| fs::read_to_string(&p).map_err(|e| format!("{}: {e}", p.display()));
    let certs = crate::tls::certs_from_pem(&read(paths.cert())?)?;
    let kp = rcgen::KeyPair::from_pem(&read(paths.key())?).map_err(|e| e.to_string())?;
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(kp.serialize_der().into());
    let provider = crate::tls::provider();
    let mut cfg = ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| e.to_string())?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(Pinned {
            provider,
            fp: c.cert_sha256.clone(),
        }))
        .with_client_auth_cert(certs, key)
        .map_err(|e| e.to_string())?;
    cfg.alpn_protocols = vec![proto::ALPN.to_vec()];
    cfg.enable_sni = false;
    let addrs: Vec<_> = c
        .addr
        .to_socket_addrs()
        .map_err(|e| format!("resolve {}: {e}", c.addr))?
        .collect();
    let mut last = format!("{}: no address", c.addr);
    for a in addrs {
        match TcpStream::connect_timeout(&a, Duration::from_secs(15)) {
            Ok(tcp) => {
                let t = |e: std::io::Error| e.to_string();
                tcp.set_read_timeout(Some(Duration::from_secs(30))).map_err(t)?;
                tcp.set_write_timeout(Some(Duration::from_secs(30))).map_err(t)?;
                tcp.set_nodelay(true).map_err(t)?;
                let conn =
                    ClientConnection::new(Arc::new(cfg), ServerName::try_from("nexus-edge").expect("static name"))
                        .map_err(|e| e.to_string())?;
                let mut s = StreamOwned::new(conn, tcp);
                while s.conn.is_handshaking() {
                    s.conn
                        .complete_io(&mut s.sock)
                        .map_err(|e| format!("TLS handshake with edge {}: {e}", c.addr))?;
                }
                return Ok(s);
            }
            Err(e) => last = format!("connect {}: {e}", c.addr),
        }
    }
    Err(last)
}

fn enrolled<P: Platform>(agent: &Agent<P>) -> bool {
    matches!(agent.mode(), Mode::Mtls { .. })
}

/// Starts the rendezvous and wake threads (they idle while no edge is set).
pub fn spawn<P: Platform>(agent: Arc<Agent<P>>) {
    let (tx, rx) = std::sync::mpsc::channel::<()>();
    agent.ui.set_waker(tx);
    let a = agent.clone();
    std::thread::spawn(move || {
        for () in rx {
            if let (true, Some(c)) = (enrolled(&a), current(&a.paths, &a.settings)) {
                match wake(&a.paths, &c) {
                    Ok(()) => log(format!("backup request passed to edge {}", c.addr)),
                    Err(e) => log(format!("edge {}: {e} (the request waits for the next poll)", c.addr)),
                }
            }
        }
    });
    std::thread::spawn(move || {
        let mut backoff = 5;
        let mut last_err = String::new();
        loop {
            let conf = current(&agent.paths, &agent.settings).filter(|_| enrolled(&agent));
            let Some(conf) = conf else {
                std::thread::sleep(Duration::from_secs(5));
                continue;
            };
            match rendezvous(&agent, &conf) {
                Ok(()) => {
                    backoff = 5;
                    last_err.clear();
                }
                Err((was_up, e)) => {
                    if was_up {
                        backoff = 5;
                    }
                    if e != last_err {
                        log(format!("edge {}: {e} (retrying)", conf.addr));
                        last_err = e;
                    }
                }
            }
            std::thread::sleep(Duration::from_secs(backoff));
            backoff = (backoff * 2).min(MAX_BACKOFF);
        }
    });
}

/// One rendezvous connection until it breaks (`Err((was_up, why))`) or the edge
/// setting changes (`Ok`).
fn rendezvous<P: Platform>(agent: &Arc<Agent<P>>, conf: &EdgeConf) -> Result<(), (bool, String)> {
    let mut s = connect(&agent.paths, conf).map_err(|e| (false, e))?;
    let _ = s.sock.set_read_timeout(Some(READ_TIMEOUT));
    proto::write(&mut s, &EdgeMsg::Rendezvous, MAX_PUBLIC_FRAME).map_err(|e| (false, e.to_string()))?;
    log(format!("connected to edge {}", conf.addr));
    loop {
        match proto::read(&mut s, MAX_PUBLIC_FRAME) {
            Ok(EdgeMsg::Ping) => {}
            Ok(EdgeMsg::Connect { nonce }) => {
                let (a, c) = (agent.clone(), conf.clone());
                std::thread::spawn(move || {
                    if let Err(e) = stream(&a, &c, nonce) {
                        log(format!("stream via edge {}: {e}", c.addr));
                    }
                });
            }
            Ok(_) => return Err((true, "unexpected message from the edge".into())),
            Err(e) => return Err((true, format!("connection lost: {e}"))),
        }
        if current(&agent.paths, &agent.settings).as_ref() != Some(conf) || !enrolled(agent) {
            log(format!("edge {}: setting changed, reconnecting", conf.addr));
            return Ok(());
        }
    }
}

/// A stream the appliance opened: the normal session (agent = TLS server) over it.
fn stream<P: Platform>(agent: &Agent<P>, conf: &EdgeConf, nonce: [u8; 16]) -> Result<(), String> {
    if agent.connections.fetch_add(1, Ordering::SeqCst) >= agent.settings.max_connections {
        agent.connections.fetch_sub(1, Ordering::SeqCst);
        return Err("too many connections".into());
    }
    let r = (|| {
        let mut s = connect(&agent.paths, conf)?;
        proto::write(&mut s, &EdgeMsg::Stream { nonce }, MAX_PUBLIC_FRAME).map_err(|e| e.to_string())?;
        let t = |e: std::io::Error| e.to_string();
        s.sock.set_read_timeout(Some(Duration::from_secs(3600))).map_err(t)?;
        s.sock.set_write_timeout(Some(Duration::from_secs(600))).map_err(t)?;
        match agent.handle_transport(Box::new(s), false) {
            Err(e) if e.kind() != std::io::ErrorKind::UnexpectedEof => Err(e.to_string()),
            _ => Ok(()),
        }
    })();
    agent.connections.fetch_sub(1, Ordering::SeqCst);
    r
}

/// `Wake`: a short connection, answered with `Ok`.
fn wake(paths: &Paths, conf: &EdgeConf) -> Result<(), String> {
    let mut s = connect(paths, conf)?;
    proto::write(&mut s, &EdgeMsg::Wake, MAX_PUBLIC_FRAME).map_err(|e| e.to_string())?;
    match proto::read(&mut s, MAX_PUBLIC_FRAME) {
        Ok(EdgeMsg::Ok) => Ok(()),
        Ok(_) => Err("unexpected answer".into()),
        Err(e) => Err(e.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn edge_settings() {
        let fp = "ab".repeat(32);
        assert!(validate("edge.example.com:443", &fp).is_ok());
        assert!(validate("[2001:db8::1]:443", &fp).is_ok());
        assert!(validate("edge.example.com", &fp).is_err());
        assert!(validate("edge.example.com:0", &fp).is_err());
        assert!(validate("edge.example.com:443", "abc").is_err());
        let d = tempfile::tempdir().unwrap();
        let paths = Paths {
            config: d.path().join("c"),
            state: d.path().to_path_buf(),
            run: d.path().join("r"),
        };
        let none = crate::config::Settings::default();
        assert_eq!(current(&paths, &none), None);
        set(&paths, "edge.example.com:443", &fp.to_uppercase()).unwrap();
        assert_eq!(
            current(&paths, &none),
            Some(EdgeConf {
                addr: "edge.example.com:443".into(),
                cert_sha256: fp.clone()
            })
        );
        let local =
            crate::config::Settings::parse(&format!("edge = 10.0.0.9:8443\nedge_sha256 = {}\n", "cd".repeat(32)))
                .unwrap();
        assert_eq!(
            current(&paths, &local).unwrap().addr,
            "10.0.0.9:8443",
            "agent.conf wins"
        );
        assert!(
            crate::config::Settings::parse("edge = 10.0.0.9:8443\n").is_err(),
            "fingerprint required"
        );
        set(&paths, "", "").unwrap();
        assert_eq!(current(&paths, &none), None);
        assert!(set(&paths, "nohost", &fp).is_err());
    }
}
