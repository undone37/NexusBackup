//! Check-in of the rescue agent with the appliance: `POST /api/v1/rescue/checkin`
//! over HTTPS with the token's public lookup key, the address and port the
//! appliance should connect to, and the disks of this machine. It is only a hint:
//! the appliance then enrolls the rescue agent with the token proofs bound to the
//! TLS session (docs/bmr.md "Security"). The web certificate is checked only if
//! its fingerprint was given (`appliance_sha256`); the token itself never leaves
//! this machine.

use super::RescueConfig;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, ClientConnection, DigitallySignedStruct, SignatureScheme, StreamOwned};
use serde::Serialize;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

#[derive(Serialize, Clone, Debug)]
pub struct DiskInfo {
    pub path: String,
    pub size: u64,
}

/// Accepts any certificate, or exactly the pinned one.
#[derive(Debug)]
struct Pin(String, Arc<rustls::crypto::CryptoProvider>);

impl ServerCertVerifier for Pin {
    fn verify_server_cert(
        &self,
        end: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if self.0.is_empty() || agent_core::tls::fingerprint(end).eq_ignore_ascii_case(self.0.replace(':', "").as_str())
        {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(
                "appliance certificate does not match the pinned fingerprint".into(),
            ))
        }
    }
    fn verify_tls12_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(m, c, d, &self.1.signature_verification_algorithms)
    }
    fn verify_tls13_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(m, c, d, &self.1.signature_verification_algorithms)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.1.signature_verification_algorithms.supported_schemes()
    }
}

/// `host`, `host:port`, `[v6]:port` → (host, port); default port 443.
pub fn split(addr: &str, default: u16) -> (String, u16) {
    let a = addr.trim().trim_start_matches("https://").trim_end_matches('/');
    if let Some(rest) = a.strip_prefix('[') {
        if let Some((h, p)) = rest.split_once(']') {
            return (h.to_string(), p.trim_start_matches(':').parse().unwrap_or(default));
        }
    }
    match a.rsplit_once(':') {
        Some((h, p)) if !h.contains(':') => (h.to_string(), p.parse().unwrap_or(default)),
        _ => (a.to_string(), default),
    }
}

/// The check-in request body.
pub fn body(cfg: &RescueConfig, local_ip: &str, disks: &[DiskInfo]) -> serde_json::Value {
    let (host, port) = if cfg.advertise.is_empty() {
        (local_ip.to_string(), cfg.port)
    } else {
        split(&cfg.advertise, cfg.port)
    };
    serde_json::json!({
        "lookup": agent_proto::rescue_lookup(&cfg.token),
        "host": host,
        "port": port,
        "disks": disks,
        "version": env!("CARGO_PKG_VERSION"),
    })
}

/// One check-in; Ok = the appliance's answer text.
pub fn checkin(cfg: &RescueConfig, disks: &[DiskInfo]) -> Result<String, String> {
    let (host, port) = split(&cfg.appliance, 443);
    if host.is_empty() {
        return Err("no appliance address".into());
    }
    let addr = (host.as_str(), port)
        .to_socket_addrs()
        .map_err(|e| format!("{host}: {e}"))?
        .next()
        .ok_or_else(|| format!("{host}: no address"))?;
    let tcp = TcpStream::connect_timeout(&addr, Duration::from_secs(10)).map_err(|e| format!("{addr}: {e}"))?;
    tcp.set_read_timeout(Some(Duration::from_secs(30))).ok();
    let local = tcp.local_addr().map_err(|e| e.to_string())?.ip().to_string();
    let provider = tls_pq::provider_arc();
    let tls = ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(Pin(cfg.appliance_sha256.trim().to_string(), provider)))
        .with_no_client_auth();
    let name = ServerName::try_from(host.clone()).map_err(|e| e.to_string())?;
    let conn = ClientConnection::new(Arc::new(tls), name).map_err(|e| e.to_string())?;
    let mut s = StreamOwned::new(conn, tcp);
    let payload = body(cfg, &local, disks).to_string();
    let req = format!(
        "POST /api/v1/rescue/checkin HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
        payload.len()
    );
    s.write_all(req.as_bytes()).map_err(|e| e.to_string())?;
    let mut resp = vec![];
    // the server may close without close_notify: keep what arrived
    let _ = s.read_to_end(&mut resp);
    let text = String::from_utf8_lossy(&resp);
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
    let status: u16 = head.split_whitespace().nth(1).and_then(|c| c.parse().ok()).unwrap_or(0);
    if status == 200 {
        Ok(body.trim().to_string())
    } else {
        Err(format!(
            "HTTP {status}: {}",
            body.trim().chars().take(300).collect::<String>()
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addresses_and_body() {
        assert_eq!(split("nexus.lab", 443), ("nexus.lab".into(), 443));
        assert_eq!(split("https://10.0.2.2:18453/", 443), ("10.0.2.2".into(), 18453));
        assert_eq!(split("[fd00::1]:8443", 443), ("fd00::1".into(), 8443));
        assert_eq!(split("fd00::1", 443), ("fd00::1".into(), 443));
        let cfg = RescueConfig {
            token: "TOKEN".into(),
            port: 7444,
            ..Default::default()
        };
        let b = body(&cfg, "10.0.2.15", &[]);
        assert_eq!(b["host"], "10.0.2.15");
        assert_eq!(b["port"], 7444);
        assert_eq!(b["lookup"], agent_proto::rescue_lookup("TOKEN"));
        assert!(
            !b.to_string().contains("TOKEN"),
            "the token never leaves the rescue machine"
        );
        let cfg = RescueConfig {
            advertise: "127.0.0.1:17449".into(),
            ..cfg
        };
        assert_eq!(body(&cfg, "10.0.2.15", &[])["port"], 17449);
    }
}
