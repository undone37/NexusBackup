//! Minimal HTTP/1.1 client over TLS 1.3 (rustls) for the secondary: the
//! primary's certificate is **pinned** (SHA-256 of the leaf DER, handshake
//! signature checked), ALPN selects the enrollment or the peer configuration of
//! the primary's web-api, the peer configuration presents the client
//! certificate. Keep-alive, `Content-Length` and `chunked` bodies; everything
//! the primary sends is bounded.

use crate::sha256_hex;
use anyhow::{anyhow, bail, Context, Result};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{verify_tls13_signature, CryptoProvider};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{ClientConfig, ClientConnection, DigitallySignedStruct, Error, SignatureScheme, StreamOwned};
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

/// ring with the post-quantum hybrid X25519MLKEM768 preferred (Phase 39 S5, crate tls-pq).
pub fn provider() -> Arc<CryptoProvider> {
    tls_pq::provider_arc()
}

/// Accepts exactly the pinned certificate (and checks the handshake signature).
#[derive(Debug)]
pub struct PinVerifier {
    pub provider: Arc<CryptoProvider>,
    pub pin: String,
}

impl ServerCertVerifier for PinVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        if self.pin.eq_ignore_ascii_case(&sha256_hex(end_entity)) {
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

/// Where the primary is: `host:port` (`url` in the catalog), optional connect address.
#[derive(Clone, Debug)]
pub struct Target {
    pub host: String,
    pub port: u16,
    pub connect_addr: Option<SocketAddr>,
    /// SHA-256 (hex) of the primary's TLS certificate
    pub pin: String,
    pub timeout: Duration,
}

impl Target {
    /// `host:port` / `[v6]:port` (port 8443 if omitted).
    pub fn parse(url: &str, pin: &str) -> Result<Target> {
        let url = url.trim().trim_start_matches("https://").trim_end_matches('/');
        let (host, port) = match url.rsplit_once(':') {
            Some((h, p)) if !h.is_empty() && !p.contains(']') => (h, p.parse().context("port")?),
            _ => (url, 8443),
        };
        let host = host.trim_matches(['[', ']']);
        if host.is_empty() || host.contains('/') || port == 0 {
            bail!("invalid primary address {url:?} (host:port)");
        }
        if !crate::valid_hex64(&pin.to_ascii_lowercase()) {
            bail!("certificate fingerprint must be 64 hex characters (SHA-256)");
        }
        Ok(Target {
            host: host.to_owned(),
            port,
            connect_addr: None,
            pin: pin.to_ascii_lowercase(),
            timeout: Duration::from_secs(120),
        })
    }
}

pub fn client_config(
    pin: &str,
    alpn: &[u8],
    client_auth: Option<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)>,
) -> Result<Arc<ClientConfig>> {
    let b = ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinVerifier {
            provider: provider(),
            pin: pin.to_owned(),
        }));
    let mut cfg = match client_auth {
        Some((chain, key)) => b.with_client_auth_cert(chain, key)?,
        None => b.with_no_client_auth(),
    };
    cfg.alpn_protocols = vec![alpn.to_vec()];
    Ok(Arc::new(cfg))
}

pub type TlsStream = StreamOwned<ClientConnection, TcpStream>;

/// One HTTP/1.1 connection; `S` is the TLS stream (generic for the fuzz target).
pub struct Conn<S = TlsStream> {
    s: S,
    /// read buffer: `rbuf[rpos..rlen]` is unread
    rbuf: Box<[u8]>,
    rpos: usize,
    rlen: usize,
    /// a response body was not read to its end: the connection cannot be reused
    dirty: bool,
}

const MAX_HEAD: usize = 16 << 10;

impl<S: Read + Write> Conn<S> {
    /// HTTP over an already established stream (tests, fuzzing).
    pub fn over(s: S) -> Conn<S> {
        Conn {
            s,
            rbuf: vec![0u8; 64 << 10].into_boxed_slice(),
            rpos: 0,
            rlen: 0,
            dirty: false,
        }
    }
}

impl Conn<TlsStream> {
    pub fn connect(t: &Target, cfg: Arc<ClientConfig>) -> Result<Conn> {
        let addrs: Vec<SocketAddr> = match t.connect_addr {
            Some(a) => vec![a],
            None => (t.host.as_str(), t.port)
                .to_socket_addrs()
                .with_context(|| format!("resolve {}", t.host))?
                .collect(),
        };
        let mut last = None;
        let mut tcp = None;
        for a in addrs {
            match TcpStream::connect_timeout(&a, Duration::from_secs(15)) {
                Ok(s) => {
                    tcp = Some(s);
                    break;
                }
                Err(e) => last = Some(e),
            }
        }
        let tcp = match (tcp, last) {
            (Some(s), _) => s,
            (None, Some(e)) => return Err(e).with_context(|| format!("connect {}:{}", t.host, t.port)),
            (None, None) => bail!("{}: no address", t.host),
        };
        tcp.set_read_timeout(Some(t.timeout))?;
        tcp.set_write_timeout(Some(t.timeout))?;
        tcp.set_nodelay(true)?;
        let name = ServerName::try_from(t.host.clone()).unwrap_or_else(|_| ServerName::try_from("nexus").unwrap());
        let conn = ClientConnection::new(cfg.clone(), name)?;
        let mut s = StreamOwned::new(conn, tcp);
        while s.conn.is_handshaking() {
            s.conn
                .complete_io(&mut s.sock)
                .with_context(|| format!("TLS handshake with {}:{} (certificate pinned)", t.host, t.port))?;
        }
        let want = cfg.alpn_protocols.first().map(Vec::as_slice);
        if s.conn.alpn_protocol() != want {
            bail!(
                "{}:{}: the primary did not accept the replication protocol (ALPN); is replication supported there?",
                t.host,
                t.port
            );
        }
        Ok(Conn::over(s))
    }

    pub fn exporter(&self, label: &[u8]) -> Result<[u8; 32]> {
        Ok(self.s.conn.export_keying_material([0u8; 32], label, None)?)
    }
}

impl<S: Read + Write> Conn<S> {
    fn fill(&mut self) -> io::Result<usize> {
        if self.rpos == self.rlen {
            self.rlen = self.s.read(&mut self.rbuf)?;
            self.rpos = 0;
        }
        Ok(self.rlen - self.rpos)
    }

    fn read_some(&mut self, out: &mut [u8]) -> io::Result<usize> {
        // large reads with an empty buffer go straight to the caller (chunk data)
        if self.rpos == self.rlen && out.len() >= self.rbuf.len() {
            return self.s.read(out);
        }
        if self.fill()? == 0 {
            return Ok(0);
        }
        let n = out.len().min(self.rlen - self.rpos);
        out[..n].copy_from_slice(&self.rbuf[self.rpos..self.rpos + n]);
        self.rpos += n;
        Ok(n)
    }

    fn read_line(&mut self, max: usize) -> io::Result<String> {
        let mut line = Vec::new();
        loop {
            if self.fill()? == 0 {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "connection closed"));
            }
            let b = self.rbuf[self.rpos];
            self.rpos += 1;
            if b == b'\n' {
                break;
            }
            line.push(b);
            if line.len() > max {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "HTTP line too long"));
            }
        }
        if line.last() == Some(&b'\r') {
            line.pop();
        }
        String::from_utf8(line).map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "HTTP line not UTF-8"))
    }

    /// Sends a request and reads the response head; the body is read through the result.
    pub fn request(&mut self, method: &str, path: &str, ctype: Option<&str>, body: &[u8]) -> Result<Response<'_, S>> {
        if self.dirty {
            bail!("connection has an unread response body");
        }
        let mut head = format!(
            "{method} {path} HTTP/1.1\r\nHost: nexus-primary\r\nContent-Length: {}\r\n",
            body.len()
        );
        if let Some(c) = ctype {
            head.push_str(&format!("Content-Type: {c}\r\n"));
        }
        head.push_str("\r\n");
        self.s.write_all(head.as_bytes())?;
        self.s.write_all(body)?;
        self.s.flush()?;
        let status_line = self.read_line(MAX_HEAD).context("response status")?;
        let status: u16 = status_line
            .strip_prefix("HTTP/1.1 ")
            .and_then(|r| r.get(..3))
            .filter(|c| c.bytes().all(|b| b.is_ascii_digit()))
            .and_then(|c| c.parse().ok())
            .filter(|s| (100..600).contains(s))
            .ok_or_else(|| anyhow!("malformed HTTP status line {status_line:?}"))?;
        let (mut len, mut chunked, mut total) = (None, false, 0);
        loop {
            let l = self.read_line(MAX_HEAD)?;
            total += l.len();
            if total > MAX_HEAD {
                bail!("HTTP response head too large");
            }
            if l.is_empty() {
                break;
            }
            let Some((k, v)) = l.split_once(':') else { continue };
            let v = v.trim();
            if k.eq_ignore_ascii_case("content-length") {
                len = Some(v.parse::<u64>().context("Content-Length")?);
            } else if k.eq_ignore_ascii_case("transfer-encoding") {
                chunked = v.eq_ignore_ascii_case("chunked");
            }
        }
        let body = if chunked {
            Body::Chunked { left: 0, done: false }
        } else {
            Body::Length(len.unwrap_or(0))
        };
        self.dirty = !matches!(body, Body::Length(0));
        Ok(Response {
            conn: self,
            status,
            body,
        })
    }
}

enum Body {
    Length(u64),
    Chunked { left: u64, done: bool },
}

pub struct Response<'a, S = TlsStream> {
    conn: &'a mut Conn<S>,
    pub status: u16,
    body: Body,
}

impl<S: Read + Write> Response<'_, S> {
    fn finished(&self) -> bool {
        matches!(self.body, Body::Length(0) | Body::Chunked { done: true, .. })
    }

    /// Whole body, at most `max` bytes.
    pub fn bytes(mut self, max: u64) -> Result<Vec<u8>> {
        let mut v = Vec::new();
        (&mut self).take(max + 1).read_to_end(&mut v)?;
        if v.len() as u64 > max {
            bail!("response larger than {max} bytes");
        }
        Ok(v)
    }

    /// 2xx: the JSON body; otherwise an error with the primary's `{error}` text.
    pub fn json<T: serde::de::DeserializeOwned>(self, max: u64) -> Result<T> {
        let status = self.status;
        let b = self.bytes(max)?;
        if !(200..300).contains(&status) {
            bail!("{}", error_text(status, &b));
        }
        serde_json::from_slice(&b).context("malformed JSON from the primary")
    }

    /// Fails on a non-2xx status (reading the error text).
    pub fn ok(self) -> Result<Self> {
        if (200..300).contains(&self.status) {
            return Ok(self);
        }
        let status = self.status;
        let b = self.bytes(64 << 10).unwrap_or_default();
        bail!("{}", error_text(status, &b))
    }
}

pub fn error_text(status: u16, body: &[u8]) -> String {
    let msg = serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|v| v["error"].as_str().map(str::to_owned))
        .unwrap_or_else(|| String::from_utf8_lossy(&body[..body.len().min(200)]).into_owned());
    format!("primary answered {status}: {msg}")
}

impl<S: Read + Write> Read for Response<'_, S> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        let n = match &mut self.body {
            Body::Length(0) => 0,
            Body::Length(left) => {
                let k = (*left).min(out.len() as u64) as usize;
                let n = self.conn.read_some(&mut out[..k])?;
                if n == 0 {
                    return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "body truncated"));
                }
                *left -= n as u64;
                n
            }
            Body::Chunked { done: true, .. } => 0,
            Body::Chunked { left, done } => {
                if *left == 0 {
                    let l = self.conn.read_line(1024)?;
                    let size = u64::from_str_radix(l.split(';').next().unwrap_or("").trim(), 16)
                        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "bad chunk size"))?;
                    if size == 0 {
                        // trailers until the empty line
                        while !self.conn.read_line(MAX_HEAD)?.is_empty() {}
                        *done = true;
                        self.conn.dirty = false;
                        return Ok(0);
                    }
                    *left = size;
                }
                let k = (*left).min(out.len() as u64) as usize;
                let n = self.conn.read_some(&mut out[..k])?;
                if n == 0 {
                    return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "body truncated"));
                }
                *left -= n as u64;
                if *left == 0 && !self.conn.read_line(2)?.is_empty() {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "bad chunk terminator"));
                }
                n
            }
        };
        if self.finished() {
            self.conn.dirty = false;
        }
        Ok(n)
    }
}
