//! HTTP/1.1 over TLS 1.3 to a paired NexusStor (contract "Transport"): ALPN
//! `nexusbackup/1`, NexusStor's certificate pinned by the SHA-256 of its leaf
//! (handshake signature checked, names and CAs ignored), this pairing's client
//! certificate. One request per connection (NexusStor forwards each to a
//! one-shot root helper). Response heads and chunk framing are bounded; bodies are
//! read through [`Response`], which callers bound per request.

use anyhow::{anyhow, bail, Context, Result};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{verify_tls13_signature, CryptoProvider};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{ClientConfig, ClientConnection, DigitallySignedStruct, SignatureScheme, StreamOwned};
use sha2::{Digest, Sha256};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

/// ALPN of the backup protocol.
pub const ALPN: &[u8] = b"nexusbackup/1";
/// Path prefix of every request.
pub const PREFIX: &str = "/nexusbackup/v1";
const MAX_HEAD: usize = 16 << 10;

/// SHA-256 of a DER certificate, lowercase hex.
pub fn fingerprint(der: &[u8]) -> String {
    Sha256::digest(der).iter().map(|b| format!("{b:02x}")).collect()
}

/// Accepts exactly the pinned certificate (and checks the handshake signature).
#[derive(Debug)]
struct Pinned {
    provider: Arc<CryptoProvider>,
    pin: String,
}

impl ServerCertVerifier for Pinned {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        if fingerprint(end_entity) == self.pin {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ))
        }
    }
    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::PeerIncompatible(
            rustls::PeerIncompatible::Tls12NotOffered,
        ))
    }
    fn verify_tls13_signature(
        &self,
        msg: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(msg, cert, dss, &self.provider.signature_verification_algorithms)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

/// The server's certificate is not the pinned one (the caller shows the pin hint).
#[derive(Debug)]
pub struct PinMismatch;

impl std::fmt::Display for PinMismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "the server's TLS certificate does not match the pinned NexusStor fingerprint"
        )
    }
}
impl std::error::Error for PinMismatch {}

/// A non-2xx answer: status and NexusStor's `{"error"}` text.
#[derive(Debug)]
pub struct Status {
    /// HTTP status.
    pub code: u16,
    /// The error text (bounded, control characters removed).
    pub message: String,
}

impl std::fmt::Display for Status {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "NexusStor answered {}: {}", self.code, self.message)
    }
}
impl std::error::Error for Status {}

/// The HTTP status of a [`Status`] error in the chain, if any.
pub fn status_of(e: &anyhow::Error) -> Option<u16> {
    e.chain().find_map(|c| c.downcast_ref::<Status>()).map(|s| s.code)
}

/// Where and how to connect.
#[derive(Clone)]
pub struct Client {
    host: String,
    port: u16,
    cfg: Arc<ClientConfig>,
    /// read/write timeout per socket operation
    pub timeout: Duration,
}

impl Client {
    /// `cert_pem`/`key_pem`: this pairing's client certificate and PKCS#8 key.
    pub fn new(host: &str, port: u16, pin: &str, cert_pem: &str, key_pem: &str) -> Result<Client> {
        let cert = pem::parse(cert_pem.trim()).context("client_cert: not PEM")?;
        if cert.tag() != "CERTIFICATE" {
            bail!("client_cert: expected a CERTIFICATE");
        }
        let key = pem::parse(key_pem.trim()).context("client_key: not PEM")?;
        if key.tag() != "PRIVATE KEY" {
            bail!("client_key: expected a PKCS#8 PRIVATE KEY");
        }
        let provider = tls_pq::provider_arc();
        let mut cfg = ClientConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(Pinned {
                provider,
                pin: pin.to_owned(),
            }))
            .with_client_auth_cert(
                vec![CertificateDer::from(cert.contents().to_vec())],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.contents().to_vec())),
            )
            .context("client_cert/client_key: not a usable key pair")?;
        cfg.alpn_protocols = vec![ALPN.to_vec()];
        Ok(Client {
            host: host.to_owned(),
            port,
            cfg: Arc::new(cfg),
            timeout: Duration::from_secs(300),
        })
    }

    fn connect(&self) -> Result<StreamOwned<ClientConnection, TcpStream>> {
        let addrs: Vec<SocketAddr> = (self.host.as_str(), self.port)
            .to_socket_addrs()
            .with_context(|| format!("resolve {}", self.host))?
            .collect();
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
            (None, Some(e)) => return Err(e).with_context(|| format!("connect {}:{}", self.host, self.port)),
            (None, None) => bail!("{}: no address", self.host),
        };
        tcp.set_read_timeout(Some(self.timeout))?;
        tcp.set_write_timeout(Some(self.timeout))?;
        tcp.set_nodelay(true)?;
        let name =
            ServerName::try_from(self.host.clone()).unwrap_or_else(|_| ServerName::try_from("nexusstor").unwrap());
        let mut s = StreamOwned::new(ClientConnection::new(self.cfg.clone(), name)?, tcp);
        while s.conn.is_handshaking() {
            if let Err(e) = s.conn.complete_io(&mut s.sock) {
                let pin = e
                    .get_ref()
                    .and_then(|x| x.downcast_ref::<rustls::Error>())
                    .is_some_and(|x| {
                        matches!(
                            x,
                            rustls::Error::InvalidCertificate(rustls::CertificateError::ApplicationVerificationFailure)
                        )
                    });
                if pin {
                    return Err(anyhow!(PinMismatch));
                }
                return Err(e).with_context(|| format!("TLS handshake with {}:{}", self.host, self.port));
            }
        }
        if s.conn.alpn_protocol() != Some(ALPN) {
            bail!(
                "{}:{} does not speak the NexusBackup protocol (ALPN nexusbackup/1); is it a NexusStor with NexusBackup pairing?",
                self.host,
                self.port
            );
        }
        Ok(s)
    }

    /// Sends one request (`path` below [`PREFIX`]) and reads the response head.
    pub fn request(&self, method: &str, path: &str, body: Option<&serde_json::Value>) -> Result<Response> {
        let body = body.map(serde_json::Value::to_string).unwrap_or_default();
        if body.len() > 1 << 20 {
            bail!("request body larger than 1 MiB");
        }
        let mut s = self.connect()?;
        let mut head = format!(
            "{method} {PREFIX}{path} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nContent-Length: {}\r\n",
            self.host,
            body.len()
        );
        if !body.is_empty() {
            head.push_str("Content-Type: application/json\r\n");
        }
        head.push_str("\r\n");
        s.write_all(head.as_bytes())?;
        s.write_all(body.as_bytes())?;
        s.flush()?;
        Response::read_head(BufReader::with_capacity(256 << 10, Box::new(s)))
            .with_context(|| format!("{method} {path}"))
    }
}

enum Body {
    Length(u64),
    /// `crlf`: the CRLF after the previous chunk's data is still to be read
    Chunked {
        left: u64,
        done: bool,
        crlf: bool,
    },
}

/// A response: status and the (de-chunked) body as `Read`/`BufRead`.
pub struct Response {
    r: BufReader<Box<dyn Read + Send>>,
    /// HTTP status.
    pub status: u16,
    body: Body,
}

fn read_line(r: &mut impl BufRead, max: usize) -> io::Result<String> {
    let mut line = Vec::new();
    r.take(max as u64 + 1).read_until(b'\n', &mut line)?;
    if line.last() != Some(&b'\n') {
        return Err(io::Error::new(
            if line.len() > max {
                io::ErrorKind::InvalidData
            } else {
                io::ErrorKind::UnexpectedEof
            },
            "HTTP line too long or connection closed",
        ));
    }
    line.pop();
    if line.last() == Some(&b'\r') {
        line.pop();
    }
    String::from_utf8(line).map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "HTTP line not UTF-8"))
}

impl Response {
    /// Parses status line and headers from `r` (tests: any byte stream).
    pub fn read_head(mut r: BufReader<Box<dyn Read + Send>>) -> Result<Response> {
        let status_line = read_line(&mut r, MAX_HEAD).context("response status")?;
        let status: u16 = status_line
            .strip_prefix("HTTP/1.1 ")
            .and_then(|x| x.get(..3))
            .filter(|c| c.bytes().all(|b| b.is_ascii_digit()))
            .and_then(|c| c.parse().ok())
            .filter(|s| (200..600).contains(s))
            .ok_or_else(|| anyhow!("malformed HTTP status line"))?;
        let (mut len, mut chunked, mut total) = (None, false, 0);
        loop {
            let l = read_line(&mut r, MAX_HEAD)?;
            total += l.len() + 2;
            if total > MAX_HEAD {
                bail!("HTTP response head too large");
            }
            if l.is_empty() {
                break;
            }
            let Some((k, v)) = l.split_once(':') else {
                bail!("malformed HTTP header");
            };
            let v = v.trim();
            if k.eq_ignore_ascii_case("content-length") {
                if len.is_some() {
                    bail!("two Content-Length headers");
                }
                len = Some(v.parse::<u64>().context("Content-Length")?);
            } else if k.eq_ignore_ascii_case("transfer-encoding") {
                if !v.eq_ignore_ascii_case("chunked") {
                    bail!("unsupported Transfer-Encoding {v:?}");
                }
                chunked = true;
            }
        }
        let body = match (chunked, len) {
            (true, None) => Body::Chunked {
                left: 0,
                done: false,
                crlf: false,
            },
            (false, Some(n)) => Body::Length(n),
            (false, None) => Body::Length(0),
            (true, Some(_)) => bail!("both Content-Length and chunked"),
        };
        Ok(Response { r, status, body })
    }

    /// Whole body, at most `max` bytes.
    pub fn bytes(mut self, max: u64) -> Result<Vec<u8>> {
        let mut v = Vec::new();
        (&mut self).take(max + 1).read_to_end(&mut v)?;
        if v.len() as u64 > max {
            bail!("answer larger than {max} bytes");
        }
        Ok(v)
    }

    /// Fails on a non-2xx status with a [`Status`] error carrying NexusStor's text.
    pub fn ok(self) -> Result<Response> {
        if (200..300).contains(&self.status) {
            return Ok(self);
        }
        let code = self.status;
        let b = self.bytes(64 << 10).unwrap_or_default();
        let raw = serde_json::from_slice::<serde_json::Value>(&b)
            .ok()
            .and_then(|v| v["error"].as_str().map(str::to_owned))
            .unwrap_or_else(|| String::from_utf8_lossy(&b[..b.len().min(200)]).into_owned());
        let mut message: String = raw.chars().filter(|c| !c.is_control()).take(500).collect();
        if message.is_empty() {
            message = "(no reason given)".into();
        }
        Err(anyhow!(Status { code, message }))
    }

    /// 2xx: the JSON body (at most `max` bytes).
    pub fn json<T: serde::de::DeserializeOwned>(self, max: u64) -> Result<T> {
        let b = self.ok()?.bytes(max)?;
        serde_json::from_slice(&b).context("malformed JSON from NexusStor")
    }
}

impl Read for Response {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let n = {
            let b = self.fill_buf()?;
            let n = b.len().min(out.len());
            out[..n].copy_from_slice(&b[..n]);
            n
        };
        self.consume(n);
        Ok(n)
    }
}

impl BufRead for Response {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        let limit = match &mut self.body {
            Body::Length(0) | Body::Chunked { done: true, .. } => return Ok(&[]),
            Body::Length(left) => *left,
            Body::Chunked { left, done, crlf } => {
                if *left == 0 {
                    if *crlf {
                        if !read_line(&mut self.r, 2)?.is_empty() {
                            return Err(io::Error::new(io::ErrorKind::InvalidData, "bad chunk terminator"));
                        }
                        *crlf = false;
                    }
                    let l = read_line(&mut self.r, 1024)?;
                    let size = u64::from_str_radix(l.split(';').next().unwrap_or("").trim(), 16)
                        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "bad chunk size"))?;
                    if size == 0 {
                        let mut total = 0;
                        loop {
                            let t = read_line(&mut self.r, MAX_HEAD)?;
                            total += t.len();
                            if t.is_empty() {
                                break;
                            }
                            if total > MAX_HEAD {
                                return Err(io::Error::new(io::ErrorKind::InvalidData, "trailers too large"));
                            }
                        }
                        *done = true;
                        return Ok(&[]);
                    }
                    *left = size;
                }
                *left
            }
        };
        let b = self.r.fill_buf()?;
        if b.is_empty() {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "answer truncated"));
        }
        let n = (b.len() as u64).min(limit) as usize;
        Ok(&b[..n])
    }

    fn consume(&mut self, n: usize) {
        if n == 0 {
            return;
        }
        self.r.consume(n);
        match &mut self.body {
            Body::Length(left) => *left -= n as u64,
            Body::Chunked { left, crlf, .. } => {
                *left -= n as u64;
                *crlf = *left == 0;
            }
        }
    }
}
