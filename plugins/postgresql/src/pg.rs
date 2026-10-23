//! Minimal PostgreSQL client (frontend/backend protocol 3.0), just what the plugin
//! needs: TLS (rustls), cleartext / md5 / SCRAM-SHA-256 authentication, simple
//! queries with text results, COPY out/in and raw message access for the
//! replication commands (BASE_BACKUP, START_REPLICATION). No libpq, no binaries:
//! the plugin sandbox cannot run client tools the appliance image does not ship.

use anyhow::{anyhow, bail, Context, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use hmac::{Hmac, Mac};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, ClientConnection, DigitallySignedStruct, RootCertStore, SignatureScheme, StreamOwned};
use sha2::{Digest, Sha256};
use std::io::{BufReader, Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum SslMode {
    Disable,
    /// encrypted, server certificate not verified (libpq `require`)
    Require,
    /// chain against `ca_cert` (else the public web PKI roots) + host name
    VerifyFull,
}

#[derive(Clone, Debug)]
pub struct Opts {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub password: String,
    pub dbname: String,
    pub ssl: SslMode,
    pub ca_cert: Option<String>,
    /// physical replication connection (`replication=true`)
    pub replication: bool,
}

/// A server error (ErrorResponse) with its SQLSTATE.
#[derive(Debug)]
pub struct PgError {
    pub code: String,
    pub message: String,
}

impl std::fmt::Display for PgError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} (SQLSTATE {})", self.message, self.code)
    }
}
impl std::error::Error for PgError {}

/// SQLSTATE of an error from this module, if it came from the server.
pub fn sqlstate(e: &anyhow::Error) -> Option<&str> {
    e.downcast_ref::<PgError>().map(|p| p.code.as_str())
}

pub type Row = Vec<Option<String>>;

trait Io: Read + Write + Send {}
impl<T: Read + Write + Send> Io for T {}

pub struct Conn {
    io: BufReader<Box<dyn Io>>,
    /// server major version (e.g. 17)
    pub major: u32,
    pub server_version: String,
    /// startup done (later ParameterStatus messages are skipped)
    ready: bool,
}

/// Messages larger than this are refused (CopyData of BASE_BACKUP/WAL are ≤ ~1 MiB).
const MAX_MSG: usize = 256 << 20;

/// Seconds a read may wait. A server that stops talking must not hang the job forever (the host's idle
/// limit is 15 min); a query may be silent for minutes (an index build during a restore), a replication
/// stream is not: a base backup sends data once its checkpoint is done, WAL streaming a keepalive every
/// `wal_sender_timeout / 2` (30 s by default). A primary that vanished without closing the connection (a
/// failover by a hard stop) is noticed after 3 minutes instead of 10 (lab 2026-10-23).
pub fn read_timeout(replication: bool) -> u64 {
    if replication {
        180
    } else {
        600
    }
}

impl Conn {
    pub fn connect(o: &Opts) -> Result<Conn> {
        let tcp =
            TcpStream::connect((o.host.as_str(), o.port)).with_context(|| format!("connect {}:{}", o.host, o.port))?;
        tcp.set_nodelay(true)?;
        tcp.set_read_timeout(Some(Duration::from_secs(read_timeout(o.replication))))?;
        let io: Box<dyn Io> = if o.ssl == SslMode::Disable {
            Box::new(tcp)
        } else {
            let mut tcp = tcp;
            // SSLRequest
            tcp.write_all(&[0, 0, 0, 8, 0x04, 0xd2, 0x16, 0x2f])?;
            let mut b = [0u8; 1];
            tcp.read_exact(&mut b)?;
            if b[0] != b'S' {
                bail!(
                    "{}:{}: the server does not offer TLS (sslmode {:?})",
                    o.host,
                    o.port,
                    o.ssl
                );
            }
            let name = ServerName::try_from(o.host.clone()).map_err(|_| anyhow!("invalid host name {}", o.host))?;
            let tls = ClientConnection::new(Arc::new(tls_config(o)?), name)?;
            Box::new(StreamOwned::new(tls, tcp))
        };
        let mut c = Conn {
            io: BufReader::with_capacity(1 << 16, io),
            major: 0,
            server_version: String::new(),
            ready: false,
        };
        c.startup(o)?;
        Ok(c)
    }

    fn startup(&mut self, o: &Opts) -> Result<()> {
        let mut body = 196608u32.to_be_bytes().to_vec(); // protocol 3.0
        let mut param = |k: &str, v: &str| {
            body.extend_from_slice(k.as_bytes());
            body.push(0);
            body.extend_from_slice(v.as_bytes());
            body.push(0);
        };
        param("user", &o.user);
        if o.replication {
            param("replication", "true");
        } else {
            param("database", &o.dbname);
        }
        param("client_encoding", "UTF8");
        param("application_name", "nexusbackup");
        body.push(0);
        let mut m = ((body.len() + 4) as u32).to_be_bytes().to_vec();
        m.extend_from_slice(&body);
        self.write(&m)?;
        let mut scram: Option<Scram> = None;
        loop {
            let (t, b) = self.recv()?;
            match t {
                b'R' => {
                    let code = be32(&b, 0)?;
                    match code {
                        0 => {}
                        3 => self.send(b'p', &cstr(&o.password))?,
                        5 => {
                            let salt = b.get(4..8).context("md5 salt")?;
                            let inner = hex(&md5::Md5::digest(format!("{}{}", o.password, o.user)));
                            let mut h = md5::Md5::new();
                            h.update(inner.as_bytes());
                            h.update(salt);
                            self.send(b'p', &cstr(&format!("md5{}", hex(&h.finalize()))))?;
                        }
                        10 => {
                            let mechs: Vec<&[u8]> = b[4..].split(|x| *x == 0).collect();
                            if !mechs.contains(&&b"SCRAM-SHA-256"[..]) {
                                bail!("the server offers no supported SASL mechanism");
                            }
                            let s = Scram::new(&o.password)?;
                            let first = s.client_first();
                            let mut m = cstr("SCRAM-SHA-256");
                            m.extend_from_slice(&(first.len() as u32).to_be_bytes());
                            m.extend_from_slice(first.as_bytes());
                            self.send(b'p', &m)?;
                            scram = Some(s);
                        }
                        11 => {
                            let s = scram.as_mut().context("SASL continue without start")?;
                            let fin = s.client_final(std::str::from_utf8(&b[4..])?)?;
                            self.send(b'p', fin.as_bytes())?;
                        }
                        12 => {
                            let s = scram.as_ref().context("SASL final without start")?;
                            s.verify_server(std::str::from_utf8(&b[4..])?)?;
                        }
                        c => bail!("unsupported authentication method {c} (use scram-sha-256, md5 or password)"),
                    }
                }
                b'S' => {
                    let mut it = b.split(|x| *x == 0);
                    if it.next() == Some(b"server_version") {
                        self.server_version = String::from_utf8_lossy(it.next().unwrap_or_default()).into_owned();
                        self.major = self
                            .server_version
                            .split(|c: char| !c.is_ascii_digit())
                            .next()
                            .and_then(|s| s.parse().ok())
                            .unwrap_or(0);
                    }
                }
                b'K' | b'N' => {}
                b'Z' => {
                    self.ready = true;
                    return Ok(());
                }
                b'E' => return Err(error(&b).into()),
                t => bail!("unexpected message {:?} during startup", t as char),
            }
        }
    }

    fn write(&mut self, b: &[u8]) -> Result<()> {
        let w = self.io.get_mut();
        w.write_all(b)?;
        w.flush()?;
        Ok(())
    }

    /// Sends one frontend message.
    pub fn send(&mut self, tag: u8, body: &[u8]) -> Result<()> {
        let mut m = Vec::with_capacity(body.len() + 5);
        m.push(tag);
        m.extend_from_slice(&((body.len() + 4) as u32).to_be_bytes());
        m.extend_from_slice(body);
        self.write(&m)
    }

    /// Sends a query and leaves reading the answer to the caller (replication commands).
    pub fn query_start(&mut self, sql: &str) -> Result<()> {
        self.send(b'Q', &cstr(sql))
    }

    /// Next backend message (tag, body); notices and parameter changes are skipped.
    pub fn recv(&mut self) -> Result<(u8, Vec<u8>)> {
        loop {
            let mut h = [0u8; 5];
            self.io.read_exact(&mut h).context("server closed the connection")?;
            let len = u32::from_be_bytes([h[1], h[2], h[3], h[4]]) as usize;
            if !(4..=MAX_MSG).contains(&len) {
                bail!("invalid message length {len}");
            }
            let mut b = vec![0u8; len - 4];
            self.io.read_exact(&mut b)?;
            match h[0] {
                b'N' | b'A' => continue,
                b'S' if self.ready => continue,
                t => return Ok((t, b)),
            }
        }
    }

    /// Runs `sql` (simple query protocol); the rows of all its result sets.
    pub fn query(&mut self, sql: &str) -> Result<Vec<Row>> {
        self.send(b'Q', &cstr(sql))?;
        let mut rows = Vec::new();
        let mut err = None;
        loop {
            let (t, b) = self.recv()?;
            match t {
                b'D' => rows.push(data_row(&b)?),
                b'E' => err = Some(error(&b)),
                // COPY started by a statement that is not expected to: end it
                b'G' => self.send(b'f', &cstr("unexpected COPY"))?,
                b'H' | b'd' | b'c' | b'T' | b'C' | b'I' => {}
                b'Z' => break,
                t => bail!("unexpected message {:?}", t as char),
            }
        }
        match err {
            Some(e) => Err(e.into()),
            None => Ok(rows),
        }
    }

    pub fn exec(&mut self, sql: &str) -> Result<()> {
        self.query(sql).map(|_| ())
    }

    /// One value of a one-row query.
    pub fn value(&mut self, sql: &str) -> Result<Option<String>> {
        let rows = self.query(sql)?;
        Ok(rows.into_iter().next().and_then(|r| r.into_iter().next()).flatten())
    }

    /// `COPY … TO STDOUT`: every data message goes to `out`.
    pub fn copy_out(&mut self, sql: &str, out: &mut dyn FnMut(&[u8]) -> Result<()>) -> Result<()> {
        self.send(b'Q', &cstr(sql))?;
        let mut err: Option<anyhow::Error> = None;
        loop {
            let (t, b) = self.recv()?;
            match t {
                b'd' => {
                    if err.is_none() {
                        if let Err(e) = out(&b) {
                            err = Some(e);
                        }
                    }
                }
                b'E' => err = Some(error(&b).into()),
                b'H' | b'c' | b'C' => {}
                b'Z' => break,
                t => bail!("unexpected message {:?} during COPY", t as char),
            }
        }
        err.map_or(Ok(()), Err)
    }

    /// `COPY … FROM STDIN`: start; then [`Conn::copy_data`]*, [`Conn::copy_end`].
    pub fn copy_in(&mut self, sql: &str) -> Result<()> {
        self.send(b'Q', &cstr(sql))?;
        let (t, b) = self.recv()?;
        match t {
            b'G' => Ok(()),
            b'E' => {
                let e = error(&b);
                self.until_ready()?;
                Err(e.into())
            }
            t => bail!("unexpected message {:?} (expected CopyInResponse)", t as char),
        }
    }

    pub fn copy_data(&mut self, data: &[u8]) -> Result<()> {
        self.send(b'd', data)
    }

    pub fn copy_end(&mut self) -> Result<()> {
        self.send(b'c', &[])?;
        let mut err = None;
        loop {
            let (t, b) = self.recv()?;
            match t {
                b'E' => err = Some(error(&b)),
                b'C' => {}
                b'Z' => break,
                t => bail!("unexpected message {:?} after COPY", t as char),
            }
        }
        err.map_or(Ok(()), |e| Err(e.into()))
    }

    fn until_ready(&mut self) -> Result<()> {
        while self.recv()?.0 != b'Z' {}
        Ok(())
    }

    pub fn close(mut self) {
        let _ = self.send(b'X', &[]);
    }
}

pub fn error(b: &[u8]) -> PgError {
    let mut e = PgError {
        code: String::new(),
        message: String::new(),
    };
    for f in b.split(|x| *x == 0) {
        let Some((&k, v)) = f.split_first() else { continue };
        let v = String::from_utf8_lossy(v).into_owned();
        match k {
            b'C' => e.code = v,
            b'M' => e.message = v,
            b'D' => e.message = format!("{}; {v}", e.message),
            _ => {}
        }
    }
    e
}

/// Columns of a DataRow (text format).
pub fn data_row(b: &[u8]) -> Result<Row> {
    let n = u16::from_be_bytes([*b.first().context("row")?, *b.get(1).context("row")?]) as usize;
    let mut out = Vec::with_capacity(n);
    let mut p = 2;
    for _ in 0..n {
        let len = be32(b, p)? as i32;
        p += 4;
        if len < 0 {
            out.push(None);
        } else {
            let v = b.get(p..p + len as usize).context("short row")?;
            out.push(Some(String::from_utf8_lossy(v).into_owned()));
            p += len as usize;
        }
    }
    Ok(out)
}

pub fn be32(b: &[u8], at: usize) -> Result<u32> {
    let s = b.get(at..at + 4).context("short message")?;
    Ok(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
}

pub fn be64(b: &[u8], at: usize) -> Result<u64> {
    let s = b.get(at..at + 8).context("short message")?;
    Ok(u64::from_be_bytes(s.try_into()?))
}

fn cstr(s: &str) -> Vec<u8> {
    let mut v = s.as_bytes().to_vec();
    v.push(0);
    v
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// SQL string literal (standard_conforming_strings = on).
pub fn lit(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

/// Quoted identifier.
pub fn ident(s: &str) -> String {
    format!("\"{}\"", s.replace('"', "\"\""))
}

/// `X/Y` (hex) → LSN.
pub fn parse_lsn(s: &str) -> Result<u64> {
    let (a, b) = s.split_once('/').with_context(|| format!("invalid LSN {s:?}"))?;
    Ok((u64::from_str_radix(a, 16)? << 32) | u64::from_str_radix(b, 16)?)
}

pub fn fmt_lsn(l: u64) -> String {
    format!("{:X}/{:X}", l >> 32, l & 0xffff_ffff)
}

// ---- SCRAM-SHA-256 (RFC 5802 / 7677), no channel binding -------------------

type HmacSha256 = Hmac<Sha256>;

fn hmac(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut m = HmacSha256::new_from_slice(key).expect("any key length");
    m.update(data);
    m.finalize().into_bytes().into()
}

pub(crate) struct Scram {
    password: String,
    nonce: String,
    first_bare: String,
    server_sig: Option<[u8; 32]>,
}

impl Scram {
    fn new(password: &str) -> Result<Scram> {
        let mut n = [0u8; 18];
        getrandom::getrandom(&mut n).map_err(|e| anyhow!("random: {e}"))?;
        Ok(Scram::with_nonce(password, &B64.encode(n)))
    }

    pub(crate) fn with_nonce(password: &str, nonce: &str) -> Scram {
        Scram {
            password: password.into(),
            nonce: nonce.into(),
            first_bare: format!("n=,r={nonce}"),
            server_sig: None,
        }
    }

    pub(crate) fn client_first(&self) -> String {
        format!("n,,{}", self.first_bare)
    }

    pub(crate) fn client_final(&mut self, server_first: &str) -> Result<String> {
        let (mut r, mut s, mut i) = (None, None, None);
        for a in server_first.split(',') {
            match a.split_at_checked(2) {
                Some(("r=", v)) => r = Some(v),
                Some(("s=", v)) => s = Some(B64.decode(v)?),
                Some(("i=", v)) => i = Some(v.parse::<u32>()?),
                _ => {}
            }
        }
        let (r, salt, iters) = (
            r.context("SCRAM: no nonce")?,
            s.context("SCRAM: no salt")?,
            i.context("SCRAM: no iteration count")?,
        );
        if !r.starts_with(&self.nonce) || !(1..=10_000_000).contains(&iters) {
            bail!("SCRAM: invalid server-first-message");
        }
        // Hi() = PBKDF2-HMAC-SHA-256
        let mut u = hmac(
            self.password.as_bytes(),
            &[salt.as_slice(), &1u32.to_be_bytes()].concat(),
        );
        let mut salted = u;
        for _ in 1..iters {
            u = hmac(self.password.as_bytes(), &u);
            for (a, b) in salted.iter_mut().zip(u) {
                *a ^= b;
            }
        }
        let client_key = hmac(&salted, b"Client Key");
        let stored: [u8; 32] = Sha256::digest(client_key).into();
        let without_proof = format!("c=biws,r={r}");
        let auth = format!("{},{server_first},{without_proof}", self.first_bare);
        let sig = hmac(&stored, auth.as_bytes());
        let proof: Vec<u8> = client_key.iter().zip(sig).map(|(a, b)| a ^ b).collect();
        self.server_sig = Some(hmac(&hmac(&salted, b"Server Key"), auth.as_bytes()));
        Ok(format!("{without_proof},p={}", B64.encode(proof)))
    }

    pub(crate) fn verify_server(&self, server_final: &str) -> Result<()> {
        let v = server_final
            .split(',')
            .find_map(|a| a.strip_prefix("v="))
            .context("SCRAM: no server signature")?;
        if Some(B64.decode(v)?.as_slice()) != self.server_sig.as_ref().map(|s| &s[..]) {
            bail!("SCRAM: the server's signature is wrong (not the server holding the password)");
        }
        Ok(())
    }
}

// ---- TLS ------------------------------------------------------------------

/// `require`: encrypted, any certificate (handshake signatures are still checked).
#[derive(Debug)]
struct AnyCert(Arc<CryptoProvider>);

impl ServerCertVerifier for AnyCert {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        msg: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(msg, cert, dss, &self.0.signature_verification_algorithms)
    }
    fn verify_tls13_signature(
        &self,
        msg: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(msg, cert, dss, &self.0.signature_verification_algorithms)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

fn tls_config(o: &Opts) -> Result<ClientConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let b = ClientConfig::builder_with_provider(provider.clone()).with_safe_default_protocol_versions()?;
    Ok(match o.ssl {
        SslMode::Require => b
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AnyCert(provider)))
            .with_no_client_auth(),
        _ => {
            let mut roots = RootCertStore::empty();
            match o.ca_cert.as_deref().filter(|s| !s.trim().is_empty()) {
                Some(pem) => {
                    let pem = crate::rewrap_pem(pem);
                    for c in CertificateDer::pem_slice_iter(pem.as_bytes()) {
                        roots.add(c.context("ca_cert")?).context("ca_cert")?;
                    }
                    if roots.is_empty() {
                        bail!("ca_cert: no certificate");
                    }
                }
                None => roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned()),
            }
            b.with_root_certificates(roots).with_no_client_auth()
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scram_rfc7677_vector() {
        // RFC 7677 §3 (user "user", password "pencil")
        let mut s = Scram::with_nonce("pencil", "rOprNGfwEbeRWgbNEkqO");
        s.first_bare = "n=user,r=rOprNGfwEbeRWgbNEkqO".into();
        let fin = s
            .client_final("r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096")
            .unwrap();
        assert_eq!(
            fin,
            "c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ="
        );
        s.verify_server("v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=")
            .unwrap();
        assert!(s.verify_server("v=AAAA").is_err());
    }

    #[test]
    fn quoting_and_lsn() {
        assert_eq!(lit("it's"), "'it''s'");
        assert_eq!(ident("a\"b"), "\"a\"\"b\"");
        assert_eq!(parse_lsn("16/B374D848").unwrap(), 0x16_B374_D848);
        assert_eq!(fmt_lsn(0x16_B374_D848), "16/B374D848");
        assert!(parse_lsn("nope").is_err());
    }

    #[test]
    fn rows_and_errors() {
        let mut b = vec![0, 2];
        b.extend_from_slice(&3u32.to_be_bytes());
        b.extend_from_slice(b"abc");
        b.extend_from_slice(&(-1i32).to_be_bytes());
        assert_eq!(data_row(&b).unwrap(), vec![Some("abc".into()), None]);
        assert!(data_row(&b[..6]).is_err());
        let e = error(b"SERROR\0C42P01\0Mrelation \"x\" does not exist\0\0");
        assert_eq!(
            (e.code.as_str(), e.message.as_str()),
            ("42P01", "relation \"x\" does not exist")
        );
    }
}
