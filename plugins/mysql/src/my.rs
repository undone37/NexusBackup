//! Minimal MySQL/MariaDB client (client/server protocol 4.1), just what the plugin
//! needs: TLS (rustls), mysql_native_password and caching_sha2_password
//! authentication (full authentication only over TLS), text queries with
//! binary-safe rows, and COM_BINLOG_DUMP for the binlog pull. No libmysqlclient,
//! no binaries: the plugin sandbox cannot run client tools the appliance image
//! does not ship.

use anyhow::{anyhow, bail, Context, Result};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, ClientConnection, DigitallySignedStruct, RootCertStore, SignatureScheme, StreamOwned};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::io::{BufReader, Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum SslMode {
    Disable,
    /// encrypted, server certificate not verified
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
    /// default database ("" = none)
    pub dbname: String,
    pub ssl: SslMode,
    pub ca_cert: Option<String>,
}

/// A server error (ERR packet).
#[derive(Debug)]
pub struct MyError {
    pub code: u16,
    pub state: String,
    pub message: String,
}

impl std::fmt::Display for MyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} (error {}, SQLSTATE {})", self.message, self.code, self.state)
    }
}
impl std::error::Error for MyError {}

/// Server error code of an error from this module.
pub fn code(e: &anyhow::Error) -> Option<u16> {
    e.downcast_ref::<MyError>().map(|m| m.code)
}

/// A row of a text result set: binary-safe values, NULL = None.
pub type Row = Vec<Option<Vec<u8>>>;

/// Column of a result set (what the dump needs to render values).
#[derive(Clone, Debug)]
pub struct Column {
    pub ty: u8,
    pub charset: u16,
}

pub const BINARY_CHARSET: u16 = 63;

trait Io: Read + Write + Send {}
impl<T: Read + Write + Send> Io for T {}

// capability flags
const LONG_PASSWORD: u32 = 1;
const LONG_FLAG: u32 = 4;
const CONNECT_WITH_DB: u32 = 8;
const PROTOCOL_41: u32 = 0x200;
const SSL: u32 = 0x800;
const TRANSACTIONS: u32 = 0x2000;
const SECURE_CONNECTION: u32 = 0x8000;
const PLUGIN_AUTH: u32 = 0x8_0000;
const PLUGIN_AUTH_LENENC: u32 = 0x20_0000;

/// Packets larger than this are refused (a row or an event; max_allowed_packet is ≤ 1 GiB).
const MAX_PACKET: usize = 1 << 30;

pub struct Conn {
    io: BufReader<Box<dyn Io>>,
    seq: u8,
    pub server_version: String,
    /// MariaDB (else MySQL)
    pub mariadb: bool,
    /// (major, minor) of the server version
    pub version: (u32, u32),
    tls: bool,
}

fn read_packet(r: &mut impl Read, seq: &mut u8) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let mut h = [0u8; 4];
        r.read_exact(&mut h).context("server closed the connection")?;
        let len = u32::from_le_bytes([h[0], h[1], h[2], 0]) as usize;
        *seq = h[3].wrapping_add(1);
        if out.len() + len > MAX_PACKET {
            bail!("packet larger than {MAX_PACKET} bytes");
        }
        let at = out.len();
        out.resize(at + len, 0);
        r.read_exact(&mut out[at..])?;
        if len < 0xff_ffff {
            return Ok(out);
        }
    }
}

fn frame(payload: &[u8], seq: &mut u8) -> Vec<u8> {
    let mut m = Vec::with_capacity(payload.len() + 8);
    let mut chunks = payload.chunks(0xff_ffff).peekable();
    if payload.is_empty() {
        m.extend_from_slice(&[0, 0, 0, *seq]);
        *seq = seq.wrapping_add(1);
    }
    while let Some(c) = chunks.next() {
        m.extend_from_slice(&(c.len() as u32).to_le_bytes()[..3]);
        m.push(*seq);
        *seq = seq.wrapping_add(1);
        m.extend_from_slice(c);
        if c.len() == 0xff_ffff && chunks.peek().is_none() {
            m.extend_from_slice(&[0, 0, 0, *seq]);
            *seq = seq.wrapping_add(1);
        }
    }
    m
}

/// mysql_native_password: SHA1(pw) XOR SHA1(scramble + SHA1(SHA1(pw))).
pub fn native_scramble(password: &str, scramble: &[u8]) -> Vec<u8> {
    if password.is_empty() {
        return Vec::new();
    }
    let h1 = Sha1::digest(password.as_bytes());
    let h2 = Sha1::digest(h1);
    let mut h = Sha1::new();
    h.update(scramble);
    h.update(h2);
    h1.iter().zip(h.finalize()).map(|(a, b)| a ^ b).collect()
}

/// caching_sha2_password fast path: SHA256(pw) XOR SHA256(SHA256(SHA256(pw)) + scramble).
pub fn sha2_scramble(password: &str, scramble: &[u8]) -> Vec<u8> {
    if password.is_empty() {
        return Vec::new();
    }
    let h1 = Sha256::digest(password.as_bytes());
    let h2 = Sha256::digest(h1);
    let mut h = Sha256::new();
    h.update(h2);
    h.update(scramble);
    h1.iter().zip(h.finalize()).map(|(a, b)| a ^ b).collect()
}

/// Reads a length-encoded integer at `*p`.
pub fn lenenc(b: &[u8], p: &mut usize) -> Result<Option<u64>> {
    let first = *b.get(*p).context("truncated packet")?;
    *p += 1;
    let n = match first {
        0xfb => return Ok(None),
        0xfc => 2,
        0xfd => 3,
        0xfe => 8,
        x => return Ok(Some(x as u64)),
    };
    let s = b.get(*p..*p + n).context("truncated packet")?;
    *p += n;
    let mut v = [0u8; 8];
    v[..n].copy_from_slice(s);
    Ok(Some(u64::from_le_bytes(v)))
}

fn lenenc_bytes<'a>(b: &'a [u8], p: &mut usize) -> Result<Option<&'a [u8]>> {
    match lenenc(b, p)? {
        None => Ok(None),
        Some(n) => {
            let s = b.get(*p..*p + n as usize).context("truncated packet")?;
            *p += n as usize;
            Ok(Some(s))
        }
    }
}

fn put_lenenc(out: &mut Vec<u8>, n: usize) {
    match n {
        0..=250 => out.push(n as u8),
        251..=0xffff => {
            out.push(0xfc);
            out.extend_from_slice(&(n as u16).to_le_bytes());
        }
        0x1_0000..=0xff_ffff => {
            out.push(0xfd);
            out.extend_from_slice(&(n as u32).to_le_bytes()[..3]);
        }
        _ => {
            out.push(0xfe);
            out.extend_from_slice(&(n as u64).to_le_bytes());
        }
    }
}

fn cstr(b: &[u8], p: &mut usize) -> Result<Vec<u8>> {
    let end = b[*p..].iter().position(|x| *x == 0).context("unterminated string")?;
    let s = b[*p..*p + end].to_vec();
    *p += end + 1;
    Ok(s)
}

pub fn err_packet(b: &[u8]) -> MyError {
    let code = b.get(1..3).map_or(0, |c| u16::from_le_bytes([c[0], c[1]]));
    let (state, msg) = match b.get(3) {
        Some(b'#') if b.len() >= 9 => (String::from_utf8_lossy(&b[4..9]).into_owned(), &b[9..]),
        _ => (String::new(), b.get(3..).unwrap_or_default()),
    };
    MyError {
        code,
        state,
        message: String::from_utf8_lossy(msg).into_owned(),
    }
}

/// EOF packet (0xfe, short): not a row starting with a 8-byte length.
fn is_eof(b: &[u8]) -> bool {
    b.first() == Some(&0xfe) && b.len() < 9
}

/// Status flags of an EOF packet (SERVER_MORE_RESULTS_EXISTS = 8).
fn eof_status(b: &[u8]) -> u16 {
    b.get(3..5).map_or(0, |s| u16::from_le_bytes([s[0], s[1]]))
}

/// Status flags of an OK packet.
fn ok_status(b: &[u8]) -> Result<u16> {
    let mut p = 1;
    lenenc(b, &mut p)?;
    lenenc(b, &mut p)?;
    Ok(b.get(p..p + 2).map_or(0, |s| u16::from_le_bytes([s[0], s[1]])))
}

impl Conn {
    pub fn connect(o: &Opts) -> Result<Conn> {
        let mut tcp =
            TcpStream::connect((o.host.as_str(), o.port)).with_context(|| format!("connect {}:{}", o.host, o.port))?;
        tcp.set_nodelay(true)?;
        // a server that stops talking must not hang the job forever (the host's idle limit is 15 min)
        tcp.set_read_timeout(Some(Duration::from_secs(600)))?;
        let mut seq = 0;
        let hs = read_packet(&mut tcp, &mut seq)?;
        if hs.first() == Some(&0xff) {
            return Err(err_packet(&hs).into());
        }
        if hs.first() != Some(&10) {
            bail!("{}:{}: not a MySQL/MariaDB server (protocol {:?})", o.host, o.port, hs.first());
        }
        let mut p = 1;
        let version = String::from_utf8_lossy(&cstr(&hs, &mut p)?).into_owned();
        p += 4; // thread id
        let mut scramble = hs.get(p..p + 8).context("handshake")?.to_vec();
        p += 9;
        let caps_lo = u16::from_le_bytes([hs[p], hs[p + 1]]) as u32;
        p += 2 + 1 + 2; // caps, charset, status
        let caps_hi = hs.get(p..p + 2).map_or(0, |c| u16::from_le_bytes([c[0], c[1]]) as u32);
        let server_caps = caps_lo | caps_hi << 16;
        p += 2;
        let auth_len = *hs.get(p).unwrap_or(&0) as usize;
        p += 1 + 10;
        if server_caps & SECURE_CONNECTION != 0 {
            let n = auth_len.saturating_sub(8).max(13);
            let part = hs.get(p..p + n).context("handshake scramble")?;
            scramble.extend_from_slice(part.strip_suffix(&[0]).unwrap_or(part));
            p += n;
        }
        let mut plugin = if server_caps & PLUGIN_AUTH != 0 && p < hs.len() {
            String::from_utf8_lossy(&cstr(&hs, &mut p).unwrap_or_else(|_| hs[p..].to_vec())).into_owned()
        } else {
            "mysql_native_password".into()
        };

        let mut caps = LONG_PASSWORD
            | LONG_FLAG
            | PROTOCOL_41
            | TRANSACTIONS
            | SECURE_CONNECTION
            | PLUGIN_AUTH
            | PLUGIN_AUTH_LENENC;
        if !o.dbname.is_empty() {
            caps |= CONNECT_WITH_DB;
        }
        let head = |caps: u32| {
            let mut b = caps.to_le_bytes().to_vec();
            b.extend_from_slice(&(16u32 << 20).to_le_bytes());
            b.push(45); // utf8mb4_general_ci (both servers know it)
            b.extend_from_slice(&[0; 23]);
            b
        };
        let io: Box<dyn Io> = if o.ssl == SslMode::Disable {
            Box::new(tcp)
        } else {
            if server_caps & SSL == 0 {
                bail!("{}:{}: the server does not offer TLS (TLS mode {:?})", o.host, o.port, o.ssl);
            }
            caps |= SSL;
            tcp.write_all(&frame(&head(caps), &mut seq))?;
            let name = ServerName::try_from(o.host.clone()).map_err(|_| anyhow!("invalid host name {}", o.host))?;
            let tls = ClientConnection::new(Arc::new(tls_config(o)?), name)?;
            Box::new(StreamOwned::new(tls, tcp))
        };
        let mut c = Conn {
            io: BufReader::with_capacity(1 << 16, io),
            seq,
            mariadb: version.contains("MariaDB"),
            version: parse_version(&version),
            server_version: version.trim_start_matches("5.5.5-").to_owned(),
            tls: o.ssl != SslMode::Disable,
        };
        let mut resp = head(caps);
        resp.extend_from_slice(o.user.as_bytes());
        resp.push(0);
        let auth = c.auth_data(&plugin, &o.password, &scramble)?;
        put_lenenc(&mut resp, auth.len());
        resp.extend_from_slice(&auth);
        if !o.dbname.is_empty() {
            resp.extend_from_slice(o.dbname.as_bytes());
            resp.push(0);
        }
        resp.extend_from_slice(plugin.as_bytes());
        resp.push(0);
        c.send_raw(&resp)?;
        loop {
            let b = c.recv()?;
            match b.first() {
                Some(0) => return Ok(c),
                Some(0xff) => return Err(err_packet(&b).into()),
                Some(0xfe) => {
                    // auth switch: plugin name + new scramble
                    let mut q = 1;
                    plugin = String::from_utf8_lossy(&cstr(&b, &mut q)?).into_owned();
                    scramble = b[q..].strip_suffix(&[0]).unwrap_or(&b[q..]).to_vec();
                    let a = c.auth_data(&plugin, &o.password, &scramble)?;
                    c.send_raw(&a)?;
                }
                Some(1) if plugin == "caching_sha2_password" => match b.get(1) {
                    Some(3) => {} // fast auth ok, the OK packet follows
                    Some(4) => {
                        if !c.tls {
                            bail!(
                                "caching_sha2_password: the server wants the full authentication, which needs TLS \
                                 (TLS mode disable)"
                            );
                        }
                        let mut pw = o.password.as_bytes().to_vec();
                        pw.push(0);
                        c.send_raw(&pw)?;
                    }
                    x => bail!("caching_sha2_password: unexpected state {x:?}"),
                },
                x => bail!("unexpected packet {x:?} during authentication"),
            }
        }
    }

    fn auth_data(&self, plugin: &str, password: &str, scramble: &[u8]) -> Result<Vec<u8>> {
        Ok(match plugin {
            "mysql_native_password" => native_scramble(password, scramble),
            "caching_sha2_password" => sha2_scramble(password, scramble),
            "mysql_clear_password" if self.tls => {
                let mut v = password.as_bytes().to_vec();
                v.push(0);
                v
            }
            p => bail!("unsupported authentication plugin {p} (use mysql_native_password or caching_sha2_password)"),
        })
    }

    fn send_raw(&mut self, payload: &[u8]) -> Result<()> {
        let m = frame(payload, &mut self.seq);
        let w = self.io.get_mut();
        w.write_all(&m)?;
        w.flush()?;
        Ok(())
    }

    /// Starts a command (sequence 0).
    pub fn command(&mut self, cmd: u8, body: &[u8]) -> Result<()> {
        self.seq = 0;
        let mut m = Vec::with_capacity(body.len() + 1);
        m.push(cmd);
        m.extend_from_slice(body);
        self.send_raw(&m)
    }

    /// Next packet.
    pub fn recv(&mut self) -> Result<Vec<u8>> {
        read_packet(&mut self.io, &mut self.seq)
    }

    /// Runs `sql`; calls `row` for every row of every result set (with that set's
    /// columns). Statements without a result set just succeed.
    pub fn query_each(&mut self, sql: &str, mut row: impl FnMut(&[Column], Row) -> Result<()>) -> Result<()> {
        self.command(0x03, sql.as_bytes())?;
        loop {
            let b = self.recv()?;
            let more = match b.first() {
                Some(0) => ok_status(&b)? & 8 != 0,
                Some(0xff) => return Err(err_packet(&b).into()),
                Some(0xfb) => bail!("LOCAL INFILE requested by the server"),
                _ => {
                    let mut p = 0;
                    let n = lenenc(&b, &mut p)?.context("column count")? as usize;
                    let mut cols = Vec::with_capacity(n);
                    for _ in 0..n {
                        let d = self.recv()?;
                        let mut q = 0;
                        for _ in 0..6 {
                            lenenc_bytes(&d, &mut q)?; // catalog, schema, table, org_table, name, org_name
                        }
                        lenenc(&d, &mut q)?; // length of the fixed fields
                        let f = d.get(q..q + 7).context("column definition")?;
                        cols.push(Column {
                            charset: u16::from_le_bytes([f[0], f[1]]),
                            ty: f[6],
                        });
                    }
                    let e = self.recv()?;
                    if !is_eof(&e) {
                        bail!("expected EOF after the column definitions");
                    }
                    let mut first_err = None;
                    let status = loop {
                        let r = self.recv()?;
                        if is_eof(&r) {
                            break eof_status(&r);
                        }
                        if r.first() == Some(&0xff) {
                            return Err(err_packet(&r).into());
                        }
                        if first_err.is_some() {
                            continue; // drain the result set, then report
                        }
                        let mut p = 0;
                        let mut vals = Vec::with_capacity(n);
                        for _ in 0..n {
                            vals.push(lenenc_bytes(&r, &mut p)?.map(<[u8]>::to_vec));
                        }
                        if let Err(e) = row(&cols, vals) {
                            first_err = Some(e);
                        }
                    };
                    if let Some(e) = first_err {
                        return Err(e);
                    }
                    status & 8 != 0
                }
            };
            if !more {
                return Ok(());
            }
        }
    }

    /// All rows of `sql` as (lossy) strings.
    pub fn query(&mut self, sql: &str) -> Result<Vec<Vec<Option<String>>>> {
        let mut out = Vec::new();
        self.query_each(sql, |_, r| {
            out.push(
                r.into_iter()
                    .map(|v| v.map(|v| String::from_utf8_lossy(&v).into_owned()))
                    .collect(),
            );
            Ok(())
        })?;
        Ok(out)
    }

    /// First column of the first row.
    pub fn value(&mut self, sql: &str) -> Result<Option<String>> {
        Ok(self.query(sql)?.into_iter().next().and_then(|r| r.into_iter().next().flatten()))
    }

    pub fn exec(&mut self, sql: &str) -> Result<()> {
        self.query_each(sql, |_, _| Ok(()))
    }

    pub fn close(mut self) {
        let _ = self.command(0x01, &[]);
    }
}

fn parse_version(v: &str) -> (u32, u32) {
    let v = v.trim_start_matches("5.5.5-");
    let mut it = v.split(|c: char| !c.is_ascii_digit()).map(|s| s.parse().unwrap_or(0));
    (it.next().unwrap_or(0), it.next().unwrap_or(0))
}

/// A string literal ('…' with backslash escapes, as mysqldump writes them).
pub fn lit(s: &[u8]) -> Vec<u8> {
    let mut o = Vec::with_capacity(s.len() + 2);
    o.push(b'\'');
    for &c in s {
        match c {
            0 => o.extend_from_slice(b"\\0"),
            b'\n' => o.extend_from_slice(b"\\n"),
            b'\r' => o.extend_from_slice(b"\\r"),
            0x1a => o.extend_from_slice(b"\\Z"),
            b'\'' => o.extend_from_slice(b"\\'"),
            b'\\' => o.extend_from_slice(b"\\\\"),
            c => o.push(c),
        }
    }
    o.push(b'\'');
    o
}

pub fn lit_str(s: &str) -> String {
    String::from_utf8_lossy(&lit(s.as_bytes())).into_owned()
}

/// A quoted identifier.
pub fn ident(s: &str) -> String {
    format!("`{}`", s.replace('`', "``"))
}

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
        SslMode::Require | SslMode::Disable => b
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AnyCert(provider)))
            .with_no_client_auth(),
        SslMode::VerifyFull => {
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
    fn scrambles() {
        // mysql_native_password: the stored hash is '*' + hex(SHA1(SHA1(pw))); the
        // server checks SHA1(scramble XOR-recovered) — here: recover and compare
        let s = b"abcdefghijklmnopqrst";
        let a = native_scramble("secret", s);
        let h2 = Sha1::digest(Sha1::digest(b"secret"));
        let mut h = Sha1::new();
        h.update(s);
        h.update(h2);
        let h1: Vec<u8> = a.iter().zip(h.finalize()).map(|(a, b)| a ^ b).collect();
        assert_eq!(Sha1::digest(&h1).as_slice(), h2.as_slice());
        assert!(native_scramble("", s).is_empty());
        let b = sha2_scramble("secret", s);
        assert_eq!(b.len(), 32);
        let h1 = Sha256::digest(b"secret");
        let mut h = Sha256::new();
        h.update(Sha256::digest(h1));
        h.update(s);
        let x: Vec<u8> = b.iter().zip(h.finalize()).map(|(a, b)| a ^ b).collect();
        assert_eq!(x, h1.to_vec());
    }

    #[test]
    fn packets_and_lenenc() {
        let mut seq = 0;
        let f = frame(b"abc", &mut seq);
        assert_eq!(f, [3, 0, 0, 0, b'a', b'b', b'c']);
        assert_eq!(seq, 1);
        let mut r = &f[..];
        let mut s2 = 0;
        assert_eq!(read_packet(&mut r, &mut s2).unwrap(), b"abc");
        assert_eq!(s2, 1);
        // a payload of exactly 0xffffff bytes is followed by an empty packet
        let big = vec![7u8; 0xff_ffff];
        let mut seq = 0;
        let f = frame(&big, &mut seq);
        assert_eq!(f.len(), 0xff_ffff + 8);
        let mut r = &f[..];
        assert_eq!(read_packet(&mut r, &mut s2).unwrap().len(), 0xff_ffff);
        for n in [0usize, 250, 251, 65535, 65536, 0xff_ffff, 0x100_0000] {
            let mut b = Vec::new();
            put_lenenc(&mut b, n);
            let mut p = 0;
            assert_eq!(lenenc(&b, &mut p).unwrap(), Some(n as u64));
            assert_eq!(p, b.len());
        }
        assert_eq!(lenenc(&[0xfb], &mut 0).unwrap(), None);
        let e = err_packet(b"\xff\x15\x04#28000Access denied");
        assert_eq!((e.code, e.state.as_str(), e.message.as_str()), (1045, "28000", "Access denied"));
        assert!(is_eof(&[0xfe, 0, 0, 2, 0]));
        assert!(!is_eof(&[0xfe, 1, 2, 3, 4, 5, 6, 7, 8, 9]));
    }

    #[test]
    fn quoting() {
        assert_eq!(lit(b"it's\\\n\0"), b"'it\\'s\\\\\\n\\0'");
        assert_eq!(ident("a`b"), "`a``b`");
        assert_eq!(parse_version("5.5.5-10.11.6-MariaDB"), (10, 11));
        assert_eq!(parse_version("8.4.11"), (8, 4));
    }
}
