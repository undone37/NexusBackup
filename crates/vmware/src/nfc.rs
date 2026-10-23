//! NFC disk reads without a proxy VM (the vStorage APIs for Data Protection transport that VDDK calls "network
//! mode"). With an NFC ticket ([`crate::vsphere::Client::nfc_ticket`]) the appliance talks the NFC protocol to
//! the ESXi NFC service directly and reads a snapshot's disk over it.
//!
//! Three layers, all here:
//!  1. authd on TCP 902: the server greets with a plaintext `220` banner, then the client wraps the socket with
//!     TLS (pinned to the ticket's SHA-1 thumbprint) and sends the text commands `SESSION` / `BANNER` /
//!     `THUMBPRINT_SHA2` / `PROXY`. On `useSSL=0` (NBD) the NFC bytes then flow over the raw TCP connection, as
//!     VDDK's network mode does; NBDSSL (a second TLS) is a later option.
//!  2. the classic 264-byte NFC handshake (fixed little-endian frames).
//!  3. the AIO layer (16-byte header, magic `0xA100DA7A`): open the session, open the file, read sectors.
//!
//! This is a clean reimplementation from the public protocol description (docs/nfc-protocol.md); no NexusBackup
//! component ships a VMware library. It reads uncompressed (the chunk store deduplicates and compresses on its
//! own), so FastLZ is not needed here.

use crate::vsphere::NfcTicket;
use anyhow::{bail, Context, Result};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, ClientConnection, DigitallySignedStruct, Error, SignatureScheme, StreamOwned};
use sha1::{Digest, Sha1};
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

const CLASSIC_LEN: usize = 264;
const AIO_MAGIC: u32 = 0xA100_DA7A;
const AIO_HDR: usize = 16;
const DEFAULT_SECTOR: u32 = 512;
/// AIO receive buffer the server splits its read fragments to (2 MiB worked on the lab ESXi 8; 16/32 MiB were
/// rejected). Larger means fewer fragments per read.
const AIO_BUF: u32 = 2 << 20;
const PROTO_VERSION: u32 = 11;

// classic message types (uint32 at offset 0)
const C_SESSION_COMPLETE: u32 = 4;
const C_SESSION_PARAMS: u32 = 33;
const C_SESSION_PARAMS_REPLY: u32 = 36;
const C_HANDSHAKE: u32 = 43;
const C_VERSION: u32 = 51;
const C_AIO_SESSION_OPEN: u32 = 52;
const C_CONNECTION_DATA: u32 = 54;
const C_SESSION_FEATURES: u32 = 55;

// AIO message types
const A_ERROR: u32 = 1;
const A_OPEN_SESSION: u32 = 2;
const A_CLOSE_SESSION: u32 = 3;
const A_OPEN_FILE: u32 = 4;
const A_CLOSE_FILE: u32 = 5;
const A_IO: u32 = 7;
const A_SET_SOCK_OPTS: u32 = 9;
const A_SET_RES_POOL: u32 = 22;

const NFC_DISK: u32 = 2;
const OPEN_READONLY: u32 = 0x1e;
const IO_READ: u64 = 1;

/// A read-only disk opened over NFC. `read_at` reads sector-aligned ranges; the chunk store calls it in offset
/// order from the changed extents.
pub struct NfcDisk {
    conn: Box<dyn Conn>,
    handle: u64,
    sector_size: u32,
    capacity: u64,
    op_id: u32,
}

trait Conn: Read + Write + Send {}
impl<T: Read + Write + Send> Conn for T {}

impl NfcDisk {
    /// Opens `ds_path` (`[datastore] dir/disk.vmdk`, from a snapshot disk's `file`) read-only for a disk of
    /// `capacity` bytes, using `ticket` (NBD transport: plain TCP for the data after the authd TLS handshake).
    pub fn open(ticket: &NfcTicket, ds_path: &str, capacity: u64, timeout: Duration) -> Result<NfcDisk> {
        let addr = (ticket.host.as_str(), ticket.port)
            .to_socket_addrs()?
            .next()
            .with_context(|| format!("cannot resolve {}:{}", ticket.host, ticket.port))?;
        let tcp =
            TcpStream::connect_timeout(&addr, timeout).with_context(|| format!("connect to the NFC service {addr}"))?;
        tcp.set_read_timeout(Some(timeout))?;
        tcp.set_write_timeout(Some(timeout))?;
        tcp.set_nodelay(true)?;

        // authd greets with a plaintext 220 banner before any TLS; read it on the raw socket first
        let banner = read_line(&mut &tcp).context("reading the authd banner")?;
        if !banner.starts_with("220") {
            bail!("unexpected authd banner: {banner:?}");
        }

        // wrap the socket with TLS pinned to the ticket's thumbprint, run the text commands
        let want = parse_thumbprint(&ticket.ssl_thumbprint).context("NFC ticket sslThumbprint")?;
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let cfg = ClientConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(Pin { provider, want }))
            .with_no_client_auth();
        let name = ServerName::try_from(ticket.host.clone()).context("NFC host name")?;
        let conn = ClientConnection::new(Arc::new(cfg), name)?;
        let mut tls = StreamOwned::new(conn, tcp);
        authd_commands(&mut tls, ticket).context("authd handshake")?;
        // NBD: the NFC data flows over the raw TCP connection; drop the authd TLS and keep the socket.
        // ponytail: NBDSSL (a second TLS over this socket) would encrypt the bulk reads; add it if a backup
        // network is untrusted. VDDK's network mode is this plain path.
        let mut raw = tls.sock;

        classic_handshake(&mut raw).context("classic NFC handshake")?;
        let mut op_id = 0u32;
        aio_setup(&mut raw, &mut op_id).context("NFC AIO session")?;
        let (handle, sector_size) =
            aio_open_file(&mut raw, &mut op_id, ds_path).with_context(|| format!("NFC open of {ds_path}"))?;
        if !capacity.is_multiple_of(u64::from(sector_size)) {
            bail!("{ds_path}: capacity {capacity} is not a multiple of the sector size {sector_size}");
        }
        Ok(NfcDisk {
            conn: Box::new(raw),
            handle,
            sector_size,
            capacity,
            op_id,
        })
    }

    pub fn capacity(&self) -> u64 {
        self.capacity
    }

    /// Reads `buf.len()` bytes at `offset`. Offset and length are rounded out to the sector size and the
    /// requested slice copied out, so unaligned calls work (the backup's calls are 4 MiB-aligned).
    pub fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<()> {
        let end = offset
            .checked_add(buf.len() as u64)
            .filter(|e| *e <= self.capacity)
            .with_context(|| {
                format!(
                    "read {}..{} beyond the disk end {}",
                    offset,
                    offset + buf.len() as u64,
                    self.capacity
                )
            })?;
        let ss = u64::from(self.sector_size);
        let a_off = offset - offset % ss;
        let a_end = end.div_ceil(ss) * ss;
        let data = self.io_read(a_off, (a_end - a_off) as usize)?;
        let start = (offset - a_off) as usize;
        buf.copy_from_slice(&data[start..start + buf.len()]);
        Ok(())
    }

    /// One IO read of `len` bytes at the sector-aligned `off`; reassembles the server's fragments.
    fn io_read(&mut self, off: u64, len: usize) -> Result<Vec<u8>> {
        let op = self.next_op();
        let mut payload = [0u8; 44];
        payload[0..8].copy_from_slice(&self.handle.to_le_bytes());
        payload[8..16].copy_from_slice(&IO_READ.to_le_bytes()); // low: read; high (compression): 0 = none
        payload[16..24].copy_from_slice(&off.to_le_bytes());
        payload[24..32].copy_from_slice(&(len as u64).to_le_bytes());
        payload[32..36].copy_from_slice(&(len as u32).to_le_bytes());
        payload[36..40].copy_from_slice(&(len as u32).to_le_bytes());
        aio_send(&mut self.conn, A_IO, &payload, op)?;

        let mut out = vec![0u8; len];
        let mut filled = 0usize;
        while filled < len {
            let (ty, size) = aio_recv_header(&mut self.conn, op)?;
            if ty == A_ERROR {
                let mut p = vec![0u8; size];
                self.conn.read_exact(&mut p)?;
                bail!("NFC read error, code {}", le32(&p, 0).unwrap_or(0));
            }
            if ty != A_IO || size != 44 {
                bail!("unexpected NFC reply type {ty} size {size} during a read");
            }
            let mut p = [0u8; 44];
            self.conn.read_exact(&mut p)?;
            let comp = (u64::from_le_bytes(p[8..16].try_into().unwrap()) >> 32) as u32;
            let dest = le32(&p, 28).unwrap() as usize;
            let chunk = le32(&p, 32).unwrap() as usize;
            let extra = le32(&p, 36).unwrap() as usize;
            let mut data = vec![0u8; extra];
            self.conn.read_exact(&mut data)?;
            if comp != 0 {
                bail!("NFC server sent compressed data (type {comp}) though none was requested");
            }
            if extra != chunk || dest + chunk > len {
                bail!("NFC fragment out of range: dest {dest} chunk {chunk} extra {extra} of {len}");
            }
            out[dest..dest + chunk].copy_from_slice(&data);
            filled += chunk;
        }
        Ok(out)
    }

    fn next_op(&mut self) -> u32 {
        let op = self.op_id;
        self.op_id += 1;
        op
    }

    /// Closes the file and the session (best effort).
    pub fn close(mut self) {
        let op = self.next_op();
        let _ = aio_send(&mut self.conn, A_CLOSE_FILE, &self.handle.to_le_bytes(), op);
        let op = self.next_op();
        let _ = aio_send(&mut self.conn, A_CLOSE_SESSION, &0u32.to_le_bytes(), op);
        let _ = self.conn.write_all(&classic(C_SESSION_COMPLETE, &[]));
    }
}

// --- authd (TCP 902) ---------------------------------------------------------------------------------------

fn authd_commands(s: &mut impl ReadWrite, ticket: &NfcTicket) -> Result<()> {
    // SESSION has no reply; the server may send a second 220 after BANNER, which we skip
    write_line(s, &format!("SESSION {}", ticket.session_id))?;
    write_line(s, "BANNER ")?;
    write_line(s, "THUMBPRINT_SHA2 PlainText")?;
    let r = read_reply(s, "THUMBPRINT_SHA2")?; // the 200 thumbprint line (220 banners skipped)
    if !r.starts_with("200") {
        bail!("authd THUMBPRINT_SHA2 refused: {r:?}");
    }
    write_line(s, &format!("PROXY {}", ticket.service))?;
    let r = read_reply(s, "PROXY")?;
    if !r.starts_with("200") {
        bail!("authd PROXY {} refused: {r:?}", ticket.service);
    }
    Ok(())
}

/// Reads authd reply lines, skipping informational `220` banners, until a final (2xx/5xx) status.
fn read_reply(s: &mut impl Read, what: &str) -> Result<String> {
    for _ in 0..8 {
        let line = read_line(s)?;
        if !line.starts_with("220") {
            return Ok(line);
        }
    }
    bail!("authd {what}: only banners received")
}

// --- classic NFC (264-byte frames) -------------------------------------------------------------------------

fn classic(msg_type: u32, body: &[u8]) -> [u8; CLASSIC_LEN] {
    let mut m = [0u8; CLASSIC_LEN];
    m[0..4].copy_from_slice(&msg_type.to_le_bytes());
    m[4..4 + body.len()].copy_from_slice(body);
    m
}

fn classic_recv(s: &mut impl Read, want: u32) -> Result<[u8; CLASSIC_LEN]> {
    let mut m = [0u8; CLASSIC_LEN];
    s.read_exact(&mut m)?;
    let ty = u32::from_le_bytes(m[0..4].try_into().unwrap());
    if ty != want {
        bail!("classic NFC: expected type {want}, got {ty}");
    }
    Ok(m)
}

fn classic_handshake(s: &mut impl ReadWrite) -> Result<()> {
    s.write_all(&classic(C_HANDSHAKE, b"PlainText"))?;
    s.write_all(&classic(C_SESSION_PARAMS, &[]))?;
    classic_recv(s, C_SESSION_PARAMS_REPLY)?;

    s.write_all(&classic(C_VERSION, &PROTO_VERSION.to_le_bytes()))?;
    let v = classic_recv(s, C_VERSION)?;
    let server = u32::from_le_bytes(v[4..8].try_into().unwrap());
    if server < 3 {
        bail!("NFC server version {server} is below 3 (no connection info)");
    }
    // CONNECTION_DATA: name length then op-id length, followed by the two raw strings (not framed)
    let (name, mode) = (b"vddk".as_slice(), b"nbdmode".as_slice());
    let mut body = [0u8; 8];
    body[0..4].copy_from_slice(&(name.len() as u32).to_le_bytes());
    body[4..8].copy_from_slice(&(mode.len() as u32).to_le_bytes());
    s.write_all(&classic(C_CONNECTION_DATA, &body))?;
    s.write_all(name)?;
    s.write_all(mode)?;

    s.write_all(&classic(C_SESSION_FEATURES, &3u32.to_le_bytes()))?;
    s.write_all(&classic(C_AIO_SESSION_OPEN, &[]))?;
    classic_recv(s, C_AIO_SESSION_OPEN)?;
    Ok(())
}

// --- AIO ----------------------------------------------------------------------------------------------------

fn aio_send(s: &mut impl Write, msg_type: u32, payload: &[u8], op: u32) -> Result<()> {
    let mut hdr = [0u8; AIO_HDR];
    hdr[0..4].copy_from_slice(&AIO_MAGIC.to_le_bytes());
    hdr[4..8].copy_from_slice(&msg_type.to_le_bytes());
    hdr[8..12].copy_from_slice(&(payload.len() as u32).to_le_bytes());
    hdr[12..16].copy_from_slice(&op.to_le_bytes());
    s.write_all(&hdr)?;
    s.write_all(payload)?;
    Ok(())
}

/// Reads an AIO header, checks the magic and the echoed op id, returns `(type, payload size)`.
fn aio_recv_header(s: &mut impl Read, op: u32) -> Result<(u32, usize)> {
    let mut hdr = [0u8; AIO_HDR];
    s.read_exact(&mut hdr)?;
    let magic = u32::from_le_bytes(hdr[0..4].try_into().unwrap());
    if magic != AIO_MAGIC {
        bail!("bad AIO magic {magic:#x}");
    }
    let ty = u32::from_le_bytes(hdr[4..8].try_into().unwrap());
    let size = u32::from_le_bytes(hdr[8..12].try_into().unwrap()) as usize;
    let got = u32::from_le_bytes(hdr[12..16].try_into().unwrap());
    if got != op {
        bail!("AIO reply op id {got}, expected {op}");
    }
    Ok((ty, size))
}

/// Reads an AIO reply of `want` type and returns its payload.
fn aio_recv(s: &mut impl Read, want: u32, op: u32) -> Result<Vec<u8>> {
    let (ty, size) = aio_recv_header(s, op)?;
    let mut p = vec![0u8; size];
    s.read_exact(&mut p)?;
    if ty == A_ERROR {
        bail!("NFC error, code {}", le32(&p, 0).unwrap_or(0));
    }
    if ty != want {
        bail!("AIO reply type {ty}, expected {want}");
    }
    Ok(p)
}

fn aio_setup(s: &mut impl ReadWrite, op_id: &mut u32) -> Result<()> {
    // OPEN_SESSION: buffer size and count
    let mut body = [0u8; 16];
    body[4..8].copy_from_slice(&AIO_BUF.to_le_bytes());
    body[8..12].copy_from_slice(&1u32.to_le_bytes());
    let op = take(op_id);
    aio_send(s, A_OPEN_SESSION, &body, op)?;
    aio_recv(s, A_OPEN_SESSION, op)?;

    let op = take(op_id);
    aio_send(s, A_SET_SOCK_OPTS, &[0u8; 12], op)?;
    aio_recv(s, A_SET_SOCK_OPTS, op)?;

    let op = take(op_id);
    aio_send(s, A_SET_RES_POOL, &1u32.to_le_bytes(), op)?;
    aio_recv(s, A_SET_RES_POOL, op)?;
    Ok(())
}

fn aio_open_file(s: &mut impl ReadWrite, op_id: &mut u32, ds_path: &str) -> Result<(u64, u32)> {
    let path = ds_path.as_bytes();
    let mut body = [0u8; 60];
    body[0..4].copy_from_slice(&(path.len() as u32).to_le_bytes());
    body[16..20].copy_from_slice(&NFC_DISK.to_le_bytes());
    body[20..24].copy_from_slice(&OPEN_READONLY.to_le_bytes());
    let op = take(op_id);
    aio_send(s, A_OPEN_FILE, &body, op)?;
    s.write_all(path)?;
    let p = aio_recv(s, A_OPEN_FILE, op)?;
    if p.len() < 40 {
        bail!("OPEN_FILE reply too short ({} bytes)", p.len());
    }
    let handle = u64::from_le_bytes(p[8..16].try_into().unwrap());
    let sector = le32(&p, 36).filter(|s| *s != 0).unwrap_or(DEFAULT_SECTOR);
    Ok((handle, sector))
}

// --- helpers ------------------------------------------------------------------------------------------------

trait ReadWrite: Read + Write {}
impl<T: Read + Write> ReadWrite for T {}

fn take(op: &mut u32) -> u32 {
    let v = *op;
    *op += 1;
    v
}

fn le32(b: &[u8], off: usize) -> Option<u32> {
    b.get(off..off + 4).map(|s| u32::from_le_bytes(s.try_into().unwrap()))
}

fn write_line(s: &mut impl Write, line: &str) -> Result<()> {
    s.write_all(line.as_bytes())?;
    s.write_all(b"\r\n")?;
    Ok(())
}

fn read_line(s: &mut impl Read) -> Result<String> {
    let mut out = Vec::new();
    let mut b = [0u8; 1];
    loop {
        s.read_exact(&mut b)?;
        match b[0] {
            b'\n' => break,
            b'\r' => {}
            c => out.push(c),
        }
        if out.len() > 4096 {
            bail!("authd line too long");
        }
    }
    Ok(String::from_utf8_lossy(&out).into_owned())
}

/// `AA:BB:...` (SHA-1, 20 bytes) to raw bytes.
fn parse_thumbprint(s: &str) -> Result<[u8; 20]> {
    let bytes: Vec<u8> = s
        .split(':')
        .map(|h| u8::from_str_radix(h.trim(), 16))
        .collect::<Result<_, _>>()
        .with_context(|| format!("not a hex thumbprint: {s:?}"))?;
    bytes
        .try_into()
        .map_err(|v: Vec<u8>| anyhow::anyhow!("thumbprint has {} bytes, not 20", v.len()))
}

/// TLS verifier that accepts exactly the certificate whose SHA-1 matches the NFC ticket's thumbprint.
#[derive(Debug)]
struct Pin {
    provider: Arc<CryptoProvider>,
    want: [u8; 20],
}

impl ServerCertVerifier for Pin {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        let got: [u8; 20] = Sha1::digest(end_entity.as_ref()).into();
        if got == self.want {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ))
        }
    }
    fn verify_tls12_signature(
        &self,
        msg: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls12_signature(msg, cert, dss, &self.provider.signature_verification_algorithms)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn thumbprint_parsing() {
        let t = "BE:22:58:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:76";
        assert_eq!(parse_thumbprint(t).unwrap()[0], 0xBE);
        assert_eq!(parse_thumbprint(t).unwrap()[19], 0x76);
        assert!(parse_thumbprint("BE:22").is_err());
        assert!(parse_thumbprint("zz:22:...").is_err());
    }

    #[test]
    fn classic_frame_layout() {
        let m = classic(C_VERSION, &PROTO_VERSION.to_le_bytes());
        assert_eq!(m.len(), 264);
        assert_eq!(le32(&m, 0), Some(C_VERSION));
        assert_eq!(le32(&m, 4), Some(11));
        assert_eq!(le32(&m, 8), Some(0));
    }
}
