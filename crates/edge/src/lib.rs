//! `nexus-edge`: the edge proxy for roaming agents (docs/edge.md, protocol
//! `agent_proto::edge`). Both the appliance and the agents connect *out* to it:
//!
//! - **Public port** (agents, default 443): TLS 1.3 with a mandatory client
//!   certificate that chains to the appliance agent CA and is one of the pinned
//!   certificates the appliance pushed (`Configure`); everything else fails in the
//!   handshake. Rate limits per source IP (before TLS), per agent certificate and in
//!   total. An agent keeps a `Rendezvous` connection; `Stream { nonce }` connections
//!   answer `Connect` requests; `Wake` passes a "back up now" request on.
//! - **Control port** (appliance, default 7445): before enrollment any client
//!   certificate plus the one-time token proofs (bound to the TLS exporter); after
//!   it only the pinned appliance client certificate. `Configure`, `Wait` (long
//!   poll for health, wakes and log lines), `Update` (signed binary) and `Open`
//!   (a stream to an agent).
//!
//! A stream pairs an appliance `Open` connection with a fresh agent `Stream`
//! connection and copies bytes both ways. Inside, the appliance and the agent run
//! the normal agent protocol over their own TLS session: the edge holds no key that
//! could read it, logs only connection metadata and never payload.

#![warn(missing_docs)]

use agent_core::config::{ensure_dir, write_atomic};
use agent_core::tls::{certs_from_pem, common_name, fingerprint};
use agent_proto::edge::{self as proto, EdgeHealth, EdgeLimits, EdgeMsg, MAX_CONTROL_FRAME, MAX_PUBLIC_FRAME};
use agent_proto::{enroll_proof, proof_eq, token_digest};
use rustls::client::danger::HandshakeSignatureValid;
use rustls::crypto::{verify_tls13_signature, CryptoProvider};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::server::ParsedCertificate;
use rustls::{
    CertificateError, DigitallySignedStruct, DistinguishedName, Error, RootCertStore, ServerConfig, SignatureScheme,
};
use std::collections::{HashMap, VecDeque};
use std::fs;
use std::io;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot, Notify};
use tokio::time::timeout;
use tokio_rustls::server::TlsStream;
use tokio_rustls::TlsAcceptor;

/// Version of this build (Cargo package version), reported in [`EdgeHealth`].
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
/// Embedded in every build: the signed update's real version (same marker format as
/// the agents, `agent_core::update::embedded_version`).
#[used]
pub static VERSION_MARKER: &[u8] = concat!("\0NEXUS-AGENT-VERSION=", env!("CARGO_PKG_VERSION"), "\0").as_bytes();
/// Marks an edge binary: a signed *agent* binary is refused as an edge update.
#[used]
pub static EDGE_MARKER: &[u8] = b"\0NEXUS-EDGE-BINARY\0";

/// default state directory (`--state`), see [`Files`]
pub const DEFAULT_STATE: &str = "/var/lib/nexus-edge";
/// default directory of the release public keys that verify pushed updates (`--release-keys`)
pub const DEFAULT_RELEASE_KEYS: &str = "/usr/share/nexus-edge/release-keys";
/// default limit of new public-port connections per source IP and minute (checked before TLS)
pub const PER_IP_PER_MIN: u32 = 60;
/// default limit of new public-port connections per agent certificate and minute
pub const PER_AGENT_PER_MIN: u32 = 120;
/// default limit of concurrent public-port connections in total
pub const MAX_CONNECTIONS: u32 = 1024;
/// new control-port connections per source IP and minute (not configurable)
pub const CONTROL_PER_IP_PER_MIN: u32 = 30;
/// rejected enrollment proofs before enrollment locks until the next `nexus-edge init`
pub const MAX_FAILED_PROOFS: u32 = 5;
const HANDSHAKE: Duration = Duration::from_secs(10);
const PING: Duration = Duration::from_secs(30);
const OPEN_TIMEOUT: Duration = Duration::from_secs(15);
/// a relayed stream without traffic in either direction for this long is closed
const IDLE: Duration = Duration::from_secs(3600);
const LOG_KEEP: usize = 1000;
const TAP_MAX: usize = 1 << 20;

/// Files below the state directory (0700, owned by the service user).
#[derive(Clone, Debug)]
pub struct Files {
    /// the state directory ([`DEFAULT_STATE`] unless `--state`)
    pub dir: PathBuf,
}

impl Files {
    /// edge private key (PEM, 0600), created by [`identity`]
    pub fn key(&self) -> PathBuf {
        self.dir.join("edge.key")
    }
    /// self-signed edge certificate (PEM); agents and the appliance pin its SHA-256
    pub fn cert(&self) -> PathBuf {
        self.dir.join("edge.crt")
    }
    /// digest of the one-time enrollment token (until enrolled)
    pub fn token(&self) -> PathBuf {
        self.dir.join("token")
    }
    /// SHA-256 of the appliance client certificate (after enrollment)
    pub fn pin(&self) -> PathBuf {
        self.dir.join("appliance.pin")
    }
    /// the last `Configure` (CA certificate + agent pins; nothing secret)
    pub fn config(&self) -> PathBuf {
        self.dir.join("config.bin")
    }
    /// count of rejected enrollment proofs (see [`MAX_FAILED_PROOFS`]), removed by `init` and on enrollment
    pub fn failures(&self) -> PathBuf {
        self.dir.join("enroll.failures")
    }
    /// signed updates pushed by the appliance (`nexus-edge`, `.sig`, `.version`)
    pub fn update_dir(&self) -> PathBuf {
        self.dir.join("update")
    }
}

/// The rustls crypto provider (ring) used for both listeners.
pub fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

fn key_from_pem(pem: &str) -> Result<PrivateKeyDer<'static>, String> {
    let kp = rcgen::KeyPair::from_pem(pem).map_err(|e| format!("private key: {e}"))?;
    Ok(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(kp.serialize_der())))
}

/// The edge key and self-signed certificate (created on first use). Returns the
/// PEMs; peers pin the certificate's SHA-256.
pub fn identity(files: &Files) -> Result<(String, String), String> {
    let io = |p: &Path, e: io::Error| format!("{}: {e}", p.display());
    ensure_dir(&files.dir, 0o700).map_err(|e| io(&files.dir, e))?;
    if let (Ok(k), Ok(c)) = (fs::read_to_string(files.key()), fs::read_to_string(files.cert())) {
        return Ok((k, c));
    }
    let kp = rcgen::KeyPair::generate().map_err(|e| e.to_string())?;
    let mut p = rcgen::CertificateParams::new(vec!["nexus-edge".to_string()]).map_err(|e| e.to_string())?;
    p.distinguished_name.push(rcgen::DnType::CommonName, "nexus-edge");
    p.not_after = rcgen::date_time_ymd(2099, 12, 31);
    let cert = p.self_signed(&kp).map_err(|e| e.to_string())?;
    write_atomic(&files.key(), kp.serialize_pem().as_bytes(), 0o600).map_err(|e| io(&files.key(), e))?;
    write_atomic(&files.cert(), cert.pem().as_bytes(), 0o644).map_err(|e| io(&files.cert(), e))?;
    Ok((kp.serialize_pem(), cert.pem()))
}

/// `nexus-edge init --token <T>`: (re-)enrollment. Keeps the edge identity (agents
/// pin it), drops the appliance pin and the pushed configuration. Returns the edge
/// certificate fingerprint to compare with the appliance UI.
pub fn init(files: &Files, token: &str) -> Result<String, String> {
    let token = token.trim();
    if token.len() < 16 || !token.bytes().all(|b| b.is_ascii_graphic()) {
        return Err("token looks invalid (expected the value shown in the appliance UI)".into());
    }
    let (_, cert) = identity(files)?;
    for p in [files.pin(), files.config(), files.failures()] {
        match fs::remove_file(&p) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(format!("{}: {e}", p.display())),
            _ => {}
        }
    }
    write_atomic(&files.token(), token_digest(token).as_bytes(), 0o600)
        .map_err(|e| format!("{}: {e}", files.token().display()))?;
    Ok(fingerprint(&certs_from_pem(&cert)?.remove(0)))
}

fn read_trim(p: &Path) -> Option<String> {
    fs::read_to_string(p)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// `nexus-edge status`.
pub fn status(files: &Files) -> String {
    let mut out = format!("nexus-edge {VERSION}\n");
    if let Some(c) = fs::read_to_string(files.cert())
        .ok()
        .and_then(|c| certs_from_pem(&c).ok())
    {
        out.push_str(&format!("edge certificate sha256: {}\n", fingerprint(&c[0])));
    }
    match (read_trim(&files.pin()), files.token().exists()) {
        (Some(p), _) => out.push_str(&format!("enrolled; appliance certificate sha256: {p}\n")),
        (None, true) => out.push_str(&format!("awaiting enrollment ({} failed proofs)\n", failures(files))),
        (None, false) => out.push_str("not initialised (run nexus-edge init --token <T>)\n"),
    }
    match fs::read(files.config()).ok().and_then(|b| proto::decode(&b).ok()) {
        Some(EdgeMsg::Configure { agents, .. }) => out.push_str(&format!("configured: {} agents\n", agents.len())),
        _ => out.push_str("configured: no (the appliance has not connected yet)\n"),
    }
    out
}

fn failures(files: &Files) -> u32 {
    read_trim(&files.failures()).and_then(|s| s.parse().ok()).unwrap_or(0)
}

fn is_native_elf(b: &[u8]) -> bool {
    #[cfg(target_arch = "x86_64")]
    const MACHINE: u16 = 62;
    #[cfg(target_arch = "aarch64")]
    const MACHINE: u16 = 183;
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    const MACHINE: u16 = 0;
    b.len() > 64 && b[..4] == *b"\x7fELF" && b[4] == 2 && u16::from_le_bytes([b[18], b[19]]) == MACHINE
}

/// All update checks: release-key signature, embedded version = claimed, newer
/// than `current`, native ELF, and an edge binary. Returns the version.
pub fn check_update(
    claimed: &str,
    binary: &[u8],
    signature: &[u8],
    keys: &[(String, Vec<u8>)],
    current: &str,
) -> Result<String, String> {
    let (_, v) = agent_core::update::check_candidate(claimed, binary, signature, keys, current, is_native_elf)?;
    if !binary.windows(EDGE_MARKER.len()).any(|w| w == EDGE_MARKER) {
        return Err("not a nexus-edge binary".into());
    }
    Ok(v)
}

/// At start: a verified newer binary in the update directory replaces this process
/// (the image's `/usr/bin/nexus-edge` is read-only). Returns only if there is none.
pub fn exec_update(files: &Files, keys_dir: &Path) {
    let d = files.update_dir();
    let (Ok(bin), Ok(sig), Some(ver)) = (
        fs::read(d.join("nexus-edge")),
        fs::read(d.join("nexus-edge.sig")),
        read_trim(&d.join("nexus-edge.version")),
    ) else {
        return;
    };
    let keys = agent_core::update::load_keys(keys_dir);
    match check_update(&ver, &bin, &sig, &keys, VERSION) {
        Ok(_) => {
            use std::os::unix::process::CommandExt;
            eprintln!("nexus-edge: starting the updated binary {ver}");
            let e = std::process::Command::new(d.join("nexus-edge"))
                .args(std::env::args_os().skip(1))
                .exec();
            eprintln!("nexus-edge: exec of the updated binary failed: {e}");
        }
        Err(e) if e.contains("not newer") => {}
        Err(e) => eprintln!("nexus-edge: ignoring {}: {e}", d.display()),
    }
}

/// Token bucket per key: `per_min` per minute, a burst of a third of it (≥ 5).
#[derive(Default)]
struct Buckets(HashMap<String, (f64, Instant)>);

impl Buckets {
    fn allow(&mut self, key: &str, per_min: u32, now: Instant) -> bool {
        let rate = f64::from(per_min) / 60.0;
        let burst = (f64::from(per_min) / 3.0).max(5.0);
        if self.0.len() > 50_000 {
            // forget keys whose bucket is full again
            self.0
                .retain(|_, (t, at)| *t + now.duration_since(*at).as_secs_f64() * rate < burst);
        }
        let e = self.0.entry(key.to_string()).or_insert((burst, now));
        e.0 = (e.0 + now.duration_since(e.1).as_secs_f64() * rate).min(burst);
        e.1 = now;
        if e.0 >= 1.0 {
            e.0 -= 1.0;
            true
        } else {
            false
        }
    }
}

/// Public port: the client certificate must chain to the pushed CA (EKU serverAuth,
/// as issued to agents), carry `CN=nexus-agent:<id>` and be pinned for that id.
#[derive(Debug)]
struct AgentVerifier {
    provider: Arc<CryptoProvider>,
    roots: RootCertStore,
    /// pinned fingerprint → agent id
    by_fp: HashMap<String, String>,
}

impl AgentVerifier {
    fn agent(&self, end_entity: &CertificateDer<'_>) -> Option<&String> {
        self.by_fp.get(&fingerprint(end_entity))
    }
}

impl ClientCertVerifier for AgentVerifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }
    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, Error> {
        let cert = ParsedCertificate::try_from(end_entity)?;
        rustls::client::verify_server_cert_signed_by_trust_anchor(
            &cert,
            &self.roots,
            intermediates,
            now,
            self.provider.signature_verification_algorithms.all,
        )?;
        let id = self.agent(end_entity).ok_or(Error::InvalidCertificate(
            CertificateError::ApplicationVerificationFailure,
        ))?;
        if common_name(end_entity).ok() != Some(format!("{}{id}", agent_core::tls::AGENT_CN_PREFIX)) {
            return Err(Error::InvalidCertificate(CertificateError::NotValidForName));
        }
        Ok(ClientCertVerified::assertion())
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

/// Control port: the pinned appliance certificate (any certificate before
/// enrollment; the token proofs decide then).
#[derive(Debug)]
struct ApplianceVerifier {
    provider: Arc<CryptoProvider>,
    pin: Option<String>,
}

impl ClientCertVerifier for ApplianceVerifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }
    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: UnixTime,
    ) -> Result<ClientCertVerified, Error> {
        ParsedCertificate::try_from(end_entity)?;
        match &self.pin {
            Some(p) if !p.eq_ignore_ascii_case(&fingerprint(end_entity)) => Err(Error::InvalidCertificate(
                CertificateError::ApplicationVerificationFailure,
            )),
            _ => Ok(ClientCertVerified::assertion()),
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

fn server_config(verifier: Arc<dyn ClientCertVerifier>, key: &str, cert: &str) -> Result<Arc<ServerConfig>, String> {
    let mut c = ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| e.to_string())?
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs_from_pem(cert)?, key_from_pem(key)?)
        .map_err(|e| format!("edge certificate: {e}"))?;
    c.alpn_protocols = vec![proto::ALPN.to_vec()];
    c.max_early_data_size = 0;
    Ok(Arc::new(c))
}

/// What the appliance pushed last.
struct Pushed {
    tls: Arc<ServerConfig>,
    verifier: Arc<AgentVerifier>,
    limits: EdgeLimits,
}

type Pending = HashMap<[u8; 16], (String, oneshot::Sender<TlsStream<TcpStream>>)>;

/// The running edge: identity, enrollment state, the pushed configuration, connected agents and counters.
/// Created by [`Edge::open`], served by [`Edge::run`].
pub struct Edge {
    files: Files,
    release_keys: PathBuf,
    key_pem: String,
    cert_pem: String,
    /// SHA-256 of the edge certificate, as peers pin it
    pub cert_sha256: String,
    started: Instant,
    control_tls: RwLock<Arc<ServerConfig>>,
    enrolled: AtomicBool,
    pushed: RwLock<Option<Pushed>>,
    /// agent id → (connection number, sender to its rendezvous connection)
    agents: Mutex<HashMap<String, (u64, mpsc::Sender<EdgeMsg>)>>,
    next_conn: AtomicU64,
    pending: Mutex<Pending>,
    wakes: Mutex<Vec<String>>,
    wake: Notify,
    log: Mutex<VecDeque<String>>,
    ip_buckets: Mutex<Buckets>,
    agent_buckets: Mutex<Buckets>,
    connections: AtomicU32,
    relays: AtomicU32,
    refused: AtomicU64,
    rate_limited: AtomicU64,
    /// exit after a successful `Update` (systemd restarts into it; off in tests)
    pub exit_on_update: bool,
    /// test hook: the first bytes of every relayed direction (to show they are TLS records)
    pub tap: Option<Arc<Mutex<Vec<Vec<u8>>>>>,
}

/// Decrements a counter when dropped.
struct Count<'a>(&'a AtomicU32);
impl Drop for Count<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

async fn read_frame<R: AsyncRead + Unpin>(r: &mut R, max: usize) -> io::Result<EdgeMsg> {
    let mut len = [0u8; 4];
    r.read_exact(&mut len).await?;
    let len = u32::from_be_bytes(len) as usize;
    if len > max {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "frame too large"));
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body).await?;
    proto::decode(&body)
}

async fn write_frame<W: AsyncWrite + Unpin>(w: &mut W, m: &EdgeMsg, max: usize) -> io::Result<()> {
    w.write_all(&proto::encode(m, max)?).await?;
    w.flush().await
}

fn error(code: u32, message: impl Into<String>) -> EdgeMsg {
    EdgeMsg::Error {
        code,
        message: message.into(),
    }
}

fn nonce() -> [u8; 16] {
    let mut b = [0u8; 16];
    ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut b).expect("system random");
    b
}

impl Edge {
    /// Loads (or creates) the identity and the persisted state.
    pub fn open(files: Files, release_keys: PathBuf) -> Result<Edge, String> {
        let (key_pem, cert_pem) = identity(&files)?;
        let cert_sha256 = fingerprint(&certs_from_pem(&cert_pem)?[0]);
        let pin = read_trim(&files.pin());
        let control = server_config(
            Arc::new(ApplianceVerifier {
                provider: provider(),
                pin: pin.clone(),
            }),
            &key_pem,
            &cert_pem,
        )?;
        let e = Edge {
            release_keys,
            key_pem,
            cert_pem,
            cert_sha256,
            started: Instant::now(),
            control_tls: RwLock::new(control),
            enrolled: AtomicBool::new(pin.is_some()),
            pushed: RwLock::new(None),
            agents: Mutex::default(),
            next_conn: AtomicU64::new(1),
            pending: Mutex::default(),
            wakes: Mutex::default(),
            wake: Notify::new(),
            log: Mutex::default(),
            ip_buckets: Mutex::default(),
            agent_buckets: Mutex::default(),
            connections: AtomicU32::new(0),
            relays: AtomicU32::new(0),
            refused: AtomicU64::new(0),
            rate_limited: AtomicU64::new(0),
            exit_on_update: true,
            tap: None,
            files,
        };
        if let Some(m) = fs::read(e.files.config()).ok().and_then(|b| proto::decode(&b).ok()) {
            if let Err(err) = e.configure(&m, false) {
                e.note(format!("stored configuration ignored: {err}"));
            }
        }
        Ok(e)
    }

    /// A log line: journal and the appliance (connection metadata only, never payload).
    fn note(&self, msg: impl AsRef<str>) {
        eprintln!("nexus-edge: {}", msg.as_ref());
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let mut l = self.log.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if l.len() >= LOG_KEEP {
            l.pop_front();
        }
        l.push_back(format!("{} {}", agent_core::server::utc(now), msg.as_ref()));
    }

    /// Version, uptime, connected agents and counters, sent to the appliance in `Wait` answers.
    pub fn health(&self) -> EdgeHealth {
        let mut online: Vec<String> = self
            .agents
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .keys()
            .cloned()
            .collect();
        online.sort();
        EdgeHealth {
            version: VERSION.into(),
            uptime_secs: self.started.elapsed().as_secs(),
            cert_sha256: self.cert_sha256.clone(),
            agents_online: online,
            connections: self.connections.load(Ordering::SeqCst),
            relays: self.relays.load(Ordering::SeqCst),
            refused: self.refused.load(Ordering::SeqCst),
            rate_limited: self.rate_limited.load(Ordering::SeqCst),
            configured: self
                .pushed
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .is_some(),
        }
    }

    fn limits(&self) -> EdgeLimits {
        let l = self
            .pushed
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .map(|p| p.limits)
            .unwrap_or_default();
        let or = |v: u32, d: u32| if v == 0 { d } else { v };
        EdgeLimits {
            per_ip_per_min: or(l.per_ip_per_min, PER_IP_PER_MIN),
            per_agent_per_min: or(l.per_agent_per_min, PER_AGENT_PER_MIN),
            max_connections: or(l.max_connections, MAX_CONNECTIONS),
        }
    }

    /// Applies (and with `persist` stores) a `Configure`; drops rendezvous
    /// connections of agents no longer listed.
    fn configure(&self, m: &EdgeMsg, persist: bool) -> Result<usize, String> {
        let EdgeMsg::Configure { ca_pem, agents, limits } = m else {
            return Err("not a configuration".into());
        };
        let mut roots = RootCertStore::empty();
        for c in certs_from_pem(ca_pem)? {
            roots.add(c).map_err(|e| format!("CA certificate: {e}"))?;
        }
        let mut by_fp = HashMap::new();
        for a in agents {
            if !agent_core::tls::valid_id(&a.id) {
                return Err(format!("invalid agent id {:?}", a.id));
            }
            for p in &a.pins {
                by_fp.insert(p.to_ascii_lowercase(), a.id.clone());
            }
        }
        let verifier = Arc::new(AgentVerifier {
            provider: provider(),
            roots,
            by_fp,
        });
        let tls = server_config(verifier.clone(), &self.key_pem, &self.cert_pem)?;
        if persist {
            write_atomic(
                &self.files.config(),
                &proto::encode(m, MAX_CONTROL_FRAME).map_err(|e| e.to_string())?[4..],
                0o600,
            )
            .map_err(|e| format!("{}: {e}", self.files.config().display()))?;
        }
        *self.pushed.write().unwrap_or_else(std::sync::PoisonError::into_inner) = Some(Pushed {
            tls,
            verifier,
            limits: *limits,
        });
        let keep: std::collections::HashSet<&str> = agents.iter().map(|a| a.id.as_str()).collect();
        self.agents
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .retain(|id, _| keep.contains(id.as_str()));
        Ok(agents.len())
    }

    /// Accept loops of both ports (runs until the listeners fail).
    pub async fn run(self: Arc<Self>, public: TcpListener, control: TcpListener) {
        let me = self.clone();
        let p = tokio::spawn(async move {
            loop {
                match public.accept().await {
                    Ok((tcp, peer)) => {
                        let e = me.clone();
                        tokio::spawn(async move { e.public_conn(tcp, peer).await });
                    }
                    Err(_) => tokio::time::sleep(Duration::from_millis(100)).await,
                }
            }
        });
        let me = self.clone();
        let c = tokio::spawn(async move {
            loop {
                match control.accept().await {
                    Ok((tcp, peer)) => {
                        let e = me.clone();
                        tokio::spawn(async move { e.control_conn(tcp, peer).await });
                    }
                    Err(_) => tokio::time::sleep(Duration::from_millis(100)).await,
                }
            }
        });
        let _ = tokio::join!(p, c);
    }

    fn allow(&self, buckets: &Mutex<Buckets>, key: &str, per_min: u32) -> bool {
        let ok = buckets
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .allow(key, per_min, Instant::now());
        if !ok {
            self.rate_limited.fetch_add(1, Ordering::SeqCst);
        }
        ok
    }

    fn refuse(&self, msg: String) {
        self.refused.fetch_add(1, Ordering::SeqCst);
        self.note(msg);
    }

    // ------------------------------------------------------------ public port

    async fn public_conn(self: Arc<Self>, tcp: TcpStream, peer: SocketAddr) {
        let limits = self.limits();
        if !self.allow(&self.ip_buckets, &format!("pub:{}", peer.ip()), limits.per_ip_per_min) {
            return; // silently: no log flood from a scanner
        }
        if self.connections.fetch_add(1, Ordering::SeqCst) >= limits.max_connections {
            self.connections.fetch_sub(1, Ordering::SeqCst);
            self.rate_limited.fetch_add(1, Ordering::SeqCst);
            return;
        }
        let _c = Count(&self.connections);
        let Some(cfg) = self
            .pushed
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .map(|p| p.tls.clone())
        else {
            self.refused.fetch_add(1, Ordering::SeqCst);
            return; // not configured: nobody gets in
        };
        let _ = tcp.set_nodelay(true);
        let mut tls = match timeout(HANDSHAKE, TlsAcceptor::from(cfg).accept(tcp)).await {
            Ok(Ok(t)) => t,
            Ok(Err(e)) => return self.refuse(format!("refused {}: {e}", peer.ip())),
            Err(_) => return self.refuse(format!("refused {}: handshake timeout", peer.ip())),
        };
        let agent = {
            let der = tls.get_ref().1.peer_certificates().and_then(|c| c.first()).cloned();
            let p = self.pushed.read().unwrap_or_else(std::sync::PoisonError::into_inner);
            match (der, p.as_ref()) {
                (Some(d), Some(p)) => p.verifier.agent(&d).cloned(),
                _ => None,
            }
        };
        let Some(agent) = agent else {
            return self.refuse(format!("refused {}: agent no longer configured", peer.ip()));
        };
        if !self.allow(&self.agent_buckets, &agent, limits.per_agent_per_min) {
            return self.note(format!("agent {agent} from {}: rate limited", peer.ip()));
        }
        match timeout(HANDSHAKE, read_frame(&mut tls, MAX_PUBLIC_FRAME)).await {
            Ok(Ok(EdgeMsg::Rendezvous)) => self.rendezvous(agent, tls, peer).await,
            Ok(Ok(EdgeMsg::Stream { nonce })) => {
                let mut pending = self.pending.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                match pending.remove(&nonce) {
                    Some((id, tx)) if id == agent => {
                        let _ = tx.send(tls);
                    }
                    Some(entry) => {
                        pending.insert(nonce, entry);
                        drop(pending);
                        self.refuse(format!("agent {agent} from {}: stream of another agent", peer.ip()));
                    }
                    None => {
                        drop(pending);
                        self.refuse(format!("agent {agent} from {}: unknown stream", peer.ip()));
                    }
                }
            }
            Ok(Ok(EdgeMsg::Wake)) => {
                self.note(format!("agent {agent} from {}: backup requested", peer.ip()));
                self.wakes
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push(agent);
                self.wake.notify_one();
                let _ = write_frame(&mut tls, &EdgeMsg::Ok, MAX_PUBLIC_FRAME).await;
                let _ = tls.shutdown().await;
            }
            Ok(Ok(_)) => self.refuse(format!("agent {agent} from {}: unexpected message", peer.ip())),
            Ok(Err(e)) => self.refuse(format!("agent {agent} from {}: {e}", peer.ip())),
            Err(_) => self.refuse(format!("agent {agent} from {}: no request", peer.ip())),
        }
    }

    /// The long-lived connection of an agent: pings, and `Connect` for every stream
    /// the appliance opens. A newer rendezvous of the same agent replaces it.
    async fn rendezvous(&self, agent: String, tls: TlsStream<TcpStream>, peer: SocketAddr) {
        let (tx, mut rx) = mpsc::channel(16);
        let conn = self.next_conn.fetch_add(1, Ordering::SeqCst);
        self.agents
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(agent.clone(), (conn, tx));
        self.note(format!("agent {agent} online from {peer}"));
        let (mut rd, mut wr) = tokio::io::split(tls);
        let mut ping = tokio::time::interval(PING);
        let mut b = [0u8; 1];
        loop {
            let m = tokio::select! {
                m = rx.recv() => match m { Some(m) => m, None => break },
                _ = ping.tick() => EdgeMsg::Ping,
                _ = rd.read(&mut b) => break, // agents send nothing here: EOF or a protocol error
            };
            if write_frame(&mut wr, &m, MAX_PUBLIC_FRAME).await.is_err() {
                break;
            }
        }
        let mut a = self.agents.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if a.get(&agent).is_some_and(|(c, _)| *c == conn) {
            a.remove(&agent);
        }
        drop(a);
        self.note(format!("agent {agent} offline ({peer})"));
    }

    // ----------------------------------------------------------- control port

    async fn control_conn(self: Arc<Self>, tcp: TcpStream, peer: SocketAddr) {
        if !self.allow(&self.ip_buckets, &format!("ctl:{}", peer.ip()), CONTROL_PER_IP_PER_MIN) {
            return;
        }
        if self.enrolled.load(Ordering::SeqCst) && !self.files.pin().exists() {
            // `nexus-edge init` ran on the console: back to enrollment mode
            match server_config(
                Arc::new(ApplianceVerifier {
                    provider: provider(),
                    pin: None,
                }),
                &self.key_pem,
                &self.cert_pem,
            ) {
                Ok(c) => {
                    *self
                        .control_tls
                        .write()
                        .unwrap_or_else(std::sync::PoisonError::into_inner) = c;
                    *self.pushed.write().unwrap_or_else(std::sync::PoisonError::into_inner) = None;
                    self.agents
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .clear();
                    self.enrolled.store(false, Ordering::SeqCst);
                    self.note("re-initialised on the console: awaiting enrollment");
                }
                Err(e) => return self.note(format!("control: {e}")),
            }
        }
        let cfg = self
            .control_tls
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let _ = tcp.set_nodelay(true);
        let mut tls = match timeout(HANDSHAKE, TlsAcceptor::from(cfg).accept(tcp)).await {
            Ok(Ok(t)) => t,
            Ok(Err(e)) => return self.refuse(format!("control: refused {}: {e}", peer.ip())),
            Err(_) => return self.refuse(format!("control: refused {}: handshake timeout", peer.ip())),
        };
        if !self.enrolled.load(Ordering::SeqCst) {
            return self.enroll(tls, peer).await;
        }
        loop {
            let m = match read_frame(&mut tls, MAX_CONTROL_FRAME).await {
                Ok(m) => m,
                Err(_) => return,
            };
            let reply = match m {
                EdgeMsg::Configure { .. } => match self.configure(&m, true) {
                    Ok(n) => {
                        self.note(format!("configuration from the appliance: {n} agents"));
                        EdgeMsg::Ok
                    }
                    Err(e) => error(400, e),
                },
                EdgeMsg::Wait { secs } => {
                    let empty = self
                        .wakes
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .is_empty();
                    if empty {
                        let secs = secs.min(proto::MAX_WAIT_SECS);
                        let _ = timeout(Duration::from_secs(secs.into()), self.wake.notified()).await;
                    }
                    let mut wakes =
                        std::mem::take(&mut *self.wakes.lock().unwrap_or_else(std::sync::PoisonError::into_inner));
                    wakes.sort();
                    wakes.dedup();
                    let log = self
                        .log
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .drain(..)
                        .collect();
                    EdgeMsg::Events {
                        health: self.health(),
                        wakes,
                        log,
                    }
                }
                EdgeMsg::Update {
                    version,
                    binary,
                    signature,
                } => match self.install_update(&version, &binary, &signature) {
                    Ok(v) => {
                        self.note(format!("update {v} installed; restarting"));
                        let _ = write_frame(&mut tls, &EdgeMsg::Ok, MAX_CONTROL_FRAME).await;
                        let _ = tls.shutdown().await;
                        if self.exit_on_update {
                            std::process::exit(0); // systemd restarts into the update (exec_update)
                        }
                        return;
                    }
                    Err(e) => {
                        self.note(format!("update refused: {e}"));
                        error(400, e)
                    }
                },
                EdgeMsg::Open { agent_id } => return self.open_stream(tls, agent_id).await,
                _ => error(400, "unexpected message"),
            };
            if write_frame(&mut tls, &reply, MAX_CONTROL_FRAME).await.is_err() {
                return;
            }
        }
    }

    async fn enroll(&self, mut tls: TlsStream<TcpStream>, peer: SocketAddr) {
        let Some(digest) = read_trim(&self.files.token()) else {
            let _ = write_frame(&mut tls, &error(423, "not initialised: run nexus-edge init"), 4096).await;
            return;
        };
        if failures(&self.files) >= MAX_FAILED_PROOFS {
            let _ = write_frame(
                &mut tls,
                &error(423, "enrollment locked; run nexus-edge init again"),
                4096,
            )
            .await;
            return;
        }
        let mut ex = [0u8; 32];
        let (cert, exported) = {
            let c = tls.get_ref().1;
            (
                c.peer_certificates().and_then(|c| c.first()).cloned(),
                c.export_keying_material(&mut ex, proto::EXPORTER_LABEL, None).is_ok(),
            )
        };
        let proof = match timeout(HANDSHAKE, read_frame(&mut tls, 4096)).await {
            Ok(Ok(EdgeMsg::Enroll { proof })) => proof,
            _ => return,
        };
        let (Some(cert), true) = (cert, exported) else { return };
        if !proof_eq(&proof, &enroll_proof(&digest, "edge-appliance", &ex)) {
            let n = failures(&self.files) + 1;
            let _ = write_atomic(&self.files.failures(), n.to_string().as_bytes(), 0o600);
            self.refuse(format!(
                "control: enrollment proof from {} rejected ({n}/{MAX_FAILED_PROOFS})",
                peer.ip()
            ));
            let _ = write_frame(&mut tls, &error(401, "enrollment proof rejected"), 4096).await;
            return;
        }
        let pin = fingerprint(&cert);
        let control = server_config(
            Arc::new(ApplianceVerifier {
                provider: provider(),
                pin: Some(pin.clone()),
            }),
            &self.key_pem,
            &self.cert_pem,
        );
        let stored = control.and_then(|c| {
            write_atomic(&self.files.pin(), pin.as_bytes(), 0o600).map_err(|e| e.to_string())?;
            let _ = fs::remove_file(self.files.token());
            let _ = fs::remove_file(self.files.failures());
            Ok(c)
        });
        match stored {
            Ok(c) => {
                *self
                    .control_tls
                    .write()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = c;
                self.enrolled.store(true, Ordering::SeqCst);
                self.note(format!(
                    "enrolled by the appliance at {} (certificate {pin})",
                    peer.ip()
                ));
                let m = EdgeMsg::Enrolled {
                    proof: enroll_proof(&digest, "edge", &ex),
                    version: VERSION.into(),
                };
                let _ = write_frame(&mut tls, &m, 4096).await;
                let _ = tls.shutdown().await;
            }
            Err(e) => {
                self.note(format!("enrollment failed: {e}"));
                let _ = write_frame(&mut tls, &error(500, e), 4096).await;
            }
        }
    }

    fn install_update(&self, version: &str, binary: &[u8], signature: &[u8]) -> Result<String, String> {
        let keys = agent_core::update::load_keys(&self.release_keys);
        let v = check_update(version, binary, signature, &keys, VERSION)?;
        let d = self.files.update_dir();
        let io = |e: io::Error| format!("{}: {e}", d.display());
        ensure_dir(&d, 0o700).map_err(io)?;
        // the version file last: it marks a complete set
        let _ = fs::remove_file(d.join("nexus-edge.version"));
        write_atomic(&d.join("nexus-edge"), binary, 0o755).map_err(io)?;
        write_atomic(&d.join("nexus-edge.sig"), signature, 0o600).map_err(io)?;
        write_atomic(&d.join("nexus-edge.version"), v.as_bytes(), 0o600).map_err(io)?;
        Ok(v)
    }

    /// `Open`: ask the agent for a stream, then relay until either side closes.
    async fn open_stream(&self, mut appliance: TlsStream<TcpStream>, agent: String) {
        let tx = self
            .agents
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&agent)
            .map(|(_, tx)| tx.clone());
        let Some(tx) = tx else {
            let _ = write_frame(&mut appliance, &error(404, "agent is not connected to this edge"), 4096).await;
            return;
        };
        let n = nonce();
        let (stx, srx) = oneshot::channel();
        self.pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(n, (agent.clone(), stx));
        let got = if tx.send(EdgeMsg::Connect { nonce: n }).await.is_ok() {
            timeout(OPEN_TIMEOUT, srx).await.ok().and_then(Result::ok)
        } else {
            None
        };
        self.pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&n);
        let Some(agent_tls) = got else {
            let _ = write_frame(&mut appliance, &error(504, "agent did not open the stream"), 4096).await;
            return;
        };
        if write_frame(&mut appliance, &EdgeMsg::Opened, 4096).await.is_err() {
            return;
        }
        self.relays.fetch_add(1, Ordering::SeqCst);
        let _r = Count(&self.relays);
        let t0 = Instant::now();
        let (a_r, a_w) = tokio::io::split(appliance);
        let (g_r, g_w) = tokio::io::split(agent_tls);
        let (up, down) = tokio::join!(self.pump(a_r, g_w), self.pump(g_r, a_w));
        self.note(format!(
            "stream to agent {agent} closed after {} s: {up} bytes to the agent, {down} bytes from it",
            t0.elapsed().as_secs()
        ));
    }

    /// Copies one direction; the bytes are inner TLS records, never inspected.
    async fn pump<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(&self, mut r: R, mut w: W) -> u64 {
        let mut buf = vec![0u8; 64 << 10];
        let mut total = 0u64;
        let slot = self.tap.as_ref().map(|t| {
            let mut t = t.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            t.push(Vec::new());
            t.len() - 1
        });
        loop {
            let n = match timeout(IDLE, r.read(&mut buf)).await {
                Ok(Ok(n)) if n > 0 => n,
                _ => break,
            };
            if let (Some(t), Some(i)) = (&self.tap, slot) {
                let t = &mut t.lock().unwrap_or_else(std::sync::PoisonError::into_inner)[i];
                let room = TAP_MAX.saturating_sub(t.len()).min(n);
                t.extend_from_slice(&buf[..room]);
            }
            if w.write_all(&buf[..n]).await.is_err() {
                break;
            }
            total += n as u64;
        }
        let _ = w.shutdown().await;
        total
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_buckets() {
        let mut b = Buckets::default();
        let t = Instant::now();
        // 60/min: a burst of 20, then one per second
        assert_eq!((0..30).filter(|_| b.allow("ip:a", 60, t)).count(), 20);
        assert!(b.allow("ip:b", 60, t), "keys are independent");
        assert!(!b.allow("ip:a", 60, t + Duration::from_millis(500)));
        assert!(b.allow("ip:a", 60, t + Duration::from_millis(1600)));
        // small limits keep a burst of 5
        assert_eq!((0..10).filter(|_| b.allow("agent:x", 6, t)).count(), 5);
    }

    #[test]
    fn init_keeps_identity_and_drops_enrollment() {
        let d = tempfile::tempdir().unwrap();
        let f = Files {
            dir: d.path().join("s"),
        };
        assert!(init(&f, "short").is_err());
        let fp = init(&f, "ABCDEFGHIJKLMNOPQRSTUVWX").unwrap();
        fs::write(f.pin(), "ab").unwrap();
        assert!(status(&f).contains("enrolled"));
        assert_eq!(
            init(&f, "ABCDEFGHIJKLMNOPQRSTUVWX").unwrap(),
            fp,
            "agents pin the edge certificate"
        );
        assert!(!f.pin().exists());
        assert!(status(&f).contains("awaiting enrollment"));
        assert_eq!(read_trim(&f.token()).unwrap(), token_digest("ABCDEFGHIJKLMNOPQRSTUVWX"));
    }

    /// The release-key check of the agents, plus: only edge binaries.
    #[test]
    fn updates_must_be_signed_edge_binaries() {
        use ring::signature::{EcdsaKeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};
        let kp = rcgen::KeyPair::generate().unwrap();
        let rng = ring::rand::SystemRandom::new();
        let signer = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &kp.serialize_der(), &rng).unwrap();
        let keys = vec![(
            "test".to_string(),
            agent_core::update::parse_public_key(&kp.public_key_pem()).unwrap(),
        )];
        let elf = |edge: bool| {
            let mut b = b"\x7fELF\x02".to_vec();
            b.resize(64, 0);
            b[18..20].copy_from_slice(&62u16.to_le_bytes());
            b.extend_from_slice(b"\0NEXUS-AGENT-VERSION=9.0.0\0");
            if edge {
                b.extend_from_slice(EDGE_MARKER);
            }
            b
        };
        let sign = |b: &[u8]| signer.sign(&rng, b).unwrap().as_ref().to_vec();
        let (edge, agent) = (elf(true), elf(false));
        if cfg!(target_arch = "x86_64") {
            assert_eq!(
                check_update("9.0.0", &edge, &sign(&edge), &keys, VERSION).unwrap(),
                "9.0.0"
            );
        }
        let e = check_update("9.0.0", &agent, &sign(&agent), &keys, VERSION).unwrap_err();
        assert!(
            e.contains("not a nexus-edge binary") || !cfg!(target_arch = "x86_64"),
            "{e}"
        );
        assert!(
            check_update("9.0.0", &edge, &sign(&agent), &keys, VERSION).is_err(),
            "signature"
        );
        assert!(
            check_update("9.0.0", &edge, &sign(&edge), &keys, "9.0.0").is_err(),
            "not newer"
        );
        assert!(
            check_update("9.0.0", &edge, &sign(&edge), &[], VERSION).is_err(),
            "no keys"
        );
    }
}
