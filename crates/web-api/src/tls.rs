//! HTTPS on 8443 (docs/replication.md §3). The ClientHello is read first and
//! the server configuration chosen by ALPN:
//! - `nexus-replication/1`: TLS 1.3, client certificate **required** (chain to
//!   the replication CA, EKU clientAuth); requests carry [`ReplConn::Peer`].
//! - `nexus-replication-enroll/1`: TLS 1.3, no client certificate; requests
//!   carry [`ReplConn::Enroll`] with this session's TLS exporter.
//! - anything else: the normal UI/API configuration (no CertificateRequest).
//!
//! Replication connections always get the self-signed identity certificate
//! (`cert.pem`, pinned by secondaries); UI/API connections get the imported
//! `web.pem` when there is one ([`WebCert`], reloaded when the file changes),
//! so importing a CA-signed certificate breaks no pin.

use anyhow::{Context, Result};
use axum::extract::ConnectInfo;
use axum::Router;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto;
use hyper_util::service::TowerToHyperService;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert, WebPkiClientVerifier};
use rustls::sign::CertifiedKey;
use rustls::{RootCertStore, ServerConfig};
use std::future::Future;
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};
use tower::ServiceExt;

/// What kind of TLS connection a request arrived on (request extension).
#[derive(Clone, Debug)]
pub enum ReplConn {
    /// enrollment connection: TLS exporter (`repl_proto::EXPORTER_LABEL`)
    Enroll { exporter: [u8; 32] },
    /// peer connection: SHA-256 (hex) of the verified client certificate
    Peer { fp: String },
}

/// Certificate for UI/API connections: the imported chain + key file (`web.pem`,
/// written by nexus-tls) or, without one, the identity certificate. One `stat`
/// per handshake notices a replaced file (mtime, size, inode); a file that does
/// not load keeps the previous certificate in use.
#[derive(Debug)]
pub struct WebCert {
    identity: Arc<CertifiedKey>,
    path: Option<PathBuf>,
    cur: Mutex<(Option<FileId>, Arc<CertifiedKey>)>,
}

type FileId = (SystemTime, u64, u64);

impl WebCert {
    pub fn new(identity: Arc<CertifiedKey>, path: Option<PathBuf>) -> WebCert {
        let w = WebCert {
            cur: Mutex::new((None, identity.clone())),
            identity,
            path,
        };
        w.current();
        w
    }

    /// The certificate served now (reloaded if the file changed).
    pub fn current(&self) -> Arc<CertifiedKey> {
        let Some(path) = &self.path else {
            return self.identity.clone();
        };
        let id = std::fs::metadata(path)
            .ok()
            .map(|m| (m.modified().unwrap_or(SystemTime::UNIX_EPOCH), m.len(), m.ino()));
        let mut cur = self.cur.lock().unwrap();
        if cur.0 == id {
            return cur.1.clone();
        }
        let next = match id {
            None => Ok(self.identity.clone()),
            Some(_) => load_web(path).map(Arc::new),
        };
        match next {
            Ok(k) => {
                match id {
                    Some(_) => eprintln!("<5>web-api: serving the imported certificate {}", path.display()),
                    None => eprintln!("<5>web-api: serving the self-signed certificate"),
                }
                *cur = (id, k);
            }
            Err(e) => {
                eprintln!("<4>web-api: {}: {e:#}; keeping the current certificate", path.display());
                cur.0 = id;
            }
        }
        cur.1.clone()
    }
}

impl ResolvesServerCert for WebCert {
    fn resolve(&self, _: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.current())
    }
}

/// Chain + private key from one PEM file.
fn load_web(path: &std::path::Path) -> Result<CertifiedKey> {
    let pem = std::fs::read(path)?;
    let certs = CertificateDer::pem_slice_iter(&pem).collect::<Result<Vec<_>, _>>()?;
    if certs.is_empty() {
        anyhow::bail!("no certificate");
    }
    let key = PrivateKeyDer::from_pem_slice(&pem)?;
    Ok(CertifiedKey::from_der(certs, key, &provider())?)
}

pub struct Tls {
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    normal: Arc<ServerConfig>,
    pub web: Arc<WebCert>,
    enroll: Arc<ServerConfig>,
    /// replication CA certificate (published by nexus-replicad)
    repl_ca: Option<PathBuf>,
    peer: Mutex<Option<(SystemTime, Arc<ServerConfig>)>>,
}

/// ring with the post-quantum hybrid X25519MLKEM768 preferred (Phase 39 S5, crate tls-pq): browsers
/// and nexus clients that offer it get it, everyone else X25519 as before.
fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    tls_pq::provider_arc()
}

impl Tls {
    /// `web`: the imported certificate file (`web.pem`), served to UI/API clients when present.
    pub fn load(
        cert: &std::path::Path,
        key: &std::path::Path,
        web: Option<PathBuf>,
        repl_ca: Option<PathBuf>,
    ) -> Result<Arc<Tls>> {
        let certs = CertificateDer::pem_file_iter(cert)
            .with_context(|| format!("{}", cert.display()))?
            .collect::<Result<Vec<_>, _>>()
            .with_context(|| format!("{}", cert.display()))?;
        let key = PrivateKeyDer::from_pem_file(key).with_context(|| format!("{}", key.display()))?;
        Self::with_web(certs, key, web, repl_ca)
    }

    pub fn new(
        certs: Vec<CertificateDer<'static>>,
        key: PrivateKeyDer<'static>,
        repl_ca: Option<PathBuf>,
    ) -> Result<Arc<Tls>> {
        Self::with_web(certs, key, None, repl_ca)
    }

    pub fn with_web(
        certs: Vec<CertificateDer<'static>>,
        key: PrivateKeyDer<'static>,
        web: Option<PathBuf>,
        repl_ca: Option<PathBuf>,
    ) -> Result<Arc<Tls>> {
        let identity = Arc::new(CertifiedKey::from_der(certs.clone(), key.clone_key(), &provider())?);
        let web = Arc::new(WebCert::new(identity, web));
        let mut normal = ServerConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()?
            .with_no_client_auth()
            .with_cert_resolver(web.clone());
        normal.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        let mut enroll = ServerConfig::builder_with_provider(provider())
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_no_client_auth()
            .with_single_cert(certs.clone(), key.clone_key())?;
        enroll.alpn_protocols = vec![repl_proto::ALPN_ENROLL.to_vec()];
        Ok(Arc::new(Tls {
            certs,
            key,
            normal: Arc::new(normal),
            web,
            enroll: Arc::new(enroll),
            repl_ca,
            peer: Mutex::new(None),
        }))
    }

    /// Peer configuration, rebuilt when the CA file changes; None without CA.
    fn peer_config(&self) -> Option<Arc<ServerConfig>> {
        let path = self.repl_ca.as_ref()?;
        let mtime = std::fs::metadata(path).and_then(|m| m.modified()).ok()?;
        let mut cur = self.peer.lock().unwrap();
        if let Some((t, c)) = cur.as_ref() {
            if *t == mtime {
                return Some(c.clone());
            }
        }
        let build = || -> Result<ServerConfig> {
            let mut roots = RootCertStore::empty();
            for c in CertificateDer::pem_file_iter(path)? {
                roots.add(c?)?;
            }
            let verifier = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider()).build()?;
            let mut sc = ServerConfig::builder_with_provider(provider())
                .with_protocol_versions(&[&rustls::version::TLS13])?
                .with_client_cert_verifier(verifier)
                .with_single_cert(self.certs.clone(), self.key.clone_key())?;
            sc.alpn_protocols = vec![repl_proto::ALPN_PEER.to_vec()];
            Ok(sc)
        };
        match build() {
            Ok(sc) => {
                let sc = Arc::new(sc);
                *cur = Some((mtime, sc.clone()));
                Some(sc)
            }
            Err(e) => {
                eprintln!("<4>web-api: replication CA {}: {e:#}", path.display());
                None
            }
        }
    }
}

/// Accept loop until `shutdown` resolves.
pub async fn serve(listener: tokio::net::TcpListener, tls: Arc<Tls>, app: Router, shutdown: impl Future<Output = ()>) {
    tokio::pin!(shutdown);
    loop {
        let (tcp, peer) = tokio::select! {
            r = listener.accept() => match r {
                Ok(x) => x,
                Err(e) => {
                    eprintln!("<4>web-api: accept: {e}");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            },
            _ = &mut shutdown => return,
        };
        let (tls, app) = (tls.clone(), app.clone());
        tokio::spawn(async move {
            let acc = tokio_rustls::LazyConfigAcceptor::new(rustls::server::Acceptor::default(), tcp);
            let Ok(Ok(start)) = tokio::time::timeout(Duration::from_secs(10), acc).await else {
                return;
            };
            let offered = |p: &[u8]| start.client_hello().alpn().is_some_and(|mut a| a.any(|x| x == p));
            let (cfg, peer_conn) = if offered(repl_proto::ALPN_PEER) {
                match tls.peer_config() {
                    Some(c) => (c, Some(true)),
                    None => return, // no replication CA yet: refuse
                }
            } else if offered(repl_proto::ALPN_ENROLL) {
                (tls.enroll.clone(), Some(false))
            } else {
                (tls.normal.clone(), None)
            };
            let Ok(Ok(stream)) = tokio::time::timeout(Duration::from_secs(10), start.into_stream(cfg)).await else {
                return;
            };
            let repl = match peer_conn {
                Some(true) => {
                    let Some(fp) = stream
                        .get_ref()
                        .1
                        .peer_certificates()
                        .and_then(|c| c.first())
                        .map(|c| repl_proto::sha256_hex(c))
                    else {
                        return;
                    };
                    Some(ReplConn::Peer { fp })
                }
                Some(false) => {
                    let mut ex = [0u8; 32];
                    if stream
                        .get_ref()
                        .1
                        .export_keying_material(&mut ex, repl_proto::EXPORTER_LABEL, None)
                        .is_err()
                    {
                        return;
                    }
                    Some(ReplConn::Enroll { exporter: ex })
                }
                None => None,
            };
            let svc = app.map_request(move |mut req: axum::http::Request<hyper::body::Incoming>| {
                req.extensions_mut().insert(ConnectInfo(peer));
                if let Some(r) = &repl {
                    req.extensions_mut().insert(r.clone());
                }
                req
            });
            let mut b = auto::Builder::new(TokioExecutor::new());
            b.http1()
                .timer(TokioTimer::new())
                .header_read_timeout(Duration::from_secs(15));
            let _ = b
                .serve_connection(TokioIo::new(stream), TowerToHyperService::new(svc))
                .await;
        });
    }
}
