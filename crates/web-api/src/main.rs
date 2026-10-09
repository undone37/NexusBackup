//! `nexus-web-api`: HTTPS (rustls) on 8443, REST API + embedded SPA.
//! Configuration via environment, see `web_api::Config::from_env`.

use anyhow::{bail, Context, Result};
use axum::extract::ConnectInfo;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto;
use hyper_util::service::TowerToHyperService;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::sync::Arc;
use std::time::Duration;
use tokio_rustls::TlsAcceptor;
use tower::ServiceExt;
use web_api::{AppState, Config};

fn tls(cfg: &Config) -> Result<TlsAcceptor> {
    let certs = CertificateDer::pem_file_iter(&cfg.tls_cert)
        .with_context(|| format!("{}", cfg.tls_cert.display()))?
        .collect::<Result<Vec<_>, _>>()
        .with_context(|| format!("{}", cfg.tls_cert.display()))?;
    let key = PrivateKeyDer::from_pem_file(&cfg.tls_key).with_context(|| format!("{}", cfg.tls_key.display()))?;
    let mut sc = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    sc.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(TlsAcceptor::from(Arc::new(sc)))
}

/// `sd_notify(READY=1)` for `Type=notify` without a libsystemd dependency.
fn notify_ready() {
    use std::os::linux::net::SocketAddrExt;
    use std::os::unix::net::{SocketAddr, UnixDatagram};
    let Some(path) = std::env::var_os("NOTIFY_SOCKET") else {
        return;
    };
    let path = path.to_string_lossy().into_owned();
    let addr = match path.strip_prefix('@') {
        Some(abs) => SocketAddr::from_abstract_name(abs.as_bytes()),
        None => SocketAddr::from_pathname(&path),
    };
    let sent = UnixDatagram::unbound().and_then(|s| s.send_to_addr(b"READY=1", &addr?));
    if let Err(e) = sent {
        eprintln!("<4>web-api: sd_notify: {e}");
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cfg = Config::from_env()?;
    if !cfg.setup_done.exists() {
        bail!("{} missing: run nexus-setup first", cfg.setup_done.display());
    }
    let cat = catalog::Catalog::open(&cfg.catalog).with_context(|| format!("{}", cfg.catalog.display()))?;
    let token = std::fs::read_to_string(&cfg.metrics_token)
        .ok()
        .map(|t| t.trim().to_owned())
        .filter(|t| !t.is_empty());
    if token.is_none() {
        eprintln!(
            "<4>web-api: no metrics token at {}, /metrics disabled",
            cfg.metrics_token.display()
        );
    }
    let (totp, created) = catalog::secret::TotpKey::open_or_create(&cfg.totp_key, &cat)
        .with_context(|| format!("{}", cfg.totp_key.display()))?;
    if created {
        cat.audit(
            "web-api",
            "secret.key_create",
            "webapi/totp.key",
            &serde_json::json!({}),
        )?;
    }
    let st = AppState::with_keys(cat, token, cfg.downloads.clone(), totp, Some(cfg.secrets_pub.clone()));
    let migrated = web_api::migrate_totp_seeds(&st)?;
    if migrated > 0 {
        eprintln!("<5>web-api: encrypted {migrated} legacy TOTP seed(s)");
    }
    let app = web_api::router(st.clone());
    let acceptor = tls(&cfg)?;

    // quorum expiry also runs inline on every quorum call; this keeps it
    // timely for metrics and the audit log
    tokio::spawn({
        let st = st.clone();
        async move {
            loop {
                tokio::time::sleep(Duration::from_secs(60)).await;
                let _ = web_api::quorum::expire(&st);
            }
        }
    });

    let listener = tokio::net::TcpListener::bind(cfg.listen).await?;
    eprintln!("<6>web-api: listening on https://{}", cfg.listen);
    notify_ready();
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
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
            _ = term.recv() => return Ok(()),
        };
        let (acceptor, app) = (acceptor.clone(), app.clone());
        tokio::spawn(async move {
            let Ok(Ok(tls)) = tokio::time::timeout(Duration::from_secs(10), acceptor.accept(tcp)).await else {
                return;
            };
            let svc = app.map_request(move |mut req: axum::http::Request<hyper::body::Incoming>| {
                req.extensions_mut().insert(ConnectInfo(peer));
                req
            });
            let mut b = auto::Builder::new(TokioExecutor::new());
            b.http1()
                .timer(TokioTimer::new())
                .header_read_timeout(Duration::from_secs(15));
            let _ = b
                .serve_connection(TokioIo::new(tls), TowerToHyperService::new(svc))
                .await;
        });
    }
}
