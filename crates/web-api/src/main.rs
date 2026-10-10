//! `nexus-web-api`: HTTPS (rustls) on 8443, REST API + embedded SPA, and the
//! replication peer endpoint (docs/replication.md: ALPN-selected mTLS).
//! Configuration via environment, see `web_api::Config::from_env`.

use anyhow::{bail, Context, Result};
use std::time::Duration;
use web_api::replication::ReplPaths;
use web_api::{AppState, Config};

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
    let st = AppState::with_replication(
        cat,
        token,
        cfg.downloads.clone(),
        totp,
        Some(cfg.secrets_pub.clone()),
        ReplPaths {
            socket: Some(cfg.replicad_socket.clone()),
            seal_pub: Some(cfg.replicad_pub.clone()),
            tls_cert: Some(cfg.tls_cert.clone()),
        },
    );
    let migrated = web_api::migrate_totp_seeds(&st)?;
    if migrated > 0 {
        eprintln!("<5>web-api: encrypted {migrated} legacy TOTP seed(s)");
    }
    let app = web_api::router(st.clone());
    let tls = web_api::tls::Tls::load(&cfg.tls_cert, &cfg.tls_key, Some(cfg.replication_ca.clone()))?;

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
    web_api::tls::serve(listener, tls, app, async move {
        term.recv().await;
    })
    .await;
    Ok(())
}
