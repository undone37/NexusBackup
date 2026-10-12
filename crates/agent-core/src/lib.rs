//! Platform-independent core of the NexusBackup agents (`nexus-agent` on Linux,
//! `nexus-agent.exe` on Windows), see docs/agent-protocol.md:
//! TLS / enrollment / mTLS server, the protocol session state machine, FastCDC +
//! BLAKE3 chunking, the metadata cache, `Want` serving, restore stream handling and
//! update signature verification. The host-specific half implements
//! [`server::Platform`] and [`restore::RestoreFs`].

pub mod cache;
pub mod chunk;
pub mod config;
pub mod filter;
pub mod glob;
pub mod limit;
pub mod restore;
pub mod server;
pub mod tls;
pub mod update;

use config::{ensure_dir, write_atomic, Paths, Settings};
use std::fs;

/// `nexus-agent init --token <T>`: (re-)initialise enrollment. Stores only
/// `sha256(token)`, creates a fresh key pair and self-signed certificate, and drops any
/// previous enrollment (certificates, agent id, failure counter / lock).
/// Returns the enrollment certificate fingerprint.
pub fn init(paths: &Paths, token: &str, port: Option<u16>, hostname: &str) -> Result<String, String> {
    let token = token.trim();
    if token.len() < 16 || !token.bytes().all(|b| b.is_ascii_graphic()) {
        return Err("token looks invalid (expected the value shown in the appliance UI)".into());
    }
    let io = |p: &std::path::Path, e: std::io::Error| format!("{}: {e}", p.display());
    ensure_dir(&paths.config, 0o700).map_err(|e| io(&paths.config, e))?;
    ensure_dir(&paths.state, 0o700).map_err(|e| io(&paths.state, e))?;
    let hostname = Some(hostname.to_string())
        .filter(|h| !h.is_empty())
        .unwrap_or_else(|| "localhost".into());
    let (key_pem, cert_pem) = tls::new_identity(&hostname)?;
    for p in [paths.cert(), paths.ca(), paths.agent_id(), paths.failures()] {
        match fs::remove_file(&p) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(io(&p, e)),
            _ => {}
        }
    }
    write_atomic(&paths.key(), key_pem.as_bytes(), 0o600).map_err(|e| io(&paths.key(), e))?;
    write_atomic(&paths.enroll_cert(), cert_pem.as_bytes(), 0o644).map_err(|e| io(&paths.enroll_cert(), e))?;
    write_atomic(&paths.token(), agent_proto::token_digest(token).as_bytes(), 0o600)
        .map_err(|e| io(&paths.token(), e))?;
    if let Some(port) = port {
        let mut text = fs::read_to_string(paths.conf()).unwrap_or_default();
        text = text
            .lines()
            .filter(|l| !l.trim_start().starts_with("port"))
            .map(|l| format!("{l}\n"))
            .collect();
        text.push_str(&format!("port = {port}\n"));
        Settings::parse(&text)?;
        write_atomic(&paths.conf(), text.as_bytes(), 0o600).map_err(|e| io(&paths.conf(), e))?;
    }
    let der = tls::certs_from_pem(&cert_pem)?.remove(0);
    Ok(tls::fingerprint(&der))
}

/// Common part of `nexus-agent status`: listen address, mode, certificates, release
/// keys, metadata cache.
pub fn status_common(paths: &Paths, version: &str) -> String {
    let settings = Settings::load(paths);
    let mut out = format!("nexus-agent {version}\n");
    match &settings {
        Ok(s) => out.push_str(&format!("listen: {}:{}\n", s.listen, s.port)),
        Err(e) => out.push_str(&format!("agent.conf: {e}\n")),
    }
    let mode = server::load_mode(paths, &settings.clone().unwrap_or_default());
    out.push_str(&format!("mode: {}\n", server::describe_mode(paths, mode)));
    for (label, p) in [("agent cert", paths.cert()), ("CA cert", paths.ca())] {
        if let Ok(pem) = fs::read_to_string(&p) {
            if let Ok(mut c) = tls::certs_from_pem(&pem) {
                out.push_str(&format!("{label} sha256: {}\n", tls::fingerprint(&c.remove(0))));
            }
        }
    }
    let keys = update::load_keys(&paths.release_keys());
    out.push_str(&format!(
        "release keys: {}\n",
        if keys.is_empty() {
            "none (self-update disabled)".to_string()
        } else {
            keys.iter().map(|k| k.0.clone()).collect::<Vec<_>>().join(", ")
        }
    ));
    match cache::Cache::load(paths) {
        Some(c) => out.push_str(&format!("metadata cache: {} files from job {}\n", c.files.len(), c.job)),
        None => out.push_str("metadata cache: none (next backup reads everything)\n"),
    }
    out
}
