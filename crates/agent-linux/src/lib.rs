//! NexusBackup Linux agent (`nexus-agent`), see docs/agent-protocol.md and
//! docs/agent-linux.md.

pub mod cache;
pub mod config;
pub mod glob;
pub mod hooks;
pub mod restore;
pub mod scan;
pub mod server;
pub mod snapshot;
pub mod sys;
pub mod tls;
pub mod update;
pub mod volumes;

use config::{ensure_dir, write_atomic, Paths, Settings};
use std::fs;

/// `nexus-agent init --token <T>`: (re-)initialise enrollment. Stores only
/// `sha256(token)`, creates a fresh key pair and self-signed certificate, and drops any
/// previous enrollment (certificates, agent id, failure counter / lock).
pub fn init(paths: &Paths, token: &str, port: Option<u16>) -> Result<String, String> {
    let token = token.trim();
    if token.len() < 16 || !token.bytes().all(|b| b.is_ascii_graphic()) {
        return Err("token looks invalid (expected the value shown in the appliance UI)".into());
    }
    let io = |p: &std::path::Path, e: std::io::Error| format!("{}: {e}", p.display());
    ensure_dir(&paths.config, 0o700).map_err(|e| io(&paths.config, e))?;
    ensure_dir(&paths.state, 0o700).map_err(|e| io(&paths.state, e))?;
    let hostname = Some(sys::uname().1)
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
    Ok(format!(
        "initialised for enrollment (token stored as sha256 only)\nenrollment certificate sha256 {}\n(re)start the service: systemctl restart nexus-agent",
        tls::fingerprint(&der)
    ))
}

/// `nexus-agent status`
pub fn status(paths: &Paths) -> String {
    let settings = Settings::load(paths);
    let mut out = format!("nexus-agent {}\n", env!("CARGO_PKG_VERSION"));
    match &settings {
        Ok(s) => out.push_str(&format!("listen: {}:{}\n", s.listen, s.port)),
        Err(e) => out.push_str(&format!("agent.conf: {e}\n")),
    }
    let mode = match server::load_mode(paths, &settings.clone().unwrap_or_default()) {
        Ok(server::Mode::Uninitialized) => "not initialised (run nexus-agent init --token <T>)".to_string(),
        Ok(server::Mode::Enroll(_)) => format!("enrollment pending ({} failed proofs)", server::failures(paths)),
        Ok(server::Mode::Locked(_)) => "LOCKED after failed enrollment proofs; run nexus-agent init again".to_string(),
        Ok(server::Mode::Mtls { agent_id, .. }) => format!("enrolled as {agent_id}"),
        Err(e) => format!("error: {e}"),
    };
    out.push_str(&format!("mode: {mode}\n"));
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
    let left = snapshot::leftover_count(paths);
    if left > 0 {
        out.push_str(&format!(
            "snapshot journal: {left} entries (removed at next service start)\n"
        ));
    }
    out.push_str("volumes:\n");
    for v in volumes::list_volumes() {
        out.push_str(&format!(
            "  {} {} {} snapshot={:?}\n",
            v.mountpoint, v.fstype, v.device, v.snapshot
        ));
    }
    out
}

/// `nexus-agent hooks test`: permission checks + a dry run of pre and post hooks.
pub fn hooks_test(paths: &Paths) -> (bool, String) {
    let s = Settings::load(paths).unwrap_or_default();
    let t = std::time::Duration::from_secs(s.hook_timeout_secs);
    let env = [("NEXUS_JOB", "0".to_string()), ("NEXUS_TEST", "1".to_string())];
    let mut out = String::new();
    let mut ok = true;
    for phase in ["pre", "post"] {
        match hooks::list(&paths.hooks(), phase, s.hook_owner) {
            Ok(h) => out.push_str(&format!("{phase}: {} hook(s)\n", h.len())),
            Err(e) => {
                out.push_str(&format!("{phase}: REFUSED: {e}\n"));
                ok = false;
                continue;
            }
        }
        let mut env = env.to_vec();
        if phase == "post" {
            env.push(("NEXUS_SUCCESS", "1".into()));
        }
        let (good, log) = hooks::run(&paths.hooks(), phase, s.hook_owner, t, &env);
        ok &= good;
        out.push_str(&log);
    }
    (ok, out)
}
