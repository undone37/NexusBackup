//! Platform-independent core of the NexusBackup agents (`nexus-agent` on Linux,
//! `nexus-agent.exe` on Windows), see docs/agent-protocol.md:
//! TLS / enrollment / mTLS server, the protocol session state machine, FastCDC +
//! BLAKE3 chunking, the metadata cache, `Want` serving, restore stream handling and
//! update signature verification. The host-specific half implements
//! [`server::Platform`] and [`restore::RestoreFs`].

pub mod cache;
pub mod chunk;
pub mod config;
pub mod edge;
pub mod filter;
pub mod glob;
pub mod limit;
pub mod releases;
pub mod restore;
pub mod server;
pub mod standalone;
pub mod tls;
pub mod ui;
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
    init_digest(paths, &agent_proto::token_digest(token), None, port, hostname)
}

/// `nexus-agent init --fleet-secret <S>`: like [`init`], with a reusable fleet secret
/// (docs/agent-protocol.md "Fleet enrollment"): the agent waits until an appliance
/// that knows the secret finds it in a scan and the admin accepts it. Refused on an
/// enrolled agent (a package upgrade or GPO re-run must not drop the enrollment;
/// re-enrollment uses a one-time token).
pub fn init_fleet(paths: &Paths, secret: &str, port: Option<u16>, hostname: &str) -> Result<String, String> {
    let id = agent_proto::fleet_id(secret)
        .ok_or("fleet secret looks invalid (expected nxf1.<id>.<secret> as shown in the appliance UI)")?;
    if paths.agent_id().exists() && paths.cert().exists() {
        return Err("already enrolled: a fleet secret only initialises new agents (re-enroll with --token)".into());
    }
    init_digest(paths, &agent_proto::token_digest(secret), Some(id), port, hostname)
}

/// A fleet secret file dropped by a package deployment: adopted (if the agent is not
/// initialised yet) and deleted in any case. `None` = no file.
pub fn adopt_fleet_secret(paths: &Paths, hostname: &str) -> Option<Result<String, String>> {
    let f = paths.fleet_secret();
    let secret = fs::read_to_string(&f).ok()?;
    let r = if fs::remove_file(&f).is_err() {
        Err(format!("{}: cannot delete it; not adopted", f.display()))
    } else if paths.token().exists() || paths.cert().exists() {
        Err(format!(
            "{} ignored and deleted: the agent is already initialised",
            f.display()
        ))
    } else {
        init_fleet(paths, &secret, None, hostname)
            .map(|fp| format!("fleet secret adopted (enrollment certificate sha256 {fp})"))
    };
    Some(r)
}

fn init_digest(
    paths: &Paths,
    digest: &str,
    fleet: Option<&str>,
    port: Option<u16>,
    hostname: &str,
) -> Result<String, String> {
    let io = |p: &std::path::Path, e: std::io::Error| format!("{}: {e}", p.display());
    ensure_dir(&paths.config, 0o700).map_err(|e| io(&paths.config, e))?;
    ensure_dir(&paths.state, 0o700).map_err(|e| io(&paths.state, e))?;
    let hostname = Some(hostname.to_string())
        .filter(|h| !h.is_empty())
        .unwrap_or_else(|| "localhost".into());
    let (key_pem, cert_pem) = tls::new_identity(&hostname)?;
    for p in [
        paths.cert(),
        paths.ca(),
        paths.agent_id(),
        paths.failures(),
        paths.fleet(),
    ] {
        match fs::remove_file(&p) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(io(&p, e)),
            _ => {}
        }
    }
    write_atomic(&paths.key(), key_pem.as_bytes(), 0o600).map_err(|e| io(&paths.key(), e))?;
    write_atomic(&paths.enroll_cert(), cert_pem.as_bytes(), 0o644).map_err(|e| io(&paths.enroll_cert(), e))?;
    if let Some(id) = fleet {
        write_atomic(&paths.fleet(), id.as_bytes(), 0o600).map_err(|e| io(&paths.fleet(), e))?;
    }
    write_atomic(&paths.token(), digest.as_bytes(), 0o600).map_err(|e| io(&paths.token(), e))?;
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
    match edge::current(paths, &settings.clone().unwrap_or_default()) {
        Some(e) => out.push_str(&format!(
            "edge proxy: {} (certificate sha256 {})\n",
            e.addr, e.cert_sha256
        )),
        None => out.push_str("edge proxy: none\n"),
    }
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
    let packaged = update::packaged(&update::package_marker());
    if let Some(p) = &packaged {
        out.push_str(&format!("installed from: {p} package\n"));
    }
    match update::self_update_blocked(settings.as_ref().ok().and_then(|s| s.self_update), packaged.as_deref()) {
        Some(why) => out.push_str(&format!("self-update: off; {why}\n")),
        None => out.push_str(&format!(
            "self-update: allowed with {} updates from the appliance\n",
            match packaged.as_deref() {
                Some(p) => format!("{p} package"),
                None => "binary".into(),
            }
        )),
    }
    let state = update::state_json(paths);
    if state != "{}" {
        out.push_str(&format!("last update: {state}\n"));
    }
    match cache::Cache::load(paths) {
        Some(c) => out.push_str(&format!("metadata cache: {} files from job {}\n", c.files.len(), c.job)),
        None => out.push_str("metadata cache: none (next backup reads everything)\n"),
    }
    out
}

/// The agent's TCP listener. `::` is one dual-stack socket (IPv6 + IPv4-mapped): Windows
/// defaults to IPV6_V6ONLY=1, so a plain bind to `::` refused every IPv4 connection there
/// (and on Linux with `net.ipv6.bindv6only=1`). Without IPv6 on the host, `::` falls back
/// to `0.0.0.0`. Any other address is bound as given.
pub fn listen(addr: &str, port: u16) -> std::io::Result<std::net::TcpListener> {
    use socket2::{Domain, Socket, Type};
    if addr != "::" {
        return std::net::TcpListener::bind((addr, port));
    }
    let dual = || -> std::io::Result<std::net::TcpListener> {
        let s = Socket::new(Domain::IPV6, Type::STREAM, None)?;
        s.set_only_v6(false)?;
        #[cfg(unix)]
        s.set_reuse_address(true)?;
        s.bind(&std::net::SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, port)).into())?;
        s.listen(128)?;
        Ok(s.into())
    };
    dual().or_else(|_| std::net::TcpListener::bind(("0.0.0.0", port)))
}

#[cfg(test)]
mod listen_tests {
    #[test]
    fn unspecified_accepts_ipv4_and_ipv6() {
        let l = super::listen("::", 0).unwrap();
        let port = l.local_addr().unwrap().port();
        std::net::TcpStream::connect(("127.0.0.1", port)).expect("IPv4 to the :: listener");
        if l.local_addr().unwrap().is_ipv6() {
            std::net::TcpStream::connect(("::1", port)).expect("IPv6 to the :: listener");
        }
    }
}
