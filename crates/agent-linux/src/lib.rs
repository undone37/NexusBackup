//! NexusBackup Linux agent (`nexus-agent`), see docs/agent-protocol.md and
//! docs/agent-linux.md.

pub mod blockdev;
pub mod endpoint;
pub mod hooks;
pub mod layout;
pub mod power;
pub mod rescue;
pub mod restore;
pub mod scan;
pub mod server;
pub mod snapshot;
pub mod sys;
pub mod update;
pub mod volumes;

// shared with the Windows agent (crates/agent-core)
pub use agent_core::{cache, config, glob, tls};

use config::{Paths, Settings};

/// `nexus-agent init --token <T>`: (re-)initialise enrollment. Stores only
/// `sha256(token)`, creates a fresh key pair and self-signed certificate, and drops any
/// previous enrollment (certificates, agent id, failure counter / lock).
pub fn init(paths: &Paths, token: &str, port: Option<u16>) -> Result<String, String> {
    let fp = agent_core::init(paths, token, port, &sys::uname().1)?;
    Ok(format!(
        "initialised for enrollment (token stored as sha256 only)\nenrollment certificate sha256 {fp}\n(re)start the service: systemctl restart nexus-agent"
    ))
}

/// `nexus-agent init --fleet-secret <S>` (docs/agent-linux.md "Fleet deployment").
pub fn init_fleet(paths: &Paths, secret: &str, port: Option<u16>) -> Result<String, String> {
    let fp = agent_core::init_fleet(paths, secret, port, &sys::uname().1)?;
    Ok(format!(
        "initialised for fleet enrollment (secret stored as sha256 only)\nenrollment certificate sha256 {fp}\nstart the service: systemctl enable --now nexus-agent; the appliance finds it in its next scan"
    ))
}

/// `nexus-agent status`
pub fn status(paths: &Paths) -> String {
    let mut out = agent_core::status_common(paths, env!("CARGO_PKG_VERSION"));
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
