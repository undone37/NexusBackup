//! Non-interactive driver: `nexus-setup --script answers.json`.
//!
//! For tests and lab provisioning. The answers file holds passwords and TOTP
//! secrets: keep it on tmpfs and delete it afterwards. Because nobody reads
//! the screen, the recovery key goes to stdout exactly once (the caller's
//! pipe, never a file written by setup), and the group challenge is answered
//! from memory.
//!
//! ```json
//! {
//!   "network": {"nic": "eth0", "method": "static", "address": "192.0.2.10", "prefix": 24,
//!               "gateway": "192.0.2.1", "dns": ["192.0.2.53"], "hostname": "nexus01"},
//!   "admin": {"name": "admin", "password": "…", "totp_secret": "BASE32…", "totp_code": "123456"},
//!   "security_officer": {"name": "so", "password": "…", "totp_secret": "…", "totp_code": "…"},
//!   "recovery_key": {"confirm_full": "only to confirm a key whose confirmation was interrupted"}
//! }
//! ```
//! `"network"` may carry `"link": {"bond": ["eth1"], "bond_mode": "802.3ad", "vlan": 20,
//! "mtu": 9000}` (each optional): the management interface as a bond, a tagged VLAN and/or
//! with another MTU, written by nexus-net (Phase 22a).
//! `"replace": true` in an account replaces an existing account of that role.
//! The second person is optional: instead of `"security_officer"`, give
//! `"second_person_later": true`; the appliance then starts with approvals
//! disabled (single administrator) until a second person exists and an admin
//! enables them in the web UI.

use crate::{challenge, KeyState, NetConfig, Role, Setup, Step};
use anyhow::{anyhow, bail, Result};
use serde::Deserialize;
use std::io::Write;
use zeroize::Zeroize;

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Answers {
    #[serde(default)]
    pub network: Option<NetConfig>,
    #[serde(default)]
    pub admin: Option<Account>,
    #[serde(default)]
    pub security_officer: Option<Account>,
    /// no security officer now: approvals start disabled
    #[serde(default)]
    pub second_person_later: bool,
    #[serde(default)]
    pub recovery_key: Option<RecoveryAnswers>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Account {
    pub name: String,
    pub password: String,
    #[serde(default)]
    pub password_repeat: Option<String>,
    pub totp_secret: String,
    pub totp_code: String,
    #[serde(default)]
    pub replace: bool,
}

impl Drop for Account {
    fn drop(&mut self) {
        self.password.zeroize();
        self.password_repeat.zeroize();
        self.totp_secret.zeroize();
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryAnswers {
    #[serde(default)]
    pub confirm_full: Option<String>,
}

impl Drop for RecoveryAnswers {
    fn drop(&mut self) {
        self.confirm_full.zeroize();
    }
}

fn flush_log(s: &mut Setup, out: &mut dyn Write) -> Result<()> {
    for l in s.log.drain(..) {
        writeln!(out, "+ {l}")?;
    }
    Ok(())
}

fn account(s: &mut Setup, role: Role, a: Option<&Account>, out: &mut dyn Write) -> Result<()> {
    let existing = s.user_with_role(role)?;
    let a = match (existing, a) {
        (Some(_), Some(a)) if a.replace => a,
        (Some(name), _) => {
            writeln!(out, "{}: {name} exists, kept", role.label())?;
            return Ok(());
        }
        (None, Some(a)) => a,
        (None, None) if role == Role::SecurityOfficer => {
            bail!("answers lack \"security_officer\" (or set \"second_person_later\": true)")
        }
        (None, None) => bail!("answers lack \"{}\"", role.as_str()),
    };
    crate::check_password_pair(&a.password, a.password_repeat.as_deref().unwrap_or(&a.password))?;
    s.create_user(role, &a.name, &a.password, &a.totp_secret, &a.totp_code, a.replace)?;
    writeln!(
        out,
        "{}: {} {}",
        role.label(),
        a.name,
        if a.replace { "replaced" } else { "created" }
    )?;
    Ok(())
}

pub fn run(s: &mut Setup, ans: &Answers, force_network: bool, out: &mut dyn Write) -> Result<()> {
    if s.paths.setup_done.exists() {
        // --force-reconfigure-network on a finished appliance
        let net = ans
            .network
            .as_ref()
            .ok_or_else(|| anyhow!("answers lack \"network\""))?;
        let tls = s.reconfigure_network(net)?;
        flush_log(s, out)?;
        writeln!(
            out,
            "network reconfigured; new TLS fingerprint (SHA-256): {}",
            tls.fingerprint
        )?;
        return Ok(());
    }
    for step in Step::ALL {
        let done = s.is_done(step)?;
        match step {
            Step::Network if done && !force_network => writeln!(out, "network: already configured, kept")?,
            Step::Network => {
                let net = ans
                    .network
                    .as_ref()
                    .ok_or_else(|| anyhow!("answers lack \"network\""))?;
                let ips = s.apply_network(net)?;
                writeln!(out, "network: {} configured, addresses {ips:?}", net.nic)?;
            }
            Step::Admin => account(s, Role::Admin, ans.admin.as_ref(), out)?,
            Step::SecurityOfficer => match (&ans.security_officer, ans.second_person_later) {
                (Some(_), true) => bail!("give either \"security_officer\" or \"second_person_later\", not both"),
                (None, _) if done => match s.user_with_role(Role::SecurityOfficer)? {
                    Some(name) => writeln!(out, "Security officer: {name} exists, kept")?,
                    None => writeln!(out, "Security officer: later (chosen before)")?,
                },
                (None, true) => {
                    s.second_person_later()?;
                    writeln!(
                        out,
                        "Security officer: later. Approvals start DISABLED (single administrator); \
                         add a second person in the web UI and enable approvals there"
                    )?;
                }
                (a, false) => account(s, Role::SecurityOfficer, a.as_ref(), out)?,
            },
            Step::RecoveryKey => match s.key_state()? {
                KeyState::Confirmed => writeln!(out, "recovery key: already confirmed")?,
                KeyState::Unconfirmed => {
                    let full = ans
                        .recovery_key
                        .as_ref()
                        .and_then(|r| r.confirm_full.as_deref())
                        .ok_or_else(|| {
                            anyhow!(
                                "keyd is initialised but its recovery key was never confirmed; it cannot be shown again. \
                                 Provide the full recovery key as recovery_key.confirm_full, or re-image the appliance"
                            )
                        })?;
                    s.confirm_recovery_full(full)?;
                    writeln!(out, "recovery key: confirmed (full re-entry)")?;
                }
                KeyState::Uninitialized => {
                    let key = s.keyd_init()?;
                    writeln!(out, "RECOVERY KEY (shown once, record it now): {}", key.expose())?;
                    let idx = challenge();
                    let groups = key.groups();
                    let answers: Vec<&str> = idx.iter().map(|&i| groups[i].as_str()).collect();
                    if !s.confirm_recovery_groups(&key, &idx, &answers)? {
                        bail!("internal error: recovery key self-check failed");
                    }
                    writeln!(out, "recovery key: confirmed")?;
                }
            },
            Step::Tls => {
                let t = s.tls(false)?;
                writeln!(
                    out,
                    "TLS fingerprint (SHA-256): {}  SAN: {}",
                    t.fingerprint,
                    t.sans.join(", ")
                )?;
            }
            Step::MetricsToken if done => writeln!(out, "metrics token: exists, kept")?,
            Step::MetricsToken => {
                s.metrics_token()?;
                writeln!(out, "metrics token: {}", s.paths.metrics_token.display())?;
            }
            Step::Finish => {
                s.finish()?;
                flush_log(s, out)?;
                if s.approvals_start_enabled()? {
                    writeln!(out, "approvals: enabled (two people)")?;
                } else {
                    writeln!(out, "approvals: DISABLED (single administrator)")?;
                }
                writeln!(out, "setup complete")?;
            }
        }
        flush_log(s, out)?;
    }
    Ok(())
}
