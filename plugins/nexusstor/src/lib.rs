//! The NexusStor plugin (docs/nexusstor-design.md, wire contract: NexusStor's
//! `docs/nexusbackup-protocol.md`). A source is one paired NexusStor; its guests
//! are the vStors the pairing may back up; one snapshot per vStor and run
//! ([`backup`]). Pairing: the web-api decodes the pasted token into `host`,
//! `port` and the pinned `fingerprint` and generates this pairing's client
//! certificate; `Validate` calls `pair` with the token's one-time code when
//! NexusStor does not know the certificate yet.
//!
//! Without the default feature `client` only [`token`] is built (web-api).

#![warn(missing_docs)]

pub mod token;

#[cfg(feature = "client")]
#[allow(missing_docs)]
pub mod backup;
#[cfg(feature = "client")]
pub mod client;
#[cfg(feature = "client")]
#[allow(missing_docs)]
pub mod proto;
#[cfg(feature = "client")]
#[allow(missing_docs)]
pub mod restore;

#[cfg(feature = "client")]
pub use plugin::*;

#[cfg(feature = "client")]
mod plugin {
    use crate::client::{status_of, Client, PinMismatch};
    use crate::proto::{Inventory, Nst};
    use crate::token::{valid_fingerprint, valid_host, Token, DEFAULT_PORT};
    use plugin_sdk::{error, BackupResult, Ctx, Guest, Plugin, Result, Sink, Source, Validation};
    use serde_json::Value;
    use std::time::{SystemTime, UNIX_EPOCH};

    /// The source config (manifest `config_schema`; secrets `token`, `client_key`).
    #[derive(Debug, Clone)]
    pub struct Config {
        /// NexusStor management address.
        pub host: String,
        /// Its port (8443).
        pub port: u16,
        /// SHA-256 of NexusStor's TLS identity certificate (pinned).
        pub fingerprint: String,
        /// This pairing's client certificate (PEM).
        pub client_cert: String,
        /// Its PKCS#8 key (PEM).
        pub client_key: String,
        /// The pairing token (its code is used once, by `Validate`).
        pub token: Option<String>,
        /// Name of this NexusBackup shown on NexusStor.
        pub appliance: String,
    }

    /// (config field, problem)
    pub type Bad = (&'static str, String);

    impl Config {
        /// Parses and checks the config.
        pub fn parse(v: &Value) -> std::result::Result<Config, Bad> {
            let s = |k: &'static str| -> std::result::Result<String, Bad> {
                v[k].as_str()
                    .filter(|s| !s.is_empty())
                    .map(str::to_owned)
                    .ok_or((k, "required (paste the pairing token from NexusStor)".into()))
            };
            let port = match &v["port"] {
                Value::Null => DEFAULT_PORT,
                x => x
                    .as_u64()
                    .and_then(|p| u16::try_from(p).ok())
                    .filter(|p| *p > 0)
                    .ok_or(("port", "expected a port".to_owned()))?,
            };
            let c = Config {
                host: s("host")?,
                port,
                fingerprint: s("fingerprint")?,
                client_cert: s("client_cert")?,
                client_key: s("client_key")?,
                token: v["token"].as_str().filter(|s| !s.is_empty()).map(str::to_owned),
                appliance: v["appliance"]
                    .as_str()
                    .filter(|s| !s.is_empty())
                    .unwrap_or("NexusBackup")
                    .to_owned(),
            };
            if !valid_host(&c.host) {
                return Err(("host", "not a host name or IP address".into()));
            }
            if !valid_fingerprint(&c.fingerprint) {
                return Err(("fingerprint", "expected 64 lowercase hex digits (SHA-256)".into()));
            }
            if c.appliance.len() > 64 || c.appliance.chars().any(char::is_control) {
                return Err(("appliance", "1 to 64 printable characters".into()));
            }
            Ok(c)
        }

        /// The protocol client of this pairing.
        pub fn nst(&self) -> Result<Nst> {
            Ok(Nst {
                client: Client::new(
                    &self.host,
                    self.port,
                    &self.fingerprint,
                    &self.client_cert,
                    &self.client_key,
                )?,
            })
        }
    }

    /// The plugin.
    pub struct NexusStorPlugin;

    fn invalid(field: &str, message: impl Into<String>) -> Validation {
        Validation::Invalid {
            field: field.into(),
            message: message.into(),
        }
    }

    fn config(ctx: &Ctx) -> Result<Config> {
        Config::parse(&ctx.config).map_err(|(f, m)| error(22, format!("config.{f}: {m}")))
    }

    fn now() -> u64 {
        SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
    }

    fn is_pin(e: &anyhow::Error) -> bool {
        e.chain().any(|c| c.downcast_ref::<PinMismatch>().is_some())
    }

    /// The inventory, with the errors an admin can act on spelled out.
    fn inventory(c: &Config, nst: &Nst) -> Result<Inventory> {
        nst.inventory().map_err(|e| {
            if is_pin(&e) {
                error(
                    13,
                    format!(
                        "{}:{}: {e:#} ({}); pair again if NexusStor's certificate was replaced",
                        c.host, c.port, c.fingerprint
                    ),
                )
            } else if status_of(&e) == Some(403) {
                error(
                    13,
                    format!("{e:#}: this NexusBackup is not paired with the NexusStor (or the pairing was revoked there); run \"Validate connection\" with a new pairing token"),
                )
            } else {
                e
            }
        })
    }

    impl Plugin for NexusStorPlugin {
        /// Connects with the pinned certificate; pairs with the token's code when
        /// NexusStor does not know this certificate yet; then reads the inventory.
        fn validate(&mut self, ctx: &Ctx) -> Result<Validation> {
            let c = match Config::parse(&ctx.config) {
                Ok(c) => c,
                Err((f, m)) => return Ok(invalid(f, m)),
            };
            let nst = match c.nst() {
                Ok(n) => n,
                Err(e) => return Ok(invalid("client_key", format!("{e:#}"))),
            };
            let inv = match nst.inventory() {
                Ok(i) => i,
                Err(e) if is_pin(&e) => {
                    return Ok(invalid(
                        "fingerprint",
                        format!("{}:{}: {e}; the pairing token pins {}", c.host, c.port, c.fingerprint),
                    ))
                }
                Err(e) if status_of(&e) == Some(403) => {
                    let Some(raw) = &c.token else {
                        return Ok(invalid(
                            "token",
                            "not paired (or the pairing was revoked on NexusStor): paste a new pairing token",
                        ));
                    };
                    let t = match Token::parse(raw) {
                        Ok(t) => t,
                        Err(e) => return Ok(invalid("token", format!("{e:#}"))),
                    };
                    if t.host != c.host || t.port != c.port || t.fingerprint != c.fingerprint {
                        return Ok(invalid(
                            "token",
                            "the token names another NexusStor than host, port and fingerprint",
                        ));
                    }
                    if t.expired(now()) {
                        return Ok(invalid(
                            "token",
                            "NexusStor does not know this NexusBackup and the pairing token has expired (valid 15 minutes): create a new one on NexusStor and paste it",
                        ));
                    }
                    match nst.pair(&t.code, &c.appliance) {
                        Ok(p) => ctx.info(format!(
                            "paired with NexusStor {:?} (pairing {}), vStors: {}",
                            p.nexusstor,
                            p.pairing,
                            if p.vstors == "*" {
                                "all".to_owned()
                            } else {
                                p.vstors.to_string()
                            }
                        )),
                        Err(e) => return Ok(invalid("token", format!("pairing refused: {e:#}"))),
                    }
                    match nst.inventory() {
                        Ok(i) => i,
                        Err(e) => return Ok(invalid("token", format!("paired, but the inventory failed: {e:#}"))),
                    }
                }
                Err(e) => return Ok(invalid("host", format!("{}:{}: {e:#}", c.host, c.port))),
            };
            ctx.info(format!(
                "NexusStor {:?}: {} vStor(s) in this pairing's scope",
                inv.nexusstor,
                inv.vstors.len()
            ));
            Ok(Validation::Valid)
        }

        /// The vStors of the pairing's scope.
        fn list_guests(&mut self, ctx: &Ctx) -> Result<Vec<Guest>> {
            let c = config(ctx)?;
            let inv = inventory(&c, &c.nst()?)?;
            Ok(inv
                .vstors
                .iter()
                .map(|v| {
                    let mut what = Vec::new();
                    if !v.exports.is_empty() {
                        what.push(format!("{} NFS", v.exports.len()));
                    }
                    if !v.shares.is_empty() {
                        what.push(format!("{} SMB", v.shares.len()));
                    }
                    if v.s3_root.is_some() {
                        what.push("S3".to_owned());
                    }
                    if !v.luns.is_empty() {
                        what.push(format!("{} LUN", v.luns.len()));
                    }
                    Guest {
                        id: v.name.clone(),
                        title: if what.is_empty() {
                            v.name.clone()
                        } else {
                            format!("{} ({})", v.name, what.join(", "))
                        },
                        size: v.used,
                    }
                })
                .collect())
        }

        /// #137: NexusStor shows the newest report on the vStor and raises `backup_overdue` without one.
        fn report(&mut self, ctx: &Ctx) -> Result<()> {
            let c = config(ctx)?;
            let Some(guest) = ctx.guest() else { return Ok(()) };
            crate::backup::check_guest(guest)?;
            let p = &ctx.params;
            if let Some(f) = p["finding"].as_object() {
                // #137: NexusBackup found something in its backup of the vStor
                let body = serde_json::json!({
                    "kind": f.get("kind"), "severity": f.get("severity"), "snapshot": f.get("snapshot"),
                    "message": f.get("message").and_then(|m| m.as_str()).unwrap_or("").chars().take(500).collect::<String>(),
                });
                if !c.nst()?.finding(guest, &body)? {
                    ctx.warn("this NexusStor does not take findings yet (no finding endpoint): nothing sent");
                }
                return Ok(());
            }
            let body = serde_json::json!({
                "time": p["time"], "state": p["state"], "snapshot": p["snapshot"],
                "message": p["message"].as_str().unwrap_or("").chars().take(500).collect::<String>(),
            });
            c.nst()?.report(guest, &body)
        }

        fn backup(&mut self, ctx: &Ctx, sink: &mut Sink) -> Result<BackupResult> {
            let c = config(ctx)?;
            let guest = ctx
                .guest()
                .ok_or_else(|| error(22, "select the vStors to back up in the group (each vStor is a guest)"))?;
            crate::backup::check_guest(guest)?;
            let nst = c.nst()?;
            let inv = inventory(&c, &nst)?;
            let vs = inv.vstors.iter().find(|v| v.name == guest).ok_or_else(|| {
                error(
                    2,
                    format!(
                        "vStor {guest:?} is not on NexusStor {:?} or not in this pairing's scope",
                        inv.nexusstor
                    ),
                )
            })?;
            crate::backup::run(ctx, sink, &nst, &inv.nexusstor, vs)
        }

        fn restore(&mut self, ctx: &Ctx, src: &mut Source) -> Result<String> {
            if ctx.params["restore"].as_str() != Some("to_vstor") {
                return Err(error(95, format!("unknown restore {}", ctx.params["restore"])));
            }
            let c = config(ctx)?;
            // the guest, else from the snapshot's source `plugin-nexusstor-<source id>-<vStor>`
            let from_source = ctx.params["snapshot"]["source"]
                .as_str()
                .and_then(|s| s.strip_prefix("plugin-nexusstor-"))
                .and_then(|r| r.split_once('-'))
                .map(|(_, v)| v.to_owned());
            let vstor = ctx
                .guest()
                .map(str::to_owned)
                .or(from_source)
                .ok_or_else(|| error(22, "restore into a vStor: the snapshot of one vStor"))?;
            let vstor = vstor.as_str();
            crate::backup::check_guest(vstor)?;
            crate::restore::to_vstor(ctx, src, &c.nst()?, vstor)
        }
    }
}
