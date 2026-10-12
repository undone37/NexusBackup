//! Vault profile of a replication secondary (Phase 17c, docs/control-plane.md
//! "Vault mode"): setting `vault_mode` `{enabled, since, by}`. A one-way
//! profile: enabling needs approval; switching it off needs an approved
//! `vault.disable` request and then the recovery key at the console
//! (`nexus-setup vault-disable`), because the web-api never reads keyd's escrow.

use crate::{set_setting, setting};
use rusqlite::Connection;
use serde::{Deserialize, Serialize};

pub const SETTING: &str = "vault_mode";
pub const ENABLE: &str = "vault.enable";
pub const DISABLE: &str = "vault.disable";
/// A restore or download requested while vault mode is on (the web-api queues
/// the wrapped jobs on approval).
pub const RESTORE: &str = "vault.restore";
/// An approved `vault.disable` must be carried out at the console within this time.
pub const DISABLE_VALID_SECS: i64 = 72 * 3600;

#[derive(Serialize, Deserialize, Default, Clone, Debug, PartialEq)]
pub struct Vault {
    pub enabled: bool,
    pub since: Option<i64>,
    pub by: Option<String>,
}

pub fn load(c: &Connection) -> rusqlite::Result<Vault> {
    Ok(setting(c, SETTING)?
        .and_then(|v| serde_json::from_str(&v).ok())
        .unwrap_or_default())
}

pub fn enabled(c: &Connection) -> rusqlite::Result<bool> {
    Ok(load(c)?.enabled)
}

pub fn store(c: &Connection, v: &Vault) -> rusqlite::Result<()> {
    set_setting(c, SETTING, &serde_json::to_string(v).expect("vault json"))
}
