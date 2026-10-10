//! `nexus-plugin-install`: one installer pass (docs/plugin-system.md "Trust and
//! lifecycle"). Runs as `nexus-plugins` (owner of /var/lib/nexus/plugins, not the
//! plugin runtime uid), started by `nexus-plugin-install.path` when the web-api
//! touches `<staging>/.trigger` after an approval, and once at boot.
//! Environment: NEXUS_CATALOG, NEXUS_PLUGIN_STAGING, NEXUS_PLUGIN_KEYS, NEXUS_PLUGINS.

use anyhow::{Context, Result};
use plugin_manager::{run_pending, Paths};
use std::path::PathBuf;

fn env(k: &str, d: &str) -> PathBuf {
    PathBuf::from(std::env::var_os(k).unwrap_or_else(|| d.into()))
}

fn main() -> Result<()> {
    let cat = catalog::Catalog::open(&env("NEXUS_CATALOG", "/var/lib/nexus/catalog/catalog.db")).context("catalog")?;
    let p = Paths {
        staging: env("NEXUS_PLUGIN_STAGING", "/var/lib/nexus/plugins-staging"),
        plugins: env("NEXUS_PLUGINS", "/var/lib/nexus/plugins"),
        project_keys: env("NEXUS_PLUGIN_KEYS", "/etc/pki/nexus/plugin-keys"),
    };
    for l in run_pending(&cat, &p)? {
        println!("{l}");
    }
    Ok(())
}
