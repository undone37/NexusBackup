//! Keys for `nexus-offsite dr` (fresh appliance, only the offsite copy left)
//! and the escrow files the upload keeps on the remote under `keys/`:
//! ```text
//! keys/kek.recovery                         KEK under the appliance recovery key
//! keys/tenants/<t>/dek.<v>                  DEK v under the KEK
//! keys/tenants/<t>/tenant-escrow.<kid>.<v>  DEK v sealed to the tenant recovery key (optional, Phase 17e)
//! ```
//! - [`appliance_keys`]: appliance recovery key → KEK → the tenant's DEKs (the
//!   KEK is re-sealed on this machine, as `keyd recover`).
//! - [`tenant_keys`]: tenant recovery key → only this tenant's DEKs, stored
//!   under this appliance's own KEK. `kek.recovery` is never read, so other
//!   tenants stay locked.

use crate::remote::Remote;
use anyhow::{bail, Context, Result};
use keyd::tenant_key;
use std::path::Path;

pub type Deks = Vec<(u32, [u8; 32])>;

fn tenant_files(remote: &dyn Remote, tenant: &str, keep: impl Fn(&str) -> bool) -> Result<Vec<(String, Vec<u8>)>> {
    let mut out = Vec::new();
    for (n, _, dir) in remote.list(&format!("keys/tenants/{tenant}"))? {
        if !dir && keep(&n) {
            let b = remote
                .get(&format!("keys/tenants/{tenant}/{n}"), 0, None)
                .with_context(|| format!("keys/tenants/{tenant}/{n}"))?;
            out.push((n, b));
        }
    }
    Ok(out)
}

/// The appliance escrow of `tenant` on the remote, named as keyd stores it:
/// `kek.recovery` and `tenants/<t>/dek.<v>` (also for the web UI attach, Phase 17d).
pub fn appliance_escrow(remote: &dyn Remote, tenant: &str) -> Result<Vec<(String, Vec<u8>)>> {
    let mut files = vec![("kek.recovery".to_owned(), remote.get("keys/kek.recovery", 0, None)?)];
    for (n, b) in tenant_files(remote, tenant, |n| n.starts_with("dek."))? {
        files.push((format!("tenants/{tenant}/{n}"), b));
    }
    if files.len() == 1 {
        bail!("the offsite target holds no escrowed keys of tenant {tenant}");
    }
    Ok(files)
}

/// Appliance-wide DR: installs `kek.recovery` and the tenant's wrapped DEKs
/// into `keyd_dir` and re-seals the KEK with the appliance recovery key.
pub fn appliance_keys(remote: &dyn Remote, tenant: &str, keyd_dir: &Path, recovery_key: &str) -> Result<Deks> {
    let files = appliance_escrow(remote, tenant)?;
    keyd::import_escrow(keyd_dir, &files)?;
    keyd::recover(keyd_dir, recovery_key)?;
    Ok(keyd::tenant_deks(keyd_dir, tenant)?
        .into_iter()
        .map(|(v, k)| (v, *k))
        .collect())
}

/// Tenant-level DR on an initialized appliance (keyd has its own KEK): opens
/// the tenant's escrow files with the tenant recovery key and stores the DEKs
/// under this keyd's KEK.
pub fn tenant_keys(remote: &dyn Remote, tenant: &str, keyd_dir: &Path, tenant_key: &str) -> Result<Deks> {
    if !keyd_dir.join("kek.local").exists() {
        bail!("keyd is not initialized in {}: run the setup first", keyd_dir.display());
    }
    let files = tenant_files(remote, tenant, tenant_key::is_escrow_file)?;
    let deks = tenant_key::open(tenant, tenant_key, &files)?;
    tenant_key::install(keyd_dir, tenant, &deks)?;
    Ok(deks.into_iter().map(|(v, k)| (v, *k)).collect())
}

/// After the upload: removes tenant escrow files of a replaced (or removed)
/// tenant recovery key from the remote. Best effort: a locked object (S3
/// Object Lock) only gets a delete marker and its version stays until the
/// lock runs out. Returns the names removed.
pub fn prune_tenant_escrow(remote: &dyn Remote, tenant: &str, current: &[(String, Vec<u8>)]) -> Vec<String> {
    let keep: Vec<&str> = current.iter().filter_map(|(n, _)| n.rsplit('/').next()).collect();
    let Ok(list) = remote.list(&format!("keys/tenants/{tenant}")) else {
        return vec![];
    };
    let mut gone = Vec::new();
    for (n, _, _) in list {
        if tenant_key::is_escrow_file(&n) && !keep.contains(&n.as_str()) {
            match remote.delete(&format!("keys/tenants/{tenant}/{n}")) {
                Ok(()) => gone.push(n),
                Err(e) => eprintln!("<4>nexus-offsite: cannot delete old tenant escrow {n}: {e}"),
            }
        }
    }
    gone
}
