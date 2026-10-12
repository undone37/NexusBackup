//! Tenant deactivation (catalog v22, Phase 17f), shared by the web-api
//! (deactivate/reactivate, login and token refusal) and the scheduler (skips
//! the tenant's backups, offsite copies and replication; suppresses its alerts).

use rusqlite::{Connection, OptionalExtension};
use std::collections::HashSet;

/// Quorum action of a deactivation (backups stop: a weakening of protection).
pub const DISABLE_ACTION: &str = "tenant.disable";
/// The one alert kind a deactivated tenant still raises (info).
pub const ALERT_KIND: &str = "tenant_disabled";

/// Is `tenant` deactivated? (unknown tenants are not)
pub fn disabled(c: &Connection, tenant: &str) -> rusqlite::Result<bool> {
    Ok(
        c.query_row("SELECT disabled FROM tenants WHERE name = ?1", [tenant], |r| {
            r.get::<_, bool>(0)
        })
        .optional()?
        .unwrap_or(false),
    )
}

/// Names of all deactivated tenants.
pub fn all_disabled(c: &Connection) -> rusqlite::Result<HashSet<String>> {
    c.prepare("SELECT name FROM tenants WHERE disabled = 1")?
        .query_map([], |r| r.get(0))?
        .collect()
}
