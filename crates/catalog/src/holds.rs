//! Legal holds (catalog v18, Phase 15c, docs/control-plane.md "Legal hold"),
//! shared by the web-api (set, release request, list) and the scheduler
//! (retention, GC and deletes skip held snapshots; replication advisories).

use rusqlite::{params, Connection, OptionalExtension};
use std::collections::BTreeSet;

/// Quorum action of a release (a second approver while approvals are enabled).
pub const RELEASE_ACTION: &str = "snapshot.hold_release";
/// Alert kind on a secondary for a hold the primary reports.
pub const ADVISORY_KIND: &str = "legal_hold_advisory";

/// `(source, time)` of the tenant's active holds.
pub fn held(c: &Connection, tenant: &str) -> rusqlite::Result<BTreeSet<(String, u64)>> {
    c.prepare("SELECT source, time FROM legal_holds WHERE tenant = ?1 AND state = 'active'")?
        .query_map([tenant], |r| Ok((r.get(0)?, r.get::<_, i64>(1)? as u64)))?
        .collect()
}

/// Id of the snapshot's active hold.
pub fn active(c: &Connection, tenant: &str, source: &str, time: i64) -> rusqlite::Result<Option<i64>> {
    c.query_row(
        "SELECT id FROM legal_holds WHERE tenant = ?1 AND source = ?2 AND time = ?3 AND state = 'active'",
        params![tenant, source, time],
        |r| r.get(0),
    )
    .optional()
}

/// Key of the advisory alert of one snapshot (resolved when applied or withdrawn).
pub fn advisory_key(tenant: &str, source: &str, time: u64) -> String {
    format!("{ADVISORY_KIND}:{tenant}/{source}/{time}")
}
