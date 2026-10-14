//! Phase 29 (docs/netbackup-comparison.md Tier 1 #2, #4), shared by the web-api
//! (refuses requests) and the scheduler (refuses or trims jobs):
//!
//! - **Freezes** chosen when incident mode is entered (setting `incident`,
//!   appliance-wide: configuration, deletions, restores to production) or a
//!   tenant is locked down (`tenant_lockdowns.state`: deletions, restores to
//!   production; its configuration is refused by the lockdown itself). They
//!   end with incident mode / the lockdown, or earlier through the approval
//!   action [`FREEZE_LIFT`].
//! - **Production restores** ([`production_restore`]): restores that put data
//!   back where it runs (over or next to the original with the network up,
//!   files into their original paths or overwriting, plugin restores). A
//!   restore of a flagged snapshot ([`flagged`]) of that kind needs the
//!   approval action [`RESTORE_INFECTED`]; isolated restores (network
//!   disconnected, another path, downloads, mounts, restore tests) do not.

use rusqlite::{params, Connection, OptionalExtension};
use serde_json::Value;

/// Approval action: restore a flagged snapshot to production.
pub const RESTORE_INFECTED: &str = "restore.infected";
/// Approval action: lift the freezes of incident mode or a tenant lockdown.
pub const FREEZE_LIFT: &str = "incident.freeze.lift";
/// Setting of incident mode (web-api `incident.rs`).
const INCIDENT_SETTING: &str = "incident";

/// What is frozen for one tenant (appliance-wide freezes and the tenant's lockdown merged).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Freeze {
    pub config: bool,
    pub deletions: bool,
    pub restores: bool,
}

impl Freeze {
    fn of(v: &Value) -> Freeze {
        if v["active"] != true {
            return Freeze::default();
        }
        let f = &v["freeze"];
        Freeze {
            config: f["config"] == true,
            deletions: f["deletions"] == true,
            restores: f["restores"] == true,
        }
    }

    fn or(self, o: Freeze) -> Freeze {
        Freeze {
            config: self.config || o.config,
            deletions: self.deletions || o.deletions,
            restores: self.restores || o.restores,
        }
    }

    pub fn any(&self) -> bool {
        self.config || self.deletions || self.restores
    }
}

/// The appliance-wide freezes of an active incident.
pub fn appliance(c: &Connection) -> rusqlite::Result<Freeze> {
    let v: Option<Value> = crate::setting(c, INCIDENT_SETTING)?.and_then(|s| serde_json::from_str(&s).ok());
    Ok(v.as_ref().map_or_else(Freeze::default, Freeze::of))
}

/// The freezes of `tenant`'s active lockdown (config is never set here: the
/// lockdown refuses the tenant's configuration changes itself).
pub fn tenant(c: &Connection, tenant: &str) -> rusqlite::Result<Freeze> {
    let v: Option<Value> = c
        .query_row(
            "SELECT state FROM tenant_lockdowns WHERE tenant = ?1 AND active = 1",
            [tenant],
            |r| r.get::<_, String>(0),
        )
        .optional()?
        .and_then(|s| serde_json::from_str(&s).ok());
    Ok(v.as_ref().map_or_else(Freeze::default, Freeze::of))
}

/// Appliance-wide and tenant freezes together.
pub fn frozen(c: &Connection, tenant_name: &str) -> rusqlite::Result<Freeze> {
    Ok(appliance(c)?.or(tenant(c, tenant_name)?))
}

/// Does this restore job put data back into production? (module doc)
pub fn production_restore(kind: &str, p: &Value) -> bool {
    let link_down = p["link_down"] == true;
    match kind {
        "restore" | "restore_ct" => p["replace"] == true || !link_down,
        "instant_recover" => !link_down,
        "instant_disk" | "plugin_restore" => true,
        "restore_files" => {
            let target = p["target"].as_str().unwrap_or("/");
            target.trim_end_matches('/').is_empty() || p["overwrite"].as_str().is_some_and(|o| o != "never")
        }
        // Phase 33: onto a host like restore_files; downloads are isolated
        "synthetic_restore" if p["mode"] == "host" => production_restore("restore_files", p),
        _ => false,
    }
}

/// Why the snapshot is flagged as infected (an anomaly flag or a YARA hit
/// that a security officer has not cleared), or `None`.
pub fn flagged(c: &Connection, tenant: &str, source: &str, time: i64) -> rusqlite::Result<Option<String>> {
    let row: Option<(Option<String>, Option<String>, Option<i64>)> = c
        .query_row(
            "SELECT anomaly, scan_state, anomaly_cleared_at FROM snapshots
             WHERE tenant = ?1 AND source = ?2 AND time = ?3",
            params![tenant, source, time],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()?;
    Ok(match row {
        Some((_, _, Some(_))) | None => None,
        Some((Some(a), _, None)) => Some(a),
        Some((None, Some(s), None)) if s == "hit" => Some("YARA scan hit".into()),
        Some(_) => None,
    })
}

/// A job's snapshot (`source`, `time` params), if it names one.
pub fn job_snapshot(p: &Value) -> Option<(&str, i64)> {
    Some((p["source"].as_str()?, p["time"].as_i64()?))
}

/// Is `id` an approved (or executed) `restore.infected` request for this
/// tenant's snapshot? (The scheduler's check of a production restore.)
pub fn infected_approved(c: &Connection, id: i64, tenant: &str, source: &str, time: i64) -> rusqlite::Result<bool> {
    let p: Option<String> = c
        .query_row(
            "SELECT params FROM quorum WHERE id = ?1 AND action = ?2 AND state IN ('approved', 'executed')",
            params![id, RESTORE_INFECTED],
            |r| r.get(0),
        )
        .optional()?;
    let Some(p) = p.and_then(|p| serde_json::from_str::<Value>(&p).ok()) else {
        return Ok(false);
    };
    Ok(p["tenant"] == tenant && p["params"]["source"] == source && p["params"]["time"] == time)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn production_or_isolated() {
        for (kind, p, prod) in [
            ("restore", json!({"link_down": true}), false),
            ("restore", json!({}), true),
            ("restore", json!({"link_down": true, "replace": true}), true),
            ("restore_ct", json!({"link_down": false}), true),
            ("instant_recover", json!({"link_down": true}), false),
            ("instant_recover", json!({}), true),
            ("instant_disk", json!({"link_down": true}), true),
            ("plugin_restore", json!({}), true),
            ("restore_files", json!({"target": "/", "overwrite": "never"}), true),
            (
                "restore_files",
                json!({"target": "/restore", "overwrite": "never"}),
                false,
            ),
            (
                "restore_files",
                json!({"target": "/restore", "overwrite": "if_older"}),
                true,
            ),
            ("files_get", json!({}), false),
            (
                "synthetic_restore",
                json!({"mode": "host", "target": "/", "overwrite": "never"}),
                true,
            ),
            (
                "synthetic_restore",
                json!({"mode": "host", "target": "/r", "overwrite": "never"}),
                false,
            ),
            ("synthetic_restore", json!({"mode": "download"}), false),
            ("plugin_mount", json!({}), false),
            ("restore_test", json!({}), false),
        ] {
            assert_eq!(production_restore(kind, &p), prod, "{kind} {p}");
        }
    }

    #[test]
    fn flags_and_freezes() {
        let cat = crate::Catalog::open_memory().unwrap();
        let c = cat.conn();
        c.execute_batch(
            "INSERT INTO tenants (name) VALUES ('t');
             INSERT INTO snapshots (tenant, source, time, size, local, offsite, lock_until, anomaly, scan_state,
               anomaly_cleared_at) VALUES
               ('t','vm-1',1,0,1,0,0,NULL,NULL,NULL), ('t','vm-1',2,0,1,0,0,'YARA: 2 matches','hit',NULL),
               ('t','vm-1',3,0,1,0,0,'x','hit',9), ('t','vm-1',4,0,1,0,0,NULL,'hit',NULL),
               ('t','vm-1',5,0,1,0,0,NULL,'clean',NULL);",
        )
        .unwrap();
        let f = |t| flagged(&c, "t", "vm-1", t).unwrap();
        assert_eq!(f(1), None);
        assert_eq!(f(2).as_deref(), Some("YARA: 2 matches"));
        assert_eq!(f(3), None, "cleared by a security officer");
        assert_eq!(f(4).as_deref(), Some("YARA scan hit"));
        assert_eq!(f(5), None);
        assert_eq!(f(6), None, "unknown snapshot");

        assert_eq!(frozen(&c, "t").unwrap(), Freeze::default());
        crate::set_setting(
            &c,
            "incident",
            r#"{"active": true, "freeze": {"config": true, "deletions": false, "restores": false}}"#,
        )
        .unwrap();
        c.execute(
            "INSERT INTO tenant_lockdowns (tenant, active, state) VALUES ('t', 1, ?1)",
            [r#"{"active": true, "freeze": {"deletions": true, "restores": true}}"#],
        )
        .unwrap();
        let all = Freeze {
            config: true,
            deletions: true,
            restores: true,
        };
        assert_eq!(frozen(&c, "t").unwrap(), all);
        assert!(
            !frozen(&c, "u").unwrap().deletions,
            "other tenants: appliance freezes only"
        );
        crate::set_setting(&c, "incident", r#"{"active": false, "freeze": {"config": true}}"#).unwrap();
        assert!(!appliance(&c).unwrap().any(), "a left incident freezes nothing");
    }
}
