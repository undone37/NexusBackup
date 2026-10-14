//! Tenant-side approvers (Phase 33, docs/control-plane.md "Tenant-side
//! approvers"): a tenant that opted in (`tenant_approvals`, catalog v46) must
//! co-approve every request that destroys or weakens its data, through one of
//! its `tenant_admin` accounts, in addition to the provider's approver. An
//! account approves at the earliest [`WAIT_SECS`] after it became a tenant admin
//! of that tenant, was activated or re-enabled (`users.approver_since`, set by a
//! trigger). A tenant approver's refusal is final.

use rusqlite::{params, Connection, OptionalExtension};
use serde_json::Value;

/// A new tenant approver waits this long before approving.
pub const WAIT_SECS: i64 = 24 * 3600;
/// Quorum action that switches a tenant's approvers off (itself gated by them).
pub const DISABLE_ACTION: &str = "tenant.approvers.disable";
/// Alert kind: an account becomes a tenant-side approver after the wait.
pub const ALERT_KIND: &str = "tenant_approver";

/// When `tenant` opted in (None = it did not).
pub fn enabled_at(c: &Connection, tenant: &str) -> rusqlite::Result<Option<i64>> {
    c.query_row(
        "SELECT enabled_at FROM tenant_approvals WHERE tenant = ?1",
        [tenant],
        |r| r.get(0),
    )
    .optional()
}

/// The tenants `action` with params `p` destroys or weakens, whether or not they opted in.
pub fn affected(c: &Connection, action: &str, p: &Value) -> rusqlite::Result<Vec<String>> {
    let s = |k: &str| p[k].as_str().map(str::to_owned);
    let mut out: Vec<String> = match action {
        "snapshot.delete" | crate::holds::RELEASE_ACTION | DISABLE_ACTION => s("tenant").into_iter().collect(),
        crate::tenants::DISABLE_ACTION | "tenant.delete" | "tenant.update" => s("name").into_iter().collect(),
        // weakening group changes and deletions (the request carries the group's id)
        "group.update" | "group.delete" => match p["id"].as_i64() {
            Some(id) => c
                .query_row("SELECT tenant FROM groups WHERE id = ?1", [id], |r| r.get(0))
                .optional()?
                .into_iter()
                .collect(),
            None => Vec::new(),
        },
        // a weakening policy change weakens every group using it
        "policy.update" => match p["id"].as_i64() {
            Some(id) => c
                .prepare("SELECT DISTINCT tenant FROM groups WHERE policy_id = ?1 ORDER BY tenant")?
                .query_map([id], |r| r.get(0))?
                .collect::<rusqlite::Result<_>>()?,
            None => Vec::new(),
        },
        "replication.key_export" => p["tenants"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect(),
        _ => Vec::new(),
    };
    out.sort();
    out.dedup();
    Ok(out)
}

/// The opted-in tenants among [`affected`]: their approvers must co-approve.
pub fn gated(c: &Connection, action: &str, p: &Value) -> rusqlite::Result<Vec<String>> {
    let mut out = Vec::new();
    for t in affected(c, action, p)? {
        if enabled_at(c, &t)?.is_some() {
            out.push(t);
        }
    }
    Ok(out)
}

/// One tenant admin of a tenant and when it may approve.
#[derive(Debug, PartialEq, serde::Serialize)]
pub struct Approver {
    pub name: String,
    pub eligible_from: i64,
}

/// The enabled, activated, unexpired tenant admins of `tenant`.
pub fn approvers(c: &Connection, tenant: &str) -> rusqlite::Result<Vec<Approver>> {
    c.prepare(
        "SELECT name, COALESCE(approver_since, created) FROM users WHERE role = 'tenant_admin' AND tenant = ?1
         AND disabled = 0 AND activation_hash IS NULL AND (expires IS NULL OR expires > ?2) ORDER BY name",
    )?
    .query_map(params![tenant, crate::now()], |r| {
        Ok(Approver {
            name: r.get(0)?,
            eligible_from: r.get::<_, i64>(1)? + WAIT_SECS,
        })
    })?
    .collect()
}

/// When `user` may approve for `tenant` (None = not a tenant approver of it at all).
pub fn eligible_from(c: &Connection, tenant: &str, user: &str) -> rusqlite::Result<Option<i64>> {
    Ok(approvers(c, tenant)?
        .into_iter()
        .find(|a| a.name == user)
        .map(|a| a.eligible_from))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Catalog;
    use serde_json::json;

    #[test]
    fn affected_and_gated_tenants() {
        let cat = Catalog::open_memory().unwrap();
        let c = cat.conn();
        c.execute_batch(
            r#"INSERT INTO tenants (name) VALUES ('acme'), ('globex');
               INSERT INTO sources (id, tenant, kind, name, config) VALUES (1,'acme','pve','a','{}'), (2,'globex','pve','g','{}');
               INSERT INTO policies (id, name, schedule, gfs) VALUES (1,'p','daily 22:00','{}'), (2,'q','daily 22:00','{}');
               INSERT INTO groups (id, tenant, source_id, policy_id, name, guests) VALUES
                 (1,'acme',1,1,'a1','[]'), (2,'globex',2,1,'g1','[]'), (3,'globex',2,2,'g2','[]');"#,
        )
        .unwrap();
        let a = |action: &str, p: Value| affected(&c, action, &p).unwrap();
        assert_eq!(a("snapshot.delete", json!({"tenant": "acme"})), ["acme"]);
        assert_eq!(a("snapshot.hold_release", json!({"tenant": "acme"})), ["acme"]);
        assert_eq!(a("tenant.disable", json!({"name": "globex"})), ["globex"]);
        assert_eq!(a("group.delete", json!({"id": 1})), ["acme"]);
        assert_eq!(a("policy.update", json!({"id": 1})), ["acme", "globex"]);
        assert_eq!(a("policy.update", json!({"id": 2})), ["globex"]);
        assert_eq!(
            a("replication.key_export", json!({"tenants": ["globex", "acme", "acme"]})),
            ["acme", "globex"]
        );
        assert!(a("plugin.install", json!({"tenant": "acme"})).is_empty());
        assert!(gated(&c, "policy.update", &json!({"id": 1})).unwrap().is_empty());
        c.execute(
            "INSERT INTO tenant_approvals (tenant, enabled_at, enabled_by) VALUES ('globex', 1, 'alice')",
            [],
        )
        .unwrap();
        assert_eq!(gated(&c, "policy.update", &json!({"id": 1})).unwrap(), ["globex"]);
    }

    /// `approver_since` follows activation, role / tenant changes and re-enabling
    /// (trigger); created accounts count from `created`.
    #[test]
    fn approver_wait() {
        let cat = Catalog::open_memory().unwrap();
        let c = cat.conn();
        c.execute_batch(
            "INSERT INTO tenants (name) VALUES ('acme');
             INSERT INTO users (name, password_hash, totp_secret, role, tenant, created) VALUES
               ('dana','x','y','tenant_admin','acme',100), ('tim','x','y','tenant_user','acme',100),
               ('new','x','y','tenant_admin','acme',100);
             UPDATE users SET activation_hash = 'h' WHERE name = 'new';",
        )
        .unwrap();
        let names =
            |c: &Connection| -> Vec<String> { approvers(c, "acme").unwrap().into_iter().map(|a| a.name).collect() };
        assert_eq!(
            names(&c),
            ["dana"],
            "pending activation and other roles are no approvers"
        );
        assert_eq!(eligible_from(&c, "acme", "dana").unwrap(), Some(100 + WAIT_SECS));
        let now = crate::now();
        c.execute("UPDATE users SET role = 'tenant_admin' WHERE name = 'tim'", [])
            .unwrap();
        c.execute("UPDATE users SET activation_hash = NULL WHERE name = 'new'", [])
            .unwrap();
        for n in ["tim", "new"] {
            let from = eligible_from(&c, "acme", n).unwrap().unwrap();
            assert!(from >= now + WAIT_SECS && from <= crate::now() + WAIT_SECS, "{n}");
        }
        c.execute("UPDATE users SET disabled = 1 WHERE name = 'dana'", [])
            .unwrap();
        assert_eq!(eligible_from(&c, "acme", "dana").unwrap(), None);
        c.execute("UPDATE users SET disabled = 0 WHERE name = 'dana'", [])
            .unwrap();
        assert!(
            eligible_from(&c, "acme", "dana").unwrap().unwrap() >= now + WAIT_SECS,
            "re-enabled"
        );
        // other updates leave it alone
        c.execute("UPDATE users SET approver_since = 5 WHERE name = 'dana'", [])
            .unwrap();
        c.execute(
            "UPDATE users SET last_login = 7, can_download = 1 WHERE name = 'dana'",
            [],
        )
        .unwrap();
        assert_eq!(eligible_from(&c, "acme", "dana").unwrap(), Some(5 + WAIT_SECS));
    }
}
