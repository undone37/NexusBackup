//! Service-provider tenancy (catalog v25, Phase 19b): policies assigned to a
//! tenant, policy tier templates, tombstones of deleted tenant names, and the
//! tenant an audit entry concerns (`audit_tenants`, read by tenant admins).

use rusqlite::{params, Connection, OptionalExtension};
use serde_json::{json, Value};

/// Actor suffix of entries written while an admin views a tenant
/// (`alice impersonating:acme`).
pub const IMPERSONATING: &str = " impersonating:";

/// Policy tiers (`policies.tier`) and their templates: (tier, name, schedule,
/// GFS `[recent, daily, weekly, monthly, yearly]`, offsite).
pub const TEMPLATES: &[(&str, &str, &str, [u32; 5], bool)] = &[
    ("bronze", "Bronze", "daily 02:00", [0, 7, 4, 3, 0], false),
    ("silver", "Silver", "daily 01:00", [0, 14, 8, 12, 0], true),
    ("gold", "Gold", "every 6h at 15", [0, 30, 12, 24, 7], true),
];

pub fn tier_ok(t: &str) -> bool {
    TEMPLATES.iter().any(|x| x.0 == t)
}

/// The templates as the API shows them.
pub fn templates() -> Value {
    Value::Array(
        TEMPLATES
            .iter()
            .map(|(tier, name, schedule, g, offsite)| {
                json!({"tier": tier, "name": name, "schedule": schedule, "offsite": offsite,
                       "gfs": {"recent": g[0], "daily": g[1], "weekly": g[2], "monthly": g[3], "yearly": g[4]}})
            })
            .collect(),
    )
}

/// Policy ids assigned to `tenant`.
pub fn assigned(c: &Connection, tenant: &str) -> rusqlite::Result<Vec<i64>> {
    c.prepare("SELECT policy_id FROM tenant_policies WHERE tenant = ?1 ORDER BY policy_id")?
        .query_map([tenant], |r| r.get(0))?
        .collect()
}

pub fn is_assigned(c: &Connection, tenant: &str, policy_id: i64) -> rusqlite::Result<bool> {
    Ok(c.query_row(
        "SELECT 1 FROM tenant_policies WHERE tenant = ?1 AND policy_id = ?2",
        params![tenant, policy_id],
        |_| Ok(()),
    )
    .optional()?
    .is_some())
}

/// Replaces the assignments of `tenant`.
pub fn assign(c: &Connection, tenant: &str, ids: &[i64]) -> rusqlite::Result<()> {
    c.execute("DELETE FROM tenant_policies WHERE tenant = ?1", [tenant])?;
    for id in ids {
        c.execute(
            "INSERT OR IGNORE INTO tenant_policies (tenant, policy_id) VALUES (?1, ?2)",
            params![tenant, id],
        )?;
    }
    Ok(())
}

/// The tenant's immutable uid (v25; `None` for unknown tenants).
pub fn uid(c: &Connection, tenant: &str) -> rusqlite::Result<Option<String>> {
    Ok(
        c.query_row("SELECT uid FROM tenants WHERE name = ?1", [tenant], |r| r.get(0))
            .optional()?
            .flatten(),
    )
}

/// Whether a tenant of this name existed before (deleted names are never reused).
pub fn tombstoned(c: &Connection, name: &str) -> rusqlite::Result<bool> {
    Ok(
        c.query_row("SELECT 1 FROM tenant_tombstones WHERE name = ?1", [name], |_| Ok(()))
            .optional()?
            .is_some(),
    )
}

/// Records a deleted tenant (call before deleting its row, in the same transaction).
pub fn bury(c: &Connection, name: &str, by: &str) -> rusqlite::Result<()> {
    c.execute(
        "INSERT OR REPLACE INTO tenant_tombstones (name, uid, deleted_at, deleted_by)
         SELECT name, uid, ?2, ?3 FROM tenants WHERE name = ?1",
        params![name, crate::now(), by],
    )?;
    c.execute("DELETE FROM tenant_policies WHERE tenant = ?1", [name])?;
    Ok(())
}

/// The tenant an audit entry concerns, if any: the impersonated tenant of the
/// actor, `details.tenant` (also of quorum params / targets inside details), or
/// the target (`tenant/<t>`, `snapshot/<t>/…`, or the tenant of the source,
/// group, agent, user, job or quorum request it names).
pub fn audit_tenant(c: &Connection, actor: &str, target: &str, details: &str) -> rusqlite::Result<Option<String>> {
    if let Some((_, t)) = actor.split_once(IMPERSONATING) {
        return Ok(Some(t.to_owned()));
    }
    let d: Value = serde_json::from_str(details).unwrap_or_default();
    for v in [&d["tenant"], &d["params"]["tenant"], &d["user"]["tenant"]] {
        if let Some(t) = v.as_str() {
            return Ok(Some(t.to_owned()));
        }
    }
    if let Some(t) = target_tenant(c, target)? {
        return Ok(Some(t));
    }
    match d["target"].as_str() {
        Some(t) => target_tenant(c, t),
        None => Ok(None),
    }
}

fn target_tenant(c: &Connection, target: &str) -> rusqlite::Result<Option<String>> {
    let mut parts = target.splitn(3, '/');
    let (Some(kind), Some(id)) = (parts.next(), parts.next()) else {
        return Ok(None);
    };
    let sql = match kind {
        "tenant" | "snapshot" => return Ok(Some(id.to_owned())),
        "source" => "SELECT tenant FROM sources WHERE id = ?1",
        "group" => "SELECT tenant FROM groups WHERE id = ?1",
        "agent" => "SELECT tenant FROM agents WHERE id = ?1",
        "job" => "SELECT tenant FROM jobs WHERE id = ?1",
        "user" => "SELECT tenant FROM users WHERE name = ?1",
        "quorum" => "SELECT json_extract(params, '$.tenant') FROM quorum WHERE id = ?1 AND json_valid(params)",
        _ => return Ok(None),
    };
    Ok(c.query_row(sql, [id], |r| r.get::<_, Option<String>>(0))
        .optional()?
        .flatten())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Catalog;

    #[test]
    fn audit_tenants_and_tombstones() {
        let cat = Catalog::open_memory().unwrap();
        {
            let c = cat.conn();
            c.execute_batch(
                "INSERT INTO tenants (name) VALUES ('acme'), ('globex');
                 INSERT INTO sources (id, tenant, kind, name, config) VALUES (3, 'acme', 'pve', 'pve', '{}');
                 INSERT INTO users (name, password_hash, totp_secret, role, tenant, created)
                   VALUES ('tina', 'x', '', 'tenant_user', 'globex', 0);",
            )
            .unwrap();
            let a = uid(&c, "acme").unwrap().unwrap();
            assert_eq!(a.len(), 32);
            assert_ne!(Some(a.clone()), uid(&c, "globex").unwrap());
            assert!(c
                .execute("UPDATE tenants SET uid = 'x' WHERE name = 'acme'", [])
                .is_err());
            assert!(c
                .execute("UPDATE tenants SET name = 'acme2' WHERE name = 'acme'", [])
                .is_err());
            c.execute("UPDATE tenants SET offsite = '{}' WHERE name = 'acme'", [])
                .unwrap();
            bury(&c, "globex", "alice").unwrap();
            assert!(tombstoned(&c, "globex").unwrap() && !tombstoned(&c, "acme").unwrap());
        }
        let cases = [
            ("alice", "source/3", json!({}), Some("acme")),
            ("alice", "user/tina", json!({}), Some("globex")),
            ("alice", "x/1", json!({"tenant": "globex"}), Some("globex")),
            ("alice", "quorum/9", json!({"params": {"tenant": "acme"}}), Some("acme")),
            ("alice impersonating:acme", "auth/me", json!({}), Some("acme")),
            ("alice", "tenant/acme/recovery-key", json!({}), Some("acme")),
            ("alice", "settings/x", json!({}), None),
        ];
        let n = cases.len() as i64;
        for (actor, target, d, want) in cases {
            let seq = cat.audit(actor, "a", target, &d).unwrap();
            let got: Option<String> = cat
                .conn()
                .query_row("SELECT tenant FROM audit_tenants WHERE seq = ?1", [seq], |r| r.get(0))
                .optional()
                .unwrap();
            assert_eq!(got.as_deref(), want, "{actor} {target}");
        }
        assert_eq!(cat.verify_audit().unwrap(), n);
    }
}
