//! Just-in-time role elevation (Phase 30, catalog v45, docs/control-plane.md
//! "Role elevation"): an appliance-wide local account with a standing lower
//! role (operator or viewer) may hold an *eligible* role (admin or security
//! officer). One of its sessions acts in that role for 15 minutes to 8 hours
//! after a re-authentication (password + TOTP or passkey) and, when the setting
//! asks for it, an approval (`role.elevate`); it ends at expiry, at sign-out or
//! when the account changes. Each elevation raises an info `role_elevation`
//! alert (resolved when it ends).

use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};

/// Approval action of an elevation (when the setting requires one).
pub const ACTION: &str = "role.elevate";
/// Approval action that switches the approval requirement off (a weakening).
pub const SETTING_ACTION: &str = "security.elevation";
pub const SETTING: &str = "elevation";
pub const ALERT_KIND: &str = "role_elevation";
pub const MIN_MINUTES: i64 = 15;
pub const MAX_MINUTES: i64 = 480;
/// Standing roles that may hold an eligible role.
pub const STANDING: &[&str] = &["operator", "viewer"];
/// Roles an account may be eligible for.
pub const ELIGIBLE: &[&str] = &["admin", "security_officer"];

/// Setting `elevation`.
#[derive(Deserialize, Serialize, Debug, Clone, PartialEq, Default)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    /// every elevation needs a second person (`role.elevate`)
    pub approval: bool,
}

pub fn settings(c: &Connection) -> rusqlite::Result<Settings> {
    Ok(crate::setting(c, SETTING)?
        .and_then(|v| serde_json::from_str(&v).ok())
        .unwrap_or_default())
}

/// Whether an account (standing role, tenant, sign-in method) may hold an
/// eligible role: appliance-wide local operators and viewers only.
pub fn can_hold(standing: &str, tenant: Option<&str>, auth: &str) -> bool {
    STANDING.contains(&standing) && tenant.is_none() && auth == "local"
}

/// The elevation a session may act in now: `(role, until)` when it is set,
/// not expired and still matches the account's eligible role.
pub fn effective(
    standing: &str,
    eligible: Option<&str>,
    elevated: Option<&str>,
    until: Option<i64>,
    now: i64,
) -> Option<(String, i64)> {
    let (role, until) = (elevated?, until?);
    (until > now && eligible == Some(role) && STANDING.contains(&standing)).then(|| (role.to_owned(), until))
}

/// Starts an elevation on session `session_id` of `user_id` (the session must
/// still exist) and raises the info alert. Returns the end time.
pub fn start(
    c: &Connection,
    session_id: i64,
    user_id: i64,
    role: &str,
    minutes: i64,
    reason: &str,
) -> rusqlite::Result<Option<i64>> {
    let now = crate::now();
    let until = now + minutes * 60;
    let row: Option<(String, String)> = c
        .query_row(
            "SELECT name, role FROM users WHERE id = ?1 AND eligible_role = ?2 AND disabled = 0",
            params![user_id, role],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let Some((name, standing)) = row else {
        return Ok(None);
    };
    let n = c.execute(
        "UPDATE sessions SET elevated_role = ?3, elevated_until = ?4 WHERE id = ?1 AND user_id = ?2",
        params![session_id, user_id, role, until],
    )?;
    if n != 1 {
        return Ok(None);
    }
    let key = format!("{ALERT_KIND}:{user_id}:{session_id}");
    let msg = format!(
        "account {name} ({standing}) elevated to {role} for {minutes} min (until {:02}:{:02} UTC): {reason}",
        until.rem_euclid(86_400) / 3600,
        until.rem_euclid(3600) / 60
    );
    let open = c.execute(
        "UPDATE alerts SET last_ts = ?2, message = ?3, count = count + 1 WHERE key = ?1 AND resolved_at IS NULL",
        params![key, now, msg],
    )?;
    if open == 0 {
        c.execute(
            "INSERT INTO alerts (ts, last_ts, severity, kind, key, message) VALUES (?1, ?1, 'info', ?2, ?3, ?4)",
            params![now, ALERT_KIND, key, msg],
        )?;
    }
    Ok(Some(until))
}

/// Ends the elevation of a session (if any) and resolves its alert.
pub fn end(c: &Connection, session_id: i64, user_id: i64, by: &str) -> rusqlite::Result<bool> {
    let n = c.execute(
        "UPDATE sessions SET elevated_role = NULL, elevated_until = NULL WHERE id = ?1 AND elevated_role IS NOT NULL",
        [session_id],
    )?;
    resolve(c, &format!("{ALERT_KIND}:{user_id}:{session_id}"), by)?;
    Ok(n == 1)
}

fn resolve(c: &Connection, key: &str, by: &str) -> rusqlite::Result<()> {
    c.execute(
        "UPDATE alerts SET resolved_at = ?2, resolved_by = ?3, auto = 1 WHERE key = ?1 AND resolved_at IS NULL",
        params![key, crate::now(), by],
    )?;
    Ok(())
}

/// Housekeeping (scheduler): resolves the alerts of elevations that ended
/// without a request (expired, session gone). Returns how many.
pub fn resolve_ended(c: &Connection, by: &str) -> rusqlite::Result<usize> {
    c.execute(
        "UPDATE alerts SET resolved_at = ?1, resolved_by = ?2, auto = 1
         WHERE kind = ?3 AND resolved_at IS NULL AND key NOT IN (
           SELECT ?3 || ':' || user_id || ':' || id FROM sessions WHERE elevated_until > ?1)",
        params![crate::now(), by, ALERT_KIND],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn effective_rules() {
        let now = 1000;
        assert_eq!(
            effective("operator", Some("admin"), Some("admin"), Some(1060), now),
            Some(("admin".into(), 1060))
        );
        // expired, eligibility gone or changed, standing role no longer lower
        assert_eq!(
            effective("operator", Some("admin"), Some("admin"), Some(1000), now),
            None
        );
        assert_eq!(effective("operator", None, Some("admin"), Some(1060), now), None);
        assert_eq!(
            effective("operator", Some("security_officer"), Some("admin"), Some(1060), now),
            None
        );
        assert_eq!(effective("admin", Some("admin"), Some("admin"), Some(1060), now), None);
        assert_eq!(effective("viewer", Some("admin"), None, None, now), None);
        assert!(can_hold("viewer", None, "local"));
        assert!(!can_hold("tenant_admin", Some("acme"), "local"));
        assert!(!can_hold("operator", None, "oidc"));
        assert!(!can_hold("operator", Some("acme"), "local"));
    }

    #[test]
    fn start_end_and_alerts() {
        let cat = crate::Catalog::open_memory().unwrap();
        let c = cat.conn();
        c.execute_batch(
            "INSERT INTO users (id, name, password_hash, totp_secret, role, created, eligible_role)
               VALUES (1, 'bob', 'x', 'y', 'operator', 1, 'admin'), (2, 'eve', 'x', 'y', 'operator', 1, NULL);
             INSERT INTO sessions (id, id_hash, user_id, csrf, created, last_seen) VALUES (7, 'h7', 1, 'c', 1, 1),
               (8, 'h8', 2, 'c', 1, 1), (9, 'h9', 1, 'c', 1, 1);",
        )
        .unwrap();
        let until = start(&c, 7, 1, "admin", 30, "patching").unwrap().unwrap();
        assert!(until > crate::now() + 29 * 60);
        let (sev, msg): (String, String) = c
            .query_row(
                "SELECT severity, message FROM alerts WHERE key = 'role_elevation:1:7'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(sev, "info");
        assert!(
            msg.starts_with("account bob (operator) elevated to admin for 30 min"),
            "{msg}"
        );
        // not eligible, other role, another user's session
        assert_eq!(start(&c, 8, 2, "admin", 30, "x").unwrap(), None);
        assert_eq!(start(&c, 9, 1, "security_officer", 30, "x").unwrap(), None);
        assert_eq!(start(&c, 8, 1, "admin", 30, "x").unwrap(), None);
        // a second session elevated, then expired: housekeeping resolves its alert only
        start(&c, 9, 1, "admin", 30, "x").unwrap().unwrap();
        c.execute("UPDATE sessions SET elevated_until = 5 WHERE id = 9", [])
            .unwrap();
        assert_eq!(resolve_ended(&c, "scheduler").unwrap(), 1);
        assert!(end(&c, 7, 1, "bob").unwrap());
        assert!(!end(&c, 7, 1, "bob").unwrap());
        let open: i64 = c
            .query_row("SELECT COUNT(*) FROM alerts WHERE resolved_at IS NULL", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(open, 0);
    }
}
