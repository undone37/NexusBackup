//! Break-glass (docs/phase12-contract.md §7): `nexus-setup recover-admin` on the
//! console (root) when the sole administrator lost the password or authenticator.
//!
//! Requires the recovery key (checked against keyd's escrow exactly as at setup).
//! The chosen local admin account is reset to "pending activation" with a new
//! one-time activation code (printed once; the person enrolls a new password and
//! authenticator in the web UI). With approvals enabled and at least two possible
//! approvers the console path is refused (the other approver can issue a code in
//! the UI) unless `--force-solo`, which is recorded.
//!
//! Audited `user.break_glass` (actor `console`), critical alert `break_glass`, and
//! the setting `break_glass` (`{at, user, alert, forced_solo}`) that keeps the
//! banner in the web UI until an admin or security officer acknowledges the alert.

use crate::Paths;
use anyhow::{bail, Context, Result};
use catalog::rusqlite::{params, OptionalExtension};
use catalog::Catalog;
use serde_json::json;
use sha2::{Digest, Sha256};

pub const ACTOR: &str = "console";
/// as for codes issued in the web UI
pub const ACTIVATION_SECS: i64 = 72 * 3600;

pub struct Recovered {
    pub user: String,
    pub code: String,
    pub expires: i64,
    pub forced_solo: bool,
}

/// Resets the admin account; `recovery_key` as printed at first boot.
pub fn recover_admin(paths: &Paths, user: Option<&str>, force_solo: bool, recovery_key: &str) -> Result<Recovered> {
    if !paths.setup_done.exists() {
        bail!("the appliance is not set up yet: run nexus-setup (first boot) instead");
    }
    keyd::check_recovery_key(&paths.keyd_dir, recovery_key.trim())
        .map_err(|e| anyhow::anyhow!("recovery key rejected: {e}"))?;
    let cat = Catalog::open(&paths.catalog).with_context(|| format!("opening {}", paths.catalog.display()))?;
    let admins: Vec<String> = cat
        .conn()
        .prepare("SELECT name FROM users WHERE role = 'admin' AND auth = 'local' ORDER BY name")?
        .query_map([], |r| r.get(0))?
        .collect::<Result<_, _>>()?;
    let name = match user {
        Some(u) if admins.iter().any(|a| a == u) => u.to_owned(),
        Some(u) => bail!(
            "{u:?} is not a local admin account (local admins: {})",
            admins.join(", ")
        ),
        None if admins.len() == 1 => admins[0].clone(),
        None if admins.is_empty() => bail!("there is no local admin account"),
        None => bail!(
            "several local admin accounts exist ({}): choose one with --user NAME",
            admins.join(", ")
        ),
    };
    let (approvals, approvers) = {
        let c = cat.conn();
        (catalog::approvals_enabled(&c)?, catalog::possible_approvers(&c)?)
    };
    let forced_solo = approvals && approvers.len() >= 2;
    if forced_solo && !force_solo {
        bail!(
            "approvals are enabled and {} people can approve ({}): let another admin or security officer issue a \
             new activation code in the web UI (Users), or repeat with --force-solo (recorded and alerted)",
            approvers.len(),
            approvers.join(", ")
        );
    }
    let code = catalog::auth::new_code();
    let digest: String = Sha256::digest(code.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let now = catalog::now();
    let expires = now + ACTIVATION_SECS;
    let alert = {
        let mut c = cat.conn();
        let tx = c.transaction()?;
        let id: i64 = tx
            .query_row("SELECT id FROM users WHERE name = ?1", [&name], |r| r.get(0))
            .optional()?
            .context("account vanished")?;
        // old password and authenticator stop working now; the account is enabled
        // again so that its owner can activate it
        tx.execute(
            "UPDATE users SET password_hash = ?2, totp_secret = '', activation_hash = ?3, activation_expires = ?4,
             disabled = 0 WHERE id = ?1",
            params![id, catalog::NO_PASSWORD, digest, expires],
        )?;
        tx.execute("DELETE FROM sessions WHERE user_id = ?1", [id])?;
        let msg = format!(
            "break-glass: admin account {name} was reset at the console with the recovery key{}; \
             verify with its owner that this was intended",
            if forced_solo {
                " (--force-solo: approvals were enabled with two or more approvers)"
            } else {
                ""
            }
        );
        tx.execute(
            "INSERT INTO alerts (ts, severity, kind, message) VALUES (?1, 'critical', 'break_glass', ?2)",
            params![now, msg],
        )?;
        let alert = tx.last_insert_rowid();
        catalog::set_setting(
            &tx,
            "break_glass",
            &json!({"at": now, "user": name, "alert": alert, "forced_solo": forced_solo}).to_string(),
        )?;
        tx.commit()?;
        alert
    };
    cat.audit(
        ACTOR,
        "user.break_glass",
        &format!("user/{name}"),
        &json!({"forced_solo": forced_solo, "approvals_enabled": approvals, "alert": alert,
                "activation_expires": expires}),
    )?;
    Ok(Recovered {
        user: name,
        code,
        expires,
        forced_solo,
    })
}

/// `nexus-setup reset-mgmt-allow` (Phase 14d): someone locked themselves out
/// with the management allow-list (Settings → Security). Clears the setting
/// (empty = any address), audited `security.mgmt_allow_reset` (actor
/// `console`) with a warning alert; returns the list that was removed. The
/// caller also opens the firewall sets at once ([`open_mgmt_firewall`]); the
/// scheduler rewrites the firewall file on its next tick either way.
pub fn reset_mgmt_allow(paths: &Paths) -> Result<Vec<String>> {
    if !paths.setup_done.exists() {
        bail!("the appliance is not set up yet: there is no allow-list to reset");
    }
    let cat = Catalog::open(&paths.catalog).with_context(|| format!("opening {}", paths.catalog.display()))?;
    let old = {
        let mut c = cat.conn();
        let tx = c.transaction()?;
        let old = catalog::access::mgmt_allow(&tx)?;
        catalog::set_setting(&tx, catalog::access::MGMT_ALLOW, "[]")?;
        tx.execute(
            "INSERT INTO alerts (ts, last_ts, severity, kind, key, message) VALUES (?1, ?1, 'warning', 'mgmt_allow_reset',
             'mgmt_allow_reset', ?2)",
            params![
                catalog::now(),
                format!(
                    "the management allow-list ({}) was cleared at the console: the web UI is reachable from any address again",
                    if old.is_empty() { "empty".to_owned() } else { old.join(", ") }
                )
            ],
        )?;
        tx.commit()?;
        old
    };
    cat.audit(
        ACTOR,
        "security.mgmt_allow_reset",
        "settings/mgmt_allow",
        &json!({"old": old}),
    )?;
    Ok(old)
}

/// Opens `mgmt_allowed_v4/v6` to any address right away (root, real appliance).
pub fn open_mgmt_firewall(nft: &std::path::Path) -> Result<()> {
    nftsync::apply(nft, &nftsync::script(None, &nftsync::mgmt_state(&[])))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn appliance() -> (tempfile::TempDir, Paths, String) {
        let d = tempfile::tempdir().unwrap();
        let paths = Paths::under(d.path());
        std::fs::create_dir_all(&paths.keyd_dir).unwrap();
        std::fs::create_dir_all(paths.catalog.parent().unwrap()).unwrap();
        let rk = keyd::init(&paths.keyd_dir).unwrap();
        std::fs::write(&paths.setup_done, "").unwrap();
        let cat = Catalog::open(&paths.catalog).unwrap();
        cat.conn()
            .execute_batch(
                "INSERT INTO users (name, password_hash, totp_secret, role, created) VALUES ('root-admin', 'h', 'enc:v1:x', 'admin', 1);
                 INSERT INTO users (name, password_hash, totp_secret, role, created) VALUES ('op', 'h', 's', 'operator', 1);
                 INSERT INTO sessions (id_hash, user_id, csrf, created, last_seen) VALUES ('s', 1, 'c', 1, 1);
                 INSERT INTO settings (key, value) VALUES ('approvals_enabled', 'false')
                   ON CONFLICT(key) DO UPDATE SET value = excluded.value;",
            )
            .unwrap();
        (d, paths, rk)
    }

    #[test]
    fn resets_the_sole_admin_with_the_recovery_key() {
        let (_d, paths, rk) = appliance();
        let wrong = keyd::format_recovery_key(&[9; 32]);
        assert!(recover_admin(&paths, None, false, &wrong)
            .err()
            .unwrap()
            .to_string()
            .contains("recovery key rejected"));
        assert!(
            recover_admin(&paths, Some("op"), false, &rk).is_err(),
            "operators are not admins"
        );
        let r = recover_admin(&paths, None, false, &format!(" {rk}\n")).unwrap();
        assert_eq!(
            (r.user.as_str(), r.forced_solo, r.code.len()),
            ("root-admin", false, 26)
        );
        let cat = Catalog::open(&paths.catalog).unwrap();
        let c = cat.conn();
        let (pw, seed, act, disabled): (String, String, String, i64) = c
            .query_row(
                "SELECT password_hash, totp_secret, activation_hash, disabled FROM users WHERE name = 'root-admin'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .unwrap();
        assert_eq!((pw.as_str(), seed.as_str(), disabled), (catalog::NO_PASSWORD, "", 0));
        let digest: String = Sha256::digest(r.code.as_bytes())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(act, digest);
        let sessions: i64 = c.query_row("SELECT COUNT(*) FROM sessions", [], |r| r.get(0)).unwrap();
        assert_eq!(sessions, 0);
        let bg: serde_json::Value =
            serde_json::from_str(&catalog::setting(&c, "break_glass").unwrap().unwrap()).unwrap();
        assert_eq!(bg["user"], "root-admin");
        let kind: String = c
            .query_row(
                "SELECT kind FROM alerts WHERE id = ?1",
                [bg["alert"].as_i64().unwrap()],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(kind, "break_glass");
        drop(c);
        let n: i64 = cat
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM audit WHERE action = 'user.break_glass'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(n, 1);
        assert!(cat.verify_audit().is_ok());
    }

    #[test]
    fn resets_the_management_allow_list() {
        let (_d, paths, _rk) = appliance();
        catalog::set_setting(
            &Catalog::open(&paths.catalog).unwrap().conn(),
            catalog::access::MGMT_ALLOW,
            r#"["192.0.2.0/24"]"#,
        )
        .unwrap();
        assert_eq!(reset_mgmt_allow(&paths).unwrap(), vec!["192.0.2.0/24"]);
        let cat = Catalog::open(&paths.catalog).unwrap();
        assert!(catalog::access::mgmt_allow(&cat.conn()).unwrap().is_empty());
        let n: i64 = cat
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM audit WHERE action = 'security.mgmt_allow_reset' AND actor = 'console'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(n, 1);
        let kind: String = cat
            .conn()
            .query_row("SELECT kind FROM alerts ORDER BY id DESC LIMIT 1", [], |r| r.get(0))
            .unwrap();
        assert_eq!(kind, "mgmt_allow_reset");
    }

    #[test]
    fn refuses_with_two_approvers_unless_forced() {
        let (_d, paths, rk) = appliance();
        {
            let cat = Catalog::open(&paths.catalog).unwrap();
            cat.conn()
                .execute_batch(
                    "INSERT INTO users (name, password_hash, totp_secret, role, created) VALUES ('so', 'h', 's', 'security_officer', 1);
                     INSERT INTO users (name, password_hash, totp_secret, role, created) VALUES ('second', 'h', 's', 'admin', 1);
                     UPDATE settings SET value = 'true' WHERE key = 'approvals_enabled';",
                )
                .unwrap();
        }
        let e = recover_admin(&paths, Some("root-admin"), false, &rk)
            .err()
            .unwrap()
            .to_string();
        assert!(e.contains("--force-solo"), "{e}");
        assert!(recover_admin(&paths, None, false, &rk)
            .err()
            .unwrap()
            .to_string()
            .contains("--user"));
        let r = recover_admin(&paths, Some("root-admin"), true, &rk).unwrap();
        assert!(r.forced_solo);
    }
}
