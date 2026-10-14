//! Account housekeeping (Phase 14d, docs/control-plane.md "Access"): sessions
//! of expired accounts end (the web-api also refuses them on the next request),
//! and with setting `dormant_days` (0 = off, the default) accounts that have not
//! logged in for that many days are disabled: audited `user.dormant_disabled`,
//! info alert `account_dormant`. Never disabled: the last enabled local admin
//! (console recovery and every config change need one), and, with approvals
//! enabled, an admin or security officer whose loss would leave fewer than two
//! possible approvers (nobody could approve re-enabling anyone). Pending
//! activations are not dormant (their code expires on its own).
//!
//! Phase 30: the info alerts of just-in-time elevations that ended without a
//! request (expired, session gone) are resolved (catalog::elevation).

use crate::{Scheduler, ACTOR};
use anyhow::Result;
use serde_json::json;

const DAY: i64 = 86400;

impl Scheduler {
    pub(crate) fn check_accounts(&self, now: i64) -> Result<()> {
        let (ended, days) = {
            let c = self.db.conn();
            let n = c.execute(
                "DELETE FROM sessions WHERE user_id IN (SELECT id FROM users WHERE expires IS NOT NULL AND expires <= ?1)",
                [now],
            )?;
            catalog::elevation::resolve_ended(&c, ACTOR)?;
            (n, catalog::access::dormant_days(&c)?)
        };
        if ended > 0 {
            eprintln!("scheduler: ended {ended} sessions of expired accounts");
        }
        if days == 0 {
            return Ok(());
        }
        let cutoff = now - days * DAY;
        let dormant: Vec<(i64, String, String, i64)> = {
            let c = self.db.conn();
            let mut q = c.prepare(
                "SELECT id, name, role, COALESCE(last_login, created) FROM users
                 WHERE disabled = 0 AND activation_hash IS NULL AND COALESCE(last_login, created) < ?1
                   AND (expires IS NULL OR expires > ?2)
                 ORDER BY COALESCE(last_login, created), id",
            )?;
            let rows = q.query_map([cutoff, now], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?;
            rows.collect::<Result<_, _>>()?
        };
        for (id, name, role, last) in dormant {
            let disabled = {
                let mut c = self.db.conn();
                let tx = c.transaction()?;
                let other_admins: i64 = tx.query_row(
                    "SELECT COUNT(*) FROM users WHERE role = 'admin' AND auth = 'local' AND disabled = 0
                     AND activation_hash IS NULL AND id != ?1",
                    [id],
                    |r| r.get(0),
                )?;
                let approvers = catalog::possible_approvers(&tx)?;
                let keep = (role == "admin" && other_admins == 0)
                    || (catalog::approvals_enabled(&tx)? && approvers.contains(&name) && approvers.len() <= 2);
                if keep {
                    false
                } else {
                    tx.execute("UPDATE users SET disabled = 1 WHERE id = ?1", [id])?;
                    tx.execute("DELETE FROM sessions WHERE user_id = ?1", [id])?;
                    tx.commit()?;
                    true
                }
            };
            if !disabled {
                continue;
            }
            self.db.audit(
                ACTOR,
                "user.dormant_disabled",
                &format!("user/{name}"),
                &json!({"role": role, "last_login": last, "dormant_days": days}),
            )?;
            self.raise(
                "info",
                "account_dormant",
                &format!("account_dormant:{name}"),
                &format!(
                    "account {name} ({role}) was disabled: no login for more than {days} days; an admin re-enables it on the Users page"
                ),
                None,
            )?;
        }
        Ok(())
    }
}
