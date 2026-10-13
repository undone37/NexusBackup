//! DEK rotation reminder (Phase 21b, docs/control-plane.md "Access"): with
//! setting `dek_rotation_days` (default 365, 0 = off) a tenant whose current
//! DEK is older gets the info alert `dek_rotation:<tenant>` pointing to the
//! rotation at the console (`keyd tenant-rotate`); a rotation resolves it.
//! keyd reports the version and when its file was written (`dek-age`).
//! Replicated tenants are skipped (their keys are rotated on the primary).

use crate::Scheduler;
use anyhow::Result;

const DAY: i64 = 86400;

pub(crate) fn key(tenant: &str) -> String {
    format!("dek_rotation:{tenant}")
}

impl Scheduler {
    pub(crate) fn check_dek_rotation(&self, now: i64) -> Result<()> {
        let tenants: Vec<String> = {
            let c = self.db.conn();
            let mut q = c.prepare("SELECT name FROM tenants ORDER BY name")?;
            let rows = q.query_map([], |r| r.get(0))?;
            rows.collect::<Result<_, _>>()?
        };
        let replicated = self.replicated_tenants()?;
        let ages: Vec<(String, u32, i64)> = tenants
            .into_iter()
            .filter(|t| !replicated.contains_key(t))
            // keyd down (or tests without keyd): no reminder, no noise
            .filter_map(|t| keyd::request_dek_age(&self.cfg.keyd_socket, &t).ok().map(|(v, ts)| (t, v, ts)))
            .collect();
        self.dek_reminders(now, &ages)
    }

    /// Raises or resolves the reminder per `(tenant, current version, written at)`.
    pub(crate) fn dek_reminders(&self, now: i64, ages: &[(String, u32, i64)]) -> Result<()> {
        let days = catalog::access::dek_rotation_days(&self.db.conn())?;
        for (t, v, ts) in ages {
            let age = (now - ts) / DAY;
            if days > 0 && age >= days {
                self.raise(
                    "info",
                    "dek_rotation",
                    &key(t),
                    &format!(
                        "tenant {t}: data encryption key v{v} is {age} days old (rotation interval {days} days); \
                         rotate it at the console with keyd tenant-rotate"
                    ),
                    Some(t),
                )?;
            } else {
                self.resolve(&key(t))?;
            }
        }
        Ok(())
    }
}
