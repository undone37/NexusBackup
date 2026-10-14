//! Tenant-side approvers (Phase 33, `catalog::approvers`): every account that
//! becomes an approver of a tenant requiring its own approval (a tenant admin
//! created, activated, re-enabled or moved there after the tenant opted in)
//! raises `tenant_approver` once, during its 24-hour wait, so the tenant and
//! the provider can object before it may decide.

use crate::Scheduler;
use anyhow::Result;
use catalog::approvers::{ALERT_KIND, WAIT_SECS};
use catalog::rusqlite::params;

/// Accounts that became approvers longer ago than this are not reported any more.
const LOOKBACK_SECS: i64 = 7 * 86400;

impl Scheduler {
    pub(crate) fn check_tenant_approvers(&self, now: i64) -> Result<()> {
        let rows: Vec<(i64, String, String, i64)> = {
            let c = self.db.conn();
            let mut q = c.prepare(
                "SELECT u.id, u.name, u.tenant, COALESCE(u.approver_since, u.created) FROM users u
                 JOIN tenant_approvals a ON a.tenant = u.tenant
                 WHERE u.role = 'tenant_admin' AND u.disabled = 0 AND u.activation_hash IS NULL
                   AND COALESCE(u.approver_since, u.created) >= a.enabled_at
                   AND COALESCE(u.approver_since, u.created) > ?1
                   AND NOT EXISTS (SELECT 1 FROM alerts x WHERE x.kind = ?2
                     AND x.key = 'tenant_approver:' || u.tenant || ':' || u.id || ':'
                       || COALESCE(u.approver_since, u.created))",
            )?;
            let rows = q.query_map(params![now - LOOKBACK_SECS, ALERT_KIND], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
            })?;
            rows.collect::<std::result::Result<_, _>>()?
        };
        for (id, name, tenant, since) in rows {
            self.raise(
                "warning",
                ALERT_KIND,
                &format!("{ALERT_KIND}:{tenant}:{id}:{since}"),
                &format!(
                    "account {name} becomes a tenant-side approver of tenant {tenant}: it may approve deletions and \
                     weakening changes of the tenant's backups from {} (unix time, 24 hours after it became a tenant \
                     admin, was activated or re-enabled)",
                    since + WAIT_SECS
                ),
                Some(&tenant),
            )?;
        }
        Ok(())
    }
}
