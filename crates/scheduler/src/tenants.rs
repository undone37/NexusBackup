//! Deactivated tenants (catalog v22, Phase 17f): no scheduled or chained
//! backups, offsite copies or replication syncs, queued ones fail unstarted;
//! retention, GC and verify keep running. Their alerts are suppressed
//! (`raise`), except one info `tenant_disabled` per tenant, resolved on
//! reactivation.

use crate::Scheduler;
use anyhow::{bail, Result};
use catalog::tenants::{all_disabled, ALERT_KIND};
use std::collections::HashSet;

/// Job kinds a deactivated tenant does not run (as web-api `tenants::PAUSED_KINDS`).
const PAUSED_KINDS: &[&str] = &["backup", "plugin_backup", "offsite", "replica_sync"];

fn key(tenant: &str) -> String {
    format!("{ALERT_KIND}:{tenant}")
}

impl Scheduler {
    pub(crate) fn disabled_tenants(&self) -> Result<HashSet<String>> {
        Ok(all_disabled(&self.db.conn())?)
    }

    /// Refuses (unstartable) a paused job kind of a deactivated tenant.
    pub(crate) fn refuse_disabled(&self, tenant: &str, kind: &str) -> Result<()> {
        if PAUSED_KINDS.contains(&kind) && catalog::tenants::disabled(&self.db.conn(), tenant)? {
            bail!("tenant {tenant} is deactivated: no {kind} jobs until it is reactivated");
        }
        Ok(())
    }

    /// One info alert per deactivated tenant; resolved once it is active again.
    pub(crate) fn check_disabled_tenants(&self) -> Result<()> {
        let off = self.disabled_tenants()?;
        for t in &off {
            self.raise(
                "info",
                ALERT_KIND,
                &key(t),
                &format!(
                    "tenant {t} is deactivated: no backups, offsite copies or replication; its alerts are suppressed"
                ),
                Some(t),
            )?;
        }
        let open: Vec<String> = {
            let c = self.db.conn();
            let mut st =
                c.prepare("SELECT tenant FROM alerts WHERE kind = ?1 AND resolved_at IS NULL AND tenant IS NOT NULL")?;
            let rows = st.query_map([ALERT_KIND], |r| r.get(0))?;
            rows.collect::<std::result::Result<_, _>>()?
        };
        for t in open.iter().filter(|t| !off.contains(*t)) {
            self.resolve(&key(t))?;
        }
        Ok(())
    }
}
