//! Legal holds on a replication secondary (Phase 15c, docs/replication.md §7):
//! the primary's active holds come with every `replica_sync` report. They are
//! advisory here: stored as `advisory` rows with a `legal_hold_advisory`
//! warning, never applied automatically; a security officer applies one with a
//! click (web-api `POST /snapshots/…/hold`). An advisory the primary no longer
//! reports is `withdrawn` and its alert resolved. (Enforcement of applied holds:
//! `Plan::held`, read when a job is planned.)

use super::*;
use catalog::holds::{advisory_key, ADVISORY_KIND};

impl Scheduler {
    /// Syncs the advisories of `origin` for `tenant` with the primary's list.
    /// Only snapshots this appliance has (catalog row or just `imported`) get one.
    pub(crate) fn hold_advisories(
        &self,
        tenant: &str,
        origin: &str,
        holds: &[replication::HoldInfo],
        imported: &[String],
    ) -> Result<()> {
        let open: Vec<(i64, String, i64)> = {
            let c = self.db.conn();
            let mut st = c.prepare(
                "SELECT id, source, time FROM legal_holds WHERE tenant=?1 AND origin=?2 AND state='advisory'",
            )?;
            let rows = st.query_map(params![tenant, origin], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
            rows.collect::<std::result::Result<_, _>>()?
        };
        for (id, source, time) in open {
            if holds.iter().any(|h| h.source == source && h.time as i64 == time) {
                continue;
            }
            self.db.conn().execute(
                "UPDATE legal_holds SET state='withdrawn', released_at=?2 WHERE id=?1 AND state='advisory'",
                params![id, catalog::now()],
            )?;
            self.db.audit(
                ACTOR,
                "snapshot.hold_withdrawn",
                &format!("snapshot/{tenant}/{source}/{time}"),
                &json!({"origin": origin, "hold_id": id}),
            )?;
            self.resolve(&advisory_key(tenant, &source, time as u64))?;
        }
        for h in holds {
            let time = h.time as i64;
            let (present, has_open): (bool, bool) = self.db.conn().query_row(
                "SELECT EXISTS (SELECT 1 FROM snapshots WHERE tenant=?1 AND source=?2 AND time=?3),
                        EXISTS (SELECT 1 FROM legal_holds WHERE tenant=?1 AND source=?2 AND time=?3
                                AND state IN ('active','advisory'))",
                params![tenant, h.source, time],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?;
            if has_open || !(present || imported.contains(&format!("{}/{}", h.source, h.time))) {
                continue;
            }
            self.db.conn().execute(
                "INSERT INTO legal_holds (tenant, source, time, state, reason, held_by, held_at, origin)
                 VALUES (?1,?2,?3,'advisory',?4,?5,?6,?7)",
                params![tenant, h.source, time, h.reason, h.held_by, h.held_at, origin],
            )?;
            self.db.audit(
                ACTOR,
                "snapshot.hold_advisory",
                &format!("snapshot/{tenant}/{}/{}", h.source, h.time),
                &json!({"origin": origin, "reason": h.reason, "held_by": h.held_by}),
            )?;
            self.raise(
                "warning",
                ADVISORY_KIND,
                &advisory_key(tenant, &h.source, h.time),
                &format!(
                    "primary {origin} holds {tenant}/{}/{} under a legal hold ({}, set by {}); not applied here",
                    h.source, h.time, h.reason, h.held_by
                ),
                Some(tenant),
            )?;
        }
        Ok(())
    }
}
