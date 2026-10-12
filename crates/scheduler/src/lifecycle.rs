//! Alert lifecycle (catalog v14, docs/phase13-18-plan.md §13f): the code that
//! detects a problem raises an alert under a key; a repeat while it is open
//! counts (`count`, `last_ts`) instead of adding a row, and is delivered again
//! only when its severity rises or after the reminder interval while nobody has
//! acknowledged it. The matching success path resolves it (`auto`). People
//! acknowledge (seen, still open) or resolve (closed) it in the web UI.
//! Resolved alerts are pruned after the retention per severity.

use crate::{alerts, Job, Scheduler, ACTOR};
use anyhow::Result;
use catalog::alerting;
use catalog::rusqlite::{params, OptionalExtension};
use serde_json::{json, Value};

/// Longest stored key (message-derived keys are cut).
const KEY_MAX: usize = 200;

/// `job_failed:<tenant>/<kind>/<target>`: the group, source, agent or
/// replication source of the job (plus the guest, if any). A later successful
/// run of the same job resolves it.
pub(crate) fn job_failed_key(job: &Job) -> String {
    let p = &job.params;
    let mut target = ["group_id", "source_id", "agent_id", "replication_source_id"]
        .iter()
        .find_map(|k| match &p[*k] {
            Value::Null => None,
            Value::String(s) => Some(format!("{}/{s}", k.trim_end_matches("_id"))),
            v => Some(format!("{}/{v}", k.trim_end_matches("_id"))),
        })
        .unwrap_or_else(|| "-".into());
    if let Some(s) = p["source"].as_str() {
        target = format!("{target}/{s}");
    }
    format!("job_failed:{}/{}/{target}", job.tenant, job.kind)
}

/// Appliance jobs (tenant `-`) raise alerts without a tenant.
pub(crate) fn tenant_of(job: &Job) -> Option<&str> {
    Some(job.tenant.as_str()).filter(|t| *t != "-")
}

impl Scheduler {
    /// Raises the alert `key`, or counts a repeat of the open one (message
    /// updated to the latest; a higher severity is delivered again).
    pub fn raise(&self, severity: &str, kind: &str, key: &str, message: &str, tenant: Option<&str>) -> Result<()> {
        let key: String = key.chars().take(KEY_MAX).collect();
        let now = catalog::now();
        let c = self.db.conn();
        let open: Option<(i64, String)> = c
            .query_row(
                "SELECT id, severity FROM alerts WHERE key = ?1 AND resolved_at IS NULL ORDER BY id DESC LIMIT 1",
                [&key],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        match open {
            Some((id, old)) => {
                let up = alerting::rank(severity) > alerting::rank(&old);
                c.execute(
                    "UPDATE alerts SET count = count + 1, last_ts = ?2, message = ?3,
                       severity = CASE WHEN ?4 THEN ?5 ELSE severity END,
                       notified_ts = CASE WHEN ?4 THEN NULL ELSE notified_ts END WHERE id = ?1",
                    params![id, now, message, up, severity],
                )?;
                if up {
                    eprintln!("<4>alert {id} escalated to {severity} {kind}: {message}");
                }
            }
            None => {
                c.execute(
                    "INSERT INTO alerts (ts, last_ts, severity, kind, key, message, tenant) VALUES (?1,?1,?2,?3,?4,?5,?6)",
                    params![now, severity, kind, key, message, tenant],
                )?;
                eprintln!("<4>alert {severity} {kind}: {message}");
            }
        }
        Ok(())
    }

    /// Closes the open alert `key` (the problem went away), audited.
    pub fn resolve(&self, key: &str) -> Result<()> {
        let id: Option<i64> = {
            let c = self.db.conn();
            let id = c
                .query_row(
                    "SELECT id FROM alerts WHERE key = ?1 AND resolved_at IS NULL",
                    [key],
                    |r| r.get(0),
                )
                .optional()?;
            if id.is_some() {
                c.execute(
                    "UPDATE alerts SET resolved_at = ?2, resolved_by = ?3, auto = 1 WHERE key = ?1 AND resolved_at IS NULL",
                    params![key, catalog::now(), ACTOR],
                )?;
            }
            id
        };
        if let Some(id) = id {
            eprintln!("alert {id} resolved: {key}");
            self.db.audit(
                ACTOR,
                "alert.resolve",
                &format!("alert/{id}"),
                &json!({"key": key, "auto": true}),
            )?;
        }
        Ok(())
    }

    /// A job finished ok: its own failure alert and what the job proves fixed
    /// (a verify, a clean offsite check, an approved large GC).
    pub(crate) fn resolve_after_ok(&self, job: &Job) -> Result<()> {
        self.resolve(&job_failed_key(job))?;
        let t = &job.tenant;
        match job.kind.as_str() {
            "verify" => self.resolve(&format!("verify:{t}")),
            "offsite" => self.resolve(&format!("inventory:{t}")),
            "gc" if job.params["approved"] == json!(true) => {
                self.resolve(&format!("gc_quorum:{t}"))?;
                self.resolve(&format!("gc_confirm:{t}"))
            }
            _ => Ok(()),
        }
    }

    /// Queues new and escalated alerts, and reminders of open unacknowledged
    /// ones, for delivery (`notified_ts` records it).
    pub(crate) fn deliver_alerts(&mut self) -> Result<()> {
        let now = catalog::now();
        let rows: Vec<alerts::Alert> = {
            let c = self.db.conn();
            let remind = alerting::reminder_hours(&c)? * 3600;
            let mut st = c.prepare(
                "SELECT id, ts, COALESCE(last_ts, ts), count, severity, kind, message, tenant FROM alerts
                 WHERE notified_ts IS NULL
                    OR (?1 > 0 AND resolved_at IS NULL AND acked_by IS NULL AND notified_ts <= ?2 - ?1)
                 ORDER BY id",
            )?;
            let rows = st.query_map(params![remind, now], |r| {
                let id = r.get(0)?;
                let kind: String = r.get(5)?;
                Ok(alerts::Alert {
                    id,
                    ts: r.get(1)?,
                    first_ts: r.get(1)?,
                    last_ts: r.get(2)?,
                    count: r.get(3)?,
                    severity: r.get(4)?,
                    hint: alerting::hint(&kind).into(),
                    kind,
                    message: r.get(6)?,
                    tenant: r.get(7)?,
                    host: self.host.clone(),
                    alert_url: alerts::Alert::url(&self.host, id),
                })
            })?;
            let rows: Vec<alerts::Alert> = rows.collect::<std::result::Result<_, _>>()?;
            for a in &rows {
                c.execute("UPDATE alerts SET notified_ts = ?2 WHERE id = ?1", params![a.id, now])?;
            }
            rows
        };
        if rows.is_empty() {
            return Ok(());
        }
        let cfg = self.alerts_config().unwrap_or_else(|e| {
            eprintln!("<3>scheduler: alert delivery configuration: {e:#}");
            alerts::AlertsConfig::default()
        });
        for a in rows {
            let _ = self.alert_tx.send((cfg.clone(), a));
        }
        Ok(())
    }

    /// Deletes resolved alerts older than the retention of their severity.
    pub(crate) fn prune_alerts(&self, now: i64) -> Result<()> {
        let c = self.db.conn();
        for (sev, days) in alerting::retention_days(&c)? {
            let n = c.execute(
                "DELETE FROM alerts WHERE resolved_at IS NOT NULL AND resolved_at < ?1 AND severity = ?2",
                params![now - days * 86400, sev],
            )?;
            if n > 0 {
                eprintln!("scheduler: pruned {n} resolved {sev} alert(s) older than {days} days");
            }
        }
        Ok(())
    }
}
