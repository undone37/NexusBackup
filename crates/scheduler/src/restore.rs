//! Restore options (Phase 15a, docs/control-plane.md "Restore options"): job
//! params → `nexus-pve restore|restore-ct|instant-recover` flags
//! (`crates/pve/src/restore.rs`), and approved `restore.replace` requests → restore jobs.

use crate::{Job, Scheduler};
use anyhow::{bail, Context, Result};
use serde_json::{json, Value};

fn pve_name(s: &str) -> bool {
    (1..=63).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.' || b == b'_')
        && !s.starts_with(['-', '.'])
}

/// CLI flags of a restore / instant recovery job's options.
pub(crate) fn restore_flags(job: &Job) -> Result<Vec<String>> {
    let p = &job.params;
    let mut out = Vec::new();
    for (k, flag) in [("name", "--name"), ("name_prefix", "--name-prefix"), ("pool", "--pool")] {
        if let Some(v) = p.get(k).filter(|v| !v.is_null()) {
            let v = v
                .as_str()
                .filter(|v| pve_name(v))
                .with_context(|| format!("invalid {k}"))?;
            out.extend([flag.to_owned(), v.to_owned()]);
        }
    }
    if p["link_down"].as_bool() == Some(true) {
        out.push("--link-down".into());
    }
    if job.kind == "instant_recover" {
        // older jobs have no `start`: the VM starts (the CLI default)
        if p["start"].as_bool() == Some(false) {
            out.push("--no-start".into());
        }
        return Ok(out);
    }
    if p["start"].as_bool() == Some(true) {
        out.push("--start".into());
    }
    if p["replace"].as_bool() == Some(true) {
        // only the approval poller below creates these jobs
        if !p["quorum_id"].is_i64() {
            bail!("replace without an approved restore.replace request");
        }
        out.push("--replace".into());
        if p["keep_original_links"].as_bool() == Some(true) {
            out.push("--keep-original-links".into());
        }
    }
    Ok(out)
}

impl Scheduler {
    /// Approved `restore.replace` requests (web-api `jobs.rs`) become restore jobs.
    pub(crate) fn queue_restore_replaces(&mut self) -> Result<()> {
        let rows: Vec<(i64, String, String, Option<String>)> = {
            let c = self.db.conn();
            let mut st = c.prepare(
                "SELECT q.id, q.params, q.requested_by, q.decided_by FROM quorum q \
                 WHERE q.action='restore.replace' AND q.state='approved' \
                 AND NOT EXISTS (SELECT 1 FROM jobs j WHERE j.kind IN ('restore','restore_ct') \
                                 AND json_extract(j.params,'$.quorum_id')=q.id)",
            )?;
            let rows = st.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?;
            rows.collect::<std::result::Result<_, _>>()?
        };
        for (id, p, by, decided) in rows {
            if decided.as_deref() == Some(by.as_str()) && catalog::approvals_enabled(&self.db.conn())? {
                continue;
            }
            let p: Value = serde_json::from_str(&p).unwrap_or(Value::Null);
            let (Some(tenant), Some(kind), Some(params)) =
                (p["tenant"].as_str(), p["kind"].as_str(), p["params"].as_object())
            else {
                continue;
            };
            if kind != "restore" && kind != "restore_ct" {
                continue;
            }
            let mut params = params.clone();
            params.insert("replace".into(), json!(true));
            params.insert("quorum_id".into(), json!(id));
            params.insert("requested_by".into(), json!(by));
            self.insert_job(kind, tenant, &Value::Object(params))?;
        }
        Ok(())
    }
}
