//! Restore options (Phase 15a, docs/control-plane.md "Restore options"): job
//! params → `nexus-pve restore|restore-ct|instant-recover` flags
//! (`crates/pve/src/restore.rs`), and approved `restore.replace` / `restore.infected`
//! (Phase 29: a production restore of a flagged snapshot, any restore kind) requests → jobs.

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
    /// Approved `restore.replace` and `restore.infected` requests (web-api
    /// `jobs.rs`, `infected.rs`) become restore jobs.
    pub(crate) fn queue_restore_replaces(&mut self) -> Result<()> {
        let rows: Vec<(i64, String, String, String, Option<String>)> = {
            let c = self.db.conn();
            let mut st = c.prepare(
                "SELECT q.id, q.action, q.params, q.requested_by, q.decided_by FROM quorum q \
                 WHERE q.action IN ('restore.replace', 'restore.infected') AND q.state='approved' \
                 AND NOT EXISTS (SELECT 1 FROM jobs j WHERE json_extract(j.params,'$.quorum_id')=q.id \
                                 AND j.kind IN ('restore','restore_ct','instant_recover','instant_disk', \
                                                'restore_files','plugin_restore'))",
            )?;
            let rows = st.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)))?;
            rows.collect::<std::result::Result<_, _>>()?
        };
        for (id, action, p, by, decided) in rows {
            if decided.as_deref() == Some(by.as_str()) && catalog::approvals_enabled(&self.db.conn())? {
                continue;
            }
            let p: Value = serde_json::from_str(&p).unwrap_or(Value::Null);
            let (Some(tenant), Some(kind), Some(params)) =
                (p["tenant"].as_str(), p["kind"].as_str(), p["params"].as_object())
            else {
                continue;
            };
            let infected = action == catalog::incident::RESTORE_INFECTED;
            if !infected && kind != "restore" && kind != "restore_ct" {
                continue;
            }
            if infected && !catalog::incident::production_restore(kind, &Value::Object(params.clone())) {
                continue;
            }
            let mut params = params.clone();
            if !infected {
                params.insert("replace".into(), json!(true));
            }
            params.insert("quorum_id".into(), json!(id));
            params.insert("requested_by".into(), json!(by));
            self.insert_job(kind, tenant, &Value::Object(params))?;
        }
        Ok(())
    }
}

impl Scheduler {
    /// Instant disk recovery (Phase 22b, `nexus-pve instant-disk`): one disk of a
    /// VM snapshot attached to an existing VM of the same source that a group of
    /// the tenant protects (a tenant cannot hand its data to a VM it does not own,
    /// nor touch other tenants' VMs). Exclusive per snapshot source, like
    /// instant recovery; the job runs while the disk is served.
    pub(crate) fn plan_instant_disk(&self, job: &Job, mut plan: crate::run::Plan) -> Result<crate::run::Plan> {
        let p = &job.params;
        let source = p["source"].as_str().context("source")?;
        let vmid: u32 = source
            .strip_prefix("vm-")
            .and_then(|v| v.parse().ok())
            .with_context(|| format!("instant_disk needs a vm-<vmid> snapshot, not {source:?}"))?;
        let time = p["time"].as_u64().context("time")?;
        let device = p["device"]
            .as_str()
            .filter(|d| d.strip_prefix("drive-").is_some_and(crate::selection::valid_disk_key))
            .context("device: drive-<slot>")?;
        let node = p["node"].as_str().filter(|n| pve_name(n)).context("node")?;
        let target = p["target"]
            .as_u64()
            .and_then(|t| u32::try_from(t).ok())
            .context("target")?;
        let sid = self.resolve_source(job, Some(vmid))?;
        let protected = self
            .groups()?
            .into_iter()
            .any(|g| g.tenant == job.tenant && g.source_id == sid && g.guests.contains(&target));
        if !protected {
            bail!(
                "VM {target} is not protected by a group of tenant {} on this source",
                job.tenant
            );
        }
        plan.key = format!("guest:{}/{source}", job.tenant);
        plan.files = self.pve_config(&job.tenant, sid, &plan.dir, &[])?;
        let mut args = vec![
            plan.dir.join("pve.json").to_string_lossy().into_owned(),
            "instant-disk".into(),
            vmid.to_string(),
            time.to_string(),
            device.to_owned(),
            node.to_owned(),
            target.to_string(),
        ];
        if let Some(k) = p["key"].as_str() {
            if !crate::selection::valid_disk_key(k) {
                bail!("invalid key {k:?}");
            }
            args.extend(["--key".into(), k.to_owned()]);
        }
        if let Some(s) = p["move_to"].as_str() {
            if !pve_name(s) {
                bail!("invalid move_to {s:?}");
            }
            args.extend(["--move-to".into(), s.to_owned()]);
        }
        plan.steps.push(crate::run::Step::Cli {
            bin: self.cfg.pve_bin.clone(),
            args,
            alert: None,
            capture: false,
        });
        Ok(plan)
    }
}
