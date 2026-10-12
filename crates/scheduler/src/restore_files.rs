//! `restore_files` (Phase 15b, docs/control-plane.md "Restore to a host"): files of
//! a snapshot onto a path of an enrolled agent of the same tenant.
//!
//! - file-tree snapshots (`host-<agent>`, `nas-…`, `share-…`, `plugin-…`): one
//!   `nexus-agentctl restore` step that reads the tree from the store;
//! - VM/CT snapshots (`vm-<id>`, `ct-<id>`): `nexus-pve files|ct-files … get` writes
//!   the selection as a tar into the downloads directory (restore micro-VM / CT tar
//!   stream, like a download), then `nexus-agentctl restore` bridges that tar to the
//!   agent and removes it (on failure the scheduler removes it, `Plan::download`).
//!
//! The target agent defaults to the snapshot's own agent for `host-` sources and is
//! required otherwise; `Scheduler::agent` refuses agents of another tenant.

use super::*;

impl Scheduler {
    pub(crate) fn plan_restore_files(&self, job: &Job, mut plan: Plan, replicated: bool) -> Result<Plan> {
        let (p, tenant, dir) = (&job.params, job.tenant.as_str(), plan.dir.clone());
        let src = ident(p, "source")?;
        let own = src.strip_prefix("host-").filter(|a| valid_agent_id(a));
        let tree = own.is_some()
            || src.starts_with("share-") && nas::parse_source_name(src).is_some()
            || src.starts_with("nas-") && truenas::parse_source_name(src).is_some()
            || src.starts_with("plugin-") && plugin_proto::parse_source_name(src).is_some();
        let target = match (p["agent_id"].as_str(), own) {
            (Some(a), _) | (None, Some(a)) => a,
            (None, None) => bail!("restore_files from {src} needs a target agent (agent_id)"),
        };
        let a = self.agent(tenant, target)?;
        if a.cert_sha256.is_none() {
            bail!("agent {} ({}) is not enrolled", a.name, a.id);
        }
        plan.key = format!("agent:{}", a.id);
        let time = num(p, "time")?;
        let mut restore = json!({
            "source": src, "time": time, "paths": file_paths(p)?,
            "target": p["target"].as_str().context("missing parameter target")?,
            "overwrite": p["overwrite"].as_str().unwrap_or("never"),
            "confirm": p["confirm"].as_str().context("missing parameter confirm")?,
        });
        if !tree {
            let (ct, vmid) = guest(src).context("restore_files: not a file-tree, VM or CT snapshot")?;
            plan.files = match self.resolve_source(job, Some(vmid)) {
                Ok(sid) => self.pve_config(tenant, sid, &dir, &[])?,
                // replicated snapshots without a local PVE source: store-only file commands
                Err(_) if replicated => {
                    let cfg = json!({"store": self.cfg.store_base.join(tenant), "tenant": tenant,
                                     "keyd_socket": self.cfg.keyd_socket});
                    vec![("pve.json".into(), serde_json::to_vec_pretty(&cfg)?)]
                }
                Err(e) => return Err(e),
            };
            // not a files_get name (64 hex): never served by GET /downloads/{token}
            let staging = self
                .cfg
                .downloads
                .join(format!("restore-{}-{:016x}.tar", job.id, rand::random::<u64>()));
            let mut args = vec![
                dir.join("pve.json").to_string_lossy().into_owned(),
                if ct { "ct-files" } else { "files" }.to_owned(),
                vmid.to_string(),
                time.to_string(),
                "get".into(),
                staging.to_string_lossy().into_owned(),
            ];
            args.extend(file_paths(p)?);
            plan.steps.push(Step::Cli {
                bin: self.cfg.pve_bin.clone(),
                args,
                alert: None,
                capture: false,
            });
            restore["tar"] = json!(staging);
            plan.download = Some(staging);
        }
        let (f, step) = self.agentctl(&dir, job, &a, "restore", json!({"restore": restore}))?;
        plan.files.push(f);
        plan.steps.push(step);
        Ok(plan)
    }
}
