//! Plugin jobs (docs/plugin-system.md): `nexus-pluginhost <job>/plugin.json <op>`.
//!
//! `sources.config` of kind `plugin:<kind>` is the plugin's config object
//! (secret fields of the manifest sealed to the scheduler). The job config names the
//! installed plugin (id, version, install dir, binary digest and manifest from the
//! catalog — the host checks them against the files), the kind, the config with the
//! secrets opened (memory → 0600 job file only) and the op's parameters. Snapshots
//! are `plugin-<id>-<source>[-<guest>]`; download/listing run without the plugin.

use crate::run::{Plan, Step};
use crate::{download_file, file_arg, file_paths, ident, num, valid_name, Files, Job, Scheduler};
use anyhow::{bail, Context, Result};
use catalog::rusqlite::{params, OptionalExtension};
use catalog::secret::source_owner;
use chunkstore::retention::Gfs;
use plugin_manager::Current;
use plugin_proto::{parse_source_name, source_name, valid_guest_id};
use serde_json::{json, Value};

impl Scheduler {
    /// (plugin, kind, config with secrets opened) of a plugin source of `tenant`.
    pub(crate) fn plugin_source(&self, tenant: &str, id: i64) -> Result<(Current, String, Value)> {
        let (t, kind, cfg): (String, String, String) = self
            .db
            .conn()
            .query_row("SELECT tenant, kind, config FROM sources WHERE id=?1", [id], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?))
            })
            .optional()?
            .with_context(|| format!("source {id} not found"))?;
        if t != tenant {
            bail!("source {id} belongs to another tenant");
        }
        let k = kind
            .strip_prefix("plugin:")
            .with_context(|| format!("source {id} is not a plugin source"))?
            .to_owned();
        let cur = plugin_manager::current_for_kind(&self.db.conn(), &k)
            .map_err(|e| anyhow::anyhow!("{e}"))?
            .with_context(|| format!("no installed plugin provides kind plugin:{k}"))?;
        if !cur.enabled {
            bail!("plugin {} is disabled", cur.id);
        }
        let spec = cur.manifest.kinds.iter().find(|x| x.kind == k).unwrap();
        let fields: Vec<&str> = spec.secret_fields.iter().map(String::as_str).collect();
        let mut v: Value = serde_json::from_str(&cfg).context("source config")?;
        self.secrets
            .open_all_with(&source_owner(id), &mut v, &fields)
            .with_context(|| format!("source {id}"))?;
        Ok((cur, k, v))
    }

    pub(crate) fn plugin_cfg(
        &self,
        job: &Job,
        cur: &Current,
        kind: &str,
        sid: i64,
        config: Value,
        extra: Value,
    ) -> Result<Files> {
        let mut cfg = json!({
            "tenant": job.tenant,
            "store": self.cfg.store_base.join(&job.tenant),
            "keyd_socket": self.cfg.keyd_socket,
            "job": job.id,
            "plugin": {
                "id": cur.id, "version": cur.version,
                "dir": self.cfg.plugins_dir.join(&cur.id).join(&cur.version),
                "bin_sha256": cur.bin_sha256, "manifest": cur.manifest_raw, "enabled": cur.enabled,
            },
            "source_id": sid,
            "kind": kind,
            "config": config,
        });
        if let (Some(c), Some(e)) = (cfg.as_object_mut(), extra.as_object()) {
            c.extend(e.clone());
        }
        Ok(vec![("plugin.json".into(), serde_json::to_vec_pretty(&cfg)?)])
    }

    pub(crate) fn host_step(&self, plan: &Plan, args: &[String], capture: bool) -> Step {
        Step::Cli {
            bin: self.cfg.pluginhost_bin.clone(),
            args: std::iter::once(plan.dir.join("plugin.json").to_string_lossy().into_owned())
                .chain(args.iter().cloned())
                .collect(),
            alert: None,
            capture,
        }
    }

    /// Backup of a plugin source (one host run, one plugin process per guest).
    pub(crate) fn plan_plugin_backup(&self, job: &Job, mut plan: Plan, sid: i64, guests: &[String]) -> Result<Plan> {
        let (cur, kind, config) = self.plugin_source(&job.tenant, sid)?;
        if guests.iter().any(|g| !valid_guest_id(g)) {
            bail!("invalid guest id");
        }
        plan.key = format!("source:{sid}");
        plan.files = self.plugin_cfg(job, &cur, &kind, sid, config, json!({"guests": guests}))?;
        plan.steps.push(self.host_step(&plan, &["backup".into()], false));
        Ok(plan)
    }

    /// A snapshot source of one of the tenant's plugin sources → its source id.
    fn plugin_snapshot(&self, job: &Job, source: &str) -> Result<i64> {
        let (pid, sid, _) =
            parse_source_name(source).with_context(|| format!("invalid plugin snapshot source {source:?}"))?;
        let sid = sid as i64;
        let kind: String = self
            .db
            .conn()
            .query_row(
                "SELECT kind FROM sources WHERE id=?1 AND tenant=?2",
                params![sid, job.tenant],
                |r| r.get(0),
            )
            .optional()?
            .with_context(|| format!("source {sid} not found in tenant {}", job.tenant))?;
        let owner = kind
            .strip_prefix("plugin:")
            .and_then(|k| plugin_manager::current_for_kind(&self.db.conn(), k).ok().flatten());
        if owner.is_none_or(|c| c.id != pid) {
            bail!("snapshot {source} does not belong to a plugin source of this tenant");
        }
        Ok(sid)
    }

    pub(crate) fn plan_plugin(&self, job: &Job, mut plan: Plan) -> Result<Plan> {
        let p = &job.params;
        match job.kind.as_str() {
            "plugin_validate" | "plugin_guests" => {
                let sid = p["source_id"].as_i64().context("missing parameter source_id")?;
                let (cur, kind, config) = self.plugin_source(&job.tenant, sid)?;
                plan.key = format!("source:{sid}");
                plan.files = self.plugin_cfg(job, &cur, &kind, sid, config, json!({}))?;
                let op = if job.kind == "plugin_validate" {
                    "validate"
                } else {
                    "guests"
                };
                plan.steps.push(self.host_step(&plan, &[op.into()], true));
            }
            "plugin_backup" => {
                let sid = p["source_id"].as_i64().context("missing parameter source_id")?;
                let guests: Vec<String> = match p["guests"].as_array() {
                    Some(a) => a.iter().filter_map(|g| g.as_str().map(str::to_owned)).collect(),
                    // default: the guests of the source's first group, else the whole source
                    None => match self
                        .groups()?
                        .into_iter()
                        .find(|g| g.tenant == job.tenant && g.source_id == sid)
                    {
                        Some(g) if g.auto && g.plugin.as_ref().is_none_or(|x| x.1.is_empty()) => {
                            bail!("nothing to back up: no guests match the group (inventory)")
                        }
                        g => g.and_then(|g| g.plugin.map(|x| x.1)).unwrap_or_default(),
                    },
                };
                return self.plan_plugin_backup(job, plan, sid, &guests);
            }
            "plugin_restore" | "plugin_mount" => {
                let source = ident(p, "source")?;
                let sid = self.plugin_snapshot(job, source)?;
                let (cur, kind, config) = self.plugin_source(&job.tenant, sid)?;
                plan.key = format!("guest:{}/{source}", job.tenant);
                let snap = json!({"source": source, "time": num(p, "time")?, "params": p["params"].clone()});
                let (extra, op) = if job.kind == "plugin_restore" {
                    let mut s = snap;
                    s["id"] = json!(p["restore"].as_str().context("missing parameter restore")?);
                    (json!({ "restore": s }), "restore")
                } else {
                    let mut s = snap;
                    s["minutes"] = json!(p["minutes"].as_u64().unwrap_or(60).clamp(1, 1440));
                    (json!({ "mount": s }), "mount")
                };
                plan.files = self.plugin_cfg(job, &cur, &kind, sid, config, extra)?;
                plan.steps.push(self.host_step(&plan, &[op.into()], false));
            }
            "files_list" | "files_get" => {
                let source = ident(p, "source")?;
                self.plugin_snapshot(job, source)?;
                plan.key = format!("guest:{}/{source}", job.tenant);
                // store only: no plugin, no secrets
                let cfg = json!({"tenant": job.tenant, "store": self.cfg.store_base.join(&job.tenant),
                                 "keyd_socket": self.cfg.keyd_socket});
                plan.files = vec![("plugin.json".into(), serde_json::to_vec_pretty(&cfg)?)];
                let mut args = vec!["files".to_owned(), source.to_owned(), num(p, "time")?.to_string()];
                if job.kind == "files_list" {
                    args.push("ls".into());
                    args.push(file_arg(p["path"].as_str().unwrap_or("/"))?);
                } else {
                    let out = self.cfg.downloads.join(download_file(p)?);
                    args.push("get".into());
                    args.push(out.to_string_lossy().into_owned());
                    args.extend(file_paths(p)?);
                    plan.download = Some(out);
                }
                plan.steps.push(self.host_step(&plan, &args, true));
            }
            k => bail!("unknown plugin job kind {k:?}"),
        }
        Ok(plan)
    }

    /// Retention of a plugin source's snapshots (`source_id` + `plugin`, or one `source`):
    /// the GFS of the group backing up that source.
    pub(crate) fn plan_plugin_retention(&self, job: &Job, mut plan: Plan) -> Result<Plan> {
        let p = &job.params;
        let (sources, prefixes, sid) = match p["source"].as_str() {
            Some(s) => {
                if !valid_name(s) {
                    bail!("invalid source {s:?}");
                }
                (vec![s.to_owned()], Vec::new(), self.plugin_snapshot(job, s)?)
            }
            None => {
                let sid = p["source_id"].as_i64().context("missing parameter source_id")?;
                let (cur, _, _) = self.plugin_source(&job.tenant, sid)?;
                let base = source_name(&cur.id, sid as u64, None);
                (vec![base.clone()], vec![format!("{base}-")], sid)
            }
        };
        let gfs = self
            .groups()?
            .into_iter()
            .find(|g| g.tenant == job.tenant && g.source_id == sid && g.plugin.is_some())
            .map_or_else(Gfs::default, |g| g.gfs);
        plan.key = format!("source:{sid}");
        plan.steps.push(Step::Retention { sources, prefixes, gfs });
        Ok(plan)
    }

    /// Firewall: every plugin source's manifest endpoints resolved in its config.
    pub(crate) fn plugin_targets(&self) -> Result<Vec<(String, u16)>> {
        let rows: Vec<(String, String)> = {
            let c = self.db.conn();
            let mut st = c.prepare("SELECT kind, config FROM sources WHERE kind LIKE 'plugin:%'")?;
            let rows = st.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?;
            rows.collect::<std::result::Result<_, _>>()?
        };
        let mut out = Vec::new();
        for (kind, cfg) in rows {
            let Ok(Some(cur)) = plugin_manager::current_for_kind(&self.db.conn(), &kind["plugin:".len()..]) else {
                continue;
            };
            let v: Value = serde_json::from_str(&cfg).unwrap_or_default();
            if let Some(spec) = cur
                .manifest
                .kinds
                .iter()
                .find(|k| kind.ends_with(&format!(":{}", k.kind)))
            {
                // manifest endpoints resolved in the config (fixed `default_host`s included);
                // TCP only: the appliance allow-list is TCP (UDP endpoints are not opened)
                out.extend(spec.tcp_targets(&v));
            }
        }
        Ok(out)
    }
}
