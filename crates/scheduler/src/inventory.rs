//! Guest inventory (Phase 13c, auto-protect; docs/control-plane.md "Inventory").
//!
//! An `inventory` job per source, every `Config::inventory_secs` and on request
//! (web-api: `POST /jobs {kind: inventory}`): PVE `nexus-pve <cfg> inventory`
//! (`/cluster/resources`), TrueNAS the source's datasets (catalog only), plugins
//! the host's `guests` op (also the result of a manual `plugin_guests` job). The
//! result `{"guests": [{id, title, kind?, tags}]}` replaces the source's rows in
//! `inventory` (catalog::inventory); `all` / `tags` groups resolve from it in
//! `groups()`. Guests a group newly protects are audited (`group.auto_protect`).

use crate::run::{InProc, Plan, Step};
use crate::{GroupRow, Job, Scheduler, ACTOR};
use anyhow::{bail, Context, Result};
use catalog::inventory::Item;
use catalog::rusqlite::{params, OptionalExtension};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

/// Guest ids of a resolved group (inventory keys).
fn guest_ids(g: &GroupRow) -> BTreeSet<String> {
    g.guests
        .iter()
        .map(u32::to_string)
        .chain(g.datasets.iter().cloned())
        .chain(g.vms.iter().cloned())
        .chain(g.plugin.iter().flat_map(|(_, x)| x.iter().cloned()))
        .collect()
}

/// Whether guest `id` is a valid guest of a source of `kind`.
fn valid_guest(kind: &str, id: &str) -> bool {
    match kind {
        "pve" => id.parse::<u32>().is_ok_and(|v| v > 0) && !id.starts_with('0'),
        "truenas" => truenas::valid_dataset(id),
        "vmware" => vmware::names::valid_uuid(id),
        k if k.starts_with("plugin:") => plugin_proto::valid_guest_id(id),
        _ => false,
    }
}

impl Scheduler {
    /// (id, tenant, kind) of the sources that have an inventory: PVE, TrueNAS and
    /// plugin sources whose (enabled) plugin lists guests. Replicated tenants have
    /// no local sources to list.
    fn inventory_sources(&self) -> Result<Vec<(i64, String, String)>> {
        let replicated = self.replicated_tenants()?;
        let c = self.db.conn();
        let rows: Vec<(i64, String, String)> = c
            .prepare("SELECT id, tenant, kind FROM sources ORDER BY id")?
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
            .collect::<std::result::Result<_, _>>()?;
        Ok(rows
            .into_iter()
            .filter(|(_, t, _)| !replicated.contains_key(t))
            .filter(|(_, _, kind)| match kind.strip_prefix("plugin:") {
                None => kind == "pve" || kind == "truenas" || kind == "vmware",
                Some(k) => plugin_manager::current_for_kind(&c, k)
                    .ok()
                    .flatten()
                    .filter(|cur| cur.enabled)
                    .and_then(|cur| cur.manifest.kinds.into_iter().find(|x| x.kind == k))
                    .is_some_and(|spec| spec.guests.is_some_and(|g| g["list"] == true)),
            })
            .collect())
    }

    /// Queues an `inventory` job for every source whose last listing (inventory or
    /// plugin_guests job, any outcome) is older than `inventory_secs`.
    pub(crate) fn queue_inventory(&mut self, now: i64) -> Result<()> {
        if self.cfg.inventory_secs <= 0 {
            return Ok(());
        }
        for (sid, tenant, _) in self.inventory_sources()? {
            let (active, last): (i64, Option<i64>) = self.db.conn().query_row(
                "SELECT COALESCE(SUM(state IN ('queued','running')), 0), MAX(created) FROM jobs \
                 WHERE kind IN ('inventory','plugin_guests') AND json_extract(params,'$.source_id')=?1",
                [sid],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?;
            if active > 0 || last.is_some_and(|t| now - t < self.cfg.inventory_secs) {
                continue;
            }
            self.insert_job("inventory", &tenant, &json!({ "source_id": sid }))?;
        }
        Ok(())
    }

    pub(crate) fn plan_inventory(&self, job: &Job, mut plan: Plan) -> Result<Plan> {
        let sid = job.params["source_id"]
            .as_i64()
            .context("missing parameter source_id")?;
        let (kind, cfg): (String, String) = self
            .db
            .conn()
            .query_row(
                "SELECT kind, config FROM sources WHERE id=?1 AND tenant=?2",
                params![sid, job.tenant],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?
            .with_context(|| format!("source {sid} not found in tenant {}", job.tenant))?;
        // never behind a running backup of the source: listing is read-only
        plan.key = format!("inventory:{sid}");
        if kind == "pve" {
            plan.files = self.pve_config(&job.tenant, sid, &plan.dir, &[])?;
            plan.steps.push(Step::Cli {
                bin: self.cfg.pve_bin.clone(),
                args: vec![
                    plan.dir.join("pve.json").to_string_lossy().into_owned(),
                    "inventory".into(),
                ],
                alert: Some("inventory_refresh"),
                capture: true,
            });
        } else if kind == "truenas" {
            // the datasets configured on the source (no call to the NAS)
            let cfg: Value = serde_json::from_str(&cfg).context("source config")?;
            let guests: Vec<Value> = cfg["datasets"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .map(|d| {
                    let pool = d.split('/').next().unwrap_or(d);
                    json!({"id": d, "title": d, "kind": "dataset", "tags": [format!("pool:{pool}")]})
                })
                .collect();
            let out = json!({ "guests": guests }).to_string();
            plan.steps.push(Step::Func(InProc(Box::new(move || Ok(out.clone())))));
        } else if kind == "vmware" {
            // the VMs of the ESXi host or vCenter, the VM UUID as guest id (the snapshot source is vmw-<uuid>)
            plan.files = self.vmware_config(&job.tenant, sid, &plan.dir, &[])?;
            plan.steps.push(Step::Cli {
                bin: self.cfg.vmware_bin.clone(),
                args: vec![
                    plan.dir.join("vmware.json").to_string_lossy().into_owned(),
                    "inventory".into(),
                ],
                alert: Some("inventory_refresh"),
                capture: true,
            });
        } else if kind.starts_with("plugin:") {
            let (cur, k, config) = self.plugin_source(&job.tenant, sid)?;
            plan.files = self.plugin_cfg(job, &cur, &k, sid, config, json!({}))?;
            let mut step = self.host_step(&plan, &["guests".into()], true);
            if let Step::Cli { alert, .. } = &mut step {
                *alert = Some("inventory_refresh");
            }
            plan.steps.push(step);
        } else {
            bail!("source {sid}: {kind} sources have no guest inventory");
        }
        Ok(plan)
    }

    /// Stores a listing (`inventory` / `plugin_guests` result) and records what the
    /// source's auto-protect groups gained or lost.
    pub(crate) fn apply_inventory(&self, job: &Job, result: &Value) -> Result<()> {
        let Some(sid) = job.params["source_id"].as_i64() else {
            return Ok(());
        };
        let kind: String = self.db.conn().query_row(
            "SELECT kind FROM sources WHERE id=?1 AND tenant=?2",
            params![sid, job.tenant],
            |r| r.get(0),
        )?;
        let items: Vec<Item> = result["guests"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|g| {
                let id = g["id"].as_str().filter(|id| valid_guest(&kind, id))?;
                let tags: Vec<String> = g["tags"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(|t| t.as_str().map(str::to_owned))
                    .collect();
                let gk = g["kind"].as_str().map(str::to_owned).unwrap_or_else(|| {
                    tags.iter()
                        .find_map(|t| t.strip_prefix("type:"))
                        .unwrap_or_default()
                        .to_owned()
                });
                Some(Item {
                    guest: id.to_owned(),
                    name: g["title"].as_str().unwrap_or_default().chars().take(200).collect(),
                    kind: gk.chars().take(32).collect(),
                    tags,
                })
            })
            .collect();
        let covered = |s: &Self| -> Result<BTreeMap<i64, BTreeSet<String>>> {
            Ok(s.groups()?
                .iter()
                .filter(|g| g.source_id == sid && g.auto)
                .map(|g| (g.id, guest_ids(g)))
                .collect())
        };
        let before = covered(self)?;
        let (added, gone) = catalog::inventory::update(&self.db.conn(), sid, &items, catalog::now())?;
        if !added.is_empty() || !gone.is_empty() {
            eprintln!(
                "<6>inventory source {sid}: {} guests, new {added:?}, gone {gone:?}",
                items.len()
            );
            self.db.audit(
                ACTOR,
                "inventory.update",
                &format!("source/{sid}"),
                &json!({"guests": items.len(), "added": added, "gone": gone}),
            )?;
        }
        for (gid, now_set) in covered(self)? {
            let old = before.get(&gid).cloned().unwrap_or_default();
            let new: Vec<&String> = now_set.difference(&old).collect();
            let lost: Vec<&String> = old.difference(&now_set).collect();
            if !new.is_empty() {
                eprintln!("<6>group {gid}: now protects {new:?} (auto-protect)");
                self.db.audit(
                    ACTOR,
                    "group.auto_protect",
                    &format!("group/{gid}"),
                    &json!({"source_id": sid, "guests": new}),
                )?;
            }
            if !lost.is_empty() {
                eprintln!("<6>group {gid}: no longer selects {lost:?} (gone, untagged or excluded)");
            }
        }
        Ok(())
    }
}
