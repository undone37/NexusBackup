//! Offsite in the web UI (Phase 17d, docs/control-plane.md "Offsite in the UI").
//!
//! - `offsite_list`: `nexus-offsite list --json` (what the box holds, sizes,
//!   offsite locks, cross-checked with the offsite inventory and the local
//!   store) becomes the job result `{snapshots: [...]}`.
//! - `offsite_restore {source, time}`: fetches one snapshot back into the local
//!   store (`nexus-offsite restore <source> <time> <keep>`); the store locks it
//!   for `Config::offsite_fetch_keep_secs` (default 7 days) so local retention
//!   does not delete it again right away. The refresh marks it local again.
//! - `offsite_attach {attach_quorum, recovery_key}`: the approved
//!   `tenant.attach_offsite` request (web-api `tenants.rs`) names the tenant and
//!   its offsite target; its requester submits the recovery key once, sealed to
//!   this scheduler (`catalog::secret::attach_key_location`). Planning opens it,
//!   removes it from the job row and writes it to a 0600 file in the private job
//!   dir, which `nexus-offsite attach` deletes after reading; keyd re-wraps the
//!   escrowed DEKs. On success the tenant row is created with the request's
//!   offsite config and the request is `executed`; a failed attempt leaves it
//!   `approved`, so the requester can submit the key again within the window.
//!   While such a request is approved, its target is in the egress allow-list.

use super::*;

/// Quorum action of "Attach an offsite copy".
pub const ATTACH_ACTION: &str = "tenant.attach_offsite";
/// An approved attach request can be run (and its target is reachable) this
/// long after its approval.
pub const ATTACH_WINDOW_SECS: i64 = 72 * 3600;

impl Scheduler {
    /// `(tenant, offsite config as stored)` of an approved, not yet executed
    /// attach request inside its window.
    fn attach_request(&self, id: i64) -> Result<(String, Value)> {
        let p: String = self
            .db
            .conn()
            .query_row(
                "SELECT params FROM quorum WHERE id=?1 AND action=?2 AND state='approved' AND decided_at >= ?3",
                params![id, ATTACH_ACTION, catalog::now() - ATTACH_WINDOW_SECS],
                |r| r.get(0),
            )
            .optional()?
            .with_context(|| format!("no approved {ATTACH_ACTION} request {id} (executed, expired or rejected)"))?;
        let p: Value = serde_json::from_str(&p)?;
        let name = p["name"]
            .as_str()
            .filter(|n| valid_name(n))
            .context("attach request: tenant name")?;
        Ok((name.to_owned(), p["offsite"].clone()))
    }

    /// Egress for approved attach requests (their tenant does not exist yet).
    pub(crate) fn attach_targets(&self) -> Result<Vec<(String, u16)>> {
        let c = self.db.conn();
        let mut st =
            c.prepare("SELECT params FROM quorum WHERE action=?1 AND state='approved' AND decided_at >= ?2")?;
        let rows = st.query_map(params![ATTACH_ACTION, catalog::now() - ATTACH_WINDOW_SECS], |r| {
            r.get::<_, String>(0)
        })?;
        let mut out = Vec::new();
        for p in rows {
            if let Ok(v) = serde_json::from_str::<Value>(&p?) {
                out.extend(firewall::offsite_targets(&v["offsite"]));
            }
        }
        Ok(out)
    }

    pub(crate) fn plan_offsite_ui(&self, job: &Job, mut plan: Plan) -> Result<Plan> {
        let (tenant, p, dir) = (job.tenant.as_str(), &job.params, plan.dir.clone());
        // Phase 30: `target` 2 browses / fetches from the second offsite target
        let n = crate::offsite_job_target(p);
        let cfg_file = dir.join(format!("{}.json", crate::offsite_prefix(n)));
        let offsite = |args: Vec<String>, capture: bool| Step::Cli {
            bin: self.cfg.offsite_bin.clone(),
            args: std::iter::once(cfg_file.to_string_lossy().into_owned())
                .chain(args)
                .collect(),
            alert: None,
            capture,
        };
        match job.kind.as_str() {
            "offsite_list" => {
                plan.files = self
                    .offsite_config_n(tenant, &dir, n)?
                    .with_context(|| format!("tenant has no offsite target {n}"))?;
                plan.steps.push(offsite(vec!["list".into(), "--json".into()], true));
            }
            "offsite_restore" => {
                let (source, time) = (ident(p, "source")?, num(p, "time")?);
                plan.files = self
                    .offsite_config_n(tenant, &dir, n)?
                    .with_context(|| format!("tenant has no offsite target {n}"))?;
                let keep = self.cfg.offsite_fetch_keep_secs.to_string();
                plan.steps.push(offsite(
                    vec!["restore".into(), source.to_owned(), time.to_string(), keep],
                    false,
                ));
            }
            "offsite_attach" => {
                // the key is used once: off the job row before anything can fail
                let sealed = p["recovery_key"].as_str().map(str::to_owned);
                self.db.conn().execute(
                    "UPDATE jobs SET params=json_remove(params, '$.recovery_key') WHERE id=?1",
                    [job.id],
                )?;
                let id = p["attach_quorum"].as_i64().context("missing parameter attach_quorum")?;
                let (name, mut o) = self.attach_request(id)?;
                if name != tenant {
                    bail!("attach request {id} is for tenant {name}, not {tenant}");
                }
                let exists: Option<i64> = self
                    .db
                    .conn()
                    .query_row("SELECT 1 FROM tenants WHERE name=?1", [tenant], |r| r.get(0))
                    .optional()?;
                if exists.is_some() {
                    bail!("tenant {tenant} exists already");
                }
                let sealed = sealed.context("the recovery key was already used: submit it again")?;
                let rk = self
                    .secrets
                    .open(&catalog::secret::attach_key_location(id, tenant), &sealed)
                    .context("recovery key")?;
                self.secrets
                    .open_all(&tenant_owner(tenant), &mut o)
                    .with_context(|| format!("offsite config of attach request {id}"))?;
                if !o["remote"].is_object() {
                    bail!("attach request {id} has no offsite target");
                }
                plan.files = self.offsite_files(tenant, &o, &dir, 1)?;
                plan.files.push(("recovery.key".into(), rk.as_bytes().to_vec()));
                plan.steps.push(offsite(
                    vec!["attach".into(), dir.join("recovery.key").to_string_lossy().into_owned()],
                    false,
                ));
            }
            k => bail!("unknown job kind {k:?}"),
        }
        Ok(plan)
    }

    /// After `offsite_attach`: the tenant exists from now on (with the request's
    /// offsite config), the request is executed, the snapshots get listed.
    pub(crate) fn attach_bookkeeping(&mut self, job: &Job, ok: bool) -> Result<()> {
        let Some(id) = job.params["attach_quorum"].as_i64() else {
            return Ok(());
        };
        if !ok {
            return Ok(()); // still approved: the requester may submit the key again
        }
        let (name, o) = self.attach_request(id)?;
        let (by, approver): (String, Option<String>) = {
            let mut c = self.db.conn();
            let tx = c.transaction()?;
            tx.execute(
                "INSERT INTO tenants (name, offsite) VALUES (?1, ?2) ON CONFLICT (name) DO NOTHING",
                params![name, o.to_string()],
            )?;
            tx.execute(
                "UPDATE quorum SET state='executed' WHERE id=?1 AND state='approved'",
                [id],
            )?;
            let who = tx.query_row("SELECT requested_by, decided_by FROM quorum WHERE id=?1", [id], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })?;
            tx.commit()?;
            who
        };
        self.db.audit(
            ACTOR,
            ATTACH_ACTION,
            &format!("tenant/{name}"),
            &json!({"quorum_id": id, "job": job.id, "requested_by": by, "approved_by": approver}),
        )?;
        self.db.audit(
            ACTOR,
            "quorum.execute",
            &format!("quorum/{id}"),
            &json!({"job": job.id, "state": "ok"}),
        )?;
        self.dirty.insert(name);
        Ok(())
    }
}
