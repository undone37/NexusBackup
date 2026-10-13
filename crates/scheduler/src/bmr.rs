//! Bare-metal recovery and P2V jobs (Phase 19a, docs/bmr.md).
//!
//! - `bmr` (session checked in, snapshot chosen): `nexus-agentctl … rescue` enrolls
//!   the rescue agent with the sealed recovery token digest (unless done in an earlier
//!   attempt), recreates the layout, restores the snapshot, installs the boot loader;
//!   for P2V sessions `nexus-pve … p2v-cleanup` then detaches and deletes the config disk.
//! - `p2v`: `nexus-agentctl … layout` reads the layout from the snapshot, then
//!   `nexus-pve … p2v` creates the VM (disks sized from the layout, UEFI if the
//!   original booted UEFI), uploads the config disk with the plaintext recovery token
//!   (unsealed only here) and starts the VM. Its check-in queues the `bmr` job.
//!
//! Bookkeeping from the CLI lines: `rescue-enrolled {json}` (pin, token spent),
//! `rescue-step <step>`, `rescue-done {json}`, `p2v-vm {json}`.

use super::*;
use catalog::secret::{rescue_p2v_token_location, rescue_token_location};

struct Session {
    id: String,
    agent: String,
    host: Option<String>,
    port: Option<u16>,
    token_hash: Option<String>,
    cert_sha256: Option<String>,
    reboot: bool,
    p2v: Option<Value>,
}

impl Scheduler {
    fn rescue_session(&self, tenant: &str, id: &str) -> Result<Session> {
        self.db
            .conn()
            .query_row(
                "SELECT id, agent_id, host, port, token_hash, cert_sha256, reboot, p2v FROM rescue_sessions \
                 WHERE id = ?1 AND tenant = ?2",
                params![id, tenant],
                |r| {
                    Ok(Session {
                        id: r.get(0)?,
                        agent: r.get(1)?,
                        host: r.get(2)?,
                        port: r.get(3)?,
                        token_hash: r.get(4)?,
                        cert_sha256: r.get(5)?,
                        reboot: r.get(6)?,
                        p2v: r
                            .get::<_, Option<String>>(7)?
                            .and_then(|t| serde_json::from_str(&t).ok()),
                    })
                },
            )
            .optional()?
            .with_context(|| format!("rescue session {id} not found in tenant {tenant}"))
    }

    pub(crate) fn plan_bmr(&self, job: &Job, mut plan: Plan) -> Result<Plan> {
        let (p, tenant, dir) = (&job.params, job.tenant.as_str(), plan.dir.clone());
        let s = self.rescue_session(tenant, ident(p, "session")?)?;
        if !valid_agent_id(&s.id) || !valid_agent_id(&s.agent) || p["source_agent"].as_str() != Some(s.agent.as_str()) {
            bail!("invalid rescue session");
        }
        let (Some(host), Some(port)) = (s.host.clone(), s.port) else {
            bail!("the rescue console has not checked in");
        };
        plan.key = format!("agent:{}", s.id);
        let mut agent = json!({"id": s.id, "host": host, "port": port});
        let mut extra = json!({"rescue": {"source_agent": s.agent, "time": num(p, "time")?, "reboot": s.reboot}});
        match (&s.cert_sha256, &s.token_hash) {
            (Some(pin), _) => agent["cert_sha256"] = json!(pin),
            (None, Some(sealed)) => {
                let digest = self
                    .secrets
                    .open(&rescue_token_location(&s.id, &s.agent), sealed)
                    .with_context(|| format!("rescue session {}", s.id))?;
                plan.files.push(("token".into(), digest.as_bytes().to_vec()));
                extra["token_file"] = json!(dir.join("token"));
            }
            (None, None) => bail!(
                "the recovery token of session {} was spent or expired: issue a new one",
                s.id
            ),
        }
        let mut cfg = self.agentctl_base(tenant, job, None, extra);
        cfg["agent"] = agent;
        // a whole machine: allow a long restore
        cfg["timeout_secs"] = json!(24 * 3600);
        plan.files
            .push(("rescue.json".into(), serde_json::to_vec_pretty(&cfg)?));
        plan.steps.push(Step::Cli {
            bin: self.cfg.agentctl_bin.clone(),
            args: vec![dir.join("rescue.json").to_string_lossy().into_owned(), "rescue".into()],
            alert: None,
            capture: false,
        });
        if let Some(v) = &s.p2v {
            if let (Some(sid), Some(node), Some(vmid), Some(vol)) = (
                v["source_id"].as_i64(),
                v["node"].as_str(),
                v["vm"]["vmid"].as_u64(),
                v["vm"]["config_volid"].as_str(),
            ) {
                plan.files.extend(self.pve_config(tenant, sid, &dir, &[])?);
                plan.steps.push(Step::Cli {
                    bin: self.cfg.pve_bin.clone(),
                    args: vec![
                        dir.join("pve.json").to_string_lossy().into_owned(),
                        "p2v-cleanup".into(),
                        node.to_owned(),
                        vmid.to_string(),
                        vol.to_owned(),
                    ],
                    alert: None,
                    capture: false,
                });
            }
        }
        Ok(plan)
    }

    pub(crate) fn plan_p2v(&self, job: &Job, mut plan: Plan) -> Result<Plan> {
        let (p, tenant, dir) = (&job.params, job.tenant.as_str(), plan.dir.clone());
        let s = self.rescue_session(tenant, ident(p, "session")?)?;
        let v = s.p2v.clone().context("not a P2V session")?;
        let sealed = v["token"].as_str().context("P2V session without token")?;
        let token = self
            .secrets
            .open(&rescue_p2v_token_location(&s.id, &s.agent), sealed)
            .with_context(|| format!("rescue session {}", s.id))?;
        let time = num(p, "time")?;
        plan.key = format!("agent:{}", s.id);
        let sid = v["source_id"].as_i64().context("source_id")?;
        plan.files = self.pve_config(tenant, sid, &dir, &[])?;
        let actl = self.agentctl_base(tenant, job, None, json!({}));
        plan.files
            .push(("agentctl.json".into(), serde_json::to_vec_pretty(&actl)?));
        let mut vm = v.clone();
        if let Some(o) = vm.as_object_mut() {
            o.remove("token");
            o.remove("appliance");
            o.remove("appliance_sha256");
        }
        vm["session"] = json!(s.id);
        // what the rescue system reads from the config disk (crate agent-linux rescue::RescueConfig)
        vm["rescue"] = json!({
            "appliance": v["appliance"], "token": token.as_str(), "appliance_sha256": v["appliance_sha256"],
            "network": {"mode": "dhcp"}, "disks": ["auto"], "confirm": true,
        });
        plan.files.push(("p2v.json".into(), serde_json::to_vec_pretty(&vm)?));
        let layout = dir.join("layout.json").to_string_lossy().into_owned();
        plan.steps.push(Step::Cli {
            bin: self.cfg.agentctl_bin.clone(),
            args: vec![
                dir.join("agentctl.json").to_string_lossy().into_owned(),
                "layout".into(),
                s.agent.clone(),
                time.to_string(),
                layout.clone(),
            ],
            alert: None,
            capture: false,
        });
        plan.steps.push(Step::Cli {
            bin: self.cfg.pve_bin.clone(),
            args: vec![
                dir.join("pve.json").to_string_lossy().into_owned(),
                "p2v".into(),
                dir.join("p2v.json").to_string_lossy().into_owned(),
                layout,
            ],
            alert: None,
            capture: false,
        });
        Ok(plan)
    }

    /// Session state from a finished `bmr` / `p2v` job.
    pub(crate) fn rescue_bookkeeping(&self, job: &Job, log: &str, ok: bool) -> Result<()> {
        let Some(id) = job.params["session"].as_str().filter(|s| valid_agent_id(s)) else {
            return Ok(());
        };
        let mut step = None;
        for l in log.lines() {
            if let Some(v) = l
                .strip_prefix("rescue-enrolled ")
                .and_then(|j| serde_json::from_str::<Value>(j).ok())
            {
                let fp = v["cert_sha256"].as_str().unwrap_or_default();
                if v["agent_id"].as_str() == Some(id) && fp.len() == 64 && fp.bytes().all(|b| b.is_ascii_hexdigit()) {
                    self.db.conn().execute(
                        "UPDATE rescue_sessions SET cert_sha256 = ?2, token_hash = NULL WHERE id = ?1 AND tenant = ?3",
                        params![id, fp, job.tenant],
                    )?;
                    self.db.audit(
                        ACTOR,
                        "rescue.enrolled",
                        &format!("rescue/{id}"),
                        &json!({"job": job.id, "cert_sha256": fp}),
                    )?;
                }
            }
            if let Some(s) = l.strip_prefix("rescue-step ") {
                if matches!(s, "apply" | "restore" | "finish") {
                    step = Some(s.to_owned());
                }
            }
            if let Some(v) = l
                .strip_prefix("p2v-vm ")
                .and_then(|j| serde_json::from_str::<Value>(j).ok())
            {
                let p2v: Option<String> = self
                    .db
                    .conn()
                    .query_row("SELECT p2v FROM rescue_sessions WHERE id = ?1", [id], |r| r.get(0))
                    .optional()?
                    .flatten();
                if let Some(mut p) = p2v.and_then(|t| serde_json::from_str::<Value>(&t).ok()) {
                    p["vm"] = json!({"vmid": v["vmid"], "config_volid": v["config_volid"], "node": v["node"]});
                    self.db.conn().execute(
                        "UPDATE rescue_sessions SET p2v = ?2 WHERE id = ?1",
                        params![id, p.to_string()],
                    )?;
                }
            }
        }
        let last_err = log
            .lines()
            .rev()
            .find(|l| l.contains("rror"))
            .map(|l| l.chars().take(500).collect::<String>());
        match (job.kind.as_str(), ok) {
            ("bmr", true) => {
                self.db.conn().execute(
                    "UPDATE rescue_sessions SET state = 'done', step = 'finish', message = NULL WHERE id = ?1",
                    [id],
                )?;
            }
            ("bmr", false) => {
                self.db.conn().execute(
                    "UPDATE rescue_sessions SET state = 'failed', step = COALESCE(?2, step), message = ?3 WHERE id = ?1",
                    params![id, step, last_err.unwrap_or_else(|| format!("job {} failed", job.id))],
                )?;
            }
            ("p2v", false) => {
                self.db.conn().execute(
                    "UPDATE rescue_sessions SET state = 'failed', token_hash = NULL, message = ?2 WHERE id = ?1",
                    params![id, last_err.unwrap_or_else(|| format!("job {} failed", job.id))],
                )?;
            }
            _ => {}
        }
        Ok(())
    }

    /// Rescue agents the appliance must reach (checked-in sessions not finished yet).
    pub(crate) fn rescue_targets(&self) -> Result<Vec<(String, u16)>> {
        let c = self.db.conn();
        let mut st = c.prepare(
            "SELECT host, port FROM rescue_sessions WHERE state IN ('waiting','running') \
             AND host IS NOT NULL AND port IS NOT NULL",
        )?;
        let rows = st
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, u16>(1)?)))?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows
            .into_iter()
            .map(|(h, p)| (h.trim_matches(['[', ']']).to_owned(), p))
            .collect())
    }
}
