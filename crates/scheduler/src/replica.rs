//! Appliance replication in the scheduler (docs/replication.md).
//!
//! Primary: executes approved `replication.key_export` quorum requests (keyd
//! `export-for`, the sealed blob goes into `replication_peers.key_exports`).
//! Secondary: queues `replica_sync` per replication source and tenant on the
//! source's schedule, plans `replica_enroll` / `replica_sync` (spawned
//! `nexus-replica`), records their results, raises the replication alerts and
//! keeps replicated tenants away from keyd `ensure` (their DEKs are imported).

use super::*;
use catalog::secret::replication_source_token_location;

pub(crate) struct SourceRow {
    pub id: i64,
    pub name: String,
    pub url: String,
    pub peer_id: String,
    pub cert_pin: String,
    pub tenants: Vec<String>,
    pub schedule: String,
    pub gfs: Value,
    pub bwlimit: Option<i64>,
    pub state: String,
    pub token_hash: Option<String>,
    pub created: i64,
    pub status: Value,
}

impl Scheduler {
    pub(crate) fn replication_sources(&self) -> Result<Vec<SourceRow>> {
        let c = self.db.conn();
        let mut st = c.prepare(
            "SELECT id, name, url, peer_id, cert_pin, tenants, schedule, gfs, bwlimit, state, token_hash, created, status \
             FROM replication_sources ORDER BY id",
        )?;
        let rows = st.query_map([], |r| {
            Ok(SourceRow {
                id: r.get(0)?,
                name: r.get(1)?,
                url: r.get(2)?,
                peer_id: r.get(3)?,
                cert_pin: r.get(4)?,
                tenants: serde_json::from_str(&r.get::<_, String>(5)?).unwrap_or_default(),
                schedule: r.get(6)?,
                gfs: serde_json::from_str(&r.get::<_, String>(7)?).unwrap_or(Value::Null),
                bwlimit: r.get(8)?,
                state: r.get(9)?,
                token_hash: r.get(10)?,
                created: r.get(11)?,
                status: serde_json::from_str(&r.get::<_, String>(12)?).unwrap_or(json!({})),
            })
        })?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    fn replication_source(&self, id: i64) -> Result<SourceRow> {
        self.replication_sources()?
            .into_iter()
            .find(|s| s.id == id)
            .with_context(|| format!("replication source {id} not found"))
    }

    /// Tenants whose data (and DEKs) come from a primary.
    pub(crate) fn replicated_tenants(&self) -> Result<HashMap<String, String>> {
        Ok(self
            .replication_sources()?
            .into_iter()
            .flat_map(|s| s.tenants.into_iter().map(move |t| (t, s.name.clone())))
            .collect())
    }

    /// `host:port` of every replication source (outbound allow-list).
    pub(crate) fn replication_targets(&self) -> Result<Vec<(String, u16)>> {
        Ok(self
            .replication_sources()?
            .iter()
            .filter_map(|s| {
                let (h, p) = s.url.rsplit_once(':')?;
                Some((h.trim_matches(['[', ']']).to_owned(), p.parse().ok()?))
            })
            .collect())
    }

    /// Secondary: one `replica_sync` per enrolled source and tenant when due.
    pub(crate) fn queue_replication(&mut self, now: i64) -> Result<()> {
        let off = self.disabled_tenants()?;
        for s in self.replication_sources()? {
            if s.state != "enrolled" {
                continue;
            }
            let sched = match Schedule::parse(&s.schedule) {
                Ok(x) => x,
                Err(e) => {
                    self.alert(
                        "warning",
                        "config",
                        &format!("replication source {}: {e}", s.name),
                        None,
                    )?;
                    continue;
                }
            };
            for t in s.tenants.iter().filter(|t| !off.contains(*t)) {
                let active: i64 = self.db.conn().query_row(
                    "SELECT COUNT(*) FROM jobs WHERE kind='replica_sync' AND tenant=?1 AND state IN ('queued','running') \
                     AND json_extract(params,'$.replication_source_id')=?2",
                    params![t, s.id],
                    |r| r.get(0),
                )?;
                if active > 0 {
                    continue;
                }
                let last = self.last_run(
                    &format!("replica/{}/{t}", s.id),
                    "SELECT MAX(created) FROM jobs WHERE kind='replica_sync' AND requested_by='scheduler' \
                     AND tenant=?1 AND json_extract(params,'$.replication_source_id')=?2",
                    &[t, &s.id],
                    now,
                )?;
                if sched.due(last, now) {
                    self.insert_job("replica_sync", t, &json!({"replication_source_id": s.id, "tenant": t}))?;
                }
            }
        }
        Ok(())
    }

    fn replica_config(&self, s: &SourceRow, extra: Value) -> Value {
        let mut cfg = json!({
            "source_id": s.id,
            "name": alerts::hostname(),
            "url": s.url,
            "cert_pin": s.cert_pin,
            "peer_id": s.peer_id,
            "cred_dir": self.cfg.replica_cred_dir(s.id),
            "keyd_socket": self.cfg.keyd_socket,
        });
        if let (Some(c), Some(e)) = (cfg.as_object_mut(), extra.as_object()) {
            c.extend(e.clone());
        }
        cfg
    }

    /// Plans `replica_enroll` / `replica_sync` (spawned `nexus-replica`).
    pub(crate) fn plan_replica(&self, job: &Job, mut plan: Plan) -> Result<Plan> {
        let id = job.params["replication_source_id"]
            .as_i64()
            .context("missing parameter replication_source_id")?;
        let s = self.replication_source(id)?;
        let step = |cmd: &str| Step::Cli {
            bin: self.cfg.replica_bin.clone(),
            args: vec![
                plan.dir.join("replica.json").to_string_lossy().into_owned(),
                cmd.to_owned(),
            ],
            alert: Some("replication"),
            capture: false,
        };
        if job.kind == "replica_enroll" {
            plan.key = format!("replica:{id}");
            let sealed = s
                .token_hash
                .as_deref()
                .context("no enrollment code (consumed): enter a new code from the primary")?;
            let digest = self
                .secrets
                .open(
                    &replication_source_token_location(s.id, &s.url, &s.peer_id, &s.cert_pin),
                    sealed,
                )
                .with_context(|| format!("replication source {id}"))?;
            plan.files.push(("token".into(), digest.as_bytes().to_vec()));
            let cfg = self.replica_config(&s, json!({"token_file": plan.dir.join("token")}));
            plan.files
                .push(("replica.json".into(), serde_json::to_vec_pretty(&cfg)?));
            let st = step("enroll");
            plan.steps.push(st);
            return Ok(plan);
        }
        // replica_sync {replication_source_id, tenant}: exclusive with GC/verify of the tenant
        if s.state != "enrolled" {
            bail!("replication source {} is not enrolled", s.name);
        }
        if !s.tenants.contains(&job.tenant) {
            bail!("tenant {} is not replicated by source {}", job.tenant, s.name);
        }
        plan.key = format!("tenant:{}", job.tenant);
        let cfg = self.replica_config(
            &s,
            json!({"tenant": job.tenant, "store": self.cfg.store_base.join(&job.tenant), "gfs": s.gfs,
                   "bwlimit": s.bwlimit, "parallel": self.cfg.replica_parallel, "held": plan.held}),
        );
        plan.files
            .push(("replica.json".into(), serde_json::to_vec_pretty(&cfg)?));
        let st = step("sync");
        plan.steps.push(st);
        Ok(plan)
    }

    /// `enrolled {json}` / `replicated {json}` lines of nexus-replica → catalog,
    /// audit and alerts.
    pub(crate) fn replica_bookkeeping(&self, job: &Job, log: &str, ok: bool) -> Result<()> {
        let Some(id) = job.params["replication_source_id"].as_i64() else {
            return Ok(());
        };
        let line = |pfx: &str| {
            log.lines()
                .find_map(|l| serde_json::from_str::<Value>(l.strip_prefix(pfx)?).ok())
        };
        let now = catalog::now();
        if job.kind == "replica_enroll" {
            match line("enrolled ") {
                Some(v) => {
                    let fp = v["cert_sha256"].as_str().unwrap_or_default();
                    let keyd = v["keyd_pub"].as_str().unwrap_or_default();
                    let n = self.db.conn().execute(
                        "UPDATE replication_sources SET state='enrolled', cert_sha256=?2, keyd_pub=?3, token_hash=NULL \
                         WHERE id=?1",
                        params![id, fp, keyd],
                    )?;
                    if n == 1 {
                        self.db.audit(
                            ACTOR,
                            "replication_source.enrolled",
                            &format!("replication-source/{id}"),
                            &json!({"job": job.id, "cert_sha256": fp, "tenants": v["tenants"],
                                    "keyd_fingerprint": replication::unhex(keyd).map(|k| replication::key_fingerprint(&k))}),
                        )?;
                    }
                }
                None if !ok => {
                    self.db.conn().execute(
                        "UPDATE replication_sources SET state='failed' WHERE id=?1 AND state='enrolling'",
                        [id],
                    )?;
                }
                None => {}
            }
            return Ok(());
        }
        let s = self.replication_source(id)?;
        let mut status = s.status.clone();
        if !status.is_object() {
            status = json!({});
        }
        let entry = &mut status[&job.tenant];
        if !entry.is_object() {
            *entry = json!({});
        }
        if let (true, Some(r)) = (ok, line("replicated ")) {
            entry["last_ok"] = json!(now);
            entry["last_error"] = Value::Null;
            entry["imported"] = json!(r["imported"].as_array().map_or(0, Vec::len));
            entry["bytes"] = r["bytes_fetched"].clone();
            entry["remote"] = r["remote"].clone();
            entry["key_versions"] = r["key_versions"].clone();
            entry["job"] = json!(job.id);
            self.db.conn().execute(
                "UPDATE replication_sources SET status=?2, last_sync=?3 WHERE id=?1",
                params![id, status.to_string(), now],
            )?;
            // a report without `holds` (before 15c) leaves the advisories alone
            if let Ok(h) = serde_json::from_value::<Vec<replication::HoldInfo>>(r["holds"].clone()) {
                let imported: Vec<String> = serde_json::from_value(r["imported"].clone()).unwrap_or_default();
                self.hold_advisories(&job.tenant, &s.name, &h, &imported)?;
            }
        } else if !ok {
            let tail: String = log
                .lines()
                .rev()
                .find(|l| !l.trim().is_empty())
                .unwrap_or_default()
                .to_owned();
            entry["last_error"] = json!(tail.chars().take(300).collect::<String>());
            entry["last_error_at"] = json!(now);
            entry["job"] = json!(job.id);
            self.db.conn().execute(
                "UPDATE replication_sources SET status=?2 WHERE id=?1",
                params![id, status.to_string()],
            )?;
        }
        for l in log.lines() {
            if let Some(v) = l.strip_prefix("key-mismatch ") {
                let pfx = format!(
                    "replication of tenant {} from {}: key version mismatch",
                    job.tenant, s.name
                );
                self.alert(
                    "critical",
                    "replication_keys",
                    &format!("{pfx} (re-export the keys on the primary): {v}"),
                    Some(&pfx),
                )?;
                break;
            }
        }
        if let Some(v) = log.lines().find_map(|l| l.strip_prefix("verify-failed ")) {
            self.alert(
                "critical",
                "replication_verify",
                &format!(
                    "replication of tenant {} from {}: verification failed, nothing imported: {v}",
                    job.tenant, s.name
                ),
                None,
            )?;
        }
        Ok(())
    }

    /// Secondary: no successful sync of a source/tenant for longer than the lag limit.
    pub(crate) fn check_replication_lag(&self, now: i64) -> Result<()> {
        for s in self.replication_sources()? {
            if s.state != "enrolled" {
                continue;
            }
            for t in &s.tenants {
                let last = s.status[t]["last_ok"].as_i64().unwrap_or(s.created);
                let key = format!("replication_lag:{}:{t}", s.name);
                if now - last > self.cfg.replication_lag_secs {
                    self.raise(
                        "warning",
                        "replication_lag",
                        &key,
                        &format!(
                            "replication of tenant {t} from {} lags: no successful sync for {} h",
                            s.name,
                            (now - last) / 3600
                        ),
                        Some(t),
                    )?;
                } else {
                    self.resolve(&key)?;
                }
            }
        }
        Ok(())
    }

    /// Primary: executes approved `replication.key_export` requests (docs §5).
    /// keyd seals each tenant's DEKs to the peer keyd's public key; the blob is
    /// stored for the peer to fetch. Never without an approved request.
    pub fn execute_key_exports(&mut self) -> Result<()> {
        let rows: Vec<(i64, String, String, Option<String>)> = {
            let c = self.db.conn();
            let mut st = c.prepare(
                "SELECT id, params, requested_by, decided_by FROM quorum \
                 WHERE action='replication.key_export' AND state='approved' ORDER BY id",
            )?;
            let rows = st.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?;
            rows.collect::<std::result::Result<_, _>>()?
        };
        for (qid, p, by, decided) in rows {
            let p: Value = serde_json::from_str(&p).unwrap_or(Value::Null);
            match self.key_export(qid, &p, &by, decided.as_deref()) {
                Ok(()) => {}
                Err(e) => {
                    let msg = format!("{e:#}");
                    // a request that can never succeed is closed; keyd being down is retried
                    let permanent = !msg.contains("keyd");
                    if permanent {
                        self.db.conn().execute(
                            "UPDATE quorum SET state='expired' WHERE id=?1 AND state='approved'",
                            [qid],
                        )?;
                        self.db.audit(
                            ACTOR,
                            "replication.key_export_failed",
                            &format!("quorum/{qid}"),
                            &json!({"error": msg}),
                        )?;
                    }
                    self.alert(
                        "critical",
                        "replication_keys",
                        &format!("key export (quorum request {qid}) failed: {msg}"),
                        Some(&format!("key export (quorum request {qid}) failed")),
                    )?;
                }
            }
        }
        Ok(())
    }

    fn key_export(&mut self, qid: i64, p: &Value, by: &str, decided: Option<&str>) -> Result<()> {
        // decided by the requester: only an export made while approvals are
        // disabled (web-api records it that way, plan §2), and only while they still are
        let own = decided == Some(by) && !catalog::approvals_enabled(&self.db.conn())?;
        if decided.is_none_or(|d| d == by) && !own {
            bail!("not approved by a second person");
        }
        let peer_id = p["peer_id"].as_str().context("params: peer_id")?;
        let keyd_pub = p["keyd_pub"].as_str().context("params: keyd_pub")?;
        let tenants: Vec<String> = serde_json::from_value(p["tenants"].clone()).context("params: tenants")?;
        let (state, cur_pub, scope, exports): (String, Option<String>, String, String) = self
            .db
            .conn()
            .query_row(
                "SELECT state, keyd_pub, tenants, key_exports FROM replication_peers WHERE id=?1",
                [peer_id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .optional()?
            .with_context(|| format!("replication peer {peer_id} not found"))?;
        if state != "enrolled" || cur_pub.as_deref() != Some(keyd_pub) {
            bail!("replication peer {peer_id} is not enrolled with the approved keyd key");
        }
        let scope: Vec<String> = serde_json::from_str(&scope).unwrap_or_default();
        if tenants.is_empty() || tenants.iter().any(|t| !scope.contains(t) || !valid_name(t)) {
            bail!("tenants outside the peer's scope");
        }
        let pk: [u8; 32] = replication::unhex(keyd_pub)
            .and_then(|b| b.try_into().ok())
            .context("invalid keyd public key")?;
        let mut exports: Value = serde_json::from_str(&exports).unwrap_or(json!({}));
        if !exports.is_object() {
            exports = json!({});
        }
        let mut done = BTreeMap::new();
        for t in &tenants {
            // versions as keyd has them now (ensure: a tenant without backups gets its DEK here)
            let versions = (self.ctx.keys)(t)
                .with_context(|| format!("keyd: keys of tenant {t}"))?
                .versions();
            let blob = keyd::request_export(&self.cfg.keyd_socket, t, &pk, qid)
                .with_context(|| format!("keyd: export of tenant {t}"))?;
            exports[t] = json!({"versions": versions, "blob": replication::hex(&blob), "quorum_id": qid,
                                "created": catalog::now()});
            done.insert(t.clone(), versions);
        }
        let n = self.db.conn().execute(
            "UPDATE replication_peers SET key_exports=?2 WHERE id=?1 AND state='enrolled' AND keyd_pub=?3",
            params![peer_id, exports.to_string(), keyd_pub],
        )?;
        if n != 1 {
            bail!("replication peer {peer_id} changed during the export");
        }
        self.db.conn().execute(
            "UPDATE quorum SET state='executed' WHERE id=?1 AND state='approved'",
            [qid],
        )?;
        self.db.audit(
            ACTOR,
            "replication.key_export",
            &format!("replication-peer/{peer_id}"),
            &json!({"quorum_id": qid, "requested_by": by, "approved_by": decided, "versions": done,
                    "keyd_fingerprint": replication::key_fingerprint(&pk)}),
        )?;
        Ok(())
    }
}
