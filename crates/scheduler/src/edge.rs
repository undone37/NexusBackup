//! Edge proxies for roaming agents, scheduler side (docs/edge.md, catalog v39
//! `edges`, `agents.edge_id / via / edge_pushed`).
//!
//! - **Enrollment:** job `edge_enroll {edge_id}` (`nexus-agentctl … edge-enroll`)
//!   proves the sealed one-time token; `edge-enrolled {json}` pins the edge certificate.
//! - **Control link:** one `nexus-agentctl … edge-link` process per enrolled edge,
//!   restarted 15 s after it ends and replaced when what it pushes changes (agent CA,
//!   pins of the agents assigned to the edge). Its lines update `edges.last_seen /
//!   version / health / log`; `edge-wake` (a "back up now" on a laptop) makes that
//!   agent due for an immediate poll, so the request becomes a job within seconds.
//! - **Routes:** sessions of an agent with an enrolled edge try the direct address
//!   first and then the edge (`agent.edge`, poll `edge`); the poll pushes the edge's
//!   public address to agents with CAP_EDGE (`set_edge`, v1.7) until they confirmed it.
//! - **Firewall:** the edges' control ports (data streams use the same port).

use super::*;
use std::io::BufRead;
use std::process::{Child, Command, Stdio};

/// Keep this many log lines per edge (`edges.log`).
const LOG_KEEP: usize = 200;
/// Wait before restarting an ended link.
const RESTART_SECS: i64 = 15;

pub(crate) struct EdgeLinks {
    links: HashMap<String, (Child, String)>,
    retry: HashMap<String, i64>,
    tx: Sender<(String, String)>,
    rx: Receiver<(String, String)>,
}

impl Default for EdgeLinks {
    fn default() -> Self {
        let (tx, rx) = channel();
        EdgeLinks {
            links: HashMap::new(),
            retry: HashMap::new(),
            tx,
            rx,
        }
    }
}

impl Drop for EdgeLinks {
    fn drop(&mut self) {
        for (c, _) in self.links.values_mut() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

/// `host:port` with IPv6 literals bracketed.
fn host_port(h: &str, p: i64) -> String {
    let h = h.trim_matches(['[', ']']);
    if h.contains(':') {
        format!("[{h}]:{p}")
    } else {
        format!("{h}:{p}")
    }
}

impl Scheduler {
    /// `{host, port, cert_sha256}` of the agent's enrolled edge (agentctl `agent.edge`).
    pub(crate) fn agent_edge_route(&self, agent: &str) -> Result<Option<Value>> {
        Ok(self
            .db
            .conn()
            .query_row(
                "SELECT e.host, e.port, e.cert_sha256 FROM agents a JOIN edges e ON e.id = a.edge_id \
                 WHERE a.id = ?1 AND e.cert_sha256 IS NOT NULL",
                [agent],
                |r| {
                    Ok(
                        json!({"host": r.get::<_, String>(0)?.trim_matches(['[', ']']), "port": r.get::<_, i64>(1)?,
                              "cert_sha256": r.get::<_, String>(2)?}),
                    )
                },
            )
            .optional()?)
    }

    /// The `SetEdge` the agent still needs: (`{addr, cert_sha256}`, key stored in
    /// `agents.edge_pushed` once confirmed); `None` when it has it already.
    pub(crate) fn agent_edge_push(&self, agent: &str, pushed: Option<&str>) -> Result<Option<(Value, String)>> {
        let want: Option<(String, String)> = self
            .db
            .conn()
            .query_row(
                "SELECT e.public_host, e.public_port, e.cert_sha256 FROM agents a JOIN edges e ON e.id = a.edge_id \
                 WHERE a.id = ?1 AND e.cert_sha256 IS NOT NULL",
                [agent],
                |r| Ok((host_port(&r.get::<_, String>(0)?, r.get(1)?), r.get(2)?)),
            )
            .optional()?;
        let (addr, fp) = want.unwrap_or_default();
        let key = if addr.is_empty() {
            String::new()
        } else {
            format!("{addr} {fp}")
        };
        if pushed.unwrap_or_default() == key {
            return Ok(None);
        }
        Ok(Some((json!({"addr": addr, "cert_sha256": fp}), key)))
    }

    /// Firewall: every edge's control port (enrollment included).
    pub(crate) fn edge_targets(&self) -> Result<Vec<(String, u16)>> {
        let c = self.db.conn();
        let mut st = c.prepare("SELECT host, port FROM edges")?;
        let rows = st.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, u16>(1)?)))?;
        Ok(rows
            .filter_map(std::result::Result::ok)
            .map(|(h, p)| (h.trim_matches(['[', ']']).to_owned(), p))
            .collect())
    }

    pub(crate) fn plan_edge_enroll(&self, job: &Job, mut plan: Plan) -> Result<Plan> {
        let id = job.params["edge_id"].as_str().unwrap_or_default().to_owned();
        let (host, port, sealed, expires): (String, u16, Option<String>, Option<i64>) = self
            .db
            .conn()
            .query_row(
                "SELECT host, port, token_hash, token_expires FROM edges WHERE id = ?1",
                [&id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .optional()?
            .with_context(|| format!("edge {id:?} not found"))?;
        let sealed = sealed.context("edge has no enrollment token (create a new token first)")?;
        if expires.is_none_or(|e| e <= catalog::now()) {
            bail!("the enrollment token of edge {id} expired (create a new token)");
        }
        let digest = self
            .secrets
            .open(&catalog::secret::edge_token_location(&id, &host, port), &sealed)
            .with_context(|| format!("edge {id}"))?;
        plan.key = format!("edge:{id}");
        plan.files.push(("token".into(), digest.as_bytes().to_vec()));
        let cfg = self.agentctl_base(
            &job.tenant,
            job,
            None,
            json!({"timeout_secs": 60, "edge": {"id": id, "host": host.trim_matches(['[', ']']), "port": port,
                                                "token_file": plan.dir.join("token")}}),
        );
        plan.files
            .push(("agentctl.json".into(), serde_json::to_vec_pretty(&cfg)?));
        plan.steps.push(Step::Cli {
            bin: self.cfg.agentctl_bin.clone(),
            args: vec![
                plan.dir.join("agentctl.json").to_string_lossy().into_owned(),
                "edge-enroll".into(),
            ],
            alert: None,
            capture: false,
        });
        Ok(plan)
    }

    /// `edge-enrolled {json}`: pin the edge certificate, drop the token.
    pub(crate) fn edge_bookkeeping(&self, job: &Job, log: &str) -> Result<()> {
        let id = job.params["edge_id"].as_str().unwrap_or_default();
        for l in log.lines() {
            let Some(v) = l
                .strip_prefix("edge-enrolled ")
                .and_then(|j| serde_json::from_str::<Value>(j).ok())
            else {
                continue;
            };
            let fp = v["cert_sha256"].as_str().unwrap_or_default();
            if v["edge_id"] != id || fp.len() != 64 || !fp.bytes().all(|b| b.is_ascii_hexdigit()) {
                continue;
            }
            let version = v["version"].as_str().map(|s| s.chars().take(64).collect::<String>());
            self.db.conn().execute(
                "UPDATE edges SET cert_sha256 = ?2, enrolled_at = ?3, version = ?4, token_hash = NULL, \
                 token_expires = NULL WHERE id = ?1",
                params![id, fp.to_ascii_lowercase(), catalog::now(), version],
            )?;
            self.db.audit(
                ACTOR,
                "edge.enrolled",
                &format!("edge/{id}"),
                &json!({"cert_sha256": fp, "version": version}),
            )?;
        }
        Ok(())
    }

    /// Keeps one link per enrolled edge and processes their lines. Returns whether an
    /// agent asked for a backup (the caller starts a poll round right away).
    pub(crate) fn edge_links(&mut self, now: i64) -> Result<bool> {
        let mut woke = false;
        while let Ok((id, line)) = self.edges.rx.try_recv() {
            match self.edge_event(&id, &line, now) {
                Ok(w) => woke |= w,
                Err(e) => eprintln!("<4>scheduler: edge {id}: {e:#}"),
            }
        }
        let edges: Vec<(String, String, u16, String)> = {
            let c = self.db.conn();
            let mut st = c.prepare("SELECT id, host, port, cert_sha256 FROM edges WHERE cert_sha256 IS NOT NULL")?;
            let rows = st.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?;
            rows.collect::<std::result::Result<_, _>>()?
        };
        let off = self.disabled_tenants()?;
        let gone: Vec<String> = self
            .edges
            .links
            .keys()
            .filter(|k| !edges.iter().any(|e| &e.0 == *k))
            .cloned()
            .collect();
        for k in gone {
            if let Some((mut c, _)) = self.edges.links.remove(&k) {
                let _ = c.kill();
                let _ = c.wait();
            }
        }
        for (id, host, port, fp) in edges {
            let agents: Vec<Value> = {
                let c = self.db.conn();
                let mut st = c.prepare(
                    "SELECT id, tenant, cert_sha256, cert_sha256_next FROM agents \
                     WHERE edge_id = ?1 AND cert_sha256 IS NOT NULL ORDER BY id",
                )?;
                let rows = st.query_map([&id], |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, String>(2)?,
                        r.get::<_, Option<String>>(3)?,
                    ))
                })?;
                rows.filter_map(std::result::Result::ok)
                    .filter(|(_, t, _, _)| !off.contains(t))
                    .map(|(a, _, p, n)| {
                        let pins: Vec<String> = [Some(p), n].into_iter().flatten().collect();
                        json!({"id": a, "pins": pins})
                    })
                    .collect()
            };
            let cfg = json!({
                "tenant": settings_tenant(), "ca_dir": self.cfg.agent_ca_path(), "timeout_secs": 60,
                "edge": {"id": id, "host": host.trim_matches(['[', ']']), "port": port, "cert_sha256": fp,
                         "link": {"agents": agents, "update_dir": self.cfg.edge_update_dir}},
            });
            let hash = cfg.to_string();
            if let Some((c, h)) = self.edges.links.get_mut(&id) {
                let running = matches!(c.try_wait(), Ok(None));
                if running && *h == hash {
                    continue;
                }
                if running {
                    let _ = c.kill();
                } else {
                    self.edges.retry.insert(id.clone(), now + RESTART_SECS);
                }
                let _ = c.wait();
                self.edges.links.remove(&id);
            }
            if self.edges.retry.get(&id).is_some_and(|t| *t > now) {
                continue;
            }
            match self.spawn_link(&id, &cfg) {
                Ok(c) => {
                    self.edges.links.insert(id, (c, hash));
                }
                Err(e) => {
                    eprintln!("<4>scheduler: edge {id}: starting the link: {e:#}");
                    self.edges.retry.insert(id, now + RESTART_SECS);
                }
            }
        }
        Ok(woke)
    }

    #[cfg(test)]
    pub(crate) fn edges_running(&mut self, id: &str) -> bool {
        self.edges
            .links
            .get_mut(id)
            .is_some_and(|(c, _)| matches!(c.try_wait(), Ok(None)))
    }

    fn spawn_link(&self, id: &str, cfg: &Value) -> Result<Child> {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        fs::create_dir_all(&self.cfg.runtime_dir)?;
        let path = self.cfg.runtime_dir.join(format!("edge-{id}.json"));
        let _ = fs::remove_file(&path);
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)?
            .write_all(cfg.to_string().as_bytes())?;
        let mut child = Command::new(&self.cfg.agentctl_bin)
            .arg(&path)
            .arg("edge-link")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .spawn()
            .with_context(|| format!("{}", self.cfg.agentctl_bin.display()))?;
        let out = child.stdout.take().context("link stdout")?;
        let (tx, id) = (self.edges.tx.clone(), id.to_owned());
        std::thread::spawn(move || {
            for l in std::io::BufReader::new(out).lines().map_while(std::result::Result::ok) {
                if tx.send((id.clone(), l)).is_err() {
                    break;
                }
            }
        });
        Ok(child)
    }

    /// One line of a link. Returns true for a wake of an agent of this edge.
    fn edge_event(&mut self, id: &str, line: &str, now: i64) -> Result<bool> {
        let (kind, rest) = line.split_once(' ').unwrap_or((line, ""));
        let v: Value = serde_json::from_str(rest).unwrap_or_default();
        match kind {
            "edge-health" => {
                let version = v["version"].as_str().map(|s| s.chars().take(64).collect::<String>());
                self.db.conn().execute(
                    "UPDATE edges SET last_seen = ?2, version = COALESCE(?3, version), health = ?4 WHERE id = ?1",
                    params![id, now, version, v.to_string()],
                )?;
            }
            "edge-log" => {
                let Some(l) = v["line"].as_str() else { return Ok(false) };
                let c = self.db.conn();
                let old: Option<String> = c
                    .query_row("SELECT log FROM edges WHERE id = ?1", [id], |r| r.get(0))
                    .optional()?
                    .flatten();
                let mut log: Vec<String> = old.and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default();
                log.push(l.chars().take(1024).collect());
                let n = log.len();
                if n > LOG_KEEP {
                    log.drain(..n - LOG_KEEP);
                }
                c.execute(
                    "UPDATE edges SET log = ?2 WHERE id = ?1",
                    params![id, serde_json::to_string(&log)?],
                )?;
            }
            "edge-wake" => {
                let Some(agent) = v["agent_id"].as_str().filter(|a| valid_agent_id(a)) else {
                    return Ok(false);
                };
                let ours: bool = self.db.conn().query_row(
                    "SELECT EXISTS (SELECT 1 FROM agents WHERE id = ?1 AND edge_id = ?2)",
                    params![agent, id],
                    |r| r.get(0),
                )?;
                if ours {
                    self.poll.next.remove(agent);
                    return Ok(true);
                }
            }
            "edge-updated" => {
                self.db.audit(ACTOR, "edge.updated", &format!("edge/{id}"), &v)?;
            }
            _ => {}
        }
        Ok(false)
    }
}

/// Appliance-wide jobs and links run under this pseudo tenant (catalog settings).
fn settings_tenant() -> &'static str {
    "-"
}

#[cfg(test)]
mod tests {
    #[test]
    fn host_port_brackets_ipv6() {
        assert_eq!(super::host_port("edge.example.com", 443), "edge.example.com:443");
        assert_eq!(super::host_port("2001:db8::1", 443), "[2001:db8::1]:443");
        assert_eq!(super::host_port("[2001:db8::1]", 8443), "[2001:db8::1]:8443");
    }
}
