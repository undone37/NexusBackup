//! `nexus-scheduler` (docs/control-plane.md "Scheduler"): turns policies into
//! jobs, runs queued jobs by spawning `nexus-pve` / `nexus-offsite` (or, for
//! retention / GC / verify, by operating on the chunk store directly with the
//! tenant keyring from keyd), refreshes the `snapshots` table, raises and
//! delivers alerts. The web-api only writes intent; every job state change made
//! here is audited with actor `scheduler`.
//!
//! Per-tenant layout (all under `Config`): store `<store_base>/<tenant>`,
//! offsite inventory `<offsite_state_base>/<tenant>`, key escrow (output of
//! `keyd export-escrow`) `<escrow_base>/<tenant>`.
//!
//! `sources.config` (kind `pve`, as written by the web-api):
//! ```json
//! { "host": "pve1", "port": 8006, "connect_addr": "10.0.0.5:8006", "ca_pem": "-----BEGIN…",
//!   "token_id": "nexus@pve!backup", "token_secret": "…", "storage": "nexus", "fleecing_storage": "local-lvm",
//!   "nodes": { "pve1": { "host": "10.0.0.5", "port": 22, "key": "/etc/nexus/ssh/pve1",
//!                        "known_hosts": "/etc/nexus/ssh/known_hosts" } } }
//! ```
//! `nodes` may also be an array of `{ "name": …, … }`. The API fields may sit
//! under `"api"` instead; nodes may carry inline `key_pem` / `known_hosts_text`
//! (the web-api refuses inline secrets, so normally paths). `ca_pem` and
//! `token_secret` are written to 0600 files in the job dir.
//!
//! `tenants.offsite`: `{ "remote": { "type": "sftp", "host": …, "user": …, "host_key": …,
//! "key_file": "/path", "port"?, "base_dir"? } | { "type": "local", "path": … },
//! "bwlimit"?: bytes/s, "uploaders"?: n }`. No `remote` = no offsite for this tenant.
//!
//! Job params beyond the contract: `source_id` may be given for `backup {vmid}`,
//! restores and file jobs; without it the source is found via the tenant's
//! groups (or the tenant's only source). `instant_recover` takes `link_down`.
//! `files_get` writes `<downloads>/<download_token>.<format>` (token set by the
//! web-api). Structured results go into `jobs.result` (see [`Scheduler::finish`]).

pub mod alerts;
pub mod run;
pub mod schedule;

use anyhow::{bail, Context, Result};
use catalog::rusqlite::{params, OptionalExtension};
use catalog::Catalog;
use chunkstore::retention::Gfs;
use chunkstore::Options;
use run::{execute, Ctx, Finished, KeySource, Outcome, Plan, Step};
use schedule::Schedule;
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::Arc;
use std::time::{Duration, Instant};

pub const ACTOR: &str = "scheduler";

/// (file name in the job dir, contents)
type Files = Vec<(String, Vec<u8>)>;

#[derive(Deserialize, Clone, Debug)]
#[serde(default)]
pub struct Config {
    pub catalog: PathBuf,
    pub store_base: PathBuf,
    pub offsite_state_base: PathBuf,
    pub escrow_base: PathBuf,
    pub keyd_socket: PathBuf,
    pub downloads: PathBuf,
    /// private (0700) dir for generated job configs
    pub runtime_dir: PathBuf,
    /// alert delivery cursor
    pub state_dir: PathBuf,
    pub pve_bin: PathBuf,
    pub offsite_bin: PathBuf,
    pub alerts_config: PathBuf,
    /// full tick (scheduling, refresh, alerts)
    pub tick_secs: u64,
    /// between ticks: pick up newly queued jobs
    pub poll_secs: u64,
    /// running jobs at once (over all sources)
    pub max_parallel: usize,
    /// bytes of output kept per job
    pub log_max: usize,
    /// daily gc + verify per tenant
    pub maintenance: String,
    /// verify re-reads 1/verify_parts of the chunks per run (rolling)
    pub verify_parts: u64,
    pub refresh_secs: i64,
    pub download_ttl_secs: i64,
    pub offsite_lag_secs: i64,
    /// alert above this used share of the store file system
    pub capacity_threshold: f64,
    /// retry delays of alert delivery
    pub alert_retry_secs: [u64; 2],
}

impl Default for Config {
    fn default() -> Self {
        let lib = Path::new("/var/lib/nexus");
        Config {
            catalog: lib.join("catalog/catalog.db"),
            store_base: lib.join("chunkstore"),
            offsite_state_base: lib.join("offsite"),
            escrow_base: lib.join("escrow"),
            keyd_socket: "/run/nexus-keyd/keyd.sock".into(),
            downloads: lib.join("downloads"),
            runtime_dir: "/run/nexus-scheduler".into(),
            state_dir: lib.join("scheduler"),
            pve_bin: "/usr/libexec/nexus/nexus-pve".into(),
            offsite_bin: "/usr/libexec/nexus/nexus-offsite".into(),
            alerts_config: "/etc/nexus/alerts.json".into(),
            tick_secs: 30,
            poll_secs: 2,
            max_parallel: 4,
            log_max: 256 << 10,
            maintenance: "daily 03:00".into(),
            verify_parts: 7,
            refresh_secs: 900,
            download_ttl_secs: 86400,
            offsite_lag_secs: 48 * 3600,
            capacity_threshold: 0.75,
            alert_retry_secs: [10, 60],
        }
    }
}

#[derive(Debug, Clone)]
pub struct Job {
    pub id: i64,
    pub kind: String,
    pub tenant: String,
    pub params: Value,
}

struct GroupRow {
    id: i64,
    tenant: String,
    source_id: i64,
    guests: Vec<u32>,
    schedule: String,
    gfs: Gfs,
    offsite: bool,
}

pub struct Scheduler {
    pub cfg: Config,
    pub db: Arc<Catalog>,
    ctx: Arc<Ctx>,
    running: HashMap<i64, String>,
    tx: Sender<Finished>,
    rx: Receiver<Finished>,
    /// first time an item without scheduled history was seen (no immediate run)
    first_seen: HashMap<String, i64>,
    /// tenants whose keys are known to exist in keyd
    keyed: HashSet<String>,
    dirty: BTreeSet<String>,
    last_refresh: i64,
    alert_cursor: i64,
    alert_tx: Sender<alerts::Alert>,
    host: String,
    /// time of the current tick: `created` of queued jobs (due computation)
    now: i64,
}

fn valid_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && !s.starts_with(['.', '-'])
        && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}

fn ident<'a>(p: &'a Value, k: &str) -> Result<&'a str> {
    let v = p[k].as_str().with_context(|| format!("missing parameter {k}"))?;
    if !valid_name(v) {
        bail!("invalid {k} {v:?}");
    }
    Ok(v)
}

fn num(p: &Value, k: &str) -> Result<u64> {
    p[k].as_u64()
        .or_else(|| p[k].as_str().and_then(|s| s.parse().ok()))
        .with_context(|| format!("missing or invalid parameter {k}"))
}

/// `vm-100` / `ct-200` -> (is_ct, vmid)
fn guest(source: &str) -> Result<(bool, u32)> {
    let parse = |s: &str| s.parse::<u32>().ok().filter(|v| *v > 0);
    match (source.strip_prefix("vm-"), source.strip_prefix("ct-")) {
        (Some(v), _) => parse(v).map(|v| (false, v)),
        (_, Some(v)) => parse(v).map(|v| (true, v)),
        _ => None,
    }
    .with_context(|| format!("invalid source {source:?} (expected vm-<id> or ct-<id>)"))
}

fn gfs_of(v: &Value) -> Gfs {
    let d = Gfs::default();
    let f = |k: &str, def: u32| v[k].as_u64().map_or(def, |n| n.min(10_000) as u32);
    Gfs {
        daily: f("daily", d.daily),
        weekly: f("weekly", d.weekly),
        monthly: f("monthly", d.monthly),
        yearly: f("yearly", d.yearly),
    }
}

/// `<download_token>.<format>`: token = 64 hex chars chosen by the web-api.
fn download_file(p: &Value) -> Result<String> {
    let token = p["download_token"].as_str().unwrap_or_default();
    if token.len() != 64 || !token.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!("files_get needs a download_token (64 hex characters)");
    }
    let ext = match p["format"].as_str().unwrap_or("tar") {
        f @ ("tar" | "zip") => f,
        f => bail!("invalid format {f:?}"),
    };
    Ok(format!("{token}.{ext}"))
}

impl Scheduler {
    pub fn new(cfg: Config, db: Arc<Catalog>, keys: KeySource, store_options: fn() -> Options) -> Result<Self> {
        let (tx, rx) = channel();
        let alerts_cfg = alerts::AlertsConfig::load(&cfg.alerts_config)?;
        let alert_tx = alerts::spawn_delivery(alerts_cfg, cfg.alert_retry_secs.map(Duration::from_secs));
        let ctx = Arc::new(Ctx {
            keys,
            store_options,
            log_max: cfg.log_max,
        });
        let mut s = Scheduler {
            cfg,
            db,
            ctx,
            running: HashMap::new(),
            tx,
            rx,
            first_seen: HashMap::new(),
            keyed: HashSet::new(),
            dirty: BTreeSet::new(),
            last_refresh: i64::MIN,
            alert_cursor: 0,
            alert_tx,
            host: alerts::hostname(),
            now: catalog::now(),
        };
        s.startup()?;
        Ok(s)
    }

    /// Production wiring: catalog file, keyring from keyd.
    pub fn open(cfg: Config) -> Result<Self> {
        let db = Arc::new(Catalog::open(&cfg.catalog).context("catalog")?);
        let sock = cfg.keyd_socket.clone();
        Self::new(
            cfg,
            db,
            // ensure: tenants are created in the UI; keyd creates their first DEK on first use
            Arc::new(move |t: &str| keyd::ensure_keyring(&sock, t)),
            Options::default,
        )
    }

    fn startup(&mut self) -> Result<()> {
        // runtime dir: private, and no secrets of a crashed predecessor left behind
        fs::create_dir_all(&self.cfg.runtime_dir)?;
        fs::set_permissions(&self.cfg.runtime_dir, fs::Permissions::from_mode(0o700))?;
        for e in fs::read_dir(&self.cfg.runtime_dir)? {
            let p = e?.path();
            if p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("job-"))
            {
                fs::remove_dir_all(&p)?;
            }
        }
        // downloads: setgid dir in the catalog's group (= nexus-catalog), so web-api can read
        fs::create_dir_all(&self.cfg.downloads)?;
        fs::set_permissions(&self.cfg.downloads, fs::Permissions::from_mode(0o2750))?;
        if let Some(gid) = self
            .cfg
            .catalog
            .parent()
            .and_then(|p| fs::metadata(p).ok())
            .map(|m| m.gid())
        {
            for p in std::iter::once(self.cfg.downloads.clone())
                .chain(fs::read_dir(&self.cfg.downloads)?.filter_map(|e| e.ok().map(|e| e.path())))
            {
                if let Err(e) = std::os::unix::fs::chown(&p, None, Some(gid)) {
                    eprintln!("<4>cannot set group of {}: {e}", p.display());
                }
            }
        }
        fs::create_dir_all(&self.cfg.state_dir)?;
        self.alert_cursor = match fs::read_to_string(self.cursor_path()) {
            Ok(s) => s.trim().parse().unwrap_or(0),
            Err(_) => self
                .db
                .conn()
                .query_row("SELECT COALESCE(MAX(id), 0) FROM alerts", [], |r| r.get(0))?,
        };
        self.recover()
    }

    fn cursor_path(&self) -> PathBuf {
        self.cfg.state_dir.join("alerts.cursor")
    }

    /// Jobs left `running` by a crashed scheduler are failed with a note.
    pub fn recover(&mut self) -> Result<()> {
        let stale: Vec<(i64, String)> = {
            let c = self.db.conn();
            let mut st = c.prepare("SELECT id, kind FROM jobs WHERE state='running' ORDER BY id")?;
            let rows = st.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?;
            rows.collect::<std::result::Result<_, _>>()?
        };
        for (id, kind) in stale {
            self.db.conn().execute(
                "UPDATE jobs SET state='failed', finished=?1, \
                 log = log || '\n[scheduler] interrupted: the scheduler stopped while this job was running' \
                 WHERE id=?2 AND state='running'",
                params![catalog::now(), id],
            )?;
            self.db.audit(
                ACTOR,
                "job.failed",
                &format!("job/{id}"),
                &json!({"kind": kind, "reason": "scheduler restart"}),
            )?;
        }
        Ok(())
    }

    // ---------------------------------------------------------------- loop

    pub fn run(&mut self, stop: &AtomicBool) -> Result<()> {
        let tick = Duration::from_secs(self.cfg.tick_secs.max(1));
        let poll = Duration::from_secs(self.cfg.poll_secs.clamp(1, self.cfg.tick_secs.max(1)));
        while !stop.load(Ordering::Relaxed) {
            if let Err(e) = self.tick(catalog::now()) {
                eprintln!("<3>scheduler tick failed: {e:#}");
            }
            let next = Instant::now() + tick;
            while Instant::now() < next && !stop.load(Ordering::Relaxed) {
                let wait = poll.min(next.saturating_duration_since(Instant::now()));
                if let Ok(f) = self.rx.recv_timeout(wait) {
                    self.now = catalog::now();
                    self.log_err(|s| s.finish(f));
                }
                self.log_err(|s| s.start_jobs());
            }
        }
        Ok(())
    }

    fn log_err(&mut self, f: impl FnOnce(&mut Self) -> Result<()>) {
        if let Err(e) = f(self) {
            eprintln!("<3>scheduler: {e:#}");
        }
    }

    /// One full scheduling round at time `now` (unix seconds).
    pub fn tick(&mut self, now: i64) -> Result<()> {
        self.now = now;
        self.collect();
        self.log_err(|s| s.ensure_tenant_keys());
        self.log_err(|s| s.expire_downloads(catalog::now()));
        self.log_err(|s| s.queue_approved_gc());
        self.log_err(|s| s.queue_scheduled(now));
        self.log_err(|s| s.queue_maintenance(now));
        self.log_err(|s| s.start_jobs());
        let all = now.saturating_sub(self.last_refresh) >= self.cfg.refresh_secs;
        if all || !self.dirty.is_empty() {
            self.log_err(|s| s.refresh(now, all));
            if all {
                self.last_refresh = now;
                self.log_err(|s| s.check_capacity());
            }
        }
        self.log_err(|s| s.check_offsite_lag(now));
        self.deliver_alerts()
    }

    /// Handles finished jobs without blocking.
    pub fn collect(&mut self) {
        while let Ok(f) = self.rx.try_recv() {
            self.log_err(|s| s.finish(f));
        }
    }

    /// Waits until no job is running (tests, shutdown).
    pub fn wait_idle(&mut self, timeout: Duration) -> Result<()> {
        let end = Instant::now() + timeout;
        while !self.running.is_empty() {
            let left = end
                .checked_duration_since(Instant::now())
                .context("jobs still running")?;
            if let Ok(f) = self.rx.recv_timeout(left) {
                self.finish(f)?;
            }
        }
        Ok(())
    }

    pub fn running(&self) -> Vec<(i64, String)> {
        let mut v: Vec<_> = self.running.iter().map(|(i, k)| (*i, k.clone())).collect();
        v.sort();
        v
    }

    // ------------------------------------------------------------- queueing

    pub fn insert_job(&self, kind: &str, tenant: &str, params: &Value) -> Result<i64> {
        let id = {
            let c = self.db.conn();
            c.execute(
                "INSERT INTO jobs (kind, tenant, params, state, requested_by, created) VALUES (?1,?2,?3,'queued',?4,?5)",
                params![kind, tenant, params.to_string(), ACTOR, self.now],
            )?;
            c.last_insert_rowid()
        };
        self.db.audit(
            ACTOR,
            "job.queue",
            &format!("job/{id}"),
            &json!({"kind": kind, "tenant": tenant, "params": params}),
        )?;
        Ok(id)
    }

    fn groups(&self) -> Result<Vec<GroupRow>> {
        let c = self.db.conn();
        let mut st = c.prepare(
            "SELECT g.id, g.tenant, g.source_id, g.guests, p.schedule, p.gfs, p.offsite \
             FROM groups g JOIN policies p ON p.id = g.policy_id ORDER BY g.id",
        )?;
        let rows = st.query_map([], |r| {
            let guests: String = r.get(3)?;
            let gfs: String = r.get(5)?;
            Ok(GroupRow {
                id: r.get(0)?,
                tenant: r.get(1)?,
                source_id: r.get(2)?,
                guests: serde_json::from_str(&guests).unwrap_or_default(),
                schedule: r.get(4)?,
                gfs: gfs_of(&serde_json::from_str(&gfs).unwrap_or(Value::Null)),
                offsite: r.get::<_, i64>(6)? != 0,
            })
        })?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    /// `last_run` for an item: newest scheduler-queued job matching `filter`,
    /// else the first time this scheduler saw the item (no run on first sight).
    fn last_run(&mut self, item: &str, sql: &str, p: &[&dyn catalog::rusqlite::ToSql], now: i64) -> Result<i64> {
        let last: Option<i64> = self.db.conn().query_row(sql, p, |r| r.get(0))?;
        Ok(match last {
            Some(t) => t,
            None => *self.first_seen.entry(item.to_owned()).or_insert(now),
        })
    }

    fn queue_scheduled(&mut self, now: i64) -> Result<()> {
        for g in self.groups()? {
            let sched = match Schedule::parse(&g.schedule) {
                Ok(s) => s,
                Err(e) => {
                    self.alert("warning", "config", &format!("group {}: {e}", g.id), None)?;
                    continue;
                }
            };
            let active: i64 = self.db.conn().query_row(
                "SELECT COUNT(*) FROM jobs WHERE kind='backup' AND state IN ('queued','running') \
                 AND json_extract(params,'$.group_id')=?1",
                [g.id],
                |r| r.get(0),
            )?;
            if active > 0 {
                continue;
            }
            let last = self.last_run(
                &format!("group/{}", g.id),
                "SELECT MAX(created) FROM jobs WHERE kind='backup' AND requested_by='scheduler' \
                 AND json_extract(params,'$.group_id')=?1",
                &[&g.id],
                now,
            )?;
            if sched.due(last, now) {
                self.insert_job("backup", &g.tenant, &json!({"group_id": g.id}))?;
            }
        }
        Ok(())
    }

    fn tenants(&self) -> Result<Vec<(String, Value)>> {
        let c = self.db.conn();
        let mut st = c.prepare("SELECT name, offsite FROM tenants ORDER BY name")?;
        let rows = st.query_map([], |r| {
            let o: String = r.get(1)?;
            Ok((r.get(0)?, serde_json::from_str(&o).unwrap_or(Value::Null)))
        })?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    fn queue_maintenance(&mut self, now: i64) -> Result<()> {
        let sched = Schedule::parse(&self.cfg.maintenance)?;
        for (tenant, _) in self.tenants()? {
            if !valid_name(&tenant) || !self.cfg.store_base.join(&tenant).join("keycheck").exists() {
                continue; // no backups yet
            }
            for kind in ["gc", "verify"] {
                let last = self.last_run(
                    &format!("{kind}/{tenant}"),
                    "SELECT MAX(created) FROM jobs WHERE kind=?1 AND tenant=?2 AND requested_by='scheduler'",
                    &[&kind, &tenant],
                    now,
                )?;
                if sched.due(last, now) {
                    self.insert_job(kind, &tenant, &json!({}))?;
                }
            }
        }
        Ok(())
    }

    /// Approved `gc_large` quorum requests become a GC job with the approval flag.
    fn queue_approved_gc(&mut self) -> Result<()> {
        let rows: Vec<(i64, String)> = {
            let c = self.db.conn();
            c.execute(
                "UPDATE quorum SET state='expired' WHERE action='gc_large' AND state='pending' AND created < ?1",
                [catalog::now() - 72 * 3600],
            )?;
            let mut st = c.prepare(
                "SELECT q.id, q.params FROM quorum q WHERE q.action='gc_large' AND q.state='approved' \
                 AND NOT EXISTS (SELECT 1 FROM jobs j WHERE j.kind='gc' AND json_extract(j.params,'$.quorum_id')=q.id)",
            )?;
            let rows = st.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?;
            rows.collect::<std::result::Result<_, _>>()?
        };
        for (id, p) in rows {
            let p: Value = serde_json::from_str(&p).unwrap_or(Value::Null);
            let Some(tenant) = p["tenant"].as_str() else { continue };
            self.insert_job("gc", tenant, &json!({"approved": true, "quorum_id": id}))?;
        }
        Ok(())
    }

    // ------------------------------------------------------------- running

    fn queued(&self) -> Result<Vec<Job>> {
        let c = self.db.conn();
        let mut st = c.prepare("SELECT id, kind, tenant, params FROM jobs WHERE state='queued' ORDER BY id")?;
        let rows = st.query_map([], |r| {
            let p: String = r.get(3)?;
            Ok(Job {
                id: r.get(0)?,
                kind: r.get(1)?,
                tenant: r.get(2)?,
                params: serde_json::from_str(&p).unwrap_or(Value::Null),
            })
        })?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    /// FIFO over queued jobs; a job whose key (source) is busy waits, later
    /// jobs of other sources may pass it. At most `max_parallel` at once.
    pub fn start_jobs(&mut self) -> Result<()> {
        if self.running.len() >= self.cfg.max_parallel {
            return Ok(());
        }
        let mut busy: HashSet<String> = self.running.values().cloned().collect();
        for job in self.queued()? {
            if self.running.len() >= self.cfg.max_parallel {
                break;
            }
            let plan = match self.plan(&job) {
                Ok(p) => p,
                Err(e) => {
                    self.fail_unstartable(&job, &format!("{e:#}"))?;
                    continue;
                }
            };
            if !busy.insert(plan.key.clone()) {
                continue;
            }
            let changed = self.db.conn().execute(
                "UPDATE jobs SET state='running', started=?1 WHERE id=?2 AND state='queued'",
                params![catalog::now(), job.id],
            )?;
            if changed == 0 {
                busy.remove(&plan.key);
                continue; // cancelled meanwhile
            }
            self.db.audit(
                ACTOR,
                "job.start",
                &format!("job/{}", job.id),
                &json!({"kind": job.kind, "tenant": job.tenant, "key": plan.key}),
            )?;
            self.running.insert(job.id, plan.key.clone());
            let (tx, ctx, id) = (self.tx.clone(), self.ctx.clone(), job.id);
            std::thread::spawn(move || {
                let f = execute(id, &plan, &ctx);
                let _ = tx.send(f);
            });
        }
        Ok(())
    }

    fn fail_unstartable(&mut self, job: &Job, msg: &str) -> Result<()> {
        let changed = self.db.conn().execute(
            "UPDATE jobs SET state='failed', started=?1, finished=?1, log=?2 WHERE id=?3 AND state='queued'",
            params![catalog::now(), format!("[scheduler] {msg}\n"), job.id],
        )?;
        if changed > 0 {
            self.db.audit(
                ACTOR,
                "job.failed",
                &format!("job/{}", job.id),
                &json!({"kind": job.kind, "error": msg}),
            )?;
            self.alert(
                "critical",
                "job_failed",
                &format!("{} job {} ({}) failed: {msg}", job.kind, job.id, job.tenant),
                None,
            )?;
        }
        Ok(())
    }

    fn job(&self, id: i64) -> Result<Job> {
        Ok(self
            .db
            .conn()
            .query_row("SELECT id, kind, tenant, params FROM jobs WHERE id=?1", [id], |r| {
                let p: String = r.get(3)?;
                Ok(Job {
                    id: r.get(0)?,
                    kind: r.get(1)?,
                    tenant: r.get(2)?,
                    params: serde_json::from_str(&p).unwrap_or(Value::Null),
                })
            })?)
    }

    /// Records a finished job, then queues follow-ups and raises alerts.
    pub fn finish(&mut self, f: Finished) -> Result<()> {
        self.running.remove(&f.id);
        let job = self.job(f.id)?;
        let ok = f.outcome == Outcome::Ok;
        let mut log = f.log;
        let result = if ok {
            self.result(&job, f.stdout.as_deref(), &mut log)
        } else {
            None
        };
        let state = if ok { "ok" } else { "failed" };
        self.db.conn().execute(
            "UPDATE jobs SET state=?1, finished=?2, log=?3, result=?4 WHERE id=?5",
            params![state, catalog::now(), log, result.map(|r| r.to_string()), job.id],
        )?;
        self.db.audit(
            ACTOR,
            &format!("job.{state}"),
            &format!("job/{}", job.id),
            &json!({"kind": job.kind, "tenant": job.tenant}),
        )?;
        if matches!(job.kind.as_str(), "backup" | "retention" | "offsite" | "gc") {
            self.dirty.insert(job.tenant.clone());
        }
        if let Some(q) = job.params["quorum_id"].as_i64() {
            self.db.conn().execute(
                "UPDATE quorum SET state='executed' WHERE id=?1 AND state='approved'",
                [q],
            )?;
            self.db.audit(
                ACTOR,
                "quorum.execute",
                &format!("quorum/{q}"),
                &json!({"job": job.id, "state": state}),
            )?;
        }
        match f.outcome {
            Outcome::Ok => self.follow_up(&job)?,
            Outcome::Quorum { message } => self.request_gc_quorum(&job, &message)?,
            Outcome::Failed { alert } => {
                let tail: String = log
                    .lines()
                    .rev()
                    .take(3)
                    .collect::<Vec<_>>()
                    .into_iter()
                    .rev()
                    .collect::<Vec<_>>()
                    .join(" | ");
                let (sev, kind, what) = match alert {
                    Some("verify") => ("critical", "verify", "verification failed"),
                    Some("inventory") => ("critical", "inventory", "offsite inventory anomaly"),
                    _ => ("critical", "job_failed", "failed"),
                };
                self.alert(
                    sev,
                    kind,
                    &format!("{} job {} ({}) {what}: {tail}", job.kind, job.id, job.tenant),
                    None,
                )?;
            }
        }
        Ok(())
    }

    /// Structured result of a successful job (`jobs.result`, docs/control-plane.md).
    fn result(&self, job: &Job, stdout: Option<&str>, log: &mut String) -> Option<Value> {
        match job.kind.as_str() {
            "files_list" => {
                let out = stdout.unwrap_or_default();
                match serde_json::from_str::<Value>(out) {
                    Ok(entries @ Value::Array(_)) => Some(json!({ "entries": entries })),
                    _ => {
                        log.push_str(out);
                        log.push_str("[scheduler] unexpected listing output (no JSON array)\n");
                        None
                    }
                }
            }
            "files_get" => {
                let out = stdout.unwrap_or_default();
                log.push_str(out);
                let file = download_file(&job.params).ok()?;
                let path = self.cfg.downloads.join(&file);
                let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o640));
                let size = fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
                // `<n> entries written to <out>` (nexus-pve files/ct-files get)
                let entries = out
                    .lines()
                    .find_map(|l| l.split_once(" entries written to ")?.0.trim().parse::<u64>().ok());
                let r = json!({
                    "download_token": job.params["download_token"],
                    "format": job.params["format"].as_str().unwrap_or("tar"),
                    "entries": entries,
                    "size": size,
                    "expires": catalog::now() + self.cfg.download_ttl_secs,
                });
                log.push_str(&format!("[scheduler] download ready: {file} ({size} bytes)\n"));
                Some(r)
            }
            "backup" => {
                // `committed <source>/<time>` per guest (nexus-pve backup-all)
                let snaps: Vec<Value> = log
                    .lines()
                    .filter_map(|l| {
                        let (s, t) = l
                            .strip_prefix("committed ")?
                            .split_whitespace()
                            .next()?
                            .rsplit_once('/')?;
                        Some(json!({"source": s, "time": t.parse::<i64>().ok()?}))
                    })
                    .collect();
                let mut r = json!({ "snapshots": snaps });
                if let [one] = snaps.as_slice() {
                    r["source"] = one["source"].clone();
                    r["time"] = one["time"].clone();
                }
                Some(r)
            }
            _ => None,
        }
    }

    fn follow_up(&mut self, job: &Job) -> Result<()> {
        match job.kind.as_str() {
            "backup" => {
                let mut p = json!({"chain": true});
                for k in ["group_id", "source_id", "vmid"] {
                    if !job.params[k].is_null() {
                        p[k] = job.params[k].clone();
                    }
                }
                self.insert_job("retention", &job.tenant, &p)?;
            }
            "retention" if job.params["chain"].as_bool() == Some(true) => {
                let wants = match job.params["group_id"].as_i64() {
                    Some(g) => self.groups()?.iter().any(|r| r.id == g && r.offsite),
                    None => job.params["vmid"].as_u64().is_some_and(|v| {
                        self.groups().is_ok_and(|gs| {
                            gs.iter()
                                .any(|g| g.tenant == job.tenant && g.offsite && g.guests.contains(&(v as u32)))
                        })
                    }),
                };
                let pending: i64 = self.db.conn().query_row(
                    "SELECT COUNT(*) FROM jobs WHERE kind='offsite' AND tenant=?1 AND state='queued'",
                    [&job.tenant],
                    |r| r.get(0),
                )?;
                if wants && pending == 0 && self.offsite_cfg(&job.tenant)?.is_some() {
                    self.insert_job("offsite", &job.tenant, &json!({"chain": true}))?;
                }
            }
            "verify" => {
                self.db.conn().execute(
                    "UPDATE snapshots SET verified=?1 WHERE tenant=?2 AND local=1",
                    params![catalog::now(), job.tenant],
                )?;
            }
            _ => {}
        }
        Ok(())
    }

    fn request_gc_quorum(&mut self, job: &Job, message: &str) -> Result<()> {
        let open: i64 = self.db.conn().query_row(
            "SELECT COUNT(*) FROM quorum WHERE action='gc_large' AND state IN ('pending','approved') \
             AND json_extract(params,'$.tenant')=?1",
            [&job.tenant],
            |r| r.get(0),
        )?;
        if open > 0 {
            return Ok(());
        }
        let id = {
            let c = self.db.conn();
            c.execute(
                "INSERT INTO quorum (action, params, requested_by, created, state) VALUES ('gc_large', ?1, ?2, ?3, 'pending')",
                params![
                    json!({"tenant": job.tenant, "job": job.id, "reason": message}).to_string(),
                    ACTOR,
                    catalog::now()
                ],
            )?;
            c.last_insert_rowid()
        };
        self.db.audit(
            ACTOR,
            "quorum.request",
            &format!("quorum/{id}"),
            &json!({"action": "gc_large", "tenant": job.tenant, "job": job.id}),
        )?;
        self.alert(
            "warning",
            "gc_quorum",
            &format!(
                "GC for tenant {} needs approval by a security officer (quorum request {id}): {message}",
                job.tenant
            ),
            None,
        )
    }

    // ------------------------------------------------------------- planning

    fn source(&self, tenant: &str, id: i64) -> Result<Value> {
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
        if kind != "pve" {
            bail!("source {id}: unsupported kind {kind}");
        }
        serde_json::from_str(&cfg).context("source config")
    }

    /// Source of a job: explicit `source_id`, else the group containing the
    /// guest, else the tenant's only source.
    fn resolve_source(&self, job: &Job, vmid: Option<u32>) -> Result<i64> {
        if let Some(s) = job.params["source_id"].as_i64() {
            return Ok(s);
        }
        if let Some(v) = vmid {
            if let Some(g) = self
                .groups()?
                .iter()
                .find(|g| g.tenant == job.tenant && g.guests.contains(&v))
            {
                return Ok(g.source_id);
            }
        }
        let ids: Vec<i64> = {
            let c = self.db.conn();
            let mut st = c.prepare("SELECT id FROM sources WHERE tenant=?1")?;
            let rows = st.query_map([&job.tenant], |r| r.get(0))?;
            rows.collect::<std::result::Result<_, _>>()?
        };
        match ids.as_slice() {
            [one] => Ok(*one),
            _ => bail!("cannot determine the source: give source_id"),
        }
    }

    fn job_dir(&self, id: i64) -> PathBuf {
        self.cfg.runtime_dir.join(format!("job-{id}"))
    }

    /// nexus-pve config for a source (secrets as files in the job dir).
    fn pve_config(&self, tenant: &str, source_id: i64, dir: &Path, vmids: &[u32]) -> Result<Files> {
        let src = self.source(tenant, source_id)?;
        let api = if src["api"].is_object() { &src["api"] } else { &src };
        let s = |v: &Value, k: &str| -> Result<String> {
            v[k].as_str()
                .map(str::to_owned)
                .with_context(|| format!("source {source_id}: missing {k}"))
        };
        let mut files = vec![
            ("ca.pem".to_owned(), s(api, "ca_pem")?.into_bytes()),
            ("token".to_owned(), s(api, "token_secret")?.into_bytes()),
        ];
        let mut nodes = serde_json::Map::new();
        let node_list: Vec<(String, &Value)> = match &src["nodes"] {
            Value::Object(m) => m.iter().map(|(k, v)| (k.clone(), v)).collect(),
            Value::Array(a) => a
                .iter()
                .map(|n| (n["name"].as_str().unwrap_or_default().to_owned(), n))
                .collect(),
            _ => Vec::new(),
        };
        for (name, n) in &node_list {
            if !valid_name(name) {
                bail!("source {source_id}: invalid node name {name:?}");
            }
            let mut file_or_path = |inline: &str, path: &str, fname: String| -> Result<String> {
                if let Some(text) = n[inline].as_str() {
                    let mut t = text.to_owned();
                    if !t.ends_with('\n') {
                        t.push('\n');
                    }
                    files.push((fname.clone(), t.into_bytes()));
                    Ok(dir.join(fname).to_string_lossy().into_owned())
                } else {
                    s(n, path)
                }
            };
            let key = file_or_path("key_pem", "key", format!("node-{name}.key"))?;
            let kh = file_or_path("known_hosts_text", "known_hosts", format!("node-{name}.known_hosts"))?;
            nodes.insert(
                name.clone(),
                json!({"host": s(n, "host")?, "port": n["port"].as_u64().unwrap_or(22), "key": key, "known_hosts": kh}),
            );
        }
        let cfg = json!({
            "store": self.cfg.store_base.join(tenant),
            "tenant": tenant,
            "keyd_socket": self.cfg.keyd_socket,
            "api": {
                "host": s(api, "host")?,
                "port": api["port"].as_u64().unwrap_or(8006),
                "connect_addr": api["connect_addr"],
                "ca_pem_file": dir.join("ca.pem"),
                "token_id": s(api, "token_id")?,
                "token_secret_file": dir.join("token"),
            },
            "storage": s(&src, "storage")?,
            // optional in the web-api; VM backups fail in PVE without it
            "fleecing_storage": src["fleecing_storage"].as_str().unwrap_or_default(),
            "nodes": nodes,
            "vmids": vmids,
        });
        files.push(("pve.json".into(), serde_json::to_vec_pretty(&cfg)?));
        Ok(files)
    }

    fn offsite_cfg(&self, tenant: &str) -> Result<Option<Value>> {
        let o: Option<String> = self
            .db
            .conn()
            .query_row("SELECT offsite FROM tenants WHERE name=?1", [tenant], |r| r.get(0))
            .optional()?;
        let v: Value = o.map(|s| serde_json::from_str(&s)).transpose()?.unwrap_or(Value::Null);
        Ok(v["remote"].is_object().then_some(v))
    }

    /// Offsite GFS: the most generous value of each class over the tenant's
    /// offsite policies (never deletes what any of them keeps).
    // ponytail: one GFS per tenant box; per-source offsite retention when policies diverge in practice.
    fn offsite_gfs(&self, tenant: &str) -> Result<Gfs> {
        let gs: Vec<Gfs> = self
            .groups()?
            .into_iter()
            .filter(|g| g.tenant == tenant && g.offsite)
            .map(|g| g.gfs)
            .collect();
        Ok(gs
            .into_iter()
            .reduce(|a, b| Gfs {
                daily: a.daily.max(b.daily),
                weekly: a.weekly.max(b.weekly),
                monthly: a.monthly.max(b.monthly),
                yearly: a.yearly.max(b.yearly),
            })
            .unwrap_or_default())
    }

    /// Spawned CLIs only *fetch* keys, so every catalog tenant gets its DEK
    /// created (via the keyring source = keyd `ensure`) before its first job.
    fn ensure_tenant_keys(&mut self) -> Result<()> {
        let tenants: Vec<String> = {
            let c = self.db.conn();
            let mut st = c.prepare("SELECT name FROM tenants")?;
            let rows = st.query_map([], |r| r.get(0))?;
            rows.collect::<Result<_, _>>()?
        };
        for t in tenants {
            if self.keyed.contains(&t) {
                continue;
            }
            (self.ctx.keys)(&t).with_context(|| format!("keys for tenant {t}"))?;
            self.keyed.insert(t);
        }
        Ok(())
    }

    /// Refreshes the tenant's wrapped escrow files from keyd (new DEK versions
    /// after a rotation reach the box with the next upload).
    fn refresh_escrow(&self, tenant: &str) {
        let Ok(files) = keyd::fetch_escrow(&self.cfg.keyd_socket, tenant) else {
            return; // tests / keyd down: nexus-offsite reports a missing escrow dir itself
        };
        let dir = self.cfg.escrow_base.join(tenant);
        for (name, bytes) in files {
            let p = dir.join(&name);
            let ok = p.parent().is_some_and(|d| fs::create_dir_all(d).is_ok())
                && chunkstore::store::write_atomic(&p, &bytes).is_ok();
            if !ok {
                eprintln!("<4>scheduler: cannot write escrow file {}", p.display());
            }
        }
    }

    fn offsite_config(&self, tenant: &str, dir: &Path) -> Result<Option<Files>> {
        let Some(o) = self.offsite_cfg(tenant)? else {
            return Ok(None);
        };
        self.refresh_escrow(tenant);
        let mut files = Vec::new();
        let mut remote = o["remote"].clone();
        if let Some(k) = remote["key_pem"].as_str() {
            let mut k = k.to_owned();
            if !k.ends_with('\n') {
                k.push('\n');
            }
            files.push(("offsite.key".to_owned(), k.into_bytes()));
            remote["key_file"] = json!(dir.join("offsite.key"));
            remote.as_object_mut().unwrap().remove("key_pem");
        }
        let g = self.offsite_gfs(tenant)?;
        let mut cfg = json!({
            "store": self.cfg.store_base.join(tenant),
            "tenant": tenant,
            "keyd_socket": self.cfg.keyd_socket,
            "escrow_dir": self.cfg.escrow_base.join(tenant),
            "state": self.cfg.offsite_state_base.join(tenant),
            "remote": remote,
            "gfs": {"daily": g.daily, "weekly": g.weekly, "monthly": g.monthly, "yearly": g.yearly},
        });
        for k in ["uploaders", "bwlimit"] {
            if let Some(n) = o[k].as_u64() {
                cfg[k] = n.into();
            }
        }
        files.push(("offsite.json".into(), serde_json::to_vec_pretty(&cfg)?));
        Ok(Some(files))
    }

    pub fn plan(&self, job: &Job) -> Result<Plan> {
        let tenant = job.tenant.as_str();
        if !valid_name(tenant) {
            bail!("invalid tenant {tenant:?}");
        }
        let p = &job.params;
        let dir = self.job_dir(job.id);
        let pve = |args: Vec<String>| Step::Cli {
            bin: self.cfg.pve_bin.clone(),
            args: std::iter::once(dir.join("pve.json").to_string_lossy().into_owned())
                .chain(args)
                .collect(),
            alert: None,
            capture: false,
        };
        let offsite = |args: &[&str], alert: Option<&'static str>| Step::Cli {
            bin: self.cfg.offsite_bin.clone(),
            args: std::iter::once(dir.join("offsite.json").to_string_lossy().into_owned())
                .chain(args.iter().map(|s| s.to_string()))
                .collect(),
            alert,
            capture: false,
        };
        let mut plan = Plan {
            key: format!("tenant:{tenant}"),
            tenant: tenant.to_owned(),
            store: self.cfg.store_base.join(tenant),
            dir: dir.clone(),
            files: Vec::new(),
            steps: Vec::new(),
            download: None,
        };
        let group = |id: i64| -> Result<GroupRow> {
            self.groups()?
                .into_iter()
                .find(|g| g.id == id && g.tenant == tenant)
                .with_context(|| format!("group {id} not found in tenant {tenant}"))
        };
        match job.kind.as_str() {
            "backup" => {
                let (source_id, vmids) = match p["group_id"].as_i64() {
                    Some(g) => {
                        let g = group(g)?;
                        (g.source_id, g.guests)
                    }
                    None => {
                        let v = u32::try_from(num(p, "vmid")?).context("vmid")?;
                        (self.resolve_source(job, Some(v))?, vec![v])
                    }
                };
                if vmids.is_empty() {
                    bail!("nothing to back up: no guests");
                }
                plan.key = format!("source:{source_id}");
                plan.files = self.pve_config(tenant, source_id, &dir, &vmids)?;
                plan.steps.push(pve(vec!["backup-all".into()]));
            }
            "retention" if p["group_id"].is_null() && p["vmid"].is_null() && p["source"].is_null() => {
                // manual retention for the whole tenant: every group with its own GFS
                for g in self.groups()?.into_iter().filter(|g| g.tenant == tenant) {
                    let sources = g
                        .guests
                        .iter()
                        .flat_map(|v| [format!("vm-{v}"), format!("ct-{v}")])
                        .collect();
                    plan.steps.push(Step::Retention { sources, gfs: g.gfs });
                }
            }
            "retention" => {
                let (source_id, vmids, gfs) = match p["group_id"].as_i64() {
                    Some(g) => {
                        let g = group(g)?;
                        (g.source_id, g.guests, g.gfs)
                    }
                    None => {
                        let v = match p["source"].as_str() {
                            Some(s) => guest(s)?.1,
                            None => u32::try_from(num(p, "vmid")?).context("vmid")?,
                        };
                        let gfs = self
                            .groups()?
                            .into_iter()
                            .find(|g| g.tenant == tenant && g.guests.contains(&v))
                            .map_or_else(Gfs::default, |g| g.gfs);
                        (self.resolve_source(job, Some(v))?, vec![v], gfs)
                    }
                };
                plan.key = format!("source:{source_id}");
                let sources = vmids
                    .iter()
                    .flat_map(|v| [format!("vm-{v}"), format!("ct-{v}")])
                    .collect();
                plan.steps.push(Step::Retention { sources, gfs });
            }
            "offsite" => {
                plan.files = self
                    .offsite_config(tenant, &dir)?
                    .context("tenant has no offsite target")?;
                plan.steps.push(offsite(&["upload"], None));
                plan.steps.push(offsite(&["check"], Some("inventory")));
                plan.steps.push(offsite(&["retention"], None));
            }
            "gc" => {
                plan.steps.push(Step::Gc {
                    approved: p["approved"].as_bool() == Some(true) && p["quorum_id"].is_i64(),
                });
                if let Some(f) = self.offsite_config(tenant, &dir)? {
                    plan.files = f;
                    plan.steps.push(offsite(&["gc"], None));
                }
            }
            "verify" => {
                let parts = self.cfg.verify_parts.max(1);
                plan.steps.push(Step::Verify {
                    part: (catalog::now() / 86400) as u64 % parts,
                    parts,
                });
                if let Some(f) = self.offsite_config(tenant, &dir)? {
                    plan.files = f;
                    plan.steps.push(offsite(&["verify", "3"], Some("verify")));
                }
            }
            "restore" | "restore_ct" | "instant_recover" => {
                let source = ident(p, "source")?;
                let (ct, vmid) = guest(source)?;
                if ct != (job.kind == "restore_ct") {
                    bail!("{} cannot restore {source}", job.kind);
                }
                let sid = self.resolve_source(job, Some(vmid))?;
                plan.key = format!("guest:{tenant}/{source}");
                plan.files = self.pve_config(tenant, sid, &dir, &[])?;
                let cmd = match job.kind.as_str() {
                    "restore" => "restore",
                    "restore_ct" => "restore-ct",
                    _ => "instant-recover",
                };
                let mut args = vec![
                    cmd.to_owned(),
                    vmid.to_string(),
                    num(p, "time")?.to_string(),
                    ident(p, "node")?.to_owned(),
                    u32::try_from(num(p, "target")?).context("target")?.to_string(),
                    ident(p, "storage")?.to_owned(),
                ];
                if job.kind == "instant_recover" && p["link_down"].as_bool() == Some(true) {
                    args.push("--link-down".into());
                }
                plan.steps.push(pve(args));
            }
            "files_list" | "files_get" => {
                let source = ident(p, "source")?;
                let (ct, vmid) = guest(source)?;
                let sid = self.resolve_source(job, Some(vmid))?;
                plan.key = format!("guest:{tenant}/{source}");
                plan.files = self.pve_config(tenant, sid, &dir, &[])?;
                let mut args = vec![
                    if ct { "ct-files" } else { "files" }.to_owned(),
                    vmid.to_string(),
                    num(p, "time")?.to_string(),
                ];
                let check_path = |s: &str| -> Result<String> {
                    if s.is_empty() || s.starts_with('-') || s.contains('\0') || s.len() > 4096 {
                        bail!("invalid path {s:?}");
                    }
                    Ok(s.to_owned())
                };
                if job.kind == "files_list" {
                    args.push("ls".into());
                    args.push(check_path(p["path"].as_str().unwrap_or("/"))?);
                } else {
                    let file = download_file(p)?;
                    let out = self.cfg.downloads.join(file);
                    let paths: Vec<String> = p["paths"]
                        .as_array()
                        .filter(|a| !a.is_empty() && a.len() <= 1000)
                        .context("paths must be a non-empty list")?
                        .iter()
                        .map(|v| check_path(v.as_str().unwrap_or_default()))
                        .collect::<Result<_>>()?;
                    args.push("get".into());
                    args.push(out.to_string_lossy().into_owned());
                    args.extend(paths);
                    plan.download = Some(out);
                }
                let mut step = pve(args);
                if let Step::Cli { capture, .. } = &mut step {
                    *capture = true; // files_list: JSON listing, files_get: entry count
                }
                plan.steps.push(step);
            }
            k => bail!("unknown job kind {k:?}"),
        }
        Ok(plan)
    }

    // ------------------------------------------------------------ snapshots

    /// Rebuilds `snapshots` for dirty tenants (or all): local rows from the
    /// store, offsite rows from `nexus-offsite list`.
    fn refresh(&mut self, now: i64, all: bool) -> Result<()> {
        let tenants: Vec<String> = if all {
            self.tenants()?.into_iter().map(|t| t.0).collect()
        } else {
            std::mem::take(&mut self.dirty).into_iter().collect()
        };
        if all {
            self.dirty.clear();
        }
        for t in tenants {
            if let Err(e) = self.refresh_tenant(&t, now) {
                eprintln!("<4>snapshot refresh of tenant {t} failed: {e:#}");
            }
        }
        Ok(())
    }

    fn refresh_tenant(&mut self, tenant: &str, now: i64) -> Result<()> {
        let root = self.cfg.store_base.join(tenant);
        if !valid_name(tenant) || !root.join("keycheck").exists() {
            return Ok(());
        }
        let store = chunkstore::Store::open(&root, (self.ctx.keys)(tenant)?, (self.ctx.store_options)())?;
        // (source, time) -> (lock_until, size)
        let mut local: BTreeMap<(String, i64), (i64, Option<i64>)> = BTreeMap::new();
        let known: HashSet<(String, i64)> = {
            let c = self.db.conn();
            let mut st = c.prepare("SELECT source, time FROM snapshots WHERE tenant=?1 AND local=1")?;
            let rows = st.query_map([tenant], |r| Ok((r.get(0)?, r.get(1)?)))?;
            rows.collect::<std::result::Result<_, _>>()?
        };
        for m in store.list_snapshots()? {
            let key = (m.source.clone(), m.time as i64);
            let size = if known.contains(&key) {
                None
            } else {
                let mut n = 0u64;
                for i in &m.indexes {
                    match store.load_index(&m, i)? {
                        chunkstore::Index::Fixed { size, .. } => n += size,
                        chunkstore::Index::Dynamic { entries } => n += entries.iter().map(|e| e.size).sum::<u64>(),
                    }
                }
                Some(n as i64)
            };
            local.insert(key, (m.lock_until as i64, size));
        }
        drop(store);
        let offsite = if self.offsite_cfg(tenant)?.is_some()
            && !self.running.values().any(|k| k == &format!("tenant:{tenant}"))
        {
            match self.offsite_list(tenant) {
                Ok(s) => Some(s),
                Err(e) => {
                    eprintln!("<4>offsite list of tenant {tenant} failed: {e:#}");
                    None
                }
            }
        } else if self.offsite_cfg(tenant)?.is_none() {
            Some(HashSet::new())
        } else {
            None
        };
        // vanished while still locked = someone deleted around the store's locks
        let vanished: Vec<(String, i64)> = {
            let c = self.db.conn();
            let mut st =
                c.prepare("SELECT source, time FROM snapshots WHERE tenant=?1 AND local=1 AND lock_until > ?2")?;
            let rows = st.query_map(params![tenant, now], |r| Ok((r.get(0)?, r.get(1)?)))?;
            rows.collect::<std::result::Result<Vec<_>, _>>()?
                .into_iter()
                .filter(|k| !local.contains_key(k))
                .collect()
        };
        {
            let mut c = self.db.conn();
            let tx = c.transaction()?;
            tx.execute("UPDATE snapshots SET local=0 WHERE tenant=?1", [tenant])?;
            if let Some(o) = &offsite {
                tx.execute("UPDATE snapshots SET offsite=0 WHERE tenant=?1", [tenant])?;
                for (s, t) in o {
                    tx.execute(
                        "INSERT INTO snapshots (tenant, source, time, local, offsite) VALUES (?1,?2,?3,0,1) \
                         ON CONFLICT (tenant, source, time) DO UPDATE SET offsite=1",
                        params![tenant, s, t],
                    )?;
                }
            }
            for ((s, t), (lock, size)) in &local {
                tx.execute(
                    "INSERT INTO snapshots (tenant, source, time, size, local, offsite, lock_until) VALUES (?1,?2,?3,?4,1,0,?5) \
                     ON CONFLICT (tenant, source, time) DO UPDATE SET local=1, lock_until=?5, size=COALESCE(?6, size)",
                    params![tenant, s, t, size.unwrap_or(0), lock, size],
                )?;
            }
            tx.execute(
                "DELETE FROM snapshots WHERE tenant=?1 AND local=0 AND offsite=0",
                [tenant],
            )?;
            tx.commit()?;
        }
        for (s, t) in vanished {
            self.alert(
                "critical",
                "inventory",
                &format!("snapshot {tenant}/{s}/{t} disappeared from the local store while locked"),
                None,
            )?;
        }
        Ok(())
    }

    fn offsite_list(&self, tenant: &str) -> Result<HashSet<(String, i64)>> {
        let dir = self.cfg.runtime_dir.join(format!("job-refresh-{tenant}"));
        let _ = fs::remove_dir_all(&dir);
        let files = self.offsite_config(tenant, &dir)?.context("no offsite target")?;
        run::write_private(&dir, &files)?;
        let log = Arc::new(std::sync::Mutex::new(run::BoundedLog::new(8192)));
        let r = run::run_cli(
            &self.cfg.offsite_bin,
            &[dir.join("offsite.json").to_string_lossy().into_owned(), "list".into()],
            &log,
            true,
        );
        let _ = fs::remove_dir_all(&dir);
        let (ok, out) = r?;
        if !ok {
            bail!(
                "{}",
                Arc::try_unwrap(log)
                    .ok()
                    .map(|l| l.into_inner().unwrap().finish())
                    .unwrap_or_default()
            );
        }
        Ok(out
            .lines()
            .filter_map(|l| {
                let (s, t) = l.trim().rsplit_once('/')?;
                Some((s.to_owned(), t.parse().ok()?))
            })
            .collect())
    }

    // --------------------------------------------------------------- alerts

    /// Inserts an alert unless an unacknowledged one with the same kind and
    /// message prefix (`dedupe`, default the whole message) exists.
    pub fn alert(&self, severity: &str, kind: &str, message: &str, dedupe: Option<&str>) -> Result<()> {
        let prefix = dedupe.unwrap_or(message);
        let c = self.db.conn();
        let dup: i64 = c.query_row(
            "SELECT COUNT(*) FROM alerts WHERE kind=?1 AND acked_by IS NULL AND substr(message, 1, length(?2)) = ?2",
            params![kind, prefix],
            |r| r.get(0),
        )?;
        if dup == 0 {
            c.execute(
                "INSERT INTO alerts (ts, severity, kind, message) VALUES (?1,?2,?3,?4)",
                params![catalog::now(), severity, kind, message],
            )?;
            eprintln!("<4>alert {severity} {kind}: {message}");
        }
        Ok(())
    }

    fn deliver_alerts(&mut self) -> Result<()> {
        let rows: Vec<alerts::Alert> = {
            let c = self.db.conn();
            let mut st = c.prepare("SELECT id, ts, severity, kind, message FROM alerts WHERE id > ?1 ORDER BY id")?;
            let rows = st.query_map([self.alert_cursor], |r| {
                Ok(alerts::Alert {
                    id: r.get(0)?,
                    ts: r.get(1)?,
                    severity: r.get(2)?,
                    kind: r.get(3)?,
                    message: r.get(4)?,
                    host: self.host.clone(),
                })
            })?;
            rows.collect::<std::result::Result<_, _>>()?
        };
        if let Some(last) = rows.last() {
            self.alert_cursor = last.id;
            fs::write(self.cursor_path(), format!("{}\n", last.id))?;
        }
        for a in rows {
            let _ = self.alert_tx.send(a);
        }
        Ok(())
    }

    fn check_capacity(&self) -> Result<()> {
        let path = std::ffi::CString::new(self.cfg.store_base.as_os_str().as_encoded_bytes())?;
        let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
        if unsafe { libc::statvfs(path.as_ptr(), &mut st) } != 0 || st.f_blocks == 0 {
            return Ok(());
        }
        let used = 1.0 - st.f_bavail as f64 / st.f_blocks as f64;
        if used > self.cfg.capacity_threshold {
            let pfx = format!("store capacity above {:.0} %", self.cfg.capacity_threshold * 100.0);
            self.alert(
                "warning",
                "capacity",
                &format!("{pfx} (now {:.0} %)", used * 100.0),
                Some(&pfx),
            )?;
        }
        Ok(())
    }

    /// Oldest local snapshot of an offsite-protected guest that is not offsite yet.
    fn check_offsite_lag(&self, now: i64) -> Result<()> {
        let mut protected: BTreeMap<String, HashSet<String>> = BTreeMap::new();
        for g in self.groups()?.into_iter().filter(|g| g.offsite) {
            let e = protected.entry(g.tenant).or_default();
            for v in g.guests {
                e.insert(format!("vm-{v}"));
                e.insert(format!("ct-{v}"));
            }
        }
        for (tenant, sources) in protected {
            if self.offsite_cfg(&tenant)?.is_none() {
                continue;
            }
            let oldest: Option<i64> = {
                let c = self.db.conn();
                let mut st =
                    c.prepare("SELECT source, time FROM snapshots WHERE tenant=?1 AND local=1 AND offsite=0")?;
                let rows = st.query_map([&tenant], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))?;
                rows.filter_map(|r| r.ok())
                    .filter(|(s, _)| sources.contains(s))
                    .map(|(_, t)| t)
                    .min()
            };
            if let Some(t) = oldest.filter(|t| now - t > self.cfg.offsite_lag_secs) {
                let pfx = format!("offsite copy of tenant {tenant} lags");
                self.alert(
                    "warning",
                    "offsite_lag",
                    &format!("{pfx} by {} h (oldest snapshot not offsite: {t})", (now - t) / 3600),
                    Some(&pfx),
                )?;
            }
        }
        Ok(())
    }

    // ------------------------------------------------------------ downloads

    fn expire_downloads(&self, now: i64) -> Result<()> {
        for e in fs::read_dir(&self.cfg.downloads)? {
            let e = e?;
            let m = e.metadata()?;
            if m.is_file() && now - m.mtime() > self.cfg.download_ttl_secs {
                fs::remove_file(e.path())?;
            }
        }
        Ok(())
    }
}

/// Entry point used by `main`: loads `/etc/nexus/scheduler.json` (optional).
pub fn load_config(path: &Path) -> Result<Config> {
    match fs::read(path) {
        Ok(b) => serde_json::from_slice(&b).with_context(|| format!("{}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Config::default()),
        Err(e) => Err(e).with_context(|| format!("{}", path.display())),
    }
}

#[cfg(test)]
mod tests;
