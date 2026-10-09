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
//! Secrets (`token_secret`, `key_pem`, see `catalog::secret`) are stored as
//! `sealed:v1:` values sealed to the scheduler key (`Config::secrets_key`); the
//! web-api only has the public key (`Config::secrets_pub`, written at start).
//! They are opened in memory when a job config is generated. Legacy plaintext
//! values are sealed at startup (audit `secret.migrate`).
//!
//! `sources.config` (kind `linux`): `{ "agent_id", "paths", "excludes", "hooks" }`;
//! the agent endpoint, fingerprint and sealed enrollment token digest live in
//! `agents`. Agent jobs spawn `nexus-agentctl` (crate agent-conn) with
//! `agent-<id>.json` in the job dir; groups of linux sources list agent ids
//! as guests, their snapshots are `host-<agent_id>`.
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
pub mod firewall;
pub mod run;
pub mod schedule;

use anyhow::{bail, Context, Result};
use catalog::rusqlite::{params, OptionalExtension};
use catalog::secret::{source_owner, tenant_owner, SchedulerKey};
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
    /// Linux agent connector (crate agent-conn)
    pub agentctl_bin: PathBuf,
    /// appliance CA for agents (created by nexus-agentctl on first use); default `<state_dir>/agent-ca`
    pub agent_ca_dir: Option<PathBuf>,
    /// signed agent binaries for `agent_update` (nexus-agent, .sig, .version)
    pub agent_update_dir: PathBuf,
    pub alerts_config: PathBuf,
    /// outbound allow-list for nexus-nft-sync (skipped if its directory is missing)
    pub nft_allowed: PathBuf,
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
    /// private key that opens sealed source/offsite secrets (0600, created on
    /// first start); default `<state_dir>/secrets.key`
    pub secrets_key: Option<PathBuf>,
    /// public key published for the web-api (0640, catalog group); default
    /// `secrets.pub` next to the catalog
    pub secrets_pub: Option<PathBuf>,
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
            agentctl_bin: "/usr/libexec/nexus/nexus-agentctl".into(),
            agent_ca_dir: None,
            agent_update_dir: "/usr/share/nexus/agent".into(),
            alerts_config: "/etc/nexus/alerts.json".into(),
            nft_allowed: nftsync::ALLOWED_FILE.into(),
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
            secrets_key: None,
            secrets_pub: None,
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

struct AgentRow {
    id: String,
    tenant: String,
    name: String,
    host: String,
    port: u16,
    cert_sha256: Option<String>,
    token_hash: Option<String>,
    token_expires: Option<i64>,
}

/// A path argument for the file CLIs (never an option).
fn file_arg(s: &str) -> Result<String> {
    if s.is_empty() || s.starts_with('-') || s.contains('\0') || s.len() > 4096 {
        bail!("invalid path {s:?}");
    }
    Ok(s.to_owned())
}

fn file_paths(p: &Value) -> Result<Vec<String>> {
    p["paths"]
        .as_array()
        .filter(|a| !a.is_empty() && a.len() <= 1000)
        .context("paths must be a non-empty list")?
        .iter()
        .map(|v| file_arg(v.as_str().unwrap_or_default()))
        .collect()
}

struct GroupRow {
    id: i64,
    tenant: String,
    source_id: i64,
    /// vmids (pve sources)
    guests: Vec<u32>,
    /// agent ids (linux sources: the group's guests are strings)
    agents: Vec<String>,
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
    /// opens the sealed secrets in `sources.config` / `tenants.offsite`
    secrets: SchedulerKey,
    secrets_created: bool,
}

/// Agent ids: 16 lowercase hex characters (chosen by the web-api).
fn valid_agent_id(s: &str) -> bool {
    s.len() == 16 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Snapshot sources of a group: `vm-/ct-<vmid>` for PVE, `host-<agent>` for Linux agents.
fn group_sources(g: &GroupRow) -> Vec<String> {
    g.guests
        .iter()
        .flat_map(|v| [format!("vm-{v}"), format!("ct-{v}")])
        .chain(g.agents.iter().map(|a| format!("host-{a}")))
        .collect()
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
        let (secrets, secrets_created) =
            SchedulerKey::load_or_create(&cfg.secrets_key_path()).context("scheduler secrets key")?;
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
            secrets,
            secrets_created,
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
        // only when needed: on the appliance tmpfiles already created it 2750, and the
        // unit's RestrictSUIDSGID= refuses any chmod that sets the setgid bit (EPERM)
        if fs::metadata(&self.cfg.downloads)?.permissions().mode() & 0o7777 != 0o2750 {
            fs::set_permissions(&self.cfg.downloads, fs::Permissions::from_mode(0o2750))
                .with_context(|| format!("chmod 2750 {}", self.cfg.downloads.display()))?;
        }
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
                if fs::symlink_metadata(&p).is_ok_and(|m| m.gid() == gid) {
                    continue;
                }
                if let Err(e) = std::os::unix::fs::chown(&p, None, Some(gid)) {
                    eprintln!("<4>cannot set group of {}: {e}", p.display());
                }
            }
        }
        fs::create_dir_all(&self.cfg.state_dir)?;
        self.publish_secrets_key()?;
        self.migrate_secrets()?;
        self.alert_cursor = match fs::read_to_string(self.cursor_path()) {
            Ok(s) => s.trim().parse().unwrap_or(0),
            Err(_) => self
                .db
                .conn()
                .query_row("SELECT COALESCE(MAX(id), 0) FROM alerts", [], |r| r.get(0))?,
        };
        self.recover()
    }

    /// Writes the public key for the web-api (group of the catalog dir, 0640).
    fn publish_secrets_key(&mut self) -> Result<()> {
        let path = self.cfg.secrets_pub_path();
        let gid = self
            .cfg
            .catalog
            .parent()
            .and_then(|p| fs::metadata(p).ok())
            .map(|m| m.gid());
        self.secrets
            .write_public(&path, gid)
            .or_else(|_| self.secrets.write_public(&path, None))
            .with_context(|| format!("publishing {}", path.display()))?;
        if std::mem::take(&mut self.secrets_created) {
            self.db.audit(
                ACTOR,
                "secret.key_create",
                "scheduler/secrets.key",
                &json!({"public": self.secrets.public().to_base64()}),
            )?;
        }
        Ok(())
    }

    /// Seals legacy plaintext secrets in `sources.config` / `tenants.offsite`
    /// to the scheduler key (review H-2); one audit entry per changed row.
    pub fn migrate_secrets(&self) -> Result<()> {
        let pk = self.secrets.public();
        for (table, key) in [("sources", "id"), ("tenants", "name")] {
            let col = if table == "sources" { "config" } else { "offsite" };
            let rows: Vec<(String, String)> = {
                let c = self.db.conn();
                let mut st = c.prepare(&format!("SELECT CAST({key} AS TEXT), {col} FROM {table}"))?;
                let rows = st.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?;
                rows.collect::<std::result::Result<_, _>>()?
            };
            for (k, raw) in rows {
                let Ok(mut v) = serde_json::from_str::<Value>(&raw) else {
                    continue;
                };
                let (owner, target) = if table == "sources" {
                    (source_owner(k.parse()?), format!("source/{k}"))
                } else {
                    (tenant_owner(&k), format!("tenant/{k}"))
                };
                let fields = pk.seal_all(&owner, &mut v)?;
                if fields.is_empty() {
                    continue;
                }
                // compare-and-swap: a concurrent web-api write wins (and seals itself)
                let n = self.db.conn().execute(
                    &format!("UPDATE {table} SET {col} = ?1 WHERE CAST({key} AS TEXT) = ?2 AND {col} = ?3"),
                    params![v.to_string(), k, raw],
                )?;
                if n == 1 {
                    self.db
                        .audit(ACTOR, "secret.migrate", &target, &json!({"sealed": fields}))?;
                }
            }
        }
        Ok(())
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
        self.log_err(|s| s.sync_firewall());
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
            let guests: Vec<Value> = serde_json::from_str(&r.get::<_, String>(3)?).unwrap_or_default();
            let gfs: String = r.get(5)?;
            Ok(GroupRow {
                id: r.get(0)?,
                tenant: r.get(1)?,
                source_id: r.get(2)?,
                guests: guests
                    .iter()
                    .filter_map(|g| g.as_u64().and_then(|v| u32::try_from(v).ok()))
                    .collect(),
                agents: guests
                    .iter()
                    .filter_map(|g| g.as_str().filter(|a| valid_agent_id(a)).map(str::to_owned))
                    .collect(),
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

    /// Writes the outbound allow-list (sources, offsite boxes, alert delivery)
    /// for nexus-nft-sync; the file only changes when the destinations do.
    fn sync_firewall(&self) -> Result<()> {
        let mut targets = Vec::new();
        {
            let c = self.db.conn();
            let mut st = c.prepare("SELECT config FROM sources WHERE kind='pve'")?;
            for cfg in st.query_map([], |r| r.get::<_, String>(0))? {
                if let Ok(v) = serde_json::from_str::<Value>(&cfg?) {
                    targets.extend(firewall::source_targets(&v));
                }
            }
        }
        {
            let c = self.db.conn();
            let mut st = c.prepare("SELECT host, port FROM agents")?;
            for a in st.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, u16>(1)?)))? {
                let (h, p) = a?;
                targets.push((h.trim_matches(['[', ']']).to_owned(), p));
            }
        }
        for (_, o) in self.tenants()? {
            targets.extend(firewall::offsite_target(&o));
        }
        if let Ok(a) = alerts::AlertsConfig::load(&self.cfg.alerts_config) {
            targets.extend(firewall::alert_targets(&a));
        }
        if nftsync::write_allowed(&self.cfg.nft_allowed, firewall::resolve(&targets))? {
            eprintln!(
                "scheduler: firewall allow-list updated ({} destinations)",
                targets.len()
            );
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
        self.agent_bookkeeping(&job, &log)?;
        if ok && job.kind == "backup" {
            // agent backups without snapshots / with failed hooks are usable but not crash-consistent
            for l in log.lines().filter(|l| l.starts_with("inconsistent host-")) {
                let what = l.trim_start_matches("inconsistent ");
                let src = what.split('/').next().unwrap_or_default();
                self.alert(
                    "warning",
                    "backup_inconsistent",
                    &format!("backup job {} ({}): snapshot {what}", job.id, job.tenant),
                    Some(&format!("backup job {} ({}): snapshot {src}", job.id, job.tenant)),
                )?;
            }
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

    /// Agent state from nexus-agentctl's log lines: `agent-info {json}` (version,
    /// OS, last seen; any job) and `enrolled {json}` (fingerprint; recorded even if
    /// the job failed afterwards: the agent has consumed its token).
    fn agent_bookkeeping(&self, job: &Job, log: &str) -> Result<()> {
        // jobs naming one agent only update that one; group backups any of the tenant's
        let Some(expected) = job.params["agent_id"]
            .as_str()
            .filter(|a| valid_agent_id(a))
            .map(str::to_owned)
        else {
            return self.agent_info_lines(job, log, None);
        };
        self.agent_info_lines(job, log, Some(&expected))?;
        if job.kind != "agent_enroll" {
            return Ok(());
        }
        for l in log.lines() {
            let Some(v) = l
                .strip_prefix("enrolled ")
                .and_then(|j| serde_json::from_str::<Value>(j).ok())
            else {
                continue;
            };
            let fp = v["cert_sha256"].as_str().unwrap_or_default();
            if v["agent_id"].as_str() != Some(expected.as_str())
                || fp.len() != 64
                || !fp.bytes().all(|b| b.is_ascii_hexdigit())
            {
                continue;
            }
            let n = self.db.conn().execute(
                "UPDATE agents SET cert_sha256=?2, enrolled_at=?3, token_hash=NULL, token_expires=NULL, last_seen=?3 \
                 WHERE id=?1 AND tenant=?4",
                params![expected, fp, catalog::now(), job.tenant],
            )?;
            if n == 1 {
                self.db.audit(
                    ACTOR,
                    "agent.enrolled",
                    &format!("agent/{expected}"),
                    &json!({"job": job.id, "cert_sha256": fp}),
                )?;
            }
        }
        Ok(())
    }

    fn agent_info_lines(&self, job: &Job, log: &str, only: Option<&str>) -> Result<()> {
        for l in log.lines() {
            let Some(v) = l
                .strip_prefix("agent-info ")
                .and_then(|j| serde_json::from_str::<Value>(j).ok())
            else {
                continue;
            };
            let Some(id) = v["agent_id"].as_str().filter(|a| valid_agent_id(a)) else {
                continue;
            };
            if only.is_some_and(|o| o != id) {
                continue;
            }
            let short = |k: &str| v[k].as_str().map(|s| s.chars().take(128).collect::<String>());
            self.db.conn().execute(
                "UPDATE agents SET last_seen=?2, version=?3, os=?4 WHERE id=?1 AND tenant=?5",
                params![id, catalog::now(), short("version"), short("os"), job.tenant],
            )?;
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
                // nexus-agentctl adds `… chunks transferred (<n> bytes, …)` and an
                // `inconsistent <source>/<time>: …` line for a backup without a consistent view
                let snaps: Vec<Value> = log
                    .lines()
                    .filter_map(|l| {
                        let rest = l.strip_prefix("committed ")?;
                        let id = rest.split_whitespace().next()?;
                        let (s, t) = id.rsplit_once('/')?;
                        let mut v = json!({"source": s, "time": t.parse::<i64>().ok()?});
                        if s.starts_with("host-") {
                            let bad = format!("inconsistent {id}:");
                            v["consistent"] = json!(!log.lines().any(|x| x.starts_with(&bad)));
                            if let Some(n) = rest
                                .split_once("chunks transferred (")
                                .and_then(|(_, x)| x.split_once(" bytes"))
                                .and_then(|(n, _)| n.parse::<u64>().ok())
                            {
                                v["transferred_bytes"] = json!(n);
                            }
                        }
                        Some(v)
                    })
                    .collect();
                let mut r = json!({ "snapshots": snaps });
                if let [one] = snaps.as_slice() {
                    for k in ["source", "time", "consistent", "transferred_bytes"] {
                        if !one[k].is_null() {
                            r[k] = one[k].clone();
                        }
                    }
                }
                Some(r)
            }
            // `restored {json}` / `enrolled {json}` (nexus-agentctl)
            "restore_files" | "agent_enroll" => {
                let pfx = if job.kind == "restore_files" {
                    "restored "
                } else {
                    "enrolled "
                };
                log.lines()
                    .find_map(|l| serde_json::from_str::<Value>(l.strip_prefix(pfx)?).ok())
            }
            _ => None,
        }
    }

    fn follow_up(&mut self, job: &Job) -> Result<()> {
        match job.kind.as_str() {
            "backup" => {
                let mut p = json!({"chain": true});
                for k in ["group_id", "source_id", "vmid", "agent_id"] {
                    if !job.params[k].is_null() {
                        p[k] = job.params[k].clone();
                    }
                }
                self.insert_job("retention", &job.tenant, &p)?;
            }
            "retention" if job.params["chain"].as_bool() == Some(true) => {
                let wants = match (job.params["group_id"].as_i64(), job.params["agent_id"].as_str()) {
                    (Some(g), _) => self.groups()?.iter().any(|r| r.id == g && r.offsite),
                    (None, Some(a)) => self
                        .groups()?
                        .iter()
                        .any(|g| g.tenant == job.tenant && g.offsite && g.agents.iter().any(|x| x == a)),
                    (None, None) => job.params["vmid"].as_u64().is_some_and(|v| {
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
        let mut v: Value = serde_json::from_str(&cfg).context("source config")?;
        // in memory only: the plaintext goes into the 0600 job dir and nowhere else
        self.secrets
            .open_all(&source_owner(id), &mut v)
            .with_context(|| format!("source {id}"))?;
        Ok(v)
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
            let mut st = c.prepare("SELECT id FROM sources WHERE tenant=?1 AND kind='pve'")?;
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
        let mut v: Value = o.map(|s| serde_json::from_str(&s)).transpose()?.unwrap_or(Value::Null);
        self.secrets
            .open_all(&tenant_owner(tenant), &mut v)
            .with_context(|| format!("offsite config of tenant {tenant}"))?;
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

    fn agent(&self, tenant: &str, id: &str) -> Result<AgentRow> {
        if !valid_agent_id(id) {
            bail!("invalid agent id {id:?}");
        }
        let a = self
            .db
            .conn()
            .query_row(
                "SELECT id, tenant, name, host, port, cert_sha256, token_hash, token_expires FROM agents WHERE id=?1",
                [id],
                |r| {
                    Ok(AgentRow {
                        id: r.get(0)?,
                        tenant: r.get(1)?,
                        name: r.get(2)?,
                        host: r.get(3)?,
                        port: r.get(4)?,
                        cert_sha256: r.get(5)?,
                        token_hash: r.get(6)?,
                        token_expires: r.get(7)?,
                    })
                },
            )
            .optional()?
            .with_context(|| format!("agent {id} not found"))?;
        if a.tenant != tenant {
            bail!("agent {id} belongs to another tenant");
        }
        Ok(a)
    }

    /// The linux source (id, config) that backs up `agent` in `tenant`.
    fn agent_source(&self, tenant: &str, agent: &str) -> Result<(i64, Value)> {
        let (id, cfg): (i64, String) = self
            .db
            .conn()
            .query_row(
                "SELECT id, config FROM sources WHERE tenant=?1 AND kind='linux' \
                 AND json_extract(config,'$.agent_id')=?2 ORDER BY id LIMIT 1",
                params![tenant, agent],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?
            .with_context(|| format!("no linux source for agent {agent} in tenant {tenant}"))?;
        Ok((id, serde_json::from_str(&cfg).context("source config")?))
    }

    /// nexus-agentctl config: store, keys, CA, job id, agent endpoint + pin, extra keys.
    fn agentctl_base(&self, tenant: &str, job: &Job, a: Option<&AgentRow>, extra: Value) -> Value {
        let mut cfg = json!({
            "tenant": tenant,
            "store": self.cfg.store_base.join(tenant),
            "keyd_socket": self.cfg.keyd_socket,
            "ca_dir": self.cfg.agent_ca_path(),
            "job": job.id,
        });
        if let Some(a) = a {
            cfg["agent"] = json!({"id": a.id, "host": a.host, "port": a.port, "cert_sha256": a.cert_sha256});
        }
        if let (Some(c), Some(e)) = (cfg.as_object_mut(), extra.as_object()) {
            c.extend(e.clone());
        }
        cfg
    }

    /// (config file, step) for `nexus-agentctl <agent-<id>.json> <cmd>`.
    fn agentctl(
        &self,
        dir: &Path,
        job: &Job,
        a: &AgentRow,
        cmd: &str,
        extra: Value,
    ) -> Result<((String, Vec<u8>), Step)> {
        let name = format!("agent-{}.json", a.id);
        let cfg = self.agentctl_base(&job.tenant, job, Some(a), extra);
        let step = Step::Cli {
            bin: self.cfg.agentctl_bin.clone(),
            args: vec![dir.join(&name).to_string_lossy().into_owned(), cmd.to_owned()],
            alert: None,
            capture: false,
        };
        Ok(((name, serde_json::to_vec_pretty(&cfg)?), step))
    }

    /// Backups of Linux agents (one step per agent; the source says what to back up).
    fn plan_agent_backups(&self, job: &Job, mut plan: Plan, source_id: i64, agents: &[String]) -> Result<Plan> {
        let (kind, cfg): (String, String) = self.db.conn().query_row(
            "SELECT kind, config FROM sources WHERE id=?1 AND tenant=?2",
            params![source_id, job.tenant],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        if kind != "linux" {
            bail!("source {source_id} is not a linux source");
        }
        let src: Value = serde_json::from_str(&cfg).context("source config")?;
        plan.key = match agents {
            [one] => format!("agent:{one}"),
            _ => format!("source:{source_id}"),
        };
        for id in agents {
            let a = self.agent(&job.tenant, id)?;
            if a.cert_sha256.is_none() {
                bail!("agent {} ({}) is not enrolled", a.name, a.id);
            }
            let backup = json!({"paths": src["paths"], "excludes": src["excludes"].as_array().cloned().unwrap_or_default(),
                                "hooks": src["hooks"].as_bool().unwrap_or(false)});
            let (f, step) = self.agentctl(&plan.dir, job, &a, "backup", json!({"backup": backup}))?;
            plan.files.push(f);
            plan.steps.push(step);
        }
        if plan.steps.is_empty() {
            bail!("nothing to back up: no agents");
        }
        Ok(plan)
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
                let (source_id, vmids) = match (p["group_id"].as_i64(), p["agent_id"].as_str()) {
                    (Some(g), _) => {
                        let g = group(g)?;
                        if !g.agents.is_empty() {
                            return self.plan_agent_backups(job, plan, g.source_id, &g.agents);
                        }
                        (g.source_id, g.guests)
                    }
                    (None, Some(a)) => {
                        let (sid, _) = self.agent_source(tenant, a)?;
                        return self.plan_agent_backups(job, plan, sid, &[a.to_owned()]);
                    }
                    (None, None) => {
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
                    let sources = group_sources(&g);
                    plan.steps.push(Step::Retention { sources, gfs: g.gfs });
                }
            }
            "retention" if !p["agent_id"].is_null() || p["source"].as_str().is_some_and(|s| s.starts_with("host-")) => {
                let a = match p["agent_id"].as_str() {
                    Some(a) => a,
                    None => p["source"].as_str().unwrap_or_default().trim_start_matches("host-"),
                };
                if !valid_agent_id(a) {
                    bail!("invalid agent id {a:?}");
                }
                let gfs = self
                    .groups()?
                    .into_iter()
                    .find(|g| g.tenant == tenant && g.agents.iter().any(|x| x == a))
                    .map_or_else(Gfs::default, |g| g.gfs);
                plan.key = format!("agent:{a}");
                plan.steps.push(Step::Retention {
                    sources: vec![format!("host-{a}")],
                    gfs,
                });
            }
            "retention" => {
                let (source_id, vmids, gfs) = match p["group_id"].as_i64() {
                    Some(g) => {
                        let g = group(g)?;
                        if !g.agents.is_empty() {
                            plan.key = format!("source:{}", g.source_id);
                            plan.steps.push(Step::Retention {
                                sources: group_sources(&g),
                                gfs: g.gfs,
                            });
                            return Ok(plan);
                        }
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
            "restore_files" => {
                let src = ident(p, "source")?;
                let src_agent = src
                    .strip_prefix("host-")
                    .filter(|a| valid_agent_id(a))
                    .with_context(|| format!("restore_files needs a host-<agent> snapshot, not {src:?}"))?;
                let target = p["agent_id"].as_str().unwrap_or(src_agent);
                let a = self.agent(tenant, target)?;
                plan.key = format!("agent:{}", a.id);
                let paths: Vec<Value> = p["paths"]
                    .as_array()
                    .filter(|x| !x.is_empty() && x.len() <= 1000 && x.iter().all(Value::is_string))
                    .context("paths must be a non-empty list")?
                    .clone();
                let restore = json!({
                    "source_agent": src_agent, "time": num(p, "time")?, "paths": paths,
                    "target": p["target"].as_str().context("missing parameter target")?,
                    "overwrite": p["overwrite"].as_str().unwrap_or("never"),
                    "confirm": p["confirm"].as_str().context("missing parameter confirm")?,
                });
                let (f, step) = self.agentctl(&dir, job, &a, "restore", json!({"restore": restore}))?;
                plan.files.push(f);
                plan.steps.push(step);
            }
            "agent_update" => {
                let a = self.agent(tenant, p["agent_id"].as_str().unwrap_or_default())?;
                plan.key = format!("agent:{}", a.id);
                let (f, step) = self.agentctl(
                    &dir,
                    job,
                    &a,
                    "update",
                    json!({"update_dir": self.cfg.agent_update_dir}),
                )?;
                plan.files.push(f);
                plan.steps.push(step);
            }
            "agent_enroll" => {
                let a = self.agent(tenant, p["agent_id"].as_str().unwrap_or_default())?;
                plan.key = format!("agent:{}", a.id);
                let sealed = a
                    .token_hash
                    .as_deref()
                    .context("agent has no enrollment token (create a new token first)")?;
                if a.token_expires.is_none_or(|e| e <= catalog::now()) {
                    bail!("the enrollment token of agent {} expired (create a new token)", a.name);
                }
                let digest = self
                    .secrets
                    .open(&catalog::secret::agent_token_location(&a.id, &a.host, a.port), sealed)
                    .with_context(|| format!("agent {}", a.id))?;
                plan.files.push(("token".into(), digest.as_bytes().to_vec()));
                let (f, step) = self.agentctl(&dir, job, &a, "enroll", json!({"token_file": dir.join("token")}))?;
                plan.files.push(f);
                plan.steps.push(step);
            }
            "files_list" | "files_get" if p["source"].as_str().is_some_and(|s| s.starts_with("host-")) => {
                let source = ident(p, "source")?;
                let agent = source.trim_start_matches("host-");
                if !valid_agent_id(agent) {
                    bail!("invalid source {source:?}");
                }
                plan.key = format!("guest:{tenant}/{source}");
                let cfg = self.agentctl_base(tenant, job, None, json!({}));
                plan.files
                    .push(("agentctl.json".into(), serde_json::to_vec_pretty(&cfg)?));
                let mut args = vec![
                    dir.join("agentctl.json").to_string_lossy().into_owned(),
                    "files".into(),
                    agent.to_owned(),
                    num(p, "time")?.to_string(),
                ];
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
                plan.steps.push(Step::Cli {
                    bin: self.cfg.agentctl_bin.clone(),
                    args,
                    alert: None,
                    capture: true,
                });
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
                if job.kind == "files_list" {
                    args.push("ls".into());
                    args.push(file_arg(p["path"].as_str().unwrap_or("/"))?);
                } else {
                    let file = download_file(p)?;
                    let out = self.cfg.downloads.join(file);
                    args.push("get".into());
                    args.push(out.to_string_lossy().into_owned());
                    args.extend(file_paths(p)?);
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
                        chunkstore::Index::Tree { entries } => n += entries.iter().map(|e| e.size).sum::<u64>(),
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
            protected.entry(g.tenant.clone()).or_default().extend(group_sources(&g));
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

impl Config {
    pub fn agent_ca_path(&self) -> PathBuf {
        self.agent_ca_dir
            .clone()
            .unwrap_or_else(|| self.state_dir.join("agent-ca"))
    }
    pub fn secrets_key_path(&self) -> PathBuf {
        self.secrets_key
            .clone()
            .unwrap_or_else(|| self.state_dir.join("secrets.key"))
    }
    pub fn secrets_pub_path(&self) -> PathBuf {
        self.secrets_pub.clone().unwrap_or_else(|| {
            self.catalog
                .parent()
                .unwrap_or(Path::new("/var/lib/nexus/catalog"))
                .join("secrets.pub")
        })
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
