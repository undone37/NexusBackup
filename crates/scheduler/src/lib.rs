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
//! `sources.config` (kind `truenas`, docs/truenas-connector.md): API endpoint
//! (`host`, `port`, `connect_addr`, `ca_pem`, `user`, `token_secret` = API key),
//! `ssh` (`host`, `port`, `user`, `host_key`, `key_pem`), `datasets`, `recursive`,
//! `sudo`, `zfs_sudo`. Groups list datasets as guests; backups spawn
//! `nexus-truenas <job>/truenas.json backup` (secrets and the pinned host key as
//! 0600 files in the job dir); snapshots are `nas-<source>-<pool.dataset>`,
//! retention covers each dataset and (recursive) its children by prefix.
//!
//! `sources.config` (kinds `nfs` / `smb`, docs/nas-connector.md): one share
//! (`host`, `port`, `version`, NFS `export`/`mount_port`, SMB `share`/`user`/
//! `domain`/`sec`/`sign`/`seal` with the sealed `password` or `keytab` +
//! `principal`), `snapshot_dir`/`snapshot_prefix`/`snapshot_order`, `excludes`,
//! `threads`, `xattrs`, `timeout_secs`. Groups have no guests; backups spawn
//! `nexus-nas <job>/nas.json backup` (SMB secret as a 0600 file in the job dir;
//! the connector asks `nexus-nasmount` for the mount), snapshots are `share-<source>`.
//!
//! `tenants.offsite`: `{ "remote": { "type": "sftp", "host": …, "user": …, "host_key": …,
//! "key_file": "/path", "port"?, "base_dir"? } | { "type": "s3", "endpoint": "https://…",
//! "region", "bucket", "prefix"?, "access_key", "secret_key" (sealed), "path_style"?,
//! "ca_pem"?, "storage_class_packs"?, "storage_class_meta"?, "lock"? } (docs/s3-offsite.md)
//! | { "type": "local", "path": … }, "bwlimit"?: bytes/s, "uploaders"?: n }`. No `remote` =
//! no offsite for this tenant. The S3 secret key and CA go into 0600 files in the job dir.
//!
//! Job params beyond the contract: `source_id` may be given for `backup {vmid}`,
//! restores and file jobs; without it the source is found via the tenant's
//! groups (or the tenant's only source). Restores take the options of `restore`
//! (`name`, `name_prefix`, `pool`, `start`, `link_down`; `replace` via approval).
//! `files_get` writes `<downloads>/<download_token>.<format>` (token set by the
//! web-api). Structured results go into `jobs.result` (see [`Scheduler::finish`]).

mod accounts;
mod agent_updates;
pub mod alerts;
pub mod anomaly;
mod approvers;
mod bmr;
mod cases;
pub mod changes;
pub mod clock;
mod config_backup;
pub mod consistency;
mod dek_rotation;
pub mod disks;
mod edge;
mod endpoint;
pub mod expiry;
mod fileindex;
pub mod firewall;
mod fleecing;
mod fleet;
pub mod forward;
mod freeze;
mod fullread;
mod holds;
mod inventory;
mod keep;
mod lifecycle;
mod limits;
pub mod network;
mod offsite_ui;
pub mod orphans;
mod os_update;
mod plugins;
mod priority;
pub mod progress;
pub mod psa;
mod recovery;
mod renewal;
pub mod repair;
pub mod replica;
pub mod report_mail;
mod restore;
mod restore_files;
pub mod run;
mod runctl;
mod scan;
mod scanback;
pub mod schedule;
pub mod search;
mod selection;
mod snapmeta;
pub mod sshkeys;
pub mod stats;
pub mod synthetic;
mod tenant_key;
mod tenants;
pub mod threat;
mod windows;

use anyhow::{bail, Context, Result};
use catalog::rusqlite::{params, OptionalExtension};
use catalog::secret::{source_owner, tenant_owner, SchedulerKey};
use catalog::Catalog;
use chunkstore::retention::Gfs;
use chunkstore::Options;
use restore::restore_flags;
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
    /// nexus-index (Phase 31b file search): nudges, rules, health (fileindex.rs)
    pub index_socket: PathBuf,
    pub downloads: PathBuf,
    /// private (0700) dir for generated job configs
    pub runtime_dir: PathBuf,
    /// alert delivery cursor
    pub state_dir: PathBuf,
    pub pve_bin: PathBuf,
    pub offsite_bin: PathBuf,
    /// Linux agent connector (crate agent-conn)
    pub agentctl_bin: PathBuf,
    /// TrueNAS connector (crate truenas)
    pub truenas_bin: PathBuf,
    /// VMware connector (crate vmware)
    pub vmware_bin: PathBuf,
    /// NFS/SMB connector (crate nas)
    pub nas_bin: PathBuf,
    /// plugin host (crate plugin-host, docs/plugin-system.md)
    pub pluginhost_bin: PathBuf,
    /// installed plugins (`<id>/<version>/`, written by nexus-plugin-install)
    pub plugins_dir: PathBuf,
    /// socket of the NAS mount helper (nexus-nasmount.socket)
    pub nas_mount_socket: PathBuf,
    /// appliance CA for agents (created by nexus-agentctl on first use); default `<state_dir>/agent-ca`
    pub agent_ca_dir: Option<PathBuf>,
    /// agent releases from the image (`<version>/manifest.json`, Phase 27) and the
    /// single-binary update files of earlier releases (nexus-agent, .sig, .version)
    pub agent_update_dir: PathBuf,
    /// signed agent releases uploaded in the web UI (Phase 27)
    pub agent_release_upload: PathBuf,
    /// OS update control dir of nexus-update (`status.json`: a rolled-back update raises an alert)
    pub update_dir: PathBuf,
    /// keys agent release manifests must be signed with (the appliance's release keys)
    pub agent_release_keys: PathBuf,
    /// signed edge proxy binary pushed by the edge links (nexus-edge, .sig, .version; edge.rs)
    pub edge_update_dir: PathBuf,
    pub alerts_config: PathBuf,
    /// outbound allow-list for nexus-nft-sync (skipped if its directory is missing)
    pub nft_allowed: PathBuf,
    /// jobs wait this long after the allow-list changed (nexus-nft-sync applies it)
    pub firewall_settle_secs: u64,
    /// full tick (scheduling, refresh, alerts)
    pub tick_secs: u64,
    /// between ticks: pick up newly queued jobs
    pub poll_secs: u64,
    /// running jobs at once (over all sources); default 2 per CPU, 8..=32 (Phase 32)
    pub max_parallel: usize,
    /// of those, at most this many background jobs ([`background`]: file index, scans,
    /// verify, …) so backups and restores always find a slot; default CPUs / 2, 2..=8
    pub max_background: usize,
    /// bytes of output kept per job
    pub log_max: usize,
    /// a running job's output so far and progress go to the catalog this often
    /// (`jobs.live_log`, `jobs.progress`); 0 = only at the end
    pub live_ms: u64,
    /// daily gc + verify per tenant
    pub maintenance: String,
    /// verify re-reads 1/verify_parts of the chunks per run (rolling)
    pub verify_parts: u64,
    pub refresh_secs: i64,
    pub download_ttl_secs: i64,
    pub offsite_lag_secs: i64,
    /// a snapshot fetched back from offsite (`offsite_restore`) is locked
    /// locally at least this long, so local retention keeps it (default 7 days)
    pub offsite_fetch_keep_secs: u64,
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
    /// replication pull client (crate replication, docs/replication.md)
    pub replica_bin: PathBuf,
    /// client keys/certs per replication source; default `<state_dir>/replica`
    pub replica_dir: Option<PathBuf>,
    /// parallel connections of a replica_sync
    pub replica_parallel: usize,
    /// alert when a replicated tenant had no successful sync for this long
    pub replication_lag_secs: i64,
    /// the appliance's own SSH keys (generated here, docs/phase12-contract.md §4);
    /// skipped when the directory is missing
    pub ssh_dir: PathBuf,
    /// a cancelled job's connector gets SIGKILL this long after SIGTERM
    pub cancel_grace_secs: u64,
    /// guest inventory refresh per source (auto-protect groups); 0 = off
    pub inventory_secs: i64,
    /// audit / alert forwarding round (forward.rs); 0 = no forwarder thread
    pub forward_poll_secs: u64,
    /// PSA ticketing round (psa.rs); 0 = no ticketing thread
    pub psa_poll_secs: u64,
    /// nexus-disks status and operations (disks.rs; skipped while there is no status)
    pub disks_dir: PathBuf,
    /// nexus-net status (interface roles for bound egress) and operations (network.rs)
    pub net_dir: PathBuf,
    /// endpoint status poll of every enrolled agent (endpoint.rs); 0 = off
    pub agent_poll_secs: u64,
    /// agents polled at once
    pub agent_poll_concurrency: usize,
    /// appliance configuration backup (config_backup.rs): schedule, control dir of
    /// nexus-config-backup (skipped when missing), how long a run may take
    pub config_backup: String,
    pub config_backup_dir: PathBuf,
    pub config_backup_timeout_secs: u64,
}

fn cpus() -> usize {
    std::thread::available_parallelism().map_or(4, std::num::NonZero::get)
}

/// Job kinds that never hold back a backup or restore (Phase 32: at most
/// `max_background` of them run at once).
pub fn background(kind: &str) -> bool {
    matches!(
        kind,
        "file_index" | "snapshot_scan" | "verify" | "hash_hunt" | "file_changes" | "snapshot_diff"
    )
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
            index_socket: index_proto::DEFAULT_SOCKET.into(),
            downloads: lib.join("downloads"),
            runtime_dir: "/run/nexus-scheduler".into(),
            state_dir: lib.join("scheduler"),
            pve_bin: "/usr/libexec/nexus/nexus-pve".into(),
            offsite_bin: "/usr/libexec/nexus/nexus-offsite".into(),
            agentctl_bin: "/usr/libexec/nexus/nexus-agentctl".into(),
            truenas_bin: "/usr/libexec/nexus/nexus-truenas".into(),
            vmware_bin: "/usr/libexec/nexus/nexus-vmware".into(),
            nas_bin: "/usr/libexec/nexus/nexus-nas".into(),
            pluginhost_bin: "/usr/libexec/nexus/nexus-pluginhost".into(),
            plugins_dir: lib.join("plugins"),
            nas_mount_socket: nas::MOUNT_SOCKET.into(),
            agent_ca_dir: None,
            agent_update_dir: "/usr/share/nexus/agent".into(),
            agent_release_upload: lib.join("agent-releases"),
            update_dir: std::env::var_os("NEXUS_UPDATE_DIR")
                .map(PathBuf::from)
                .unwrap_or_else(|| "/var/lib/nexus/update".into()),
            agent_release_keys: "/etc/pki/nexus/cosign".into(),
            edge_update_dir: "/usr/share/nexus/edge".into(),
            alerts_config: "/etc/nexus/alerts.json".into(),
            nft_allowed: nftsync::ALLOWED_FILE.into(),
            firewall_settle_secs: 3,
            tick_secs: 30,
            poll_secs: 2,
            max_parallel: (cpus() * 2).clamp(8, 32),
            max_background: (cpus() / 2).clamp(2, 8),
            log_max: 256 << 10,
            live_ms: 2000,
            maintenance: "daily 03:00".into(),
            verify_parts: 7,
            refresh_secs: 900,
            download_ttl_secs: 86400,
            offsite_lag_secs: 48 * 3600,
            offsite_fetch_keep_secs: 7 * 86400,
            capacity_threshold: 0.75,
            alert_retry_secs: [10, 60],
            secrets_key: None,
            secrets_pub: None,
            replica_bin: "/usr/libexec/nexus/nexus-replica".into(),
            replica_dir: None,
            replica_parallel: 4,
            replication_lag_secs: 48 * 3600,
            ssh_dir: "/etc/nexus/ssh".into(),
            cancel_grace_secs: 30,
            inventory_secs: 3600,
            forward_poll_secs: 5,
            psa_poll_secs: 60,
            disks_dir: catalog::hardware::DIR.into(),
            net_dir: catalog::network::DIR.into(),
            agent_poll_secs: 120,
            agent_poll_concurrency: 8,
            config_backup: "daily 02:30".into(),
            config_backup_dir: lib.join("config-backup"),
            config_backup_timeout_secs: 1800,
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
    /// renewed certificate issued, not yet confirmed by a session (accepted as a second pin)
    cert_sha256_next: Option<String>,
    /// `{bwlimit, nice}` (agent_proto::Limits), sent with every backup
    limits: Value,
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
    /// datasets (truenas sources: the group's guests are dataset names)
    datasets: Vec<String>,
    /// VM UUIDs (vmware sources: the group's guests; snapshots `vmw-<uuid>`)
    vms: Vec<String>,
    /// the source is a VMware one (dispatch also when `vms` is empty: nothing to back up, not a PVE group)
    vmware: bool,
    /// nfs/smb source: the group backs up the share itself (`share-<source>`)
    share: bool,
    /// plugin source: (plugin id, guest ids; empty = the source as a whole, unless `auto`)
    plugin: Option<(String, Vec<String>)>,
    /// guests resolved from the inventory (mode `all` / `tags`, catalog::inventory):
    /// an empty list means nothing to back up, never "the whole source"
    auto: bool,
    schedule: String,
    gfs: Gfs,
    offsite: bool,
    /// PVE disks not backed up (`{"*": [...], "<vmid>": [...]}`, disk keys) and how a
    /// restore treats them (`placeholder` | `omit`)
    exclude_disks: Value,
    exclude_disks_mode: String,
    /// guests backed up at once (PVE and plugin groups)
    parallel: u32,
    /// the policy's global file filters (`{exclude, exclude_regex}`)
    file_filters: Value,
    /// Phase 28: SHA-256 per file in the name index (IOC hash hunt)
    file_hashes: bool,
    /// Phase 29: days between full reads (effective, 0 = off; catalog::fullread)
    full_read_days: i64,
}

pub struct Scheduler {
    pub cfg: Config,
    pub db: Arc<Catalog>,
    ctx: Arc<Ctx>,
    running: HashMap<i64, String>,
    /// the running jobs that are [`background`] ones
    running_background: HashSet<i64>,
    /// why each queued job waits, as last written to its `progress`
    waits: HashMap<i64, String>,
    tx: Sender<Finished>,
    rx: Receiver<Finished>,
    /// first time an item without scheduled history was seen (no immediate run)
    first_seen: HashMap<String, i64>,
    /// tenants whose keys are known to exist in keyd
    keyed: HashSet<String>,
    dirty: BTreeSet<String>,
    last_refresh: i64,
    alert_tx: Sender<(alerts::AlertsConfig, alerts::Alert)>,
    host: String,
    /// time of the current tick: `created` of queued jobs (due computation)
    now: i64,
    /// opens the sealed secrets in `sources.config` / `tenants.offsite`
    secrets: SchedulerKey,
    secrets_created: bool,
    /// last allow-list check from start_jobs; jobs wait until a changed list is applied
    fw_checked: Option<Instant>,
    fw_settle: Option<Instant>,
    /// running jobs that got SIGTERM (cancel requested), for the SIGKILL deadline
    cancel_sent: HashMap<i64, Instant>,
    /// UTC day of the last `audit.anchor` (forward.rs; None = not read yet)
    anchor_day: Option<i64>,
    /// the tenants' compliance clocks, kept running (clock.rs)
    clock: clock::Keeper,
    /// endpoint status poll of the agents (endpoint.rs)
    poll: endpoint::PollState,
    /// control links to the edge proxies (edge.rs)
    edges: edge::EdgeLinks,
    /// last automatic-mode check of the agent releases (agent_updates.rs)
    auto_checked: i64,
}

/// Agent ids: 16 lowercase hex characters (chosen by the web-api).
fn valid_agent_id(s: &str) -> bool {
    s.len() == 16 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Snapshot sources of a group: `vm-/ct-<vmid>` for PVE, `host-<agent>` for Linux agents,
/// `nas-<source>-<dataset>` for TrueNAS (children of recursive datasets: [`group_prefixes`]),
/// `share-<source>` for NFS/SMB shares, `vmw-<uuid>` for VMware VMs.
pub(crate) fn group_sources(g: &GroupRow) -> Vec<String> {
    g.guests
        .iter()
        .flat_map(|v| [format!("vm-{v}"), format!("ct-{v}")])
        .chain(g.agents.iter().map(|a| format!("host-{a}")))
        .chain(g.datasets.iter().map(|d| truenas::source_name(g.source_id as u64, d)))
        .chain(g.vms.iter().map(|u| vmware::names::source_name(u)))
        .chain(g.share.then(|| nas::source_name(g.source_id as u64)))
        .chain(g.plugin.iter().flat_map(|(pid, guests)| {
            let sid = g.source_id as u64;
            if guests.is_empty() && !g.auto {
                vec![plugin_proto::source_name(pid, sid, None)]
            } else {
                guests
                    .iter()
                    .map(|x| plugin_proto::source_name(pid, sid, Some(x)))
                    .collect()
            }
        }))
        .collect()
}

/// Source prefixes of child datasets (`nas-<source>-<pool.ds>.`), found in the store at retention time.
fn group_prefixes(g: &GroupRow) -> Vec<String> {
    g.datasets
        .iter()
        .map(|d| format!("{}.", truenas::source_name(g.source_id as u64, d)))
        .collect()
}

/// Bytes of the regular files below `dir` (no symlinks followed).
fn dir_bytes(dir: &Path) -> u64 {
    let mut n = 0;
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(rd) = fs::read_dir(&d) else { continue };
        for e in rd.flatten() {
            match e.file_type() {
                Ok(t) if t.is_dir() => stack.push(e.path()),
                Ok(t) if t.is_file() => n += e.metadata().map(|m| m.len()).unwrap_or(0),
                _ => {}
            }
        }
    }
    n
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

/// Snapshots of guest disks (PVE VMs and containers, VMware VMs: #83) whose files come from a `file_index` job,
/// not from the backup itself like the file trees of agents and shares.
pub(crate) fn guest_disks(source: &str) -> bool {
    source.starts_with("vm-") || source.starts_with("ct-") || vmware::names::parse_source_name(source).is_some()
}

fn gfs_of(v: &Value) -> Gfs {
    let d = Gfs::default();
    let f = |k: &str, def: u32| v[k].as_u64().map_or(def, |n| n.min(10_000) as u32);
    Gfs {
        recent: f("recent", d.recent),
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
        // the configuration is read again for every batch (catalog setting or file)
        alerts::AlertsConfig::load(&cfg.alerts_config)?;
        let alert_tx = alerts::spawn_delivery(cfg.alert_retry_secs.map(Duration::from_secs));
        if cfg.forward_poll_secs > 0 {
            let poll = Duration::from_secs(cfg.forward_poll_secs);
            forward::spawn(db.clone(), secrets.clone(), alerts::hostname(), poll);
        }
        if cfg.psa_poll_secs > 0 {
            let poll = Duration::from_secs(cfg.psa_poll_secs);
            psa::spawn(
                db.clone(),
                secrets.clone(),
                alerts::hostname(),
                cfg.alerts_config.clone(),
                poll,
            )?;
        }
        let ctx = Arc::new(Ctx {
            keys,
            store_options,
            log_max: cfg.log_max,
            cancels: Default::default(),
            live: (cfg.live_ms > 0).then(|| run::LiveSink {
                db: db.clone(),
                every: Duration::from_millis(cfg.live_ms),
            }),
        });
        let mut s = Scheduler {
            cfg,
            db,
            ctx,
            running: HashMap::new(),
            running_background: HashSet::new(),
            waits: HashMap::new(),
            tx,
            rx,
            first_seen: HashMap::new(),
            keyed: HashSet::new(),
            dirty: BTreeSet::new(),
            last_refresh: i64::MIN,
            fw_checked: None,
            fw_settle: None,
            cancel_sent: HashMap::new(),
            anchor_day: None,
            clock: Default::default(),
            poll: Default::default(),
            auto_checked: 0,
            edges: Default::default(),
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
        if let Err(e) = self.publish_ssh_keys() {
            eprintln!("<3>scheduler: appliance SSH keys: {e:#}");
        }
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
        // delivery state is in the catalog since v14 (`alerts.notified_ts`)
        let _ = fs::remove_file(self.cfg.state_dir.join("alerts.cursor"));
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
                 log = log || COALESCE(live_log, '') \
                    || '\n[scheduler] interrupted: the scheduler stopped while this job was running', \
                 live_log = NULL, progress = NULL \
                 WHERE id=?2 AND state='running'",
                params![catalog::now(), id],
            )?;
            self.db.audit(
                ACTOR,
                "job.failed",
                &format!("job/{id}"),
                &json!({"kind": kind, "reason": "scheduler restart"}),
            )?;
            // a backup cut off by a reboot is a failed backup like any other: the group's retry
            // policy applies, else job_failed (lab 2026-10-23: it waited for the next schedule
            // without either)
            if kind == "backup" {
                let job = self.job(id)?;
                let log: String = self
                    .db
                    .conn()
                    .query_row("SELECT log FROM jobs WHERE id = ?1", [id], |r| r.get(0))?;
                if !self.retry_failed(&job, &log)? {
                    let attempts = self.attempt_note(id);
                    self.raise(
                        "critical",
                        "job_failed",
                        &lifecycle::job_failed_key(&job),
                        &format!(
                            "backup job {id} ({}) failed{attempts}: interrupted, the appliance or its scheduler restarted",
                            job.tenant
                        ),
                        lifecycle::tenant_of(&job),
                    )?;
                }
            }
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
                // a job for a tenant created since the last tick needs its DEK first
                self.log_err(Scheduler::ensure_tenant_keys);
                // "back up now" through an edge proxy: poll that agent at once (edge.rs)
                self.log_err(|s| {
                    s.collect_agent_poll(None)?;
                    if s.edge_links(catalog::now())? {
                        s.start_agent_poll(catalog::now())?;
                    }
                    Ok(())
                });
                self.log_err(Scheduler::process_cancels);
                self.log_err(Scheduler::start_jobs);
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
        self.log_err(Scheduler::ensure_tenant_keys);
        self.log_err(|s| s.expire_downloads(catalog::now()));
        self.log_err(Scheduler::queue_approved_gc);
        self.log_err(Scheduler::queue_snapshot_deletes);
        self.log_err(Scheduler::queue_restore_replaces);
        self.log_err(|s| s.check_restore_priority(now)); // priority.rs
        self.log_err(|s| s.queue_scheduled(now));
        self.log_err(|s| s.queue_threat_scans(now)); // threat.rs
        self.log_err(|s| s.queue_maintenance(now));
        self.log_err(|s| s.queue_replication(now));
        self.log_err(|s| s.replication_windows(now));
        self.log_err(Scheduler::execute_key_exports);
        self.log_err(Scheduler::queue_ssh_rotations);
        self.log_err(|s| s.blackout_aborts(now));
        self.log_err(Scheduler::process_cancels);
        self.log_err(|s| s.check_sla(now));
        self.log_err(|s| s.check_paused(now));
        self.log_err(|s| s.queue_inventory(now));
        self.log_err(|s| s.queue_fleet_scans(now));
        self.log_err(|s| s.queue_reports(now));
        self.log_err(|s| s.collect_agent_poll(None));
        self.log_err(|s| s.edge_links(now).map(drop));
        self.log_err(|s| s.start_agent_poll(now));
        self.log_err(|s| s.agent_rollouts(now)); // agent_updates.rs
        self.log_err(|s| s.queue_config_backup(now));
        self.log_err(|s| s.queue_rekeys(now));
        // restore tests and recovery plans (recovery.rs)
        self.log_err(|s| s.queue_restore_tests(now));
        self.log_err(Scheduler::queue_recovery_executes);
        self.log_err(|s| s.queue_readiness(now));
        self.log_err(Scheduler::start_jobs);
        let all = now.saturating_sub(self.last_refresh) >= self.cfg.refresh_secs;
        if all || !self.dirty.is_empty() {
            self.log_err(|s| s.refresh(now, all));
            if all {
                self.last_refresh = now;
                self.log_err(|s| s.check_capacity());
                self.log_err(|s| s.sample_capacity(now));
                self.log_err(|s| s.check_quotas());
                self.log_err(|s| s.publish_ssh_keys());
                self.log_err(|s| s.prune_alerts(now));
                self.log_err(|s| s.check_expiry(now));
                self.log_err(|s| s.queue_agent_renewals(now));
                self.log_err(|s| forward::prune_outbox(&s.db, now));
                self.log_err(|s| s.check_accounts(now));
                self.log_err(|s| s.check_dek_rotation(now));
                self.log_err(|s| s.index_maintenance(now));
            }
        }
        self.log_err(|s| s.check_offsite_lag(now));
        self.log_err(|s| s.check_replication_lag(now));
        self.log_err(|s| s.check_forwarding(now));
        self.log_err(|s| s.check_psa(now));
        self.log_err(|s| s.check_tenant_approvers(now));
        self.log_err(|s| s.check_disks(now));
        self.log_err(|s| s.check_os_update());
        self.log_err(|s| s.audit_net_ops());
        self.log_err(Scheduler::check_clock);
        self.log_err(|s| s.check_disabled_tenants());
        self.log_err(|s| s.sync_firewall().map(drop));
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
            "SELECT g.id, g.tenant, g.source_id, g.guests, p.schedule, p.gfs, p.offsite, s.kind, \
             g.mode, g.selector, g.exclude, g.exclude_disks, g.exclude_disks_mode, g.parallel_guests, p.file_filters, \
             g.file_hashes, g.full_read_days \
             FROM groups g JOIN policies p ON p.id = g.policy_id JOIN sources s ON s.id = g.source_id ORDER BY g.id",
        )?;
        let rows = st.query_map([], |r| {
            let gfs: String = r.get(5)?;
            let kind = r.get::<_, String>(7)?;
            let mode: String = r.get(8)?;
            // explicit list or resolved from the inventory: the same set for queueing,
            // plans, retention and offsite-lag checks
            let guests = catalog::inventory::resolve(
                &c,
                r.get(2)?,
                &kind,
                &mode,
                &r.get::<_, String>(3)?,
                &r.get::<_, String>(9)?,
                &r.get::<_, String>(10)?,
            )?;
            let nas = kind == "truenas";
            let vmw = kind == "vmware";
            let share = kind == "nfs" || kind == "smb";
            let plugin = kind.strip_prefix("plugin:").map(|k| {
                (
                    k.to_owned(),
                    guests
                        .iter()
                        .filter_map(|g| {
                            g.as_str()
                                .filter(|x| plugin_proto::valid_guest_id(x))
                                .map(str::to_owned)
                        })
                        .collect::<Vec<_>>(),
                )
            });
            let other = nas || vmw || share || plugin.is_some();
            Ok(GroupRow {
                share,
                plugin,
                auto: catalog::inventory::auto(&mode),
                datasets: if nas {
                    guests
                        .iter()
                        .filter_map(|g| g.as_str().filter(|d| truenas::valid_dataset(d)).map(str::to_owned))
                        .collect()
                } else {
                    Vec::new()
                },
                vmware: vmw,
                vms: if vmw {
                    guests
                        .iter()
                        .filter_map(|g| g.as_str().filter(|u| vmware::names::valid_uuid(u)).map(str::to_owned))
                        .collect()
                } else {
                    Vec::new()
                },
                id: r.get(0)?,
                tenant: r.get(1)?,
                source_id: r.get(2)?,
                guests: if other {
                    Vec::new()
                } else {
                    guests
                        .iter()
                        .filter_map(|g| g.as_u64().and_then(|v| u32::try_from(v).ok()))
                        .collect()
                },
                agents: if other {
                    Vec::new()
                } else {
                    guests
                        .iter()
                        .filter_map(|g| g.as_str().filter(|a| valid_agent_id(a)).map(str::to_owned))
                        .collect()
                },
                schedule: r.get(4)?,
                gfs: gfs_of(&serde_json::from_str(&gfs).unwrap_or(Value::Null)),
                offsite: r.get::<_, i64>(6)? != 0,
                exclude_disks: serde_json::from_str(&r.get::<_, String>(11)?).unwrap_or_default(),
                exclude_disks_mode: r.get(12)?,
                parallel: r.get::<_, u32>(13)?.clamp(1, 8),
                file_filters: serde_json::from_str(&r.get::<_, String>(14)?).unwrap_or_default(),
                file_hashes: r.get(15)?,
                full_read_days: catalog::fullread::days(r.get(16)?, &kind),
            })
        })?;
        let mut rows: Vec<GroupRow> = rows.collect::<std::result::Result<_, _>>()?;
        // plugin groups: kind -> id of the plugin that provides it
        for g in rows.iter_mut() {
            if let Some((kind, guests)) = g.plugin.take() {
                if let Ok(Some(cur)) = plugin_manager::current_for_kind(&c, &kind) {
                    g.plugin = Some((cur.id, guests));
                }
            }
        }
        Ok(rows)
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
        if self.restore_priority()?.is_some() {
            return Ok(()); // due slots run once it ends (priority.rs)
        }
        let off = self.disabled_tenants()?;
        for g in self.groups()?.into_iter().filter(|g| !off.contains(&g.tenant)) {
            let ctl = self.control(g.id)?;
            let sched = match Schedule::parse(&g.schedule).and_then(|s| s.in_tz(&ctl.tz)) {
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
            // paused, source in maintenance, blackout: a slot that passed meanwhile runs afterwards
            if sched.due(last, now) && ctl.hold(now).is_none() {
                self.queue_group_backup(&g, now)?; // laptop policies (endpoint.rs)
            }
        }
        Ok(())
    }

    /// Writes the outbound allow-list (sources, offsite boxes, alert delivery)
    /// for nexus-nft-sync; the file only changes when the destinations do.
    /// Sources and agents (role data), offsite targets and replication primaries
    /// go into the file per role, bound to the role's interface when Settings →
    /// Network gives it one (network.rs); everything else leaves through any.
    fn sync_firewall(&self) -> Result<bool> {
        // role data: everything the appliance pulls backups from
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
            let mut st = c.prepare("SELECT config FROM sources WHERE kind='truenas'")?;
            for cfg in st.query_map([], |r| r.get::<_, String>(0))? {
                if let Ok(v) = serde_json::from_str::<Value>(&cfg?) {
                    targets.extend(firewall::truenas_targets(&v));
                }
            }
        }
        {
            let c = self.db.conn();
            let mut st = c.prepare("SELECT config FROM sources WHERE kind='vmware'")?;
            for cfg in st.query_map([], |r| r.get::<_, String>(0))? {
                if let Ok(v) = serde_json::from_str::<Value>(&cfg?) {
                    targets.extend(firewall::vmware_targets(&v));
                }
            }
        }
        {
            let c = self.db.conn();
            let mut st = c.prepare("SELECT kind, config FROM sources WHERE kind IN ('nfs','smb')")?;
            for row in st.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))? {
                let (kind, cfg) = row?;
                if let Ok(v) = serde_json::from_str::<Value>(&cfg) {
                    targets.extend(firewall::share_targets(&kind, &v));
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
        targets.extend(self.plugin_targets()?);
        // checked-in rescue agents (bare-metal recovery, bmr.rs)
        targets.extend(self.rescue_targets()?);
        // fleet enrollment: the scanned ranges on the agent port (crate::fleet)
        targets.extend(self.fleet_targets()?);
        // edge proxies: control port (enrollment, link, relayed agent sessions)
        targets.extend(self.edge_targets()?);
        let data = std::mem::take(&mut targets);
        let mut offsite = Vec::new();
        for (_, o) in self.tenants()? {
            offsite.extend(firewall::offsite_targets(&o));
            // Phase 30: the second offsite target
            offsite.extend(firewall::offsite_targets(&o["second"]));
        }
        // approved "attach an offsite copy" requests: the target before the tenant exists
        offsite.extend(self.attach_targets()?);
        // secondary: the primaries' management ports (docs/replication.md §10)
        let replication = self.replication_targets()?;
        let roles = self.egress_roles([("data", data), ("offsite", offsite), ("replication", replication)]);
        if let Ok(a) = self.alerts_config() {
            targets.extend(firewall::alert_targets(&a));
        }
        targets.extend(firewall::oidc_targets(&self.db.conn())?);
        let fwd = catalog::forwarding::Forwarding::load(&self.db.conn())?;
        targets.extend(firewall::forward_targets(&fwd));
        // inbound: per-service source lists (Settings → Firewall; empty = any)
        let inbound = nftsync::inbound_map(catalog::firewall::load(&self.db.conn())?.effective());
        let changed = nftsync::write_allowed(
            &self.cfg.nft_allowed,
            firewall::resolve(&targets),
            Some(&inbound),
            &roles,
        )?;
        if changed {
            eprintln!(
                "scheduler: firewall allow-list updated ({} destinations, {} by role)",
                targets.len(),
                roles.values().map(|r| r.endpoints.len()).sum::<usize>()
            );
        }
        Ok(changed)
    }

    /// Before jobs start: a destination added since the last tick (an agent created
    /// and enrolled right away) must be in the firewall first, or the job fails with
    /// "No route to host". At most every poll interval; when the list changed, jobs
    /// wait `firewall_settle_secs` for nexus-nft-sync (path unit) to apply it.
    fn firewall_ready(&mut self) -> bool {
        let now = Instant::now();
        if self
            .fw_checked
            .is_none_or(|t| now.duration_since(t) >= Duration::from_secs(self.cfg.poll_secs.max(1)))
        {
            self.fw_checked = Some(now);
            match self.sync_firewall() {
                Ok(true) => self.fw_settle = Some(now + Duration::from_secs(self.cfg.firewall_settle_secs)),
                Ok(false) => {}
                Err(e) => eprintln!("<3>scheduler: firewall allow-list: {e:#}"),
            }
        }
        self.fw_settle.is_none_or(|t| now >= t)
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
        if self.restore_priority()?.is_some() {
            return Ok(());
        }
        let sched = Schedule::parse(&self.cfg.maintenance)?;
        for (tenant, _) in self.tenants()? {
            if !valid_name(&tenant) || !self.cfg.store_base.join(&tenant).join("keycheck").exists() {
                continue; // no backups yet
            }
            for kind in ["gc", "verify", "file_index"] {
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
            self.resolve(&format!("gc_quorum:{tenant}"))?;
        }
        Ok(())
    }

    // ------------------------------------------------------------- running

    fn queued(&self) -> Result<Vec<Job>> {
        let c = self.db.conn();
        // retries wait for their delay (`not_before`)
        let mut st = c.prepare(
            "SELECT id, kind, tenant, params FROM jobs WHERE state='queued' \
             AND (not_before IS NULL OR not_before <= ?1) ORDER BY id",
        )?;
        let rows = st.query_map([catalog::now()], |r| {
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

    /// FIFO over queued jobs; a job whose key (group, guest, source) is busy
    /// waits, later jobs with other keys may pass it. At most `max_parallel` at
    /// once. Every queued job that does not start gets the reason in its
    /// `progress` (`{"waiting": …}`), so the UI can say why it waits.
    pub fn start_jobs(&mut self) -> Result<()> {
        let queued = self.queued()?;
        if queued.is_empty() {
            return Ok(());
        }
        let mut waits: Vec<(i64, Value)> = Vec::new();
        if !self.firewall_ready() {
            waits.extend(queued.iter().map(|j| (j.id, json!({"waiting": "firewall"}))));
            return self.record_waits(waits);
        }
        // key -> the running job holding it
        let mut busy: HashMap<String, i64> = self.running.iter().map(|(id, k)| (k.clone(), *id)).collect();
        let priority = self.restore_priority()?.is_some();
        for job in queued {
            if self.running.len() >= self.cfg.max_parallel {
                waits.push((job.id, json!({"waiting": "slots", "slots": self.cfg.max_parallel})));
                continue;
            }
            if background(&job.kind) && self.running_background.len() >= self.cfg.max_background {
                // the other slots stay free for backups and restores
                waits.push((
                    job.id,
                    json!({"waiting": "background", "slots": self.cfg.max_background}),
                ));
                continue;
            }
            if self.held_by_priority(&job, priority)? {
                waits.push((job.id, json!({"waiting": "restore_priority"})));
                continue; // restore priority: waits for its end
            }
            if self.hold_offsite(&job)? {
                waits.push((job.id, json!({"waiting": "offsite_window"})));
                continue; // pause window: waits for its end
            }
            if self.hold_for_scan(&job)? {
                waits.push((job.id, json!({"waiting": "scan_first"})));
                continue; // scan first: waits for its snapshot_scan (scan.rs)
            }
            if self.drive_scan_back(&job)? {
                waits.push((job.id, json!({"waiting": "scan_back"})));
                continue; // scan back: drives its snapshot_scan jobs (scanback.rs)
            }
            let plan = match self.plan(&job) {
                Ok(p) => p,
                Err(e) => {
                    self.fail_unstartable(&job, &format!("{e:#}"))?;
                    continue;
                }
            };
            if let Some(&other) = busy.get(&plan.key) {
                waits.push((job.id, json!({"waiting": "busy", "job": other})));
                continue;
            }
            busy.insert(plan.key.clone(), job.id);
            let changed = self.db.conn().execute(
                "UPDATE jobs SET state='running', started=?1, progress=NULL WHERE id=?2 AND state='queued'",
                params![catalog::now(), job.id],
            )?;
            if changed == 0 {
                busy.remove(&plan.key);
                continue; // cancelled meanwhile
            }
            self.waits.remove(&job.id);
            self.db.audit(
                ACTOR,
                "job.start",
                &format!("job/{}", job.id),
                &json!({"kind": job.kind, "tenant": job.tenant, "key": plan.key}),
            )?;
            self.running.insert(job.id, plan.key.clone());
            if background(&job.kind) {
                self.running_background.insert(job.id);
            }
            let (tx, ctx, id) = (self.tx.clone(), self.ctx.clone(), job.id);
            std::thread::spawn(move || {
                let f = execute(id, &plan, &ctx);
                let _ = tx.send(f);
            });
        }
        self.record_waits(waits)
    }

    /// Writes why queued jobs wait (`jobs.progress` of a queued job), only when it changed.
    fn record_waits(&mut self, waits: Vec<(i64, Value)>) -> Result<()> {
        let now: HashSet<i64> = waits.iter().map(|(id, _)| *id).collect();
        self.waits.retain(|id, _| now.contains(id));
        for (id, w) in waits {
            let s = w.to_string();
            if self.waits.get(&id) == Some(&s) {
                continue;
            }
            self.db.conn().execute(
                "UPDATE jobs SET progress = ?2 WHERE id = ?1 AND state = 'queued'",
                params![id, s],
            )?;
            self.waits.insert(id, s);
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
            self.raise(
                "critical",
                "job_failed",
                &lifecycle::job_failed_key(job),
                &format!("{} job {} ({}) failed: {msg}", job.kind, job.id, job.tenant),
                lifecycle::tenant_of(job),
            )?;
            self.recovery_unstartable(job, msg)?;
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
    pub fn finish(&mut self, mut f: Finished) -> Result<()> {
        self.running.remove(&f.id);
        self.running_background.remove(&f.id);
        self.ctx.cancels.remove(f.id);
        self.cancel_sent.remove(&f.id);
        let job = self.job(f.id)?;
        let ok = f.outcome == Outcome::Ok;
        let mut log = f.log;
        let result = if ok {
            self.result(&job, f.stdout.as_deref(), &mut log)
        } else {
            self.failed_result(&job, &log)
        };
        if job.kind == "plugin_restore" && job.params["restore"] == "verify" && f.outcome != Outcome::Cancelled {
            self.plugin_test_finished(&job, ok, result.as_ref(), &log)?;
        }
        // group backups of a plugin source run as `backup` (schedules), single sources as `plugin_backup`
        if ok && (job.kind == "backup" || job.kind == "plugin_backup") {
            self.meta_bookkeeping(&job, result.as_ref())?;
        }
        if ok && (job.kind == "backup" || job.kind == "plugin_backup") {
            // snapshots.consistency + policy `require_consistency` (crate::consistency)
            if let Some(why) = self.consistency_bookkeeping(&job, result.as_ref())? {
                log.push_str(&format!("[scheduler] {why}\n"));
                f.outcome = Outcome::Failed { alert: None };
            }
        }
        if job.kind == "backup" {
            // Phase 29: full reads (fullread.rs); snapshots committed before a failure count too
            self.full_read_bookkeeping(&job, &mut log)?;
        }
        let state = match f.outcome {
            Outcome::Ok => "ok",
            Outcome::Cancelled => "cancelled",
            _ => "failed",
        };
        self.db.conn().execute(
            "UPDATE jobs SET state=?1, finished=?2, log=log || ?3, result=?4, live_log=NULL, progress=NULL \
             WHERE id=?5",
            params![
                state,
                catalog::now(),
                log,
                result.as_ref().map(std::string::ToString::to_string),
                job.id
            ],
        )?;
        self.db.audit(
            ACTOR,
            &format!("job.{state}"),
            &format!("job/{}", job.id),
            &json!({"kind": job.kind, "tenant": job.tenant}),
        )?;
        // Phase 31: snapshot_index for file_index, nexus-index nudges (fileindex.rs)
        self.index_after_job(&job, ok, result.as_ref(), &log)?;
        if job.kind == "report_send" && state != "cancelled" {
            return self.report_finished(&job, ok, &log, result.as_ref());
        }
        let recovery = recovery::KINDS.contains(&job.kind.as_str());
        if recovery {
            self.recovery_finished(&job, state, &log, f.stdout.as_deref())?;
        }
        if job.kind.starts_with("config_") && state != "cancelled" {
            return self.config_finished(&job, ok, &log, result.as_ref());
        }
        if matches!(
            job.kind.as_str(),
            "backup"
                | "plugin_backup"
                | "retention"
                | "offsite"
                | "gc"
                | "replica_sync"
                | "snapshot_delete"
                | "offsite_restore"
        ) {
            self.dirty.insert(job.tenant.clone());
        }
        if job.kind == "offsite_attach" {
            self.attach_bookkeeping(&job, ok)?;
        }
        self.agent_bookkeeping(&job, &log)?;
        let update_handled = job.kind == "agent_update" && self.update_bookkeeping(&job, state, &log)?;
        if job.kind == "bmr" || job.kind == "p2v" {
            self.rescue_bookkeeping(&job, &log, ok)?;
        }
        if job.kind == "edge_enroll" {
            self.edge_bookkeeping(&job, &log)?;
        }
        if job.kind == "fleet_scan" {
            self.fleet_bookkeeping(&job, &log)?;
        }
        self.endpoint_bookkeeping(&job, state, &log)?;
        if job.kind == "backup" {
            self.fleecing_bookkeeping(&job, &log)?;
            self.backup_meta_bookkeeping(&job, &log)?; // limits.rs
        }
        if job.kind.starts_with("ssh_key_") {
            self.publish_ssh_keys()?;
            if ok {
                let action = if job.kind == "ssh_key_rotate" {
                    "ssh_key.rotate"
                } else {
                    "ssh_key.retired"
                };
                self.db.audit(
                    ACTOR,
                    action,
                    &format!("ssh_key/{}", job.params["name"].as_str().unwrap_or_default()),
                    result.as_ref().unwrap_or(&Value::Null),
                )?;
            }
        }
        // a cancelled sync (window closed, vault closed) is no error: the next one resumes
        if job.kind.starts_with("replica_") && state != "cancelled" {
            self.replica_bookkeeping(&job, &log, ok)?;
        }
        if ok && (job.kind == "backup" || job.kind == "plugin_backup") {
            self.inconsistent_alerts(job.id, &job.tenant, &log)?;
            self.record_stats(&job.tenant, &log)?;
            self.keep_until_bookkeeping(&job, &log)?;
            self.queue_name_index(&job, result.as_ref())?;
            self.queue_changes_after_backup(&job.tenant, &log)?;
        }
        // file-level change signals (changes.rs): VM/CT once their disks are indexed
        if ok && job.kind == "file_index" {
            if let (Some(s), Some(t)) = (job.params["source"].as_str(), job.params["time"].as_i64()) {
                self.queue_file_changes(&job.tenant, s, t)?;
            }
        }
        if ok && job.kind == "file_changes" {
            self.changes_bookkeeping(&job, result.as_ref())?;
        }
        if job.kind == "snapshot_scan" {
            self.scan_bookkeeping(&job, ok, result.as_ref())?;
        }
        if ok && job.kind == "hash_hunt" {
            self.hunt_bookkeeping(&job, result.as_ref())?; // threat.rs
        }
        if ok && job.kind == "file_search" && job.params["case_id"].is_i64() {
            self.case_bookkeeping(&job, result.as_ref())?; // cases.rs
        }
        if job.kind == "gc" {
            self.orphan_bookkeeping(&job.tenant, f.stdout.as_deref())?;
        }
        if job.kind == "verify" || job.kind == "chunk_repair" {
            self.health_bookkeeping(&job, f.stdout.as_deref())?; // repair.rs
        }
        if ok && job.kind == "snapshot_delete" {
            let p = &job.params;
            self.db.audit(
                ACTOR,
                "snapshot.delete",
                &format!(
                    "snapshot/{}/{}/{}",
                    job.tenant,
                    p["source"].as_str().unwrap_or_default(),
                    p["time"]
                ),
                &json!({"job": job.id, "quorum_id": p["quorum_id"], "requested_by": p["requested_by"]}),
            )?;
        }
        if let (true, Some(r)) = (job.kind == "inventory" || job.kind == "plugin_guests", &result) {
            self.apply_inventory(&job, r)?;
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
            Outcome::Ok => {
                self.resolve_after_ok(&job)?;
                self.follow_up(&job)?;
            }
            Outcome::Quorum { message } => self.request_gc_quorum(&job, &message)?,
            Outcome::Cancelled => {}
            // recovery_finished raised restore_test / recovery_plan alerts
            Outcome::Failed { .. } if recovery => {}
            // agent_update_failed (or nothing for a busy agent) instead of job_failed
            Outcome::Failed { .. } if update_handled => {}
            Outcome::Failed { alert } => {
                if alert.is_none() && self.retry_failed(&job, &log)? {
                    return Ok(()); // job_failed only after the last attempt
                }
                let tail: String = log
                    .lines()
                    .rev()
                    .filter(|l| !run::is_time_mark(l))
                    .take(3)
                    .collect::<Vec<_>>()
                    .into_iter()
                    .rev()
                    .collect::<Vec<_>>()
                    .join(" | ");
                let (sev, kind, what) = match alert {
                    Some("verify") => ("critical", "verify", "verification failed"),
                    Some("inventory") => ("critical", "inventory", "offsite inventory anomaly"),
                    // an unreachable source: one open warning per source, not one per hour
                    Some("inventory_refresh") => {
                        let what = format!("guest inventory of source {} ", job.params["source_id"]);
                        return self.alert(
                            "warning",
                            "inventory_refresh",
                            &format!("{what}could not be refreshed (job {}): {tail}", job.id),
                            Some(&what),
                        );
                    }
                    // replica_bookkeeping raised replication_verify / replication_keys already
                    Some("replication")
                        if log
                            .lines()
                            .any(|l| l.starts_with("verify-failed ") || l.starts_with("key-mismatch ")) =>
                    {
                        return Ok(());
                    }
                    _ => ("critical", "job_failed", "failed"),
                };
                let attempts = self.attempt_note(job.id);
                let key = match kind {
                    "job_failed" => lifecycle::job_failed_key(&job),
                    // Phase 30: the second offsite target's inventory alert is its own
                    "inventory" if offsite_job_target(&job.params) == 2 => format!("{kind}:{}:2", job.tenant),
                    _ => format!("{kind}:{}", job.tenant),
                };
                self.raise(
                    sev,
                    kind,
                    &key,
                    &format!("{} job {} ({}) {what}{attempts}: {tail}", job.kind, job.id, job.tenant),
                    lifecycle::tenant_of(&job),
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
            self.agent_info_lines(job, log, None)?;
            return self.agent_cert_lines(job, log, None);
        };
        self.agent_info_lines(job, log, Some(&expected))?;
        if job.kind != "agent_enroll" {
            return self.agent_cert_lines(job, log, Some(&expected));
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
                "UPDATE agents SET cert_sha256=?2, enrolled_at=?3, token_hash=NULL, token_expires=NULL, last_seen=?3, \
                 cert_sha256_next=NULL, cert_issued=NULL, cert_expires=NULL \
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
        // the confirming session's `agent-cert` line: validity of the new certificate
        self.agent_cert_lines(job, log, Some(&expected))
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
            self.agent_facts(id, &v)?;
        }
        Ok(())
    }

    /// Structured result of a successful job (`jobs.result`, docs/control-plane.md).
    fn result(&self, job: &Job, stdout: Option<&str>, log: &mut String) -> Option<Value> {
        match job.kind.as_str() {
            "synthetic_restore" => self.synthetic_result(job, stdout, log),
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
            "alert_test" | "forward_test" | "report_send" | "ssh_key_rotate" | "ssh_key_retire" | "file_search"
            | "file_index" | "file_changes" | "snapshot_diff" | "config_backup" | "snapshot_scan" | "hash_hunt" => {
                serde_json::from_str(stdout.unwrap_or_default()).ok()
            }
            "offsite_list" => match serde_json::from_str::<Value>(stdout.unwrap_or_default().trim()) {
                Ok(s @ Value::Array(_)) => Some(json!({ "snapshots": s })),
                _ => {
                    log.push_str("[scheduler] unexpected offsite listing (no JSON array)\n");
                    None
                }
            },
            "plugin_validate" | "plugin_guests" | "inventory" => {
                let out = stdout.unwrap_or_default();
                match serde_json::from_str::<Value>(out.trim()) {
                    Ok(v @ Value::Object(_)) => Some(v),
                    _ => {
                        log.push_str("[scheduler] unexpected plugin host output (no JSON object)\n");
                        None
                    }
                }
            }
            "plugin_restore" | "plugin_mount" => {
                let pfx = if job.kind == "plugin_restore" {
                    "restored "
                } else {
                    "unmounted "
                };
                log.lines()
                    .find_map(|l| serde_json::from_str::<Value>(l.strip_prefix(pfx)?).ok())
            }
            "backup" | "plugin_backup" => {
                // `committed <source>/<time>` per guest (nexus-pve backup-all)
                // nexus-agentctl adds `… chunks transferred (<n> bytes, …)` and an
                // `inconsistent <source>/<time>: …` line for a backup without a consistent view
                let mut snaps: Vec<Value> = log
                    .lines()
                    .filter_map(|l| {
                        let rest = l.strip_prefix("committed ")?;
                        let id = rest.split_whitespace().next()?;
                        let (s, t) = id.rsplit_once('/')?;
                        let mut v = json!({"source": s, "time": t.parse::<i64>().ok()?});
                        if s.starts_with("nas-") || s.starts_with("share-") {
                            // `… in <s>s: <n> entries, …` (Phase 22b sizing note, web-api nasops)
                            if let Some(n) = rest
                                .split_once(": ")
                                .and_then(|(_, x)| x.split_once(" entries"))
                                .and_then(|(n, _)| n.parse::<u64>().ok())
                            {
                                v["entries"] = json!(n);
                            }
                        }
                        if s.starts_with("nas-") {
                            // `…, <n> bytes transferred[, full read …]` (nexus-truenas)
                            if let Some(n) = rest
                                .split_once(" bytes transferred")
                                .and_then(|(a, _)| a.rsplit(' ').next())
                                .and_then(|n| n.parse::<u64>().ok())
                            {
                                v["transferred_bytes"] = json!(n);
                            }
                        }
                        if s.starts_with("share-") || s.starts_with("plugin-") {
                            // `…, <n> bytes transferred, …` and `inconsistent <id>: …` (nexus-nas)
                            let bad = format!("inconsistent {id}:");
                            v["consistent"] = json!(!log.lines().any(|x| x.starts_with(&bad)));
                            if let Some(n) = rest
                                .split_once(" bytes transferred")
                                .and_then(|(a, _)| a.rsplit(' ').next())
                                .and_then(|n| n.parse::<u64>().ok())
                            {
                                v["transferred_bytes"] = json!(n);
                            }
                        }
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
                        // `warnings <id>: <n> items …` (nexus-pluginhost, contract v1.7): ok with warnings
                        let warn = format!("warnings {id}: ");
                        if let Some(n) = log
                            .lines()
                            .find_map(|x| x.strip_prefix(&warn)?.split(' ').next()?.parse::<u64>().ok())
                        {
                            v["warnings"] = json!(n);
                        }
                        Some(v)
                    })
                    .collect();
                self.add_consistency(&job.tenant, log, &mut snaps);
                snapmeta::attach(log, &mut snaps);
                limits::attach_identity(log, &mut snaps); // VM identity (Phase 22b)
                let warnings: u64 = snaps.iter().filter_map(|s| s["warnings"].as_u64()).sum();
                let mut r = json!({ "snapshots": snaps });
                if let [one] = snaps.as_slice() {
                    for k in ["source", "time", "consistent", "consistency", "transferred_bytes"] {
                        if !one[k].is_null() {
                            r[k] = one[k].clone();
                        }
                    }
                }
                if warnings > 0 {
                    r["warnings"] = json!(warnings);
                }
                Some(r)
            }
            // `restored {json}` / `enrolled {json}` (nexus-agentctl, nexus-replica), `replicated {json}`
            // Phase 30: an in-place rollback reports `rolled-back {json}` instead
            "restore" if log.lines().any(|l| l.starts_with("rolled-back {")) => log.lines().find_map(|l| {
                let mut v = serde_json::from_str::<Value>(l.strip_prefix("rolled-back ")?).ok()?;
                v["rolled_back"] = json!(true);
                Some(v)
            }),
            "restore_files" | "agent_enroll" | "replica_enroll" | "replica_sync" | "restore" | "restore_ct"
            | "instant_disk" => {
                let pfx = match job.kind.as_str() {
                    "restore_files" | "restore" | "restore_ct" => "restored ",
                    "instant_disk" => "attached ",
                    "replica_sync" => "replicated ",
                    _ => "enrolled ",
                };
                log.lines()
                    .find_map(|l| serde_json::from_str::<Value>(l.strip_prefix(pfx)?).ok())
            }
            _ => None,
        }
    }

    /// Follow-up jobs carry `after_job` (the job that queued them) so the UI can show
    /// them with it (backup -> retention -> offsite, backup -> file_index).
    fn follow_up(&mut self, job: &Job) -> Result<()> {
        match job.kind.as_str() {
            "plugin_backup" => {
                let p =
                    json!({"chain": true, "source_id": job.params["source_id"], "plugin": true, "after_job": job.id});
                self.insert_job("retention", &job.tenant, &p)?;
            }
            "backup" => {
                let mut p = json!({"chain": true, "after_job": job.id});
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
                    (None, None) if job.params["plugin"] == true => {
                        let sid = job.params["source_id"].as_i64();
                        self.groups()?
                            .iter()
                            .any(|g| g.tenant == job.tenant && g.offsite && Some(g.source_id) == sid)
                    }
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
                // Phase 30: one offsite job per configured target
                for n in self.offsite_targets(&job.tenant)? {
                    let pending: i64 = self.db.conn().query_row(
                        "SELECT COUNT(*) FROM jobs WHERE kind='offsite' AND tenant=?1 AND state='queued'
                           AND COALESCE(json_extract(params, '$.target'), 1) = ?2",
                        params![job.tenant, n],
                        |r| r.get(0),
                    )?;
                    if wants && pending == 0 && !catalog::tenants::disabled(&self.db.conn(), &job.tenant)? {
                        let p = if n == 1 {
                            json!({"chain": true, "after_job": job.id})
                        } else {
                            json!({"chain": true, "target": n, "after_job": job.id})
                        };
                        self.insert_job("offsite", &job.tenant, &p)?;
                    }
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

    /// A GC that would delete too much: a quorum request, or — with approvals
    /// disabled (plan §2) — a `gc_confirm/<tenant>` setting that an admin
    /// confirms (`POST /api/v1/gc/approve-large`). Never runs silently.
    fn request_gc_quorum(&mut self, job: &Job, message: &str) -> Result<()> {
        let key = format!("gc_confirm/{}", job.tenant);
        if !catalog::approvals_enabled(&self.db.conn())? {
            let fresh = self.db.conn().execute(
                "INSERT OR IGNORE INTO settings (key, value) VALUES (?1, ?2)",
                params![
                    key,
                    json!({"job": job.id, "reason": message, "created": catalog::now()}).to_string()
                ],
            )?;
            if fresh == 0 {
                return Ok(()); // already waiting for confirmation
            }
            self.db.audit(
                ACTOR,
                "gc.confirm_required",
                &format!("tenant/{}", job.tenant),
                &json!({"job": job.id, "reason": message, "approvals": "disabled"}),
            )?;
            return self.raise(
                "warning",
                "gc_confirm",
                &format!("gc_confirm:{}", job.tenant),
                &format!(
                    "GC for tenant {} was not run: {message}. Approvals are disabled, so an admin must confirm it \
                     (Approvals page, or POST /api/v1/gc/approve-large)",
                    job.tenant
                ),
                Some(&job.tenant),
            );
        }
        // approvals were enabled again since: a stale confirmation no longer applies
        self.db.conn().execute("DELETE FROM settings WHERE key = ?1", [&key])?;
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
        self.raise(
            "warning",
            "gc_quorum",
            &format!("gc_quorum:{}", job.tenant),
            &format!(
                "GC for tenant {} needs approval by an admin or security officer (quorum request {id}): {message}",
                job.tenant
            ),
            Some(&job.tenant),
        )
    }

    // ------------------------------------------------------------- planning

    fn source(&self, tenant: &str, id: i64) -> Result<Value> {
        self.source_of(tenant, id, "pve")
    }

    /// Config of a source of kind `want`, secrets opened (in memory only).
    fn source_of(&self, tenant: &str, id: i64, want: &str) -> Result<Value> {
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
        if kind != want {
            bail!("source {id}: unsupported kind {kind} (expected {want})");
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
            // free-space thresholds (absent = nexus-pve's defaults)
            "fleecing_guard": src.get("fleecing_guard").filter(|g| g.is_object()).cloned().unwrap_or(json!({})),
            "nodes": nodes,
            "vmids": vmids,
        });
        let mut cfg = cfg;
        limits::pve_limits(&src, &mut cfg); // Phase 22b: caps and read limit
        files.push(("pve.json".into(), serde_json::to_vec_pretty(&cfg)?));
        Ok(files)
    }

    /// nexus-truenas config (docs/truenas-connector.md); the CA/pinned certificate,
    /// API key, SSH key and pinned host key go into 0600 files in the job dir.
    fn truenas_config(&self, tenant: &str, source_id: i64, dir: &Path, datasets: &[String]) -> Result<Files> {
        let src = self.source_of(tenant, source_id, "truenas")?;
        let s = |v: &Value, k: &str| -> Result<String> {
            v[k].as_str()
                .map(str::to_owned)
                .with_context(|| format!("source {source_id}: missing {k}"))
        };
        let ssh = &src["ssh"];
        let host = s(ssh, "host")?;
        let port = ssh["port"].as_u64().unwrap_or(22);
        let known = if port == 22 {
            host.clone()
        } else {
            format!("[{host}]:{port}")
        };
        let mut key = s(ssh, "key_pem")?;
        if !key.ends_with('\n') {
            key.push('\n');
        }
        let mut files: Files = vec![
            ("ca.pem".into(), s(&src, "ca_pem")?.into_bytes()),
            ("api-key".into(), s(&src, "token_secret")?.into_bytes()),
            ("ssh.key".into(), key.into_bytes()),
            (
                "known_hosts".into(),
                format!("{known} {}\n", s(ssh, "host_key")?).into_bytes(),
            ),
        ];
        let cfg = json!({
            "tenant": tenant,
            "store": self.cfg.store_base.join(tenant),
            "keyd_socket": self.cfg.keyd_socket,
            "source_id": source_id,
            "api": {
                "host": s(&src, "host")?,
                "port": src["port"].as_u64().unwrap_or(443),
                "connect_addr": src["connect_addr"],
                "ca_file": dir.join("ca.pem"),
                "user": src["user"].as_str().unwrap_or("nexusbackup"),
                "key_file": dir.join("api-key"),
            },
            "ssh": {
                "host": host,
                "port": port,
                "user": ssh["user"].as_str().unwrap_or("nexusbackup"),
                "key_file": dir.join("ssh.key"),
                "known_hosts_file": dir.join("known_hosts"),
            },
            "datasets": datasets,
            "recursive": src["recursive"].as_bool().unwrap_or(false),
            "sudo": src["sudo"].as_bool().unwrap_or(true),
            "zfs_sudo": src["zfs_sudo"].as_bool().unwrap_or(true),
        });
        let mut cfg = cfg;
        // Phase 22b: read limit, "use existing snapshots" with the snapshots the last backups came from
        self.truenas_limits(tenant, source_id, &src, &mut cfg)?;
        files.push(("truenas.json".into(), serde_json::to_vec_pretty(&cfg)?));
        Ok(files)
    }

    /// Backup of TrueNAS datasets (one nexus-truenas run; exclusive per source).
    fn plan_truenas_backup(&self, mut plan: Plan, source_id: i64, datasets: &[String]) -> Result<Plan> {
        if datasets.is_empty() {
            bail!("nothing to back up: no datasets");
        }
        plan.key = format!("source:{source_id}");
        plan.files = self.truenas_config(&plan.tenant, source_id, &plan.dir, datasets)?;
        plan.steps.push(Step::Cli {
            bin: self.cfg.truenas_bin.clone(),
            args: vec![
                plan.dir.join("truenas.json").to_string_lossy().into_owned(),
                "backup".into(),
            ],
            alert: None,
            capture: false,
        });
        Ok(plan)
    }

    /// nexus-vmware config (docs/vmware-design.md). Source config: `host`, `port` (443), `ca_pem` (the vSphere
    /// certificate or its CA, pinned), `user`, `password` (sealed), `datacenter` (`ha-datacenter` on a
    /// standalone host), `transport` (`nfc`). The password and the certificate go into 0600 files in the job dir.
    fn vmware_config(&self, tenant: &str, source_id: i64, dir: &Path, vms: &[String]) -> Result<Files> {
        let src = self.source_of(tenant, source_id, "vmware")?;
        let s = |k: &str| -> Result<String> {
            src[k]
                .as_str()
                .map(str::to_owned)
                .with_context(|| format!("source {source_id}: missing {k}"))
        };
        let files: Files = vec![
            ("ca.pem".into(), s("ca_pem")?.into_bytes()),
            ("password".into(), s("password")?.into_bytes()),
        ];
        let cfg = json!({
            "tenant": tenant,
            "store": self.cfg.store_base.join(tenant),
            "keyd_socket": self.cfg.keyd_socket,
            "source_id": source_id,
            "host": s("host")?,
            "port": src["port"].as_u64().unwrap_or(443),
            "ca_file": dir.join("ca.pem"),
            "user": s("user")?,
            "password_file": dir.join("password"),
            "datacenter": src["datacenter"].as_str().unwrap_or("ha-datacenter"),
            "transport": src["transport"].as_str().unwrap_or("nfc"),
            "vms": vms,
        });
        let mut files = files;
        files.push(("vmware.json".into(), serde_json::to_vec_pretty(&cfg)?));
        Ok(files)
    }

    /// Backup of VMware VMs (one nexus-vmware run; exclusive per source: one vSphere session and the VMs'
    /// snapshots at a time).
    /// Hot-add (#80): per VM `proxy-prepare`, `nexus-agentctl block-read` on the proxy's agent, `proxy-finish`.
    fn plan_vmware_backup(&self, job: &Job, mut plan: Plan, source_id: i64, vms: &[String]) -> Result<Plan> {
        if vms.is_empty() {
            bail!("nothing to back up: no VMs");
        }
        plan.key = format!("source:{source_id}");
        plan.files = self.vmware_config(&plan.tenant, source_id, &plan.dir, vms)?;
        let src = self.source_of(&plan.tenant, source_id, "vmware")?;
        if src["transport"] == "hotadd" {
            let agent = src["proxy_agent"]
                .as_str()
                .with_context(|| format!("source {source_id}: missing proxy_agent"))?;
            let a = self.agent(&plan.tenant, agent)?;
            let mut base: Value = serde_json::from_slice(&plan.files.pop().context("vmware.json")?.1)?;
            base["proxy"] = src["proxy_vm"].clone();
            base["job"] = json!(job.id);
            // ponytail: a failed step ends the job, so the VMs after a failed one wait for the next run; the next
            // proxy-prepare removes what an aborted run left (snapshot, hot-added disks)
            for (i, uuid) in vms.iter().enumerate() {
                let work = plan.dir.join(format!("vm-{i}"));
                let name = format!("vmware-{i}.json");
                let mut cfg = base.clone();
                cfg["vms"] = json!([uuid]);
                cfg["work_dir"] = json!(work);
                plan.files.push((name.clone(), serde_json::to_vec_pretty(&cfg)?));
                let vmw = |cmd: &str| Step::Cli {
                    bin: self.cfg.vmware_bin.clone(),
                    args: vec![plan.dir.join(&name).to_string_lossy().into_owned(), cmd.into()],
                    alert: None,
                    capture: false,
                };
                let extra = json!({"block_read": {"plan": work.join("plan.json"), "out_dir": work}});
                let file = (
                    format!("agent-{}-{i}.json", a.id),
                    serde_json::to_vec_pretty(&self.agentctl_base(&plan.tenant, job, Some(&a), extra))?,
                );
                let read = Step::Cli {
                    bin: self.cfg.agentctl_bin.clone(),
                    args: vec![
                        plan.dir.join(&file.0).to_string_lossy().into_owned(),
                        "block-read".into(),
                    ],
                    alert: None,
                    capture: false,
                };
                plan.files.push(file);
                plan.steps.extend([vmw("proxy-prepare"), read, vmw("proxy-finish")]);
            }
            return Ok(plan);
        }
        plan.steps.push(Step::Cli {
            bin: self.cfg.vmware_bin.clone(),
            args: vec![
                plan.dir.join("vmware.json").to_string_lossy().into_owned(),
                "backup".into(),
            ],
            alert: None,
            capture: false,
        });
        Ok(plan)
    }

    /// nexus-nas config (docs/nas-connector.md); the SMB password / keytab go
    /// into 0600 files in the job dir (the connector hands them to the mount
    /// helper, which gives the password to the kernel as one mount parameter).
    fn share_config(&self, tenant: &str, source_id: i64, dir: &Path) -> Result<Files> {
        let kind: String = self
            .db
            .conn()
            .query_row(
                "SELECT kind FROM sources WHERE id=?1 AND tenant=?2",
                params![source_id, tenant],
                |r| r.get(0),
            )
            .optional()?
            .with_context(|| format!("source {source_id} not found in tenant {tenant}"))?;
        if kind != "nfs" && kind != "smb" {
            bail!("source {source_id} is not a share source");
        }
        let src = self.source_of(tenant, source_id, &kind)?;
        let mut files: Files = Vec::new();
        let mut share = json!({
            "kind": kind,
            "host": src["host"].as_str().with_context(|| format!("source {source_id}: missing host"))?,
            "sign": src["sign"].as_bool().unwrap_or(true),
            "seal": src["seal"].as_bool().unwrap_or(false),
            "timeout_secs": src["timeout_secs"].as_u64().unwrap_or(60),
        });
        for k in [
            "port",
            "version",
            "export",
            "mount_port",
            "share",
            "user",
            "domain",
            "sec",
            "principal",
        ] {
            if !src[k].is_null() {
                share[k] = src[k].clone();
            }
        }
        if let Some(p) = src["password"].as_str() {
            files.push(("smb-password".into(), p.as_bytes().to_vec()));
            share["password_file"] = json!(dir.join("smb-password"));
        }
        if let Some(k) = src["keytab"].as_str() {
            use base64::Engine;
            let raw = base64::engine::general_purpose::STANDARD
                .decode(k)
                .with_context(|| format!("source {source_id}: keytab is not base64"))?;
            files.push(("smb.keytab".into(), raw));
            share["keytab_file"] = json!(dir.join("smb.keytab"));
        }
        let mut cfg = json!({
            "tenant": tenant,
            "store": self.cfg.store_base.join(tenant),
            "keyd_socket": self.cfg.keyd_socket,
            "source_id": source_id,
            "mount_socket": self.cfg.nas_mount_socket,
            "share": share,
            "excludes": src["excludes"].as_array().cloned().unwrap_or_default(),
            "threads": src["threads"].as_u64().unwrap_or(16),
            "xattrs": src["xattrs"].as_bool().unwrap_or(true),
        });
        for k in ["snapshot_dir", "snapshot_prefix", "snapshot_order"] {
            if src[k].is_string() {
                cfg[k] = src[k].clone();
            }
        }
        if src["read_limit"].is_object() {
            cfg["read_limit"] = src["read_limit"].clone(); // Phase 22b
        }
        files.push(("nas.json".into(), serde_json::to_vec_pretty(&cfg)?));
        Ok(files)
    }

    /// Backup of an NFS/SMB share (one nexus-nas run; exclusive per source).
    fn plan_share_backup(&self, mut plan: Plan, source_id: i64, policy_filters: &Value) -> Result<Plan> {
        plan.key = format!("source:{source_id}");
        plan.files = self.share_config(&plan.tenant, source_id, &plan.dir)?;
        // filters only (no secrets): the plain stored config is enough
        let src: String = self.db.conn().query_row(
            "SELECT config FROM sources WHERE id=?1 AND tenant=?2",
            params![source_id, plan.tenant],
            |r| r.get(0),
        )?;
        let src: Value = serde_json::from_str(&src).unwrap_or_default();
        selection::patch_share_config(&mut plan.files, &src, policy_filters)?;
        plan.steps.push(Step::Cli {
            bin: self.cfg.nas_bin.clone(),
            args: vec![
                plan.dir.join("nas.json").to_string_lossy().into_owned(),
                "backup".into(),
            ],
            alert: None,
            capture: false,
        });
        Ok(plan)
    }

    fn offsite_cfg(&self, tenant: &str) -> Result<Option<Value>> {
        self.offsite_cfg_n(tenant, 1)
    }

    /// Offsite target `n` of a tenant (Phase 30: 1 = `tenants.offsite`, 2 = its
    /// `second`), secrets opened; `None` without a remote.
    pub(crate) fn offsite_cfg_n(&self, tenant: &str, n: u8) -> Result<Option<Value>> {
        let o: Option<String> = self
            .db
            .conn()
            .query_row("SELECT offsite FROM tenants WHERE name=?1", [tenant], |r| r.get(0))
            .optional()?;
        let mut v: Value = o.map(|s| serde_json::from_str(&s)).transpose()?.unwrap_or(Value::Null);
        self.secrets
            .open_all(&tenant_owner(tenant), &mut v)
            .with_context(|| format!("offsite config of tenant {tenant}"))?;
        Ok(offsite_target(&v, n))
    }

    /// The configured offsite targets of a tenant (1, and 2 when there is a second).
    fn offsite_targets(&self, tenant: &str) -> Result<Vec<u8>> {
        Ok([1u8, 2]
            .into_iter()
            .filter(|n| matches!(self.offsite_cfg_n(tenant, *n), Ok(Some(_))))
            .collect())
    }

    /// Phase 30: the retention of offsite target `o`: per class the larger of its
    /// own `gfs` and the policies' (offsite retention is never shorter than local).
    fn offsite_gfs_of(&self, tenant: &str, o: &Value) -> Result<Gfs> {
        let mut g = self.offsite_gfs(tenant)?;
        let own = |k: &str| o["gfs"][k].as_u64().map(|n| n.min(u32::MAX as u64) as u32).unwrap_or(0);
        g.daily = g.daily.max(own("daily"));
        g.weekly = g.weekly.max(own("weekly"));
        g.monthly = g.monthly.max(own("monthly"));
        g.yearly = g.yearly.max(own("yearly"));
        Ok(g)
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
                recent: 0, // offsite copies keep the period classes only
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
        // replicated tenants get the primary's DEKs (keyd import-sealed), never a local one;
        // after a configuration restore the offsite escrow's (config_backup.rs)
        let replicated = self.replicated_tenants()?;
        let restoring = self.rekey_pending()?;
        for t in tenants {
            if self.keyed.contains(&t) || replicated.contains_key(&t) || restoring.contains(&t) {
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
        crate::tenant_key::sync(&self.db, &self.cfg.keyd_socket, tenant);
        let Ok(files) = keyd::fetch_escrow(&self.cfg.keyd_socket, tenant) else {
            return; // tests / keyd down: nexus-offsite reports a missing escrow dir itself
        };
        let dir = self.cfg.escrow_base.join(tenant);
        crate::tenant_key::prune_escrow_dir(&dir, tenant, &files);
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
        self.offsite_config_n(tenant, dir, 1)
    }

    /// Job files of offsite target `n` (`offsite.json`, or `offsite2.json` and
    /// its own secret files for the second target).
    fn offsite_config_n(&self, tenant: &str, dir: &Path, n: u8) -> Result<Option<Files>> {
        let Some(o) = self.offsite_cfg_n(tenant, n)? else {
            return Ok(None);
        };
        self.refresh_escrow(tenant);
        self.offsite_files(tenant, &o, dir, n).map(Some)
    }

    /// Job dir files for nexus-offsite from an opened offsite config `o` of target `n`.
    fn offsite_files(&self, tenant: &str, o: &Value, dir: &Path, n: u8) -> Result<Files> {
        let pfx = offsite_prefix(n);
        let mut files = Vec::new();
        let mut remote = o["remote"].clone();
        if let Some(k) = remote["key_pem"].as_str() {
            let mut k = k.to_owned();
            if !k.ends_with('\n') {
                k.push('\n');
            }
            files.push((format!("{pfx}.key"), k.into_bytes()));
            remote["key_file"] = json!(dir.join(format!("{pfx}.key")));
            remote.as_object_mut().unwrap().remove("key_pem");
        }
        if remote["type"] == "s3" {
            let r = remote.as_object_mut().unwrap();
            if let Some(Value::String(k)) = r.remove("secret_key") {
                files.push((format!("{pfx}-s3.secret"), k.into_bytes()));
                r.insert("secret_key_file".into(), json!(dir.join(format!("{pfx}-s3.secret"))));
            }
            if let Some(Value::String(ca)) = r.remove("ca_pem") {
                files.push((format!("{pfx}-ca.pem"), ca.into_bytes()));
                r.insert("ca_file".into(), json!(dir.join(format!("{pfx}-ca.pem"))));
            }
        }
        let g = self.offsite_gfs_of(tenant, o)?;
        // the second target keeps its own upload state (packs present on that target)
        let state = match n {
            1 => self.cfg.offsite_state_base.join(tenant),
            _ => self.cfg.offsite_state_base.join(".second").join(tenant),
        };
        let mut cfg = json!({
            "store": self.cfg.store_base.join(tenant),
            "tenant": tenant,
            "keyd_socket": self.cfg.keyd_socket,
            "escrow_dir": self.cfg.escrow_base.join(tenant),
            "state": state,
            "remote": remote,
            "gfs": {"daily": g.daily, "weekly": g.weekly, "monthly": g.monthly, "yearly": g.yearly},
            "held": catalog::holds::held(&self.db.conn(), tenant)?,
        });
        for k in ["uploaders", "bwlimit"] {
            if let Some(n) = o[k].as_u64() {
                cfg[k] = n.into();
            }
        }
        // bandwidth windows (Phase 17a): nexus-offsite follows them while uploading
        for k in ["windows", "timezone"] {
            if !o[k].is_null() {
                cfg[k] = o[k].clone();
            }
        }
        files.push((format!("{pfx}.json"), serde_json::to_vec_pretty(&cfg)?));
        Ok(files)
    }

    fn agent(&self, tenant: &str, id: &str) -> Result<AgentRow> {
        if !valid_agent_id(id) {
            bail!("invalid agent id {id:?}");
        }
        let a = self
            .db
            .conn()
            .query_row(
                "SELECT id, tenant, name, host, port, cert_sha256, token_hash, token_expires, cert_sha256_next, limits \
                 FROM agents WHERE id=?1",
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
                        cert_sha256_next: r.get(8)?,
                        limits: serde_json::from_str(&r.get::<_, String>(9)?).unwrap_or_default(),
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
            cfg["agent"] = json!({"id": a.id, "name": a.name, "host": a.host, "port": a.port,
                                  "cert_sha256": a.cert_sha256, "cert_sha256_next": a.cert_sha256_next});
            // roaming agent: direct first, then through its edge proxy (edge.rs)
            if let Ok(Some(e)) = self.agent_edge_route(&a.id) {
                cfg["agent"]["edge"] = e;
            }
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
    fn plan_agent_backups(
        &self,
        job: &Job,
        mut plan: Plan,
        source_id: i64,
        agents: &[String],
        policy_filters: &Value,
    ) -> Result<Plan> {
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
            let (excludes, filters) = selection::agent_filters(&src, policy_filters);
            let backup = json!({"paths": src["paths"], "excludes": excludes,
                                "hooks": src["hooks"].as_bool().unwrap_or(false),
                                "filters": filters, "limits": selection::agent_limits(&a.limits)});
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
        self.check_restore_guard(job)?; // freeze.rs (Phase 29)
        let mut plan = self.plan_job(job)?;
        self.patch_file_hashes(job, &mut plan)?;
        self.patch_full_read(job, &mut plan)?; // fullread.rs
        self.patch_freeze(job, &mut plan)?; // freeze.rs
        Ok(plan)
    }

    /// Phase 28: a backup of a group with `file_hashes` (or of an agent in such a
    /// group) tells its connector to record file hashes.
    fn patch_file_hashes(&self, job: &Job, plan: &mut Plan) -> Result<()> {
        if job.kind != "backup" {
            return Ok(());
        }
        let p = &job.params;
        let on = self.groups()?.into_iter().any(|g| {
            g.tenant == job.tenant
                && g.file_hashes
                && (p["group_id"].as_i64() == Some(g.id)
                    || (p["group_id"].is_null()
                        && p["agent_id"].as_str().is_some_and(|a| g.agents.iter().any(|x| x == a))))
        });
        if !on {
            return Ok(());
        }
        for (name, body) in plan.files.iter_mut().filter(|(n, _)| n.ends_with(".json")) {
            let mut cfg: Value = serde_json::from_slice(body)?;
            if cfg["backup"].is_object() {
                cfg["backup"]["file_hashes"] = json!(true); // nexus-agentctl
            } else if ["nas.json", "truenas.json", "plugin.json"].contains(&name.as_str()) {
                cfg["file_hashes"] = json!(true);
            } else {
                continue;
            }
            *body = serde_json::to_vec_pretty(&cfg)?;
        }
        Ok(())
    }

    fn plan_job(&self, job: &Job) -> Result<Plan> {
        Self::check_scanned(job)?; // scan.rs
        if let Some(plan) = self.plan_config(job)? {
            return Ok(plan); // config_backup.rs
        }
        if self.rekey_pending()?.contains(&job.tenant) {
            bail!(
                "the keys of tenant {} are still being restored from its offsite copy after the configuration restore",
                job.tenant
            );
        }
        if let Some(plan) = self.plan_appliance(job)? {
            return Ok(plan);
        }
        // appliance-wide (tenant "-"), no store: before the tenant checks below
        if job.kind == "edge_enroll" {
            let plan = Plan {
                key: "edge".into(),
                tenant: job.tenant.clone(),
                store: self.cfg.store_base.clone(),
                dir: self.job_dir(job.id),
                files: Vec::new(),
                steps: Vec::new(),
                download: None,
                held: Default::default(),
            };
            return self.plan_edge_enroll(job, plan); // edge.rs
        }
        let tenant = job.tenant.as_str();
        if !valid_name(tenant) {
            bail!("invalid tenant {tenant:?}");
        }
        // replicated tenants (docs/replication.md §7): no local backups, and nothing
        // that opens the store before the primary's DEKs were imported (keyd
        // `ensure` would create a local DEK and block the import)
        self.refuse_disabled(tenant, &job.kind)?;
        self.refuse_locked(job)?; // threat.rs
        let replicated = self.replicated_tenants()?.contains_key(tenant);
        if replicated && job.kind == "backup" {
            bail!("tenant {tenant} is replicated from a primary: no local backups");
        }
        if replicated
            && !job.kind.starts_with("replica_")
            && !self.cfg.store_base.join(tenant).join("keycheck").exists()
        {
            bail!("tenant {tenant} is replicated from a primary and has no replicated data yet");
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
        // nexus-offsite on target `n` (Phase 30: `offsite2.json` for the second)
        let offsite_n = |n: u8, args: &[&str], alert: Option<&'static str>| Step::Cli {
            bin: self.cfg.offsite_bin.clone(),
            args: std::iter::once(
                dir.join(format!("{}.json", offsite_prefix(n)))
                    .to_string_lossy()
                    .into_owned(),
            )
            .chain(args.iter().map(std::string::ToString::to_string))
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
            held: catalog::holds::held(&self.db.conn(), tenant)?,
        };
        let group = |id: i64| -> Result<GroupRow> {
            self.groups()?
                .into_iter()
                .find(|g| g.id == id && g.tenant == tenant)
                .with_context(|| format!("group {id} not found in tenant {tenant}"))
        };
        if job.kind == "file_search" || job.kind == "file_index" {
            return self.plan_files_index(job, plan);
        }
        if job.kind == "hash_hunt" {
            return self.plan_hunt(job, plan); // threat.rs
        }
        match job.kind.as_str() {
            "bmr" => return self.plan_bmr(job, plan), // bmr.rs
            "p2v" => return self.plan_p2v(job, plan),
            _ => {}
        }
        if job.kind == "file_changes" || job.kind == "snapshot_diff" {
            return self.plan_changes(job, plan); // changes.rs
        }
        if job.kind == "snapshot_scan" {
            return self.plan_scan(job, plan); // scan.rs
        }
        if job.kind.starts_with("offsite_") {
            return self.plan_offsite_ui(job, plan); // offsite_ui.rs
        }
        if job.kind == "chunk_repair" {
            return self.plan_chunk_repair(plan); // repair.rs
        }
        if job.kind == "retention"
            && (p["plugin"] == true || p["source"].as_str().is_some_and(|s| s.starts_with("plugin-")))
        {
            return self.plan_plugin_retention(job, plan);
        }
        match job.kind.as_str() {
            "backup" => {
                let (source_id, vmids, group_row) = match (p["group_id"].as_i64(), p["agent_id"].as_str()) {
                    (Some(g), _) => {
                        let g = runctl::restrict(group(g)?, p);
                        if !g.datasets.is_empty() {
                            return self.plan_truenas_backup(plan, g.source_id, &g.datasets);
                        }
                        if g.vmware {
                            return self.plan_vmware_backup(job, plan, g.source_id, &g.vms);
                        }
                        if g.share {
                            return self.plan_share_backup(plan, g.source_id, &g.file_filters);
                        }
                        if let Some((_, guests)) = &g.plugin {
                            if g.auto && guests.is_empty() {
                                bail!("nothing to back up: no guests match the group (inventory)");
                            }
                            let guests = guests.clone();
                            return self.plan_plugin_backup(job, plan, g.source_id, &guests, g.parallel);
                        }
                        if !g.agents.is_empty() {
                            return self.plan_agent_backups(job, plan, g.source_id, &g.agents, &g.file_filters);
                        }
                        (g.source_id, g.guests.clone(), Some(g))
                    }
                    (None, Some(a)) => {
                        let (sid, _) = self.agent_source(tenant, a)?;
                        return self.plan_agent_backups(job, plan, sid, &[a.to_owned()], &Value::Null);
                    }
                    (None, None) => {
                        let v = u32::try_from(num(p, "vmid")?).context("vmid")?;
                        (self.resolve_source(job, Some(v))?, vec![v], None)
                    }
                };
                if vmids.is_empty() {
                    bail!("nothing to back up: no guests");
                }
                // Phase 32: per group (or guest), not per source: groups of one cluster run at once;
                // nexus-pve's lock files keep one backup per node and per guest across them
                plan.key = match &group_row {
                    Some(g) => format!("group:{}", g.id),
                    None => format!("guest:{tenant}/vm-{}", vmids[0]),
                };
                plan.files = self.pve_config(tenant, source_id, &dir, &vmids)?;
                if let Some(g) = &group_row {
                    // exclude_disks, restore mode, parallel guests (selection.rs)
                    if let Some((_, body)) = plan.files.iter_mut().find(|(n, _)| n == "pve.json") {
                        let mut cfg: Value = serde_json::from_slice(body)?;
                        if let (Some(c), Some(o)) = (cfg.as_object_mut(), selection::pve_options(g, &vmids).as_object())
                        {
                            c.extend(o.clone());
                        }
                        *body = serde_json::to_vec_pretty(&cfg)?;
                    }
                }
                plan.steps.push(pve(vec!["backup-all".into()]));
            }
            "retention" if p["group_id"].is_null() && p["vmid"].is_null() && p["source"].is_null() => {
                // manual retention for the whole tenant: every group with its own GFS
                for g in self.groups()?.into_iter().filter(|g| g.tenant == tenant) {
                    let (sources, prefixes) = (group_sources(&g), group_prefixes(&g));
                    plan.steps.push(Step::Retention {
                        sources,
                        prefixes,
                        gfs: g.gfs,
                    });
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
                    prefixes: Vec::new(),
                    gfs,
                });
            }
            "retention" if p["source"].as_str().is_some_and(|s| s.starts_with("nas-")) => {
                let source = ident(p, "source")?;
                let (sid, ds) =
                    truenas::parse_source_name(source).with_context(|| format!("invalid source {source:?}"))?;
                // GFS of the group that backs up this dataset (or an ancestor of it)
                let gfs = self
                    .groups()?
                    .into_iter()
                    .find(|g| {
                        g.tenant == tenant
                            && g.source_id as u64 == sid
                            && g.datasets.iter().any(|d| truenas::under(&ds, d))
                    })
                    .map_or_else(Gfs::default, |g| g.gfs);
                plan.key = format!("source:{sid}");
                plan.steps.push(Step::Retention {
                    sources: vec![source.to_owned()],
                    prefixes: Vec::new(),
                    gfs,
                });
            }
            "plugin_validate" | "plugin_guests" | "plugin_backup" | "plugin_restore" | "plugin_mount" => {
                return self.plan_plugin(job, plan);
            }
            "files_list" | "files_get" if p["source"].as_str().is_some_and(|s| s.starts_with("plugin-")) => {
                return self.plan_plugin(job, plan);
            }
            "retention"
                if p["source"]
                    .as_str()
                    .is_some_and(|s| s.starts_with(vmware::names::SOURCE_PREFIX)) =>
            {
                let source = ident(p, "source")?;
                let uuid =
                    vmware::names::parse_source_name(source).with_context(|| format!("invalid source {source:?}"))?;
                let g = self
                    .groups()?
                    .into_iter()
                    .find(|g| g.tenant == tenant && g.vms.iter().any(|u| u == uuid));
                plan.key = match &g {
                    Some(g) => format!("source:{}", g.source_id),
                    None => format!("vmware:{uuid}"),
                };
                plan.steps.push(Step::Retention {
                    sources: vec![source.to_owned()],
                    prefixes: Vec::new(),
                    gfs: g.map_or_else(Gfs::default, |g| g.gfs),
                });
            }
            "retention" if p["source"].as_str().is_some_and(|s| s.starts_with("share-")) => {
                let source = ident(p, "source")?;
                let sid = nas::parse_source_name(source).with_context(|| format!("invalid source {source:?}"))?;
                let gfs = self
                    .groups()?
                    .into_iter()
                    .find(|g| g.tenant == tenant && g.share && g.source_id as u64 == sid)
                    .map_or_else(Gfs::default, |g| g.gfs);
                plan.key = format!("source:{sid}");
                plan.steps.push(Step::Retention {
                    sources: vec![source.to_owned()],
                    prefixes: Vec::new(),
                    gfs,
                });
            }
            "retention" => {
                let (_source_id, vmids, gfs) = match p["group_id"].as_i64() {
                    Some(g) => {
                        let g = group(g)?;
                        if !g.agents.is_empty() || !g.datasets.is_empty() || g.share || g.vmware || g.plugin.is_some() {
                            plan.key = format!("source:{}", g.source_id);
                            plan.steps.push(Step::Retention {
                                sources: group_sources(&g),
                                prefixes: group_prefixes(&g),
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
                // like the PVE backup (Phase 32): after its own group's backup, beside other groups
                plan.key = match p["group_id"].as_i64() {
                    Some(g) => format!("group:{g}"),
                    None => format!("guest:{tenant}/vm-{}", vmids.first().copied().unwrap_or_default()),
                };
                let sources = vmids
                    .iter()
                    .flat_map(|v| [format!("vm-{v}"), format!("ct-{v}")])
                    .collect();
                plan.steps.push(Step::Retention {
                    sources,
                    prefixes: Vec::new(),
                    gfs,
                });
            }
            "offsite" => {
                // Phase 30: `target` 2 = the second offsite target (own state, own retention)
                let n = offsite_job_target(p);
                plan.files = self
                    .offsite_config_n(tenant, &dir, n)?
                    .with_context(|| format!("tenant has no offsite target {n}"))?;
                let cfg = dir.join(format!("{}.json", offsite_prefix(n)));
                let step = |args: &[&str], alert: Option<&'static str>| Step::Cli {
                    bin: self.cfg.offsite_bin.clone(),
                    args: std::iter::once(cfg.to_string_lossy().into_owned())
                        .chain(args.iter().map(std::string::ToString::to_string))
                        .collect(),
                    alert,
                    capture: false,
                };
                plan.steps.push(step(&["upload"], None));
                plan.steps.push(step(&["check"], Some("inventory")));
                plan.steps.push(step(&["retention"], None));
            }
            "gc" => {
                // quorum-approved, or confirmed by one admin while approvals are disabled
                // (only honoured while they still are)
                let confirmed = p["confirmed_by"].is_string() && !catalog::approvals_enabled(&self.db.conn())?;
                // orphaned sources first, so this GC reclaims their chunks
                plan.steps.extend(self.orphan_step(tenant)?);
                plan.steps.push(Step::Gc {
                    approved: p["approved"].as_bool() == Some(true) && (p["quorum_id"].is_i64() || confirmed),
                });
                for n in self.offsite_targets(tenant)? {
                    if let Some(f) = self.offsite_config_n(tenant, &dir, n)? {
                        plan.files.extend(f);
                        plan.steps.push(offsite_n(n, &["gc"], None));
                    }
                }
            }
            "snapshot_delete" => {
                let source = ident(p, "source")?;
                plan.steps.push(Step::Delete {
                    source: source.to_owned(),
                    time: num(p, "time")?,
                });
            }
            "verify" => {
                let parts = self.cfg.verify_parts.max(1);
                plan.steps.push(Step::Verify {
                    part: (catalog::now() / 86400) as u64 % parts,
                    parts,
                });
                for n in self.offsite_targets(tenant)? {
                    if let Some(f) = self.offsite_config_n(tenant, &dir, n)? {
                        plan.files.extend(f);
                        plan.steps.push(offsite_n(n, &["verify", "3"], Some("verify")));
                    }
                }
            }
            // a VMware VM snapshot restored as a Proxmox VE VM (#34): `source_id` is the target PVE cluster
            "restore"
                if p["source"]
                    .as_str()
                    .is_some_and(|s| s.starts_with(vmware::names::SOURCE_PREFIX)) =>
            {
                let source = ident(p, "source")?;
                let uuid =
                    vmware::names::parse_source_name(source).with_context(|| format!("invalid source {source:?}"))?;
                let sid = p["source_id"]
                    .as_i64()
                    .context("restore of a VMware VM: source_id (the target Proxmox VE cluster) is required")?;
                self.source_of(tenant, sid, "pve")
                    .context("restore of a VMware VM: source_id must be a Proxmox VE source of the tenant")?;
                plan.key = format!("guest:{tenant}/{source}");
                plan.files = self.pve_config(tenant, sid, &dir, &[])?;
                let bridge = p["bridge"].as_str().unwrap_or("vmbr0");
                if !bridge
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
                    || bridge.len() > 32
                {
                    bail!("invalid bridge {bridge:?}");
                }
                let mut args = vec![
                    "restore-vmware".to_owned(),
                    uuid.to_owned(),
                    num(p, "time")?.to_string(),
                    ident(p, "node")?.to_owned(),
                    u32::try_from(num(p, "target")?).context("target")?.to_string(),
                    ident(p, "storage")?.to_owned(),
                    bridge.to_owned(),
                ];
                args.extend(restore_flags(job)?);
                plan.steps.push(pve(args));
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
                args.extend(restore_flags(job)?);
                plan.steps.push(pve(args));
            }
            "restore_files" => return self.plan_restore_files(job, plan, replicated),
            "synthetic_restore" => return self.plan_synthetic(job, plan), // synthetic.rs
            "instant_disk" => return self.plan_instant_disk(job, plan),   // restore.rs
            k if recovery::KINDS.contains(&k) => return self.plan_recovery(job, plan),
            "fleet_scan" => return self.plan_fleet_scan(job, plan),
            "agent_renew" => {
                let a = self.agent(tenant, p["agent_id"].as_str().unwrap_or_default())?;
                if a.cert_sha256.is_none() {
                    bail!("agent {} ({}) is not enrolled", a.name, a.id);
                }
                plan.key = format!("agent:{}", a.id);
                let (f, step) = self.agentctl(&dir, job, &a, "renew", json!({}))?;
                plan.files.push(f);
                plan.steps.push(step);
            }
            "agent_update" => {
                let a = self.agent(tenant, p["agent_id"].as_str().unwrap_or_default())?;
                plan.key = format!("agent:{}", a.id);
                let cfg = self.agent_update_config(p)?; // agent_updates.rs
                let (f, step) = self.agentctl(&dir, job, &a, "update", cfg)?;
                plan.files.push(f);
                plan.steps.push(step);
            }
            "agent_enroll" => {
                let a = self.agent(tenant, p["agent_id"].as_str().unwrap_or_default())?;
                plan.key = format!("agent:{}", a.id);
                let digest = if p["fleet_id"].is_string() {
                    // accepted from a fleet scan: the fleet secret proves it (crate::fleet)
                    self.fleet_enroll_digest(job, &a)?
                } else {
                    let sealed = a
                        .token_hash
                        .as_deref()
                        .context("agent has no enrollment token (create a new token first)")?;
                    if a.token_expires.is_none_or(|e| e <= catalog::now()) {
                        bail!("the enrollment token of agent {} expired (create a new token)", a.name);
                    }
                    self.secrets
                        .open(&catalog::secret::agent_token_location(&a.id, &a.host, a.port), sealed)
                        .with_context(|| format!("agent {}", a.id))?
                };
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
            "files_list" | "files_get" if p["source"].as_str().is_some_and(|s| s.starts_with("nas-")) => {
                let source = ident(p, "source")?;
                let (sid, _) =
                    truenas::parse_source_name(source).with_context(|| format!("invalid source {source:?}"))?;
                plan.key = format!("guest:{tenant}/{source}");
                // download only from the store: no TrueNAS access, no secrets
                let cfg = json!({
                    "tenant": tenant,
                    "store": self.cfg.store_base.join(tenant),
                    "keyd_socket": self.cfg.keyd_socket,
                    "source_id": sid,
                });
                plan.files
                    .push(("truenas.json".into(), serde_json::to_vec_pretty(&cfg)?));
                let mut args = vec![
                    dir.join("truenas.json").to_string_lossy().into_owned(),
                    "files".into(),
                    source.to_owned(),
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
                    bin: self.cfg.truenas_bin.clone(),
                    args,
                    alert: None,
                    capture: true,
                });
            }
            "files_list" | "files_get" if p["source"].as_str().is_some_and(|s| s.starts_with("share-")) => {
                let source = ident(p, "source")?;
                let sid = nas::parse_source_name(source).with_context(|| format!("invalid source {source:?}"))?;
                plan.key = format!("guest:{tenant}/{source}");
                // download only from the store: no mount, no secrets
                let cfg = json!({
                    "tenant": tenant,
                    "store": self.cfg.store_base.join(tenant),
                    "keyd_socket": self.cfg.keyd_socket,
                    "source_id": sid,
                });
                plan.files.push(("nas.json".into(), serde_json::to_vec_pretty(&cfg)?));
                let mut args = vec![
                    dir.join("nas.json").to_string_lossy().into_owned(),
                    "files".into(),
                    source.to_owned(),
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
                    bin: self.cfg.nas_bin.clone(),
                    args,
                    alert: None,
                    capture: true,
                });
            }
            "files_list" | "files_get" => {
                let source = ident(p, "source")?;
                // VMware VM snapshots (#83): fixed disk images like a PVE VM's, read from the store only
                let vmw = vmware::names::parse_source_name(source).is_some();
                let (ct, vmid) = if vmw { (false, 0) } else { guest(source)? };
                plan.key = format!("guest:{tenant}/{source}");
                let resolved = if vmw {
                    Err(anyhow::anyhow!("VMware snapshot: no PVE source"))
                } else {
                    self.resolve_source(job, Some(vmid))
                };
                plan.files = match resolved {
                    Ok(sid) => self.pve_config(tenant, sid, &dir, &[])?,
                    // replicated VM/CT snapshots without a local PVE source: the
                    // file commands only read the store
                    Err(_) if replicated || vmw => {
                        let cfg = json!({"store": self.cfg.store_base.join(tenant), "tenant": tenant,
                                         "keyd_socket": self.cfg.keyd_socket});
                        vec![("pve.json".into(), serde_json::to_vec_pretty(&cfg)?)]
                    }
                    Err(e) => return Err(e),
                };
                let mut args = vec![
                    if ct { "ct-files" } else { "files" }.to_owned(),
                    if vmw { source.to_owned() } else { vmid.to_string() },
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
            "replica_enroll" | "replica_sync" => return self.plan_replica(job, plan),
            "inventory" => return self.plan_inventory(job, plan),
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
        // replicated tenants: the snapshots came from this replication source
        let origin = self.replicated_tenants()?.remove(tenant);
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
        // per offsite target (Phase 30): what it holds, `None` = unknown now (busy or unreachable)
        let busy = self.running.values().any(|k| k == &format!("tenant:{tenant}"));
        let mut listed: [Option<HashSet<(String, i64)>>; 2] = [None, None];
        for (i, n) in [1u8, 2].into_iter().enumerate() {
            listed[i] = if self.offsite_cfg_n(tenant, n)?.is_none() {
                Some(HashSet::new())
            } else if busy {
                None
            } else {
                match self.offsite_list_n(tenant, n) {
                    Ok(s) => Some(s),
                    Err(e) => {
                        eprintln!("<4>offsite list of tenant {tenant} (target {n}) failed: {e:#}");
                        None
                    }
                }
            };
        }
        let [offsite, offsite2] = listed;
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
            if let Some(o) = &offsite2 {
                tx.execute("UPDATE snapshots SET offsite2=0 WHERE tenant=?1", [tenant])?;
                for (s, t) in o {
                    tx.execute(
                        "INSERT INTO snapshots (tenant, source, time, local, offsite, offsite2) VALUES (?1,?2,?3,0,0,1) \
                         ON CONFLICT (tenant, source, time) DO UPDATE SET offsite2=1",
                        params![tenant, s, t],
                    )?;
                }
            }
            for ((s, t), (lock, size)) in &local {
                tx.execute(
                    "INSERT INTO snapshots (tenant, source, time, size, local, offsite, lock_until, origin) \
                     VALUES (?1,?2,?3,?4,1,0,?5,?7) \
                     ON CONFLICT (tenant, source, time) DO UPDATE SET local=1, lock_until=?5, size=COALESCE(?6, size), origin=?7",
                    params![tenant, s, t, size.unwrap_or(0), lock, size, origin],
                )?;
            }
            tx.execute(
                "DELETE FROM snapshots WHERE tenant=?1 AND local=0 AND offsite=0 AND offsite2=0",
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

    fn offsite_list_n(&self, tenant: &str, n: u8) -> Result<HashSet<(String, i64)>> {
        let dir = self.cfg.runtime_dir.join(format!("job-refresh-{tenant}"));
        let _ = fs::remove_dir_all(&dir);
        let files = self.offsite_config_n(tenant, &dir, n)?.context("no offsite target")?;
        run::write_private(&dir, &files)?;
        let log = Arc::new(std::sync::Mutex::new(run::BoundedLog::new(8192)));
        let r = run::run_cli(
            &self.cfg.offsite_bin,
            &[
                dir.join(format!("{}.json", offsite_prefix(n)))
                    .to_string_lossy()
                    .into_owned(),
                "list".into(),
            ],
            &log,
            true,
            None,
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
    /// Agent / share backups without a consistent view (user decision 2026-10-10):
    /// a missing snapshot alone warns ONCE per source (afterwards only the snapshot's
    /// `consistent` flag shows it); files that really changed while read warn every
    /// time (counted while the open alert is unacknowledged, a new alert after an ack).
    fn inconsistent_alerts(&self, job_id: i64, tenant: &str, log: &str) -> Result<()> {
        for l in log.lines().filter(|l| {
            l.starts_with("inconsistent host-")
                || l.starts_with("inconsistent share-")
                || l.starts_with("inconsistent plugin-")
        }) {
            let what = l.trim_start_matches("inconsistent ");
            let src = what.split('/').next().unwrap_or_default();
            let changed = changed_while_read(what);
            let (key, detail) = if src.starts_with("plugin-") {
                (
                    format!("{src}: not consistent"),
                    "the plugin reported no consistent view of its source; reported once per source".into(),
                )
            } else if changed > 0 {
                (
                    format!("{src}: files changed while read"),
                    format!("{changed} file(s) changed while read"),
                )
            } else {
                (
                    format!("{src}: no snapshot"),
                    "read without a snapshot (not crash-consistent); reported once per source".into(),
                )
            };
            if changed == 0 && self.ever_alerted("backup_inconsistent", &key)? {
                continue;
            }
            // changed files warn again once the open alert was acknowledged (user decision
            // 2026-10-10); with the 13f lifecycle that means closing the seen one first
            let akey = format!("backup_inconsistent:{key}");
            if changed > 0 {
                let seen: Option<i64> = self
                    .db
                    .conn()
                    .query_row(
                        "SELECT id FROM alerts WHERE key = ?1 AND resolved_at IS NULL AND acked_by IS NOT NULL",
                        [&akey],
                        |r| r.get(0),
                    )
                    .optional()?;
                if seen.is_some() {
                    self.resolve(&akey)?;
                }
            }
            self.alert(
                "warning",
                "backup_inconsistent",
                &format!("{key} — {detail} (backup job {job_id}, tenant {tenant}, snapshot {what})"),
                Some(&key),
            )?;
        }
        Ok(())
    }

    /// Any alert (acknowledged or not) of `kind` whose message starts with `prefix`.
    fn ever_alerted(&self, kind: &str, prefix: &str) -> Result<bool> {
        let n: i64 = self.db.conn().query_row(
            "SELECT COUNT(*) FROM alerts WHERE kind=?1 AND substr(message, 1, length(?2)) = ?2",
            params![kind, prefix],
            |r| r.get(0),
        )?;
        Ok(n > 0)
    }

    /// An alert without a resolving success path, keyed `kind:<dedupe or message>`
    /// (see [`Scheduler::raise`]).
    pub fn alert(&self, severity: &str, kind: &str, message: &str, dedupe: Option<&str>) -> Result<()> {
        self.raise(
            severity,
            kind,
            &format!("{kind}:{}", dedupe.unwrap_or(message)),
            message,
            None,
        )
    }

    /// Alert delivery: the catalog setting (web UI), else `/etc/nexus/alerts.json`.
    fn alerts_config(&self) -> Result<alerts::AlertsConfig> {
        alerts::AlertsConfig::current(&self.db, &self.secrets, &self.cfg.alerts_config)
    }

    // ------------------------------------------------------------ appliance jobs

    /// Jobs of no tenant (tenant `-`, queued by the web-api settings pages):
    /// `alert_test` {rule?}, `forward_test` {}, `report_send` {name, from, to}, `ssh_key_rotate` {name, quorum_id}, `ssh_key_retire` {name}.
    /// They run in-process; their stdout (a JSON object) becomes the result.
    fn plan_appliance(&self, job: &Job) -> Result<Option<Plan>> {
        let step: Box<dyn Fn() -> Result<String, String> + Send> = match job.kind.as_str() {
            "alert_test" => {
                let cfg = self.alerts_config()?;
                let host = self.host.clone();
                let rule = job.params["rule"].as_str().map(str::to_owned);
                Box::new(move || Ok(alerts::test(&cfg, &host, rule.as_deref()).to_string()))
            }
            "forward_test" => {
                let cfg = catalog::forwarding::Forwarding::load(&self.db.conn())?;
                let (key, host) = (self.secrets.clone(), self.host.clone());
                Box::new(move || Ok(forward::test(&cfg, &key, &host).to_string()))
            }
            "report_send" => self.report_step(job),
            "ssh_key_rotate" | "ssh_key_retire" => {
                let name = ident(&job.params, "name")?.to_owned();
                let dir = self.cfg.ssh_dir.clone();
                let rotate = job.kind == "ssh_key_rotate";
                Box::new(move || {
                    let r = if rotate {
                        sshkeys::rotate(&dir, &name).map(|fp| json!({"name": name, "next": fp}))
                    } else {
                        sshkeys::retire(&dir, &name).map(|(old, new)| json!({"name": name, "old": old, "new": new}))
                    };
                    r.map(|v| v.to_string()).map_err(|e| format!("{e:#}"))
                })
            }
            _ => return Ok(None),
        };
        Ok(Some(Plan {
            key: format!("appliance:{}", job.kind),
            tenant: job.tenant.clone(),
            store: PathBuf::new(),
            dir: self.job_dir(job.id),
            files: Vec::new(),
            steps: vec![Step::Func(run::InProc(step))],
            download: None,
            held: Default::default(),
        }))
    }

    /// Key files below `ssh_dir` the configuration uses: PVE node keys (`nodes.*.key`)
    /// and SFTP offsite keys (`remote.key_file`), with what uses them.
    fn used_ssh_keys(&self) -> Result<Vec<(String, String)>> {
        let mut used: BTreeMap<String, BTreeSet<&str>> = BTreeMap::new();
        let mut add = |path: Option<&str>, purpose: &'static str| {
            let Some(p) = path.map(Path::new) else { return };
            if p.parent() == Some(self.cfg.ssh_dir.as_path()) {
                if let Some(n) = p.file_name().and_then(|n| n.to_str()) {
                    used.entry(n.to_owned()).or_default().insert(purpose);
                }
            }
        };
        let pve: Vec<String> = {
            let c = self.db.conn();
            let mut st = c.prepare("SELECT config FROM sources WHERE kind='pve'")?;
            let rows = st.query_map([], |r| r.get(0))?;
            rows.collect::<std::result::Result<_, _>>()?
        };
        for cfg in pve {
            let v: Value = serde_json::from_str(&cfg).unwrap_or(Value::Null);
            let nodes: Vec<&Value> = match &v["nodes"] {
                Value::Object(m) => m.values().collect(),
                Value::Array(a) => a.iter().collect(),
                _ => Vec::new(),
            };
            for n in nodes {
                add(n["key"].as_str(), sshkeys::PURPOSE_PVE);
            }
        }
        for (_, o) in self.tenants()? {
            if o["remote"]["type"] == "sftp" {
                add(o["remote"]["key_file"].as_str(), sshkeys::PURPOSE_OFFSITE);
            }
        }
        Ok(used
            .into_iter()
            .map(|(n, p)| (n, p.into_iter().collect::<Vec<_>>().join("; ")))
            .collect())
    }

    /// Public halves of the keys in use into the catalog (`GET /ssh-keys`).
    fn publish_ssh_keys(&self) -> Result<()> {
        if !self.cfg.ssh_dir.is_dir() {
            return Ok(());
        }
        let used = self.used_ssh_keys()?;
        let names: Vec<String> = used.iter().map(|u| u.0.clone()).collect();
        sshkeys::ensure(&self.cfg.ssh_dir, &names)?;
        let v = sshkeys::list(&self.cfg.ssh_dir, &used).to_string();
        let c = self.db.conn();
        if catalog::setting(&c, sshkeys::SETTING)?.as_deref() != Some(v.as_str()) {
            catalog::set_setting(&c, sshkeys::SETTING, &v)?;
        }
        Ok(())
    }

    /// Approved `ssh_key.rotate` requests become `ssh_key_rotate` jobs. A request
    /// decided by its own requester (approvals were disabled) only while
    /// approvals are still disabled.
    fn queue_ssh_rotations(&mut self) -> Result<()> {
        let rows: Vec<(i64, String, String, Option<String>)> = {
            let c = self.db.conn();
            let mut st = c.prepare(
                "SELECT q.id, q.params, q.requested_by, q.decided_by FROM quorum q \
                 WHERE q.action='ssh_key.rotate' AND q.state='approved' \
                 AND NOT EXISTS (SELECT 1 FROM jobs j WHERE j.kind='ssh_key_rotate' AND json_extract(j.params,'$.quorum_id')=q.id)",
            )?;
            let rows = st.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?;
            rows.collect::<std::result::Result<_, _>>()?
        };
        for (id, p, by, decided) in rows {
            if decided.as_deref() == Some(by.as_str()) && catalog::approvals_enabled(&self.db.conn())? {
                continue;
            }
            let p: Value = serde_json::from_str(&p).unwrap_or(Value::Null);
            let Some(name) = p["name"].as_str() else { continue };
            self.insert_job("ssh_key_rotate", "-", &json!({"name": name, "quorum_id": id}))?;
        }
        Ok(())
    }

    /// Daily capacity sample per tenant (catalog v10 `capacity_samples`, the
    /// dashboard's growth chart and forecast): physical = bytes in the tenant's
    /// store, logical = sizes of its local snapshots. Plus the store file
    /// system's total / used / free (setting `capacity`).
    fn sample_capacity(&self, now: i64) -> Result<()> {
        let path = std::ffi::CString::new(self.cfg.store_base.as_os_str().as_encoded_bytes())?;
        // SAFETY: libc::statvfs is plain C data (integers only); all-zero is a valid value for the out buffer.
        let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
        // SAFETY: `path` is a NUL-terminated CString alive across the call and `st` a valid, exclusive out buffer.
        if unsafe { libc::statvfs(path.as_ptr(), &mut st) } == 0 && st.f_blocks > 0 {
            let f = st.f_frsize;
            let (total, free) = (st.f_blocks * f, st.f_bavail * f);
            let v = json!({"total": total, "used": total.saturating_sub(st.f_bfree * f), "free": free, "at": now});
            catalog::set_setting(&self.db.conn(), "capacity", &v.to_string())?;
        }
        let day = schedule::day(now);
        for (tenant, _) in self.tenants()? {
            let done: bool = self.db.conn().query_row(
                "SELECT COUNT(*) FROM capacity_samples WHERE day = ?1 AND tenant = ?2",
                params![day, tenant],
                |r| r.get::<_, i64>(0),
            )? > 0;
            let root = self.cfg.store_base.join(&tenant);
            if done || !valid_name(&tenant) || !root.is_dir() {
                continue;
            }
            let used = dir_bytes(&root);
            let c = self.db.conn();
            // offsite (Phase 23a usage export): logical size of the snapshots with an offsite copy
            let (logical, offsite): (i64, i64) = c.query_row(
                "SELECT COALESCE(SUM(CASE WHEN local = 1 THEN size END), 0),
                        COALESCE(SUM(CASE WHEN offsite = 1 THEN size END), 0) FROM snapshots WHERE tenant = ?1",
                [&tenant],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?;
            c.execute(
                "INSERT OR REPLACE INTO capacity_samples (day, tenant, used, logical, offsite) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![day, tenant, used as i64, logical, offsite],
            )?;
        }
        Ok(())
    }

    fn check_capacity(&self) -> Result<()> {
        let path = std::ffi::CString::new(self.cfg.store_base.as_os_str().as_encoded_bytes())?;
        // SAFETY: libc::statvfs is plain C data (integers only); all-zero is a valid value for the out buffer.
        let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
        // SAFETY: `path` is a NUL-terminated CString alive across the call and `st` a valid, exclusive out buffer.
        if unsafe { libc::statvfs(path.as_ptr(), &mut st) } != 0 || st.f_blocks == 0 {
            return Ok(());
        }
        let used = 1.0 - st.f_bavail as f64 / st.f_blocks as f64;
        if used > self.cfg.capacity_threshold {
            let pfx = format!("store capacity above {:.0} %", self.cfg.capacity_threshold * 100.0);
            self.raise(
                "warning",
                "capacity",
                "capacity",
                &format!("{pfx} (now {:.0} %)", used * 100.0),
                None,
            )?;
        } else {
            self.resolve("capacity")?;
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
            // Phase 30: per offsite target (the second: key `offsite_lag:<tenant>:2`)
            for (n, col) in [(1u8, "offsite"), (2, "offsite2")] {
                let key = if n == 1 {
                    format!("offsite_lag:{tenant}")
                } else {
                    format!("offsite_lag:{tenant}:2")
                };
                if self.offsite_cfg_n(&tenant, n)?.is_none() {
                    self.resolve(&key)?;
                    continue;
                }
                let oldest: Option<i64> = {
                    let c = self.db.conn();
                    let mut st = c.prepare(&format!(
                        "SELECT source, time FROM snapshots WHERE tenant=?1 AND local=1 AND {col}=0"
                    ))?;
                    let rows = st.query_map([&tenant], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))?;
                    rows.filter_map(std::result::Result::ok)
                        .filter(|(s, _)| sources.contains(s))
                        .map(|(_, t)| t)
                        .min()
                };
                let which = if n == 1 { "offsite copy" } else { "second offsite copy" };
                if let Some(t) = oldest.filter(|t| now - t > self.cfg.offsite_lag_secs) {
                    self.raise(
                        "warning",
                        "offsite_lag",
                        &key,
                        &format!(
                            "{which} of tenant {tenant} lags by {} h (oldest snapshot not there: {t})",
                            (now - t) / 3600
                        ),
                        Some(&tenant),
                    )?;
                } else {
                    self.resolve(&key)?;
                }
            }
        }
        Ok(())
    }

    // ------------------------------------------------------------ downloads

    fn expire_downloads(&self, now: i64) -> Result<()> {
        for e in fs::read_dir(&self.cfg.downloads)? {
            let e = e?;
            let m = e.metadata()?;
            if now - m.mtime() <= self.cfg.download_ttl_secs {
                continue;
            }
            if m.is_file() {
                fs::remove_file(e.path())?;
            } else if m.is_dir() && e.file_name().to_string_lossy().ends_with(".d") {
                // staging dir of an export (nexus-pluginhost export) left by a crash
                fs::remove_dir_all(e.path())?;
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
    /// Client key + certificate of one replication source (nexus-replica only).
    pub fn replica_cred_dir(&self, id: i64) -> PathBuf {
        self.replica_dir
            .clone()
            .unwrap_or_else(|| self.state_dir.join("replica"))
            .join(id.to_string())
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

/// Phase 30: offsite target `n` of a tenant's offsite config (1 = the config
/// itself without its `second`, 2 = the `second`), `None` without a remote.
fn offsite_target(v: &Value, n: u8) -> Option<Value> {
    let mut t = match n {
        1 => v.clone(),
        _ => v.get("second")?.clone(),
    };
    if let Some(o) = t.as_object_mut() {
        o.remove("second");
    }
    t["remote"].is_object().then_some(t)
}

/// Job file name prefix of offsite target `n`.
pub(crate) fn offsite_prefix(n: u8) -> &'static str {
    if n == 2 {
        "offsite2"
    } else {
        "offsite"
    }
}

/// The offsite target an offsite job works on (`target`, default 1).
fn offsite_job_target(p: &Value) -> u8 {
    if p["target"].as_u64() == Some(2) {
        2
    } else {
        1
    }
}

#[cfg(test)]
mod tests;

/// "N files changed while read" from an `inconsistent …` line of nexus-agentctl / nexus-nas.
fn changed_while_read(line: &str) -> u64 {
    line.split(" files changed while read")
        .next()
        .and_then(|head| head.rsplit(|c: char| !c.is_ascii_digit()).next())
        .and_then(|n| n.parse().ok())
        .unwrap_or(0)
}

#[cfg(test)]
mod inconsistent_tests {
    #[test]
    fn parses_changed_count() {
        use super::changed_while_read as c;
        assert_eq!(
            c("host-a/17: consistent=false (3 files changed while read without a snapshot)"),
            3
        );
        assert_eq!(
            c("share-2/9: consistent=false (no snapshot; 0 files changed while read; 1 entries unreadable)"),
            0
        );
        assert_eq!(
            c("share-2/9: consistent=false (no snapshot; 12 files changed while read; 0 entries unreadable)"),
            12
        );
        assert_eq!(c("garbage"), 0);
    }
}
