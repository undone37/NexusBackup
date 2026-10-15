//! `nexus-agentctl <config.json> enroll | backup | restore | update | hello | renew | fleet-scan | poll |
//! edge-enroll | edge-link | rescue | layout <agent-id> <time> <out.json> |
//! files <agent-id> <time> ls <dir> | files <agent-id> <time> get <out.tar|out.zip> <path>...`
//!
//! Spawned by the scheduler with a generated 0600 config (docs/agent-protocol.md
//! "Appliance side"). Machine-readable lines on stdout (parsed from the job log):
//! `agent-info {json}` after every successful Hello, `enrolled {json}`,
//! `committed host-<id>/<time>`, `inconsistent host-<id>/<time>: …`,
//! `restore` reads any file-tree snapshot of the tenant (`restore.source`) or,
//! for VM/CT files, the tar `restore.tar` written by `nexus-pve` (then removed);
//! `restored {json}`; `fleet-agent {json}` per agent found by `fleet-scan`;
//! `files … ls` prints the JSON listing only.
//! `synthetic` (Phase 33) composes a synthetic restore from the scheduler's plan
//! (`synthetic.plan`) and writes it to `synthetic.out` (tar/zip) or restores it to
//! `agent` (`synthetic.restore`); progress on stderr, the result as the last
//! stdout line.

use agent_conn::backup::{self, Spec as BackupSpec};
use agent_conn::ca::Ca;
use agent_conn::edge::EdgeTarget;
use agent_conn::files::{self, Format};
use agent_conn::map::MapDb;
use agent_conn::restore::{self, parse_overwrite, Spec as RestoreSpec};
use agent_conn::tls::{session_config_pins, AgentInfo, Route, Session};
use agent_conn::{enroll, tarbridge, update, valid_agent_id};
use anyhow::{bail, Context, Result};
use chunkstore::{Options, Store};
use serde::Deserialize;
use serde_json::json;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    tenant: String,
    #[serde(default)]
    store: Option<PathBuf>,
    #[serde(default)]
    keyd_socket: Option<PathBuf>,
    ca_dir: PathBuf,
    /// catalog job id (protocol `job` field)
    #[serde(default)]
    job: u64,
    #[serde(default)]
    agent: Option<AgentCfg>,
    /// enroll: file with the token digest
    #[serde(default)]
    token_file: Option<PathBuf>,
    #[serde(default)]
    backup: Option<BackupCfg>,
    #[serde(default)]
    restore: Option<RestoreCfg>,
    #[serde(default)]
    update_dir: Option<PathBuf>,
    /// signed release from the release store (Phase 27, docs/agent-update-plan.md)
    #[serde(default)]
    update: Option<UpdateCfg>,
    /// bare-metal recovery onto the rescue agent `agent` (docs/bmr.md)
    #[serde(default)]
    rescue: Option<RescueCfg>,
    #[serde(default)]
    fleet: Option<FleetCfg>,
    #[serde(default = "timeout")]
    timeout_secs: u64,
    /// `poll`: the due agents (agent_conn::poll)
    #[serde(default)]
    poll: Option<PollCfg>,
    /// `edge-enroll` / `edge-link` (docs/edge.md)
    #[serde(default)]
    edge: Option<EdgeCfg>,
    /// Phase 33 synthetic restore
    #[serde(default)]
    synthetic: Option<SyntheticCfg>,
}

/// `synthetic`: the scheduler's plan and where it goes.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SyntheticCfg {
    plan: PathBuf,
    /// download (`.tar` / `.zip` in the downloads directory)
    #[serde(default)]
    out: Option<PathBuf>,
    /// or onto the agent of `agent`
    #[serde(default)]
    restore: Option<SyntheticRestoreCfg>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SyntheticRestoreCfg {
    target: String,
    overwrite: String,
    confirm: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PollCfg {
    agents: Vec<agent_conn::poll::Target>,
    #[serde(default = "concurrency")]
    concurrency: usize,
}

fn concurrency() -> usize {
    8
}

/// `fleet-scan`: the fleet id, the file with the fleet secret digest, the addresses
/// (expanded ranges) and the agent port.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FleetCfg {
    id: String,
    digest_file: PathBuf,
    port: u16,
    targets: Vec<String>,
    #[serde(default = "fleet_parallel")]
    parallel: usize,
    #[serde(default = "fleet_rate")]
    rate: u32,
    #[serde(default = "fleet_timeout")]
    timeout_secs: u64,
}

fn fleet_parallel() -> usize {
    8
}
fn fleet_rate() -> u32 {
    20
}
fn fleet_timeout() -> u64 {
    2
}

fn timeout() -> u64 {
    3600
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentCfg {
    id: String,
    /// display name (live progress label)
    #[serde(default)]
    name: Option<String>,
    host: String,
    port: u16,
    #[serde(default)]
    cert_sha256: Option<String>,
    /// a renewed certificate issued but not yet confirmed (accepted as well)
    #[serde(default)]
    cert_sha256_next: Option<String>,
    /// edge proxy of a roaming agent: tried when the direct connection fails
    #[serde(default)]
    edge: Option<EdgeTarget>,
}

/// `update` from the release store: the version to install (`rollback`: an approved
/// downgrade), the store directories and the pinned release keys.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UpdateCfg {
    version: String,
    #[serde(default)]
    rollback: bool,
    #[serde(default = "release_dirs")]
    dirs: Vec<PathBuf>,
    #[serde(default = "release_keys")]
    keys_dir: PathBuf,
    /// seconds to wait for the agent to come back (default by plan: 120 / 600)
    #[serde(default)]
    reconnect_secs: Option<u64>,
}

fn release_dirs() -> Vec<PathBuf> {
    vec![
        agent_core::releases::IMAGE_DIR.into(),
        agent_core::releases::UPLOAD_DIR.into(),
    ]
}
fn release_keys() -> PathBuf {
    agent_core::releases::KEYS_DIR.into()
}

/// `edge-enroll` / `edge-link`: the edge's control address, pin, token digest file
/// (enrollment) and what the link pushes.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EdgeCfg {
    id: String,
    #[serde(flatten)]
    target: EdgeTarget,
    #[serde(default)]
    token_file: Option<PathBuf>,
    #[serde(default)]
    link: Option<agent_conn::edge::LinkSpec>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BackupCfg {
    paths: Vec<String>,
    #[serde(default)]
    excludes: Vec<String>,
    #[serde(default)]
    hooks: bool,
    #[serde(default)]
    filters: agent_proto::Filters,
    #[serde(default)]
    limits: agent_proto::Limits,
    /// Phase 28: SHA-256 per file in the name index (group option `file_hashes`)
    #[serde(default)]
    file_hashes: bool,
    /// Phase 29: scheduled full read (set by the scheduler when due)
    #[serde(default)]
    full_read: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RestoreCfg {
    /// `host-<agent>`, `nas-…`, `share-…`, `plugin-…` (file trees), or `vm-…`/`ct-…` with `tar`
    source: String,
    time: u64,
    paths: Vec<String>,
    target: String,
    overwrite: String,
    confirm: String,
    /// VM/CT files: the selection as a tar, written by `nexus-pve … get` into the
    /// downloads directory (removed here when done)
    #[serde(default)]
    tar: Option<PathBuf>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RescueCfg {
    /// the original agent (`host-<id>` snapshot)
    source_agent: String,
    time: u64,
    #[serde(default)]
    reboot: bool,
}

/// Removes the staging tar of a VM/CT file restore on every exit path.
struct RemoveOnDrop(Option<PathBuf>);
impl Drop for RemoveOnDrop {
    fn drop(&mut self) {
        if let Some(p) = &self.0 {
            let _ = fs::remove_file(p);
        }
    }
}

impl Config {
    fn agent(&self) -> Result<&AgentCfg> {
        let a = self.agent.as_ref().context("config: agent missing")?;
        if !valid_agent_id(&a.id) {
            bail!("invalid agent id {:?}", a.id);
        }
        Ok(a)
    }
    fn store(&self) -> Result<Store> {
        let root = self.store.as_ref().context("config: store missing")?;
        let sock = self.keyd_socket.as_ref().context("config: keyd_socket missing")?;
        let keys = keyd::fetch_keyring(sock, &self.tenant).context("keyd")?;
        Ok(Store::open(root, keys, Options::default())?)
    }
    fn session(&self, ca: &Ca) -> Result<(Session, AgentInfo)> {
        let a = self.agent()?;
        let pin = a
            .cert_sha256
            .as_deref()
            .context("agent is not enrolled (no certificate fingerprint)")?;
        let pins: Vec<&str> = std::iter::once(pin).chain(a.cert_sha256_next.as_deref()).collect();
        let route = Route {
            host: &a.host,
            port: a.port,
            edge: a.edge.as_ref(),
        };
        let mut s = Session::connect_route(
            &route,
            ca,
            &a.id,
            session_config_pins(ca, &a.id, &pins)?,
            Duration::from_secs(self.timeout_secs),
        )?;
        let info = s.hello(&a.id)?;
        println!("agent-info {}", serde_json::to_string(&info)?);
        // which certificate the agent presented (confirms a renewed one) and its validity
        if let Some((fp, nb, na)) = s.peer_cert() {
            println!(
                "agent-cert {}",
                json!({"agent_id": a.id, "cert_sha256": fp, "not_before": nb, "not_after": na})
            );
        }
        Ok((s, info))
    }
}

fn main() -> Result<()> {
    keyd::deny_dumps();
    let args: Vec<String> = std::env::args().skip(1).collect();
    let usage = "usage: nexus-agentctl <config.json> enroll | backup | restore | update | hello | renew | fleet-scan | poll | edge-enroll | edge-link | rescue | layout <agent-id> <time> <out.json> | files <agent-id> <time> ls <dir> | files <agent-id> <time> get <out.tar|out.zip> <path>...";
    let [cfg_path, cmd, rest @ ..] = args.as_slice() else {
        bail!("{usage}");
    };
    let cfg: Config = serde_json::from_slice(&fs::read(cfg_path)?).context("config")?;
    match (cmd.as_str(), rest) {
        ("enroll", []) => {
            let ca = Ca::load_or_create(&cfg.ca_dir)?;
            let a = cfg.agent()?;
            let digest = fs::read_to_string(cfg.token_file.as_ref().context("config: token_file missing")?)?;
            let e = enroll::enroll(
                &ca,
                &a.host,
                a.port,
                digest.trim(),
                &a.id,
                Duration::from_secs(cfg.timeout_secs.min(300)),
            )?;
            // recorded by the scheduler even if the check below fails: the agent has consumed its token
            println!(
                "enrolled {}",
                json!({"agent_id": a.id, "cert_sha256": e.cert_sha256, "appliance_id": ca.appliance_id})
            );
            // the agent switches to mTLS: confirm with a verified session (retry while it restarts)
            let pinned = Config {
                agent: Some(AgentCfg {
                    id: a.id.clone(),
                    name: None,
                    host: a.host.clone(),
                    port: a.port,
                    cert_sha256: Some(e.cert_sha256.clone()),
                    cert_sha256_next: None,
                    edge: a.edge.clone(),
                }),

                ..cfg
            };
            let end = Instant::now() + Duration::from_secs(60);
            loop {
                match pinned.session(&ca) {
                    Ok((s, _)) => {
                        s.close();
                        break;
                    }
                    Err(err) if Instant::now() < end => {
                        eprintln!("waiting for the agent's mTLS listener: {err:#}");
                        std::thread::sleep(Duration::from_secs(2));
                    }
                    Err(err) => return Err(err.context("enrolled, but the mTLS session check failed")),
                }
            }
        }
        ("fleet-scan", []) => {
            let f = cfg.fleet.as_ref().context("config: fleet missing")?;
            let ca = Ca::load_or_create(&cfg.ca_dir)?;
            let digest = fs::read_to_string(&f.digest_file)?;
            let pace = agent_conn::fleet::Pace {
                parallel: f.parallel,
                rate: f.rate,
                timeout: Duration::from_secs(f.timeout_secs.max(1)),
            };
            let t = Instant::now();
            let n = agent_conn::fleet::scan(&ca, &f.targets, f.port, &f.id, digest.trim(), &pace, &|a| {
                println!("fleet-agent {}", serde_json::to_string(a).unwrap_or_default());
            });
            println!(
                "fleet {}: {} addresses scanned on port {} in {:.0?}, {n} agents awaiting enrollment",
                f.id,
                f.targets.len(),
                f.port,
                t.elapsed()
            );
        }
        ("poll", []) => {
            let p = cfg.poll.as_ref().context("config: poll missing")?;
            let ca = Ca::load_or_create(&cfg.ca_dir)?;
            agent_conn::poll::poll_all(
                &ca,
                &p.agents,
                p.concurrency,
                Duration::from_secs(cfg.timeout_secs.min(60)),
                &mut |v| println!("poll {v}"),
            );
        }
        ("edge-enroll", []) => {
            let e = cfg.edge.as_ref().context("config: edge missing")?;
            let ca = Ca::load_or_create(&cfg.ca_dir)?;
            let digest = fs::read_to_string(e.token_file.as_ref().context("config: token_file missing")?)?;
            let r = agent_conn::edge::enroll(
                &ca,
                &e.target.host,
                e.target.port,
                digest.trim(),
                Duration::from_secs(cfg.timeout_secs.min(60)),
            )?;
            println!(
                "edge-enrolled {}",
                json!({"edge_id": e.id, "cert_sha256": r.cert_sha256, "version": r.version})
            );
        }
        ("edge-link", []) => {
            let e = cfg.edge.as_ref().context("config: edge missing")?;
            let ca = Ca::load_or_create(&cfg.ca_dir)?;
            let spec = e.link.clone().unwrap_or_default();
            agent_conn::edge::link(&ca, &e.target, &spec, &mut |l| {
                use std::io::Write;
                let mut o = std::io::stdout().lock();
                let _ = writeln!(o, "{l}");
                let _ = o.flush();
            })?;
        }
        ("hello", []) => {
            let ca = Ca::load_or_create(&cfg.ca_dir)?;
            cfg.session(&ca)?.0.close();
        }
        ("renew", []) => {
            let ca = Ca::load_or_create(&cfg.ca_dir)?;
            let a = cfg.agent()?;
            let (mut s, _) = cfg.session(&ca)?;
            let line = |what: &str, r: &agent_conn::renew::Renewed| {
                println!(
                    "{what} {}",
                    json!({"agent_id": a.id, "cert_sha256": r.cert_sha256, "not_before": r.not_before, "not_after": r.not_after})
                );
            };
            // `renew-issued` first: the scheduler accepts it as a second pin even if
            // the confirmation below never arrives
            let r = agent_conn::renew::renew(&ca, &mut s, &a.id, &mut |r| line("renew-issued", r))?;
            s.close();
            line("renewed", &r);
            // confirm with a session pinned to the new certificate only
            let pinned = Config {
                agent: Some(AgentCfg {
                    id: a.id.clone(),
                    name: None,
                    host: a.host.clone(),
                    port: a.port,
                    cert_sha256: Some(r.cert_sha256.clone()),
                    cert_sha256_next: None,
                    edge: a.edge.clone(),
                }),
                ..cfg
            };
            pinned.session(&ca)?.0.close();
        }
        ("backup", []) => {
            let b = cfg.backup.as_ref().context("config: backup missing")?;
            if b.paths.is_empty() {
                bail!("nothing to back up: no paths");
            }
            let ca = Ca::load_or_create(&cfg.ca_dir)?;
            let store = cfg.store()?;
            let mut map = MapDb::open(cfg.store.as_deref().unwrap())?;
            let (mut s, info) = cfg.session(&ca)?;
            let t = Instant::now();
            // the Windows agent's change tracker is the USN journal (with the cache)
            let tracker = match info.os.to_ascii_lowercase().contains("windows") {
                true => "usn",
                false => "metadata-cache",
            };
            let spec = BackupSpec {
                job: cfg.job,
                paths: b.paths.clone(),
                excludes: b.excludes.clone(),
                hooks: b.hooks,
                filters: b.filters.clone(),
                limits: b.limits,
                file_hashes: b.file_hashes,
                full_read: b.full_read.then_some(tracker),
            };
            let written = store.written();
            let agent = cfg.agent()?;
            chunkstore::progress::name_item(&agent_conn::source_name(&agent.id), agent.name.as_deref());
            let r = backup::backup(&store, &mut map, &mut s, &agent.id, &spec, &mut |l| println!("{l}"))?;
            s.close();
            for (what, h) in [("pre", &r.prepare_hook_log), ("post", &r.release_hook_log)] {
                for l in h.lines() {
                    println!("hook ({what}): {l}");
                }
            }
            println!(
                "committed {}/{} in {:.1?}: {} entries, {} bytes, {} unchanged files, {} chunks transferred ({} bytes, {} new)",
                r.source,
                r.time,
                t.elapsed(),
                r.entries,
                r.bytes,
                r.unchanged,
                r.wanted_chunks,
                r.wanted_bytes,
                r.new_chunks
            );
            let m = store.load_manifest(&r.source, r.time)?;
            // `read` = what the agent read from its disks (Phase 30: the dedup-rate anomaly compares
            // the new data with it); the chunks it sent are the part the appliance did not have yet
            let read = r.scan.read_bytes.max(r.wanted_bytes);
            println!("{}", store.stats_line(&m, read, store.written().since(written))?);
            if let Some(h) = store.take_hash_stats() {
                println!("{h}");
            }
            if !r.consistent || r.inconsistent_files > 0 {
                println!(
                    "inconsistent {}/{}: consistent={} ({} files changed while read without a snapshot)",
                    r.source, r.time, r.consistent, r.inconsistent_files
                );
            }
        }
        ("restore", []) => {
            let rc = cfg.restore.as_ref().context("config: restore missing")?;
            let _staging = RemoveOnDrop(rc.tar.clone());
            if rc.tar.is_none() && restore::tree_index(&rc.source).is_none() {
                bail!("invalid source {:?}: not a file-tree snapshot", rc.source);
            }
            let ca = Ca::load_or_create(&cfg.ca_dir)?;
            let spec = RestoreSpec {
                job: cfg.job,
                source: rc.source.clone(),
                time: rc.time,
                paths: rc.paths.clone(),
                target: rc.target.clone(),
                overwrite: parse_overwrite(&rc.overwrite)?,
                confirm: rc.confirm.clone(),
                target_agent: cfg.agent()?.id.clone(),
            };
            let st = match &rc.tar {
                Some(tar) => {
                    let (mut s, _) = cfg.session(&ca)?;
                    let st = tarbridge::restore_tar(&mut s, tar, &spec, &mut |l| println!("{l}"))?;
                    s.close();
                    st
                }
                None => {
                    let store = cfg.store()?;
                    let map = MapDb::open(cfg.store.as_deref().unwrap())?;
                    let (mut s, _) = cfg.session(&ca)?;
                    let st = restore::restore(&store, &map, &mut s, &spec, &mut |l| println!("{l}"))?;
                    s.close();
                    st
                }
            };
            println!(
                "restored {}",
                json!({"target": rc.target, "files": st.files, "dirs": st.dirs, "bytes": st.bytes, "errors": st.errors.len()})
            );
            if !st.errors.is_empty() {
                bail!("{} entries could not be restored", st.errors.len());
            }
        }
        ("synthetic", []) => synthetic(&cfg)?,
        ("update", []) if cfg.update.is_some() => update_release(&cfg)?,
        ("update", []) => {
            let dir = cfg.update_dir.as_ref().context("config: update_dir missing")?;
            let bundle = update::load(dir)?;
            let ca = Ca::load_or_create(&cfg.ca_dir)?;
            let (mut s, info) = cfg.session(&ca)?;
            println!(
                "updating agent {} from {:?} to {}",
                info.agent_id, info.version, bundle.version
            );
            update::push(&mut s, &bundle)?;
            s.close();
            // the agent restarts itself; report the new version when it is back
            let end = Instant::now() + Duration::from_secs(120);
            loop {
                std::thread::sleep(Duration::from_secs(2));
                match cfg.session(&ca) {
                    Ok((s, i)) => {
                        s.close();
                        if i.version != bundle.version {
                            bail!("agent still runs version {} after the update", i.version);
                        }
                        break;
                    }
                    Err(e) if Instant::now() < end => eprintln!("waiting for the agent: {e:#}"),
                    Err(e) => return Err(e.context("agent did not come back after the update")),
                }
            }
        }
        ("layout", [agent, time, out]) => {
            if !valid_agent_id(agent) {
                bail!("invalid agent id");
            }
            let json = agent_conn::rescue::load_layout(&cfg.store()?, agent, time.parse()?)?;
            fs::write(out, json)?;
        }
        ("rescue", []) => rescue(&cfg)?,
        ("files", [agent, time, op, args @ ..]) => {
            if !valid_agent_id(agent) {
                bail!("invalid agent id");
            }
            let store = cfg.store()?;
            let tree = restore::load_tree(&store, agent, time.parse()?)?;
            match (op.as_str(), args) {
                ("ls", [dir]) => println!("{}", serde_json::to_string_pretty(&files::list(&tree, dir)?)?),
                ("get", [out, paths @ ..]) if !paths.is_empty() => {
                    let out = Path::new(out);
                    let n = files::extract(
                        &store,
                        &tree,
                        paths,
                        Format::from_path(out)?,
                        fs::File::create_new(out)?,
                    )?;
                    println!("{n} entries written to {}", out.display());
                }
                _ => bail!("{usage}"),
            }
        }
        _ => bail!("{usage}"),
    }
    Ok(())
}

/// `synthetic`: composes the tree the plan names and writes or restores it.
fn synthetic(cfg: &Config) -> Result<()> {
    let sc = cfg.synthetic.as_ref().context("config: synthetic missing")?;
    let plan: chunkstore::synthetic::Plan =
        serde_json::from_slice(&fs::read(&sc.plan).with_context(|| format!("{}", sc.plan.display()))?)
            .context("synthetic plan")?;
    if plan.source.starts_with("plugin-") || restore::tree_index(&plan.source).is_none() {
        bail!(
            "invalid source {:?}: not a file-tree snapshot of an agent, NAS or share",
            plan.source
        );
    }
    let store = cfg.store()?;
    let base = restore::load_source_tree(&store, &plan.source, plan.time)?;
    let c = chunkstore::synthetic::compose(&plan, base, &mut |t| {
        eprintln!("synthetic: reading versions from {}/{t}", plan.source);
        restore::load_source_tree(&store, &plan.source, t).map_err(std::io::Error::other)
    })?;
    for m in &c.missing {
        eprintln!("synthetic: /{m} is no longer in its snapshot: left out");
    }
    for d in &c.dangling {
        eprintln!("synthetic: /{d} is a hard link to a left-out file: left out");
    }
    let mut result = plan.stats.clone();
    if !result.is_object() {
        result = json!({});
    }
    result["missing"] = json!(c.missing.len());
    result["dangling"] = json!(c.dangling.len());
    let nothing = || anyhow::anyhow!("nothing to restore: every selected file was left out (see the CSV of the job)");
    match (&sc.out, &sc.restore) {
        (Some(out), None) => {
            let n = files::extract(
                &store,
                &c.entries,
                &plan.paths,
                Format::from_path(out)?,
                fs::File::create_new(out)?,
            )
            .map_err(|e| if c.entries.is_empty() { nothing() } else { e })?;
            eprintln!("{n} entries written to {}", out.display());
            result["entries"] = json!(n);
        }
        (None, Some(r)) => {
            if c.entries.is_empty() {
                return Err(nothing());
            }
            let ca = Ca::load_or_create(&cfg.ca_dir)?;
            let spec = RestoreSpec {
                job: cfg.job,
                source: plan.source.clone(),
                time: plan.time,
                paths: plan.paths.clone(),
                target: r.target.clone(),
                overwrite: parse_overwrite(&r.overwrite)?,
                confirm: r.confirm.clone(),
                target_agent: cfg.agent()?.id.clone(),
            };
            let map = MapDb::open(cfg.store.as_deref().context("config: store missing")?)?;
            let (mut s, _) = cfg.session(&ca)?;
            let st = restore::restore_tree(&store, &map, &mut s, &spec, &c.entries, &mut |l| eprintln!("{l}"))?;
            s.close();
            result["written"] = json!({"target": r.target, "files": st.files, "dirs": st.dirs, "bytes": st.bytes,
                                        "errors": st.errors.len()});
            if !st.errors.is_empty() {
                println!("{result}");
                bail!("{} entries could not be restored", st.errors.len());
            }
        }
        _ => bail!("config: synthetic needs exactly one of out or restore"),
    }
    println!("{result}");
    Ok(())
}

/// `update` with a release from the store (protocol v1.8 chunked, or the single
/// frame for older agents), then the reconnect check. Lines: `update-plan`,
/// `update-sent`, `update-state`, `update-result` (docs/agent-update-plan.md).
fn update_release(cfg: &Config) -> Result<()> {
    let u = cfg.update.as_ref().context("config: update missing")?;
    let keys = agent_core::update::load_keys(&u.keys_dir);
    let dirs: Vec<(PathBuf, &'static str)> = u
        .dirs
        .iter()
        .enumerate()
        .map(|(i, d)| (d.clone(), if i == 0 { "image" } else { "upload" }))
        .collect();
    let releases = agent_core::releases::scan(&dirs, &keys);
    let rel = agent_core::releases::find(&releases, &u.version)
        .filter(|r| r.usable())
        .with_context(|| {
            format!(
                "release {} is not in the store or not signed by a pinned key",
                u.version
            )
        })?;
    let ca = Ca::load_or_create(&cfg.ca_dir)?;
    let (mut s, info) = cfg.session(&ca)?;
    let result = |state: &str, version: &str, error: &str| {
        println!(
            "update-result {}",
            json!({"agent_id": info.agent_id, "state": state, "version": version, "error": error})
        );
    };
    let older = agent_core::releases::older(&u.version, &info.version);
    if u.version == info.version || (older && !u.rollback) {
        result(
            "failed",
            &info.version,
            &format!("the agent runs {}; {} is not newer", info.version, u.version),
        );
        bail!(
            "agent {} runs {}, not older than {}",
            info.agent_id,
            info.version,
            u.version
        );
    }
    if u.rollback && !older {
        bail!("a rollback must go to an older release");
    }
    let plan = match update::plan(rel, &info.facts(), &info.caps) {
        Ok(p) => p,
        Err(e) => {
            result("failed", &info.version, &format!("{e:#}"));
            return Err(e);
        }
    };
    let names: Vec<String> = match &plan {
        update::Plan::Chunked(a) => a.iter().map(|a| a.name.clone()).collect(),
        update::Plan::Legacy(a) => vec![a.name.clone()],
    };
    println!(
        "update-plan {}",
        json!({"from": info.version, "to": u.version, "install": info.install, "arch": info.arch,
               "artifacts": names, "rollback": u.rollback,
               "mode": if matches!(plan, update::Plan::Chunked(_)) { "chunked" } else { "legacy" }})
    );
    let mut last = Instant::now();
    if let Err(e) = update::push_release(&mut s, rel, &plan, u.rollback, &mut |sent, total| {
        if last.elapsed() >= Duration::from_secs(2) || sent == total {
            last = Instant::now();
            println!("progress {}", json!({"bytes": sent, "bytes_total": total}));
        }
    }) {
        let msg = format!("{e:#}");
        result(
            if msg.contains("agent error 409") {
                "busy"
            } else {
                "failed"
            },
            &info.version,
            &msg,
        );
        return Err(e);
    }
    s.close();
    println!("update-sent {}", json!({"to": u.version}));
    // the agent restarts (binary swap) or a package manager restarts it
    let wait = u.reconnect_secs.unwrap_or_else(|| update::reconnect_secs(&plan));
    let end = Instant::now() + Duration::from_secs(wait);
    let mut seen_state = json!({});
    loop {
        std::thread::sleep(Duration::from_secs(3));
        match cfg.session(&ca) {
            Ok((mut s2, i)) => {
                let st = update::status(&mut s2).unwrap_or_else(|_| json!({}));
                s2.close();
                if st != seen_state {
                    println!("update-state {st}");
                    seen_state = st.clone();
                }
                let state = st["state"].as_str().unwrap_or_default();
                if i.version == u.version && state != "installing" {
                    result("ok", &i.version, "");
                    return Ok(());
                }
                if matches!(state, "failed" | "rolled_back") && st["to"] == json!(u.version) {
                    let err = st["error"].as_str().unwrap_or("update failed on the agent").to_owned();
                    result(state, &i.version, &err);
                    bail!("update to {} {state} on the agent: {err}", u.version);
                }
                if Instant::now() >= end {
                    let err = format!("the agent still runs {} after {wait} s", i.version);
                    result("failed", &i.version, &err);
                    bail!("{err}");
                }
            }
            Err(e) if Instant::now() < end => eprintln!("waiting for the agent: {e:#}"),
            Err(e) => {
                result("failed", &info.version, &format!("the agent did not come back: {e:#}"));
                return Err(e.context("agent did not come back after the update"));
            }
        }
    }
}

/// `rescue`: enroll the rescue agent with the recovery token (if not done yet),
/// then the recovery. Lines for the scheduler: `rescue-enrolled {json}`,
/// `rescue-step <apply|restore|finish>`, `rescue-done {json}`.
fn rescue(cfg: &Config) -> Result<()> {
    let rc = cfg.rescue.as_ref().context("config: rescue missing")?;
    if !valid_agent_id(&rc.source_agent) {
        bail!("invalid source agent id");
    }
    let ca = Ca::load_or_create(&cfg.ca_dir)?;
    let a = cfg.agent()?;
    let store = cfg.store()?;
    // fail early (before the token is spent) if the snapshot cannot be recovered
    agent_conn::rescue::load_layout(&store, &rc.source_agent, rc.time)?;
    let pin = match &a.cert_sha256 {
        Some(p) => p.clone(),
        None => {
            let digest = fs::read_to_string(cfg.token_file.as_ref().context("config: token_file missing")?)?;
            // the firewall may open the rescue address only with the next scheduler tick
            let end = Instant::now() + Duration::from_secs(120);
            let e = loop {
                match enroll::enroll(&ca, &a.host, a.port, digest.trim(), &a.id, Duration::from_secs(60)) {
                    Ok(e) => break e,
                    Err(e) if Instant::now() < end && format!("{e:#}").contains("connect") => {
                        eprintln!("waiting for the rescue agent: {e:#}");
                        std::thread::sleep(Duration::from_secs(5));
                    }
                    Err(e) => return Err(e.context("enrolling the rescue agent")),
                }
            };
            println!(
                "rescue-enrolled {}",
                json!({"agent_id": a.id, "cert_sha256": e.cert_sha256})
            );
            e.cert_sha256
        }
    };
    let pinned = Config {
        agent: Some(AgentCfg {
            id: a.id.clone(),
            name: None,
            host: a.host.clone(),
            port: a.port,
            cert_sha256: Some(pin),
            cert_sha256_next: None,
            edge: None,
        }),
        tenant: cfg.tenant.clone(),
        store: cfg.store.clone(),
        keyd_socket: cfg.keyd_socket.clone(),
        ca_dir: cfg.ca_dir.clone(),
        job: cfg.job,
        token_file: None,
        backup: None,
        restore: None,
        update_dir: None,
        update: None,
        rescue: None,
        poll: None,
        fleet: None,
        edge: None,
        synthetic: None,
        timeout_secs: cfg.timeout_secs,
    };
    let end = Instant::now() + Duration::from_secs(60);
    let (mut s, _) = loop {
        match pinned.session(&ca) {
            Ok(x) => break x,
            Err(e) if Instant::now() < end => {
                eprintln!("waiting for the rescue agent's mTLS listener: {e:#}");
                std::thread::sleep(Duration::from_secs(2));
            }
            Err(e) => return Err(e),
        }
    };
    let map = MapDb::open(cfg.store.as_deref().unwrap())?;
    let t = Instant::now();
    let spec = agent_conn::rescue::Spec {
        job: cfg.job,
        agent: rc.source_agent.clone(),
        time: rc.time,
        reboot: rc.reboot,
    };
    let st = agent_conn::rescue::recover(&store, &map, &mut s, &spec, &mut |l| println!("{l}"), &mut |st| {
        println!("rescue-step {st}");
    })?;
    s.close();
    println!(
        "rescue-done {}",
        json!({"files": st.files, "dirs": st.dirs, "bytes": st.bytes, "errors": st.errors.len(),
               "seconds": t.elapsed().as_secs(), "reboot": rc.reboot})
    );
    Ok(())
}
