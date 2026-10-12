//! `nexus-agentctl <config.json> enroll | backup | restore | update | hello |
//! files <agent-id> <time> ls <dir> | files <agent-id> <time> get <out.tar|out.zip> <path>...`
//!
//! Spawned by the scheduler with a generated 0600 config (docs/agent-protocol.md
//! "Appliance side"). Machine-readable lines on stdout (parsed from the job log):
//! `agent-info {json}` after every successful Hello, `enrolled {json}`,
//! `committed host-<id>/<time>`, `inconsistent host-<id>/<time>: …`,
//! `restore` reads any file-tree snapshot of the tenant (`restore.source`) or,
//! for VM/CT files, the tar `restore.tar` written by `nexus-pve` (then removed);
//! `restored {json}`; `files … ls` prints the JSON listing only.

use agent_conn::backup::{self, Spec as BackupSpec};
use agent_conn::ca::Ca;
use agent_conn::files::{self, Format};
use agent_conn::map::MapDb;
use agent_conn::restore::{self, parse_overwrite, Spec as RestoreSpec};
use agent_conn::tls::{session_config, AgentInfo, Session};
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
    #[serde(default = "timeout")]
    timeout_secs: u64,
}

fn timeout() -> u64 {
    3600
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentCfg {
    id: String,
    host: String,
    port: u16,
    #[serde(default)]
    cert_sha256: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BackupCfg {
    paths: Vec<String>,
    #[serde(default)]
    excludes: Vec<String>,
    #[serde(default)]
    hooks: bool,
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
        let mut s = Session::connect(
            &a.host,
            a.port,
            session_config(ca, &a.id, Some(pin))?,
            Duration::from_secs(self.timeout_secs),
        )?;
        let info = s.hello(&a.id)?;
        println!("agent-info {}", serde_json::to_string(&info)?);
        Ok((s, info))
    }
}

fn main() -> Result<()> {
    keyd::deny_dumps();
    let args: Vec<String> = std::env::args().skip(1).collect();
    let usage = "usage: nexus-agentctl <config.json> enroll | backup | restore | update | hello | files <agent-id> <time> ls <dir> | files <agent-id> <time> get <out.tar|out.zip> <path>...";
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
                    host: a.host.clone(),
                    port: a.port,
                    cert_sha256: Some(e.cert_sha256.clone()),
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
        ("hello", []) => {
            let ca = Ca::load_or_create(&cfg.ca_dir)?;
            cfg.session(&ca)?.0.close();
        }
        ("backup", []) => {
            let b = cfg.backup.as_ref().context("config: backup missing")?;
            if b.paths.is_empty() {
                bail!("nothing to back up: no paths");
            }
            let ca = Ca::load_or_create(&cfg.ca_dir)?;
            let store = cfg.store()?;
            let mut map = MapDb::open(cfg.store.as_deref().unwrap())?;
            let (mut s, _) = cfg.session(&ca)?;
            let t = Instant::now();
            let spec = BackupSpec {
                job: cfg.job,
                paths: b.paths.clone(),
                excludes: b.excludes.clone(),
                hooks: b.hooks,
            };
            let written = store.written();
            let r = backup::backup(&store, &mut map, &mut s, &cfg.agent()?.id, &spec, &mut |l| {
                println!("{l}")
            })?;
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
            println!(
                "{}",
                store.stats_line(&m, r.wanted_bytes, store.written().since(written))?
            );
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
