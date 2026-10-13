//! `nexus-truenas <config.json> backup | check | snapshots | authorized-key <pubkey-file> [from] |
//! files <nas-source> <time> ls <dir> | files <nas-source> <time> get <out.tar|out.zip> <path>...`
//!
//! Spawned by the scheduler with a generated 0600 config (docs/truenas-connector.md).
//! Machine-readable lines on stdout: `committed nas-<id>-<ds>/<time> …` per
//! dataset, `result {json}` at the end of a backup (exit status 1 if any
//! dataset failed); `files … ls` prints the JSON listing only.

use agent_conn::files::{self, Format};
use anyhow::{bail, Context, Result};
use chunkstore::{Index, Options, Store};
use serde::Deserialize;
use serde_json::json;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;
use truenas::api::{Api, ApiConfig, Nas};
use truenas::backup::{self, Spec};
use truenas::fc::{self, Fc, Tools};
use truenas::remote::{Remote, Ssh};
use truenas::{parse_snap_name, parse_source_name, TREE_INDEX};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    tenant: String,
    /// Phase 28: SHA-256 per file in the name index (group option `file_hashes`)
    #[serde(default)]
    file_hashes: bool,
    #[serde(default)]
    store: Option<PathBuf>,
    #[serde(default)]
    keyd_socket: Option<PathBuf>,
    source_id: u64,
    #[serde(default)]
    api: Option<ApiCfg>,
    #[serde(default)]
    ssh: Option<SshCfg>,
    #[serde(default)]
    datasets: Vec<String>,
    #[serde(default)]
    recursive: bool,
    #[serde(default = "yes")]
    sudo: bool,
    /// `zfs diff` via sudo (default). false: `zfs allow -u <user> diff <ds>` + traverse permission on the dataset root
    #[serde(default = "yes")]
    zfs_sudo: bool,
    #[serde(default = "timeout")]
    timeout_secs: u64,
    /// "use existing snapshots" (Phase 22b): back up the newest `<prefix>*` snapshot
    #[serde(default)]
    existing_snapshots: Option<String>,
    /// store source -> {time, snapshot} of the newest store snapshot (from the catalog)
    #[serde(default)]
    references: std::collections::HashMap<String, Reference>,
    #[serde(default)]
    read_limit: Option<catalog::schedule::ReadLimit>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Reference {
    time: u64,
    snapshot: String,
}

fn yes() -> bool {
    true
}
fn timeout() -> u64 {
    120
}
fn https() -> u16 {
    443
}
fn ssh_port() -> u16 {
    22
}
fn user() -> String {
    "nexusbackup".into()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ApiCfg {
    host: String,
    #[serde(default = "https")]
    port: u16,
    #[serde(default)]
    connect_addr: Option<String>,
    /// PEM file: the TrueNAS certificate (pinned) and/or its CA
    ca_file: PathBuf,
    #[serde(default = "user")]
    user: String,
    /// file with the API key
    key_file: PathBuf,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SshCfg {
    host: String,
    #[serde(default = "ssh_port")]
    port: u16,
    #[serde(default = "user")]
    user: String,
    key_file: PathBuf,
    known_hosts_file: PathBuf,
}

impl Config {
    fn store(&self) -> Result<Store> {
        let root = self.store.as_ref().context("config: store missing")?;
        let sock = self.keyd_socket.as_ref().context("config: keyd_socket missing")?;
        let keys = keyd::fetch_keyring(sock, &self.tenant).context("keyd")?;
        let s = Store::open(root, keys, Options::default())?;
        if self.file_hashes {
            s.enable_file_hashes();
        }
        Ok(s)
    }
    fn api(&self) -> Result<Api> {
        let a = self.api.as_ref().context("config: api missing")?;
        Api::connect(&ApiConfig {
            host: a.host.clone(),
            port: a.port,
            connect_addr: a
                .connect_addr
                .as_deref()
                .map(|s| s.parse().context("api.connect_addr: expected ip:port"))
                .transpose()?,
            ca_pem: fs::read(&a.ca_file).context("api.ca_file")?,
            user: a.user.clone(),
            api_key: fs::read_to_string(&a.key_file)
                .context("api.key_file")?
                .trim()
                .to_owned(),
            timeout: Duration::from_secs(self.timeout_secs),
        })
    }
    fn ssh(&self) -> Result<Ssh> {
        let s = self.ssh.as_ref().context("config: ssh missing")?;
        Ok(Ssh {
            host: s.host.clone(),
            port: s.port,
            user: s.user.clone(),
            key: s.key_file.clone(),
            known_hosts: s.known_hosts_file.clone(),
        })
    }
    fn fc(&self) -> Fc {
        Fc {
            datasets: self.datasets.clone(),
            recursive: self.recursive,
            sudo: self.sudo,
            zfs_sudo: self.zfs_sudo,
            existing_prefix: self.existing_snapshots.clone(),
        }
    }
}

fn load_tree(store: &Store, source: &str, time: u64) -> Result<Vec<chunkstore::TreeEntry>> {
    let m = store.load_manifest(source, time)?;
    match store.load_index(&m, TREE_INDEX)? {
        Index::Tree { entries } => Ok(entries),
        _ => bail!("{source}/{time} is not a file tree snapshot"),
    }
}

fn main() -> Result<()> {
    keyd::deny_dumps();
    let args: Vec<String> = std::env::args().skip(1).collect();
    let usage = "usage: nexus-truenas <config.json> backup | check | snapshots | authorized-key <pubkey-file> [from] | files <nas-source> <time> ls <dir> | files <nas-source> <time> get <out.tar|out.zip> <path>...";
    let [cfg_path, cmd, rest @ ..] = args.as_slice() else {
        bail!("{usage}");
    };
    let cfg: Config = serde_json::from_slice(&fs::read(cfg_path)?).context("config")?;
    match (cmd.as_str(), rest) {
        ("backup", []) => {
            let store = cfg.store()?;
            let mut api = cfg.api()?;
            let ssh = cfg.ssh()?;
            let throttle = cfg.read_limit.as_ref().map(|r| r.throttle()).transpose()?.flatten();
            let spec = Spec {
                source_id: cfg.source_id,
                datasets: cfg.datasets.clone(),
                recursive: cfg.recursive,
                existing: cfg.existing_snapshots.as_ref().map(|prefix| backup::Existing {
                    prefix: prefix.clone(),
                    references: cfg
                        .references
                        .iter()
                        .map(|(k, r)| (k.clone(), (r.time, r.snapshot.clone())))
                        .collect(),
                }),
                pace: throttle.map(|t| -> truenas::remote::Pace { std::sync::Arc::new(move |n| t.account(n)) }),
            };
            let r = backup::backup(&store, &mut api, &ssh, &spec, &mut |l| println!("{l}"))?;
            api.close();
            for (ds, e) in &r.failed {
                println!("failed {ds}: {}", e.escape_debug());
            }
            println!(
                "result {}",
                json!({
                    "time": r.time,
                    "datasets": r.committed,
                    "snapshots": r.committed.iter().map(|c| json!({"source": c.source, "time": c.time, "meta": {"zfs_snapshot": c.snapshot}})).collect::<Vec<_>>(),
                    "failed": r.failed.iter().map(|(d, e)| json!({"dataset": d, "error": e})).collect::<Vec<_>>(),
                    "skipped": r.skipped.iter().map(|(d, e)| json!({"dataset": d, "reason": e})).collect::<Vec<_>>(),
                    "deleted_snapshots": r.deleted_snapshots,
                    "transferred_bytes": r.committed.iter().map(|c| c.transferred_bytes).sum::<u64>(),
                })
            );
            if !r.failed.is_empty() {
                bail!(
                    "{} of {} datasets failed",
                    r.failed.len(),
                    r.failed.len() + r.committed.len()
                );
            }
        }
        ("check", []) => {
            let mut api = cfg.api()?;
            for root in &cfg.datasets {
                for d in api.datasets(root, cfg.recursive)? {
                    println!(
                        "dataset {} {}",
                        d.name,
                        d.mountpoint.as_deref().unwrap_or("(not mounted)")
                    );
                }
            }
            api.close();
            let ssh = cfg.ssh()?;
            println!("ssh {}", Remote::new(&ssh).hello()?);
        }
        ("snapshots", []) => {
            let mut api = cfg.api()?;
            for root in &cfg.datasets {
                for d in api.datasets(root, cfg.recursive)? {
                    for n in api.snapshots(&d.name)? {
                        if parse_snap_name(cfg.source_id, &n).is_some() {
                            println!("{}@{n}", d.name);
                        }
                    }
                }
            }
            api.close();
        }
        ("authorized-key", [pubkey, from @ ..]) if from.len() <= 1 => {
            let k = fs::read_to_string(pubkey).context("public key file")?;
            println!(
                "{}",
                fc::authorized_keys(&cfg.fc(), &Tools::default(), k.trim(), from.first().map(String::as_str))?
            );
        }
        ("files", [source, time, op, args @ ..]) => {
            if parse_source_name(source).is_none() {
                bail!("invalid source {source:?} (expected nas-<id>-<dataset>)");
            }
            let store = cfg.store()?;
            let tree = load_tree(&store, source, time.parse()?)?;
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
