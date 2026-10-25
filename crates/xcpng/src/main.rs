//! `nexus-xcpng <config.json> inventory | backup | restore` (docs/xcpng-design.md, #40)
//!
//! Spawned with a generated 0600 config like `nexus-vmware`. Machine lines on stdout: `committed xcp-<uuid>/<time>
//! in <n>s: <name>` and `consistency xcp-<uuid>/<time>: crash` per VM, `result {json}` at the end of a backup (exit
//! status 1 if any VM failed); `inventory` prints `{"guests":[{id, title, kind, tags}]}`; `restore` (the config's
//! `restore`: a snapshot as a new VM in the pool) prints `restored {"vm": <uuid>, "name": ...}`.

use anyhow::{bail, Context, Result};
use chunkstore::{Options, Store};
use serde::Deserialize;
use serde_json::json;
use std::fs;
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use xcpng::backup::{backup_vm, inventory, source_name};
use xcpng::xapi::Xapi;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    tenant: String,
    #[serde(default)]
    store: Option<PathBuf>,
    #[serde(default)]
    keyd_socket: Option<PathBuf>,
    #[serde(default)]
    source_id: i64,
    /// the pool master
    host: String,
    #[serde(default = "https")]
    port: u16,
    /// the host's certificate or its CA (PEM), pinned
    ca_file: PathBuf,
    user: String,
    password_file: PathBuf,
    /// VM UUIDs to back up (the group's guests)
    #[serde(default)]
    vms: Vec<String>,
    /// names the XCP-ng snapshot `nexus-backup-<job>` (default: the start time)
    #[serde(default)]
    job: Option<u64>,
    #[serde(default = "timeout")]
    timeout_secs: u64,
    #[serde(default)]
    restore: Option<RestoreCfg>,
}

/// `restore`: snapshot `source`/`time` as a new VM `name` (empty: "<stored name> (restored)") on SR `sr` with its
/// NICs on `network` (UUIDs; empty: the pool's default SR, the management network).
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RestoreCfg {
    source: String,
    time: u64,
    #[serde(default)]
    name: String,
    #[serde(default)]
    sr: Option<String>,
    #[serde(default)]
    network: Option<String>,
}

fn https() -> u16 {
    443
}
fn timeout() -> u64 {
    120
}

impl Config {
    fn xapi(&self) -> Result<Xapi> {
        let ca = fs::read(&self.ca_file).context("ca_file")?;
        let pw = fs::read_to_string(&self.password_file).context("password_file")?;
        Xapi::login(
            &self.host,
            self.port,
            &ca,
            &self.user,
            pw.trim_end_matches(['\r', '\n']),
        )
        .with_context(|| format!("XAPI login to {}", self.host))
    }
    fn store(&self) -> Result<Store> {
        let root = self.store.as_ref().context("config: store missing")?;
        let sock = self.keyd_socket.as_ref().context("config: keyd_socket missing")?;
        let keys = keyd::fetch_keyring(sock, &self.tenant).context("keyd")?;
        Ok(Store::open(root, keys, Options::default())?)
    }
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

fn main() -> Result<()> {
    keyd::deny_dumps();
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [cfg_path, cmd] = args.as_slice() else {
        bail!("usage: nexus-xcpng <config.json> inventory | backup");
    };
    let cfg: Config = serde_json::from_slice(&fs::read(cfg_path)?).context("config")?;
    let x = cfg.xapi()?;
    match cmd.as_str() {
        "inventory" => println!("{}", json!({"guests": inventory(&x)?})),
        "backup" => {
            let store = cfg.store()?;
            let job = cfg.job.unwrap_or_else(now);
            let mut ok = Vec::new();
            let mut failed = Vec::new();
            for uuid in &cfg.vms {
                let t0 = Instant::now();
                match backup_vm(&x, &store, uuid, job, Duration::from_secs(cfg.timeout_secs)) {
                    Ok(d) => {
                        let m = &d.manifest;
                        println!(
                            "committed {}/{} in {}s: {}",
                            m.source,
                            m.time,
                            t0.elapsed().as_secs(),
                            d.name
                        );
                        println!("consistency {}/{}: crash", m.source, m.time);
                        eprintln!(
                            "{}: {} bytes read over NBD, {} disk(s) incremental",
                            d.name, d.bytes_read, d.incremental
                        );
                        ok.push(json!({"source": m.source, "time": m.time}));
                    }
                    Err(e) => {
                        eprintln!("{}: {e:#}", source_name(uuid));
                        failed.push(json!({"source": source_name(uuid), "error": format!("{e:#}")}));
                    }
                }
            }
            println!(
                "result {}",
                json!({"snapshots": ok, "failed": failed, "source_id": cfg.source_id})
            );
            if !failed.is_empty() {
                std::process::exit(1);
            }
        }
        "restore" => {
            let r = cfg.restore.as_ref().context("config: restore missing")?;
            let t = xcpng::restore::Target {
                name: &r.name,
                sr: r.sr.as_deref(),
                network: r.network.as_deref(),
            };
            let t0 = Instant::now();
            let vm = xcpng::restore::restore_vm(
                &x,
                &cfg.store()?,
                &r.source,
                r.time,
                &t,
                Duration::from_secs(cfg.timeout_secs),
            )?;
            eprintln!("{}/{} restored in {}s", r.source, r.time, t0.elapsed().as_secs());
            println!("restored {}", json!({"vm": vm, "name": r.name}));
        }
        _ => bail!("unknown command {cmd}"),
    }
    Ok(())
}
