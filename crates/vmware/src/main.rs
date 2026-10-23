//! `nexus-vmware <config.json> backup | inventory | check`
//!
//! Spawned by the scheduler with a generated 0600 config (plan.md Phase 41, docs/vmware-design.md). Machine lines
//! on stdout: `committed vmw-<uuid>/<time> …` and `consistency vmw-<uuid>/<time>: application|crash` per VM,
//! `result {json}` at the end of a backup (exit status 1 if any VM failed); `inventory` prints
//! `{"guests":[{id, title, kind, tags}]}` with the VM UUID as the guest id; progress lines go to stderr.

use anyhow::{bail, Context, Result};
use chunkstore::progress;
use chunkstore::{Options, Store};
use serde::Deserialize;
use serde_json::json;
use std::fs;
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use vmware::backup::{backup_vm, Spec, Transport};
use vmware::names::{source_name, valid_uuid};
use vmware::vsphere::Client;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    tenant: String,
    #[serde(default)]
    store: Option<PathBuf>,
    #[serde(default)]
    keyd_socket: Option<PathBuf>,
    source_id: i64,
    /// ESXi host or vCenter
    host: String,
    #[serde(default = "https")]
    port: u16,
    /// the host's certificate or its CA (PEM), pinned
    ca_file: PathBuf,
    user: String,
    password_file: PathBuf,
    /// datacenter of the `.vmx` downloads (`ha-datacenter` on a standalone host)
    #[serde(default = "ha_datacenter")]
    datacenter: String,
    /// `nfc` (no proxy VM); the hot-add proxy is not run by this binary yet
    #[serde(default = "nfc")]
    transport: String,
    /// VM UUIDs to back up (the group's guests)
    #[serde(default)]
    vms: Vec<String>,
    /// read every block, ignore CBT (scheduled full read)
    #[serde(default)]
    full_read: bool,
    /// job id: names the vSphere snapshot `nexus-backup-<job>` (default: the start time)
    #[serde(default)]
    job: Option<u64>,
    #[serde(default = "timeout")]
    timeout_secs: u64,
}

fn https() -> u16 {
    443
}
fn ha_datacenter() -> String {
    "ha-datacenter".into()
}
fn nfc() -> String {
    "nfc".into()
}
fn timeout() -> u64 {
    120
}

impl Config {
    fn client(&self) -> Result<Client> {
        let ca = fs::read(&self.ca_file).context("ca_file")?;
        let pw = fs::read_to_string(&self.password_file).context("password_file")?;
        Client::login(
            &self.host,
            self.port,
            &ca,
            &self.user,
            pw.trim_end_matches(['\r', '\n']),
        )
        .with_context(|| format!("vSphere login to {}", self.host))
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
    let usage = "usage: nexus-vmware <config.json> backup | inventory | check";
    let [cfg_path, cmd] = args.as_slice() else {
        bail!("{usage}");
    };
    let cfg: Config = serde_json::from_slice(&fs::read(cfg_path)?).context("config")?;
    match cmd.as_str() {
        "check" => {
            let c = cfg.client()?;
            println!("{}", c.about());
            c.logout();
        }
        "inventory" => {
            let c = cfg.client()?;
            let guests: Vec<_> = c
                .vm_list()?
                .into_iter()
                .filter(|(_, i)| valid_uuid(&i.uuid))
                .map(|(_, i)| json!({"id": i.uuid, "title": i.name, "kind": "vm", "tags": []}))
                .collect();
            c.logout();
            println!("{}", json!({ "guests": guests }));
        }
        "backup" => {
            if cfg.transport != "nfc" {
                // ponytail: the proxy transport needs the agent session (appliance CA, enrolled proxy) in this
                // binary; until then it is reached through the library only
                bail!(
                    "transport {:?}: only \"nfc\" is supported by nexus-vmware yet",
                    cfg.transport
                );
            }
            if let Some(bad) = cfg.vms.iter().find(|u| !valid_uuid(u)) {
                bail!("config: vms: {bad:?} is not a VM UUID");
            }
            let ok = backup(&cfg)?;
            if !ok {
                std::process::exit(1);
            }
        }
        _ => bail!("{usage}"),
    }
    Ok(())
}

/// Backs up every VM of `cfg.vms`; false if any failed (the others are still committed).
fn backup(cfg: &Config) -> Result<bool> {
    let store = cfg.store()?;
    let c = cfg.client()?;
    let vms = c.vm_list()?;
    let job = cfg.job.unwrap_or_else(now);
    let (mut snapshots, mut failed) = (Vec::new(), Vec::new());
    for (i, uuid) in cfg.vms.iter().enumerate() {
        let source = source_name(uuid);
        let Some((vm, info)) = vms.iter().find(|(_, v)| &v.uuid == uuid) else {
            println!("failed {source}: not in the vSphere inventory of {}", cfg.host);
            failed.push(json!({"source": source, "error": "not in the inventory"}));
            continue;
        };
        let mut item = progress::item(&source, Some(&info.name), i as u32 + 1, cfg.vms.len() as u32);
        let spec = Spec {
            vm,
            datacenter: &cfg.datacenter,
            job,
            full: cfg.full_read,
        };
        let mut transport = Transport::Nfc {
            timeout: Duration::from_secs(cfg.timeout_secs),
        };
        let t0 = Instant::now();
        // NFC needs no agent mapping index (only the proxy transport does; #85)
        match backup_vm(&c, &store, &mut transport, &spec, &mut |l| println!("{l}")) {
            Ok(m) => {
                item.ok();
                println!(
                    "committed {}/{} in {}s: {}",
                    m.source,
                    m.time,
                    t0.elapsed().as_secs(),
                    info.name
                );
                // quiesced through VMware Tools when they run (backup_vm), else crash-consistent
                let level = if info.tools { "application" } else { "crash" };
                println!("consistency {}/{}: {level}", m.source, m.time);
                snapshots.push(json!({"source": m.source, "time": m.time}));
            }
            Err(e) => {
                println!("failed {source}: {e:#}");
                failed.push(json!({"source": source, "error": format!("{e:#}")}));
            }
        }
    }
    c.logout();
    println!(
        "result {}",
        json!({"source_id": cfg.source_id, "snapshots": snapshots, "failed": failed})
    );
    Ok(failed.is_empty())
}
