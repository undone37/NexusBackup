//! `nexus-vmware <config.json> backup | inventory | check | proxy-prepare | proxy-finish`
//!
//! Spawned by the scheduler with a generated 0600 config (plan.md Phase 41, docs/vmware-design.md). Machine lines
//! on stdout: `committed vmw-<uuid>/<time> …` and `consistency vmw-<uuid>/<time>: application|crash` per VM,
//! `result {json}` at the end of a backup (exit status 1 if any VM failed); `inventory` prints
//! `{"guests":[{id, title, kind, tags}]}` with the VM UUID as the guest id; progress lines go to stderr.
//!
//! The hot-add proxy runs as three job steps because only nexus-agentctl may hold the agent CA (#80):
//! `proxy-prepare` (snapshot, disks hot-added to the proxy, `<work_dir>/plan.json` for `nexus-agentctl
//! block-read`), the block read, then `proxy-finish` (always: disks detached, snapshot removed, the indexes the
//! block read wrote committed). One VM per job (`vms` holds exactly one UUID).

use anyhow::{bail, Context, Result};
use chunkstore::progress;
use chunkstore::{Options, Store};
use serde::Deserialize;
use serde_json::json;
use std::fs;
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use vmware::backup::{backup_vm, proxy_finish, proxy_prepare, ProxyState, Spec, Transport};
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
    /// `nfc` (no proxy VM) or `hotadd` (`proxy-prepare` / `proxy-finish`)
    #[serde(default = "nfc")]
    transport: String,
    /// hot-add: the proxy VM's UUID
    #[serde(default)]
    proxy: Option<String>,
    /// hot-add: the job's directory shared with the block read (`plan.json`, `state.json`, `<disk>.idx`)
    #[serde(default)]
    work_dir: Option<PathBuf>,
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

/// `committed <source>/<time> in <n>s: <VM name>`: the scheduler takes the snapshot from the first word, so nothing
/// may follow the time directly (#88: `…/<time>: name` dropped the snapshot from the job result).
fn committed(source: &str, time: u64, secs: u64, name: &str) -> String {
    format!("committed {source}/{time} in {secs}s: {name}")
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

fn main() -> Result<()> {
    keyd::deny_dumps();
    let args: Vec<String> = std::env::args().skip(1).collect();
    let usage = "usage: nexus-vmware <config.json> backup | inventory | check | proxy-prepare | proxy-finish";
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
        "proxy-prepare" => proxy_step(&cfg, true)?,
        "proxy-finish" => proxy_step(&cfg, false)?,
        _ => bail!("{usage}"),
    }
    Ok(())
}

/// `proxy-prepare` / `proxy-finish` of the one VM in `cfg.vms`; finish prints the same lines as `backup`.
fn proxy_step(cfg: &Config, prepare: bool) -> Result<()> {
    let dir = cfg.work_dir.as_ref().context("config: work_dir missing")?;
    let [uuid] = cfg.vms.as_slice() else {
        bail!("config: vms: the proxy transport backs up one VM per job");
    };
    if !valid_uuid(uuid) {
        bail!("config: vms: {uuid:?} is not a VM UUID");
    }
    let store = cfg.store()?;
    let c = cfg.client()?;
    let r = if prepare {
        let proxy = cfg.proxy.as_deref().context("config: proxy missing")?;
        fs::create_dir_all(dir).context("work_dir")?;
        let vms = c.vm_list()?;
        let find = |u: &str| vms.iter().find(|(_, v)| v.uuid == u).map(|(m, _)| m);
        let vm = find(uuid).with_context(|| format!("VM {uuid} not in the inventory of {}", cfg.host))?;
        let proxy = find(proxy).with_context(|| format!("proxy VM {proxy} not in the inventory"))?;
        let spec = Spec {
            vm,
            datacenter: &cfg.datacenter,
            job: cfg.job.unwrap_or_else(now),
            full: cfg.full_read,
        };
        proxy_prepare(&c, &store, &spec, proxy, &mut |l| println!("{l}")).and_then(|(state, plan)| {
            fs::write(dir.join("state.json"), serde_json::to_vec(&state)?)?;
            fs::write(dir.join("plan.json"), serde_json::to_vec(&plan)?)?;
            println!("prepared {} disk(s) of {}", plan.disks.len(), state.vm_name);
            Ok(())
        })
    } else {
        let source = source_name(uuid);
        let res = fs::read(dir.join("state.json"))
            .context("no state from proxy-prepare")
            .and_then(|b| Ok(serde_json::from_slice::<ProxyState>(&b)?))
            .and_then(|st| {
                let m = proxy_finish(&c, &store, &st, dir, &cfg.datacenter, &mut |l| println!("{l}"))?;
                Ok((st, m))
            });
        match res {
            Ok((st, m)) => {
                println!(
                    "{}",
                    committed(&m.source, m.time, now().saturating_sub(st.started), &st.vm_name)
                );
                let level = if st.quiesced { "application" } else { "crash" };
                println!("consistency {}/{}: {level}", m.source, m.time);
                println!(
                    "result {}",
                    json!({"source_id": cfg.source_id, "snapshots": [{"source": m.source, "time": m.time}], "failed": []})
                );
                Ok(())
            }
            Err(e) => {
                println!("failed {source}: {e:#}");
                println!(
                    "result {}",
                    json!({"source_id": cfg.source_id, "snapshots": [], "failed": [{"source": source, "error": format!("{e:#}")}]})
                );
                Err(e)
            }
        }
    };
    c.logout();
    r
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
                println!("{}", committed(&m.source, m.time, t0.elapsed().as_secs(), &info.name));
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

#[cfg(test)]
mod tests {
    #[test]
    fn committed_line_parses_like_the_scheduler() {
        let (src, time) = ("vmw-5010503d-a8fa-1617-640a-36b092405869", 1792837785);
        let l = super::committed(src, time, 20, "nx-cbt");
        // crates/scheduler lib.rs `result` / runctl.rs
        let id = l.strip_prefix("committed ").unwrap().split_whitespace().next().unwrap();
        let (s, t) = id.rsplit_once('/').unwrap();
        assert_eq!((s, t.parse::<u64>().unwrap()), (src, time));
    }
}
