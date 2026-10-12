//! Dev CLI until the scheduler exists: `nexus-pve <config.json> backup <vmid> | backup-ct <vmid> | backup-all | restore <vmid> <time> <node> <target> <storage> | restore-ct <vmid> <time> <node> <target> <storage> | instant-recover <vmid> <time> <node> <target> <storage> [--link-down] | ir-serve <node> <target> | dump <vmid> <time> <device> | files <vmid> <time> mounts|ls <path>|get <out> <path>... | ct-files <vmid> <time> ls [dir]|get <out> <path>... | push-index | list | inventory`.
//! `backup-all` backs up every guest in `vmids`, VM or container (type from /cluster/resources).

use anyhow::{bail, Context, Result};
use chunkstore::{Options, Store};
use pve::api::{Api, ApiConfig};
use pve::backup::{Cluster, SshNode};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

#[derive(Deserialize)]
struct Config {
    store: PathBuf,
    tenant: String,
    keyd_socket: PathBuf,
    /// absent: store-only commands (`files`, `ct-files`, `dump`, `list`), e.g. for
    /// replicated snapshots on a secondary without a PVE source (docs/replication.md)
    api: Option<ApiFile>,
    #[serde(default)]
    storage: String,
    #[serde(default)]
    fleecing_storage: String,
    #[serde(default)]
    nodes: BTreeMap<String, SshNode>,
    /// guests (VMs and containers) protected by `backup-all` (scheduled via systemd timer)
    #[serde(default)]
    vmids: Vec<u32>,
}

#[derive(Deserialize)]
struct ApiFile {
    host: String,
    port: u16,
    connect_addr: Option<std::net::SocketAddr>,
    ca_pem_file: PathBuf,
    token_id: String,
    token_secret_file: PathBuf,
}

fn main() -> Result<()> {
    keyd::deny_dumps();
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [cfg_path, cmd, rest @ ..] = args.as_slice() else {
        bail!("usage: nexus-pve <config.json> backup <vmid> | backup-ct <vmid> | backup-all | restore <vmid> <time> <node> <target> <storage> | restore-ct <vmid> <time> <node> <target> <storage> | instant-recover <vmid> <time> <node> <target> <storage> [--link-down] | ir-serve <node> <target> | dump <vmid> <time> <device> | files <vmid> <time> mounts|ls <path>|get <out> <path>... | ct-files <vmid> <time> ls [dir]|get <out> <path>... | push-index | list | inventory");
    };
    let cfg: Config = serde_json::from_slice(&fs::read(cfg_path)?).context("config")?;
    if let ("inventory", []) = (cmd.as_str(), rest) {
        // the cluster's guests (auto-protect, docs/control-plane.md): API only, no store or keys
        let a = cfg.api.context("inventory: this configuration has no PVE API")?;
        println!("{}", pve::inventory::list(&api(a)?)?);
        return Ok(());
    }
    let keys = keyd::fetch_keyring(&cfg.keyd_socket, &cfg.tenant).context("keyd")?;
    let store = Store::open(&cfg.store, keys, Options::default())?;
    match (cmd.as_str(), rest) {
        ("ct-files", [vmid, time, cmd, args @ ..]) => return ct_files(&store, vmid, time, cmd, args),
        ("dump", [vmid, time, device]) => {
            // raw device image of a snapshot to stdout (verification / download restore)
            let m = store.load_manifest(&pve::backup::source_name(vmid.parse()?), time.parse()?)?;
            let idx = store.load_index(&m, device)?;
            return store
                .write_chunks(idx.chunk_ids(), std::io::BufWriter::new(std::io::stdout().lock()))
                .map_err(Into::into);
        }
        ("files", [vmid, time, args @ ..]) => return pve::restorevm::cli(&store, vmid.parse()?, time.parse()?, args),
        ("list", []) => {
            println!("{}", serde_json::to_string_pretty(&pve::backup::build_index(&store)?)?);
            return Ok(());
        }
        _ => {}
    }
    let Some(a) = cfg.api else {
        bail!("{cmd}: this configuration has no PVE API (store-only)");
    };
    let api = api(a)?;
    let vmids = cfg.vmids.clone();
    let cluster = Cluster {
        api,
        storage: cfg.storage,
        fleecing_storage: cfg.fleecing_storage,
        nodes: cfg.nodes,
    };
    match (cmd.as_str(), rest) {
        ("backup", [vmid]) => {
            let t = std::time::Instant::now();
            let m = cluster.backup_vm(&store, vmid.parse()?)?;
            println!(
                "committed {}/{} in {:.1?}, indexes {:?}",
                m.source,
                m.time,
                t.elapsed(),
                m.indexes
            );
            cluster.push_index(&store)?;
        }
        ("backup-ct", [vmid]) => {
            let t = std::time::Instant::now();
            let (m, st) = cluster.backup_ct(&store, vmid.parse()?)?;
            println!(
                "committed {}/{} in {:.1?}: tar stream {} bytes, {} chunks, {} new chunks ({} bytes new)",
                m.source,
                m.time,
                t.elapsed(),
                st.size,
                st.chunks.len(),
                st.new_chunks,
                st.new_bytes
            );
            cluster.push_index(&store)?;
        }
        ("restore-ct", [vmid, time, node, target, storage]) => {
            let exit = cluster.restore_ct(&store, vmid.parse()?, time.parse()?, node, target.parse()?, storage)?;
            println!("restore finished: {exit}");
        }
        ("restore", [vmid, time, node, target, storage]) => {
            let exit = cluster.restore_vm(&store, vmid.parse()?, time.parse()?, node, target.parse()?, storage)?;
            println!("restore finished: {exit}");
        }
        ("instant-recover", [vmid, time, node, target, storage, opts @ ..]) => {
            let link_down = match opts {
                [] => false,
                [o] if o == "--link-down" => true,
                _ => bail!("instant-recover: unknown options {opts:?}"),
            };
            let r = cluster.instant_recover(
                &store,
                vmid.parse()?,
                time.parse()?,
                node,
                target.parse()?,
                storage,
                link_down,
            )?;
            println!("VM running after {:.1?}", r.running_after);
            for (disk, d) in &r.moves {
                println!("{disk} moved in {d:.1?}");
            }
            if !r.move_errors.is_empty() {
                bail!("disk moves failed: {}", r.move_errors.join("; "));
            }
        }
        // resume serving an instant recovery (e.g. after an appliance restart)
        ("ir-serve", [node, target]) => cluster.ir_resume(&store, node, target.parse()?)?,
        ("backup-all", []) => {
            // ponytail: sequential, one guest at a time; parallel per node when windows get tight
            let failed: Vec<u32> = vmids
                .iter()
                .copied()
                .filter(|&vmid| match cluster.backup_guest(&store, vmid) {
                    Ok(m) => {
                        println!("committed {}/{}", m.source, m.time);
                        false
                    }
                    Err(e) => {
                        eprintln!("backup of guest {vmid} failed: {e:#}");
                        true
                    }
                })
                .collect();
            cluster.push_index(&store)?;
            if !failed.is_empty() {
                bail!("failed guests: {failed:?}");
            }
        }
        ("push-index", []) => cluster.push_index(&store)?,
        _ => bail!("unknown command"),
    }
    Ok(())
}

fn api(a: ApiFile) -> Result<Api> {
    Api::new(&ApiConfig {
        host: a.host,
        port: a.port,
        connect_addr: a.connect_addr,
        ca_pem: fs::read(&a.ca_pem_file)?,
        token_id: a.token_id,
        token_secret: fs::read_to_string(&a.token_secret_file)?.trim().to_owned(),
    })
}

fn ct_files(store: &Store, vmid: &str, time: &str, cmd: &str, args: &[String]) -> Result<()> {
    let m = store.load_manifest(&format!("ct-{vmid}"), time.parse()?)?;
    let root = pve::ct::root_tar(store, &m)?;
    let r = store.chunk_reader(&root.chunks);
    match (cmd, args) {
        ("ls", [dir]) => println!("{}", serde_json::to_string_pretty(&pve::files::list(r, dir)?)?),
        ("ls", []) => println!("{}", serde_json::to_string_pretty(&pve::files::list(r, "")?)?),
        ("get", [out, paths @ ..]) if !paths.is_empty() => {
            let out = std::path::Path::new(out);
            let fmt = pve::files::Format::from_path(out)?;
            let n = pve::files::extract(r, paths, fmt, fs::File::create_new(out)?)?;
            println!("{n} entries written to {}", out.display());
        }
        _ => bail!("ct-files <vmid> <time> ls [dir] | get <out.tar|out.zip> <path>..."),
    }
    Ok(())
}
