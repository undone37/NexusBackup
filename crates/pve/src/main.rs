//! Dev CLI until the scheduler exists: `nexus-pve <config.json> backup <vmid> | backup-ct <vmid> | backup-all | restore <vmid> <time> <node> <target> <storage> [opts] | restore-ct <vmid> <time> <node> <target> <storage> [opts] | instant-recover <vmid> <time> <node> <target> <storage> [opts] [--no-start] | instant-disk <vmid> <time> <device> <node> <target> [--key <slot>] [--move-to <storage>] | ir-serve <node> <target> | dump <vmid> <time> <device> | files <vmid> <time> mounts|ls <path>|get <out> <path>...|index | ct-files <vmid> <time> ls [dir]|get <out> <path>...|index | scan <source> <time> <rules.json> [budget-secs] | restore-test <spec.json> | lab-check <spec.json> | push-index | list | inventory`.
//! `backup-all` backs up every guest in `vmids`, VM or container (type from /cluster/resources).

use anyhow::{bail, Context, Result};
use chunkstore::{progress, Options, Store};
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
    /// free-space thresholds of the fleecing storage (source `fleecing_guard`)
    #[serde(default)]
    fleecing_guard: pve::fleecing::Guard,
    #[serde(default)]
    nodes: BTreeMap<String, SshNode>,
    /// guests (VMs and containers) protected by `backup-all` (scheduled via systemd timer)
    #[serde(default)]
    vmids: Vec<u32>,
    /// `backup-all`: guests at once (group `parallel_guests`, 1..=8)
    #[serde(default = "one")]
    parallel: usize,
    /// VM devices not backed up, per vmid (`{"101": ["drive-scsi1"]}`, group `exclude_disks`)
    #[serde(default)]
    exclude_disks: BTreeMap<String, Vec<String>>,
    #[serde(default)]
    exclude_disks_mode: pve::exclude::Mode,
    /// appliance-side read limit of the source (Phase 22b)
    #[serde(default)]
    read_limit: Option<catalog::schedule::ReadLimit>,
    /// `backup-all`: per-source cap of `parallel` (source `max_parallel`, Phase 22b)
    #[serde(default)]
    max_parallel: Option<usize>,
    /// `backup-all`: at most this many guests at once with a disk on the storage (source `storage_caps`)
    #[serde(default)]
    storage_caps: std::collections::HashMap<String, usize>,
}

fn one() -> usize {
    1
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
        bail!("usage: nexus-pve <config.json> backup <vmid> | backup-ct <vmid> | backup-all | restore <vmid> <time> <node> <target> <storage> [opts] | restore-ct <vmid> <time> <node> <target> <storage> [opts] | instant-recover <vmid> <time> <node> <target> <storage> [opts] [--no-start] | instant-disk <vmid> <time> <device> <node> <target> [--key <slot>] [--move-to <storage>] | ir-serve <node> <target> | dump <vmid> <time> <device> | files <vmid> <time> mounts|ls <path>|get <out> <path>...|index | ct-files <vmid> <time> ls [dir]|get <out> <path>...|index | scan <source> <time> <rules.json> [budget-secs] | restore-test <spec.json> | lab-check <spec.json> | push-index | list | inventory | task-stop <upid> | p2v <req.json> <layout.json> | p2v-cleanup <node> <vmid> <volid>");
    };
    let cfg: Config = serde_json::from_slice(&fs::read(cfg_path)?).context("config")?;
    // P2V (docs/bmr.md): API only, no store or keys
    match (cmd.as_str(), rest) {
        ("p2v", [req, layout]) => {
            let a = api(cfg.api.context("p2v: this configuration has no PVE API")?)?;
            let req: pve::p2v::Req = serde_json::from_slice(&fs::read(req)?).context("p2v request")?;
            let l: agent_proto::layout::Layout = serde_json::from_slice(&fs::read(layout)?).context("layout")?;
            return pve::p2v::run(&a, &req, &l);
        }
        ("p2v-cleanup", [node, vmid, volid]) => {
            let a = api(cfg.api.context("p2v-cleanup: this configuration has no PVE API")?)?;
            return pve::p2v::cleanup(&a, node, vmid.parse()?, volid);
        }
        _ => {}
    }
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
        // opt-in YARA scan in the restore micro-VM (Phase 21e, any local snapshot)
        ("scan", [source, time, rules, budget @ ..]) if budget.len() <= 1 => {
            let budget = budget.first().map(|b| b.parse()).transpose()?;
            return pve::scan::cli(&store, source, time.parse()?, std::path::Path::new(rules), budget);
        }
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
    let mut exclude = BTreeMap::new();
    for (vmid, devices) in cfg.exclude_disks {
        exclude.insert(vmid.parse::<u32>().context("exclude_disks: vmid keys")?, devices);
    }
    let (store_root, keyd_socket, tenant) = (cfg.store.clone(), cfg.keyd_socket.clone(), cfg.tenant.clone());
    let cluster = Cluster {
        api,
        storage: cfg.storage,
        fleecing_storage: cfg.fleecing_storage,
        fleecing_guard: cfg.fleecing_guard,
        nodes: cfg.nodes,
        exclude,
        exclude_mode: cfg.exclude_disks_mode,
        read_limit: cfg.read_limit.as_ref().map(|r| r.throttle()).transpose()?.flatten(),
    };
    match (cmd.as_str(), rest) {
        ("backup", [vmid]) => {
            let t = std::time::Instant::now();
            let before = store.written();
            let (m, read) = cluster.backup_vm(&store, vmid.parse()?)?;
            println!(
                "committed {}/{} in {:.1?}, indexes {:?}",
                m.source,
                m.time,
                t.elapsed(),
                m.indexes
            );
            println!("{}", store.stats_line(&m, read, store.written().since(before))?);
            cluster.push_index(&store)?;
        }
        ("backup-ct", [vmid]) => {
            let t = std::time::Instant::now();
            let before = store.written();
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
            println!("{}", store.stats_line(&m, st.size, store.written().since(before))?);
            cluster.push_index(&store)?;
        }
        ("restore-ct", [vmid, time, node, target, storage, opts @ ..]) => {
            let opts = pve::restore::RestoreOpts::parse(opts)?;
            let r = cluster.restore_ct(
                &store,
                vmid.parse()?,
                time.parse()?,
                node,
                target.parse()?,
                storage,
                &opts,
            )?;
            println!("restored {}", serde_json::to_string(&r)?);
        }
        ("restore", [vmid, time, node, target, storage, opts @ ..]) => {
            let opts = pve::restore::RestoreOpts::parse(opts)?;
            let r = cluster.restore_vm(
                &store,
                vmid.parse()?,
                time.parse()?,
                node,
                target.parse()?,
                storage,
                &opts,
            )?;
            println!("restored {}", serde_json::to_string(&r)?);
        }
        ("instant-recover", [vmid, time, node, target, storage, opts @ ..]) => {
            // CLI default: start the VM (as before); `--no-start` creates it powered off
            let mut opts: Vec<String> = opts.to_vec();
            let no_start = opts.iter().any(|o| o == "--no-start");
            opts.retain(|o| o != "--no-start" && o != "--start");
            let mut opts = pve::restore::RestoreOpts::parse(&opts)?;
            opts.start = !no_start;
            let r = cluster.instant_recover(
                &store,
                vmid.parse()?,
                time.parse()?,
                node,
                target.parse()?,
                storage,
                &opts,
            )?;
            println!("VM running after {:.1?}", r.running_after);
            for (disk, d) in &r.moves {
                println!("{disk} moved in {d:.1?}");
            }
            if !r.move_errors.is_empty() {
                bail!("disk moves failed: {}", r.move_errors.join("; "));
            }
        }
        // instant disk recovery (Phase 22b): one disk attached to an existing VM
        ("instant-disk", [vmid, time, device, node, target, opts @ ..]) => {
            let (mut key, mut move_to) = (None, None);
            let mut it = opts.iter();
            while let Some(o) = it.next() {
                match o.as_str() {
                    "--key" => key = Some(it.next().context("--key <slot>")?.as_str()),
                    "--move-to" => move_to = Some(it.next().context("--move-to <storage>")?.as_str()),
                    x => bail!("instant-disk: unknown option {x}"),
                }
            }
            let r = cluster.instant_disk(
                &store,
                vmid.parse()?,
                time.parse()?,
                device,
                node,
                target.parse()?,
                key,
                move_to,
            )?;
            for (disk, d) in &r.moves {
                println!("{disk} moved in {d:.1?}");
            }
            if !r.move_errors.is_empty() {
                bail!("disk move failed: {}", r.move_errors.join("; "));
            }
        }
        // resume serving an instant recovery (e.g. after an appliance restart)
        ("ir-serve", [node, target]) => cluster.ir_resume(&store, node, target.parse()?)?,
        ("backup-all", []) => {
            // guest names for the live progress (`item 2/3: vm-101 dc1dev`); none when unreadable
            let names = cluster.guest_names().unwrap_or_default();
            // true = failed; every line is printed whole (parallel workers interleave lines only)
            let one = |store: &Store, vmid: u32| -> bool {
                let index = vmids.iter().position(|v| *v == vmid).map_or(0, |i| i + 1);
                let (item, label) = pve::backup::progress_item(vmid, &names);
                progress::start_item(&item, label, index as u32, vmids.len() as u32);
                let before = store.written();
                let failed = match cluster.backup_guest(store, vmid) {
                    Ok((m, read)) => {
                        println!("committed {}/{}", m.source, m.time);
                        match store.stats_line(&m, read, store.written().since(before)) {
                            Ok(l) => println!("{l}"),
                            Err(e) => eprintln!("stats of {}/{}: {e}", m.source, m.time),
                        }
                        false
                    }
                    Err(e) => {
                        eprintln!("backup of guest {vmid} failed: {e:#}");
                        true
                    }
                };
                progress::end_item(!failed);
                failed
            };
            let parallel = match cfg.max_parallel {
                Some(m) if m < cfg.parallel => {
                    println!(
                        "note: parallel guests capped at {m} by the source (group asks for {})",
                        cfg.parallel
                    );
                    m.max(1)
                }
                _ => cfg.parallel,
            };
            let failed: Vec<u32> = if parallel <= 1 || vmids.len() <= 1 {
                vmids.iter().copied().filter(|&vmid| one(&store, vmid)).collect()
            } else {
                let nodes = cluster.guest_nodes()?;
                let items: Vec<pve::parallel::Item<u32>> = vmids
                    .iter()
                    .map(|v| {
                        let node = nodes.get(v).map(|(n, _)| n.clone()).unwrap_or_default();
                        // per-storage caps need the guest's disks (one config read per guest)
                        let storages = match nodes.get(v) {
                            Some((n, kind)) if !cfg.storage_caps.is_empty() => cluster
                                .api
                                .guest_config(n, kind, *v)
                                .map(|c| pve::parallel::guest_storages(&c))
                                .unwrap_or_else(|e| {
                                    println!("note: storages of guest {v} unknown ({e:#}); not capped");
                                    Vec::new()
                                }),
                            _ => Vec::new(),
                        };
                        pve::parallel::Item {
                            item: *v,
                            node,
                            storages,
                        }
                    })
                    .collect();
                // each guest gets its own Store handle: `written()` deltas stay per snapshot
                let res = pve::parallel::run(&items, parallel.min(8), &cfg.storage_caps, |&vmid| {
                    let own = keyd::fetch_keyring(&keyd_socket, &tenant)
                        .context("keyd")
                        .and_then(|k| Ok(Store::open(&store_root, k, Options::default())?));
                    match own {
                        Ok(s) => one(&s, vmid),
                        Err(e) => {
                            eprintln!("backup of guest {vmid} failed: {e:#}");
                            true
                        }
                    }
                });
                vmids.iter().zip(res).filter(|(_, f)| *f).map(|(v, _)| *v).collect()
            };
            cluster.push_index(&store)?;
            if !failed.is_empty() {
                bail!("failed guests: {failed:?}");
            }
        }
        // restore tests / recovery plans (crates/pve/src/restoretest.rs): one `restore-test {json}` per guest
        ("restore-test", [spec]) => {
            let spec: pve::restoretest::Spec = serde_json::from_slice(&fs::read(spec)?).context("restore test spec")?;
            on_sigterm();
            let lab = pve::restoretest::PveLab {
                cluster: &cluster,
                store: &store,
                spec: &spec,
            };
            let out = pve::restoretest::run(&lab, &spec, &|r| {
                println!("restore-test {}", serde_json::to_string(r).unwrap_or_default());
            });
            let bad = out.iter().filter(|r| r.state != "passed").count();
            if bad > 0 {
                bail!("{bad} of {} guests did not pass", out.len());
            }
        }
        ("lab-check", [spec]) => {
            let spec: pve::restoretest::Spec = serde_json::from_slice(&fs::read(spec)?).context("restore test spec")?;
            println!("{}", pve::restoretest::lab_check(&cluster, &spec));
        }
        ("push-index", []) => cluster.push_index(&store)?,
        // a cancelled job's vzdump / restore task (the scheduler, crates/scheduler/src/run.rs)
        ("task-stop", [upid]) => cluster.api.stop_task(upid)?,
        _ => bail!("unknown command"),
    }
    Ok(())
}

/// SIGTERM (job cancelled) lets a restore test destroy its guests first.
fn on_sigterm() {
    extern "C" fn term(_: libc::c_int) {
        pve::restoretest::CANCEL.store(true, std::sync::atomic::Ordering::SeqCst);
    }
    // SAFETY: the handler only stores to an atomic (async-signal-safe)
    unsafe {
        libc::signal(libc::SIGTERM, term as extern "C" fn(libc::c_int) as libc::sighandler_t);
    }
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
        // the snapshot's name index for the file search (groups.index_files)
        ("index", rest) if rest.iter().all(|a| a == "hashes") => {
            let names = pve::files::index(r, !rest.is_empty())?;
            store.write_names(&m.source, m.time, &names)?;
            println!("{}", serde_json::json!({"entries": names.len(), "complete": true}));
        }
        ("get", [out, paths @ ..]) if !paths.is_empty() => {
            let out = std::path::Path::new(out);
            let fmt = pve::files::Format::from_path(out)?;
            let n = pve::files::extract(r, paths, fmt, fs::File::create_new(out)?)?;
            println!("{n} entries written to {}", out.display());
        }
        _ => bail!("ct-files <vmid> <time> ls [dir] | get <out.tar|out.zip> <path>... | index"),
    }
    Ok(())
}
