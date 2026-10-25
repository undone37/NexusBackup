//! VM backup orchestration and the shared catalog (contract: docs/pve-connector.md).
//! Containers: `crate::ct`.

use crate::api::Api;
use crate::exclude::{self, Excluded};
use crate::fleecing::{self, Level};
use anyhow::{bail, Context, Result};
use chunkstore::drift::{self, Drift};
use chunkstore::progress::Meter;
use chunkstore::store::IMAGE_CHUNK_SIZE;
use chunkstore::{FileEntry, Index, Manifest, Store};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufReader, BufWriter, Write};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

#[derive(Deserialize, Clone)]
pub struct SshNode {
    pub host: String,
    pub port: u16,
    pub key: PathBuf,
    pub known_hosts: PathBuf,
}

impl SshNode {
    /// `ssh nexusbackup@node <cmd>`; the forced command on the node ignores
    /// everything but `SSH_ORIGINAL_COMMAND`. Host keys are pinned via known_hosts.
    pub fn cmd(&self, args: &str) -> Command {
        let mut c = Command::new("ssh");
        c.arg("-i")
            .arg(&self.key)
            .arg("-p")
            .arg(self.port.to_string())
            .args([
                "-o",
                "BatchMode=yes",
                "-o",
                "IdentitiesOnly=yes",
                "-o",
                "StrictHostKeyChecking=yes",
            ])
            .arg("-o")
            .arg(format!("UserKnownHostsFile={}", self.known_hosts.display()))
            .args(["-o", "ServerAliveInterval=15", "-T"])
            .arg(format!("nexusbackup@{}", self.host))
            .arg(args);
        c
    }

    pub(crate) fn run(&self, args: &str, stdin: Option<&[u8]>) -> Result<Vec<u8>> {
        let mut child = self
            .cmd(args)
            .stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("spawn ssh")?;
        if let Some(data) = stdin {
            child.stdin.take().unwrap().write_all(data)?;
        }
        let out = child.wait_with_output()?;
        if !out.status.success() {
            bail!(
                "ssh {}: {} {}",
                args,
                out.status,
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        Ok(out.stdout)
    }
}

pub struct Cluster {
    pub api: Api,
    pub storage: String,
    pub fleecing_storage: String,
    pub fleecing_guard: fleecing::Guard,
    /// PVE node name -> SSH endpoint
    pub nodes: BTreeMap<String, SshNode>,
    /// VM devices not backed up (`drive-scsi1`), per vmid (group `exclude_disks`)
    pub exclude: BTreeMap<u32, Vec<String>>,
    pub exclude_mode: exclude::Mode,
    /// appliance-side read limit of the source (Phase 22b), shared by all guests of the run
    pub read_limit: Option<std::sync::Arc<catalog::schedule::Throttle>>,
    /// VMs due for a scheduled full read (Phase 29, pve.json `full_read`): read every
    /// disk in full, compare with the base where PVE reused its dirty bitmap
    pub full_read: BTreeSet<u32>,
}

#[derive(Deserialize)]
pub(crate) struct Job {
    /// "qemu" or "lxc" (absent in VM jobs of older plugins)
    #[serde(rename = "type", default = "qemu")]
    pub kind: String,
    pub archive: String,
    #[serde(default)]
    devices: Vec<Device>,
    /// VM only; containers send pct.conf in-band
    #[serde(default)]
    config: String,
    pub firewall: Option<String>,
}

fn qemu() -> String {
    "qemu".into()
}

impl Job {
    /// Snapshot time = the `<unixtime>` of `nexus-<vmid>-<unixtime>`.
    pub fn time(&self) -> Result<u64> {
        self.archive
            .rsplit('-')
            .next()
            .and_then(|t| t.parse().ok())
            .context("archive name without time")
    }
}

#[derive(Deserialize)]
struct Device {
    name: String,
    size: u64,
    bitmap_mode: String,
    bitmap_name: Option<String>,
}

/// The pre-rollback backup would read these disks in full (no reusable dirty bitmap).
#[derive(Debug)]
pub struct BitmapGone(pub String);

impl std::fmt::Display for BitmapGone {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "no reusable dirty bitmap for {}", self.0)
    }
}

impl std::error::Error for BitmapGone {}

pub fn source_name(vmid: u32) -> String {
    format!("vm-{vmid}")
}

/// Live progress item of a guest: its snapshot source (`vm-101` / `ct-200`)
/// and name, from [`Cluster::guest_names`] (unknown guests count as VMs).
pub fn progress_item(vmid: u32, names: &BTreeMap<u32, (String, String)>) -> (String, Option<&str>) {
    match names.get(&vmid) {
        Some((kind, name)) => (format!("{kind}-{vmid}"), Some(name.as_str()).filter(|n| !n.is_empty())),
        None => (source_name(vmid), None),
    }
}

impl Cluster {
    /// Active vzdump tasks of `vmid` on `node` that the token of `ours` started before it ([`stale_of`]);
    /// none when the task list cannot be read.
    fn stale_tasks(&self, node: &str, vmid: u32, ours: &str) -> Vec<String> {
        self.api
            .get(&format!(
                "/nodes/{node}/tasks?source=active&typefilter=vzdump&vmid={vmid}"
            ))
            .map(|v| stale_of(&v, vmid, ours))
            .unwrap_or_default()
    }

    /// (node, type) of a guest; type is "qemu" or "lxc".
    pub fn guest(&self, vmid: u32) -> Result<(String, String)> {
        let res = self.api.get("/cluster/resources?type=vm")?;
        res.as_array()
            .into_iter()
            .flatten()
            .find(|r| r["vmid"].as_u64() == Some(vmid as u64))
            .and_then(|r| Some((r["node"].as_str()?.to_owned(), r["type"].as_str()?.to_owned())))
            .with_context(|| format!("guest {vmid} not found in cluster"))
    }

    /// (`vm` | `ct`, name) of every guest of the cluster (one `/cluster/resources`
    /// call; live progress labels).
    pub fn guest_names(&self) -> Result<BTreeMap<u32, (String, String)>> {
        let res = self.api.get("/cluster/resources?type=vm")?;
        Ok(res
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|r| {
                let kind = if r["type"].as_str()? == "lxc" { "ct" } else { "vm" };
                Some((
                    u32::try_from(r["vmid"].as_u64()?).ok()?,
                    (kind.to_owned(), r["name"].as_str().unwrap_or_default().to_owned()),
                ))
            })
            .collect())
    }

    /// (node, type) of every guest of the cluster (one `/cluster/resources` call).
    pub fn guest_nodes(&self) -> Result<BTreeMap<u32, (String, String)>> {
        let res = self.api.get("/cluster/resources?type=vm")?;
        Ok(res
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|r| {
                Some((
                    u32::try_from(r["vmid"].as_u64()?).ok()?,
                    (r["node"].as_str()?.to_owned(), r["type"].as_str()?.to_owned()),
                ))
            })
            .collect())
    }

    /// Backs up a VM or a container, whichever `vmid` is. Returns the manifest
    /// and the bytes read from the guest.
    pub fn backup_guest(&self, store: &Store, vmid: u32) -> Result<(Manifest, u64)> {
        match self.guest(vmid)?.1.as_str() {
            "qemu" => self.backup_vm(store, vmid),
            "lxc" => {
                if self.exclude.get(&vmid).is_some_and(|x| !x.is_empty()) {
                    println!("note: excluded disks do not apply to container {vmid} (set backup=0 on mount points)");
                }
                if self.full_read.contains(&vmid) {
                    println!(
                        "note: full read does not apply to container {vmid} (every container backup reads all files)"
                    );
                }
                self.backup_ct(store, vmid).map(|(m, st)| (m, st.size))
            }
            t => bail!("guest {vmid} has unsupported type {t}"),
        }
    }

    pub(crate) fn ssh(&self, node: &str) -> Result<&SshNode> {
        self.nodes
            .get(node)
            .with_context(|| format!("no SSH endpoint configured for node {node}"))
    }

    /// One full backup run of a VM. The snapshot is committed before the node is
    /// told `done ok`, because QEMU commits the dirty bitmap when backup_vm returns.
    /// Returns the manifest and the bytes read over NBD (dirty extents only when incremental).
    pub fn backup_vm(&self, store: &Store, vmid: u32) -> Result<(Manifest, u64)> {
        self.backup_vm_with(store, vmid, false)
    }

    /// [`Cluster::backup_vm`]; `require_bitmap` (Phase 30, the pre-rollback backup):
    /// refused with [`BitmapGone`] before anything is read unless PVE reuses the
    /// dirty bitmap of every disk (the vzdump task then fails, nothing is committed).
    pub fn backup_vm_with(&self, store: &Store, vmid: u32, require_bitmap: bool) -> Result<(Manifest, u64)> {
        let (node, kind) = self.guest(vmid)?;
        if kind != "qemu" {
            bail!("guest {vmid} is not a VM ({kind})");
        }
        let ssh = self.ssh(&node)?;
        // The node decides incremental vs. full (bitmap reuse) from its copy of
        // the index; a stale one (new/replaced store, retention since the last
        // push) would make PVE reuse a bitmap whose base snapshot is gone.
        ssh.run(
            &format!("put-index {}", self.storage),
            Some(&serde_json::to_vec(&build_index(store)?)?),
        )
        .with_context(|| format!("push index to {node}"))?;
        self.check_fleecing(&node)?;
        let fleecing = format!("enabled=1,storage={}", self.fleecing_storage);
        let upid = self.api.start_backup(&node, vmid, &self.storage, Some(&fleecing))?;
        // the fleecing storage is watched while the guest runs; critical = vzdump stopped
        let stop = AtomicBool::new(false);
        let (pulled, tripped) = std::thread::scope(|sc| {
            let watcher = sc.spawn(|| self.watch_fleecing(&node, &upid, &stop));
            let pulled = self.wait_job(&node, ssh, vmid, &upid, "qemu").and_then(|job| {
                let result = self.pull(store, ssh, vmid, &job, require_bitmap);
                let done = match &result {
                    Ok(_) => "ok".to_owned(),
                    Err(e) => format!("fail {}", e.to_string().replace(['\n', '\''], " ")),
                };
                let signalled = ssh.run(&format!("done {vmid} {done}"), None);
                // the node never heard about the failure (the SSH session broke, e.g. a network outage): its
                // vzdump task would keep the guest's backup lock up to the plugin's job timeout (lab 2026-10-23)
                if result.is_err() && signalled.is_err() {
                    let _ = self.api.stop_task(&upid);
                }
                let manifest = result?;
                signalled?;
                Ok(manifest)
            });
            stop.store(true, Ordering::SeqCst);
            (pulled, watcher.join().unwrap_or(None))
        });
        let manifest = match (pulled, tripped) {
            (Err(e), Some(why)) => {
                bail!(
                    "fleecing storage {} on node {node}: {why} ({e:#})",
                    self.fleecing_storage
                )
            }
            (r, _) => r?,
        };
        let exit = self.api.wait_task(&node, &upid, Duration::from_secs(3600))?;
        if exit != "OK" {
            // ponytail: snapshot is kept (bitmap already committed); alerting comes with the scheduler
            eprintln!("warning: vzdump task for VM {vmid} ended with {exit}; snapshot kept");
        }
        let log = self.api.task_log(&node, &upid).unwrap_or_default();
        let level = crate::consistency::vm_level(&log);
        println!(
            "{}",
            crate::consistency::line(&source_name(vmid), manifest.0.time, level)
        );
        Ok(manifest)
    }

    /// Before a VM: its node's fleecing storage must have room (fleecing.rs);
    /// an unreadable status is not guarded.
    fn check_fleecing(&self, node: &str) -> Result<()> {
        let (fl, g) = (&self.fleecing_storage, &self.fleecing_guard);
        if fl.is_empty() {
            return Ok(());
        }
        let s = match fleecing::space(&self.api, node, fl) {
            Ok(s) => s,
            Err(e) => {
                println!("note: fleecing storage {fl} on node {node}: free space unknown ({e:#}); not guarded");
                return Ok(());
            }
        };
        let level = g.level(&s);
        fleecing::report(node, fl, &s, level);
        if level != Level::Ok {
            bail!(
                "fleecing storage {fl} on node {node} has {}, below the guard ({} % or {} GiB free, whichever is smaller): guest skipped",
                g.describe(&s),
                g.min_free_pct,
                g.min_free_gib
            );
        }
        Ok(())
    }

    /// While a VM backup runs: stops its vzdump task when the fleecing storage
    /// drops below the critical level; returns why.
    fn watch_fleecing(&self, node: &str, upid: &str, stop: &AtomicBool) -> Option<String> {
        let (fl, g) = (&self.fleecing_storage, self.fleecing_guard);
        if fl.is_empty() {
            return None;
        }
        g.watch(
            Duration::from_secs(g.interval_secs.max(5)),
            stop,
            || {
                let s = fleecing::space(&self.api, node, fl)?;
                let level = g.level(&s);
                if level != Level::Ok {
                    fleecing::report(node, fl, &s, level);
                }
                Ok((s, level))
            },
            || {
                eprintln!("fleecing storage {fl} on node {node} below the critical level: stopping {upid}");
                if let Err(e) = self.api.stop_task(upid) {
                    eprintln!("task-stop {upid}: {e:#}");
                }
            },
        )
    }

    /// Polls `job <vmid>` until the plugin published the job of the running vzdump task.
    /// The node's job of this backup's vzdump task `upid` (refused: the job of an older task).
    pub(crate) fn wait_job(&self, node: &str, ssh: &SshNode, vmid: u32, upid: &str, kind: &str) -> Result<Job> {
        loop {
            if let Some(exit) = self.api.task_status(node, upid)? {
                let log = self.api.task_log(node, upid).unwrap_or_default();
                bail!("vzdump ended ({exit}) before the job was ready: {}", log.join("\n"));
            }
            if let Ok(out) = ssh.run(&format!("job {vmid}"), None) {
                let job = serde_json::from_slice::<Job>(&out).context("job JSON")?;
                if job.kind != kind {
                    bail!("node published a {} job for {vmid}, expected {kind}", job.kind);
                }
                // The job of another vzdump task of this guest (one whose appliance went away
                // still holds the guest's backup lock; found on the PVE lab host): serving it
                // would end that task and leave ours waiting for us forever. Ours sets the
                // archive time when its backup starts, after the lock: never before the task.
                if let Some(start) = upid_start(upid) {
                    if job.time()? < start {
                        let _ = self.api.stop_task(upid);
                        // A task of an interrupted run of this appliance (same token, e.g. a reboot during the
                        // backup) waits up to the plugin's job timeout (6 h): stop it, so the retry goes through
                        // (lab 2026-10-23). Tasks of other users are left alone.
                        let stale = self.stale_tasks(node, vmid, upid);
                        if !stale.is_empty() {
                            for s in &stale {
                                let _ = self.api.stop_task(s);
                            }
                            bail!(
                                "guest {vmid} on node {node} was still held by a backup task of an interrupted run \
                                 of this appliance (job {}): stopped it ({}); the next attempt backs the guest up",
                                job.archive,
                                stale.join(", ")
                            );
                        }
                        bail!(
                            "another backup task of guest {vmid} on node {node} still waits for an appliance (job {}, \
                             published before this backup started): stop that vzdump task in the Proxmox VE task \
                             list, then back up again",
                            job.archive
                        );
                    }
                }
                return Ok(job);
            }
            std::thread::sleep(Duration::from_secs(1));
        }
    }

    fn pull(
        &self,
        store: &Store,
        ssh: &SshNode,
        vmid: u32,
        job: &Job,
        require_bitmap: bool,
    ) -> Result<(Manifest, u64)> {
        let time = job.time()?;
        let source = source_name(vmid);
        let prev = store.list_snapshots()?.into_iter().rfind(|m| m.source == source);
        if require_bitmap {
            let excluded = self.exclude.get(&vmid).map(Vec::as_slice).unwrap_or_default();
            let fresh: Vec<&str> = job
                .devices
                .iter()
                .filter(|d| !excluded.contains(&d.name))
                .filter(|d| d.bitmap_mode != "reuse" || !prev.as_ref().is_some_and(|m| m.indexes.contains(&d.name)))
                .map(|d| d.name.as_str())
                .collect();
            if !fresh.is_empty() {
                return Err(anyhow::Error::new(BitmapGone(fresh.join(", "))));
            }
        }
        // build_index hid its devices from the node (fresh bitmaps); a reuse now is a stale node index
        let prev_damaged = prev.as_ref().map(|m| store.is_damaged(m)).transpose()?.unwrap_or(false);
        // VM identity (Phase 22b): a changed vmgenid / SMBIOS UUID means the VMID now
        // belongs to another VM (deleted and re-created, or restored over)
        let prev_conf = match &prev {
            Some(m) => read_config(store, m, "qemu-server.conf")?,
            None => None,
        };
        let (mut names, mut indexes, mut read) = (Vec::new(), Vec::new(), 0);
        let backup_off = exclude::backup_off(&job.config);
        for key in &backup_off {
            println!("disk {key} of VM {vmid} has backup=0: skipped by PVE");
        }
        let excluded = self.exclude.get(&vmid).map(Vec::as_slice).unwrap_or_default();
        let parts = job.devices.iter().filter(|d| !excluded.contains(&d.name)).count() as u32;
        let mut part = 0;
        // Phase 29: per-chunk comparison with the base of every disk whose bitmap was reused
        let force = self.full_read.contains(&vmid);
        let mut drift = Drift::new("dirty-bitmap", prev.as_ref().map(|m| m.time));
        let mut compared = false;
        let mut skipped = Excluded {
            mode: self.exclude_mode,
            disks: Vec::new(),
        };
        for dev in &job.devices {
            if excluded.contains(&dev.name) {
                let key = exclude::disk_key(&dev.name).to_owned();
                println!("excluded disk {key} of VM {vmid} ({} bytes): not backed up", dev.size);
                skipped.disks.push(exclude::Disk {
                    device: dev.name.clone(),
                    key,
                    size: dev.size,
                });
                continue;
            }
            let base = match (dev.bitmap_mode.as_str(), &prev) {
                ("reuse", Some(_)) if prev_damaged => {
                    bail!(
                        "{}: the base snapshot references bad chunks (verify), but PVE reuses its dirty bitmap",
                        dev.name
                    )
                }
                ("reuse", Some(m)) if m.indexes.contains(&dev.name) => Some(store.load_index(m, &dev.name)?),
                ("reuse", _) => bail!("{}: PVE reuses a dirty bitmap but no base snapshot exists", dev.name),
                _ => None,
            };
            part += 1;
            let at = (part, parts);
            let (idx, n, reported) = pull_device(
                store,
                ssh,
                vmid,
                dev,
                base.as_ref(),
                self.read_limit.as_deref(),
                at,
                force,
            )
            .with_context(|| format!("device {}", dev.name))?;
            if let (Some(r), Some(b)) = (reported, &base) {
                drift::fixed(&mut drift, b, &idx, &r, &dev.name);
                compared = true;
            }
            read += n;
            names.push(dev.name.as_str());
            indexes.push(idx);
        }
        let mut entries = vec![config_entry(store, "qemu-server.conf", &job.config)?];
        if let Some(fw) = &job.firewall {
            entries.push(config_entry(store, "firewall.fw", fw)?);
        }
        if !skipped.disks.is_empty() {
            entries.push(config_entry(store, exclude::FILE, &serde_json::to_string(&skipped)?)?);
        }
        names.push("config");
        indexes.push(Index::Dynamic { entries });
        let refs: Vec<(&str, Index)> = names.into_iter().zip(indexes).collect();
        let m = store.commit_snapshot(&source, time, &refs)?;
        // not an error (the admin's PVE setting), but never a silent "ok": the scheduler
        // turns this line into a backup warning (dashboard, job state)
        if !backup_off.is_empty() {
            println!(
                "warnings {source}/{time}: {} disk(s) not in the snapshot, Proxmox VE option backup=0: {}",
                backup_off.len(),
                backup_off.join(", ")
            );
        }
        let id = Identity::of(&job.config);
        let previous = prev_conf.as_deref().map(Identity::of);
        let changed = previous.as_ref().is_some_and(|p| id.differs(p));
        if changed {
            println!(
                "warning: VM {vmid} has a new identity (vmgenid / SMBIOS UUID changed): the VMID was reused or the VM was replaced; this snapshot starts a new chain"
            );
        }
        println!(
            "identity {source}/{time} {}",
            serde_json::json!({"vmgenid": id.vmgenid, "smbios_uuid": id.smbios_uuid, "changed": changed,
                               "previous": if changed { serde_json::to_value(&previous).unwrap_or_default() } else { serde_json::Value::Null }})
        );
        if force {
            println!("{}", if compared { drift } else { Drift::none() }.line(&source, time));
        }
        Ok((m, read))
    }

    /// Full restore of snapshot `vm-<vmid>/<time>` as VM `target` on `node` with
    /// the options of `crate::restore`. PVE pulls each disk through `qemu-nbd` on
    /// the node; we serve it over `ssh restore-serve`.
    #[allow(clippy::too_many_arguments)]
    pub fn restore_vm(
        &self,
        store: &Store,
        vmid: u32,
        time: u64,
        node: &str,
        target: u32,
        target_storage: &str,
        opts: &crate::restore::RestoreOpts,
    ) -> Result<crate::restore::Restored> {
        let m = store.load_manifest(&source_name(vmid), time)?;
        let conf = read_config(store, &m, "qemu-server.conf")?.unwrap_or_default();
        let ssh = self.ssh(node)?;
        let archive = format!("nexus-{vmid}-{time}");
        let volid = format!("{}:backup/{archive}", self.storage);
        let name = crate::restore::conf_value(&conf, "name");
        let stamp = crate::restore::stamp(crate::restore::unix_now());
        crate::restore::run(
            self,
            "qemu",
            node,
            target,
            vmid,
            &volid,
            target_storage,
            name.as_deref(),
            opts,
            &stamp,
            |params| {
                let upid = self.api.start_restore(node, "qemu", params)?;
                self.serve_restore(store, &m, ssh, node, &archive, &upid, &BTreeMap::new())
            },
        )
    }

    /// Restore of a VMware VM snapshot `vmw-<uuid>/<time>` (#34) or an XCP-ng one `xcp-<uuid>/<time>` (#40) as PVE
    /// VM `target` on `node` (crate::fromvmware): the `.vmx` (or `xcpng.json`) becomes the configuration, the disk
    /// indexes PVE drives; a temporary archive `nexus-<target>-<time>` in the nodes' index.json carries both while
    /// PVE restores. `bridge`: the NICs' bridge. No replace or rollback: there is no PVE original.
    #[allow(clippy::too_many_arguments)]
    pub fn restore_vmware(
        &self,
        store: &Store,
        source: &str,
        time: u64,
        node: &str,
        target: u32,
        target_storage: &str,
        bridge: &str,
        opts: &crate::restore::RestoreOpts,
    ) -> Result<crate::restore::Restored> {
        use crate::fromvmware::{vmx_from_xcpng, VMX_FILE, XCPNG_FILE};
        if opts.replace || opts.rollback {
            bail!("replace / rollback: a VMware or XCP-ng snapshot has no Proxmox VE original to replace");
        }
        let m = store.load_manifest(source, time)?;
        let file = if source.starts_with("xcp-") {
            XCPNG_FILE
        } else {
            VMX_FILE
        };
        let cfg =
            read_config(store, &m, file)?.with_context(|| format!("{source}/{time}: no {file} in the snapshot"))?;
        let vmx = if file == XCPNG_FILE {
            vmx_from_xcpng(&serde_json::from_str(&cfg).context(XCPNG_FILE)?)
        } else {
            cfg
        };
        let mut disks = Vec::new();
        for name in m.indexes.iter().filter(|n| *n != "config") {
            if let Index::Fixed { size, .. } = store.load_index(&m, name)? {
                disks.push(crate::fromvmware::VmDisk {
                    index: name.clone(),
                    size,
                });
            }
        }
        let conv = crate::fromvmware::convert(&vmx, &disks, target, target_storage, bridge)?;
        for n in &conv.notes {
            println!("note: {n}");
        }
        let archive = format!("nexus-{target}-{time}");
        let volid = format!("{}:backup/{archive}", self.storage);
        // ponytail: a regular index push (another backup finishing) in the seconds between this push and PVE
        // reading the entry (restore_vm_init) drops it and fails the restore; a retry works. A lock shared with
        // the index pushes would close that window.
        let mut index = build_index(store)?;
        let entry = CatalogArchive {
            volname: format!("backup/{archive}"),
            vmid: target,
            kind: "qemu",
            ctime: time,
            size: conv.devices.iter().map(|d| d.2).sum(),
            devices: conv.devices.iter().map(|d| d.0.clone()).collect(),
            device_sizes: conv.devices.iter().map(|d| (d.0.clone(), d.2)).collect(),
            config: conv.conf.clone(),
            firewall: None,
            notes: format!("restored from snapshot {source}/{time}"),
            protected: false,
        };
        index["archives"]
            .as_array_mut()
            .context("index without archives")?
            .push(serde_json::to_value(&entry)?);
        self.push_index_value(&index)?;
        let map: BTreeMap<String, String> = conv.devices.iter().map(|d| (d.0.clone(), d.1.clone())).collect();
        let ssh = self.ssh(node)?;
        let stamp = crate::restore::stamp(crate::restore::unix_now());
        let r = crate::restore::run(
            self,
            "qemu",
            node,
            target,
            target,
            &volid,
            target_storage,
            Some(&conv.name),
            opts,
            &stamp,
            |params| {
                let upid = self.api.start_restore(node, "qemu", params)?;
                self.serve_restore(store, &m, ssh, node, &archive, &upid, &map)
            },
        );
        // the temporary archive leaves the catalog again (also after a failure)
        if let Err(e) = self.push_index(store) {
            eprintln!("warning: removing the temporary archive {archive} from the nodes' catalog failed: {e:#}");
        }
        r
    }

    /// `map`: PVE device -> snapshot index, for snapshots whose index names are not PVE device names (VMware).
    #[allow(clippy::too_many_arguments)]
    fn serve_restore(
        &self,
        store: &Store,
        m: &Manifest,
        ssh: &SshNode,
        node: &str,
        archive: &str,
        upid: &str,
        map: &BTreeMap<String, String>,
    ) -> Result<()> {
        let excluded = read_excluded(store, m)?;
        let mut served = std::collections::HashSet::new();
        loop {
            if let Some(exit) = self.api.task_status(node, upid)? {
                if exit != "OK" {
                    let log = self.api.task_log(node, upid).unwrap_or_default();
                    bail!("restore task ended with {exit}: {}", log.join("\n"));
                }
                return Ok(());
            }
            let Ok(out) = ssh.run(&format!("restore-job {archive}"), None) else {
                std::thread::sleep(Duration::from_secs(1));
                continue;
            };
            let req: serde_json::Value = serde_json::from_slice(&out).context("restore job JSON")?;
            let device = req["device"].as_str().context("restore job without device")?.to_owned();
            if !served.insert(device.clone()) {
                std::thread::sleep(Duration::from_secs(1)); // previous serve of this device still finishing
                continue;
            }
            if device == "config" {
                bail!("snapshot has no device {device}");
            }
            if let Some(index) = map.get(&device) {
                let idx = store.load_index(m, index)?;
                let at = (served.len() as u32, map.len() as u32);
                serve_device(store, ssh, archive, &device, &idx, at)
                    .with_context(|| format!("serve {device} ({index})"))?;
                continue;
            }
            if !map.is_empty() {
                bail!("snapshot has no device {device}");
            }
            if !m.indexes.contains(&device) {
                // an excluded disk (mode placeholder): PVE creates it, we serve zeros
                let size = excluded
                    .as_ref()
                    .and_then(|x| x.placeholder(&device))
                    .with_context(|| format!("snapshot has no device {device}"))?;
                eprintln!("{device} was excluded from the backup: restored empty ({size} bytes)");
                serve(ssh, archive, &device, size, |_, buf| {
                    buf.fill(0);
                    Ok(())
                })
                .with_context(|| format!("serve {device}"))?;
                continue;
            }
            let idx = store.load_index(m, &device)?;
            // progress: devices of the snapshot (PVE asks for them one by one)
            let at = (
                served.len() as u32,
                m.indexes.iter().filter(|i| *i != "config").count() as u32,
            );
            serve_device(store, ssh, archive, &device, &idx, at).with_context(|| format!("serve {device}"))?;
        }
    }

    /// Writes the catalog the node plugin needs for offline calls to every node.
    pub fn push_index(&self, store: &Store) -> Result<()> {
        self.push_index_value(&build_index(store)?)
    }

    fn push_index_value(&self, index: &serde_json::Value) -> Result<()> {
        let json = serde_json::to_vec(index)?;
        for (name, ssh) in &self.nodes {
            ssh.run(&format!("put-index {}", self.storage), Some(&json))
                .with_context(|| format!("push index to {name}"))?;
        }
        Ok(())
    }
}

pub(crate) struct Kill(pub Child);
impl Drop for Kill {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// `(offset, length)` ranges of a device
type Extents = Vec<(u64, u64)>;

/// Returns the device index, the bytes read from the export and, for a forced
/// full read (`full`) over a reused bitmap, the extents the bitmap reported.
/// Progress: part `at.0` of `at.1` with the bytes to read (dirty extents and
/// grown area) as its total (chunkstore::progress).
#[allow(clippy::too_many_arguments)]
fn pull_device(
    store: &Store,
    ssh: &SshNode,
    vmid: u32,
    dev: &Device,
    base: Option<&Index>,
    limit: Option<&catalog::schedule::Throttle>,
    at: (u32, u32),
    full: bool,
) -> Result<(Index, u64, Option<Extents>)> {
    let ctx = dev.bitmap_name.as_ref().map(|b| format!("qemu:dirty-bitmap:{b}"));
    let meta: Vec<&str> = ctx
        .iter()
        .map(String::as_str)
        .filter(|_| dev.bitmap_mode != "none")
        .collect();
    // base:allocation only for full reads (a reused bitmap names the few changed blocks; QEMU
    // refused block status on a small EFI disk with both contexts: "can't get block status")
    let incremental = dev.bitmap_mode == "reuse" && base.is_some();
    let optional: &[&str] = if incremental { &[] } else { &[ALLOCATION] };
    let connect = |meta: &[&str], optional: &[&str]| -> Result<(Kill, NbdClient)> {
        let mut child = Kill(
            ssh.cmd(&format!("nbd {vmid}"))
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()?,
        );
        let r = BufReader::with_capacity(1 << 20, child.0.stdout.take().unwrap());
        let w = BufWriter::new(child.0.stdin.take().unwrap());
        let c = nbd::Client::connect_opt(r, w, &dev.name, meta, optional)?;
        if c.size() != dev.size {
            bail!("export size {} != job size {}", c.size(), dev.size);
        }
        Ok((child, c))
    };
    // the ssh process lives as long as its connection (Kill on drop)
    let (mut _session, mut c) = connect(&meta, optional)?;
    let (dirty, tracked) = match meta.first() {
        Some(ctx) => match c.block_status(ctx) {
            Ok(e) => (nbd::flagged(&e, 1), true),
            Err(e) => {
                // never fail the guest over the change list: a fresh connection without meta
                // contexts and a full read of this device are always correct
                println!("{}: dirty bitmap unreadable ({e}): reading the whole device", dev.name);
                drop(c);
                (_session, c) = connect(&[], &[])?;
                (vec![(0, dev.size)], false)
            }
        },
        None => (vec![(0, dev.size)], false),
    };
    let (dirty, reported) = read_plan(dirty, dev.size, incremental && tracked && full);
    if reported.is_some() {
        println!(
            "{}: full read (Phase 29): the whole device, compared with the dirty bitmap",
            dev.name
        );
    }
    // regions the export reports as reading zero (unallocated / discarded) are filled locally,
    // never transported; plain holes without NBD_STATE_ZERO are read (their content is unspecified)
    let mut zero = match c.context_id(ALLOCATION) {
        Some(_) => nbd::flagged(&c.block_status(ALLOCATION)?, NBD_STATE_ZERO),
        None => Vec::new(),
    };
    if zero.is_empty() {
        // zvols and LVM report no holes to QEMU: the node helper scans the frozen export
        // locally and names the all-zero blocks (an older helper refuses: nothing skipped)
        zero = zero_map(ssh, vmid, &dev.name, &scan_extents(base, dev.size, &dirty), at);
    }
    let (mut read, mut skipped) = (0, 0);
    // where the time goes: NBD read round trips (request -> complete reply) vs. the rest of the
    // reading thread's time; the chunks are sealed and written by the store's worker threads
    // meanwhile, so a low share means the reader waited for the workers (full queue): CPU/disk-bound
    let (mut requests, mut waited, started) = (0u64, std::time::Duration::ZERO, std::time::Instant::now());
    let total = Store::image_extents_bytes(base, IMAGE_CHUNK_SIZE, dev.size, &dirty);
    let mut meter = Meter::new(exclude::disk_key(&dev.name), at.0, at.1, Some(total));
    // the ranges store_image_extents will ask for, in order; whole-zero ones are filled locally,
    // the others are fetched ahead by a reader thread with READ_AHEAD requests in flight (one
    // request at a time paid a full SSH round trip per 4 MiB)
    let is_zero = |(a, b): (u64, u64)| split_zero(&zero, a, b - a).as_slice() == [(a, b, true)];
    let fetch: Vec<(u64, u64)> = Store::image_extents_reads(base, IMAGE_CHUNK_SIZE, dev.size, &dirty)
        .into_iter()
        .filter(|&r| !is_zero(r))
        .map(|(a, b)| (a, b - a))
        .collect();
    let (tx, rx) = std::sync::mpsc::sync_channel::<(u64, Vec<u8>)>(READ_AHEAD);
    let idx = std::thread::scope(|scope| -> Result<Index> {
        let reader = scope.spawn(move || -> std::io::Result<()> {
            let r = c.read_many(&fetch, READ_AHEAD, |i, data| {
                // the consumer stopped (store error): end quietly, its error is the one reported
                tx.send((fetch[i].0, data))
                    .map_err(|_| std::io::Error::other("consumer gone"))
            });
            if r.is_ok() {
                c.disconnect()?;
            }
            r
        });
        let idx = store.store_image_extents(base, IMAGE_CHUNK_SIZE, dev.size, &dirty, |off, buf| {
            let len = buf.len() as u64;
            if is_zero((off, off + len)) {
                buf.fill(0);
                skipped += len;
            } else {
                let t0 = std::time::Instant::now();
                let (got, data) = rx.recv().map_err(|_| std::io::Error::other("NBD reader stopped"))?;
                waited += t0.elapsed();
                if got != off || data.len() != buf.len() {
                    return Err(std::io::Error::other(format!(
                        "read-ahead out of step: got {got}+{}, want {off}+{len}",
                        data.len()
                    )));
                }
                buf.copy_from_slice(&data);
                read += len;
                requests += 1;
                if let Some(t) = limit {
                    t.account(len);
                }
            }
            meter.add(len);
            Ok(())
        });
        drop(rx);
        let reader = reader.join().map_err(|_| anyhow::anyhow!("NBD reader panicked"))?;
        // a store error wins (the reader then only saw "consumer gone"); else the reader's error
        let idx = idx?;
        reader.with_context(|| format!("read {}", dev.name))?;
        Ok(idx)
    })?;
    meter.finish();
    if skipped > 0 {
        println!("{}: {skipped} bytes unallocated (zero), not transferred", dev.name);
    }
    if requests > 0 {
        let total = started.elapsed();
        println!(
            "{}: {requests} NBD reads, {read} bytes in {total:.1?} ({:.0} MB/s): {:.2} ms per read waiting for data from the node ({} in flight), {:.0}% of the time ({} chunk workers)",
            dev.name,
            read as f64 / total.as_secs_f64().max(1e-3) / 1e6,
            waited.as_secs_f64() * 1e3 / requests as f64,
            READ_AHEAD,
            100.0 * waited.as_secs_f64() / total.as_secs_f64().max(1e-3),
            store.chunk_workers()
        );
    }
    Ok((idx, read, reported))
}

/// The extents to read and, for a forced full read over a reused bitmap
/// (`compare`), the bitmap's extents kept as the "reported" ones.
fn read_plan(dirty: Extents, size: u64, compare: bool) -> (Extents, Option<Extents>) {
    match compare {
        true => (vec![(0, size)], Some(dirty)),
        false => (dirty, None),
    }
}

/// Ranges a backup reads: the dirty extents plus a grown (or never backed up) tail, merged.
fn scan_extents(base: Option<&Index>, size: u64, dirty: &[(u64, u64)]) -> Vec<(u64, u64)> {
    let prev = match base {
        Some(Index::Fixed { size, .. }) => *size,
        _ => 0,
    };
    let mut r: Vec<(u64, u64)> = dirty.iter().map(|&(o, l)| (o, (o + l).min(size))).collect();
    if prev < size {
        r.push((prev, size));
    }
    r.sort_unstable();
    let mut out: Vec<(u64, u64)> = Vec::new();
    for (a, b) in r.into_iter().filter(|(a, b)| a < b) {
        match out.last_mut() {
            Some(last) if a <= last.1 => last.1 = last.1.max(b),
            _ => out.push((a, b)),
        }
    }
    out.into_iter().map(|(a, b)| (a, b - a)).collect()
}

/// All-zero 64 KiB blocks within `extents`, scanned by the node helper (`zeromap`); its
/// `zeromap-progress <bytes>` lines on stderr become a progress part of their own.
fn zero_map(ssh: &SshNode, vmid: u32, export: &str, extents: &[(u64, u64)], at: (u32, u32)) -> Vec<(u64, u64)> {
    use std::io::{BufRead, Read, Write};
    if extents.is_empty() {
        return Vec::new();
    }
    let total: u64 = extents.iter().map(|e| e.1).sum();
    println!("{export}: scanning {total} bytes on the node for empty blocks");
    let req = serde_json::json!({ "extents": extents, "granularity": 65536 }).to_string();
    let started = std::time::Instant::now();
    let run = || -> Result<serde_json::Value> {
        let mut child = Kill(
            ssh.cmd(&format!("zeromap {vmid} {export}"))
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()?,
        );
        child.0.stdin.take().unwrap().write_all(req.as_bytes())?; // dropped: EOF for the helper
        let mut out = child.0.stdout.take().unwrap();
        let reader = std::thread::spawn(move || {
            let mut v = Vec::new();
            out.read_to_end(&mut v).map(|_| v)
        });
        let mut meter = Meter::new(
            &format!("{} (scanning for empty blocks)", exclude::disk_key(export)),
            at.0,
            at.1,
            Some(total),
        );
        let (mut seen, mut errors) = (0u64, Vec::new());
        for line in BufReader::new(child.0.stderr.take().unwrap()).lines() {
            let line = line?;
            match line
                .strip_prefix("zeromap-progress ")
                .and_then(|n| n.trim().parse::<u64>().ok())
            {
                Some(n) if n >= seen => {
                    meter.add(n - seen);
                    seen = n;
                }
                _ => errors.push(line),
            }
        }
        meter.finish();
        let status = child.0.wait()?;
        let out = reader
            .join()
            .map_err(|_| anyhow::anyhow!("zeromap reader panicked"))??;
        if !status.success() {
            anyhow::bail!("{status}: {}", errors.join("; "));
        }
        Ok(serde_json::from_slice(&out)?)
    };
    match run() {
        Ok(v) => {
            let zero: Vec<(u64, u64)> = v["zero"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|e| Some((e[0].as_u64()?, e[1].as_u64()?)))
                        .collect()
                })
                .unwrap_or_default();
            println!(
                "{export}: zero map scanned on the node in {:.1?}: {} bytes zero of {}",
                started.elapsed(),
                zero.iter().map(|z| z.1).sum::<u64>(),
                v["scanned"].as_u64().unwrap_or(0)
            );
            zero
        }
        Err(e) => {
            println!("{export}: no zero map from the node ({e:#}): every block is transferred");
            Vec::new()
        }
    }
}

const ALLOCATION: &str = "base:allocation";
/// NBD read requests in flight per device (4 MiB each).
const READ_AHEAD: usize = 8;
type NbdClient = nbd::Client<BufReader<std::process::ChildStdout>, BufWriter<std::process::ChildStdin>>;
const NBD_STATE_ZERO: u32 = 2;

/// `[off, off+len)` split at the zero extents (sorted, disjoint): `(start, end, is_zero)`.
fn split_zero(zero: &[(u64, u64)], off: u64, len: u64) -> Vec<(u64, u64, bool)> {
    let end = off + len;
    let mut out = Vec::new();
    let mut pos = off;
    let first = zero.partition_point(|&(o, l)| o + l <= off);
    for &(o, l) in zero[first..].iter().take_while(|&&(o, _)| o < end) {
        let (zs, ze) = (o.max(pos), (o + l).min(end));
        if zs > pos {
            out.push((pos, zs, false));
        }
        if ze > zs {
            out.push((zs, ze, true));
        }
        pos = pos.max(ze);
    }
    if pos < end {
        out.push((pos, end, false));
    }
    out
}

fn serve_device(store: &Store, ssh: &SshNode, archive: &str, device: &str, idx: &Index, at: (u32, u32)) -> Result<()> {
    let mut img = store.image_reader(idx)?;
    let size = img.size();
    let mut meter = Meter::new(exclude::disk_key(device), at.0, at.1, Some(size));
    serve(ssh, archive, device, size, |off, buf| {
        img.read_at(off, buf)?;
        meter.add(buf.len() as u64);
        Ok(())
    })?;
    meter.finish();
    Ok(())
}

fn serve(
    ssh: &SshNode,
    archive: &str,
    device: &str,
    size: u64,
    read_at: impl FnMut(u64, &mut [u8]) -> std::io::Result<()>,
) -> Result<()> {
    let mut child = Kill(
        ssh.cmd(&format!("restore-serve {archive} {device}"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()?,
    );
    let r = BufReader::with_capacity(1 << 20, child.0.stdout.take().unwrap());
    let w = BufWriter::with_capacity(1 << 20, child.0.stdin.take().unwrap());
    nbd::server::serve(r, w, device, size, read_at)?;
    Ok(())
}

pub(crate) fn config_entry(store: &Store, name: &str, text: &str) -> Result<FileEntry> {
    let (chunks, size) = store.store_file(text.as_bytes())?;
    Ok(FileEntry {
        path: name.into(),
        mode: 0o640,
        size,
        mtime: 0,
        chunks,
    })
}

#[derive(Serialize)]
struct CatalogArchive {
    volname: String,
    vmid: u32,
    #[serde(rename = "type")]
    kind: &'static str,
    ctime: u64,
    size: u64,
    devices: Vec<String>,
    device_sizes: BTreeMap<String, u64>,
    config: String,
    firewall: Option<String>,
    notes: String,
    protected: bool,
}

/// The snapshot's excluded-disks record (`None`: nothing was excluded).
pub fn read_excluded(store: &Store, m: &Manifest) -> Result<Option<Excluded>> {
    if !m.indexes.iter().any(|i| i == "config") {
        return Ok(None);
    }
    read_config(store, m, exclude::FILE)?
        .map(|t| serde_json::from_str(&t).context("excluded-disks.json"))
        .transpose()
}

/// Identity of a VM from its `qemu-server.conf` (current section only).
#[derive(Serialize, Debug, Default, PartialEq)]
pub struct Identity {
    pub vmgenid: Option<String>,
    pub smbios_uuid: Option<String>,
}

impl Identity {
    pub fn of(conf: &str) -> Identity {
        let mut id = Identity::default();
        for line in conf.lines().take_while(|l| !l.starts_with('[')) {
            let Some((k, v)) = line.split_once(':') else { continue };
            match k.trim() {
                "vmgenid" => id.vmgenid = Some(v.trim().to_ascii_lowercase()).filter(|v| !v.is_empty() && v != "0"),
                "smbios1" => {
                    id.smbios_uuid = v
                        .trim()
                        .split(',')
                        .find_map(|o| o.strip_prefix("uuid="))
                        .map(str::to_ascii_lowercase);
                }
                _ => {}
            }
        }
        id
    }

    /// A field set on both sides differs (a field added later is no change).
    pub fn differs(&self, old: &Identity) -> bool {
        let ne = |a: &Option<String>, b: &Option<String>| matches!((a, b), (Some(a), Some(b)) if a != b);
        ne(&self.vmgenid, &old.vmgenid) || ne(&self.smbios_uuid, &old.smbios_uuid)
    }
}

pub(crate) fn read_config(store: &Store, m: &Manifest, file: &str) -> Result<Option<String>> {
    let Index::Dynamic { entries } = store.load_index(m, "config")? else {
        bail!("config index is not dynamic")
    };
    let Some(e) = entries.iter().find(|e| e.path == file) else {
        return Ok(None);
    };
    let mut out = Vec::new();
    store.write_chunks(&e.chunks, &mut out)?;
    Ok(Some(String::from_utf8_lossy(&out).into_owned()))
}

pub fn build_index(store: &Store) -> Result<serde_json::Value> {
    let mut archives = Vec::new();
    for m in store.list_snapshots()? {
        if let Some(vmid) = m.source.strip_prefix("ct-").and_then(|v| v.parse().ok()) {
            archives.push(CatalogArchive {
                volname: format!("backup/nexus-{vmid}-{}", m.time),
                vmid,
                kind: "lxc",
                ctime: m.time,
                size: crate::ct::root_tar(store, &m)?.size,
                devices: Vec::new(),
                device_sizes: BTreeMap::new(),
                config: read_config(store, &m, crate::ct::CONFIG_FILE)?.unwrap_or_default(),
                firewall: read_config(store, &m, "firewall.fw")?,
                notes: String::new(),
                protected: false,
            });
            continue;
        }
        let Some(vmid) = m.source.strip_prefix("vm-").and_then(|v| v.parse().ok()) else {
            continue;
        };
        let devices: Vec<String> = m.indexes.iter().filter(|n| *n != "config").cloned().collect();
        let mut device_sizes = BTreeMap::new();
        for d in &devices {
            if let Index::Fixed { size, .. } = store.load_index(&m, d)? {
                device_sizes.insert(d.clone(), size);
            }
        }
        let size = device_sizes.values().sum();
        // a base with bad chunks (chunkstore::health) must not be built upon: without its
        // devices the node starts fresh bitmaps, so the next backup reads the disks in full
        let devices = if store.is_damaged(&m)? { Vec::new() } else { devices };
        let mut config = read_config(store, &m, "qemu-server.conf")?.unwrap_or_default();
        if let Some(x) = read_excluded(store, &m)? {
            let (c, placeholders) = x.catalog(&config);
            config = c;
            device_sizes.extend(placeholders);
        }
        archives.push(CatalogArchive {
            volname: format!("backup/nexus-{vmid}-{}", m.time),
            vmid,
            kind: "qemu",
            ctime: m.time,
            size,
            devices,
            device_sizes,
            config,
            firewall: read_config(store, &m, "firewall.fw")?,
            notes: String::new(),
            protected: false,
        });
    }
    Ok(serde_json::json!({ "version": 1, "archives": archives }))
}

/// Start time of a PVE task: `UPID:node:pid:pstart:starttime:type:id:user:` (hex).
fn upid_start(upid: &str) -> Option<u64> {
    u64::from_str_radix(upid.split(':').nth(4)?, 16).ok()
}

/// The user (token) that started a task: `UPID:node:pid:pstart:starttime:type:id:user:`.
fn upid_user(upid: &str) -> Option<&str> {
    upid.split(':').nth(7).filter(|u| !u.is_empty())
}

/// Of the active tasks (`GET /nodes/<node>/tasks?source=active`), the vzdump tasks of `vmid` that the
/// user of `ours` started before it.
fn stale_of(tasks: &Value, vmid: u32, ours: &str) -> Vec<String> {
    let (Some(user), Some(start)) = (upid_user(ours), upid_start(ours)) else {
        return Vec::new();
    };
    tasks
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|t| t["upid"].as_str())
        .filter(|u| {
            *u != ours
                && upid_user(u) == Some(user)
                && u.split(':').nth(5) == Some("vzdump")
                && u.split(':').nth(6) == Some(vmid.to_string().as_str())
                && upid_start(u).is_some_and(|s| s < start)
        })
        .map(str::to_owned)
        .collect()
}

#[cfg(test)]
mod tests {

    #[test]
    fn stale_tasks_of_the_same_token_only() {
        let ours = "UPID:pve-test:0003DBBC:003D1E27:6ADB123B:vzdump:242:nexus@pve!backup:";
        let tasks = serde_json::json!([
            {"upid": ours},
            // the interrupted run (lab 2026-10-23)
            {"upid": "UPID:pve-test:0003CB19:003BCD43:6ADB0EDD:vzdump:242:nexus@pve!backup:"},
            // someone else's backup of the guest, another guest, a later task
            {"upid": "UPID:pve-test:00000001:00000001:6ADB0000:vzdump:242:root@pam:"},
            {"upid": "UPID:pve-test:00000002:00000002:6ADB0000:vzdump:243:nexus@pve!backup:"},
            {"upid": "UPID:pve-test:00000003:00000003:6ADB2000:vzdump:242:nexus@pve!backup:"},
            {"upid": "UPID:pve-test:00000004:00000004:6ADB0000:qmstart:242:nexus@pve!backup:"}
        ]);
        assert_eq!(
            super::stale_of(&tasks, 242, ours),
            ["UPID:pve-test:0003CB19:003BCD43:6ADB0EDD:vzdump:242:nexus@pve!backup:"]
        );
        assert_eq!(super::upid_user(ours), Some("nexus@pve!backup"));
        assert!(super::stale_of(&tasks, 242, "garbage").is_empty());
    }

    #[test]
    fn upid_start_and_older_jobs() {
        // the lab case: the orphaned task's job (20:34) vs. our task started 20:39:35
        let ours = "UPID:pve-test:0000D2DB:000CD731:6ACFCC67:vzdump:101:nexus@pve!backup:";
        assert_eq!(super::upid_start(ours), Some(1792003175));
        let job = |archive: &str| super::Job {
            archive: archive.into(),
            ..serde_json::from_value(serde_json::json!({"vmid": 101, "archive": "x", "devices": [], "config": ""}))
                .unwrap()
        };
        assert!(
            job("nexus-101-1792002845").time().unwrap() < 1792003175,
            "older job: refused"
        );
        assert!(
            job("nexus-101-1792003679").time().unwrap() >= 1792003175,
            "ours (after the lock)"
        );
        assert_eq!(super::upid_start("UPID:x"), None);
        assert_eq!(super::upid_start("UPID:n:1:2:zz:vzdump:1:u:"), None);
    }

    #[test]
    fn scan_extents_merge_dirty_and_tail() {
        let fixed = |size| Index::Fixed {
            chunk_size: 65536,
            size,
            chunks: vec![],
        };
        // full backup: dirty = whole disk, no base: one range
        assert_eq!(scan_extents(None, 1000, &[(0, 1000)]), vec![(0, 1000)]);
        // incremental with a grown disk: dirty ranges plus the new tail, overlaps merged
        assert_eq!(
            scan_extents(Some(&fixed(600)), 1000, &[(100, 50), (550, 100)]),
            vec![(100, 50), (550, 450)]
        );
        // nothing changed: nothing to scan
        assert!(scan_extents(Some(&fixed(1000)), 1000, &[]).is_empty());
    }

    #[test]
    fn split_zero_regions() {
        let zero = [(100u64, 50u64), (300, 100)];
        assert_eq!(split_zero(&zero, 0, 100), vec![(0, 100, false)]);
        assert_eq!(
            split_zero(&zero, 0, 200),
            vec![(0, 100, false), (100, 150, true), (150, 200, false)]
        );
        assert_eq!(split_zero(&zero, 120, 20), vec![(120, 140, true)]);
        assert_eq!(
            split_zero(&zero, 140, 300),
            vec![(140, 150, true), (150, 300, false), (300, 400, true), (400, 440, false)]
        );
        assert_eq!(split_zero(&[], 5, 10), vec![(5, 15, false)]);
        assert_eq!(split_zero(&zero, 400, 10), vec![(400, 410, false)]);
    }

    use super::*;
    use crate::exclude::{Disk, Mode};

    #[test]
    fn progress_items_name_the_guest() {
        let names = BTreeMap::from([
            (101, ("vm".to_owned(), "dc1dev".to_owned())),
            (200, ("ct".to_owned(), String::new())),
        ]);
        assert_eq!(progress_item(101, &names), ("vm-101".into(), Some("dc1dev")));
        assert_eq!(progress_item(200, &names), ("ct-200".into(), None));
        assert_eq!(progress_item(7, &names), ("vm-7".into(), None));
        let (item, label) = progress_item(101, &names);
        assert_eq!(
            chunkstore::progress::item_line(&item, label, 2, 3),
            "item 2/3: vm-101 dc1dev"
        );
    }

    #[test]
    fn identity_of_a_config() {
        let a = Identity::of(
            "name: web\nsmbios1: uuid=13E1FD94-5545-4e60-8309-3e50cb85a8c0,manufacturer=QUNNRQ==\nvmgenid: 5b65ecd1-44f5-4b88-8b6c-96cd092a9d2e\n\n[snap]\nvmgenid: 00000000-0000-0000-0000-000000000001\n",
        );
        assert_eq!(
            a.vmgenid.as_deref(),
            Some("5b65ecd1-44f5-4b88-8b6c-96cd092a9d2e"),
            "snapshot section ignored"
        );
        assert_eq!(a.smbios_uuid.as_deref(), Some("13e1fd94-5545-4e60-8309-3e50cb85a8c0"));
        assert!(!a.differs(&a));
        // vmgenid added later (older config without it): no change
        let old = Identity::of("smbios1: uuid=13e1fd94-5545-4e60-8309-3e50cb85a8c0\n");
        assert!(!a.differs(&old));
        // re-created VM: new SMBIOS UUID and vmgenid
        let new = Identity::of("smbios1: uuid=aaaaaaaa-5545-4e60-8309-3e50cb85a8c0\nvmgenid: 1\n");
        assert!(new.differs(&a));
        assert!(!Identity::of("").differs(&a), "nothing known: no change");
    }

    /// A VM snapshot as `pull` commits it: one backed-up disk, scsi1 excluded.
    fn snapshot(store: &Store, time: u64, mode: Mode) -> Manifest {
        let idx = store
            .store_image_extents(None, IMAGE_CHUNK_SIZE, 1 << 20, &[(0, 1 << 20)], |_, b| {
                b.fill(7);
                Ok(())
            })
            .unwrap();
        let conf = "scsi0: local-lvm:vm-101-disk-0,size=1M\nscsi1: local-lvm:vm-101-disk-1,size=4M\n\
                    #qmdump#map:scsi0:drive-scsi0:local-lvm:raw:\n#qmdump#map:scsi1:drive-scsi1:local-lvm:raw:\n";
        let x = Excluded {
            mode,
            disks: vec![Disk {
                device: "drive-scsi1".into(),
                key: "scsi1".into(),
                size: 4 << 20,
            }],
        };
        let entries = vec![
            config_entry(store, "qemu-server.conf", conf).unwrap(),
            config_entry(store, exclude::FILE, &serde_json::to_string(&x).unwrap()).unwrap(),
        ];
        store
            .commit_snapshot(
                "vm-101",
                time,
                &[("drive-scsi0", idx), ("config", Index::Dynamic { entries })],
            )
            .unwrap()
    }

    #[test]
    fn excluded_disks_in_the_catalog() {
        let dir = tempfile::tempdir().unwrap();
        let keys = chunkstore::Keyring::new("t", &[(1, [7; 32])]);
        let store = Store::open(dir.path(), keys, chunkstore::Options::default()).unwrap();
        let m = snapshot(&store, 1760000000, Mode::Placeholder);
        assert_eq!(read_excluded(&store, &m).unwrap().unwrap().keys(), vec!["scsi1"]);
        snapshot(&store, 1760000100, Mode::Omit);
        let idx = build_index(&store).unwrap();
        let a = idx["archives"].as_array().unwrap();
        // placeholder: sized for the restore, but not a backed-up device (incremental bitmaps)
        assert_eq!(a[0]["devices"], serde_json::json!(["drive-scsi0"]));
        assert_eq!(a[0]["device_sizes"]["drive-scsi1"], 4 << 20);
        assert_eq!(a[0]["size"], 1 << 20);
        assert!(a[0]["config"].as_str().unwrap().contains("#qmdump#map:scsi1:"));
        // omit: the disk is gone from the restored config
        assert_eq!(a[1]["device_sizes"], serde_json::json!({"drive-scsi0": 1 << 20}));
        let c = a[1]["config"].as_str().unwrap();
        assert!(!c.contains("scsi1") && c.contains("scsi0:"), "{c}");
    }

    /// Phase 21d: a newest snapshot with bad chunks lists no devices, so the node
    /// answers `new` (fresh bitmap, full read) instead of reusing its bitmap.
    #[test]
    fn damaged_base_hides_its_devices_from_the_node() {
        let dir = tempfile::tempdir().unwrap();
        let keys = chunkstore::Keyring::new("t", &[(1, [7; 32])]);
        let store = Store::open(dir.path(), keys, chunkstore::Options::default()).unwrap();
        let m = snapshot(&store, 1760000000, Mode::Placeholder);
        let disk = store.load_index(&m, "drive-scsi0").unwrap();
        assert_eq!(
            build_index(&store).unwrap()["archives"][0]["devices"],
            serde_json::json!(["drive-scsi0"])
        );
        store.mark_bad(disk.chunk_ids()).unwrap();
        let idx = build_index(&store).unwrap();
        assert_eq!(idx["archives"][0]["devices"], serde_json::json!([]));
        assert_eq!(
            idx["archives"][0]["device_sizes"]["drive-scsi0"],
            1 << 20,
            "restore sizes stay"
        );
    }

    /// Phase 29: a forced full read over a reused bitmap reads the whole disk and
    /// finds the chunk the bitmap missed; the reported change is not drift.
    #[test]
    fn full_read_finds_changes_the_bitmap_missed() {
        let dir = tempfile::tempdir().unwrap();
        let keys = chunkstore::Keyring::new("t", &[(1, [7; 32])]);
        let store = Store::open(dir.path(), keys, chunkstore::Options::default()).unwrap();
        let cs = 4096;
        let mut disk = vec![1u8; 4 * cs];
        let read = |d: &[u8]| {
            let d = d.to_vec();
            move |off: u64, buf: &mut [u8]| {
                buf.copy_from_slice(&d[off as usize..off as usize + buf.len()]);
                Ok(())
            }
        };
        let base = store
            .store_image_extents(None, cs, disk.len() as u64, &[(0, disk.len() as u64)], read(&disk))
            .unwrap();
        disk[cs] = 2; // reported by the bitmap
        disk[3 * cs + 5] = 3; // missed
        let bitmap = vec![(cs as u64, 512)];
        // an incremental without a full read: dirty = the bitmap, nothing to compare
        assert_eq!(
            read_plan(bitmap.clone(), disk.len() as u64, false),
            (bitmap.clone(), None)
        );
        let (dirty, reported) = read_plan(bitmap.clone(), disk.len() as u64, true);
        assert_eq!(
            (dirty.as_slice(), reported.as_deref()),
            (&[(0, 4 * cs as u64)][..], Some(&bitmap[..]))
        );
        let idx = store
            .store_image_extents(Some(&base), cs, disk.len() as u64, &dirty, read(&disk))
            .unwrap();
        let mut d = Drift::new("dirty-bitmap", Some(1));
        drift::fixed(&mut d, &base, &idx, &reported.unwrap(), "drive-scsi0");
        assert_eq!(
            (d.compared, d.changed, d.unreported, d.unreported_bytes),
            (4, 2, 1, cs as u64)
        );
        assert_eq!(d.examples, [format!("drive-scsi0@{}", 3 * cs)]);
    }
}
