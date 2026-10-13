//! VM backup orchestration and the shared catalog (contract: docs/pve-connector.md).
//! Containers: `crate::ct`.

use crate::api::Api;
use crate::exclude::{self, Excluded};
use crate::fleecing::{self, Level};
use anyhow::{bail, Context, Result};
use chunkstore::store::IMAGE_CHUNK_SIZE;
use chunkstore::{FileEntry, Index, Manifest, Store};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
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

pub fn source_name(vmid: u32) -> String {
    format!("vm-{vmid}")
}

impl Cluster {
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
                let result = self.pull(store, ssh, vmid, &job);
                let done = match &result {
                    Ok(_) => "ok".to_owned(),
                    Err(e) => format!("fail {}", e.to_string().replace(['\n', '\''], " ")),
                };
                let signalled = ssh.run(&format!("done {vmid} {done}"), None);
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
                return Ok(job);
            }
            std::thread::sleep(Duration::from_secs(1));
        }
    }

    fn pull(&self, store: &Store, ssh: &SshNode, vmid: u32, job: &Job) -> Result<(Manifest, u64)> {
        let time = job.time()?;
        let source = source_name(vmid);
        let prev = store.list_snapshots()?.into_iter().rfind(|m| m.source == source);
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
            let (idx, n) = pull_device(store, ssh, vmid, dev, base.as_ref(), self.read_limit.as_deref())
                .with_context(|| format!("device {}", dev.name))?;
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
                self.serve_restore(store, &m, ssh, node, &archive, &upid)
            },
        )
    }

    fn serve_restore(
        &self,
        store: &Store,
        m: &Manifest,
        ssh: &SshNode,
        node: &str,
        archive: &str,
        upid: &str,
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
            serve_device(store, ssh, archive, &device, &idx).with_context(|| format!("serve {device}"))?;
        }
    }

    /// Writes the catalog the node plugin needs for offline calls to every node.
    pub fn push_index(&self, store: &Store) -> Result<()> {
        let json = serde_json::to_vec(&build_index(store)?)?;
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

/// Returns the device index and the bytes read from the export.
fn pull_device(
    store: &Store,
    ssh: &SshNode,
    vmid: u32,
    dev: &Device,
    base: Option<&Index>,
    limit: Option<&catalog::schedule::Throttle>,
) -> Result<(Index, u64)> {
    let mut child = Kill(
        ssh.cmd(&format!("nbd {vmid}"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()?,
    );
    let r = BufReader::with_capacity(1 << 20, child.0.stdout.take().unwrap());
    let w = BufWriter::new(child.0.stdin.take().unwrap());
    let ctx = dev.bitmap_name.as_ref().map(|b| format!("qemu:dirty-bitmap:{b}"));
    let meta: Vec<&str> = ctx
        .iter()
        .map(String::as_str)
        .filter(|_| dev.bitmap_mode != "none")
        .collect();
    let mut c = nbd::Client::connect(r, w, &dev.name, &meta)?;
    if c.size() != dev.size {
        bail!("export size {} != job size {}", c.size(), dev.size);
    }
    let dirty = match meta.first() {
        Some(ctx) => nbd::flagged(&c.block_status(ctx)?, 1),
        None => vec![(0, dev.size)],
    };
    let mut read = 0;
    let idx = store.store_image_extents(base, IMAGE_CHUNK_SIZE, dev.size, &dirty, |off, buf| {
        read += buf.len() as u64;
        c.read_at(off, buf)?;
        if let Some(t) = limit {
            t.account(buf.len() as u64);
        }
        Ok(())
    })?;
    c.disconnect()?;
    Ok((idx, read))
}

fn serve_device(store: &Store, ssh: &SshNode, archive: &str, device: &str, idx: &Index) -> Result<()> {
    let mut img = store.image_reader(idx)?;
    let size = img.size();
    serve(ssh, archive, device, size, |off, buf| img.read_at(off, buf))
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
                        .map(str::to_ascii_lowercase)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exclude::{Disk, Mode};

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
}
