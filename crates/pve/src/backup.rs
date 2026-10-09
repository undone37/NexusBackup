//! VM backup orchestration and the shared catalog (contract: docs/pve-connector.md).
//! Containers: `crate::ct`.

use crate::api::Api;
use anyhow::{bail, Context, Result};
use chunkstore::store::IMAGE_CHUNK_SIZE;
use chunkstore::{FileEntry, Index, Manifest, Store};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::{BufReader, BufWriter, Write};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
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
    /// PVE node name -> SSH endpoint
    pub nodes: BTreeMap<String, SshNode>,
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

    /// Backs up a VM or a container, whichever `vmid` is. Returns the manifest.
    pub fn backup_guest(&self, store: &Store, vmid: u32) -> Result<Manifest> {
        match self.guest(vmid)?.1.as_str() {
            "qemu" => self.backup_vm(store, vmid),
            "lxc" => Ok(self.backup_ct(store, vmid)?.0),
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
    pub fn backup_vm(&self, store: &Store, vmid: u32) -> Result<Manifest> {
        let (node, kind) = self.guest(vmid)?;
        if kind != "qemu" {
            bail!("guest {vmid} is not a VM ({kind})");
        }
        let ssh = self.ssh(&node)?;
        let fleecing = format!("enabled=1,storage={}", self.fleecing_storage);
        let upid = self.api.start_backup(&node, vmid, &self.storage, Some(&fleecing))?;
        let job = self.wait_job(&node, ssh, vmid, &upid, "qemu")?;
        let result = self.pull(store, ssh, vmid, &job);
        let done = match &result {
            Ok(_) => "ok".to_owned(),
            Err(e) => format!("fail {}", e.to_string().replace(['\n', '\''], " ")),
        };
        let signalled = ssh.run(&format!("done {vmid} {done}"), None);
        let manifest = result?;
        signalled?;
        let exit = self.api.wait_task(&node, &upid, Duration::from_secs(3600))?;
        if exit != "OK" {
            // ponytail: snapshot is kept (bitmap already committed); alerting comes with the scheduler
            eprintln!("warning: vzdump task for VM {vmid} ended with {exit}; snapshot kept");
        }
        Ok(manifest)
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

    fn pull(&self, store: &Store, ssh: &SshNode, vmid: u32, job: &Job) -> Result<Manifest> {
        let time = job.time()?;
        let source = source_name(vmid);
        let prev = store.list_snapshots()?.into_iter().rfind(|m| m.source == source);
        let (mut names, mut indexes) = (Vec::new(), Vec::new());
        for dev in &job.devices {
            let base = match (dev.bitmap_mode.as_str(), &prev) {
                ("reuse", Some(m)) if m.indexes.contains(&dev.name) => Some(store.load_index(m, &dev.name)?),
                ("reuse", _) => bail!("{}: PVE reuses a dirty bitmap but no base snapshot exists", dev.name),
                _ => None,
            };
            let idx =
                pull_device(store, ssh, vmid, dev, base.as_ref()).with_context(|| format!("device {}", dev.name))?;
            names.push(dev.name.as_str());
            indexes.push(idx);
        }
        let mut entries = vec![config_entry(store, "qemu-server.conf", &job.config)?];
        if let Some(fw) = &job.firewall {
            entries.push(config_entry(store, "firewall.fw", fw)?);
        }
        names.push("config");
        indexes.push(Index::Dynamic { entries });
        let refs: Vec<(&str, Index)> = names.into_iter().zip(indexes).collect();
        Ok(store.commit_snapshot(&source, time, &refs)?)
    }

    /// Full restore of snapshot `vm-<vmid>/<time>` as VM `target` on `node`. PVE pulls
    /// each disk through `qemu-nbd` on the node; we serve it over `ssh restore-serve`.
    pub fn restore_vm(
        &self,
        store: &Store,
        vmid: u32,
        time: u64,
        node: &str,
        target: u32,
        target_storage: &str,
    ) -> Result<String> {
        let m = store.load_manifest(&source_name(vmid), time)?;
        let ssh = self.ssh(node)?;
        let archive = format!("nexus-{vmid}-{time}");
        let volid = format!("{}:backup/{archive}", self.storage);
        let upid = self.api.start_restore(node, target, &volid, target_storage)?;
        let mut served = std::collections::HashSet::new();
        loop {
            if let Some(exit) = self.api.task_status(node, &upid)? {
                if exit != "OK" {
                    let log = self.api.task_log(node, &upid).unwrap_or_default();
                    bail!("restore task ended with {exit}: {}", log.join("\n"));
                }
                return Ok(exit);
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
            if !m.indexes.contains(&device) || device == "config" {
                bail!("snapshot has no device {device}");
            }
            let idx = store.load_index(&m, &device)?;
            serve_device(store, ssh, &archive, &device, &idx).with_context(|| format!("serve {device}"))?;
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

fn pull_device(store: &Store, ssh: &SshNode, vmid: u32, dev: &Device, base: Option<&Index>) -> Result<Index> {
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
    let idx = store.store_image_extents(base, IMAGE_CHUNK_SIZE, dev.size, &dirty, |off, buf| c.read_at(off, buf))?;
    c.disconnect()?;
    Ok(idx)
}

fn serve_device(store: &Store, ssh: &SshNode, archive: &str, device: &str, idx: &Index) -> Result<()> {
    let mut child = Kill(
        ssh.cmd(&format!("restore-serve {archive} {device}"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()?,
    );
    let r = BufReader::with_capacity(1 << 20, child.0.stdout.take().unwrap());
    let w = BufWriter::with_capacity(1 << 20, child.0.stdin.take().unwrap());
    let mut img = store.image_reader(idx)?;
    let size = img.size();
    nbd::server::serve(r, w, device, size, |off, buf| img.read_at(off, buf))?;
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

fn read_config(store: &Store, m: &Manifest, file: &str) -> Result<Option<String>> {
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
        archives.push(CatalogArchive {
            volname: format!("backup/nexus-{vmid}-{}", m.time),
            vmid,
            kind: "qemu",
            ctime: m.time,
            size: device_sizes.values().sum(),
            devices,
            device_sizes,
            config: read_config(store, &m, "qemu-server.conf")?.unwrap_or_default(),
            firewall: read_config(store, &m, "firewall.fw")?,
            notes: String::new(),
            protected: false,
        });
    }
    Ok(serde_json::json!({ "version": 1, "archives": archives }))
}
