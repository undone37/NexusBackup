//! Instant rollback of a VM in place (Phase 30, docs/pve-connector.md "Instant
//! rollback", docs/netbackup-comparison.md Tier 2): only the chunks that differ
//! between the chosen snapshot and the VM's current disks are written back.
//!
//! 1. Checks (else [`Outcome::Fallback`], the caller does a full restore with
//!    replace original): the VM exists and runs, its identity (vmgenid / SMBIOS
//!    UUID) is the snapshot's, its disks are the snapshot's (same keys, same
//!    sizes; extra or missing disks change the layout).
//! 2. The VM is paused (`status/suspend`: no more writes, QEMU keeps its dirty
//!    bitmap), then backed up incrementally: the pre-rollback snapshot reads
//!    exactly the regions in the bitmap (the writes since the newest backup) and
//!    keeps the current state in the store. A bitmap PVE cannot reuse (VM
//!    restarted since the last backup, a new disk) means a full read: the backup
//!    is refused before reading and the VM resumed (fallback).
//! 3. The VM is stopped, tagged `nexus-rollback` (`PUT config`), and the node's
//!    root service (`rollback-begin`, pve-plugin/rollback) sets the PVE lock
//!    `rollback`, so it cannot be started meanwhile.
//! 4. Per disk the fixed indexes of the snapshot and of the pre-rollback snapshot
//!    are compared by chunk ID (no data read); the differing chunks are written
//!    through `rollback-nbd` (qemu-nbd on the node, NBD over the SSH stdio),
//!    then flushed. Every session is opened (and its size checked) before the
//!    first write.
//! 5. `rollback-end` removes the lock, the tag goes, the VM starts if asked
//!    (NICs `link_down=1` first if asked). Its configuration stays as it is now.
//!
//! A failure after the lock leaves the VM stopped and locked: running the
//! rollback again resumes (stopped + tagged + locked `rollback`: steps 1-3 are
//! skipped, the pre-rollback snapshot is the newest one) and writes the
//! differing chunks again.

use crate::backup::{read_config, source_name, Identity};
use crate::exclude::disk_key;
use anyhow::{bail, Context, Result};
use chunkstore::{Index, Store};
use serde::Serialize;
use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, BufReader, BufWriter};
use std::process::{Child, ChildStdin, ChildStdout, Stdio};

pub const TAG: &str = "nexus-rollback";
/// Writes in flight per disk (each up to one 4 MiB chunk).
pub const DEPTH: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Power {
    Running,
    Paused,
    Stopped,
}

/// A disk session on the node (`rollback-nbd`): the volume, writable.
pub trait DiskWriter {
    fn size(&self) -> u64;
    /// Writes `(offset, data)` items; `done(index, bytes)` per acknowledged write.
    fn write(
        &mut self,
        writes: &mut dyn Iterator<Item = io::Result<(u64, Vec<u8>)>>,
        done: &mut dyn FnMut(usize, u64),
    ) -> io::Result<()>;
    /// Flush and disconnect.
    fn finish(self: Box<Self>) -> io::Result<()>;
}

/// [`DiskWriter`] over the stdio of a `rollback-nbd <vmid> <device>` helper
/// session (ssh, or the helper itself in tests): the export is the device.
pub struct NbdDisk {
    child: Option<Child>,
    client: Option<nbd::Client<BufReader<ChildStdout>, BufWriter<ChildStdin>>>,
}

impl NbdDisk {
    /// `child` must have piped stdin and stdout.
    pub fn over(mut child: Child, device: &str) -> Result<NbdDisk> {
        let r = BufReader::with_capacity(1 << 20, child.stdout.take().context("child stdout")?);
        let w = BufWriter::with_capacity(1 << 20, child.stdin.take().context("child stdin")?);
        let mut d = NbdDisk {
            child: Some(child),
            client: None,
        };
        d.client = Some(nbd::Client::connect(r, w, device, &[]).context("NBD handshake")?);
        Ok(d)
    }

    fn client(&mut self) -> &mut nbd::Client<BufReader<ChildStdout>, BufWriter<ChildStdin>> {
        self.client.as_mut().expect("connected")
    }
}

impl Drop for NbdDisk {
    fn drop(&mut self) {
        if let Some(mut c) = self.child.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

impl DiskWriter for NbdDisk {
    fn size(&self) -> u64 {
        self.client.as_ref().map_or(0, |c| c.size())
    }

    fn write(
        &mut self,
        writes: &mut dyn Iterator<Item = io::Result<(u64, Vec<u8>)>>,
        done: &mut dyn FnMut(usize, u64),
    ) -> io::Result<()> {
        self.client().write_many(writes, DEPTH, done)
    }

    fn finish(mut self: Box<Self>) -> io::Result<()> {
        let mut c = self.client.take().expect("connected");
        c.flush()?;
        // dropped with it: stdin closes, the helper ends once the node side has closed
        c.disconnect()?;
        if let Some(mut child) = self.child.take() {
            let st = child.wait()?;
            if !st.success() {
                return Err(io::Error::other(format!("rollback-nbd session ended with {st}")));
            }
        }
        Ok(())
    }
}

/// `rollback-nbd` over the given command (stdin/stdout piped here).
pub fn open_nbd(mut cmd: std::process::Command, device: &str) -> Result<Box<dyn DiskWriter>> {
    let child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .context("spawn rollback-nbd")?;
    Ok(Box::new(NbdDisk::over(child, device)?))
}

/// What the rollback needs from PVE (implemented for `Cluster`; tests use a fake).
pub trait RollbackOps {
    /// node of an existing VM (`None`: no such VM, or not a VM)
    fn locate(&self, vmid: u32) -> Result<Option<String>>;
    fn config(&self, node: &str, vmid: u32) -> Result<Map<String, Value>>;
    fn set_config(&self, node: &str, vmid: u32, changes: &[(String, Option<String>)]) -> Result<()>;
    fn power(&self, node: &str, vmid: u32) -> Result<Power>;
    /// `suspend`, `resume`, `stop`, `start`, to completion
    fn act(&self, node: &str, vmid: u32, action: &str) -> Result<()>;
    /// An incremental backup that reuses the dirty bitmap of every disk; the
    /// snapshot time, or `None` (nothing committed) when PVE would read a disk in full.
    fn pre_backup(&self, store: &Store, vmid: u32) -> Result<Option<u64>>;
    /// `rollback-begin` / `rollback-end` on the node: its answer line
    fn helper(&self, node: &str, cmd: &str) -> Result<String>;
    fn open_disk(&self, node: &str, vmid: u32, device: &str) -> Result<Box<dyn DiskWriter>>;
}

#[derive(Debug, Default, Clone, PartialEq)]
pub struct RollbackOpts {
    pub start: bool,
    pub link_down: bool,
}

#[derive(Debug, PartialEq, Serialize)]
pub struct DiskReport {
    pub device: String,
    pub chunks: usize,
    pub changed: usize,
    pub bytes_written: u64,
}

/// Printed as `rolled-back {json}` for the job result.
#[derive(Debug, PartialEq, Serialize)]
pub struct Report {
    pub vmid: u32,
    pub snapshot: u64,
    /// the pre-rollback snapshot (the state before, kept in the store)
    pub pre_snapshot: u64,
    pub resumed: bool,
    pub disks: Vec<DiskReport>,
    /// disks the snapshot does not hold (backup=0, excluded): left as they are
    pub untouched: Vec<String>,
    pub started: bool,
    pub link_down: bool,
}

#[derive(Debug, PartialEq)]
pub enum Outcome {
    RolledBack(Report),
    /// in place is impossible (the reason); nothing was changed
    Fallback(String),
}

/// Disk keys of a VM config (main section): data disks, EFI and TPM state;
/// CD-ROMs, `none` and cloud-init drives are not disks of the snapshot.
pub fn disk_keys(conf: &BTreeMap<String, String>) -> BTreeMap<String, Option<u64>> {
    conf.iter()
        .filter(|(k, _)| is_disk_key(k))
        .filter(|(_, v)| {
            let first = v.split(',').next().unwrap_or("");
            !v.split(',').any(|o| o == "media=cdrom") && first != "none" && !first.contains("cloudinit")
        })
        .map(|(k, v)| {
            (
                k.clone(),
                v.split(',').find_map(|o| parse_size(o.strip_prefix("size=")?)),
            )
        })
        .collect()
}

fn is_disk_key(k: &str) -> bool {
    if k == "efidisk0" || k == "tpmstate0" {
        return true;
    }
    ["ide", "sata", "scsi", "virtio"].iter().any(|p| {
        k.strip_prefix(p)
            .is_some_and(|n| !n.is_empty() && n.len() <= 2 && n.bytes().all(|b| b.is_ascii_digit()))
    })
}

/// `32G`, `4M`, `528K`, `1T`, plain bytes.
pub fn parse_size(s: &str) -> Option<u64> {
    let (num, mul) = match s.chars().last()? {
        'K' => (&s[..s.len() - 1], 1u64 << 10),
        'M' => (&s[..s.len() - 1], 1 << 20),
        'G' => (&s[..s.len() - 1], 1 << 30),
        'T' => (&s[..s.len() - 1], 1 << 40),
        _ => (s, 1),
    };
    if let Ok(n) = num.parse::<u64>() {
        return n.checked_mul(mul);
    }
    let f: f64 = num.parse().ok()?;
    (f.is_finite() && f >= 0.0).then(|| (f * mul as f64).round() as u64)
}

/// `key: value` lines of a backed-up `qemu-server.conf` (main section).
pub fn conf_map(conf: &str) -> BTreeMap<String, String> {
    conf.lines()
        .take_while(|l| !l.starts_with('['))
        .filter_map(|l| {
            let (k, v) = l.split_once(':')?;
            Some((k.trim().to_owned(), v.trim().to_owned()))
        })
        .collect()
}

/// A live config (`GET …/config`) as `key -> value` strings.
pub fn live_map(cfg: &Map<String, Value>) -> BTreeMap<String, String> {
    cfg.iter()
        .filter_map(|(k, v)| {
            let s = match v {
                Value::String(s) => s.clone(),
                Value::Number(n) => n.to_string(),
                _ => return None,
            };
            Some((k.clone(), s))
        })
        .collect()
}

fn live_conf_text(m: &BTreeMap<String, String>) -> String {
    m.iter().map(|(k, v)| format!("{k}: {v}\n")).collect()
}

/// Step 1: why the VM cannot be rolled back in place (`None` = it can):
/// identity and disk layout of the snapshot config against the live one.
pub fn precheck(snap_conf: &str, live: &BTreeMap<String, String>) -> Option<String> {
    let id_then = Identity::of(snap_conf);
    let id_now = Identity::of(&live_conf_text(live));
    if id_now.differs(&id_then) {
        return Some(
            "the VM identity changed since the snapshot (vmgenid / SMBIOS UUID): its VMID belongs to another VM now"
                .into(),
        );
    }
    let then = disk_keys(&conf_map(snap_conf));
    let now = disk_keys(live);
    let a: BTreeSet<&String> = then.keys().collect();
    let b: BTreeSet<&String> = now.keys().collect();
    if a != b {
        let gone: Vec<&str> = a.difference(&b).map(|s| s.as_str()).collect();
        let new: Vec<&str> = b.difference(&a).map(|s| s.as_str()).collect();
        return Some(format!(
            "the disks changed since the snapshot (removed: {}; added: {})",
            if gone.is_empty() {
                "none".into()
            } else {
                gone.join(", ")
            },
            if new.is_empty() { "none".into() } else { new.join(", ") }
        ));
    }
    for (k, size) in &then {
        if let (Some(s), Some(n)) = (size, now.get(k).copied().flatten()) {
            if *s != n {
                return Some(format!("disk {k} was resized since the snapshot ({s} -> {n} bytes)"));
            }
        }
    }
    None
}

/// Step 4: the chunks of `target` that differ from `current` (same disk size and
/// chunk size required).
pub fn changed_chunks(target: &Index, current: &Index) -> Result<Vec<usize>> {
    let (
        Index::Fixed {
            chunk_size: cs_t,
            size: size_t,
            chunks: t,
        },
        Index::Fixed {
            chunk_size: cs_c,
            size: size_c,
            chunks: c,
        },
    ) = (target, current)
    else {
        bail!("not a disk index");
    };
    if cs_t != cs_c || size_t != size_c || t.len() != c.len() {
        bail!("disk size or chunk size differs ({size_t} vs {size_c} bytes)");
    }
    Ok(t.iter()
        .zip(c)
        .enumerate()
        .filter(|(_, (a, b))| a != b)
        .map(|(i, _)| i)
        .collect())
}

fn tags_with(tags: Option<&String>, add: bool) -> Option<String> {
    let mut v: Vec<&str> = tags
        .map(|t| {
            t.split([';', ',', ' '])
                .filter(|x| !x.is_empty() && *x != TAG)
                .collect()
        })
        .unwrap_or_default();
    if add {
        v.push(TAG);
    }
    (!v.is_empty()).then(|| v.join(";"))
}

/// Writes the differing chunks of every disk; all sessions are opened first.
fn write_disks(
    ops: &impl RollbackOps,
    store: &Store,
    node: &str,
    vmid: u32,
    plan: &[(String, Index, Vec<usize>)],
) -> Result<Vec<DiskReport>> {
    let mut sessions = Vec::new();
    for (dev, idx, _) in plan {
        let w = ops
            .open_disk(node, vmid, dev)
            .with_context(|| format!("open {dev} on {node}"))?;
        if w.size() != idx.size() {
            bail!("{dev}: the volume has {} bytes, the snapshot {}", w.size(), idx.size());
        }
        sessions.push(w);
    }
    let mut out = Vec::new();
    let parts = plan.len() as u32;
    for (n, ((dev, idx, changed), mut w)) in plan.iter().zip(sessions).enumerate() {
        let Index::Fixed {
            chunk_size,
            size,
            chunks,
        } = idx
        else {
            unreachable!()
        };
        let cs = *chunk_size as u64;
        let bytes: u64 = changed.iter().map(|&i| (size - i as u64 * cs).min(cs)).sum();
        let mut meter = chunkstore::progress::Meter::new(dev, n as u32 + 1, parts, Some(bytes));
        let mut writes = changed.iter().map(|&i| {
            let off = i as u64 * cs;
            let want = (size - off).min(cs) as usize;
            let data = store.read_chunk(&chunks[i])?;
            if data.len() != want {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("chunk {i} has {} bytes, expected {want}", data.len()),
                ));
            }
            Ok((off, data))
        });
        let mut written = 0u64;
        w.write(&mut writes, &mut |_, b| {
            written += b;
            meter.add(b);
        })
        .with_context(|| format!("write {dev}"))?;
        w.finish().with_context(|| format!("flush {dev}"))?;
        meter.finish();
        println!(
            "rolled back {dev}: {} of {} chunks written ({} bytes)",
            changed.len(),
            chunks.len(),
            written
        );
        out.push(DiskReport {
            device: dev.clone(),
            chunks: chunks.len(),
            changed: changed.len(),
            bytes_written: written,
        });
    }
    Ok(out)
}

/// Rolls VM `vmid` back to snapshot `vm-<vmid>/<time>` in place (module doc).
pub fn rollback(ops: &impl RollbackOps, store: &Store, vmid: u32, time: u64, o: &RollbackOpts) -> Result<Outcome> {
    let source = source_name(vmid);
    let m = store.load_manifest(&source, time)?;
    let snap_conf = read_config(store, &m, "qemu-server.conf")?.context("snapshot without qemu-server.conf")?;
    let Some(node) = ops.locate(vmid)? else {
        return Ok(Outcome::Fallback(format!("VM {vmid} no longer exists")));
    };
    let live = live_map(&ops.config(&node, vmid)?);
    let tagged = live
        .get("tags")
        .is_some_and(|t| t.split([';', ',', ' ']).any(|x| x == TAG));
    let resumed = tagged && live.get("lock").map(String::as_str) == Some("rollback");
    let pre = if resumed {
        // an interrupted rollback: the newest snapshot after the target is the pre-rollback one
        let pre = store
            .list_snapshots()?
            .into_iter()
            .filter(|s| s.source == source && s.time > time)
            .map(|s| s.time)
            .max()
            .context("resume: no snapshot newer than the target (the pre-rollback snapshot is gone)")?;
        println!("resuming the interrupted rollback of VM {vmid} (pre-rollback snapshot {source}/{pre})");
        pre
    } else {
        if let Some(why) = precheck(&snap_conf, &live) {
            return Ok(Outcome::Fallback(why));
        }
        match ops.power(&node, vmid)? {
            Power::Stopped => {
                return Ok(Outcome::Fallback(
                    "the VM is stopped: its dirty bitmap is gone (Proxmox VE keeps it only while the VM runs)".into(),
                ))
            }
            Power::Running => ops.act(&node, vmid, "suspend").context("pause the VM")?,
            Power::Paused => {}
        }
        println!("VM {vmid} paused: backing up its current state (pre-rollback snapshot)");
        let pre = match ops.pre_backup(store, vmid) {
            Ok(Some(t)) => t,
            Ok(None) => {
                ops.act(&node, vmid, "resume").context("resume the VM")?;
                return Ok(Outcome::Fallback(
                    "Proxmox VE cannot reuse the dirty bitmap of every disk (restarted since the last backup, or a new disk)"
                        .into(),
                ));
            }
            Err(e) => {
                if let Err(x) = ops.act(&node, vmid, "resume") {
                    eprintln!("resume VM {vmid} after the failed backup: {x:#}");
                }
                return Err(e.context("pre-rollback backup"));
            }
        };
        println!("pre-rollback snapshot {source}/{pre} committed");
        ops.act(&node, vmid, "stop").context("stop the VM")?;
        ops.set_config(&node, vmid, &[("tags".into(), tags_with(live.get("tags"), true))])
            .context("tag the VM for the rollback")?;
        pre
    };
    let answer = ops.helper(&node, &format!("rollback-begin {vmid}"))?;
    println!("node {node}: {answer}");

    // per disk: the differing chunks (snapshot vs. pre-rollback state)
    let pm = store.load_manifest(&source, pre)?;
    let mut plan = Vec::new();
    let mut untouched = Vec::new();
    for dev in m.indexes.iter().filter(|i| *i != "config") {
        let idx = store.load_index(&m, dev)?;
        let changed = if pm.indexes.contains(dev) {
            changed_chunks(&idx, &store.load_index(&pm, dev)?).with_context(|| dev.clone())?
        } else {
            // not in the pre-rollback snapshot (excluded there): every chunk
            (0..idx.chunk_ids().len()).collect()
        };
        plan.push((dev.clone(), idx, changed));
    }
    for k in disk_keys(&live).keys() {
        if !m.indexes.iter().any(|d| disk_key(d) == k) {
            untouched.push(k.clone());
        }
    }
    for k in &untouched {
        println!("disk {k} is not in the snapshot (backup=0 or excluded): left as it is");
    }
    let disks = write_disks(ops, store, &node, vmid, &plan).context(
        "rollback interrupted: the VM stays stopped and locked (rollback); run the rollback again to finish it, \
         or restore the VM with Replace original",
    )?;
    let answer = ops.helper(&node, &format!("rollback-end {vmid}"))?;
    println!("node {node}: {answer}");
    let live = ops.config(&node, vmid)?;
    let mut changes = vec![("tags".to_owned(), tags_with(live_map(&live).get("tags"), false))];
    if o.link_down {
        changes.extend(crate::restore::link_down_changes(&live));
    }
    ops.set_config(&node, vmid, &changes).context("untag the VM")?;
    if o.start {
        ops.act(&node, vmid, "start").context("start the VM")?;
    }
    Ok(Outcome::RolledBack(Report {
        vmid,
        snapshot: time,
        pre_snapshot: pre,
        resumed,
        disks,
        untouched,
        started: o.start,
        link_down: o.link_down,
    }))
}

impl RollbackOps for crate::backup::Cluster {
    fn locate(&self, vmid: u32) -> Result<Option<String>> {
        Ok(self
            .guest_nodes()?
            .remove(&vmid)
            .filter(|(_, k)| k == "qemu")
            .map(|(n, _)| n))
    }
    fn config(&self, node: &str, vmid: u32) -> Result<Map<String, Value>> {
        self.api.vm_config(node, vmid)
    }
    fn set_config(&self, node: &str, vmid: u32, changes: &[(String, Option<String>)]) -> Result<()> {
        self.api.set_config(node, "qemu", vmid, changes)
    }
    fn power(&self, node: &str, vmid: u32) -> Result<Power> {
        let st = self.api.get(&format!("/nodes/{node}/qemu/{vmid}/status/current"))?;
        Ok(match (st["status"].as_str(), st["qmpstatus"].as_str()) {
            (Some("running"), Some("paused" | "suspended" | "prelaunch")) => Power::Paused,
            (Some("running"), _) => Power::Running,
            _ => Power::Stopped,
        })
    }
    fn act(&self, node: &str, vmid: u32, action: &str) -> Result<()> {
        self.api.guest_power(node, "qemu", vmid, action, &[])
    }
    fn pre_backup(&self, store: &Store, vmid: u32) -> Result<Option<u64>> {
        let before = store.written();
        match self.backup_vm_with(store, vmid, true) {
            Ok((m, read)) => {
                println!("committed {}/{}", m.source, m.time);
                println!("{}", store.stats_line(&m, read, store.written().since(before))?);
                self.push_index(store)?;
                Ok(Some(m.time))
            }
            Err(e) if e.downcast_ref::<crate::backup::BitmapGone>().is_some() => {
                println!("pre-rollback backup refused: {e}");
                Ok(None)
            }
            Err(e) => Err(e),
        }
    }
    fn helper(&self, node: &str, cmd: &str) -> Result<String> {
        let out = self.ssh(node)?.run(cmd, None)?;
        Ok(String::from_utf8_lossy(&out).trim().to_owned())
    }
    fn open_disk(&self, node: &str, vmid: u32, device: &str) -> Result<Box<dyn DiskWriter>> {
        open_nbd(self.ssh(node)?.cmd(&format!("rollback-nbd {vmid} {device}")), device)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn live(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    const SNAP: &str = "name: web\nvmgenid: 1111-aa\nsmbios1: uuid=AAAA-1\nscsi0: local-lvm:vm-100-disk-0,size=32G\n\
        efidisk0: local-lvm:vm-100-disk-1,size=528K\nide2: local:iso/d.iso,media=cdrom\nide0: local-lvm:vm-100-cloudinit,media=cdrom\n\
        [snap1]\nscsi1: local-lvm:vm-100-disk-9,size=1G\n";

    #[test]
    fn sizes_and_disk_keys() {
        assert_eq!(parse_size("32G"), Some(32 << 30));
        assert_eq!(parse_size("528K"), Some(528 << 10));
        assert_eq!(parse_size("1.5G"), Some(3 << 29));
        assert_eq!(parse_size("4096"), Some(4096));
        assert_eq!(parse_size("x"), None);
        let k = disk_keys(&conf_map(SNAP));
        assert_eq!(
            k,
            [
                ("efidisk0".to_owned(), Some(528 << 10)),
                ("scsi0".to_owned(), Some(32 << 30))
            ]
            .into()
        );
        assert!(is_disk_key("virtio15") && !is_disk_key("net0") && !is_disk_key("scsihw") && !is_disk_key("scsi"));
    }

    #[test]
    fn precheck_identity_and_layout() {
        let same = live(&[
            ("vmgenid", "1111-AA"),
            ("smbios1", "uuid=aaaa-1"),
            ("scsi0", "local-lvm:vm-100-disk-0,iothread=1,size=32G"),
            ("efidisk0", "local-lvm:vm-100-disk-1,size=528K"),
            ("ide2", "none,media=cdrom"),
            ("tags", "prod"),
        ]);
        assert_eq!(precheck(SNAP, &same), None);
        let mut other = same.clone();
        other.insert("vmgenid".into(), "2222".into());
        assert!(precheck(SNAP, &other).unwrap().contains("identity"));
        let mut grown = same.clone();
        grown.insert("scsi0".into(), "local-lvm:vm-100-disk-0,size=40G".into());
        assert!(precheck(SNAP, &grown).unwrap().contains("resized"));
        let mut added = same.clone();
        added.insert("virtio1".into(), "local-lvm:vm-100-disk-5,size=8G".into());
        assert_eq!(
            precheck(SNAP, &added).unwrap(),
            "the disks changed since the snapshot (removed: none; added: virtio1)"
        );
        let mut removed = same;
        removed.remove("efidisk0");
        assert!(precheck(SNAP, &removed).unwrap().contains("removed: efidisk0"));
    }

    #[test]
    fn changed_chunks_by_id() {
        let id = |b: u8| -> chunkstore::ChunkId { [b; 32] };
        let a = Index::Fixed {
            chunk_size: 4,
            size: 10,
            chunks: vec![id(1), id(2), id(3)],
        };
        let b = Index::Fixed {
            chunk_size: 4,
            size: 10,
            chunks: vec![id(1), id(9), id(3)],
        };
        assert_eq!(changed_chunks(&a, &b).unwrap(), vec![1]);
        let c = Index::Fixed {
            chunk_size: 4,
            size: 12,
            chunks: vec![id(1), id(2), id(3)],
        };
        assert!(changed_chunks(&a, &c).is_err());
    }

    #[test]
    fn tags() {
        assert_eq!(
            tags_with(Some(&"prod;db".to_owned()), true).as_deref(),
            Some("prod;db;nexus-rollback")
        );
        assert_eq!(
            tags_with(Some(&"prod;nexus-rollback".to_owned()), false).as_deref(),
            Some("prod")
        );
        assert_eq!(tags_with(Some(&"nexus-rollback".to_owned()), false), None);
        assert_eq!(tags_with(None, true).as_deref(), Some("nexus-rollback"));
    }
}
