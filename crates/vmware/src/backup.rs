//! Backup of one VM (docs/vmware-design.md "Flow of a backup"): snapshot the VM, read each disk's changed
//! blocks, write one fixed index per disk plus the configuration, remove the snapshot (also after an error).
//! The disk data is read either over NFC directly (no proxy VM) or through a hot-add proxy (an enrolled agent
//! with the block-read capability); both produce the same snapshot layout.

use crate::nfc::NfcDisk;
use crate::vsphere::{Client, Controller, Disk, MoRef};
use agent_conn::blocks::{block_ranges, read_disk, DiskRead, ReadPlan};
use agent_conn::map::MapDb;
use agent_conn::tls::Session;
use anyhow::{bail, Context, Result};
use chunkstore::progress;
use chunkstore::{FileEntry, Index, Manifest, Store};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Configuration entry with the VMware state of a snapshot: the disks and their change ids.
pub const STATE_FILE: &str = "vmware.json";
/// Largest `.vmx` taken (a real one is a few KiB).
const MAX_VMX: usize = 1 << 20;

/// What the next incremental backup needs, per disk name (`scsi0-0`, ...).
#[derive(Serialize, Deserialize, Debug, Default, Clone, PartialEq, Eq)]
pub struct State {
    pub vm: String,
    pub disks: BTreeMap<String, DiskState>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct DiskState {
    pub size: u64,
    /// CBT change id of the backed-up state (None: CBT was off)
    pub change_id: Option<String>,
    /// the disk file the snapshot pointed at
    pub file: String,
}

/// Where and as what one backup runs.
pub struct Spec<'a> {
    pub vm: &'a MoRef,
    /// datacenter of the `.vmx` download (`ha-datacenter` on a standalone host)
    pub datacenter: &'a str,
    /// job id: snapshot name `nexus-backup-<job>`, block read jobs `job * 16 + unit` on the proxy
    pub job: u64,
    /// read every block, ignore CBT (a full read)
    pub full: bool,
}

/// How the disk data is read.
pub enum Transport<'a> {
    /// over NFC directly, no proxy VM (a fresh ticket per disk; `crate::nfc`)
    Nfc { timeout: Duration },
    /// through a hot-add proxy VM: `proxy` is the proxy's moref, `session` the mTLS session to its agent, `map`
    /// the store's agent mapping index (plain block hash -> chunk; only this transport needs it)
    Proxy {
        proxy: &'a MoRef,
        session: &'a mut Session,
        map: &'a mut MapDb,
    },
}

pub use crate::names::source_name;

/// The index name of a disk: controller kind, bus and unit (`scsi0-1`).
pub fn disk_name(d: &Disk, controllers: &[Controller]) -> String {
    match controllers.iter().find(|c| c.key == d.controller_key) {
        Some(c) => format!("{}{}-{}", c.kind, c.bus, d.unit),
        None => format!("disk{}", d.key),
    }
}

fn config_entry(store: &Store, name: &str, data: &[u8]) -> Result<FileEntry> {
    let (chunks, size) = store.store_file(data)?;
    Ok(FileEntry {
        path: name.into(),
        mode: 0o640,
        size,
        mtime: 0,
        chunks,
    })
}

/// The previous snapshot of `source` and its state, if it has one.
fn previous(store: &Store, source: &str) -> Result<Option<(Manifest, State)>> {
    let Some(m) = store
        .list_snapshots()?
        .into_iter()
        .filter(|m| m.source == source)
        .max_by_key(|m| m.time)
    else {
        return Ok(None);
    };
    let Index::Dynamic { entries } = store.load_index(&m, "config")? else {
        bail!("{source}/{}: config index is not dynamic", m.time);
    };
    let Some(e) = entries.iter().find(|e| e.path == STATE_FILE) else {
        return Ok(None);
    };
    let mut b = Vec::new();
    store.write_chunks(&e.chunks, &mut b)?;
    Ok(Some((m, serde_json::from_slice(&b).context(STATE_FILE)?)))
}

/// Changed byte extents to read for a disk: the CBT extents for an incremental, or the whole disk.
fn dirty_of(changed: &Option<(Vec<(u64, u64)>, u64)>, capacity: u64) -> Vec<(u64, u64)> {
    match changed {
        Some((ext, _)) => ext.clone(),
        None => vec![(0, capacity)],
    }
}

/// Change-tracking check of a scheduled full read (scheduler `fullread.rs`, #91): blocks whose chunk differs
/// from the previous snapshot although CBT did not report them. Printed as `full-read <source>/<time> {json}`,
/// which also schedules the next full read.
#[derive(Default, Debug)]
pub struct FullRead {
    /// time of the previous snapshot the disks were compared with (none: nothing to compare)
    pub baseline: Option<u64>,
    pub compared: u64,
    pub changed: u64,
    pub unreported: u64,
    pub unreported_bytes: u64,
    pub examples: Vec<String>,
}

impl FullRead {
    /// One disk: `reported` are CBT's byte extents since the previous snapshot. Only whole blocks present in
    /// both sizes are compared (a grown disk's new blocks are new anyway).
    pub fn disk(&mut self, name: &str, baseline: u64, prev: &Index, new: &Index, reported: &[(u64, u64)]) {
        let (
            Index::Fixed {
                chunks: p, size: ps, ..
            },
            Index::Fixed {
                chunks: n, size: ns, ..
            },
        ) = (prev, new)
        else {
            return;
        };
        const B: u64 = agent_proto::BLOCK_SIZE;
        let mut rep = vec![false; n.len()];
        for &(off, len) in reported.iter().filter(|e| e.1 > 0) {
            for b in off / B..(off + len).div_ceil(B).min(n.len() as u64) {
                rep[b as usize] = true;
            }
        }
        let whole = (*ps).min(*ns) / B;
        for b in 0..whole.min(p.len() as u64).min(n.len() as u64) as usize {
            self.compared += 1;
            if p[b] != n[b] {
                self.changed += 1;
                if !rep[b] {
                    self.unreported += 1;
                    self.unreported_bytes += B;
                    if self.examples.len() < 10 {
                        self.examples.push(format!("{name}@{}", b as u64 * B));
                    }
                }
            }
        }
        self.baseline = Some(baseline);
    }

    pub fn line(&self, source: &str, time: u64) -> String {
        format!(
            "full-read {source}/{time} {}",
            serde_json::json!({"tracker": "cbt", "baseline": self.baseline, "compared": self.compared,
                               "changed": self.changed, "unreported": self.unreported,
                               "unreported_bytes": self.unreported_bytes, "examples": self.examples})
        )
    }
}

/// Reads a disk over NFC into a fixed index, with the unchanged blocks taken from `prev_index`.
#[allow(clippy::too_many_arguments)]
fn read_disk_nfc(
    c: &Client,
    store: &Store,
    vm: &MoRef,
    d: &Disk,
    prev_index: Option<&Index>,
    changed: &Option<(Vec<(u64, u64)>, u64)>,
    timeout: Duration,
    part: (&str, u32, u32),
    log: &mut dyn FnMut(&str),
) -> Result<Index> {
    let dirty = dirty_of(changed, d.capacity);
    let prev = changed.as_ref().and(prev_index);
    let chunk = agent_proto::BLOCK_SIZE as usize;
    let to_read = Store::image_extents_bytes(prev, chunk, d.capacity, &dirty);
    let ticket = c.nfc_ticket(vm)?; // single-use: a fresh ticket per disk
    let mut disk = NfcDisk::open(&ticket, &d.file, d.capacity, timeout)?;
    // live progress of the job: the bytes of this disk read over NFC
    let mut meter = progress::Meter::new(part.0, part.1, part.2, Some(to_read));
    let idx = store.store_image_extents(prev, chunk, d.capacity, &dirty, |off, buf| {
        disk.read_at(off, buf)
            .map_err(|e| std::io::Error::other(format!("{e:#}")))?;
        meter.add(buf.len() as u64);
        Ok(())
    });
    meter.finish();
    disk.close();
    let idx = idx?;
    log(&format!("{}: {to_read} bytes read over NFC", d.file));
    Ok(idx)
}

/// Reads a disk through the hot-add proxy: attach, block-scan via the proxy agent, detach.
#[allow(clippy::too_many_arguments)]
fn read_disk_proxy(
    c: &Client,
    store: &Store,
    map: &mut MapDb,
    session: &mut Session,
    proxy: &MoRef,
    job: u64,
    d: &Disk,
    prev_index: Option<&Index>,
    changed: &Option<(Vec<(u64, u64)>, u64)>,
    log: &mut dyn FnMut(&str),
) -> Result<Index> {
    let (pdisks, pcontrollers) = c.devices(proxy)?;
    let bus0 = pcontrollers
        .iter()
        .find(|k| k.kind == "scsi" && k.bus == 0)
        .context("the proxy has no SCSI controller 0")?;
    // a free unit on controller 0 (each disk is detached after it is read, so units are reused)
    let unit = (1..=agent_proto::MAX_BLOCK_TARGET as i32)
        .find(|u| *u != 7 && !pdisks.iter().any(|x| x.controller_key == bus0.key && x.unit == *u))
        .context("no free SCSI unit on the proxy's controller 0")?;
    let (ranges, prev) = match changed {
        Some((ext, psize)) => (block_ranges(ext, d.capacity, *psize), prev_index),
        None => (block_ranges(&[], d.capacity, 0), None),
    };
    c.attach(proxy, bus0.key, unit, &d.file, d.capacity)
        .with_context(|| format!("hot-add of {} to the proxy", d.file))?;
    let r = read_disk(
        store,
        map,
        session,
        job * 16 + unit as u64,
        unit as u32,
        d.capacity,
        &ranges,
        prev,
        log,
    );
    // remove the attached device, as the proxy's configuration has it now (also on a read error)
    let detached = c.devices(proxy).and_then(|(now, _)| {
        match now.iter().find(|x| x.controller_key == bus0.key && x.unit == unit) {
            Some(x) => c.detach(proxy, x),
            None => Ok(()),
        }
    });
    let (idx, rep) = r?;
    detached.with_context(|| format!("removal of {} from the proxy", d.file))?;
    log(&format!(
        "{}: {} blocks read ({} bytes), {} fetched ({} bytes on the wire)",
        d.file, rep.blocks, rep.bytes, rep.wanted, rep.wire_bytes
    ));
    Ok(idx)
}

/// One VM over the given transport. Returns the committed snapshot.
pub fn backup_vm(
    c: &Client,
    store: &Store,
    transport: &mut Transport,
    spec: &Spec,
    log: &mut dyn FnMut(&str),
) -> Result<Manifest> {
    let info = c.vm_info(spec.vm)?;
    let source = source_name(&info.uuid);
    if !info.cbt {
        // takes effect with the snapshot below: this backup is a full read, the next one incremental
        log(&format!("{}: changed block tracking enabled", info.name));
        c.set_cbt(spec.vm, true)?;
    }
    // a full read still compares with the previous snapshot (FullRead)
    let prev = previous(store, &source)?;
    if !info.tools {
        log(&format!(
            "{}: VMware Tools not running: crash-consistent snapshot",
            info.name
        ));
    }
    let snap = c
        .create_snapshot(spec.vm, &format!("nexus-backup-{}", spec.job), info.tools)
        .with_context(|| format!("snapshot of {}", info.name))?;
    let r = with_snapshot(c, store, transport, spec, &info.vmx, &source, &snap, prev.as_ref(), log);
    if let Err(e) = c.remove_snapshot(&snap) {
        // the backup itself may have worked: report the leftover by name
        log(&format!(
            "warning: snapshot nexus-backup-{} of {} not removed: {e:#}",
            spec.job, info.name
        ));
    }
    r
}

#[allow(clippy::too_many_arguments)]
fn with_snapshot(
    c: &Client,
    store: &Store,
    transport: &mut Transport,
    spec: &Spec,
    vmx_path: &str,
    source: &str,
    snap: &MoRef,
    prev: Option<&(Manifest, State)>,
    log: &mut dyn FnMut(&str),
) -> Result<Manifest> {
    let (disks, controllers) = c.devices(snap)?;
    let mut state = State {
        vm: vmx_path.into(),
        disks: BTreeMap::new(),
    };
    let mut names = Vec::new();
    let mut indexes = Vec::new();
    let mut full = spec.full.then(FullRead::default);
    for (i, d) in disks.iter().enumerate() {
        let name = disk_name(d, &controllers);
        let base = prev.and_then(|(m, st)| Some((m, st.disks.get(&name)?)));
        let prev_index = match base {
            Some((m, _)) if m.indexes.contains(&name) => Some(store.load_index(m, &name)?),
            _ => None,
        };
        // incremental: CBT byte extents against the previous change id of this disk; anything else is a full read
        let mut changed = match (base, &prev_index) {
            (Some((_, ds)), Some(_)) => match &ds.change_id {
                Some(id) => match c.changed_areas(spec.vm, snap, d, id) {
                    Ok(x) => Some((x, ds.size)),
                    Err(e) => {
                        log(&format!("{name}: no changed blocks ({e:#}): full read"));
                        None
                    }
                },
                None => None,
            },
            _ => None,
        };
        // scheduled full read: every block is read, CBT's answer is only kept for the check
        let reported = if full.is_some() { changed.take() } else { None };
        log(&format!(
            "{name}: {} bytes{}",
            d.capacity,
            if changed.is_some() && prev_index.is_some() {
                " (incremental)"
            } else {
                " (full)"
            }
        ));
        let idx = match transport {
            Transport::Nfc { timeout } => {
                let part = (name.as_str(), i as u32 + 1, disks.len() as u32);
                read_disk_nfc(c, store, spec.vm, d, prev_index.as_ref(), &changed, *timeout, part, log)
                    .with_context(|| format!("{name}: NFC read"))?
            }
            Transport::Proxy { proxy, session, map } => read_disk_proxy(
                c,
                store,
                map,
                session,
                proxy,
                spec.job,
                d,
                prev_index.as_ref(),
                &changed,
                log,
            )
            .with_context(|| format!("{name}: block read through the proxy"))?,
        };
        if let (Some(f), Some(p), Some((ext, _)), Some((m, _))) = (&mut full, &prev_index, &reported, prev) {
            f.disk(&name, m.time, p, &idx, ext);
        }
        state.disks.insert(
            name.clone(),
            DiskState {
                size: d.capacity,
                change_id: d.change_id.clone(),
                file: d.file.clone(),
            },
        );
        names.push(name);
        indexes.push(idx);
    }
    commit_vm(
        c,
        store,
        spec.datacenter,
        source,
        &state,
        names,
        indexes,
        prev.map(|(m, _)| m.time),
        full.as_ref(),
        log,
    )
}

/// Commits the snapshot of one VM: the disk indexes plus the config index (`vmware.json`, the `.vmx`).
#[allow(clippy::too_many_arguments)]
fn commit_vm(
    c: &Client,
    store: &Store,
    datacenter: &str,
    source: &str,
    state: &State,
    mut names: Vec<String>,
    mut indexes: Vec<Index>,
    prev_time: Option<u64>,
    full: Option<&FullRead>,
    log: &mut dyn FnMut(&str),
) -> Result<Manifest> {
    let mut entries = vec![config_entry(store, STATE_FILE, &serde_json::to_vec_pretty(state)?)?];
    match c.download(&state.vm, datacenter, MAX_VMX) {
        Ok(vmx) => entries.push(config_entry(store, "vm.vmx", &vmx)?),
        Err(e) => log(&format!("warning: the .vmx was not stored: {e:#}")),
    }
    names.push("config".into());
    indexes.push(Index::Dynamic { entries });
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let time = now.max(prev_time.map_or(0, |t| t + 1));
    let refs: Vec<(&str, Index)> = names.iter().map(String::as_str).zip(indexes).collect();
    let m = store.commit_snapshot(source, time, &refs)?;
    if let Some(f) = full {
        log(&f.line(source, m.time));
    }
    Ok(m)
}

// ---- hot-add proxy in three job steps (#80): the agent CA stays with nexus-agentctl -------------------------

/// What `proxy-prepare` leaves for `proxy-finish`: the snapshot and the disks hot-added to the proxy.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct ProxyState {
    pub vm: MoRef,
    pub vm_name: String,
    pub snap: MoRef,
    pub proxy: MoRef,
    /// key of the proxy's SCSI controller 0
    pub bus0: i32,
    pub source: String,
    /// `[ds] dir/vm.vmx`
    pub vmx: String,
    /// VMware Tools quiesced the snapshot
    pub quiesced: bool,
    pub prev_time: Option<u64>,
    /// a scheduled full read: finish compares with the previous snapshot (FullRead)
    #[serde(default)]
    pub full: bool,
    pub disks: Vec<ProxyDisk>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct ProxyDisk {
    pub name: String,
    /// SCSI unit on the proxy's controller 0
    pub unit: i32,
    pub file: String,
    pub capacity: u64,
    pub change_id: Option<String>,
    /// full read: CBT's byte extents since the previous snapshot, for the check in finish
    #[serde(default)]
    pub reported: Option<Vec<(u64, u64)>>,
}

/// Removes what an aborted proxy job left: `nexus-backup-*` snapshots of the VM and disks of other VMs still
/// hot-added to the proxy (any disk on controller 0 outside the proxy's own directory).
/// ponytail: assumes one proxy job per proxy at a time (the scheduler runs one backup per source); two sources
/// sharing a proxy concurrently would detach each other's disks.
fn proxy_cleanup(c: &Client, vm: &MoRef, proxy: &MoRef, log: &mut dyn FnMut(&str)) -> Result<()> {
    for (s, name) in c.snapshots(vm)? {
        if name.starts_with("nexus-backup-") {
            log(&format!("removing the leftover snapshot {name}"));
            c.remove_snapshot(&s)?;
        }
    }
    let own = c.vm_info(proxy)?.vmx;
    let own_dir = own.rsplit_once('/').map_or(own.as_str(), |(d, _)| d);
    let (pdisks, pcontrollers) = c.devices(proxy)?;
    let bus0 = pcontrollers.iter().find(|k| k.kind == "scsi" && k.bus == 0);
    for d in pdisks {
        if bus0.is_some_and(|b| b.key == d.controller_key) && !d.file.starts_with(&format!("{own_dir}/")) {
            log(&format!("detaching the leftover disk {} from the proxy", d.file));
            c.detach(proxy, &d)?;
        }
    }
    Ok(())
}

/// Step 1: snapshot of the VM, its disks hot-added to `proxy`, the read plan for nexus-agentctl (`job`: the
/// block read job ids on the proxy). Undoes itself (detach, snapshot removal) when it fails half way.
pub fn proxy_prepare(
    c: &Client,
    store: &Store,
    spec: &Spec,
    proxy: &MoRef,
    log: &mut dyn FnMut(&str),
) -> Result<(ProxyState, ReadPlan)> {
    let info = c.vm_info(spec.vm)?;
    let source = source_name(&info.uuid);
    proxy_cleanup(c, spec.vm, proxy, log).context("cleanup of an earlier proxy job")?;
    if !info.cbt {
        log(&format!("{}: changed block tracking enabled", info.name));
        c.set_cbt(spec.vm, true)?;
    }
    let prev = previous(store, &source)?;
    if !info.tools {
        log(&format!(
            "{}: VMware Tools not running: crash-consistent snapshot",
            info.name
        ));
    }
    let snap = c
        .create_snapshot(spec.vm, &format!("nexus-backup-{}", spec.job), info.tools)
        .with_context(|| format!("snapshot of {}", info.name))?;
    let mut state = ProxyState {
        vm: spec.vm.clone(),
        vm_name: info.name.clone(),
        snap: snap.clone(),
        proxy: proxy.clone(),
        bus0: 0,
        source,
        vmx: info.vmx.clone(),
        quiesced: info.tools,
        prev_time: prev.as_ref().map(|(m, _)| m.time),
        full: spec.full,
        disks: Vec::new(),
    };
    let mut plan = ReadPlan {
        job: spec.job,
        disks: Vec::new(),
    };
    let r = (|| -> Result<()> {
        let (disks, controllers) = c.devices(&snap)?;
        let (pdisks, pcontrollers) = c.devices(proxy)?;
        state.bus0 = pcontrollers
            .iter()
            .find(|k| k.kind == "scsi" && k.bus == 0)
            .context("the proxy has no SCSI controller 0")?
            .key;
        let mut free = (1..=agent_proto::MAX_BLOCK_TARGET as i32)
            .filter(|u| *u != 7 && !pdisks.iter().any(|x| x.controller_key == state.bus0 && x.unit == *u));
        for d in &disks {
            let name = disk_name(d, &controllers);
            let base = prev.as_ref().and_then(|(m, st)| Some((m, st.disks.get(&name)?)));
            let mut changed = match base {
                Some((m, ds)) if m.indexes.contains(&name) => match &ds.change_id {
                    Some(id) => match c.changed_areas(spec.vm, &snap, d, id) {
                        Ok(x) => Some((x, ds.size, m.time)),
                        Err(e) => {
                            log(&format!("{name}: no changed blocks ({e:#}): full read"));
                            None
                        }
                    },
                    None => None,
                },
                _ => None,
            };
            // scheduled full read: every block is read, CBT's answer is only kept for the check
            let reported = if spec.full {
                changed.take().map(|(x, _, _)| x)
            } else {
                None
            };
            let unit = free.next().context("no free SCSI unit on the proxy's controller 0")?;
            c.attach(proxy, state.bus0, unit, &d.file, d.capacity)
                .with_context(|| format!("hot-add of {} to the proxy", d.file))?;
            state.disks.push(ProxyDisk {
                name: name.clone(),
                unit,
                file: d.file.clone(),
                capacity: d.capacity,
                change_id: d.change_id.clone(),
                reported,
            });
            let (ranges, prev) = match &changed {
                Some((x, psize, t)) => (block_ranges(x, d.capacity, *psize), Some((state.source.clone(), *t))),
                None => (block_ranges(&[], d.capacity, 0), None),
            };
            log(&format!(
                "{name}: {} bytes, {} block range(s){} at the proxy's SCSI 0:{unit}",
                d.capacity,
                ranges.len(),
                if prev.is_some() { " (incremental)" } else { " (full)" }
            ));
            plan.disks.push(DiskRead {
                name,
                target: unit as u32,
                size: d.capacity,
                ranges,
                prev,
            });
        }
        Ok(())
    })();
    if let Err(e) = r {
        let _ = proxy_detach(c, &state, log);
        let _ = c.remove_snapshot(&snap);
        return Err(e);
    }
    Ok((state, plan))
}

/// Removes the hot-added disks from the proxy; the first error after trying all.
fn proxy_detach(c: &Client, state: &ProxyState, log: &mut dyn FnMut(&str)) -> Result<()> {
    let (now, _) = c.devices(&state.proxy)?;
    let mut first = None;
    for d in &state.disks {
        if let Some(x) = now.iter().find(|x| x.controller_key == state.bus0 && x.unit == d.unit) {
            if let Err(e) = c.detach(&state.proxy, x) {
                log(&format!("warning: {} not removed from the proxy: {e:#}", d.file));
                first.get_or_insert(e);
            }
        }
    }
    first.map_or(Ok(()), Err)
}

/// Step 3: the disks removed from the proxy and the snapshot removed (always), then the snapshot committed from
/// the indexes nexus-agentctl wrote to `dir` (`<name>.idx`; a `<name>.err` fails the VM).
pub fn proxy_finish(
    c: &Client,
    store: &Store,
    state: &ProxyState,
    dir: &Path,
    datacenter: &str,
    log: &mut dyn FnMut(&str),
) -> Result<Manifest> {
    let detached = proxy_detach(c, state, log);
    if let Err(e) = c.remove_snapshot(&state.snap) {
        log(&format!("warning: snapshot of {} not removed: {e:#}", state.vm_name));
    }
    detached.context("removal of the disks from the proxy")?;
    if let Ok(err) = std::fs::read_to_string(dir.join("block-read.err")) {
        bail!("block read through the proxy failed: {err}");
    }
    let mut names = Vec::new();
    let mut indexes = Vec::new();
    let mut disks = BTreeMap::new();
    let mut full = state.full.then(FullRead::default);
    let base = match (state.full, state.prev_time) {
        (true, Some(t)) => Some(store.load_manifest(&state.source, t)?),
        _ => None,
    };
    for d in &state.disks {
        if let Ok(err) = std::fs::read_to_string(dir.join(format!("{}.err", d.name))) {
            bail!("{}: block read through the proxy failed: {err}", d.name);
        }
        let idx: Index = serde_json::from_slice(
            &std::fs::read(dir.join(format!("{}.idx", d.name)))
                .with_context(|| format!("{}: no index from the block read", d.name))?,
        )
        .with_context(|| format!("{}.idx", d.name))?;
        match &idx {
            Index::Fixed { size, .. } if *size == d.capacity => {}
            _ => bail!("{}: the block read's index does not match the disk", d.name),
        }
        if let (Some(f), Some(m), Some(ext)) = (&mut full, &base, &d.reported) {
            if m.indexes.contains(&d.name) {
                f.disk(&d.name, m.time, &store.load_index(m, &d.name)?, &idx, ext);
            }
        }
        disks.insert(
            d.name.clone(),
            DiskState {
                size: d.capacity,
                change_id: d.change_id.clone(),
                file: d.file.clone(),
            },
        );
        names.push(d.name.clone());
        indexes.push(idx);
    }
    let st = State {
        vm: state.vmx.clone(),
        disks,
    };
    commit_vm(
        c,
        store,
        datacenter,
        &state.source,
        &st,
        names,
        indexes,
        state.prev_time,
        full.as_ref(),
        log,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_read_finds_changes_cbt_did_not_report() {
        const B: u64 = agent_proto::BLOCK_SIZE;
        let fixed = |ids: &[u8], size: u64| Index::Fixed {
            chunk_size: B as u32,
            size,
            chunks: ids.iter().map(|i| [*i; 32]).collect(),
        };
        // 4 blocks before, the disk grew to 5; blocks 1 and 3 changed, CBT reported only a byte inside block 1
        let prev = fixed(&[0, 1, 2, 3], 4 * B);
        let new = fixed(&[0, 9, 2, 8, 7], 5 * B);
        let mut f = FullRead::default();
        f.disk("scsi0-0", 1000, &prev, &new, &[(B + 10, 5)]);
        assert_eq!((f.compared, f.changed, f.unreported), (4, 2, 1));
        assert_eq!(f.unreported_bytes, B);
        assert_eq!(f.examples, [format!("scsi0-0@{}", 3 * B)]);
        let line = f.line("vmw-x", 2000);
        let (head, js) = line.split_at(line.find('{').unwrap());
        assert_eq!(head, "full-read vmw-x/2000 ");
        let v: serde_json::Value = serde_json::from_str(js).unwrap();
        assert_eq!(
            (v["baseline"].as_u64(), v["tracker"].as_str()),
            (Some(1000), Some("cbt"))
        );
        // nothing compared: no baseline (the scheduler records "no_baseline")
        assert!(FullRead::default().line("vmw-x", 1).contains("\"baseline\":null"));
    }

    #[test]
    fn disk_names() {
        let c = [
            Controller {
                key: 1000,
                bus: 0,
                kind: "scsi",
            },
            Controller {
                key: 15000,
                bus: 1,
                kind: "sata",
            },
        ];
        let d = |controller_key, unit| Disk {
            key: 2000,
            controller_key,
            unit,
            capacity: 1,
            file: String::new(),
            base_file: String::new(),
            change_id: None,
        };
        assert_eq!(disk_name(&d(1000, 1), &c), "scsi0-1");
        assert_eq!(disk_name(&d(15000, 0), &c), "sata1-0");
        assert_eq!(disk_name(&d(99, 0), &c), "disk2000");
    }
}
