//! Appliance side of Hyper-V host backups (agent protocol v1.10, `CAP_HYPERV`, docs/hyperv-design.md M1): the
//! agent on the host takes a recovery checkpoint and opens the frozen disks, the appliance reads each disk with
//! block reads into a fixed index and commits snapshot `hv-<vm id>` in the PVE VM layout (one index per disk plus
//! `config` with `hyperv.json`); then the agent turns the checkpoint into a reference point (the next run's RCT
//! base) or, when anything failed, removes it.

use crate::blocks::{block_ranges, read_disk, valid_index_name, BlockReport};
use crate::map::MapDb;
use crate::name;
use crate::name as name_of;
use crate::tls::Session;
use agent_proto::{Message, BLOCK_SIZE, CAP_HYPERV, CAP_HYPERV_RCT, MAX_BLOCK_TARGET};
use anyhow::{bail, Context, Result};
use chunkstore::{FileEntry, Index, Store};
use serde::Deserialize;
use serde_json::Value;
use std::time::{SystemTime, UNIX_EPOCH};

/// Config file in the snapshot's `config` index: the agent's `HvPrepared` answer (VM settings, disks).
pub const CONFIG_FILE: &str = "hyperv.json";

/// Snapshot source of a VM: `hv-` and its id in lower case (Hyper-V ids are GUIDs).
pub fn source_name(vm: &str) -> String {
    format!("hv-{}", vm.to_ascii_lowercase())
}

/// A Hyper-V VM id as the agent reports it (a GUID; also part of the source name).
pub fn valid_vm_id(vm: &str) -> bool {
    vm.len() == 36 && vm.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-')
}

/// The VMs of the host behind `s` (`HvVms`).
pub fn list(s: &mut Session) -> Result<Value> {
    if !s.has_cap(CAP_HYPERV) {
        bail!("the agent offers no Hyper-V backups (not a Hyper-V host, or agent older than 1.10)");
    }
    s.send(&Message::HvList)?;
    match s.recv()? {
        Message::HvVms { json } => serde_json::from_str(&json).context("HvVms"),
        m => bail!("unexpected answer to HvList: {}", name(&m)),
    }
}

#[derive(Deserialize)]
struct Prepared {
    disks: Vec<PreparedDisk>,
}

#[derive(Deserialize)]
struct PreparedDisk {
    name: String,
    target: u32,
    size: u64,
    /// #39 M2: byte ranges `[offset, length]` written since the base reference point; None = no valid base
    #[serde(default)]
    changed: Option<Vec<(u64, u64)>>,
}

/// One committed VM backup.
#[derive(Debug)]
pub struct Report {
    pub source: String,
    pub time: u64,
    /// per disk: index name and what reading it cost
    pub disks: Vec<(String, BlockReport)>,
    /// the agent's `HvFinished` answer (`{reference_point, rct}`)
    pub finished: Value,
}

/// Backs up VM `vm` of the host behind `s` (job id `job`, unique on that agent): checkpoint, the disks read (#39 M2:
/// with the previous snapshot's reference point only the blocks RCT reports as changed, the rest from the previous
/// index; a disk without a valid base in full), the checkpoint turned into a reference point, then the snapshot,
/// whose `hyperv.json` records that reference point as the next run's base.
pub fn backup(
    store: &Store,
    map: &mut MapDb,
    s: &mut Session,
    job: u64,
    vm: &str,
    log: &mut dyn FnMut(&str),
) -> Result<Report> {
    if !valid_vm_id(vm) {
        bail!("invalid VM id {vm:?}");
    }
    if !s.has_cap(CAP_HYPERV) {
        bail!("the agent offers no Hyper-V backups (not a Hyper-V host, or agent older than 1.10)");
    }
    let source = source_name(vm);
    let prev = previous(store, &source)?;
    let base = prev
        .as_ref()
        .and_then(|p| p.config["reference"]["rct"].as_array().cloned());
    match (&base, s.has_cap(CAP_HYPERV_RCT)) {
        (Some(rct), true) => s.send(&Message::HvPrepareBase {
            job,
            json: serde_json::json!({"vm": vm, "base": {"rct": rct}}).to_string(),
        })?,
        _ => s.send(&Message::HvPrepare { job, vm: vm.into() })?,
    }
    let json = match s.recv()? {
        Message::HvPrepared { job: j, json } if j == job => json,
        m => bail!("unexpected answer to HvPrepare: {}", name(&m)),
    };
    let r = read_disks(store, map, s, job, &json, prev.as_ref(), log);
    s.send(&Message::HvFinish { job, keep: r.is_ok() })?;
    let finished = match s.recv() {
        Ok(Message::HvFinished { job: j, json }) if j == job => serde_json::from_str(&json).unwrap_or(Value::Null),
        Ok(m) => bail!("unexpected answer to HvFinish: {}", name(&m)),
        // the disks were read: the snapshot is still committed, the next run has no base and reads in full
        Err(e) if r.is_ok() => {
            log(&format!(
                "warning: the checkpoint was not converted to a reference point: {e:#}"
            ));
            Value::Null
        }
        Err(e) => {
            return Err(r
                .unwrap_err()
                .context(format!("and the checkpoint was not removed: {e:#}")))
        }
    };
    let (names, indexes, disks) = r?;
    let (source, time) = commit(
        store,
        &source,
        &json,
        &finished,
        names,
        indexes,
        prev.as_ref().map(|p| p.time),
    )?;
    Ok(Report {
        source,
        time,
        disks,
        finished,
    })
}

/// The newest snapshot of a VM: its time, `hyperv.json` and disk indexes (the base of an incremental run).
struct Previous {
    time: u64,
    config: Value,
    manifest: chunkstore::Manifest,
}

fn previous(store: &Store, source: &str) -> Result<Option<Previous>> {
    let Some(m) = store
        .list_snapshots()?
        .into_iter()
        .filter(|m| m.source == source)
        .max_by_key(|m| m.time)
    else {
        return Ok(None);
    };
    let Index::Dynamic { entries } = store.load_index(&m, "config")? else {
        return Ok(None);
    };
    let Some(e) = entries.iter().find(|e| e.path == CONFIG_FILE) else {
        return Ok(None);
    };
    let mut data = Vec::new();
    for id in &e.chunks {
        data.extend(store.read_chunk(id)?);
    }
    let config = serde_json::from_slice(&data).unwrap_or(Value::Null);
    Ok(Some(Previous {
        time: m.time,
        config,
        manifest: m,
    }))
}

type Read = (Vec<String>, Vec<Index>, Vec<(String, BlockReport)>);

fn read_disks(
    store: &Store,
    map: &mut MapDb,
    s: &mut Session,
    job: u64,
    json: &str,
    prev: Option<&Previous>,
    log: &mut dyn FnMut(&str),
) -> Result<Read> {
    let p: Prepared = serde_json::from_str(json).context("HvPrepared")?;
    if p.disks.is_empty() {
        bail!("the VM has no virtual disk the checkpoint covers");
    }
    let mut names = Vec::new();
    let mut indexes = Vec::new();
    let mut reports = Vec::new();
    for d in &p.disks {
        if !valid_index_name(&d.name) || d.name == "config" || names.contains(&d.name) {
            bail!("agent: invalid disk name {:?}", d.name);
        }
        if !(1..=MAX_BLOCK_TARGET).contains(&d.target) || d.size == 0 {
            bail!("agent: disk {} at target {} with {} bytes", d.name, d.target, d.size);
        }
        // incremental: RCT's byte ranges as blocks, the rest from the previous snapshot's index of this disk
        let base_idx = match (&d.changed, prev) {
            (Some(_), Some(pv)) => store.load_index(&pv.manifest, &d.name).ok(),
            _ => None,
        };
        let (ranges, prev_idx) = match (&d.changed, base_idx) {
            (Some(ch), Some(idx @ Index::Fixed { size: psize, .. })) => {
                let mut ch = ch.clone();
                ch.sort_unstable();
                (block_ranges(&ch, d.size, psize), Some(idx))
            }
            _ => (vec![(0, d.size.div_ceil(BLOCK_SIZE))], None),
        };
        let mode = if prev_idx.is_some() {
            "changed blocks (RCT)"
        } else {
            "full read"
        };
        let (idx, rep) = read_disk(
            store,
            map,
            s,
            job * 16 + u64::from(d.target),
            d.target,
            d.size,
            &ranges,
            prev_idx.as_ref(),
            log,
        )
        .with_context(|| format!("disk {}", d.name))?;
        log(&format!(
            "{}: {mode}: {} blocks read ({} bytes), {} fetched ({} bytes on the wire)",
            d.name, rep.blocks, rep.bytes, rep.wanted, rep.wire_bytes
        ));
        names.push(d.name.clone());
        indexes.push(idx);
        reports.push((d.name.clone(), rep));
    }
    Ok((names, indexes, reports))
}

/// Commits the snapshot: the disk indexes plus `config/hyperv.json` = the agent's `HvPrepared` answer with the
/// reference point of this run (`reference`, the next run's base; null when the conversion failed).
fn commit(
    store: &Store,
    source: &str,
    prepared: &str,
    finished: &Value,
    mut names: Vec<String>,
    mut indexes: Vec<Index>,
    prev: Option<u64>,
) -> Result<(String, u64)> {
    let mut config: Value = serde_json::from_str(prepared).context("HvPrepared")?;
    // the changed ranges were only this run's input
    if let Some(ds) = config["disks"].as_array_mut() {
        for d in ds {
            if let Some(o) = d.as_object_mut() {
                o.remove("changed");
            }
        }
    }
    config["reference"] = if finished["rct"].is_array() {
        finished.clone()
    } else {
        Value::Null
    };
    let data = serde_json::to_vec(&config)?;
    let (chunks, size) = store.store_file(&data[..])?;
    names.push("config".into());
    indexes.push(Index::Dynamic {
        entries: vec![FileEntry {
            path: CONFIG_FILE.into(),
            mode: 0o640,
            size,
            mtime: 0,
            chunks,
        }],
    });
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let time = now.max(prev.map_or(0, |t| t + 1));
    let refs: Vec<(&str, Index)> = names.iter().map(String::as_str).zip(indexes).collect();
    let m = store.commit_snapshot(source, time, &refs)?;
    Ok((source.to_owned(), m.time))
}

/// #39 M4: snapshot `source`/`time` (an `hv-` snapshot) back onto the Hyper-V host behind `s` as a new VM `name`
/// (powered off, NICs not connected): the agent creates the disks, the appliance writes every block that is not
/// all zeros, then the agent defines the VM from the snapshot's settings. On any error the new disks are deleted.
/// Returns the agent's answer (`{vm}`, the new VM's id).
pub fn restore(
    store: &Store,
    s: &mut Session,
    job: u64,
    source: &str,
    time: u64,
    name: &str,
    log: &mut dyn FnMut(&str),
) -> Result<Value> {
    if !s.has_cap(agent_proto::CAP_HYPERV_RESTORE) {
        bail!("the agent cannot restore Hyper-V VMs (agent older than this feature, or not a Hyper-V host)");
    }
    if name.is_empty() || name.len() > 100 || name.chars().any(|c| c.is_control() || "\\/:*?\"<>|".contains(c)) {
        bail!("invalid VM name {name:?}");
    }
    let m = store.load_manifest(source, time)?;
    let Index::Dynamic { entries } = store.load_index(&m, "config")? else {
        bail!("{source}/{time}: no config index");
    };
    let e = entries
        .iter()
        .find(|e| e.path == CONFIG_FILE)
        .with_context(|| format!("{source}/{time}: no {CONFIG_FILE}"))?;
    let mut data = Vec::new();
    for id in &e.chunks {
        data.extend(store.read_chunk(id)?);
    }
    let cfg: Value = serde_json::from_slice(&data).context(CONFIG_FILE)?;
    let mut disks = Vec::new();
    for d in cfg["disks"].as_array().into_iter().flatten() {
        let n = d["name"]
            .as_str()
            .filter(|n| valid_index_name(n))
            .context("hyperv.json: disk name")?;
        let Index::Fixed { size, chunks, .. } = store.load_index(&m, n)? else {
            bail!("{source}/{time}: disk {n} is not a disk image");
        };
        disks.push((n.to_owned(), size, chunks));
    }
    if disks.is_empty() {
        bail!("{source}/{time}: no disks");
    }
    let spec = serde_json::json!({"name": name, "config": cfg["config"],
        "disks": disks.iter().map(|(n, size, _)| serde_json::json!({"name": n, "size": size})).collect::<Vec<_>>()});
    s.send(&Message::HvRestoreBegin {
        job,
        json: spec.to_string(),
    })?;
    let ready: Value = match s.recv()? {
        Message::HvRestoreReady { job: j, json } if j == job => {
            serde_json::from_str(&json).context("HvRestoreReady")?
        }
        m => bail!("unexpected answer to HvRestoreBegin: {}", name_of(&m)),
    };
    let r = (|| -> Result<()> {
        for (n, size, chunks) in &disks {
            let target = ready["disks"]
                .as_array()
                .into_iter()
                .flatten()
                .find(|d| d["name"] == n.as_str())
                .and_then(|d| d["target"].as_u64())
                .and_then(|t| u32::try_from(t).ok())
                .filter(|t| (1..=MAX_BLOCK_TARGET).contains(t))
                .with_context(|| format!("agent: no target for disk {n}"))?;
            let bjob = job * 16 + u64::from(target);
            let (mut sent, mut skipped) = (0u64, 0u64);
            for (i, id) in chunks.iter().enumerate() {
                let block = store.read_chunk(id)?;
                if block.iter().all(|b| *b == 0) {
                    skipped += 1;
                    continue;
                }
                s.send(&Message::BlockWrite {
                    job: bjob,
                    target,
                    offset: i as u64 * BLOCK_SIZE,
                    data: block,
                })?;
                sent += 1;
            }
            s.send(&Message::BlockWriteEnd { job: bjob, target })?;
            match s.recv()? {
                Message::BlockWritten { job: j, bytes } if j == bjob => {
                    log(&format!(
                        "{n}: {sent} blocks written ({bytes} bytes), {skipped} zero blocks skipped, {size} bytes"
                    ));
                }
                m => bail!("unexpected answer to BlockWriteEnd: {}", name_of(&m)),
            }
        }
        Ok(())
    })();
    s.send(&Message::HvRestoreFinish { job, keep: r.is_ok() })?;
    let fin = match s.recv() {
        Ok(Message::HvFinished { job: j, json }) if j == job => serde_json::from_str(&json).unwrap_or(Value::Null),
        Ok(m) => bail!("unexpected answer to HvRestoreFinish: {}", name_of(&m)),
        Err(e) => return Err(r.err().unwrap_or(e)),
    };
    r?;
    Ok(fin)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vm_ids_and_source_names() {
        let id = "5A1C2F0E-7B3D-4E6F-9A8B-0C1D2E3F4A5B";
        assert!(valid_vm_id(id));
        assert_eq!(source_name(id), "hv-5a1c2f0e-7b3d-4e6f-9a8b-0c1d2e3f4a5b");
        for bad in [
            "",
            "../x",
            "5A1C2F0E-7B3D-4E6F-9A8B-0C1D2E3F4A5",
            "5A1C2F0E/7B3D-4E6F-9A8B-0C1D2E3F4A5B",
        ] {
            assert!(!valid_vm_id(bad), "{bad}");
        }
    }
}
