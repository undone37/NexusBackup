//! Appliance side of Hyper-V host backups (agent protocol v1.10, `CAP_HYPERV`, docs/hyperv-design.md M1): the
//! agent on the host takes a recovery checkpoint and opens the frozen disks, the appliance reads each disk with
//! block reads into a fixed index and commits snapshot `hv-<vm id>` in the PVE VM layout (one index per disk plus
//! `config` with `hyperv.json`); then the agent turns the checkpoint into a reference point (the next run's RCT
//! base) or, when anything failed, removes it.

use crate::blocks::{read_disk, valid_index_name, BlockReport};
use crate::map::MapDb;
use crate::name;
use crate::tls::Session;
use agent_proto::{Message, BLOCK_SIZE, CAP_HYPERV, MAX_BLOCK_TARGET};
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

/// Backs up VM `vm` of the host behind `s` (job id `job`, unique on that agent): checkpoint, a full read of every
/// disk, the snapshot, the reference point. M1: every block is read (incrementals by RCT are M2).
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
    s.send(&Message::HvPrepare { job, vm: vm.into() })?;
    let json = match s.recv()? {
        Message::HvPrepared { job: j, json } if j == job => json,
        m => bail!("unexpected answer to HvPrepare: {}", name(&m)),
    };
    let r = commit(store, map, s, job, vm, &json, log);
    s.send(&Message::HvFinish { job, keep: r.is_ok() })?;
    let finished = match s.recv() {
        Ok(Message::HvFinished { job: j, json }) if j == job => serde_json::from_str(&json).unwrap_or(Value::Null),
        Ok(m) => bail!("unexpected answer to HvFinish: {}", name(&m)),
        // the snapshot is committed (or the error below says why not); a failed conversion only costs M2's base
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
    let (source, time, disks) = r?;
    Ok(Report {
        source,
        time,
        disks,
        finished,
    })
}

type Committed = (String, u64, Vec<(String, BlockReport)>);

fn commit(
    store: &Store,
    map: &mut MapDb,
    s: &mut Session,
    job: u64,
    vm: &str,
    json: &str,
    log: &mut dyn FnMut(&str),
) -> Result<Committed> {
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
        let blocks = d.size.div_ceil(BLOCK_SIZE);
        let (idx, rep) = read_disk(
            store,
            map,
            s,
            job * 16 + u64::from(d.target),
            d.target,
            d.size,
            &[(0, blocks)],
            None,
            log,
        )
        .with_context(|| format!("disk {}", d.name))?;
        log(&format!(
            "{}: {} blocks read ({} bytes), {} fetched ({} bytes on the wire)",
            d.name, rep.blocks, rep.bytes, rep.wanted, rep.wire_bytes
        ));
        names.push(d.name.clone());
        indexes.push(idx);
        reports.push((d.name.clone(), rep));
    }
    let (chunks, size) = store.store_file(json.as_bytes())?;
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
    let source = source_name(vm);
    let prev = store
        .list_snapshots()?
        .into_iter()
        .filter(|m| m.source == source)
        .map(|m| m.time)
        .max();
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let time = now.max(prev.map_or(0, |t| t + 1));
    let refs: Vec<(&str, Index)> = names.iter().map(String::as_str).zip(indexes).collect();
    let m = store.commit_snapshot(&source, time, &refs)?;
    Ok((source, m.time, reports))
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
