//! Inventory and backups of XCP-ng VMs (docs/xcpng-design.md): a snapshot read over NBD, incremental with changed
//! block tracking against the previous run's metadata-only snapshot VDIs (`VDI.data_destroy`,
//! `VDI.list_changed_blocks`).

pub use crate::names::{source_name, valid_uuid};
use crate::nbdtls::{self, NbdInfo};
use crate::xapi::Xapi;
use anyhow::{bail, Context, Result};
use chunkstore::{FileEntry, Index, Manifest, Store};
use serde_json::{json, Value};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const CONFIG: &str = "xcpng.json";
/// CBT granularity of `VDI.list_changed_blocks`
const CBT_BLOCK: u64 = 64 << 10;

/// XAPI sends 64-bit integers as strings over JSON-RPC.
fn int(v: &Value) -> Option<u64> {
    v.as_u64().or_else(|| v.as_str()?.parse().ok())
}

/// The VMs of the pool: not templates, not snapshots, not the control domains.
pub fn inventory(x: &Xapi) -> Result<Vec<Value>> {
    let all = x.call("VM.get_all_records", &[])?;
    let mut out: Vec<Value> = all
        .as_object()
        .context("VM.get_all_records")?
        .values()
        .filter(|r| {
            !r["is_a_template"].as_bool().unwrap_or(true)
                && !r["is_a_snapshot"].as_bool().unwrap_or(true)
                && !r["is_control_domain"].as_bool().unwrap_or(true)
        })
        .map(|r| {
            json!({"id": r["uuid"], "title": r["name_label"], "kind": "vm", "tags": r["tags"],
                   "power": r["power_state"]})
        })
        .collect();
    out.sort_by(|a, b| a["title"].as_str().cmp(&b["title"].as_str()));
    Ok(out)
}

/// The index name of a disk by its VBD position: `xvda` for userdevice 0, ...
pub fn disk_name(userdevice: &str) -> String {
    match userdevice.parse::<u8>() {
        Ok(n) if n < 26 => format!("xvd{}", (b'a' + n) as char),
        _ => format!("disk{userdevice}"),
    }
}

/// One disk of a snapshot: its index name, the snapshot VDI and its size.
struct Disk {
    name: String,
    userdevice: String,
    vdi: String,
    size: u64,
}

fn disks(x: &Xapi, vm: &str) -> Result<Vec<Disk>> {
    let mut out = Vec::new();
    for vbd in x.call("VM.get_VBDs", &[json!(vm)])?.as_array().context("VBDs")? {
        let r = x.call("VBD.get_record", std::slice::from_ref(vbd))?;
        if r["type"].as_str() != Some("Disk") || r["empty"].as_bool() == Some(true) {
            continue;
        }
        let vdi = r["VDI"].as_str().context("VBD without VDI")?.to_owned();
        let size = int(&x.call("VDI.get_virtual_size", &[json!(vdi)])?).context("VDI size")?;
        let userdevice = r["userdevice"].as_str().unwrap_or("").to_owned();
        out.push(Disk {
            name: disk_name(&userdevice),
            userdevice,
            vdi,
            size,
        });
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
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

/// Destroys a snapshot VM, then its VDIs (only VDIs of the snapshot; the VM's own disks are never touched). A VDI
/// stays in use for a moment after an NBD read (xapi-nbd detaches it from dom0 asynchronously): retried for 60 s.
fn destroy_snapshot(x: &Xapi, snap: &str) -> Result<()> {
    if x.call("VM.get_is_a_snapshot", &[json!(snap)])?.as_bool() != Some(true) {
        bail!("{snap} is not a snapshot");
    }
    let vdis: Vec<String> = disks(x, snap)?.into_iter().map(|d| d.vdi).collect();
    x.call("VM.destroy", &[json!(snap)])?;
    for vdi in vdis {
        retry(x, "VDI.destroy", &vdi)?;
    }
    Ok(())
}

/// `method(vdi)`, retried for 60 s while the VDI is still in use.
fn retry(x: &Xapi, method: &str, vdi: &str) -> Result<()> {
    let mut tries = 0;
    loop {
        match x.call(method, &[json!(vdi)]) {
            Ok(_) => return Ok(()),
            Err(_) if tries < 30 => {
                tries += 1;
                std::thread::sleep(Duration::from_secs(2));
            }
            Err(e) => return Err(e),
        }
    }
}

/// After a commit: the snapshot VM destroyed, its VDIs with CBT reduced to CBT metadata (the next run's base, no data
/// on the SR), the others destroyed; then the previous run's metadata VDIs (`prev`: their UUIDs) destroyed.
fn keep_metadata(x: &Xapi, snap: &str, prev: &[String]) -> Result<()> {
    let vdis = disks(x, snap)?;
    x.call("VM.destroy", &[json!(snap)])?;
    for d in vdis {
        let cbt = x.call("VDI.get_cbt_enabled", &[json!(d.vdi)])?.as_bool() == Some(true);
        retry(x, if cbt { "VDI.data_destroy" } else { "VDI.destroy" }, &d.vdi)?;
    }
    for uuid in prev {
        // gone already (or never ours: only snapshot VDIs are destroyed)
        let Ok(r) = x.call("VDI.get_by_uuid", &[json!(uuid)]) else {
            continue;
        };
        if x.call("VDI.get_is_a_snapshot", std::slice::from_ref(&r))?.as_bool() == Some(true) {
            x.call("VDI.destroy", &[r])?;
        }
    }
    Ok(())
}

/// `(offset, length)` byte extents of the blocks set in a `VDI.list_changed_blocks` bitmap (64 KiB blocks, most
/// significant bit first), clipped to `size`, adjacent blocks merged.
fn bitmap_extents(bits: &[u8], size: u64) -> Vec<(u64, u64)> {
    let mut out: Vec<(u64, u64)> = Vec::new();
    for (i, byte) in bits.iter().enumerate().filter(|(_, b)| **b != 0) {
        for j in 0..8 {
            let off = (i as u64 * 8 + j) * CBT_BLOCK;
            if byte & (0x80 >> j) == 0 || off >= size {
                continue;
            }
            let len = CBT_BLOCK.min(size - off);
            match out.last_mut() {
                Some((o, l)) if *o + *l == off => *l += len,
                _ => out.push((off, len)),
            }
        }
    }
    out
}

/// The blocks changed between the metadata VDI `from` (UUID) and the snapshot VDI `to` (ref).
fn changed_extents(x: &Xapi, from: &str, to: &str, size: u64) -> Result<Vec<(u64, u64)>> {
    use base64::Engine;
    let from = x.call("VDI.get_by_uuid", &[json!(from)])?;
    let b = x.call("VDI.list_changed_blocks", &[from, json!(to)])?;
    let bits = base64::engine::general_purpose::STANDARD
        .decode(b.as_str().context("VDI.list_changed_blocks")?)
        .context("CBT bitmap")?;
    Ok(bitmap_extents(&bits, size))
}

/// The previous snapshot of `source` and its `xcpng.json`, if it has one.
fn previous(store: &Store, source: &str) -> Result<Option<(Manifest, Value)>> {
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
    let e = entries.iter().find(|e| e.path == CONFIG).context(CONFIG)?;
    let mut b = Vec::new();
    store.write_chunks(&e.chunks, &mut b)?;
    Ok(Some((m, serde_json::from_slice(&b).context(CONFIG)?)))
}

/// The metadata VDI UUIDs a config lists (`disks[].cbt_vdi`).
fn cbt_vdis(cfg: &Value) -> Vec<String> {
    cfg["disks"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|d| Some(d["cbt_vdi"].as_str()?.to_owned()))
        .collect()
}

/// Snapshots an earlier run left behind (`nexus-backup-*` of this VM: an aborted job) are removed first.
fn remove_leftovers(x: &Xapi, vm: &Value, name: &str) -> Result<()> {
    for snap in x
        .call("VM.get_snapshots", std::slice::from_ref(vm))?
        .as_array()
        .context("VM.get_snapshots")?
    {
        let label = x.call("VM.get_name_label", std::slice::from_ref(snap))?;
        if label.as_str().is_some_and(|l| l.starts_with("nexus-backup-")) {
            eprintln!("{name}: removing the leftover snapshot {label}");
            destroy_snapshot(x, snap.as_str().context("snapshot ref")?)?;
        }
    }
    Ok(())
}

/// What one VM's backup did.
#[derive(Debug)]
pub struct Done {
    pub manifest: Manifest,
    pub name: String,
    pub bytes_read: u64,
    /// disks read incrementally (the others in full)
    pub incremental: usize,
}

/// A backup of VM `uuid`: CBT enabled on its disks, snapshot, every disk of the snapshot read over NBD/TLS into a
/// fixed index (only the changed blocks when the previous run left a metadata VDI), the VM record and the disk map as
/// `xcpng.json`; then the snapshot reduced to CBT metadata, or destroyed after an error.
pub fn backup_vm(x: &Xapi, store: &Store, uuid: &str, job: u64, timeout: Duration) -> Result<Done> {
    if !valid_uuid(uuid) {
        bail!("invalid VM UUID {uuid:?}");
    }
    let vm = x.call("VM.get_by_uuid", &[json!(uuid)])?;
    let rec = x.call("VM.get_record", std::slice::from_ref(&vm))?;
    let name = rec["name_label"].as_str().unwrap_or(uuid).to_owned();
    remove_leftovers(x, &vm, &name)?;
    for d in disks(x, vm.as_str().context("VM ref")?)? {
        if x.call("VDI.get_cbt_enabled", &[json!(d.vdi)])?.as_bool() != Some(true) {
            // a VDI that refuses CBT (a raw VDI, an SR without it) is read in full every time
            if let Err(e) = x.call("VDI.enable_cbt", &[json!(d.vdi)]) {
                eprintln!("{name}: {}: no changed block tracking: {e:#}", d.name);
            }
        }
    }
    let prev = previous(store, &source_name(uuid))?;
    let snap = x.call("VM.snapshot", &[vm, json!(format!("nexus-backup-{job}"))])?;
    let snap = snap.as_str().context("VM.snapshot")?.to_owned();
    let res = read_snapshot(x, store, uuid, &rec, &snap, prev.as_ref(), timeout);
    let cleanup = match &res {
        Ok(_) => keep_metadata(x, &snap, &prev.as_ref().map(|(_, c)| cbt_vdis(c)).unwrap_or_default()),
        Err(_) => destroy_snapshot(x, &snap),
    };
    if let Err(e) = cleanup {
        eprintln!("{name}: snapshot nexus-backup-{job} not cleaned up: {e:#}");
    }
    let (manifest, bytes_read, incremental) = res?;
    Ok(Done {
        manifest,
        name,
        bytes_read,
        incremental,
    })
}

fn read_snapshot(
    x: &Xapi,
    store: &Store,
    uuid: &str,
    rec: &Value,
    snap: &str,
    prev: Option<&(Manifest, Value)>,
    timeout: Duration,
) -> Result<(Manifest, u64, usize)> {
    let chunk = agent_proto::BLOCK_SIZE as usize;
    let mut indexes = Vec::new();
    let mut map = Vec::new();
    let (mut read, mut incremental) = (0u64, 0);
    for d in disks(x, snap)? {
        // incremental: the previous index of this disk and CBT's extents since its metadata VDI; else a full read
        let base = prev.and_then(|(m, cfg)| {
            let e = cfg["disks"].as_array()?.iter().find(|e| e["name"] == d.name.as_str())?;
            Some((m, e["cbt_vdi"].as_str()?))
        });
        let changed = match base {
            Some((m, from)) => match changed_extents(x, from, &d.vdi, d.size) {
                Ok(ext) => Some((store.load_index(m, &d.name)?, ext)),
                Err(e) => {
                    eprintln!("{}: full read, no changed blocks: {e:#}", d.name);
                    None
                }
            },
            None => None,
        };
        let (prev_idx, dirty) = match &changed {
            Some((i, ext)) => (Some(i), ext.clone()),
            None => (None, vec![(0, d.size)]),
        };
        let info: Vec<NbdInfo> =
            serde_json::from_value(x.call("VDI.get_nbd_info", &[json!(d.vdi)])?).context("VDI.get_nbd_info")?;
        let info = info.first().with_context(|| {
            format!(
                "{}: no NBD export (is the `nbd` purpose set on a network of the host?)",
                d.name
            )
        })?;
        let mut c = nbdtls::connect(info, timeout).with_context(|| format!("{}: NBD", d.name))?;
        if c.size() != d.size {
            bail!("{}: the NBD export has {} bytes, the VDI {}", d.name, c.size(), d.size);
        }
        read += Store::image_extents_bytes(prev_idx, chunk, d.size, &dirty);
        incremental += usize::from(changed.is_some());
        let idx = store.store_image_extents(prev_idx, chunk, d.size, &dirty, |off, buf| c.read_at(off, buf))?;
        let _ = c.disconnect();
        let cbt = x.call("VDI.get_cbt_enabled", &[json!(d.vdi)])?.as_bool() == Some(true);
        let cbt_vdi = if cbt {
            x.call("VDI.get_uuid", &[json!(d.vdi)])?
        } else {
            Value::Null
        };
        map.push(json!({"name": d.name, "userdevice": d.userdevice, "size": d.size, "cbt_vdi": cbt_vdi}));
        indexes.push((d.name, idx));
    }
    // NICs by device number with their MACs (a restore keeps them when asked to)
    let mut vifs = Vec::new();
    for vif in x.call("VM.get_VIFs", &[json!(snap)])?.as_array().context("VIFs")? {
        let r = x.call("VIF.get_record", std::slice::from_ref(vif))?;
        vifs.push(json!({"device": r["device"], "MAC": r["MAC"]}));
    }
    let config = json!({"format": 1, "vifs": vifs, "vm": {
        "uuid": uuid, "name_label": rec["name_label"], "name_description": rec["name_description"],
        "VCPUs_max": rec["VCPUs_max"], "memory_static_max": rec["memory_static_max"], "platform": rec["platform"],
        "HVM_boot_params": rec["HVM_boot_params"], "HVM_boot_policy": rec["HVM_boot_policy"],
        "other_config": rec["other_config"], "tags": rec["tags"]}, "disks": map});
    let cfg = Index::Dynamic {
        entries: vec![config_entry(store, CONFIG, &serde_json::to_vec_pretty(&config)?)?],
    };
    let mut refs: Vec<(&str, Index)> = indexes.iter().map(|(n, i)| (n.as_str(), i.clone())).collect();
    refs.push(("config", cfg));
    let time = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let m = store.commit_snapshot(&source_name(uuid), time, &refs)?;
    Ok((m, read, incremental))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_and_numbers() {
        assert_eq!(
            (disk_name("0"), disk_name("1"), disk_name("x")),
            ("xvda".into(), "xvdb".into(), "diskx".into())
        );
        assert_eq!(
            (int(&json!("1073741824")), int(&json!(5)), int(&json!("x"))),
            (Some(1 << 30), Some(5), None)
        );
    }

    #[test]
    fn changed_block_bitmap() {
        const K: u64 = 64 << 10;
        // blocks 0, 1 and 23; block 24 lies beyond the disk's end; the last block clipped
        assert_eq!(
            bitmap_extents(&[0b1100_0000, 0, 0b0000_0001, 0b1000_0000], 24 * K - 100),
            vec![(0, 2 * K), (23 * K, K - 100)]
        );
        assert_eq!(bitmap_extents(&[0xff], 8 * K), vec![(0, 8 * K)]);
        assert!(bitmap_extents(&[], K).is_empty());
        assert_eq!(
            cbt_vdis(&json!({"disks": [{"cbt_vdi": "a"}, {"cbt_vdi": null}]})),
            vec!["a".to_owned()]
        );
    }
}
