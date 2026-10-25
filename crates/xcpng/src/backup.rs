//! Inventory and backups of XCP-ng VMs (docs/xcpng-design.md). M1: full reads; changed block tracking with
//! metadata-only snapshots (`VDI.data_destroy`, `VDI.list_changed_blocks`) is M2.

use crate::nbdtls::{self, NbdInfo};
use crate::xapi::Xapi;
use anyhow::{bail, Context, Result};
use chunkstore::{FileEntry, Index, Manifest, Store};
use serde_json::{json, Value};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Snapshot source of a VM: `xcp-<vm uuid>`.
pub fn source_name(uuid: &str) -> String {
    format!("xcp-{uuid}")
}

/// A VM UUID as XAPI prints them (lowercase, 8-4-4-4-12).
pub fn valid_uuid(s: &str) -> bool {
    s.len() == 36
        && s.char_indices().all(|(i, c)| {
            if [8, 13, 18, 23].contains(&i) {
                c == '-'
            } else {
                c.is_ascii_hexdigit()
            }
        })
}

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
        let mut tries = 0;
        loop {
            match x.call("VDI.destroy", &[json!(vdi)]) {
                Ok(_) => break,
                Err(_) if tries < 30 => {
                    tries += 1;
                    std::thread::sleep(Duration::from_secs(2));
                }
                Err(e) => return Err(e),
            }
        }
    }
    Ok(())
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
}

/// A full backup of VM `uuid`: snapshot, every disk of the snapshot read over NBD/TLS into a fixed index, the VM
/// record and the disk map as `xcpng.json`, the snapshot destroyed (also after an error).
pub fn backup_vm(x: &Xapi, store: &Store, uuid: &str, job: u64, timeout: Duration) -> Result<Done> {
    if !valid_uuid(uuid) {
        bail!("invalid VM UUID {uuid:?}");
    }
    let vm = x.call("VM.get_by_uuid", &[json!(uuid)])?;
    let rec = x.call("VM.get_record", std::slice::from_ref(&vm))?;
    let name = rec["name_label"].as_str().unwrap_or(uuid).to_owned();
    remove_leftovers(x, &vm, &name)?;
    let snap = x.call("VM.snapshot", &[vm, json!(format!("nexus-backup-{job}"))])?;
    let snap = snap.as_str().context("VM.snapshot")?.to_owned();
    let res = read_snapshot(x, store, uuid, &rec, &snap, timeout);
    if let Err(e) = destroy_snapshot(x, &snap) {
        eprintln!("{name}: snapshot nexus-backup-{job} not removed: {e:#}");
    }
    let (manifest, bytes_read) = res?;
    Ok(Done {
        manifest,
        name,
        bytes_read,
    })
}

fn read_snapshot(
    x: &Xapi,
    store: &Store,
    uuid: &str,
    rec: &Value,
    snap: &str,
    timeout: Duration,
) -> Result<(Manifest, u64)> {
    let chunk = agent_proto::BLOCK_SIZE as usize;
    let mut indexes = Vec::new();
    let mut map = Vec::new();
    let mut read = 0u64;
    for d in disks(x, snap)? {
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
        let idx = store.store_image_extents(None, chunk, d.size, &[(0, d.size)], |off, buf| c.read_at(off, buf))?;
        let _ = c.disconnect();
        read += d.size;
        map.push(json!({"name": d.name, "userdevice": d.userdevice, "size": d.size}));
        indexes.push((d.name, idx));
    }
    let config = json!({"format": 1, "vm": {
        "uuid": uuid, "name_label": rec["name_label"], "name_description": rec["name_description"],
        "VCPUs_max": rec["VCPUs_max"], "memory_static_max": rec["memory_static_max"], "platform": rec["platform"],
        "HVM_boot_params": rec["HVM_boot_params"], "HVM_boot_policy": rec["HVM_boot_policy"],
        "other_config": rec["other_config"], "tags": rec["tags"]}, "disks": map});
    let cfg = Index::Dynamic {
        entries: vec![config_entry(store, "xcpng.json", &serde_json::to_vec_pretty(&config)?)?],
    };
    let mut refs: Vec<(&str, Index)> = indexes.iter().map(|(n, i)| (n.as_str(), i.clone())).collect();
    refs.push(("config", cfg));
    let time = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let m = store.commit_snapshot(&source_name(uuid), time, &refs)?;
    Ok((m, read))
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
        assert!(valid_uuid("4b885545-0f69-4a05-9f95-f1f0a75cf2cb"));
        assert!(!valid_uuid("4b885545-0f69-4a05-9f95-f1f0a75cf2c") && !valid_uuid("../../etc/passwd/x/x/x/x/x/x/x/x/"));
        assert_eq!(
            (int(&json!("1073741824")), int(&json!(5)), int(&json!("x"))),
            (Some(1 << 30), Some(5), None)
        );
        assert_eq!(source_name("a"), "xcp-a");
    }
}
