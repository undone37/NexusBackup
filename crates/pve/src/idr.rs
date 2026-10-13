//! Instant disk recovery (Phase 22b, docs/pve-connector.md "Instant disk
//! recovery", Veeam row 7): one disk of a VM snapshot is attached to an
//! existing VM through the same NBD-backed qcow2 overlay as instant recovery
//! (`<storeid>:ir/<target>/<archive>.<device>.qcow2`, created by the node's
//! storage plugin when PVE activates it). A running VM gets it hot-plugged.
//! With `move_to` the disk is then moved to real storage (`move_disk`, live
//! drive-mirror) and serving ends; without, the appliance serves it until the
//! disk is moved or detached and removed from the VM (no IR volume left).

use crate::backup::{read_excluded, source_name, Cluster};
use crate::ir::{ir_volid, is_disk_key, IrReport};
use anyhow::{bail, Context, Result};
use chunkstore::Store;
use std::time::{Duration, Instant};

/// Bus key for the attached disk: `want` if valid and free, else the first free `scsiN`.
pub fn pick_key(cfg: &serde_json::Map<String, serde_json::Value>, want: Option<&str>) -> Result<String> {
    if let Some(k) = want {
        if !is_disk_key(k) || k == "efidisk0" || k == "tpmstate0" {
            bail!("{k}: not a data disk slot (ide/sata/scsi/virtio + number)");
        }
        if cfg.contains_key(k) {
            bail!("{k} is already used by the VM");
        }
        return Ok(k.to_owned());
    }
    (0..31)
        .map(|n| format!("scsi{n}"))
        .find(|k| !cfg.contains_key(k))
        .context("the VM has no free scsi slot")
}

impl Cluster {
    /// Attaches `device` (`drive-scsi1`) of snapshot `vm-<vmid>/<time>` to VM
    /// `target` on `node` as `key`; serves it until it is moved (`move_to`) or
    /// detached. Returns once the VM no longer uses the overlay.
    #[allow(clippy::too_many_arguments)]
    pub fn instant_disk(
        &self,
        store: &Store,
        vmid: u32,
        time: u64,
        device: &str,
        node: &str,
        target: u32,
        key: Option<&str>,
        move_to: Option<&str>,
    ) -> Result<IrReport> {
        let start = Instant::now();
        let m = store.load_manifest(&source_name(vmid), time)?;
        if device == "config" || !m.indexes.iter().any(|d| d == device) {
            if read_excluded(store, &m)?.is_some_and(|x| x.disks.iter().any(|d| d.device == device)) {
                bail!("{device} was excluded from this backup (no data to attach)");
            }
            bail!("snapshot vm-{vmid}/{time} has no disk {device}");
        }
        if device.ends_with("efidisk0") || device.ends_with("tpmstate0") {
            bail!("{device}: EFI and TPM state disks cannot be attached");
        }
        let (on, kind) = self.guest(target)?;
        if kind != "qemu" {
            bail!("guest {target} is not a VM ({kind})");
        }
        if on != node {
            bail!("VM {target} runs on node {on}, not {node}");
        }
        let cfg = self.api.vm_config(node, target)?;
        let key = pick_key(&cfg, key)?;
        let archive = format!("nexus-{vmid}-{time}");
        let volid = ir_volid(&self.storage, target, &archive, device);
        // the node plugin sizes the overlay from the catalog
        self.push_index(store)?;
        let disks = [(key.clone(), device.to_owned())];
        self.serve_ir(store, &m, node, target, &archive, &disks, |api| {
            api.set_config(node, "qemu", target, &[(key.clone(), Some(volid.clone()))])
                .with_context(|| format!("attach {volid} to VM {target} as {key}"))?;
            let running_after = start.elapsed();
            println!(
                "attached {}",
                serde_json::json!({"target": target, "key": key, "device": device, "volid": volid,
                                   "secs": running_after.as_secs_f64(), "move_to": move_to})
            );
            eprintln!("{device} of vm-{vmid}/{time} attached to VM {target} as {key} after {running_after:.1?}");
            let mut report = IrReport {
                running_after,
                moves: Vec::new(),
                move_errors: Vec::new(),
            };
            match move_to {
                Some(storage) => {
                    let t = Instant::now();
                    let res = api
                        .post_task(
                            &format!("/nodes/{node}/qemu/{target}/move_disk"),
                            &[("disk", key.as_str()), ("storage", storage), ("delete", "1")],
                        )
                        .and_then(|upid| api.run_task(node, &upid, Duration::from_secs(7 * 86400)));
                    match res {
                        Ok(()) => {
                            eprintln!("{key} moved to {storage} in {:.1?}", t.elapsed());
                            report.moves.push((key.clone(), t.elapsed()));
                        }
                        Err(e) => {
                            eprintln!(
                                "moving {key} failed: {e:#}\nstill serving; move the disk (qm disk move {target} {key} <storage> --delete 1) or detach it"
                            );
                            report.move_errors.push(format!("{key}: {e:#}"));
                        }
                    }
                }
                None => eprintln!(
                    "serving {key} until it is moved (qm disk move {target} {key} <storage> --delete 1) or detached and removed"
                ),
            }
            Ok(report)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn picks_a_free_slot() {
        let cfg: serde_json::Map<String, serde_json::Value> =
            serde_json::from_str(r#"{"scsi0":"a:1","scsi1":"a:2","virtio0":"a:3","unused0":"a:4"}"#).unwrap();
        assert_eq!(pick_key(&cfg, None).unwrap(), "scsi2");
        assert_eq!(pick_key(&cfg, Some("virtio1")).unwrap(), "virtio1");
        assert!(pick_key(&cfg, Some("scsi0"))
            .unwrap_err()
            .to_string()
            .contains("already used"));
        for bad in ["efidisk0", "net0", "scsi", "tpmstate0"] {
            assert!(pick_key(&cfg, Some(bad)).is_err(), "{bad}");
        }
        let full: serde_json::Map<String, serde_json::Value> =
            (0..31).map(|n| (format!("scsi{n}"), serde_json::json!("x"))).collect();
        assert!(pick_key(&full, None).is_err());
    }
}
