# XCP-ng / XenServer backups: design (Phase 42, #40)

Status: proposal (2026-10-25), before any code (plan.md Phase 42: a design note first). Lab plan at the end; the
facts about XAPI below are from its documentation and the behaviour of other backup products, to be confirmed in the
lab before the connector is written.

## Decisions proposed

- **A native connector `nexus-xcpng`** (a crate like `nexus-vmware`, trusted, its own SELinux domain), not a
  sandboxed plugin, for the same reasons as VMware (docs/vmware-design.md "Why not a sandboxed plugin"): the snapshot
  is written in the PVE VM layout (one fixed index per disk plus the configuration), so instant restore to Proxmox VE,
  the file index, malware scans and restore tests work unchanged.
- **No proxy VM.** XAPI exports a VDI over **NBD** (TCP 10809, TLS) from the host that has its SR: the appliance reads
  the snapshot's disks directly, only the changed blocks for an incremental (below). This is the counterpart of the
  VMware NFC path; a proxy is not needed because NBD is a public, stable protocol XCP-ng ships for this purpose.
- **Changed block tracking with metadata-only snapshots**, as XenServer's own incremental backups do: CBT on every
  VDI of a protected VM, the backup snapshot's VDIs turned into CBT-metadata-only VDIs after the read
  (`VDI.data_destroy`), so the next run asks XAPI for the blocks changed since then without keeping a snapshot's
  data on the SR.
- **Crash-consistent snapshots**, application consistency through the agent's pre/post hooks in the guest where it
  runs. XCP-ng 8.x has no quiesced snapshot any more (`VM.snapshot_with_quiesce` and the VSS provider were removed in
  XenServer 7.x/8); we do not promise more than the platform offers.
- **Restore** to Proxmox VE first (as for VMware: `nexus-pve` builds the VM from the stored config), to the pool
  second (VDI import over HTTP `import_raw_vdi`, VM record from the stored metadata), single files through the micro-VM
  as for every VM snapshot.

## XAPI pieces used

| Step | XAPI | Notes |
|---|---|---|
| Session | `session.login_with_password` (JSON-RPC over HTTPS to the pool master, port 443) | a dedicated pool user with a role that can snapshot, read VDIs and set CBT (`vm-power-admin` is enough in XenServer's RBAC; XCP-ng without RBAC: a pool admin account); the master's certificate pinned |
| Inventory | `VM.get_all_records` (filter: not template, not snapshot, not control domain) | VM UUID, name, power state, host, VBDs/VDIs, SR, tags |
| Enable CBT | `VDI.enable_cbt` per disk VDI (once) | CBT starts with the next snapshot; costs a small metadata log per VDI |
| Snapshot | `VM.snapshot(vm, "nexus-backup-<job>")` | crash-consistent; returns the snapshot VM with its VDIs |
| Changed blocks | `VDI.list_changed_blocks(vdi_from, vdi_to)` | base64 bitmap, one bit per 64 KiB block; `vdi_from` = the previous run's metadata-only snapshot VDI |
| Read | `VDI.get_nbd_info(snapshot_vdi)` → host, port, export name, TLS subject + certificate | NBD over TLS (`NBD_OPT_STARTTLS`), the export read-only; needs the network's purpose `nbd` set by the admin |
| Keep only metadata | `VDI.data_destroy(snapshot_vdi)` | the snapshot VDI becomes `cbt_metadata` (no data, no SR space); kept until the next run, then destroyed |
| Delete snapshot | `VM.destroy` of the snapshot VM after its VDIs are metadata-only | a leftover (aborted job) is found by name and cleaned up at the next run |
| VM configuration | `VM.get_record` (+ VIFs, VBDs, `platform`, `HVM_boot_params`, firmware) | stored as `xcpng.json`; enough to recreate on PVE or on the pool |

## Flow of a backup (one VM)

1. Connector: ensure CBT on each VDI of the VM (`VDI.get_cbt_enabled`, else `VDI.enable_cbt`; a VDI without CBT is
   read in full).
2. `VM.snapshot`; map each snapshot VDI to the VM's disk by its VBD userdevice (`xvda`, `xvdb`, ...).
3. Per disk: full = the whole VDI; incremental = `VDI.list_changed_blocks(previous metadata VDI, snapshot VDI)`; a
   missing or invalid previous (CBT disabled meanwhile, VDI migrated to another SR, a reset) makes it a full read.
4. Read the extents over NBD from the host `VDI.get_nbd_info` names; 64 KiB bitmap blocks become 4 MiB chunk ranges
   (`agent_conn::blocks::block_ranges`), unchanged chunks are re-referenced from the previous index.
5. `VDI.data_destroy` on each snapshot VDI, destroy the previous run's metadata-only VDIs, keep the new ones' UUIDs in
   `xcpng.json` (the next run's `vdi_from`).
6. Commit the snapshot `xcp-<vm uuid>/<time>`: one fixed index per disk (`xvda`, `xvdb`, ...), the config index with
   `xcpng.json`.

A failure after step 2 destroys the snapshot (data and VM record) so nothing is left on the SR; the previous
metadata-only VDIs stay, so the next run can still be incremental.

## Source and jobs

- Source kind `xcpng`: `host` (pool master), `port` (443), `ca_pem` (pinned), `user`, `password` (write-only, sealed,
  bound to host/port/ca_pem/user), `nbd_hosts` (all hosts of the pool: the firewall allows 10809 to them; the pool
  master may change, so every host is listed).
- Groups list VM UUIDs from the inventory (or all / by tag), as for VMware; the scheduler runs
  `nexus-xcpng <config> backup` per group (exclusive per source) and `inventory`.
- SELinux: domain `nexus_xcpng_t` (https for XAPI, `nexus_nbd_port_t` = 10809/tcp outbound), no write access to
  anything but its job dir and the store, like `nexus_vmware_t`.
- Firewall: outbound 443 to `host`, 10809 to `nbd_hosts` (nftables sets from the source config, as for VMware NFC).

## Restore

- **To Proxmox VE** (first): the stored disks are fixed indexes, so the existing VM restore (`nexus-pve restore`
  with a foreign source, as `restore-vmware` does) creates the VM; `xcpng.json` maps to `qemu-server.conf` (firmware:
  BIOS / UEFI from `HVM_boot_params`; disks as SCSI; NICs as virtio with the stored MACs optional; Windows guests get
  the same SATA/e1000 fallback as VMware restores, since the XCP-ng PV drivers do not exist on PVE).
- **To the pool** (second): `VDI.create` on a chosen SR, upload with HTTP `PUT /import_raw_vdi?vdi=...&format=raw`,
  VM record and VBDs/VIFs from `xcpng.json`; never over the original (a new VM; "replace original" later, with the
  approval rules of PVE replaces).
- **Files**: the micro-VM as for every VM snapshot.

## Open questions for the lab

- NBD on XCP-ng 8.3: the `nbd` network purpose, TLS certificate per host, and whether `get_nbd_info` answers for a
  snapshot VDI of a running VM (expected yes; XenServer's own backup reads snapshots this way).
- `list_changed_blocks` between a metadata-only VDI and a new snapshot after `data_destroy` (expected: works; this is
  the documented incremental pattern), and its behaviour after a live migration within the pool and after an SR
  migration (expected: CBT reset, full read).
- Throughput of NBD over TLS from a nested host; whether a non-TLS NBD purpose (`insecure_nbd`) should ever be offered
  (proposal: no).
- RBAC on XCP-ng (no role-based access control in the free edition): document the account the connector needs.

## Lab plan

1. Nested XCP-ng 8.3 on pve-test as a VM from 200 (CPU type host, 8 GB, a 100 GB disk as local SR), installed from
   the ISO with an answer file; a Debian 13 and a Windows Server 2022 guest on it (HVM).
2. The XAPI facts above checked with a small script before the connector exists (`lab/pvehost/xcpng.sh`): CBT enable,
   snapshot, NBD read of the snapshot VDI, `data_destroy`, a second snapshot and `list_changed_blocks`.
3. Then the connector in steps as for VMware: inventory and full backup (M1), incremental with CBT (M2), source, jobs
   and restore to PVE (M3), restore to the pool (M4).
