# XCP-ng / XenServer backups: design (Phase 42, #40)

Status (2026-10-25): M1 to M4 implemented (`crates/xcpng`, source kind `xcpng`, restore to Proxmox VE and into the
pool) and tested on a nested XCP-ng 8.3 ("Lab results" below). The XAPI facts the design rests on were
checked before any code (`lab/pvehost/xcpng.sh xapi`).

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
- SELinux: domain `nexus_xcpng_t` (https for XAPI, NBD on 10809/tcp, which the base policy labels
  `unreserved_port_t`: no own port type), no write access to anything but the store, like `nexus_vmware_t`.
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

## Lab results (2026-10-25, XCP-ng 8.3 nested on pve-test, `lab/pvehost/xcpng.sh`)

- CBT: `VDI.enable_cbt`, `VDI.snapshot`, `VDI.data_destroy` (the snapshot becomes `cbt_metadata`) and
  `VDI.list_changed_blocks(S1, S2)` work as designed: 4 MiB written at 512 MiB gave exactly 64 blocks of 64 KiB at
  524288..528384 KiB; the bitmap is most significant bit first.
- NBD: `VDI.get_nbd_info` answers for a snapshot VDI once the management network has the `nbd` purpose (host, port
  10809, the host's certificate and its subject). The export name carries the XAPI session (`/<vdi>?session_id=...`):
  the connector keeps its session open while it reads. A root session from the local socket is refused by xapi-nbd;
  a session from `login_with_password` over HTTPS (as the connector's) is accepted.
- xapi-nbd speaks fixed-newstyle NBD with STARTTLS and `NBD_OPT_EXPORT_NAME`; it denies `NBD_OPT_LIST`. qemu's
  client fails on that (it checks the export with LIST before falling back from GO), libnbd's `nbdcopy` reads it. The
  connector's NBD client needs: STARTTLS with the pinned certificate and the subject as host name, then
  EXPORT_NAME (no LIST); `crates/nbd` gets that mode.
- Read: the snapshot's data over NBD/TLS byte-identical to what was written; 1 GiB in 44 s (nested, TLS, one
  connection).
- M1 connector (`crates/xcpng`): a full backup of a 1 GiB VM in 31 to 37 s. The snapshot VM must be destroyed
  before its VDIs (`VDI.destroy` fails while a VBD of the snapshot still holds the VDI).
- M2 (CBT): after 4 MiB written at 512 MiB, the incremental read exactly that 4 MiB chunk (7.1 s against 34 s for
  the full 1 GiB); `VDI.data_destroy` after `VM.destroy` of the snapshot, the previous metadata VDI destroyed.

- M3 through the appliance (0.0.52-dev on VM 201, SELinux enforcing, `lab/pvehost/xcpng-e2e.sh`): source,
  inventory, a group with the running Debian 13 guest (`xcpng.sh guest`): full 3 GiB in 119 s, the next backup
  incremental (256 KiB read, 7 s); files listed from the snapshot (`/vda1/etc`); restored to pve-test as a new VM
  (VirtIO SCSI, 2 cores, 1 GiB, `ostype l26` from the "Debian Trixie 13" template) in 48 s, booted to the login
  prompt. The restore gives the NICs new MACs (PVE `unique`), as for VMware.

- M4 (restore into the pool, `crates/xcpng/tests/lab.rs`): the 1 GiB test VM restored as a new VM in 21 to 23 s
  (`import_raw_vdi`), its disk read back over NBD identical to the backup. Two XAPI details: the HTTP client must
  read the import's response until XAPI closes, or XAPI leaves the VDI plugged into dom0 (it cannot be destroyed or
  attached afterwards); and our metadata VDIs carry `other_config:nexusbackup`, so each run removes its older ones
  (also those whose snapshot left the store) without touching other tools' CBT bases.

## Open questions

- CBT after a live migration within a pool and after an SR migration (expected: CBT reset, full read).
- Throughput with several NBD connections per disk; whether a non-TLS NBD purpose (`insecure_nbd`) should ever be
  offered (proposal: no).
- RBAC on XCP-ng (no role-based access control in the free edition): document the account the connector needs.

## Lab plan

1. Nested XCP-ng 8.3 on pve-test as a VM from 200 (CPU type host, 8 GB, a 100 GB disk as local SR), installed from
   the ISO with an answer file; a Debian 13 and a Windows Server 2022 guest on it (HVM).
2. The XAPI facts above checked with a small script before the connector exists (`lab/pvehost/xcpng.sh`): CBT enable,
   snapshot, NBD read of the snapshot VDI, `data_destroy`, a second snapshot and `list_changed_blocks`.
3. Then the connector in steps as for VMware: inventory and full backup (M1), incremental with CBT (M2), source, jobs
   and restore to PVE (M3), restore to the pool (M4).
