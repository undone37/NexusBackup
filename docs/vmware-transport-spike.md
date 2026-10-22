# VMware vSphere source: transport spike

Status: analysis and spike plan (Phase 33, 2026-10-15). **Not implemented.** Decides open question 6 of
docs/commvault-comparison.md ("VMware transport ... needs a spike before the item is scheduled"); the Tier 2 item
"VMware vSphere source with restore to PVE" is scheduled only after the spike below has been run against a real
vSphere lab (none is available to this phase). No vSphere installation was used for this document; statements about
vSphere behaviour that the spike must confirm are marked **(verify)**.

## Goal and constraints

Back up VMs from ESXi / vCenter (vSphere 7 and 8) incrementally into the chunk store, restore them as Proxmox VE VMs
(the main audience: SMBs leaving VMware), optionally also back to vSphere later. Constraints from the architecture:

- **Pull model**: the appliance connects to vCenter / ESXi with a read-mostly service account; nothing is installed on
  the hosts. The connection is one more egress target on the allow-list.
- **AGPL-3.0 image**: nothing proprietary may ship in the signed image.
- **Plugin system** (Phase 9): new sources are signed plugins in a sandbox (landlock, seccomp, no network except the
  declared targets, no keys: the host does the chunking and encryption). A VMware source is a plugin `vmware` of the
  same kind as `m365`.
- **Incremental by changed blocks**: reading whole disks every night is not acceptable beyond small installations.

## What every transport shares

1. **Session and snapshot**: vSphere API (SOAP `vim25` or the REST/JSON API of vSphere 8) with a service account;
   `CreateSnapshot_Task(memory=false, quiesce=true|false)`; read the snapshot's disks; `RemoveSnapshot_Task`.
   Quiescing uses VMware Tools in the guest (VSS on Windows); a failed quiesce falls back to crash-consistent, like
   the PVE guest agent rule.
2. **Changed Block Tracking (CBT)**: `ctkEnabled` per VM (`ReconfigVM_Task` with `changeTrackingEnabled`, takes effect
   after a stun/unstun, e.g. the next snapshot); `QueryChangedDiskAreas(snapshot, deviceKey, startOffset, changeId)`
   returns the changed extents since the `changeId` recorded at the previous backup (`*` = all allocated extents,
   which also gives a sparse first full). The change ids are kept in the plugin state (like the M365 delta links).
   CBT is a vSphere API feature, independent of the data transport. Known failure modes: a CBT reset after storage
   vMotion or snapshot consolidation errors (the plugin must fall back to `*` when the change id is rejected); the
   Phase 29 scheduled full read applies unchanged and finds silent CBT drift.
3. **Mapping into the store**: one fixed index per disk (like PVE VM disks); unchanged extents are carried over from
   the previous snapshot without reading, exactly as the PVE dirty-bitmap path does; the file index (Phase 31) works on
   the result without changes (`nexus-fsindex` parses the disk images regardless of where they came from).

The transports differ only in how the bytes of the snapshot's disks are read.

## Option A: HTTPS datastore reads + `QueryChangedDiskAreas`

Read the frozen base disk (`<vm>-flat.vmdk` of the disk that the snapshot made read-only) through the HTTPS datastore
file access of vCenter or ESXi (`GET https://<host>/folder/<path>?dcPath=<dc>&dsName=<ds>`, session cookie or basic
auth), with HTTP `Range` requests for exactly the extents CBT reports.

- **Licensing**: none beyond the customer's vSphere licence; no VMware code on the appliance. Fits the AGPL image and
  the plugin sandbox (HTTPS client only).
- **Precedent**: Proxmox VE's own ESXi import (PVE 8.2, `esxi-folder-fuse`) reads VMs through this datastore file
  interface with random access, so the interface works for range reads of flat VMDKs **(verify throughput and
  `Range` behaviour on vCenter vs. direct ESXi)**.
- **Throughput**: datastore file access goes through `hostd` and is known to be slow compared to VDDK transports,
  commonly tens of MB/s per stream **(verify)**. Several disks in parallel and several range requests in flight per
  disk help; incrementals read only the changed extents, so the steady state is usually acceptable, the first full of
  large VMs is the problem (for example 2 TB at 60 MB/s is about 9 hours).
- **Datastore types**: VMFS and NFS datastores expose `-flat.vmdk` files. **vSAN and vVols do not** expose flat files
  through the datastore browser **(verify for vSphere 8 vSAN ESA)**: those VMs cannot be read with option A at all.
  Thin disks are fine (sparse reads return zeros; CBT `*` skips unallocated areas).
- **Snapshot handling**: after `CreateSnapshot` the parent disk is read-only and consistent; the plugin reads the
  parent file named in the snapshot's `layoutEx` (not the delta), then removes the snapshot. Disks that already have
  snapshots (customer snapshots) mean reading through a chain: option A would have to read each delta and merge
  (complex) or refuse such VMs **(proposal: refuse with a clear message in the first version)**.
- **Encrypted VMs** (VM encryption with a KMS): the flat file is ciphertext; not readable with option A.
- **Effort**: M-L. vSphere SOAP client in Rust (a small hand-written subset: login, PropertyCollector, snapshot
  tasks, ReconfigVM, QueryChangedDiskAreas; about 15 calls), range reader with retries, plugin contract use as M365,
  CBT state handling; 5-7 weeks including tests against a vSphere simulator (`vcsim` from govmomi covers the API
  calls but not datastore data: the data path needs a real ESXi).

## Option B: nbdkit with a customer-supplied VDDK

Read disks through VMware's Virtual Disk Development Kit, which offers the real backup transports (`nbd`/`nbdssl`
over the network, `hotadd` from a proxy VM, `san` over FC/iSCSI). The appliance would run `nbdkit` (BSD licence) with
its `vddk` plugin, which loads `libvixDiskLib.so` at run time from a directory the customer provides, and read the
NBD export with a normal NBD client (the appliance already speaks NBD for instant recovery, crate `nbd`).

- **Licensing**: VDDK is proprietary (VMware, now Broadcom); its licence does not allow redistribution in the image,
  and an AGPL image must not contain it anyway. The customer downloads VDDK from Broadcom (account required) and
  uploads the tarball to the appliance. nbdkit and its vddk plugin are BSD-licensed and may ship in the image; VDDK is
  only `dlopen`ed by nbdkit, a separate process from the AGPL code (communication over a Unix socket), so the
  appliance software itself is not combined with VDDK **(have counsel confirm before shipping)**. The upload must be
  checked (expected file list, ELF libraries only, size cap) and stored outside the signed image in a staging area like
  plugin uploads; each VDDK version must be tested (Broadcom ships about two releases a year, support matrix per
  vSphere version).
- **Throughput**: `nbdssl` is typically several times faster than datastore file access, `hotadd` and `san` faster
  still **(verify)**; `hotadd` needs a proxy VM in the vSphere cluster, which contradicts the appliance-pulls model and
  is not proposed; `san` needs direct storage access and is not proposed either. So in practice: `nbdssl`.
- **Datastore types**: VDDK reads through the host, so **vSAN and vVols work**, as do encrypted VMs (with the KMS
  configured in vSphere) **(verify)**. Snapshots with existing chains are handled by VDDK (it reads the disk as of the
  snapshot).
- **Sandbox**: VDDK is a large native library with its own threads, OpenSSL copy and network code. It has to run in
  its own sandboxed process (nbdkit under a dedicated SELinux domain, network only to the vCenter / ESXi targets,
  no store, no keys); its CVE stream becomes the customer's patch duty (re-upload).
- **Effort**: L. Everything of option A except the range reader, plus: VDDK upload, validation and versioning UI and
  API, nbdkit packaging in the image and SELinux policy, NBD client integration with CBT extents, transport fallbacks,
  per-VDDK-version test matrix; 8-11 weeks. Support burden: VDDK and vSphere version combinations, Broadcom account
  hurdles for customers.

## Option C (rejected): OVF export / `HttpNfcLease`

`ExportVm` returns an NFC lease with URLs of stream-optimized VMDKs. It needs no VDDK but delivers whole disks only
(no ranges, no CBT): every backup would be a full read and transfer. Usable at most for a one-off migration import,
which Proxmox VE's own ESXi import already covers. Rejected for backups.

## Comparison

| | A: HTTPS datastore + CBT | B: nbdkit + customer VDDK |
|---|---|---|
| Ships in the AGPL image | yes, fully | nbdkit only; VDDK uploaded by the customer |
| Customer effort | service account | service account + Broadcom download + upload per version |
| Incremental (CBT) | yes (API) | yes (API) |
| VMFS / NFS datastores | yes | yes |
| vSAN / vVols | **no** (verify) | yes |
| Encrypted VMs | no | yes (verify) |
| VMs with existing snapshots | refuse (first version) | yes |
| First full of a large VM | slow (hostd) | faster (`nbdssl`) |
| Attack surface on the appliance | HTTPS client in the plugin sandbox | proprietary native library in its own sandbox |
| Effort | M-L (5-7 weeks) | L (8-11 weeks) |

Restore to PVE is the same for both: write the disks to the PVE storage through the existing PVE restore path, then
convert the guest (VirtIO drivers for Windows, `fstab`/initramfs for Linux) inside the restore micro-VM with
`virt-v2v`-style steps (`virt-v2v` itself is GPL-2.0, fine for the image; the VirtIO driver package for Windows must be
checked for redistribution **(verify licence)**, else the customer provides the ISO like VDDK).

## Recommendation

1. **Run the spike with option A first** (it needs nothing proprietary and decides most of the question): one ESXi 8
   host with a VMFS and an NFS datastore and, if available, a vSAN cluster; a Linux VM (200 GB, 10 % changed per day)
   and a Windows VM.
   - Measure: full read MB/s per disk and with 2/4/8 parallel range readers, against ESXi directly and through vCenter;
     incremental read time for the CBT extents of one day; CPU on the appliance.
   - Check: `Range` support and behaviour on large ranges; reading the snapshot parent while the VM writes; CBT reset
     after storage vMotion and after a failed snapshot removal; behaviour on vSAN (expected: no flat file).
   - Pass criteria: incremental of the 200 GB VM under 15 minutes; full under 4 hours; no read errors under load.
2. **If A passes for VMFS/NFS**: implement the `vmware` plugin with option A only (customers on vSAN/vVols are told so
   in the source dialog; VMs with existing snapshots are refused with a message). This covers the typical SMB leaving
   VMware (a few hosts, SAN/NFS datastores) without any licensing question.
3. **Option B as a later, optional accelerator** (separate item): only if customers on vSAN/vVols or with large VMs
   ask for it, and only after counsel confirmed the upload model. It reuses everything of A except the reader.
4. **Decision for open question 6** (taking the proposal: spike first): VDDK is never shipped; the first version uses
   HTTPS datastore reads with `QueryChangedDiskAreas`; nbdkit with a customer-supplied VDDK stays an option for later.
   The item is scheduled once the spike above has run in a vSphere lab.

## Lab results

2026-10-23, nested ESXi 7.0U3g on pve-test (`lab/pvehost/esxi.sh`), 4 GiB flat VMDK on a VMFS-6 datastore, read over
HTTPS `/folder` with `Range` from the appliance (VM 201) on the same bridge:

| Read | MB/s |
|---|---|
| one stream, 2 GiB | 26.7 |
| 4 parallel ranges of 512 MiB | 41 |
| 64 random 4 MiB ranges, sequential | 12 (312 ms each) |

The workstation (through a router) measured the same (28 / 46.5 / 14.2), so `hostd` is the limit. A nested host on
old hardware is a lower bound; a real host is expected to be faster **(verify on real hardware)**.

**CBT works, the datastore read of a running VM does not** (Debian 12 guest nx-cbt, 16 GB thin disk, CBT on in the
`.vmx`; `lab/pvehost/esxi.sh guest` and `cbt`, control side `esxi_cbt.py` with pyvmomi):

- `QueryChangedDiskAreas` after 512 MB new data and 103 MB overwritten in the guest: 648 MB in 126 extents (the
  writes plus file system metadata). The answer takes under a second.
- With `changeId = "*"` it reports the whole partition (16.16 GB) although the thin disk has 3.9 GB allocated: a
  first full read cannot rely on it to skip unallocated space.
- **`/folder` refuses the base disk of a powered-on VM, also while a snapshot exists**: HTTP 500, hostd logs
  "Error creating Reader: Failed to lock file". The VMX holds the base disk open (VMFS lock mode 2); `dd` on the ESXi
  shell gets "Device or resource busy" as well. Option A as written therefore only works for powered-off VMs.
- `VirtualMachineSnapshot.ExportSnapshot` (an NFC lease on the snapshot) is not supported on a standalone host
  (`vmodl.fault.NotSupported`); it needs vCenter.

That leaves, without VDDK, a **hot-add proxy**: the snapshot's base disk attached to a small proxy VM on the same
host and read there as a block device, with the extents from `QueryChangedDiskAreas`. This is what VDDK's `hotadd`
transport does, done with plain vSphere API calls (`ReconfigVM_Task` adds the base disk as
`independent_nonpersistent` at SCSI 0:1, then removes it again without a file operation). **Tested and passed**
(2026-10-23, `esxi.sh hotadd`, proxy nx-proxy with 2 vCPU on the same host, 4 reader threads):

| Read on the proxy | Data | Time | MB/s |
|---|---|---|---|
| full, snapshot cbt1 | 16.16 GB | 38.7 s | 418 |
| incremental, CBT extents since cbt1 (124 extents) | 657 MB | 2.0 s | 336 |
| check: full read at cbt2 against cbt1 plus the incremental | 16.16 GB | 37.6 s | 0 mismatched 1 MiB blocks |

The disk attaches while nx-cbt keeps running with its snapshot (the VMX's lock allows a second read-only opener; the
shell `dd` does not get one). About 12 GB of the 16 GB thin disk are unallocated and read fast, so the incremental
figure is the better guide for real data. That is more than ten times the `/folder` path.

In the lab the proxy is a plain Debian VM (only to answer whether hot-add works); a product proxy would be the
appliance's own AlmaLinux bootc image in a proxy role (same signed updates, SELinux policy and hardening).

Consequences for the design (to be decided in plan.md Phase 41):

- **Transport: hot-add proxy, no VDDK.** One proxy VM per ESXi host (or per cluster with shared datastores, through
  vCenter later). The proxy reads the extents and sends chunks to the appliance like an agent does.
- `/folder` stays only for powered-off VMs and for the small files (`.vmx`, `.nvram`, descriptors).
- A full backup cannot use `changeId = "*"` to skip free space on this disk; reading the whole disk is cheap on the
  proxy (unallocated blocks), and identical zero chunks deduplicate.
- Open: vSAN and vVols (hot-add is expected to work, verify), NFS datastores, a proxy on a different host than the
  VM (needs shared storage), quiesced snapshots with VMware Tools, CBT reset after storage vMotion.

## Spike steps (for the maintainer's lab)

```sh
# 1. Service account on vCenter: role with VirtualMachine.State.CreateSnapshot / RemoveSnapshot,
#    VirtualMachine.Config.ChangeTracking, Datastore.Browse, Datastore.FileManagement (read), System.View
# 2. Enable CBT on the test VM (PowerCLI):
#    $vm | Get-View | % { $s = New-Object VMware.Vim.VirtualMachineConfigSpec; $s.ChangeTrackingEnabled = $true; $_.ReconfigVM($s) }
# 3. Snapshot, then time a full read of the parent flat file with 1/4/8 parallel ranges:
curl -k -u 'svc-backup@vsphere.local' -o /dev/null -w '%{speed_download}\n' \
  -H 'Range: bytes=0-1073741823' \
  'https://vcenter.example/folder/vm1/vm1-flat.vmdk?dcPath=DC1&dsName=datastore1'
# 4. QueryChangedDiskAreas for the disk (govc or pyvmomi), read only those extents, compare checksums with a
#    full read of the same snapshot (must be equal where CBT reported nothing changed).
# 5. Repeat 3-4 against the ESXi host directly and on a vSAN datastore; record results in state.md.
```
