# Microsoft Hyper-V backups: design (Phase 42, #39)

Status: proposal (2026-10-25), before any code (plan.md Phase 42: a design note first). The WMI facts below were
checked the same day on a nested Hyper-V host (Windows Server 2022 in a KVM VM on pve-test, `lab/windows/hyperv.sh`,
"Lab results"), the RCT change query included.

## Decisions proposed

- **A mode of the Windows agent** on each Hyper-V host, not a separate connector: the host is a Windows server the
  agent already runs on (MSI, service, VSS, mTLS protocol, edge, signed updates, pipe UI). The appliance never needs
  WinRM or a Windows account. The agent talks to the local Virtualization WMI provider (`root\virtualization\v2`)
  and reads the virtual disks itself; the appliance plans and stores, as for the hot-add proxy's `block-read`.
- **Snapshots in the PVE VM layout** (one fixed index per virtual disk plus `hyperv.json` with the VM's
  configuration), snapshot source `hv-<VM id>`: instant restore to Proxmox VE, the file index, malware scans and
  restore tests work unchanged, as for VMware and XCP-ng.
- **Recovery checkpoints and reference points** (the backup path Hyper-V offers since 2016): per backup a recovery
  checkpoint (`CreateSnapshot`, type 32768, application consistent through the guest's integration services when they
  run, else crash consistent), the disks read from the checkpoint's frozen parent VHDX, then the checkpoint converted to
  a **reference point** whose **Resilient Change Tracking** identifiers are the next run's base. No checkpoint stays
  behind: a reference point keeps only the change-tracking state (`.rct`/`.mrt` next to the VHDX), no data.
- **Incrementals by RCT**: during the recovery checkpoint the agent opens the frozen parent VHDX read-only through
  `virtdisk.dll` (`OpenVirtualDisk`) and asks `QueryChangesVirtualDisk` for the ranges changed since the previous
  reference point's identifier, then reads only those (the WMI `GetVirtualDiskChanges` refused the same identifier in
  the lab); without a valid base (first run, RCT reset, VHDX changed outside Hyper-V) a full read.
- **Failover clusters**: the agent on every node; a VM is backed up by the node that owns it at that moment (the
  appliance asks each node's agent for its VMs); CSV paths are read like local ones. Reference points move with the VM.
- **Restore**: to Proxmox VE first (`xcpng.json`-style mapping to the existing VMware converter: Gen 1 = BIOS, Gen 2
  = OVMF; Windows guests get SATA and e1000e as for VMware), back to the Hyper-V host second (a new VM: VHDX files
  written by the agent, `DefineSystem` from `hyperv.json`), single files through the micro-VM.

## Lab results (2026-10-25, Windows Server 2022 with Hyper-V nested on pve-test, VM 296)

- Nested Hyper-V on KVM works (CPU type host, `kvm_intel nested=Y`): the role installs, a Gen 2 test VM runs.
- Recovery checkpoint through WMI: `Msvm_VirtualSystemSnapshotService.CreateSnapshot(vm, settings, 32768)`. With
  `ConsistencyLevel = 1` (application) a VM without integration services fails ("Production checkpoints cannot be
  created"); `2` (crash consistent) works. The VM then runs on an `.avhdx`; the base `.vhdx` is frozen.
- **Reading while the VM runs**: the base VHDX attached read-only on the host (`Mount-VHD -ReadOnly`) during the
  checkpoint gave the written 64 MiB byte-identical, and later the data the guest had written before the checkpoint.
- `ConvertToReferencePoint` is a method of the **snapshot** service (not the reference point service). It returns the
  checkpoint merged away and a `Msvm_VirtualSystemReferencePoint` with `ResilientChangeTrackingIdentifiers`
  (`rctX:<guid>:<sequence>`); `.rct` / `.mrt` files appear next to the VHDX.
- WMI details for the implementation: an asynchronous job (`ReturnValue` 4096) leaves the out-references
  (`ResultingSnapshot`, `ResultingReferencePoint`) empty: find the new instance afterwards (snapshots by
  `VirtualSystemType = Microsoft:Hyper-V:Snapshot:Recovery`; reference points are new instance ids, `CreationTime` is
  empty). Positional method arguments go in MOF order, not the documented one: call with named parameters
  (`GetMethodParameters` / `InvokeMethod`).
- Writes through a host-mounted VHDX while the VM is off are **not** tracked by RCT (the identifier did not advance,
  no changes reported): a disk changed outside Hyper-V needs a full read; the agent must check that its base
  identifier is still the disk's.
- **The change query works through `virtdisk.dll`** (`lab/windows/hyperv/incremental.ps1`): guest writes 4 MiB at
  128 MiB (`dd` in an Alpine live system), recovery checkpoint, the frozen parent opened read-only, then
  `QueryChangesVirtualDisk` against the previous reference point's identifier: exactly one range, 134217728 + 4194304,
  over the whole 1 GiB. Earlier attempts, kept for the implementation: with guest writes between two reference points (4 MiB at 512 MiB, written
  with `dd` in an Alpine live system, the data visible in the base afterwards), `GetVirtualDiskChanges` reported no
  ranges when asked between the two reference point identifiers, and "the specified change tracking identifier is
  not valid" when asked on the base or the `.avhdx` while the second checkpoint existed. The identifier sequence also
  looked off (a new reference point taken right after the previous one carried its number). The Win32 way
  (`lab/windows/hyperv/qcvd.ps1`: `OpenVirtualDisk` v2 with `GetInfoOnly`, then `QueryChangesVirtualDisk` with the
  reference point's identifier) on the running VM's VHDX: opened, but the query is refused with
  `ERROR_ACCESS_DENIED`; the WMI call keeps refusing the identifier also on the frozen parent. So: Win32, on the
  frozen parent, opened read-only, in the order checkpoint, query, read, convert.
- Lab tooling: `Msvm_Keyboard.TypeText` does not reach a Linux guest's synthetic keyboard; `TypeKey` with virtual-key
  codes does (`lab/windows/hyperv/keys.ps1`); the VM's screen comes from `GetVirtualSystemThumbnailImage` (RGB565).

## Open questions

- The cost of the change query on large disks, and RCT after a live migration within a cluster.
- Shared VHDX / VHD Set (guest clusters): excluded at first.
- Server 2019 vs 2025 differences in the WMI classes (the lab ran 2022).

## Lab plan

1. M1: agent mode `hyperv`: inventory, full backup through a recovery checkpoint, reference point kept.
2. M2: incrementals by RCT; M3: source kind, scheduler, restore to PVE; M4: restore to Hyper-V; clusters with a
   second nested host.
