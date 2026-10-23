# VMware ESXi / vCenter backups: design (Phase 41)

Status: proposal (2026-10-23), based on the transport spike in [vmware-transport-spike.md](vmware-transport-spike.md).
Decided by the maintainer: no VDDK; the proxy is the appliance's bootc image in a proxy role, shipped as an OVA
that the admin deploys and enrols (no automatic deployment); lab tests on nested ESXi 7.0U3 and 8.0U3.
**Open for the maintainer:** the component split below (native connector instead of a sandboxed plugin).

## What the spike decided

- Changed blocks: `QueryChangedDiskAreas` on the backup snapshot, against the change ID of the previous backup.
  Works on ESXi 7.0U3 standalone (lab: 649 MB in 124 extents, answer in under a second).
- Data path: **hot-add**. ESXi does not serve the disk of a running VM over `/folder`, not even with a snapshot
  (hostd "Failed to lock file"), and `ExportSnapshot` needs vCenter. Attaching the snapshot's base disk read-only
  (`independent_nonpersistent`) to a proxy VM on the same host works: 418 MB/s full, 336 MB/s incremental of the
  changed extents, 0 mismatches against a full read (lab, nested on old hardware).
- Not usable: `changeId = "*"` to skip free space on a full (it reported the whole partition); the proxy reads the
  whole disk, unallocated blocks are cheap and deduplicate.

## Components

```text
 scheduler ── nexus-vmware (connector binary, like nexus-pve) ── vSphere API (HTTPS, SOAP) ── ESXi / vCenter
                   │                                                        │
                   │ agent protocol (mTLS, agent-conn)                      │ ReconfigVM: hot-add / remove
                   ▼                                                        ▼
             proxy VM (bootc image, proxy role) ── reads /dev/sdX of the hot-added snapshot disk
```

- **`nexus-vmware`** (new crate, trusted like `nexus-pve`): vSphere session, CBT enablement per VM, snapshots
  (quiesced through VMware Tools when available, else crash-consistent with an alert), `QueryChangedDiskAreas`,
  hot-add and removal on the proxy, the VM configuration (`.vmx` via `/folder`, hardware version, NICs,
  firmware). It writes the snapshot in the PVE VM layout (one fixed index per disk plus the configuration), so
  instant restore, the file index (Phase 31), malware scans and restore tests work unchanged.
- **Proxy** (the agent in the appliance image's proxy role): enrolled like an agent (token, exporter-bound proofs,
  mTLS, `CN=nexus-agent:<id>`), updated like an agent. One new capability **`block-read`**: "read these extents of
  the disk at SCSI target 0:N", the agent chunks the extents into fixed 4 MiB blocks (the VM index granularity),
  hashes them and the appliance asks only for blocks it does not have (`Want`/`Chunk`, LZ4 as today). The proxy
  accepts only devices that were hot-added (SCSI targets 0:1..0:15, read-only open) and never its own disk.
- **Appliance UI**: a VMware source (ESXi host or vCenter, credentials, the proxy per host), groups of VMs from the
  inventory, restores to Proxmox VE first.

## Why not a sandboxed plugin (the plan's original split)

A plugin may talk only to the endpoints of its source and only through the plugin host; it cannot drive an
enrolled agent, and giving it the proxy's credentials would make the proxy trust untrusted code. Alternatives:

| | native connector + agent proxy (recommended) | plugin + its own proxy protocol | plugin + NBD export on the proxy |
|---|---|---|---|
| Proxy trust | agent enrolment and mTLS as today | new protocol and credentials in the source config | NBD over TLS with a PSK in the source config |
| Dedup on the wire | yes (`Want`: only missing blocks cross the network) | would need reimplementing | no (every changed block crosses) |
| Updates, fleet view, alerts | as for agents | new | new |
| Snapshot layout | PVE VM layout: instant restore, file index, restore tests | plugin streams/files: none of those | as plugin |
| Untrusted code | none added | plugin sandbox | plugin sandbox |

The plugin route keeps VMware out of the trusted code base, but loses instant restore and the file index, and
needs a second trust mechanism for the proxy. Recommended: the native connector.

## Flow of a backup (one VM)

1. Connector: ensure CBT is on (first run: `ReconfigVM ctkEnabled`, then a snapshot cycle to start tracking).
2. Snapshot (quiesced if Tools run), read each disk's `changeId` from the snapshot's backing.
3. Hot-add each disk's base (`independent_nonpersistent`) to the proxy as SCSI 0:N (N from 1, free units only).
4. Extents: full = the whole disk; incremental = `QueryChangedDiskAreas(snapshot, key, 0, previous changeId)`.
   A missing or reset change ID (storage vMotion, snapshot errors) makes it a full read of that disk.
5. Proxy reads the extents, the appliance stores the new blocks and writes the disk index (unchanged blocks
   re-referenced from the previous index).
6. Remove the hot-added disks (no file operation), remove the snapshot; on any error both still happen, and a
   leftover is reported with its name (`nexus-backup-<job>`).
7. Store the `.vmx`, `.nvram` and the change IDs in the snapshot metadata.

## Open points

- vCenter (VCSA and licences not in the lab yet): `ExportSnapshot`, clusters, VMs moving between hosts (the proxy
  must be on a host that sees the VM's datastore).
- vSAN and vVols: hot-add is expected to work; to verify.
- Windows guests: quiescing with VSS through VMware Tools, application-consistent flags.
- Restore to ESXi (later): the reverse path through the proxy (write mode is a separate capability, off by
  default).
