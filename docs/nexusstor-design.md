# NexusStor backups and integration: design

Status: proposal (2026-11-01), before any code. NexusStor (`undone37/NexusStor`) is the sibling NAS appliance:
vStors (isolated storage servers in network namespaces) on ZFS, each with its own encrypted dataset, exports, SMB
shares, S3 buckets and iSCSI LUNs. Both products are one family (maintainer, 2026-11-01): the integration should
feel built in on both sides, not like a generic NAS connector.

## Decisions proposed

- **Paired appliances, no SSH and no API key.** NexusStor has no SSH in its image, and its replication already
  runs over 8443 with ALPN and pinned mTLS. NexusBackup pairs the same way: a one-time pairing code shown on the
  NexusStor (admin, four-eyes when approvals are on) is entered on NexusBackup; both pin each other's certificate;
  NexusBackup connects with ALPN `nexusbackup/1`. The pairing grants exactly the backup protocol below, nothing of
  the NexusStor API. Unpairing on either side ends it.
- **A plugin, `plugins/nexusstor`** (source kind `plugin:nexusstor`, the plugin SDK as `plugins/truenas`): the
  sandbox, the endpoint allow-list and the signed bundle come for free. Guests are **vStors** (`ListGuests` asks the
  NexusStor); groups and policies select vStors as they select VMs.
- **A root helper on NexusStor, `storctl backup-serve`**, behind a socket unit like `nexusstor-replsend.socket`
  (one request per connection, the web-api only forwards the authenticated stream, as for replication). Requests:
  - `inventory`: vStors with their exports, SMB shares, S3 roots and LUNs, sizes, and the vStor definition (the
    desired state without secrets);
  - `snapshot <vstor>`: a recursive snapshot `nexusbackup-<unix time>` with a `zfs hold` tag `nexusbackup`, so
    NexusStor's retention cannot remove it while a backup reads it or while it is the next run's base;
  - `diff <vstor> <base> <snap>`: `zfs diff -FH` per dataset (the TrueNAS connector's parser and limits);
  - `files <vstor> <snap> <paths>`: metadata (owner, mode, times, xattrs and NFSv4 ACLs, which SMB shares rely
    on) and contents of the listed files, read from `.zfs/snapshot/<snap>`;
  - `lun <vstor> <snap> <lun> <offset> <len>`: reads of a zvol snapshot (block LUNs);
  - `release <vstor> <snap>`: drop the hold of a base that is no longer needed (after the next commit).
  The helper only ever creates and releases `nexusbackup-*` snapshots and their holds; it writes nothing else.
- **One NexusBackup snapshot per vStor and run**, source `nst-<nexusstor id>-<vstor>`: an `Index::Tree` `files`
  with one top folder per export, share root and S3 root; one fixed index per LUN; `vstor.json` (the definition).
  Incrementals from `zfs diff` against the held base, unchanged files reuse their chunk ids (as TrueNAS). LUNs are
  read in full the first time and then deduplicated by the chunk store (`ponytail`: no block-level change tracking
  for zvols; `zfs send -i` parsing would give it, add when LUN sizes make full reads too slow).
- **Tenants**: a vStor maps to a NexusBackup tenant (default: one tenant per paired NexusStor, a vStor can be moved
  to another tenant): its data is sealed under that tenant's keys; a NexusStor vStor admin never sees other vStors.
- **Restores** (plugin restore kinds):
  - download (generic, the host);
  - files back into an export of the same or another vStor, into a new folder `nexusbackup-restore-<date>`
    (overwrite only when asked): a write request the NexusStor helper checks (path inside the export, quota);
  - a whole vStor recreated on a paired NexusStor as a new vStor (name, network, exports, shares, buckets, LUNs
    and data; S3 and SMB users as NexusStor's restore of a deleted vStor brings them back, iSCSI CHAP secrets set
    anew);
  - a LUN as a new LUN; files of every snapshot browsable, indexed and searchable like other file backups.
- **Both UIs show the other side**:
  - NexusStor: per vStor "last backup by NexusBackup" (time, result, a link to the job), sent back by NexusBackup
    after each run (`report` request), and an alert when a vStor in a backup policy has no good backup for its RPO;
  - NexusBackup: the vStor's protocols, quota and NexusStor snapshot locks next to the source.
- **Ransomware signals both ways**: NexusStor's change-rate alert (it already locks the last good ZFS snapshot)
  is passed to NexusBackup, which pins the vStor's last backup before the jump (retention lock, as its own change-rate
  alert does) and raises the alert there too; a NexusBackup malware finding in a vStor backup raises an alert on the
  NexusStor.
- **NexusStor as a backup target** (second step): an S3 vStor with Object Lock as NexusBackup's offsite target
  (`crates/remote` S3 client). With a pairing, NexusStor creates the bucket, the S3 user and the lock period for
  NexusBackup in one step instead of copying keys by hand.

## Security

- Everything from the NexusStor is hostile input on NexusBackup (the TrueNAS connector's rule): strict parsers,
  limits, validated paths; the plugin runs sandboxed and never sees tenant keys.
- On NexusStor the helper validates vStor, snapshot, path and LUN names against the catalog and refuses anything
  outside the named vStor's datasets. The data leaves the vStor only through the management network, inside the
  pinned TLS connection; it is decrypted from the vStor key on NexusStor and sealed again under the tenant's key on
  NexusBackup. Restores that write into a vStor are separate requests, approval-gated on NexusBackup.
- A test on each side that fails without the check: the helper refuses another vStor's path; the pairing refuses
  an unpinned peer.

## Work split

1. NexusStor: pairing (ALPN `nexusbackup/1`, pinned mTLS, pairing code), `storctl backup-serve` (inventory,
   snapshot, diff, files, lun, release), UI status per vStor. Built in a separate branch and worktree.
2. NexusBackup: `plugins/nexusstor` (Validate, ListGuests, Backup), pairing on the source form, manual chapter.
3. Restores (files, LUN, whole vStor), reports back, ransomware signals both ways.
4. NexusStor as an S3 target with Object Lock.

## Implementation notes (step 2, NexusBackup)

Wire contract: NexusStor `docs/nexusbackup-protocol.md`. Where the plugin system shapes the result:

- Snapshots are plugin snapshots, so the source name is `plugin-nexusstor-<source id>-<vstor>` (not `nst-…`), and
  LUNs are the streams `luns/<name>` in the `streams` index (`Index::Dynamic`, content-defined chunks) instead of a
  fixed index per LUN; `vstor.json` is a stream too. The tree uses exactly the inventory's dataset dirs.
- The web-api cannot reach NexusStor before the egress firewall opens the source's endpoint, so pairing is split:
  the web-api decodes the token (host, port, pinned fingerprint) and generates the pairing's client certificate
  (`crates/web-api/src/nexusstor.rs`); the plugin's `Validate` sends `pair` when the inventory answers 403.
- The plugin does not see the host's commit: the previous base is released at the start of the next run (state
  blob `prev`), as the TrueNAS plugin rotates. Only snapshots this source recorded are released.
- NFSv4 ACLs are kept as the xattr `system.nfs4_acl` (as the NAS connector keeps ACLs); no new metadata field.
- Ransomware signal NexusStor -> NexusBackup (step 3, first part): the inventory's `anomaly` (contract) goes into the
  snapshot meta as `anomaly {system, snapshot, at, last_good, last_good_created}` (known fields only). The scheduler
  treats an `anomaly` object in any plugin's snapshot meta as the source system's own finding
  (`snapmeta::external_anomaly`): the snapshot is flagged and `anomaly` (critical) names the newest clean snapshot
  from no later than `last_good_created`. No contract change.

## Lab plan

A NexusStor appliance VM on pve-test (≥ 200) with a vStor carrying an export, an SMB share, an S3 bucket and a LUN,
paired with appliance VM 201: full, incremental after changes, file restore into the export, whole-vStor restore
as a new vStor, the change-rate signal pinning a backup.
