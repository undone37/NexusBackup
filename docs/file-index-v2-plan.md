# Plan: guest file index without the restore micro-VM (Phase 31)

Status: proposed 2026-10-13 by maintainer request, not started. Goal: every snapshot's files are searchable, the same
way for VM/CT disks (Windows, Linux) and for agent, NAS and plugin snapshots, without booting the restore micro-VM,
and searches stay fast with many snapshots and millions of files.

## Where we are

- File-tree snapshots (agents, NAS, TrueNAS, plugins) get a sealed per-snapshot name index at commit
  (`chunkstore/src/names.rs`: path, size, mtime, kind; sealed with the tenant keyring).
- VM/CT disks: names are listed by the restore micro-VM (`nexus-pve files … index`), opt-in per group
  (`groups.index_files`), slow (boot + mount per snapshot), therefore rarely on.
- Search (`scheduler/src/search.rs`): a job decodes the name indexes of a tenant's snapshots, newest first, matches a
  glob, stops after a 30 s budget (`truncated`). Linear in snapshots x files; no ranking, no word search.

## Index storage: recommendation

| Option | Fit | Verdict |
|---|---|---|
| **Tantivy** (Rust library, Lucene-like, used by Quickwit) embedded in a new `nexus-index` service | No extra runtime, no network port, one SELinux domain, segments are immutable files (easy to seal), handles 100 M+ documents, fast prefix/term/range queries | **Recommended** |
| Meilisearch (Rust, separate server) | Good typo-tolerant search, but a second server with an HTTP API and master key, plaintext data on disk, LMDB size limits per index, indexing throughput is low for 10-100 M paths, built for product search rather than file catalogues | Possible, not recommended |
| OpenSearch | JVM, 1-2 GB heap minimum, cluster-oriented operations, large attack surface on a hardened appliance | Not suitable |

Decisive points: the appliance is a hardened single box (no extra network services), file names are tenant data
(they are sealed today and must stay encrypted at rest), and the index must be rebuildable from the sealed per-snapshot
name indexes (they stay the source of truth; the search index is a cache).

**Encryption at rest:** Tantivy's `Directory` trait is implemented by a sealing directory: every segment file is
written once, sealed with the tenant keyring (XChaCha20-Poly1305 as all store objects), and decrypted into a bounded
in-memory cache on open. One index per tenant, under `/var/lib/nexus/index/<tenant>/`; losing it costs a rebuild, never
data. The `nexus-index` service gets tenant keys from keyd like the scheduler does today.

## Reading VM disks without the micro-VM

A new helper `nexus-fsindex` lists the files of one disk image read-only:

- **Input:** the snapshot's disk image streamed from the chunk store (the parent opens the store; the helper gets
  plaintext image bytes through a pipe/fd and random-access requests, never keys).
- **Parsers (read-only, Rust):** partition tables (GPT, MBR), LVM2 (text metadata; linear and striped LVs; thin pools
  later), NTFS (crate `ntfs`), ext2/3/4 (crate `ext4-view`), XFS (own minimal read-only walker: superblock, AG inode
  B+trees, directory blocks; no mature crate exists), FAT/exFAT. Not indexable (reported per disk, the micro-VM remains
  the fallback): btrfs (later), ZFS inside a guest, ReFS, Windows dynamic disks (LDM, later), LUKS/BitLocker volumes.
- **Isolation:** guest file systems are untrusted input. The helper runs with its own SELinux domain, seccomp filter,
  no network, no file system access beyond its stdin/stdout, memory and time limits, and as an unprivileged user; each
  parser is fuzzed in CI (cargo-fuzz targets with corpora from the lab images). Output is a stream of entries (path,
  size, mtime, kind, optionally owner/SID) that the parent writes into the sealed name index, exactly as for agents.
- **Incremental:** metadata lives in a few regions (NTFS `$MFT`, ext4 inode tables, XFS inode chunks). Parsed metadata
  is cached per chunk id: a chunk that is identical to the previous snapshot's (same id) is not parsed again. A typical
  incremental VM snapshot re-parses only the MFT/inode chunks that changed.
- **When:** right after each VM/CT backup as a low-priority follow-up job (or in the maintenance window), default on
  for all groups once measured; the group option `index_files` becomes "off / on (default)".

Containers (CT tar streams) already pass through the appliance as a file tree: their name index is written at commit
like an agent's, no parser needed.

## Index model and search

- Documents are **file versions**: (source, path, size, mtime, kind[, owner]) with `first_seen` and `gone_at` snapshot
  times. Each new snapshot adds documents only for new or changed versions and closes versions that disappeared, so
  an unchanged file costs one document for its whole history (about 150-250 bytes each; 10 M versions ~ 2 GB).
- Queries: name and path (exact, prefix, glob, word/token search over path components), extension, size and time
  ranges, source, group, guest; "deleted files" (versions with `gone_at`), "all versions of this file". Results show
  the version timeline and offer the existing restore actions (restore to agent/path, download, restore VM file).
- Retention and legal hold: deleting a snapshot updates the affected versions; the nightly check compares index and
  catalog and rebuilds a tenant's index from the sealed name indexes if they disagree.
- API: `GET /files/search` (synchronous, paged, tenant-scoped; replaces the 30 s job for normal queries), `nexusctl
  files search`, audit entry `file.search` (queries reveal names). Roles: as today (tenant users see their tenant).
- UI: Find files becomes an instant search with filters and a version timeline per result.

## Steps

- **31a** `nexus-fsindex` with GPT/MBR, LVM2 linear, NTFS, ext4, FAT; sandbox (SELinux domain, seccomp); fuzz targets;
  VM name indexes written without the micro-VM; per-chunk metadata cache; lab: Windows Server 2022 / Windows 11 / DC
  VMs on the PVE lab host, Debian LVM + XFS + ext4 lab VMs, compare with the micro-VM listing (same entries).
- **31b** `nexus-index` (Tantivy, sealing Directory), file-version model, incremental updates after each commit and
  retention, rebuild from name indexes, synchronous search API, UI, nexusctl, manual.
- **31c** XFS walker, LVM thin, btrfs, Windows LDM; owners/SIDs as filters; optional content hashes from the agents
  (shared with the Commvault/NetBackup hash-hunting item).

## Proposed decisions

1. Tantivy embedded in a dedicated `nexus-index` service; no OpenSearch/Meilisearch.
2. The search index is a sealed, rebuildable cache; per-snapshot sealed name indexes remain the source of truth.
3. Guest file systems are parsed in a sandboxed helper without keys; the micro-VM stays the fallback for unsupported
   file systems and for file restores.
4. VM file indexing on by default after measurement in the lab (cost per incremental snapshot).

## Open questions

- Memory budget of the decrypted segment cache on small appliances (8 GB RAM): segment size caps and an LRU.
- Whether owners/ACLs belong in the index (useful for "files of user X", but larger and more sensitive).
- Full-text content search is out of scope (parsing documents is a much larger attack surface).

## How Cohesity does it (research 2026-10-13)

Sources: Cohesity DataProtect 7.4.1 documentation, local copies under `/home/ah/Cohesity/` (the online
[docs.cohesity.com](https://docs.cohesity.com/) pages need a login): User Guide 7.4.1 (**UG**, printed page numbers),
Release Notes 7.4.1 (**RN**), solution guide *Protect Generic NAS with Cohesity* v1.1, May 2025 (**NAS**), best
practice guide *VMware vSphere Data Protection* (**VBP**). API calls are taken from Cohesity's public scripts repo
[cohesity/community-automation-samples](https://github.com/cohesity/community-automation-samples) and the
[Cohesity.PowerShell module](https://www.powershellgallery.com/packages/Cohesity.PowerShell/1.10.4/Content/Scripts%5CRestore%5CRestore-CohesityRemoteFileV2.ps1).
"Unverified" marks statements no source confirmed.

### Indexing

- **Switch and timing.** "Indexing" is a protection group option, on by default for VMware/Hyper-V/AHV VMs,
  block-based physical servers, NAS, Microsoft 365 and (new in 7.4.1) S3 views (UG pp. 1644, 2595; RN "Indexing
  Support for S3 Views"). It runs after the protection run as an indexing phase with its own progress in the run
  details, only for objects that were backed up successfully (NAS pp. 55-56). Incremental: "only the data that has
  changed since the previous snapshot is scanned and indexed" (UG p. 1644). Without indexing there is no file search
  and no download: "only items that were indexed when the Snapshot was created can be downloaded (this does not apply
  to NAS)" (UG p. 168). File-based physical jobs: UG p. 54 lists them as "agnostic of the file system", UG p. 2969 says
  "Indexing is not supported for file-based Jobs" (contradictory, unverified).
- **File systems** (UG p. 54, "Supported File Systems for Indexing"): VMs and block-based physical: ext2/3/4, XFS,
  NTFS, and btrfs (not multi-device btrfs). NAS: whatever NFS/SMB presents. LVM: linear, striped, mirrored,
  mirrored+striped and thin; a volume group with a missing disk is skipped entirely (UG pp. 2644, 2651). Windows
  dynamic disks: simple, spanned, striped and mirrored volumes yes, RAID-5 no (UG p. 234). Not indexed: ReFS (no file
  recovery either), volumes with disk-level encryption such as BitLocker, encrypted VMs, Storage Spaces (UG p. 2648,
  RN pp. 33-34). Excluding one disk of a striped volume disables indexing of that volume (UG p. 2594).
- **Paths.** Files are shown under the guest mount point: Linux from `/etc/fstab` (`UUID=…`, `/dev/mapper/VG-LV`,
  `/dev/VG/LV`), Windows with drive letters from the guest's mount information; if no mount point is found the volume
  appears as `/lvol_N/…` (UG pp. 2650-2652). A known Windows 8/2012 issue (drive letter changes not yet in the
  registry) makes the index show stale drive letters (UG p. 2644).
- **Mechanism.** The indexing service is `yoda` with a distributed helper `yoda_agent` (UG p. 277), which runs in a
  "Nexus proxy VM" (alert CE03008019) and is not available in DoD mode, where the host node mounts the volumes itself
  (RN p. 31). The snapshot is cloned into an internal view and mounted on the node (`yoda_clone_backup` mounts, stale
  mount health check, UG p. 764; alerts VMWareMountFailure, VMVolumeIndexingSkipped "fails to mount a volume of a
  VMDK", NonEmptyUnmountedDirectory, UG pp. 4738-4741). That means the guest file systems are mounted by a Linux kernel.
  Optimized NTFS and XFS paths exist, with fallback to an unoptimized path (CE03008013/14). Whether the optimized path
  parses metadata directly is unverified. Two alerts show the risk of kernel mounts: CorruptFileSystemNotIndexed
  ("indexing of a VM snapshot causes the indexing service to become unresponsive … only applicable for xfs VMs") and
  NodeRebootedForYodaStuck ("Due to bugs in the Linux kernel, XFS volumes' indexing in VMs that do not use
  app-consistent snapshots may result in instability. Action: Restart the nodes.") (UG pp. 4741-4745).
- **Default scope** (UG pp. 1235-1236, "Customize Indexing"): include `/`, exclude `/$Recycle.Bin`, `/Windows`,
  `/Program Files`, `/Program Files (x86)`, `/ProgramData`, `/System Volume Information`, `/Users/*/AppData`,
  `/Recovery`, `/var`, `/usr`, `/sys`, `/proc`, `/lib`, `/grub`, `/grub2`, `/opt/splunk`, `/splunk`. Rules use `/` on
  Windows too; `/C/Users` selects one drive and `/Users` all drives; a more specific include wins (`exclude /var` plus
  `include /var/log`). Cohesity recommends against indexing pseudo file systems (`/sys`, `/proc`, `/dev`, `/run`,
  `/tmp`, `/dev/pts`, `/dev/shm`). The reason given for exclusions is index disk space. Hidden files are also left out
  (UG p. 2650).
- **Storage and technology.** The search index used to be Elasticsearch on every node (alerts SearchClusterHealth
  "elastic search is down on a node", ESDiskUsageExceedsThreshold "all the indices in ES, such as files, audit logs")
  and is migrated to `librarian`, the "Index Catalog" service (alerts CE03008015-18 "search index migration to
  Librarian"; UG p. 275). Librarian is distributed with a fault tolerance factor and a data shuffle (CE03018002/3). Its
  internals are not documented (unverified). A Virtual Edition example reserves 163.64 GiB for librarian on a 7.99 TiB
  data disk, about 2 % (UG p. 4945). Encryption of the index is not documented (unverified; cluster encryption at rest
  presumably covers it).
- **Limits and health.** IndexingBacklog when a VM waits more than 48 h for indexing; IndexingPaused below 10 MB free
  space for the indexing component; SearchIndexSizeExceedsThreshold (UG pp. 4741-4744). No throughput or per-file
  figures are published (unverified); the NAS guide claims search "across billions of files" (NAS p. 9). VBP advises
  to switch indexing off during a disaster recovery to free resources.
- **Retention.** Index entries follow the snapshots: "Deleted snapshots may be displayed as valid recover points for
  a brief period until they are removed from the search index by a background process" (UG p. 2650). Stale indexing
  directories are cleaned periodically since 6.8.2/7.1.2 (UG p. 282, RN p. 21). A NetApp SnapDiff snapshot cannot be
  deleted while it is being indexed (UG p. 3561).
- **Tenants.** Assigning a cluster-level protection group to an organization reindexes changed files at the next run;
  "After the reindex, only the organization (tenant) users can search for files and folders" (UG p. 921). Tenant
  admins may search and browse files (UG p. 79).

### Search

- **UI** (UG pp. 2649-2652): *Recoveries → Recover → Files or Folders*. "Files and Folders" searches characters of a
  name or path, wildcard `*`; filters: object type, source, object, protection group, storage domain, files only,
  folders only. Windows paths are typed with `/` (`C:/Windows/System32/winevt/`). The latest snapshot is preselected;
  "Edit recovery point" lists only indexed snapshots by default ("Show Indexed Snapshots Only"), with a date range; with
  several items selected the recovery point cannot be changed. "Browse or Specify Path" opens one object; "Browse on
  Indexed Data" is fast but hides excluded and hidden paths, switching it off browses the mounted snapshot itself. No
  size, date or extension filters are documented for file search (unverified whether the UI has them). The global
  search box at the top searches objects (VMs, groups), not files (UG p. 312).
- **API.** v1: `GET /irisservices/api/v1/searchfiles?filename=…&jobIds=…&entityTypes=…`, paged
  `GET /public/restore/files?paginate=true&pageSize=…&paginationCookie=…`, and a separate
  `GET /file/versions?entityId=…&filename=…&jobId=…` per file. v2: `POST /v2/data-protect/search/indexed-objects`
  (`objectType: "Files"`, `fileParams.searchString`, `sourceEnvironments`, `objectIds`, `protectionGroupIds`), restore
  through `POST /v2/data-protect/recoveries` (`recoveryAction: RecoverFiles`), zip through
  `GET /v2/data-protect/recoveries/{id}/downloadFiles` (samples `python/fileSearch`, `python/restoreVMFiles`,
  `python/downloadZipFile`, `powershell/findFiles` in community-automation-samples). A search hit is one
  `fileDocument` per object and path; versions are a second request.
- **RBAC.** A "Search Objects" privilege exists (UG p. 611); file search is open to cluster and tenant admins (UG
  p. 79). Finer per-role rules for file search: unverified.
- **Content.** DataProtect searches names only (Microsoft 365 mail has its own filters: from, to, subject, folder,
  dates, attachments; UG pp. 3726-3727). Content classification and IOC scans are the DataHawk add-on (SaaS SKUs;
  security white paper p. 22, Splunk solution guide).

### Restore from search

- **Download** (UG pp. 2652, 2649): one file goes straight to the browser; several items create a recovery task that
  builds a zip, fetched later from the Recoveries page. The zip needs ZIP64, holds regular files and folders only (no
  symlinks), and renames `:` to `_COLON_` and `\` to `_BACK_SLASH_`. Not from tape. No size limit is documented
  (unverified).
- **Into a VM, original or new location** (UG pp. 2652-2660): restore methods "Auto Deploy Cohesity Agent" (guest
  credentials; Windows local admin or domain admin with UAC off), "Use Existing Cohesity Agent" (VMware Tools also
  required), or "Use VMware Tools" (guest operations; "maximum recovery speed is 1-2 Mbps", not recommended above
  "10 GB or 10,000 files", no Windows ACLs, no reparse points, no Linux symlinks). The snapshot's disks are attached to
  the target VM as SCSI disks (at most 15 at a time) and the Linux agent mounts and copies them with `sudo` (`mount`,
  `losetup`, `dmsetup`, `lvcreate`, `rsync`, …; needs `NOPASSWD` and `!requiretty`). Options: overwrite existing
  (default on; otherwise duplicates are skipped or land in `cohesity<taskid>_N`), preserve attributes (ACLs,
  permissions, timestamps; default on), continue on error. The default alternate path for VMs is `/tmp/`. Only Windows
  to Windows and Linux to Linux; VM to physical and back is not supported (RN p. 33). Hyper-V needs AD membership,
  PowerShell remoting, the Guest Service Interface and WinRM; AHV needs the agent.
- **Instant Volume Mount** (UG pp. 169-170, 2698): the volume is cloned into a temporary view and mounted on a target
  (VMware Windows/Linux, Hyper-V Windows, block-based physical; not AHV); teardown deletes changes.
- **Windows deduplication** (UG p. 2698): file restore and volume mount need a target with the Data Deduplication role
  installed; VMware Tools restores from deduplicated volumes are not supported.
- **NAS:** restore to the original or another volume; NetApp SnapDiff allows at most 8 files or one folder per task
  (UG p. 3562).

### What we adopt / change in Phase 31

- **31a: report every skipped volume with a reason.** Like VMVolumeIndexingSkipped and DiskWithCorruptedPartitionTable,
  but per volume in the snapshot's index status: encrypted (BitLocker, LUKS), ReFS, Storage Spaces, LDM RAID-5,
  LVM volume group with a missing PV, striped volume with an excluded disk, corrupted partition table, parser
  limit hit. One `index.skipped` alert per group and day, not per snapshot.
- **31a: LVM scope.** Cohesity indexes linear, striped, mirrored and thin LVs. Take striped and raid1/mirror (read one
  leg) into 31a with linear; thin stays in 31c. A volume group with a missing PV is skipped and reported, as above.
- **31a: mount point mapping.** Show guest paths, not partitions: Linux from `/etc/fstab` (`UUID=`, `LABEL=`,
  `/dev/mapper/…`, `/dev/<vg>/<lv>`), read by the parser from the root file system; Windows `C:` is the volume holding
  `Windows/System32`, other volumes by NTFS label; unmapped volumes appear as `vol<N>` (Cohesity: `lvol_N`). Exact
  Windows drive letters from the SYSTEM hive (`MountedDevices`) need a registry parser and move to 31c.
- **31a: crash-consistent snapshots.** Cohesity documents node reboots from XFS indexing of crash-consistent VM
  snapshots. This confirms the user-space, sandboxed parser. Our parsers never replay a journal (XFS log, ext4 jbd2,
  NTFS `$LogFile`); they read the on-disk metadata and mark the volume "crash-consistent: recent changes may be
  missing". Add lab and fuzz cases with dirty logs.
- **31a: Windows deduplication.** NTFS files with the dedup reparse tag are listed with their logical size and marked;
  the lab checks whether the micro-VM can restore them (Linux NTFS drivers do not read the dedup chunk store, so
  unverified). If not, the restore dialog says so and points to the Windows agent.
- **31b: per-group index scope with Cohesity's default excludes, applied to the search index only.** The sealed
  per-snapshot name index stays complete (it is the source of truth and is cheap); include/exclude rules only filter what
  goes into Tantivy, so a later change of rules is a re-ingest, not a re-parse. Rule syntax as Cohesity: `/` separators
  on Windows, `/C/…` for one drive, `/…` for all drives, `*` per path component, the most specific rule wins. Default
  excludes: Cohesity's Windows list (`/$Recycle.Bin`, `/Windows`, `/Program Files`, `/Program Files (x86)`,
  `/ProgramData`, `/System Volume Information`, `/Users/*/AppData`, `/Recovery`) and the Linux pseudo/system trees
  (`/proc`, `/sys`, `/dev`, `/run`, `/tmp`, `/usr`, `/lib`, `/lib64`, `/boot`, `/var/cache`, `/var/tmp`,
  `/var/lib/docker`, `/var/lib/containerd`). Unlike Cohesity we keep `/var` (database, web and mail data live there)
  and do not ship product-specific entries (`/opt/splunk`). Browsing and downloading never depend on the index.
- **31b: toggle semantics.** `index_files` (off / on, default on) controls the VM/CT parser follow-up job and the
  ingestion into the search index. Agent, NAS and plugin name indexes are always written at commit. Each snapshot shows
  an index state (indexed / pending / partial with reasons / off); the version timeline marks snapshots that are not
  indexed (Cohesity: "Show Indexed Snapshots Only"). The indexing job reports progress through the existing live
  progress lines.
- **31b: filters.** Cohesity's filters: source kind (VM, CT, agent, NAS, plugin), source/guest, group, files only /
  folders only. In addition to Cohesity: extension, size range and modification time range (they are cheap in Tantivy;
  Cohesity documents none of them).
- **31b: one request for name and versions.** Cohesity needs a second call per file (`/file/versions`); our file
  version documents return the version timeline with the hit. `GET /files/search` is paged with a cursor (like
  `paginationCookie`).
- **31b: retention without a lag.** Cohesity removes deleted snapshots from the index in the background, so deleted
  snapshots appear as recovery points for a while. We close the versions in the snapshot delete path, run the nightly
  compare as the safety net, and a hit whose snapshot is gone returns a clear "snapshot deleted" error. Snapshot
  deletion is never blocked by indexing; a running indexing job for that snapshot is cancelled.
- **31b: health alerts.** `index.backlog` when a snapshot waits more than 48 h for indexing (Cohesity's threshold);
  indexing pauses and alerts when the index volume falls below a free space floor; the index size is shown in
  **Storage** (Cohesity reserves about 2 % of a data disk; our estimate is ~2 GB per 10 M versions).
- **31b: tenant moves.** Moving a source to another tenant removes its documents from the old tenant index and ingests
  them into the new one (Cohesity reindexes at the next run); search is never cross-tenant.
- **31b: download.** One file streams directly without a job (as Cohesity); several items stay a job with tar or zip.
  zip is written as ZIP64; entries that zip cannot hold (symlinks, special files) are skipped and listed in a
  `SKIPPED.txt` inside the archive, not silently dropped. Names are not rewritten (`:` and `\` are legal in zip and
  in tar). No hard size cap; above 10 GB or 10,000 files the dialog suggests a restore to a host (Cohesity's own
  threshold for slow guest-tools restores).
- **31c: restore into a running VM** (optional). Cohesity attaches the backup disks to the target VM and copies with
  an agent, or uses VMware Tools guest operations (1-2 Mbps). The PVE equivalent is the existing **Attach one disk to a
  VM…** plus the QEMU guest agent for small sets (`guest-file-open/write`, speed unverified, limit to ~1 GB / 10,000
  files). Defaults differ from Cohesity on purpose: an alternate directory `nexus-restore-<job>/` instead of `/tmp/`,
  and **no overwrite** by default (a restore during a ransomware incident must not overwrite evidence). Same OS family
  only, as Cohesity.

**Deliberately different from Cohesity**

- No Elasticsearch/OpenSearch: Cohesity itself moved its file index from Elasticsearch to its own Librarian service;
  an embedded Tantivy index is the single-box equivalent (decision 1).
- No kernel mounts of guest file systems for indexing, neither on the appliance nor in a helper VM; the sandboxed
  parser replaces Cohesity's clone-and-mount (decision 3). The micro-VM stays for browsing and restores.
- The index is sealed with the tenant keyring (decision 2); Cohesity documents nothing about index encryption.
- Downloads and browsing work for every snapshot whether indexed or not (Cohesity: only indexed items can be
  downloaded, except NAS).
- No content search or classification (Cohesity sells it as DataHawk); names, sizes and times only.
