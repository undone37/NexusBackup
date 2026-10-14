# File index and file search (Phase 15g)

Find a file by name across all snapshots of a tenant, then open, download or restore it.

## Format

Each snapshot can have a **name index** next to its manifest:

```text
snapshots/<source>/<time>/names
```

The file is `postcard(NameIndex)`. It is zstd-compressed and sealed with the tenant keyring, like a manifest or an
index (`crates/chunkstore/src/names.rs`). The AEAD context is `names:<source>/<time>`, so a name index copied into
another snapshot, or opened with another tenant's key, fails to decode.

```rust
struct NameIndex {
    paths: String,   // every path relative to the snapshot root, each one ending in NUL
    size: Vec<u64>,
    mtime: Vec<i64>, // seconds
    kind: Vec<u8>,   // 0 file (and hard link), 1 dir, 2 symlink, 3 other
}
```

The layout is column-wise: all paths share one string. Decoding 200,000 names costs one copy and one UTF-8 check,
not 200,000 allocations. Paths match the file browser (`/` + path). Names that are not UTF-8 are stored lossily
(U+FFFD).

## Where the index comes from

| Snapshot | When | Content |
|---|---|---|
| `host-*`, `nas-*`, `share-*`, `plugin-*` (any `Tree` index) | at commit (`Store::commit_snapshot`), before the manifest | the tree entries; plugin streams appear below `.nexus-streams/` |
| `vm-*` | after each backup of a group with `index_files`: job `file_index {source, time}` → `nexus-pve … files <vmid> <time> index` | a walk of the guest file systems in the restore micro-VM (`ls` from `/`, symlinks not followed, paths `<mountpoint>/…`); at most 5 million entries or 1 h; unreadable directories are skipped |
| `ct-*` | the same job → `nexus-pve … ct-files <vmid> <time> index` | every entry of the stored tar stream (no micro-VM) |
| older snapshots, offsite or replicated imports | daily job `file_index {}` per tenant (with gc/verify) | built from the snapshot's `Tree` indexes; idempotent |

The index lives in the snapshot directory, so retention, `snapshot_delete` and GC remove it together with its
snapshot. Offsite copies and replication do not carry it (it is derived data): a restored or replicated store gets
the index back from the daily backfill, except for VM/CT disks, which are indexed after the next backup.

**Cost of VM indexing.** The micro-VM boots once more after every backup of the group. It reads only the guest file
system metadata (not the file contents) through the chunk store: one boot plus the directory walk per VM.
Container indexing reads the container's whole tar stream from the store. That is why both are opt-in per group
(`groups.index_files`, catalog v19, `PUT /groups/{id}/index-files`, admin, audited `group.index_files`).

## Search

`POST /api/v1/search {tenant, query, source?, from?, to?, case_sensitive?, limit?}` is open to admin, operator and
tenant_user (own tenant only), the same roles that may run `files_list`. It queues a `file_search` job and returns
202 `{id}`. The request is audited as `file.search` with all its parameters, including the query. The result comes
from `GET /jobs/{id}`:

```json
{"matches": [{"source": "host-a1", "path": "home/ann/report.docx", "kind": "file", "size": 12345,
              "mtime": 1760000000, "times": [1760300000, 1760200000]}],
 "scanned": 120, "unindexed": 3, "truncated": false, "elapsed_ms": 840}
```

- **Query.** A glob with `*`, `?`, `[abc]`, `[a-z]`, `[!x]` and `\` escapes. A query without wildcards is a
  substring search. A query that contains `/` matches the whole path, where `*` also matches `/`. Any other query
  matches the last path component only. Matching is case-insensitive unless `case_sensitive` is set; non-ASCII
  letters are folded too.
- **Versions.** One `(source, path, size, mtime)` across snapshots is one match. `times` lists the snapshots that
  contain it, newest first.
- **Limits.** At most `limit` matches (default 500, at most 2000). The job stops picking up snapshots after 30 s.
  Either limit sets `truncated`. `unindexed` counts snapshots without a name index, for example VM/CT snapshots of
  groups without `index_files`.
- **Execution.** The scheduler runs the job in process with the tenant keyring from keyd (`Step::Store`). The key is
  `search:<job>`, so it never waits for the tenant's backups. Snapshots are decoded in parallel (up to 8 threads),
  and matches are merged newest snapshot first, so the result does not depend on thread timing. Only local
  snapshots are searched; an offsite-only snapshot has no local index.

Benchmark (`cargo test -p scheduler --release search_benchmark -- --ignored --nocapture`, dev box with 16 threads):
100 snapshots × 200,000 names, about 1.4 MiB sealed per index, are searched in **0.6–1.6 s**. The target was under
10 s. A per-tenant aggregate index (path → snapshot bitmap) would only be needed far beyond that size.
<!-- ponytail: per-snapshot scan; aggregate index only if tenants reach ~10^4 snapshots × 10^6 names -->

## Security

- **No file names in plaintext.** File names never leave the tenant's sealed store. The catalog holds neither
  names nor an index; it holds only the search job's parameters (the query) and its result. Like `files_list`
  results, those are visible to whoever may see the tenant's jobs.
- **Search needs the key.** The search runs in the scheduler, which gets the tenant keyring from keyd, the same way
  as retention, GC and verify. The web-api never sees a key.
- **Hostile sources.** A guest or source can put arbitrary names into its own tenant's index (NUL is replaced), and
  nothing more. Names are shown as text, and every download or restore goes through the existing `files_get` /
  `restore_files` path checks.
- **API tokens.** `POST /search` is not on the token allow-list.

## File hashes and the IOC hash hunt (Phase 28)
Groups with **`file_hashes`** (`PUT /groups/{id}/file-hashes`, Groups page) record the SHA-256 of every regular file
in the sealed name index, so a hunt for known-bad hashes (IOC feeds) needs no restore.

- **Format:** name index v2 (`chunkstore::names`): the v1 columns plus a sparse list `(entry index, SHA-256)`,
  sealed with the context `names2:<source>/<time>` (v1: `names:<source>/<time>`). An index without hashes is still
  written as v1, so the previous release reads every snapshot taken without the option. Readers try v2, then v1;
  out-of-range or unordered hash entries are refused. Never offsite (derived data, rebuilt from the snapshot).
- **Where the hashes come from** (`Store::enable_file_hashes`, at commit): computed while reading by the connector
  (NAS shares, TrueNAS, plugin file trees: `store_file*`) or by the agent (`file-hash` capability,
  docs/agent-protocol.md); carried over from the previous snapshot of the source for files with the same chunk
  list; otherwise read back from the store (older agents, the first run after switching it on). The job log has a
  line `file hashes: N while reading, N from the previous snapshot, N read back from the store, N failed`.
- **Containers:** with `index_files` and `file_hashes` the `file_index` job hashes every regular file of the root
  tar (`nexus-pve … ct-files … index hashes`). **VM disks** get no hashes yet (the walk in the micro-VM would read
  every file; decision: later, opt-in).
- **Hash lists:** `PUT /hash-lists/{name} {text}` (admins, security officers; text or CSV, the first SHA-256 per
  line; MD5/SHA-1 skipped and counted); at most 20 lists, 100 000 hashes each, 500 000 together; stored normalised
  in `hash_lists` (catalog v43), audited with their SHA-256.
- **Hunt:** `POST /hunts {tenant, lists?, source?, from?, to?}` queues `hash_hunt`; the scheduler opens the tenant's
  store (in-process, read-only, own plan key, 30 minute budget, parallel like the file search), compares the hashes
  of every name index v2 with the lists and returns `{matches: [{source, path, size, sha256, lists, times}],
  scanned, unhashed, truncated, hashes}` (at most 2000 file versions). Hits flag the snapshots that contain them
  (anomaly reason `IOC hash: …`, so restores default to an earlier clean snapshot) and raise the critical
  `hash_hunt_hit` alert for the tenant. The Hash hunt page shows the results with **Restore…** and **Legal hold…**.

## Phase 31: VM files without the micro-VM, instant search (2026-10-14)

Plan and decisions: `docs/file-index-v2-plan.md`. What changed against the sections above:

**VM name indexes (31a).** `nexus-pve … files <vmid> <time> index` no longer boots the restore micro-VM. It starts
`nexus-fsindex --helper` (crate `fsindex`) and answers its read requests from the chunk store; the helper never
sees a key. The helper parses GPT/MBR (with logical partitions), LVM2 (linear, striped, mirror, raid1 by its first
leg; a volume group with a missing PV is skipped as a whole), ext2/3/4 (`ext4-view`, the jbd2 journal is applied
in memory only), NTFS (`ntfs`; size from `$DATA`, mtime from `$STANDARD_INFORMATION`, DOS 8.3 names and metadata
files left out, Windows deduplication files counted), FAT12/16/32 (`fatfs`, writes refused by the device) and
exFAT (own parser). Paths in the name index stay the file browser's (`vda1/…`, `lvm/<vg>-<lv>/…`), so open,
download and restore work unchanged. The micro-VM walk is still available as `files … index-vm`.

Every snapshot gets a sealed volume report `snapshots/<source>/<time>/fsindex` (chunkstore `snapfile.rs`): per
volume the browse name, device, file system, label, UUID, PARTUUID, state (`indexed`, `skipped`, `unsupported`,
`failed`, `partial`) with a reason, the guest mount point (from the root file system's `/etc/fstab`: `UUID=`,
`LABEL=`, `PARTUUID=`, `/dev/mapper/…`, `/dev/<vg>/<lv>`; Windows: drive letters from the system volume's
SYSTEM hive, see below; else the label or `vol<N>`) and the chunks its parse read. A volume whose read chunks are
unchanged in the next snapshot is not parsed again; its listing is copied from the previous name index (the cache
key is the set of chunk ids, the granularity is the volume). ZFS and multi-device btrfs volumes (XFS and btrfs
until Phase 31c, see below) are listed through the micro-VM when its image is installed (`NEXUS_FSINDEX_NO_VM` turns that off);
BitLocker, LUKS, ReFS, striped and RAID-5 dynamic volumes, Storage Spaces, md RAID, LVM cache/VDO/RAID5 are reported
with their reason (LVM thin volumes and simple / spanned dynamic volumes are read since Phase 31c, see below).

Lab measurement (restore-vm fixtures, 1.1 GB GPT disk with ext4, XFS, NTFS, btrfs, vfat, LVM; 256 MB ZFS disk):
the helper lists the same entries as the micro-VM walk for ext4, NTFS, vfat and ext4-on-LVM in **0.14 s**
(micro-VM: 8.8 s); with the micro-VM fallback for XFS/btrfs/ZFS the second snapshot took 9.7 s, the four
unchanged volumes reused (`crates/pve/tests/restore_vm.rs` `fsindex_matches_micro_vm_listing`).

**Parallel walk (Phase 32).** `nexus-pve` starts one helper per CPU (up to 8) for a listing; each stays
single-threaded and sandboxed (seccomp, no threads or processes). The NTFS and ext4 trees are split between them
(`fsindex::Part`): every directory belongs to one helper (the root to helper 0, others by an FNV hash of their path,
from depth 3 down of their first three components, so a subtree stays together), which reads its entries' MFT records
and emits them; directories above depth 3 are also walked by the other helpers, which only take the subdirectories
from the index entries (NTFS) or directory entries (ext4) without reading the children; FAT, exFAT
and the volume layout come from helper 0 alone. The parent serves each helper on its own thread with one shared LRU
cache of 128 decoded chunks (a miss decrypts and decompresses outside the lock, so in parallel) and merges the
listings per volume (worst state, union of the read chunks, entries sorted by path). Lab (Windows Server C:, 391k
entries): 150-217 s with one helper and a FIFO cache of 32, 82-90 s with the LRU cache, 70-72 s with 8 helpers
splitting from depth 2 (the subdirectories of `Windows/WinSxS` all went to one helper; hence depth 3 and per-directory
owners).

**Directories taken over (Phase 31c, NTFS).** A running Windows system volume changes somewhere between any two
snapshots, so the per-volume reuse rarely applies to it. Every NTFS directory listed completely gets a record (side
file `fsindex-dirs`, postcard, sealed: path, the chunks its listing read, its subdirectories with their MFT record
numbers, its dedup / skipped counts). The helper's block cache logs every block a directory's listing touches (hits
included: its index root and allocation blocks and its children's MFT records) and sends it with the record (frame
`L`); before listing a directory the helper asks (frame `U`, by path), and when every chunk of the previous
snapshot's record is unchanged (chunk ids compared, nothing decrypted) the parent adds the previous name index's
entries of that directory and answers with its subdirectories, which the helper walks on without reading the
directory. A renamed or moved directory has another path and is listed again. Volumes taken over whole carry their
records on. XFS directories get records the same way (see below). ext4 keeps no records: crate `ext4-view` caches blocks itself, so the helper cannot see everything a
listing depends on; ext4 volumes are taken over per volume as before. The job log line says how many directories
were taken over; the result has `dirs_taken_over`.

**XFS (Phase 31c).** The helper reads XFS itself (`fsindex::xfs`, no maintained crate exists): the superblock (v4
and v5; on v5 the superblock, inode, extent-tree and directory block CRC-32C checksums are checked and unknown
incompatible features refuse the volume), inodes by number (an inode number encodes its AG, block and slot, so the AG
inode B+trees are not needed; v5 inodes must carry their own number), big time stamps and 64-bit extent counters,
data forks in local, extent and B+tree format, and directories in every format (short form in the inode; block, leaf,
node and B+tree directories by their data blocks below 32 GiB, also when a directory block spans several file system
blocks; leaf and free index blocks are not needed for a listing). Bounds: B+tree depth 10, 2^20 extents per fork,
1 GiB of directory data per directory, every block number checked against the AG geometry, directories entered
once, the time budget checked per directory. The XFS log is never replayed (as for the other file systems). XFS
volumes are split between the helpers like NTFS and ext4, and every block goes through the helper's logged block
cache, so XFS directories get records and are taken over unread like NTFS ones. The micro-VM fallback stays for
btrfs and ZFS. Tests: mkfs.xfs with a protofile (no root), v5 with 4 KiB and 1 KiB blocks and v4 without file
types, each with short form, block, leaf, node and B+tree directories; fuzz target `xfs_walk` (checksums are not
verified in fuzz builds, `cfg(fuzzing)`, so the fuzzer reaches the parsers behind them).

**btrfs (Phase 31c).** Single-device btrfs is read by an own parser too (`fsindex::btrfs`): superblock (CRC-32C
checked when that is the checksum type; xxhash, SHA-256 and BLAKE2 file systems are read without verifying),
the system chunk array and the chunk tree (logical to physical; single, DUP and RAID1 profiles by their first stripe),
the root tree and the file system trees (directory index items, inode items; inline and uncompressed extents for
`/etc/fstab`). The listing starts at the default subvolume, as the micro-VM mounts it (no `subvol=`), so the browse
paths match the file browser; subvolumes and snapshots below it are directories with their contents. Tree nodes are
checked (address, fsid or metadata UUID, level, item bounds), descents are bounded by the strictly decreasing node
level, directories are entered once; extent tree v2 and the RAID stripe tree are refused. A log tree is not replayed
(`dirty`). btrfs gets no directory records: it is copy-on-write, every change rewrites the path up to the tree
root, so a directory's read set would always have changed; unchanged volumes are still reused whole, and the
helpers split the tree as for the other file systems. Multi-device btrfs is reported by the probe and goes to the
micro-VM fallback (as does ZFS). Tests: mkfs.btrfs `--rootdir` (top level with nested subvolumes, a default
subvolume with 4 KiB nodes, zstd compression); fuzz target `btrfs_walk` (input: sparse records of a 512 MiB disk,
seeds are the non-zero blocks of small images; run with `-max_len` 1 MiB).

**LVM thin volumes (Phase 31c).** A thin LV's blocks come from its pool's dm-thin metadata (the pool's `_tmeta` LV,
mapped like any LV): the superblock (magic, version 1/2, 4 KiB metadata blocks, checksum), the top-level B+tree
(thin device id from the LV's `device_id` -> root of its mapping tree) and the device's mapping tree (thin block ->
pool data block, in key order). Consecutive mappings become one segment on the pool's `_tdata` LV (and through it on
the disks); unmapped blocks read zeros, as dm-thin returns them. Every node's checksum (persistent-data CRC-32C with
the block type's constant), block number, layout and key order is checked; tree depth 16, every node once, at most
2^21 runs per thin LV (more: "too fragmented", reported). Thin snapshots are thin LVs of their own and are listed;
thin LVs with an external origin are reported. The pool LV is reported as `skipped` ("its thin volumes are
listed"). The metadata is read as committed on disk (dm-thin writes it transactionally); the volume key includes a
hash of the mapping, so a thin LV whose mapping changed is parsed again (its old read set no longer describes it).
Test: LVM metadata, pool metadata and an ext4 spread over the pool in reverse block order, written by the test
(lvcreate needs root); a damaged node and a device missing from the metadata are reported. Fuzz target `lvm_thin`.

**Windows dynamic disks (Phase 31c).** The LDM database is read as the Linux kernel's `block/partitions/ldm.c` reads
it (`fsindex::ldm`): the private header (MBR disks with partition type 0x42: sector 6; GPT disks: the last sector of
the LDM metadata partition), the table of contents, the database header (`VMDB` 4.10) and its `VBLK` records
(fragmented records joined; disks `DSK3`/`DSK4`, volumes `VOL5`, components `CMP3`, partitions `PRT3`; every
variable-length field and record size checked as the kernel checks it). Of the disks of the snapshot, the newest
database copy wins; disks are matched by the GUIDs of their private headers. Simple and spanned volumes become
volumes `ldm/<name>` (segments on one or several disks); mirrored volumes are read by their first plex; striped and
RAID-5 volumes, volumes whose disk is missing and damaged databases are reported. Each dynamic volume carries its
volume GUID as `win_id`, so the drive letters of the SYSTEM hive (`DMIO:ID:` + volume GUID) apply to them. Browse
paths of dynamic volumes (`ldm/<name>/…`) are the index's own: the restore micro-VM does not assemble dynamic volumes,
so their files are found by the search and listed, but are restored through the Windows agent. Several disk groups
in one VM: only the newest database's group is read. The layout of GPT dynamic disks follows libldm and is not yet
checked against a Windows-made disk (MBR layout as the kernel). Test: two MBR disks with a database written by the
test (simple NTFS system volume whose hive names the dynamic volumes C: and D:, an ext4 spanned over both disks, a
striped and a RAID-5 volume; the second disk missing). Fuzz target `ldm_db`.

**Windows drive letters (Phase 31c).** The NTFS volume holding `Windows/System32` is the system volume. Helper 0
reads its `Windows/System32/config/SYSTEM` in place (random access through the file's `$DATA`, never the whole file)
with an own read-only registry hive parser (`fsindex::regf`: base block checksum, `nk`/`vk` cells, `lf`/`lh`/`li`/`ri`
subkey lists, every offset checked against the hive, lists and `ri` nesting bounded, big-data values not read) and
takes the `\DosDevices\X:` values of `HKLM\SYSTEM\MountedDevices`: `DMIO:ID:` + GUID names a GPT partition (its
unique partition GUID) or a dynamic volume, 12 bytes name an MBR partition (disk signature at 0x1B8 + byte offset).
The volume report keeps them (`drives`, and `win_id` per volume); the parent's mount mapping accepts only `A:`-`Z:`
and volumes it listed, gives each letter once, and keeps `C:` for the system volume when the hive does not name it
(missing, unreadable or damaged hive: as before). The hive's transaction logs (`SYSTEM.LOG1/2`) are not replayed: a
letter changed in the last minutes before a crash-consistent snapshot may still show the old one (Cohesity documents
the same staleness). MBR partitions now also carry Linux's `PARTUUID=<signature>-<number>`.

`groups.index_files` is on by default for new Proxmox VE groups. The job result (catalog, plaintext) names only
browse names, file systems, mount points, states and reasons; labels, UUIDs and fstab contents stay sealed.
`snapshot_index` (catalog v42) keeps the state per VM/CT snapshot (`pending` while queued).

**Search (31b).** `GET /api/v1/files/search` answers synchronously from `nexus-index` (crate `fileindex`): one
Tantivy index per tenant under `/var/lib/nexus/index/<tenant>/`, every file sealed with the tenant keyring in
256 KiB blocks (decrypted blocks in a cache bounded in bytes). Documents are file versions (source, guest path,
browse path, size, mtime, kind, `first` snapshot, `gone` snapshot); the index follows the stores (sync after
nudges from the scheduler and every 10 minutes: new snapshots are appended, anything else rebuilds that source
from its sealed name indexes). Queries: path glob (`/` in the query; `*` within a folder, `**` across), name glob
(`*`, `?`; no wildcard = substring) or words; filters for source, group, source kind, extension, size, modified
time, files/folders, deleted files. Each hit is one file with all its versions and the local snapshots holding
them; the answer also marks the snapshots of the hit sources that are not indexed (with the reason). Per group,
`GET|PUT /groups/{id}/index-rules` scopes what goes into the search index (default excludes: Windows system
folders, `/proc`, `/sys`, `/dev`, `/run`, `/tmp`, `/usr`, `/lib*`, `/boot`, `/var/cache`, `/var/tmp`,
`/var/lib/docker`, `/var/lib/containerd`; `/var` stays searchable); the name indexes always hold everything.
`POST /search` (the job above) stays as the fallback when nexus-index is not running. `nexusctl files search`.
Alerts: `index_backlog` (a snapshot waits more than 48 h), `index_space` (indexing paused below the free-space
floor). Threat model T60, T61.
