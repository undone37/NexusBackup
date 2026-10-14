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
`LABEL=`, `PARTUUID=`, `/dev/mapper/…`, `/dev/<vg>/<lv>`; Windows `C:` = the NTFS volume with
`Windows/System32`; else the label or `vol<N>`) and the chunks its parse read. A volume whose read chunks are
unchanged in the next snapshot is not parsed again; its listing is copied from the previous name index (the cache
key is the set of chunk ids, the granularity is the volume). XFS, btrfs and ZFS volumes are listed through the
micro-VM when its image is installed (`NEXUS_FSINDEX_NO_VM` turns that off); BitLocker, LUKS, ReFS, Windows dynamic
disks (LDM), Storage Spaces, md RAID, LVM thin/cache/VDO/RAID5 are reported with their reason.

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
