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
