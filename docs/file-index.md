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
(`groups.index_files`, catalog v18, `PUT /groups/{id}/index-files`, admin, audited `group.index_files`).

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
