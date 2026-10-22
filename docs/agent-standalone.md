# Standalone agents (Phase 38b/38c)

Status: first step, 2026-10-22. The Linux agent backs up into a repository of its own, without an appliance:
`nexus-agent repo init|open|backup|list|restore`. Scope and order of the whole phase: docs/veeam-agent-comparison.md
"Scope decision". Not yet: Windows CLI, schedules and triggers (38e), retention and GC runs, network targets other
than a mounted directory, the desktop UI (38h), import into an appliance (38i). Since the second step: `repo prune`
(GFS retention of the appliance, then GC) and one writer at a time (`<repo>/lock`, an OS file lock).

## Design

- **One agent, two modes.** The same binary and the same platform code (snapshots, walk, FastCDC chunking, metadata
  cache, restore engine) as in managed mode. `agent_core::standalone` takes the appliance's half: chunk ids, the
  tree, the commit, listing, and feeding restores to the platform's restore engine.
- **Repository = the appliance's chunk store** (`crates/chunkstore`, now also built for Windows): deduplicated,
  zstd, XChaCha20-Poly1305, keyed chunk ids; one snapshot source per machine (`host-<hostname>`), tree index
  `tree` as in agent snapshots on the appliance, so 38i can take a repository over without conversion. Snapshot
  locks: none by default (the owner's own disk; Object Lock comes with S3 targets).
- **Keys.** `repo init` creates a random data key and a random recovery key; `key.recovery` in the repository holds
  the data key wrapped under the recovery key (XChaCha20-Poly1305, label `nexus-standalone-dek:v1`), the recovery
  key is printed once as 24 words (crate recovery-key, ADR-015). The machine keeps the data key in its standalone
  state directory (`<state>/standalone/repo-<id>.key`, 0600 root; Windows: the state directory's ACL), so scheduled
  backups need no input. `repo open` on another machine reads the 24 words from stdin and keeps the key from then
  on. Whoever has the repository but neither the machine nor the words reads nothing.
- **Its own state directory** (`<state>/standalone`): metadata cache and spool are not shared with managed mode. A
  file the cache calls unchanged is unchanged since the last standalone snapshot, whose chunk ids it takes over by
  path; if that snapshot is gone or does not match, the backup reads everything again (once).
- **Restores** go through the platform's restore engine with the confirmation `standalone` (the local
  administrator started them): same path safety, overwrite policy and metadata as appliance restores.
- **Durability on Windows:** the store cannot flush directories there; files are flushed before their rename and
  NTFS journals the rename (`chunkstore::store::sync_dir`).

## Tests

`crates/agent-linux/tests/standalone.rs`: backup, an incremental that reuses the unchanged big file's chunks,
restore of the first snapshot, opening on another machine with the 24 words (wrong words refused).
