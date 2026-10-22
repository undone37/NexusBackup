# Standalone agents (Phase 38b/38c)

Status: first step, 2026-10-22. The Linux agent backs up into a repository of its own, without an appliance:
`nexus-agent repo init|open|backup|list|restore`. Scope and order of the whole phase: docs/veeam-agent-comparison.md
"Scope decision". Also `repo prune` (the appliance's GFS retention, then GC) and one writer at a time
(`<repo>/lock`, an OS file lock). Not yet: the desktop UI (38h), import into an appliance (38i). Since 38e (first part): scheduled jobs in
`<config>/standalone.json`, run by the agent service (also on a machine that is not enrolled). The commands are shared
(`agent_core::standalone::cli`): `nexus-agent repo …` on Linux, `nexus-agent.exe repo …` on Windows (builds; not yet
run on a Windows machine).

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

## Scheduled jobs (38e, first part)

`<config>/standalone.json` (`/etc/nexus-agent`, `%ProgramData%\NexusAgent\config`):

```json
{"jobs": [{"name": "home", "repo": "/mnt/usb/nexus", "paths": ["/home", "/etc"], "schedule": "daily 21:00",
           "tz": "Europe/Berlin", "keep": "24,7,4,12,0", "min_battery": 30, "skip_metered": true}]}
```

- The service checks the jobs every minute (`standalone::tick`) with the appliance's schedule grammar (crate
  `schedule`, moved out of the catalog for this): a slot is due once; after downtime one catch-up run, not one per
  missed slot. A new job is due at once. A slot counts as done once attempted; a failure is recorded and the next
  slot tries again.
- A due job **waits** (and says why, once) while its repository is not there (a disconnected USB disk or an
  unmounted share: "backup when the target is connected"), while the battery is below `min_battery` on battery,
  and while the network is metered with `skip_metered` (the power state the agent already reports to the appliance).
- After the backup, `keep` prunes (`""` = no pruning). State per job in `<state>/standalone/jobs.json` (last run,
  last success with its summary, last error, why it waits); `repo jobs` shows it, `repo run <job>` runs one now.
- An agent that is not enrolled but has jobs runs them and nothing else (no listener).
- Not yet: lock/log-off and wake triggers, retries within a slot, bandwidth limits, a status in the desktop UI
  (38h), e-mail.

## Copies to SFTP, S3 or another directory (38c)

`repo copy <dir> <target.json>` (and a job's `"copy": "<target.json>"` after backup and prune) mirrors the
repository with the offsite storage clients (crate `remote`, split out of `offsite` for this): files the target
lacks are uploaded (everything is already encrypted), chunks first, a snapshot's files before its manifest (the
commit point), manifests and the top-level files (clock) replaced every time, files the repository no longer has
deleted (manifests first, chunks last). On S3 with Object Lock (`lock_days`), chunks are uploaded locked; a locked
object that local GC removed stays until its date and is deleted by a later copy. `repo fetch <target.json> <dir>`
downloads a copy into an empty directory; `repo open` with the 24 words then opens it on any machine. The target
file holds credentials: keep it next to the jobs file (root / Administrators only).

Mirror, not the appliance's offsite packs: one object per chunk (many small objects on S3; an SFTP box with a
file-count limit fills faster). ponytail: packs like `crates/offsite` when that matters.

## Local UI (38h, first part)

The UI channel (crate `agent-ui-proto`) has `jobs` (each job with schedule, next slot, last success and summary, last
error, why it waits, whether a run is queued) and `run_job` (queues a run for the job loop, which starts it within
about a second and applies the usual waits; refused while the appliance's UI policy hides "backup now"). An older
service refuses the ops and the UIs hide the jobs. The desktop window shows a card "Backups on this computer" with
"Run now" per job; on Linux, `nexus-agent jobs` and `nexus-agent run-job <name>` do the same for members of
`nexus-agent-ui` without root. The run-now queue lives in the service process (one job pass at a time); a run asked
for while the job waits keeps waiting with it. Not yet: a jobs view in the TUI, job configuration or restores from
the UI.

## Tests

`crates/agent-linux/tests/standalone.rs`: backup, an incremental that reuses the unchanged big file's chunks,
restore of the first snapshot, prune, the writer lock, opening on another machine with the 24 words (wrong words
refused); the job pass (once per slot, prune after the backup, waiting for a missing repository and running when it
appears, a broken jobs file reported); a copy (incremental, deletions after a prune), fetched and opened on another
machine with the words, restored; the UI ops (`jobs`, `run_job` for an unknown and a known job, the next pass
runs the queued job although its slot is not due).
