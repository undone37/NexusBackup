# Ransomware signals (Phase 21a)

Anomalous snapshots are flagged, file-level change signals come from the name index, two snapshots can be diffed,
and each source has change trends. User view: manual chapters 06 and 11.

## Snapshot flag

Catalog v26 adds `snapshots.anomaly` (the reasons, `; `-joined, NULL = clean), `anomaly_at`, and
`anomaly_cleared_by` / `anomaly_cleared_at` / `anomaly_note`. Only the scheduler sets a flag
(`Scheduler::flag_snapshot`, audited `snapshot.anomaly` by `scheduler`):

- the change-rate check (`anomaly.rs`, Phase 13e) on a finding;
- the file-level check (`changes.rs`) on a finding.

The row is upserted like `consistency`, so the snapshot refresh keeps it. A new finding on a cleared snapshot sets
the flag again. "Clean" = `anomaly IS NULL OR anomaly_cleared_at IS NOT NULL`. The `anomaly` alert names the newest
clean snapshot before the flagged one (`last snapshot before: <source>/<time>`, `Scheduler::last_clean`), which is
what **Hold last good snapshot** holds.

`GET /snapshots` returns `anomaly {reason, at, cleared_by, cleared_at, note} | null` and `anomalous` (flagged and
not cleared). `POST /snapshots/{tenant}/{source}/{time}/anomaly/clear {note}`: security officers (within their
tenant scope), immediate, audited `snapshot.anomaly_clear`; 409 if not flagged. No approval: clearing does not
delete or weaken anything, and the reason stays. The UI's restore, plugin-restore, restore-to-host and legal-hold
dialogs opened on a flagged snapshot switch to the newest clean snapshot before it (switchable back); "Restore
several" picks the newest clean snapshot per guest.

## File-level change signals

Job `file_changes {source, time}` (scheduler, `Step::Store`, key `changes:<job>`: never waits for the tenant's
backups) is queued

- after a successful `backup` / `plugin_backup`, for every snapshot in its `nexus-stats` lines that is not `vm-*` /
  `ct-*` (tree snapshots get their name index at commit);
- after a successful `file_index {source, time}` (VM/CT disks of groups with `index_files`).

It decodes the name indexes of the snapshot and of the previous local snapshot of the source and counts added,
changed (size or mtime) and deleted entries; directories are ignored. Result:

```json
{"indexed": true, "base": 1791842400, "files": 2906, "added": 424, "changed": 3, "deleted": 412,
 "new_ext": 424, "new_exts": ["lockbit3", "txt"], "notes": ["Users/HOW_TO_DECRYPT.txt"], "notes_total": 12}
```

`indexed: false` when there is no previous snapshot or one index is missing. The counts go into
`backup_stats.files_added/_changed/_deleted` (v26). When the `anomaly` setting is enabled, a finding raises the
`anomaly` alert (`anomaly:<tenant>/<source>`, critical, message `file-level anomaly on …`) and flags the snapshot:

- **ransom notes**: an added file whose last path component matches a glob of `changes::RANSOM_NOTES` (built in)
  or the setting's `ransom_notes` (admin-supplied, case-insensitive, `search::Glob`);
- **mass rename**: deleted ≥ 50, deleted ≥ 10 % of the previous snapshot's files, and added files with an extension
  the previous snapshot did not have ≥ 50 % of the deleted ones.

Setting `anomaly` gains `ransom_notes: [glob]` (≤ 100 patterns of 1..=100 characters, no `/`). Adding patterns
applies at once; removing one is a weakening and goes through approval (`settings.anomaly`), like switching
detection off.

## Snapshot diff

`POST /snapshots/diff {tenant, source, time, base?, change?, offset?, limit?}` (202 `{id}`) queues
`snapshot_diff`; roles = file search (admin, operator, tenant_admin, tenant_user; own tenant), both snapshots must be
local, `base < time` (default: the previous snapshot), `change` ∈ added/changed/deleted, `limit` 1..=1000
(default 200). Audited `snapshot.diff`. The result (`GET /jobs/{id}`):

```json
{"indexed": true, "base": 1, "time": 3, "added": 101, "changed": 0, "deleted": 101, "total": 101, "offset": 0,
 "limit": 200, "entries": [{"path": "docs/f000.docx", "change": "deleted", "kind": "file", "size": 10,
 "mtime": 1, "old_size": 10, "old_mtime": 1}]}
```

Sorted by path; one page per job (a second page re-reads both indexes, which costs about the same as one search
over two snapshots). Only names, sizes and times; never contents.

## Trends

`GET /stats/trends?tenant=` (any role, tenant-scoped; also for `read` API tokens): per `(tenant, source)` the last
30 `backup_stats` rows, oldest first, `{time, new_plain, new_stored, files_changed, anomalous, read, secs}` with
`files_changed` = added + changed + deleted (null without a name index) and `secs` = the backup's duration (null
from connectors before Phase 30), plus the source's `sensitivity`. Shown on **Sources** as sparklines.

## Duration and dedup rate (Phase 30)

Two more signals next to the change rate (`scheduler/src/anomaly.rs`), with the same median-of-history model over
the source's last `history` runs (setting `anomaly`) and at least 5 earlier runs:

- **Dedup rate**: the share of the data read that did not deduplicate, `new_plain / read` (capped at 100 %). A
  finding when it is above max(factor x its median, floor) and at least `floor_bytes / 4` were read. Critical. An
  agent that rewrites the same files every night usually adds a few percent of what it reads; after encryption
  everything it reads is new. A VM whose dirty regions are always new (median near 100 %) cannot pass the floor, so
  the rule stays quiet there and the change-rate rule watches it.
- **Duration**: `secs` above max(factor x the median duration, median + margin). Alone a **warning** (slow storage or
  a busy network look the same); together with another finding the alert is critical. Runs without a duration
  (older connectors) do not count; the rule needs 5 runs with one.

The doc's proposal said "new-chunk ratio (unique / logical)"; unique / logical is the change rate divided by the
size and adds nothing to the volume rule, so the dedup rate is measured against the data **read**. For agents
`read` is now what the agent read from its disks (changed files) instead of the chunk bytes it sent, which were
already only the part the appliance did not have (docs/storage-accounting.md).

**Sensitivity per source** (`anomaly_sensitivity`, catalog v45; no row = `medium`) instead of raw thresholds:

| level | change rate (x the setting's `factor`) | dedup rate | duration |
|---|---|---|---|
| low | 1.5 (4.5 with the default 3) | 4 x median, at least 90 % | 4 x median, at least median + 30 min |
| medium | 1 (3) | 3 x median, at least 75 % | 3 x median, at least median + 15 min |
| high | 2/3 (2, never below 1.5) | 2 x median, at least 50 % | 2 x median, at least median + 5 min |

`PUT /stats/sensitivity {tenant, source, level}`: admins, security officers and tenant admins (own tenant). Raising
applies at once (audited `anomaly.sensitivity`); lowering weakens a ransomware signal and goes through the approval
gate (`anomaly.sensitivity`, executed by the web-api, refused when the level changed since the request or while the
tenant is locked down; it counts as a weakening request for the risk signals). The configuration freeze of incident
mode refuses both.

One alert per run under the existing key `anomaly:<tenant>/<source>` (kind `anomaly`): the prefix names the first
finding (`change-rate anomaly`, `dedup-rate anomaly`, `backup-duration anomaly`), the level when it is not medium, then
every finding, e.g. `dedup-rate anomaly on acme/host-a1 (sensitivity high): snapshot 1791580000: 60 % of the 1.5 GiB
read did not deduplicate (usually 5 %, limit 50 %); last snapshot before: host-a1/1791493600`. Every finding flags
the snapshot like the change-rate rule (so a production restore of it needs `restore.infected`, Phase 29).

## Not in this step

Secure restore (docs/veeam-comparison.md row 8) is the opt-in YARA scan of Phase 21e (docs/malware-scan.md); its
matches set the same flag. Thresholds of the mass-rename rule are constants. The file browser and the file
search do not warn about flagged snapshots.
