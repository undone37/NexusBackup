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
30 `backup_stats` rows, oldest first, `{time, new_plain, new_stored, files_changed, anomalous}` with
`files_changed` = added + changed + deleted (null without a name index). Shown on **Sources** as sparklines.

## Not in this step

Secure restore (docs/veeam-comparison.md row 8) needs the opt-in YARA scan of a snapshot in the restore micro-VM,
a separate Phase 21 sub-step. Thresholds of the mass-rename rule are constants. The file browser and the file
search do not warn about flagged snapshots.
