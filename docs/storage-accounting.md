# Storage accounting, soft quotas and the change-rate anomaly alert

Phase 13d/e. User-facing description: manual chapters 03 (Storage page) and 11 (`anomaly`, `quota` alerts).

## Data path

1. **chunkstore** counts, per `Store` handle, the chunks it adds (`Store::written()` → `Written {chunks, plain,
   stored}`): `plain` = plaintext bytes of new chunks, `stored` = their sealed size (zstd level 3 if smaller, then
   XChaCha20-Poly1305 + header; exactly the bytes written to `chunks/`). Existing chunks (dedup hits) and
   `insert_chunk_raw` (offsite restore, DR) do not count. `FileStats` carries the same per file (`new_bytes` = plain,
   `new_stored` = sealed).
2. Each connector backs up one snapshot at a time per process, so `written()` after − before a snapshot is that
   snapshot's new data. After every commit it prints one line (`Store::stats_line`):

   ```text
   nexus-stats {"source":"vm-100","time":1791580000,"read":…,"logical":…,"new_chunks":…,"new_plain":…,"new_stored":…}
   ```

   `logical` = sum of the snapshot's index sizes (same as `snapshots.size`), `read` = bytes read from the source:
   | connector | `read` |
   |---|---|
   | nexus-pve, VM | bytes read over NBD (dirty extents for incrementals, everything for a full) |
   | nexus-pve, CT | size of the tar stream |
   | nexus-agentctl | chunk bytes transferred by the agent |
   | nexus-nas | bytes of files read (changed files) |
   | nexus-truenas | bytes received over SSH (diff + walk + content), per dataset snapshot |
   | nexus-pluginhost | bytes received from the plugin, per guest snapshot |
3. The scheduler parses the lines of a finished `backup` / `plugin_backup` job into `backup_stats` (catalog v11,
   upsert per `(tenant, source, time)`; `stats.rs`), then runs the anomaly check on each row (`anomaly.rs`).

## Figures (`GET /storage`, dashboard)

Sums over `backup_stats` rows whose snapshot is still kept locally (`snapshots.local = 1`):

| Figure | Definition |
|---|---|
| Logical | Σ logical |
| Data in | Σ new_plain |
| Stored | Σ new_stored |
| Saved | Logical − Stored |
| dedup | Logical / Data in |
| compression | Data in / Stored |
| reduction | Logical / Stored |

Per tenant and per protection group: a snapshot source maps to the first group (lowest id) of its tenant whose
source and guest list cover it (the scheduler's `group_sources` / `group_prefixes` rules; empty guest lists cover the
whole source for TrueNAS and plugins); everything else lands in the ungrouped bucket (`group_id: null`). Growth 7 /
30 / 90 days = latest `capacity_samples.used` − the newest sample at least N days older (null without one; samples
older than 120 days are not read). The dashboard's `capacity.dedup` / `capacity.compression` use the same sums;
`capacity.reduction` stays logical ÷ measured store size.

**Approximation.** A chunk is attributed to the snapshot that wrote it first. When that snapshot expires, its bytes
leave the sums although later snapshots may still reference them, so Stored is a lower bound of the real store size
(the authority is `capacity_samples.used`, a directory walk) and the ratios lean high for long-lived data. Snapshots
without stats (taken before v11, replicated from a primary, imported) are not in the sums; the response reports
`totals.snapshots` (covered) and `totals.snapshots_all`. An exact per-group figure would need a chunk → snapshots
reference count per GC mark phase; not worth it for a dashboard.

## Soft quotas

`tenants.quota_bytes` (NULL = none), set by an admin with `PUT /tenants/{name}/quota` (direct, audited
`tenant.quota`: it cannot weaken protection). At every full refresh, after the daily capacity sample, the scheduler
compares the tenant's latest `capacity_samples.used` with the quota: `quota` alert, warning at ≥ 80 %, critical at
≥ 100 %, deduplicated while unacknowledged by the message prefix. Backups are never blocked or slowed: a quota
that stops backups would turn a billing problem into data loss.

## Change-rate anomaly alert

Setting `anomaly` `{enabled, factor, history, floor_bytes}`, defaults `{true, 3, 14, 1 GiB}`. For each new stats row,
with H = the source's previous `history` rows (newest first) and at least 5 of them:

- volume: `new_plain > max(factor × median(H.new_plain), floor_bytes)`, or
- entropy: compression of the new data (`new_plain / new_stored`) < 1.05 while the median compression of H > 1.3
  and `new_plain > floor_bytes / 4`.

Either raises a critical `anomaly` alert naming tenant, source, the snapshot time, the numbers and the last kept
snapshot of the source before it (the restore point). Dedup prefix `change-rate anomaly on <tenant>/<source>`.
`PUT /settings/anomaly` applies stricter values directly; disabling it or raising `factor` / `floor_bytes` goes
through the approval gate (`settings.anomaly`, executed by the web-api). Phase 15c adds "hold last good snapshot".
