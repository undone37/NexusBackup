# PostgreSQL plugin (reference plugin, M9)

Backs up PostgreSQL 14 or newer (tested: 14, 17, 18) through the plugin SDK. Source kind `plugin:postgresql`.

| Group selects | Snapshot (`plugin-postgresql-<source>[-<db>]`) | Restores |
|---|---|---|
| databases | one logical dump per database: stream `<db>.sql` | `to_target`: into a new (or existing) database on the source or the alternate server; `download` |
| nothing (whole source) | the cluster: `data/` (base backup), `tablespaces/<oid>/`, `wal/` (all WAL since it); snapshot metadata: the recoverable range | `pitr`: new data directory on the restore host via SSH, recovered to a time, an LSN or a restore point, optionally started; `download` |

## How (and why this way)
The plugin sandbox can only execute what the appliance image ships, and `pg_dump`/`pg_basebackup` would have to
match every server's major version. So everything speaks the PostgreSQL wire protocol in Rust (`src/pg.rs`: TLS via
rustls, SCRAM-SHA-256/md5/password; no new crates, all were already in the workspace):
- **Logical dump** (`src/dump.rs`): generated from the catalogs in one `REPEATABLE READ, READ ONLY` transaction
  (consistent), tables locked `ACCESS SHARE`, data via `COPY`. The format is a plain SQL script (`psql -1 -f` works
  on a download) with length-prefixed statement markers, so the restore needs no SQL parser. Covered: schemas,
  extensions, enum/domain/composite types, functions/procedures, sequences, tables (identity, generated columns,
  collations, partitioning, unlogged), views (dependency order), materialized views, data, constraints, indexes,
  triggers. **Not covered** (a warning names them when present): owners/grants, comments, RLS policies,
  aggregates, operators, range types, rules, foreign tables, table inheritance, large objects, publications, event
  triggers, statistics objects, roles (cluster globals). Use a cluster backup where these matter.
- **Cluster backup** (`src/physical.rs`): `BASE_BACKUP` (fast checkpoint, WAL included, manifest) streamed tar
  entry by tar entry as snapshot files, plus a physical replication slot (`slot`, default `nexusbackup`) that keeps
  WAL on the server between backups. Later backups re-reference `data/` (`Unchanged`, the host reuses the stored
  chunks) and stream only the new WAL (`START_REPLICATION` from the previous end, segment files, the last one
  zero-padded). Every snapshot is self-contained (base + WAL to its time). A new base backup is taken every
  `full_every_days` (default 7), on a timeline/system change (failover), or when the slot lost WAL.
- **WAL-only frequent runs** (1.2.0): an incremental run on an unchanged base sends no data file, only the WAL
  since the previous run (the partial last segment again, ≤ 16 MiB plus what was written), so `every 15m`
  schedules are cheap; the policy's `recent` class keeps them all for N hours. Each run first commits a marker
  transaction (`SELECT pg_current_xact_id()` on a normal connection to `postgres`) and waits until it is flushed:
  its commit record carries a timestamp, so every time up to the run is reachable by `recovery_target_time` even on
  an idle server (recovery ends with FATAL when no commit after the target is in the WAL). On a standby or without
  SQL access the run warns and uses the server's/appliance's clock.
- **Recoverable range** (snapshot metadata, protocol v1.8 `SnapshotMeta`): `{"recoverable": {from_time, from_lsn,
  to_time, to_lsn, timeline}}` = first full second after the base backup's end (its end LSN) → the marker's time
  (the streamed WAL end). A full snapshot recovers to the end of its base backup only (from = to). The appliance
  stores it in `snapshots.meta`; the restore dialog shows it and bounds its time picker.
- **Point-in-time restore** (`src/pitr.rs`): unpacks `data/` into a new directory on the restore host over SSH
  (`tar -x`, host key pinned), the WAL into `<dir>/nexus_wal/`, each tablespace into the directory given for it
  (`tablespaces`: `<oid or old path>=<new path>`, every tablespace needs one; `tablespace_map` is rewritten, so
  PostgreSQL creates the `pg_tblspc` links), and appends `restore_command`, one target (`recovery_target_time`,
  `recovery_target_lsn` or `recovery_target_name`; none = end of WAL), `recovery_target_action = 'promote'`,
  `archive_mode = 'off'` (and `port`) to `postgresql.auto.conf` + `recovery.signal`. A source that keeps its
  configuration outside the data directory (Debian) gets an empty `postgresql.conf` and a `pg_hba.conf` with
  `local all all peer`. With `start`, `pg_ctl -D <dir> -l <dir>/nexus_restore.log -w -t 600 start` runs over SSH
  (`ssh_pg_ctl`, else `/usr/lib/postgresql/<PG_VERSION>/bin`, `/usr/pgsql-<PG_VERSION>/bin`, else `PATH`); a
  failed start returns the end of the log. Otherwise start a PostgreSQL of the same major version on it.
- **High availability** (`src/ha.rs`): `host` plus `hosts` (`host` or `host:port`, firewall/Landlock via the
  v1.8 endpoint host list). With more than one server every operation first asks each `SELECT
  pg_is_in_recovery()` and uses the first primary in the configured order (two primaries: the first, with a
  warning); the job log lists every server as primary/standby/unreachable, and `validate` fails on `hosts` when
  there is none. Dumps, dump restores to the source and cluster backups all go to the primary; after a failover
  the timeline changed, so the next cluster backup is a new base backup that creates the slot on the new
  primary. **Following a switchover or failover** (1.3.1): when the new primary still has the slot with the WAL
  from the last backup's end, the next run streams the old timeline up to its switch point, stores the newer
  timelines' history files in `wal/` and continues on the new timeline, without a new base backup, so every time
  across the failover stays restorable. A physical slot exists only on the primary unless a cluster manager keeps it
  on the standbys: with **Patroni**, declare it as a permanent slot (`patronictl edit-config -s
  'slots.nexusbackup.type=physical'`; Patroni creates it on every node and advances it on the standbys). Without
  that (or before PostgreSQL 15, where the slot cannot be checked first), the run after a failover is a new base
  backup on the new timeline and the WAL between the last backup and the failover is lost: times in that window
  cannot be restored (lab 2026-10-23). The slot on the old primary stays when it rejoins without Patroni; drop it.
- **Recovery minimums** (1.2.1): every cluster backup stores the source's `max_connections`,
  `max_worker_processes`, `max_wal_senders`, `max_prepared_transactions` and `max_locks_per_transaction` in
  `settings.conf`; the point-in-time restore writes them into `postgresql.auto.conf`. PostgreSQL aborts recovery when
  they are lower than on the primary, which happened with a source that keeps its configuration outside the data
  directory (Debian, Patroni with `max_connections = 1000`). Snapshots from 1.2.0 lack the file: set the values in
  the restored `postgresql.auto.conf` by hand if the start fails with "insufficient parameter settings".

## Server setup
```sql
CREATE ROLE nexus LOGIN REPLICATION PASSWORD '…';
GRANT pg_read_all_data TO nexus;     -- logical dumps
ALTER ROLE nexus CREATEDB;           -- only for dump restores to the source server
```
`pg_hba.conf` needs the role for its databases **and** for `replication`; `wal_level` ≥ `replica`, one free
`max_wal_senders`/`max_replication_slots`. Mind the slot: if backups stop, it retains WAL — drop it
(`SELECT pg_drop_replication_slot('nexusbackup')`) when the source is removed, or set `max_slot_wal_keep_size`.
The alternate restore server's user needs `CREATEDB`; the SSH user on the restore host owns the new data directory
(usually `postgres`; unencrypted OpenSSH key, the host key as a known_hosts line).

## Limits
Restore into a running server; the restored server's version must be the source's major version; the marker
waits at most 30 s for its commit to be flushed (`wal_writer_delay` is far below that); failover slots (PostgreSQL 17 `failover = true`) are not used, so the WAL between the last backup on the old
primary and the failover is only in the next base backup if the new primary still has it.

## Tests
`cargo test -p postgresql` — unit tests, and with podman the integration test (`tests/pg.rs`) against
`testbox/run.sh` (PostgreSQL `$PG`, default 17, + sshd + an alternate server, rootless): validate, guests, dump →
restore to the source and the alternate server compared with `pg_dump`, cluster full + incrementals (incl. an idle
WAL-only run) → PITR to a time, to the end of the recoverable range and to the end, started and queried; recovery to
an LSN and to a restore point with a tablespace moved (by oid and by old path) and the server started by the
plugin; HA: a streaming replica started inside the main container (`pg_basebackup -R`, port 5433 published as
`$REPLICA_PORT`), the configured host a standby → the primary is used, then the replica promoted and the old
primary unreachable → a full backup from the new primary on timeline 2. `PG=14 cargo test -p postgresql --test pg`
for another version; `NAME=… PORT=… ALT_PORT=… SSH_PORT=… REPLICA_PORT=…` run a second testbox next to one in use;
`NEXUS_PG_TESTBOX=skip` skips it. Unit tests cover primary selection with a fake cluster (`ha.rs`), recovery
targets, tablespace remapping and the start command (`pitr.rs`).

## Packaging
Build against glibc ≤ 2.39 (e.g. in an AlmaLinux 10 container, like the image's builder stage) or statically for
`x86_64-unknown-linux-musl` (needs a musl C toolchain for `ring`), then `nexus-plugin pack manifest.json <binary>
postgresql-1.3.1.nxplugin` and sign it (docs/plugin-sdk.md, lab/appliance/plugins.sh).
