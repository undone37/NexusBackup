# PostgreSQL plugin (reference plugin, M9)

Backs up PostgreSQL 14 or newer (tested: 14, 17, 18) through the plugin SDK. Source kind `plugin:postgresql`.

| Group selects | Snapshot (`plugin-postgresql-<source>[-<db>]`) | Restores |
|---|---|---|
| databases | one logical dump per database: stream `<db>.sql` | `to_target`: into a new (or existing) database on the source or the alternate server; `download` |
| nothing (whole source) | the cluster: `data/` (base backup), `wal/` (all WAL since it) | `pitr`: new data directory on the restore host via SSH, recovered to a point in time; `download` |

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
  `full_every_days` (default 7), on a timeline/system change, or when the slot lost WAL.
- **Point-in-time restore**: unpacks `data/` into a new directory on the restore host over SSH (`tar -x`, host key
  pinned), the WAL into `<dir>/nexus_wal/`, and appends `restore_command`, `recovery_target_time` (or end of WAL),
  `recovery_target_action = 'promote'`, `archive_mode = 'off'` (and `port`) to `postgresql.auto.conf` +
  `recovery.signal`. Start a PostgreSQL of the same major version on it (`pg_ctl -D <dir> start`).

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

## Limits (v1)
Point-in-time restore of clusters with additional tablespaces (use the download); recovery targets other than time;
restore to a running server; the restored server's version must be the source's major version.

## Tests
`cargo test -p postgresql` — unit tests, and with podman the integration test (`tests/pg.rs`) against
`testbox/run.sh` (PostgreSQL `$PG`, default 17, + sshd + an alternate server, rootless): validate, guests, dump →
restore to the source and the alternate server compared with `pg_dump`, cluster full + incrementals → PITR to a
time and to the end, started and queried. `PG=14 cargo test -p postgresql --test pg` for another version;
`NEXUS_PG_TESTBOX=skip` skips it.

## Packaging
Build against glibc ≤ 2.39 (e.g. in an AlmaLinux 10 container, like the image's builder stage) or statically for
`x86_64-unknown-linux-musl` (needs a musl C toolchain for `ring`), then `nexus-plugin pack manifest.json <binary>
postgresql-1.0.0.nxplugin` and sign it (docs/plugin-sdk.md, lab/appliance/plugins.sh).
