# Database log chains: SQL Server, Oracle, log schedules (design, Phase 42: #41, #42, #43)

Status: accepted (2026-11-01, plan.md §2: the options below as proposed), before any code. Written without a SQL Server or Oracle installation: both need a
licence decision by the maintainer (SQL Server Developer edition, Oracle Database Free) before the lab. The plan's rule
for Phase 42 ("a short design note first") applies.

## What exists

- **PostgreSQL and MySQL/MariaDB plugins** (docs/mysql.md, plugins/postgresql): a server backup is a base backup plus
  the log (WAL / binlog) pulled up to the run; later runs re-reference the base pieces (`Unchanged`) and add only the
  new log, so an "every 15 minutes" policy is cheap. Each snapshot carries its **recoverable range**
  (`SnapshotMeta {"recoverable": {unit, from_time, from_lsn, to_time, to_lsn}}`); the restore dialog bounds its time
  picker by it; a new base every `full_every_days`, after a failover, or when the log the next pull needs is gone.
- **SQL Server through the Windows agent** (docs/agent-windows.md): VSS copy-only snapshots of the data files,
  application consistent, never truncating the log; the documented way to a log chain is native `BACKUP LOG` jobs
  whose files the agent backs up.
- **Oracle**: nothing.

## #43: log runs on their own schedule

- **A second schedule per group**, `log_schedule` (for example `every 15m`), next to the policy's snapshot schedule,
  only for source kinds that declare log support (manifest `backup.logs: true`; agents: the `mssql` / `oracle` modes
  below). A due log run is a normal backup job with `mode: "log"`; the policy's schedule gives `mode: "full"` (base or
  differential, the connector decides as today).
- **Each log run is a snapshot** that references the newest base (and differential) and adds the new log pieces, as
  PostgreSQL and MySQL runs do now. Every snapshot is therefore restorable on its own; deleting an older snapshot never
  breaks a later one (chunks are shared, not chained).
- **Retention**: log snapshots are kept by a `recent` class (`keep all of the last N hours`, default 48 h, the
  `Gfs.recent` field of Phase 18b, crates/retention); after that the normal GFS thins them like any snapshot. The
  recoverable ranges of the kept snapshots are shown as one timeline per database (gaps marked).
- **Overlap**: a log run never runs while a full run of the same source does (plan key per source); a log run that
  finds no base yet runs as full.
- **Alerts**: `log_lag` (warning) when the last good log run is older than three log intervals; a broken chain (the
  connector reports it: another tool took a log backup, a failover, a gap) raises `log_chain` (critical) and makes the
  next run a base.

**Implemented (#43, PostgreSQL 1.6.0 and MySQL 1.4.0):** catalog `groups.log_schedule` (SCHEMA_V52), `PUT
/groups/{id}/log-schedule` (crates/web-api/src/logschedule.rs, only for kinds whose manifest says `backup.logs`), the
scheduler's queueing (`mode` `full` / `log`, one run of a group at a time, the policy slot first) and `log_lag`. A
`log` run makes the plugins skip the age-based new base (`full_every_days`); `full` keeps today's behaviour, so the
connector still decides between base and incremental. `log_chain` (critical): the plugins put `chain_break` into the new
base snapshot's meta, the scheduler raises it, the next snapshot that continues the chain resolves it. The point-in-time restore dialog shows the recoverable ranges of all snapshots of the database as one timeline
(merged spans, gaps marked) and switches to the snapshot that covers a picked time. Retention uses the existing
`recent` class.

## #41: SQL Server log chain and point-in-time restore

**Changed 2026-11-02 (maintainer):** a sources plugin over SSH like Oracle (plugin `mssql`, plugins/mssql/README.md)
instead of a mode of the Windows agent, and SQL Server on Linux (installed or in Docker / Podman) as well. Reason:
agent sources have none of the plugins' log machinery (log schedules, `log_chain`, the recoverable range in the
restore dialog, its server-side check, restore tests); the plugin gets all of it unchanged. First step: SQL Server
writes into a staging folder (as for Oracle); VDI streaming without staging is a later step. The original proposal,
kept for reference:

- **Where**: a mode `mssql` of the Windows agent on each SQL Server host (the agent is there for VSS anyway). No
  connector on the appliance, no SQL credentials leave the host.
- **Login**: integrated authentication as the agent service (`NT SERVICE\NexusAgent`), which the administrator adds
  as a SQL login with `db_backupoperator` in each database plus `VIEW SERVER STATE` (a setup script in the manual);
  SQL logins only for instances without Windows authentication. The T-SQL connection is TDS over shared memory or
  local TCP (proposed: the `tiberius` crate, pure Rust, MIT/Apache, with SSPI; ODBC would need a driver install).
- **Streaming**: SQL Server's Virtual Device Interface (VDI, `sqlvdi.dll`, COM, part of every edition): the agent
  creates a virtual device set, issues `BACKUP DATABASE … TO VIRTUAL_DEVICE = 'nexus-<guid>'` (full or
  `WITH DIFFERENTIAL`) or `BACKUP LOG …`, and reads the stream from the device straight into the agent protocol (an
  application stream like the plugins' `Stream`, chunked and deduplicated on the appliance; repeated fulls of mostly
  unchanged databases deduplicate well). No staging on the host's disks.
- **Chain**: from `msdb.dbo.backupset` after each backup: `first_lsn`, `last_lsn`, `database_backup_lsn`,
  `differential_base_lsn`, recorded in the snapshot meta. Before a log run the agent checks that the newest log backup
  in msdb is its own; a foreign one (another tool, a native job) breaks the chain: `log_chain` alert, next run full.
  Databases in the SIMPLE model get full/differential only (their recoverable range is the snapshot time); the agent
  reports the recovery model per database.
- **Who owns the chain**: the appliance does when the group has a log schedule (its fulls are then normal, not
  `COPY_ONLY`, and its log backups truncate the log). Without a log schedule the agent keeps today's VSS copy-only
  path. The manual says to stop native log jobs before switching.
- **Always On availability groups**: the agent on every replica; the appliance asks each for its role and
  `sys.fn_hadr_backup_is_preferred_replica`; backups run on the preferred one (on a secondary: `COPY_ONLY` full, log
  backups allowed); the chain is per database across replicas (LSNs, not hosts).
- **Restore**: `RESTORE DATABASE … FROM VIRTUAL_DEVICE … WITH NORECOVERY`, then the differential and the log backups up
  to the target time `WITH STOPAT`, then `RECOVERY`, into the same instance (new database name, or overwrite with
  approval) or another instance with an agent; the target time is bounded by the recoverable range. Also: download of
  the backups as `.bak` / `.trn` files for a manual restore anywhere.
- **Lab**: SQL Server 2022 Developer edition on a lab Windows VM (licence: maintainer), databases in FULL model,
  a load generator; full, log runs every few minutes, a foreign log backup (chain alert), point-in-time restore to a
  second name, compared row counts; then a two-replica availability group.

## #42: Oracle through RMAN

- **Where** (changed 2026-11-02, maintainer: "oracle rman sources plugin"): a plugin `oracle` that logs in to the
  database host over SSH as the Oracle software owner and runs `rman target /` there (OS authentication), instead of
  a mode of the Linux agent. The plugin path already has the log schedule (#43), the recoverable range and the
  restore dialog; no agent is needed on the database host. The staging directory, levels and chain below are the
  same. Implementation: plugins/oracle/README.md.
- **First step: RMAN to a staging directory** (`/var/lib/nexus-agent/rman/<sid>`), which the agent then streams to the
  appliance and empties: level 0 (base) and level 1 (with block change tracking) incremental backups, archived logs
  `BACKUP ARCHIVELOG … DELETE INPUT` for log runs, control file and spfile autobackup. No vendor library, standard
  RMAN only; the cost is staging space of one backup set.
- **Later, if staging space is a problem: an SBT media management library** (a shared library RMAN loads with
  `SBT_LIBRARY=`, implemented in Rust, streaming to the local agent over a Unix socket). Not first: the SBT
  interface is large and its documentation is not public in full; the staging path gives the same backups.
- **Chain and range**: SCNs and times from RMAN's catalog views (`V$BACKUP_SET`, `V$ARCHIVED_LOG`) into the snapshot
  meta; a missing archived log (deleted outside RMAN) breaks the chain: `log_chain`, next run level 0.
- **Restore**: pieces back into staging, then `RESTORE` / `RECOVER … UNTIL TIME`, into the same host or a new
  host with the same Oracle version (duplicate database); download of the pieces for a DBA.
- **Lab**: Oracle Database Free on a lab Linux VM (licence: maintainer), archivelog mode, level 0/1 and log runs,
  point-in-time restore, a deleted archived log (chain alert).

## Order

1. #43 for the existing PostgreSQL and MySQL plugins (scheduler, retention class, timeline view, alerts): no new
   database, testable in the existing testbox suites.
2. #41 SQL Server (plugin `mssql` over SSH, Windows and Linux / Docker, staging), after the licence decision.
3. #42 Oracle (plugin `oracle`, RMAN over SSH, staging), after the licence decision.

## Open questions

- `tiberius` with SSPI against VDI's requirement that the T-SQL session and the device set run on the same host (it
  does: the agent is local); whether VDI needs the agent to run as a sysadmin-equivalent (Microsoft documents
  sysadmin or `db_backupoperator` plus `CREATE DATABASE` for restores).
- Transparent data encryption (SQL Server TDE, Oracle TDE): backups stay encrypted with the database's keys; the
  restore target needs the certificate / wallet. Out of scope for the first version; documented.
