# Oracle Database plugin (#42)

Backs up an Oracle Database (single instance, CDB with its PDBs or non-CDB) with RMAN, run over SSH on the database
host. Source kind `plugin:oracle`. Design: [docs/database-logs-design.md](../../docs/database-logs-design.md) "#42".

| Group | Snapshot (`plugin-oracle-<source>`) | Restores |
|---|---|---|
| the whole database (no guests) | `rman/<run>_<type>_<%U>` RMAN backup pieces + `rman/nexus.json`; metadata: the recoverable range (SCN and time) | `pitr`: on the database host, to a time, an SCN or the end of the snapshot; `download` of the pieces |

## How
- The appliance logs in as the Oracle software owner (`user`, default `oracle`) with a pinned host key and runs
  `rman target /` and `sqlplus / as sysdba` (OS authentication: no database password on the appliance).
  `ORACLE_HOME` from the config or the SID's line in `/etc/oratab`.
- RMAN writes into the **staging directory** (`<staging>/<SID>`, default `/opt/oracle/nexus-rman/<SID>`); the plugin
  streams each piece into the snapshot and deletes it. The pieces' records stay in the control file (a level 1
  needs its level 0 there as the parent; RMAN on the host lists them as available although the files are gone:
  `crosscheck backup` marks them expired, which makes the next policy run a level 0). Staging needs room for one run (a level 0 = the used data file blocks).
- **Levels:** level 0 for the first run, every `full_every_days` (default 7), after a RESETLOGS (new incarnation),
  on another DBID and when an archived log the chain needs is gone; policy runs in between are level 1 (enable block
  change tracking so they read only changed blocks); **log runs** (the group's log schedule, #43) back up only the
  archived logs. Every run switches the log (`alter system archive log current`) and backs up the archived logs
  since the last run (by sequence), the control file and the spfile.
- **Self-contained snapshots:** each one re-references the level 0, the level 1s and all archived logs since it
  (`Unchanged`, no data sent again) plus its own pieces and the newest control file: a restore needs one snapshot.
- **Chain check:** before a run, `crosscheck archivelog all` and `v$archived_log` from the first sequence not yet
  backed up; a missing or deleted log makes the run a level 0 and puts `chain_break` into the snapshot metadata
  (the appliance raises the `log_chain` alert).
- **Recoverable range** (`{"recoverable": {from_time, from_lsn, to_time, to_lsn, unit: "scn"}}`): from the end of
  the level 0's data file backup to the moment right before the run's log switch.
- `delete_archived_logs` (default off): `DELETE INPUT` on the archived log backups. Leave it off when another tool
  or a standby needs the logs.

## Point-in-time restore
Replaces the running database on the source host (the params must repeat the SID, `confirm`): the pieces go into
`<staging>/restore-<time>`, then `startup force nomount`, `restore controlfile from` the snapshot's control file
piece, `mount`, `crosscheck backup`, `catalog start with` the directory, `set until time | scn`, `restore database`,
`recover database`, `alter database open resetlogs`, PDBs opened. A target time is converted to the host's local
time (RMAN reads it so). The next backup is a level 0 of the new incarnation.

## Host setup
```sql
-- as sysdba, once
SHUTDOWN IMMEDIATE; STARTUP MOUNT; ALTER DATABASE ARCHIVELOG; ALTER DATABASE OPEN;
ALTER DATABASE ENABLE BLOCK CHANGE TRACKING;        -- level 1 reads only changed blocks
```
The appliance's public key in `~oracle/.ssh/authorized_keys`, the host key (`/etc/ssh/ssh_host_ed25519_key.pub`)
in the source's `ssh_host_key`.

## Limits
- Restores go to the source host only (same SID and paths); a restore to another host (duplicate) and restore tests
  are not implemented yet.
- RAC: the archived log chain is tracked per thread, but only single instances were tested.
- Transparent data encryption: the pieces stay encrypted with the database's keys; a restore needs the wallet.
- One run's pieces must fit into the staging directory.

## Tests
`cargo test -p oracle`: level decisions, the archived log chain check, the configuration. The lab:
`lab/pvehost/oracle.sh` (Oracle AI Database Free 26ai on AlmaLinux 9) and state.md.
