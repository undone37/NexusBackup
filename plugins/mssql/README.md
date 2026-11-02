# SQL Server plugin (#41)

Backs up SQL Server databases on Windows or on Linux (installed, or in a Docker / Podman container) over SSH. Source
kind `plugin:mssql`. Design: [docs/database-logs-design.md](../../docs/database-logs-design.md) "#41".

| Group | Snapshot (`plugin-mssql-<source>-<db>`) | Restores |
|---|---|---|
| databases (each its own snapshot) | `mssql/<run>_<full\|diff\|log>_<n>.<bak\|trn>` native backup files + `mssql/nexus.json`; metadata: the recoverable range | `pitr`: into a new database (or over the existing one) on the source instance, to a time or the end; `verify`: restore test; `download` of the `.bak` / `.trn` files |

## How
- **Transport.** The appliance logs in over SSH (pinned host key) and runs T-SQL on the host:
  - **Windows** (`platform: windows`): the OpenSSH server that ships with Windows Server 2019 and later; every run uploads
    `nexus-sql.ps1` (`src/sql.ps1`) into the staging folder and runs batches through it with
    `System.Data.SqlClient`, integrated security as the SSH account (no SQL password on the appliance). Backup
    files come back as raw bytes on PowerShell's stdout; restores upload them over the SFTP subsystem of the same
    OpenSSH server (PowerShell 5.1 cannot read a binary stdin stream over OpenSSH: it stalls after 128 KiB).
  - **Linux** (`platform: linux`): `sqlcmd` with a SQL login (`sql_user`, `sql_password`; the password goes over
    stdin, never onto a command line); with `container` set, `docker exec -i <container>` (or `podman`, optionally
    with `sudo`) runs sqlcmd, `cat` and `rm` inside the container, so the staging folder is a path in the container
    and no volume has to be shared with the host. Microsoft's images ship sqlcmd as
    `/opt/mssql-tools18/bin/sqlcmd` (the default).
- **Staging.** SQL Server writes each backup into the staging folder (as SQL Server sees it: default
  `C:\NexusBackup\staging` / `/var/opt/mssql/nexus-staging`), the plugin streams the file into the snapshot and
  deletes it. Room for one full backup is needed. Backups are `CHECKSUM, NO_COMPRESSION` (uncompressed files
  deduplicate across fulls on the appliance).
- **Runs.** The first run and every `full_every_days` (default 7) a full; policy runs in between a differential; log
  runs (the group's log schedule, #43) a log backup. In the FULL / BULK_LOGGED model every policy run also backs up
  the log. SIMPLE: full and differential only, the range is the newest of them; log runs do nothing.
- **Self-contained snapshots.** Each holds the newest full, its differentials and all log backups since it
  (`Unchanged`, nothing sent twice), plus `nexus.json` with the `msdb.dbo.backupset` facts per file (LSNs, times,
  the full's file list).
- **The plugin owns the log chain.** Its fulls and log backups are normal (not `COPY_ONLY`). Before each run it checks
  `sys.database_recovery_status.last_log_backup_lsn` against its own last log backup: a log backup by another tool or
  a native job, or a broken log chain (SIMPLE and back), makes the run a full with `chain_break` in the snapshot
  metadata (the `log_chain` alert). A full by another tool moves the differential base: the next run is a full (no
  alert). Stop native log backup jobs and take other fulls `WITH COPY_ONLY`.
- **Recoverable range** (`unit: "lsn"`): from the end of the full to the moment right before the last log backup
  started (everything committed before it is in it). The restore dialog bounds its time picker by it.

## Restores
- **Point in time** (`pitr`): the needed files go into `<staging>/restore-<time>`, then `RESTORE DATABASE` (full,
  `NORECOVERY`, the files moved under the instance's default data and log paths as `<target>_<n>.<ext>` when the name
  differs), the newest differential before the target, the log backups up to the first one that reaches it
  (`STOPAT`, the UTC target converted to the server's local time), `RECOVERY`, `DBCC CHECKDB`. Over an existing
  database only with **Replace** and its name typed again (`SINGLE_USER WITH ROLLBACK IMMEDIATE` first).
- **Restore test** (`verify`): the same into `nexus_verify_<snapshot time>`, `DBCC CHECKDB`, the optional SQL check
  (passes when its first value is true or not zero), dropped again. Scheduled tests pick a random time of the range.
- **Download**: the `.bak` / `.trn` files for a manual `RESTORE` anywhere.

## Host setup
**Windows**: `Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0`, `Start-Service sshd`; an account that
is sysadmin on the instance (a local administrator's key goes into `C:\ProgramData\ssh\administrators_authorized_keys`);
the staging folder writable by the SQL Server service (`icacls C:\NexusBackup /grant "NT SERVICE\MSSQLSERVER:(OI)(CI)M"`).
**Linux / Docker**: an SSH user that may run `docker` (group `docker`, root-equivalent: prefer a dedicated host) and a
sysadmin SQL login. The host key line goes into `ssh_host_key`.

## Limits
- Restores go to the source instance (a new name or Replace); another instance: download the files.
- Availability groups: back up the primary (the plugin does not ask for the preferred replica yet).
- TDE databases: the backups stay encrypted with the database encryption key; a restore elsewhere needs the
  certificate.
- Database names must be `[A-Za-z0-9._-]` (others are listed with a warning and skipped).
- Streaming without staging (VDI) is a later step.

## Tests
`cargo test -p mssql`: run decisions (chain checks, differential base, age, SIMPLE), restore sequences (differential
choice, gaps, bounds), time parsing, configuration. Lab: `lab/windows/mssql.sh` (SQL Server 2022 Developer on Windows
Server 2022) and `lab/pvehost/mssql-docker.sh` (the SQL Server 2022 image on Debian 13 with Docker); results in
state.md.
