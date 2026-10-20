# Open-source backup tools compared with NexusBackup (2026-10-20)

A review of four widely used open-source backup programs and their common front-ends: restic (with Backrest),
BorgBackup (with BorgWarehouse), Duplicati and UrBackup. The other tools are described from their own documentation,
release notes and repositories as of 2026-10-20; none of them was installed or tested for this. "Not confirmed" means
the sources checked did not settle the point. NexusBackup is described only from this repository (README, `manual/`,
`docs/`). NexusBackup is a vibe-coded alpha without external review: it is not for production use. Every tool below
is more mature than it.

## What kind of tools these are

restic and Borg are **backup programs**: a command-line tool that runs on the machine being backed up. It reads
files, deduplicates, compresses and encrypts them on the client and writes them to a repository (a directory, an SSH
server or object storage). They have no scheduler, no web UI and no central view. Front-ends add those: Backrest
(web UI and scheduler around restic), resticprofile and autorestic (configuration files and scheduling for restic),
borgmatic (configuration, scheduling, database dumps and monitoring hooks for Borg), Vorta (desktop GUI for Borg) and
BorgWarehouse (web UI to run the server side, the repositories, of Borg).

Duplicati is a **backup client with its own web UI and scheduler** on each machine. It also has an optional hosted
console from Duplicati Inc. UrBackup is a **client/server system**: one server with a web UI pulls file and image
backups from clients on the LAN or over the Internet.

NexusBackup is an **appliance**: its own OS image with storage, web UI, scheduler, catalog and offsite copy in one
box. It pulls from sources (Proxmox VE, agents, NAS, databases, Microsoft 365) instead of having clients push. Most
differences below follow from that: the appliance holds the keys and the data, the protected hosts do not.

## Versions used

| Tool | Version | Date | Notes |
|---|---|---|---|
| restic | 0.19.1 | 2026-07-05 | repository format v2 (compression) is the default since 0.14 |
| rest-server | 0.14.0 | 2025-05-31 | restic's HTTP repository server (append-only mode) |
| Backrest | 1.14.1 | 2026-07-12 | requires restic 0.19.1 |
| resticprofile / autorestic | 0.33.1 / 1.8.3 | 2026-04-15 / 2024-08-28 | autorestic had no release since August 2024 |
| BorgBackup | 1.4.5 stable, 2.0.0b25 beta | 2026-07-18 / 2026-09-27 | Borg 2 is still beta: "do not use for production" |
| BorgWarehouse | 3.7.0 | 2026-09-20 | Docker image installs Borg from Debian bookworm-backports |
| borgmatic / Vorta | 2.1.10 / 0.11.6 | 2026-10-05 / 2026-09-07 | |
| Duplicati | 2.4.0.1 stable | 2026-10-07 | 2.x has regular stable releases since 2.1 (no longer a permanent beta) |
| UrBackup | server 2.5.38, clients 2.5.32 (Windows), 2.5.31 (Linux), 2.5.30 (macOS) | 2026-08-30 (server) | |
| NexusBackup | main as of 2026-10-20 | | alpha, no release for production use |

## Feature table

| | NexusBackup | restic + Backrest | Borg + BorgWarehouse | Duplicati | UrBackup |
|---|---|---|---|---|---|
| **Architecture / deployment** | appliance OS image (ISO or VM), pulls from sources | client CLI pushes to a repository; Backrest is a per-host web UI and scheduler (Linux, macOS, Windows, FreeBSD, Docker) | client CLI pushes over SSH to `borg serve`; BorgWarehouse is a Docker image running the repository server with a web UI | per-machine client with web UI and scheduler (Windows, Linux, macOS, Docker, Synology); optional hosted console | central server (Windows, Linux, FreeBSD, NAS packages, Docker) pulls from clients |
| **Files (Linux)** | agent with LVM, ZFS or btrfs snapshots | yes | yes | yes | yes (LVM, btrfs, dattobd or device-mapper snapshots) |
| **Windows** | agent: one VSS snapshot set with all writers (copy-only, writer status per job), USN journal, security descriptors, ADS; no image backup yet (Phase 37) | yes, native; VSS with `--use-fs-snapshot` | not officially supported (WSL and Cygwin experimental) | yes; VSS automatic with admin rights | yes; VSS, the main platform |
| **macOS** | no | yes | yes | yes | client yes |
| **VMs / Proxmox VE** | native backup provider plugin, dirty bitmaps, containers too | no native integration (back up dumps or files) | no native integration | no native integration | no native integration (image backup of a guest through its client) |
| **Databases** | PostgreSQL, MySQL/MariaDB plugins (dump and physical with WAL/binlog, point in time) | via `--stdin-from-command` (for example `mysqldump`); Backrest hooks | borgmatic dump hooks: PostgreSQL, MySQL, MariaDB, MongoDB, SQLite and others | not confirmed (release notes mention MSSQL handling, not checked in detail) | not confirmed |
| **NAS** | NFS/SMB shares, TrueNAS over its API | local or mounted paths | local or mounted paths | local paths; remote sources S3, SSH, CIFS, cloud drives | server runs on NAS platforms; NAS shares as sources not confirmed |
| **Microsoft 365** | plugin, never run against a real tenant | no | no | yes, proprietary module (source available, license for production) | no |
| **Image / bare-metal** | Linux bare-metal recovery and P2V from a rescue ISO; whole PVE VMs | no | no | full disk and partition backup on Windows, Linux, macOS, proprietary module | image backups of Windows (NTFS) and Linux (ext, XFS, with limits) clients; bootable restore stick |
| **Deduplication** | content-defined chunks, per tenant across all its sources | content-defined (Rabin, about 1 MiB average), per repository | content-defined (buzhash), per repository | fixed-size blocks, per backup job | file level (hash + hard links), block level for incrementals on btrfs; ZFS dedup if enabled |
| **Encryption** | always on, XChaCha20-Poly1305, per-tenant keys wrapped by a KEK on the appliance | always on, AES-256-CTR + Poly1305-AES, key from password (scrypt) | optional; 1.4 AES-256-CTR + HMAC-SHA256 or BLAKE2b; Borg 2 AES-OCB or ChaCha20-Poly1305 | optional; AES-256 or GPG | Internet mode transport AES-GCM; LAN transport unencrypted; at-rest encryption not documented |
| **Compression** | zstd | zstd (repository v2) | lz4, zstd, zlib (1.4 also lzma) | zip or 7z volumes | VHDZ for images; files not confirmed |
| **Immutability** | retention locks that can only be extended (compliance clock), legal hold, S3 Object Lock offsite | rest-server `--append-only`; Object Lock not supported natively (not confirmed) | 1.4 append-only repositories; Borg 2 drops append-only for `BORG_REPO_PERMISSIONS` (no-delete, write-only); BorgWarehouse sets append-only per repository | remote file locks on S3, Azure, B2, iDrive e2, GCS (governance or compliance) | none built in (relies on the server's file system) |
| **Multi-tenancy** | tenants with separate keys, tenant admins, per-tenant OIDC | rest-server `--private-repos` (one repository per user); Backrest none | one repository and SSH key per client; BorgWarehouse users beyond the admin not confirmed | hosted console: sub-organizations (commercial) | per-client rights for web UI accounts |
| **RBAC / approvals** | roles (admin, operator, security officer, viewer, tenant), quorum approvals for destructive actions | Backrest: login with username and password; no roles documented | BorgWarehouse: local accounts plus OIDC sign-in; roles not documented | web UI password; SSO and delegation only in the commercial console | user accounts with per-client rights (admin, limited); no approvals |
| **Web UI** | yes, one for everything | Backrest | BorgWarehouse (server side); Vorta is a desktop GUI | yes, per machine | yes, central |
| **Scheduling / orchestration** | policies, protection groups, auto-protect, blackout windows, retries, concurrency caps | Backrest: cron schedules, prune/check/forget, hooks; resticprofile and autorestic: config files; experimental multi-host sync in Backrest 1.13+ | borgmatic: config, hooks, scheduling via cron/systemd; BorgWarehouse: monitors, does not schedule clients | built-in scheduler, smart retention, multiple destinations per job | server-side intervals and retention per client or group |
| **Offsite targets** | SFTP, S3 with Object Lock, second appliance (pull replication over mTLS) | local, SFTP, REST server, S3 and compatibles, B2, Azure, GCS, Swift, rclone | 1.4: SSH only; Borg 2 beta: file, SSH/SFTP, rclone, S3/B2 | many: S3, Azure, GCS, B2, SFTP, FTP, WebDAV, SMB, cloud drives, rclone, Duplicati Storage | server is the target; offsite through Internet clients or a copy of the server's storage (for example `zfs send`) |
| **Restore options** | file browser and tar/zip download, restore to a host, full VM/CT restore, instant recovery, instant disk attach, in-place rollback, file search across snapshots | `restore`, `dump` (tar/zip), FUSE `mount` (Linux, macOS, FreeBSD); Backrest browse and download | `extract`, `export-tar`, FUSE `mount` | web UI restore of files and versions; full disk restore; recreate the local database from the destination | web file browse and download, restore to client, image restore via restore stick, VHD mount |
| **Monitoring / alerts** | e-mail, webhooks, syslog, Prometheus, PSA tickets, anomaly alerts | Backrest: Discord, Slack, Shoutrrr, Gotify, Healthchecks, Telegram | borgmatic: Healthchecks, Uptime Kuma, ntfy, Apprise, Zabbix and others; BorgWarehouse: e-mail, Apprise, webhooks, "no recent backup" | e-mail and HTTP reports, live reporting; hosted console alerts (paid tiers) | e-mail reports for failed backups |
| **License** | AGPL-3.0 | restic BSD-2-Clause; Backrest GPL-3.0 | Borg BSD-3-Clause; BorgWarehouse AGPL-3.0 | MIT; M365, Google Workspace and disk image modules proprietary (source available) | AGPL-3.0 |
| **Maturity** | vibe-coded alpha, no support, formats may change | mature, large user base; restic is pre-1.0 by version number but stable format | 1.4 mature; Borg 2 in beta for years | stable releases since 2.1 after a long beta history | mature, small core team |

## restic and Backrest

**What it is.** restic is a single static binary that backs up files into an encrypted, deduplicated repository on
local disk, SFTP, its own REST server, S3 and compatible stores, B2, Azure, GCS, Swift or anything rclone reaches.
Encryption cannot be turned off. Backrest wraps restic in a web UI with cron schedules, retention (`forget`),
`prune` and `check` maintenance, pre/post hooks and notifications; since 1.13 it has experimental multi-host sync.
resticprofile and autorestic do the same from configuration files without a UI.

**Strengths.** Very wide storage backend support; runs natively on Linux, macOS, Windows and BSD; simple to install;
a well-documented, stable repository format; read-only FUSE mount and tar/zip `dump`; large community. rest-server's
append-only mode protects against a compromised client deleting its backups.

**Where NexusBackup differs.** restic is push-based: the client holds the repository password and storage credentials.
NexusBackup pulls; the protected host has no credentials for the backups. NexusBackup adds what restic leaves to the
operator: VM-level Proxmox VE backups with changed blocks, instant recovery, restore tests, a central catalog for many
hosts and tenants, retention locks that no role can shorten and approvals for destructive actions. restic's
repository is per client or shared by clients that trust each other; NexusBackup separates tenants by key.

**Where restic is clearly better.** Maturity and the size of its user base; macOS and BSD support; storage backends
(NexusBackup has SFTP and S3 only); no appliance needed, it fits on any host or container; the format is documented
and readable by independent tools. For file-level backups of a handful of hosts, restic with Backrest is the simpler,
proven choice.

## BorgBackup and BorgWarehouse

**What it is.** Borg is a deduplicating archiver for Linux, macOS and BSD that writes to a local repository or over
SSH to `borg serve`. Borg 1.4 is the stable line. Borg 2 (2.0.0b25 at the time of writing) is still beta with a new,
incompatible repository format on borgstore (file, SSH/SFTP, rclone, S3/B2), AEAD encryption (AES-OCB,
ChaCha20-Poly1305) and repository permissions in place of the 1.x append-only mode. BorgWarehouse is a web UI for the
server side: it creates repositories, system users and restricted SSH keys, sets quotas and append-only, monitors the
time of the last backup and alerts by e-mail, Apprise or webhook. borgmatic adds configuration, retention, database
dump hooks, file system snapshot hooks (ZFS, LVM, btrfs) and monitoring integrations on the client; Vorta is a
desktop GUI for Linux and macOS.

**Strengths.** Efficient compression and dedup, a long track record, a small and auditable design; borgmatic's
database hooks and monitoring integrations cover many setups; BorgWarehouse makes a central repository server for
many clients easy to run, with per-repository quotas and append-only by default. Hosting providers offer Borg
repositories as a service.

**Where NexusBackup differs.** Borg clients push and hold their own key; the server never needs it. NexusBackup's
appliance holds every key (wrapped by a key-encryption key on the appliance, see "What it does not do" in the README),
which allows central restore, search and verification but makes the appliance the high-value target. Borg has no
Windows support, no VM integration and no image backups. BorgWarehouse manages repositories, not backup jobs: it
does not schedule or start client backups.

**Where Borg is clearly better.** Maturity of the 1.4 line; client-side key ownership (a stolen backup server reveals
nothing without the client's key); low resource use; works on a plain Linux server or a hosted Borg service; borgmatic
covers more databases (MongoDB, SQLite and others) than NexusBackup's two plugins.

## Duplicati

**What it is.** A backup client with a built-in web UI and scheduler for Windows, Linux and macOS. It splits files
into fixed-size blocks, packs them into compressed volumes (zip or 7z), encrypts them (AES-256 or GPG) and uploads
them to a large list of backends: S3 and compatibles, Azure, GCS, B2, SFTP, FTP, WebDAV, SMB and consumer cloud
drives. Since 2.1 it has regular stable releases; 2.4.0.1 is the current stable. Recent releases added multiple
destinations per job, remote file locks (S3 Object Lock and equivalents in governance or compliance mode), PAR2
parity files, a sync mode and full disk backup on Windows, Linux and macOS. Microsoft 365, Google Workspace and full
disk backup are proprietary modules (source available, a paid license for production). Duplicati Inc runs a hosted
console with free and paid tiers for monitoring and remote management.

**Strengths.** The widest choice of destinations of the tools here; an easy UI for single machines; object locking
on several cloud stores; Microsoft 365 and Google Workspace backup that has run against real tenants; disk images on
three operating systems.

**Where NexusBackup differs.** Duplicati is configured per machine; a central view comes from the commercial hosted
console. NexusBackup is self-hosted and central by design, with tenants, roles and approvals in the open-source code.
Duplicati dedups per backup job; NexusBackup dedups across all sources of a tenant. Duplicati keeps a local database
per job that must be rebuilt from the destination after a loss; NexusBackup keeps one catalog and backs it up to the
offsite target daily.

**Where Duplicati is clearly better.** Storage backends and desktop platforms (macOS); a tested Microsoft 365
and Google Workspace module (NexusBackup's ran only against a Graph mock); full disk backup on Windows (NexusBackup
has no bare-metal recovery for Windows); a commercial company behind it offering support for paid tiers.

## UrBackup

**What it is.** A client/server system. The server runs on Windows, Linux, FreeBSD, several NAS platforms and Docker
and pulls file and image backups from clients over the LAN or, in Internet mode, over an AES-GCM-encrypted channel.
File backups dedup identical files with hard links (and blocks on btrfs); image backups of Windows NTFS volumes are
the main use case, written as VHD(X), VHDZ or raw images on btrfs, ZFS, ReFS and XFS. Linux image backups exist since
2.5 with dattobd or device-mapper snapshots and are documented for limited layouts (for example cloud instances; LVM,
mdraid and btrfs are not the target). A bootable restore stick restores images and files.

**Strengths.** Mature Windows image backups with bare-metal restore; a central web UI for many clients with per-client
rights; Internet mode for roaming clients without a VPN; low hardware needs and NAS packages.

**Where NexusBackup differs.** Both pull from clients and have a central web UI, so the model is the closest of the
four. UrBackup does not document encryption at rest and sends LAN traffic unencrypted; NexusBackup encrypts every chunk
and talks to its agents over mutual TLS 1.3. UrBackup has no offsite target of its own and no immutability; NexusBackup
copies to SFTP or S3 with Object Lock and has extend-only retention locks. NexusBackup covers Proxmox VE VMs, NAS
shares, TrueNAS and databases; UrBackup covers client machines.

**Where UrBackup is clearly better.** Windows image backup and bare-metal restore (NexusBackup has file-level Windows
backups only); years of production use; runs on existing NAS hardware; macOS client.

## Summary

The four tools are mature and protect files on client machines well; Duplicati and UrBackup also take disk images.
None of them integrates with Proxmox VE at the VM level, enforces approvals for destructive actions or keeps
tenants apart by key. NexusBackup does those things, but as an untested alpha that has run only in a small lab. For
anything that matters today, use one of these tools (or Proxmox Backup Server for PVE) and treat NexusBackup as an
experiment.

## Sources

restic
- https://github.com/restic/restic/releases (0.19.1, 0.19.0 changelog)
- https://restic.readthedocs.io/en/stable/030_preparing_a_new_repo.html (backends, repository versions)
- https://restic.readthedocs.io/en/stable/040_backup.html (VSS, stdin)
- https://restic.readthedocs.io/en/stable/050_restore.html (restore, mount, dump)
- https://restic.readthedocs.io/en/stable/100_references.html (crypto, chunking, compression)
- https://github.com/restic/rest-server (append-only, private repositories)
- https://github.com/garethgeorge/backrest and https://github.com/garethgeorge/backrest/releases (features, 1.13
  multi-host sync, 1.14.1)
- https://github.com/creativeprojects/resticprofile, https://github.com/cupcakearmy/autorestic

BorgBackup
- https://github.com/borgbackup/borg/releases (1.4.5, 2.0.0b25)
- https://borgbackup.readthedocs.io/en/master/changes.html (Borg 2 changes, beta warning)
- https://borgbackup.readthedocs.io/en/stable/usage/notes.html (append-only in 1.4)
- https://borgbackup.readthedocs.io/en/stable/usage/init.html (encryption modes)
- https://borgbackup.readthedocs.io/en/stable/installation.html (platforms, Windows)
- https://github.com/Ravinou/borgwarehouse, https://borgwarehouse.com/docs/ ,
  https://borgwarehouse.com/docs/admin-manual/oauth-oidc/
- https://torsion.org/borgmatic/ , https://github.com/borgbase/vorta

Duplicati
- https://github.com/duplicati/duplicati/releases (2.4.0.1, 2.4.0.0, 2.3.0.x release notes)
- https://github.com/duplicati/duplicati/blob/master/LICENSE and
  https://github.com/duplicati/duplicati/tree/master/proprietary
- https://www.duplicati.com/ (console tiers, backends)
- https://docs.duplicati.com/technical-details/understanding-backup/how-backup-works

UrBackup
- https://github.com/uroni/urbackup_backend/releases (server 2.5.38, clients 2.5.30 to 2.5.32)
- https://www.urbackup.org/features.html , https://www.urbackup.org/download.html
- https://www.urbackup.org/administration_manual.html (Internet mode, rights, dedup, restore; manual for 2.5.x)
- https://blog.urbackup.org/date/2021/06 (Linux image backups in 2.5)

NexusBackup
- [`../README.md`](../README.md), [`../manual/`](../manual), [`../state.md`](../state.md)
