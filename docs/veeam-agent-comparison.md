# Veeam Agent for Windows and Linux compared with the NexusBackup agents

Status: Phase 38a, 2026-10-22. Fixes the scope of 38b-38j (plan.md "Phase 38"). Sources: the Veeam Help Center
user guides for **Veeam Agent for Microsoft Windows 13** (guide pages state build 13.1.1.700; KB2683 lists 13.1.1.700
as of 2026-08-13 and 13.0.4.1341 as of 2026-08-25) and **Veeam Agent for Linux 13** (guide pages state build
13.1.1.4), plus the Veeam Backup & Replication (VBR) 13 user guide for the managed mode and malware detection. The
NexusBackup side was read from docs/agent-linux.md, docs/agent-windows.md, docs/bmr.md, manual chapters 04 (agents,
endpoint and laptops), 06, 16, 17, README.md "What it does not do" and plan.md Phases 27, 37 and 38. Earlier
background: docs/veeam-comparison.md (VBR features), docs/endpoint-ui.md (endpoint UI).

Main Veeam URLs (all with `?ver=13`):

- Windows guide: <https://helpcenter.veeam.com/docs/agentforwindows/userguide/overview.html>
- Linux guide: <https://helpcenter.veeam.com/docs/agentforlinux/userguide/overview.html>
- Windows builds: <https://www.veeam.com/kb2683>
- Linux kernel module support: <https://www.veeam.com/kb2804>

Short names below: **VAW** = Veeam Agent for Microsoft Windows, **VAL** = Veeam Agent for Linux, **Free / WS / Srv**
= the Free, Workstation and Server editions. "Managed" means managed by VBR (or the Veeam Service Provider Console).
Our agents today are **managed only**: the appliance pulls (the agent listens on TCP 7444; a roaming laptop instead
keeps a connection to the edge proxy, which relays the appliance's sessions, docs/edge.md), the appliance
schedules, stores, encrypts, keeps retention and restores. There is no standalone mode yet.

Gap column: **has** = equivalent today; **partial** = exists, but only managed by the appliance, or narrower;
**missing** = nothing comparable. Effort: S (days), M (one to three weeks), L (more). Anything not confirmed in
Veeam's current documentation is marked "(not confirmed)".

## 1. Editions, modes and licensing

Sources: <https://helpcenter.veeam.com/docs/agentforwindows/userguide/license_editions.html>,
<https://helpcenter.veeam.com/docs/agentforlinux/userguide/license_modes.html>,
<https://helpcenter.veeam.com/docs/agentforwindows/userguide/operation_modes.html>.

| Feature | Veeam Agent (edition notes) | NexusBackup agent today | Gap | Effort | Phase 38 item |
|---|---|---|---|---|---|
| Standalone mode (agent schedules and writes itself) | VAW and VAL: all editions; installed and operated by the user | none: the appliance drives every backup | missing | L | 38b |
| Managed mode | VBR or Service Provider Console; VAW "managed by backup server" (job lives on VBR, no local UI) or "managed by agent" (policy pushed, local UI and restores stay) | managed by the appliance (pull model, policies and protection groups on the appliance) | has (pull only) | - | - |
| Policy pushed to a standalone agent, agent keeps running it locally ("managed by agent") | VBR backup policies | none | missing | M | 38i |
| Read-only end-user mode (run backup, view sessions, restore files only) | VAW managed mode option | endpoint UI shows sessions and "request backup now" (rate limited, can be hidden); no restore on the endpoint | partial | S | 38g, 38h |
| Number of jobs | Free: 1; WS: 1 (unlimited to Cloud Connect); Srv: unlimited | unlimited (groups on the appliance) | has | - | - |
| Edition limits (schedules, guest processing, object storage, GFS, CBT driver only in paid editions) | see the rows below | no editions (AGPL): every feature for every host | has | - | out of scope (no licensing by design) |
| License expiry behaviour | VAW: paid options must be disabled or the job fails; VAL: falls back to Free | n/a | - | - | out of scope |

## 2. Backup modes

Sources: <https://helpcenter.veeam.com/docs/agentforwindows/userguide/backup_job_mode.html>,
<https://helpcenter.veeam.com/docs/agentforlinux/userguide/backup_job_mode.html>,
<https://helpcenter.veeam.com/docs/agentforwindows/userguide/backup_types.html>.

| Feature | Veeam Agent (edition notes) | NexusBackup agent today | Gap | Effort | Phase 38 item |
|---|---|---|---|---|---|
| Entire computer (image of all disks) | VAW, VAL: all editions; VAW can add connected external VSS-capable USB disks (no flash drives) | Linux: file-level backup of `/` with nested mounts plus the machine layout, rebuilt by BMR (docs/bmr.md); Windows: no image | partial (Linux), missing (Windows) | L | 38d with 37a/37b |
| Volume level (selected volumes as images) | all editions; VAW cannot back up hidden non-system volumes; VAL relies on persistent `/dev` names | none (all backups are file trees) | missing | M (on top of 37b) | 38d |
| File level (folders, include/exclude masks) | all editions; Veeam calls it slower than volume level | Linux: snapshot-based file backups (LVM thin/thick, ZFS, btrfs), globs, regex excludes, include roots, nested mounts; Windows: VSS file backups with USN incrementals, ADS, ACLs, SACLs, reparse points | has | - | - |
| Snapshot-less file backup (file systems without snapshot support, NFS/SMB mounts) | VAL "Disable snapshot"; also the "nosnap" package without kernel module | live read with per-file inconsistency detection and spool; network file systems skipped by default (`skip_fstypes`) | has | - | - |
| System state / personal files presets | VAW: system state backup and personal files backup as file-level presets | none (paths chosen on the appliance) | missing | S | 38h |
| Parallel disk processing | VAW Srv only; not for dynamic disks | n/a for file backups; images not yet | missing | S | 38d |
| Backup cache (local cache while the target is offline, synced later) | VAW WS and Srv | none (laptop "catch up missed runs" re-runs the backup when reachable) | partial | M | out of scope at first: a standalone agent with a USB/NAS target runs when the target is back (38e trigger); revisit after 38c |
| Standalone full backup outside the chain (`/standalone`) | VAW CLI | appliance "Back up now, keep until" (Phase 23a) | partial (managed) | S | 38h (CLI) |

## 3. Change tracking

Sources: <https://helpcenter.veeam.com/docs/agentforwindows/userguide/backup_cbt.html>,
<https://helpcenter.veeam.com/docs/agentforwindows/userguide/backup_cbt_driver.html>,
<https://helpcenter.veeam.com/docs/agentforlinux/userguide/backup_hiw_volume.html>,
<https://helpcenter.veeam.com/docs/agentforlinux/userguide/backup_hiw_file.html>, <https://www.veeam.com/kb2804>.

| Feature | Veeam Agent (edition notes) | NexusBackup agent today | Gap | Effort | Phase 38 item |
|---|---|---|---|---|---|
| Windows default CBT for volume images | all editions, NTFS only (mechanism not described in the guide) | none for images; file backups use the USN journal (only changed files are read; their chunks deduplicate) | missing for images | M | 38d (user-mode, see Scope decision) |
| Windows CBT filter driver | WS and Srv; Windows 10/11 and supported Server versions; NTFS, ReFS, FAT (volume level only); used for files of 50 MB and more in file-level backups; Veeam warns that BitLocker together with the driver may cause driver failures and an unbootable OS | none | missing | L | out of scope (needs a Microsoft-signed kernel driver; see Scope decision) |
| Linux kernel module (snapshots + CBT): veeamsnap up to kernel 5.18, blksnap from 5.10 (pre-built packages from 5.3.18), DKMS elsewhere | all editions; CBT map in RAM, reset on reboot or module unload (then a full re-read with checksum comparison) | no kernel module: snapshots from LVM, ZFS, btrfs; plain partitions read live | partial (snapshots), missing (CBT) | M | 38d (LVM thin metadata diff for images; re-read plus dedup elsewhere) |
| Linux file-level incrementals | VAL: modification time compared with the previous backup; a small change in a large file resends the whole file | metadata cache plus content-defined chunks (FastCDC, BLAKE3): a changed file is re-read but only its changed chunks are sent | has (better transfer) | - | - |
| Snapshot-less ("nosnap") variant | VAL nosnap: no CBT, no application-aware processing | the agent never needs a module: every distribution runs the same static binary | has | - | - |

## 4. Targets

Sources: <https://helpcenter.veeam.com/docs/agentforwindows/userguide/backup_job_target.html>,
<https://helpcenter.veeam.com/docs/agentforwindows/userguide/backup_job_share.html>,
<https://helpcenter.veeam.com/docs/agentforwindows/userguide/rotated_drives.html>,
<https://helpcenter.veeam.com/docs/agentforwindows/userguide/system_requirements.html>,
<https://helpcenter.veeam.com/docs/agentforlinux/userguide/system_requirements.html>.

| Feature | Veeam Agent (edition notes) | NexusBackup agent today | Gap | Effort | Phase 38 item |
|---|---|---|---|---|---|
| Local disk (separate volume) | all editions; the target folder is excluded automatically if inside the scope | none: data only goes to the appliance | missing | M | 38c |
| USB / external disk (USB, eSATA, FireWire; no flash drives as source) | all editions; "eject after backup" | none | missing | S (after local disk) | 38c |
| Rotated drives (each drive its own chain, registered devices) | VAW: drives must be registered; any registered drive is used if the previous one is absent; GFS fulls not on rotated drives | none (appliance-side removable-disk offsite was proposed in docs/veeam-comparison.md #12, still open) | missing | M | 38c |
| SMB share | VAW: UNC path, optional credentials or the computer account; VAL: SMB via cifs-utils | none on the agent; the appliance backs up and restores SMB/NFS shares as sources | missing | S | 38c |
| NFS share | VAL: yes (nfs-utils); VAW: not mentioned (not confirmed) | none on the agent | missing | S | 38c |
| SFTP | not offered by either agent | none on the agent; the appliance has SFTP offsite | missing (beyond Veeam) | S | 38c |
| S3-compatible, Amazon S3, Azure Blob, Google Cloud Storage | VAW and VAL: WS and Srv (not Free) | S3 only, appliance offsite (docs/s3-offsite.md); no Azure or GCS | missing (agent), partial (S3 via appliance) | M | 38c (S3 only; Azure/GCS out of scope, no native client in the tree) |
| Veeam backup repository (VBR) | standalone agents may also write to a VBR repository; encryption then set by VBR | the appliance store (pull) | has (managed) | - | - |
| Veeam Cloud Connect (service provider repository) | WS and Srv | none; no vendor-hosted service (README "What it does not do") | missing | - | out of scope: no vendor-hosted vault; a provider can run an appliance and use 38i |
| exFAT as target | not supported by VAW | n/a | - | - | - |
| Data written to the target | Veeam backup files (full + incremental chain, synthetic fulls, compact) | chunk store: content-defined chunks, deduplication across hosts, zstd, XChaCha20-Poly1305 | n/a | - | 38c uses `crates/chunkstore` on every target |

## 5. Schedules and triggers

Sources: <https://helpcenter.veeam.com/docs/agentforwindows/userguide/scheduled_backup.html>,
<https://helpcenter.veeam.com/docs/agentforwindows/userguide/scheduled_backup_events.html>,
<https://helpcenter.veeam.com/docs/agentforlinux/userguide/backup_job_schedule.html>.

| Feature | Veeam Agent (edition notes) | NexusBackup agent today | Gap | Effort | Phase 38 item |
|---|---|---|---|---|---|
| Daily at / on weekdays | all editions (VAW, VAL) | policy schedule grammar on the appliance (daily, weekdays, hourly, every N h, monthly), per group time zone | has (managed) | S | 38e (agent-side scheduler reusing the grammar) |
| Monthly, periodic (every N hours or minutes) | Srv only (VAW, VAL) | every N h, monthly on the appliance | has (managed) | S | 38e |
| Backup window (no start outside) | VAW Srv | blackout windows per group | has (managed) | S | 38e |
| Retries | VAW Free/WS: every 10 min for 23 h, fixed; Srv: configurable | 0-10 retries, minutes between attempts, per policy | has (managed) | S | 38e |
| At lock, at log off | VAW Free and WS (Srv not stated) | none | missing | S | 38e (Windows session notifications; Linux logind `Lock`/session end) |
| When the backup target becomes available (known USB disk attached, network share reachable) | VAW Free and WS; "not more often than every N hours" for event-triggered runs | appliance "catch up missed runs when the laptop is back" (poll-driven, managed) | partial | S | 38e |
| Eject removable storage after backup | VAW | none | missing | S | 38e |
| On idle | not documented as a trigger in VAW 13 or VAL 13 (not confirmed) | none | missing (no Veeam equivalent) | S | 38e (optional; low priority) |
| Not on battery | VAW: scheduled jobs do not start on battery below 20 % | skip scheduled runs on battery below N % (configurable) and on metered networks, power state reported by the agent | has (managed) | S | 38e (same rule evaluated locally) |
| Wake from sleep to run | VAW | none (pull model cannot wake a sleeping laptop) | missing | S | 38e (Windows waitable timer task; Linux `systemd` timer `WakeSystem=`) |
| Scheduled without a logged-on user | VAL: yes; VAW: service-based | yes (service) | has | - | - |
| Linux event triggers | none documented in VAL 13 (not confirmed) | none | - | - | - |
| "Back up now" from the tray / TUI | VAW tray and control panel; VAL control panel | request to the appliance (rate limited, hideable) | partial | S | 38e/38h (local run in standalone mode) |

## 6. Retention, chain maintenance and health

Sources: <https://helpcenter.veeam.com/docs/agentforwindows/userguide/retention.html>,
<https://helpcenter.veeam.com/docs/agentforwindows/userguide/gfs_retention.html>,
<https://helpcenter.veeam.com/docs/agentforlinux/userguide/retention.html>,
<https://helpcenter.veeam.com/docs/agentforwindows/userguide/backup_health_check.html>.

| Feature | Veeam Agent (edition notes) | NexusBackup agent today | Gap | Effort | Phase 38 item |
|---|---|---|---|---|---|
| Short-term retention | by days (VAL 13.1: restore-point retention deprecated for new jobs; at least 3 points kept); separate retention for outdated backups (source no longer backed up) | GFS periods per policy (`crates/retention`), store retention locks, orphaned-source alert | has (managed) | S | 38c |
| GFS (weekly, monthly, yearly flags on fulls) | WS and Srv; not on rotated drives | GFS classes by period, each with its lock duration, restore point preview | has (managed) | S | 38c |
| Active full / synthetic full / forever incremental, merges | Veeam chain maintenance (synthetic full WS and Srv) | not needed: every snapshot is a full manifest over deduplicated chunks; no merge | has (by design) | - | - |
| Health check | standard check of the latest point (CRC on metadata, hashes on blocks), metadata-only for object storage; default last Friday of the month; corrupt blocks re-sent from the source in a retry session | daily verification of chunks, offsite sample, bad chunks marked and re-sent by the next backup (Phase 21d) | has (managed) | S | 38c (scheduled by the agent) |
| Compact of full backup file | VAW, VAL | garbage collection of unreferenced chunks | has (managed) | S | 38c |
| Retention for SQL Server log backups (until the image is deleted / last N days) | VAW | none (no log backups) | missing | S (with 38f) | 38f |

## 7. Encryption, immutability and security

Sources: <https://helpcenter.veeam.com/docs/agentforwindows/userguide/data_encryption.html>,
<https://helpcenter.veeam.com/docs/agentforwindows/userguide/encryption_hiw.html>,
<https://helpcenter.veeam.com/docs/agentforwindows/userguide/backup_immutability.html>,
<https://helpcenter.veeam.com/docs/vbr/userguide/agents_malware_detection.html>.

| Feature | Veeam Agent (edition notes) | NexusBackup agent today | Gap | Effort | Phase 38 item |
|---|---|---|---|---|---|
| Backup encryption | optional, per job, password-derived user key, password hint; source-side except for VBR repositories (VBR sets it). Algorithm not named in the agent guides (AES-256 in VBR; for the agents not confirmed) | always on: XChaCha20-Poly1305 per chunk, keys in `keyd` on the appliance; no plaintext option | has (managed) | M | 38c (local key, sealed on the host) |
| Recovery when the password or key is lost | not possible; restores on the same computer work without the password because keys stay in the agent database | tenant recovery key as 24 BIP39 words (ADR-015) | has (managed), missing (standalone) | S | 38c (24 words shown at standalone setup) |
| Immutability | object storage only (S3 Object Lock in compliance mode, Azure version-level immutability, GCS retention lock, Veeam Data Cloud Vault); period plus an automatic block generation period; VBR hardened repository when managed | store retention locks on the appliance; S3 Object Lock on offsite copies | has (managed) | M | 38c (Object Lock on S3 targets; local/USB/SMB targets cannot enforce it, say so) |
| Ransomware protection of USB targets | eject after backup | none | missing | S | 38e |
| Malware detection | managed only, in VBR: guest index scan (suspicious names and extensions, IOCs, mass deletes and extension changes) for VAW and VAL; inline entropy scan only for VAW with jobs managed by VBR; signature scans with Threat Hunter or third-party AV | scheduled YARA scans of agent snapshots, per-snapshot verdict, IOC hash hunting over per-file SHA-256, anomaly signals, clean-file restore | has (managed) | - | out of scope for standalone (no scanner on the client); available after 38i |
| MFA | not an agent feature; VBR console MFA when managed (not confirmed for the agent UI) | appliance accounts with TOTP; restores need the appliance | has (managed) | - | out of scope on the client (the local OS login guards the client UI) |
| Signed updates, rollback floor | not described in the agent guides (not confirmed) | cosign-signed releases, pinned keys, start watchdog, rollback floor (Phase 27) | has | - | 38j keeps it |
| Agent attack surface | VAW 13 fixed a local privilege escalation (CVE-2026-32996, KB4738) | agent listens only for the appliance (mTLS), local UI socket/pipe cannot change configuration | has | - | 38b must keep the local UI unprivileged; configuration changes need root/Administrators |

## 8. Application-aware processing

Sources: <https://helpcenter.veeam.com/docs/agentforwindows/userguide/application_aware_processing.html>,
<https://helpcenter.veeam.com/docs/agentforwindows/userguide/guest_processing.html>,
<https://helpcenter.veeam.com/docs/agentforwindows/userguide/backup_job_vss_sql.html>,
<https://helpcenter.veeam.com/docs/agentforwindows/userguide/sql_backup.html>,
<https://helpcenter.veeam.com/docs/agentforlinux/userguide/database_processing.html>,
<https://helpcenter.veeam.com/docs/agentforlinux/userguide/postgresql_backup.html>,
<https://helpcenter.veeam.com/docs/agentforlinux/userguide/mysql_backup.html>,
<https://helpcenter.veeam.com/docs/agentforlinux/userguide/oracle_backup.html>.

| Feature | Veeam Agent (edition notes) | NexusBackup agent today | Gap | Effort | Phase 38 item |
|---|---|---|---|---|---|
| Windows VSS writers take part (application-consistent) | VAW Srv only (guest processing) | all writers except excluded class ids; writer report per job; failed application writer marks the snapshot crash-consistent | has | - | - |
| Log truncation (full VSS backup) | VAW Srv: "process transaction logs" (full) or "copy only" | copy only, never truncates (documented workaround: native SQL log backups, Exchange circular logging) | missing | M | 38f (option per job; default stays copy only) |
| SQL Server transaction log backup | VAW Srv: every N minutes (default 15, max 480), log retention; one job per machine; Full or Bulk-logged recovery model; SQL Server 2012-2025 | none; native `BACKUP LOG` to a folder plus agent backups is the documented route | missing | L | 38f |
| SQL Server point-in-time and database restore | through Veeam Explorer for SQL Server, requires VBR | manual `RESTORE ... STOPAT` from restored `.bak`/`.trn` files | missing | L | 38g (after 38f) |
| Exchange (2016, 2019, SE) | VAW Srv: consistency and log truncation; item restore via Veeam Explorer (VBR) | VSS copy only; database restore with `eseutil` + recovery database (documented) | partial | L (items) | 38f (truncation); item restore out of scope (on-prem Exchange explorer, see docs/veeam-comparison.md) |
| SharePoint (2016, 2019, SE) | VAW Srv: account settings, item restore via Veeam Explorer (VBR) | VSS writer only | partial | L | out of scope (item restore); consistency via the writer |
| Active Directory (domain controllers 2012 R2-2025) | VAW Srv; object restore via Veeam Explorer for AD (VBR) | NTDS writer, restored `ntds.dit` in clean shutdown (lab), BMR runbook planned in 37e | partial | L | 38g "AD objects as far as 38a decides": recommend LDIF export/compare later, not in the first round |
| Oracle on Windows (11g-21c, no ASM/RAC/Data Guard) and Linux (11g-21c; ARCHIVELOG: backup mode around the snapshot; archived logs deleted by age or size; NOARCHIVELOG: shutdown) | VAW Srv, VAL Srv | none | missing | L | 38f, last (only if there is demand; RMAN-free "backup mode + archived logs" as Veeam does) |
| PostgreSQL on Linux (13-18; checkpoint or online backup around the snapshot; no clusters/HA; volume-level jobs only) | VAL Srv; instance restore via Veeam Explorer for PostgreSQL (VBR) | file-level backup with pre hook (dump); appliance plugin with base backup, WAL and point-in-time restore, run from the appliance over SSH | has (managed, better: PITR) | M | 38f (run the plugin locally in standalone mode) |
| MySQL on Linux (5.7-9.0; MyISAM locked, InnoDB not; one instance; no MariaDB stated) | VAL Srv | pre hook dump; appliance plugin with logical dumps, xtrabackup/mariadb-backup, binlogs and point-in-time restore (MySQL 8.0+, MariaDB 10.6+) | has (managed, better: PITR, MariaDB) | M | 38f (run locally) |
| Pre/post job scripts and pre-freeze/post-thaw scripts | VAW (pre-freeze/post-thaw for apps without a VSS writer); VAL Srv only (also used for e-mail) | Linux: `hooks.d/pre` and `post` (root-owned, checked, timeout, `hooks test`); Windows: not supported | has (Linux), missing (Windows) | S | 38f |
| File system indexing for search | VAW, VAL Srv; search and 1-click restore need VBR Enterprise Manager | file index of every agent snapshot, search across snapshots, per-file hashes | has (managed) | M | 38g (local search in standalone repositories) |

## 9. Restores

Sources: <https://helpcenter.veeam.com/docs/agentforwindows/userguide/restore.html>,
<https://helpcenter.veeam.com/docs/agentforwindows/userguide/restore_file.html>,
<https://helpcenter.veeam.com/docs/agentforwindows/userguide/integration_explorers.html>,
<https://helpcenter.veeam.com/docs/agentforwindows/userguide/volume_restore_allocate.html>,
<https://helpcenter.veeam.com/docs/agentforlinux/userguide/restore_file.html>.

| Feature | Veeam Agent (edition notes) | NexusBackup agent today | Gap | Effort | Phase 38 item |
|---|---|---|---|---|---|
| File-level restore on the client | VAW: backup published by a Veeam driver under `C:\VeeamFLR\`, browsed in the Backup Browser or Explorer; VAL: backup attached to a loop device and mounted under `/mnt/backup` | restores only from the appliance (to the original or another host, tar/zip download, clean-file restore); the endpoint cannot restore | partial (managed) | M | 38g (browse + restore in GUI/TUI/CLI without a mount driver first; Linux FUSE mount as an option) |
| Restore with original permissions, streams, links | Veeam copy from the mounted backup (overwrite handling not described) | full metadata (ACLs, SACLs, owners, ADS, reparse points, xattrs, SELinux), confinement against links, overwrite policy | has (managed) | - | - |
| Volume restore (resize to fit, dynamic disk layouts) | VAW: volumes or whole image, resize; spanned/striped/mirrored/parity on dynamic disks from a running system | none (Linux BMR recreates partitions and LVM; Windows none) | missing | M | 38g with 37b |
| Bare metal recovery | VAW: Veeam Recovery Media (WinRE based, manual or unattended); sources: local, share, object storage, VBR, service provider; dynamic volumes only as simple volumes from the media. VAL: recovery ISO (generic download or custom) with volume and file restore wizards | Linux: rescue ISO driven by the appliance (recovery token, layout, recreate, restore, initramfs and boot loader), lab-tested; Windows: Phase 37 not started | partial (Linux managed), missing (Windows, standalone) | L | 37c (Windows media), 38g (rescue reading a standalone repository) |
| Restore to a VM (instant recovery) | managed: vSphere, Hyper-V, Nutanix, Proxmox VE, Scale HyperCore, oVirt | Linux "Restore as PVE VM" (P2V through the rescue ISO, not instant) | partial | L | 37d (Windows P2V); instant recovery of agent images on PVE after 38d (later) |
| Restore to cloud VMs (Azure, EC2, GCE) | managed | none | missing | - | out of scope (README: no cloud VMs) |
| Export disk / volume as virtual disk (VMDK, VHD, VHDX) | managed ("disk export"); export of a restore point to a full backup file | none | missing | M | 38g (VHDX and qcow2 from image backups) |
| Disk publishing (mount backup disks on another machine) | managed | appliance NBD overlay for PVE VM disks only | missing | M | later (after 38d) |
| Application item restore (AD, Exchange, SharePoint, SQL Server, Oracle, PostgreSQL) | Veeam Explorers through VBR | PostgreSQL and MySQL: database and point-in-time restores (appliance plugins); others: files only | partial | L | 38g for SQL Server databases; others out of scope at first |
| Restore from encrypted backup on another computer | password required | appliance holds the keys; recovery key words for disaster recovery | has (managed) | S | 38c/38g (24 words or the local key) |

## 10. Recovery media

Sources: <https://helpcenter.veeam.com/docs/agentforwindows/userguide/recovery_media.html>,
<https://helpcenter.veeam.com/docs/agentforlinux/userguide/recovery_media.html>.

| Feature | Veeam Agent (edition notes) | NexusBackup agent today | Gap | Effort | Phase 38 item |
|---|---|---|---|---|---|
| Windows media built from WinRE on the protected computer (USB, SD card, ISO), drivers of the computer included, network and Wi-Fi selection, unattended mode, reboots after 72 h (WinRE limit) | all editions | none | missing | L | 37c (spike: Linux rescue ISO vs customer-built WinPE) |
| Linux generic ISO (download) and custom media built on the host | all editions; Secure Boot on a separate page (not confirmed whether the media is signed) | generic `nexus-rescue-<version>.iso`, BIOS and UEFI, unsigned (Secure Boot off), network config, config disk for unattended P2V | has (managed) | - | - |
| Media restores from local disk, USB, share, object storage | VAW and VAL | rescue only talks to the appliance | missing | M | 38g |
| Shell and tools on the media | VAW tools and WinRE; VAL shell | shell on the rescue ISO (not confirmed as documented for end users) | partial | S | 38g |

## 11. Bandwidth, priority and notifications

Sources: <https://helpcenter.veeam.com/docs/agentforwindows/userguide/settings_network_bandwidth.html>,
<https://helpcenter.veeam.com/docs/agentforwindows/userguide/settings_resources.html>,
<https://helpcenter.veeam.com/docs/agentforwindows/userguide/settings.html>,
<https://helpcenter.veeam.com/docs/agentforlinux/userguide/integration_settings.html>.

| Feature | Veeam Agent (edition notes) | NexusBackup agent today | Gap | Effort | Phase 38 item |
|---|---|---|---|---|---|
| Bandwidth limit | VAW: global limit in settings; VBR throttling rules when managed | per-source `bwlimit` (token bucket on the agent), set on the appliance | has (managed) | S | 38e |
| Metered connections, VPN, Wi-Fi allow-list | VAW: block backups on metered networks, VPN or Wi-Fi other than listed | skip scheduled runs on metered networks (managed) | partial | S | 38e |
| Throttle when the system is busy | VAW: lower priority of backup processes | nice 10 and idle I/O class (Linux), background mode (Windows), `nice` limit | has | - | - |
| E-mail notifications | VAW standalone: SMTP, Gmail or Microsoft 365; VAL standalone: none documented, Veeam suggests a post-job script (not confirmed beyond that); managed: VBR global settings | appliance alerts by e-mail, webhook, PSA tickets, syslog forwarding; desktop notifications on the client (off by default) | has (managed), missing (standalone) | S | 38h |
| Control panel notifications | VAW tray notifications (can be disabled) | tray icon state and desktop notifications (Linux D-Bus, Windows toasts) | has | - | - |

## 12. User interface, CLI and automation

Sources: <https://helpcenter.veeam.com/docs/agentforwindows/userguide/backup_cmd.html>,
<https://helpcenter.veeam.com/docs/agentforwindows/configurator/>,
<https://helpcenter.veeam.com/docs/agentforlinux/userguide/ui_overview_cmd.html>.

| Feature | Veeam Agent (edition notes) | NexusBackup agent today | Gap | Effort | Phase 38 item |
|---|---|---|---|---|---|
| Tray icon and control panel (Windows) | VAW: tray, control panel with sessions, job wizard, restore, settings | tray + window (status, last 30 sessions, details, request backup); no configuration, no restore | partial | M | 38h |
| Linux control panel | VAL: text UI (`veeam`) with job wizard and restores; no graphical UI (not confirmed) | `nexus-agent tui` (status, sessions, log, request backup) and a graphical tray app for desktops | partial (no config/restore), has (GUI beyond Veeam) | M | 38h |
| CLI | VAW: `Veeam.EndPoint.Manager.exe` (`/backup`, `/activefull`, `/standalone [folder]`, exit codes); VAL: `veeamconfig` (job, schedule, repository, objectstorage, backup, point, session, gfs, healthcheck, aap, config, mode, vbrserver, ...) | `nexus-agent status/sessions/session/request-backup [--json]`, `hooks test`, `init`, `rescue` | partial | M | 38h (`nexus-agent job`, `backup`, `restore`, `repo` ...) |
| Configuration as file / mass configuration | VAW Configurator (export/import XML, install CBT driver); VAL `veeamconfig config` export/import | `agent.conf` (key = value, unknown keys refused); fleet enrollment by GPO/Intune/Ansible | partial | S | 38h (job definitions as files) |
| PowerShell module | none for the agent itself (VBR has one for managed agents) (not confirmed) | none; appliance REST API and `nexusctl` | - | - | out of scope (CLI with JSON output is enough) |

## 13. Management (managed mode)

Sources: <https://helpcenter.veeam.com/docs/agentforwindows/userguide/operation_modes.html>,
<https://helpcenter.veeam.com/docs/vbr/userguide/agents_infrastructure.html>.

| Feature | Veeam Agent (edition notes) | NexusBackup agent today | Gap | Effort | Phase 38 item |
|---|---|---|---|---|---|
| Protection groups (AD, computer lists, CSV, pre-installed agents) | VBR; deployment from VBR or external tools | fleet secrets with range scans, accept/auto-accept, template groups by host name, CSV bulk tokens (Phase 24d) | has | - | - |
| Agent updates from the server | VBR | signed releases, waves, canary, rollback with approval (Phase 27) | has | - | - |
| Failover clusters (Windows) | VAW only when managed by VBR | none (file paths per node) | missing | L | out of scope (as Phase 37e) |
| Roaming laptops outside the network | VBR/Cloud Connect (agent connects out) | edge proxy (TLS end to end; lab run open) | has | - | - |
| Attach a standalone agent to a server without a new full | VBR can map existing backups (VAW "map to existing backup") | none | missing | M | 38i |

## 14. Platform support and limits

Sources: the two system requirements pages above, <https://www.veeam.com/kb2804>,
<https://helpcenter.veeam.com/docs/agentforwindows/userguide/backup_cbt_driver.html>.

| Feature | Veeam Agent (edition notes) | NexusBackup agent today | Gap | Effort | Phase 38 item |
|---|---|---|---|---|---|
| Windows versions | Server 2012 R2-2025 (no Server Core, no ReFS boot volume); Windows 10 22H2, 10 LTSC 2015-2021, Windows 11 22H2-25H2; Embedded/IoT | Server 2016-2025 documented; lab: Server 2022 (member, DC) and Windows 11 | partial (client versions untested, Server Core not mentioned in our docs) | S | 38j (state Windows 10/11 support, test matrix) |
| Linux distributions | Debian 11-13, Ubuntu 16.04-26.04, RHEL 7.9 ELS-10.2, Oracle Linux, SLES 12 SP5-16, Rocky and Alma 8.10-10.2; kernel 3.10-7.0 from the distribution | any systemd distribution (static musl binary, no module); lab: 14 releases incl. Ubuntu 22.04-26.10, Debian 12/13/testing, Alma/Rocky 8-10, openSUSE Leap 16 | has | - | - |
| Architectures | VAW x64 only; VAL x86_64 only (Veeam staff: no arm64 in v13, forum, not in the docs) | Linux x86_64 and aarch64 packages (aarch64 untested on hardware); Windows x64 only | has (Linux, ahead), same (Windows) | S | 38j (aarch64 lab test); Windows arm64 out of scope for now |
| File systems (Windows) | NTFS, ReFS, FAT32, exFAT; volumes up to 64 TB (VSS); 512 B and 4 KB sectors | NTFS and ReFS with VSS, FAT/exFAT live; ReFS/FAT untested | has (untested parts) | S | 38j test matrix |
| File systems (Linux) | snapshot: btrfs (only directly on a device), ext2/3/4, F2FS, FAT, HFS(+), JFS, NTFS, ReiserFS, XFS; LVM2, mdadm, dm-crypt; btrfs subvolumes and compression not supported; ZFS not listed | LVM thin/thick, ZFS, btrfs (incl. nested subvolumes) snapshots; any file system live; BMR refuses LUKS, md RAID, ZFS | has (snapshots broader for ZFS/btrfs), partial (BMR) | M | 38d/38g (BMR on md RAID and LUKS later) |
| Dynamic disks, Storage Spaces | VAW: restore to dynamic layouts from a running system; media restores dynamic volumes as simple only; Storage Spaces behaviour for standalone not stated (not confirmed) | file backups work; BMR out of scope (37a reports them) | partial | L | out of scope at first (37e) |
| BitLocker | VAW: Microsoft BitLocker only, volumes unlocked at backup and restore; CBT driver conflict warning | file backups read through VSS in plain text; 37a/37b plan the same for images | has (files) | S | 37b |
| EFS files | not stated in the requirements (not confirmed) | not backed up (README) | missing | M | out of scope at first (raw EFS export API, `ReadEncryptedFileRaw`, as a later item) |
| Clusters (Linux) | VAL: local disks of cluster nodes only; shared/clustered file systems snapshot-less | not addressed | - | - | out of scope |

## Scope decision for 38b-38j

### In scope, in this order

1. **38b + 38c: standalone mode and local repository.** One agent, two modes chosen in the configuration. The
   standalone agent writes to a `crates/chunkstore` repository on a local disk, USB disk, SMB, NFS, SFTP or S3
   (Object Lock where the target supports it), with a local key protected on the host and the 24 recovery words
   shown once at setup; GFS retention from `crates/retention`; scheduled verify and GC. Rotated USB drives (one
   repository per drive, registered by volume id) and "eject after backup" belong here. Azure Blob and Google Cloud
   Storage stay out (no client in the tree; S3-compatible gateways exist). Cloud Connect stays out.
2. **38e: schedules and triggers on the client.** Reuse the appliance schedule grammar, retries and blackout
   windows; add lock and log off (Windows), "when the target becomes available" with a minimum interval, wake from
   sleep, battery and metered-network rules (already measured by the agent), a bandwidth limit with network
   allow-lists, and a local "back up now". Idle is optional and last: Veeam does not document it.
3. **38d with Phase 37: entire computer and volume images.** Images of the used blocks from snapshots (VSS on
   Windows, LVM/ZFS/btrfs or a frozen file system on Linux), chunked and deduplicated, BMR-capable. Incrementals
   without a kernel driver (see below).
4. **38f: application-aware processing.** Windows pre/post scripts (Linux has hooks); a per-job option for full VSS
   backups with log truncation (default stays copy only); SQL Server transaction log backups every N minutes with
   their own retention; the existing PostgreSQL and MySQL/MariaDB plugins run locally in standalone mode. Oracle
   last and only on demand.
5. **38g: restores from the client.** Browse, search and restore files in the GUI/TUI/CLI (no mount driver on
   Windows; FUSE mount on Linux as an option); volume restore; BMR from a standalone repository with the Linux rescue
   ISO and the Phase 37 Windows media; export of image backups as VHDX and qcow2; SQL Server database restore to a
   point in time after 38f.
6. **38h: UI and CLI.** Job and target setup, restore wizards and a notification history in the desktop UI and TUI,
   `nexus-agent job|backup|restore|repo` with JSON output, job definitions as files, SMTP e-mail in standalone mode.
7. **38i: growing into the appliance.** Import or read a standalone repository on the share and take the agent over
   as managed without a new full; later push policies to standalone agents ("managed by agent").
8. **38j: packaging and test matrix.** The same signed .deb/.rpm/.msi with the mode chosen at install; state and test
   Windows 10/11 client support, aarch64 Linux on hardware, ReFS/FAT.

### Deliberately not in scope (now)

- **Windows CBT filter driver.** A kernel-mode volume filter must be signed by Microsoft: an EV code signing
  certificate, a Microsoft Partner Center hardware developer account, attestation signing (accepted on Windows 10/11
  client) and, for Windows Server, WHQL/HLK certification with test runs per Windows version; plus the kernel code
  itself, a crash-safe change map on disk, reset handling after unclean shutdowns, and the BitLocker interaction
  Veeam itself warns about. A bug there stops the machine from booting. Veeam limits its driver to the paid editions
  and keeps a driverless default. **Recommendation: re-read plus deduplication**, made cheaper in user mode: the
  volume bitmap (`FSCTL_GET_VOLUME_BITMAP`) limits the read to used clusters, and the USN journal between two
  backups names the changed files, whose cluster runs (`FSCTL_GET_RETRIEVAL_POINTERS`) plus the NTFS metadata files
  give the changed ranges; a full re-read happens only when the journal wrapped or was recreated (as for file
  backups today). Revisit the driver only if lab numbers show the re-read is too slow for real volumes.
- **Linux kernel module (blksnap/veeamsnap style).** DKMS builds, Secure Boot module signing (MOK enrolment) and kernel
  version tracking for every distribution would end the "one static binary, no dependencies" property. Use LVM thin
  metadata differences (`thin_delta`) where the volume is a thin LV, ZFS/btrfs snapshots for file trees, and re-read
  plus deduplication elsewhere.
- **Veeam Cloud Connect equivalent** (vendor-hosted repository) and restores to Azure, EC2 or GCE: no vendor-hosted
  services and no cloud VMs (README). A service provider can run an appliance and use 38i.
- **Item-level restores for Exchange, SharePoint and AD objects:** large explorers with little standalone value; the
  documented routes (Exchange recovery database, AD runbook) stay. AD object export (LDIF and diff) can follow
  later, as docs/veeam-comparison.md #13 already proposes.
- **Windows failover clusters, dynamic disks and Storage Spaces for images/BMR, EFS files, Windows arm64:** as Phase
  37e; file backups of such systems keep working.
- **Malware scanning and MFA on the client:** they stay appliance features (available after 38i); the client UI is
  guarded by the local OS login and needs administrator rights to change anything.
- **Editions and licence limits:** none; every feature is available everywhere.

### Where we are already ahead (keep it that way)

Deduplication across hosts and content-defined chunks for file incrementals, always-on authenticated encryption with
recovery words, point-in-time restores for PostgreSQL and MySQL/MariaDB, ZFS and nested btrfs snapshots, one static
Linux binary without a kernel module (aarch64 included), signed updates with rollback floor, file index and malware
scans of agent snapshots, laptop policies and the edge proxy.
