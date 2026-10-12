# 06 Restores

Every restore starts on the **Snapshots** page. Pick a snapshot, open its **Restore** menu (or **Browse files**),
choose the restore type, and the appliance queues a job. The job's detail page shows its log live. The appliance initiates every connection, as it does for
backups. It reaches PVE nodes, agents and database servers. Nothing on the source side reaches the appliance.

## Who may restore

| Role | Restores |
|---|---|
| **Administrator** | all restore types, all tenants |
| **Operator** | all restore types, all tenants |
| **Tenant user** | all restore types, own tenant only (the UI shows only that tenant's snapshots) |
| **Security officer** | none: reads everything, restores nothing |

Restores never need an approval. They write only to new
targets or to targets you confirm explicitly. Existing backups are never touched.

![Snapshots of tenant initech with Browse files and the Restore menu](images/snapshots.png)

## Which restores a snapshot offers

Each snapshot row has a **Browse files** button and a **Restore** menu. Click **Restore** to see the restores that fit
the snapshot; each entry has a short explanation below its name.

![The Restore menu of a VM snapshot](images/snapshot-restore-menu.png)

The snapshot name tells you what was backed up. The menu follows from it:

| Snapshot name | Source | **Restore** menu | Other button |
|---|---|---|---|
| `vm-<id>` | Proxmox VE virtual machine | **Full restore to a new VM / container**, **Instant recover**, **Restore files to a host…** | **Browse files** |
| `ct-<id>` | Proxmox VE container | **Full restore to a new VM / container**, **Restore files to a host…** | **Browse files** |
| `host-<agent id>` | Linux/Windows host (agent) | **Restore to path** | **Browse files** |
| `nas-<source>-<pool.dataset>` | TrueNAS dataset (built-in connector) | **Restore to a host…** | **Browse files** |
| `share-<source>` | NFS / SMB share | **Restore to a host…** | **Browse files** |
| `plugin-<plugin>-<source>[-<guest>]` | plugin source, e.g. PostgreSQL or Microsoft 365 | the plugin's restores that apply to this kind of snapshot (see below); **Restore to a host…** if the plugin offers a download | the plugin's download button, e.g. **Download (tar/zip)** |

Plugin snapshots come in two kinds: a **guest** snapshot (`plugin-<plugin>-<source>-<guest>`, e.g. one database or
one mailbox) and a **source** snapshot (`plugin-<plugin>-<source>`, the whole source, e.g. a PostgreSQL cluster). A
plugin declares for each of its restores whether it applies to guest snapshots, source snapshots or both, and the
menu offers only the matching ones. The appliance refuses a restore that does not match the snapshot kind.

Use the **Tenant** and **Guest (e.g. vm-100)** filters to narrow the list. Each row shows **Local**,
**Offsite** and **Verified** marks and the **Locked until** date. A locked snapshot cannot be deleted
before that date (see [01 Concepts](01-concepts.md)).

## Restore a VM or container (full restore)

1. On **Snapshots**, open **Restore** on the snapshot and choose **Full restore to a new VM / container**.
2. Fill in the dialog:
   - **Target node**: the PVE node that runs the restore. The list offers the nodes of the tenant's PVE
     sources.
   - **New VM/CT ID**: an ID that is not in use on the cluster yet.
   - **Target storage**: the PVE storage for the disks or the root file system, e.g. `local-lvm`. It must be a
     storage that holds VM disk images / container volumes, not the NexusBackup storage itself.
3. Click **Start**. The job page opens.

![Restore dialog for vm-100](images/snapshot-restore-vm.png)

What happens:

- **VMs**: PVE creates the VM from the backed-up configuration. The node attaches the appliance's read-only
  NBD export (over the restricted SSH helper) as a block device and copies every disk.
- **Containers**: PVE restores them as **unprivileged** containers with new MAC addresses (`unique=1`).
  PVE refuses privileged restores from backup providers. The node extracts the container into a staging
  directory under `/var/tmp/nexusbackup` first, so it needs that much free space on its root file system.
- PVE cannot live-restore from a backup provider: the guest starts only after the copy has finished. To
  start it immediately, use instant recovery.

> **Status:** Full VM and CT restore was verified in the nested PVE 9 lab (single node). Multi-node clusters
> are untested. The PVE API token needs `SDN.Use` on the guest's bridge zone for restores.

## Instant recovery (VMs)

Instant recovery boots the VM straight from the backup, then moves its disks to real storage while it runs.

1. Open **Restore** on a `vm-` snapshot and choose **Instant recover**.
2. Enter **Target node**, **New VM/CT ID** and **Target storage** (the storage the disks move to).
3. Click **Start**.

![Instant recovery dialog](images/snapshot-instant-recover.png)

How it works: the node creates qcow2 overlays whose backing file is the appliance's read-only NBD export.
The VM starts from them. Guest writes go into the overlays on the node. A live disk move then copies each
disk to the target storage and drops the overlay. In the lab the VM ran about 4.5 s after the start, and a
4 GiB disk moved in 24–30 s.

Limits:

- VMs with a TPM state (`tpmstate0`) and templates are refused.
- Guest writes accumulate on the node's root file system until the disk move finishes. Keep enough free
  space there.
- The VM gets new NIC MAC addresses and a new `vmgenid`. If the original VM still runs on the same network,
  start the recovered VM with its links down. The API accepts `link_down` for `instant_recover` jobs; the
  web UI dialog has no switch for it.
- If the appliance or the network to the node fails during instant recovery, reads of blocks that are not
  yet in the overlay stall, and fail after 60 s. Moved data and guest writes are not affected. Resuming the
  serving is a command-line step (`nexus-pve … ir-serve`, see `docs/pve-connector.md`).

> **Status:** Lab-verified on PVE 9.2 (single node). Behaviour after a node reboot during instant recovery is
> untested.

## Browse files and download them (tar or zip)

**Browse files** opens a file browser for the snapshot. The appliance reads the file system from the backup:

- **VM images**: the disks are attached read-only to an isolated restore micro-VM on the appliance. Its kernel
  mounts the guest file systems read-only: ext4, XFS, btrfs, NTFS, vfat, exFAT, ISO 9660, LVM, md and ZFS.
  The appliance's own kernel never mounts guest file systems. The first listing takes a few seconds.
  Not supported: encrypted volumes (LUKS, ZFS native encryption, BitLocker), Windows dynamic disks and
  Storage Spaces, ZFS zvols, and duplicate pool or volume-group names across disks.
- **Containers, hosts, TrueNAS datasets, NFS/SMB shares, plugin snapshots**: read directly from the stored
  backup (container tar stream or file tree). No VM is needed.

To download:

1. Open folders by clicking their names, and tick the files and folders you want.
2. Choose **tar** or **zip** and click **Prepare download**. The appliance packs the archive in a job.
3. Click **Download …** when it appears.

![File browser with two selected paths and a prepared zip download](images/files-download.png)

- tar keeps owners, modes, modification times, symlinks, hard links and extended attributes (incl. ACLs).
  zip keeps modes and modification times.
- A prepared download is valid for **24 hours** and can be fetched only by the user who requested it.
- For TrueNAS datasets and NFS/SMB shares there is no restore back into the dataset or share itself. Download
  the files, or restore them onto a host with an agent (next section), for example a server that mounts the share.

## Find a file

When you do not know which snapshot (or which guest) holds a file, open **Monitor → Find files** (or **Find files**
on the Snapshots page).

1. Choose the **Tenant** (tenant users search their own tenant only).
2. Type a **Name or pattern**:
   - without wildcards the name only has to contain the text (`budget` finds `budget-2026-q4.xlsx`);
   - `*` stands for any characters, `?` for one character, `[abc]` / `[a-z]` for one of the listed characters,
     `[!x]` for any character except those listed (`report-202?.pdf`, `*.[ch]`);
   - without a `/` the pattern is matched against the file or folder name; with a `/` against the whole path from
     the snapshot root (`home/*/Documents/*.docx`);
   - upper and lower case are treated alike unless you tick **Case-sensitive**.
3. Optionally narrow it to one **Guest** and a date range (**Snapshots from / until**), then click **Search**.

![Search results for budget* in tenant acme](images/search.png)

Each row is one version of a file: the same path with the same size and modification time in several snapshots is
shown once, with the number of snapshots that hold it. Pick the snapshot in the list (default: the newest), then:

- **Open** shows the folder in the file browser of that snapshot ([Browse files](#browse-files-and-download-them-tar-or-zip));
- **Download** packs the file as a tar archive (needs the download permission);
- **Restore…** (host snapshots) opens the [restore to a host](#restore-files-to-a-host-agents) dialog for this path.

At most 500 versions are listed, and a search stops after 30 seconds. If either limit is hit, a note asks you to narrow
the search (a longer name, one guest, a date range). The search runs as a **File search** job; every search is
recorded in the audit log (`file.search`) with the query.

What is searched:

- Host (agent), TrueNAS, NFS/SMB and plugin snapshots: always. Each snapshot gets its own file index when it is
  committed; snapshots taken before this release are indexed by the daily maintenance.
- VM and container snapshots: only for protection groups with **Index files in VM/CT disks** switched on
  ([05 Policies and groups](05-policies-and-groups.md#index-files-in-vmct-disks)). It costs a restore micro-VM boot
  (VMs) or a read of the backup (containers) after every backup. Other VM/CT snapshots are counted in a note
  ("… snapshots have no file index").
- Snapshots that exist only offsite are not searched.

Privacy: the file names never appear in plaintext in the catalog. The index of a snapshot is stored next to the
snapshot, encrypted with the tenant key, and is deleted together with the snapshot (retention, manual delete). The
search runs on the appliance in the scheduler, which opens the indexes with the tenant key; the web interface only
receives the matches.

> **Status:** The search and the per-snapshot index are covered by unit and scheduler tests with a temporary store.
> Indexing of VM disks through the restore micro-VM has not run in the VM lab yet.

## Restore files to a host (agents)

An enrolled agent writes files from a snapshot onto its host. This works for every snapshot with files:
host snapshots (`host-`, back onto the same host or onto another one), TrueNAS datasets (`nas-`), NFS/SMB shares
(`share-`), plugin snapshots whose plugin offers a download (`plugin-…`, including the streams under
`.nexus-streams/`), and files inside VM and container snapshots (`vm-`, `ct-`). The target is always an agent of the
snapshot's tenant; agents of other tenants are not offered and the appliance refuses them.

1. Choose what to restore:
   - **Host snapshots:** open **Restore** and choose **Restore to path** (everything), or open **Browse files**,
     select paths and click **Restore to path** (with nothing selected the button reads **Restore everything to
     path**).
   - **TrueNAS datasets, shares, plugin snapshots:** open **Restore** and choose **Restore to a host…**
     (everything), or select paths in **Browse files** and click **Restore to a host…**.
   - **VMs and containers:** open **Restore** and choose **Restore files to a host…**. The file browser opens;
     select files or folders (a VM shows its file systems at the top level, e.g. `/sda1`), then click
     **Restore to a host…**. The restore micro-VM reads the selection from the snapshot, the same way as for a
     download.
2. Fill in the dialog:
   - **Target directory on the host**: an absolute path, e.g. `/srv/restore`. The restored paths keep
     their structure below it. The directory is created if missing.
   - **Existing files**: **Never overwrite (skip existing files)**, **Overwrite if older than the backup
     copy**, or **Always overwrite**. Restoring onto `/` (or a Windows drive root) is refused unless you
     choose **Always overwrite**.
   - **Target agent**: for host snapshots by default the host the backup came from. Enrolled agents of the tenant
     are listed first, with their last contact; agents that are not enrolled cannot be chosen.
   - **Confirmation**: type the target agent's name. The appliance checks it, and the agent logs it.
3. Click **Start restore**. The job page opens.

![Restore files to a host](images/restore-to-path.png)

![A share snapshot restored onto another host](images/restore-to-host.png)

The agent writes only below the target directory. It never follows symlinks or junctions planted in the target.
Skipped files (kept by the overwrite policy) appear in the log, not as errors.

**Back onto the same host**, the agent restores owners, modes, extended attributes, ACLs and modification times.

**Onto another host** (and always for shares, TrueNAS, plugins, VMs and containers) the dialog shows a note, and the
appliance adapts the metadata, because owner IDs and ACLs of another machine mean something else there:

- Owners and groups are not mapped: the files belong to the agent's restore user (root for the installed service).
- setuid, setgid and sticky bits are cleared; permissions and modification times are kept.
- Device nodes and sockets are skipped; on Windows also FIFOs.
- Extended attributes are kept only if the target can store them: `user.*` attributes on Linux, Windows metadata
  (`win.*`) on Windows. ACLs, SELinux labels and SMB security descriptors of the other machine are dropped. The job
  log counts what was skipped.
- Files from VMs and containers carry modes, times, symlinks and hard links, but no extended attributes.
  Sparse files are written fully allocated.

![Files of a VM restored onto a host](images/restore-vm-files-to-host.png)

On Windows, write paths as `/D/restore` or `D:\restore`. The agent restores security descriptors, alternate
data streams and attributes. The security descriptor of a directory that already exists is only replaced
with **Always overwrite**. EFS-encrypted files are not supported. Names that Windows does not allow (for example
`a:b` or `name.` from a Linux share) fail as single entries; the job then fails and lists them, the other files are
written.

> **Status:** Linux restore was tested in the agent VM lab (Debian, AlmaLinux, Ubuntu, Fedora). Restores from
> shares, TrueNAS, plugins and VM/CT files onto a host (Phase 15b) are tested against a fake agent, and restores onto
> another host also against the real Linux agent; the VM lab run is pending. The Windows agent has been built and
> unit-tested only. It has never run on Windows, so treat Windows restores as untested.

## Plugin restores (PostgreSQL)

Plugin snapshots offer the restores declared by the plugin in their **Restore** menu. Restores marked
**application-specific** do more than copy files. The download button of a plugin uses its own title and replaces
**Browse files**. In the file browser, application
streams such as database dumps and WAL appear under `.nexus-streams/`.

The PostgreSQL plugin ([12 Plugins](12-plugins.md)) produces two kinds of snapshots:

| Snapshot | Contains | Useful restores |
|---|---|---|
| `plugin-postgresql-<source>-<db>` (database snapshot) | logical dump of one database (stream `<db>.sql`) | **Restore database dump to a server**, download |
| `plugin-postgresql-<source>` (cluster snapshot, group without databases) | the whole cluster: `data/` (base backup) and `wal/` | **Point-in-time restore (new data directory via SSH)**, download |

The **Restore** menu offers the dump restore only on database snapshots and the point-in-time restore only on cluster
snapshots.

> **Status:** The per-snapshot filtering needs plugin manifests that declare it (manifest v1.4, `applies_to`). With
> an older plugin version the menu shows every restore of the plugin on every snapshot of it; then use the dump
> restore on database snapshots and the point-in-time restore on cluster snapshots.

### Restore a database dump to a server

1. Open **Restore** on a database snapshot and choose **Restore database dump to a server**.
2. Enter the **Target database**, choose **Server** (`source` = the backed-up server, `alternate` = the
   **Alternate restore server** configured in the source), and tick **Restore into an existing database**
   only if you really want that.
3. Click **Start**.

![Dump restore dialog](images/snapshot-pg-to-target.png)

On the source server the backup role needs `CREATEDB`. The alternate server's user needs `CREATEDB` too.
A logical dump does not cover owners and grants, comments, RLS policies, large objects, roles and some other
objects (a warning in each backup log names those present). Use a cluster backup where these matter.

### Point-in-time restore

1. Open **Restore** on a cluster snapshot and choose **Point-in-time restore (new data directory via SSH)**.
2. Enter the **New data directory on the restore host (must not exist)**, optionally a time to recover to
   (e.g. `2026-10-10 14:30:00+00`; empty = the end of the backup), and optionally a port.
3. Click **Start**.

![Point-in-time restore dialog](images/snapshot-pg-pitr.png)

The plugin connects over SSH to the restore host configured in the source (host key pinned). It unpacks the
base backup into the new directory and the WAL into `<dir>/nexus_wal/`, and writes the recovery settings
(target time, then promote). **It does not start PostgreSQL.** On the restore host, start a server of the
same major version on the directory:

```sh
pg_ctl -D /var/lib/postgresql/18/restore-1013 start
```

Limits: clusters with additional tablespaces can only be downloaded, not restored point-in-time. Only time
targets are supported. The restore always creates a new data directory and never writes into a running
server.

> **Status:** Tested against PostgreSQL 14, 17 and 18 in the plugin's container test box. A run on the
> appliance image (VM lab) is still pending.

## Microsoft 365 restores

Microsoft 365 snapshots (`plugin-m365-<source>-u.…` for a user, `-s.…` for a site, `-t.…` for a team) offer three
restores (download and two restores in the **Restore** menu). None of them overwrites anything in Microsoft 365: restores always write into a **new** folder,
calendar or channel.

| Snapshot | Contains (folders in the file browser) |
|---|---|
| user (`u.…`) | `mail/` (one `.eml` per message), `calendar/` (one `.ics` per event), `contacts/` (one `.vcf` per contact), `onedrive/` (the files) |
| site (`s.…`) | `libraries/<library>/` (the files) |
| team (`t.…`) | `files/` (the team's files), `channels/<channel>/` (one `.json` per conversation, if channel messages are backed up) |

### Download

Click the download button (**Download (mail .eml, events .ics, contacts .vcf, files, threads .json)**), select
folders or single items and prepare a tar or zip archive as described in
[Browse files and download them](#browse-files-and-download-them-tar-or-zip). Mail opens in any mail client,
`.ics` files in any calendar, `.vcf` files in any address book. Names containing `/` or `%` are shown encoded
(`Projects%2F2026` is the folder `Projects/2026`).

### Restore to the original user, site or team

1. Open **Restore** on the snapshot and choose **Restore to the original user / site / team (into a new folder)**.
2. Optionally fill in **Only these snapshot paths**, one per line, e.g. `mail/Inbox` or
   `onedrive/Documents/Contracts` (empty = everything), and **New folder** (empty = `Restored <date> <time>`). The
   folder must not exist yet.
3. Click **Start**.

Where the items end up:

- **Mail**: a new top-level mail folder with that name, containing the backed-up folder structure.
- **Calendars**: a new calendar `<folder> – <calendar name>` per backed-up calendar. Restored events have **no
  attendees**, so nobody receives invitations. The attendee list is still in the `.ics` file of the backup.
- **Contacts**: a new contact folder with one subfolder per backed-up contact folder.
- **OneDrive, team files**: the new folder in the user's OneDrive or the team's document library.
- **SharePoint libraries**: the new folder inside the library of the same name. If the target site has no such
  library, `<folder>/<library>/…` in its default document library.
- **Teams conversations**: a new channel `<channel> (restored <date> <time>)` per backed-up channel. Messages
  appear with their original author and time. Deleted messages and messages from bots are skipped.

### Restore to another user, site or team

Use **Restore → Restore to another user / site / team (into a new folder)**, for example to give a successor the mailbox
and OneDrive of a person who left. In addition to the fields above, enter the **Target**:

- for a user snapshot: the other user's sign-in name (`jane@contoso.com`) or object ID;
- for a site snapshot: the site's address (`https://contoso.sharepoint.com/sites/archive`) or Graph site ID;
- for a team snapshot: the team's ID or its exact name.

The target must be of the same kind as the snapshot (a user's mailbox cannot be restored into a site). The job
fails with "target … not found" if the target does not exist.

The app registration needs the write permissions listed in [04 Sources](04-sources.md#microsoft-365-exchange-onedrive-sharepoint-teams)
for restores, and for Teams conversations also `Teamwork.Migrate.All` and `Channel.Create`.

> **Status:** Tested against a local Microsoft Graph simulation only. A run against a real Microsoft 365 tenant is
> still pending; it also checks whether restored mails show up as drafts in Outlook.

## Follow a restore job

Every restore is a job. The dialog opens the job page, which refreshes every 2 s while the job runs. All jobs
are listed on **Jobs** (see [03 The web interface](03-web-interface.md)).

![A running job with its live log](images/job-running.png)

## Tenant users

A tenant user sees only **Dashboard**, **Snapshots** and **Jobs**, and only for their own tenant. They can
use every restore type there. Restores still go only to targets the administrator configured: the tenant's
PVE nodes, its enrolled agents and the plugin's servers.

![Snapshots as seen by the tenant user of acme](images/tenant-user-snapshots.png)

## Restores on a replication secondary

Snapshots that came from another appliance are marked **Replicated from <source>**
([08 Replication to a second appliance](08-replication.md)). They restore with the secondary's own keys, even when the primary is
gone:

- **Browse files** and downloads work without any source in the tenant.
- For a full VM/CT restore, add a PVE source to the replicated tenant as a **restore target**, e.g. the DR
  site's cluster. Replicated tenants take no backups, so that source is only used for restores.

![Replicated snapshots of tenant globex](images/snapshots-replicated.png)

## Deleting a snapshot

Retention deletes snapshots on its own (see [05 Policies and protection groups](05-policies-and-groups.md)). To remove
a restore point earlier, an administrator clicks **Delete** in its row on **Snapshots** and confirms.

![Deleting an unlocked snapshot](images/snapshot-delete.png)

- **Delete** appears only when the snapshot's retention lock has expired (**Locked until** shows —). A locked
  snapshot cannot be deleted by anyone; the appliance refuses the request.
- Only the local copy is deleted. An offsite copy stays until the offsite retention removes it; a snapshot that
  exists only offsite has no **Delete**.
- Snapshots replicated from another appliance have no **Delete**: they follow the replication source's retention.
- A snapshot under a [legal hold](#legal-hold) has no **Delete**; the appliance refuses it until the hold is released.
- With approvals enabled, the deletion is a `snapshot.delete` request that a second person approves on
  **Approvals** (see [10 Approvals and audit](10-approvals-and-audit.md)). After approval (or at once with approvals
  disabled) the scheduler deletes the snapshot in a **snapshot_delete** job. The next garbage collection frees the
  space its data used, unless other snapshots share it.

## Legal hold

A legal hold keeps a snapshot for as long as it is needed as evidence or as the last good copy after an incident,
whatever its retention says. While a snapshot is held:

- the protection group's retention, the retention of [snapshots in no group](05-policies-and-groups.md#snapshots-of-objects-in-no-group),
  the offsite retention and the retention of a replication secondary never delete it;
- garbage collection keeps all its data;
- **Delete** is not offered, and a delete request approved earlier fails.

The hold adds protection only; nothing else about the snapshot changes (restores work as usual).

**Setting a hold** is up to the **security officer**, takes effect at once and is recorded in the audit log
(`snapshot.hold`):

- one snapshot: **Legal hold…** in its row on **Snapshots**, enter the reason (case or ticket reference) and
  **Put on hold**;
- many snapshots at once, e.g. everything since an incident began: **Hold a time range…** at the top of
  **Snapshots**, choose the tenant, optionally one guest, the time range and the reason;
- from a change-rate `anomaly` alert: **Hold last good snapshot** on **Alerts** puts the last snapshot before the
  anomaly on hold (see [11 Alerts and monitoring](11-alerts-and-monitoring.md#change-rate-anomalies)).

![Holding every snapshot of a guest in a time range](images/snapshot-hold-range.png)

Held snapshots carry a **Legal hold** badge (hover it for who set it, when and why). **Legal holds only** in the
filter bar lists them.

![Snapshots under a legal hold](images/snapshots-held.png)

**Releasing a hold** needs a second person: a security officer or an administrator clicks **Release hold**, and
another administrator or security officer approves the `snapshot hold release` request on **Approvals** (see
[10 Approvals and audit](10-approvals-and-audit.md)). Until then the badge shows **release requested** and the hold
stays in force. After the release the snapshot follows its retention again and may be deleted by the next run.
The holds and their history (who set and released them, who approved) are also available over the API
(`GET /api/v1/holds`).

On a **replication secondary** the primary's holds are only advice: they show as **Hold advised by <primary>** and
raise a `legal_hold_advisory` alert, but the secondary's retention ignores them until its own security officer
clicks **Apply hold…** (or **Apply hold** on the alert). See
[08 Replication](08-replication.md#legal-holds-from-the-primary).

> **Status:** Retention reads the holds when a job starts; a hold set while a retention job is already running
> applies from the next run. The VM lab verifies that a hold blocks retention; the offsite and replication paths are
> covered by integration tests.

## Restore from the offsite copy

The web UI has no restore from the offsite tier. Restores always read the local store. The offsite engine can
bring a snapshot back from the Storage Box or bucket into the local store
(`nexus-offsite <config.json> restore <source> <time>`), but this is a command-line tool. No UI or API job
exposes it in this version. Rebuilding an appliance from the offsite copy is covered in
[14 Disaster recovery](14-disaster-recovery.md).

> **Status:** Offsite restore and DR were verified with the SFTP test box and MinIO, not yet against a real
> Hetzner Storage Box or a real S3 provider.
