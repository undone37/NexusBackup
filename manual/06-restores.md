# 06 Restores

Every restore starts on the **Snapshots** page. Pick a snapshot, choose the restore type, and the appliance queues
a job. The job's detail page shows its log live. The appliance initiates every connection, as it does for
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

![Snapshots of tenant initech with restore buttons](images/snapshots.png)

## Which restore buttons a snapshot offers

The snapshot name tells you what was backed up. The buttons follow from it:

| Snapshot name | Source | Buttons |
|---|---|---|
| `vm-<id>` | Proxmox VE virtual machine | **Restore**, **Instant recover**, **Browse files** |
| `ct-<id>` | Proxmox VE container | **Restore**, **Browse files** |
| `host-<agent id>` | Linux/Windows host (agent) | **Restore to path**, **Browse files** |
| `nas-<source>-<pool.dataset>` | TrueNAS dataset (built-in connector) | **Browse files** (download only) |
| `share-<source>` | NFS / SMB share | **Browse files** (download only) |
| `plugin-<plugin>-<source>[-<guest>]` | plugin source, e.g. PostgreSQL or Microsoft 365 | the plugin's restores, plus its download button |

Use the **Tenant** and **Guest (e.g. vm-100)** filters to narrow the list. Each row shows **Local**,
**Offsite** and **Verified** marks and the **Locked until** date. A locked snapshot cannot be deleted
before that date (see [01 Concepts](01-concepts.md)).

## Restore a VM or container (full restore)

1. On **Snapshots**, click **Restore** on the snapshot.
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

1. Click **Instant recover** on a `vm-` snapshot.
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
- For TrueNAS datasets and NFS/SMB shares, download is the only restore in this version. There is no restore
  back to the dataset or share.

## Restore files to a host (agents)

For `host-` snapshots, the agent writes the files back onto a host.

1. Either click **Restore to path** on the snapshot (restores everything), or open **Browse files**, select
   paths and click **Restore to path** (with nothing selected the button reads **Restore everything to
   path**).
2. Fill in the dialog:
   - **Target directory on the host**: an absolute path, e.g. `/srv/restore`. The restored paths keep
     their structure below it. The directory is created if missing.
   - **Existing files**: **Never overwrite (skip existing files)**, **Overwrite if older than the backup
     copy**, or **Always overwrite**. Restoring onto `/` (or a Windows drive root) is refused unless you
     choose **Always overwrite**.
   - **Target agent**: by default the host the backup came from. Any enrolled agent of the same tenant can
     receive the files.
   - **Confirmation**: type the target agent's name. The appliance checks it, and the agent logs it.
3. Click **Start restore**.

![Restore files to a host](images/restore-to-path.png)

The agent writes only below the target directory. It never follows symlinks or junctions planted in the target,
and it restores owners, modes, extended attributes, ACLs and modification times. Skipped files (kept by the
overwrite policy) appear in the log, not as errors.

On Windows, write paths as `/D/restore` or `D:\restore`. The agent restores security descriptors, alternate
data streams and attributes. The security descriptor of a directory that already exists is only replaced
with **Always overwrite**. EFS-encrypted files are not supported.

> **Status:** Linux restore was tested in the agent VM lab (Debian, AlmaLinux, Ubuntu, Fedora). The Windows
> agent has been built and unit-tested only. It has never run on Windows, so treat Windows restores as
> untested.

## Plugin restores (PostgreSQL)

Plugin snapshots offer the restores declared by the plugin. Restores marked **application-specific** do more
than copy files. The download button of a plugin uses its own title. In the file browser, application
streams such as database dumps and WAL appear under `.nexus-streams/`.

The PostgreSQL plugin ([12 Plugins](12-plugins.md)) produces two kinds of snapshots:

| Snapshot | Contains | Useful restores |
|---|---|---|
| `plugin-postgresql-<source>-<db>` | logical dump of one database (stream `<db>.sql`) | **Restore database dump to a server**, download |
| `plugin-postgresql-<source>` (group without databases) | the whole cluster: `data/` (base backup) and `wal/` | **Point-in-time restore (new data directory via SSH)**, download |

The snapshot list shows every restore of the plugin on every PostgreSQL snapshot. Use the dump restore on
database snapshots and the point-in-time restore on cluster snapshots.

### Restore a database dump to a server

1. Click **Restore database dump to a server** on a database snapshot.
2. Enter the **Target database**, choose **Server** (`source` = the backed-up server, `alternate` = the
   **Alternate restore server** configured in the source), and tick **Restore into an existing database**
   only if you really want that.
3. Click **Start**.

![Dump restore dialog](images/snapshot-pg-to-target.png)

On the source server the backup role needs `CREATEDB`. The alternate server's user needs `CREATEDB` too.
A logical dump does not cover owners and grants, comments, RLS policies, large objects, roles and some other
objects (a warning in each backup log names those present). Use a cluster backup where these matter.

### Point-in-time restore

1. Click **Point-in-time restore (new data directory via SSH)** on a cluster snapshot.
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
restores. None of them overwrites anything in Microsoft 365: restores always write into a **new** folder,
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

1. Click **Restore to the original user / site / team (into a new folder)** on the snapshot.
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

Use **Restore to another user / site / team (into a new folder)**, for example to give a successor the mailbox
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

## Restore from the offsite copy

The web UI has no restore from the offsite tier. Restores always read the local store. The offsite engine can
bring a snapshot back from the Storage Box or bucket into the local store
(`nexus-offsite <config.json> restore <source> <time>`), but this is a command-line tool. No UI or API job
exposes it in this version. Rebuilding an appliance from the offsite copy is covered in
[14 Disaster recovery](14-disaster-recovery.md).

> **Status:** Offsite restore and DR were verified with the SFTP test box and MinIO, not yet against a real
> Hetzner Storage Box or a real S3 provider.
