# 05 Policies and protection groups

You do not schedule individual backup jobs. You define **policies** (when to back up, how long to keep, whether to
copy offsite) and **protection groups** (which guests of a source get which policy). The scheduler does the rest.

Only administrators can change policies and groups. Operators can start a group's backup at any time with
**Back up now** on the Dashboard, cancel running jobs and pause groups (see [Run control](#run-control)).

## Policies

Open **Configuration → Policies**.

![Policies](images/policies.png)

**Used by** says how many protection groups use the policy ("no group" for one nobody uses yet); a click on a row
opens the policy.

Click **New policy** (or **Edit** on an existing one) and fill in:

| Field | Meaning |
|---|---|
| **Name** | e.g. `gold`, `databases-hourly` |
| **Tier** | optional: **Bronze**, **Silver** or **Gold**; shown in the SLA report and on the Tenants page (see [Assigned policies and tiers](#assigned-policies-and-tiers)) |
| **Schedule** | when the group's backup runs, in the **time zone of the group** (see [Schedules](#schedules)) |
| **Retention (GFS)** | **Keep all snapshots of the last N hours** (0 = off, see [Frequent runs](#frequent-runs-keep-all-recent-snapshots)), then how many **Daily**, **Weekly**, **Monthly** and **Yearly** restore points to keep (0 = none of that class) |
| **Copy offsite** | upload the snapshots to the tenant's offsite target after each backup |
| **Retries** | how often a failed backup is retried (0–10, default 3) and the minutes between attempts (default 5) |
| **Run-time SLA (minutes)** | optional: raise an `sla_missed` warning when a backup of a group runs longer |
| **Blackout windows** | times in which no scheduled backups start, optionally cancelling running ones |
| **Required consistency** | optional: warn or fail when a snapshot is less consistent than a minimum level (see [Required consistency](#required-consistency)) |
| **Global file excludes** | glob patterns and regular expressions excluded from **every** agent and NFS/SMB source of the policy's groups, on top of each source's own excludes (see [File selection](04-sources.md#file-selection-include-paths-regex-excludes-nested-mounts)) |

![Editing a policy: lowering a retention value needs approval](images/policy-edit.png)

How retention counts is explained in [01 Concepts](01-concepts.md#retention-gfs). A good starting point is the
default 14 daily, 4 weekly, 6 monthly, 2 yearly.

### Restore point preview

Below the retention fields, **Restore point preview** runs the schedule forward for 400 days and applies the same
retention rule the appliance uses after every run:

- the chart shows how many restore points are kept over time (when you edit a policy, the dashed line is the policy
  as it is now, the solid line with your change);
- **Restore points** is the number at the end, split into recent, daily, weekly, monthly and yearly points (a point
  can be several at once, so the sum of the GFS values is an upper bound), and **Oldest restore point then** how far
  back you can restore;
- **Estimated store use**: a compressed full copy of each source plus one run's new data per restore point, from the
  **measured** backups of the policy's groups (for a new policy: of all sources). It is an estimate, not a promise:
  the change between weekly or monthly points is usually smaller than 7 or 30 daily changes, and deduplication across
  sources is not counted. Without measured backups no estimate is shown.

![Restore point preview while editing a policy](images/policy-simulator.png)

The same preview appears on the **Approvals** page for a change that lowers retention, so the approver sees what the
change means (see [10 Approvals and audit](10-approvals-and-audit.md#deciding-requests)).

### Assigned policies and tiers

Service providers sell protection levels. **Create from template** on the Policies page creates a ready-made tier
in one click (its name is the tier's; adjust it afterwards like any policy):

| Tier | Schedule | Retention (daily / weekly / monthly / yearly) | Offsite |
|---|---|---|---|
| **Bronze** | daily 02:00 | 7 / 4 / 3 / 0 | no |
| **Silver** | daily 01:00 | 14 / 8 / 12 / 0 | yes |
| **Gold** | every 6 h at :15 | 30 / 12 / 24 / 7 | yes |

![Creating a policy from a tier template](images/policies-templates.png)

An administrator then **assigns** policies to a tenant: **Configuration → Tenants**, **Edit** in the **Assigned
policies** column. The tenant's **tenant admins** (see [09 Users and access](09-users-and-access.md#tenant-admins-service-providers))
see only these policies (and those its groups already use) and can create or change protection groups only with an
assigned one; administrators are not restricted. Removing an assignment does not change existing groups. A policy
assigned to a tenant cannot be deleted. The tiers of the assigned policies appear as badges next to the tenant's
name, and the **SLA** report names the tier of the policy behind each breach (column `tier`).

![Assigning policies to a tenant](images/tenants-assigned-policies.png)

### Frequent runs: keep all recent snapshots

Sources whose incremental runs are cheap can run every few minutes, above all PostgreSQL cluster backups: a run
on an unchanged base backup sends only the new WAL (see [12 Plugins](12-plugins.md)). Daily/weekly/… retention
would keep only the last snapshot of each day, so a policy for such a group sets **Keep all snapshots of the last
N hours**, for example `every 15m` with 24 hours: every snapshot of the last 24 hours stays (96 restore points,
each a point-in-time restore range), older ones are thinned out to one per day, week, month and year.

![A policy for WAL-only runs every 15 minutes](images/policy-wal-frequent.png)

- The hours count back from the **newest** snapshot of the object, not from now: if backups stop, nothing of the
  last day is pruned.
- Snapshots kept only for this reason are not locked beyond the lock every new snapshot gets when it is written
  (the store's minimum lock, 14 days by default). They are pruned once that lock has expired, so on an appliance
  with the default minimum lock the store keeps 14 days of 15-minute snapshots anyway; the space is small because
  they share their data with each other.
- Lowering the hours shortens retention and needs approval, like lowering any other class.
- Offsite copies and replication keep the daily/weekly/monthly/yearly classes only.

Rules:

- **Lowering** any retention value, switching **Copy offsite** off, **adding a blackout window**, **relaxing the
  required consistency** (a milder action, or a lower minimum level) or **adding a global file exclude** weakens
  protection. With approvals enabled the change becomes an approval request ("Pending approval: request #N …") and
  takes effect only after another administrator or security officer approves it. Raising values, removing blackout
  windows or global excludes, a stricter consistency requirement and changing the schedule, retries or SLA take
  effect immediately.
- Lowering retention never shortens existing retention locks. Snapshots that are locked stay until their lock
  expires, even if the new policy would no longer keep them.
- Deleting a policy needs approval (when approvals are enabled).
- **Copy offsite** only has an effect if the group's tenant has an offsite target
  (see [07 Offsite copies](07-offsite.md)).

### When backups run

- The scheduler checks every 30 seconds and queues a group's backup once per schedule period.
- If the appliance was down when backups were due, it runs **one** catch-up backup per group after it is back, not one
  per missed period. The same applies to a slot that passed while the group was paused, its source was in
  maintenance or a blackout window was active: it runs once when that ends.
- A failed backup is retried for the guests that failed (see [Retries](#retries)).
- At most one job per source runs at a time; further jobs of that source wait in the queue.
- After each successful backup the scheduler runs **retention** for that source and then, if the policy has
  **Copy offsite**, the **offsite copy** of the tenant.
- Garbage collection and verification run once a day per tenant (daily maintenance at 03:00 UTC).

The schedule also sets the recovery point objective (RPO) the Dashboard measures against: 24 hours for a daily
schedule, 1 hour for an hourly one, N hours for `every Nh`, the longest gap between two run days for a weekday
schedule (e.g. 3 days for `Mon-Fri`) and 31 days for a monthly one. Its key figures count an object as **RPO breached** when the last good backup is
older than 1.5 × the RPO (36 hours or 90 minutes). The **Protection status** table below them uses the same
rule: a guest shows **RPO breached** when its newest snapshot is older than 1.5 × the policy period. Guests of a paused group
(or of a source in maintenance) show **Paused** instead and do not count as breaches. See
[03 The web interface](03-web-interface.md#dashboard).

## Protection groups

Open **Configuration → Protection groups**.

![Protection groups](images/groups.png)

The list shows for every group its **Last backup** (state and how long ago; a click opens that job; "never backed
up" for a new group) and when the policy's schedule starts the **next** one. It refreshes every 15 seconds while the
page is open. A click on a row opens the group's settings.

A group belongs to one tenant and one source and uses one policy. Click **New group** and choose **Tenant**,
**Name**, **Source** (only sources of that tenant are offered), **Policy** and **Time zone** (an IANA name such as
`Europe/Berlin`; default `UTC`: the policy's schedule and blackout windows are evaluated in it). What you select next depends on the
kind of source:

| Source kind | What the group backs up |
|---|---|
| Proxmox VE cluster | the VMs and containers you list in **Guests (VM/CT IDs, comma separated)**, e.g. `100, 101, 200`, or all of them / those with given tags ([auto-protect](#auto-protect-all-guests-or-guests-by-tag)) |
| Linux or Windows host (agent) | the agent's host, with the paths configured in the source (nothing to select) |
| TrueNAS (ZFS datasets) | the datasets you tick; none ticked = **All guests**: every dataset of the source, including datasets added to the source later |
| NFS share / SMB share | the whole share (nothing to select) |
| Plugin source with guests (e.g. PostgreSQL) | the guests you tick after **Load …**; none ticked = the whole source (Microsoft 365: at least one user, site or team must be ticked) |
| Plugin source without guests | the whole source as configured |

![A protection group of Proxmox VE guests](images/group-pve.png)

![A TrueNAS group: choose datasets](images/group-truenas.png)

For plugin sources that offer guests, click **Load …** (for PostgreSQL: **Load Databases**). The appliance starts a
short **List plugin guests** job that asks the source what it has and then shows check boxes.

![PostgreSQL group after loading the databases](images/group-postgresql.png)

For PostgreSQL the choice matters:

- Ticked databases are backed up as **logical dumps**, one snapshot per database
  (`plugin-postgresql-<source>-<database>`). They can be restored into a database.
- No database ticked backs up the **whole cluster** (base backup plus WAL, snapshot `plugin-postgresql-<source>`).
  Only this kind of snapshot supports point-in-time restore.

You can create two groups on the same PostgreSQL source (one with databases, one without) to get both, as the demo
does with `acme-databases` and `acme-pg-cluster`. See [04 Sources](04-sources.md) and [06 Restores](06-restores.md).

### Auto-protect: all guests or guests by tag

For sources with a guest inventory (Proxmox VE clusters, TrueNAS sources and plugin sources whose kind lists guests,
such as PostgreSQL or Microsoft 365) the group dialog offers **What to protect**:

| Choice | The group protects |
|---|---|
| **Selected guests** | exactly the guests you list or tick (as before) |
| **All guests** | every guest the source lists, now and in future |
| **By tag or pool** | every guest with at least one of the ticked **Tags** |

The guests come from the source's **inventory** (see [04 Sources](04-sources.md#guest-inventory)), which the
appliance refreshes every hour and when you click **Refresh inventory**. A new VM in a selected pool, or a new
Microsoft 365 user, is therefore backed up from the first backup after the next refresh, without anyone editing the
group. The audit log records it (`group.auto_protect`, with the new guests); guests that disappear from the source
are no longer selected (their snapshots stay).

Tags you can select:

| Tag | Meaning |
|---|---|
| `pool:<pool>` | member of the Proxmox VE resource pool (TrueNAS: the ZFS pool of the dataset) |
| `tag:<tag>` | Proxmox VE tag of the VM or container |
| `node:<node>` | Proxmox VE node the guest runs on (changes with migrations) |
| `type:qemu`, `type:lxc` | Proxmox VE VM or container |
| `type:user`, `type:site`, `type:team`, `type:group` | Microsoft 365 object type |
| `license:none` | Microsoft 365 user without any license |
| `site:team` | Microsoft 365 site that belongs to a team or group (backed up with the team or group) |

Guests tagged `license:none` or `site:team` are **left out** of groups of mode **All guests**, and of tag groups that
do not select that tag explicitly: unlicensed accounts usually have no mailbox or OneDrive, and team sites would
otherwise be backed up twice. To back them up anyway, select the tag (for example `license:none`) in a tag group,
or tick the guests in a group with an explicit list.

The tag list shows the tags the inventory currently contains; type a tag and click **Add tag** to select one that no
guest has yet. **Exclusions** lists the guests the selection matches: ticked guests are never backed up by this group,
even if they match (exclusions always win). The line below shows how many guests the group protects right now.

![An auto-protect group: PVE pool "dev" without the build runner](images/group-auto.png)

Notes:

- Before the first inventory refresh an **All guests** or **By tag or pool** group protects nothing. Its backup fails
  with "nothing to back up" and raises a `job_failed` alert; click **Refresh inventory** after creating the group.
- `node:` tags follow migrations: a group selecting `node:pve1` loses a VM that moves to another node. Prefer pools and
  PVE tags.
- Agent hosts and NFS/SMB shares have no inventory: their groups are always **Selected guests**.
- When the inventory cannot be refreshed (source unreachable), the last listing stays in effect and an
  `inventory_refresh` warning is raised (once while it is open).
- Microsoft 365 tags by Entra group (`group:<name>`) are not available yet.

### File index of VM/CT disks

Files of host, TrueNAS, NFS/SMB and plugin snapshots are always findable under **Monitor → Find files**
([06 Restores](06-restores.md#find-a-file)). For VM and container snapshots it is a setting of the Proxmox VE group:
**File index: On (default) / Off** in the group's dialog. New Proxmox VE groups have it on; the list of groups shows a
**File index** label for them.

![Group dialog: file index and file search scope](images/group-search-scope.png)

After each backup of the group, the appliance queues a **File index** job per VM or container snapshot. For a VM it
reads the partition tables and file systems of the backed-up disks itself, with a sandboxed parser that only reads
(no VM is booted, nothing is mounted): GPT and MBR partitions, LVM (linear, striped, mirrored, thin), Windows dynamic
disks (simple, spanned and mirrored volumes), ext4, NTFS, XFS, btrfs (single disk), FAT and exFAT. ZFS and btrfs
spread over several disks are listed with the restore micro-VM instead. A container's stored tar stream is read
directly. Only the metadata of changed volumes and folders is read again, so the job usually takes seconds to a few
minutes. Linux paths are shown with their mount points from the guest's `/etc/fstab`, Windows paths with the drive
letters from the guest's registry (`C:` for the system volume when the registry does not say). The index also keeps
each file's owner (Windows account SID, Linux user and group number); the search API returns it with each version
of a hit (`versions[].owner`, with `owner_name` for Windows' built-in accounts and groups). **Find files** filters by
owner (**More filters → Owner**): a Linux uid (any group) or `uid:gid`, a Windows SID, or a built-in Windows name
such as `Administrators`, `SYSTEM` or `Users` (API: `owner=`, comma separated). Names of domain and local accounts and
of Linux users are not resolved yet; search by SID or uid.
Volumes the parser cannot read (BitLocker or LUKS encryption, ReFS, Storage Spaces, striped or RAID-5 dynamic volumes)
are skipped and reported per snapshot (**partly indexed** on the Snapshots page and in the search). Only snapshots
taken while the setting is on are indexed. Turning it on or off is recorded in the audit log (`group.index_files`).

### File search scope

**File search scope** in the group's dialog (every kind of group) decides which folders of the group's sources go
into the search index. It never limits backups, browsing, downloads or restores: a file outside the scope is still in
the snapshot, it is just not found by **Find files**.

- **Leave out system folders (recommended)**, on by default, leaves out `/$Recycle.Bin`, `/Windows`,
  `/Program Files`, `/Program Files (x86)`, `/ProgramData`, `/System Volume Information`, `/Users/*/AppData`,
  `/Recovery`, `/proc`, `/sys`, `/dev`, `/run`, `/tmp`, `/usr`, `/lib`, `/lib64`, `/boot`, `/var/cache`,
  `/var/tmp`, `/var/lib/docker` and `/var/lib/containerd`. `/var` itself stays searchable (databases, web and mail
  data live there).
- **Include anyway** and **Leave out** take one rule per line, at most 64 each: absolute paths with `/` separators
  (also for Windows), `*` matches within one folder name (`/Users/*/Downloads`). `/C/…` applies to one Windows drive,
  `/…` to every drive. The most specific (longest) rule wins, so `/var/log` under **Include anyway** brings back the
  logs of an otherwise left-out tree, and `/data/tmp` under **Leave out** hides a scratch folder.

Changing the rules re-reads the existing file lists into the search index (no backup or disk read is needed). It
needs an administrator or a tenant administrator and is recorded in the audit log (`group.index_rules`).

### Threat detection: scheduled scans and file hashes

The **Threat detection** part of a group's dialog (every source kind) has two options:

- **Scheduled malware scan:** **Off**, **Daily** at a time, or a **Custom schedule** (the same forms as a policy
  schedule), in the group's time zone, and an optional **Time budget per scan** (minutes, default 240). When the
  schedule is due, the newest local snapshot of each guest or source of the group that has not been scanned yet is
  scanned with the YARA rules from **Settings → Malware scan**, one scan at a time inside the restore micro-VM.
  Without rules nothing is scanned (saving the option says so). The list of groups shows **Scan: daily 03:00**.
  Details and the recovery calendar: [11 Alerts and monitoring](11-alerts-and-monitoring.md#scheduled-scans-and-the-recovery-calendar).
- **Record file hashes (IOC hash hunt):** the SHA-256 of every file is stored in the snapshot's sealed file index,
  so the **Hash hunt** page can search all snapshots for known-bad files without a restore. Agents with the
  capability (version with Phase 28) compute the hashes while they read; for older agents, shares, TrueNAS
  datasets and plugin file trees the appliance computes them, and unchanged files take the hash of the previous
  snapshot. The first backup after switching it on reads the files once more from the store, so it takes longer.
  Containers and VM disks (NTFS, ext4, XFS, btrfs, FAT and exFAT volumes) are hashed together with **Index
  files in VM/CT disks**: the
  first file index after switching it on reads every file of the guest's disks once (up to half of the job's time;
  files left over are hashed with the next snapshot), later ones only the changed folders. The list of groups shows
  **File hashes**. See [11 Alerts and monitoring](11-alerts-and-monitoring.md#ioc-hash-hunt).

![Protection group: threat detection](images/group-threat-scan.png)

Both options apply at once (no approval: they only add detection) and are audited (`group.threat_scan`,
`group.file_hashes`). Administrators and tenant administrators set them here; security officers can set the scan
schedule through the API (`PUT /api/v1/groups/{id}/threat-scan`).

### Full read (change-tracking check)

Incremental backups trust **change tracking**: the dirty bitmap of a Proxmox VM, VMware's changed block tracking (CBT), the agents' metadata cache (size,
modification time, inode) or the Windows USN journal, the metadata cache of NFS/SMB shares and `zfs diff` on
TrueNAS. If the tracker misses a change (a crash of the PVE host while the VM wrote, a file changed with its old
modification time restored, a journal that wrapped), the snapshots look fine but lack that change. A scheduled
**full read** finds this out.

**Full read (change-tracking check) → Days between full reads** in the group's dialog: every this many days the next
backup of each guest or source of the group reads everything instead of trusting the tracker, still asks the tracker
what it would have reported, and compares the result with the previous snapshot. Data that changed although the
tracker did not report it is **unreported**. Empty = the default (**90 days** for Proxmox VE and VMware groups, **30 days** for
agents, NFS/SMB shares and TrueNAS), **0** = off. Containers and plugin sources have no full read (containers are
read in full by every backup anyway); XCP-ng groups have none yet.

![Protection group: full read](images/group-full-read.png)

The full-read backup is a normal snapshot (complete and usable). It takes as long as a first backup and moves the
whole source over the network, so a long interval suits large VMs. The result of each source is shown on the
**Dashboard** in the **Change tracking** card ([11 Alerts and monitoring](11-alerts-and-monitoring.md#change-tracking-scheduled-full-reads));
a source with unreported changes raises the critical alert `change_tracking`. The interval applies at once (no
approval) and is audited (`group.full_read`); administrators and tenant administrators set it, through the API
`PUT /api/v1/groups/{id}/full-read {"days": null | 0..365}`.

> **Status:** Implemented in Phase 29 (scheduler, connectors and API tests, demo backend); a lab run with a real
> PVE dirty bitmap and the Windows agent's USN journal is pending.

### Excluded disks and parallel guests (Proxmox VE)

A Proxmox VE group has two more settings in its dialog:

- **Excluded disks (all guests)** and **Excluded disks per guest** (fieldset **Disk selection**, one line per guest: `101: scsi2`): disk keys of the guest configuration that are **not** backed up, e.g. `scsi1` (a scratch or
  swap disk) or `virtio2`. Enter them for **all guests of the group** or for single guests (by VM ID). Disks that
  have `backup=0` in Proxmox VE are skipped by PVE itself as before; the job log names them ("disk scsi2 of VM 101
  has backup=0: skipped by PVE"), and excluded disks too ("excluded disk scsi1 of VM 101 (… bytes): not backed up").
  A VM with `backup=0` disks ends the job **with a warning** (Dashboard, Jobs), so a system disk that someone excluded
  in PVE does not go unnoticed. Check `backup=0` on the VM's disks when a VM backup is suspiciously small.
  Containers are not affected: exclude a mount point there with `backup=0` in PVE.
- **On restore, excluded disks are**:
  - **recreated empty (original size and settings)** (default): the restored VM gets the disk with its original size and options, filled with
    zeros, so the VM configuration stays complete (boot order, `/etc/fstab` on the guest still find a disk);
  - **left out of the restored VM**: the restored VM has no such disk (its line is removed from the configuration).
  The choice is stored in each snapshot at backup time; changing it later affects new snapshots only. Instant
  recovery always leaves excluded disks out.
- **Guests backed up at once** (1–8, default 4 for new groups): how many guests of the group are backed up in parallel.
  Proxmox VE runs one backup (vzdump) per node at a time, so the appliance backs up **at most one guest per node**
  across all groups and jobs: the setting is in effect how many nodes work for this group at once, and on a single
  node the guests run one after the other whatever it says. Several groups of the same cluster run at the same time
  (each on nodes the others leave free), and a guest that is in two groups is never backed up twice at once. Snapshots, the
  per-guest statistics, retries of failed guests and **Cancel** work per guest as before; a cancel stops every running
  vzdump task. The same setting runs several guests of a **plugin** group (e.g. several PostgreSQL databases) at once.
  The source can cap it (**Guests at once (source cap)**, and per PVE storage, see
  [04 Sources](04-sources.md#limits-guests-at-once-busy-storages-read-rate)).

Excluding another disk backs up less: like a weaker policy it needs approval when approvals are enabled. Removing an
excluded disk, the restore choice and **Guests backed up at once** take effect immediately.

![A Proxmox VE group with an excluded disk and two guests at once](images/group-disks.png)

> **Status:** Proxmox VE may run only one vzdump at a time on a node (its global vzdump lock): guests on the same node
> then wait for each other and parallel backups only help across nodes. This, the empty-disk restore and the
> cancellation of parallel vzdump tasks are covered by unit and scheduler tests; the VM lab run is pending.

### Changing and deleting groups

- **Edit** lets you change the name, source, policy, guests, the **What to protect** choice, tags and exclusions. Moving a group to a policy that is weaker in any
  respect (a lower retention value, no offsite copy, more global excludes) or excluding another disk needs approval,
  like weakening the policy itself.

- **Delete** needs approval when approvals are enabled. Deleting a group stops future backups. Existing snapshots are
  not deleted.

### Snapshots of objects in no group

Retention normally runs after a group's backups, with that group's policy. Snapshots of a guest, host, dataset or
share that no longer belongs to any group of its tenant (the guest was removed from its group, the group was deleted,
or it was backed up once by hand) are *orphaned*. The daily maintenance prunes them before garbage collection with the
default retention (14 daily, 4 weekly, 6 monthly, 2 yearly), so the newest restore points stay and the space of the
older ones is freed. Retention locks are respected as always. The first time this happens for an object, an `orphaned`
info alert names it (see [11 Alerts and monitoring](11-alerts-and-monitoring.md)).

- Put the object into a group again to give it that group's retention instead.
- To remove restore points you no longer need before they expire, delete them one by one on **Snapshots** once their
  lock has expired (see [06 Restores](06-restores.md#deleting-a-snapshot)).
- Tenants replicated from another appliance are not affected: their snapshots follow the replication source's
  retention.

> **Status:** The default retention for orphaned snapshots can be changed only in the catalog setting `orphan_gfs`
> (JSON like a policy's retention, e.g. `{"daily":7,"weekly":4,"monthly":3,"yearly":1}`); there is no page for it yet.
- Groups cannot be created in a tenant that is replicated from another appliance: replicated tenants receive no local
  backups (see [08 Replication](08-replication.md)).

## Run control

### Schedules

The schedule editor offers five kinds; the **Schedule string** below it is what is stored (you can also type it):

| Kind | Schedule string | Runs |
|---|---|---|
| Daily | `daily 01:30` | every day at 01:30 |
| Every N minutes | `every 15m` | every 15 minutes from the full hour (:00, :15, :30, :45; N = 5, 6, 10, 12, 15, 20 or 30) |
| Every N hours | `hourly 15`, `every 6h at 15` | every hour at :15; every 6 hours at 00:15, 06:15, 12:15, 18:15 (N = 1, 2, 3, 4, 6, 8 or 12) |
| On weekdays | `Mon,Wed,Fri 22:00`, `Mon-Fri 20:00` | on the listed days (`Mon` … `Sun`, lists and ranges) |
| Monthly | `monthly 1 03:00` | on that day of the month (a month without day 29–31 runs on its last day) |

All times are in the **time zone of the group**. Daylight saving time is handled: a time that does not exist on the
day the clocks go forward (for example 02:30 in Central Europe) runs one hour later (03:30); a time that occurs twice
when the clocks go back runs once. Groups created before this release use `UTC`, so their backups keep their times.

### Retries

When a group's backup fails, the scheduler queues a new attempt after **Minutes between attempts**, for **the guests
that failed** only (the ones without a committed snapshot in the job log; if that cannot be told, for example for a
share, the whole group). The failed job's log ends with `attempt 1 of 4 failed; retry as job N in 5 min`, and the
job list shows the attempt number. The `job_failed` alert is raised only after the last attempt failed
("… failed after 4 attempts: …"). Retries apply to scheduled and manual group backups; they are not created while
the group is paused or its source is in maintenance. Set **Retries after a failure** to 0 to alert on the first
failure.

### Blackout windows

![A policy with a weekday schedule, retries and a blackout window](images/policy-runcontrol.png)

A blackout window is a time range (**From**, **To**, in the group's time zone) on the selected start days (none
selected = every day). A window whose end is before its start runs over midnight (e.g. 22:00–06:00). Inside a
window the scheduler starts no scheduled backups; a slot that falls into the window runs when it ends. **Back up
now** stays possible; the dialog warns that a window is active. Retries are not held by a window.

With **Cancel running backups when the window starts**, a backup of the policy's groups that started before the
window and is still running when it begins is cancelled (as if an operator had cancelled it, actor `blackout` in the
job). A backup started by hand inside the window is left alone.

Adding a window needs approval when approvals are enabled (it reduces protection); removing one does not.

### Run-time SLA

With **Run-time SLA (minutes)** set, a group backup that is still running after that time raises one
`sla_missed` warning per job (see [11 Alerts and monitoring](11-alerts-and-monitoring.md)). The job keeps running.

### Required consistency

Every snapshot records how consistent it is: **application**, **crash**, **inconsistent** or **unknown** (see
[06 Restores](06-restores.md#consistency)). Under **Required consistency** a policy sets:

- **If a snapshot falls short**: **Do nothing** (default), **Warn (alert)** or **Fail the job (and warn)**.
- **Minimum level**: **Application-consistent** or **Crash-consistent (point in time)**. **inconsistent** and
  **unknown** never meet a minimum.

With **Warn**, a snapshot below the minimum raises one `consistency` warning per guest (alert key
`consistency:<tenant>/<guest>`). It resolves by itself with the next snapshot of that guest that meets the minimum.
With **Fail**, the backup job also ends **failed**: the snapshot is kept (it is still a restore point), and the job is
retried like any failed backup, which helps when, say, the guest agent was not running yet.
The requirement applies to backups of the policy's groups (scheduled, **Back up now** and retries). A backup of a
single VM through the API outside a group is not checked.

Typical settings: **Warn** at **Application-consistent** for database servers (finds VMs whose guest agent stopped
working), **Fail** at **Crash-consistent** for file servers backed up by an agent (finds hosts read without a
snapshot).

### Pausing a group

**Pause** on the Protection groups page stops scheduled backups of the group for 1–30 days or until **Resume**.
Manual backups stay possible, and nothing is deleted. A paused group shows a **Paused** badge, and the Dashboard shows
its guests as **Paused** instead of overdue. A pause of more than 7 days (or until resumed) raises a `paused` warning,
so a forgotten pause does not go unnoticed. Pausing needs no approval but is recorded in the audit log
(`group.pause`, `group.resume`). The Protection groups page is for administrators; operators may pause and resume
too, through the API (`POST /api/v1/groups/{id}/pause` with `{"until": <unix time>}` or `{}` for "until resumed",
`POST /api/v1/groups/{id}/resume`).

![Pausing a group](images/group-pause.png)

To stop backups of all groups of a source (for example during a host upgrade), put the source into
[maintenance](04-sources.md#maintenance) instead.

### Back up now

**Back up now** (Protection groups page or Dashboard) asks what to back up:

- **All guests of the group**,
- **Selected guests** (groups with more than one guest), or
- **Guests that failed in the last run**: refused when the group's last finished run did not fail.

**Keep these snapshots until a date** (under **Retention**) keeps the snapshots this run writes at least until the
end of the chosen day, in addition to the policy (for example before a migration, or the year-end state): they get a
**store lock** to that date. Retention, garbage collection and **Delete** cannot remove them before, and nobody can
shorten the lock, not even an administrator. The snapshots still count as ordinary restore points of the policy.
Because such a lock cannot be undone and holds storage, a date further out than the limit under **Settings →
Approvals → Backups kept until a date** (90 days by default, at most 10 years) needs approval: the backup starts
once a second person approved it. Lowering that limit applies at once, raising it needs approval. The lock shows as
**Locked until** on the Snapshots page; offsite copies keep their own retention.

![Back up now and keep the snapshots until a date](images/backup-keep.png)

![Back up now inside a blackout window](images/group-backup-now.png)

![Back up now for selected guests](images/group-backup-guests.png)

Running jobs can be cancelled from the job list or the job's page (see
[03 The web interface](03-web-interface.md#jobs)).

## Tips

- Put guests with the same recovery requirements into one group; a group's backup runs them one after the other.
- Use an hourly schedule (`hourly MM`) only where one backup run is short. A logical PostgreSQL dump, for example,
  reads the whole database on every run (storage stays small thanks to deduplication).
- Check the Dashboard the morning after you create a group: every guest should be **Protected**, and nothing of the
  group should appear under **Objects needing attention**.
- Objects counted as **Not in a group** on the Dashboard are known to the appliance (from the inventory of each
  source, enrolled agents and NFS/SMB sources) but not backed up. The Dashboard lists them under **Not in a group**;
  add them to a group, use an **All guests** group, or decide consciously to leave them out (an exclusion documents
  that decision).
