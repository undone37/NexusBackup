# 05 Policies and protection groups

You do not schedule individual backup jobs. You define **policies** (when to back up, how long to keep, whether to
copy offsite) and **protection groups** (which guests of a source get which policy). The scheduler does the rest.

Only administrators can change policies and groups. Operators can start a group's backup at any time with
**Back up now** on the Dashboard, cancel running jobs and pause groups (see [Run control](#run-control)).

## Policies

Open **Configuration → Policies**.

![Policies](images/policies.png)

Click **New policy** (or **Edit** on an existing one) and fill in:

| Field | Meaning |
|---|---|
| **Name** | e.g. `gold`, `databases-hourly` |
| **Schedule** | when the group's backup runs, in the **time zone of the group** (see [Schedules](#schedules)) |
| **Retention (GFS)** | how many **Daily**, **Weekly**, **Monthly** and **Yearly** restore points to keep (0 = none of that class) |
| **Copy offsite** | upload the snapshots to the tenant's offsite target after each backup |
| **Retries** | how often a failed backup is retried (0–10, default 3) and the minutes between attempts (default 5) |
| **Run-time SLA (minutes)** | optional: raise an `sla_missed` warning when a backup of a group runs longer |
| **Blackout windows** | times in which no scheduled backups start, optionally cancelling running ones |

![Editing a policy: lowering a retention value needs approval](images/policy-edit.png)

How retention counts is explained in [01 Concepts](01-concepts.md#retention-gfs). A good starting point is the
default 14 daily, 4 weekly, 6 monthly, 2 yearly.

Rules:

- **Lowering** any retention value, switching **Copy offsite** off or **adding a blackout window** weakens
  protection. With approvals enabled the change becomes an approval request ("Pending approval: request #N …") and
  takes effect only after another administrator or security officer approves it. Raising values, removing blackout
  windows and changing the schedule, retries or SLA take effect immediately.
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
rule: a guest is **Overdue** when its newest snapshot is older than 1.5 × the policy period. Guests of a paused group
(or of a source in maintenance) show **Paused** instead and do not count as breaches. See
[03 The web interface](03-web-interface.md#dashboard).

## Protection groups

Open **Configuration → Protection groups**.

![Protection groups](images/groups.png)

A group belongs to one tenant and one source and uses one policy. Click **New group** and choose **Tenant**,
**Name**, **Source** (only sources of that tenant are offered), **Policy** and **Time zone** (an IANA name such as
`Europe/Berlin`; default `UTC`: the policy's schedule and blackout windows are evaluated in it). What you select next depends on the
kind of source:

| Source kind | What the group backs up |
|---|---|
| Proxmox VE cluster | the VMs and containers you list in **Guests (VM/CT IDs, comma separated)**, e.g. `100, 101, 200` |
| Linux or Windows host (agent) | the agent's host, with the paths configured in the source (nothing to select) |
| TrueNAS (ZFS datasets) | the datasets you tick; none ticked = all datasets of the source |
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

### Changing and deleting groups

- **Edit** lets you change the name, source, policy and guests. Moving a group to a policy that is weaker in any
  respect (a lower retention value or no offsite copy) needs approval, like weakening the policy itself.
- **Delete** needs approval when approvals are enabled. Deleting a group stops future backups. Existing snapshots are
  not deleted.

> **Status:** Retention runs as part of a group's backups, with that group's policy. Snapshots of guests that no
> longer belong to any group are therefore not pruned automatically, and the web interface has no function to delete
> individual snapshots. They keep using space until the guest is in a group again.
- Groups cannot be created in a tenant that is replicated from another appliance: replicated tenants receive no local
  backups (see [08 Replication](08-replication.md)).

## Run control

### Schedules

The schedule editor offers four kinds; the **Schedule string** below it is what is stored (you can also type it):

| Kind | Schedule string | Runs |
|---|---|---|
| Daily | `daily 01:30` | every day at 01:30 |
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
- Objects counted as **Not in a group** on the Dashboard are known to the appliance (e.g. VMs of a connected cluster)
  but not backed up; add them to a group or decide consciously to leave them out.
