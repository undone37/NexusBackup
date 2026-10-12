# 05 Policies and protection groups

You do not schedule individual backup jobs. You define **policies** (when to back up, how long to keep, whether to
copy offsite) and **protection groups** (which guests of a source get which policy). The scheduler does the rest.

Only administrators can change policies and groups. Operators can start a group's backup at any time with
**Back up now** on the Dashboard.

## Policies

Open **Configuration → Policies**.

![Policies](images/policies.png)

Click **New policy** (or **Edit** on an existing one) and fill in:

| Field | Meaning |
|---|---|
| **Name** | e.g. `gold`, `databases-hourly` |
| **Schedule** | `daily HH:MM` (once a day at that time) or `hourly MM` (every hour at that minute). Times are **UTC**. |
| **Retention (GFS)** | how many **Daily**, **Weekly**, **Monthly** and **Yearly** restore points to keep (0 = none of that class) |
| **Copy offsite** | upload the snapshots to the tenant's offsite target after each backup |

![Editing a policy: lowering a retention value needs approval](images/policy-edit.png)

How retention counts is explained in [01 Concepts](01-concepts.md#retention-gfs). A good starting point is the
default 14 daily, 4 weekly, 6 monthly, 2 yearly.

Rules:

- **Lowering** any retention value or switching **Copy offsite** off weakens protection. With approvals enabled the
  change becomes an approval request ("Pending approval: request #N …") and takes effect only after another
  administrator or security officer approves it. Raising values and changing the schedule take effect immediately.
- Lowering retention never shortens existing retention locks. Snapshots that are locked stay until their lock
  expires, even if the new policy would no longer keep them.
- Deleting a policy needs approval (when approvals are enabled).
- **Copy offsite** only has an effect if the group's tenant has an offsite target
  (see [07 Offsite copies](07-offsite.md)).

### When backups run

- The scheduler checks every 30 seconds and queues a group's backup once per schedule period.
- If the appliance was down when backups were due, it runs **one** catch-up backup per group after it is back, not one
  per missed period.
- At most one job per source runs at a time; further jobs of that source wait in the queue.
- After each successful backup the scheduler runs **retention** for that source and then, if the policy has
  **Copy offsite**, the **offsite copy** of the tenant.
- Garbage collection and verification run once a day per tenant (daily maintenance at 03:00 UTC).

The schedule also sets the recovery point objective (RPO) the Dashboard measures against: 24 hours for a daily
schedule, 1 hour for an hourly one. Its key figures count an object as **RPO breached** when the last good backup is
older than 1.5 × the RPO (36 hours or 90 minutes). The **Protection status** table below them uses the same
rule: a guest is **Overdue** when its newest snapshot is older than 1.5 × the policy period. See
[03 The web interface](03-web-interface.md#dashboard).

## Protection groups

Open **Configuration → Protection groups**.

![Protection groups](images/groups.png)

A group belongs to one tenant and one source and uses one policy. Click **New group** and choose **Tenant**,
**Name**, **Source** (only sources of that tenant are offered) and **Policy**. What you select next depends on the
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
| `type:user`, `type:site`, `type:team` | Microsoft 365 object type |
| `license:none` | Microsoft 365 user without any license |

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

### Changing and deleting groups

- **Edit** lets you change the name, source, policy, guests, the **What to protect** choice, tags and exclusions. Moving a group to a policy that is weaker in any
  respect (a lower retention value or no offsite copy) needs approval, like weakening the policy itself.
- **Delete** needs approval when approvals are enabled. Deleting a group stops future backups. Existing snapshots are
  not deleted.

> **Status:** Retention runs as part of a group's backups, with that group's policy. Snapshots of guests that no
> longer belong to any group are therefore not pruned automatically, and the web interface has no function to delete
> individual snapshots. They keep using space until the guest is in a group again.
- Groups cannot be created in a tenant that is replicated from another appliance: replicated tenants receive no local
  backups (see [08 Replication](08-replication.md)).

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
