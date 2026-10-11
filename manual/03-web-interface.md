# 03 The web interface

This chapter walks through every page of the web interface. Task-oriented details are in the chapters linked from
each section.

The screenshots show a fictional demo appliance (tenants **acme**, **initech** and **globex**). Your pages show your
own data.

## Signing in

Open `https://<appliance>:8443/` in a browser. The certificate is the self-signed one created during setup; compare
its fingerprint with the one the setup wizard showed (see [02 Installation](02-installation.md)).

![Sign-in page](images/login.png)

Enter your **User name**, **Password** and the 6-digit **Authenticator code** from your authenticator app, then click
**Sign in**.

- Each code can be used only once. If a sign-in fails right after a successful one, wait for the next code.
- After 5 failed attempts within 15 minutes, the account (and the address you sign in from) is locked for 15
  minutes. Failed sign-ins are recorded in the audit log.
- A session ends after 30 minutes without activity and after 12 hours at the latest. You then see "Your session has
  expired. Please sign in again."
- New accounts are activated with an activation code through **Activate account** below the form; see
  [09 Users and access](09-users-and-access.md#activating-your-account).

Click **Sign out** (top right) when you are done. The top bar shows your user name, role and, for tenant-scoped
accounts, your tenant.

## Navigation and roles

The sidebar shows only what your role may use. The server checks every request again; hiding is a convenience.

| Page | Administrator | Security officer | Operator | Tenant user |
|---|---|---|---|---|
| Dashboard, Snapshots, Jobs | ✓ | ✓ | ✓ | ✓ (own tenant) |
| Alerts | ✓ | ✓ | ✓ | — |
| Approvals | ✓ | ✓ (decides) | ✓ (read) | — |
| Audit log | ✓ | ✓ | — | — |
| Configuration: Tenants, Sources, Agents, Policies, Protection groups, Users | ✓ | — | — | — |
| Configuration: Replication, Plugins | ✓ | read | read | — |

Accounts limited to one tenant (any role with a tenant set) see only that tenant's data and do not see the Alerts,
Approvals and Replication pages. A security officer can see snapshots but cannot start restores.

![Dashboard of an operator: no configuration pages except Replication and Plugins](images/dashboard-operator.png)

![Snapshots page of the tenant user "acme": only Dashboard, Snapshots and Jobs](images/tenant-user-snapshots.png)

## Dashboard

![Dashboard](images/dashboard.png)

The four tiles at the top:

- **Protected**: guests whose last backup is recent, out of all guests in protection groups. A guest counts as
  protected if its newest snapshot is younger than 26 hours (2 hours for hourly policies). The tile turns amber when
  anything is not protected.
- **Failed jobs (7 days)**: click it to see the failed jobs.
- **Open alerts**: unacknowledged alerts (not shown to tenant-scoped accounts).
- **Pending approvals**: requests waiting for a decision (only for roles that can see approvals).

**Protection status** lists every protection group with one row per guest (VM, container, host, dataset, share,
database). The columns show the time of the last backup and whether the newest copies are **Local**, **Offsite** and
**Verified**. **Offsite** shows *n/a* when the group's policy does not copy offsite. **Status** is **Protected**,
**Overdue** or **No backup**. Administrators and operators can start a backup of the whole group with
**Back up now**.

Below are the most recent **Failed jobs** and **Open alerts**. The page refreshes every 30 seconds.

When approvals are disabled although two or more people could approve, administrators see a banner recommending to
enable them. **Dismiss** hides it for the current browser session.

![Dashboard with the approvals recommendation banner](images/dashboard-approvals-off.png)

## Snapshots

![Snapshots of tenant initech](images/snapshots.png)

One row per snapshot, newest first. Filter by **Tenant** and by **Guest (e.g. vm-100)**, then click **Filter**.

Snapshot names tell you what was backed up:

| Name | Content |
|---|---|
| `vm-<id>` / `ct-<id>` | Proxmox VE VM / container |
| `host-<agent id>` | Linux or Windows host (agent); the agent's name is shown below |
| `nas-<source id>-<pool.dataset>` | TrueNAS dataset (built-in connector) |
| `share-<source id>` | NFS or SMB share; the source name is shown below |
| `plugin-<plugin>-<source id>[-<guest>]` | plugin source, e.g. a PostgreSQL database |

**Size** is the logical size of the snapshot. **Local**, **Offsite** and **Verified** show where copies exist and
whether the local copy passed verification. **Locked until** is the retention lock (— when it has expired).
Snapshots received from another appliance carry a **Replicated from …** label.

The buttons depend on the snapshot type and your role: **Restore**, **Instant recover** (VMs only),
**Browse files**, **Restore to path** (agent hosts), and the restores a plugin offers (for example
**Point-in-time restore**). See [06 Restores](06-restores.md).

## Files

**Browse files** opens the file browser for one snapshot. Click directories to open them, use the breadcrumb or
**.. (Up one level)** to go back. Select files and directories with the check boxes, choose **tar** or **zip** and click
**Prepare download**. When the archive is ready, a **Download** button appears. Details:
[06 Restores](06-restores.md#browse-files-and-download-them-tar-or-zip).

![File browser with two selected entries and a prepared download](images/files-download.png)

Reading a VM's file systems starts an isolated restore micro-VM in the background, so the first listing of a VM
snapshot takes a few seconds.

## Jobs

![Jobs](images/jobs.png)

All jobs, newest first (the 100 most recent). Filter by **State** and **Kind**. The list refreshes every 4 seconds
while jobs are queued or running. Click a job number to see its details.

The job page shows kind, state, tenant, who requested it (`scheduler` for scheduled work), the times and the
parameters. While the job runs, the log refreshes every 2 seconds (**Live — refreshing every 2 s**).

![A running offsite copy](images/job-running.png)

![A failed backup with its log](images/job-failed.png)

- Administrators and operators can **Cancel job** while it is still queued; running jobs cannot be cancelled.
- A finished **Download files** job shows a **Download** button to the person who requested it.
- Plugin jobs show a **Result** section (validation result, list of guests, restore summary).
- A backup that could not take a point-in-time consistent view (an agent without snapshot support, a share without
  NAS snapshot, or files that changed while they were read) shows a warning banner:

![A share backup that was not point-in-time consistent](images/job-inconsistent.png)

## Alerts

![Alerts](images/alerts.png)

Alerts the appliance raised, newest first: failed jobs, verification failures, capacity above 75 %, offsite or
replication lag over 48 hours, inconsistent backups, garbage collections waiting for approval and more. **Acknowledge**
marks an alert as handled (recorded with your name); **Show acknowledged** shows those again. See
[11 Alerts and monitoring](11-alerts-and-monitoring.md).

## Approvals

![Approvals as seen by a security officer](images/approvals.png)

The approval setting and all requests waiting for a second person. See
[10 Approvals and audit](10-approvals-and-audit.md).

## Audit log

![Audit log after verifying the chain](images/audit.png)

Every recorded action, newest first. **Verify chain** recomputes the hash chain over all entries; **Load more** pages
back in time. See [10 Approvals and audit](10-approvals-and-audit.md#audit-log).

## Configuration pages

| Page | What you do there | Chapter |
|---|---|---|
| **Tenants** | create tenants, set each tenant's offsite target | [07 Offsite copies](07-offsite.md) |
| **Sources** | connect Proxmox VE, agent hosts, TrueNAS, NFS/SMB shares and plugin sources | [04 Sources](04-sources.md) |
| **Agents** | register Linux/Windows backup agents, issue enrollment tokens, update agents | [04 Sources](04-sources.md) |
| **Replication** | pair this appliance with a second appliance | [08 Replication](08-replication.md) |
| **Policies** | schedules, retention and offsite switch | [05 Policies and protection groups](05-policies-and-groups.md) |
| **Protection groups** | which guests of a source are backed up with which policy | [05 Policies and protection groups](05-policies-and-groups.md) |
| **Users** | accounts, roles, activation codes | [09 Users and access](09-users-and-access.md) |
| **Plugins** | install, upgrade and remove plugins; publisher keys | [12 Plugins](12-plugins.md) |

![Tenants](images/tenants.png)

![Sources](images/sources.png)

![Agents](images/agents.png)

![Replication](images/replication.png)

![Policies](images/policies.png)

![Protection groups](images/groups.png)

![Users](images/users.png)

![Plugins](images/plugins.png)

## Messages and dialogs

- Results of actions appear as short messages at the bottom right. "Pending approval: request #N …" means the action
  was turned into an approval request and has **not** taken effect yet.
- Destructive actions ask for confirmation in a dialog first. Secrets you enter (passwords, API keys, tokens) are
  **write-only**: the appliance never shows them again. When you edit a source, leave a secret field empty to keep the
  stored value.
- One-time values (enrollment tokens, activation codes, replication codes) are shown once in a dialog. Copy them
  before you close it.
