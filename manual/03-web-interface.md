# 03 The web interface

This chapter walks through every page of the web interface. Task-oriented details are in the chapters linked from
each section.

The screenshots show a fictional demo appliance (tenants **acme**, **initech** and **globex**). Your pages show your
own data.

> **Status:** The web interface was redesigned in this release (new layout, dark mode, KPI dashboard, **Settings**
> page, single sign-on). The new pages were tested against the demo backend. The appliance-side parts of the KPI
> dashboard, single sign-on, alert delivery, appliance SSH keys, updates and break-glass recovery are still being
> integrated; until an appliance runs them, those pages show an error or no data there.

## Signing in

Open `https://<appliance>:8443/` in a browser. The certificate is the self-signed one created during setup; compare
its fingerprint with the one the setup wizard showed (see [02 Installation](02-installation.md)).

![Sign-in page with the single sign-on button](images/login.png)

The sign-in page has two ways in:

- **Sign in with <identity provider>** (for example **Sign in with Keycloak**): shown only when an administrator has
  set up single sign-on. Your browser goes to your organization's identity provider, which checks your password and
  second factor, and then comes back signed in. See
  [09 Users and access](09-users-and-access.md#single-sign-on-oidc).
- **or with an appliance account**: enter your **User name**, **Password** and the 6-digit **Authenticator code**
  from your authenticator app, then click **Sign in**.

For appliance accounts:

- Each code can be used only once. If a sign-in fails right after a successful one, wait for the next code.
- After 5 failed attempts within 15 minutes, the account (and the address you sign in from) is locked for 15
  minutes. Failed sign-ins are recorded in the audit log.
- New accounts are activated with an activation code through **Activate account** below the form; see
  [09 Users and access](09-users-and-access.md#activating-your-account).

A session ends after 30 minutes without activity and after 12 hours at the latest. You then see "Your session has
expired. Please sign in again." If single sign-on fails, the sign-in page shows the reason in a red box; see
[15 Troubleshooting](15-troubleshooting-faq.md#single-sign-on).

## Layout

![Dashboard with the sidebar on the left and the top bar](images/dashboard.png)

**Sidebar (left).** The pages in three groups:

| Group | Pages |
|---|---|
| **Monitor** | Dashboard, Snapshots, Jobs, Alerts |
| **Governance** | Approvals, Audit log |
| **Configuration** | Tenants, Sources, Agents, Replication, Policies, Protection groups, Users, Plugins, Settings |

**Alerts** and **Approvals** carry a counter: open alerts (red when one of them is critical, amber otherwise) and
pending approval requests. **Collapse sidebar** at the bottom shrinks the sidebar to an icon rail; hover an icon to
see its name. The browser remembers the choice. In a narrow window (below about 900 px, e.g. a phone) the sidebar is
hidden; open it with the **Menu** button at the top left.

**Top bar.** From left to right:

- the breadcrumb: group and page, e.g. **Monitor / Dashboard**;
- the **Approvals** button (stamp icon) with the number of pending requests, for roles that see approvals;
- the **Alerts** button (bell icon) with the number of open alerts, for roles that see alerts;
- the **theme** button (see below);
- your user name and role, and for tenant-scoped accounts your tenant (e.g. "Tenant user · acme");
- **Sign out** (arrow icon).

**Theme (light / dark).** By default the interface follows your operating system's light or dark setting. The theme
button cycles through **Theme: follow the system** → **Theme: light** → **Theme: dark** → back to following the
system; its tooltip tells you the current choice and the next one. The choice is stored in this browser only.

![The dashboard in the dark theme](images/dashboard-dark.png)

Keyboard users: the first Tab stop is **Skip to content**.

## Navigation and roles

The sidebar shows only what your role may use. The server checks every request again; hiding is a convenience.

| Page | Administrator | Security officer | Operator | Tenant user |
|---|---|---|---|---|
| Dashboard, Snapshots, Jobs | ✓ | ✓ | ✓ | ✓ (own tenant) |
| Alerts | ✓ | ✓ | ✓ | — |
| Approvals | ✓ | ✓ (decides) | ✓ (read) | — |
| Audit log | ✓ | ✓ | — | — |
| Tenants, Sources, Agents, Policies, Protection groups, Users | ✓ | — | — | — |
| Replication, Plugins | ✓ | read | read | — |
| Settings | ✓ (all tabs) | read (all tabs) | read (Approvals, Appliance SSH keys, Updates) | — |

Accounts limited to one tenant (any role with a tenant set) see only that tenant's data and do not see the Alerts,
Approvals, Replication and Settings pages. A security officer can see snapshots but cannot start restores.

![Dashboard of an operator: no configuration pages except Replication, Plugins and Settings](images/dashboard-operator.png)

![Snapshots page of the tenant user "acme": only Dashboard, Snapshots and Jobs](images/tenant-user-snapshots.png)

## Dashboard

The Dashboard answers two questions at a glance: *is everything protected?* and *is the appliance healthy?* The top
part shows key figures (KPIs) and charts; below them is the per-guest **Protection status** table.

The header shows when the figures were computed (**Updated …**) and what they cover: **All tenants**, or your tenant
for tenant-scoped accounts. **7 days** / **30 days** switches the period of the job figures and charts (remembered
for the browser session). The key figures refresh every minute, the table below every 30 seconds.

### Terms used on the dashboard

- **Object**: one protected unit: a Proxmox VE VM or container, an agent host, a TrueNAS dataset, an NFS/SMB share,
  or a plugin guest or source (e.g. a PostgreSQL database or a Microsoft 365 mailbox).
- **RPO** (recovery point objective): how much data you may lose at most. The dashboard takes it from the object's
  policy schedule: **daily** = 24 h, **hourly** = 1 h, **every N hours** = N h, weekdays = the longest gap between
  two run days, **monthly** = 31 days (see [05](05-policies-and-groups.md#schedules)).
- **Within RPO**: the last good (successful) backup is no older than **1.5 × the RPO**, e.g. 36 h for a daily
  policy, 90 minutes for an hourly one. The half period is slack for a long or delayed backup.
- **RPO breached**: the last good backup is older than 1.5 × the RPO.
- **Paused**: behind the RPO, but every group of the object is paused or its source is in maintenance. Not counted as
  a breach (see [05](05-policies-and-groups.md#pausing-a-group)).
- **Never backed up**: the object is in a protection group but has no successful backup yet.
- **Not in a group**: the appliance knows the object (e.g. a VM on a connected Proxmox VE cluster, a database of a
  PostgreSQL source) but no protection group covers it. Nothing backs it up.

### Key figures

| Tile | What it shows | Act when |
|---|---|---|
| **Protection** | share of all known objects that are protected, "16 of 19 objects protected" | below 100 % (amber): objects are not in a group; add them or decide consciously not to back them up |
| **RPO breaches** | number of objects whose last good backup is older than 1.5 × RPO; below: how many are within RPO and how many were **never backed up** | red: any breach; amber: objects never backed up. See **Objects needing attention** |
| **Job success rate** | share of jobs in the period that finished OK; below: failed jobs, warnings, total. Click it to see the failed jobs | below 95 % (red), any failure (amber) |
| **Storage used** | how full the local chunk store is; below: free and total space | above 75 % (amber; the `capacity` alert fires), above 90 % (red) |
| **Data reduction** | logical data ÷ stored data, e.g. **4.2×** = 4.2 TiB of backed-up data need 1 TiB of disk; below: the deduplication and compression factors (their product is the total) | a sudden drop: new data that does not deduplicate (e.g. encrypted or compressed files) |
| **Forecast to full** | days until the store is full if it keeps growing like in the last 30 days (a straight line through the daily usage, the "linear trend"); **Not growing** when usage is flat or falling, or fewer than 7 days of samples exist; **> 2 years** for very long horizons | below 90 days (amber), below 30 days (red): add storage or review retention |
| **Offsite lag** | how far the offsite copy of the most-behind tenant trails; below: how many tenants with an offsite target are lagging, and the replication lag. "no offsite copies" when no tenant has an offsite target. Click it to open **Replication** | any lagging tenant (amber); see the `offsite_lag` alert |
| **Lock coverage** | share of snapshots under an immutable retention lock; below: the last verification and failed verifications | below 100 % (amber), any failed verification (red) |

The figures are computed on the appliance from its catalog. A tile shows "—" when a value is unknown (for example a
data reduction factor before the first backup).

### Charts

- **Jobs per day**: one stacked bar per day: backups, copies, verifies and restores, split into **OK** (green),
  **Warning** (amber) and **Failed** (red). The legend sums up the period. **Jobs** opens the job list.
- **Protection status**: a ring of all objects by RPO compliance: **Within RPO**, **RPO breached**, **Never backed
  up**, **Not in a group**. The centre shows the share within RPO.
- **Capacity trend**: stored data per day (after deduplication and compression), the linear forecast as a dashed line
  and the store's capacity as a dotted red line. The chip at the top right ("full in 197 days") repeats the forecast.
- **Data reduction**: a ring of **Stored** against **Saved** space, with the **Logical** size and the
  **Deduplication** and **Compression** factors below it.
- **Failures by source type**: failed jobs in the period per source type (Proxmox VE, SMB shares, TrueNAS, agent
  hosts, plugins by name, …). Shows where problems cluster.
- **Objects needing attention**: up to 10 objects with an RPO breach or that were never backed up, worst first:
  **Object**, **Tenant**, **Type**, **Last good backup**, **RPO** and the **SLA** chip (**Breached** or **Never**).
  "Every object is within its RPO." when there is nothing to do.

Hover over a bar or ring segment to see its value. Screen readers get each chart as a table.

If the key figures cannot be loaded, a banner says so; the table below still works.

### Protection status table, failed jobs, open alerts

**Protection status** lists every protection group with one row per guest (VM, container, host, dataset, share,
database). The columns show the time of the last backup and whether the newest copies are **Local**, **Offsite** and
**Verified**. **Offsite** shows *n/a* when the group's policy does not copy offsite. **Status** is **Protected**,
**Overdue**, **Paused** (the group is paused or its source in maintenance) or **No backup**; this column uses a simpler rule than the key figures: **Overdue** means the newest
snapshot is older than 1.5 × the policy period (36 hours for daily, 90 minutes for hourly policies; the same rule as the RPO KPIs). Administrators and operators can start a backup with **Back up now**:
the whole group, selected guests or the guests that failed in the last run (see
[05](05-policies-and-groups.md#back-up-now)).

Below the table are the most recent **Failed jobs** (last 7 days) and **Open alerts**.

When approvals are disabled although two or more people could approve, administrators see a banner recommending to
enable them, with a link **Open approval settings**. **Dismiss** hides it for the current browser session.

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

Each row has two controls (not for security officers, who cannot restore):

- **Browse files** opens the file browser. Plugins can give it their own name, e.g. **Download (tar/zip)**.
- **Restore** opens a menu with the restores that fit this snapshot:

![The Restore menu of a VM snapshot](images/snapshot-restore-menu.png)

| Snapshot | Restore menu |
|---|---|
| `vm-` | **Full restore to a new VM / container**, **Instant recover** |
| `ct-` | **Full restore to a new VM / container** |
| `host-` | **Restore to path** |
| `plugin-…` | the plugin's restores that apply to this kind of snapshot, e.g. **Restore database dump to a server** only on database snapshots and **Point-in-time restore** only on cluster snapshots of PostgreSQL |
| `nas-`, `share-` | no menu: download only |

See [06 Restores](06-restores.md).

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

- Administrators and operators can cancel a queued or running job (**Cancel** in the list, **Cancel job** on the
  job page). A queued job is cancelled at once. For a running job the scheduler stops the connector (SIGTERM, then
  SIGKILL after 30 seconds) and, for a Proxmox VE backup or restore, the running PVE task; the job ends
  **cancelled**, and "Cancellation requested by …" is shown meanwhile. A backup cancelled half-way leaves no
  snapshot: a snapshot only exists once its manifest is written as the very last step, and the chunks it had
  already stored are removed by the next garbage collection. Steps that run inside the appliance (retention, GC,
  verify) are not interrupted; the job stops after the current step. Cancelling is recorded in the audit log
  (`job.cancel`).
- Failed backups are retried (see [05](05-policies-and-groups.md#retries)): the job list shows **Attempt n**, and a
  retry's page links to the first job of the chain; a retry waiting for its delay shows **Starts not before**.
- A finished **Download files** job shows a **Download** button to the person who requested it.
- Plugin jobs show a **Result** section (validation result, list of guests, restore summary).
- A backup that could not take a point-in-time consistent view (an agent without snapshot support, a share without
  NAS snapshot, or files that changed while they were read) shows a warning banner:

![A share backup that was not point-in-time consistent](images/job-inconsistent.png)

## Alerts

![Alerts](images/alerts.png)

Alerts the appliance raised, newest first: failed jobs, verification failures, capacity above 75 %, offsite or
replication lag over 48 hours, inconsistent backups, garbage collections waiting for approval, break-glass recovery
and more. **Acknowledge** marks an alert as handled (recorded with your name); **Show acknowledged** shows those
again. The bell in the top bar counts the open alerts. Where alerts are sent (webhook, e-mail) is set under
**Settings → Alert delivery**. See [11 Alerts and monitoring](11-alerts-and-monitoring.md).

**Break-glass banner.** If someone used the console recovery for a locked-out administrator, every administrator
sees a red banner under the top bar: "Break-glass recovery was used: … Check the audit log, then acknowledge." with
**Open audit log** and **Acknowledge**. It stays until an administrator acknowledges it. See
[14 Disaster recovery](14-disaster-recovery.md#break-glass-the-only-administrator-lost-their-authenticator).

## Approvals

![Approvals as seen by a security officer](images/approvals.png)

All requests waiting for a second person, and (with **Pending only** cleared) the history. The chip at the top right
shows whether approvals are **Enabled** or **Disabled**; **Approval settings** leads to **Settings → Approvals**,
where they are switched on and off. See [10 Approvals and audit](10-approvals-and-audit.md).

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
| **Users** | accounts, roles, activation codes; single sign-on accounts are marked **Single sign-on** | [09 Users and access](09-users-and-access.md) |
| **Plugins** | install, upgrade and remove plugins; publisher keys | [12 Plugins](12-plugins.md) |
| **Settings** | appliance-wide settings in five tabs (below) | see below |

![Tenants](images/tenants.png)

![Sources](images/sources.png)

![Agents](images/agents.png)

![Replication](images/replication.png)

![Policies](images/policies.png)

![Protection groups](images/groups.png)

![Users](images/users.png)

![Plugins](images/plugins.png)

## Settings

**Configuration → Settings** holds the appliance-wide settings. Only administrators change them; security officers
see every tab read-only ("Read-only: only administrators change these settings."), operators see **Approvals**,
**Appliance SSH keys** and **Updates**. Changes that weaken protection or change who can sign in need a second person
when approvals are enabled.

| Tab | What it is for | Chapter |
|---|---|---|
| **Approvals** | the **Approval requirement**: enable or disable four-eyes approvals | [10 Approvals and audit](10-approvals-and-audit.md#enabling-and-disabling-approvals) |
| **Alert delivery** | webhook and e-mail (SMTP) for alerts, minimum severity, **Send test** | [11 Alerts and monitoring](11-alerts-and-monitoring.md#delivery-by-webhook-and-e-mail) |
| **Single sign-on** | the OpenID Connect identity provider, group mappings, **Test connection** | [09 Users and access](09-users-and-access.md#single-sign-on-oidc) |
| **Appliance SSH keys** | the public keys the appliance signs in to sources with; **Copy**, **Rotate**, **Retire old key** | [04 Sources](04-sources.md#appliance-ssh-keys) |
| **Updates** | running, staged, available and rollback image; **Check now**, **Install now** | [13 Updates](13-updates.md#updates-in-the-web-interface) |

![Settings: Approvals](images/settings-approvals.png)

![Settings: Alert delivery](images/settings-alerts.png)

![Settings: Single sign-on](images/settings-sso.png)

![Settings: Appliance SSH keys](images/settings-ssh-keys.png)

![Settings: Updates](images/settings-updates.png)

## Messages and dialogs

- Results of actions appear as short messages at the bottom right. "Pending approval: request #N …" means the action
  was turned into an approval request and has **not** taken effect yet.
- Destructive actions ask for confirmation in a dialog first. Secrets you enter (passwords, API keys, tokens, client
  secrets) are **write-only**: the appliance never shows them again. When you edit a source or a setting, leave a
  secret field empty to keep the stored value ("Stored — leave empty to keep the current value.").
- One-time values (enrollment tokens, activation codes, replication codes) are shown once in a dialog. Copy them
  before you close it.
