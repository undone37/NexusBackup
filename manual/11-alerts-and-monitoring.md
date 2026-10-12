# 11 Alerts and monitoring

The appliance watches its own work and raises **alerts** when something needs attention. You see them on the
**Alerts** page, behind the bell in the top bar and on the Dashboard, and the appliance sends them by e-mail and to
webhooks according to **notification rules** (**Settings → Alert delivery**).

## The Alerts page

![Alerts: open alerts with counts, a note and an expanded hint](images/alerts.png)

The page lists alerts newest first with:

- **Severity**: `critical`, `warning` or `info`.
- **Seen**: when the alert was last seen. Below it: how often it was seen and, for repeats, when it was first seen.
  Hover for the exact times.
- **Kind**: for alerts that belong to a tenant, the tenant is shown below the kind.
- **Message**: the latest message. **What to do** opens a short hint for this kind of alert. A note written when
  the alert was acknowledged or resolved is shown below it.

The switch at the top right shows **Open** alerts (the default), **Resolved** ones or **All**. A link from a
notification (`…/#/alerts?id=<n>`) opens that one alert, whatever its state.

![Alerts: all alerts, including resolved and auto-resolved ones](images/alerts-all.png)

The bell in the top bar and the counter next to **Alerts** in the sidebar count the open alerts nobody has
acknowledged (red when one of them is critical). The Dashboard lists the newest of them under **Open alerts**.

Administrators, operators and security officers can acknowledge and resolve alerts. Only administrators and
security officers can close a `break_glass`, `console_unlock` or `console_root_shell` alert. Alerts are appliance-wide: accounts limited to one tenant do not see
them.

### Life of an alert

1. **Raised.** The appliance detects a problem and raises an alert. The alert is sent to the matching notification
   rules.
2. **Repeated.** While the alert is open, the same problem does not create a new alert. The appliance counts the
   repeat ("147 times"), updates **Seen** and keeps the latest message. A repeat is sent out again only when its
   severity rises (for example from warning to critical).
3. **Acknowledged** (optional). Click **Acknowledge** and add a note if you like ("Storage team is on it"). The alert
   stays open and keeps counting repeats, but it no longer counts in the bell and is no longer sent as a reminder.
4. **Resolved.** The alert is closed. Most kinds **resolve themselves** when the matching success happens, for
   example the next successful run of the failed job. These alerts are marked **auto-resolved**. Close the others with
   **Resolve**: the dialog takes an optional note on what was done. Resolving also acknowledges the alert.
5. **Back again.** If the problem comes back after the alert was resolved, the appliance raises a new alert.

![Resolving an alert with a note](images/alert-resolve.png)

Reminders: an open alert that nobody has acknowledged is sent again every 24 hours (setting **Remind every**; 0
turns reminders off).

Resolved alerts are deleted after a while: `info` alerts after 14 days, `warning` and `critical` alerts after 180 days
(setting **Keep resolved … alerts**). Acknowledging, resolving and every automatic resolve are recorded in the audit
log (`alert.ack`, `alert.resolve`).

## Alert kinds

| Kind | Severity | Raised when | Resolves itself when | What to do |
|---|---|---|---|---|
| `job_failed` | critical | any job fails (backup, restore, offsite, GC, …); the message ends with the last log lines. Group backups are retried first (policy **Retries**): the alert comes only after the last attempt ("failed after 4 attempts") | the same job succeeds (same tenant, job kind and group, source, agent or guest), e.g. a later retry or **Back up now** | open the job on **Jobs**, read the log, fix the cause, run it again (**Back up now**, e.g. **Guests that failed in the last run**) |
| `sla_missed` | warning | a group backup runs longer than its policy's **Run-time SLA** (one alert per job) | — | check why the run is slow (source load, network, a hanging guest); cancel it on **Jobs** if needed, or raise the SLA |
| `paused` | warning | a group was paused, or a source put into maintenance, for more than 7 days or indefinitely (one alert per pause) | the group is resumed / the maintenance ends (next scheduler tick) | make sure the pause is intended; **Resume** the group / **End maintenance** when the work is done |
| `verify` | critical | the daily verification found missing or corrupt chunks (locally or in the offsite sample) | the tenant's next verification succeeds | see [15 Troubleshooting](15-troubleshooting-faq.md#verification-failed); do not run GC until it is understood |
| `inventory` | critical | the offsite inventory check found packs missing on the target or unknown packs there; or a locked snapshot disappeared from the local store | the tenant's next offsite job (with its inventory check) succeeds | treat as a possible attack or storage fault; check the offsite target, see [07 Offsite copies](07-offsite.md) |
| `capacity` | warning | the chunk store is more than 75 % full | usage is back under 75 % | add storage, or review retention; GC only frees chunks no snapshot uses any more |
| `offsite_lag` | warning | the oldest snapshot not yet offsite is more than 48 hours old (one alert per tenant) | the tenant's offsite copy has caught up | check the tenant's offsite jobs and the target's reachability and space |
| `backup_inconsistent` | warning | an agent or share backup could not use a snapshot of the source, or files changed while they were read (shown once per source for a missing snapshot) | — (resolve by hand) | configure snapshot support on the source (LVM/ZFS/btrfs on agent hosts, a NAS snapshot directory for shares), see [04 Sources](04-sources.md) |
| `consistency` | warning | a group backup's snapshot is less consistent than its policy requires (one per guest, see [05](05-policies-and-groups.md#required-consistency)) | the next snapshot of that guest that meets the requirement | enable the QEMU guest agent (VMs), hooks or VSS (agents) or snapshots on the source |
| `gc_quorum` | warning | a garbage collection would delete more than 20 % of a tenant's chunks and waits for approval | the request is approved (the GC is queued) | decide the `gc_large` request on **Approvals** after checking why so much data became unreferenced |
| `gc_confirm` | warning | the same, while approvals are disabled | the confirmed GC has run | an administrator confirms it on **Approvals** (**Confirm and run GC**) |
| `replication_lag` | warning | (secondary) no successful replication sync of a tenant for 48 hours | a sync of that tenant succeeds | check the replication source and the primary, see [08 Replication](08-replication.md) |
| `replication_keys` | critical | (secondary) the primary uses a tenant key version this appliance does not have, or a key export failed | — | export the keys again on the primary and have it approved |
| `replication_verify` | critical | (secondary) replicated data failed verification; nothing was imported | — | check the primary; the next sync retries |
| `config` | warning | the scheduler cannot use a group or replication source configuration | — | fix the configuration named in the message |
| `orphaned` | info | snapshots of an object that is in no protection group of its tenant were found; they are pruned with the default retention (shown once per object) | — | put the object into a group if it should keep being protected with that group's retention, or ignore it; see [05 Policies and protection groups](05-policies-and-groups.md#snapshots-of-objects-in-no-group) |
| `anomaly` | critical | a backup added far more new data than usual for its source, or new data that suddenly does not compress (see [Change-rate anomalies](#change-rate-anomalies)) | — | check the source for mass changes or encryption (ransomware); a security officer puts the last good snapshot on hold with **Hold last good snapshot** |
| `legal_hold_advisory` | warning | (secondary) the primary holds a replicated snapshot under a legal hold; not applied here (one alert per snapshot) | a security officer applies the hold, or the primary releases it | decide whether the hold applies here too; **Apply hold** on the alert. See [08 Replication](08-replication.md#legal-holds-from-the-primary) |
| `quota` | warning at 80 %, critical at 100 % | a tenant's store reached 80 % or 100 % of its soft quota (**Tenants**); one alert per tenant, escalated at 100 % | usage is back under 80 % | review retention or what the tenant backs up, or raise the quota; backups continue either way |
| `cert_expiry` | info at 90 days, warning at 30, critical at 7 (API tokens: info, last 7 days) | a certificate, the IdP client secret or an API token expires soon (see [Expiry warnings](#expiry-warnings)); one alert per item, escalated | renewed (new certificate, new secret date, token revoked or replaced) | renew as the message says |
| `account_dormant` | info | an account was disabled because nobody signed in with it for the configured number of days (**Settings → Security → Dormant accounts**; one alert per account) | — | re-enable the account on **Users** if it is still needed, else leave it disabled. See [09 Users and access](09-users-and-access.md#dormant-accounts) |
| `firewall_reset` | warning | every inbound firewall restriction was cleared on the console (`nexus-setup reset-firewall`) | — | confirm with the person who did it, then set correct source lists in **Settings → Firewall**. See [02 Installation](02-installation.md#inbound-firewall) |
| `mgmt_allow_reset` | warning | (before Phase 16) the management allow-list was cleared on the console | — | as `firewall_reset` |
| `report` | warning | a scheduled report could not be mailed (SMTP server unreachable or refusing, no SMTP server configured, report removed meanwhile) or its schedule is invalid; one alert per report (`report:<name>`) | the report is mailed successfully (scheduled or **Send now**) | check the SMTP server under **Settings → Alert delivery** and the recipients on **Reports**, then **Send now** |
| `break_glass` | critical | an administrator account was reset on the console with the recovery key (`nexus-setup recover-admin`), or approvals were switched off there (`nexus-setup disable-approvals`) | — | make sure the recovery was planned (check the audit entry `user.break_glass`), then acknowledge it; until then every administrator sees a red banner. See [14 Disaster recovery](14-disaster-recovery.md#break-glass-the-only-administrator-lost-their-authenticator) |
| `console_unlock` | critical | a one-time code for a root shell on the console was shown to its requester (**Settings → Console access**) | — | make sure the request was planned; revoke the code there if not. See [14 Disaster recovery](14-disaster-recovery.md#emergency-root-shell-on-the-console) |
| `console_root_shell` | critical | a root shell was opened on the appliance console with a one-time code or the recovery key; while it runs every administrator, security officer and operator sees a red banner | — | confirm with the requester (or whoever holds the recovery key) what was done, check the audit log (`console.root_shell`, `console.root_shell_end`), then acknowledge |
| `disk` | critical: SMART failing, array degraded or failed, bad sectors growing; warning: bad sectors, NVMe wear ≥ 90 % or critical warning, media errors, too hot (HDD > 55 °C, SSD/NVMe > 70 °C), failed self-test, no disk status for 30 minutes; info: rebuild, resync or reshape running (with progress) | the scan of `nexus-disks` (every 5 minutes, SMART hourly) finds a problem; one alert per disk (`disk:<serial>`) and per array (`disk:md:<uuid>`, the rebuild as `disk:md:<uuid>:sync`) | the disk or array is healthy again (a rebuild finished, the disk was replaced) | open **Configuration → Hardware**; replace a failing disk, see [15 Troubleshooting](15-troubleshooting-faq.md#replacing-a-disk) |
| `forwarding` | warning | audit / alert forwarding to a syslog or HTTPS sink has failed for 15 minutes (one alert per sink; the message names the destination and the error) | the sink delivers again (or is disabled / removed) | check the receiver (reachable, certificate, token) and **Settings → Forwarding** (**Send test message**); nothing is lost, the backlog follows. See [10 Approvals and audit](10-approvals-and-audit.md#forwarding-to-a-siem) |

## Expiry warnings

The scheduler checks every 15 minutes what expires and raises one `cert_expiry` alert per item: **info** 90 days
before, **warning** 30 days before, **critical** 7 days before and after expiry. The alert is escalated in place and
resolves itself once the item is renewed or gone.

| Item | Expiry from | Renew |
|---|---|---|
| **Web certificate** (imported) | the certificate | **Settings → Certificate**: new request, install the new certificate ([02 Installation](02-installation.md#use-your-own-certificate)) |
| **Self-signed appliance certificate** (pinned by replication secondaries) | the certificate (10 years from setup) | `nexus-setup --force-reconfigure-network` creates a new one; give the new fingerprint to the secondaries |
| **Agent certificates** | 10 years after the agent's enrollment | enroll the agent again ([04 Sources](04-sources.md)) |
| **Agent CA** (the appliance's client certificate for agents) | 10 years after the first agent enrollment | not automated yet: plan a re-enrollment of all agents |
| **Replication secondaries** (their client certificates, on the primary) | 10 years after enrollment | enroll the secondary again ([08 Replication](08-replication.md)) |
| **IdP client secret** | the date entered under **Settings → Single sign-on** (optional) | create a new secret at the IdP, enter it and the new date |
| **API tokens** (info only, last 7 days) | the token | create a new token, revoke the old one ([09 Users and access](09-users-and-access.md#api-tokens)) |

> **Status:** agent and replication certificates are not stored on the appliance (only their fingerprints), so their
> dates are computed from the enrollment time and the fixed lifetimes. A replication secondary does not warn about
> the primary's certificate.

## Change-rate anomalies

After every backup the appliance compares the amount of **new data** the backup added to the store (after
deduplication, before compression) with the same source's history. It raises a critical `anomaly` alert when

- the new data is more than **3 ×** the median of the source's last **14** backups and more than **1 GiB**, or
- the new data hardly compresses (factor below 1.05) while the source's data usually compresses well (median above
  1.3), and it is more than a quarter of that 1 GiB floor. Encrypted files do not compress, so this is the typical
  signature of ransomware encrypting a share or a server.

Both rules need at least 5 earlier backups of the source. Example message:

```text
change-rate anomaly on acme/share-6: snapshot 1791580000: 412.0 GiB new data, limit 36.0 GiB (3× the median
12.0 GiB of the last 14 runs); last snapshot before: share-6/1791493600
```

The message names the tenant, the source, the time of the suspicious snapshot and the **last snapshot before** it:
the one to restore from if the data was encrypted. While the alert is open, further anomalies of the same source
raise its count instead of a second alert.

A **security officer** sees **Hold last good snapshot** on the alert. It opens the legal hold dialog for that snapshot
with a prepared reason; after **Put on hold** no retention, garbage collection or delete removes it until a release
is approved ([06 Restores](06-restores.md#legal-hold)). Without a hold, act before the snapshot reaches the end of
its retention.

![Hold last good snapshot on an anomaly alert](images/alert-hold-last-good.png)

The thresholds are in **Configuration → Settings → Anomaly detection** (administrators; security officers read
only): **Detect unusual change rates**, **Alert above this multiple of the median**, **Median over the last runs**
and **Never alert below (GiB of new data)**. Stricter values apply at once; switching detection off or raising the
multiple or the floor needs a second person when approvals are enabled (request `settings.anomaly`).

![Settings: Anomaly detection](images/settings-anomaly.png)

> **Status:** The figures come from the connectors' per-backup statistics, introduced in this release. Backups taken
> before carry none, so detection starts after 5 backups per source with this release.

## Delivery: notification rules

Administrators set up delivery under **Configuration → Settings → Alert delivery**; security officers see the tab
read-only.

![Settings: Alert delivery with three rules and a successful test](images/settings-alerts.png)

A **notification rule** decides which alerts go where. Each rule has:

- a **Name** (letters, digits, dot, dash, underscore);
- **Send alerts of**: **Info and above**, **Warning and above** (default) or **Critical only**;
- **Alert kinds**: none ticked means every kind;
- **Tenants**: none ticked means every tenant, including appliance-wide alerts such as `capacity`. With tenants
  ticked, the rule gets only those tenants' alerts. This way a tenant's own team can receive its alerts;
- **Channels**: **E-mail recipients** (one per line) and/or a **Webhook URL**.

An alert goes to every rule it matches. If several matching rules have the same recipient, that person gets one
e-mail.

To add a rule, click **Add rule**. **Edit** and **Delete** change a rule. Each change is saved at once.
**Send test** sends one test alert through that rule's channels, using the saved settings, and shows the result per
channel: **Webhook** "ok", or **E-mail** "error: …" with the reason. A test ignores the rule's severity, kind and
tenant filters.

![Editing a rule: kinds, tenant, webhook with a Slack template](images/settings-alert-rule.png)

**SMTP server**: e-mail goes out through one SMTP server for all rules. Tick **Send e-mail through an SMTP server** and
fill in **SMTP server**, **Port** (e.g. 587), **Sender address**, **Use STARTTLS** and, if the relay needs them,
**SMTP user (optional)** and **SMTP password**. The password is write-only ("Stored — leave empty to keep the current
value."). If you change the server, port or user, you must enter the password again. Rules with e-mail recipients need
the SMTP server.

**Reminders and retention**: **Remind every (hours, 0 = never)** (default 24) and how many days resolved alerts are
kept per severity (defaults 14 / 180 / 180). Click **Save** to store these and the SMTP server.

### Webhook payload

Without a template, the webhook receives one JSON `POST` per alert:

```json
{
  "id": 1093, "ts": 1791712800, "first_ts": 1791712800, "last_ts": 1791968400, "count": 147,
  "severity": "warning", "kind": "capacity", "message": "store capacity above 75 % (now 78 %)",
  "hint": "The store is filling up. Shorten retention, run GC or add disks. Resolves when usage drops below the threshold.",
  "tenant": null, "host": "backup", "alert_url": "https://backup/#/alerts?id=1093"
}
```

- `ts` is the time the alert was first seen (the same as `first_ts`). `last_ts` and `count` describe the repeats.
- `hint` is the English "what to do" text.
- `tenant` is `null` for appliance-wide alerts.
- `alert_url` opens the alert in the web interface. It uses the appliance's host name.
- The same alert can arrive more than once: again when its severity rises, and as a reminder. Use `id` to tell
  them apart.

E-mails have the subject `[NexusBackup <host>] <severity>: <kind>`. The body has the message, the hint, the tenant,
the counts and the link.

**Extra headers**: a webhook can send headers such as `Authorization: Bearer …`. The values are stored encrypted
for the scheduler and never shown again; leave a value empty to keep it. If you change the webhook URL, you must enter
the header values again.

### Webhook templates (Slack, Teams, …)

Many chat tools expect their own JSON. Put it in **Body template (optional)**, with placeholders where the alert's
values go: `{{id}}`, `{{ts}}`, `{{first_ts}}`, `{{last_ts}}`, `{{count}}`, `{{severity}}`, `{{kind}}`,
`{{message}}`, `{{hint}}`, `{{tenant}}`, `{{host}}`, `{{alert_url}}`.

- Each value is inserted **JSON-escaped without quotes**, so write placeholders inside a JSON string (`"{{message}}"`).
  Quotes and line breaks in a message cannot break the JSON.
- Numbers (`{{count}}`, `{{id}}`, the times) can also stand outside quotes.
- A missing tenant becomes empty text.
- When you save, the template is checked: an unknown placeholder or a template that does not produce valid JSON is
  refused with the reason.
- **Insert example** fills in a Slack or a Teams template.

Slack (incoming webhook):

```json
{"text": ":rotating_light: [{{severity}}] {{kind}} on {{host}}: {{message}}\n{{hint}}\n<{{alert_url}}|Open alert> (seen {{count}}x)"}
```

Microsoft Teams (a Workflows webhook that posts an Adaptive Card):

```json
{"type": "message", "attachments": [{"contentType": "application/vnd.microsoft.card.adaptive", "content": {
  "$schema": "http://adaptivecards.io/schemas/adaptive-card.json", "type": "AdaptiveCard", "version": "1.4",
  "body": [{"type": "TextBlock", "weight": "Bolder", "wrap": true, "text": "[{{severity}}] {{kind}} on {{host}}"},
           {"type": "TextBlock", "wrap": true, "text": "{{message}}"},
           {"type": "TextBlock", "wrap": true, "isSubtle": true, "text": "{{hint}}"}],
  "actions": [{"type": "Action.OpenUrl", "title": "Open alert", "url": "{{alert_url}}"}]}}]}
```

Other details:

- Delivery is retried a few times (after 10 and 60 seconds).
- The webhook host of every rule and the SMTP server are added to the outbound firewall allow-list automatically.
- The settings are stored in the catalog. The SMTP password and the header values are sealed like other secrets.
- An appliance upgraded from a release without rules keeps working: its single webhook and recipient list become
  one rule `default` (every kind and tenant, at the old minimum severity).

### Fallback: the file `/etc/nexus/alerts.json`

Appliances set up before the **Alert delivery** tab existed may have the file `/etc/nexus/alerts.json`. The settings
in the web interface take precedence. The file is used only when nothing is configured there, and then acts as one
rule for every alert:

```json
{
  "webhook": { "url": "https://hooks.example.com/nexus", "headers": { "Authorization": "Bearer <token>" } },
  "smtp": {
    "host": "mail.example.com", "port": 587, "tls": "starttls",
    "from": "nexus@example.com", "to": ["backup-team@example.com"],
    "username": "nexus", "password_file": "/etc/nexus/smtp-password"
  }
}
```

- Both parts are optional.
- `tls` is `starttls` (default), `tls` (implicit TLS, usually port 465) or `none` (only for a local relay).
- The file has to be placed on the appliance from the console, which the hardened image does not make easy (see
  [02 Installation](02-installation.md)).

> **Status:** The alert lifecycle (counting, auto-resolve, reminders, retention) and the notification rules
> (routing, templates, sealed headers) are covered by the scheduler and API tests and were tried in the web interface
> against the demo backend. They have not yet been run on an installed appliance in the VM labs.

### Forwarding to syslog or a SIEM

Notification rules pick alerts for people. To feed a log server or SIEM with **every** alert event (raised,
escalated, acknowledged, resolved), every finished job and the audit log, use **Settings → Forwarding** (syslog
over TLS and/or HTTPS JSON, in order, at least once); see
[10 Approvals and audit](10-approvals-and-audit.md#forwarding-to-a-siem). A sink that fails for 15 minutes raises the
`forwarding` alert.

> **Status:** Forwarding is covered by scheduler tests against local TLS syslog and HTTPS receivers (resume after a
> restart, nothing skipped after failures) and by API tests; the lab step `lab/appliance/forwarding.sh` checks it
> on an installed appliance against an rsyslog container.

## Scheduled reports

Administrators can have the reports of **Monitor → Reports** (see
[03 The web interface](03-web-interface.md#reports)) mailed regularly, for example a weekly status for the
operations team or a monthly report per customer tenant.

![A scheduled report](images/report-schedule.png)

1. Set up the SMTP server first (**Settings → Alert delivery**); reports use the same server and sender address.
   The SMTP server is already in the appliance's outbound allow-list, nothing else needs to be opened.
2. **Reports → Scheduled reports → Add report**:
   - **Name**: letters, digits, `.`, `-`, `_`; it is part of the attachment names (`weekly-ops-failed-2026-10-12.csv`).
   - **Data of**: all tenants, or one tenant (the report then contains only that tenant's objects and jobs; useful for
     a customer's contact).
   - **Reports**: one or more of the four reports.
   - **Schedule**: on weekdays (`Mon 07:00`), daily (`daily 07:00`) or monthly (`monthly 1 06:00`; a month without
     the day sends on its last day), in the chosen **Time zone**. Hourly schedules are not offered.
   - **Recipients**: up to 16 mail addresses.
3. **Save**. The change applies at once and is recorded in the audit log (`settings.reports`).

What is sent: one HTML e-mail with a short summary per report (number of rows, the first 20 rows as a table) and
every report as a CSV attachment (all rows), plus a plain-text part. Each mail covers the time since the previous
scheduled run: a weekly report sent on Monday 07:00 covers Monday 07:00 of the week before up to this Monday 07:00; a
monthly one the previous month. Protection status and Storage show the state at sending time.

- The scheduler queues an appliance job `report_send` when a slot has passed. After downtime it sends once, not once
  per missed slot. A newly added report waits for its first slot.
- **Send now** sends a report immediately, covering one schedule period up to now (one week, one month). It does not
  move the schedule.
- **Last sent** shows the state of the latest send job; the job (on **Jobs**, appliance jobs) holds the log and the
  attachment names.
- A sent report is audited (`report.sent`, with recipients, range and attachment names). If it cannot be sent, the
  appliance raises a `report` warning (see [Alert kinds](#alert-kinds)) that resolves itself after the next successful
  send.
- The mail leaves the appliance unencrypted beyond the SMTP connection's TLS. Send tenant reports only to people who
  may see that tenant's data.

## Metrics (Prometheus)

`GET https://<appliance>:8443/metrics` serves Prometheus metrics. It requires the bearer token from
`/etc/nexus/metrics-token`, created by the first-boot wizard:

```sh
curl --cacert appliance.pem -H "Authorization: Bearer $(cat metrics-token)" https://backup.example.com:8443/metrics
```

Series:

| Metric | Meaning |
|---|---|
| `nexus_jobs{state}` | number of jobs per state |
| `nexus_snapshots{tenant,location}` | snapshots per tenant, `location` = `local` or `offsite` |
| `nexus_last_successful_backup_timestamp_seconds{tenant,group}` | time of the last successful backup of each group (0 = never) |
| `nexus_failed_logins_total` | failed sign-ins |
| `nexus_audit_entries` | number of audit log entries |
| `nexus_quorum_pending` | pending approval requests |

Useful alerting rules in your monitoring system: no successful backup of a group for more than 36 hours (1.5 × a daily RPO), any
pending approvals older than a day, a sudden rise in failed sign-ins, and the appliance not answering `/health`.

`GET /health` (no token) answers `{"ok": true}` while the web API runs.

For more than metrics, use a read-only **API token** ([09 Users and access](09-users-and-access.md#api-tokens)): for
example `GET /api/v1/dashboard` (protection status and RPO per group) or `GET /api/v1/alerts?state=open`.

## Daily checklist for operators

1. Dashboard: **RPO breaches** at 0, **Objects needing attention** empty ("Every object is within its RPO."), no
   new entries under **Failed jobs**.
2. **Alerts**: acknowledge new alerts when someone takes them on; resolve the ones that do not resolve themselves once fixed, with a note.
3. **Jobs**: no job stuck in **Queued** for hours (a long-running job of the same source blocks the next one).
4. **Approvals**: tell the approvers about pending requests (they expire after 72 hours).
