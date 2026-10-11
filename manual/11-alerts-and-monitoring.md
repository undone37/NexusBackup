# 11 Alerts and monitoring

The appliance watches its own work and raises **alerts** when something needs attention. You see them on the
**Alerts** page, behind the bell in the top bar and on the Dashboard, and the appliance can send them by webhook and
e-mail (**Settings → Alert delivery**).

## The Alerts page

![Alerts](images/alerts.png)

Alerts are listed newest first with **Severity** (`critical`, `warning`, `info`), **Time**, **Kind** and
**Message**. Click **Acknowledge** when you have handled an alert; the appliance records who acknowledged it.
**Show acknowledged** also lists handled alerts. The bell in the top bar and the counter next to **Alerts** in the
sidebar show the number of unacknowledged alerts (red when one of them is critical); the Dashboard lists the newest
under **Open alerts**.

Administrators, operators and security officers can acknowledge alerts. Alerts are appliance-wide: accounts limited to
one tenant do not see them.

Acknowledging does not fix anything. While an alert is unacknowledged, the same condition does not raise a
duplicate; after you acknowledge it, a condition that persists (for example a full store) raises it again.

## Alert kinds

| Kind | Severity | Raised when | What to do |
|---|---|---|---|
| `job_failed` | critical | any job fails (backup, restore, offsite, GC, …); the message ends with the last log lines | open the job on **Jobs**, read the log, fix the cause, run it again (**Back up now**) |
| `verify` | critical | the daily verification found missing or corrupt chunks (locally or in the offsite sample) | see [15 Troubleshooting](15-troubleshooting-faq.md#verification-failed); do not run GC until it is understood |
| `inventory` | critical | the offsite inventory check found packs missing on the target or unknown packs there; or a locked snapshot disappeared from the local store | treat as a possible attack or storage fault; check the offsite target, see [07 Offsite copies](07-offsite.md) |
| `capacity` | warning | the chunk store is more than 75 % full | add storage, or review retention; GC only frees chunks no snapshot uses any more |
| `offsite_lag` | warning | the oldest snapshot not yet offsite is more than 48 hours old | check the tenant's offsite jobs and the target's reachability and space |
| `backup_inconsistent` | warning | an agent or share backup could not use a snapshot of the source, or files changed while they were read (shown once per source for a missing snapshot, every time for changed files) | configure snapshot support on the source (LVM/ZFS/btrfs on agent hosts, a NAS snapshot directory for shares), see [04 Sources](04-sources.md) |
| `gc_quorum` | warning | a garbage collection would delete more than 20 % of a tenant's chunks and waits for approval | decide the `gc_large` request on **Approvals** after checking why so much data became unreferenced |
| `gc_confirm` | warning | the same, while approvals are disabled | an administrator confirms it on **Approvals** (**Confirm and run GC**) |
| `replication_lag` | warning | (secondary) no successful replication sync of a tenant for 48 hours | check the replication source and the primary, see [08 Replication](08-replication.md) |
| `replication_keys` | critical | (secondary) the primary uses a tenant key version this appliance does not have, or a key export failed | export the keys again on the primary and have it approved |
| `replication_verify` | critical | (secondary) replicated data failed verification; nothing was imported | check the primary; the next sync retries |
| `config` | warning | the scheduler cannot use a group or replication source configuration | fix the configuration named in the message |
| `break_glass` | critical | an administrator account was reset on the console with the recovery key (`nexus-setup recover-admin`) | make sure the recovery was planned (check the audit entry `user.break_glass`), then acknowledge it; until then every administrator sees a red banner. See [14 Disaster recovery](14-disaster-recovery.md#break-glass-the-only-administrator-lost-their-authenticator) |

## Delivery by webhook and e-mail

The scheduler delivers every new alert to a webhook and/or by e-mail. Administrators set this up under
**Configuration → Settings → Alert delivery**; security officers see the tab read-only.

![Settings: Alert delivery with webhook, e-mail and a successful test](images/settings-alerts.png)

1. **Webhook**: enter the **Webhook URL (HTTPS)**. It receives one JSON `POST` per alert. Leave it empty to turn the
   webhook off.
2. **E-mail (SMTP)**: tick **Send alerts by e-mail** and fill in **SMTP server**, **Port** (e.g. 587), **Sender
   address**, **Use STARTTLS**, **Recipients (one per line)** and, if the relay needs it, **SMTP user (optional)** and
   **SMTP password**. The password is write-only ("Stored — leave empty to keep the current value.").
3. **Send alerts of**: **Info and above**, **Warning and above** (default) or **Critical only**. Alerts below that
   severity appear only in the web interface.
4. Click **Save**, then **Send test**. The test sends one test alert through every configured channel, using the
   saved settings, and shows the result per channel, e.g. **Webhook** "ok" and **E-mail** "ok", or "error: …" with
   the reason.

Details:

- The webhook receives a JSON `POST` with `id`, `ts` (Unix time), `severity`, `kind`, `message` and `host`
  (the appliance's name). E-mails have the subject `[NexusBackup <host>] <severity>: <kind>`.
- Delivery is retried a few times (after 10 and 60 seconds). The webhook host and the SMTP relay are added to the
  outbound firewall allow-list automatically.
- The settings are stored in the catalog; the SMTP password is sealed like other secrets.

### Fallback: the file `/etc/nexus/alerts.json`

Appliances set up before the **Alert delivery** tab existed may have the file `/etc/nexus/alerts.json`. The settings
in the web interface take precedence; the file is used only when nothing is configured there. The file can also set
HTTP headers for the webhook (e.g. a bearer token) and implicit TLS for SMTP, which the web interface does not offer:

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

> **Status:** The **Alert delivery** tab was tested against the demo backend; its appliance-side part is still being
> integrated. Until it is, delivery works only through `/etc/nexus/alerts.json`.

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

Useful alerting rules in your monitoring system: no successful backup of a group for more than 26 hours, any
pending approvals older than a day, a sudden rise in failed sign-ins, and the appliance not answering `/health`.

`GET /health` (no token) answers `{"ok": true}` while the web API runs.

## Daily checklist for operators

1. Dashboard: **RPO breaches** at 0, **Objects needing attention** empty ("Every object is within its RPO."), no
   new entries under **Failed jobs**.
2. **Alerts**: handle and acknowledge new alerts.
3. **Jobs**: no job stuck in **Queued** for hours (a long-running job of the same source blocks the next one).
4. **Approvals**: tell the approvers about pending requests (they expire after 72 hours).
