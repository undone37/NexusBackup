# 11 Alerts and monitoring

The appliance watches its own work and raises **alerts** when something needs attention. You see them on the
**Alerts** page and the Dashboard, and the appliance can send them by webhook and email.

## The Alerts page

![Alerts](images/alerts.png)

Alerts are listed newest first with **Severity** (`critical`, `warning`, `info`), **Time**, **Kind** and
**Message**. Click **Acknowledge** when you have handled an alert; the appliance records who acknowledged it.
**Show acknowledged** also lists handled alerts. The Dashboard's **Open alerts** tile counts the unacknowledged ones.

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

## Delivery by webhook and email

The scheduler delivers every new alert to a webhook and/or by email, configured in the file
`/etc/nexus/alerts.json` on the appliance:

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

- Both parts are optional. Without the file, alerts only appear in the web interface.
- `tls` is `starttls` (default), `tls` (implicit TLS, usually port 465) or `none` (only for a local relay).
- The webhook receives a JSON `POST` with `id`, `ts` (Unix time), `severity`, `kind`, `message` and `host`
  (the appliance's name). Emails have the subject `[NexusBackup <host>] <severity>: <kind>`.
- Delivery is retried a few times (after 10 and 60 seconds). The webhook host and the SMTP relay are added to the
  outbound firewall allow-list automatically.

> **Status:** There is no web interface for alert delivery yet. The file has to be placed on the appliance from the
> console, which the hardened image does not make easy (see [02 Installation](02-installation.md)). Plan this during
> installation.

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

1. Dashboard: every guest **Protected**, the **Failed jobs** tile at 0.
2. **Alerts**: handle and acknowledge new alerts.
3. **Jobs**: no job stuck in **Queued** for hours (a long-running job of the same source blocks the next one).
4. **Approvals**: tell the approvers about pending requests (they expire after 72 hours).
