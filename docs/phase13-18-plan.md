# Phases 13–19: Cohesity-inspired features (Tier 1 + 2 + 3)

## Context
We compared Cohesity 7.4.1 with NexusBackup; the findings are in `docs/cohesity-comparison.md`. The user wants every
"worth copying" item implemented, Tier 3 included. Decisions confirmed on 2026-10-12:
- All tiers are in scope.
- **No failover.** A secondary never takes over a tenant; the plan.md decision stands.
- **Emergency console root access** unlocks with an **approved one-time code or the recovery key**.
- **Audit and alert forwarding** goes to **syslog over TLS and to HTTPS JSON**.

Goal: close our operational gaps (unprotected guests, missed RPOs from one-off failures, snapshots that are never
pruned, no forwarding off the box, no root shell, storage figures that are always empty) and add the restore,
vault, workload and access features. Every phase ships with tests, labs, the manual and screenshots, following the
existing rules: record decisions in plan.md, update state.md and commit after every step.

## How the work is organised
- Phases build on each other: 13 → 14 → (15, 16 and 17 in parallel) → 18. Within a phase, sub-steps that touch
  different files run as parallel worktree agents, as in Phases 9–12. Sub-steps that touch the catalog schema are
  merged one at a time, and each takes the next migration number.
- Every sub-step includes:
  - the catalog migration (v11 onwards, added to `MIGRATIONS` in `crates/catalog/src/lib.rs` with a migration test);
  - the API with tests in `crates/web-api/tests/`;
  - the mock (`web/mock/api.ts`), i18n (`web/src/lib/i18n.ts`) and UI;
  - the manual chapter, plus a scene in `manual/tools/screenshots.mjs`;
  - new pages and tabs in `lab/e2e/ui-smoke.mjs`;
  - SELinux rules (`os/selinux/nexus.te`) for any new helper;
  - state.md and a commit.
- New risky actions go through the existing approval pattern (`quorum::request` / an `execute` arm or a scheduler
  poller, `crates/web-api/src/quorum.rs`).
- New outbound destinations go through a `*_targets` function in `crates/scheduler/src/firewall.rs`, which feeds
  `sync_firewall`.
- After each phase: run the full local suite and the VM labs, then tag a pre-release (0.1.0-alpha after Phase 14,
  then one per phase). The ISO workflow attaches the ISO automatically.

---

## Phase 13: Operations core (Tier 1)

**13a. Retention for orphaned snapshots, and approved snapshot delete** (first, because the store grows today)
- Scheduler: after the per-group retention, sweep the store. List each tenant's store sources, subtract the union of
  `group_sources()`/`group_prefixes()` (`crates/scheduler/src/lib.rs:308,330`), and apply `Gfs::default()` (or the
  setting `orphan_gfs`) with `store.apply_retention`. Raise an `orphaned` info alert once per source.
- New approval action `snapshot.delete`, executed by the scheduler poller. `store.delete_snapshot`
  (`chunkstore/src/store.rs:680`) already refuses locked snapshots. Add a Delete action on the Snapshots page,
  shown only when the snapshot's lock has expired.

**13b. Run control**
- Migration:
  - `policies`: `retry` JSON (default `{count:3, delay_min:5}`), `blackout` JSON
    `[{days, from, to, abort}]`, `sla_minutes`.
  - `groups`: `paused_until` (NULL, a timestamp, or "indefinite"), `timezone`.
  - `sources`: `maintenance_until`.
  - `jobs`: `not_before`, `attempt`, `retry_of`.
- Schedule model (`scheduler/src/schedule.rs`): add `every N hours`, weekdays and `monthly D HH:MM`, all evaluated
  in the group's time zone (crate `chrono-tz`, must pass cargo deny). The existing `daily`/`hourly` strings stay
  valid.
- Retries: when a backup fails and the attempt limit isn't reached, queue a retry for the failed guests only, with
  `not_before = now + delay`. `job_failed` is raised only after the last attempt.
- Pause: a paused group or a source in maintenance is skipped in `queue_scheduled` (lib.rs:796). The dashboard
  status becomes "paused", and a pause longer than 7 days raises a warning.
- Blackout windows block new runs inside the window. With `abort`, a run that is still going is cancelled when the
  window starts.
- **Cancel running jobs:** a child-PID registry in `run.rs` (TERM, then KILL after 30 s); stop PVE tasks through
  the task DELETE API; the job state becomes `cancelled`. This is safe because a manifest is committed last and GC
  removes orphaned chunks. `web-api/src/jobs.rs:431` will then accept cancelling running jobs.
- SLA: if a running backup exceeds `sla_minutes`, raise an `sla_missed` alert.
- "Back up now" with `{group_id, guests:[…]}`, plus a "failed guests only" option. The planner already accepts
  guest lists (lib.rs:2085).

**13c. Auto-protect and guest inventory**
- New table `inventory(source_id, guest, name, tags JSON, seen, gone)`. The scheduler refreshes it periodically:
  - PVE: from `/cluster/resources?type=vm`, including `pool` and `tags`, read in `crates/pve`.
  - TrueNAS: datasets.
  - Plugins: the `ListGuests` result. `plugin-proto` gets an optional `tags` field on the guest; M365 emits
    `group:<Entra group>` and `license:none`.
- `groups.mode`: `explicit` (today's behaviour), `all`, or `tags` (any of the given tags, such as `pool:x`, `tag:y`,
  `group:Sales`), plus `exclude` (guest ids, which always win).
- Guests are resolved at queue and plan time in `groups()` (lib.rs:713). `group_sources()` uses the same resolved
  set, so retention and offsite-lag checks stay correct.
- TrueNAS "all" is no longer frozen at save time (`web-api/src/resources.rs:1535`).
- The dashboard's "not in a group" count comes from the inventory, which closes the open KPI gap.

**13d. Storage accounting and quotas**
- Connectors emit one structured line, `nexus-stats {json}`: read, logical, new_chunks, new_plain, new_stored.
  - chunkstore `FileStats` gains the sealed (stored) size, taken from `Keyring::seal` at `crypto.rs:147`.
  - Changes: nas `main.rs:292`, truenas `backup.rs:187`, pve `main.rs:102` plus the VM path, plugin-host
    `backup.rs:576`, agent-conn `main.rs:200`.
- The scheduler's `result()` (lib.rs:1296) parses that line into a new table
  `backup_stats(tenant, source, time, read, logical, new_chunks, new_plain, new_stored)`.
- Dashboard (`web-api/src/dashboard.rs:394`):
  - real figures: dedup = logical/new_plain, compression = new_plain/new_stored;
  - a breakdown per tenant and per group, with source mapped to group;
  - growth over 7, 30 and 90 days.
  - New Storage page.
- `tenants.quota_bytes`: a soft quota with `quota` alerts at 80 % and 100 %.

**13e. Change-rate anomaly alert**
- Runs after each backup, on `backup_stats`. Raise a critical `anomaly` alert when either holds:
  - `new_plain` > max(3 × the median of the last 14 runs, 1 GiB);
  - the compression ratio of new data is below 1.05 while the source's median is above 1.3 (an entropy proxy).
- The alert links to the source's last snapshot before the anomaly. Its Legal hold button arrives in 15c.
  Thresholds are in the setting `anomaly`.

**13f. Alert lifecycle and notification rules**
- `alerts` gains: `key` (dedup key), `tenant`, `count`, `last_ts`, `resolved_at`, `resolved_by`, `note`, `auto`.
- `alert()` (lib.rs:2702) increments `count` on a repeat. The code that raises an alert names a key, and the
  matching success path resolves it:
  - job OK resolves `job_failed:<group>`;
  - lag cleared resolves `offsite_lag`;
  - capacity back under the threshold resolves `capacity`;
  - a finished verify resolves `verify`;
  - an approved quorum resolves `gc_quorum`.
- Resolve and acknowledge in the UI with a note. Info alerts are pruned after 14 days (setting).
- Each alert kind gets a "what to do" hint (i18n plus the API payload).
- Setting `alert_rules`: named rules `{min_severity, kinds[], tenants[], channels}`, where a channel is email
  recipients, a webhook (fixed headers plus an optional body template with `{{field}}` placeholders and JSON
  escaping), syslog or HTTPS (14a). The current single configuration migrates to one rule.
- The payload gains `alert_url`, `first_ts`, `last_ts`, `count`, `hint`. Code: `scheduler/src/alerts.rs`,
  Settings → Alert delivery.

## Phase 14: Security and operations (Tier 1 + 2)

**14a. Audit and alert forwarding**
- A scheduler `forward` thread follows the `audit` table by seq (cursor persisted, at-least-once delivery, no gaps),
  plus alerts and job events.
- Two sinks, both configurable together:
  - **Syslog over TLS:** RFC 5424 with RFC 5425 octet framing over rustls, verified against a CA or a pinned
    certificate. Each audit message carries `seq` and `hash`.
  - **HTTPS JSON:** batched POST with a bearer or custom header, retries with backoff.
- A daily `audit.anchor` record carries the head hash, which anchors the chain outside the appliance.
- Audit page: filters (actor, action, target, date), CSV export (`/audit.csv`, including the hash column) and a
  forwarding status.

**14b. Diagnostics and self-checks**
- Root oneshot `nexus-diag`, triggered by a path unit (the `nexus-update.path` pattern). It writes:
  - a redacted support bundle (journal for a time range, `nexus-update status`, AVCs, nft drops, chrony, SMART,
    catalog statistics, keyd status) to `/var/lib/nexus/diag/`;
  - a `checks.json` with pass/warn/fail, severity and a link to the manual for each check: disk, time, egress,
    keyd, certificates, audit verify, catalog integrity, SELinux mode.
- Settings → Diagnostics (admin only, audited), with download through the existing download mechanism.
- `nexus-update` runs the checks before staging an update and refuses when a check fails.

**14c. Emergency console root access**
- Gate program `/usr/libexec/nexus/console-gate`, run by an agetty on tty2 with no login prompt. It accepts either:
  - (a) a one-time code issued after an approved `console.unlock` request (target user, duration of at most 8 h;
    the requester sees the code once; only a hash is stored in `/var/lib/nexus/console-unlock/`); or
  - (b) the recovery key (keyd escrow check, as in `crates/setup/src/recover.rs`).
- On success it starts `systemd-run --pty -p RuntimeMaxSec=<dur> /bin/bash`, writes the audit entry
  `console.root_shell`, raises a critical alert and shows a banner in the web UI.
- An SELinux transition to `unconfined_t` for the shell only, documented in the threat model.
- Closes the "no root shell" gap in manual/02.

**14d. Access**
- Migration that rebuilds `users`: adds roles `viewer` and later `tenant_admin` (18c), a `can_download` flag (default
  on for admin and operator, off for viewer), and `expires`.
- Sessions: `ip` and `user_agent` columns; list and revoke one session, all sessions of a user, or all sessions
  (admin). Configurable idle (5–120 min) and absolute (1–24 h) timeouts (setting `session`, `auth.rs:19`). Accounts
  unused for N days are disabled, never the last admin.
- **API tokens:** table `api_tokens(id, user_id, name, hash, scope read|operator, expires, last_used)`;
  `Authorization: Bearer nxt_…` accepted in the `Ctx` extractor (`auth.rs:110`), no CSRF needed. Tokens can never
  approve, change settings, users or tokens, or download. They are shown once, audited and revocable.
- **Web certificate import:** root helper `nexus-tls` (path unit) creates the key and CSR on the appliance, then
  validates the imported chain (matches the key, SAN covers the host, chain complete). The web-api hot-reloads it
  through a rustls cert resolver that watches the file (`web-api/src/tls.rs:49`).
- **Expiry alerts** at 90/30/7 days for the web certificate, agent certificates (`agent-conn/src/ca.rs`), replication
  peer pins and the IdP client secret, if its expiry is entered.
- Login banner (setting, public `/auth/banner`).
- **Management source-IP allow-list:** an input set in `os/nftables.conf` managed by nftsync (empty = any). Changes
  need approval. The console wizard's menu can reset it.
- Warning when fewer than 3 people can approve. Document the procedure for when approvers are unavailable (manual/10).

**14e. Scheduled reports**
- `/reports/{sla,failed,storage,protection}.csv`, tenant-scoped.
- Setting `reports`: weekly or monthly HTML email with CSV attachments, sent through the existing SMTP path in
  `alerts.rs`.

## Phase 15: Restore and protection (Tier 2)

- **15g. Per-tenant file index and search (moved here from 18a by user request, 2026-10-12).** A sealed index per
  tenant and source, written at snapshot commit from the Tree entries (path, size, mtime, snapshot); search API +
  search field (name/wildcard, filters tenant/source/date); results open download or restore; entries go with
  their snapshot; VM disks opt-in via the restorevm micro-VM listing.

- **15a. Restore options.**
  - `RestoreP` (`web-api/src/jobs.rs:89`) gains `link_down` (the backend already exists, `pve/src/ir.rs:115`),
    `start`, `name` (prefix or name) and `pool`.
  - Restore several guests or a whole group in one dialog (one job per guest).
  - **Replace original** (approval `restore.replace`): the original is stopped, renamed `<name>-replaced-<ts>` and set
    to onboot=0, never deleted. The restored VM gets the original name.
  - Cancelling a running restore uses 13b.
- **15b. Restore into a host through an agent.** Generalise `agent-conn/src/restore.rs:80` `load_tree` to any Tree
  snapshot of the same tenant (nas-, share-, plugin- file trees), and add a target-agent picker on the Snapshots
  page. VM/CT files: the restorevm microVM streams a tar, which is bridged into agent entries. Ends download-only
  for NAS and VM file restores.
- **15c. Legal hold.**
  - `snapshots.legal_hold` (by, reason, ts). Setting it is security officer only, immediate and audited. Releasing
    it needs approval.
  - Retention, GC, `snapshot.delete` and offsite retention skip held snapshots.
  - The anomaly alert (13e) offers "hold last good snapshot".
  - Holds are exported to a secondary as advisory metadata; the secondary's security officer gets an alert with
    "apply".
- **15d. Consistency per snapshot.** Parse the guest-agent fs-freeze lines from the vzdump task log
  (`pve/src/backup.rs:187`, `api.task_log`). Add `snapshots.consistency` (`app|crash|unknown`, also from agent and
  plugin results). Policy option `require_consistent`: warn, or fail.
- **15e. Disk and file selection.**
  - Per-group `exclude_disks` (PVE), respecting `backup=0`; restore creates empty placeholder disks.
  - Agent and NAS: include paths, regex excludes, global excludes in the policy, skipping nested mounts by file-system
    type (`agent-core`, `crates/nas`).
- **15f. Agents.**
  - Certificate renewal over the existing mTLS session, 30 days before expiry, with a new CSR (`ca.rs:179`).
  - Re-registration that keeps `agent_id` and settings.
  - Appliance-side bandwidth and CPU limits enforced by the agent.
  - Run guests in parallel within a group (per-group limit, default 2).

## Phase 16: Hardware and inbound firewall (added 2026-10-12, user request)

- **16a. Disks + SMART:** disk inventory, smartmontools in the image, SMART attributes/self-tests in the UI, `disk`
  alerts (SMART failing, pending/reallocated sectors, temperature, md degraded/rebuilding).
- **16b. Disk layout (mdadm + XFS):** data/metadata arrays from empty disks, spares, replace + rebuild, grow, via a
  root helper with its own SELinux domain; approval + typed confirmation for destructive steps; system disks shown only.
- **16c. Inbound firewall:** per-service source restrictions (8443, replication, future services) in the UI,
  generalising the 14d management allow-list; approval for every change; console reset.

## Phase 17 (was 16): Offsite, replication, vault, tenants (Tier 2)

- **16a. Time windows.** One shared window type, `[{days, from, to, action: pause|limit, rate}]`, in
  `schedule.rs`:
  - per offsite target: the uploader reads its current limit dynamically (`offsite/src/target.rs:349`);
  - per replication source: `replication/src/client.rs:363` Limiter;
  - per replication source sync window: the firewall target is added only inside the window
    (`scheduler/src/replica.rs:73`); a sync still running is cancelled when the window closes and resumes next time.
- **16b. "Close vault now".** Sets `closed_until = ∞` on a replication source: the firewall drops the target
  immediately. Reopening needs approval.
- **16c. Vault profile** for a secondary (setting `vault_mode`):
  - no local-backup tenants and no outgoing peers;
  - approvals forced on (`approvals.disable` refused);
  - restores and downloads need approval;
  - the management allow-list (14d) is required;
  - turning the profile off needs approval plus the recovery key.
- **16d. Offsite in the UI.**
  - Job kinds `offsite_list` and `offsite_restore`. The restore pulls the snapshot into the local store, and the
    normal restores apply from there. They wrap `crates/offsite/src/main.rs` `list`/`restore`.
  - Offsite-only snapshots appear on the Snapshots page.
  - **Attach an offsite copy** to a fresh appliance: Tenants → Attach, which wraps `nexus-offsite dr`. The security
    officer types the recovery key, approval is required, and it is audited.
- **16e. Optional per-tenant recovery key.** keyd escrow adds a second wrap of the tenant's data keys
  (`keys/tenants/<t>/`). The key is generated on request (approval) and shown once. `nexus-offsite dr --tenant-key`
  then lets a tenant rebuild without the appliance-wide recovery key.
- **16f. Tenant deactivate.** `tenants.disabled` pauses schedules and blocks the tenant's logins and tokens.
  Quotas are in 13d.

## Phase 18 (was 17): Workloads (Tier 2)

- **17a. M365** (`plugins/m365`):
  - Skip and report failed items: the guest ends as a **warning** with a failure count instead of aborting.
    `backup.rs`'s `Err(e) => return Err(e)` becomes per-item; core gains `result.warnings`, shown on the dashboard.
  - Unlicensed users tagged and excluded by default (`assignedLicenses`).
  - Recoverable Items: Deletions folder.
  - Private and shared channel sites under the team.
  - Group mailbox: conversations and calendar, for teams and M365 Groups (a new guest type).
  - Team sites hidden from the Sites list.
  - Several app registrations used round-robin: config `apps[]`, with the single app as a compatible default.
  - 1:1 and group chats through the export API: download only, opt-in because it is metered.
  - Cross-tenant restore: target another registered source of the same plugin kind (core: restore target
    selection).
  - App registration helper script (az CLI / PowerShell) in `plugins/m365/tools/`, run on the admin's machine.
- **17b. PostgreSQL** (`plugins/postgresql`):
  - WAL-only runs: an "every 15 min" schedule (13b) plus a `recent: hours` keep-all class in `Gfs`
    (`chunkstore/src/retention.rs`). `data/` stays `Unchanged`, so only new WAL is transferred.
  - The recoverable range (base start to WAL end) is stored in the snapshot metadata and shown in the PITR dialog.
  - Options to start the server after restore (`pg_ctl start` over SSH) and to remap tablespaces, replacing the
    current refusal (`physical.rs:615`). LSN and named restore-point targets.
  - HA: a list of hosts; back up from the primary (`pg_is_in_recovery()`), and take a new base backup after a
    failover.

## Phase 19 (was 18): Tier 3

- **18a. File-name search across snapshots.**
  - First step: a search job that scans the sealed Tree indexes of a tenant's snapshots with a time budget and
    returns path, snapshot and size. The results can start a restore.
  - If that is too slow: a sealed per-source path index (fst) written at commit time.
  - VM file search: an opt-in group flag lists the VM's files through the restorevm microVM after each backup and
    stores the list sealed.
  - M365: subject, from, to and date as metadata, so items can be found and picked into restore `paths`.
- **18b. Linux bare-metal recovery and P2V.**
  - The agent records the disk layout (sfdisk, LVM, file-system UUIDs, bootloader) in the snapshot.
  - A rescue ISO (from `restore-vm/` plus the agent in rescue mode, built by the ISO workflow) enrolls with a
    one-time token over mTLS, recreates the partitions, runs restore-to-path, then reinstalls the bootloader.
  - "Restore as PVE VM": create the VM with matching disks and boot the rescue ISO in it.
- **18c. Tenant-admin role.**
  - Manages the tenant's own users (tenant_user and tenant_admin), sources and protection groups, using only
    policies the admin assigned (`tenant_policies` table).
  - No access to offsite, keys, retention cuts or approvals.
  - An admin can "view as tenant"; this is audited.
  - OIDC role mapping updated (`oidc.rs:61` `ROLES_BY_RANK`).
- **18d. Mail export.** mbox and `.eml` tree first, then a PST writer in the plugin (Unicode PST, mail only).

**Not done (decision kept):** failover or promotion of replicated tenants. DR stays "rebuild a primary from the
secondary or the offsite copy".

---

## plan.md updates (first commit of Phase 13)
- §15: add Phases 13–18 as above.
- §2: decision rows:
  - no failover (reconfirmed);
  - emergency root access by approved code or recovery key;
  - forwarding by syslog over TLS and HTTPS JSON;
  - orphan retention uses default GFS;
  - legal hold set by security officer only, release needs approval;
  - API tokens can never approve;
  - vault mode can only be turned off with approval plus the recovery key;
  - PST after mbox/eml.
- §16: risks: the anomaly heuristics' false-positive rate, tenant-admin scope creep, PST writer complexity.

## Verification (per phase, plus at the end)
- **Unit and integration tests:**
  - catalog migration tests;
  - scheduler tests (`crates/scheduler/src/tests.rs`): retry, pause, blackout, auto-protect resolution, orphan
    sweep, anomaly, auto-resolve;
  - web-api tests (`tests/api.rs` role matrix including viewer, tenant_admin and tokens; `phase12.rs` pattern for
    settings).
- **Local gates:** `cargo test --all`, nightly clippy, fmt, cargo deny, `npm run check && npm run build`,
  greenboot tests, check-trust.
- **VM labs on the real image, SELinux enforcing, 0 unexpected AVCs:**
  - `lab/appliance/e2e.sh all`: PVE retries, pause, auto-protect by pool/tag, replace-original restore, cancel a
    running backup, legal hold blocks retention;
  - `lab/appliance/plugins.sh`: PG WAL-only plus PITR range; M365 against the Graph mock;
  - replication lab: sync window, close vault, vault mode;
  - offsite lab: UI restore, attach to a fresh appliance;
  - forwarding against an rsyslog TLS testbox container and a local HTTPS sink;
  - console gate driven over the serial console (`con.py`), with a code and with the recovery key;
  - BMR: rescue ISO restores a Linux lab VM, which then boots.
- **UI:** `lab/e2e/ui-smoke.mjs` with every new page and tab, both themes; regenerate the manual screenshots.
- **CI:** green on GitHub; a pre-release tag per phase; ISO attached; `lab/appliance/iso-test.sh` on the new ISO.
