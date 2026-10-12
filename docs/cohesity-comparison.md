# Cohesity 7.4.1 compared with NexusBackup

Source: Cohesity 7.4.1 User Guide, Platform CLI reference and release notes (local copies in `tmp/`, not in git;
page numbers are User Guide pages). Out of scope and skipped: SmartFiles, cloud platforms, NetBackup, Hadoop,
Kubernetes, SAN. Review date 2026-10-12, NexusBackup 0.0.1-alpha.

## Where NexusBackup is already ahead

- **Retention locks** only ever extend, follow GFS promotion and run on the compliance clock. Cohesity fixes a lock at
  snapshot or archive time and lets a role edit it (p.1246–49, 4300–02).
- **Four-eyes approvals** are built into the appliance, with split activation codes and diffs. Cohesity's quorum
  needs Helios (p.691–696).
- **Replication key hand-over** is sealed to the peer's key service and needs approval. Cohesity has the user paste
  the raw key (p.4431).
- **Offsite copies** are incremental-forever and self-describing, and the key escrow is locked too. Cohesity uses
  periodic fulls and reference chains (p.4358–61).
- **Teams channel posts** are restored with the original author and time. Cohesity can only download them
  (p.3818).
- **PostgreSQL** WAL is read from a replication slot, so no database restart is needed. Each snapshot is
  self-contained, so a point-in-time chain cannot break (p.3445, 2958).
- **Hardening:** no SSH or remote exec, default-deny egress, SELinux, mandatory TOTP, signed bootc updates with
  automatic rollback.

## Worth copying

Effort: S = days, M = 1–2 weeks, L = more.

### Tier 1: high value, fits the architecture as it is

| # | What | Cohesity | Effort | Where |
|---|---|---|---|---|
| 1 | **Auto-protect.** Group modes "all guests of the source except …", PVE pool/tag/node, M365 "members of an Entra group"; resolved on each run; exclusion wins | p.2583, 3698, 3709 | M | pve inventory, scheduler group resolution, plugin ListGuests; closes the "unprotected" KPI gap |
| 2 | **Run control.** Retries per policy (default 3 × 5 min, failed guests only); pause/resume a group and source maintenance mode with an end time; blackout windows; runtime-SLA alert ("run took > N min"); Back up now for failed or selected guests only | p.1223–24, 1644, 1725, 2596, 4442 | S–M | scheduler, catalog, Groups UI |
| 3 | **Change-rate anomaly alert** (ransomware signal): `new_bytes` far above the median of recent runs, or compression ratio collapsing; links to the last good snapshot | p.4799, 4805 | S–M | scheduler alerts; the data is already in job results |
| 4 | **Audit off the box.** RFC 5424 syslog over TLS with each entry's hash; filters and CSV export | p.393, 4898–4921 | S–M | anchors the hash chain externally (open gap in manual/10) |
| 5 | **Storage accounting.** Real dedup/compression ratios; logical / unique / stored per tenant and group; 7/30/90-day growth; soft per-tenant quota with alert | p.4638–48, 925–927 | M | dashboard (ratios are `null` today), Tenants page |
| 6 | **Alert lifecycle.** Resolve with a note; auto-resolve on a later success; a "what to do" text in each alert; notification rules by severity/kind with their own channels; webhook body template | p.4651–4662 | S–M | alerts, Settings → Alert delivery |
| 7 | **Diagnostics.** Redacted support bundle plus pass/warn/fail self-checks (also run before updates); **time-limited, approved console root access** that raises an alert | p.247–250, 702–769, 5171 | M | closes the "no console root shell" gap (manual/02) |
| 8 | **Retention for orphaned snapshots** (guests no longer in any group) and an approved, lock-safe snapshot delete | p.4452–56 | M | today these snapshots are never pruned (manual/05 Status) |

### Tier 2: clear benefit, smaller audience

- **Restore options:** network link down, powered off, name prefix, several guests in one job, restore over the
  original. For the last one, keep the old VM renamed and stopped; never delete it first, as Cohesity does on p.2670.
  Cancel a running restore. (p.2667–76)
- **Restore into a running host through an enrolled agent**, for VM files and NAS Tree snapshots. This replaces
  download-only. (p.2643)
- **Legal hold**, set and cleared by the security officer only, excluded from retention and GC (p.4457–59).
- **Replication sync window** (the firewall rule is open only inside it) plus **"Close vault now"**. A **vault
  profile** for a secondary: approvals forced on, restores need approval, management only from allowed IPs.
  (p.807–842)
- **Bandwidth time windows** for offsite and replication. plan.md promises these; they are not implemented.
  (p.4432)
- **Offsite browse and restore in the UI**, and attaching an offsite copy to a fresh appliance (p.4433–35).
- **M365:** skip and report failed items instead of failing the guest; hide unlicensed users; Recoverable Items;
  private channels; group mailbox; run guests in parallel, then multiple app registrations (p.3667, 3696–3724).
- **PostgreSQL:** frequent WAL-only runs (point-in-time RPO in minutes); show the recoverable time range; optional
  server start after restore; tablespace remap (p.3441–61).
- **Access:** Viewer role; file download as its own privilege; session list and revoke; configurable timeouts;
  scoped API tokens that can never approve; web certificate import via a CSR made on the appliance, with expiry
  alerts; login banner; management source-IP allow-list (p.586–702).
- **Scheduled CSV/HTML reports:** SLA per object, failed objects, storage per tenant (p.4850–98).
- **Consistency recorded per snapshot** (guest-agent fs-freeze yes/no), with a policy flag "require
  app-consistent" (p.2594–95, 2607).

### Tier 3: large

- Cross-snapshot file-name search.
- Linux bare-metal recovery or P2V through a rescue ISO enrolled as a temporary agent.
- A tenant-admin role.
- Controlled promotion of a replicated tenant (failover). This conflicts with the plan.md decision that a secondary
  never takes over.
- PST export.

## Deliberately not copied

- Push-install agents or run scripts over SSH/WinRM with stored admin credentials; NOPASSWD:ALL sudo; a support
  reverse tunnel; an SSH support user (p.4522, 3861, 702–769). These break the no-remote-exec, default-deny model.
- Locks fixed at creation or editable by a role; periodic full backups; separate log and full retention; Glacier or
  cloud tiering. Ours is simpler and safer.
- Overwrite-restore that deletes the original first.
- Instant volume or NAS mounts that serve decrypted backup data over the network.
- Password expiry and complexity rules, email OTP, admins exempt from lockout. These go against NIST 800-63B or
  weaken MFA.
- One-way feature toggles. Use approvals instead.
- Optional encryption, cross-tenant dedup, per-tenant external KMS.
- SNMP v1/v2c, a reporting database open to the network, cURL-option webhooks.
- Public folders: Microsoft ends programmatic access in 2026/27 (p.3733).
