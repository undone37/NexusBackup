# Cohesity NetBackup (formerly Veritas NetBackup) compared with NexusBackup

Sources: NetBackup 11.0, 11.1 and 11.2 release notes (Cohesity documentation portal), NetBackup 11.x administrator
guide pages on docs.cohesity.com, Cohesity press releases and blogs, trade press; links in [Sources](#sources). No
NetBackup installation was tested. Checked against plan.md (§2, Phases 13–27), state.md, docs/agent-update-plan.md,
the manual, docs/cohesity-comparison.md, docs/veeam-comparison.md and docs/commvault-comparison.md, so items already
built or planned there are not listed as gaps, and items the Commvault review already proposes are cross-referenced
instead of repeated. Review date 2026-10-13, NexusBackup main (0.1.x alpha).

## Summary

**Product state.** Cohesity completed the combination with Veritas' enterprise data-protection business in December
2024; NetBackup, the NetBackup appliances and the Alta cloud services moved to Cohesity, while Backup Exec,
InfoScale and the compliance products went to the spin-off Arctera [1]. NetBackup continues as its own product line
next to Cohesity DataProtect: 11.0 (March 2025: post-quantum TLS, risk-engine user-behaviour detection, more PaaS)
[2][3], 11.1 (late 2025: freeze mode, YARA scanning, abort-on-infection, KVM, network access control) [4] and 11.2
(GA 28 May 2026, 11.2.0.1 in September 2026: file-hash threat detection, role elevation, Helios integration,
Java console removed) [5]. The convergence path is management (NetBackup domains registered in Cohesity Helios [5])
and storage (NetBackup DirectIO / "Cohesity Data Cloud for NetBackup" writing to Cohesity SpanFS [6]); the Veritas
names are being replaced (Alta Recovery Vault is now "FortKnox for NetBackup" [7]). Because Cohesity DataProtect is
already covered in docs/cohesity-comparison.md, this review concentrates on what is specific to NetBackup.

**Positioning.** NetBackup is a large-enterprise, multi-tier product: a primary server (catalog, policies), media
servers that move data to storage units (MSDP dedup pools, cloud, tape, OST devices), clients and plugins for almost
every workload, plus appliances (Flex, Flex Scale clusters of 4–16 nodes [8]) and cloud services. Its strengths are
breadth (databases, tape, NDMP, cloud PaaS, Kubernetes), very flexible copy management (storage lifecycle policies,
Auto Image Replication) and a long list of cyber-resilience features added since 9.1.

NexusBackup is one hardened appliance for Proxmox VE-centric SMBs and MSPs: pull model, default-deny egress, SELinux,
signed bootc image, per-tenant encryption, four-eyes approvals, offsite to Storage Box or S3 Object Lock, replication
to a vault appliance. NetBackup has no native Proxmox VE integration (its 11.1/11.2 KVM support is plain KVM; the
Proxmox community still asks for it [9]). The lessons worth taking are in NetBackup's cyber-recovery details and
copy management, not in its workload list or its media-server architecture.

## Feature comparison

Status: **has** = built (lab-proven at least), **partial** = some of it built or planned in an open phase,
**missing** = neither built nor planned.

| Area | NetBackup 11.x | NexusBackup | Status |
|---|---|---|---|
| **Workloads** | | | |
| Proxmox VE | no native support; KVM agentless since 11.1, Accelerator and single-file restore for KVM in 11.2 [4][5][9] | VMs + LXC via the PVE backup provider API, dirty bitmaps, fleecing guard, instant recovery, instant disk, restore tests | has (ahead) |
| VMware, Hyper-V, Nutanix AHV, RHV/OLVM, OpenStack | yes; Instant Access VMs on AHV since 11.1, VMware → AHV cross-hypervisor restore [4] | none; Hyper-V host-level open (Phase 23); VMware as plugin is Commvault Tier 2 | missing |
| Physical Linux / Windows, BMR | clients, Accelerator, BMR | agents (deb/rpm/MSI, x86_64 + aarch64), fleet enrollment, edge proxy, Linux BMR/P2V; Windows BMR open | has / partial |
| NAS | NDMP, Dynamic NAS (NAS-Data-Protection), Universal Shares [10] | NFS/SMB, TrueNAS incl. existing-snapshot mode | has |
| Databases | Oracle, SQL Server, SAP HANA (intelligent policy 11.2), DB2, Informix, SAP ASE, MongoDB, PostgreSQL (pgBackRest 11.1), MySQL (XtraBackup 11.1), Greenplum [3][4][5] | PostgreSQL and MySQL/MariaDB plugins with PITR; MSSQL PITR open | partial |
| Exchange / M365 | Exchange GRT (web UI recovery 11.2), M365 as a separate SaaS service [5] | M365 plugin (Exchange, OneDrive, SharePoint, Teams, Entra ID export, PST export); on-prem Exchange VSS copy only | has / partial |
| Kubernetes, cloud PaaS, object stores | Kubernetes operator, ~30 PaaS databases, cloud object store protection [2][11] | none | missing (out of scope) |
| **Architecture / storage / dedup** | | | |
| Topology | primary server + media servers + storage units; Flex (containerised instances), Flex Scale (4–16 nodes) [8] | one appliance; scale-out only as groundwork (docs/scale-out.md) | different by design |
| Dedup | MSDP: global per pool, client-side dedup, fingerprint cache, cloud tier (MSDP-C), Instant Access from MSDP [5][10] | per-tenant keyed dedup, agent-side chunking, always-on XChaCha20 envelope encryption | has |
| Incremental change tracking | Accelerator (track log, change journal) with scheduled **forced rescan** [12] | dirty bitmaps (PVE), USN journal (Windows), metadata cache (Linux, NAS); scheduled full read per group with drift check (Phase 29) | has |
| Immutability | MSDP WORM in compliance or enterprise mode (enterprise: security admin can lift locks), cloud Object Lock, local WORM cache for MSDP-C (11.2) [5][13] | extend-only store locks on a compliance clock, no role can shorten them; S3 Object Lock offsite | has (stricter) |
| **Lifecycle / replication** | | | |
| Copy management | Storage lifecycle policies: any chain of backup → duplicate → replicate → import, retention per copy, retries until done [14] | local copy + one offsite target per tenant + replication; offsite retention = largest GFS class of the tenant's policies | partial |
| Cross-domain replication | Auto Image Replication (target domain imports and owns retention), cross-domain replication of single images (11.1) [4] | pull replication with independent secondary retention, vault mode, sync windows | has |
| Air-gapped vault | Isolated Recovery Environment: pull-based MSDP reverse connection inside an air-gap schedule [15] | vault mode, replication sync window, "Close vault now" | has |
| Vendor cloud vault | FortKnox for NetBackup (formerly Alta Recovery Vault) on AWS/Azure [7] | customer-owned Storage Box / S3 Object Lock / vault appliance | different model |
| **Security / cyber resilience** | | | |
| Multi-person authorization | MPA tickets for image expiry, hold removal, security settings, keys, policy changes, WORM changes; exempt users possible [16] | quorum on all destructive/weakening actions, no exemptions | has |
| Backup anomaly detection | ML clustering on image size, file count, KB transferred, dedup rate, job duration; sensitivity setting [17] | change-rate and compression anomalies, ransom-note names, mass renames, snapshot diff, trend sparklines | has (no duration signal) |
| User-behaviour / risk engine | unusual sign-in time, unusual policy updates/deletes, MFA challenge for suspicious configuration changes, risk score [2][3] | failed-login metric, dormant-account disable, posture checks, new-device notice (Phase 28), deterministic risk signals with step-up (Phase 29) | has (no score) |
| Malware scanning | on-demand and anomaly-triggered scans, Trend Micro, Sophos, NextGen scanner, YARA (11.1), abort on first infection (11.1), file SHA-256 hashes for IOC matching (11.2), permission "recover from infected images" [4][5][18] | YARA in an offline restore micro-VM, "scan first" restores; scheduled scans and IOC hashes are Commvault Tier 1 #1/#2 | partial |
| Clean restore | `bpcleanrestore`: infected files replaced by their last clean version [19] | restore dialogs default to the newest clean snapshot; synthetic clean restore is Commvault Tier 2 | partial |
| Freeze / lockdown | freeze mode: blocks configuration changes, backups/SLP, restores and image expiry; maintenance mode auto-reverts [4][20] | incident mode: holds, paused groups, all other sessions and tokens ended, optional freezes of configuration, deletions and restores to production (Phase 29); tenant lockdown with its own freezes | has |
| Least privilege | RBAC with custom roles and object groups, role elevation (11.2) [5] | fixed roles (admin, operator, SO, viewer, tenant roles), scoped API tokens, passkeys | partial |
| Post-quantum crypto | hybrid PQC for TLS 1.3 via the OQS provider (11.0) [3] | XChaCha20 data (256-bit keys, quantum-robust); X25519 in TLS, tenant escrow sealed boxes and replication key export | missing |
| Management access control | network access control for web APIs (11.1) [4] | inbound firewall per service with approval | has |
| **Recovery** | | | |
| Instant access | Instant Access VMs (VMware, AHV), Instant Access for MSDP-based file and DB images via NFS/SMB [10] | instant recovery, instant disk recovery, plugin mount | has |
| Instant rollback | roll a running VMware VM back by writing only blocks that differ (CBT) [21] | replace-original restore with approval (full write) | missing |
| Orchestrated DR | Resiliency Platform (status after the merger unclear), recovery to cloud | restore tests, recovery plans with waves, readiness, DR report | has |
| **Operations / automation / analytics** | | | |
| Policies | classic policies, Protection Plans, intelligent (query-based) policies | policies, protection groups, auto-protect, policy tiers, restore point simulator | has |
| Job control | queue priorities editable in Activity Monitor (11.2), checkpoint restart, auto-resume [5] | retries for failed guests, blackout/pause, restore priority, caps; no per-job priority | partial |
| API / automation | REST (Swagger on the primary), Ansible playbooks (11.0) [3] | OpenAPI, `nexusctl`, scoped API tokens, webhooks | has |
| Analytics | NetBackup IT Analytics: multi-vendor reporting, chargeback, forecasts [22]; Helios cross-domain view (11.2) [5] | dashboard KPIs, growth forecast, scheduled reports, billing export; multi-appliance view is Commvault Tier 2 | partial |
| Support | log collection by job ID, Troubleshooter with status-code guidance (11.2) [5] | redacted diagnostics bundle, self-checks, alert hints | has |
| **Multi-tenancy** | RBAC object groups, Flex multi-tenant instances, MSP via separate domains | tenants with per-tenant keys, tenant admin, per-tenant OIDC, view-as-tenant, billing export | has |
| **Cloud** | MSDP-C cloud tier incl. archive tiers (AIR/DR from Glacier 11.0, archive verify 11.2), Cloud Scale on Kubernetes [3][5] | S3 offsite (Glacier IR / IA classes, no archive classes) | different scope |
| **Licensing / deployment** | commercial subscription editions; software, Flex/Flex Scale appliances, Cloud Scale | AGPL-3.0, no per-TB or per-VM licence, one bootc image (ISO, VM) | different model |

## Where NexusBackup is deliberately different or ahead

- **Proxmox VE is first-class.** NetBackup protects plain KVM and other hypervisors but not PVE through its own backup
  provider API; NexusBackup does VMs and LXC with dirty bitmaps, fleecing guard, VM identity checks, instant recovery
  and isolated restore tests.
- **Locks nobody can shorten.** NetBackup's WORM enterprise mode lets a security administrator lift a lock, and MPA
  allows exempt users [13][16]. NexusBackup locks only extend; approvals have no exemptions; disabling them needs a
  second person.
- **No media-server tier to secure.** NetBackup spreads trust over primary, media servers, clients and scan hosts
  that all hold certificates into the domain. NexusBackup pulls from sources that hold no credentials to the
  appliance; PVE and TrueNAS get a forced-command SSH key; agents never connect out (the edge relay sees only TLS
  records).
- **Encryption always on, keys per tenant**, offline recovery key, self-describing offsite copies that a fresh
  appliance restores without any catalog import. NetBackup DR needs the catalog backup and DR package.
- **Forever-incremental without synthetic fulls.** Every NexusBackup snapshot is a complete index over shared chunks;
  NetBackup's Accelerator still produces "fulls" whose cost is hidden by the track log and needs forced rescans.
- **Appliance hardening as product:** SELinux enforcing, signed bootc with rollback, no SSH, GRUB lock, approved and
  time-limited console root, egress default-deny. NetBackup 11.2 adds STIG verification for MSDP packages on
  build-your-own servers [5]; the rest is left to the customer.
- **No vendor cloud in the loop.** Helios integration, Copilot and FortKnox need Cohesity's cloud [5][7]; NexusBackup
  works fully offline and stays customer-owned.

## Worth copying

Effort: S = days, M = 1–2 weeks, L = more. Phase labels are suggestions: Phase 27 = agent updates, Phase 28 is
reserved for the Commvault items, so everything here is **Phase 29+** (see the open questions for the numbering).
Items the Commvault review already proposes are not repeated: scheduled threat scans and a recovery calendar
(Commvault #1), IOC hash hunting (Commvault #2, matching NetBackup 11.2 file hashes), tenant lockdown (#3), the
new-device sign-in notice (#4), synthetic clean restore (NetBackup `bpcleanrestore`), the multi-appliance overview
(NetBackup Helios integration) and a VMware plugin. NetBackup confirms that each of them is industry practice.

### Tier 1: high value, small, fits the architecture as it is

| # | What | NetBackup | Effort | Where |
|---|---|---|---|---|
| 1 | **Scheduled full read ("forced rescan") with drift check.** Policy setting `full_read_days` (0 = off; proposed default 30 for agents/NAS, 90 for PVE): the next backup after the interval ignores change tracking (PVE: drop the dirty bitmap for that run; Windows: ignore the USN journal; Linux/NAS: ignore the metadata cache). The run then compares: chunks that changed in regions or files the tracker had reported unchanged since the previous snapshot raise `change_tracking` (warning) and are counted in the job result. Catches silent bitmap/USN/cache bugs that otherwise corrupt every later restore point | Accelerator forced rescan schedule [12] | S–M | `crates/retention`/policy schema, `crates/scheduler` (run flag), `crates/pve`, `crates/agent-core`, `crates/nas`; read-limit windows and fleecing guard apply as usual |
| 2 | **Restore from an infected snapshot needs a second person.** A snapshot with a YARA hit (21e flag, not the change-rate flag) can still be browsed and scanned, but restoring it to a production target (original VM/CT, replace-original, `restore_files` into an agent, instant recovery with links up) needs approval `restore.infected` or forces `scan_first: link_down`; downloads by admins/SOs only. The default "newest clean" stays | permission "Allow recovery from infected images", warning dialog [18][19] | S | `crates/scheduler` (`plan` check next to `hold_for_scan`), `crates/web-api` quorum action, restore dialogs |
| 3 | **Scan back to the last clean snapshot.** Job `scan_back {source, from}`: scans `from`, then older snapshots one by one, each scan **stopping at its first match**; the first complete clean scan is marked "verified clean" and offered as the restore point; optional bisect over long chains. Abort-on-first-hit also for normal scans (`stop_on_match`, default on for `scan_first`) | abort malware scan on infection, "move to the next recovery point" (11.1) [4] | S | `crates/scheduler` scan.rs, restore micro-VM scan runner (`nexus-pve scan` flag), Snapshots page; complements Commvault #1 (schedules) |
| 4 | **Freeze options for incident mode.** Checkboxes when entering: *freeze configuration* (every configuration-changing API call is refused, including by admins, except incident, approvals and user lock/disable endpoints); *freeze deletions* (retention, GC, offsite retention and replication pruning paused; locks keep running); *freeze restores to production* (only downloads and isolated restore tests). Leaving stays a two-person action. Pairs with Commvault #3 (tenant-scoped lockdown) | freeze mode, maintenance mode (11.1) [4][20] | S–M | `crates/web-api/src/incident.rs` (middleware check), `crates/scheduler` (maintenance gates), manual 14 |
| 5 | **Risk signals on privileged activity.** Deterministic rules, no ML: sign-in at an hour the account has not used in 90 days; burst of weakening requests (≥ N retention/approval/firewall/forwarding changes in an hour); bulk deletes or hold-release requests; download volume far above the account's median; first API token use from a new network. Raises `user_risk` (category security) and marks the session "step-up": the next sensitive action asks for password + TOTP/passkey again. Same tables as Commvault #4 (seen devices) | risk engine: unusual sign-in time, unusual policy changes, MFA for suspicious configuration changes [2][3] | S–M | `crates/web-api` auth/audit hooks, `crates/catalog` (per-account activity summary), alerts |

**Status (Phase 29): all five Tier 1 items are implemented** (API, scheduler, connector and UI tests, demo backend;
lab runs pending). Deviations from the proposals above:

- **#1 Full read:** a per-group setting (`groups.full_read_days`, `PUT /groups/{id}/full-read`), not a policy field;
  on by default (90 days PVE VM groups, 30 days agents/NAS/TrueNAS), 0 = off. Containers and plugin sources have no
  full read. A PVE VM keeps reusing its dirty bitmap during the full read (so the tracker's report can be compared);
  without a reusable bitmap there is no baseline. Drift raises `change_tracking` as **critical** (not warning); the
  result per source is on the Dashboard (`GET /full-reads`).
- **#2 Infected restores:** applies to every **flagged** snapshot (anomaly or scan hit, not cleared), not only YARA
  hits. No forced `link_down`: the dialogs offer the isolated variants and a production restore becomes the approval
  `restore.infected`; with approvals off only administrators (security officers do not restore at all). Downloads,
  mounts and other isolated restores stay open to the usual roles; API tokens are refused.
- **#3 Scan back:** job `scan_back` running one ordinary `snapshot_scan` per snapshot with `stop_on_match`, newest
  first, at most 30 (up to 100) snapshots; the recommended snapshot is marked (`clean_point`, badge "Recommended
  restore point") and preferred by the restore dialogs. No bisect; stop-on-match is used for scan back only (normal
  scans and scan first still list all matches).
- **#4 Freezes:** checkboxes when entering incident mode (configuration, deletions, restores to production) and, for
  deletions and restores, in the tenant lockdown dialog. A frozen configuration still accepts jobs (backups continue),
  holds, pauses, scans, approvals and account disabling; updates are refused like other configuration changes.
  Lifting a freeze is its own second-person approval (`incident.freeze.lift`); leaving incident mode ends it too.
- **#5 Risk signals:** four rules (unusual hour, >= 5 weakening requests or >= 10 delete requests per hour, download
  volume); the "first API token use from a new network" rule was left out (Phase 28's device records cover sessions
  only). A mark lasts 24 hours: step-up once per session (428 until `POST /auth/step-up`), API tokens read-only,
  cleared by a second person (`GET /risk`, `POST /users/{id}/risk/clear`).

### Tier 2: clear benefit, larger effort or smaller audience

- **Instant rollback of a PVE VM.** Roll a VM back to a snapshot by writing only the blocks that differ: compare the
  fixed indexes of the target snapshot and the newest snapshot by chunk ID (no data read), add the regions in the
  VM's current dirty bitmap (writes since the newest backup), then write exactly those chunks onto the stopped VM's
  disks through the existing NBD/forced-command path. Falls back to a full replace if the bitmap is gone or the VM
  identity changed. Same approval as replace-original (`restore.replace`), old state kept as a PVE snapshot when the
  storage supports it. After ransomware on a 2 TB VM with 5 % changed blocks this is minutes instead of hours. Effort
  M–L; `crates/pve`, `pve-plugin` helper (new write command), restore dialog. [21]
- **Second offsite copy with its own retention (SLP-style).** A tenant gets up to two offsite targets (e.g. Storage
  Box for fast restores, S3 Object Lock for immutability), each with its own GFS and lock, plus optional
  per-policy offsite GFS ("local 30 days, offsite monthly for 7 years"). The offsite engine already works per target
  and keeps independent retention; the change is a target list per tenant, copy status per target on Snapshots,
  inventory/verify per target and `offsite_lag` per target. Touches the plan §2 decision "offsite retention identical
  to local" (see questions). Effort M–L; `crates/offsite`, `crates/retention`, catalog, Tenants page. [14]
- **Just-in-time role elevation.** Accounts can hold a standing lower role (operator or viewer) plus an *eligible*
  role (admin or SO). Elevation for 15 min to 8 h needs password + passkey/TOTP, optionally approval
  (`role.elevate`), raises an info alert and shows a banner; it ends at expiry or sign-out. A new posture check can then warn about
  standing admin accounts. Effort M; `crates/web-api` RBAC and sessions, Users page. [5]
- **Hybrid post-quantum key wrapping.** Inventory the places where long-lived secrets rest under X25519 only: tenant
  recovery-key escrow (`tenant-escrow.*` sealed boxes stored offsite for years), replication key export
  (`export-for`), configuration bundle sealing. Add an X25519 + ML-KEM-768 hybrid layer in keyd (pure-Rust ML-KEM
  crate, subject to `cargo deny`) with a format version, so data harvested from an offsite provider today cannot be
  opened later. TLS (agents, replication, edge) follows once the rustls provider in use offers the
  X25519MLKEM768 group (the `ring` provider currently does not; `aws-lc-rs` would add a C dependency). Chunk data
  needs nothing: XChaCha20 with 256-bit keys is already quantum-robust. Effort M; `crates/keyd`, `crates/offsite`
  escrow, `crates/replication`, ADR. [3]
- **Backup-duration and dedup-rate anomalies.** Add job duration and new-chunk ratio (unique / logical) per guest to
  the existing change-rate checks, with the same median-of-history model and a per-source sensitivity (low, medium,
  high) instead of raw thresholds. A ransomware-encrypted guest shows up as "same size, nothing deduplicates, takes
  three times as long". Effort S–M; `crates/scheduler` anomaly.rs, `backup_stats`. [17]

**Status (Phase 30): all five Tier 2 items are implemented** (API, scheduler, node helper and keyd tests, demo
backend; lab runs pending). Deviations from the proposals above:

- **Rollback:** an option of "replace original" (approval `restore.replace`). The VM's current dirty bitmap is read
  by a pre-rollback incremental backup of the paused VM (the bitmap is only reachable through a backup job; the
  backup also keeps the current state, instead of a PVE snapshot), then the VM is stopped, tagged `nexus-rollback`
  and locked. The node's write path is a new socket-activated root service behind the helper's
  `rollback-begin|nbd|end` commands (qemu-nbd with the storage's format, no paths from the appliance); the helper
  itself stays unprivileged. Only disk contents are rolled back, the VM configuration stays. Fallback to the full
  replace when the VM is stopped, its identity or disk layout changed or a bitmap cannot be reused.
- **Second offsite target:** a target plus its own `gfs` per tenant (`PUT /tenants/{name}/offsite2`); the first
  target got its own `gfs` too. No per-policy offsite GFS (the per-target retention covers "local 30 days, offsite
  monthly for 7 years"). Offsite retention is `max(policies, target)` per class (decision 5).
- **Role elevation:** per session, appliance-wide local operators and viewers only; the approval per elevation is a
  setting (off by default); posture check `posture.standing_admins` (more than two standing admins).
- **Post-quantum:** ADR-014; ML-KEM keys derived from the existing X25519 secrets; existing tenant recovery keys and
  replication peers stay X25519-only until replaced or enrolled again.
- **Anomalies:** the dedup rate is new data / data read (not unique / logical); duration alone is a warning.

### Tier 3: later or niche

- **Job priority:** a priority per protection group (high/normal/low) used when caps or the queue are full, and
  "move to front" for a queued job (admin/operator, audited). [5]
- **Plain KVM/libvirt hosts as a source** (Debian/Ubuntu/RHEL KVM without PVE): libvirt incremental backup
  (`virDomainBackupBegin`, pull mode NBD with dirty bitmaps) maps onto the existing `crates/nbd` and fixed-index
  code; forced-command SSH like PVE. Plugin, effort L. [4][5]
- **Signature engine next to YARA:** ClamAV in the restore micro-VM with admin-uploaded `.cvd` databases (no feed,
  no egress); ClamAV is GPL-2.0 and runs as a separate program inside the VM like yara. [4][18]
- **Ansible collection** wrapping the OpenAPI for configuration as code (sources, policies, groups, fleet secrets),
  using operator-scoped API tokens; nothing new on the appliance. [3]
- **Kubernetes** (CSI snapshots + manifests) as a plugin, also listed as out of scope in the Commvault review. [11]
- **Database corruption signal:** surface PostgreSQL/MySQL page-checksum failures seen during physical backups as
  their own alert instead of a generic job failure. [3]

## Deliberately not copied

- **Media servers, storage units, Flex Scale clusters:** single appliance by decision; scale-out stays in
  docs/scale-out.md. More nodes means more trust paths into the store.
- **Universal Shares** (an NFS/SMB share on the backup target that sources write into) [10]: an inbound writable
  share on the appliance breaks the pull model and default-deny; database dumps go through agents with hooks or the
  database plugins.
- **Instant Access over NFS/SMB** exporting backup data to the network: same decision as in the Cohesity review
  (decrypted backup data served over the network); instant recovery, instant disk and plugin mounts cover the need.
- **WORM enterprise mode, MPA exemptions, a CLI to disable MPA as root** [13][16]: weaken the guarantees.
- **FortKnox / vendor-hosted vault, Helios, Copilot:** vendor cloud and egress; customers keep S3 Object Lock, Storage
  Box or a vault appliance, and MSPs can run the vault appliance as their own service.
- **External KMS and HSM** for data keys: same decision as in the Cohesity review; TPM sealing of the KEK stays the
  plan.
- **Tape, vault/robot management, NDMP, archive-tier (Glacier/Deep Archive) storage:** outside the audience; DR and
  verify must read packs without restore requests (docs/s3-offsite.md).
- **Custom RBAC roles and object groups:** fixed roles keep the approval model analysable; tenant roles and
  role elevation (Tier 2) cover least privilege.
- **Cloud PaaS, Cloud Scale on Kubernetes, cloud snapshot management:** not the PVE/SMB audience.
- **ML anomaly scoring:** deterministic, explainable signals on the box (Tier 1 #5 and Tier 2 anomalies follow
  that rule).

## Proposed decisions and open questions

1. **Numbering.** The Commvault review proposes its Tier 1 as Phase 28 and its Tier 2 as Phase 29. Proposal: Phase 29
   = Commvault Tier 2 items chosen by the maintainer **plus** NetBackup Tier 1 (#1–#5, all S–M, several touch the
   same files as Commvault #1/#3/#4); NetBackup Tier 2 as Phase 30, each item decided separately.
2. **Forced full read defaults (#1).** *Decided in Phase 29: on by default per group (90/30 days).* On by default (30 days agents/NAS, 90 days PVE), or off with a recommendation?
   A full read of a PVE VM costs I/O on production storage and fleecing space. Proposal: on, staggered by source id
   so not all guests rescan on the same night, skipped while restore priority is on.
3. **Infected-snapshot restores (#2).** *Decided in Phase 29: approval; administrators only with approvals off.* Approval (four eyes) or only security officers? Proposal: approval when
   approvals are on; security officer only when they are off.
4. **Freeze configuration (#4).** *Phase 29: a frozen configuration refuses updates like any change; lift the
   freeze (approval) to update.* Should a frozen appliance still accept updates (security fixes during an incident)?
   Proposal: OS updates allowed only through an approval; agent rollouts (Phase 27) frozen.
5. **Second offsite target (Tier 2).** *Decided in Phase 30 (proposal taken): identical by default, longer per target
   only; the scheduler keeps the larger of the policies' and the target's value per class.* This revisits plan §2 "Offsite retention identical to local". Proposal: keep
   "identical" as the default and allow *longer* offsite retention only (never shorter), so the original customer
   requirement still holds.
6. **Instant rollback (Tier 2).** *Decided in Phase 30 (maintainer: a new helper write command): the helper forwards
   to a socket-activated root service on the node that writes only a stopped, tagged and locked VM's disks through
   qemu-nbd; lab spike still pending.* Writing into a stopped production VM's disks needs a new write command in the PVE
   helper (today restores create new volumes or swap). Accept the larger helper surface, or keep rollback as "restore
   to new volumes, then swap" (slower, existing code)? Needs a lab spike.
7. **Post-quantum (Tier 2).** *Decided in Phase 30 (proposal taken): keyd hybrid wrapping with RustCrypto `ml-kem`
   (already in the tree through russh), TLS later (docs/adr.md ADR-014).* Which ML-KEM implementation (RustCrypto `ml-kem` vs. a vetted alternative) and whether
   to move rustls to `aws-lc-rs` for PQ TLS; the latter conflicts with the pure-Rust preference (plan §2, SFTP and
   S3 client decisions). Proposal: keyd hybrid wrapping first (pure Rust), TLS later when a pure-Rust provider offers
   the hybrid group.
8. **Not verified in this review:** the post-merger status of Veritas Resiliency Platform, current NetBackup
   licensing editions, and whether NetBackup can schedule malware scans after every backup (the 11.x docs describe
   on-demand and anomaly-triggered scans only [18]).

## Sources

1. TechCrunch, "Cohesity completes its merger with Veritas" (2024-12-10): https://techcrunch.com/2024/12/10/cohesity-completes-its-merger-with-veritas-heres-how-theyll-integrate
2. Cohesity press release, NetBackup 11.0 (2025-03-26): https://www.cohesity.com/newsroom/press/cohesity-introduces-new-data-security-capabilities-for-netbackup-with-expanded-cloud-support/ ; Blocks and Files: https://www.blocksandfiles.com/public-cloud/2025/03/26/cohesity-launches-netbackup-11-with-quantum-proof-encryption/1601511
3. NetBackup 11.0 Release Notes (PQC via OQS, risk-engine anomalies, HSM, Trend Micro, Ansible, DB corruption detection): https://docs.cohesity.com/docs/pdf/103228346-168289021-1
4. NetBackup 11.1 Release Notes (freeze mode, YARA, abort on infection, network access control, KVM, cross-domain replication, pgBackRest, XtraBackup): https://docs.cohesity.com/docs/pdf/103228346-170351487-1 ; Cohesity blog "NetBackup 11.1": https://www.cohesity.com/blogs/netbackup-11-1--powering-a-new-era-of-data-resilience/
5. NetBackup 11.2 Release Notes (file hash calculation, role elevation, Helios integration, job priority, KVM Accelerator/SFR, local WORM cache, archive-tier verification, Troubleshooter): https://docs.cohesity.com/docs/pdf/103228346-171368441-1 ; Cohesity blog "Introducing NetBackup 11.2": https://www.cohesity.com/blogs/netbackup-11-2/ ; compatibility list with GA dates: https://netbackuppublicassets.blob.core.windows.net/netbackuppublicassets/scl/nbu_110_scl.html
6. Cohesity, NetBackup DirectIO solution brief: https://www.cohesity.com/content/dam/cohesity/resource-assets/solution-brief/netbackup-directio-modernizing-netbackup-with-cohesity-data-cloud-en.pdf ; blog "From DirectIO to Data Cloud": https://www.cohesity.com/blogs/from-directio-to-data-cloud-extending-netbackup-with-a-scale-out-platform/
7. About FortKnox for NetBackup (11.2): https://docs.cohesity.com/docs/netbackup/11.2/25074086-172090016-0/v159573266-172090016 ; Recovery Vault product page: https://www.cohesity.com/products/alta/recovery-vault/
8. NetBackup Flex Scale Best Practices and Troubleshooting Guide: https://www.veritas.com/support/en_US/doc/158255118-162121584-0/v160508694-162121584
9. Proxmox forum, "Veritas NetBackup integration — current support status and future plans": https://forum.proxmox.com/threads/veritas-netbackup-integration-%E2%80%94-current-support-status-and-future-plans.184918/
10. Overview of universal shares (11.1): https://docs.cohesity.com/docs/netbackup/11.1/25074086-170198669-0/v142119812-170198669 ; Instant Access for universal shares (11.2): https://docs.cohesity.com/docs/netbackup/11.2/25074086-172090016-0/v156214063-172090016
11. NetBackup for Kubernetes Administrator's Guide 11.2: https://docs.cohesity.com/docs/netbackup/11.2/pdf/150157643-172472261-1
12. About the NetBackup Accelerator for virtual machines (11.2): https://docs.cohesity.com/docs/netbackup/11.2/166027891-172478504-0/v77418244-172478504 ; Accelerator force rescan (11.0): https://docs.cohesity.com/docs/netbackup/11.0/156091361-167856407-0/v156872471-167856407
13. NetBackup WORM storage support (11.0): https://docs.cohesity.com/docs/netbackup/11.0/25074086-168257404-0/v143250065-168257404 ; About lockdown modes (11.0): https://docs.cohesity.com/docs/netbackup/11.0/160799157-169128346-0/v151650793-169128346
14. About storage lifecycle policies (11.2): https://docs.cohesity.com/docs/netbackup/11.2/156989604-172152055-0/v156537727-172152055 ; writing multiple copies with an SLP (11.0): https://docs.cohesity.com/docs/netbackup/11.0/18716246-168258057-0/v42386843-168258057
15. Configuring an isolated recovery environment on a BYO media server (11.2): https://docs.cohesity.com/docs/netbackup/11.2/25074086-172090016-0/v156688908-172090016
16. NetBackup operations that need multi-person authorization (11.0): https://docs.cohesity.com/docs/netbackup/11.0/21733320-167894921-0/v162212040-167894921 ; disable MPA: https://docs.cohesity.com/docs/netbackup/11.0/21733320-167894921-0/v162576573-167894921
17. Configure backup anomaly detection settings (11.1): https://docs.cohesity.com/docs/netbackup/11.1/21733320-170163306-0/v152007140-170163306 ; technical brief "NetBackup Detection": https://www.veritas.com/content/dam/www/en_us/documents/technical-documents/TB_netbackup_detection_malware_scanning_V1508.pdf
18. About malware scanning (11.1): https://docs.cohesity.com/docs/netbackup/11.1/21733320-170163306-0/v152076052-170163306
19. `bpcleanrestore` command (11.0): https://docs.cohesity.com/docs/netbackup/11.0/15263389-167321334-0/v152270274-167321334
20. About freeze mode in NetBackup (11.1): https://docs.cohesity.com/docs/netbackup/11.1/21733320-170163306-0/v171053249-170163306
21. Instant rollback from a VM backup image (11.1): https://docs.cohesity.com/docs/netbackup/11.1/166027891-170176766-0/v147561262-170176766
22. NetBackup IT Analytics 11.8, reports in the Foundation license: https://docs.cohesity.com/docs/netbackupitanalytics/11.8/156156279-171083365-0/v156185628-171083365
