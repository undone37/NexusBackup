# Commvault Cloud compared with NexusBackup

Sources: Commvault public documentation (SaaS and 11.4x software docs, feature newsletters July 2025 to January
2026), press releases and trade press up to August 2026; links in [Sources](#sources). No Commvault installation was
tested. Checked against plan.md (§2, Phases 13–27), state.md, the manual and docs/cohesity-comparison.md /
docs/veeam-comparison.md, so items already built or planned there are not listed as gaps. Review date 2026-10-13,
NexusBackup main (0.1.x alpha).

## Summary

Commvault is a broad enterprise data-protection platform: one control plane (Command Center, Global Command Center
for MSPs) over self-managed software, HyperScale X appliances and the Commvault Cloud SaaS (formerly Metallic). It
covers almost every workload (hypervisors, databases, SaaS, Kubernetes, cloud PaaS, Snowflake), offers cloud-hosted
immutable storage (Air Gap Protect), cloud clean rooms and cloud-application rebuild (Cleanroom Recovery, Cloud
Rewind, Clumio), and since the November 2025 "Commvault Cloud Unity" release adds AI-driven threat detection
(Threat Scan, Synthetic Recovery), identity resilience for Active Directory and an AI assistant (Arlie, MCP server)
[1][2][3][4].

NexusBackup is a single hardened appliance for Proxmox VE-centric SMBs and MSPs: pull model, default-deny, SELinux,
signed bootc image, per-tenant encryption, four-eyes approvals, offsite to Storage Box or S3 Object Lock, replication
to a vault appliance. It does not try to match Commvault's breadth. The useful lessons are in Commvault's cyber
recovery and MSP tooling, not in its workload list.

## Feature comparison

Status: **has** = built (lab-proven at least), **partial** = some of it built or planned in an open phase,
**missing** = neither built nor planned.

| Area | Commvault | NexusBackup | Status |
|---|---|---|---|
| **Workloads** | | | |
| Proxmox VE | VMs via Virtual Server Agent on each node, change tracking and app consistency since 2025, PVE 9 since Nov 2025; VMware → PVE conversion on restore [5][6][7] | VMs + LXC through the PVE backup provider API, dirty bitmaps, fleecing guard, instant recovery, instant disk | has |
| VMware, Hyper-V, Nutanix, OpenStack | yes, with Live Mount and Live Sync [8] | none; Hyper-V host-level open in Phase 23; VMware only named as a plugin example | missing |
| Physical Linux / Windows | agents, 1-Touch BMR | agents (deb/rpm/MSI), fleet enrollment, edge proxy, Linux BMR/P2V; Windows BMR open | has / partial |
| NAS, TrueNAS | NDMP, file servers, IntelliSnap array snapshots | NFS/SMB, TrueNAS incl. existing-snapshot mode | has |
| Databases | Oracle, SQL Server, SAP HANA, DB2, PostgreSQL, MySQL, cloud PaaS | PostgreSQL + MySQL/MariaDB plugins with PITR; MSSQL PITR open | partial |
| Microsoft 365 / Entra ID | Exchange, OneDrive, SharePoint, Teams, Entra ID, AD forest recovery [1][2] | M365 plugin incl. Teams, Entra ID export, PST export; AD runbook only | has / partial |
| Kubernetes, Salesforce, Google Workspace, GitHub, Snowflake | yes [1] | no | missing (out of scope) |
| **Storage / dedup** | | | |
| Dedup, compression, encryption | global dedup, optional encryption, KMS integrations | per-tenant dedup with keyed chunk IDs, always-on XChaCha20 envelope encryption | has |
| Immutability | retention lock on plans (disable needs a Commvault authorization code), HyperScale X WORM [9] | extend-only store locks on a compliance clock, S3 Object Lock offsite | has |
| Scale-out | HyperScale X clusters | single appliance by decision (docs/scale-out.md) | missing (by design) |
| **Security / cyber resilience** | | | |
| Multi-person authorization | per operation, approver groups, exclusions, MSP + tenant two-level routing, 24 h wait for new approvers [10] | quorum on all destructive/weakening actions; split activation codes for privileged accounts | has (no tenant-side approvers) |
| Anomaly detection | ML anomaly on backups, file-activity anomaly and honeypot files on clients [11] | change-rate anomalies, ransom-note names, mass renames, snapshot diff, trend sparklines | has |
| Malware scan of backups | Threat Scan: signatures, ML, entropy, YARA + IOC hash hunting on the backup index, scheduled scans, recovery calendar [3][12] | YARA scan in an offline restore micro-VM, on demand, "scan first" restores and scheduled per group with a recovery calendar; IOC hash hunt over per-file SHA-256 (Phase 28; VM disk files not hashed yet) | has |
| Clean restore point | Synthetic Recovery: newest clean version of each file across backups [13] | restore dialogs default to the newest clean snapshot | partial |
| Security posture | Security IQ dashboard, Cyber Resiliency Index score [14] | `nexus-diag` posture checks (pass/warn) | has |
| Containment | Tenant Lockdown Mode (one tenant read-only) [1] | incident mode (appliance-wide) and tenant lockdown (one tenant: holds, pauses, its sessions, tokens and sign-ins, changes refused; Phase 28) | has |
| New-device sign-in notice | e-mail on login from a new browser/host [15] | `login_new_device` alert (SIEM) and mail to the account (Phase 28) | has |
| Identity resilience (AD) | AD change audit and rollback, forest recovery into a clean room [2] | AD DC VSS backup + restore runbook; AD object export open (Veeam #13) | partial |
| **Recovery** | | | |
| Instant access | Live Mount | instant recovery, instant disk recovery | has |
| Standby copies | Live Sync: incremental replication from backup to a warm standby VM [8] | none (appliance failover rejected by design; standby VMs not considered) | missing |
| Recovery validation, runbooks | Cleanroom Recovery: recovery groups, runbooks, readiness report, cleanup [16] | restore tests, recovery plans with waves, daily readiness, isolated test runs, DR report | has (on-prem PVE only) |
| Cloud clean room / Cloud Rewind | AWS/Azure/GCP clean rooms, rebuild of cloud infrastructure [4][17] | no | missing (out of scope) |
| Search / eDiscovery | Compliance Search, Case Manager, sensitive data governance [18] | file-name search across snapshots, legal hold, mail export; M365 item metadata search planned (Phase 19), not built | partial |
| **Operations / automation** | | | |
| Policies | Plans (schedule + retention + storage) | policies, protection groups, auto-protect, policy tiers, restore point simulator | has |
| API, automation | REST API, Workflows engine, MCP server, Arlie AI agents [19][20] | OpenAPI, `nexusctl`, scoped API tokens, webhooks | has (no workflows/AI by choice) |
| Reports, alerts | reports, SIEM integrations (CrowdStrike, Splunk) | scheduled reports, syslog/HTTPS forwarding, Splunk HEC, notification rules | has |
| **Multi-tenancy / MSP** | | | |
| Tenants | Companies, tenant admins, per-tenant IdP | tenants, tenant admin, per-tenant OIDC, view-as-tenant, billing export, onboarding wizard | has |
| Multi-site management | Global Command Center: aggregated dashboards/jobs/alerts over many CommCells, blueprints [21] | one appliance per UI | missing |
| PSA integration | HaloPSA ticket creation from alerts [1] | e-mail and webhook templates (no ticket lifecycle) | partial |
| **Cloud / SaaS** | Commvault Cloud SaaS, Air Gap Protect (vendor-hosted immutable storage), Clumio for S3/GCS | customer-owned Storage Box / S3 Object Lock / vault appliance; no vendor-operated service | different model |
| **Compliance / governance** | Risk Analysis (classification, PII), FedRAMP, SEC 17a-4 claims [9][18] | backup ≠ archive (plan §1.2); legal hold; hash-chained audit with external anchor | partial (by design) |
| **Licensing / deployment** | subscription; historically per front-end TB, per VM/socket or per user [22] | AGPL-3.0, no per-TB or per-VM licence, one bootc image | different model |

## Where NexusBackup is deliberately different or ahead

- **Pull model and no vendor control plane.** Commvault's Proxmox support runs an access node (VSA) on every PVE node
  that sends data to the MediaAgent [5]; its SaaS needs outbound connections to Commvault. NexusBackup's PVE nodes
  get a restricted forced-command SSH key and never hold credentials to the appliance; the appliance works fully
  offline behind default-deny egress.
- **Locks that cannot be shortened by anyone.** Commvault's retention lock can be disabled with an authorization
  code from Commvault approved by a company officer [9]. NexusBackup's store locks only extend, also for the vendor.
- **Four-eyes without bypass lists.** Commvault MPA has per-operation exclusion lists and a seven-day onboarding
  window without dual authorization [10]. NexusBackup approvals have no exclusions; disabling them needs a second
  person, and privileged accounts are activated with split codes.
- **Encryption is not optional** and keys are per tenant with an offline recovery key; offsite copies are
  self-describing and restorable without the appliance. No external KMS dependency.
- **Appliance hardening** (SELinux enforcing, signed bootc with rollback, no SSH, GRUB lock, time-limited approved
  console root) is part of the product, not a reference-architecture task; HyperScale X has a restricted shell and
  WORM file system, but BMC/hardware hardening is left to the customer there as well [9].
- **PVE depth.** Commvault's PVE support is recent and needs QCOW2 volume chains or staging directories on thick LVM
  [5]; the documentation found covers VMs and templates, not LXC. NexusBackup uses PVE's own backup provider API
  with dirty bitmaps, LXC, fleecing guard, VM identity checks, instant recovery and isolated restore tests.
- **No appliance failover** (plan §2, reconfirmed 2026-10-12). Commvault Auto Recovery and Live Sync fail over and
  back; NexusBackup rebuilds a primary from the vault or offsite and keeps one-way trust.
- **No AI in the data path.** Commvault's ML scoring, Arlie and the MCP server need its cloud services and send
  metadata to them. NexusBackup's signals are deterministic and explainable and run on the box.

## Worth copying

Effort: S = days, M = 1–2 weeks, L = more. Phase numbers are suggestions (Phase 27 = agent updates).

### Tier 1: high value, fits the architecture as it is (Phase 28, implemented 2026-10-14; deviations: plan.md Phase 28)

| # | What | Commvault | Effort | Where |
|---|---|---|---|---|
| 1 | **Scheduled threat scans and a recovery calendar.** Policy option `scan: off / daily latest / after each backup` per protection group; scans queue behind the existing one-at-a-time `snapshot_scan` plan key with a budget; each snapshot gets a scan state (clean / hit / incomplete / unscanned) shown as a calendar on the Snapshots page; "restore latest clean" then prefers scanned-clean snapshots | Threat Scan schedules, recovery calendar [1][3] | S–M | `crates/scheduler` (scan.rs), catalog column, web-api, UI; reuses the 21e micro-VM scanner unchanged |
| 2 | **IOC hash hunting without restore.** Optional SHA-256 per regular file recorded in the sealed name index (`NameIndex` gets an optional hash column): agents compute it while reading (new capability in `agent-proto`), NAS/TrueNAS/plugin trees on the appliance while chunking, VM/CT only when `index_files` is on. Admin/SO upload hash lists like YARA rules; a `hash_hunt` job searches all name indexes of a tenant in the scheduler (same path as file search) and flags hits as `malware` alerts | IOC hash hunting on the backup index [12] | M | `crates/chunkstore` names.rs, agents, `crates/scheduler`, web-api; hashes stay sealed and never go offsite (derived data) |
| 3 | **Tenant lockdown.** Incident mode scoped to one tenant: legal holds on that tenant's snapshots, its groups paused, sessions and API tokens of its users ended, restores that overwrite, deletes and source edits for it refused; other tenants keep running. Entering by SO or admin at once, leaving needs approval (as incident mode) | Tenant Lockdown Mode [1] | S–M | `web-api/src/incident.rs` (tenant parameter, per-tenant setting), MSP manual chapter |
| 4 | **New-device sign-in notice.** Remember (account, browser family, client network prefix) per account; the first sign-in from an unseen combination raises `login_new_device` (category security, warning for admin/SO, info otherwise), forwarded to SIEM sinks and e-mailed to the account when an address is known (OIDC claim or profile) | e-mail on login from a new device [15] | S | web-api auth, catalog table, alerts |

### Tier 2: clear benefit, smaller audience or larger effort (proposed Phase 29)

- **Synthetic (clean-file) restore** for file-tree snapshots (agents, NAS, shares): for a chosen snapshot, take each
  file's newest version that has no YARA or hash hit and is not in the 21a mass-rename / ransom-note set, falling
  back through older snapshots; result as restore-to-host or download, with a CSV of substituted files. Built on the
  name index, 21a signals and #1/#2. Effort M–L; `crates/scheduler`, tree composition in `crates/chunkstore`. [13]
- **Tenant-side approvers for MSPs.** Opt-in per tenant: a `tenant_admin` of that tenant becomes a required second
  approver for actions that destroy or weaken that tenant's data (snapshot delete, legal hold release, retention
  weakening of its groups, tenant deactivation, replication key export of that tenant). Plus a 24 h wait before a
  newly activated approver may approve. Effort M; quorum code in `crates/web-api`. [10]
- **Multi-appliance overview.** A read-only aggregator for MSPs running one appliance per customer: pulls dashboard,
  open alerts and failed jobs from several appliances with scoped read API tokens (`nexusctl fleet` first, a small
  web page later); no write actions, no blueprints. Fits the pull model (aggregator → appliance 8443, inbound
  allow-list). Effort M; `crates/nexusctl`, `crates/reports` figures. [21]
- **VMware vSphere source with restore to PVE.** Signed plugin reading vSphere snapshots with changed-block tracking,
  restore as a PVE VM (VirtIO driver injection in the restore micro-VM). High value for SMBs leaving VMware;
  transport choice is open (see questions). Effort L; `plugins/vmware`, `crates/pve` restore path. [7]
- **PSA ticketing.** Alert rule channel "PSA" for HaloPSA / ConnectWise / Autotask: OAuth2 client-credentials token
  fetch, one ticket per alert key, note on repeats, close on resolve. E-mail-to-ticket already works today. Effort
  S–M; alerts delivery in `crates/scheduler`/web-api. [1]
- **M365 compliance search and cases.** Finish the planned M365 item metadata search (Phase 19) and add a saved
  "case": search criteria + legal hold on the matching snapshots + export as eml/PST. Effort M; m365 plugin, file
  index pattern, legal holds. [18]

### Tier 3: later or niche

- **Standby VM refresh** (Live Sync-like): after each backup, update a powered-off copy on a DR PVE node by writing
  only changed extents. Not appliance failover, so it does not conflict with plan §2, but L effort and PVE restore
  API limits. [8]
- **Clean-room profile for recovery plans:** target a separate isolated PVE cluster (restore-only source), scan
  first mandatory, run by tenant admins. Mostly configuration on top of Phase 25. [16]
- **AD object-level export and forest recovery runbook** in an isolated recovery plan (existing open Veeam #13). [2]
- **Resilience score** on the dashboard derived from the posture checks (S, low value). [14]
- **Read-only MCP adapter** in `nexusctl` using read API tokens, running on the admin's workstation, never on the
  appliance. [20]
- Kubernetes and Hyper-V sources (Hyper-V already open in Phase 23).

## Deliberately not copied

- **AI assistant, ML scoring, agentic actions** (Arlie, AI Studio): needs vendor cloud and LLM access from the
  appliance; conflicts with default-deny egress and explainable signals.
- **Sensitive data discovery / Risk Analysis** and data classification: not a backup appliance task (same decision
  as in the Cohesity review).
- **Cloud Rewind, Clumio, cloud clean rooms, Snowflake/PaaS protection:** outside the PVE/SMB audience.
- **HyperScale X scale-out:** single appliance by decision; scale-out stays in docs/scale-out.md.
- **IntelliSnap array snapshot orchestration:** the TrueNAS existing-snapshot mode covers the relevant case;
  array APIs mean vendor SDKs and credentials on the appliance.
- **Auto Recovery failover/failback** of appliances: conflicts with the no-failover decision; Phase 25 recovery
  plans cover workload DR.
- **Workflows engine** with custom scripts in the appliance: remote code execution by design.
- **Retention lock removable by vendor code, MPA exclusion lists, onboarding without dual authorization:** weaken
  the guarantees NexusBackup sells.
- **Vendor-hosted air-gapped storage** (Air Gap Protect): NexusBackup stays customer-owned (S3 Object Lock, Storage
  Box, vault appliance); an MSP can offer the vault appliance as its own service.
- **External credential vaults** (CyberArk, Delinea): sealed secrets on the box; another egress path for little gain.
- **Honeypot files on clients:** agents are passive and only run during backups; continuous file monitoring is an
  EDR's job, and 21a already detects ransom notes and mass renames per backup.

## Proposed decisions and open questions

1. **Phase 28 = Tier 1 (#1–#4)** after Phase 27, in the order 1, 2, 3, 4 (#4 can go first, it is days). Tier 2 as
   Phase 29, each item decided separately.
2. **Hash format for #2:** SHA-256 only (what IOC feeds publish) or also MD5/SHA-1 for older lists? Proposal:
   SHA-256 only; per-file hashing cost on agents to be measured (it is an extra pass over data already read).
3. **VM file hashes for #2:** opt-in per group together with `index_files`, since the walk in the micro-VM would
   read every file. Proposal: opt-in, off by default.
4. **Scheduled scans and capacity (#1):** one scan at a time stays; with "after each backup" on many groups the
   queue may never drain. Proposal: daily-latest as the only automatic mode in the first version.
5. **Tenant-side approvers (Tier 2):** should a tenant admin's refusal be final, or can two appliance-side approvers
   override (MSP emergency)? Proposal: final, with the MSP's legal-hold path as the safety valve.
6. **VMware transport:** VDDK is proprietary and cannot ship in the AGPL image; alternatives are HTTPS datastore
   reads of snapshot disks plus `QueryChangedDiskAreas`, or nbdkit with a customer-supplied VDDK. Needs a spike
   before the item is scheduled.
7. **Multi-appliance overview:** CLI only, or a separate small web service (another component to harden)? Proposal:
   CLI and a static HTML report first.

## Sources

1. Commvault Cloud SaaS, "Newsletter for New Features" (July 2025 – January 2026): https://documentation.commvault.com/saas/newsletter_for_new_features.html
2. SiliconANGLE, "Commvault launches Cloud Unity platform" (2025-11-12): https://siliconangle.com/2025/11/12/commvault-launches-cloud-unity-platform-unify-data-security-recovery-identity-resilience/
3. Commvault Threat Scan (SaaS docs): https://documentation.commvault.com/saas/commvault_threat_scan.html
4. Commvault, "Commvault Transforms Cyber Recoveries" (Cleanroom Recovery, Cloud Rewind, 2025-09-18): https://www.commvault.com/news/commvault-transforms-cyber-recoveries
5. Commvault 11.44, "Backups for Proxmox VMs": https://documentation.commvault.com/11.44/software/backups_for_proxmox_vms.html
6. Commvault 11.46, "Restoring a Full Virtual Machine Out of Place for Proxmox": https://documentation.commvault.com/11.46/software/restoring_full_virtual_machine_out_of_place_for_proxmox.html
7. Commvault 11.46, "Converting to Proxmox Virtual Environment": https://documentation.commvault.com/11.46/software/converting_to_proxmox_virtual_environment.html
8. Commvault 11.44, Live Sync replication: https://documentation.commvault.com/11.44/commcell-console/replication_01.html
9. Commvault 11.42, "Configuring Immutability on HyperScale X": https://documentation.commvault.com/11.42/software/configuring_immutability_on_hyperscale_x.html ; community, "HyperScale X enterprise grade security capabilities": https://community.commvault.com/platform-updates-47/hyperscale-x-enterprise-grade-security-capabilities-4333 ; community, "HyperScale hardware management interface security": https://community.commvault.com/hyperscale-x-q-a-54/hyperscale-hardware-management-interface-security-10989
10. Commvault 11.44, "Multi-Person Authorization for Companies": https://documentation.commvault.com/11.44/software/multi_person_authorization_for_companies.html ; 11.42, "Multi-Person Authorization to Minimize Insider Threat": https://documentation.commvault.com/11.42/software/multi_person_authorization_to_minimize_insider_threat.html
11. Commvault, "Anomaly detection on client computers" (honeypot files, file activity anomaly): https://documentation.commvault.com/2022e/expert/anomaly_detection_on_client_computers.html
12. Commvault 11.46, "Threat Hunting Details" (YARA and IOC hash hunting): https://documentation.commvault.com/11.46/software/threat_hunting_details.html
13. Commvault 11.46, "Performing Synthetic Recovery of a File System Resource": https://documentation.commvault.com/11.46/software/performing_synthetic_recovery_of_file_system_resource.html
14. Commvault 11.46, "Security IQ dashboard": https://documentation.commvault.com/11.46/software/security_iq_dashboard.html ; "Cyber Resiliency Index Report": https://documentation.commvault.com/11.46/software/cyber_resiliency_index_report.html
15. Commvault 11.46, "Accessing the Command Center" (new-device e-mail): https://documentation.commvault.com/11.46/software/accessing_command_center.html
16. Commvault 11.42, "Run recovery runbook for a cloud-based cleanroom site": https://documentation.commvault.com/11.42/software/run_recovery_runbook_for_cloud_based_cleanroom_site.html
17. StorageNewsletter, "Commvault Advances AI and Cloud Application Resilience with Expanded Cloud Rewind Coverage" (2026-08-20): https://www.storagenewsletter.com/2026/08/20/commvault-advances-ai-and-cloud-application-resilience-with-expanded-cloud-rewind-coverage/
18. Commvault Risk Analysis: https://www.commvault.com/platform/risk-analysis ; Data Insights architecture: https://documentation.commvault.com/v11/software/architecture.html
19. Blocks and Files, Commvault AI Studio / agents (2026-04-14): https://www.blocksandfiles.com/ai-ml/2026/04/14/commvault-announces-trio-of-ai-tools-for-data-prep-agent-oversight-resilience/5217385
20. Commvault blog, "Conversational resilience" (MCP server): https://www.commvault.com/blogs/conversational-resilience-a-new-way-to-manage-and-protect-enterprise-data
21. Commvault SaaS, "Global Command Center": https://documentation.commvault.com/saas/global_command_center.html
22. Commvault 11.20, "License Types in the License Summary Report": https://documentation.commvault.com/11.20/license_types_in_license_summary_report.html
