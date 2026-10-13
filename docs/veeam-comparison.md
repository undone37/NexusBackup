# Veeam Backup & Replication / Veeam Agents compared with NexusBackup (2026-10-12)

Research of the Veeam Help Center (B&R 12/13, Agent for Linux / Windows 13.x). Only items NexusBackup neither had nor
planned (checked against plan.md Phases 13–24 and docs/cohesity-comparison.md). Endpoint UI findings: docs/endpoint-ui.md.

| # | Veeam feature | NexusBackup adaptation | Effort | Placement |
|---|---|---|---|---|
| 1 | Configuration backup (scheduled, encrypted, restore on a new server) | Daily sealed bundle (catalog, totp/secrets keys, agent CA, peers, SSH/offsite keys, plugin list) to every offsite target, encrypted to a key derived from the recovery key; `nexus-setup restore-config` at first boot | M | **now** (DR blocker) |
| 2 | SureBackup (boot in an isolated virtual lab, heartbeat/ping/app tests) | Scheduled `restore_test` jobs: instant-recovery overlay on PVE with links down / isolated VNet, guest-agent ping, optional TCP port check, destroy; result per snapshot; feeds the "restore tests" KPI | M–L | **done** (Phase 25: `restore_test` jobs and group schedules, Restore tests page, dashboard KPI; PVE lab run pending) |
| 3 | Health check with repair from source | A chunk that fails verify is marked bad; the next backup must not dedup against it (drop the PVE dirty bitmap, invalidate agent-map entries); affected snapshots flagged | S–M | Phase 21 (21d: done; repair from offsite or the replication primary) |
| 4 | Recovery Orchestrator (plans, readiness checks, test runs, DR documentation) | Recovery plans (ordered guests, target node/storage, network map), daily readiness check, test via #2, DR report (crates/reports) | M–L | **done** (Phase 25: recovery plans with waves, daily readiness, isolated test runs, approved execution, HTML DR report; PVE lab run pending) |
| 5 | Agent protection groups by CSV / IP range, pre-installed agents | CSV bulk enrollment; fleet mode: packages deployed by GPO/Intune with a time-limited fleet secret, appliance scans an admin-defined range for agents awaiting enrollment, auto group by hostname pattern | M | **done** (Phase 24d: fleet secrets, range scans, accept/auto-accept, template groups by host name, CSV bulk tokens; VM lab pending) |
| 6 | SOBR evacuate / move backups | Online store migration to a new array (chunk copy + switch-over) | M–L | Phase 22 |
| 7 | Instant Disk Recovery | Attach one disk from a backup to an existing VM (NBD overlay, optional disk move) | S–M | Phase 22 |
| 8 | Secure Restore (AV scan before restore) | Restore option "scan first" using the Phase 21 YARA scan; hit → refuse or force link down | S | Phase 21 |
| 9 | Restore point simulator / capacity planning | GFS preview in the policy dialog with estimated stored bytes from measured stats; also in retention-weakening approvals | S–M | Phase 23 |
| 10 | REST API + PowerShell | Published OpenAPI document + `nexusctl` CLI using API tokens | S–M | Phase 23 |
| 11 | VeeamZIP (ad-hoc full with own retention) | "Back up now, keep until <date>" (store lock with expiry; approval beyond N days) | S | Phase 23 |
| 12 | Rotated drives | Removable-disk offsite backend (disk-set identity, wrong/missing disk states, catch-up) | M | Phase 22 |
| 13 | Veeam Explorer for AD | Export AD objects (LDIF/CSV, diff between snapshots) from a DC snapshot in the restore microVM | L | Phase 23 |

Not copied: Data Integration API (publishes decrypted disks over the network), CDP, archive/Glacier tier, Exchange /
SharePoint on-prem item explorers, Oracle RMAN plugin, tape, licensing, remote remediation actions.
