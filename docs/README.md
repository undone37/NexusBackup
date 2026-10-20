# Design documents

Contracts and designs behind the code. The user manual is in [`../manual/`](../manual), the project plan and
decisions in [`../plan.md`](../plan.md), the current state in [`../state.md`](../state.md).

**Contract** documents describe interfaces the code must keep (wire formats, file layouts, commands); change them
together with the code. **Design** documents explain how a feature works and why. **Plan** and **review** documents
are history: they record what was proposed or compared at the time and are not updated when the code moves on.

## Architecture and security

| Document | Kind | Content |
|---|---|---|
| [adr.md](adr.md) | design | architecture decision records |
| [threat-model.md](threat-model.md) | design | assets, attackers, trust boundaries |
| [security-review.md](security-review.md) | review | internal security review, findings and their status |
| [pentest-scope.md](pentest-scope.md) | plan | scope for the external penetration test |
| [scale-out.md](scale-out.md) | design | groundwork for more than one appliance node |
| [release.md](release.md) | contract | release, signing, update and rollback chain |

## Control plane

| Document | Kind | Content |
|---|---|---|
| [control-plane.md](control-plane.md) | contract | web-api, scheduler, catalog, roles, approvals |
| [phase12-contract.md](phase12-contract.md) | contract | API of the UI redesign, KPI dashboard, OIDC, settings |
| [storage-accounting.md](storage-accounting.md) | design | storage accounting, soft quotas, change-rate anomaly |
| [hardware.md](hardware.md) | design | disks, SMART, the data array |
| [file-index.md](file-index.md) | design | file index and file search |
| [ransomware-signals.md](ransomware-signals.md) | design | ransomware signals and anomaly alerts |
| [malware-scan.md](malware-scan.md) | design | YARA scan of a snapshot in the restore micro-VM |

## Sources and connectors

| Document | Kind | Content |
|---|---|---|
| [pve-connector.md](pve-connector.md) | contract | node plugin, SSH helper and appliance (backup, restore, instant recovery, rollback) |
| [pve-backup-provider-api.md](pve-backup-provider-api.md) | design | reference notes on the Proxmox VE backup provider API |
| [agent-protocol.md](agent-protocol.md) | contract | agent wire protocol |
| [agent-linux.md](agent-linux.md), [agent-windows.md](agent-windows.md) | design | the Linux and Windows agents |
| [endpoint-ui.md](endpoint-ui.md) | design | agent TUI, CLI and desktop UI |
| [edge.md](edge.md) | design | edge proxy for roaming agents |
| [bmr.md](bmr.md) | design | Linux bare-metal recovery and P2V |
| [nas-connector.md](nas-connector.md), [truenas-connector.md](truenas-connector.md) | design | NFS/SMB shares, TrueNAS |
| [plugin-system.md](plugin-system.md) | contract | plugin bundles, sandbox, lifecycle |
| [plugin-sdk.md](plugin-sdk.md) | design | writing plugins with the Rust SDK |
| [m365.md](m365.md), [mysql.md](mysql.md) | design | Microsoft 365 and MySQL/MariaDB plugins |

## Offsite and replication

| Document | Kind | Content |
|---|---|---|
| [replication.md](replication.md) | contract | replication between two appliances |
| [s3-offsite.md](s3-offsite.md) | design | S3 offsite target with Object Lock |

## Plans and reviews (history)

| Document | Content |
|---|---|
| [phase13-18-plan.md](phase13-18-plan.md) | Phases 13 to 19 (Cohesity-inspired features) |
| [agent-update-plan.md](agent-update-plan.md) | Phase 27, agent updates pushed from the appliance |
| [file-index-v2-plan.md](file-index-v2-plan.md) | Phase 31, guest file index without the micro-VM |
| [vmware-transport-spike.md](vmware-transport-spike.md) | VMware vSphere source, transport options (not implemented) |
| [cohesity-comparison.md](cohesity-comparison.md), [veeam-comparison.md](veeam-comparison.md), [commvault-comparison.md](commvault-comparison.md), [netbackup-comparison.md](netbackup-comparison.md) | feature reviews against other products |
| [open-source-comparison.md](open-source-comparison.md) | restic + Backrest, Borg + BorgWarehouse, Duplicati, UrBackup (from their documentation, 2026-10-20) |
