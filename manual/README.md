# NexusBackup Appliance — User Manual

This manual describes how to install, operate and use the NexusBackup appliance: an open-source backup appliance that
pulls data from Proxmox VE, Linux and Windows hosts, TrueNAS, NFS/SMB shares and plugin sources such as PostgreSQL and
Microsoft 365, stores it as deduplicated, encrypted forever-full snapshots, and keeps copies offsite and on a second
appliance.

> **Status:** NexusBackup is **lab-proven, not production-ready**. All functions described here run end to end in a
> nested lab with SELinux enforcing. Real hardware, scale tests, a real Hetzner Storage Box run, the external
> penetration test, TPM/LUKS disk encryption, a VM drill of the configuration restore and the release key ceremony are still
> open. Each chapter marks lab-only or missing parts with a **Status** note.

## Who reads what

| Audience | Start with |
|---|---|
| **Administrators** (install, configure) | 01, 02, 04, 05, 07, 09, 12, 13, 14 |
| **Security officers** (approve, audit) | 01, 09, 10, 14 |
| **Operators** (daily operation, restores) | 03, 06, 11, 15 |
| **Tenant users** (restore own data) | 03 (Signing in, Snapshots, Files), 06, 09 (Activating your account) |
| **Managers** (status at a glance) | 03 (Dashboard: key figures, RPO, charts) |

## Contents

1. [Concepts](01-concepts.md): pull model, tenants, forever-full, deduplication, encryption, retention (GFS), retention
   locks, compliance clock, approvals, offsite, replication, roles
2. [Installation and first boot](02-installation.md): sizing, image, the `nexus-setup` wizard, recovery key, first
   sign-in, firewall
3. [The web interface](03-web-interface.md): layout and navigation, light/dark theme, the KPI dashboard (RPO,
   capacity forecast, data reduction, lock coverage), every page and the Settings tabs, with screenshots
4. [Sources](04-sources.md): Proxmox VE, Linux/Windows agents, TrueNAS (built-in and plugin), NFS/SMB shares,
   PostgreSQL, Microsoft 365 and other plugin sources
5. [Policies and protection groups](05-policies-and-groups.md): schedules, retention, what gets backed up
6. [Restores](06-restores.md): full VM/CT restore, instant recovery, file download, restore to path / files from any snapshot onto a host, PostgreSQL dump
   restore and point-in-time restore, Microsoft 365 restores
7. [Offsite copies](07-offsite.md): Hetzner Storage Box (SFTP), S3 with Object Lock
8. [Replication to a second appliance](08-replication.md)
9. [Users and access](09-users-and-access.md): roles, MFA, activation codes, single sign-on (OIDC) with Keycloak and
   Microsoft Entra ID examples
10. [Approvals and audit](10-approvals-and-audit.md): what needs approval, deciding requests, the approval setting,
    the audit log
11. [Alerts and monitoring](11-alerts-and-monitoring.md): alert kinds, delivery by webhook/e-mail (Settings), Prometheus
    metrics
12. [Plugins](12-plugins.md): installing, upgrading and removing signed plugins
13. [Updates and rollback](13-updates.md): Settings → Updates, console commands, maintenance window, agents
14. [Disaster recovery](14-disaster-recovery.md): the recovery key, recovery from offsite or a secondary, break-glass
    for a locked-out sole administrator
15. [Troubleshooting and FAQ](15-troubleshooting-faq.md)

## Conventions

- Labels of the web interface are printed in **bold**, exactly as they appear.
- Commands run on the appliance's local console (as root) or on the source systems, as stated.
- All names and addresses are fictional: `example.com`, `example.net` and the documentation networks 192.0.2.0/24,
  198.51.100.0/24 and 203.0.113.0/24. The screenshots show a demo appliance with the tenants **acme**, **initech**
  and **globex**.
- The screenshots are generated from the web interface against a seeded demo backend; see
  [tools/README.md](tools/README.md) to regenerate them.
