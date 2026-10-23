# NexusBackup plugin for PegaProx

[PegaProx](https://github.com/PegaProx/project-pegaprox) manages several Proxmox VE (and XCP-ng) clusters from
one web interface. This plugin shows there, per guest, what NexusBackup knows about it, and can start a backup of
a guest. It lives in this repository until it is submitted to the PegaProx plugin catalogue (plan.md Phase 43).

What the plugin's tab shows for each guest of a mapped cluster:

- the state: protected, late or failed (the newest backup is older than two schedule periods, or the group's last
  backup job failed), no backup yet, or not protected (in no protection group of that cluster's source);
- the newest backup (time, age, offsite copy, retention lock), the protection group and its policy, the next
  scheduled run, the newest restore test and open alerts that name the guest;
- **Back up now**, when the plugin settings allow it and the PegaProx user may create backups of that cluster.

## Install

Requires PegaProx 1.4 or newer. Copy the directory `nexusbackup/` into PegaProx's `plugins/` directory, then
**Settings → Plugins → Rescan**, enable **NexusBackup**, and edit its configuration there (`config.json`, see
`config.json.example`):

- `url`: the appliance's web address (`https://…:8443`).
- `token`: a NexusBackup API token (**Account → API tokens**). Scope **Read only** to show the state, or **Read and
  start backups** if `allow_backup` is on. Use the account of the tenant the clusters belong to, or a cross-tenant
  operator account; the token never gets more than that account's role.
- `cert_sha256`: the SHA-256 fingerprint of the appliance certificate (NexusBackup **Settings → Certificate**, the first certificate of the chain). The
  plugin pins it and refuses to send the token to any other certificate, also after a certificate change: update
  the fingerprint when the appliance gets a new certificate.
- `clusters`: PegaProx cluster ID → `{"tenant": …, "source_id": …}`: the NexusBackup tenant and the ID of the PVE
  source for that cluster (needed when a tenant has several clusters, whose guests share `vm-<vmid>` names).
- `allow_backup` (default `false`) and `cache_seconds` (default 60; the appliance is asked at most this often per
  cluster).

## Permissions

| Action | PegaProx | NexusBackup token |
|---|---|---|
| See the tab | `plugins.view` | — |
| See a cluster's backup state | `backup.view` on that cluster | scope read (or backup) |
| Back up now | `backup.create` or `vm.backup` on that cluster, `allow_backup` | scope backup (or operator) |

Restores, deletions, schedules and settings are never available through the plugin: they stay in NexusBackup,
with its approvals. A started backup appears in NexusBackup's audit log as `<user> via token <name>` and in
PegaProx's audit log as `nexusbackup.backup`.

## Development

`core.py` has everything without PegaProx (API client with the certificate pin, state per guest);
`python3 integrations/pegaprox/test_core.py` tests it. `__init__.py` adds the routes and PegaProx's permission
checks, `ui.html` the tab.
