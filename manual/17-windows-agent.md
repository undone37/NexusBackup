# 17. Windows agent: installation and configuration

This chapter is for the administrator of a Windows server that the appliance backs up with the agent. The appliance
side (creating the agent, the source and its paths) is in [04 Sources](04-sources.md#linux-and-windows-hosts-agents).

> **Status:** The Windows agent and its MSI are **built and checked on Linux only. They have never run on Windows.**
> Run the manual test plan in `docs/agent-windows.md` on a test server before you protect production data with it.

## How the agent works

- `nexus-agent.exe` runs as the service **NexusAgent** (LocalSystem) and **listens on TCP 7444** (TLS 1.3). It never
  connects out; the appliance connects to it.
- Trust: a one-time enrollment token from the appliance, then mutual TLS with certificates from the appliance's CA.
- Each backup creates one VSS shadow copy set for the affected NTFS/ReFS volumes. VSS writers (SQL Server, Exchange,
  AD and others) take part, so application data is consistent. The backup type is **copy**: SQL Server and Exchange
  log chains of other backup products are never truncated.
- Incremental backups use the NTFS/ReFS change journal (USN): only changed files are read.
- The appliance decides what is backed up and when. Nothing on the server can start a restore or change the backup
  configuration.

## Requirements

| | |
|---|---|
| Windows | Server 2016, 2019, 2022, 2025, x64 |
| Network | TCP 7444 reachable **from the appliance** (only from it) |
| File systems | NTFS or ReFS for snapshots; FAT/exFAT volumes are read live |
| Disk | `%ProgramData%\NexusAgent`: metadata cache (≈ 200 bytes per file) and a spool of up to 2 GiB for live reads; VSS shadow storage on each volume |

## 1. Get a token from the appliance

The appliance administrator creates the agent (**Configuration → Agents → New agent**) and gives you the one-time
token (valid 24 hours). Treat it like a password: it can be used once.

## 2. Install the MSI

Download `nexus-agent-<v>-x64.msi` from the release page and check its hash against `SHA256SUMS`:

```powershell
Get-FileHash .\nexus-agent-<v>-x64.msi -Algorithm SHA256
```

Interactive: double-click the MSI. Silent (elevated prompt):

```bat
msiexec /i nexus-agent-<v>-x64.msi /qn /l*v install.log
```

What the MSI installs:

| Path | Content |
|---|---|
| `C:\Program Files\NexusBackup Agent\nexus-agent.exe` | the agent |
| Service **NexusAgent** | LocalSystem, automatic start, restart on failure |
| `%ProgramData%\NexusAgent\config\` | `agent.conf` (optional), keys and certificates after enrollment, `release-keys\` |
| `%ProgramData%\NexusAgent\state\` | metadata cache, spool, `nexus-agent.log` (rotated at 10 MiB) |

`%ProgramData%\NexusAgent` is readable by SYSTEM and Administrators only; the agent re-applies that ACL at every
start. The MSI adds no firewall rule. The service starts and stops again by itself until the agent is enrolled.

## 3. Enroll and start

In an elevated PowerShell:

```powershell
cd "C:\Program Files\NexusBackup Agent"
.\nexus-agent.exe init --token -      # paste the token, press Enter
sc.exe start NexusAgent
.\nexus-agent.exe status
```

The token is read from stdin so it never appears in the process list or the PowerShell history. Then the appliance
administrator clicks **Enroll** on the Agents page. `status` shows the listen address, the mode (`enrollment`,
`enrolled`), certificate fingerprints, whether self-update is allowed and the metadata cache.

## 4. Open the firewall

Allow TCP 7444 from the appliance only:

```powershell
New-NetFirewallRule -DisplayName "NexusBackup Agent" -Direction Inbound -Protocol TCP -LocalPort 7444 `
  -RemoteAddress 192.0.2.10 -Action Allow -Profile Domain,Private
```

## Many servers: GPO, Intune, scripts

- **GPO:** Computer Configuration → Policies → Software Settings → Software installation → assign the MSI.
- **Intune:** line-of-business app, install context **device**, command `msiexec /i nexus-agent-<v>-x64.msi /qn`.
- **Firewall rule:** deploy the rule above with the same GPO (Windows Defender Firewall with Advanced Security).
- **Fleet enrollment (recommended for many servers):** create a time-limited fleet secret on the appliance
  (Agents → Fleet) and pass it to the MSI: `msiexec /i nexus-agent-<v>-x64.msi /qn FLEETSECRET=nxf1.…` (hidden
  from the MSI log; ignored on an already enrolled server). The appliance finds the agents in its scan of the
  fleet's address ranges; an administrator accepts them (or the fleet accepts them automatically). Chapter 4,
  "Fleet enrollment". Not yet verified on a real Windows installation.
- **Enrollment with tokens:** tokens are per server and used once, so the MSI deliberately has no token property
  (MSI properties end up in installer logs and deployment configuration). Enroll each server afterwards, for example:

```powershell
# run elevated on the server; $token comes from your secret store, never from a file share
$token | & "C:\Program Files\NexusBackup Agent\nexus-agent.exe" init --token -
Start-Service NexusAgent
```

## 5. Configure (optional): `agent.conf`

`%ProgramData%\NexusAgent\config\agent.conf` holds `key = value` lines and `#` comments. **Unknown keys are an
error**: the service refuses to start rather than ignore a typo. Restart the service after a change
(`Restart-Service NexusAgent`).

| Key | Default | Meaning |
|---|---|---|
| `listen` | `::` | address to listen on, e.g. the address of the backup network |
| `port` | `7444` | TCP port (the agent's port is also set on the appliance) |
| `spool_max_bytes` | `2147483648` | spool for files read without a shadow copy |
| `appliance_id` | – | accept only this appliance id |
| `max_connections` | `4` | concurrent appliance sessions (1–64) |
| `vss_exclude_writers` | – | comma-separated VSS writer class ids (`{guid},{guid}`) that must not take part |
| `self_update` | off for the MSI | allow the appliance's **Update agent** |

`vssadmin list writers` shows the writer class ids. Exclude a writer only if it fails every backup and its data is
protected another way: its data is then only crash-consistent.

**What gets backed up** (paths in the form `/C/Users` or `C:\Users`, excludes such as
`C:\Users\*\AppData\Local\Temp`, include-only, regex excludes) and **bandwidth / CPU limits** are set on the
appliance: see [04 Sources](04-sources.md#4-create-the-source). Excludes are case-insensitive. `pagefile.sys`,
`hiberfil.sys`, `swapfile.sys` and `System Volume Information` are always skipped. Paths through junctions or symbolic
links and UNC paths are refused; list mounted volumes by their own path.

Hooks are not supported on Windows; VSS writers provide application consistency. After each backup the agent reports
every writer's state to the job log; a failed SQL Server, Exchange or AD writer marks the snapshot crash-consistent.

## Tray icon and status window for users

The MSI also installs `nexus-agent-gui.exe`: it starts at every user logon (Task Manager → Startup can switch it
off) and shows the backup state in the notification area, the last 30 sessions as a chart and **Request backup
now** (an administrator can hide it per agent). Users cannot restore or change anything. See
[04 Sources: Desktop agent](04-sources.md#desktop-agent-backup-status-for-the-user-windows-linux-desktops).

## Restores to this server

Restores are started by the appliance administrator only. The agent restores below the confirmed target path, with
ACLs (and SACLs), owners, alternate data streams and timestamps.

## Updates

- **MSI:** install the newer MSI the same way (GPO/Intune update). It replaces the old version in place and keeps the
  enrollment; a downgrade is refused. The appliance's **Update agent** is refused for MSI installations, unless you
  set `self_update = on`.
- **Manual installation** (without MSI, `docs/agent-windows.md`): the appliance's **Update agent** verifies the
  release signature, refuses downgrades and restarts the service.

## Re-enrolling and removing

- **Server reinstalled or `%ProgramData%\NexusAgent` lost:** ask for a **New token** (the agent keeps its id,
  source and snapshots), run `nexus-agent.exe init --token -` again, then **Enroll**.
- **Five failed enrollment attempts** lock the agent; `init` with a new token clears it.
- **Uninstall:** **Apps & features → NexusBackup Agent**, or `msiexec /x nexus-agent-<v>-x64.msi /qn`. This keeps the
  enrollment in `%ProgramData%\NexusAgent`; add `PURGE=1` to delete it too. Then delete the agent on the appliance.

## Troubleshooting

| Symptom | Check |
|---|---|
| Enrollment fails with a timeout | `Get-Service NexusAgent`, the firewall rule, `listen`/`port` in `agent.conf` |
| Service stops right after start | not enrolled yet (normal), or `agent.conf` error: see `%ProgramData%\NexusAgent\state\nexus-agent.log` |
| Snapshot crash-consistent | job log lists the failed writers; `vssadmin list writers`, shadow storage space (`vssadmin list shadowstorage`) |
| First backup after a long time reads everything | the USN journal wrapped or was recreated; normal, the next one is incremental again |
| **Update agent** refused, "installed from a msi package" | update with the MSI, or set `self_update = on` |
