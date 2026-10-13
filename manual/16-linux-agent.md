# 16. Linux agent: installation and configuration

This chapter is for the administrator of a Linux host that the appliance backs up with the agent. The appliance
side (creating the agent, the source and its paths) is in [04 Sources](04-sources.md#linux-and-windows-hosts-agents).

## How the agent works

- `nexus-agent` is one static binary (no dependencies). It runs as a root systemd service and **listens on TCP
  7444** (TLS 1.3). It never connects out to the appliance; the appliance connects to it. A laptop outside the
  office can additionally keep a connection to an **edge proxy** through which the appliance reaches it (TLS end
  to end): [18 Edge proxy for roaming laptops](18-edge-proxy.md).
- Trust: a one-time enrollment token from the appliance, then mutual TLS with certificates from the appliance's CA.
  The agent accepts only the appliance that enrolled it.
- Each backup takes a snapshot of the affected volumes (LVM thin or thick, ZFS, btrfs), reads the files from the
  snapshot, and sends only chunks the appliance does not have yet. Without snapshot support the files are read live
  and the snapshot is marked **crash-consistent / inconsistent** with the reason in the job log.
- The appliance decides what is backed up and when. Nothing on the host can start a restore or change the backup
  configuration.

## Requirements

| | |
|---|---|
| Distribution | any systemd distribution; packages for Debian/Ubuntu (`.deb`) and RHEL/AlmaLinux/Rocky/Fedora (`.rpm`), a tarball bundle for the rest |
| Architecture | x86_64 (amd64); aarch64 (arm64) packages are built but untested on real hardware |
| Network | TCP 7444 reachable **from the appliance** (only from it) |
| Snapshots (recommended) | LVM with free space in the volume group (thick, default 10 % of the origin) or thin pools, ZFS, or btrfs |
| Disk | `/var/lib/nexus-agent`: metadata cache (≈ 200 bytes per file) and a spool of up to 2 GiB for live reads |

## 1. Get a token from the appliance

The appliance administrator creates the agent (**Configuration → Agents → New agent**) and gives you the one-time
token (valid 24 hours) and the host name the appliance uses. Treat the token like a password: it can be used once.

## 2. Install

Download the package from the release page and check it:

```sh
sha256sum -c SHA256SUMS --ignore-missing
# optional, with the release public key from the release page:
cosign verify-blob --key nexus-release-<…>.pub --insecure-ignore-tlog=true \
  --signature nexus-agent_<v>-1_amd64.deb.sig nexus-agent_<v>-1_amd64.deb
```

**Debian, Ubuntu**

```sh
sudo apt install ./nexus-agent_<v>-1_amd64.deb
```

**RHEL, AlmaLinux, Rocky, Fedora**

```sh
sudo dnf install ./nexus-agent-<v>-1.x86_64.rpm
```

**Other distributions (bundle)**

```sh
tar xzf nexus-agent-<v>-x86_64.tar.gz && cd nexus-agent-<v>-x86_64
sudo ./install.sh --token -      # paste the token, press Enter: installs, enrolls and starts
```

The bundle installs to `/usr/local/sbin/nexus-agent` and `/etc/systemd/system/nexus-agent.service`. Skip step 3
for it.

What the package installs:

| Path | Content |
|---|---|
| `/usr/bin/nexus-agent` | the agent |
| `/usr/lib/systemd/system/nexus-agent.service` | hardened unit (not enabled before enrollment) |
| `/etc/nexus-agent/` (0700) | `agent.conf` (optional), keys and certificates after enrollment, `hooks.d/pre`, `hooks.d/post`, `release-keys/` |
| `/var/lib/nexus-agent/` (0700) | metadata cache, spool, snapshot journal |
| `/usr/share/doc/nexus-agent/examples/` | database hook examples (PostgreSQL, MySQL/MariaDB) |

## 3. Enroll and start

```sh
sudo nexus-agent init --token -      # paste the token, press Enter
sudo systemctl enable --now nexus-agent
```

The token is read from stdin so it never shows up in the process list or the shell history. Then the appliance
administrator clicks **Enroll** on the Agents page. Check on the host:

```sh
sudo nexus-agent status
```

`status` shows the listen address, the mode (`enrollment` before, `enrolled` after), the certificate fingerprints,
whether self-update is allowed, the size of the metadata cache and, per mounted volume, the snapshot method the
agent will use (check this before the first backup).

**Many hosts (Ansible & co.):** instead of one token per host, use a time-limited **fleet secret** (Agents →
Fleet): `sudo nexus-agent init --fleet-secret -`, or put the secret into `/etc/nexus-agent/fleet-secret` (root,
0600) before installing the package — the agent adopts and deletes it at its first start and waits until the
appliance finds it in a scan of the fleet's address ranges and an administrator accepts it (or automatically).
Hosts with tokens can also be registered from a CSV file. See chapter 4, "Fleet enrollment" and "CSV bulk
enrollment". `status` then shows `awaiting fleet enrollment`.

## 4. Open the firewall

Allow TCP 7444 from the appliance's address only, for example:

```sh
# firewalld
sudo firewall-cmd --permanent --new-zone=nexus
sudo firewall-cmd --permanent --zone=nexus --add-source=192.0.2.10
sudo firewall-cmd --permanent --zone=nexus --add-port=7444/tcp
sudo firewall-cmd --reload
# ufw
sudo ufw allow from 192.0.2.10 to any port 7444 proto tcp
```

## 5. Configure (optional): `/etc/nexus-agent/agent.conf`

The agent runs without a configuration file. `agent.conf` holds `key = value` lines and `#` comments. **Unknown keys
are an error**: the agent refuses to start rather than silently ignore a typo. Restart the service after a change
(`sudo systemctl restart nexus-agent`).

| Key | Default | Meaning |
|---|---|---|
| `listen` | `::` | address to listen on, e.g. the address of the backup network |
| `port` | `7444` | TCP port (tell the appliance administrator; the agent's port is set on the appliance) |
| `lvm_snapshot_percent` | `10` | size of thick LVM snapshots in % of the origin volume (1–100) |
| `hook_timeout_secs` | `3600` | a hook running longer is killed and counts as failed |
| `spool_max_bytes` | `2147483648` | spool for files read without a snapshot |
| `appliance_id` | – | accept only this appliance id (pinning, if several appliances share a CA) |
| `max_connections` | `4` | concurrent appliance sessions (1–64) |
| `self_update` | on for bundles, off for packages | allow the appliance's **Update agent** |
| `edge` | – | `host:port` of an edge proxy for roaming laptops (with `edge_sha256`); normally pushed by the appliance, see [18 Edge proxy](18-edge-proxy.md) |
| `edge_sha256` | – | SHA-256 fingerprint of the edge proxy's certificate (pinned) |

Example:

```ini
# backup network only
listen = 198.51.100.21
lvm_snapshot_percent = 20
```

**What gets backed up** (paths, excludes, include-only, regex excludes, nested mounts, file system types to skip)
and **bandwidth / CPU limits** are set on the appliance, not on the host: see
[04 Sources](04-sources.md#4-create-the-source) and [Limits](04-sources.md#bandwidth-and-cpu-limits). The service
already runs with nice 10 and the lowest best-effort I/O priority.

### Snapshots

The agent picks the snapshot method per volume automatically:

- **LVM thin:** a thin snapshot (no size needed).
- **LVM thick:** a snapshot of `lvm_snapshot_percent` of the origin (at least 64 MiB). The volume group needs that
  much free space; otherwise the volume is read live. Raise the percentage for volumes with many writes during the
  backup.
- **ZFS:** `zfs snapshot`, read through `.zfs/snapshot/`.
- **btrfs:** a read-only snapshot in `<mountpoint>/.nexus-snapshots/` (skipped by the backup). Nested subvolumes are
  volumes of their own: add their paths, or enable nested mounts on the appliance.
- **Anything else** (plain ext4/XFS on a partition): read live; changed files are marked inconsistent. Use a
  pre hook to dump databases first (below).

Snapshots are removed after each backup. Leftovers after a crash (`nexus-snap-*`) are removed at the next service
start.

### Database hooks (application consistency)

Executable files in `/etc/nexus-agent/hooks.d/pre/` run before the snapshot, files in `hooks.d/post/` after the
backup, in name order, only when the appliance source has **Run pre/post backup hooks on the host** enabled. Hooks
must be owned by root and not writable by group or others. Environment: `NEXUS_JOB`, `NEXUS_PHASE` (`pre`/`post`),
`NEXUS_SUCCESS` (post hooks: `1` or `0`). A failing pre hook fails the backup; post hooks still run.

```sh
sudo cp /usr/share/doc/nexus-agent/examples/hooks.d/pre/10-postgresql.example /etc/nexus-agent/hooks.d/pre/10-postgresql
sudo chmod 0700 /etc/nexus-agent/hooks.d/pre/10-postgresql
sudo nexus-agent hooks test        # checks owners/modes, runs pre and post hooks once (NEXUS_TEST=1), prints the output
```

Add the dump directory (`/var/backups/nexus` in the examples) to the source's paths on the appliance. The appliance
cannot send commands to the host: only the hooks you install run.

## On the endpoint: status and backup now

Users of a Linux host can see whether their computer is protected, without access to the appliance. The agent shows
the session summaries the appliance sends after every backup, and lets them ask for a backup now. The command works
over SSH, at 80×24 or larger, and needs no mouse. It never starts a restore and never changes the configuration:
restores stay with the administrator on the appliance.

**Who may use it:** root and members of the group `nexus-agent-ui` (created when the package is installed). To add
a user, run `sudo usermod -aG nexus-agent-ui alice`. The user must then log in again. Without the group, the commands
stop with "permission denied … add your user to the group nexus-agent-ui".

**Control panel:** `nexus-agent tui`. The main screen lists the latest backup sessions, newest first. Each session
shows its result as a text label, not only a colour: `[+] Success`, `[!] Warning`, `[x] Failed`, `[-] Cancelled`.
Above the list are the agent, the appliance that manages it, the next scheduled run, the last successful backup and
whether the appliance has reached the computer recently ("not reached since …" for laptops away from the network).

```text
┌ NexusBackup Agent ───────────────────────────────────────────────────────────┐
│Agent: web01                         Version: 0.6.0                           │
│Appliance: 3f9a1c22                  Managed by: nexus01.example.com          │
│Next run: 2026-10-13 22:00           Last success: 2026-10-13 02:05           │
│State: Idle                                                                   │
│Appliance contact: reachable                                                  │
└──────────────────────────────────────────────────────────────────────────────┘
┌ Latest backup sessions ──────────────────────────────────────────────────────┐
│  Result        Start             Duration  Transferred  Warnings             │
│> [+] Success   2026-10-13 02:05     14:07      1.1 GiB         0             │
│  [!] Warning   2026-10-12 02:05     15:09      1.2 GiB         2             │
│  [+] Success   2026-10-11 02:05     13:05      1.0 GiB         0             │
│  [x] Failed    2026-10-10 02:05     14:38      1.1 GiB         0             │
│  [+] Success   2026-10-09 02:05     15:09      1.2 GiB         0             │
│  [-] Cancelled 2026-10-08 02:05     13:05      1.0 GiB         0             │
│  [+] Success   2026-10-07 02:05     15:09      1.2 GiB         0             │
│                                                                              │
│                                                                              │
│                                                                              │
│                                                                              │
│                                                                              │
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘
 Enter  Details   S  Back up now   L  Log   R  Refresh   Q  Quit
```

Keys: **Up/Down** select a session, **Enter** opens it, **S** asks for a backup now, **L** shows the log of the
selected session, **R** reloads, and **Q** or **Esc** quits. The screen also reloads by itself every 10 seconds, or
every 2 seconds while a backup runs. Set `NO_COLOR=1` for a monochrome display.

**Session details** (**Enter**): the summary (result, start, duration, processing rate, warnings) and the data
amounts (read, transferred, new, restore point). The first error and the last lines of the job log follow.
**L** opens the full log tail. **Esc** returns to the list.

```text
┌ NexusBackup Agent ───────────────────────────────────────────────────────────┐
│Agent: web01                         Version: 0.6.0                           │
│Appliance: 3f9a1c22                  Managed by: nexus01.example.com          │
│Next run: 2026-10-13 22:00           Last success: 2026-10-13 02:05           │
│State: Idle                                                                   │
│Appliance contact: reachable                                                  │
└──────────────────────────────────────────────────────────────────────────────┘
┌ Session 1188 (backup) ───────────────────┐┌ Data ────────────────────────────┐
│Result       [!] Warning                  ││Read         48.0 GiB             │
│Start        2026-10-12 02:05             ││Transferred  1.2 GiB              │
│Duration     15:09                        ││New          700.0 MiB            │
│Rate         54.1 MiB/s                   ││Point        2026-10-12 02:05     │
│Warnings     2                            ││                                  │
└──────────────────────────────────────────┘└──────────────────────────────────┘
┌ Log (last lines) ────────────────────────────────────────────────────────────┐
│13:52:10 job 1188 started (policy daily-files)                                │
│13:52:11 snapshot: LVM thin vg0/root                                          │
│13:52:40 warning: /home/anna/.cache/x: file vanished                          │
│13:58:02 warning: /srv/db.sock: socket skipped                                │
│14:04:44 48.0 GiB read, 1.7 GiB transferred                                   │
│14:04:45 snapshot released, job finished with 2 warnings                      │
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘
 L  Log   R  Refresh   Esc  Back   Q  Quit
```

**Back up now** (**S**): after you confirm, the request waits on the computer, shown as *Backup requested*. The
appliance picks it up at its next poll, within a few minutes when the computer is reachable. The agent never
connects out. You can request one backup every 10 minutes. The administrator can hide **S** for an agent. While a
backup runs, a progress bar shows the percentage (not known for the very first backup) and the bytes read and
transferred.

```text
┌ NexusBackup Agent ───────────────────────────────────────────────────────────┐
│Agent: web01                         Version: 0.6.0                           │
│Appliance: 3f9a1c22                  Managed by: nexus01.example.com          │
│Next run: 2026-10-13 22:00           Last success: 2026-10-13 02:05           │
│State: Idle                                                                   │
│Appliance contact: reachable                                                  │
└──────────────────────────────────────────────────────────────────────────────┘
┌ Latest backup sessions ──────────────────────────────────────────────────────┐
│  Result ┌ Back up now ─────────────────────────────────────────────┐         │
│> [+] Suc│Request a backup of this computer now?                    │         │
│  [!] War│                                                          │         │
│  [+] Suc│The appliance starts it at its next poll                  │         │
│  [x] Fai│(usually within a few minutes).                           │         │
│  [+] Suc│[Y] Request backup    [N] Cancel                          │         │
│  [-] Can└──────────────────────────────────────────────────────────┘         │
│  [+] Success   2026-10-07 02:05     15:09      1.2 GiB         0             │
│                                                                              │
│                                                                              │
│                                                                              │
│                                                                              │
│                                                                              │
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘
 Y  Request backup   N  Cancel
```

```text
┌ NexusBackup Agent ───────────────────────────────────────────────────────────┐
│Agent: web01                         Version: 0.6.0                           │
│Appliance: 3f9a1c22                  Managed by: nexus01.example.com          │
│Next run: 2026-10-13 22:00           Last success: 2026-10-13 02:05           │
│State: Backup requested (waiting for the appliance)                           │
│Appliance contact: reachable                                                  │
└──────────────────────────────────────────────────────────────────────────────┘
 Backup requested at 2026-10-13 14:05; it starts at the appliance's next poll.
┌ Latest backup sessions ──────────────────────────────────────────────────────┐
│  Result        Start             Duration  Transferred  Warnings             │
│> [+] Success   2026-10-13 02:05     14:07      1.1 GiB         0             │
│  [!] Warning   2026-10-12 02:05     15:09      1.2 GiB         2             │
│  [+] Success   2026-10-11 02:05     13:05      1.0 GiB         0             │
│  [x] Failed    2026-10-10 02:05     14:38      1.1 GiB         0             │
│  [+] Success   2026-10-09 02:05     15:09      1.2 GiB         0             │
│  [-] Cancelled 2026-10-08 02:05     13:05      1.0 GiB         0             │
│  [+] Success   2026-10-07 02:05     15:09      1.2 GiB         0             │
│                                                                              │
│                                                                              │
│                                                                              │
│                                                                              │
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘
 Enter  Details   S  Back up now   L  Log   R  Refresh   Q  Quit
```

```text
┌ NexusBackup Agent ───────────────────────────────────────────────────────────┐
│Agent: web01                         Version: 0.6.0                           │
│Appliance: 3f9a1c22                  Managed by: nexus01.example.com          │
│Next run: 2026-10-13 22:00           Last success: 2026-10-13 02:05           │
│State: Backup running                                                         │
│Appliance contact: reachable                                                  │
└──────────────────────────────────────────────────────────────────────────────┘
███████████Running 42 %  read 20.0 GiB, transferred 610.0 MiB  (5:30)
┌ Latest backup sessions ──────────────────────────────────────────────────────┐
│  Result        Start             Duration  Transferred  Warnings             │
│> [+] Success   2026-10-13 02:05     14:07      1.1 GiB         0             │
│  [!] Warning   2026-10-12 02:05     15:09      1.2 GiB         2             │
│  [+] Success   2026-10-11 02:05     13:05      1.0 GiB         0             │
│  [x] Failed    2026-10-10 02:05     14:38      1.1 GiB         0             │
│  [+] Success   2026-10-09 02:05     15:09      1.2 GiB         0             │
│  [-] Cancelled 2026-10-08 02:05     13:05      1.0 GiB         0             │
│  [+] Success   2026-10-07 02:05     15:09      1.2 GiB         0             │
│                                                                              │
│                                                                              │
│                                                                              │
│                                                                              │
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘
 Enter  Details   S  Back up now   L  Log   R  Refresh   Q  Quit
```

If the appliance has not reached the computer for a while (a laptop away from the office network or the VPN), the
header shows when it was last reached. A missed scheduled backup runs when the computer is reachable again. Laptops
assigned to an edge proxy stay reachable outside the office: [18 Edge proxy for roaming laptops](18-edge-proxy.md).

```text
┌ NexusBackup Agent ───────────────────────────────────────────────────────────┐
│Agent: web01                         Version: 0.6.0                           │
│Appliance: 3f9a1c22                  Managed by: nexus01.example.com          │
│Next run: 2026-10-13 22:00           Last success: 2026-10-13 02:05           │
│State: Idle                                                                   │
│Appliance contact: not reached since 2026-10-10 14:05                         │
└──────────────────────────────────────────────────────────────────────────────┘
┌ Latest backup sessions ──────────────────────────────────────────────────────┐
│  Result        Start             Duration  Transferred  Warnings             │
│> [+] Success   2026-10-13 02:05     14:07      1.1 GiB         0             │
│  [!] Warning   2026-10-12 02:05     15:09      1.2 GiB         2             │
│  [+] Success   2026-10-11 02:05     13:05      1.0 GiB         0             │
│  [x] Failed    2026-10-10 02:05     14:38      1.1 GiB         0             │
│  [+] Success   2026-10-09 02:05     15:09      1.2 GiB         0             │
│  [-] Cancelled 2026-10-08 02:05     13:05      1.0 GiB         0             │
│  [+] Success   2026-10-07 02:05     15:09      1.2 GiB         0             │
│                                                                              │
│                                                                              │
│                                                                              │
│                                                                              │
│                                                                              │
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘
 Enter  Details   S  Back up now   L  Log   R  Refresh   Q  Quit
```

**Scripts:** the same data is available on the command line, also as JSON:

```
nexus-agent status [--json]                 # protection status
nexus-agent sessions [--limit N] [--json]   # latest sessions (default 20)
nexus-agent session <id> [--json]           # one session with its log tail
nexus-agent request-backup [--json]         # ask for a backup at the next poll
```

Exit codes: `0` ok, `1` error, `2` no permission on the socket (not in `nexus-agent-ui`), `3` agent service not
running, `4` refused by the agent (rate limit, hidden by the administrator, unknown session). As root,
`nexus-agent status` also prints the local diagnostics (listen address, enrollment, certificates, cache).

> **Status:** The control panel and the commands were tested against a simulated agent service (screens above are
> rendered by the tests). Testing on a real host against the appliance's session summaries and poll is pending.

## Desktop GUI and tray icon (Linux desktops)

On workstations, install `nexus-agent-desktop_<v>-1_amd64.deb` / `nexus-agent-desktop-<v>-1.x86_64.rpm` next to the
agent: it adds `nexus-agent-gui` (tray icon and window with the session chart) to the menu and the desktop autostart;
users need to be in the group `nexus-agent-ui` (`sudo usermod -aG nexus-agent-ui alice`). See [04 Sources: Desktop agent](04-sources.md#desktop-agent-backup-status-for-the-user-windows-linux-desktops).

## Restores to this host

Restores are started by the appliance administrator only (no self-service restore on the host). The agent writes
below the target path the administrator chose and typed to confirm, never follows symlinks out of it, and refuses
`/` unless the restore explicitly overwrites everything. Files from other machines arrive owned by root with
setuid/setgid bits cleared.

## Updates

- **Packages:** install the newer `.deb`/`.rpm` (`apt install ./…`, `dnf upgrade ./…`). The service restarts; the
  enrollment stays. The appliance's **Update agent** is refused for package installations, unless you set
  `self_update = on`.
- **Bundle:** the appliance administrator clicks **Update agent**. The agent verifies the release signature against
  `/etc/nexus-agent/release-keys/`, refuses downgrades and updates only while idle.
- **Switching from the bundle to the package:** remove `/usr/local/sbin/nexus-agent` and
  `/etc/systemd/system/nexus-agent.service`, then install the package; `/etc/nexus-agent` and its enrollment are
  kept.

> **Update agents older than 0.1.0-alpha:** their systemd unit hid `/usr/lib/modules` from backups
> (`ProtectKernelModules`), so their snapshots lack the kernel modules, and a bare-metal recovery from them does not
> boot. Install the new package (or bundle) so the unit is replaced; the next backup is complete.

## Bare-metal recovery

Every backup also records the machine's disk layout (partitions, LVM, file systems, boot loader). To rebuild the
machine on empty disks or as a Proxmox VM (P2V), boot the **rescue ISO** from the release page on the target: see
[06 Restores: Bare-metal recovery](06-restores.md#bare-metal-recovery-linux-hosts). LUKS, md RAID and ZFS root layouts are not recreated automatically;
Secure Boot must be off (the ISO is not signed yet).

## Re-enrolling, moving, removing

- **Host reinstalled or `/etc/nexus-agent` lost:** ask for a **New token** on the appliance (the agent keeps its id,
  source and snapshots), then `sudo nexus-agent init --token -` and **Enroll** again.
- **Five failed enrollment attempts** lock the agent; `nexus-agent init --token -` with a new token clears the lock.
- **Remove:** `sudo apt remove nexus-agent` / `sudo dnf remove nexus-agent` stops the service and keeps
  `/etc/nexus-agent`; `sudo apt purge nexus-agent` (or deleting `/etc/nexus-agent` and `/var/lib/nexus-agent` on
  RPM systems) removes the enrollment. Then delete the agent on the appliance.

## Troubleshooting

| Symptom | Check |
|---|---|
| Enrollment job fails with "connection refused" / timeout | `systemctl status nexus-agent`, the host firewall (step 4), `listen`/`port` in `agent.conf` |
| "token expired" / "locked" | new token on the appliance, `nexus-agent init --token -` |
| Service does not start after editing `agent.conf` | `journalctl -u nexus-agent`: the line number of the unknown key or bad value |
| Backup is crash-consistent, "no snapshot support for …" | volume not on LVM/ZFS/btrfs, or the volume group has no free space: raise free space, use thin LVM, or dump databases with a pre hook |
| "pre hook failed" | `sudo nexus-agent hooks test` |
| **Update agent** refused, "installed from a deb package" | update with the package manager, or set `self_update = on` |
| Logs | `journalctl -u nexus-agent` (the job log with hook output is also on the appliance's Jobs page) |

> **Status:** packages are tested in Debian 13, AlmaLinux 10 and Fedora containers at every release; the agent has
> run end to end in the lab with LVM thin/thick, ZFS and btrfs. arm64 packages have not run on real hardware.
