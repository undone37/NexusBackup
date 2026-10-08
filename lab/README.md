# NexusBackup test lab: nested Proxmox VE 9.x

A single PVE 9.x node (`pve1.lab.local`) running headless under QEMU/KVM on the
dev machine, used as the backup source for the appliance.

## Prerequisites

- Linux host with KVM + nested virtualisation (`/sys/module/kvm_intel/parameters/nested` = Y),
  user in group `kvm`
- `qemu-system-x86_64`, `qemu-img`, `podman` (or `CTR=docker`), `curl`, `ssh`, `python3`
- ~8 GB free RAM, ~10 GB disk (sparse 64 GB qcow2 + 1.7 GB ISO x2)
- Internet access (ISO, Proxmox apt repo, Debian cloud image, LXC template)

No host packages and no sudo needed. `proxmox-auto-install-assistant` runs in a
Debian trixie container (`pve/Containerfile.assistant`).

## Usage

```sh
lab/pve/build.sh      # download + verify latest PVE 9.x ISO, build auto-install ISO, install (~10 min)
lab/pve/start.sh      # boot headless (daemonized), waits for ssh
lab/pve/provision.sh  # repos, NAT bridge, VM 100, CT 200, API token (idempotent)
lab/pve/stop.sh       # ACPI powerdown via QMP
```

`FORCE=1 lab/pve/build.sh` reinstalls the disk. `MEM`/`CPUS` override start.sh (default 6144 MB / 4).

## Artifacts and credentials (all in `/home/ah/nexus-lab/`, never in git)

| File | Content |
|---|---|
| `pve1.qcow2` | PVE system disk |
| `lab_ed25519` / `.pub` | SSH key for root@pve1 and the nested guests |
| `root-password` | root password (web UI login `root`, realm PAM) |
| `api-token` | `nexus@pve!appliance=<secret>` (privsep=1) |
| `answer.toml` | rendered answer file |
| `pve1.serial.log`, `pve1.pid`, `pve1.qmp` | serial console, pidfile, QMP socket |

## Access (bound to 127.0.0.1 only)

- Web UI / API: https://localhost:18006 (self-signed)
  `curl -k -H "Authorization: PVEAPIToken=$(cat /home/ah/nexus-lab/api-token)" https://localhost:18006/api2/json/version`
- SSH: `ssh -p 10022 -i /home/ah/nexus-lab/lab_ed25519 root@localhost`

## Lab network

- pve1 `vmbr0`: 10.0.2.15/24 on QEMU user networking (gw 10.0.2.2, dns 10.0.2.3)
- pve1 `vmbr1`: 10.10.10.1/24, NAT to vmbr0, for nested guests
  - VM 100 `testvm100`: Debian 13 genericcloud, 10.10.10.100, user `debian` (lab key),
    `ssh -J root@localhost:10022 -i .../lab_ed25519 debian@10.10.10.100`
  - CT 200 `ct200`: Debian 13 standard, unprivileged, 10.10.10.200

## Permissions

The token currently has `PVEVMAdmin`, `PVEDatastoreAdmin`, `PVEAuditor` on `/` (user and
token ACLs). This is lab-only; the least-privilege role set for the appliance is TBD.
