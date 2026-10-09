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

## M5 end-to-end (`lab/e2e/`)

The control plane as the current user under a scratch root (`target/m5-root`), no sudo:
`nexus-setup --script` (admin + security officer with TOTP, keyd init, TLS, metrics token),
then keyd, `nexus-web-api` (https://nexus-m5:18443, certificate verified) and `nexus-scheduler`
(tick 5 s). `m5-api.sh` drives the REST API only (cookie jar + CSRF): tenant `lab` with the SFTP
testbox as offsite target, source `pve1`, policy (daily schedule one minute ahead), group [100, 200];
waits for the scheduled backup → retention → offsite; checks snapshots/metrics/alerts; file
download from the CT and the VM snapshot (micro-VM) as an operator; verify; quorum (weakening
policy, approval by the security officer); audit chain. `m5-ui.mjs` repeats the main flow in
headless Chrome against the embedded SPA.

```sh
(cd web && npm ci --ignore-scripts && npm run build)
cargo build --release -p keyd -p pve -p offsite -p web-api -p scheduler -p setup
restore-vm/build.sh                      # once; m5.sh falls back to the main checkout's build
crates/offsite/testbox/run.sh start      # SFTP testbox on 127.0.0.1:2223
LAB_SSH_KEY=<appliance key of the node> lab/e2e/m5.sh all   # ~5 min; logs in target/m5-root/log
lab/e2e/m5.sh stop
```
Single steps: `lab/e2e/m5-api.sh check restore` etc. (see the script header).
