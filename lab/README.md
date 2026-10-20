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

## Linux agent lab (`lab/linux/`)

Small VMs from official cloud images, one at a time (1.5–2 GB RAM each), QEMU user
networking with host forwards on 127.0.0.1 (ssh 2240+N, agent 17440+N; the appliance VM
reaches them as 10.0.2.2:<port>), cloud-init NoCloud seed ISO (genisoimage/xorriso), user
`lab` with the lab key and passwordless sudo. Images are checksum-verified and cached in
`$LAB/linux/images`, VM state in `$LAB/linux/<vm>`. No root on the host.

| VM | Distro | Storage under test | DB |
|---|---|---|---|
| `deb-lvm` (N=1) | Debian 13 | root moved onto LVM (thick, ext4; reboot during provisioning), `/var/lib/postgresql` thick LV ext4, `/srv/xfs` XFS on a thin LV; old root partition at `/srv/plain` | PostgreSQL |
| `alma-xfs` (2) | AlmaLinux 10 (SELinux enforcing) | XFS LVs: `/srv/xfs`, `/var/lib/mysql`, `/var/backups` | MariaDB |
| `ubuntu-zfs` (3) | Ubuntu 24.04 | pool `tank` (posixacl, xattr=sa): `/srv/zfs`, `/home` | – |
| `fedora-btrfs` (4) | Fedora 44 Cloud (SELinux enforcing) | btrfs subvolumes root/home/var + nested subvolume `/srv/btrfs` | – |
| `deb-plain` (5) | Debian 13 | ext4 on a partition, no LVM (fallback mode) | MariaDB |

Every VM gets the sample tree of `provision/common.sh` (owners, setuid/sticky, ns mtimes,
user xattrs, access + default ACLs, file capabilities, hard links, symlinks, fifo, sparse
file, UTF-8/space/newline names, 24 MiB random file).

```sh
lab/pve/stop.sh                                   # if RAM is tight
COSIGN_KEY=release/testkey/TEST-cosign.key COSIGN_PASSWORD=nexus-test-key \
  crates/agent-linux/dist/build-bundle.sh --test-key --sign
lab/linux/bump-bundle.sh 0.1.1                    # signed newer bundle for the update test
cargo build --release -p keyd -p web-api -p scheduler -p setup -p agent-conn
lab/linux/e2e.sh appliance                        # dev control plane (m5.sh) on https://127.0.0.1:18453
lab/linux/vm.sh deb-lvm up                        # fetch, create, boot, provision (~2 min)
lab/linux/snapshot-tests.sh deb-lvm               # #[ignore] root snapshot tests, musl test binary
lab/linux/e2e.sh deb-lvm                          # agent backup incr restore download db update
lab/linux/vm.sh deb-lvm stop
```

`e2e.sh` steps: `agent` (POST /agents, `install.sh --token -` on the VM, enroll job, token
single use), `backup` (hook example enabled, linux source + policy + group, waits for the
*scheduled* backup; `consistent` must match the VM, deb-plain also needs the
`backup_inconsistent` alert), `incr` (4 KiB overwrite, 2 MiB append, new file, chmod,
delete; deb-plain: a file rewritten during the read must be counted inconsistent),
`restore` (wrong confirm → 400, restore to `/restore/<t>`, `manifest.py` comparison of
content, owners, modes, mtimes, xattrs, ACLs, hard links; second restore with
`overwrite=never` writes nothing), `download` (tar + zip; content, owner/mode and PAX
xattrs/ACLs), `db` (restore the dump dir, drop the database, load the dump, count rows),
`update` (new binary with a foreign signature refused, signed 0.1.1 accepted, same
version refused, backup afterwards), `reinstall` (upgrade the agent from `$BUNDLE` in
place). Results as `key=value` in `$ROOT/run/api/<vm>.results`.

Against the appliance VM (SELinux enforcing): `PVE=0 LAB=... lab/appliance/e2e.sh boot setup`,
then `ROOT=$LAB/appliance/root PORT=<port> AGENT_HOST=10.0.2.2 UPDATE_DIR= lab/linux/e2e.sh <vm>`
and `lab/appliance/e2e.sh check` for AVCs (see docs/agent-linux.md, "Lab results").

## Agent test VMs on the PVE lab host (`lab/pvehost/agent-vms.sh`)

One small VM per distribution release on pve-test (2 vCPUs, 2 GB, 16 GB thin disk, DHCP on vmbr0, IDs 220-233,
names `ag-<release>`, tag `nexus-agent-lab`): Ubuntu 22.04, 24.04, 26.04, 26.10; Debian 12, 13, testing; Alma
8.10, 9.8, 10.2; Rocky 8.10, 9.8, 10.2; openSUSE Leap 16.0. Installed unattended from the ISOs on the host
(direct kernel boot with the answer file URL: Ubuntu autoinstall, Debian preseed, kickstart, Agama profile; the
files come from a temporary HTTP server on the host), then the offline snapshot **`clean-os`** (OS only), then
the agent package of `$TAG`. Root and user `nexus` log in with `~/nexus-lab/lab_ed25519` (through the host);
the `nexus` password is in `~/nexus-lab/agent-vms/password`.

```sh
lab/pvehost/agent-vms.sh install [names]   # e.g. ubuntu-2404 debian-13; default all (4 at a time, ~45 min)
lab/pvehost/agent-vms.sh ip [names]        # addresses from the guest agent
lab/pvehost/agent-vms.sh reset [names]     # back to the clean OS (stopped); then `agent` installs the package
lab/pvehost/agent-vms.sh agent [names]
```

Stop the VMs when no test runs (`qm stop`): together they hold 28 GB of the host's memory.

## Server test VMs on the PVE lab host (`lab/pvehost/server-vms.sh`)

| ID | Name | What | Sizing |
|---|---|---|---|
| 240 | `nx-truenas-2510` | TrueNAS SCALE 25.10.7 | 2 vCPUs, 8 GB, boot 20 GB + two 8 GB disks for the pool |
| 241 | `nx-truenas-27` | TrueNAS 27.0.0-RC1 | same |
| 242 | `nx-winsrv-2022` | Windows Server 2022 Standard Evaluation (Desktop Experience) | 2 vCPUs, 4 GB, 40 GB SATA, e1000 |

Unattended like the agent VMs, with the offline snapshot **`clean-os`** after the install. TrueNAS: the live ISO's
installer API driven by `lab/truenas/install.py` (about 4 min); the installer's DHCP address is read from its first
packet on the tap interface. Windows: `autounattend.xml` on a generated CD (deleted after the install), one
automatic logon that installs the virtio-win guest tools (virtio-serial driver + QEMU guest agent), OpenSSH with
`~/nexus-lab/lab_ed25519` for Administrator, then shuts down (about 14 min). Passwords in `~/nexus-lab/server-vms/`.

```sh
lab/pvehost/server-vms.sh install [names]   # truenas-2510 truenas-27 winsrv-2022
lab/pvehost/server-vms.sh ip [names]
lab/pvehost/server-vms.sh reset [names]
ssh -i ~/nexus-lab/lab_ed25519 Administrator@<ip>   # Windows; TrueNAS: API https://<ip>/api, user truenas_admin
```

The TrueNAS lab scripts run against these VMs with their address and the real ports (state per VM in
`~/nexus-lab/server-vms/<name>/truenas/`; disks carry serial numbers, which TrueNAS needs for the pool):

```sh
export LAB=~/nexus-lab/server-vms/truenas-2510 TN_HOST=<ip> TN_API_PORT=443 TN_SSH_PORT=22
lab/truenas/provision.py                                  # pool, datasets, user, privilege, API key, appliance key
lab/e2e/m5.sh setup && lab/e2e/m5.sh start
FROM=<the dev host's address as TrueNAS sees it> lab/truenas/e2e.sh
```

## TrueNAS lab (`lab/truenas/`, docs/truenas-connector.md)

TrueNAS Community 25.10.7 in QEMU/KVM (8 GB RAM, 20 GB boot disk, two 8 GB data disks), installed
without any console interaction through the installer's own JSON-RPC API (port 8080 of the live ISO).
API https://127.0.0.1:18444 (self-signed `truenas_default`, pinned), SSH 127.0.0.1:12222. State and
credentials in `$LAB/truenas/` (admin password, lab admin key, API key, appliance key, cert, known_hosts).

```sh
lab/pve/stop.sh                       # if `free -g` shows < 10 GB available
lab/truenas/vm.sh fetch               # ISO + sha256 check
lab/truenas/vm.sh install             # unattended install (~4 min), powers off
lab/truenas/vm.sh start               # boots, waits for the API (~80 s)
lab/truenas/provision.py              # pool tank, datasets, user/privilege/API key (docs §3)
cargo build --release -p keyd -p pve -p offsite -p web-api -p scheduler -p setup -p agent-conn -p truenas
lab/e2e/m5.sh setup && lab/e2e/m5.sh start
lab/truenas/e2e.sh                    # data config backup1 modify backup2 snapshots download rotation probe
lab/e2e/m5.sh stop; lab/truenas/vm.sh stop
```

`data.sh init|modify|sums|xattrs` (run on TrueNAS via `sh.py`), `probe.py` (the appliance key can only
use the forced command), `tests/lab.rs` in crates/truenas (`NEXUS_TRUENAS_LAB=$LAB/truenas/lab-cli.json
NEXUS_TRUENAS_STORE=… NEXUS_TRUENAS_SUMS=… cargo test -p truenas --test lab`). Against the appliance VM:
`PVE=0 lab/appliance/e2e.sh boot setup`, then `ROOT=$LAB/appliance/root PORT=28443 APPL_HOST=10.0.2.2
lab/truenas/e2e.sh` and `lab/appliance/e2e.sh check`.

## NAS lab (`lab/nas/`, docs/nas-connector.md)

One Debian 13 VM (3 GB, 4 vCPUs) serves NFS v3/v4.x (`/srv/share`, `/srv/many` with 1M small files)
and Samba (`share`, `many`; signing mandatory, encryption desired). Ports on 127.0.0.1: ssh 2250,
NFS 12049, mountd 12048, SMB 10445, dev API 18453. Mounting needs root, which the dev host does not
have, so the dev control plane runs **inside** that VM (`devcp.sh`, lab/e2e/m5.sh plus the real
nexus-nasmount units) and mounts over its loopback; the appliance VM mounts through 10.0.2.2.

```sh
lab/nas/vm.sh up                      # create + boot + provision.sh (~3 min)
lab/nas/vm.sh data init; lab/nas/vm.sh data many 1000000   # test data (~30 s for 1M files)
cargo build --release -p keyd -p web-api -p scheduler -p setup -p nas
lab/nas/devcp.sh all                  # deploy + setup + start the dev control plane in the VM
lab/nas/e2e.sh                        # data config backup1 download modify backup2 churn snapshot many alerts summary
ROOT=$PWD/target/nas-devcp PORT=18453 node --experimental-websocket lab/nas/ui.mjs target/nas-ui
# appliance VM (MEM=6144: the 1M-file share needs more than 3 GB):
MEM=6144 lab/appliance/run.sh start <disk>; PVE=0 lab/appliance/e2e.sh setup
APPL=1 lab/nas/e2e.sh; ROOT=$LAB/appliance/root PORT=28443 node --experimental-websocket lab/nas/ui.mjs target/nas-ui
lab/nas/devcp.sh stop; lab/nas/vm.sh stop
```

## Appliance replication lab (`lab/appliance/replication.sh`, docs/replication.md)

Two appliance VMs from the same bootc image, both SELinux enforcing, on separate QEMU user networks:
A (primary, `$LABDIR/repl-a`, 8443 → 127.0.0.1:28471) backs up PVE lab VM 100; B (secondary,
`$LABDIR/repl-b`, 8443 → 127.0.0.1:28472) pulls from A through the host (`10.0.2.2:28471`). Needs the PVE
lab running and ~6 GB free RAM (A 2.5 GB, B 3 GB).

```sh
IMG=localhost/nexus-os:repl lab/appliance/e2e.sh image   # own tag: does not disturb other lab images
lab/appliance/replication.sh disks      # install once, copy for A and B
lab/appliance/replication.sh boot setup # first boot on both (A with the PVE keys)
lab/appliance/replication.sh primary    # A: tenant lab, PVE source, group [100], backup
lab/appliance/replication.sh enroll     # A: peer + approval; B: source + enrollment; A: key export approval
lab/appliance/replication.sh sync       # B: pull (throughput in the log)
lab/appliance/replication.sh backup2 sync   # incremental
lab/appliance/replication.sh check      # domains, AVCs (0 nexus expected) on both
lab/appliance/replication.sh restore    # stops A, then file download from vm-100 on B (micro-VM)
lab/appliance/replication.sh check stop
```

## Forwarding lab (`lab/appliance/forwarding.sh`, docs/control-plane.md "Forwarding")

Audit / alert forwarding of an installed appliance VM (after `lab/appliance/e2e.sh boot setup`, `PVE=0` is
enough) to `lab/forwarding/testbox` (rootless podman, image built from `quay.io/centos/centos:stream10`:
rsyslog with TLS on 127.0.0.1:16514 and an HTTPS JSON sink on 127.0.0.1:18445, lab CA in
`target/forwarding-testbox/`; the VM reaches both at 10.0.2.2).

```sh
lab/appliance/forwarding.sh all     # testbox, both sinks via the API, test message, every seq + hash at both
                                    # receivers (no gaps), outage + backlog, quorum for disabling, audit.csv
lab/appliance/e2e.sh check          # 0 nexus AVCs
lab/appliance/forwarding.sh stop
```

Without a VM, the formatting against a real rsyslog: `lab/forwarding/testbox/run.sh start`,
`eval "$(lab/forwarding/testbox/run.sh env)"`, `cargo test -p scheduler --lib testbox -- --ignored`.
