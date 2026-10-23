# Compatibility: what has been tested on which platform

What ran end to end against real software, with version, date and test. "Lab" means a VM, never a production
system; nothing here is a support statement (NexusBackup is an alpha, see the README). Everything not listed is
untested. Details and numbers: [`state.md`](../state.md); how to rerun: [`lab/README.md`](../lab/README.md).

## Linux agent

### Packages (.deb / .rpm) on default installations, 2026-10-20

`lab/pvehost/agent-matrix.sh`, agent 0.1.0 of the v0.1.0-alpha draft, VMs on the PVE lab host installed unattended
from the distribution ISOs with their default disk layout. Per VM: package install, `init --token`, enrolment,
backup of `/etc` and a test tree, incremental, restore of the tree compared entry by entry (owners, modes,
nanosecond times, xattrs, POSIX ACLs, file capabilities, hard and symbolic links, sparse file, FIFO, setuid).

| Distribution | Release | Package | File system (default layout) | Snapshot | Result |
|---|---|---|---|---|---|
| Ubuntu | 22.04.5 LTS | .deb | ext4 | none, read live | passed, restore identical |
| Ubuntu | 24.04.5 LTS | .deb | ext4 | none, read live | passed, restore identical |
| Ubuntu | 26.04.1 LTS | .deb | ext4 | none, read live | passed, restore identical |
| Ubuntu | 26.10 | .deb | ext4 | none, read live | passed, restore identical |
| Debian | 12.15 (bookworm) | .deb | ext4 | none, read live | passed, restore identical |
| Debian | 13.7 (trixie) | .deb | ext4 | none, read live | passed, restore identical |
| Debian | testing (forky) | .deb | ext4 | none, read live | passed, restore identical |
| AlmaLinux | 8.10 | .rpm | XFS on LVM, 4 GB free in the VG | LVM snapshot, consistent | passed, restore identical |
| AlmaLinux | 9.8 | .rpm | XFS on LVM, 4 GB free in the VG | LVM snapshot, consistent | passed, restore identical |
| AlmaLinux | 10.2 | .rpm | XFS on LVM, 4 GB free in the VG | LVM snapshot, consistent | passed, restore identical |
| Rocky Linux | 8.10 | .rpm | XFS on LVM, 4 GB free in the VG | LVM snapshot, consistent | passed, restore identical |
| Rocky Linux | 9.8 | .rpm | XFS on LVM, 4 GB free in the VG | LVM snapshot, consistent | passed, restore identical |
| Rocky Linux | 10.2 | .rpm | XFS on LVM, 4 GB free in the VG | LVM snapshot, consistent | passed, restore identical |
| openSUSE Leap | 16.0 | .rpm | btrfs | btrfs snapshot, consistent | passed, restore identical |

Notes: Ubuntu and Debian default installs (plain ext4) have no snapshots: the agent reads live and marks the backup
not consistent. LVM snapshots need free space in the volume group (about 10 % of the snapshotted volume by default,
`lvm_snapshot_percent`); the Alma and Rocky kickstart default (`autopart`) leaves none, so the agent then reads live
and says why. The lab VMs use root 10 GB + swap 1 GB with 4 GB free in the VG (2026-10-20, run against the
appliance VM on pve-test): LVM snapshot and consistent backups on all six. On Alma, Rocky and Leap firewalld blocks TCP 7444 until
the rule from manual chapter 4 is added.

### Storage layouts (bundle), 2026-10-13 and earlier

`lab/linux/e2e.sh` (agent, backup, incremental, endpoint, restore, download, database, update) on prepared VMs:

| VM | Distribution | Storage | Database | Result |
|---|---|---|---|---|
| `deb-lvm` | Debian 13 | root on thick LVM (ext4), XFS on a thin LV | PostgreSQL (hook) | passed, LVM snapshots, consistent |
| `alma-xfs` | AlmaLinux 10, SELinux enforcing | XFS logical volumes | MariaDB (hook) | passed, consistent |
| `ubuntu-zfs` | Ubuntu 24.04 | ZFS pool (posixacl, xattr=sa) | - | passed, ZFS snapshots, consistent |
| `fedora-btrfs` | Fedora 44 Cloud, SELinux enforcing | btrfs subvolumes, nested subvolume | - | passed, btrfs snapshots, consistent |
| `deb-plain` | Debian 13 | ext4 on a partition | MariaDB | passed, inconsistent as expected, alert raised |

Not tested yet: in-band package updates on the VMs above (L6 in plan.md Phase 39), arm64 hardware (only an
emulated aarch64 VM), other distributions (Arch, Alpine, SLES, RHEL itself).

## Windows agent (MSI)

| Windows | Edition, role | Date | Test | Result |
|---|---|---|---|---|
| Windows Server 2022 (21H2) | member server (maintainer's lab VM) | 2026-10-13 | `lab/windows/e2e.sh`, manual test plan steps 1-9, 11 | passed |
| Windows Server 2022 (21H2) | domain controller | 2026-10-13 | as above plus the NTDS writer, restored `ntds.dit` | passed |
| Windows 11 | client | 2026-10-13 | install, fleet enrolment, major upgrade with the GUI running, uninstall | passed |
| Windows Server 2022 Standard Evaluation | fresh installation, VM 242 | 2026-10-20 | `lab/windows/e2e.sh` default steps (MSI, VSS backup, USN incremental, restore identical, junction confinement, MSI update refused, service restart) | passed |

Not tested: Windows Server 2016, 2019, 2025; ReFS, FAT/exFAT, folder-mounted volumes; SQL Server and Exchange
writers; Data Deduplication, EFS; GPO/Intune deployment; image or bare-metal backup (not implemented, Phase 37).

## Proxmox VE

| Version | Setup | Test | Result |
|---|---|---|---|
| 9.2.2 | nested in QEMU, single node | backup, incrementals with dirty bitmaps, restore, file index | passed |
| 9.2.x (9.2.21 storage API 16 noted) | the PVE lab host `pve-test`, single node, the appliance as VM 201 | VM and container backup, full restore, instant recovery, restore tests incl. a Windows VM with vTPM, file index and search | passed |

Not tested: multi-node clusters, Ceph/RBD storage, PVE 8 (not supported).

## TrueNAS (connector `nexus-truenas`)

| Version | Date | Test | Result |
|---|---|---|---|
| TrueNAS Community Edition 25.10.7 | 2026-10-09, 2026-10-20 | `lab/truenas/e2e.sh` all steps (two scheduled backups, incremental after renames, hard links, ACL/xattr changes, downloads, rotation, forced-command probes) | passed |
| TrueNAS 27.0.0-RC1 | 2026-10-20 | as above | passed |

## VMware ESXi and vCenter (connector `nexus-vmware`)

| Version | Date | Test | Result |
|---|---|---|---|
| vCenter 8.0.3 (build 25413364) with ESXi 7.0.3 (build 20328353) | 2026-10-23/24 | `lab/pvehost/vmware-e2e.sh` on the appliance VM: inventory, backup over NFC (Debian 12 guest, 16 GiB, application-consistent), restore as a Proxmox VE VM, boot | passed |
| ESXi 7.0.3, standalone | 2026-10-23 | `crates/vmware/tests/lab.rs`: snapshot, CBT, hot-add proxy backup (full and incremental) | passed |
| vCenter 8.0.3 / ESXi 7.0.3 | 2026-10-23 | `crates/vmware/tests/lab.rs`: NFC reads and NFC backup (full and incremental, reconstructed disks bootable) | passed |
| ESXi 8.0.3, nested | 2026-10-23 | transport spike: CBT and hot-add reads (`lab/pvehost/esxi.sh hotadd`) | passed |

## Other sources and targets

| Component | Test | Result |
|---|---|---|
| NFS v3/v4.x and SMB (Samba on Debian 13) | `lab/nas/` | passed |
| PostgreSQL plugin | lab and container testbox | passed |
| MySQL/MariaDB plugin | container testbox (CI) | passed in tests; no lab run on a real server |
| S3 offsite | MinIO only | never against a real S3 provider |
| SFTP offsite | local SFTP test server only | never against a real Hetzner Storage Box |
| OIDC single sign-on | Keycloak in a container (CI) | passed |
| Microsoft 365 | Graph mock only | never against a real tenant |

## Appliance

| Platform | Test | Result |
|---|---|---|
| QEMU/KVM VM, UEFI | unattended install from the installer ISO, first-boot wizard, SELinux enforcing | passed |
| Proxmox VE VM (VM 201 on `pve-test`) | appliance in daily lab use, signed updates | passed |
| Physical hardware | none | not tested |
