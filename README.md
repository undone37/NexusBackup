# NexusBackup Appliance

A self-contained backup appliance for Proxmox VE, Linux and Windows hosts, NAS shares, TrueNAS, PostgreSQL,
MySQL/MariaDB and Microsoft 365. It **pulls** data from every source, keeps it as **deduplicated, encrypted
forever-full snapshots** and copies it to **immutable offsite storage**. Licensed under AGPL-3.0.

> [!WARNING]
> **This is fully vibe-coded software.** AI coding agents (Claude Code) wrote practically all of the code, tests,
> documentation and the manual, under human direction. No human has reviewed the code line by line.
>
> **Do not use it in production in its current state.** It is an alpha. Many features have run only against
> mocks, simulators or a small lab (see [What has been tested](#what-has-been-tested)). It has had no external
> security audit or penetration test. Its on-disk formats may still change without a migration path.
>
> **There is no guarantee whatsoever.** The software is provided "as is", without warranty of any kind, express or
> implied. That includes fitness for any purpose and the ability to restore your data. You use it entirely at your
> own risk; see sections 15 and 16 of the [license](LICENSE). Never make it the only copy of data you care about.

## What it does

The appliance runs as its own OS image, on hardware or as a VM. One web UI and REST API manage everything. It
connects out to the sources on a schedule set by policies. It reads only changed data where the source can tell
which data changed, and it stores each backup as a complete snapshot. Locally only new chunks take space, and
nothing is stored unencrypted. Retention locks can only be extended, and destructive actions can require a second
person's approval. Copies go to an offsite target (SFTP or S3 with Object Lock) and optionally to a second
appliance. An offsite copy is restorable on new hardware with nothing but the storage credentials and the offline
recovery key.

## Features

### Sources

| Source | How it is backed up | Restores |
|---|---|---|
| **Proxmox VE 9** VMs | PVE backup provider plugin on the node; changed blocks from QEMU dirty bitmaps; fleecing; zero blocks skipped | full VM restore (including EFI disk and TPM state), instant recovery (boot from the backup, then live disk move), instant disk attach, in-place rollback writing only changed blocks, single files from inside the guest |
| Proxmox VE containers | tar stream from the container's user namespace | full container restore, file download |
| Linux hosts | `nexus-agent` (static binary, .deb/.rpm, x86_64 and aarch64): LVM, ZFS or btrfs snapshots; source-side dedup | restore to a path or another host, tar/zip download, bare-metal recovery and P2V through a rescue ISO |
| Windows Server and Windows 11 | `nexus-agent` MSI: VSS snapshots, USN journal for incrementals, security descriptors, alternate data streams; tray app | restore to a path or another host, tar/zip download |
| NFS / SMB shares | read-only mounts on the appliance, parallel scan | tar/zip download, clean-file restore |
| TrueNAS (SCALE) | ZFS snapshots plus `zfs diff` over the API and a restricted SSH user | tar/zip download |
| PostgreSQL 14+ (plugin) | logical dumps per database; base backup plus WAL | restore to the source or another server, point in time |
| MySQL / MariaDB (plugin) | dumps; physical backup plus binlog | restore, point in time |
| Microsoft 365 (plugin) | Microsoft Graph: mailboxes, OneDrive, SharePoint libraries, Teams, Entra ID export | download; restore to the original or another user, site or team; export as eml/mbox/PST |

### Storage and security
- **Storage:**
  - content-defined chunking with per-tenant keyed chunk IDs;
  - zstd compression;
  - XChaCha20-Poly1305 encryption for every chunk;
  - dedup across all sources of a tenant, never across tenants.
- **Immutability:**
  - retention locks that can only be extended, kept on a tamper-resistant compliance clock;
  - GFS retention;
  - legal hold.
- **Four-eyes approvals** (quorum) for deleting, shortening, unlocking and weakening settings. Optionally tenants
  approve their own deletions.
- **Hash-chained audit log**, forwarded over syslog/TLS, HTTPS or Splunk HEC.
- **Ransomware:**
  - change-rate, duration and dedup-rate anomaly alerts;
  - YARA scans of snapshots in an offline restore micro-VM;
  - SHA-256 IOC hash hunting;
  - "newest clean snapshot" defaults;
  - clean-file (synthetic) restores;
  - incident mode and per-tenant lockdown.
- **Appliance OS:**
  - bootc image on AlmaLinux 10, updated with signed A/B updates (cosign) that roll back automatically when the
    health check fails;
  - every service in its own user, systemd sandbox and SELinux domain (enforcing);
  - default-deny firewall in both directions, with one inbound port (8443).
- **Sign-in:**
  - local accounts with TOTP and passkeys;
  - OIDC single sign-on;
  - roles: admin, operator, security officer, viewer and tenant roles;
  - just-in-time role elevation, scoped API tokens.
- **Keys:**
  - per-tenant data keys wrapped by a key-encryption key;
  - recovery key escrow;
  - hybrid post-quantum wrapping (X25519 + ML-KEM-768) for exported keys.

### Offsite, replication, disaster recovery
- **Offsite:** SFTP (e.g. Hetzner Storage Box) or S3 with Object Lock (own SigV4 client). A second offsite target
  can have its own retention.
- **Second appliance:** pull replication over mTLS, with its own retention. A vault mode opens a sync window only on
  schedule.
- **Disaster recovery:**
  - the daily configuration backup goes to every offsite target;
  - a fresh appliance can be restored from an offsite copy plus the recovery key.
- **Restore assurance:**
  - scheduled restore tests: an isolated boot plus guest-agent and port checks;
  - recovery plans with waves;
  - a daily readiness check and a DR report.

### Operations
- **Scheduling and protection:**
  - policies and protection groups;
  - auto-protect of new PVE guests by tag or pool;
  - blackout windows, retries, concurrency caps.
- **Visibility:**
  - live job progress with estimates;
  - a dashboard with KPIs and a capacity forecast;
  - scheduled reports and a billing export.
- **File search:** an index of guest file systems (NTFS, ext4, XFS, btrfs, FAT, exFAT, LVM, Windows dynamic disks)
  answers searches across all snapshots in milliseconds.
- **Alerts:**
  - e-mail, webhooks, syslog and Prometheus metrics;
  - PSA tickets in HaloPSA, ConnectWise and Autotask.
- **Multi-tenancy:**
  - separate keys per tenant;
  - tenant admins and per-tenant OIDC;
  - view-as-tenant and an onboarding wizard.
- **Agent fleet:**
  - silent MSI and package installs;
  - fleet enrollment by IP range scan or CSV;
  - agent updates pushed from the appliance (canary, rollback);
  - an edge proxy for roaming agents.
- **Plugin system:** signed, sandboxed plugins (Landlock and seccomp) on a Rust SDK.
- **Tools:** `nexusctl` CLI, an OpenAPI description, `nexusctl fleet` (read-only overview of several appliances),
  diagnostics bundle and self-checks.

## What it does not do
- **Hypervisors other than Proxmox VE:** no VMware (only a design document), Hyper-V, Nutanix, XCP-ng or OpenStack.
- **Cloud:** no AWS, Azure or GCP VMs, cloud PaaS databases, Kubernetes, Salesforce or Google Workspace.
- **Tape and NDMP:** none, and no archive storage classes (Glacier Deep Archive and similar).
- **Databases other than PostgreSQL and MySQL/MariaDB** are not handled natively: no Oracle, SQL Server (log chain
  or point in time), SAP HANA or DB2. On Windows, VSS takes copy-only snapshots and never truncates logs.
- **Windows:**
  - file-level backups only, no block-level change tracking;
  - no bare-metal recovery (Linux only);
  - EFS-encrypted files are not backed up.
- **Clustering:** no scale-out cluster and no high availability. One appliance, plus optional replication to a
  second one; replicated tenants cannot be promoted automatically.
- **Disk encryption:** no TPM-sealed key and no LUKS yet. The key-encryption key is a root-only file on the
  appliance. Chunks are always encrypted, but whoever has the appliance's disks and that file can read the data.
- **Archiving:** not a long-term archive for legal retention (GoBD, SEC 17a-4).
- **Vendor-hosted services:** no SaaS and no vendor-hosted vault. You bring your own offsite storage.
- **AI and machine learning:** none in detection or the data path. The anomaly checks are deterministic.
- **Support:** no commercial support and no SLA.

## What has been tested
In this list, "lab" means a run end to end against real software in VMs. The lab used:
- a Proxmox VE 9.2 host with a Windows Server 2022 member server and domain controller, Windows 11 and a Debian
  guest, with the appliance as a VM with SELinux enforcing;
- nested Proxmox VE;
- Linux VMs (Debian, AlmaLinux, Ubuntu with ZFS, Fedora with btrfs), and on 2026-10-20 the agent packages on the
  default installs of 14 releases: Ubuntu 22.04 to 26.10, Debian 12, 13 and testing, AlmaLinux and Rocky Linux 8, 9
  and 10, openSUSE Leap 16;
- a fresh Windows Server 2022 installation;
- TrueNAS 25.10.7 and 27.0.0-RC1;
- NFS and SMB servers;
- MinIO;
- Keycloak.

| Area | Status |
|---|---|
| Proxmox VE VM / container backup, full restore, instant recovery, restore tests, file index and search | lab (single PVE node; multi-node untested) |
| Linux agent (14 distribution releases, packages), Windows agent (Server 2022, Windows 11, domain controller with NTDS), bare-metal recovery (Linux) | lab |
| NFS/SMB, TrueNAS, PostgreSQL, replication between two appliances, configuration restore, signed updates, installer ISO | lab |
| SFTP and S3 offsite | lab against a local SFTP test server and MinIO only; never against a real Hetzner Storage Box or S3 provider |
| Microsoft 365 | Graph mock only; **never run against a real tenant** |
| MySQL/MariaDB, PSA ticketing, instant rollback, second offsite target, `nexusctl fleet`, clean-file restore, threat scans, IOC hunt, compliance cases | unit and integration tests or mocks only |
| Scale, soak tests, real backup hardware, Windows Server 2016/2019/2025 | not tested |

Measured in the lab:
- **Windows Server VM (120 GB disk):**
  - full backup 388 s, incremental 25 s;
  - restore test boots it in 130 s;
  - file index of its C: drive (391,000 entries) 15.5 s per snapshot.
- **Instant recovery:** the VM runs 4.5 s after the start.
- **Replication:** 181 MB/s for the initial sync.

Per platform and version: [compatibility matrix](docs/compatibility.md). The exact state, every open item and the
production gaps are in [`state.md`](state.md).

## Comparison
A rough orientation, not a buyer's guide. The other products are described from their public documentation as of
October 2026; none of them was installed or tested for this. Check the vendors' own documentation before you rely on
any cell. Detailed reviews: [Veeam](docs/veeam-comparison.md), [Cohesity](docs/cohesity-comparison.md),
[NetBackup](docs/netbackup-comparison.md), [Commvault](docs/commvault-comparison.md).

| | NexusBackup | Veeam B&R | Cohesity DataProtect | Rubrik | NetBackup | Commvault | Proxmox Backup Server |
|---|---|---|---|---|---|---|---|
| **Maturity** | vibe-coded alpha, no support | mature, commercial support | mature, commercial support | mature, commercial support | mature, commercial support | mature, commercial support | mature, optional subscription |
| **License** | AGPL-3.0, free | commercial | commercial | commercial | commercial | commercial | AGPL-3.0, free |
| **Deployment** | appliance image (ISO / VM) | software on Windows or a Linux appliance | appliances, virtual edition, SaaS | appliances, SaaS control plane | primary + media servers, appliances | software, HyperScale appliances, SaaS | Debian-based server |
| **Proxmox VE VMs** | native (backup provider API, dirty bitmaps) | native | as a storage target for PVE's own backups | no native support documented | KVM agentless (11.1+), no PVE-specific integration | native | native (reference implementation) |
| **Proxmox VE containers** | yes | no | through PVE's own backups | not documented | not documented | not documented | yes |
| **VMware, Hyper-V, Nutanix** | no | yes | yes | yes | yes | yes | no |
| **Physical Windows / Linux** | agents (file level on Windows) | agents | agents | agents | clients | agents | Linux client only |
| **Bare-metal recovery** | Linux only | yes | yes | yes | yes | yes | no |
| **Microsoft 365** | plugin, untested against a real tenant | separate product | yes | yes | separate SaaS | yes | no |
| **Databases** | PostgreSQL, MySQL/MariaDB | broad | broad | broad | broad | broad | no (file level only) |
| **Dedup + encryption** | per tenant, always encrypted | yes | yes | yes | yes | yes | yes (client-side encryption optional) |
| **Immutability** | extend-only locks, S3 Object Lock | hardened repository, Object Lock | WORM (DataLock) | immutable by design | WORM storage, Object Lock | WORM, Object Lock | no native lock |
| **Multi-person approval** | yes, for all destructive actions | four-eyes for selected actions | quorum | quorum authorization | multi-person authorization | multi-person authorization | no |
| **Ransomware detection** | deterministic anomalies, YARA, IOC hashes | yes | yes, ML-based | yes, ML-based | yes, ML-based | yes, ML-based | no |
| **Automated restore tests** | yes (PVE) | yes (SureBackup) | yes | yes | yes | yes | no (verify jobs check data only) |
| **Tape** | no | yes | via archive | via archive | yes | yes | yes |
| **Scale-out / HA** | no | scale-out repositories | yes | yes | yes | yes | no (sync jobs between servers) |
| **Multi-tenancy** | built in, separate keys | Cloud Connect / service providers | yes | yes | yes | yes | namespaces and permissions |

Where NexusBackup is ahead of the others: its Proxmox VE integration and its locking model. Retention locks follow a
compliance clock and no role can shorten them. Destructive and weakening actions need approvals without exemptions.
Everywhere else the commercial products are far ahead in coverage, maturity, scale and support.

### Open-source tools

File-level backup programs and their front-ends work differently from an appliance: the client pushes to a
repository and holds the keys. They are mature and proven; NexusBackup is not. Described from their documentation as
of October 2026, not installed or tested here. Details, versions and sources:
[open-source comparison](docs/open-source-comparison.md).

| | NexusBackup | restic + Backrest | Borg + BorgWarehouse | Duplicati | UrBackup |
|---|---|---|---|---|---|
| **Model** | appliance, pulls | client CLI pushes; Backrest web UI per host | client pushes over SSH; BorgWarehouse runs the repository server | client with web UI per machine | central server pulls from clients |
| **License** | AGPL-3.0 | BSD-2 / GPL-3.0 | BSD-3 / AGPL-3.0 | MIT, proprietary M365 and disk image modules | AGPL-3.0 |
| **Maturity** | vibe-coded alpha | mature | 1.4 mature, 2.0 beta | stable releases | mature |
| **Proxmox VE VMs** | native | no | no | no | no |
| **Windows** | agent: VSS with all writers (copy-only), USN incrementals; files, no image yet | yes (VSS) | no | yes (VSS) | yes, file and image |
| **Image / bare metal** | Linux BMR and P2V; whole PVE VMs | no | no | yes (proprietary module) | Windows, Linux with limits |
| **Encryption** | always, keys on the appliance | always, client key | optional, client key | optional | transport only (Internet mode) |
| **Immutability** | extend-only locks, S3 Object Lock | rest-server append-only | append-only (1.4) | S3/Azure/B2/GCS locks | none |
| **Offsite targets** | SFTP, S3, second appliance | many (S3, SFTP, B2, Azure, GCS, rclone) | SSH (1.4); S3/B2 in 2.0 beta | many | none of its own |
| **Multi-tenant, approvals** | yes | no | no | commercial console only | per-client rights, no approvals |

NexusBackup differs mainly in its model: it pulls from the sources, so protected hosts hold no backup credentials, and
it adds Proxmox VE VM integration, tenants with separate keys and approvals for destructive actions. The open-source
tools are far more mature, run on more platforms (macOS, BSD) and support many more storage backends. For files on a
few hosts, restic with Backrest or Borg with borgmatic is the proven choice today.

## Architecture
```text
                  Web UI (Svelte SPA) ── REST API: nexus-web-api (axum, TLS 1.3, TOTP/passkeys, RBAC, quorum)
                                             │ intent                       │ /replication/v1 (mTLS)
                                       catalog (SQLite WAL)            nexus-replicad (read-only)
                                             │
 sources ◄── pull ── nexus-scheduler ── spawns connectors: nexus-pve · nexus-agentctl · nexus-truenas · nexus-nas
                         │                                   nexus-offsite · nexus-replica · plugins (sandboxed)
                         ├── chunk store (dedup → zstd → XChaCha20-Poly1305, locks, GC, verify)
                         └── keyd (KEK, tenant DEKs, recovery-key escrow)
```
Details:
- [`plan.md`](plan.md): vision, decisions, phases;
- [`docs/`](docs): contracts and designs;
- [`docs/adr.md`](docs/adr.md): architecture decisions;
- [`docs/threat-model.md`](docs/threat-model.md) and [`docs/security-review.md`](docs/security-review.md): threat
  model and internal security review.

## Hardware
The appliance is x86_64 only and boots in UEFI mode. No installation on physical hardware has been tested yet; the
lab runs it as a VM. The full sizing guide is in [manual/02-installation.md](manual/02-installation.md#hardware-sizing).

| | Evaluation (what the lab VM runs) | Reference (5 tenants, 1–2 TB raw data each, GFS retention) |
|---|---|---|
| CPU | 8 cores (vCPUs) with VT-x or AMD-V | 8–16 cores with VT-x or AMD-V |
| RAM | 16 GB | 32–64 GB |
| System disk | one SSD, 24 GB or more (64 GB recommended) | 2 SSDs, mirrored |
| Metadata | on the system disk | 2 NVMe drives of at least 1 TB, mirrored |
| Data | one or more extra disks, or the system disk for a first look | for example 6 × 12 TB in RAID6: about 40 TB usable for 10 TB of raw data after two years of GFS retention |
| Network | one NIC | separate NICs for management, backup and offsite traffic (at least two) |
| Firmware | UEFI | UEFI, TPM 2.0 and Secure Boot capable |

Sizing notes:
- **RAM:** add about 0.6–0.7 GB for each NFS/SMB share with around a million files while it is backed up (the file
  list is held in memory), and 1 GB for each running restore micro-VM (file-level restore, malware scan).
- **Hardware virtualization:** the restore micro-VM uses KVM. Without it, QEMU falls back to software emulation,
  which is many times slower.
- **Headroom:** plan for 30–40 % free capacity. The appliance warns when the store is more than 75 % full.

### Bare metal
- Connect the data disks through a plain HBA (IT mode) or the onboard SATA/NVMe ports. The appliance builds the data
  array itself with mdadm in the web UI and reads SMART from each disk. A hardware RAID controller hides both, so set
  it to JBOD/pass-through or don't use it.
- Use enterprise SSDs (power-loss protection) for the system and metadata disks. The catalog is a SQLite database
  that commits often.
- ECC memory is strongly recommended for a machine whose job is to keep data unchanged for years.
- Set a firmware password and use the BMC (iDRAC/iLO) only on a separate management network.

### Virtual machine
- **Never on the Proxmox VE cluster it protects.** Put it on a separate host or cluster, ideally in another fire
  compartment.
- CPU type `host` (or a model that passes VT-x/AMD-V through) and nested virtualization enabled on the host, so the
  restore micro-VM gets KVM.
- Fixed memory: no ballooning, no overcommit; reserve the full amount.
- Separate virtual disks for the system, the metadata and the data, ideally on different datastores. Never put the
  data on a thin disk on the same datastore as the VMs it backs up. SMART is not available inside a VM; the
  hypervisor watches the physical disks.
- Use the VirtIO devices (virtio-scsi or virtio-blk, virtio-net), and one virtual NIC or VLAN per network.
- A virtual TPM is a file on the host and protects much less than a hardware TPM. Restrict who administers the host.
- Don't take hypervisor snapshots of the running appliance as a backup. Reverting one leaves the catalog older than
  the store and the offsite copies; use the configuration backup instead.

## Downloads
Each [GitHub release](https://github.com/undone37/NexusBackup/releases) carries the installer ISO, the rescue ISO
for bare-metal recovery and the agent packages:

| File | For |
|---|---|
| `nexusbackup-<v>-x86_64.iso` | the appliance installer (UEFI); updates come as signed bootc images |
| `nexus-rescue-<v>.iso` | Linux bare-metal recovery and P2V |
| `nexus-agent_<v>-1_{amd64,arm64}.deb` | Debian, Ubuntu |
| `nexus-agent-<v>-1.{x86_64,aarch64}.rpm` | RHEL, AlmaLinux, Rocky, Fedora, SUSE |
| `nexus-agent-desktop_…` (.deb / .rpm) | Linux desktops: tray icon and status window (needs `nexus-agent`) |
| `nexus-agent-<v>-x64.msi` | Windows Server and Windows 11, including the tray app (silent: `msiexec /i … /qn`) |
| `SHA256SUMS`, `*.sig` | checksums and cosign signatures made with the release key |

Check a download with `sha256sum -c --ignore-missing SHA256SUMS`. Then check its signature with `cosign verify-blob
--key release/keys/<key>.pub --signature <file>.sig --insecure-ignore-tlog=true <file>`, or check a whole directory
with `release/verify.sh --blobs DIR`. The manual starts with [installation](manual/02-installation.md) and
[sources](manual/04-sources.md).

## Documentation
- [`manual/`](manual): the user manual, 18 chapters with screenshots.
- [`lab/README.md`](lab/README.md): the reproducible labs (nested PVE, appliance VMs, Linux agent matrix, TrueNAS,
  NAS, e2e).
- [`docs/release.md`](docs/release.md): how releases are built and signed.

## Build and test
Requirements:
- Rust stable (see `rust-version` in `Cargo.toml`);
- Node 22 for the web UI;
- podman for the image and the test boxes;
- QEMU/KVM for the labs.

No root is needed on the build host.
```sh
cargo build --release                       # all binaries
cargo test --workspace                      # unit + integration tests
cargo clippy --all-targets -- -D warnings
prove pve-plugin/t                          # PVE node plugin (Perl, taint mode)
(cd web && npm ci --ignore-scripts && npm run check && npm run build)
cargo deny check                            # licenses, advisories, sources
podman build -f os/Containerfile -t localhost/nexus-os:dev .   # appliance image
```

## Repository layout
| Path | Content |
|---|---|
| `crates/chunkstore`, `crates/keyd`, `crates/catalog`, `crates/recovery-key` | chunk store (crypto, clock, retention, GC, verify), key service, SQLite catalog and audit log, recovery key words (BIP39) |
| `crates/web-api`, `web/` | REST API and Svelte web UI |
| `crates/scheduler` | policies, job runner, alerts, firewall allow-list |
| `crates/pve`, `pve-plugin/` | Proxmox VE connector and node plugin (Perl, `.deb`) |
| `crates/agent-*` | agent protocol, Linux and Windows agents, desktop UI, appliance side |
| `crates/fsindex` | guest file system readers for the file index |
| `crates/truenas`, `crates/nas` | TrueNAS and NFS/SMB connectors |
| `crates/plugin-*`, `plugins/` | plugin protocol, sandbox host, SDK; PostgreSQL, MySQL, TrueNAS, Microsoft 365 plugins |
| `crates/offsite`, `crates/replication` | offsite engine (SFTP, S3) and second-appliance replication |
| `restore-vm/` | restore micro-VM and rescue ISO |
| `os/` | bootc Containerfile, systemd units, SELinux policy, nftables, update and health checks |
| `release/` | packaging, signing, verification, promotion |
| `manual/`, `lab/`, `docs/` | user manual, labs, design documents |

## Security
Please report vulnerabilities privately to the maintainer, not in public issues. The threat model, the internal
security review and the scope for an external penetration test are in `docs/`.

## License
[GNU Affero General Public License v3.0](LICENSE) (AGPL-3.0-only), without any warranty. Third-party components keep
their own licenses, which `cargo deny` checks. The restore micro-VM image contains GPL (Linux) and CDDL (OpenZFS)
components.
