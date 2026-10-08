# Open-Source Enterprise Backup Appliance — Project Plan

**Version:** 1.0 (initial consolidated plan)
**Date:** 2026-10-08
**Status:** Draft for review

---

## 1. Vision and Goals

Build an open-source, enterprise-grade backup suite modelled on Cohesity: a hardened, self-contained backup appliance that pulls data from all sources, stores everything deduplicated as forever-full snapshots, and replicates encrypted copies to an offsite tier.

### 1.1 Design principles

1. **Forever full.** Every backup is a complete, immutable snapshot. Physically only new chunks are stored.
2. **Global deduplication per tenant.** All sources of a tenant deduplicate against each other. No deduplication across tenants (by design, for isolation).
3. **Pull model.** The appliance initiates every connection. No source ever connects to the appliance. The appliance can therefore be operated fully encapsulated behind a default-deny firewall with a single inbound port (management UI/API).
4. **Hardened by default.** Image-based OS, SELinux enforcing, full-disk encryption bound to TPM and Secure Boot, no interactive root, retention locks that nobody can shorten, four-eyes principle for destructive actions.
5. **Policy-driven, not job-driven.** Protection groups receive an SLA policy (frequency, retention, offsite). Admins define the goal, not individual runs.
6. **Self-describing offsite copies.** Every offsite copy can be restored with nothing but the storage credentials and the recovery key — without the original appliance.
7. **Single language in the core.** Rust for data plane and control plane.
8. **No code or components originating from Veeam.** (Explicit project constraint; e.g. no blksnap-based snapshotting.)

### 1.2 Non-goals (initial scope)

- Scale-out / multi-node clustering (design for it, do not build it in phase 1).
- Windows block-level CBT (file-level with VSS + USN journal only).
- NAS block-level or snapshot-based backup (file-level only).
- S3/object storage as offsite tier (Hetzner Storage Box first; S3 is a later backend implementation).
- Microsoft 365 (last phase, see roadmap).
- Long-term legal archiving (GoBD / HGB / AO retention of up to 10 years is the job of an archive/DMS, not of the backup system; this must be communicated to customers).

---

## 2. Key Decisions and Rationale

| Decision | Choice | Rationale |
|---|---|---|
| Storage engine | **Own chunk store in Rust** | Borg was evaluated and rejected: client-only CLI tool, no server component or API, single-writer repository locking, Borg 2.0 still in beta (2.0.0b23, Aug 2026) with a format incompatible to 1.x. Teaching Borg dirty bitmaps would effectively mean re-implementing the PBS fixed index. |
| Language | **Rust** (data plane and control plane) | Memory safety without GC pauses, C-level throughput for hashing/compression/encryption, mature crates (`tokio`, `blake3`, `zstd`, `fastcdc`, RustCrypto/`ring`, `axum`). Proven for this exact task by Proxmox Backup Server. Trade-offs: compile times, smaller hiring pool. |
| Direction of connections | **Pull** (appliance → sources) | Sources never hold credentials to the appliance. A compromised hypervisor or server cannot reach the backups. |
| Reference model | **Cohesity** | Single storage for all workloads, snapshot-based forever-full, SLA policies, instant mount, quorum for destructive actions. |
| MAC system | **SELinux** (not AppArmor) | Type enforcement confines every service into its own domain; root processes are still restricted by policy. AppArmor is path-based and easier to bypass. |
| Base OS | **Image-based RHEL clone with bootc** (AlmaLinux / CentOS Stream) | Signed container image, read-only `/usr`, atomic A/B updates, automatic rollback. |
| Offsite tier (phase 1) | **Hetzner Storage Box, one box per tenant** | Cheap, EU-located, SFTP/rsync, automated snapshots. Per-tenant box solves the 10-connection limit, improves isolation, enables per-customer billing. |
| Offsite retention | **Identical to local retention** | Customer requirement; the same restore points must be available offsite. |
| Catalog database | **SQLite (WAL mode)** | Single-node appliance; robust, serverless, trivially backed up. |
| Garbage collection | **Mark-and-sweep** (not reference counting) | Reference counters corrupt easily on crashes; a wrong counter means data loss. |
| VM chunking | **Fixed-size chunks aligned to dirty bitmaps** | Maps dirty-bitmap regions directly to chunks; enables random access for instant recovery and single-file restore. |
| File chunking | **Content-defined chunking (FastCDC)** | Insert/shift-resistant deduplication for file data. |
| Chunk identifiers | **Keyed hash (BLAKE3 keyed mode, per-tenant key)** | Prevents the storage provider from confirming the presence of known files (fingerprinting attacks). Implies no cross-tenant dedup. |
| Encryption | **AEAD per chunk: XChaCha20-Poly1305** (decided 2026-10-08), envelope key model | Per-tenant DEK wrapped by a KEK held in the TPM and escrowed as an offline recovery key. 192-bit random nonces have no practical collision risk at billions of chunks (AES-GCM's 96-bit nonce would limit chunks per key); fast without AES-NI; pure Rust (RustCrypto). |
| Data path order | **Dedup → compress → encrypt** | Any other order destroys deduplication. |
| License | **AGPL-3.0** (decided 2026-10-08) | Allows reuse of AGPL Proxmox / PBS crates; network clause fits an appliance that may be offered as a service. |
| VCS / CI | **git + GitHub Actions** (decided 2026-10-08) | CI runs fmt, clippy, tests and cargo-audit. |

---

## 3. Requirements

### 3.1 Functional

- **Sources (phase order):** Proxmox VE (VMs and LXC), TrueNAS Community (ZFS snapshots), Linux physical servers (agent), NAS shares via NFS/SMB (file-level), Windows physical servers (agent, VSS, file-level), Microsoft 365 (last).
- **Backup modes:** incremental-forever with full logical snapshots; VM backups use dirty bitmaps; file backups use change detection (ZFS diff, btrfs find-new, NTFS/ReFS USN journal, metadata cache for NAS).
- **Restore modes:** full VM/host restore, single-file restore from VM images and from file backups, instant recovery (VM boots directly from the backup over NBD), restore directly from the offsite tier, disaster-recovery restore without the original appliance.
- **Retention (GFS):** 14 daily, 4 weekly, 6 monthly, 2 yearly; period-based semantics ("last backup of each of the last N periods that have backups"); identical retention local and offsite; configurable per policy and per target.
- **Multi-tenancy:** up to 5 tenants per appliance initially; cryptographic separation per tenant; tenant-scoped RBAC.
- **Offsite:** encrypted, deduplicated, incremental upload of pack files to one Hetzner Storage Box per tenant; bandwidth limits and schedules; resumable uploads; independent verification; offsite inventory monitoring.
- **Replication to a second appliance (later):** the secondary appliance pulls from the primary; the primary holds no credentials for the secondary.

### 3.2 Non-functional

- Data set: 5 tenants × 1–2 TB raw (5–10 TB total), growing.
- Daily backup window must comfortably hold the daily delta (~2 % change rate assumed; measure in production).
- Throughput target: initial full of 10 TB within one weekend on local network; daily increments of 100–200 GB raw within a few hours.
- Steady-state capacity after two years (full GFS retention): ~18–20 TB for 10 TB raw → appliance sized for ~40 TB usable.
- Appliance must survive a single disk failure in any tier without data loss (RAID6 / RAIDZ2 for data, mirrors for metadata and OS).

### 3.3 Security

- Only one inbound port (management UI/API). Everything else outbound, allow-listed per configured source/target.
- Full-disk encryption, TPM-sealed, Secure Boot measured.
- Retention locks enforced in the storage layer; locks can only be extended, never shortened.
- Tamper-resistant compliance clock, independent from system time.
- Four-eyes (quorum) approval for destructive or weakening actions.
- Hash-chained audit log, forwarded to an external syslog/SIEM.
- MFA (WebAuthn or TOTP) for all interactive accounts; OIDC later.
- No interactive root; emergency access only via local console.
- Least-privilege credentials for every source (scoped PVE API tokens, SSH keys with `restrict`, forced commands, `permitopen`).

---

## 4. System Architecture

### 4.1 Component overview

The appliance consists of three layers. Every box runs as its own OS process with its own system user and its own SELinux domain, sandboxed by systemd.

**Control plane**
- `web-api` — Web UI and REST API (`axum`), authentication, RBAC, quorum workflows.
- `scheduler` — policy engine, job scheduling, retention computation, protection groups.
- `catalog` — SQLite catalog (sources, policies, snapshots, jobs, users), audit log writer, metrics endpoint.

**Data plane**
- `connectors` — one worker type per source class: Proxmox, Linux agent, Windows agent, NAS, TrueNAS, (M365 later).
- `chunkstore` — dedup index, chunk storage, compression, encryption, verify, garbage collection, retention locks, compliance clock.
- `offsite` — pack builder and uploader (SFTP to Storage Box), offsite inventory, offsite verification.
- `restore` — NBD server for instant recovery, file-level restore service, restore micro-VM for single-file restore from images.

**Base**
- `keyd` — the only process talking to the TPM; unwraps tenant keys and hands them to `chunkstore` over a local Unix socket; keys exist only in memory.
- OS — bootc image, SELinux enforcing, LUKS2, nftables, chrony with NTS.

### 4.2 Process isolation rules

- `web-api` never touches chunks or keys; it only calls `scheduler`/`catalog`/`restore` over local sockets.
- `connectors` have no key material; they hand plaintext data to `chunkstore` over a local socket (or run chunking themselves and submit chunks + IDs).
- `chunkstore` is the only process with tenant DEKs in memory.
- `offsite` only ever sees encrypted packs and encrypted indexes.
- `keyd` is the only process with TPM access.
- Every service: dedicated user, `ProtectSystem=strict`, `NoNewPrivileges=yes`, `SystemCallFilter`, private `/tmp`, own network namespace where possible, SELinux domain with explicit transitions only.

### 4.3 Storage abstraction (Rust traits)

```text
trait ChunkBackend  // local: one file per chunk (fast random access, simple GC)
trait PackBackend   // remote: chunks packed into 32–64 MiB pack files
                    // implementations: StorageBoxSftp (phase 1), S3 (later), Tape (later)
```

The local chunk store and the remote pack store share the same chunk IDs, encryption and index formats. Only the physical layout differs.

---

## 5. Chunk Store Design

### 5.1 Data path

```text
source bytes → chunking → keyed hash (chunk ID) → dedup lookup
            → [new chunk] compress (zstd) → encrypt (AEAD) → write
            → append chunk ID to snapshot index
```

### 5.2 Chunking

| Data type | Method | Default parameters | Notes |
|---|---|---|---|
| VM disks / block devices | Fixed-size, offset-aligned | 4 MiB (evaluate 1 MiB) | Aligns with QEMU dirty bitmaps; VMs from the same template dedup well because blocks are aligned. |
| Files (agents, NAS, TrueNAS) | FastCDC | avg 512 KiB, min 128 KiB, max 4 MiB | Content-defined boundaries survive inserts/shifts. Very small files = one chunk each. |

Chunk sizes are configurable per datastore. At this project's scale (~10 M chunks) the dedup index is tiny (~0.5 GB), so chunk sizes can be chosen for dedup quality rather than RAM.

Known limitation: the same file inside a VM image and in a file-level backup does not dedup against each other (different chunk boundaries). Accepted; common to all systems of this design.

### 5.3 Index structures

- **Dedup index:** chunk ID → location (local path / pack + offset), uncompressed size, compressed size. Held on NVMe; Bloom filter in RAM answers "is this chunk new?" without disk access.
- **Fixed index:** ordered list of chunk IDs for a block device; chunk N covers offset `N × chunk_size`. Enables O(1) offset lookup for NBD/instant recovery.
- **Dynamic index:** stream of (path, metadata, chunk list) entries for file trees. Includes a metadata cache (path, size, mtime, inode → chunk list) so unchanged files are never re-read on the next run.
- **Snapshot manifest:** tenant, source, type, timestamp, index references, retention classification (daily/weekly/monthly/yearly flags), lock-until timestamp, offsite status, verify status.

All indexes are encrypted with the tenant DEK before being written to disk or offsite.

### 5.4 Garbage collection (mark-and-sweep)

1. Walk every snapshot manifest and index that is still retained → mark referenced chunk IDs (snapshots under retention lock are always marked).
2. Chunks not marked are candidates; they are deleted only after a **grace period** (e.g. 24 h) so that running backups which already referenced a chunk but have not yet committed their index cannot lose it.
3. GC runs are logged and metered; a GC that would delete more than a configurable share of the store requires quorum approval (safety valve against catastrophic policy errors).

Offsite GC: whole packs are deleted when all chunks are dead; partially dead packs are re-packed only above a threshold (e.g. 50 % dead). Packs are grouped at upload time by protection group and retention class so they tend to expire together. Yearly snapshots pin chunks for two years, so occasional repacking is unavoidable — acceptable on a Storage Box (no egress cost, only time and connections).

### 5.5 Retention locks and compliance clock

- Every snapshot receives a lock on creation for at least the minimum retention (14 days).
- When the retention engine classifies a snapshot as weekly/monthly/yearly, its lock is **extended** accordingly (4 weeks / 6 months / 2 years).
- Locks can only be extended. Shortening or deleting a locked snapshot is impossible through any API, including for administrators.
- The chunk store maintains its own **compliance clock** based on a monotonic clock, persisted frequently; it accepts only small corrections from system time. A manipulated NTP server or `date` command cannot expire locks early.
- Local and offsite enforce locks independently.

### 5.6 Verification

- Every chunk carries its own authenticated tag (AEAD) and keyed hash; reads always verify.
- Scheduled verify jobs re-read a configurable fraction of chunks per week (full verification over N weeks).
- Offsite: sampled verification (download random packs, decrypt, verify hashes) to detect bit rot, misconfiguration and key problems early.

---

## 6. Encryption and Key Management

### 6.1 Envelope model

```text
Recovery key (offline, paper/HSM/external KMS)
        │ wraps
Appliance KEK (sealed in TPM, bound to Secure Boot + image measurement)
        │ wraps
Tenant DEK (one per tenant; used for chunk ID keying, chunk AEAD, index encryption)
```

- Chunk IDs: BLAKE3 keyed hash with a tenant-specific key derived from the DEK.
- Chunk payload: XChaCha20-Poly1305, random 192-bit nonce per chunk, chunk ID and tenant ID as associated data.
- Indexes, manifests and the catalog copy for offsite: encrypted with the tenant DEK.
- Hetzner (or any storage provider) sees neither content nor meaningful file names.

### 6.2 Key lifecycle

- Recovery key is generated during first boot, shown exactly once, and the wizard requires partial re-entry to prove it was recorded.
- Tenant DEKs can be rotated (new chunks use the new key; old chunks remain readable via key versioning in the manifest).
- Loss scenario: new hardware + recovery key + offsite credentials = full restore. This path is tested as part of DR drills.

---

## 7. Source Connectors

### 7.1 Proxmox VE (first source)

**Integration basis:** the official Proxmox VE Backup Provider API (available since PVE 8.4). Proxmox ships an example Borg provider plugin (`src/PVE/BackupProvider/Plugin/Borg.pm` in `pve-storage`) that serves as a developer guideline — it is explicitly not supported for production but documents the API end to end. A backup provider consists of two parts:

1. A **storage plugin** (`PVE::Storage::Custom::*`, Perl) for front-end integration (storage.cfg config, listing/deleting backups via UI/API/CLI, feature flag "has backup provider", `APIVERSION`/`APIAGE`).
2. A **backup provider plugin** (`PVE::BackupProvider::Plugin::Base`) with separate hooks for VMs and containers for backup and restore. API docs live as POD inside `Base.pm`.

**Inverting the push API into a pull flow (all connections originate from the appliance):**

1. Appliance calls the PVE API (port 8006) with a least-privilege token (`VM.Backup`, `VM.Audit` on the required paths) to start the backup job for the provider storage.
2. The on-node plugin makes **no outbound connections**. It lets PVE prepare the snapshot and the NBD export (with dirty bitmap information) and then waits.
3. The appliance opens an SSH tunnel to the node (`ssh -L` to the local NBD Unix socket) and reads only the dirty blocks, building the new fixed index.
4. Plugin signals completion; PVE finalizes the job and keeps the task log.

Dirty bitmaps are managed by PVE; the appliance only consumes them. Note: bitmaps are lost on VM/host restart; the next backup then reads the full disk but still transfers only changed chunks.

**SSH hardening on nodes:** dedicated user, key restricted in `authorized_keys` with `restrict`, forced command, `permitopen` limited to the NBD sockets.

**Instant recovery:** appliance opens an SSH **reverse** tunnel (`ssh -R`) exposing its NBD server as a local socket on the node; the VM starts from that disk, data is migrated to PVE storage in the background. Direction of the TCP connection remains appliance → node.

**Containers (LXC):** file-level via the provider API directory mechanism, chunked with FastCDC.

**Deliverable:** `.deb` package for the on-node plugin; supports PVE 8.4+ and 9.x.

### 7.2 Linux agent (physical servers)

- Static Rust binary (musl target), one binary for all distributions.
- Listens on a port; accepts **only mTLS** connections presenting the appliance certificate. Never connects out.
- Snapshot providers: LVM thin/thick, ZFS, btrfs. Change detection: `zfs diff`, `btrfs subvolume find-new`; otherwise metadata cache.
- **Fallback without snapshot capability** (plain ext4/XFS on a partition): read files live, flag files that changed during read as "inconsistent", run database dump hooks (PostgreSQL, MySQL/MariaDB, etc.). Snapshot status is shown prominently in the UI per host.
- Chunking runs **on the agent**: the appliance connects, the agent reports chunk IDs, the appliance requests only the missing chunks (bandwidth-efficient for remote sites).
- Agent is remotely updateable from the appliance (signed binaries).

### 7.3 Windows agent (physical servers)

- Rust, cross-compiled; VSS via COM (`windows` crate). File-level only; no CBT driver.
- Change detection via **NTFS/ReFS USN journal** (built into the file system, no driver).
- Application consistency via VSS writers (SQL Server, Exchange, AD) — otherwise databases are only crash-consistent; the UI must show which writers participated.
- Minimum supported version: **Windows Server 2016** (2012 R2 out of support since Oct 2023). Supported: 2016/2019/2022/2025.
- Same mTLS listen model and agent-side chunking as Linux.

### 7.4 NAS (NFS / SMB shares)

- Appliance mounts shares read-only (kernel NFS/CIFS client) and scans them.
- Metadata cache (path, size, mtime, inode → chunk list) so unchanged files are never re-read.
- Parallelized scan is critical for shares with millions of files.
- No consistent point-in-time without NAS-side snapshots; documented limitation.

### 7.5 TrueNAS Community (ZFS)

- Appliance creates a ZFS snapshot via the TrueNAS API, determines changes against the previous snapshot, reads changed files from a read-only share on `.zfs/snapshot/…` or over a restricted SSH user.
- The last backed-up snapshot is kept on TrueNAS as reference for the next run.
- `zfs send` streams were considered and rejected (poor fit with dedup and forever-full).

### 7.6 Microsoft 365 (last phase)

- Graph API; separate data models for Exchange, SharePoint, OneDrive, Teams; throttling handling. Planned as its own project phase after everything else is stable.

---

## 8. Restore

| Mode | Mechanism |
|---|---|
| Full VM restore | Write disks back over SSH tunnel + NBD or via the provider API restore hooks. |
| Instant recovery | Reverse SSH tunnel exposes appliance NBD server on the node; VM boots immediately; background migration to PVE storage. Optional NVMe cache tier on the appliance for acceptable latency. |
| Single-file restore from VM images | Image is exposed as a virtual block device from the fixed index and mounted inside a small, isolated **restore micro-VM** on the appliance (drivers for NTFS, ext4, XFS, LVM, ZFS). Foreign file systems are never mounted on the appliance host itself. |
| File-level restore | Directly from dynamic indexes; to original host via agent, to NAS, or as download. |
| Restore from offsite | SFTP range reads into pack files; only required chunks are fetched. |
| Disaster recovery | Fresh appliance (or CLI tool) + recovery key + Storage Box credentials rebuilds catalog, indexes and data for a tenant. |

---

## 9. Offsite Tier — Hetzner Storage Box

### 9.1 Facts that drive the design

- Protocols: FTP(S), SFTP, SCP, Samba/CIFS, WebDAV, rsync over SSH, BorgBackup.
- **10 concurrent connections per box**, 100 sub-accounts, 30–40 snapshots depending on size (automated snapshots available).
- Largest standard plan BX41 = 20 TB; smaller plans 1/5/10 TB; upgrade/downgrade without data loss.
- No object lock; no server-side processes.

### 9.2 Design

- **One Storage Box per tenant.** Independent connection limits, isolation, per-tenant snapshots, per-customer billing, independent sizing (1 TB raw → ~2 TB stored → 5 TB box; 2 TB raw → ~4 TB stored → 10 TB box). The appliance warns at 75 % usage.
- **Pack files** of 32–64 MiB with a pack index; uploaded over ~4 parallel SFTP connections (reserve connections for restore/verify). Packs grouped by protection group and retention class.
- **Appliance-side intelligence.** The box is "dumb": the appliance keeps a local inventory of what is offsite and performs dedup decisions itself, but also stores encrypted indexes, manifests and a catalog copy on the box so the copy is self-describing.
- **Append-only behaviour.** The appliance never overwrites existing files; deletions happen only through delayed GC.
- **Box snapshots as the immutability layer.** Automated snapshots are configured in the Hetzner console — the appliance has no Hetzner API credentials and therefore cannot delete them. Suggested schedule: 14 daily + 4 weekly (18 snapshots). This yields roughly six weeks to detect an attack on the offsite copy before deleted data becomes unrecoverable. Snapshot overhead ≈ 5–10 % per tenant (data deleted by GC stays allocated until snapshots expire; bursts after repacking).
- **Independent offsite monitoring.** The appliance regularly compares box contents with the expected catalog and alerts immediately (email + webhook, external channel) when packs or snapshots disappear unexpectedly.
- **Retention is computed independently** on both sides from snapshot timestamps with the same policy. Local deletions are never blindly propagated; locks apply separately.
- **Snapshot status in the UI:** a snapshot is "fully protected" only when it is present and verified both locally and offsite.
- **Initial seeding plan:** 6 TB take ~14 h at 1 Gbit/s, ~1 week at 100 Mbit/s; seed tenants sequentially so each reaches a complete offsite copy quickly; afterwards daily uploads are ~60–120 GB.
- **Migration between boxes** is supported: copy packs, verify, switch.

### 9.3 Later backends

S3-compatible object storage (Object Lock compliance mode, separate account, write-only credentials, hot tier for indexes + cold tier for packs) and a second appliance (pull-based replication) are additional `PackBackend` implementations; the pack format does not change.

---

## 10. Retention and Policy Engine

- **Policy model:** protection group → policy {schedule, retention per target, offsite targets, bandwidth window}. Retention is configurable separately per target even though the initial requirement is identical retention.
- **GFS schema:** 14 daily, 4 weekly, 6 monthly, 2 yearly.
- **Semantics:** period-based, as in PBS / `borg prune`: "14 daily" keeps the last backup of each of the last 14 days *that have a backup*. A snapshot may be daily, weekly, monthly and yearly at once; the union is kept. If backups stop for weeks, old restore points are not silently pruned.
- **Lock lifecycle:** minimum lock 14 days; extended automatically on classification; never shortened.

### 10.1 Capacity model (assumptions: ~2 % daily change, dedup + compression ≈ 0.6× of raw)

| Component | 5 TB raw | 10 TB raw |
|---|---|---|
| Base (first full, dedup + compressed) | ~3 TB | ~6 TB |
| 14 daily | ~0.8 TB | ~1.7 TB |
| 4 weekly | ~0.8 TB | ~1.6 TB |
| 6 monthly | ~2.5–3 TB | ~5–6 TB |
| 2 yearly | ~2–2.5 TB | ~4–5 TB |
| **Steady state (reached after 2 years)** | **~9–10 TB** | **~18–20 TB** |

Monthly and yearly restore points dominate capacity. Real change rates must be measured in the first months and the model corrected.

---

## 11. Control Plane

### 11.1 API and UI

- REST API with `axum`; the Web UI consumes the same API (everything the UI can do is scriptable).
- Authentication: local accounts with WebAuthn or TOTP; OIDC later.
- Session hardening, rate limiting, CSRF protection, strict CSP.

### 11.2 Roles (initial RBAC)

| Role | Capabilities |
|---|---|
| Administrator | Configure appliance, sources, policies; cannot shorten retention or delete locked snapshots. |
| Security Officer | Approves quorum actions; manages recovery keys and lock policies. |
| Operator | Runs backups and restores. |
| Tenant User | Sees only own tenant; can trigger restores (optional customer self-service). |

**Quorum:** shortening retention, deleting protection groups, mass-deleting snapshots, disabling offsite, large GC runs require approval by a second role (Security Officer).

### 11.3 Catalog, audit, monitoring

- Catalog: SQLite (WAL) — sources, policies, snapshots, jobs, users, offsite inventory. Encrypted copy written to each tenant's Storage Box after every run.
- Audit log: hash-chained entries (each entry includes the hash of the previous one); forwarded via syslog/TLS to an external SIEM.
- Monitoring: Prometheus `/metrics`; alerts by email and webhook for failed jobs, lagging offsite copies, capacity thresholds, verify failures, offsite inventory anomalies, clock anomalies, failed login bursts.

---

## 12. Appliance OS, Hardening and Hardware

### 12.1 OS image

- bootc-based image from AlmaLinux / CentOS Stream; built in CI as a signed OCI image; read-only `/usr`; A/B updates with health-check-gated automatic rollback (greenboot-style).
- SELinux enforcing with a project-specific policy module; every service in its own domain.
- systemd sandboxing for every unit (see 4.2).
- No interactive root; emergency access via local console only; SSH server disabled by default (optional, key-only, management interface only, break-glass with quorum).
- chrony with NTS; compliance clock in `chunkstore`.
- nftables default deny inbound (except management port) and default deny outbound (except allow-listed sources and offsite targets; rules generated automatically when sources are configured).

### 12.2 Disk layout and encryption

| Tier | Devices | Purpose |
|---|---|---|
| System | 2× small SSD, mirror | bootc image, A/B slots |
| Metadata | 2× NVMe, mirror | dedup index, snapshot indexes, catalog, Bloom filter persistence |
| Data | 6–8× HDD, RAID6 / RAIDZ2 | chunks (one file per chunk) |
| Optional | NVMe | instant-recovery cache |

All tiers LUKS2-encrypted; unlocked via TPM 2.0 bound to Secure Boot state and image measurement; recovery passphrase escrowed offline. File system for the data tier: XFS on mdraid preferred (chunk store already checksums everything; ZFS is CoW-on-CoW), decided by performance tests.

### 12.3 Hardware sizing (5 tenants, 5–10 TB raw, full GFS)

- CPU: 8–16 cores.
- RAM: 32–64 GB.
- Metadata: 2× NVMe (≥ 1 TB) mirror.
- Data: 6× 12 TB in RAID6 ≈ 48 TB nominal, ~40 TB usable → ~30–40 % headroom over the 2-year steady state.
- Network: separate NICs for management, backup and offsite (at least two, ideally three).
- TPM 2.0, Secure Boot capable firmware.

### 12.4 Networking

| Interface | Direction | Purpose |
|---|---|---|
| Management | inbound (only port) | Web UI / API |
| Backup | outbound only | PVE API 8006 + SSH 22, agents (mTLS port), NFS/SMB mounts, TrueNAS API/SSH |
| Offsite | outbound only | SFTP to Storage Boxes |

### 12.5 First boot

Console TUI wizard: network → admin account + MFA → recovery key (shown once, partial re-entry required) → disk initialization → Web UI becomes reachable.

---

## 13. Security Considerations of the Pull Model

The appliance holds credentials to every source and therefore becomes a **tier-0 asset**. A compromised source cannot reach the backups, but a compromised appliance could reach the entire infrastructure. Mitigations are part of the concept, not optional:

- Least privilege per source (scoped PVE tokens, SSH `restrict` + forced command + `permitopen`, mTLS client certs for agents, read-only NAS mounts, restricted TrueNAS user).
- Strictly separated management network, MFA, no root, quorum, hash-chained audit log, external alerting.
- Agents accept connections only from the appliance certificate; agents expose no data-modifying operations beyond restore-to-path with explicit confirmation.

---

## 14. Testing Strategy

- **Unit and property tests** for chunking (boundary stability under inserts/shifts), index formats, GC marking, lock logic, compliance clock.
- **Crash-consistency tests** for the chunk store (kill -9 / power-loss simulation during write, index commit, GC).
- **Integration lab:** a Proxmox cluster running the test matrix as VMs, backed up by a test appliance (exercises the PVE integration at the same time).
- **Test matrix:** Windows Server 2016/2019/2022/2025; Debian, Ubuntu LTS, RHEL clones — each with and without LVM/ZFS/btrfs; PVE 8.4 and 9.x; TrueNAS Community current release; NFS and SMB shares with millions of small files.
- **Restore drills:** full VM, instant recovery, single-file from NTFS/ext4/XFS/LVM images, file-level to host, restore from offsite, **DR restore on fresh hardware with recovery key only**.
- **Security tests:** SELinux policy coverage (audit2allow review, no permissive domains), systemd sandbox audit, external penetration test before first production tenant, fuzzing of network-facing parsers (agent protocol, NBD, SFTP client).
- **Performance tests:** initial full of 10 TB, daily deltas, GC runtime, instant-recovery latency with and without NVMe cache, offsite upload with 4 connections.

---

## 15. Roadmap and Milestones

Order is driven by dependencies: the chunk store first, then the key model (hard to change later), then the first real source.

**Current development scope (decided 2026-10-08):** Phase 0 (repository, CI, ADRs, threat model) plus the Phase 1 chunk store core, working toward milestone M1.

### Phase 0 — Foundations (weeks 1–4)
- Repository structure, CI (Rust toolchain, clippy, cargo-audit, image build pipeline).
- Architecture decision records for the decisions in section 2.
- Threat model document.
- OS image skeleton (bootc, SELinux enforcing with permissive-free baseline, LUKS/TPM enrolment) can start in parallel.

### Phase 1 — Chunk store and key service (months 2–4)
- On-disk chunk format, dedup index + Bloom filter, fixed and dynamic indexes, manifests.
- Compression and AEAD pipeline; keyed chunk IDs.
- `keyd` with TPM sealing, recovery key, tenant DEKs, key versioning.
- Mark-and-sweep GC with grace period; retention locks; compliance clock.
- Verify jobs. Crash-consistency test suite.
- **Milestone M1:** chunk store ingests and restores synthetic block and file data with dedup, encryption, GC and locks, surviving crash tests.

### Phase 2 — Proxmox connector (months 4–7)
- On-node storage + backup provider plugin (Perl, `.deb` package).
- Pull orchestration: PVE API job trigger, SSH tunnel to NBD socket, dirty-bitmap consumption into fixed index; LXC file-level backup.
- Full VM restore.
- **Milestone M2:** scheduled, incremental-forever backups of a PVE cluster with full restore.

### Phase 3 — Restore features (months 7–9)
- NBD server, instant recovery via reverse SSH tunnel, background migration.
- Restore micro-VM for single-file restore from images (NTFS/ext4/XFS/LVM/ZFS).
- File-level restore service.
- **Milestone M3:** instant recovery and single-file restore demonstrated on the test matrix.

### Phase 4 — Offsite (months 9–11)
- Pack format and pack index; `PackBackend` trait; Storage Box SFTP implementation.
- Per-tenant box mapping, upload scheduler with connection budget, bandwidth windows, resumable uploads.
- Offsite inventory, sampled verification, inventory anomaly alerting, independent retention/lock enforcement, restore-from-offsite.
- DR tool: rebuild tenant from box + recovery key.
- **Milestone M4:** every snapshot shows local ✓ / offsite ✓; DR drill from a Storage Box succeeds on fresh hardware.

### Phase 5 — Control plane and UI (months 10–13, overlaps phase 4)
- REST API, Web UI, MFA, RBAC, quorum workflows.
- Policy engine with GFS retention and per-target retention.
- Catalog, hash-chained audit log, syslog forwarding, Prometheus metrics, alerting.
- First-boot TUI wizard.
- **Milestone M5:** appliance operable end to end without shell access.

### Phase 6 — Hardened appliance release (months 12–14)
- Final SELinux policy, systemd sandboxing audit, nftables automation, A/B update channel with rollback, signed releases.
- External penetration test; fixes.
- **Milestone M6:** "1.0" appliance image; first production tenant on Proxmox.

### Phase 7 — Additional sources (months 14–20)
- TrueNAS connector (ZFS snapshots).
- Linux agent (LVM/ZFS/btrfs snapshots, fallback mode, DB hooks, agent-side chunking, remote update).
- NAS connector (NFS/SMB file-level, metadata cache, parallel scan).
- Windows agent (VSS, USN journal, VSS writers; Server 2016+).
- **Milestone M7:** all phase-1 source classes supported with the full test matrix passing.

### Phase 8 — Replication and S3 (months 20–24)
- Second-appliance pull replication.
- S3 `PackBackend` with Object Lock, hot/cold tiering.
- Scale-out groundwork (no multi-node yet).

### Phase 9 — Microsoft 365 (after phase 8)
- Separate project: Graph API connectors for Exchange, SharePoint, OneDrive, Teams.

Timelines assume a small dedicated team (2–4 engineers); adjust to actual staffing.

---

## 16. Risks and Open Questions

| Risk / question | Impact | Mitigation / decision needed |
|---|---|---|
| Proxmox Backup Provider API changes between PVE releases | Connector breakage | Track `pve-devel`; pin `APIVERSION`/`APIAGE`; integration tests against PVE 8.4 and 9.x. |
| Dirty bitmap loss after VM/host restart | Full re-read (not full transfer) | Document; monitor backup duration; nothing further needed. |
| Linux hosts without snapshot capability | Inconsistent file backups | Fallback mode with explicit UI status; DB dump hooks; recommend LVM for new installs. |
| Windows application consistency | Crash-consistent DBs if writers are missing | VSS writer participation shown per job; alerts if expected writers are absent. |
| Storage Box has no object lock | Offsite copy deletable by a compromised appliance | Box snapshots managed outside the appliance; inventory monitoring; ~6-week detection window; consider S3 Object Lock as second offsite later. |
| Yearly snapshots pin chunks inside offsite packs | Repacking cost | Retention-class pack grouping; repack threshold; acceptable on Storage Box. |
| Capacity model uncertainty (change rate) | Under-sized appliance or boxes | Measure in first months; 30–40 % headroom; boxes resizable without data loss. |
| Rust hiring pool | Staffing | Keep core small; clear module boundaries; good documentation. |
| Team size and licensing model (AGPL vs. others, commercial support?) | Affects reuse of AGPL code (e.g. PBS crates) and go-to-market | **Decided 2026-10-08: AGPL-3.0.** Commercial support model and team size still open. |
| Instant-recovery latency on HDD tier | Poor user experience | Optional NVMe cache tier; measure in phase 3. |
| Catalog growth with millions of NAS files | SQLite performance | Keep file metadata in dynamic indexes, not in the catalog; catalog stores only snapshots/jobs. |
| Legal retention expectations (GoBD/HGB) | Customer misunderstanding | Document clearly that backup ≠ archive. |

---

## 17. Glossary

- **Chunk:** unit of deduplication; identified by a keyed BLAKE3 hash.
- **Fixed index:** chunk list for a block device at fixed offsets.
- **Dynamic index:** chunk lists for a file tree with metadata.
- **Pack:** 32–64 MiB container of encrypted chunks used on remote storage.
- **DEK / KEK:** data-encryption key (per tenant) / key-encryption key (appliance, TPM-sealed).
- **GFS:** grandfather-father-son retention (daily/weekly/monthly/yearly).
- **Retention lock:** storage-layer guarantee that a snapshot cannot be deleted before a given time.
- **Compliance clock:** tamper-resistant clock used solely for retention locks.
- **Quorum:** second-person approval for destructive or weakening actions.
- **Pull model:** the appliance initiates all network connections to sources and targets.