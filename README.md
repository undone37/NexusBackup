# NexusBackup Appliance

An open-source (AGPL-3.0) enterprise backup appliance in the spirit of Cohesity: a hardened, self-contained
appliance that **pulls** data from all sources, stores everything as **deduplicated, encrypted forever-full
snapshots**, and keeps **immutable copies offsite** — restorable with nothing but the offsite credentials and an
offline recovery key.

> **Status: lab-proven, not production-ready.** All features below run end to end in a nested lab (nested
> Proxmox VE, Linux VMs, TrueNAS, NFS/SMB, MinIO, two appliance VMs) with SELinux enforcing. Real hardware,
> scale/soak tests, a real Hetzner Storage Box run, the external penetration test, TPM/LUKS disk encryption and
> the release key ceremony are still open. See [`state.md`](state.md) for the exact state and the list of
> production gaps.

## Highlights
- **Forever-full, deduplicated, encrypted**: content-defined chunking (FastCDC) for files, fixed chunks aligned to
  dirty bitmaps for disks; keyed BLAKE3 chunk IDs per tenant; zstd + XChaCha20-Poly1305 per chunk; global dedup
  per tenant, no cross-tenant dedup (isolation).
- **Pull model**: the appliance initiates every connection; sources hold no credentials for it. One inbound port
  (8443, management UI/API); outbound traffic is default-deny with an automatically maintained allow-list.
- **Immutability**: retention locks that can only be extended, a tamper-resistant compliance clock, four-eyes
  (quorum) approval for destructive or weakening actions, a hash-chained audit log, S3 Object Lock offsite.
- **Hardened image**: bootc (AlmaLinux 10) A/B updates signed with cosign (offline key) and health-checked rollback
  (greenboot); every service in its own user, systemd sandbox and SELinux domain.

## Supported sources and restores
| Source | How | Restore |
|---|---|---|
| Proxmox VE 9.x VMs | PVE backup-provider plugin; NBD over a restricted SSH forced command; dirty-bitmap incrementals | full VM restore, **instant recovery** (boot from backup, live disk move), single-file restore via an isolated restore micro-VM |
| Proxmox VE containers | tar stream from the CT's user namespace, chunked on the appliance | full CT restore, file download |
| Linux hosts | `nexus-agent` (static musl binary): LVM thin/thick, ZFS, btrfs snapshots or flagged live read; source-side dedup; LZ4 on the wire; DB dump hooks | restore to path, tar/zip download |
| Windows Server 2016+ | `nexus-agent.exe`: VSS (copy-only) + USN journal *(built and unit-tested only, never run on Windows)* | restore to path, tar/zip download |
| TrueNAS Community (SCALE) | JSON-RPC API snapshots + `zfs diff`, changed files over a restricted SSH user | tar/zip download |
| PostgreSQL 14+ (plugin) | pure-Rust wire protocol: logical dump per database; base backup + WAL for point-in-time restore | restore to the source or an alternate server, PITR data directory over SSH, download |
| Microsoft 365 (plugin) | Microsoft Graph with an Entra app certificate: mailboxes (mail, calendar, contacts), OneDrive, SharePoint libraries, Teams | download, restore to the original or another user/site/team (new folder, never overwrite) |
| NFS / SMB shares | read-only kernel mounts via a detached-mount helper (CAP_SYS_ADMIN only), parallel scan | tar/zip download |

Offsite tiers: **Hetzner Storage Box (SFTP)** and **S3 with Object Lock** (own SigV4 client). Replication to a
**second appliance** (pull-based, mTLS on 8443). Disaster recovery on fresh hardware from the offsite copy plus the
recovery key.

## Architecture
```text
                  Web UI (Svelte SPA) ── REST API: nexus-web-api (axum, TLS 1.3, TOTP, RBAC, quorum)
                                             │ intent                       │ /replication/v1 (mTLS)
                                       catalog (SQLite WAL)            nexus-replicad (read-only)
                                             │
 sources ◄── pull ── nexus-scheduler ── spawns connectors: nexus-pve · nexus-agentctl · nexus-truenas · nexus-nas
                         │                                   nexus-offsite · nexus-replica
                         ├── chunk store (dedup → zstd → XChaCha20-Poly1305, locks, GC, verify)
                         └── keyd (KEK, tenant DEKs; recovery-key escrow; TPM later)
```
Details: [`plan.md`](plan.md) (vision, requirements, roadmap, decisions), [`docs/`](docs) (contracts and
designs), [`docs/adr.md`](docs/adr.md) (architecture decisions), [`docs/threat-model.md`](docs/threat-model.md),
[`docs/security-review.md`](docs/security-review.md).

## Repository layout
| Path | Content |
|---|---|
| `crates/chunkstore` | chunk store: crypto, compliance clock, indexes, retention (GFS), GC, verify |
| `crates/keyd` | key service (KEK, tenant DEKs, escrow, replication key export) |
| `crates/catalog` | SQLite catalog, migrations, hash-chained audit log, auth, sealed secrets |
| `crates/web-api`, `web/` | REST API and Svelte web UI |
| `crates/scheduler` | policy engine, job runner, alerts, firewall allow-list |
| `crates/setup` | first-boot console wizard (`nexus-setup`) |
| `crates/pve`, `pve-plugin/` | Proxmox VE connector (appliance side) and node plugin (Perl, `.deb`) |
| `crates/nbd` | NBD client and read-only server |
| `crates/agent-proto`, `agent-core`, `agent-linux`, `agent-windows`, `agent-conn` | agent protocol, shared agent core, agents, appliance side |
| `crates/truenas`, `crates/nas` | TrueNAS and NFS/SMB connectors |
| `crates/plugin-proto`, `plugin-host`, `plugin-sdk`, `plugin-manager`, `plugins/` | plugin protocol, sandbox host, SDK + `nexus-plugin` CLI, installer; plugins (example-files, PostgreSQL, TrueNAS, Microsoft 365) |
| `crates/offsite` | offsite engine (packs, retention, GC, DR), SFTP and S3 backends |
| `crates/replication` | second-appliance replication |
| `crates/nftsync` | egress firewall sync |
| `restore-vm/` | restore micro-VM image (Debian kernel + initramfs, ZFS) and its agent |
| `os/` | bootc Containerfile, systemd units, SELinux policy, nftables, update/health checks |
| `release/` | signing (cosign, offline key), verification, promotion |
| `manual/` | end-user manual (Markdown, English) with screenshots; `manual/tools/screenshots.mjs` regenerates them |
| `lab/` | reproducible labs: nested PVE, appliance VMs, Linux/TrueNAS/NAS VMs, fuzzing, e2e scripts |

## Downloads
Every [GitHub release](https://github.com/undone37/NexusBackup/releases) carries the installer ISO and the backup
agent packages:

| File | For |
|---|---|
| `nexusbackup-<v>-x86_64.iso` | the appliance (installer; updates come as signed bootc images) |
| `nexus-agent_<v>-1_amd64.deb`, `nexus-agent_<v>-1_arm64.deb` | Debian, Ubuntu (x86_64, aarch64) |
| `nexus-agent-<v>-1.x86_64.rpm`, `nexus-agent-<v>-1.aarch64.rpm` | RHEL/AlmaLinux/Rocky, Fedora, SUSE (x86_64, aarch64) |
| `nexus-agent-desktop_<v>-1_{amd64,arm64}.deb`, `nexus-agent-desktop-<v>-1.{x86_64,aarch64}.rpm` | Linux desktops: tray icon + status window for users (needs `nexus-agent`) |
| `nexus-agent-<v>-x64.msi` | Windows Server 2016+, includes the tray icon + status window (silent install for GPO/Intune: `msiexec /i … /qn`) |
| `SHA256SUMS`, `*.sig` | checksums and cosign signatures with the release key |

Check a download: `sha256sum -c --ignore-missing SHA256SUMS` and `cosign verify-blob --key nexus-release-<…>.pub
--signature <file>.sig --insecure-ignore-tlog=true <file>` (or `release/verify.sh --blobs DIR`). Installing and
enrolling the agent: [manual chapter 04](manual/04-sources.md#2-install-the-agent-on-the-host).

## Build and test
Requirements: Rust (stable, see `rust-version` in `Cargo.toml`), Node 20+ (web UI), podman (image, test boxes),
QEMU/KVM (labs). No root needed on the build host.
```sh
cargo build --release                       # all binaries
cargo test --workspace                      # unit + integration tests
cargo clippy --all-targets -- -D warnings
prove pve-plugin/t                          # PVE node plugin (Perl, taint mode)
(cd web && npm ci --ignore-scripts && npm run check && npm run build)
cargo deny check                            # licenses, advisories, sources
podman build -f os/Containerfile -t localhost/nexus-os:dev .   # appliance image
```
Optional test targets: `crates/offsite/testbox/run.sh start` (SFTP, Storage-Box-like),
`crates/offsite/testbox-s3/run.sh start` (MinIO with Object Lock), `bash restore-vm/build.sh` (restore micro-VM),
`lab/fuzz/run.sh` (cargo-fuzz targets), `crates/chunkstore/tests/powerloss/run.sh` (power-loss test).

## Labs
[`lab/README.md`](lab/README.md) describes the nested labs: `lab/pve` (Proxmox VE 9), `lab/appliance` (the real
appliance image in a VM with SELinux enforcing, end-to-end flow, signed updates, replication between two appliances),
`lab/linux` (agent matrix: Debian LVM, AlmaLinux XFS, Ubuntu ZFS, Fedora btrfs, plain ext4), `lab/truenas`, `lab/nas`,
`lab/e2e` (control-plane end-to-end through the REST API and a headless browser).

## Roadmap
Phases 0–12 are implemented: foundations, chunk store, Proxmox, restore features, offsite, control plane, hardened
image, additional sources, replication + S3, **plugin system** (signed, sandboxed plugins on a Rust SDK; reference
plugins PostgreSQL, TrueNAS and Microsoft 365), **end-user manual** ([`manual/`](manual)), **Microsoft 365** (Exchange,
OneDrive, SharePoint, Teams as a plugin; tested against a Graph mock, a real-tenant run is pending) and **Phase 12**:
redesigned web UI with dark mode, a KPI dashboard for management, OIDC single sign-on (tested against Keycloak) and
settings pages for alert delivery, SSH keys and updates. First release: **0.0.1-alpha**. Production readiness work is
tracked in `state.md`.

## Security
Please report vulnerabilities privately to the maintainers (do not open public issues). The threat model, the
internal security review and the external penetration-test scope are in `docs/`.

## License
[GNU Affero General Public License v3.0](LICENSE) (AGPL-3.0-only). Third-party components keep their licenses
(checked with `cargo deny`); the restore micro-VM image contains GPL (Linux) and CDDL (OpenZFS) components.
