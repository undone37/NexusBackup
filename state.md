# Project State

_Last updated: 2026-10-08_

## Decisions (see plan.md §2, docs/adr.md)
- License AGPL-3.0 · AEAD XChaCha20-Poly1305 · git + GitHub Actions
- Session scope: Phase 0 + Phase 1 chunk store core (toward M1)

## Done
- [x] Questions answered, recorded in plan.md
- [x] git repo (branch `main`, committed after each step), Cargo workspace, LICENSE (AGPL-3.0), rustfmt.toml
- [x] CI `.github/workflows/ci.yml`: fmt, clippy `-D warnings`, tests, cargo-audit
- [x] `docs/adr.md` (ADR-001…012), `docs/threat-model.md` (T1…T11)
- [x] `crates/chunkstore`
  - `crypto.rs`: keyed BLAKE3 chunk IDs, sealed blob format (zstd + XChaCha20-Poly1305, AAD = header|tenant|context), DEK versions/rotation, key wrap/unwrap
  - `clock.rs`: compliance clock (monotonic, ≤1 % forward slew, ignores backward jumps, persisted)
  - `store.rs`: one file per chunk, fixed + dynamic index, FastCDC file chunking, manifests, commit protocol, retention locks (extend-only, delete blocked), mark-and-sweep GC (grace period, quorum valve at 20 %, abort on unreadable metadata), verify (missing + corrupt, selectable subset), keyring check, name validation
- [x] `crates/keyd`: KEK + recovery-key escrow (`kek.recovery`), tenant DEKs wrapped per version (create/rotate), DR `recover`, recovery-key check, Unix socket protocol with SO_PEERCRED uid check, `fetch_keyring` client, process hardening (umask 077, non-dumpable, mlockall); CLI `keyd init|check-recovery|recover|tenant-create|tenant-rotate|serve`
  - **KEK sealing is file-based (0600)** — user decision 2026-10-08: no TPM for now; TPM replaces `seal`/`unseal` later (needs libtss2-dev)
- [x] `store_image_extents`: incremental-forever fixed index from dirty-bitmap extents; reads only dirty bytes (PVE snapshot-access refuses clean reads), completes partly dirty chunks from the previous chunk, handles grow/shrink
- [x] Tests: 14 chunkstore + 2 keyd passing (`cargo test`), including `survives_kill_9` (6× SIGKILL during writes, then restore + GC + verify); clippy clean

- [x] `os/` bootc image skeleton (AlmaLinux 10.2 `quay.io/almalinuxorg/almalinux-bootc:10`), `podman build -t nexus-os:dev os/` succeeds, bootc lint passes
  - systemd units chunkstore/keyd/web-api (security exposure 0.4 / 0.6 / 1.1), sysusers, preset (sshd off, nftables + chronyd on), nftables default-deny in/out with allow-list sets, chrony NTS, SELinux module with 3 domains (compiles; untested under enforcing)
  - keyd unit wired to the real CLI (`keyd serve … nexus-chunkstore`, socket 0660 for group nexus-keyd, condition on `keyd init`)
  - Nexus units installed but not enabled (no binaries yet); chunkstore/web-api units expect `Type=notify` from future binaries

- [x] Power-loss test `crates/chunkstore/tests/powerloss/run.sh [ROUNDS]` (FS=ext4|xfs|btrfs): QEMU guest with host kernel, SIGKILL of QEMU = power cut, then check mode; passes on all three FS (50 ext4 rounds, ~58.8k snapshots); detects removed fsyncs
  - fixed 2 POSIX durability gaps it found by review: `syncfs` at `Store::open` (chunks renamed by a crashed process), fsync of `snapshots/` after new source dir

## M1 status
Chunk store ingests and restores synthetic block and file data with dedup, encryption, GC and locks, and survives kill -9 tests. **Still missing for M1:** TPM sealing (deferred by user), —. Power-loss test done.

## Phase 2 — Proxmox connector (started 2026-10-08)
Decisions: PVE 9.x only · NBD over SSH stdio (forced command) · .deb via dpkg-deb · nested PVE 9 lab in QEMU
- [x] Research → `docs/pve-backup-provider-api.md`. Findings that changed the design: fleecing mandatory (needs local thin storage on node; no VM templates), bitmap committed before vzdump post-steps (commit snapshot before backup_vm returns; prune_backups must never die), NBD socket root-only (plugin chgrp's it for the unprivileged helper), restore cannot take NBD URIs (needs qemu-nbd -c / nbdfuse on node), no live restore, plugin must answer list/config calls offline (appliance pushes index.json to every node), vzdump returns "OK" not UPID if guest is on another node
- [x] Contract `docs/pve-connector.md` (plugin ⇄ helper ⇄ appliance, job JSON, helper command set, index.json)
- [x] Lab `lab/pve/` (build/start/stop/provision): PVE 9.2.2 nested in QEMU, API https://localhost:18006, SSH root@localhost:10022 (key `/home/ah/nexus-lab/lab_ed25519`), VM 100 (Debian 13, local-lvm), CT 200 (unprivileged), token `nexus@pve!appliance` (lab-wide roles; least privilege TBD), creds in /home/ah/nexus-lab/ (not in git)
- [ ] On-node plugin (Perl storage + backup provider) + forced-command helper + .deb (agent running)
- [x] `crates/nbd`: NBD client (fixed newstyle, structured replies, meta contexts, block status, Read+Seek, transport-agnostic for SSH stdio); tested against qemu-nbd with a persistent dirty bitmap
- [x] `crates/pve/src/api.rs`: PVE API client (token auth, TLS pinned to cluster CA, vzdump start, task status/wait/log) — **not yet tested against lab**
- [x] `crates/pve/src/backup.rs`: orchestration — node lookup via /cluster/resources, vzdump with fleecing, poll `job`, per device NBD over `ssh nbd` → dirty extents → `store_image_extents`, config files as dynamic index, commit, then `done ok|fail`, wait task, `push_index` to all nodes; `nexus-pve` dev CLI (`backup <vmid> | push-index | list`, config JSON, keys via keyd socket) — **not yet tested against lab**
- [x] `Store::image_reader`: random access into a fixed index (one-chunk cache)
- [x] `nbd::server`: read-only NBD server (fixed newstyle, GO/INFO/LIST/EXPORT_NAME, simple replies, writes refused); client falls back to simple replies; interop-tested with qemu-img convert
- [x] Restore contract in `docs/pve-connector.md` (node attaches appliance NBD export via `qemu-nbd -c /dev/nbdX`); appliance `restore_vm` (POST /nodes/<n>/qemu archive=…, poll `restore-job`, serve each device from the fixed index via `ssh restore-serve` + `nbd::server`); `nexus-pve restore …`; index.json has `device_sizes` — **node side + lab test pending**
- [x] Scheduling: `nexus-pve backup-all` (config `vmids`, sequential, continues on error) + `os/systemd/nexus-pve-backup.{service,timer}` (daily 22:00, Persistent)
  - deviation: connector opens the chunk store in-process (same user `nexus-chunkstore`, keys via keyd) instead of a separate chunkstore daemon socket — split when the chunkstore service exists
- [ ] Lab end-to-end test of backup/restore (waiting on lab + node plugin agents)
- [ ] LXC file-level backup → M2

## Next


## Deferred (with reason)
- Bloom filter / separate dedup index: the filesystem path is the local dedup index; add when stat lookups become the bottleneck
- Single global chunk lock: per-prefix locks if contention shows
- Fsync per new chunk file (dir fsync is batched at commit): batch file syncs if HDD throughput suffers
- GFS retention classification: belongs to the scheduler (Phase 5)
- Offsite/verify status: catalog, not the immutable manifest
- keyd TPM sealing: user chose no TPM for now (no libtss2-dev install)
- OS: LUKS2/TPM enrolment, A/B updates + rollback, image signing, first-boot TUI, runtime nftables sets, SELinux refinement (see os/README.md)
