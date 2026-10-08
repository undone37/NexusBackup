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
- [x] `store_image_dirty`: incremental-forever fixed index from a dirty bitmap (reuses previous chunk IDs, handles disk growth)
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
- [ ] Research PVE Backup Provider API → docs/pve-backup-provider-api.md (agent running)
- [ ] Lab: nested PVE 9 VM (agent)
- [ ] On-node plugin (Perl storage + backup provider) + forced-command helper + .deb
- [x] `crates/nbd`: NBD client (fixed newstyle, structured replies, meta contexts, block status, Read+Seek, transport-agnostic for SSH stdio); tested against qemu-nbd with a persistent dirty bitmap
- [x] `crates/pve/src/api.rs`: PVE API client (token auth, TLS pinned to cluster CA, vzdump start, task status/wait/log) — **not yet tested against lab**
- [ ] Appliance side: orchestration (vzdump → SSH helper → NBD → fixed index → snapshot)
- [ ] LXC file-level backup, full VM restore, scheduling → M2

## Next


## Deferred (with reason)
- Bloom filter / separate dedup index: the filesystem path is the local dedup index; add when stat lookups become the bottleneck
- Single global chunk lock: per-prefix locks if contention shows
- Fsync per new chunk file (dir fsync is batched at commit): batch file syncs if HDD throughput suffers
- GFS retention classification: belongs to the scheduler (Phase 5)
- Offsite/verify status: catalog, not the immutable manifest
- keyd TPM sealing: user chose no TPM for now (no libtss2-dev install)
- OS: LUKS2/TPM enrolment, A/B updates + rollback, image signing, first-boot TUI, runtime nftables sets, SELinux refinement (see os/README.md)
