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
- [x] `pve-plugin/`: storage plugin `nexusbackup`, backup provider (backup + full VM restore via qemu-nbd /dev/nbdX), SSH forced-command helper, `build-deb.sh` → `target/deb/nexusbackup-pve_0.1.0_all.deb`; `prove pve-plugin/t` 152 tests (also in CI)
  - deviations folded into contract: NBD socket hard-linked into /run/nexusbackup/jobs (qemu-server dirs untouched), rendezvous dirs 1770, index.json owned by nexusbackup
- [x] `crates/nbd`: NBD client (fixed newstyle, structured replies, meta contexts, block status, Read+Seek, transport-agnostic for SSH stdio); tested against qemu-nbd with a persistent dirty bitmap
- [x] `crates/pve/src/api.rs`: PVE API client (token auth, TLS pinned to cluster CA, vzdump start, restore, task status/wait/log) — tested in lab
- [x] `crates/pve/src/backup.rs`: orchestration — node lookup via /cluster/resources, vzdump with fleecing, poll `job`, per device NBD over `ssh nbd` → dirty extents → `store_image_extents`, config files as dynamic index, commit, then `done ok|fail`, wait task, `push_index` to all nodes; `nexus-pve` dev CLI (`backup | backup-all | restore | dump | push-index | list`, config JSON, keys via keyd socket) — tested in lab
- [x] `Store::image_reader`: random access into a fixed index (one-chunk cache)
- [x] `nbd::server`: read-only NBD server (fixed newstyle, GO/INFO/LIST/EXPORT_NAME, simple replies, writes refused); client falls back to simple replies; interop-tested with qemu-img convert
- [x] Restore contract in `docs/pve-connector.md` (node attaches appliance NBD export via `qemu-nbd -c /dev/nbdX`); appliance `restore_vm` (POST /nodes/<n>/qemu archive=…, poll `restore-job`, serve each device from the fixed index via `ssh restore-serve` + `nbd::server`); `nexus-pve restore …`; index.json has `device_sizes`
- [x] Scheduling: `nexus-pve backup-all` (config `vmids`, sequential, continues on error) + `os/systemd/nexus-pve-backup.{service,timer}` (daily 22:00, Persistent)
  - deviation: connector opens the chunk store in-process (same user `nexus-chunkstore`, keys via keyd) instead of a separate chunkstore daemon socket — split when the chunkstore service exists
- [x] Lab end-to-end (PVE 9.2.2): full backup VM 100 73 s; incremental after 64 MiB guest write: bitmap reuse, 108 MiB dirty, 4.7 s; catalog/`pvesm list`/Show Configuration OK; fail/abort paths clean; restore via `qmrestore` on node + appliance-style NBD serve: 4 GiB in 24 s, VM 900 boots, marker sha256 matches
- [x] API-driven restore (`nexus-pve restore 100 <t> pve1 901 local-lvm`): 4 GiB in 22 s, restored LV sha256 == snapshot (`nexus-pve dump`) — after user OK: lab token gets `PVESDNUser` on /sdn/zones/localnetwork (provision.sh)
  - bug found + fixed: PVE API workers run perl -T; catalog sizes/device names, readdir and glob results reached lvcreate/qemu-nbd/unlink tainted → untainted by strict captures; `t/plugin.t` now runs under `-T` with an exec regression check (fails on old code)
- [x] Plugin `api()` reports running APIVER within tested range 11..14 (user decision), no more "older storage API" warning
- [x] `backup-all` via appliance CLI after lab reboot: full re-read (bitmap lost), 62 s
- [x] LXC backup/restore (`crates/pve/src/ct.rs`, plugin, helper `ct-stream`/`ct-restore-serve`): node streams tar (records C=config, D=data, E=status) from the CT's user namespace via a socket created in backup_container_prepare; appliance chunks with FastCDC into `ct-<vmid>` (`root.tar` + `config`), commits, then answers `ok` in-band; restore extracts into /var/tmp/nexusbackup staging dir → `directory` mechanism
  - lab: CT 200 first backup 11.9 s (679 MB tar, 956 chunks), second 9.7 s with 0 new chunks; restore to CT 902 6.9 s, marker sha256 + modes/owners (shadow, setuid, user files) identical; abort mid-stream clean; `backup-all` handles VMs + CTs
  - limitations: restore needs staging space in node /var/tmp; every CT backup reads the full tree

## M2 status
Scheduled (systemd timer + `backup-all`) incremental-forever backups of VMs and CTs on a PVE 9 cluster with full restore: **reached in the lab** (single-node nested cluster; multi-node cluster untested).

## Phase 3 — Restore features (started 2026-10-09)
Decisions (user, 2026-10-09): instant recovery via qcow2 overlay on the node backed by the appliance NBD export (writes stay local, then `qm disk move`); restore micro-VM = Debian 13 kernel + initramfs incl. ZFS (CDDL, separate component); single-file restore delivered as CLI download (tar/zip)
- [x] File restore from container snapshots: `Store::chunk_reader` (streaming Read over chunks), `pve::files` (list one dir, extract selected paths from a tar stream as tar or zip; zip keeps modes + mtimes, tar keeps owners/modes/mtimes, no xattrs), CLI `nexus-pve ct-files <vmid> <time> ls [dir] | get <out.tar|out.zip> <path>...`; lab: marker sha256 from CT 200 snapshot matches
- [x] Instant recovery (`crates/pve/src/ir.rs`, plugin `ir/` image volumes, helper `ir-serve`): node-local qcow2 overlay (created as root by the storage plugin in `activate_volume`, backing = json raw-over-nbd to a socket served by `ir-serve` over SSH, reconnect-delay 60), VM created via API from the rewritten backup config, then live `move_disk delete=1`; storage `nexus` now `content backup,images` (alloc refused, only `ir/` volumes freeable)
  - lab: running after 4.5 s, 4 GiB moved in 24–30 s (~150 MiB/s); marker present; block compare differs only in guest writes; appliance SIGKILL idle/during mirror → stalls, resumes after `nexus-pve ir-serve`; reproduced after merge (VM 904: 4.5 s / 26.2 s)
  - limits: no TPM-state VMs; guest writes accumulate on node root FS until move finishes; `--link-down` recommended when the original still runs

## M3 status
Instant recovery and single-file restore (VM images via micro-VM; containers via tar) demonstrated in the lab. Test matrix partial: Linux guests on PVE + filesystem fixtures (ext4/xfs/ntfs3/btrfs/vfat/LVM/ZFS); no Windows guest images (user decision: no Windows VMs).
- [x] Restore micro-VM (`restore-vm/`, `pve::restorevm`): Debian 13 kernel 6.12 + ZFS 2.3.9 initramfs (12+12 MB, rootless podman build ~3 min cold / 16 s cached, reproducible, manifest.txt), static musl agent as PID 1 mounting everything read-only without journal replay (ext/xfs/btrfs/ntfs3/vfat/LVM/ZFS), openat2(RESOLVE_IN_ROOT) path confinement; appliance serves disks read-only via NBD, QEMU with -sandbox, no NIC; CLI `nexus-pve files <vmid> <time> mounts|ls|get <out.tar|zip> <paths>`
  - test `cargo test --release -p pve --test restore_vm` (8 filesystems incl. LVM + ZFS, 100 MiB file sha256, tar + zip) passes; first `mounts` 5.8 s; `get` ~260–315 MiB/s
  - lab: real VM 100 snapshot → mounts (ext4 + vfat) in 2.4 s, /etc/hostname extracted as zip
  - open: QEMU runs as the caller (own user/SELinux domain/cgroup limits TBD); no encrypted volumes, zvols, duplicate pool/VG names; appliance image needs qemu-kvm

## Phase 4 — Offsite (started 2026-10-09)
- [x] `crates/offsite` skeleton: `Remote` trait (append-only put, range get, list, delete), `LocalDir`, shared `conformance()` test
- [x] GFS retention `chunkstore::retention` (period-based, union of classes, UTC periods, lock per class 14d/28d/183d/730d) + `Store::apply_retention` (extend locks of kept, delete unlocked rest) — shared by local and offsite
- [x] Pack format `offsite::pack` (byte-identical sealed chunks + sealed index bound to pack id + footer; self-describing)
- [x] `offsite::target::Target` (one box per tenant): upload with N parallel uploaders + bandwidth limit, ordering (pack before local record; manifest last), resumable per pack; independent offsite retention with offsite locks (extend-only, compliance clock); GC with repack threshold (orphan-before-phantom deletion order, abort on unreadable state); sampled verify; inventory check (missing vs unknown); restore from box into local store (chunks verified on insert); `rebuild_from_remote` (DR from box + keys only); `put_if_missing` for key escrow
  - tests with LocalDir: upload/dedup/idempotence, DR into fresh store bit-exact, retention + lock hold, forced repack, verify, second DR after GC, deleted-pack detection, wrong tenant key refused
- [x] `offsite::sftp::SftpRemote` (russh 0.64 / russh-sftp 3, ring backend): port 23, pinned host key (no TOFU), pool ≤10 (default 4), retries only on transport errors, pipelined range reads/writes, put = exclusive tmp + rename (never overwrites), remove_dir, statvfs usage; testbox `crates/offsite/testbox/run.sh` (OpenSSH chroot SFTP-only, 10-connection cap); 7 SFTP tests incl. engine test over SFTP pass (`eval "$(run.sh env)"`, skip otherwise); loopback 4 conns: put 540–735 MiB/s, get 740–1030 MiB/s
  - verify on real box: rename must refuse overwrite; openssh extensions availability; no sweep of orphan `*.tmp-*`
- [x] keyd `export_escrow`/`import_escrow` (wrapped KEK + tenant DEKs for the box; DR test passes)
- [ ] CLI `nexus-offsite` (upload incl. escrow, retention, gc, verify, check, list, restore, dr) + `keyd export-escrow` — **blocked in session: auto mode refused the command; resume outside auto mode**
- [ ] systemd timer, DR drill over SFTP, final run against a real Storage Box
Decisions (user, 2026-10-09): test against a local SFTP container mimicking Storage Box first, real box later; SFTP via russh + russh-sftp

## Phase 5 — Control plane and UI (starts after Phase 4 merge)
Decisions (user, 2026-10-09): Web UI = TypeScript SPA on the REST API; MFA = TOTP only at first; first boot = console TUI

## Phase 6 — Hardened appliance release (starts after Phase 5 merge)
Decisions (user, 2026-10-09): cosign with offline key; updates as signed bootc images on ghcr.io; internal security review + scope doc, external pentest commissioned by the user

## Phase 7 — Additional sources (starts after Phase 6 merge)
Decisions (user, 2026-10-09): order Linux agent → Windows agent → TrueNAS → NAS; Windows = build + unit tests only (no Windows VMs); agent trust = appliance CA + one-time enrollment token; Windows cross-build in podman (mingw-w64)

## Next


## Deferred (with reason)
- Bloom filter / separate dedup index: the filesystem path is the local dedup index; add when stat lookups become the bottleneck
- Single global chunk lock: per-prefix locks if contention shows
- Fsync per new chunk file (dir fsync is batched at commit): batch file syncs if HDD throughput suffers
- GFS retention classification: belongs to the scheduler (Phase 5)
- Offsite/verify status: catalog, not the immutable manifest
- keyd TPM sealing: user chose no TPM for now (no libtss2-dev install)
- OS: LUKS2/TPM enrolment, A/B updates + rollback, image signing, first-boot TUI, runtime nftables sets, SELinux refinement (see os/README.md)
