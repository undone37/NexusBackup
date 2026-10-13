# Project State

_Last updated: 2026-10-13_

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
- [x] CLI `nexus-offsite <cfg> upload|retention|gc|verify [n]|check|list|restore <src> <t>|dr <keyd-dir>` (remote `local` or `sftp`), `keyd export-escrow` (wrapped keys to `keys/` on the box on upload)
- [x] `os/systemd/nexus-offsite.{service,timer}` (daily 02:00: upload, check, retention, gc, verify 3)
- [x] DR drill over SFTP testbox with real lab data: upload 10 snapshots (670 MB, 26 packs) in 1.6 s loopback; check clean; verify 0 corrupt; fresh appliance + box + recovery key → `dr` (26 packs, 10 snapshots indexed) → restore vm-100 → disk sha256 identical to original; wrong recovery key refused
- [ ] Final run against a real Hetzner Storage Box (user to provide; check rename-no-overwrite, extensions, WAN throughput)

## M4 status
Every snapshot can be uploaded and verified offsite (`check`/`verify`), and the DR drill from the (test) box on a fresh store succeeds. Open: per-snapshot "local ✓ / offsite ✓" view belongs to the UI (Phase 5); real Storage Box run pending.
Decisions (user, 2026-10-09): test against a local SFTP container mimicking Storage Box first, real box later; SFTP via russh + russh-sftp

## Phase 5 — Control plane and UI (started 2026-10-09)
- [x] Contract `docs/control-plane.md` (processes/trust boundaries, catalog schema, audit chain, RBAC matrix, quorum actions, REST API, security headers, scheduler, first boot)
- [x] `crates/web-api` (`nexus-web-api`): axum + rustls (TLS1.2/1.3, h2), all contract endpoints, cookie sessions (sha256 stored, 30 min idle/12 h), CSRF, login rate limit/lockout (in-memory), constant-time compares, argon2 dummy hash for unknown users, RBAC + tenant scoping, quorum (four-eyes, 72 h expiry, extra gates: weaker policy via group move, privileged account creation/re-enable/demote/reset), write-only secrets, audit on every mutation, CSP + security headers, /metrics (bearer), SPA embedded from web/dist (placeholder if missing), sd_notify; 15 integration tests
  - fixed: TOTP replay — catalog migration v2 `users.totp_last_step`, `catalog::auth::totp_step`, login consumes the step atomically (`UPDATE … WHERE totp_last_step < step`), test `totp_code_cannot_be_replayed`
  - open: config change + audit not one transaction; install binary as /usr/libexec/nexus/web-api
- [x] `crates/scheduler` (`nexus-scheduler`): UTC schedules `daily HH:MM`/`hourly MM` (one catch-up after downtime), FIFO with per-source/guest/tenant exclusivity, spawns nexus-pve/nexus-offsite with generated 0600 configs in private job dirs, retention/gc/verify in-process, follow-ups (retention → offsite), daily maintenance, gc_large quorum → execute after approval, snapshot table refresh, downloads (web-api token, 24 h expiry), alerts (failed job, verify, inventory, lag > 48 h, capacity > 75 %, GC quorum) via webhook + SMTP, crash recovery, full audit; `os/systemd/nexus-scheduler.service` replaces the pve-backup/offsite timers; 15 unit + 1 lifecycle integration test
- [x] `crates/setup` (`nexus-setup`): ratatui console wizard (80x25): network via nmcli (injectable runner, dry-run), admin + mandatory security officer with TOTP (own half-block QR, decoded in test), keyd init + recovery key shown once + 3-group re-entry (never written anywhere — tested), self-signed TLS (rcgen, SAN), metrics token, audit per step, resume from audit log, lock file, `--force-reconfigure-network`; script mode for tests; `nexus-setup.service` on tty1 before getty; sysusers group `nexus-catalog`; 5 unit + 7 integration tests
- [x] Integration fixes (main): keyd protocol `ensure <tenant>` (create DEK v1 on first use) + `escrow <tenant>`; scheduler ensures keys for all catalog tenants each tick and refreshes escrow before offsite; setup also enables nexus-keyd; web-api unit without PrivateUsers (group-shared catalog); scheduler unit Wants keyd
- [x] `web/` Svelte 5 + Vite + TS SPA (5 exact-pinned devDeps, 0 vulns): login, dashboard (local/offsite/verified per guest), snapshots (restore, instant recover, file browse → tar/zip download), jobs with live log, config CRUD (write-only secrets, own QR encoder), approvals with diff, audit + verify, alerts; CSP-clean (headless Chrome, 16 flows), 42 kB gzip JS; mock API for `npm run dev`
  - gaps: no structured `jobs.result` (UI parses files_list from the log), audit paging only forward, offsite SSH key as file path (no inline secrets)
- [x] Contract gaps closed: catalog v3 `jobs.result` (files_list entries, files_get token/format, backup snapshots), `GET /audit?before=&order=desc` (UI newest first)
- [x] M5 end-to-end (`lab/e2e/m5.sh all`, 5:06): setup (script) → keyd + web-api (TLS, cert verified) + scheduler + SFTP testbox → tenant/source/policy/group via REST only → scheduled backup VM 100 + CT 200 (88–90 s) → retention → offsite (595 MB, 19 packs, 2 s) → snapshots local ✓ offsite ✓ → operator file download CT (ct200) + VM via micro-VM (testvm100), other user 404 → verify → quorum weaken policy (admin 403 on approve, SO approves → executed; reject path) → audit verify ok (53 entries); headless Chrome against real backend 10/10, 0 CSP issues
  - bugs fixed: keyd mlockall(MCL_FUTURE) under low RLIMIT_MEMLOCK broke argon2 allocations; stale node index → "reuses dirty bitmap but no base" → index now pushed before each VM backup; in-memory catalog skipped migrations
  - lab appliance SSH key now at /home/ah/nexus-lab/appliance_ed25519

## M5 status
**Reached (dev setup):** appliance operable end to end via REST/UI without shell access. Not yet exercised: real systemd units with separate users/groups on the appliance image, real network setup, real Storage Box.
- [x] `crates/catalog`: SQLite WAL schema v1 with migrations, append-only audit table (triggers) + length-prefixed sha256 hash chain + verify, `catalog::auth` (argon2id ≥12 chars, TOTP RFC 6238 ±1 step, otpauth URI)
Decisions (user, 2026-10-09): Web UI = TypeScript SPA on the REST API; MFA = TOTP only at first; first boot = console TUI

## Phase 6 — Hardened appliance release (started 2026-10-09)
- [x] A1 appliance image: multi-stage `os/Containerfile` (context = repo root; web, rust on bootc base, restore-VM, SELinux, final; 1.83 GB, ~4 min first build), binaries in /usr/libexec/nexus, tmpfiles for /var/lib/nexus/*, rootless disk build via installer VM (`lab/appliance/build-disk.sh`, `run.sh`, `e2e.sh all`)
  - full M5 flow on a fresh image + disk with **SELinux enforcing and zero nexus AVCs**: real first boot (nmcli, systemctl), keyd/web-api/scheduler in own users + domains, backup VM 100 + CT 200 (28 s), offsite (10 s), file restore CT + VM via micro-VM in `nexus_restorevm_t`, verify, quorum, audit
  - SELinux: domains keyd/webapi/scheduler/pve/offsite/restorevm/setup/nftsync, private data types, neverallows (keys, TPM, web-api isolation, restore-VM isolation)
  - nftables egress automation: scheduler writes /run/nexus-nft/allowed.json → `nexus-nft-sync` (crate nftsync, CAP_NET_ADMIN only) applies sets; unconfigured destinations dropped + logged
  - systemd-analyze security: keyd 0.4, web-api 1.3, scheduler 1.6, nft-sync 1.8, setup 1.9
  - A2 VM test passed: signature enforcement switch, unsigned rejected, signed v2 applied (greenboot green), failing v3 rolled back to v2 and not reapplied
  - fixed: shipped files kept the build host's 0664/0775 → final Containerfile step strips group/world write in /etc and /usr and asserts none remain
  - fixed: download-only staged update lost on a power cut → `nexus-update` re-stages on the next tick (test `test_staged_update_lost_on_power_cut_is_staged_again`)
  - open: source SSH key management (appliance should generate its key + show pubkey); QEMU own uid; nexus-update/greenboot/bootc unconfined (stock); nftables reload empties sets until next sync (≤ 30 min)
- [x] H-2 fixed: `catalog::secret` — source/offsite secrets sealed to the scheduler (crypto_box X25519, `sealed:v1:`, bound to owner + field + endpoint digest; web-api seals, cannot open; 503 without public key), scheduler key `secrets.key` 0600 + `secrets.pub` for web-api, legacy plaintext migrated + audited; TOTP seeds `enc:v1:` XChaCha20-Poly1305 with web-api-only `totp.key` (setup creates it); M-5: credential changes need current password + fresh TOTP (403, rate-limited, audited); SELinux: `nexus_scheduler_secret_t` (scheduler only) + `nexus_webapi_var_lib_t` (web-api + setup only) with neverallows; e2e m5 passed
  - appliance VM re-run after H-2 (`lab/appliance/e2e.sh`): enforcing, no nexus AVCs (only bootc's stock unconfined_service_t probe), catalog only `sealed:v1:`/`enc:v1:`, backup VM 100 + CT 200, offsite, CT + VM file restore, verify, quorum, audit (61) — harness fixes: catalog check runs inside the VM, API state reset on fresh setup
  - residual: scheduler uid (shared with connectors/QEMU) can open source secrets; web-api uid can decrypt TOTP seeds; back up `totp.key`/`secrets.key` with appliance config

## M6 status
Hardened image builds, boots and runs the full flow under SELinux enforcing; signed A/B updates with rollback verified in a VM; internal review done, external pentest scope ready (`docs/pentest-scope.md`). Missing for "1.0 + first production tenant" (all user-side): release key ceremony (custodian), real Storage Box run, external pentest (user commissions), first production tenant (user).
- [x] A2 updates + signing: containers policy (default reject, sigstoreSigned with pinned cosign key, matchRepository), bootc signature enforcement (`switch --enforce-container-sigpolicy`, else bootc ignores policy.json), `nexus-update` (stage, apply only in maintenance window/on request, no version downgrade, rolled-back digests not reapplied, temporary nft allow for ghcr.io), greenboot (AlmaLinux 10 AppStream) + `nexus-health` required check, `release/` (sign.sh air-gapped cosign v2.6.5 by digest, verify, promote :stable, inject-keys, check-trust, test-local), `release.yml` (build/push/SBOM, no CI signing), `docs/release.md`; local demo: signed accepted, wrong key/unsigned/foreign repo/replayed signature rejected; 44 unit tests
  - open: VM test of real bootc upgrade + greenboot rollback (A1 env); real release key (custodian); UI/quorum for update apply/rollback + scheduler inhibit; nft egress by resolved IP fragile (CDN); catalog migrations must stay one release backward compatible
- [x] A3 security review + fuzzing: 13 cargo-fuzz targets (nbd client/server, sealed open, postcard meta, pack parse, hostile Storage Box, CT records, tar files, restore-VM agent frames/requests, keyd requests, validators, whole API router per role), ~555 M execs / 4.3 CPU-h, `lab/fuzz/run.sh`; fixed: zip slip in file downloads (H), PVE plugin log symlink → root on node (H), guest config `lxc.*`/`args`/`hookscript` on restore (H), nbd overflow, hostile box panics + unauthenticated idx copy in DR, quorum stale approval race, offsite target change ungated, token exfiltration via host/CA change, tenant-scoped admins, inline SSH keys returned, clock `inf`, key-holding processes dumpable, CT staging dir ownership, unbounded verify download (+ lows); RBAC × route matrix + audit completeness test; cargo audit 0 vulns (4 warnings via ratatui/postcard), cargo deny ok (`deny.toml`), npm audit 0; `docs/security-review.md`, `docs/pentest-scope.md` (~20 PD + retest), threat model v0.2 (T12 hostile box, T13 node root)
  - open (documented): H-1 KEK plain file (TPM/LUKS deferred), H-2 catalog holds PVE token secrets + TOTP seeds in plaintext (web-api + scheduler read/write), H-3 shared uid nexus-chunkstore for scheduler/connectors/QEMU (forwarded to A1); mediums: audit chain not anchored off-box, clock file deletion, restored disks parsed by node kernel, self password/TOTP change without re-auth, admin can stop future backups
Decisions (user, 2026-10-09): LUKS disk encryption deferred with TPM; cosign with offline key; updates as signed bootc images on ghcr.io; internal security review + scope doc, external pentest commissioned by the user

## Phase 7 — Additional sources (started 2026-10-09)
Decisions (user, 2026-10-09): order Linux agent → Windows agent → TrueNAS → NAS; Windows = build + unit tests only (no Windows VMs); agent trust = appliance CA + one-time enrollment token; Windows cross-build in podman (mingw-w64); agent dedup via plain BLAKE3 + appliance-local mapping to keyed IDs
- [x] Contract `docs/agent-protocol.md` (TLS 1.3 port 7444, mTLS after enrollment, token proofs bound to the TLS exporter = no TOFU/MITM, messages, no remote command execution, limits) + crate `agent-proto` (message types, framing with limits, enroll proofs) + `Index::Tree`/`TreeEntry` (full metadata, keyed chunk IDs; old variants still decode)
- [x] Linux agent `crates/agent-linux` (`nexus-agent`, static musl 2.0 MB): enrollment (token digest + exporter-bound proofs, lock after 5 failures), mTLS (CA chain, clientAuth EKU, CN), volumes from mountinfo, snapshots LVM thin/thick (private mount ns, nouuid/norecovery/noload), ZFS, btrfs with journal + startup cleanup, fallback live read with `inconsistent` detection + spool, scan with full metadata/xattrs/hardlinks, FastCDC + plain BLAKE3, metadata cache committed on successful Release, local-only hooks (permission checks, timeout; PostgreSQL/MySQL examples), confined restore (openat2 RESOLVE_BENEATH, O_EXCL temp + rename), signed self-update (cosign blob, pinned keys, no downgrade, exit 75 restart); systemd unit (exposure 4.3, justified), install.sh, build-bundle.sh, docs/agent-linux.md
- [x] Appliance side `crates/agent-conn` (`nexus-agentctl`): appliance CA (P-256), enrollment + mTLS with fingerprint pin, backup with validation of every entry/chunk, mapping index `<store>/agent-map.db` (verified chunks only, re-transfer if GC'd), Tree snapshots `host-<agent_id>`, restore-to-path (confirm = agent name), tar/zip downloads, signed agent update; catalog v4 (`agents`, sources kind `linux` via table rebuild, migrations with FK check); web-api `/agents` (token once, enroll job, quorum delete), job kinds `agent_enroll`/`restore_files`/`agent_update`; scheduler integration (alerts incl. `backup_inconsistent`, nft allow-list); UI Agents page + restore dialog; job log escaping
- [x] Interop: real agent ↔ real agent-conn in-process (`crates/agent-linux/tests/interop.rs`): enroll, backup, second backup 0 transfers, lost mapping → re-transfer by re-read, restore with metadata
  - open: SELinux domain for nexus-agentctl (port 7444); snapshot providers + unit/install need root → VM lab; Update in one frame (< 8 MiB); entry list in memory; no cert renewal; agent host/port change unsupported
- [x] Linux agent VM lab (`lab/linux/matrix.sh`): Debian 13 LVM thick/thin + XFS + PostgreSQL, AlmaLinux 10.2 XFS-on-LVM + MariaDB (enforcing), Ubuntu 24.04 ZFS, Fedora 44 btrfs subvolumes (enforcing), Debian plain ext4 (fallback, consistent=false + alert): enroll, scheduled full + incremental (e.g. 280 MB → 127 MB full / 10 MB incr.), restore with confirm, metadata identical (owners, modes, ns mtime, xattrs, ACLs, hardlinks, caps), tar/zip, DB dump restore (200k rows), signed self-update (foreign sig + same version refused); through the appliance VM under enforcing with 0 AVCs
  - 11 bugs fixed incl. **silent data loss: nested btrfs subvolumes backed up empty**, thick LVM snapshot size alignment (silent fallback), DB hooks broken by User=root+NNP, snapshot LV left busy (fix in agent-core), XFS internal ACL xattrs, firewall race on enrollment, first-boot wizard unconfined
  - SELinux: `nexus_agentctl_t`, port type `nexus_agent_port_t` 7444 (`os/selinux/nexus-port.cil`), private `nexus_agent_ca_t` with neverallow
  - open: Alma root-on-LVM, thin pool full, very large trees (entries in memory), cert renewal, host/port change, IPv6, snapper /.snapshots, UI not browser-tested for agents; appliance image ships no agent bundle in /usr/share/nexus/agent (release process must provide it)
- [x] `crates/agent-core` (shared: TLS/enrollment/mTLS server, session, chunking/Want, metadata cache v2 with USN positions, restore stream, update verification, init/status) behind `Platform`/`RestoreFs` traits; agent-linux refactored onto it (all tests incl. interop green)
- [x] Windows agent `crates/agent-windows` (`nexus-agent.exe` 1.8 MiB, x86_64-pc-windows-gnu via podman `build.sh`, CI job): service (LocalSystem, restart policy), protected ACL on %ProgramData%\NexusAgent, VSS via hand-declared IVssBackupComponents (copy-only, writer report), USN journal change detection (fallback to full read on wrap/reset), security descriptors (`win.sd`), ADS as `<file>:<stream>` entries, reparse points not followed, confined restore (component-wise, held dir chain), signed self-update (rename + restart / reboot fallback); agent-proto v1.1 (Vss, Writers/WritersReport, additive)
  - **never run on Windows** (user decision): everything in `src/win/` compiled only; manual test plan for Server 2016–2025 in docs/agent-windows.md; open: agent-conn does not request WritersReport yet; no hooks on Windows; EFS files fail

## Phase 7 — TrueNAS (merged 2026-10-09)
- [x] `crates/truenas` (`nexus-truenas`): TrueNAS 25.10.7, JSON-RPC 2.0 WebSocket API (REST deprecated), API key with roles SNAPSHOT_WRITE/SNAPSHOT_DELETE/DATASET_READ, pinned TLS cert; per-dataset atomic snapshot `nexus-<source>-<time>`, `zfs diff` + metadata walk + read only changed files (inode-based reuse survives renames), own bounded tar reader, `Index::Tree` `nas-<source>-<pool.ds>`, snapshot rotation (keeps the reference only); forced-command `authorized_keys` line generated by the API (restrict, from=, command=; 17 lab probes); catalog v5 kind `truenas`, sealed API/SSH keys, scheduler + nft, SELinux `nexus_truenas_t`, UI; download-only restore (tar/zip)
  - lab (TrueNAS VM, unattended install via installer JSON-RPC): full 2,014 files 19 s / incremental 7 files read, 67 MB 2.3 s / no-change 1.5 s; downloads sha256-identical; appliance VM under enforcing: 0 AVCs; UI 6/6; fuzz 15 M execs
  - user accepted (2026-10-09) the privilege model — `nexusbackup` runs find/tar/realpath/zfs via passwordless sudo (root-equivalent), the forced command is the boundary (4 ops, configured datasets, nexus-* snapshots, canonical paths only)
  - limits: changed files re-read fully (no block delta), sparse files full transfer, dataset root ACL not recorded, entries in memory, cert renewal breaks pin, restore-to-dataset deferred

- [x] Dependabot: lru upgraded 0.12.5 → 0.18.5 via ratatui 0.29 → 0.30.2 (first-boot TUI; builds unchanged, tests green); paste dropped; deny.toml ignores for lru/paste removed; cargo audit: only atomic-polyfill (unmaintained, allowed)

## Production gaps (deferred by user decision 2026-10-09: continue plan order first)
SSH key management for sources, agent/TrueNAS cert renewal, minimal PVE token privileges, scale/soak tests on real hardware, multi-node PVE, GitHub push + CI + release, agent bundle in the image, TPM/LUKS, H-3 uid split; user-side: release key, real Storage Box, external pentest, pilot tenant

## Phase 7 — NAS (NFS/SMB) (merged 2026-10-09)
- [x] `crates/nas`: helper `nexus-nasmount` (socket-activated per connection, CAP_SYS_ADMIN only, SELinux `nexus_nasmount_t`, SO_PEERCRED, fuzzed request parser) builds the mount with fsopen/fsconfig/fsmount (ro,nosuid,nodev,noexec,nosymfollow), never attaches it and hands the detached mount fd to the connector → kernel cleans up on exit; connector `nexus-nas` (`nexus_nas_t`): parallel deterministic scan, reuse by path/inode+size+mtime+ctime, inconsistent detection, NAS snapshot dirs, FastCDC, `share-<id>` Tree snapshots, tar/zip download (no restore to share in v1); catalog v6 kinds nfs/smb with sealed SMB password/keytab; scheduler, nft (2049/mountd, 445), UI, docs/nas-connector.md
  - lab: NFS 4.2 + SMB 3.1.1 (signed+encrypted) full/incremental, downloads sha256-identical, xattrs/ACLs match; 1M small files: full 2,167 files/s (dev) / 1,842 (appliance), unchanged 72,900 / 36,400 entries/s; appliance VM under enforcing 0 nexus AVCs; fuzz 62 M
  - open decisions (user): server read-access model (NFS ro export with all_squash anonuid=0 / SMB backup user), SMB Kerberos (ship cifs-utils+krb5 and test vs AD, or drop krb5 from v1), alert noise for shares without NAS snapshots
  - limits: entries in memory (0.56–0.73 GB at 1M files; appliance needs ≥ 6 GB for that), one chunk per small file, Samba mtime/owner limitations, sparse files full, no NFS Kerberos

## Phase 8 — Replication + S3 (done 2026-10-10)
Decisions (user, 2026-10-09): MinIO for dev/tests, real provider later; own minimal SigV4 client; replication = secondary pulls via mTLS endpoint on primary's 8443
- [x] S3 offsite backend (`crates/offsite/src/s3.rs`, own SigV4, no SDK): never-overwrite put (HEAD + If-None-Match), multipart > 64 MiB, ranged GET, ListObjectsV2, Object Lock compliance on write + PutObjectRetention extension, storage class per kind, bounded XML parser (fuzzed 3 M); engine lock-aware (packs locked to max referencing snapshot lock, extended before manifest/retention, GC skips locked packs, DR restores locks); sealed `secret_key`; UI target choice none/SFTP/S3 (+ fixed: UI stored SFTP config in a shape the scheduler ignored; bwlimit units); MinIO testbox (community image) 7/7 incl. full engine flow; docs/s3-offsite.md (MinIO/AWS/Hetzner/Wasabi, restricted policy, lifecycle) — merged
  - open: rotating-DNS endpoints vs firewall allow-list (AWS), real provider run, per-pack lock extension cost
- [x] Replication merged (`nexus-replicad` read-only behind web-api ALPN-split mTLS on 8443, `nexus-replica` pull sync, keyd export-for/import-sealed, quorum-gated peer + key export, catalog v7 (renumbered from v6 during integration, migration tests), two-VM lab under enforcing: 181 MB/s initial sync, restore on secondary with primary off; lab rerun after integration pending (needs ≥ 10 GB free RAM): `IMG=localhost/nexus-os:merge-lab lab/appliance/replication.sh disks boot setup primary enroll sync check stop`)
  - user confirmed 2026-10-10: two quorum approvals, replicad as nexus-chunkstore (SELinux boundary), replicated tenants take no local backups
- [x] LZ4 on the wire for agent chunks (user request 2026-10-10): agent-proto v1.2 (cap `lz4`, `WantLz4`/`ChunkLz4`/`RestoreChunkLz4`, appended), `lz4_flex` (pure Rust), only sent if ≥ 10 % smaller, size-bounded decompression + BLAKE3 check on the appliance, both directions; Linux + Windows agents via agent-core; interop: 8.18 MB raw → 5.01 MB on the wire (log file ~3.2 MB → ~13 KB, random data raw); agent binary 2.1 MB
  - note: `hooks::tests::timeout_kills_process_group_and_pre_stops_on_failure` is timing-sensitive under full parallel test load (passes alone)
- [x] NAS decisions implemented: web-api refuses `sec krb5` (UI offers NTLMSSP only; helper code kept), `backup_inconsistent` once per source for a missing snapshot / every time for files changed while read (agents + shares; test `inconsistent_alerts_once_per_source`), access models documented as the supported setup (docs/nas-connector.md)
- [x] Scale-out groundwork: `docs/scale-out.md` (what is node-independent, what is node-local, sharding/leader direction, rules for new code)
- [x] Repository README.md (user request 2026-10-09): overview, honest status, sources/restores matrix, architecture, layout, build/test, labs, roadmap, security, license

## UI browser test (Claude in Chrome, 2026-10-10, mock backend)
Clicked through Dashboard, Agents (create, new token), Replication (peer create, schedule edit), Tenants (S3 form), Sources (PVE/SMB forms). Fixed:
- **security:** agent install command contained the enrollment token (visible in `ps`/shell history) → API + mock now `sudo /usr/local/sbin/nexus-agent init --token -`, token pasted on stdin; agents prompt when interactive; test asserts the token is not in the command
- replication peer dialog asked for "this appliance's certificate fingerprint" without showing it → API returns `primary_cert_sha256` (ReplPaths.tls_cert), UI shows + copy; test asserts it equals the pin
- 10 native `confirm()` + 2 `prompt()` blocked the page (and automation / future manual screenshots) → shared in-page dialog (`askConfirm`/`askText`, `ConfirmDialog`)
- mock API lacked replication endpoints → added with seed data (needed for Phase 10 screenshots)
- form grid: wrapping labels / hints misaligned inputs → subgrid rows (label | control | hint) for all 14 forms
- texts: agents run on Linux **and Windows**; shorter Host label; input dialog title
- noted for Phase 10 seeding: mock tenants lack the replicated tenant `globex`
- second round (Users, Approvals, Audit): **bug** TOTP field on the Users page had `pattern="[0-9]{6}"` — Svelte evaluates `{6}`, so re-authentication only accepted codes like "x6" → `pattern={'[0-9]{6}'}`; approving a quorum request now needs a confirmation (irreversible actions); re-auth section, reject/approve, diff highlighting, audit redaction and chain verification work
- design flaw (admin knows new users' credentials) → user decided 2026-10-10: self-enrollment at first sign-in (implementation running)
- [x] Optional approval system (user request 2026-10-10): off for single-user appliances, enable freely, disable = requester + 1 approver, approvers = admins + security officers, banner when more users exist; + self-enrollment (activation codes, split codes for privileged roles). Merged with Phase 9: catalog v8 = plugins, v9 = settings + activation columns; quorum gating returns `Outcome` (pending / direct); plugin uploads with approvals disabled are recorded first and approved directly (test `plugin_upload_without_approvals`). Checks: cargo test (336 ok), clippy, prove, svelte-check/build, cargo deny.
  - open: console recovery path when approvals deadlock (lost authenticator with two users)
- [x] SELinux neverallows are checked in the image build (selinux stage, expand-check; only the nexus module's rules gate, the distro's container module fails its own). Fixed: restorevm/nasmount `:file *` → explicit perms (base grants `map` to all domains); replicad→keyd now forbidden on keyd's sock_file (base `daemon` attribute grants connectto). Full image build + VM labs still pending (RAM).

## Phase 9 — Plugin system (added 2026-10-10)
Goal: extend with new data sources + restore functions (NetApp SVM, VMware ESXi/vCenter, PostgreSQL, …) via signed, sandboxed plugins on a versioned SDK; M9 = PostgreSQL plugin + one ported connector
Decisions (user, 2026-10-10): sandboxed processes + Rust SDK; trust = project key + admin-added publisher keys (quorum); reference plugin PostgreSQL; port TrueNAS; restore API: download, restore to target, app-specific, mount/instant access
- [x] Contract `docs/plugin-system.md` (trust split: untrusted plugin process ↔ trusted `nexus-pluginhost`; bundle + manifest + signature; quorum-gated lifecycle; protocol ops Validate/ListGuests/Backup/Restore/Mount; sandbox; SDK; catalog v8) + crate `plugin-proto` (messages, framing, limits, path/stream validation, manifest model + validation)
- [x] Platform merged (905e819/373eaaa): `nexus-pluginhost` (Landlock + seccomp + rlimits, host ops), `plugin-sdk` + `nexus-plugin` CLI (scaffold/build/sign/test), example plugin `plugins/example-files`, `plugin-manager` + installer (signed bundles, quorum lifecycle, rollback), catalog v8, web-api/scheduler/UI integration, SELinux domains + units, fuzz target, docs/plugin-sdk.md
- [x] PostgreSQL reference plugin `plugins/postgresql` (M9, README there): pure-Rust wire protocol client (TLS rustls require/verify-full, SCRAM/md5; no new crates) because the sandbox can only run what the image ships and pg_dump/pg_basebackup must match the server version. Guests = databases → consistent logical dump per database (catalog-generated SQL + COPY, psql-compatible, stream `<db>.sql`); no guest = cluster → BASE_BACKUP as files `data/` + WAL from a physical replication slot as `wal/<segment>`, incrementals re-reference data + old WAL (`Unchanged`, front-coded path list in the state blob) so every snapshot is self-contained; new base every `full_every_days`, on timeline change or lost slot. Restores: `to_target` (new/existing database on the source or an alternate server = optional endpoint), `pitr` (new data directory on an SSH restore host, host key pinned, recovery_target_time + promote), download by the host. Core change (additive, docs/plugin-system.md v1.2): `KindSpec::tcp_ports(config)` shared by nexus-pluginhost and the SDK harness (the harness ignored configured ports). Tests: 8 unit + podman integration (`testbox/run.sh`, skips without podman): dump → restore to source and alternate server identical under `pg_dump --schema-only/--data-only`, full + 2 incrementals → PITR to a time (100 of 300 rows), to the end, from the full alone, existing dir refused, dropped slot → full; passed on PostgreSQL 14, 17, 18
  - open: logical dump does not cover owners/grants, comments, RLS policies, aggregates, operators, range types, rules, foreign tables, inheritance, large objects, roles (warned per backup); PITR of clusters with extra tablespaces (download only); signed bundle build (musl needs a musl C toolchain for ring, or glibc ≤ 2.39 builder) + VM lab/UI run on the appliance; slot retains WAL if backups stop (documented)
- [x] TrueNAS connector ported to the plugin SDK (M9): `plugins/truenas` (crate `truenas-plugin`, plugin id/kind `truenas` → source kind `plugin:truenas`; built-in kind `truenas` kept, coexistence + migration in docs/truenas-connector.md §9). Shares crate `truenas` via new feature `client` (api, remote, diff/walk/stream parsers, `tree::changed_inodes` + new `tree::next_requested`/`end_of_requested` also used by `fill`); same forced command / authorized_keys line. Guests = datasets (`tank.data`), one ZFS snapshot per dataset, reference in the state blob, `Unchanged` by path against the base (renames are re-sent), rotation one run later (2 `nexus-<sid>-*` per dataset). Additive host/SDK v1.2 (docs/plugin-system.md): backup `Init.params.source_id` (`Ctx::source_id()`), SELinux `can_exec(nexus_plugin_t, ssh_exec_t)` (system `ssh` inside the sandbox), `plugin_host::endpoint_ports` shared by host + test harness (harness now opens the config's ports). Test fake moved to `crates/truenas/tests/support/` (shared via `#[path]`). Tests: `cargo test -p truenas-plugin` 4 unit + 5 integration (in-process vs fake; plugin binary in the real Landlock/seccomp sandbox over wss mock + local unprivileged sshd + real forced command); workspace 347 ok, clippy, cargo deny ok. Release builds: gnu needs GLIBC_2.39 (ok for AlmaLinux 10); musl works with `CC_x86_64_unknown_linux_musl=gcc` (plugins.sh sets it)
  - open: lab runs (TrueNAS VM 8 GB, + appliance VM 3 GB; not run, ~5 GB free): `lab/truenas/vm.sh start && python3 lab/truenas/provision.py && python3 lab/truenas/sh.py lab/truenas/data.sh sums > /tmp/sums && NEXUS_TRUENAS_LAB=/home/ah/nexus-lab/truenas/lab-cli.json NEXUS_TRUENAS_SUMS=/tmp/sums cargo test -p truenas-plugin --test lab -- --nocapture`; through the appliance: `IMG=localhost/nexus-os:plugins PLUGIN=truenas lab/appliance/plugins.sh image disk boot setup install`, then `ROOT=/home/ah/nexus-lab/plugins/appliance/root PORT=28481 KIND=plugin APPL_HOST=10.0.2.2 lab/truenas/e2e.sh` and `lab/appliance/plugins.sh check` (0 AVCs: ssh in nexus_plugin_t is untested on SELinux)
  - open: flaky unrelated `scheduler tests::share_jobs` (failed once in a full run, passes alone/rerun)
- [x] VM lab runs passed 2026-10-11 (SELinux enforcing, real image): example plugin (`plugins.sh image disk boot setup plugin check`: tampered bundle refused, signed install via quorum, validate, full + incremental (0 bytes), files_get identical, 0 unexpected AVCs); TrueNAS plugin against the TrueNAS VM directly (`cargo test -p truenas-plugin --test lab`) and through the appliance (`PLUGIN=truenas plugins.sh install` + `lab/truenas/e2e.sh KIND=plugin`: scheduled full + incremental with renames/ACL/xattr changes, tar + zip downloads match, snapshot rotation, 0 AVCs); PostgreSQL testbox 2/2; **PostgreSQL through the appliance** (`PLUGIN=postgresql lab/appliance/plugins.sh disk boot setup pg check`, M9): signed install via quorum, validate + guests through the egress firewall and sandbox, consistent backup of `labdb`, restore `to_target` on the alternate server, table + view identical, 0 AVCs
  - bugs found and fixed by the labs: plugin start EACCES (Landlock fstat of /dev/random under SELinux), DEK not ensured for jobs started between ticks (new tenants), unreadable files skipped silently (SDK now names the first 20), installer path unit fired only once (init_t needs read+watch on the trigger), ssh in the sandbox could not read /etc/passwd, web build stage lacked plugins/ manifests, lab TOTP replay between scripts

## Phase 10 — End-user manual (added 2026-10-10, after plugin system; M365 = Phase 11)
`manual/` folder, full end-user documentation in Markdown with reproducible screenshots of the web UI
Decisions (user, 2026-10-10): English; screenshots from seeded demo data via headless browser; start after Phase 9 merge
- [x] Manual `manual/` (2026-10-11): README (audiences, status, TOC) + 15 chapters: concepts, installation/first boot + recovery key, web interface (every page), sources (PVE node plugin, agents Linux/Windows, TrueNAS built-in + plugin, NFS/SMB, PostgreSQL), policies/groups, restores (full, instant, files, restore to path, PostgreSQL dump + PITR, secondary, offsite CLI), offsite (Storage Box, S3 Object Lock), replication, users/roles/MFA/activation codes, approvals + audit, alerts/metrics, plugins, updates/rollback, disaster recovery, troubleshooting/FAQ; lab-only parts and production gaps marked with **Status** notes
- [x] Seeded demo mock (`web/mock/api.ts`): tenants acme (S3 lock, replicated to dr-site) / initech (Storage Box) / globex (replicated from hq-primary), every source kind incl. built-in TrueNAS (now supported by the mock) and the real `plugins/*/manifest.json`, policies/groups, snapshots, jobs incl. failures, alerts as the scheduler writes them, approvals enabled with pending requests, users incl. pending/disabled, audit history; example domains + documentation IPs only; `NEXUS_MOCK_EPOCH` / `NEXUS_MOCK_SEED` for reproducible runs. Mock aligned with web-api: replication source POST `{code, fingerprint}` + `/sync`, tenant offsite change gated, source delete 409 with groups, pending peer → revoked, no `quorum` alerts, gc pending only with approvals off
- [x] Screenshots: `node manual/tools/screenshots.mjs` (build + `vite preview` on a free port, headless Chrome over CDP with Node's WebSocket, app served as https://backup.example.com, fixed clock/seed, 1440×900, optipng) → 56 PNGs in `manual/images/` (~5 MB); `manual/tools/README.md`
- UI fixes found while capturing: Dashboard showed plugin-group guests as `host-<guest>` / "No backup" (now plugin snapshot names, whole-source groups as one row); PVE source field "Restore storage" relabelled "NexusBackup storage ID on PVE" and no longer pre-fills the restore target storage; plugin texts said "security-officer approval" (any other admin or SO approves); plugin source summary showed PEM blocks; group legend "(none selected = all)" → "the whole source"; job kinds `replica_enroll` / `replica_sync` labelled
- open (UI, not fixed): Snapshots offers every plugin restore on every snapshot of the kind (PITR on database dumps, dump restore on cluster snapshots) and long plugin restore titles overflow the table; no UI for alert delivery (`/etc/nexus/alerts.json`), source SSH keys, updates; docs/control-plane.md still shows `init --token <T>` (UI: `--token -`)
- open: **M10** review of the manual against the real appliance build (VM lab) and regenerate screenshots per release; no console break-glass / root access procedure documented (needed by DR, updates, key files); DR not integrated with first boot

## Phase 11 — Microsoft 365 as a plugin (2026-10-11)
Decisions (user, 2026-10-11, plan.md §2): local Graph mock now, real M365 test tenant later · scope Exchange (mail, calendars, contacts), OneDrive, SharePoint document libraries, Teams (team files + channel messages via the protected export API) · Entra app registration, application permissions, certificate credential (no client secrets) · restores: download, to the original (new folder, never overwrite), to another user/site/team
- [x] Plugin `plugins/m365` (crate `m365-plugin`, id/kind `m365` → `plugin:m365`; design + Entra setup docs/m365.md, short plugins/m365/README.md). Guests: `u.<user id>` (mail/ .eml, calendar/ .ics, contacts/ .vcf, onedrive/), `s.<base64url(site+web GUID)>` (libraries/<lib>/), `t.<group id>` (files/, channels/<channel>/<thread>.json); no-guest groups refused. `.ics`/`.vcf` generated from Graph JSON with the JSON embedded (`X-NEXUSBACKUP-GRAPH`) for lossless restores
- [x] Auth: certificate + key as sealed `secret_fields` (PKCS#8/PKCS#1 RSA, key↔cert match, PEM pasted into single-line fields repaired); client-credentials grant with a PS256 client assertion (`x5t#S256` + `x5t`, aud = token URL, jti); token cache, renewal < 5 min, one refresh on 401; Entra AADSTS codes mapped to config fields in Validate; bearer only to the Graph origin (next/delta links checked, upload URLs unauthenticated)
- [x] Incremental: previous snapshot read back via new `BaseList` (ids in xattr `user.m365.id`, version tags in `user.m365.tag`) → no item lists in the 1 MiB state blob; state = Graph delta links (per mail folder, per drive; longest dropped if > 1 MiB) + last Teams export time. Mail + drives: delta queries; calendars + contacts: full listing compared (no v1.0 delta for non-expanded events); Teams messages: `getAllMessages` (model A/B/evaluation) by lastModifiedDateTime, changed threads re-read; same id+path+tag+time(+size) → `Unchanged`. Throttling 429/503/504 with Retry-After (8 attempts), paging, 32 MiB ranged downloads resumed after broken ranges, 404 between listing and download skipped
- [x] Restores `to_original` / `to_other` (target: UPN/id, site URL/id, team id/name; optional `paths`, `folder` default `Restored <date> <time>`): mail folder tree + MIME import, new calendars (events without attendees: no invitations), contact folders, drive files (PUT ≤ 4 MiB, upload sessions in 10 MiB fragments, conflictBehavior=fail; existing folder → error), site libraries by name (else default library), Teams threads into new migration-mode channels (original author/time, completeMigration even after errors). Download = generic host download
- [x] Contract v1.3 (docs/plugin-system.md, additive, api 1): endpoint `default_host` (fixed DNS hosts graph.microsoft.com / login.microsoftonline.com, overridable by the config field) with one resolver `KindSpec::tcp_targets` used by the scheduler firewall (its own copy removed) and `tcp_ports` (sandbox); `Message::BaseList { after }` (paged base listing with full metadata, host `Base::list_page`, SDK `Sink::base_list`); SDK restores drain the host's answer after a callback error so the plugin's Error reaches the job log (was "Broken pipe"). Web: plugin details show `default_host`
- [x] Graph mock `plugins/m365/tests/mock/` (HTTPS with own CA, token endpoint verifying the assertion: PS256 signature with the registered cert's key, thumbprint, aud/iss/sub/exp/nbf, jti replay; delta links, paging, faults 429/503 + Retry-After, token revocation, broken ranges, protected API denial, uploads/sessions, migration channels); runnable for development: `cargo run -p m365-plugin --example graph_mock`
- [x] Tests: `cargo test -p m365-plugin` 12 unit + 8 integration (in-process via plugin_sdk::testing + the real binary in the real Landlock/seccomp sandbox): token flow + validation per workload (wrong tenant/client/cert, missing permission, wrong SharePoint/OneDrive host, protected API refused), guests, mailbox + OneDrive full/incremental (delta links used, only changed items downloaded, delete/move/folder rename, resumed range, no-change run transfers 0), site, team (files + export API, only changed threads re-read, protected-API backup error commits nothing), throttling/paging/token revocation/early renewal, restores to original (new folder; refused when it exists) and to another user (UPN) and site (URL), 33 MiB upload session, Teams migration channels; plugin-host test for BaseList, plugin-proto tests for default_host/tcp_targets/BaseList. No new crates (reqwest/ring/pem/base64 already in the workspace), cargo deny ok
- open: **run against a real M365 developer/test tenant** (checklist in docs/m365.md "Real-tenant run": PS256 accepted, MIME-imported mails as drafts?, download redirect hosts, migration-channel createdDateTime, getAllSites filter, throttling on a large mailbox, firewall vs. Microsoft's rotating addresses); signed bundle + VM lab/UI run (`PLUGIN=m365 lab/appliance/plugins.sh …`); v1 limits: recurring-series exceptions, event attachments, contact photos, archive mailboxes/public folders, file versions/permissions, lists/subsites, private/shared channel sites (back up as sites), chats; one SharePoint + one OneDrive host per source (no multi-geo/vanity domains); folder renames re-download contents; manual screenshots for M365 not taken (no mock entry in web/mock/api.ts)

## Next


## Deferred (with reason)
- Bloom filter / separate dedup index: the filesystem path is the local dedup index; add when stat lookups become the bottleneck
- Single global chunk lock: per-prefix locks if contention shows
- Fsync per new chunk file (dir fsync is batched at commit): batch file syncs if HDD throughput suffers
- GFS retention classification: belongs to the scheduler (Phase 5)
- Offsite/verify status: catalog, not the immutable manifest
- keyd TPM sealing: user chose no TPM for now (no libtss2-dev install)
- OS: LUKS2/TPM enrolment, A/B updates + rollback, image signing, first-boot TUI, runtime nftables sets, SELinux refinement (see os/README.md)

## Release preparation (2026-10-11)
- [x] Image repo `ghcr.io/undone37/nexusbackup` (update.conf, policy.json, registries.d, release/config.env, docs, manual); check-trust ok
- [x] Alpha release key `release/keys/nexus-release-2026-alpha.pub` (sha256 604da497…28beae), generated by the maintainer on the dev machine (weak custody, documented in release/keygen.md); inject-keys + check-trust --release ok
- [x] CI fixes: clippy 1.99 `as_chunks`, audit job `checks: write`, postcard without heapless (atomic-polyfill gone)
- [x] Pushed main after Phase 12 (2026-10-12); CI fully green (rust incl. Keycloak/PostgreSQL/sandbox tests on the runner, web, audit, agent-windows); tag `v0.0.1-alpha` pushed → release workflow (image → ghcr.io/undone37/nexusbackup, SBOM, DRAFT release)
- [x] Signed with the alpha key, verified with release trust, `:stable` promoted, published 2026-10-12 as a pre-release
- [x] Installer ISO (`iso.yml`, bootc-image-builder anaconda-iso, 1.86 GB) attached to v0.0.1-alpha; `lab/appliance/iso-test.sh`: unattended UEFI install in QEMU, first boot into the nexus-setup wizard, SELinux enforcing
- [ ] ~~Make the ghcr.io package public~~ — decided 2026-10-12: repo + package stay private for now; test appliances need a pull credential (read:packages) for updates (Phase 14 add-on)
- [ ] Before beta: offline key ceremony + standby key, rotate away from the alpha key

## Phase 12 — Professional UI, KPI dashboard, OIDC (started 2026-10-11)
Decisions: plan.md §2 (UI redesign, dashboard KPIs, OIDC + JIT provisioning, branding, UI deps). Contract: docs/phase12-contract.md
Also in scope (user 2026-10-11: "fix all of them"): Snapshots page restore filtering (manifest `applies_to`), long plugin restore buttons, pages for alert delivery / appliance SSH keys / updates, break-glass for a sole admin (console + recovery key), manual + screenshots updated
- [x] Phase 11 merged into main (377 tests ok, clippy/deny/web/prove clean); CI: sandbox tests need unprivileged userns on Ubuntu 24.04 runners (sysctl step added)
- [x] Backend (agent, 2026-10-11): `GET /dashboard` (protection/SLA, job trends, capacity + linear-regression forecast, offsite/replication; tenant-scoped, cached 60 s); catalog **v10** (`capacity_samples`, `users.auth`, `users.oidc_sub`; migration test from v9); scheduler: daily capacity samples + `settings.capacity`, alert delivery from the catalog setting (SMTP password sealed, `min_severity`, file fallback), `alert_test` job, appliance SSH keys in use (PVE node keys, SFTP offsite keys below `/etc/nexus/ssh`) published to the catalog, rotation generates ed25519 keys (ssh-keygen-compatible) beside the old one, retire swaps them, allow-list adds OIDC issuer/token/JWKS hosts; OIDC (code + PKCE S256, state/nonce, discovery, JWKS cache + refresh on unknown kid, RS256/ES256/PS256 only, JIT accounts from group mappings, quorum `oidc.update`, test endpoint) — **tested against Keycloak 26.4.0** (crates/web-api/tests/oidc-testbox/run.sh, rootless podman) and a local fake IdP (replayed/unbound state, open redirect, wrong aud/iss/nonce/exp, unknown kid, key rotation, PKCE); settings APIs for alerts / SSH keys (rotate = quorum `ssh_key.rotate`, retire) / updates (`nexus-update status --json` + `api` view in status.json, check, apply = install now via quorum `update.apply`); integrator clarifications applied (flat test results, `previous` key, error codes incl. `account_disabled`, tenant rules for mappings, UPN-style SSO names, default scopes); manifest `applies_to` (plugin-proto v1.4, web-api + nexus-pluginhost refuse mismatches, PostgreSQL manifest); `nexus-setup recover-admin` (recovery key, `--force-solo`, audit + critical alert + banner); SELinux: web-api may connect out (http/unreserved ports, DNS), scheduler manages `nexus_sshkey_t`; docs: control-plane, threat-model (T15 OIDC, T16 break-glass), plugin-system v1.4, contract implementation notes (incl. the integrator's clarifications)
  - Open: PVE guest inventory for "unprotected" (only agents + plugin guest listings count today); dedup/compression ratios not measured (`null`); capacity sample walks each tenant store once a day in the tick (slow on huge stores); OIDC accounts cannot re-authenticate (no password/TOTP), so an OIDC admin cannot issue activation codes for others; IdP-driven demotions are not checked against the two-approvers rule; postgresql plugin version not bumped for the manifest change (re-sign/release needed); `expired` OIDC code not covered by an integration test (needs a clock); the image's `/etc/nexus/ssh` ownership changes to nexus-chunkstore via tmpfiles (lab e2e.sh still places hand-made keys)
- [x] Frontend (agent): enterprise-console redesign (navy icon sidebar, collapsible to a rail / off-canvas on phones, top bar with breadcrumb + approvals/alerts badges + theme toggle; card/table/chip/toast/dialog styles in web/src/app.css as light-dark() tokens; IBM Plex Sans/Mono bundled; logo web/src/components/Logo.svelte + favicon), dark mode (follows the OS, toggle stored per browser), KPI dashboard (8 KPI tiles, jobs per day stacked bars, capacity trend + forecast, protection donut, data-reduction donut, failures by source type, worst objects; 7/30 days; tooltips + hidden data tables; tenant-scoped), Settings page (Approvals moved there from the Approvals page, Alert delivery + test, Single sign-on with mappings editor + test, SSH keys copy/rotate/retire, Updates check/stage), sign-in with "Sign in with <label>" + oidc_error, SSO badge / no credential actions for OIDC users, Snapshots restore menu filtered by applies_to, break-glass banner (open `break_glass` alert, admins); mock implements every contract endpoint (+ OIDC demo user lwagner); deps @lucide/svelte + Plex fonts; check/build clean, built bundle under the preview CSP in headless Chrome without console errors / CSP violations (light, dark, 390 px); manual/tools/screenshots.mjs updated (65 PNGs regenerated, 9 new: dashboard-dark, snapshot-restore-menu, settings-approvals/alerts/sso/ssh-keys/updates, login-sso-error, user-sso)
  - Open: contract shapes assumed (web/README.md "Phase 12"): test-call answers, SSH key `previous`, updates `staged`/`rollback`, break-glass banner = open `break_glass` alert, OIDC error codes, "lock coverage" meaning (UI: "snapshots under an immutable lock"); `next` after SSO is `/#/<route>` (backend must accept a fragment or ignore it)
- [x] Manual text updated to the Phase 12 UI (2026-10-12): README TOC; 03 rewritten (sidebar groups, top bar, theme toggle, KPI dashboard for managers: KPIs, RPO 1.5× rule, never / not in a group, 30-day linear forecast, data reduction, lock coverage, charts; Restore menu; break-glass banner; Settings tabs); 06 Restore menu + `applies_to`; 09 new "Single sign-on (OIDC)" (Keycloak + Entra ID setup, mappings, highest privilege, no mapping = refused, MFA at the IdP, local accounts as break-glass, SSO accounts on Users); 10 toggle under Settings → Approvals, quorum actions oidc.update / ssh_key.rotate / update.apply, new audit actions; 11 Settings → Alert delivery + test, alerts.json as fallback, `break_glass` alert; 13 Settings → Updates; 14 new "Break-glass" (console `nexus-setup recover-admin` per contract); 04/07/02 appliance SSH keys tab; 05/01/12/15 (SSO errors, theme, Restore menu) adjusted; Status notes where the backend is still landing; all image and intra-manual links checked. login-sso-error.png not referenced (shows no error banner; regenerate)
- [x] Integration (2026-10-12, real image, SELinux enforcing): `lab/e2e/ui-smoke.mjs` (admin + security officer, light + dark, 14 pages + 5 Settings tabs = 76 page views against the real API: 0 exceptions / console errors / CSP violations / API errors, also with SSO configured); `plugins.sh oidc` against Keycloak 26.4 over TLS (testbox TLS=1): settings via quorum, discovery + JWKS from the appliance through the egress allow-list, kc-alice → admin, kc-tina → tenant user `sso`, kc-nobody refused (`oidc_error=denied`), audited; `plugins.sh check`: 0 nexus AVCs. Fixed on the way: OIDC redirect URI came from the Host header, which HTTP/2 does not send (fell back to `localhost`); the IdP reaches the allow-list one scheduler tick (≤ 30 s) after saving. Claude-in-Chrome click-through not possible while the user is away (extension not connected) — replaced by the headless smoke test
  - [x] PVE end-to-end on the Phase 12 image (`e2e.sh disk`, `boot`, `setup`, `api`, `check`, 2026-10-12): scheduled backup of vm-100 + ct-200, retention, offsite, file restore of both by an operator enrolled via activation code, verify (0 corrupt), quorum (own approval refused, security officer approves), audit; 0 nexus AVCs. Lab fixed: m5-api.sh created users with a password (self-enrollment since v9), api helper died under set -e for anonymous calls
  - manual screenshots are from the seeded mock (by design, Phase 10 decision)

## Phase 13 — Operations core (started 2026-10-12; plan: docs/phase13-18-plan.md)
Cohesity comparison (docs/cohesity-comparison.md) → Phases 13–18 approved by the user (Tiers 1–3, no failover).
Parallel worktree agents (schema versions pre-assigned, renumbered on merge if needed):
- [x] 13a orphaned-snapshot retention + approved snapshot delete (no schema) — merged 2026-10-12; sweep in daily gc job, `DELETE /snapshots/{t}/{s}/{time}` → quorum `snapshot.delete` → scheduler job; tests orphan_sweep_and_snapshot_delete, snapshot_delete_refuses_locked_and_needs_approval
- [x] 13b run control — merged 2026-10-12 as catalog v14 (policies retry/blackout/sla_minutes, groups timezone/paused_until, sources maintenance_until, jobs not_before/attempt/retry_of/cancel_by/sla_alerted); catalog::schedule shared parser; runctl.rs; cancel running jobs (process groups, PVE task-stop); tests crates/scheduler/src/tests/runctl.rs, crates/web-api/tests/runctl.rs
- [x] 13c auto-protect + guest inventory — merged 2026-10-12 as catalog v13 (`inventory`, groups.mode/selector/exclude); `nexus-pve inventory`, plugin proto v1.5 TaggedGuests, dashboard unprotected list incl. PVE; tests inventory_jobs_and_auto_protect, crates/web-api/tests/inventory.rs
- [x] 13d storage accounting + quotas; 13e anomaly alert — merged 2026-10-12 as catalog v11 (`backup_stats`, `tenants.quota_bytes`); Storage page, Settings → Anomaly detection; tests backup_stats_and_anomaly_alert, quota_alerts, storage_accounting_quota_and_anomaly_settings
- [x] 13f alert lifecycle + notification rules + webhook templates — merged 2026-10-12 as catalog v12 (alerts key/tenant/count/last_ts/resolved_*/note/auto/notified_ts; cursor file replaced); catalog::alerting (hints, rules, templates); quota/anomaly keyed; tests alert_lifecycle, job_failure_resolved_by_success, rule_webhook_template_delivery, alert_ack_and_resolve, alert_rules_validation_and_secrets
- [x] all five merged (catalog v11–v14), full local suite green, CI green on the merge commits
- [x] screenshots regenerated (78); UI fixes from the review: storage bars neutral, "RPO breached" label unified
- [x] PVE e2e on the Phase 13 image (`lab/appliance/e2e.sh all`, new `phase13` step in lab/e2e/m5-api.sh): backup, restore, verify, quorum, storage figures (dedup 2.5×, compression 3.0×), inventory via the real PVE API, auto group `all` minus 200 → [100], pause, cancel of a running backup (no snapshot committed), locked delete refused; **0 AVCs**. Found + fixed: `setpgid` denied to nexus_scheduler_t (13b process groups) → every job spawn failed
- [x] plugin lab on the Phase 13 image (example plugin incl. incremental + sha256 check, PostgreSQL backup + restore to the alternate server, OIDC alice/tina/nobody), 0 unexpected AVCs; fixed: lab skip list was overwritten by later plugin steps
- [x] UI smoke on the real API: 84 page views (admin + SO, light + dark, incl. Storage and Settings → Anomaly), 0 problems; fixed: Data reduction tile empty before the first capacity sample (falls back to dedup × compression)

**Phase 13 complete (2026-10-12).** Next: Phase 14 (security and operations), then release 0.1.0-alpha.

## Phase 14 — Security and operations (started 2026-10-12)
Six parallel worktree agents (each merges main into its branch before reporting):
- [x] 14a forwarding — merged 2026-10-12 as catalog v16 (forward_events outbox, forward_state); syslog RFC 5424/5425 over TLS + HTTPS JSON, daily `audit.anchor`, audit filters + `/audit.csv`, Settings → Forwarding; lab `lab/forwarding/testbox` + `lab/appliance/forwarding.sh` (to run in the VM)
- [x] 14b diagnostics — merged 2026-10-12: `nexus-diag` (path unit, nexus_diag_t), 15 checks, redacted bundle, pre-update gate in nexus-update, Settings → Diagnostics; lab step `m5-api.sh diag` (to run in the VM)
- [x] 14c console root access — merged 2026-10-12: `console.unlock` quorum action, code shown once, `nexus-console-gate` on tty2 (nexus_consolegate_t → unconfined_t), banner, Settings → Console access; lab `lab/appliance/console-gate.sh` (to run in the VM)
- [x] 14d1 — merged 2026-10-12 as catalog v17 (users/sessions rebuild, api_tokens FK kept); combined My account page; tokens refused for expired/disabled owners; viewer role, download privilege, expiry, sessions list/revoke, timeouts, dormant accounts, login banner, management allow-list, approver-count warning
- [x] 14d2 — merged 2026-10-12 as catalog v15 (api_tokens): tokens (allow-list middleware), `nexus-tls` helper + crates/webtls, per-handshake cert reload, `cert_expiry` alerts, My account / Settings → Certificate; lab step `m5-api.sh phase14d2` (to run in the VM)
- [x] 14e reports — merged 2026-10-12 (no schema): crates/reports (protection, failed, sla, storage), `GET /reports/{type}.csv`, `settings/reports`, scheduler `report_send` jobs; Reports page
- [x] add-on: registry pull credential for the private repo (Settings → Updates; nexus-update writes /run/ostree/auth.json only during a fetch); tests test_private_registry_login_only_during_the_fetch, update_registry_credential
- [x] all Phase 14 parts merged
- [ ] NEXT (after usage limit): full suite, build image, VM labs (PVE e2e incl. phase13/phase14d2/diag steps, console-gate.sh, forwarding.sh, plugins, ui-smoke), screenshots, CI, release 0.1.0-alpha

## Phase 14 VM verification (2026-10-12)
- PVE e2e on the real image incl. steps phase13, phase14d2 (tokens, CSR → install → revert), access, diag; console gate (code once, reuse refused, recovery key, shells unconfined_t); 0 AVCs after fixes.
- Found + fixed in the VM: nexus-tls/nexus-diag could not read web-api requests (UMask 0077), init_t watch on the request files, nexus-update → nexus-diag domain transition, RestrictSUIDSGID vs setgid mkdir, diag keyd socket group, gate scope start (init_t:system start/stop) + no password agent, nexus-update tick no longer leaves a failed unit when the private registry refuses (status.json shows the error).
- Forwarding lab not yet completed (blocked behind the gate lab); to run with the Phase 15 image.

## Phase 15 — Restore and protection (started 2026-10-12)
- [x] 15b restore to a host from any file snapshot — merged (no schema)
- [x] 15c legal hold — merged as catalog v18
- [x] 15g per-tenant file index + search — merged as catalog v19
- [x] 15a+15d restore options + consistency — merged as catalog v20
- [x] 15e+15f selection + agents — merged as catalog v21 (exclude disks placeholder/omit, file filters, agent cert renewal + re-enroll, limits, parallel guests)
- [ ] labs (PVE e2e incl. legal-hold, forwarding, console gate, plugins, linux agent xhost), screenshots, CI, release 0.1.0-alpha (Phases 13–15)

## Phase 16 — Hardware + inbound firewall (2026-10-12)
- [x] 16c inbound firewall per service — merged (settings `inbound`, nft sets in_web/in_icmp, blocked attempts, `nexus-setup reset-firewall`)
- [x] 16a/16b disks, SMART, alerts, mdadm + XFS data array — merged (`nexus-disks` helper, Hardware page; metadata tier deferred)
- [x] VM finding: outgoing MLD reports were dropped + drop log flooded the console → allowed, kernel.printk 3 4 1 7
- [ ] VM labs: m5-api `firewall` step, `lab/appliance/disks.sh` (EXTRA_DISKS=5 NVME=1)

## Phase 17 — Offsite, replication, vault, tenants (started 2026-10-12)
Four parallel agents: 17a+b windows + close vault; 17c+f vault profile + tenant deactivate; 17d offsite in the UI + attach offsite copy; 17e per-tenant recovery key.

## Phase 18 — Workloads (started 2026-10-12)
Three parallel agents: 18a1 M365 item failures as warnings, unlicensed users, Recoverable Items, private/shared channels, group mailboxes, no double team sites; 18a2 M365 several app registrations, chats (opt-in), cross-tenant restore, app registration helper; 18b PostgreSQL WAL-only frequent runs + `recent` retention class, recoverable range, start/tablespace remap/LSN/name targets, HA.
CI: rust job ran out of disk on the runner (PG/Keycloak testbox failures) → free space step + line-tables-only debug info (2026-10-12).

## Phase 17 complete (code, 2026-10-12)
- [x] 17a+b windows + close vault (v24), 17c+f vault mode + tenant deactivation (v22), 17d offsite in the UI + attach, 17e per-tenant recovery key
## Phase 18 complete (code, 2026-10-12)
- [x] 18a1 M365 warnings (contract v1.7) + coverage, 18a2 M365 apps/chats/cross-tenant (v1.6), 18b PostgreSQL 1.2.0 (v23, contract v1.8)
## Urgent hardening (2026-10-12)
- [x] GRUB password (ADR-013), fleecing guard, compliance clock fix + clock_skew, Splunk HEC + alert categories
- [ ] VM labs for 16/17/18/hardening (grub-lock.sh, disks.sh, firewall step, offsite-fetch, PG 1.2.0 bundle, vault mode, windows)

## Release candidate lab (2026-10-12/13, worktree at b481b7a)
- [x] e2e all (incl. phase13, legal-hold, phase14d2, access, diag), firewall lockout + console reset, console gate, console-check
- [x] forwarding lab found forward_test result dropped → fixed (5233b5a); rerun pending
- [ ] disks.sh, grub-lock.sh, forwarding rerun, offsite-fetch, config-restore.sh

## Phase 19 — Tier 3 (2026-10-13)
- [x] 19b tenant_admin, policy tiers, view as tenant, immutable tenant uid + tombstones (v25, T30–T32)
- [x] 19c mail export eml/mbox/PST (plugin contract v1.9, m365 1.3.0); Outlook import lab pending
- [x] 19a BMR/P2V (layout capture, rescue ISO, unattended P2V; lab: blank VM recovered + booted, v29, protocol v1.6)

## Phase 20 — Agent packages (2026-10-12)
- [x] .deb/.rpm x86_64+aarch64, MSI (wixl), release packages job, sign-blobs / verify --blobs
- [x] manual chapters 16 (Linux agent) and 17 (Windows agent)

## Configuration backup (2026-10-13)
- [x] sealed daily bundle to offsite targets, `nexus-setup restore-config`, wizard key b, tenant key rekey from escrow; VM lab `lab/appliance/config-restore.sh` pending

## Phase 24 — Endpoint UIs (2026-10-13)
- [x] 24b Linux TUI + CLI (`nexus-agent tui|status|sessions|session|request-backup`, group nexus-agent-ui)
- [x] 24a protocol v1.4 + poll + local IPC (v26), 24c desktop GUI (iced, tray, nexus-agent-desktop pkg, MSI), 24d fleet enrollment + CSV bulk (v27)

## Phase 21 — Security and ransomware (2026-10-13)
- [x] 21a anomalous snapshots, file-level change signals, snapshot diff, sparklines (v28)
- [x] 21c passkeys (WebAuthn second factor, v31, T37)
- [x] 21b incident mode, posture checks, session cap, DEK reminder (settings only, T40–T41)
- [x] 21d CVE scan (grype in release + weekly), CIS report, damaged-chunk detection + repair from offsite/primary (v32, T39, T42)
- [x] 21e YARA scan in the restore micro-VM + scan-first restores, Entra ID export (m365 1.4.0, v33, T43) — Phase 21 complete (code)

## Phase 25 — Recovery assurance (2026-10-13)
- [x] restore tests (isolated instant recovery + guest-agent checks), recovery plans, readiness checks, DR report (v34, T44); PVE lab `m5-api.sh restore-test recovery-plan` pending

## Runner note (2026-10-13)
- CI failures on 970ede6/5233b5a were the self-hosted runner's shared rootless podman ("invalid internal status … podman system migrate") — transient, podman healthy again; not fixed on the host (would stop all containers). PG testbox now per-checkout (worktrees, runner).

## Phase 22 — Network, PVE and NAS operations (2026-10-13)
- [x] 22a network interfaces (nexus-net helper, bonds/VLAN/MTU/routes, interface-bound egress, MTU check, wizard step; T45–T46); VM lab `lab/appliance/network.sh` pending
- [x] 22b concurrency caps, read limits, restore priority, VM identity, NAS sizing/split/overlap/skipped CSV, TrueNAS existing snapshots, instant disk recovery (T50–T52); open: removable-disk offsite, store migration, small-chunk packing

## Phase 23 — Service providers and workloads (2026-10-13)
- [x] 23a billing export, per-tenant IdP, onboarding wizard, restore point simulator, keep-until, OpenAPI + nexusctl (v37, T47–T49)
- [x] 23b MySQL/MariaDB plugin (dumps, physical + binlog, PITR; T56), AD restore runbook, SQL Server/Exchange notes; open: MSSQL PITR, Exchange full-VSS, Hyper-V, Windows BMR, arm64

## Phase 26 — Edge proxy (2026-10-13)
- [x] nexus-edge relay, agent rendezvous (protocol v1.7), appliance control channel, Edges page, edge image Containerfile (v39, T53–T55); open: VM lab `lab/edge/e2e.sh`, CI edge image, edge OS updates, HA

## Final lab (2026-10-13, in progress)
- [x] All phases 13–26 merged; local gates green at 8420e13
- Fixed by the lab: image web stage copies openapi.json; restorevm stage installs yara; guest selection accepts 100/"100"; dontaudit lsblk userdb; lab cancel step uses ct-200 only, auto group name unique
- [x] `lab/appliance/e2e.sh all` on a fresh image: all 12 API steps, 0 nexus AVCs (only bootc's chcon probe)
- [x] forwarding.sh all (1..129 at both sinks, equal hashes, outage + backlog, quorum disable) and pve-nas-ops.sh all (priority, limits, identity, instant disk)
- [x] config-restore.sh backup/fresh/restore/check: bundle on A, restore on a fresh B, A's admin signs in on B, tenant keys rekeyed from the escrow, 0 AVCs on A and B. Bugs fixed on the way: keyd could not publish the config backup key (SELinux), restore renamed across /var→/etc (EXDEV), offsite kept another installation's escrow silently (now refused)
- [x] lab check lists every distinct AVC (tail -20 had hidden the keyd denial)
- [x] network.sh (apply, egress, MTU ok/mismatch, mgmt rollback/confirm), disks.sh (RAID6/XFS create, fail, replace + rebuild, alerts resolve; mdadm needs CAP_MKNOD), grub-lock.sh, restore tests + recovery plan on PVE, lab/linux enroll/backup/incr/endpoint — all enforcing, 0 nexus AVCs
- [x] lab/edge: enroll, assign (rendezvous), refuse unknown certs, backup via the edge with 7444 blocked, endpoint request via the edge (start 2 s), signed edge update 0.1.0→0.1.1, check (443+7445 only, 0 AVCs). Fixed: edge_enroll refused as "invalid tenant"; edge image build; lab config lacked edge_update_dir
- [ ] lab/linux/bmr.sh rerun on the final image
- CI on bf5e4da: all Rust tests green; `prove pve-plugin/t` failed because the runner lacked libjson-perl (installed by the maintainer)
- [x] CI: gh-runner rootless podman repaired by the maintainer (linger, store reset, XDG_RUNTIME_DIR in the runner .env)
- [ ] screenshots regenerate, tag v0.1.0-alpha (draft)

## Big lab: PVE host pve-test (2026-10-13)
PVE 9.2 with a Windows DC (dc1dev), member server (member1dev, Server 2022) and Windows 11 client; driven
through the PVE guest agent (`lab/windows/gexec.py`, no Windows passwords), dev control plane on the workstation.
- [x] Windows agent on member1dev (`lab/windows/e2e.sh 101`): MSI install (auto/LocalSystem, 3 restart actions,
  protected ACL, "not initialised" stop), enrollment (4 s, second enroll 409), VSS backup (9/9 writers, consistent,
  no shadow copies left), incremental (USN: ~1130 unchanged, 1.4 KB transferred), restore identical (68 entries:
  protected DACL + foreign owner, ADS incl. Zone.Identifier, hard links, symlinks, junction, long path, unicode,
  attributes, times), restore through a planted junction writes nothing outside, MSI install refuses in-band
  update (403), taskkill -> SCM restart, sc stop -> stays stopped
- Fixed on the way (all had never run on Windows): MSI error 2613 (wixl sequenced RemoveExistingProducts inside
  the script), service-setup lacked SERVICE_START (MSI 1722), agent refused IPv4 (Windows IPV6_V6ONLY default),
  VSS GetSnapshotProperties returns S_OK with an empty struct on Server 2022 -> agent crashed in wcslen(NULL)
  (device now via Query), API/UI refused Windows paths for sources and restore targets, desktop GUI had no icon
  and its own green theme (now the web UI palette), package-check regexes (group members, CRLF)
- [x] DC dc1dev: MSI, enrollment, VSS backup (11/11 writers), NTDS writer [ok], restored ntds.dit "Clean Shutdown"
- [x] Windows 11 client: MSI, enrollment, VSS backup, incremental, restore identical, confinement, service; fleet
  enrollment through the MSI (PURGE=1 uninstall, FLEETSECRET, scan, accept, enrolled, backup). Fixed: PURGE=1 never
  ran (wixl sequenced PurgeData after RemoveFiles, error 1721), fleet secret in the verbose MSI log (HideTarget)
- [x] arm64: emulated aarch64 Debian 13 VM on pve-test (`lab/linux/remote.sh 10.2.34.210`): arm64 .deb installs,
  enrollment, backup, restore identical (1237 entries)
- [ ] GUI on Windows checked by the maintainer (new icon + web UI palette), MSI major upgrade (needs a bumped
  version), appliance VM on pve-test backing up the Windows VMs through PVE
