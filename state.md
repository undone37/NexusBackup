# Project State

_Last updated: 2026-10-23_

The lab and progress log: what was done, with numbers, dates and commits. **Open work is tracked in GitHub issues**
since 2026-10-23 (one epic per open phase: #18 to #26; the plan.md Phase 39 backlog is epic #21); open entries
below point to their issue.

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
- [ ] (#61) Real Hetzner Storage Box run: plan.md Phase 39 L1

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
- [x] ~~Make the ghcr.io package public~~ — decided 2026-10-12: repo + package stay private for now; test appliances need a pull credential (read:packages) for updates (Phase 14 add-on) (obsolete: repository and package public since 2026-10-21)
- [x] 2026-10-21 (maintainer decision): repository and ghcr.io images go public; all workflows moved from the
  self-hosted runner to GitHub-hosted `ubuntu-24.04` first (a public repository would run fork pull requests on the
  self-hosted runner). History checked for secrets before: only marked test keys, generated test certificates, AWS
  documentation example keys and a test TOTP seed. Maintainer: flip both visibilities, remove the self-hosted runner
  from the repository settings.
- [ ] (#50) Offline key ceremony + standby key before beta: plan.md Phase 39 S1
- [x] 0.2.0-alpha (2026-10-21): tag `v0.2.0-alpha` (a3f453cb) failed in the image build (slim.sh bind mount, exit 126
  under SELinux on the runner), `v0.2.0-alpha.1` (93b7d364) at the rechunk step (crun will not create a mount target
  through the base image's /home -> var/home link), `v0.2.0-alpha.2` (805db64d) in iso.yml (bootc-image-builder:
  "no dnf in container"; its draft holds image, CVE report and packages but no ISO). Fixed; `v0.2.0-alpha.3`
  (d9a0da0d) with dnf kept in the image: release.yml (CIS gate passed) and iso.yml green, draft complete (appliance
  ISO 1.55 GB, edge ISO 1.83 GB, rescue ISO, packages, SBOM, CVE report). Maintainer: sign and publish alpha.3;
  decide on the three unreleased tags and the alpha.2 draft.

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
- [x] Release 0.1.0-alpha tagged (2026-10-15); the VM labs listed here: plan.md Phase 39 L2

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
- [x] Release 0.1.0-alpha done; the labs listed here: plan.md Phase 39 L2

## Phase 16 — Hardware + inbound firewall (2026-10-12)
- [x] 16c inbound firewall per service — merged (settings `inbound`, nft sets in_web/in_icmp, blocked attempts, `nexus-setup reset-firewall`)
- [x] 16a/16b disks, SMART, alerts, mdadm + XFS data array — merged (`nexus-disks` helper, Hardware page; metadata tier deferred)
- [x] VM finding: outgoing MLD reports were dropped + drop log flooded the console → allowed, kernel.printk 3 4 1 7
- [ ] (#62) VM labs (firewall step, disks.sh): plan.md Phase 39 L2

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
- [ ] (#62) VM labs for 16/17/18/hardening: plan.md Phase 39 L2

## Release candidate lab (2026-10-12/13, worktree at b481b7a)
- [x] e2e all (incl. phase13, legal-hold, phase14d2, access, diag), firewall lockout + console reset, console gate, console-check
- [x] forwarding lab found forward_test result dropped → fixed (5233b5a); rerun pending
- [ ] (#62) disks.sh, grub-lock.sh, forwarding, offsite-fetch, config-restore.sh: plan.md Phase 39 L2

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
- [x] lab/linux/bmr.sh with the current code: backup 332 s, check-in 13 s, recover 32 s, first boot 11 s; host name, 2723-file sample, LVM thin pool + XFS layout equal, PostgreSQL running
- CI on bf5e4da: all Rust tests green; `prove pve-plugin/t` failed because the runner lacked libjson-perl (installed by the maintainer)
- [x] CI: gh-runner rootless podman repaired by the maintainer (linger, store reset, XDG_RUNTIME_DIR in the runner .env)
- [x] Tag v0.1.0-alpha (draft) done 2026-10-15; whether the screenshots were regenerated for it is not recorded

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
- [ ] (#64) Windows GUI check, MSI major upgrade, appliance backing up the Windows VMs: plan.md Phase 39 L4
- [x] Appliance VM 201 on pve-test (`lab/pvehost/deploy.sh`: upload, create, tunnel, setup with static 10.2.34.211,
  PVE source): plugin package on the host, storage `nexus` (fleecing local-zfs), user `nexusbackup` with the
  forced-command key, token `nexus@pve!backup`. VM 200 (arm64) backed up and restored as VM 210, boots to login.
- Found on the PVE host and fixed: plugin reported storage API 11 on PVE 9.2.21 ("older storage API" warning; API 16
  reviewed); manual granted the PVE roles to the token only (privsep = intersection: empty inventory); VMs whose disks
  have `backup=0` ended "ok" with only EFI/TPM state (now a warning); every full VM backup read each block twice
  (chunkstore merged ranges); zero/unallocated regions were transported (now skipped via base:allocation);
  no live progress for running jobs (now: progress lines, live log, job page + list)
- [x] byte-exact restore check (`lab/pvehost/verify.sh exact`, stopped VM 200, zvol sha256 equal) before and after
  the zero skip; zero blocks: base:allocation does not help on zvol/LVM (QEMU reports no holes on block devices),
  the node helper's `zeromap` scans the frozen export locally: VM 200 read 1.51 GB instead of 17.25 GB, restore identical
- [x] Windows VMs 100-102 (3 x 120 GB) through PVE, zero skip on: full 3774 s (sequential) -> 2052 s with 4 chunk
  workers + one NBD request per chunk; 79.5 of 386.6 GB read (zero map: ~80% of the disks empty); incremental 108 s
  (1.95 GB read). Timing line: 28-37 ms per 4 MiB read waiting for the node, 67-89% of the time -> latency-bound;
  pipelined NBD reads (8 in flight) built next
- Fixed on the way: incrementals failed on EFI disks ("can't get block status": base:allocation only for full
  reads, full-read fallback); the node's zero scan had no progress; snapshot rows were "not local" until the next
  store scan (restore test 404 right after a backup); job logs had no times (time marks + column)
- [ ] (#65) Restore test VM 101, pipelined reads byte-exact + timing: plan.md Phase 39 L5

## Live job progress (2026-10-13)
- [x] Connectors print `progress {json}` lines on stderr (`chunkstore::progress`: item/part/done/total/entries/end,
  `Meter` at most every 2 s); nexus-pve backup-all (per guest, per disk with the bytes to read, CT tar stream,
  restores per served disk), nexus-agentctl backup (scan entries, transfer bytes), nexus-truenas (per dataset)
- [x] Scheduler: output split into lines, progress lines kept out of the log and aggregated (current item, items
  done, item/overall %, rate over ~10 s, ETA); writer thread per job writes `jobs.live_log` + `jobs.progress`
  (catalog v40) every 2 s; final log/result unchanged; crash recovery keeps the partial output
- [x] API `progress` on /jobs and /jobs/{id} (log so far while running); UI job page Progress card, jobs list
  Progress column; mock + manual 03 (jobs-running.png, job-running.png)
- Found on the way: `store_image_extents` read every chunk twice on a full read (no base: dirty extent and the
  "grown" range overlapped); now each byte once (test `dirty_extents_read_each_byte_once`)
- [x] Progress lines for nexus-nas and the plugin host: plan.md Phase 39 C7 (done 2026-10-21)

## Phase 27 — Agent updates pushed from the appliance (2026-10-14)
Contract + deviations: docs/agent-update-plan.md "Implementation"; decisions plan.md Phase 27. Catalog v41, protocol v1.8,
threat model T57–T59, alerts `agent_update_failed` / `rollout_paused`, quorum action `agent.rollback`.
- [x] 27a protocol v1.8: capability `update2`, host facts as caps (`arch=`, `install=`, `gui=`), `UpdateBegin/Ready/Chunk/
  Commit/Staged/Status/State` (tags 49–55); v1.7 and older keep the single-frame `Update`
- [x] 27a release store (`agent_core::releases`): `/usr/share/nexus/agent/<v>/` + `/var/lib/nexus/agent-releases/<v>/`,
  signed `manifest.json` (`agent_proto::release`: per-OS/arch/install selection, desktop package with deb/rpm);
  `release/packages.sh` builds the tree + `nexus-agent-release-<v>.tar`, `release/sign.sh sign-agent-release`,
  `release/verify.sh --agent-release`, release workflow ships the signed tree via `os/agent-release/` (image)
- [x] 27a agents: checks (self_update off, busy 409, own package type, manifest + artifact signatures, newer or approved
  rollback >= `ROLLBACK_FLOOR`), staging, `update-pending.json` / `update-state.json` (reported by `UpdateStatus`), start
  watchdog (third failed start puts `.prev` back; Linux + Windows), Linux deb/rpm via `systemd-run --unit=nexus-agent-update`
  (apt-get / dnf / rpm, fixed argv, result from the unit + journal of this attempt), Windows MSI via detached msiexec (result
  from the verbose log), `self_update = auto` default
- [x] 27a appliance: `nexus-agentctl update` with the store (plan, chunked push with progress, reconnect check 2/10 min,
  `update-result`), agent rows with arch/install/gui/protocol/tags/update state, installer downloads via download tokens
- [x] 27b rollouts: scope (all/tenant/group/OS/tag/agents), canary count or %, soak, concurrency, failure threshold (count, or
  share from 5 finished), pause/resume/cancel (audited), busy retried, unreachable / blacked-out agents held, maintenance windows
  (UTC), agents already on the target skipped; alerts; API + UI (Agents > Updates)
- [x] 27c automatic mode per tenant/group (one rollout per release and scope, every 10 min); rollback rollouts gated by quorum
  `agent.rollback` (rejected/expired → `rejected`)
- [x] Tests: agent-proto (tags, limits, selection, host facts), agent-core (version/rollback rules, announced checks, watchdog,
  package settling, store), agent-linux (package argv without shell, unit states, swap/restore; interop: chunked update of the
  real agent by the real agentctl incl. refusals), agent-windows (msiexec argv, MSI log parsing UTF-16, restore), catalog
  (migration v41, scope/waves/skips, settings), web-api (upload/verify/list/delete/download, tags, roles, rollout states,
  approved rollback, settings, tenant_admin route table), scheduler (release choice, waves, busy retry, holds, threshold +
  alerts, windows, automatic mode, rollback approval/rejection)
- [x] Lab (container, `lab/linux/update-deb.sh`, run 2026-10-14): real musl agents 0.1.0/0.1.1 as .deb (nfpm), release signed
  with the TEST key by `release/sign.sh sign-agent-release` (cosign) and verified, Debian 13 with systemd in rootless podman:
  0.1.0 -> 0.1.1 in-band via apt-get in the transient unit, postinst restart, update state `ok` in 6 s; same version refused;
  a signed 9.9.9 .deb with an unmet dependency: apt-get exit 100 reported as `failed` with the apt output, agent stays on
  0.1.1 and keeps serving. The failure log holds only this attempt (journal by invocation id).
- [ ] (#66) Linux agent update labs: plan.md Phase 39 L6 Partly done 2026-10-24 (appliance 0.0.32-dev, `lab/pvehost/agent-release.sh`,
  TEST-signed releases 0.1.1 -> 0.1.2): .deb on debian-13 (7 s), .rpm on alma-10 (5 s), bundle install with
  install.sh and the binary swap on debian-13 (10 s); the packaged production-key agents refuse TEST-signed
  releases. Watchdog: a signed binary that cannot start at all (0.1.4, an ELF that exits) was swapped in and
  never reverted (the watchdog runs inside the new binary): #93. Open: desktop package with the GUI running,
  arm64 (needs aarch64 packages), an edge-connected laptop.
- [ ] (#67) Windows agent update labs: plan.md Phase 39 L7
- [x] (#68) Image with a signed agent release, SELinux checks: plan.md Phase 39 L8 Done 2026-10-24 (appliance 0.0.32-dev built with
  a TEST-key-signed agent release 0.1.1 in os/agent-release, `lab/pvehost/agent-release.sh`): the image's release
  listed as signed; a signed 0.1.2 uploaded through the API and listed as signed; the packaged 0.1.0 agent on
  debian-13 (production key pinned) refuses the TEST-signed release ("does not verify with any pinned release
  key"); with the image's 0.1.1 test-key .deb installed it updates to 0.1.2 in 7 s (chunked .deb). SELinux
  enforcing, no denial for nexus_agent_release_t, nexus_agentctl_t or nexus_webapi_t; no denial at all since the
  0.0.32 boot (the init_t rules of f4262897 still to be seen at the next update and shutdown).
## Phase 28 — Commvault Tier 1 (2026-10-14)
- [x] catalog v43 (`groups.scan_schedule/scan_budget_min/file_hashes`, `snapshots.scan_state`, `hash_lists`,
  `tenant_lockdowns`, `login_devices`, `users.email`; migration test), alert kinds + hints, threat model T62–T63
- [x] scheduled YARA scans per group (scheduler `threat.rs`, newest unscanned snapshot per source, `scan_hit`),
  scan verdict per snapshot, "latest clean" prefers scanned-clean (scheduler + UI), recovery calendar (Snapshots)
- [x] IOC hash hunt: name index v2 with SHA-256 (chunkstore), store hash cache + carry-over + read-back, agents
  hash while reading (`CAP_FILE_HASH`: `ScanHashed`/`EntryHashes`, old agents keep working), NAS/TrueNAS/plugin
  connectors, CT index (`ct-files … index hashes`); hash lists API + settings tab, `hash_hunt` job, Hash hunt page
  with restore / hold actions, `hash_hunt_hit`
- [x] tenant lockdown (holds, pauses, sessions/tokens ended, sign-in blocked, changes/deletes/overwriting restores
  refused in web-api and scheduler, lift by approval `tenant.lockdown.lift`), Tenants page
- [x] new-device sign-in notice (`login_new_device`, SIEM via the alert triggers, mail to the account's address),
  My account: sign-in devices + e-mail
- [x] tests: chunkstore (v1/v2, fresh/carried/computed), agent-proto/agent-core/agent-conn (fake agent with and
  without the capability, hostile hash lists), pve (CT index hashes), scheduler `tests/threat.rs`, web-api
  `tests/phase28.rs` + tenant-admin route classification; mock, manual 03/05/06/09/11/14, 7 new screenshots
  (scene `threat`), ui-smoke pages
- [ ] (#69) Scan, hash hunt, lockdown, new-device mail labs: plan.md Phase 39 L9
- [x] Remaining VM disk file hashes (btrfs, FAT, exFAT): plan.md Phase 39 C1 (done 2026-10-21)

## Phase 29 — NetBackup Tier 1 (2026-10-14)
- [x] catalog v44 (`groups.full_read_days`, `full_reads`, `snapshots.clean_point`, `login_hours`,
  `users.risk_since/risk_until/risk_reason`, `sessions.step_up_at`; migration test), `catalog::fullread`,
  `catalog::incident` (freezes, production-restore rule, flagged snapshots), alert kinds + hints, threat model T64–T65
- [x] scheduled full read: due per source (staggered), connector configs patched (PVE whole-disk read with the reused
  bitmap as the "reported" set, agents without base, NAS without cache, TrueNAS against the zfs-diff plan),
  `chunkstore::drift`, `full-read` lines -> `full_reads`, job log line, `change_tracking`; group setting, list,
  dashboard summary
- [x] restores of flagged snapshots to production: approval `restore.infected` (web-api, scheduler poller and
  plan-time re-check), administrators only with approvals off, `/restores` refuses flagged items without link_down
- [x] scan back: `POST .../scan-back`, scheduler drives stop-on-match scans newest first, `clean_point`, restore VM agent
  `stop_on_match`, `nexus-pve scan --stop-on-match` and manual `scan-back`
- [x] freezes: incident (configuration middleware, deletions, restores) and lockdown (deletions, restores), banner in
  `/auth/me`, `incident.freeze.lift`; scheduler trims retention/GC/offsite pruning, replica `prune: false`
- [x] risk signals: unusual sign-in hour, weakening burst, bulk deletes, download volume; `user_risk`, 428 step-up,
  `POST /auth/step-up`, `GET /risk`, clear
- [x] tests: catalog (v44, incident, fullread), web-api `tests/phase29.rs` + freeze/risk unit tests, scheduler
  `tests/phase29.rs`, chunkstore/pve/agent-conn/nas/truenas/restore VM agent; UI, mock, manual, screenshots, ui-smoke
- [ ] (#70) Full read, scan back, passkey step-up labs: plan.md Phase 39 L10
- [x] Risk rule + thresholds as settings: plan.md Phase 39 S2; flagged BMR/P2V and downloads: S3 (done 2026-10-20 and 2026-10-21)

## Phase 31 — Guest file index without the micro-VM, instant search (2026-10-14)
- [x] 31a `nexus-fsindex` (crate fsindex): GPT/MBR (+EBR), LVM2 linear/striped/mirror/raid1, ext2/3/4 (ext4-view),
  NTFS (ntfs), FAT (fatfs), exFAT (own); per-volume state + reason (BitLocker, LUKS, ReFS, LDM, Storage Spaces,
  md, ZFS, LVM thin, missing PV, corrupt table, limits); fstab / Windows `C:` / label / vol<N> mapping; helper
  sandbox (no_new_privs, rlimits, seccomp, SELinux `nexus_fsindex_t`), pipe protocol, parent validates everything;
  per-volume reuse by chunk ids; micro-VM fallback for XFS/btrfs/ZFS; `nexus-pve files … index` uses it
  (`index-vm` = old walk); sealed side file `fsindex`; live progress per volume
- [x] Tests with real images built locally without root (mkfs.ext4 -d, mkfs.vfat+mtools, mkntfs+ntfs-3g, mkfs.exfat
  + crafted entries, sgdisk, mkfs.xfs, mkswap, hand-written LVM metadata incl. striping): crates/fsindex/tests;
  store integration with reuse/change (crates/pve/tests/fsindex.rs); micro-VM comparison (ignored test
  `fsindex_matches_micro_vm_listing`): identical entries for ext4, NTFS, vfat, ext4-on-LVM, 0.14 s vs 8.8 s;
  with fallback all seven file systems equal
- [x] Fuzz targets (crates/fsindex/fuzz, lab/fuzz/run.sh, seeds in mkseeds.py): part_table, lvm_meta, ext4_walk,
  ntfs_walk, fat_walk, exfat_walk, helper_frames, disk_walk; 5 min each locally; findings fixed + regression tests
- [x] 31b `nexus-index` (crate fileindex): Tantivy in a sealing Directory (256 KiB sealed blocks + sealed table,
  bounded decrypted block cache, idle readers closed), file-version documents, append / per-source rebuild, rules
  (defaults keep /var), Windows agent drive letters, VM guest paths; socket protocol (crate index-proto);
  benchmark 30 x 200k files: first ingest 23 s, 428k versions, 32 MiB sealed, searches 14-200 ms, append 1.5 s
- [x] catalog v42 (snapshot_index, groups.index_rules, group_sources); scheduler: pending/indexed/partial/failed per
  VM/CT snapshot, nudges, rules push, `index_backlog` / `index_space`; web-api `GET /files/search`,
  `/files/index-status`, `POST /files/index/rebuild`, `GET|PUT /groups/{id}/index-rules`, index state on /snapshots,
  503 + UI fallback to the job search; OpenAPI; nexusctl `files search`; tokens: search + status readable
- [x] OS: nexus-index.service, SELinux `nexus_index_t` / `nexus_fsindex_t` + neverallows (policy built and
  neverallow-checked in the AlmaLinux 10 selinux stage, file contexts verified with matchpathcon), sysusers,
  tmpfiles, Containerfile, setup enables nexus-index
- [x] UI: instant Find files with filters + version timeline, group search scope, Storage index section, snapshot
  index chips, alert texts; mock; manual 03/05/06/11 + screenshots; ui-smoke
- [x] Lab on the PVE host (2026-10-14, appliance image built from main and deployed as VM 201, SELinux enforcing,
  nexus-index in `nexus_index_t`): file index of the Windows DC, member server (Server 2022) and Windows 11 client
  without the micro-VM: EFI vfat + both NTFS volumes indexed, system volume mapped to `C:`, 391k / 391k / 258k
  entries in 150-290 s per snapshot (vTPM and EFI disks skipped as "no known file system"); Debian VM 200 ext4 `/`
  + vfat `/boot/efi` (26k entries, 1 s). Instant search over 6 snapshots: 50-70 ms, guest paths
  (`C:/Users/Admin/Desktop/desktop.ini`), the default scope keeps 6916 of about 1.4 M entries (system folders out)
- [ ] (#71) File index labs: plan.md Phase 39 L11 (per-directory reuse was done in 31c) Partly done 2026-10-24 (appliance 0.0.32-dev, `lab/pvehost/fileindex.sh`,
  PVE VM backups with index-files on, sandboxed parser, no micro-VM): alma-10 XFS on LVM 29,760 entries in
  0.98 s; leap-16 btrfs 59,951 in 1.19 s; debian-13 ext4 39,635 in 1.10 s; the instant search finds
  /etc/os-release in each snapshot. Windows (jobs of the lab groups): VM 101 (Server 2022, 120 GiB) 391,887
  entries in 31.8 s with 74,109 directories taken over from the previous index; VM 242 unchanged NTFS volume
  reused, 125,456 entries in 0.99 s; the VMware snapshot of nx-cbt (ext4) 38,258 in 1.4 s. Open: LVM thin and
  LDM guests, several groups at once on a second PVE node.
- [x] File index jobs report a percentage (entries of an estimated total per volume, 2026-10-14); lab: member
  server C: rose from 5.6 % to 98.1 % against an estimate of 390,899 entries (previous snapshot's count)
- [x] 31c per-directory reuse (NTFS): records of what each directory's listing read (side file `fsindex-dirs`),
  unchanged directories taken over from the previous name index without reading them, also with parallel helpers;
  ext4 excluded (ext4-view caches blocks, read sets would be incomplete); tests: a second listing with the history
  lists the same and reads less, a dropped record is listed again, NTFS records always have their read set;
  the $MFT record (read by crate ntfs on every lookup) is left out of the read sets, the MFT's data runs are the
  layout signature instead. Lab (Windows Server C:, 391k entries, 94,230 directories): second snapshot 77,911
  directories taken over, 2,841 chunks decrypted instead of 7,176, 19 s instead of 33 s (first snapshot of the
  day 150-217 s before Phase 32)
- [x] 31c Windows drive letters from the SYSTEM hive (`MountedDevices`): own read-only regf parser
  (`fsindex::regf`), hive read in place on the system volume by helper 0, matched by GPT partition GUID / LDM volume
  GUID (`DMIO:ID:`) or MBR signature + offset (`win_id`); MBR partitions get `PARTUUID=<sig>-<nn>`; tests: unit
  (hostile hives, ri loops, byte flips), real GPT + MBR disks with mkntfs/ntfs-3g (C:, E:, F:); fuzz target
  `regf_hive`
- [x] 31c XFS walker (`fsindex::xfs`, own parser): v4/v5 (CRCs checked), inodes by number, big time stamps,
  64-bit extent counters, local/extent/B+tree forks, short form/block/leaf/node/B+tree directories, bounded;
  split between helpers and per-directory records + takeover as NTFS; the micro-VM fallback only for btrfs/ZFS;
  tests: mkfs.xfs protofile images v5 4k, v5 1k (directory blocks of 4 fs blocks), v4 ftype=0, all five directory
  formats, mount `/` from its fstab; hostile XFS volume fails alone; fuzz target `xfs_walk` (+ disk_walk seeds)
- [x] 31c LVM thin volumes: dm-thin pool metadata (superblock, top-level and per-device mapping B+trees, checksums,
  key order, depth/loop/run bounds) -> segments on the pool's data LV, unmapped blocks read zeros; pool LV
  `skipped`; external-origin thin LVs reported; volume key hashes the mapping; test with hand-written LVM + pool
  metadata and an ext4 in reverse block order (damaged node, missing device); fuzz target `lvm_thin`
- [x] 31c btrfs walker (`fsindex::btrfs`, single device): superblock, sys chunk array + chunk tree, root tree, fs
  trees, default subvolume first (as the micro-VM mounts it), subvolumes/snapshots as directories, CRC-32C nodes,
  bounded; no directory records (copy-on-write: read sets always change), split between helpers; multi-device btrfs
  -> probe "unsupported" -> micro-VM fallback; tests: mkfs.btrfs --rootdir with nested subvolumes, default
  subvolume + 4 KiB nodes, zstd; hostile btrfs fails alone; fuzz target `btrfs_walk` (sparse disk records)
- [x] 31c Windows dynamic disks (`fsindex::ldm`, as the kernel's ldm.c): private header, TOCBLOCK, VMDB, VBLKs
  (fragments), disks/volumes/components/partitions; simple + spanned (+ mirrored by first plex) volumes as
  `ldm/<name>`, striped / RAID-5 / missing disk reported; volume GUID as `win_id` (hive drive letters apply);
  test: two MBR disks, NTFS system volume (C: from the hive), ext4 spanned over both disks (D:), striped + RAID-5,
  second disk missing; fuzz target `ldm_db`. Open: GPT dynamic disks unverified against Windows; the micro-VM does
  not assemble dynamic volumes (restore through the Windows agent)
- [x] 31c owners: NTFS owner SID ($STANDARD_INFORMATION security id -> $Secure:$SDS), ext4/XFS/btrfs `uid:gid`;
  entry frame `extra` byte (owner, later hash), validated by the parent; name index v3 (`names3:` context, owner
  table + per-entry index, written only with owners; readers v3 -> v2 -> v1; mismatching owner columns refused);
  carried over on directory takeover / volume reuse; fileindex stores the owner per version and returns it in hits
  (`versions[].owner`, schema change = one rebuild); tests: chunkstore v3 round trip + older contexts refused +
  forged columns, ext4/NTFS (ntfs-3g `permissions`) owners, $SDS parser with mirror blocks and byte flips, frame
  round trip + hostile owners, pve owners after reuse, fileindex hit owners. Open: owner search filter (web-api
  parameter + UI), SID / uid names
- [x] 31c content hashes for VM disk files (groups with `index_files` + `file_hashes`): scheduler queues
  `hashes` for VM snapshots too, `files … index hashes`; helpers hash NTFS `$DATA` (not compressed / encrypted /
  dedup stubs), ext4 (ext4-view reader) and XFS (extents, holes as zeros), budget per helper (half the listing time,
  1 TiB), counters per volume and in the job result; hashes in the entry frame (files only) -> name index v2/v3;
  `hashed` on directory records and volumes: a hashing listing takes over / reuses only hashed ones; tests: SHA-256
  of known files on ext4/NTFS/XFS with 1 and 3 helpers, budget too small, pve no-hash -> hash -> reuse with hashes,
  scheduler args/queue; the walk fuzz targets (ntfs/ext4/xfs) hash too. Fuzz findings fixed (both inside the
  crates, contained by the helper's rlimit before, now refused up front; regression inputs in tests/regress): an
  NTFS `$INDEX_ROOT` with a huge index record size, an ext4 superblock whose block count made `ext4-view` allocate
  25 GB of block group descriptors (file system larger than its volume); `/etc/fstab` is read only up to 64 KiB
- [ ] (#52, #53, #71) 31c rest: plan.md Phase 39 C1, C2, C3, L11
- [x] Lab 10/11 (2026-10-15, merged main, Windows Server VM 101): C: from the SYSTEM hive, owners on the NTFS system
  volume (1,225 security descriptors, all 390,926 entries owned; web-api dropped them from search hits: fixed),
  file index 33.9 s first / 15.5 s next (78,202 of 94,230 directories taken over), full backup 388 s, incremental
  25 s, restore test passed (130 s boot; one earlier attempt timed out at 900 s while the host was loaded, rerun ok)


## Phase 32 — Throughput: more at once (2026-10-14)
Decision (maintainer): backups stay on vzdump, which runs one backup per PVE node at a time (global vzdump lock),
so per node the guests run one after the other; parallelism comes from nodes, groups and background work.
- [x] Measured on the PVE lab host (Windows Server, incremental): 26 s per guest = 16 s vzdump preparation
  (fleecing images, guest-agent freeze, NBD export), 4 s reading, the rest commit and teardown: about 140
  incremental guests per node and hour; the appliance side is not the bottleneck
- [x] scheduler: `max_parallel` default 2 per CPU (8..=32, was 4), `max_background` (CPUs / 2, 2..=8) for
  file_index / snapshot_scan / verify / hash_hunt / file_changes / snapshot_diff so backups always find a slot;
  PVE backup and retention keyed per group (was per source): the groups of one cluster run side by side
- [x] nexus-pve: lock files per node and per guest across all jobs (`pve::parallel`, `File::try_lock` in the
  scheduler's private /tmp): one backup per node (no worker waits inside a vzdump task) and a guest in two groups is
  never backed up twice at once; every backup-all goes through the runner
- [x] new groups: 4 guests at once (was 1); existing groups keep their value; UI hint + manual 05
- [x] file index: LRU chunk cache of 128 chunks (was a FIFO of 32), log line with the chunks read from the store;
  lab: Windows Server C: 82-90 s (was 150-217 s), 4779 chunks decrypted per run
- [x] file index walks in parallel: one sandboxed single-threaded helper per CPU (up to 8) splits the NTFS / ext4
  trees (`fsindex::Part`, hash of the first two path components), the parent serves them on one thread each with
  a shared LRU cache (chunks decrypted in parallel) and merges; test: 3 helpers list exactly what 1 lists
- [x] lab appliance VM: 16 GiB RAM, 8 CPUs (chunk workers follow the CPUs, up to 8)
- [ ] (#71) File index timing labs: plan.md Phase 39 L11
- [x] Per-directory reuse of Windows volumes: done in 31c (lab timing: plan.md Phase 39 L11)

## Phase 30 — NetBackup Tier 2 (2026-10-14)
Scope: docs/netbackup-comparison.md "Tier 2", one item after the other (code, tests, docs, UI, manual). Catalog v45
(`SCHEMA_V45`, all Phase 30 schema changes), threat model T66-T69.
- [x] 1 backup-duration and dedup-rate anomalies: `nexus-stats` carries `secs` (snapshot time to commit), agents
  report the bytes they read as `read`; `backup_stats.secs`, `anomaly_sensitivity` (catalog::anomaly); scheduler
  dedup-rate rule (new / read, critical) and duration rule (warning alone) next to the change rate, per-source
  sensitivity low/medium/high; one `anomaly` alert per run, every finding flags the snapshot;
  `PUT /stats/sensitivity` (lowering = approval `anomaly.sensitivity`), trends with read/secs/sensitivity; UI
  (Change trends: duration sparkline, sensitivity select), mock, manual 11, docs/ransomware-signals.md
- [x] 2 just-in-time role elevation: `users.eligible_role` (admin / security officer for appliance-wide local
  operators and viewers; granting = approval `user.update`), `sessions.elevated_role/elevated_until`
  (catalog::elevation); `POST /auth/elevate` (15 min..8 h, reason, password + TOTP or passkey; passkey only when the
  passkey policy covers the role), optional approval `role.elevate` (setting `elevation.approval`, switching it off =
  approval `security.elevation`), `POST /auth/elevate/end`, sign-out / expiry / account change end it; info alert
  `role_elevation` (resolved at the end, scheduler housekeeping for expired ones), audit `role.elevate(_end)`;
  `/auth/me` `elevation`, `/users` `eligible_role` + `elevated_until`; posture check `posture.standing_admins`
  (nexus-diag, > 2 standing admins); UI: Elevate button + dialog, banner with End now, Users page eligible role,
  Settings → Security "Role elevation"; mock; manual 09/11/15, docs/control-plane.md "Role elevation", T66
- [x] 3 instant rollback of a PVE VM: option `rollback` of "replace original" (VM restores, approval
  `restore.replace`, `--rollback`), `pve::rollback`: identity / disk layout check, pause, pre-rollback incremental
  backup that must reuse every dirty bitmap (`BitmapGone` otherwise: VM resumed, full replace), stop, tag
  `nexus-rollback`, `rollback-begin` (PVE lock `rollback`), changed chunks by fixed-index chunk ID, all disk
  sessions opened and size-checked first, pipelined NBD writes + flush (`nbd::Client::write_many`/`flush`),
  `rollback-end`, untag, start; interrupted rollbacks resume; full replace as the fallback. Node: helper commands
  `rollback-begin|nbd|end` forward to the new root service `pve-plugin/rollback` (socket-activated,
  `nexusbackup-rollback.socket`, qemu-nbd with the storage's format, config lock, tag + lock checks, one writer
  per disk); deb package with units. Tests: crates/pve/tests/rollback.rs (orchestration against an in-memory
  node: changed chunks only, fallbacks, resume; the real helper + root service (stub PVE modules) + qemu-nbd +
  NBD client end to end), crates/nbd/tests/qemu.rs (writes), pve-plugin/t/rollback.t, scheduler + web-api
  tests; UI restore dialog option, mock, manual 06, docs/pve-connector.md "Instant rollback", T67
- [ ] (#72) Instant rollback lab: plan.md Phase 39 L12. ZFS done 2026-10-24 (appliance 0.0.31-dev, PVE 9 host
  pve-test, nexusbackup-pve 0.1.0 with nexusbackup-rollback.socket active, `lab/pvehost/rollback.sh`): debian-12
  VM 224 (16 GiB on vmpool) backed up running, 300 MB junk + marker written, rollback approved by the security
  officer: the paused VM's pre-rollback snapshot 95 changed chunks (380 MB, 9 s), 95 of 4096 chunks written back,
  job 38 s, lock and tag removed, no fallback VM; the disk equals a plain restore of the snapshot (sha256), the
  guest boots without junk and marker. Windows the same day: a full clone of VM 242 (Windows Server 2022, 40 GiB
  SATA, VM 295), junk and marker through the guest agent: pre-rollback snapshot of the paused guest 412 chunks
  (1.7 GB, 21 s), 412 of 10240 chunks written back, job 77 s, disk identical (qemu-img compare), Windows boots
  with the guest agent up, junk and marker gone. Open: dir qcow2 (the host's `local` storage takes no VM images;
  needs a storage config change on pve-test), LVM-thin and RBD (no such storage in the lab).
- [x] 4 hybrid post-quantum key wrapping: `keyd::hybrid` (X25519 + ML-KEM-768, BLAKE3 combiner over both shared
  secrets, the ciphertext and the recipient; XChaCha20-Poly1305; `NXHYB2` magic; ML-KEM keys derived from the
  existing X25519 secrets), RustCrypto `ml-kem` 0.3 + `curve25519-dalek` 4 (both already in the tree via russh:
  no new crate, `cargo deny check` ok); tenant recovery escrow (new keys: `public_pq` in the catalog,
  `tenant-recovery-pq`), replication DEK exports (`keyd_pub_pq` at enrollment, catalog column, `replica-pubkey-pq`,
  `export-for-pq`, retry without it at an older primary), configuration bundles (`NXCFGB2`); every opener reads
  both formats; UI chips (tenant recovery key, replication peers), manual 08/14, docs/adr.md ADR-014,
  docs/replication.md §5, control-plane, T68; fuzz target `keyd:hybrid_open`; tests in keyd, scheduler, web-api
  replication (hybrid export end to end), setup/offsite unchanged and passing
- [x] 5 second offsite copy with its own retention: `tenants.offsite.second` (remote, own lock, `gfs`;
  `PUT /tenants/{name}/offsite2`, change/removal = approval `tenant.update`, S3 secret sealed at its own location),
  own `gfs` on the first target too, retention per class = max(policies, target) (plan §2 updated, decision 5);
  scheduler: one offsite job per target (`offsite2.json`, state `<base>/.second/<tenant>`), gc/verify on both,
  `snapshots.offsite2` (catalog v45) from each target's listing, `offsite_lag` and `inventory` per target, egress to
  both, browse/fetch with `target`; UI: Second target dialog, own retention in the tenant form, Offsite 2 column,
  target choice in Offsite copy; mock; manual 07/11, control-plane "Second offsite target", T69
- [ ] (#73) Two real offsite targets lab: plan.md Phase 39 L13
- [ ] (#55, #72) Rollback of containers: plan.md Phase 39 C6; pre-rollback Windows risk: L12; per-policy offsite GFS: decided no (plan Phase 30)

## Phase 33 — Commvault Tier 2 (2026-10-14)
Scope: docs/commvault-comparison.md Tier 2 (plan.md Phase 33); catalog v46 (`SCHEMA_V46`, after v44: v45 is
Phase 30's), threat model T70–T75.
- [x] PSA ticketing: rule channel `psa` (HaloPSA OAuth2 client credentials, ConnectWise API member keys, Autotask
  API user), scheduler thread `psa.rs` (open per alert key, note on repeat/escalation/re-raise, close on resolve),
  `psa_tickets` / `psa_state`, alert `psa`, sealed secret bound to rule + URLs, egress allow-list, test opens and
  closes a ticket, tickets on the Alerts page; tests: scheduler `tests/phase33.rs` (mock HaloPSA / ConnectWise /
  Autotask servers), web-api `tests/phase33.rs`, catalog migration; UI rule editor, mock, manual 11, screenshots
  (scene `p33psa`)
- [ ] (#74) PSA ticketing lab: plan.md Phase 39 L14
- [x] tenant-side approvers: `tenant_approvals`, `quorum_tenants`, `quorum.approved_by/at`, `users.approver_since` +
  trigger (catalog v46, `catalog::approvers`), quorum co-approval (any order, refusal final, 24 h wait, approvals-off
  path, own consent, impersonation refused), `GET/PUT /tenants/{name}/approvers`, scheduler `tenant_approver` alert;
  tests: catalog unit + migration, web-api `tests/phase33.rs` (three scenarios), tenant-admin route classification,
  scheduler `tests/phase33.rs`; UI (Approvals page box and tenant decisions, Tenants page Approvers dialog + chip),
  mock, manual 10/11, screenshot (scene `p33approvers`), threat model T71
- [x] multi-appliance overview: `nexusctl fleet` (config with token_file/token_env, read scope enforced through
  `/auth/me` `token`, parallel pull of dashboard / open alerts / failed jobs, text, JSON, static HTML, `--check`);
  tests: unit (config, token file mode, rendering and escaping), `crates/nexusctl/tests/fleet.rs` (two real web-api
  routers, operator token refused, unreachable appliance); manual 09, control-plane, threat model T72
- [ ] (#75) nexusctl fleet lab: plan.md Phase 39 L15
- [x] synthetic (clean-file) restore: `synthetic_restore` job (web-api params, gates like restore_files / files_get,
  download + report tokens, `GET /jobs/{id}/synthetic.csv`), scheduler decision (`synthetic.rs`), plan + CSV,
  `chunkstore::synthetic::compose`, `nexus-agentctl synthetic` (tar/zip or `restore_tree` onto an agent); tests:
  chunkstore compose, scheduler selection unit tests + `tests/phase33.rs` (real store, faked connector), agent-conn
  `synthetic_restore_download_and_to_host` (fake agent), web-api `tests/phase33.rs`, catalog production rule; UI
  (Snapshots menu, dialog, job result with report and download), mock, manual 06, screenshots (scene `p33synthetic`),
  threat model T73
- [x] (#76) Clean-file restore lab (2026-10-24, appliance 0.0.31-dev, agent 0.1.0 on debian-13 VM 225,
  `lab/pvehost/clean-restore.sh`): 200 files backed up, then 169 encrypted and renamed to `*.locked`, one with a
  YARA marker, 20 edited legitimately, ransom notes `HOW_TO_DECRYPT.txt`; second backup, YARA scan (1 match).
  Clean-file restore of the second snapshot as a download and onto the host (new directory): all 200 files as
  expected (renamed ones and the infected one from snapshot 1, the edits from snapshot 2), no `*.locked`, no
  note; 3 s each. A note named `README_RESTORE_FILES.txt` matches none of the built-in patterns and is restored
  (as documented: the anomaly setting `ransom_notes` adds names).
- [x] cases (M365 compliance search on the name index; item metadata search not built, design in docs/m365.md):
  catalog `cases` / `case_snapshots`, `file_search` `source_prefix` + case bookkeeping, web-api `/cases` (create,
  search, hold, export, close), Cases page, mock, manual 06, screenshot (scene `p33cases`), ui-smoke, threat model
  T74; tests: web-api `tests/phase33.rs`, scheduler `tests/phase33.rs`, route classification, catalog migration
- [ ] (#54) M365 item metadata search: plan.md Phase 39 C4
- [ ] (#77) M365 case lab: plan.md Phase 39 L17
- [x] VMware: transport spike document docs/vmware-transport-spike.md (HTTPS datastore + CBT vs. nbdkit + customer
  VDDK, licensing, effort, recommendation, spike steps); not implemented by decision
- [x] VMware spike in a vSphere lab: plan.md Phase 39 C5 (done 2026-10-23, Phase 41 spike)

## Web UI usability pass (2026-10-14/15)
Goal (maintainer): every running task explains itself, states visible everywhere, rows clickable.
- [x] Jobs: subject per job (group, source, snapshot), follow-up jobs show "after #N" and are listed under their
  backup, queued jobs say what they wait for (scheduler progress `{"waiting": ...}`), file index jobs show
  entries/s and an entry-based ETA instead of 0 MB/s, parameters by name, whole rows clickable, "Hide routine
  jobs" (remembered in the browser), failed jobs: "What went wrong" card, retry link, error lines in red
- [x] Running jobs: dashboard "Running now" card, top bar indicator on every page, every action that starts a
  job links it in its notice ("Open job #N")
- [x] Lists: rows clickable (web/src/lib/rowlink.ts), More menus instead of button rows (agents, tenants,
  snapshots, sources, groups, replication), long cells wrap
- [x] Groups: last backup state + next run, auto-refresh; policies: Used by; sources: Protection column with a
  warning for sources no group backs up; snapshots: guest names; alerts: readable titles + job links;
  approvals: changed fields first; audit: details folded + target links; sessions: browser and system
- [x] Replication: queued / running syncs per tenant with job links, Sync now greyed out while one runs,
  15 s refresh; offsite uploads log per-snapshot progress
- [ ] (#57) UI review of Plugins, Hardware, Quorum, Search: plan.md Phase 39 U1

## TPM state on restores (2026-10-15)
- [x] Restore tests and instant recovery import the backed-up `tpmstate0` (`import-from` of its IR volume, plugin
  feature `copy`) instead of a fresh vTPM; TPM VMs are no longer refused for instant recovery
- [x] Lab 12 on VM 101 (PVE host): full 459 s, incremental 29 s; restore test passed with the imported TPM state
  (`drive-tpmstate0-backup` served once, "backed-up state copied to local storage", guest agent after 146 s)
- [x] (#78) Instant recovery with disk move of a TPM VM: plan.md Phase 39 L18 Done 2026-10-24 (appliance 0.0.31-dev, `lab/pvehost/instant-tpm.sh`):
  the newest snapshot of VM 101 (Windows Server 2022 with vTPM, 120 GiB; VM 101 itself only read) recovered as
  VM 296 on vmpool, NICs link_down: the TPM state copied from the backup to vmpool when the VM was created, VM
  running after 10.3 s, efidisk0 moved in 6 s, scsi0 (120 GiB) in 1729 s; afterwards every disk and the TPM
  state on vmpool, Windows at its lock screen. VM 101 has no QEMU guest agent service (the check uses a screen
  capture).

## Phase 34 — Code quality, documentation and repository workflow (added 2026-10-15)
Scope: plan.md Phase 34 (clean code, crate docs, AGENTS.md, issue forms, versioned pre-commit hooks, CI path
filters and caching, release workflow, dependency updates). In progress (2026-10-15):
- [x] 34a: workspace lints (unsafe_op_in_unsafe_fn, undocumented_unsafe_blocks, dbg_macro, todo, semicolons, redundant
  closures, inline format args), clippy --fix applied; SAFETY comments on all 134 unsafe blocks (Linux + Windows
  target), one unsound block fixed (plugin-sdk open_parent: unchecked dup); dead code removed (5 functions, the
  Locator opener seam); one is_disk_key in pve; prettier (pinned, width 120) over all web code
- [x] 34b: rustdoc clean and a CI gate; #![warn(missing_docs)] with every public item documented in the library
  crates chunkstore, keyd, retention, nbd, webtls, nftsync, edge, reports, agent-proto, agent-ui-proto,
  index-proto, plugin-proto, plugin-sdk (with examples), plugin-host, plugin-manager; docs/README.md index
- [x] 34c: AGENTS.md (replaces AGENT.MD)
- [x] 34d: .githooks (pre-commit: fmt, prettier, emojis, secrets; pre-push: clippy, svelte-check, prove), issue
  forms, PR template, SECURITY.md, Dependabot; CI: per-area jobs, main-only push, no CI on tags, kept target/,
  cargo-nextest (all binaries in parallel), container suites in a `testbox` job, weekly full run; release notes
  from the commits, asset check after the ISO
- [x] First CI run with nextest (6b1dbddd): test job about 5 min (was about 31), testbox about 15 min
- [x] Dependabot: fastcdc 5 by hand (crates/chunkstore/tests/cut_points.rs pins the cut points; identical under
  3.2.1 and 5.0.0), zstd 0.14 (drop-in); TypeScript 7 not possible yet (svelte-check 4.7.6 peer ^5 || ^6),
  major updates ignored in dependabot.yml; PRs #1, #3, #4 closed as superseded
- [x] Dependabot PR #2: replaced by #6 and then #7 (2026-10-20); #5 merged
- [x] perlcritic: plan.md Phase 39 R3 (missing_docs for binary crates: by decision module docs only) (done 2026-10-20)

## Release 0.1.0-alpha (2026-10-15)
- [x] Tag `v0.1.0-alpha` on 6b1dbddd (CI green on main; moved from ff968dc after the runner fixes: SBOM bind
  mount under SELinux, git/gh on the runner, package check line, CVE gate report-only for pre-releases)
- [x] Release workflow 38769757069: image, cve, packages green (57 min)
- [x] ISO: two failures (ftp.fau.de refused 2655 of 3393 parallel curl downloads); iso.yml now uses librepo with
  curl as the fallback (a9749d5c); run 38781214443 green (iso, rescue, assets check), all assets attached
- [ ] (#58) Maintainer signs and publishes the draft: plan.md Phase 39 R1
- [x] Runner back online 2026-10-20; CI on main green again (b44d1749)
- [x] Image, SBOM, CVE report, packages, ISO, rescue ISO attached (assets check of run 38781214443 green); signing: plan.md Phase 39 R1

## Recovery key as 24 BIP39 words (2026-10-20, ADR-015)
- [x] Appliance and tenant recovery keys are 24 BIP39 English words (256 bits + checksum); hex format removed.
  Crate `crates/recovery-key` (sha2 + zeroize only; used by keyd, catalog, web-api without linking keyd). First boot
  asks for 3 random words; four-letter prefixes accepted; errors name the word position. BIP39 test vectors pass;
  GRUB password unchanged for the same key bytes; manual Python one-liner verified. Tenant key dialog and screenshots.
- [ ] (#79) First boot with the 24-word key screen on a console: plan.md Phase 39 L19

## Phase 39 — Open items (added 2026-10-20)
Scope: plan.md Phase 39 collects the small open points of Phases 0–34 and this log (39 items: security 6, sources
and connectors 7, storage and offsite 1, web UI 1, release and CI 5, labs and tests 19). The entries above point to
their IDs. In progress:
- [x] S3 (2026-10-20, 2e7f3892): flagged snapshots: BMR/P2V refused, downloads administrators only
- [x] R4 Dependabot at night; R5 repository settings (maintainer); S6 moved to Phase 40
- Maintainer input 2026-10-20: perlcritic may be installed (runner has it), nested hypervisors on pve-test allowed,
  ISOs on pve-test: TrueNAS SCALE 27.0.0-RC1 and 25.10.7, Windows Server (SERVER_EVAL), ESXi 7.0 and 8.0

## Lab: agent test VMs on pve-test (2026-10-20)
- [x] `lab/pvehost/agent-vms.sh install`: 14 VMs (IDs 220-233) installed unattended, snapshot `clean-os`, agent
  0.1.0 (v0.1.0-alpha draft packages) installed on all: Ubuntu 22.04/24.04/26.04/26.10, Debian 12/13/testing,
  Alma 8.10/9.8/10.2, Rocky 8.10/9.8/10.2, Leap 16.0. Ubuntu 24.04 alone 11 min; the batch of 12, four at a time,
  41 min. Fixed on the way: answer file server held the ssh session (exec in a redirected subshell), background
  jobs read the VM list from stdin, ssh jump with the lab key, Agama product id `openSUSE_Leap` and timezone
  `UTC`, agent install retried while the first boot's name resolution is not up (Leap).
- [x] Agent package matrix (2026-10-20, `lab/pvehost/agent-matrix.sh`, dev control plane): the .deb/.rpm agent 0.1.0
  on all 14 VMs from clean-os: init + enrol (4-5 s), backup of /etc + a test tree (4-12 s), incremental, restore
  of the tree identical (226 entries: owners, modes, times, xattrs, ACLs, capabilities, links, sparse, fifo) on
  every distribution. Snapshots: btrfs on Leap 16 consistent; ext4 without LVM (Ubuntu, Debian) and LVM without
  free extents (Alma/Rocky kickstart default: "insufficient free space (0 extents)") read live, marked not
  consistent, as designed. Found on the way: firewalld (Alma, Rocky, Leap) rejects 7444 until the documented
  rule is added; the job log only said "No route to host", now agent-conn names the likely cause and next step
  (firewall / service not running / no answer)
- [x] Alma/Rocky 8/9/10 re-installed with 4 GB free in the VG (kickstart: root 10 GB, swap 1 GB instead of
  autopart); the matrix against the appliance VM 201 on pve-test: LVM snapshot, consistent, restore identical on
  all six (2026-10-20). Tests run on pve-test only from now on (maintainer)
- [ ] (#66) L6: agent updates (deb/rpm in-band update, bundle swap + watchdog) on these VMs
- [x] `lab/pvehost/server-vms.sh install` (2026-10-20): TrueNAS SCALE 25.10.7 (VM 240, 3.5 min) and 27.0.0-RC1
  (VM 241, 4 min; install.py unchanged) with the API answering; Windows Server 2022 Standard Evaluation (VM 242,
  14 min, SSH and QEMU guest agent). First Windows run: the agent MSI alone left PVE without the agent (no
  virtio-serial driver); now the virtio-win guest tools. All with snapshot clean-os.
- [x] TrueNAS connector e2e (2026-10-20, dev control plane, `lab/truenas/e2e.sh` all steps) against VM 240
  (25.10.7): passed in 281 s, and VM 241 (27.0.0-RC1): passed in 274 s. Both: first backup 176 MB (2026 entries in
  tank/data), incremental after the modify step 67 MB, tar + zip downloads match TrueNAS, rotation keeps one
  snapshot, 17/17 forced-command probes. Lab fixes: scripts take TN_HOST/TN_API_PORT/TN_SSH_PORT (default: the
  local QEMU forwards), provision.py creates the appliance key, disk serials for the pool, setfattr fallback
  (27.0 ships no attr tools; `data.sh xattrs` for tests/lab.rs still needs getfattr)
- [x] Windows agent e2e (2026-10-20, `lab/windows/e2e.sh 242`, default steps, MSI 0.1.0 of the release draft) on
  VM 242 (Windows Server 2022): MSI install (auto, LocalSystem, 3 restarts, protected ACL), enrol 5 s, VSS backup
  34 s (995 entries, 267 MB), incremental 440 unchanged / 0.5 MB, restore identical (70 entries incl. long path,
  ADS, hidden, links), nothing written through a junction, MSI self-update refused, service restart behaviour.
  The first comparison showed 4 differing lines: manifest.ps1 (Windows PowerShell 5.1) descended into junction
  and symlink targets, which are restored verbatim outside the tree, and missed the long path
  (LongPathsEnabled=0 on a fresh server) and the hidden file's streams; fixed in manifest.ps1, the VM now enables
  long paths
- [ ] (#67) L7 proper: MSI major upgrade with the GUI running, 1603 log parsing, watchdog revert, MSI rollback refused
  (needs a second MSI with a bumped version, `upgrade` step)

## Phase 36 — Offline appliance updates (2026-10-20)
- [x] Spike decided B (own signature check, then `bootc switch --transport oci` from a root-only path); `release/
  update-bundle.sh` (registry image + its .sig, or an OCI layout signed offline), `POST /updates/bundle` (streamed,
  8 GiB), Settings > Updates "Offline update" card, nexus-update `import` (tar data filter, SHA256SUMS, openssl
  against the pinned keys, repository + digest + version, no downgrade / no rolled-back digest), automatic online
  checks pause after an import. 171 Python tests (13 for the bundle), web-api upload test.
- [x] Lab on the appliance VM 201 (pve-test), no re-install: one-time bootstrap of the old image to 0.0.1-dev
  (disk + console, the old code has no import), then bundles uploaded through the API. 0.0.3-dev: verified, the
  old code did not stage (same origin: switch is a no-op, fixed: upgrade), applied; **0.0.4-dev: upload (1.1 GB,
  18 s), verified, staged, approved, rebooted, booted 0.0.4-dev (rollback 0.0.3-dev), no console**. Refused: older
  0.0.3-dev, truncated (477 MB), wrong key with consistent checksums. Found and fixed: Install now never shown
  (available is derived from staged), status.json without the web view after the reboot (UI blank for up to 10
  min), refused bundles shown as "blocked by checks"
- [ ] (#27, #29) Greenboot rollback after a broken bundle build; an online update after an offline one; parts above 2 GiB
- [x] Smaller image (2026-10-20, maintainer): no GPU/Wi-Fi/audio firmware, translations, docs; release.yml rechunks
  (release/rechunk.sh). 2.09 GB -> 1.40 GB, bundle 1.1 GB -> 656 MB; installed on VM 201 as an offline update,
  booted 0.0.5-dev, system running, no failed units, network up
- [x] Packages stripped (2026-10-21, maintainer): os/slim.sh shared by both images, appliance 464 -> 356 packages,
  edge -> 332; rechunked appliance 1.40 GB -> 1.26 GB, edge 955 MB, bundle 607 MB. Lab VM 201 (pve-test): offline
  update 0.0.5 -> 0.0.8-dev, system running, greenboot ok, nexus-diag 20 pass / 6 lab posture warnings,
  `verify.sh exact` VM 200 byte-identical (355 s), 0.0.8 stages 0.0.9-dev from a bundle. Finding on the way: an
  image without podman (0.0.6-dev) booted but could not update (`bootc upgrade`: "No such file or directory"; bootc
  creates its image store through podman), recovered with `bootc rollback`; podman stays.
- [x] Appliance VM 201 disk moved from virtio-blk (virtio0) to VirtIO SCSI single (scsi0, iothread, discard, ssd),
  booted unchanged (root by UUID, API up in 30 s, 2026-10-20); deploy.sh, README and manual chapter 2 recommend
  SCSI (a virtio-blk VM did not see a hot-added disk until a reboot)

## Release 0.2.0-alpha preparation (2026-10-21)
- [x] Time servers configurable (Settings > Time, maintainer request): NTS by default, plain NTP only as an opt-in,
  approval `time.servers`; helper `nexus-time` (nexus_time_t), nft-sync reads the included sources file. Tests:
  web-api `tests/timesync.rs`, `test_nexus_time.py`, nftsync includes.
- [x] Lab VM 201 (pve-test), re-deployed from 0.0.11-dev (24-word recovery key now; the hex-key 0.1 install is
  gone; lab state backed up in the session scratchpad): `lab/pvehost/time-servers.sh` switched the servers through
  the API with the security officer's approval: chronyd restarted with them, plain NTP without the opt-in refused
  (400). Found and fixed on the way:
  - `time.nts` diagnostic read the wrong chronyc column and always warned (5f653e60);
  - the status refresh after the chronyd restart ran in initrc_t and lost its chronyc (now `nexus-time settle`);
  - systemd could not watch the sources file for nexus-nft-sync.path (init_t read/watch added): the firewall kept
    the old servers until the next sync;
  - **updates of rechunked images with new SELinux types failed** ("fsetxattr(security.selinux): Invalid
    argument"): bootc ran in unconfined_service_t without mac_admin. Now install_t (as the stock bootc units) and
    no NoNewPrivileges on nexus-update. Lab: image A (0.0.11) -> image B with a lab-only new type (0.0.12) imported,
    applied, booted, file labelled `nexus_labtest_t`;
  - a refused import (pre-update checks, e.g. clock not synchronised) left `bundle.tar` behind, so every later
    upload answered 409: the upload is discarded now (test in `test_nexus_update.py`);
  - lab API helpers step up after sign-in when the account is risk-marked (Phase 29 unusual-hour signal at 01:00 UTC).
- [x] Images stripped (os/slim.sh), podman kept (bootc's image store needs it; a podman-less image could not
  update). Dependabot: #11 closed (windows-core with windows), #13 replaced (totp-rs 6 port), #14 closed (tiny-skia
  follows iced), #12 rebased.
- [x] `nts.netnod.se` was never reachable (also on 0.1): its NTS key exchange hands out NTP servers at other
  addresses and on port 4123. nexus-time reports chronyd's NTP associations, nft-sync allows them (Phase 39 S7).
  Lab 0.0.16-dev: all four default servers usable.
- [x] Phase 39 S2: risk signal thresholds as the gated setting `risk` (Settings → Security → Risk signal rules), the
  API-token-from-a-new-network rule (catalog v47 `token_networks`); manual chapters 9 and 10, screenshots.
- [x] Phase 39 C2 (part): file search owner filter (index protocol `owners`, API `owner=`, UI field), well-known
  Windows SIDs as names; 2026-10-22 guest account names (Linux `/etc/passwd`, Windows SAM local accounts) through
  the encrypted fsindex report into the index (`owner_name`, index format 2), also as owner filter values
  (`owner=alice`, case-insensitive); domain accounts stay SIDs.
- [x] Phase 39 C7: live progress for NAS share backups, plugin jobs and agent release pushes (their lines were dropped
  before).
- [x] Phase 39 O1: the configuration backup also goes to the second offsite target.
- [x] Phase 39 S5: post-quantum TLS (X25519MLKEM768) on our endpoints, interop with OpenSSL 3.5 both ways.
- [x] Phase 39 C1 (part): content hashes of files on FAT and exFAT volumes in VM disks ; btrfs too (inline and regular extents, zlib and zstd decompressed; lzo unhashed).
- [x] Phase 39 S4 (part): keyd answers nexus-index (primary group `nexus-index`) only keyring fetches; its own uid
  stays open (group-readable stores needed). Lab 2026-10-21 (VM 201, 0.0.18-dev offline bundle): keyd runs with
  the read-only group, file search answers (index fetched the keyring), `verify.sh exact` byte-identical (371 s); getgrnam's userdb read
  denial silenced (dontaudit, like the configuration backup).
- [x] Phase 39 C4: M365 cases by sender and recipient (plugin protocol v1.10 `ItemMeta`, side file `itemmeta`,
  carried over for unchanged mails; criteria `sender` / `recipient`; Cases page fields). Tested against the Graph
  mock; the instant search does not use the records yet.
- [x] Plain NTP servers count toward the weakening-burst risk rule; config backup's userdb lookup no longer floods
  the audit log.

## Phase 40 — Disk encryption with LUKS2 and TPM, NVMe metadata tier (added 2026-10-20)
Scope: plan.md Phase 40 (was Phase 39 S6). Not started.

## Phase 41 — VMware ESXi and vCenter backups as plugins (added 2026-10-21)
Scope: plan.md Phase 41 (plugins `vmware-esxi` and `vmware-vcenter` on a shared vSphere library; transport spike
in a nested ESXi 7.0U3/8.0U3 lab on pve-test first, vCenter needs a VCSA ISO and evaluation licences; CBT
incrementals, quiesced snapshots, restore to PVE). Takes over Phase 39 C5. Spike started.
- [x] Lab (2026-10-23): nested ESXi 7.0U3g on VM 250 (`lab/pvehost/esxi.sh`: kickstart-remastered ISO, deleted
  after the install; 96 GB system disk all taken by OSDATA (VMFS-L), so datastore1 lives on a second 128 GB disk).
  Pitfalls: vmxnet3 drops the 42-byte ARP replies of the local bridge (reachable only through the router): e1000e
  works; ESXi's FIPS sshd refuses ed25519 keys: ECDSA.
- [x] Option A throughput, HTTPS `/folder` range reads of a 4 GiB flat VMDK (ESXi direct, no vCenter, no snapshot):
  from VM 201 one stream 26.7 MB/s, 4 parallel ranges 41 MB/s, 64 x 4 MiB random ranges 12 MB/s (312 ms each); from
  the workstation the same (28 / 46.5 / 14.2 MB/s), so `hostd` is the limit, not the network. Below the pass
  criterion "full of 200 GB under 4 hours" (needs about 14 MB/s: met with parallel ranges, 2 TB is not).
- [x] CBT (2026-10-23): Debian guest nx-cbt (16 GB thin, CBT in the `.vmx`); `QueryChangedDiskAreas` after 512 MB new
  + 103 MB overwritten: 649 MB in 124 extents, under a second. `changeId "*"` reports the whole partition, not the
  3.9 GB allocated. **`/folder` cannot read the base disk of a running VM** (HTTP 500, hostd "Failed to lock file",
  also with a snapshot); `ExportSnapshot` needs vCenter.
- [x] Hot-add proxy without VDDK (2026-10-23, `esxi.sh hotadd`): the snapshot's base disk attached read-only
  (independent-nonpersistent) to proxy VM nx-proxy on the same host: full 16.16 GB in 38.7 s (418 MB/s), incremental
  657 MB in 2.0 s (336 MB/s), check against a full read: 0 mismatched blocks. No snapshots or attached disks left.
  docs/vmware-transport-spike.md "Lab results"; the product proxy would be the appliance's bootc image.
- [x] ESXi 8.0.3 in the lab (2026-10-23, VM 251, `ESXI=8 esxi.sh`): the Dell 8.0U3 image installs on the lab's
  Haswell CPU with `--forceunsupportedinstall` and `allowLegacyCPU=true` (installer and installed boot.cfg). Same
  findings as 7.0U3: `/folder` refuses the running VM's base disk (500); hot-add full 447 MB/s, incremental of 659 MB
  (119 extents) 386 MB/s, 0 mismatches. No snapshots or attached disks left.
- [x] Phase 41 design decision (maintainer, 2026-10-23): hot-add proxy, native connector `nexus-vmware`, the proxy as
  an enrolled agent with `block-read`, shipped as an OVA (docs/vmware-design.md).
- [x] M1 (2026-10-23, 5d9d9016): agent protocol v1.9 block reads (the proxy role); agent-conn `blocks::read_disk`
  and `block_ranges` (973419ba), tested over a real mTLS session.
- [x] M2 `crates/vmware` (2026-10-23): vSphere SOAP client (login, inventory, devices, snapshots, CBT,
  `QueryChangedDiskAreas`, hot-add/detach), `backup_vm` with a `Transport` choice, one fixed index per disk plus
  the `.vmx`/`vmware.json` config index. Commits 91eb15f4 (backup flow), 7cf03bb5 (NFC transport).
- [x] vCenter 8.0.3 deployed in the lab (2026-10-23, `lab/pvehost/vcenter.sh`, VCSA tiny at 10.2.34.231
  vcsa-dev.dev.ah.local, on a 600 GB datastore2 on ESXi 8 VM 251), both nested hosts joined to datacenter nx-lab.
  Note: joining vCenter re-issued ESXi 7's certificate, so a cached vSphere client failed until it refetched it;
  adding datastore2 detached ESXi 8's datastore1 VMFS (VMs 1/2 "invalid") until `esxcli storage vmfs snapshot
  mount -l datastore1` and `vim-cmd vmsvc/reload` restored it (no data lost).
- [x] Hot-add proxy backup (2026-10-23, `esxi.sh proxy` + `vmware-lab.sh backup_through_proxy`, ESXi 7.0.3):
  full read 16 GiB -> 1913 distinct blocks (6.3 GB wire), incremental 13 changed blocks, dedup reuses the rest;
  byte-correct reconstruction (MBR). Full read ~6 MB/s in the nested lab (throughput follow-up open).
- [x] NFC transport without VDDK (2026-10-23, `crates/vmware/src/nfc.rs`, docs/nfc-protocol.md): clean
  reimplementation of VADP network mode (authd 220+TLS pinned to the ticket thumbprint, classic 264-byte
  handshake, AIO). `vmware-lab.sh nfc_read_disk` passed on vCenter 8.0.3 / ESXi 7.0.3 (MBR, fragment-boundary and
  determinism checks). Protocol details found against the lab: authd sends a plaintext 220 before TLS;
  SET_RES_POOL does reply.
- [x] M3 part 1 (#32, 22bc8f80): source kind `vmware` (catalog v49), `nexus-vmware` backup / inventory / check over
  NFC, scheduler jobs, firewall egress (443, NFC 902), SELinux domain `nexus_vmware_t` (902 as `nexus_nfc_port_t`).
- [x] M3 part 2 (#33, fa9f7859): the source in the web API (sealed password) and UI, VM checklist from the
  inventory, VM names, reports.
- [x] M3 part 3 (#34, 808dfb8b): `nexus-pve restore-vmware` (the .vmx as qemu-server.conf, VirtIO for Linux, SATA +
  e1000e for Windows), restore job, API, UI dialog, manual chapters 4 and 6.
- [x] Lab end to end on VM 201 (2026-10-23/24, `lab/pvehost/vmware-e2e.sh`, lab vCenter 8.0.3): inventory of 5 VMs
  by instance UUID; backup of nx-cbt (ESXi 7.0.3 host) over NFC, 16 GiB full in 238 s (~72 MB/s),
  application-consistent (VMware Tools); restored as PVE VM 290 on pve-test in 214 s (VirtIO SCSI + VirtIO NIC,
  link_down), boots to the Debian 12 login; 0 AVC denials. Two bugs found and fixed on the way: SELinux denied the
  agent mapping index to nexus-vmware (#85, 03f6fabe: NFC no longer opens it); PVE restored no disk without vzdump's
  `#qmdump#map:` hint lines (in 808dfb8b). Images 0.0.25-dev to 0.0.27-dev installed as offline updates.
- [x] Hot-add proxy transport in the binary (#80, 2026-10-24): `proxy-prepare` / `nexus-agentctl block-read` /
  `proxy-finish` as three job steps per VM (the agent CA stays agentctl's), source fields `proxy_vm` +
  `proxy_agent`, UI, SELinux `nexus_vmware_work_t`. Unit and plan tests only; no appliance lab run yet.
- [x] Files of VMware snapshots (#83, 7bae4539): browse, download, file index and search like PVE VM snapshots;
  VMware groups get the index-files switch. Plan and API tests; appliance check still to do (lab image 0.0.30-dev
  has it).
- [x] Hot-add lab run on the appliance (#88, 2026-10-24, images 0.0.28-dev and 0.0.30-dev on VM 201, vCenter 8.0.3
  with ESXi 7.0.3): agent on nx-proxy (ESXi 7) enrolled with the appliance, source `vc-hot` (transport hotadd),
  group with nx-cbt (Debian 12, 16 GiB). Incremental from the earlier NFC snapshot: 25 changed 4 MiB blocks,
  100 MB read, 11 MB on the wire (LZ4), job 20 s, application-consistent. Restored as PVE VM 290 (200 s), boots to
  the login. Full read (scheduled change-tracking check forced due): job 136 s = prepare 7 s, scan 56 s (16 GiB
  read and hashed on the proxy, 306 MB/s), fetch 65 s (1899 distinct blocks, 7.96 GB raw, 6.3 GB on the wire,
  97 MB/s), finish 6 s. No snapshot or disk left on ESXi; no AVC denial in nexus_vmware_t / nexus_agentctl_t.
  Found and fixed: scheduled full reads never reached hot-add configs and two systemd SELinux gaps (f4262897), a
  due VMware full read repeated on every backup (#91), the nightly shut down VM 251 with the vCenter on it
  (25920942; nx-vcsa now autostarts on ESXi 8).
- [x] Proxy throughput (#38): the 10 MB/s were the library lab test; on the appliance the hot-add full read runs
  at about 126 MB/s for the job, the fetch at 97 MB/s on the wire, i.e. about the 1 GbE line rate of the nested
  lab. Not done (no need measured): avoiding the proxy's second read of fetched blocks, pipelined Want batches.
- [ ] (epic #23) rest of M3: the proxy OVA (#35), lab (#37: vSAN/NFS, quiesced Windows snapshots, proxy on another
  host).
- VixDiskLib 7.0.1 + nbdkit were installed on the regression VM (VM 280) while evaluating the VDDK/nbdkit path
  (not used; we speak NFC ourselves) and removed again 2026-10-23 (`/opt/vddk-7.0.1`, nbdkit packages gone).

## Phase 42 — Further hypervisors and databases (added 2026-10-21)
Scope: plan.md Phase 42 (Hyper-V with RCT, XCP-ng/XenServer with XAPI CBT, SQL Server log chain and PITR, Oracle
RMAN and archive logs, log backups on their own schedule); listed in the README under "Planned sources". Not started.

## Lab: PostgreSQL HA cluster with Patroni (added 2026-10-23, maintainer request)
- [x] Lab (2026-10-23, `lab/pvehost/patroni.sh`): three Debian 12 nodes pg1-pg3 (VMs 261-263) with PostgreSQL 17.11,
  Patroni and etcd from autobase 2.11.0 (TLS on), deployed from control VM pg-ctl (260, Debian 13: autobase's
  ansible 14 needs Python 3.12+; its collections and `netaddr` installed there, nothing on the dev machine). Writer
  on pg-ctl: one row per second through a multi-host connection string, it follows the leader.
- [x] Backups through the appliance (VM 201, plugin installed with the TEST key and two-person approval): `labdb`
  dump 1 s; cluster full 48.6 MB in 9 s, incrementals 1 s (only WAL, 1275 data files unchanged); after a switchover
  (pg1 -> pg3) and a hard failover (VM of pg3 stopped, pg2 leader after about 30 s) the plugin found the new primary
  and took a new base backup on the new timeline. Patroni removed the `nexusbackup` slot from the old primary when
  it rejoined.
- [x] Restores: dump into the cluster as `labdb_copy`: 2243 rows, equal to the source. **PITR**, plugin 1.2.1, six
  marks across timelines 3-5: every mark with a later backup on its timeline restores exactly (a1 2016, a4 2119, a6
  2220 rows = the cluster's count at that second, 3-4 s each). Marks between a timeline's last backup and the next
  base backup (before/after the switchover, after the failover) fail with "requested recovery stop point is before
  consistent recovery point": that WAL is in no snapshot (plan.md Phase 44).
- [x] Fixed on the way: plugin 1.2.0 PITR into a fresh configuration aborted recovery ("insufficient parameter
  settings", Patroni's `max_connections = 1000`); 1.2.1 stores the recovery minimums in `settings.conf` and writes
  them on restore. Scheduler: plugin snapshot metadata (recoverable range) was only stored for `plugin_backup` jobs,
  not for group backups (every schedule).
- [x] WAL across a failover (2026-10-23, plugin 1.3.1): with `nexusbackup` as a Patroni permanent slot
  (`patroni.sh slot`), a run after a timeline change streams the old timeline up to the switch point, stores the
  history files and continues on the new timeline, without a new base backup. Scenario (timelines 7 -> 8
  switchover pg3 -> pg1, 8 -> 9 hard failover pg1 -> pg2): **all six marks restore exactly**, including the ones
  right before and after each switch (2876 / 2907 / 2932 / 2972 / 3008 / 3033 rows = the cluster's counts, 4-5 s
  each). On the way: the slot check compares segments (Patroni advances a standby's slot to a position inside the
  segment the next run starts with). Without the permanent slot the behaviour is as before (new base backup).
- [x] Same scenario on PostgreSQL 14, 15, 16 and 18 (2026-10-23, `patroni.sh matrix 14 15 16 18`, plugin 1.3.1, fresh
  three-node cluster per version from autobase): on every version both switches (switchover and hard failover) were
  followed without a new base backup, the dump restore matched, and **all six PITR marks restored exactly** (row
  counts equal to the cluster's at that second, 3-4 s each; 0 mismatches over 24 restores). PostgreSQL 14 has no
  `READ_REPLICATION_SLOT`; the slot check is skipped there and following worked the same.
- [ ] (#49) The PITR dialog bounds the target by the recoverable range; the plugin could also refuse a target outside it
  before restoring (today PostgreSQL refuses after the restore).
- [x] Restore tests through the appliance (2026-10-23, VM 201 on 0.0.22-dev, plugin 1.4.1, PostgreSQL 18 cluster,
  `patroni.sh rtest`): schedules on both groups; the scheduler's verify restores: `labdb` dump into a throwaway
  database on the cluster, 412 rows counted against the dump, dropped (1 s); cluster snapshot PITR to the end into
  `/srv/pitr/verify/…` on pg-ctl, started and queried (passed), directory removed. On the way: the check query took
  the answer from psql's whole output, and a collation-version warning (source Debian 12 glibc 2.36, restore host
  Debian 13 2.41) failed the test; 1.4.1 takes the last line.
- [x] Cleanup (2026-10-23, maintainer): the stale lab sources 2-8 of tenant pgha and their groups removed (each delete
  approved by the security officer; the bulk deletes marked the admin account as designed, every further delete
  needed a step-up, the security officer cleared the mark afterwards). Source 9 (the current PostgreSQL 18 cluster)
  stays.
- Lab left running with the writer stopped (`patroni.sh writer` / `nowriter`); `patroni.sh destroy` removes it.

## Phase 35 — CIS AlmaLinux OS 10 Benchmark (added 2026-10-15)
Scope: plan.md Phase 35 (gap analysis docs/cis.md, lab scan before/after, hardening in os/, CIS report as a gate).
Benchmark PDF in tmp/ (gitignored, CIS licence).
- [x] 35a gap analysis `docs/cis.md` (2026-10-21): CIS server L1 via ComplianceAsCode, every non-passing rule with a
  decision (37 applied but not visible to a file-tree scan, 35 deviate with reason, 10 lab check, 6 not applicable).
- [x] 35c first part: sysctl and module hardening, no core dumps, persistent journal, sshd drop-in, banners, umask,
  TMOUT. Image scan 161 -> 194 pass (116 -> 83 fail). Lab VM 201 0.0.17-dev: boots, greenboot ok, sysctls active,
  modules blocked, 0 AVCs, `verify.sh exact` byte-identical, web UI negotiates X25519MLKEM768.
- [x] `release/cis-report.sh` scans read-only from the base image (the appliance has no dnf any more).
- [x] 35b booted appliance checked by hand (2026-10-21, VM 201 on 0.0.17-dev plus the new units in /etc): `/tmp`
  (tmp.mount drop-in) and `/dev/shm` (dev-shm-noexec.service) nosuid, nodev, noexec; rpcbind/nfs disabled, no
  rsyslog, root PATH clean; greenboot green, 0 AVC denials, `verify.sh exact` byte-identical (362 s).
- [x] 35d gate: `release/cis-report.sh` fails on a rule of `release/cis-passing.txt` that no longer passes (tested on
  the 0.0.17-dev scan: passes; one rule forced to fail: exit 1 naming it); the release.yml step is no longer
  continue-on-error.

## Phase 36 — Offline (air-gapped) appliance updates (added 2026-10-15)
Scope: plan.md Phase 36 (signed update bundle as a release asset, spike: local mirror registry vs own signature
check + oci-archive, upload in Settings > Updates / nexusctl / console USB, same checks as online). Not started.

## Phase 37 — Windows bare-metal recovery (added 2026-10-20)
Scope: plan.md Phase 37 (layout, VSS volume images, recovery media spike Linux rescue ISO vs customer-built WinPE,
P2V to PVE, limits). Not started.

## Phase 38 — Standalone agents with Veeam Agent parity (added 2026-10-20)
Scope: plan.md Phase 38 (comparison doc first, managed and standalone mode, local repository in the appliance
format on disk/USB/NFS/SMB/SFTP/S3, image and file backups, client triggers, application-aware processing, client
restores, UI/CLI, import into an appliance). All in this repository.
- [x] 38a comparison `docs/veeam-agent-comparison.md` (2026-10-22, Veeam Agent 13 for Windows and Linux): 14 areas,
  scope and order for 38b-38j (38b+38c, 38e, 38d with 37, 38f, 38g, 38h, 38i, 38j); no CBT driver, no kernel module.
- [x] 38b + 38c first step (2026-10-22): standalone backup/list/restore into a directory repository on Linux
  (`nexus-agent repo …`), recovery words, incremental via the metadata cache; chunkstore builds for Windows.
- [x] 38c: `repo prune` (GFS + GC), writer lock; Windows `nexus-agent.exe repo …` (shared CLI in agent-core;
  builds and passes clippy for Windows, not run on Windows yet: lab offline).
- [x] 38e first part: scheduled jobs (`standalone.json`, the service runs them every minute; waits for a missing
  repository, low battery, metered network; `repo jobs`, `repo run`); crate `schedule` split out of the catalog.
- [x] 38c copies: `repo copy` mirrors the repository to SFTP, S3 (Object Lock for chunks) or a directory,
  `repo fetch` downloads it; crate `remote` (the offsite clients without keyd/catalog). Tested with the directory
  backend; SFTP/S3 not run from an agent yet (lab offline; the clients are the offsite ones).
- [x] 38h first part: UI ops `jobs` / `run_job` (queued for the job loop), desktop card "Backups on this computer"
  with Run now, `nexus-agent jobs` / `run-job` for UI-group users, the UI socket/pipe also in standalone-only mode.
- [x] Lab 2026-10-22 (main 8312dd90..d5811126): standalone agent on Windows Server 2022 (VM 242, reset to
  clean-os): `repo init`, backup with VSS (all writers ok), incremental (USN: 2 new chunks, the unchanged 3 MB file
  reused), `repo list`, restore of the first snapshot (old content, no later file), service installed while not
  enrolled ran the job and pruned, UI pipe `jobs` / `run_job` (unknown job refused, run started within seconds).
  nexus-agent.exe 7941 KiB (the 8 MiB frame check turned out stale, see below).
  VM 201 on 0.0.19-dev: greenboot green, 0 AVCs, /dev/shm noexec, sshd_config.d 0700, index rebuilt for format 2,
  owner filter by name `owner=root` works; `verify.sh exact` byte-identical (386 s).
- [x] 2026-10-22 maintainer request: PVE guests by name everywhere in the web UI, the id muted next to it
  (`GET /names`, component `SourceName`, `labelOf` for titles; Snapshots, Find files, Jobs, Dashboard, Groups,
  restore dialogs, Restore tests, Cases, Hash hunt, Recovery plans, change trends). One VMID with different names in
  two clusters of a tenant: both names (its snapshots share `vm-<vmid>`).
- [x] 2026-10-22 lab VM 201: "Check now" staged the channel's 0.0.1-alpha over 0.0.19-dev and the page kept
  "Last check 2 d ago" during the check: fixed (no older release staged, "checking" state). VM 201 still has that
  0.0.1-alpha staged (download-only, never applied automatically); the next image will not offer it.
- [x] nexus-agent.exe size ceiling (2026-10-23): not a protocol limit any more. Agents since 0.1.0-alpha (protocol
  v1.8, Windows and Linux) take updates as `UpdateBegin`/`UpdateChunk` in 1 MiB pieces (up to `MAX_UPDATE`, 512 MiB);
  only 0.0.1-alpha agents need the single `Update` frame, and the appliance refuses a binary above 8 MiB for them
  with "update it by hand once". The stale 8 MiB checks in `agent-windows/build.sh`, `build-bundle.sh`,
  `release/packages.sh` and `tests/dist.rs` are removed; the interop test now updates with a 9 MB binary (9 chunks).
- [ ] (#30, #31) 38 rest: SFTP/S3 copy against the lab testboxes, lock/log-off and wake
  triggers, 38d with 37, TUI jobs view, restores from the UI (38g).

## Phase 43 — PegaProx plugin (added 2026-10-23)
Scope: plan.md Phase 43 (Python plugin `pegaprox-plugin-nexusbackup`: backup state per VM and cluster in PegaProx,
then "back up now"; read-only token by default, operator token only for backup jobs; lab PegaProx VM on pve-test).
- [x] API token scope `backup` (catalog v48 `only_kinds`): read and start backup jobs, nothing else (tests: the
  scope matrix, the migration); UI token dialog, manual screenshots.
- [x] Plugin `integrations/pegaprox/nexusbackup` (PegaProx 1.4): tab with the state per guest (protected / late or
  failed / no backup yet / not protected; newest backup, group and policy, next run, lock, restore test, alerts),
  "Back up now" behind `allow_backup` plus PegaProx `backup.create`/`vm.backup` on the cluster; the API client pins
  the appliance certificate before the token is sent (`test_core.py`, 6 tests incl. a local TLS server).
- [x] Lab (2026-10-23, `lab/pvehost/pegaprox.sh`): PegaProx v1.4.0 from source on VM 270 (Debian 13), pve-test added
  through a read-only PVE user `pegaprox-lab@pve` (PVEAuditor, API token), plugin enabled with a read token of
  VM 201: 30 guests listed, VM 101 (group windows) and VM 200 (lab-arm64) protected with their newest backups, the
  rest unprotected, as on the appliance.
- [x] "Back up now" (2026-10-23, VM 201 on 0.0.22-dev, token scope `backup`, `pegaprox.sh backup`): a GET is refused
  ("POST only"); the POST through PegaProx started backup job 460 of VM 200 (group lab-arm64, `guests: [200]`), ok
  in 10 s, the plugin shows the new snapshot; the appliance's audit log names `admin via token pegaprox-backup`.
  The first try was refused correctly: the admin account carried a risk mark (sign-in at an unusual hour), and a
  marked account's tokens cannot change anything; the security officer cleared it.
- [ ] (#44) Screenshots of the tab (PegaProx in a browser; sign-in there is a manual step). Catalogue submission: not yet,
  the plugin stays in this repository (maintainer, 2026-10-23).

## Phase 44 — Backup and restore testing, databases first (added 2026-10-23)
Scope: plan.md Phase 44 (scheduled restore tests of PostgreSQL / MySQL dumps and PITR with row counts and checksums,
lab scripts as scheduled regression runs, fault injection, WAL kept across a Patroni failover).
- [x] WAL across a Patroni failover: postgresql plugin 1.3.1 (see "Lab: PostgreSQL HA cluster"), PostgreSQL 14-18.
- [x] Restore tests of database groups (2026-10-23): plugin restore `verify` (postgresql 1.4.1: dump into a throwaway
  database with per-table row counts, cluster PITR to the end started and queried; mysql 1.1.0: dump with a
  `-- nexus:rows` trailer, counts compared); restore-test schedules on plugin groups, results in `restore_tests` and
  the `restore_test` alert; Restore tests page and manual. Lab: both PostgreSQL tests pass on VM 201 (0.0.22-dev).
- [x] Table contents in PostgreSQL dump restore tests (plugin 1.4.2): an order-independent SHA-256 sum of the COPY
  rows, read back with the dump's columns under canonical output settings. Lab: 435 rows (timestamptz, inet) of the
  Patroni cluster's `labdb` compared, passed.
- [ ] (#45, #46, #47) A custom SQL check per group; a random PITR target inside the recoverable range; MySQL contents (counts only).
- [x] Lab scripts as scheduled regression runs (maintainer: a timer on a lab VM): VM 280 nx-regress (Debian 13,
  `lab/pvehost/regress.sh`) runs `lab/pvehost/nightly.sh` at 01:30 UTC after a `git pull` of main: tunnel, exact
  restore, the reboot fault test, the Patroni scenario (PostgreSQL 18), the ESXi 8 hot-add test; the VMs a step needs
  are started before it and stopped after; results as JSON on the VM (`regress.sh results`). Trial 2026-10-23 on the
  VM: tunnel + exact passed (373 s); first full run started 2026-10-23 16:20 UTC.
- [x] Fault injection, failover during a backup (2026-10-23, `patroni.sh fault`, PostgreSQL 18): a 1.3 GB table, the
  first (full) cluster backup of a new source, the leader's VM stopped hard while it streams. The job fails, no
  snapshot is committed, the scheduler queues a retry; the next run takes a full base backup from the new primary
  (36 s) and its restore test passes. Found: the failure surfaced only after the 600 s read timeout (a hard-stopped
  VM sends no reset); plugin 1.4.3 uses 180 s on replication connections: detected after 184 s.
  On the way (lab only): autobase's 4 GB swap file filled the 16 GB node disks during the bulk load; without it,
  its `vm.overcommit_memory = 2` at ratio 50 let a 4 GB node commit only 2 GB (etcd, sshd and big statements
  failed): the deploy now sets no swap file and ratio 100.
- [x] Fault injection, appliance reboot during a backup (2026-10-23, `lab/pvehost/faults.sh reboot`, VM 242, 0.0.22-dev):
  rebooted after 3.5 GB read; afterwards the job is failed ("interrupted: the scheduler stopped while this job was
  running"), no snapshot of the run exists. Found: the interrupted backup was neither retried nor alerted (crash
  recovery only marked it failed), so the guest waited for its next schedule silently. Fixed in the scheduler: an
  interrupted backup follows the group's retry policy, the last attempt raises `job_failed` (test `crash_recovery`).
- [x] Found by the reboot test as well: the vzdump task of the interrupted run kept the guest's backup lock on the node
  and waits for an appliance up to the PVE plugin's job timeout (6 h); every retry failed with "another backup task
  ... still waits". nexus-pve now stops such tasks when the same API token started them before (other users' tasks
  stay), and the retry goes through (test `stale_tasks_of_the_same_token_only`).
- [x] Both confirmed on VM 201 with 0.0.23-dev (2026-10-23, `faults.sh reboot` again): reboot during job 533 after
  1.6 GB; after the restart 533 is failed and retry 534 queued; 534 found the stale vzdump task of the interrupted
  run, stopped it and failed; retry 536 backed VM 242 up (153 s), about 10 minutes after the reboot, without anyone
  touching the node. (Could be one retry shorter if recovery stopped the task itself: the interrupted job's log has
  its UPID.)
- [x] Fault injection, network loss (2026-10-23, `faults.sh netloss`, 0.0.23-dev): the appliance's traffic to the
  PVE host dropped for 120 s after 1.3 GB: the job failed ("NBD reader stopped") 205 s after it started, the temporary
  rule was removed; retry 542 stopped the leftover vzdump task, retry 543 succeeded (151 s). Leftover task because
  the failure report to the node went over the broken SSH session: nexus-pve now also stops its task through the API
  when that report fails (saves one retry). Confirmed on 0.0.24-dev: the same outage (job 549 failed after 212 s),
  and the first retry (550) succeeded (153 s).
- [ ] (#48) Fault injection, the rest: full store, corrupt chunks, clock jumps.
