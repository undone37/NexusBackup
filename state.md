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
SSH key management for sources, appliance config backup (catalog, totp.key, secrets.key), agent/TrueNAS cert renewal, minimal PVE token privileges, scale/soak tests on real hardware, multi-node PVE, GitHub push + CI + release, agent bundle in the image, TPM/LUKS, H-3 uid split; user-side: release key, real Storage Box, external pentest, pilot tenant

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
- [ ] Optional approval system (user request 2026-10-10): off for single-user appliances, enable freely, disable = requester + 1 approver, approvers = admins + security officers, banner when more users exist; + self-enrollment — agent running

## Phase 9 — Plugin system (added 2026-10-10)
Goal: extend with new data sources + restore functions (NetApp SVM, VMware ESXi/vCenter, PostgreSQL, …) via signed, sandboxed plugins on a versioned SDK; M9 = PostgreSQL plugin + one ported connector
Decisions (user, 2026-10-10): sandboxed processes + Rust SDK; trust = project key + admin-added publisher keys (quorum); reference plugin PostgreSQL; port TrueNAS; restore API: download, restore to target, app-specific, mount/instant access
- [x] Contract `docs/plugin-system.md` (trust split: untrusted plugin process ↔ trusted `nexus-pluginhost`; bundle + manifest + signature; quorum-gated lifecycle; protocol ops Validate/ListGuests/Backup/Restore/Mount; sandbox; SDK; catalog v8) + crate `plugin-proto` (messages, framing, limits, path/stream validation, manifest model + validation)

## Phase 10 — End-user manual (added 2026-10-10, after plugin system; M365 = Phase 11)
`manual/` folder, full end-user documentation in Markdown with reproducible screenshots of the web UI
Decisions (user, 2026-10-10): English; screenshots from seeded demo data via headless browser; start after Phase 9 merge

## Next


## Deferred (with reason)
- Bloom filter / separate dedup index: the filesystem path is the local dedup index; add when stat lookups become the bottleneck
- Single global chunk lock: per-prefix locks if contention shows
- Fsync per new chunk file (dir fsync is batched at commit): batch file syncs if HDD throughput suffers
- GFS retention classification: belongs to the scheduler (Phase 5)
- Offsite/verify status: catalog, not the immutable manifest
- keyd TPM sealing: user chose no TPM for now (no libtss2-dev install)
- OS: LUKS2/TPM enrolment, A/B updates + rollback, image signing, first-boot TUI, runtime nftables sets, SELinux refinement (see os/README.md)
