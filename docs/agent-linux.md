# Linux agent (`nexus-agent`)

Static musl binary for all distributions (crate `crates/agent-linux`), implementing
`docs/agent-protocol.md`. The platform-independent half (TLS/enrollment/mTLS server,
session state machine, FastCDC + BLAKE3 chunking, metadata cache, `Want` serving,
restore stream handling, update signature checks) lives in `crates/agent-core` and is
shared with the Windows agent (docs/agent-windows.md); `agent-linux` implements its
`Platform` and `RestoreFs` traits. It listens (TCP 7444, TLS 1.3, ALPN `nexus-agent/1`) and never
connects out.

## Packages (.deb / .rpm)

Every release carries `nexus-agent_<v>-1_{amd64,arm64}.deb` and
`nexus-agent-<v>-1.{x86_64,aarch64}.rpm`, built by `release/packages.sh` (release workflow,
job `packages`) entirely in rootless podman: the static musl binaries in the official Rust
image (x86_64 with gcc, aarch64 with the Debian `gcc-aarch64-linux-gnu` cross compiler; both
link Rust's self-contained musl), the packages with nfpm (`goreleaser/nfpm`, pinned by
digest; config and maintainer scripts in `crates/agent-linux/dist/pkg/`). The package version
is the agent crate version (what self-update compares), release `1`.

Contents: `/usr/bin/nexus-agent`, `/usr/lib/systemd/system/nexus-agent.service` (the bundle's
unit with `ExecStart=/usr/bin/nexus-agent run`), `/etc/nexus-agent/{hooks.d/{pre,post},release-keys}`
(0700 / keys 0644 as config files), `/usr/lib/nexus-agent/package-managed` (`deb` or `rpm`),
`/usr/share/doc/nexus-agent/` (README, copyright, `examples/hooks.d/pre/*.example`),
`/usr/lib/sysusers.d/nexus-agent.conf` (group `nexus-agent-ui`, created by postinst with
`systemd-sysusers`, fallback `groupadd -r`; kept on removal). No system user (the agent must run
as root, see the unit), no dependencies (static binary).

Maintainer scripts (`postinst.sh`, `prerm.sh`, `postrm.sh`; the same files for deb and rpm,
they tell the two calling conventions apart):
- install: writes `/etc/modules-load.d/nexus-agent.conf` if LVM is present (as install.sh),
  `daemon-reload`, prints the enrollment commands. The unit is **not** enabled or started
  before enrollment (`nexus-agent init --token -`, then `systemctl enable --now nexus-agent`).
  A reinstall on a host that still has `/etc/nexus-agent/agent.key` enables and starts it.
- upgrade: `systemctl try-restart`.
- remove / erase: `disable --now`, removes the modules-load file; `/etc/nexus-agent` stays
  (reinstalling keeps the enrollment). `apt purge` also deletes `/etc/nexus-agent` and
  `/var/lib/nexus-agent`.
- warns if an install.sh installation (`/etc/systemd/system/nexus-agent.service`,
  `/usr/local/sbin/nexus-agent`) would shadow the packaged one; remove those two files when
  switching from the bundle to the package (`/etc/nexus-agent` is shared and kept).

Checks (`release/test-packages.sh`, run by the release workflow before the upload): install,
file modes, `nexus-agent --version` and `status`, `systemd-analyze verify`, unit not enabled,
reinstall, remove (enrollment kept) and purge in `debian:13`; install, `rpm -V`, erase in
`almalinux:10` and `fedora:43`; lintian and rpmlint without errors. The aarch64 binary is
checked with `file` and run under qemu-user when the host has binfmt for it. Known lint
warnings (accepted): no man page, 0700 directories under `/etc`, maintainer scripts call
`systemctl` directly (shared deb/rpm scripts, no debhelper), nfpm's changelog format,
`statically-linked-binary` is overridden (lintian override in the package, rpmlint filter
`crates/agent-linux/dist/pkg/rpmlintrc`). Native package signing (GPG for apt/dnf
repositories) is not done: there is no repository yet; the files are signed with cosign
(docs/release.md).

## Install from the bundle (any systemd distribution)

```
crates/agent-linux/dist/build-bundle.sh [--test-key] [--sign]   # on the build host
tar xzf nexus-agent-<v>-x86_64.tar.gz && cd nexus-agent-<v>-x86_64
echo '<token from the UI>' | sudo ./install.sh --token -          # on the server
```

`install.sh` installs `/usr/local/sbin/nexus-agent`, `/etc/systemd/system/nexus-agent.service`,
`/etc/nexus-agent/{hooks.d/{pre,post},release-keys}` and, with a token, runs
`nexus-agent init` and starts the service. Other commands (as root; with `sudo` use the full
path `/usr/local/sbin/nexus-agent`, EL and Fedora keep `/usr/local/sbin` out of sudo's `secure_path`): `nexus-agent status`,
`nexus-agent hooks test`, `nexus-agent tui`, `nexus-agent init --token <T>` (re-enrollment; also clears the
lock after 5 failed proofs), `nexus-agent run` (the service).

Files: `/etc/nexus-agent` (0700): `agent.conf`, `token` (`agent_proto::token_digest`, deleted
after enrollment), `agent.key` (0600), `enroll.crt`, `agent.crt`, `ca.crt`, `agent.id`.
`/var/lib/nexus-agent` (0700): `enroll.failures`, `cache/committed.bin`, `snapshots.journal`,
`spool/` (unlinked spool files only).

`agent.conf` (`key = value`): `listen` (`::`), `port` (7444), `lvm_snapshot_percent` (10),
`hook_timeout_secs` (3600), `spool_max_bytes` (2 GiB), `appliance_id` (pin the client
certificate CN `nexus-appliance:<id>`), `max_connections` (4), `self_update` (`on`/`off`;
unset = on, except for package installs). Unknown keys are errors.

## Enrollment and TLS

As in the contract. The HMAC key is `token_digest(T)` (hex sha256 of the trimmed token) on
both sides, because neither side keeps the plain token. Exporter context: none. Only proof
failures count towards the lock (5); garbage before the proof just closes the connection.
`EnrollDone` is accepted only if the certificate is for the agent's key, has
`CN=nexus-agent:<agent_id>`, and is signed by the delivered CA, which must be a CA. There is
no reply to `EnrollDone`: the agent closes the connection and switches to mTLS; the
appliance confirms by connecting with mTLS and `Hello`.

mTLS: client certificate must chain to the stored CA (webpki), carry an explicit clientAuth
EKU and `CN=nexus-appliance:<id>` (optionally pinned). `Hello` must be the first message.

Certificate renewal (protocol v1.3, capability `cert-renew`, docs/agent-protocol.md): the
appliance asks over an mTLS session (`RenewCert`); the agent generates a new key pair, sends
its CSR, checks the issued certificate (new key, own id, the CA it already trusts) and
swaps `agent.key` + `agent.crt` atomically (`*.new` files, certificate last; an interrupted
swap is completed or rolled back at the next start). New connections use the new identity;
running ones keep theirs. Re-enrollment (`nexus-agent init` with a new token for the same
agent) keeps the agent id.

## Backup

- `Prepare`: run pre hooks (if `hooks`), then one snapshot per affected volume:
  LVM thin (`lvcreate -s -kn`), LVM thick (`lvcreate -s -L <pct of origin, whole MiB, ≥ 64 MiB>`;
  origins that already have snapshots are fine), mounted
  read-only below `/run/nexus-agent/<job>/<n>` in the agent's private mount namespace (XFS
  `nouuid`, retry with `norecovery`; ext3/4 retry with `noload`); ZFS (`zfs snapshot`, read via
  `.zfs/snapshot/`); btrfs (read-only snapshot in `<mountpoint>/.nexus-snapshots/`, skipped by
  the scan). If a volume cannot be snapshotted the agent reads it live and `consistent` is
  `false` (reason in `hook_log`, also "no snapshot support for <mountpoint> (<fs> on <dev>)").
  A failing pre hook fails `Prepare` (post hooks still run).
- Nested btrfs subvolumes (`btrfs subvolume create` inside a mounted subvolume; not in
  mountinfo) are volumes of their own, like mount points: a btrfs snapshot does not contain
  them (they appear as empty directories). A requested path inside one is read from that
  subvolume's own snapshot; one that is only *below* a requested path is left out with a
  note in the job log (add it to the paths). Discovery: `btrfs subvolume list -o`, recursive.
- Every created object is recorded in `snapshots.journal` before creation; release removes
  it, and service start removes leftovers (journal + any LV / ZFS snapshot named
  `nexus-snap-*`; objects that are already gone count as removed). A connection that closes
  without `Release` releases its jobs as failed. Files kept open for `Want` are closed
  before the snapshots are released (agent-core), and `lvremove` is retried briefly while
  udev may still hold the device.
- Entry paths are host paths without the leading `/` (`etc/passwd`), so several volumes in
  one job never collide. The walk does not descend into other mounts (it keeps the mount
  point directory itself) unless that mount is also requested; excludes are shell globs
  (`*.tmp` on the name, `/var/cache/**` on the full path).
- `PrepareEx` (v1.3): regex excludes and include roots (`agent_core::filter`, same rules as
  the NAS connector: exclusion wins, the directories leading to an include root are kept);
  `cross_mounts` adds every data file system mounted below the requested paths (and nested
  btrfs subvolumes) as a root of its own with its own snapshot, except the `skip_fstypes`
  (default: pseudo, in-memory, overlay, network file systems), mounts at or below an
  excluded directory and anything below a skipped mount; skipped network/data file systems
  are noted in the job log. Limits: `bwlimit` paces the `Want` data (token bucket in
  agent-core), `nice` lowers the session thread's CPU priority (never raises it: the unit
  runs with `Nice=10`, best-effort 7) and from 15 on uses the idle I/O class.

- Device entries keep their file type bits (`S_IFBLK`/`S_IFCHR`) in `mode`; all other
  entries carry permission bits (`& 0o7777`).
- xattrs: everything `llistxattr` returns (user, trusted, security incl. SELinux labels and
  capabilities, `system.posix_acl_*`) except XFS's `trusted.SGI_ACL_FILE/DEFAULT` (the
  on-disk form of the POSIX ACLs, listed to root; meaningless on other file systems), which
  is neither backed up nor restored.
- Fallback (no snapshot): a file whose size/mtime/ctime changed while it was read is
  `inconsistent` (and not put in the metadata cache). Chunk data read during the scan is
  spooled (bounded by `spool_max_bytes`, unlinked file) so `Want` returns exactly the bytes
  that were hashed even if the file changes afterwards.
- `Want`: chunks are re-read (spool or file range) and verified (`blake3 == hash`) before
  sending. If some cannot be served (live file changed after the scan, beyond the spool), the
  stream ends with `Error { code: 410 }` listing them instead of `WantDone`.
- Metadata cache: the agent cannot map `BaseRef.time` to one of its scans (the appliance's
  snapshot time is never sent to the agent), so it keeps one committed cache (last
  `Release { success: true }`) and uses it for any `Scan` with a base. Safe: unchanged
  entries carry their full chunk list and every chunk remains fetchable via `Want`.

## Restore

`RestoreBegin` needs a non-empty `confirm` (the agent name typed in the UI; checked by the
appliance), which is logged to the journal with the target and policy. The target is
created if missing. `/` (also via symlinks) is refused unless `overwrite = Always`. Order as
sent by `agent-conn`: each `RestoreEntries` batch is followed by its chunks (entry and chunk
order, repeats resent); the agent places a chunk wherever a pending file needs that hash, so
any order works as long as a file's entry precedes its chunks. A root entry `""`/`"."` is
ignored. Destinations kept by the overwrite policy are logged, not reported as errors
(errors fail the appliance job). Every component is opened with
`openat2(RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS|RESOLVE_NO_MAGICLINKS)`; files are created
under a temporary name with `O_EXCL` and renamed over the destination (a planted symlink is
replaced, never followed); existing directories in the way of a file are never removed.
Owner, mode, xattrs (incl. ACLs, `security.*`), mtime are applied; directory metadata and
hard links last. Non-root restores keep the restoring user as owner.

The agent is also the restore target for files from other machines (Phase 15b: NAS shares,
TrueNAS datasets, plugin file trees, VM/CT files, other hosts). The appliance then sends
`uid`/`gid` = -1, so `fchown` leaves the agent's restore user (root for the packaged
service) as owner; setuid/setgid/sticky bits are cleared, devices and sockets are not
sent, and only `user.*` xattrs arrive (docs/agent-protocol.md "Restore to another host").
Confinement, overwrite policy and confirmation are the same as for the own host's files.

## Self-update

`Update.signature` = output of `cosign sign-blob --key <release key>` (base64 DER ECDSA
P-256 over SHA-256), produced by `release/sign.sh sign-blob`. Verified against
`/etc/nexus-agent/release-keys/*.pub`. The version is read from the marker embedded in the
signed binary (must equal the claimed version and be strictly newer). Refused while jobs
or a restore run. Atomic rename over the running binary (old one kept as `.prev`), then
exit 75 → systemd restarts (`RestartForceExitStatus=75`). The binary must stay below the
8 MiB frame limit (currently ~3.3 MiB).

Package installs: the package owns `/usr/bin/nexus-agent`, so a self-update would be undone
by the next package upgrade and flagged by `rpm -V` / `debsums`. If
`/usr/lib/nexus-agent/package-managed` exists, `Update` is refused before any check ("installed
from a deb package: update it with the package manager …") unless `agent.conf` says
`self_update = on`; `self_update = off` disables it for bundle installs too. `nexus-agent
status` shows the state. The appliance's **Update agent** job then fails with that message;
bundle installs keep updating as before.

## End-user status: `nexus-agent tui` and the status commands

Design: docs/endpoint-ui.md (Veeam Agent for Linux style). Module `crates/agent-linux/src/endpoint/`; it uses only
the local IPC contract (`crates/agent-ui-proto`: socket `/run/nexus-agent/ui.sock`, root:`nexus-agent-ui` 0660,
newline-delimited JSON) and never reads agent files, so it runs as any user in the group.

- `nexus-agent tui` (ratatui + crossterm, same binary): header (agent, appliance, managed by, next run, last
  success, state, "not reached since …"), "Latest backup sessions" (result label + glyph, start, duration,
  transferred, warnings), session detail (summary / data / first error / log tail), log view, confirm dialog for
  **S** (request backup; hidden when `ui_policy.hide_backup_now`), progress bar while running (percent if known,
  bytes). Keyboard only, 80×24, `NO_COLOR` = monochrome (results are labelled, never colour only; selection is
  reverse video). Accent colour and header text come from `ui_policy`. Reloads every 10 s (2 s while running).
- `nexus-agent status [--json]`, `sessions [--limit N] [--json]` (default 20), `session <id> [--json]`,
  `request-backup [--json]`; `--socket PATH` overrides the socket (tests). JSON = the contract's reply types.
  As root, plain `status` also prints the local diagnostics (`agent_core::status_common`, volumes), even when the
  service is down (package checks and lab use that).
- Exit codes: `0` ok, `1` error (usage, invalid answer), `2` permission denied on the socket ("add your user to
  the group nexus-agent-ui"), `3` service not running (no socket / refused), `4` the agent refused (rate limit,
  policy, unknown session).
- Tests: rendering snapshots with ratatui's `TestBackend` (80×24, UTC, monochrome) for the main, detail, log,
  confirm, requested, running, unreachable, empty and service-down screens in
  `crates/agent-linux/src/endpoint/snapshots/` (`UPDATE_SNAPSHOTS=1 cargo test -p agent-linux endpoint`; the
  dumps are the manual's screenshots, manual/04-sources.md "On the endpoint"); CLI output and exit codes against a
  fake service on a temporary socket (`tests/endpoint_cli.rs`).

## systemd hardening

See the comments in `crates/agent-linux/dist/nexus-agent.service`: capability bounding set
limited to what backup/restore/snapshots need, `PrivateMounts`, `ProtectKernel*`,
`RestrictNamespaces=mnt`, syscall deny list. Not used, with reasons: `ProtectSystem`,
`ProtectHome`, `PrivateTmp`, `PrivateDevices`, `RestrictSUIDSGID`, `MemoryDenyWriteExecute`,
`PrivateIPC`. `systemd-analyze security`: 4.3. No `User=root` (root is the default): with an
explicit `User=` and `NoNewPrivileges=yes`, systemd 257 drops `CAP_SETUID` from the
permitted set and the DB hook examples (`setpriv --reuid=postgres`) fail. `SuccessExitStatus=75`
next to `RestartForceExitStatus=75`: a self-update restart is not logged as a failure.

## Tests

`cargo test -p agent-linux` (no root): scan/metadata/hardlinks/xattrs, cache, fallback
inconsistency + spool, excludes, mount boundaries, hook permission checks and timeouts,
restore confinement (symlink attacks), update checks (the cosign signature
verification with the real `cosign sign-blob` fixture made with the TEST key is in
`agent-core`, fixture in `crates/agent-core/tests/fixtures/`), plus `tests/e2e.rs`: fake
appliance with a test CA — MITM on enrollment, lock after 5 failures, mTLS client checks,
enrollment → backup → incremental backup → restore with byte + metadata comparison; `tests/interop.rs`:
the real agent against the real `agent-conn` library (enroll, backup into a chunk store,
second backup without transfer, mapping index lost → Want of unchanged files, restore).

Root-only (`#[ignore]`), run in a VM:

```
sudo NEXUS_TEST_LVM=/mnt/lv  cargo test -p agent-linux lvm_snapshot   -- --ignored
sudo NEXUS_TEST_ZFS=/tank/ds cargo test -p agent-linux zfs_snapshot   -- --ignored
sudo NEXUS_TEST_BTRFS=/mnt/b cargo test -p agent-linux btrfs_snapshot -- --ignored
```

Each writes a marker file, snapshots, changes the file, checks the snapshot still shows
the old content, releases, and checks that nothing is left in the journal.
`lab/linux/snapshot-tests.sh <vm>` builds the static test binary
(`cargo test -p agent-linux --lib --no-run --target x86_64-unknown-linux-musl`; the
integration tests need SQLite and do not link for musl) and runs these in a lab VM.

## Lab results (2026-10-09, `lab/linux/`, see lab/README.md)

Real distributions from official cloud images, agent 0.1.0 static musl bundle (`install.sh
--token -`), the dev control plane (keyd, web-api, scheduler, `nexus-agentctl`) on the host,
one VM at a time (2 vCPU, 1.5–2 GB). Every row: root snapshot tests ok, enrollment, a
*scheduled* backup, an incremental one, restore to a new path with byte + owner/mode/mtime/
xattr/ACL/hard-link/file-capability comparison (all entries identical), tar + zip download
(content, owners, PAX xattrs/ACLs), DB restore from the hook dump, signed self-update
0.1.0 → 0.1.1 (foreign signature and same version refused), backup after the update.
Times: job duration (scheduler, s); bytes: transferred chunk bytes.

| VM | Distro / kernel | Volumes (snapshot) | consistent | full: entries, data → transferred, s | incremental: transferred, s | restore s | update s | snapshot tests |
|---|---|---|---|---|---|---|---|---|
| deb-lvm | Debian 13, 6.12 cloud | `/` LVM thick ext4 (root on LVM), `/var/lib/postgresql` LVM thick ext4, `/srv/xfs` LVM thin XFS | true | 3331, 280 MB → 127 MB, 17 | 10.0 MB, 2 | 2 | 9 | 3 × ok (0.5–0.6 s) |
| alma-xfs | AlmaLinux 10.2, 6.12 EL (SELinux enforcing, agent in `unconfined_service_t`, no AVCs) | `/srv/xfs`, `/var/lib/mysql`, `/var/backups` LVM thick XFS | true | 443, 325 MB → 85 MB, 5 | 4.5 MB, 1 | 2 | 8 | 2 × ok (0.4 s) |
| ubuntu-zfs | Ubuntu 24.04, 6.8 generic | `/home`, `/srv/zfs` ZFS datasets (posixacl, xattr=sa) | true | 464, 191 MB → 57 MB, 3 | 4.2 MB, 0 | 4 | 8 | 2 × ok (0.2 s) |
| fedora-btrfs | Fedora 44 Cloud, 6.19 (SELinux enforcing) | `/` + `/home` btrfs subvolumes, `/srv/btrfs` nested subvolume | true | 2200, 213 MB → 78 MB, 9 | 5.5 MB, 0 | 2 | 8 | 2 × ok (0.2 s) |
| deb-plain | Debian 13, 6.12 cloud | `/` ext4 on a partition (no LVM) | false + `backup_inconsistent` alert; a file rewritten during the read counted inconsistent | 1742, 292 MB → 76 MB, 5 | 21.7 MB (incl. the 16 MiB busy file), 1 | 1 | 7 | – (fallback) |

Data includes sparse 64 MiB files and DB dumps; transferred < data because of in-backup
dedup and zero chunks. Incremental: 4 KiB overwritten in a 24 MiB file, 2 MiB appended, a new
1 MiB file, a chmod, a delete, plus the hook dump and DB files. Through the **appliance VM
under SELinux enforcing** (deb-lvm via 10.0.2.2:17441; `nexus-agentctl` in
`nexus_agentctl_t`, CA files `nexus_agent_ca_t`, 7444 = `nexus_agent_port_t`): enroll,
scheduled backup (full 7 s, 153 MB transferred), incremental, restore, tar/zip, DB restore,
signed update with `/usr/share/nexus/agent` (lab: `bootc usr-overlay`) — zero AVCs since boot
(`lab/appliance/e2e.sh check`), first-boot wizard in `nexus_setup_t`.

Found and fixed in the lab: thick LVM snapshot size not a multiple of 512 (every thick
snapshot of a 3 GiB root failed → live read); `User=root` + `NoNewPrivileges` dropped
`CAP_SETUID` (DB hooks failed); the open `Want` file kept the snapshot busy (`lvremove`:
"contains a filesystem in use", leftover LVs); origins with snapshots (`o` attr) read live
without a note; journal entries for vanished objects retried forever; XFS
`trusted.SGI_ACL_*` restored as junk onto other file systems; nested btrfs subvolumes backed
up as empty directories (silent data loss); `/usr/local/sbin` not in sudo's `secure_path` on
EL/Fedora (install hints); scheduler started agent jobs before the firewall allowed the new
agent ("No route to host"); agent backup job result lacked `consistent`/transferred bytes.

Not covered by the lab: root on LVM for EL (Alma's data LVs only), thin-pool exhaustion
during a backup, ZFS child datasets below a requested path (they are mounts: not included
unless requested, as documented), very large trees (entry list in memory), certificate
renewal, agent host/port changes, IPv6, openSUSE (btrfs with snapper's `/.snapshots`).
