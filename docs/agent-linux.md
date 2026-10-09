# Linux agent (`nexus-agent`)

Static musl binary for all distributions (crate `crates/agent-linux`), implementing
`docs/agent-protocol.md`. The platform-independent half (TLS/enrollment/mTLS server,
session state machine, FastCDC + BLAKE3 chunking, metadata cache, `Want` serving,
restore stream handling, update signature checks) lives in `crates/agent-core` and is
shared with the Windows agent (docs/agent-windows.md); `agent-linux` implements its
`Platform` and `RestoreFs` traits. It listens (TCP 7444, TLS 1.3, ALPN `nexus-agent/1`) and never
connects out.

## Install

```
crates/agent-linux/dist/build-bundle.sh [--test-key] [--sign]   # on the build host
tar xzf nexus-agent-<v>-x86_64.tar.gz && cd nexus-agent-<v>-x86_64
echo '<token from the UI>' | sudo ./install.sh --token -          # on the server
```

`install.sh` installs `/usr/local/sbin/nexus-agent`, `/etc/systemd/system/nexus-agent.service`,
`/etc/nexus-agent/{hooks.d/{pre,post},release-keys}` and, with a token, runs
`nexus-agent init` and starts the service. Other commands: `nexus-agent status`,
`nexus-agent hooks test`, `nexus-agent init --token <T>` (re-enrollment; also clears the
lock after 5 failed proofs), `nexus-agent run` (the service).

Files: `/etc/nexus-agent` (0700): `agent.conf`, `token` (`agent_proto::token_digest`, deleted
after enrollment), `agent.key` (0600), `enroll.crt`, `agent.crt`, `ca.crt`, `agent.id`.
`/var/lib/nexus-agent` (0700): `enroll.failures`, `cache/committed.bin`, `snapshots.journal`,
`spool/` (unlinked spool files only).

`agent.conf` (`key = value`): `listen` (`::`), `port` (7444), `lvm_snapshot_percent` (10),
`hook_timeout_secs` (3600), `spool_max_bytes` (2 GiB), `appliance_id` (pin the client
certificate CN `nexus-appliance:<id>`), `max_connections` (4). Unknown keys are errors.

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

## Backup

- `Prepare`: run pre hooks (if `hooks`), then one snapshot per affected volume:
  LVM thin (`lvcreate -s -kn`), LVM thick (`lvcreate -s -L <pct of origin>`), mounted
  read-only below `/run/nexus-agent/<job>/<n>` in the agent's private mount namespace (XFS
  `nouuid`, retry with `norecovery`; ext3/4 retry with `noload`); ZFS (`zfs snapshot`, read via
  `.zfs/snapshot/`); btrfs (read-only snapshot in `<mountpoint>/.nexus-snapshots/`, skipped by
  the scan). If a volume cannot be snapshotted the agent reads it live and `consistent` is
  `false` (reason in `hook_log`). A failing pre hook fails `Prepare` (post hooks still run).
- Every created object is recorded in `snapshots.journal` before creation; release removes
  it, and service start removes leftovers (journal + any LV / ZFS snapshot named
  `nexus-snap-*`). A connection that closes without `Release` releases its jobs as failed.
- Entry paths are host paths without the leading `/` (`etc/passwd`), so several volumes in
  one job never collide. The walk does not descend into other mounts (it keeps the mount
  point directory itself) unless that mount is also requested; excludes are shell globs
  (`*.tmp` on the name, `/var/cache/**` on the full path).
- Device entries keep their file type bits (`S_IFBLK`/`S_IFCHR`) in `mode`; all other
  entries carry permission bits (`& 0o7777`).
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

## Self-update

`Update.signature` = output of `cosign sign-blob --key <release key>` (base64 DER ECDSA
P-256 over SHA-256), produced by `release/sign.sh sign-blob`. Verified against
`/etc/nexus-agent/release-keys/*.pub`. The version is read from the marker embedded in the
signed binary (must equal the claimed version and be strictly newer). Refused while jobs
or a restore run. Atomic rename over the running binary (old one kept as `.prev`), then
exit 75 → systemd restarts (`RestartForceExitStatus=75`). The binary must stay below the
8 MiB frame limit (currently ~2 MiB).

## systemd hardening

See the comments in `crates/agent-linux/dist/nexus-agent.service`: capability bounding set
limited to what backup/restore/snapshots need, `PrivateMounts`, `ProtectKernel*`,
`RestrictNamespaces=mnt`, syscall deny list. Not used, with reasons: `ProtectSystem`,
`ProtectHome`, `PrivateTmp`, `PrivateDevices`, `RestrictSUIDSGID`, `MemoryDenyWriteExecute`,
`PrivateIPC`. `systemd-analyze security`: 4.3.

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
