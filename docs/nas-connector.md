# NAS connector (NFS / SMB shares)

Status: v1 (2026-10-09). Decision (plan.md §2, §7.4): **kernel NFS/SMB mounts, read-only, in a private
mount namespace, done by a small privileged helper with its own SELinux domain**; file level, metadata
cache, parallel scan; no consistent point in time without NAS snapshots. Crate `crates/nas`
(binaries `nexus-nas` and `nexus-nasmount`), lab `lab/nas/`.

## 1. Design

```
scheduler (nexus-chunkstore, no capabilities, NoNewPrivileges)
  └─ nexus-nas <job>/nas.json backup              SELinux nexus_nas_t
        │ connect /run/nexus-nasmount/mount.sock  (socket 0660 root:nexus-chunkstore)
        ▼
     systemd nexus-nasmount.socket (Accept=yes) ─▶ nexus-nasmount@<n>.service   nexus_nasmount_t
        root, CapabilityBoundingSet=CAP_SYS_ADMIN, one request, then exit
        fsopen("nfs4"|"nfs"|"cifs") → fsconfig(key, value)… → FSCONFIG_CMD_CREATE
        → fsmount(MOUNT_ATTR_RDONLY|NOSUID|NODEV|NOEXEC|NOSYMFOLLOW)   (never move_mount)
        ◀─ "ok\n" + the mount fd (SCM_RIGHTS)
  nexus-nas walks the share relative to that fd (openat2 RESOLVE_BENEATH|NO_SYMLINKS|NO_XDEV),
  chunks into the tenant store, commits Index::Tree share-<source>; exits → last fd closed → kernel unmounts
```

### Mount isolation (why this design)
- **Detached mount, handed over as an fd.** `fsmount()` creates the mount in an *anonymous* mount
  namespace that no process lives in; the helper never attaches it (`move_mount` is never called, no
  `mounton` permission on any directory). It is not visible in `/proc/*/mountinfo` of any process, not
  in the host namespace, not in the connector's namespace — only reachable through the fd. This is a
  private mount namespace in the strictest sense: it contains exactly the share and nobody's root.
- **Cleanup is the kernel's.** The mount lives exactly as long as an fd refers to it. The helper exits
  right after sending the fd; when `nexus-nas` exits (normally, killed by the scheduler, crashed), the
  last reference goes and the kernel dissolves the anonymous namespace and unmounts the share. No
  unmount step can be forgotten, no stale mount survives a crash. `RuntimeMaxSec=300` bounds a helper
  instance that hangs on an unreachable server.
- **Least privilege.** The helper is the only privileged piece: root, bounding set `CAP_SYS_ADMIN`
  (nothing else), `NoNewPrivileges`, `ProtectSystem=strict`, `PrivateTmp/Devices/IPC`,
  `SystemCallFilter=@system-service @mount`, no file access beyond its runtime dir. It runs only per
  connection (socket activation). The connector stays unprivileged (scheduler user, no capabilities)
  and never mounts. SELinux: `nexus_nasmount_t` may mount `nfs_t`/`cifs_t` superblocks and nothing
  else; `nexus_nas_t` may read `nfs_t`/`cifs_t` through the received fd (`neverallow` write/mount).
- **Trust in the request.** The helper treats the connector's request as untrusted: strict bounded
  parser (`proto.rs`, fuzzed), every field validated, only fixed option names, every value a separate
  `fsconfig` call (no comma-joined option string, so no option injection through a value; the SMB
  password never touches a file or a command line). Read-only, nosuid, nodev, noexec, nosymfollow
  are set by the helper, not requested. A compromised `nexus-nas` can at most make the kernel mount
  some other NFS/SMB server read-only for itself — only on destinations the firewall allow-list
  permits (the kernel's connections pass the appliance's nftables output chain). Peer check:
  `SO_PEERCRED` uid must be `nexus-chunkstore` (`NEXUS_NASMOUNT_ALLOW_USER`), and the socket is 0660
  `root:nexus-chunkstore`.
- **Alternatives considered.** (a) A `PrivateMounts=yes` unit for the connector plus a helper that
  `setns()`es into it: two privileged steps, the mount sits in a namespace a process lives in, and the
  connector's sandbox would have to be a separate unit instead of a scheduler job. (b) The helper
  creates a namespace and execs the connector inside it: the connector would start as root (or the
  helper would need `CAP_SETUID`), and cleanup needs a reaper. (c) `mount.cifs`/`mount.nfs` with a
  credentials file: user-space mount helpers parse option strings, resolve names, and need the
  password on disk. The fd hand-over needs none of that.

### Hostile server
The kernel client's attack surface is accepted by the decision; on top of it:
- `ro` superblock + read-only, `nosuid`, `nodev`, `noexec`, `nosymfollow` mount: nothing on the share
  can become an executable, a device, a setuid binary, or redirect a path walk through a symlink.
- The walk never follows symlinks (`openat2 RESOLVE_NO_SYMLINKS`, `AT_SYMLINK_NOFOLLOW`), never leaves
  the root (`RESOLVE_BENEATH`), never crosses a mount (`RESOLVE_NO_XDEV`), and `statx` uses
  `AT_NO_AUTOMOUNT`: nested exports, referrals and automounted snapshot dirs are recorded as an empty
  directory and not descended into (logged as a note). Only the configured snapshot directory is
  entered deliberately.
- Names and link targets are bytes from the server: a path longer than 4096 bytes or containing NUL
  is refused per entry; xattr values are bounded (64 KiB per entry in total).
- NFS: `addr=` (no DNS in the kernel), `soft,timeo=<timeout>,retrans=2` (a dead server fails the job
  instead of hanging it), v3 `mountport=` (no rpcbind/portmapper) and `nolock` (no NLM/statd),
  `nosharecache`. SMB: `ip=` (no DNS upcall), `soft`, `echo_interval`, `nobrl`, `nosharesock`,
  `nolease`.

### Mount options (built by `opts.rs`)
| | NFS | SMB (`cifs`) |
|---|---|---|
| always | `ro`, `soft`, `timeo=<10×timeout>`, `retrans=2`, `sec=sys`, `nosharecache`, `addr=<ip>`, `proto=tcp\|tcp6`, `port`, `vers=3\|4.0\|4.1\|4.2` | `ro`, `ip=<ip>`, `port`, `vers=2.1\|3\|3.0\|3.02\|3.1.1`, `sec=ntlmssp\|krb5`, `noperm`, `backupuid=<connector uid>`, `soft`, `echo_interval`, `nobrl`, `nosharesock`, `nolease` |
| v3 | `mountvers=3`, `mountproto=tcp`, `mountport=<mountd>`, `nolock` | |
| options | | `sign` (default on), `seal` (SMB3 encryption), `username`, `domain`, `password` (one fsconfig value), `cruid=0` (krb5) |
| mount attributes | `RDONLY NOSUID NODEV NOEXEC NOSYMFOLLOW` | same |

`noperm`: the client does not check the faked modes; the server decides with the SMB user's rights.
`backupuid`: opens of the connector carry the backup-intent flag (a user with SeBackupPrivilege reads
everything on Windows servers). `nolease`: the client keys leases per inode, and the server refuses a
second name of a hard-linked file while the first is open (`EINVAL` on open, lab) — a one-pass reader
gains nothing from leases anyway.

### Reading every file (supported setup — decided 2026-10-10)
The connector runs unprivileged, so the server must grant read access. These two server-side models are
the **supported, documented setup** (user decision 2026-10-10); the admin configures them on the NAS:
- **NFS** (AUTH_SYS sends the connector's uid): export the share read-only to the appliance with
  `ro,all_squash,anonuid=0,anongid=0` (every request of the appliance is root on the server — read
  everything, write nothing). Without it only world-readable files are backed up (unreadable ones are
  reported and make the snapshot not consistent). Behind NAT (lab) also `insecure`.
- **SMB**: a backup user that can read everything: Windows — member of Backup Operators (SeBackupPrivilege,
  used via the backup-intent opens); Samba — `admin users = <backup user>` on a read-only share
  definition, or read ACLs on everything.
- NFS v4 with `sec=krb5*` is not supported in v1 (`sec=sys` only).

## 2. Scan and change detection (`scan.rs`)
- **Parallel scan**: a bounded pool of worker threads (`threads`, default 16, 1..=64) takes work items
  from a shared queue: `Dir` (open, xattrs, list + sort names; small directories are processed inline)
  and `Batch` (256 names of a large directory: a directory with a million files is read by all workers).
  Results are stored per directory and batch slot and assembled in pre-order with sorted names, so
  the tree is identical for any number of threads (unit test).
- **Metadata cache**: the previous `share-<id>` snapshot. A regular file reuses its keyed chunk IDs and
  xattrs if a previous regular file with the same path or the same inode has the same inode, size,
  mtime **and ctime**, was consistent, and all its chunks are still in the store; otherwise it is read.
  ctime changes with every content, xattr/ACL and owner change and cannot be set by users (mtime can);
  a renamed file gets a new ctime on most servers and is read again (deduplicated: no new chunks).
  Directories reuse their xattrs under the same rule. Reused files and directories cost no xattr RPCs.
  **Samba caveat**: Samba reports the mtime as ChangeTime, so over SMB to Samba a same-size rewrite
  with a restored mtime is not detected (lab: `small/f3`); NFS and Windows servers report the real change time.
- **Change during read**: after reading a file its attributes are fetched from the server again
  (`AT_STATX_FORCE_SYNC`); a different size/mtime/ctime, a short read, or a file replaced between
  listing and open marks it `inconsistent` (kept, flagged). Inconsistent files are never reused.
- **Hard links**: the first name in tree order is the file, later names are `Hardlink` entries (same as
  agent and TrueNAS snapshots); the content is read once. SMB clients report link count 1 for hard
  links (Samba), so there each name is stored as a file (deduplicated).
- **NAS snapshots**: with `snapshot_dir` (e.g. `.zfs/snapshot`, `.snapshot`, `~snapshot`) the connector
  reads the newest snapshot below it instead of the live share (`snapshot_prefix` filters names,
  `snapshot_order` = `name` (time-stamped names) or `mtime` (NetApp `hourly.0`)). Opening the
  snapshot may cross into an automounted file system (NFSv4 `crossmnt` submount; lab); below it the walk
  is confined again. No matching snapshot: the live share is read and the snapshot is not consistent.
  Snapshot directory names (`.snapshot`, `~snapshot`, `.zfs`) are never backed up as data.
- **Consistency**: `consistent = true` only for a NAS snapshot with no inconsistent and no unreadable
  entry; otherwise the job prints `inconsistent share-<id>/<time>: …` and the scheduler raises
  `backup_inconsistent` (as for agents without a snapshot).
- **Excludes**: patterns as for agents (`*.tmp`, `/path/**`), matched against `/<path in the share>`; also
  regex excludes and include roots (`include`, `exclude_regex` in nas.json, Phase 15e) with the same rules as the
  agents (`agent_core::filter`: exclusion wins, directories leading to an include root are kept), and the global
  excludes of the group's policy (merged by the scheduler). Nested mounts are never descended (no `cross_mounts`).
- **Memory**: entries are held in memory until the commit (one sealed `Index::Tree`, like agents and
  TrueNAS): ~0.5–0.7 KB per entry (path, chunk list, xattrs; more with an NFSv4 ACL per file) plus the
  previous tree; the 1M-entry incremental peaked at 0.73 GB (lab). Streaming the tree index needs a split tree index format in
  the chunk store (proposed, §9).
- **Store**: every new small file is one chunk file in the store (fsync each): the full backup of a
  million small files is bound by chunk writes, the unchanged run by `statx`.

### Metadata captured
| | NFSv3 | NFSv4.x | SMB 3 (Samba lab) |
|---|---|---|---|
| owner, group | numeric uid/gid | numeric (`sec=sys`; with name-based idmapping and no idmap on the appliance: `nobody`) | faked by the client (0/0; the real owner is in the security descriptor) |
| mode | real | real | faked (no unix extensions) |
| times | mtime, ctime (ns) | same | 100 ns |
| ACLs | `system.posix_acl_access/default` (NFSACL) | `system.nfs4_acl` (raw XDR, the server's NFSv4 view) | `system.cifs_acl` (security descriptor: owner, group, DACL; not listed, read by name) |
| xattrs | — | `user.*` (v4.2) | `user.*` (EAs), `user.cifs.dosattrib`, `user.cifs.creationtime` (read by name) |
| symlinks, fifos, devices | recorded (devices with rdev) | same | Samba serves in-share symlinks as the target file and hides others |
| hard links | detected (nlink) | detected | stored per name (nlink 1) |
| not captured | share root's own metadata; SACL (`system.cifs_ntsd_full`, needs SeSecurityPrivilege); `security.selinux` | | |

## 3. Restore
Download (tar keeps owners, modes, mtimes, symlinks, hard links, xattrs incl. ACLs as PAX
`SCHILY.xattr.*`; zip modes and mtimes), using agent-conn's tree download code, and since Phase 15b
**restore onto a host** through an enrolled agent of the same tenant (`restore_files`, docs/agent-protocol.md
"Restore to another host": owners not mapped, only `user.*` xattrs on Linux agents, ACLs dropped; for a
share with Windows ACLs, restore to a Windows host and set the ACLs there, or use the tar download). Restore
into the share itself would need a writable mount and a confinement story for the writer; deferred (the
usual path: restore onto a host that mounts the share).

## 4. Integration
- **Catalog v6**: source kinds `nfs`, `smb` (rebuild of `sources` like v4/v5). Config: `host`, `port`
  (2049 / 445), `version` (`4.2` / `3`), NFS `export`, `mount_port` (v3, 20048), SMB `share`, `user`,
  `domain`, `sec` (`ntlmssp` | `krb5`), `sign` (true), `seal` (false), `password` (sealed) or `keytab`
  (base64, sealed) + `principal`, and for both `snapshot_dir`, `snapshot_prefix`, `snapshot_order`,
  `excludes`, `threads` (16), `xattrs` (true), `timeout_secs` (60). Secrets are bound to
  `host`/`port`/`user` (catalog::secret); GET returns `password_set` / `keytab_set`.
- **web-api**: admin-only CRUD with the helper's own validation (`nas::proto::Request::check`), audit
  `source.create/update`; groups without guests; `share-<id>` accepted by file jobs and by `restore_files` (with a target `agent_id`).
- **Scheduler**: `backup {group_id}` spawns `nexus-nas <job>/nas.json backup` (password / keytab as
  0600 job files), exclusive per source; retention and `files_list`/`files_get` for `share-<id>`
  (no mount, no secrets); result `{source, time, consistent, transferred_bytes}`; alert
  `backup_inconsistent`. Allow-list: NFS port (+ mountd for v3), SMB port. SMB Kerberos also needs the
  KDC (88/tcp) in `/etc/nexus/allowed-hosts`.
- **SELinux**: `nexus_nas_t` (job domain entered from the scheduler), `nexus_nasmount_t` (daemon domain,
  socket activation via `init_named_socket_activation`), `nexus_nasmount_var_run_t` (socket dir and
  per-instance runtime dirs).
- **systemd**: `nexus-nasmount.socket` (enabled by the preset) + `nexus-nasmount@.service`.
- **UI**: NFS/SMB source forms (write-only secrets, keytab upload), groups ("whole share"), dashboard and
  snapshots for `share-` sources (browse, tar/zip download, no restore), job detail shows "not
  point-in-time consistent".

## 5. CLI
`nexus-nas <config.json> backup | check | files <share-<id>> <time> ls <dir> | files … get <out.tar|out.zip> <path>…`
Output: `mounted …`, `reading NAS snapshot …`, `committed share-<id>/<time> in <s>s: <n> entries, <n> files
read (<b> bytes), <n> unchanged files reused (<b> bytes), <n> new chunks (<b> bytes), <b> bytes transferred,
<n> inconsistent, <n> errors, <r> entries/s, NAS snapshot <name> | live share`, `inconsistent …`,
`error <path>: <op>: <errno>` (first 1000), `result {json}`. `local_root` (tests, no root) scans a
local directory instead of mounting. `nexus-nasmount` is socket-activated only.

## 6. SMB Kerberos (`sec=krb5`) — not offered in v1
**Decision 2026-10-10: dropped from v1.** The web-api refuses `sec: "krb5"` and the UI offers only NTLMSSP
(signed, optionally encrypted SMB3). The code below stays for a later release with an AD test lab.

Implemented in API, scheduler and helper: the keytab (sealed) goes to the helper, which writes it 0600
into its per-instance runtime dir, runs `kinit -k -t <keytab> <principal>` into
`KRB5CCNAME=FILE:/run/nexus-nasmount.<instance>/ccache` (set by the unit, so the kernel's
`cifs.upcall` finds it in the helper's environment) and mounts with `sec=krb5,cruid=0`; the keytab file
is removed right after the mount, the runtime dir when the instance ends. **Not enabled in the image**:
it needs `cifs-utils` (cifs.upcall) and `krb5-workstation` (kinit) in the image, a KDC the appliance
can resolve (DNS SRV or `/etc/krb5.conf.d`), and a lab run against an AD DC (§9). A krb5 source fails
with "kinit: No such file or directory" until then.

## 7. Lab (`lab/nas/`)
- `vm.sh` — NAS server VM (Debian 13 cloud image, 3 GB, 4 vCPUs; LVM data disk: `share` 10G ext4,
  `many` 12G ext4 with 1M small files, `store` 7G for the dev control plane, free space for LVM
  snapshots). Ports on 127.0.0.1: ssh 2250, NFS 12049, mountd 12048, SMB 10445, dev API 18453.
- `provision.sh` — nfs-kernel-server (v3 + v4.0–4.2, mountd on 20048), exports
  `ro,all_squash,anonuid=0,anongid=0,insecure,crossmnt,fsid=…`; Samba (`server signing = mandatory`,
  `smb encrypt = desired`, `acl_xattr`, read-only shares with `admin users = nexusbackup`).
- `data.sh` — test data (odd names incl. newline/backslash/UTF-8, deep tree, symlinks to `/` and
  `/etc/shadow`, hard links across dirs, POSIX ACLs, user xattrs, root-only files, other owners, fifo,
  1 GiB sparse file, 64 MiB random file, 2000 small files), `many` (1M files), `modify`, `many-modify`,
  `churn` (writer during the backup), `snap` (LVM snapshot mounted at `.snapshot/<name>`), `sums`, `xattrs`.
- `devcp.sh` — the dev control plane (lab/e2e/m5.sh) **inside the NAS VM** with the real helper units
  (the dev host has no root to mount): shares over the VM's loopback.
- `e2e.sh` — REST end to end (dev control plane, or the appliance VM with `APPL=1`): see §8.
- `compare.py` (downloads vs sha256 of the server's files; `--smb`: names Samba cannot represent are
  not required), `xattrs.py` (xattrs/ACLs in the tar vs `getfattr`).

## 8. Lab results (2026-10-09)
NAS VM: Debian 13, 3 GB, 4 vCPUs (server and, in the dev run, client too). `share`: 2,081 entries,
2,020 files, 1.14 GB apparent (1 GiB sparse file + 64 MiB random file + small files); `many`: 1,000,000
files of 64..4096 bytes in 1,000 directories (2.08 GB). Jobs through the REST API (`lab/nas/e2e.sh`);
the first nfs1 run is the scheduled one. "scan" = connector time (mount → commit).

| run | dev control plane in the NAS VM (loopback) | appliance VM (enforcing; QEMU user net, 10.0.2.2) |
|---|---|---|
| nfs1 full (NFS 4.2) | 2.2 s, 2,018 files, 1.14 GB read, 84 MB new | 9.8 s |
| smb1 full (SMB 3.1.1 signed + encrypted) | 2.6 s, 2,021 files, 1.14 GB read | 11.2 s |
| nfs1 after `modify` | 0.2 s: 9 files read (67 MB: the 64 MiB file edited in place), 2,010 reused | 0.8 s, same counts |
| smb1 after `modify` | 0.2 s: 5 files read, 2,015 reused (`small/f3` missed: Samba ChangeTime) | 0.8 s, same counts |
| nfs1 unchanged | 0.2 s, 0 files read | 0.2 s |
| nfs1 while a writer changes files | 1 file `inconsistent`, `consistent=false`, alert | same |
| nfs1 from `.snapshot/nightly-1` while the live share changes | `consistent=true` (snapshot automounted via NFSv4 crossmnt, inode-based reuse kept: 2,020 reused) | same |
| many1 full (NFS 3, 32 threads) | 462 s, **2,167 entries/s**, 1,000,000 files, 2.08 GB, 1M new chunks | 543.5 s, **1,842 entries/s** |
| many1 unchanged | 13.7 s, **72,922 entries/s** | 27.5 s, **36,410 entries/s** |
| many1 after 1,000 changed + 1,000 new + 1,000 deleted | 15.0 s, 2,000 files read (2.9 MB), 998,000 reused | 27.5 s, 2,000 files read |

Downloads (tar and zip of `/`) matched the sha256 of every file on the server: NFS 2,020/2,020; SMB
2,017/2,017 (3 names Samba cannot represent — backslash, newline, tab — appear mangled, in-share
symlinks as files). xattrs/ACLs in the tar matched `getfattr` (NFS 4.2: `user.*` values and
`system.nfs4_acl` on every POSIX-ACL entry; SMB: `user.*` values and `system.cifs_acl` on every file
and directory). Every share backup without a NAS snapshot raised `backup_inconsistent` (9 per run).
Headless Chrome against the SPA (`lab/nas/ui.mjs`): dashboard, NFS/SMB source dialogs (password
write-only), group dialog (whole share), snapshots without restore, file browser, consistency banner:
8/8 against the dev control plane and against the appliance VM, no CSP or console problems. Fuzzing (`lab/fuzz/run.sh 600 1 nas:helper_request`): 62 M executions, no crash.

Appliance VM (bootc image, real units, SELinux enforcing, nftables egress): **zero AVCs in nexus
domains** (`ausearch -m avc,user_avc,selinux_err -ts boot`; the only denials were lab tooling — the lab
image's install service's `chcon`, a memory poller started from `/var/tmp` — and the base image's
`bootc` update check); helper unit exposure 2.2 (`systemd-analyze security`). The allow-list held
exactly `10.0.2.2 . tcp . 12049/12048/10445`; the catalog held the SMB password only as `sealed:v1:`.
During a backup the kernel's NFS client was connected (`/proc/fs/nfsfs/servers`) while neither the
host namespace (`findmnt`) nor the connector's own `mountinfo` contained an NFS/CIFS mount (detached,
reachable only through the fd). Peak RSS of `nexus-nas` for the 1M-entry incremental runs (previous +
new tree; NFSv3, no xattrs): 0.56–0.73 GB. With 3 GB RAM the appliance VM's incremental run of the 1M-file share was killed by the
OOM killer (slab of 1M NFS inodes + chunk-file dentries + two trees); the runs above use 6 GB.

Lab findings fixed on the way: systemd labels the activation socket with the service domain
(connectto on `nexus_nasmount_t`); `openat2` answers ENOSYS inside the scheduler's sandbox
(`RestrictSUIDSGID=`) — component-wise fallback with the same confinement; concurrent opens of two
names of a hard-linked file over SMB fail with EINVAL under leases (`nolease`); NFSv4 walks the export
path as the mounting process (`nfs_t:dir search` for the helper); one chunk file per small file
exhausted the inodes of a 16 GB ext4 (store moved to its own file system in the lab).

## 9. Limitations and decisions
- Decided 2026-10-10: server-side read access = the two documented models in §1 (NFS export
  `ro,all_squash,anonuid=0,anongid=0`; SMB backup user with Backup Operators / Samba `admin users`).
- Decided 2026-10-10: no SMB Kerberos in v1 (§6).
- Decided 2026-10-10: shares without a NAS snapshot raise the `backup_inconsistent` warning **once per
  source**; files that actually changed while read raise it every time (deduplicated while unacknowledged).
- No restore into the share itself (download, or restore onto a host with an agent, Phase 15b).
- Entries in memory until the commit (~0.7 KB per entry); proposal: split/streamed tree index in the
  chunk store for 10M+ entry shares. Phase 22b mitigations (web-api `nasops.rs`): the sizing note on **Sources**
  (newest run's `entries` from the job result × 800 B, warning ≥ 5M entries or > 25 % of MemTotal), **Split**
  (`POST /sources/{id}/split {roots, password?, copy_groups}`: one share source per include root in one transaction,
  groups copied, audited `source.split`; SMB passwords must be re-entered: sealed values are bound to the source
  id), and the overlap warning (same kind/host/export or share, case-insensitive for SMB, overlapping include roots;
  TrueNAS: nested datasets; computed over the sources the caller sees).
- Skipped entries (Phase 22b): `GET /jobs/{id}/skipped.csv` turns the `error <path>: <reason>` lines (first 1000,
  `MAX_ERRORS`) of a backup log into `path,reason,kind` CSV (formula-leading characters neutralised); the count of
  the committed line tells how many were not listed.
- One chunk file per small file (fsync each): full backups of millions of tiny files are bound by store
  writes; proposal: pack small files into shared chunks (would change the dedup unit).
- Samba ChangeTime = mtime: same-size rewrites with a restored mtime are missed over SMB to Samba.
- Sparse files are read and stored in full (deduplicated zero chunks); the download expands them.
- NFS `sec=krb5*`, NFS over UDP and SMB1 are not supported; NFSv4 name-based id mapping needs an idmap
  configuration on the appliance (numeric ids with `sec=sys` work out of the box).
- Share root metadata (mode/ACL of the export root) is not recorded.
- Change detection is metadata-based (no NFS change attribute / SMB USN yet); every run lists every
  directory (`statx` of every entry, served by READDIRPLUS on NFS).
