# Windows agent (`nexus-agent.exe`)

Crate `crates/agent-windows`, target `x86_64-pc-windows-gnu`, Windows Server 2016 or
newer (2016/2019/2022/2025). Implements `docs/agent-protocol.md` (v1.1) with the same
listen model as the Linux agent: TCP 7444, TLS 1.3, ALPN `nexus-agent/1`, mTLS after
enrollment with the appliance CA + one-time token, never connects out. Everything that
is not Windows-specific is shared with the Linux agent in `crates/agent-core` (TLS /
enrollment / mTLS server, session state machine, FastCDC + BLAKE3 chunking, metadata
cache, `Want` serving, restore stream handling, update signature verification).

> **Test status:** there are no Windows test VMs yet (decision 2026-10-09). The
> Windows binary is cross-compiled and the platform-independent logic is unit-tested on
> Linux; **nothing has run on Windows**. See "Untested" and the manual test plan below
> before using it on a real server.

## Build

```
crates/agent-windows/build.sh [--test-key] [--sign] [--clippy]
```

Rootless podman: `docker.io/library/rust:1.93-slim-trixie` + `gcc-mingw-w64-x86-64`
(builder image cached as `localhost/nexus-agent-windows-build:<hash>`, crates cached in
the podman volume `nexus-cargo-registry`). Release profile with LTO, `opt-level=s`,
stripped, `+crt-static` (imports only system DLLs; the script checks the import table).
Output `target/agent-dist/windows/`: `nexus-agent.exe`, `nexus-agent.exe.sig`
(`--sign`: `release/sign.sh sign-blob`), `nexus-agent.version`, `release-keys/`,
`README.md`. Size 2026-10-09: **1 863 680 bytes (1.8 MiB)**, limit for in-band updates
8 MiB − 4 KiB (checked by the script). `--clippy` runs clippy `-D warnings` for the
Windows target in the container (CI job `agent-windows`).

After a signed build (`COSIGN_KEY=release/testkey/TEST-cosign.key
COSIGN_PASSWORD=nexus-test-key release/sign.sh sign-blob target/agent-dist/windows/nexus-agent.exe{,.sig}`
for lab builds), `cargo test -p agent-windows --test dist -- --ignored` checks the
artifact: PE32+ x86-64, embedded version, fits one frame, signature verifies with the
TEST key through the same code path as a self-update.

## MSI

`nexus-agent-<v>-x64.msi` on every release, built by `release/packages.sh` (after
`build.sh`) with **wixl** from msitools in a Fedora container (WiX 3 schema,
`crates/agent-windows/dist/nexus-agent.wxs`). wixl rather than WiX v4/v5: Linux-native, no
.NET SDK or Windows container, and it covers what the MSI needs (ServiceInstall,
ServiceControl, MajorUpgrade, custom actions from an installed file). What it cannot do:
the WiX util extension (failure actions, ACLs; done by the agent below) and listing
`Secure="yes"` properties in `SecureCustomProperties` (PURGE therefore reaches the server
side only for administrators; uninstalls run elevated anyway).

- `C:\Program Files\NexusBackup Agent\`: `nexus-agent.exe`, `README.md`, `package-managed`
  (`msi`: self-update off, see below). Per machine, x64, Add/Remove Programs entry
  "NexusBackup Agent" (no modify/repair), fixed UpgradeCode
  `f0236c93-ddce-4b09-a197-525c84656168`: a newer MSI replaces an older one (major
  upgrade, enrollment kept), a downgrade is refused.
- `%ProgramData%\NexusAgent\config\release-keys\*.pub` (the pinned release keys).
- Service `NexusAgent` (ServiceInstall: own process, auto start, LocalSystem, argument
  `service`); ServiceControl: start on install (without waiting), stop on install and
  uninstall, delete on uninstall. An agent that is not enrolled yet logs "not initialised"
  and stops with exit code 0 (no failure-action restarts).
- Deferred custom action `nexus-agent.exe service-setup` (LocalSystem, after
  InstallServices): the protected ACL on `%ProgramData%\NexusAgent` (also over the keys the
  MSI just wrote) and the failure actions, as `nexus-agent.exe install` sets them.
- Uninstall keeps `%ProgramData%\NexusAgent`; with `PURGE=1` the deferred custom action
  `nexus-agent.exe purge-data --yes` (after DeleteServices, not during an upgrade) deletes
  it. No firewall rule (open TCP 7444 for the appliance address yourself).
- No token property on purpose: tokens are one-time and per host, so one GPO/Intune
  command line cannot carry them, and MSI properties end up in verbose logs, deployment
  configuration and process lists. Enroll afterwards:
  `echo <token> | nexus-agent.exe init --token -` (or interactively), then
  `sc.exe start NexusAgent`.

Silent: `msiexec /i nexus-agent-<v>-x64.msi /qn [/l*v install.log]`, uninstall
`msiexec /x nexus-agent-<v>-x64.msi /qn [PURGE=1]`. GPO: computer software installation;
Intune: line-of-business app (device context).

Checked on Linux (`release/test-packages.sh`, msitools): tables present, ServiceInstall
and ServiceControl rows, custom action types and conditions, upgrade code, no token
property, x64 template, extracted file layout. **A real installation has not run on
Windows** (no Windows VMs); add the MSI to the manual test plan below.

## Desktop UI (`nexus-agent-gui.exe`)

The MSI also installs the desktop UI from `crates/agent-gui` (shared with Linux desktops, docs/endpoint-ui.md):
tray icon with the protection state and a Control Panel window (status, bar chart of the last 30 sessions, session
details, "Request backup now"). It talks only to the agent service's named pipe `\\.\pipe\nexus-agent-ui` (local
interactive users; nothing on the pipe changes configuration or reads backup data) and never to the network.

- Cross-compiled with the agent's mingw builder image: `crates/agent-gui/build.sh` (also Linux x86_64/aarch64;
  `--clippy` for the Windows target). iced with the tiny-skia software renderer (no GPU driver needed, works over RDP),
  tray via tray-icon (Win32 notification area). Imports only Windows system DLLs (checked by the script); about 3.5 MB.
- MSI: `C:\Program Files\NexusBackup Agent\nexus-agent-gui.exe`, Start menu entry "NexusBackup Agent" (`--open`), and
  the **per-machine** Run key `HKLM\Software\Microsoft\Windows\CurrentVersion\Run\NexusBackupAgentGui`, so it starts
  in the tray at every user logon (decision: the MSI is per machine and GPO/Intune deploy it in device context; a
  per-user HKCU entry would need every user to run an installer). Users switch it off in Task Manager > Startup;
  administrators remove the value by GPO. One instance per logon session (named mutex).
- Updates: the GUI is replaced by the next MSI (major upgrade); a running GUI keeps the file in use, so Windows
  Installer asks to close it (interactive) or replaces it at the next restart (`/qn`).
- Desktop notifications on failed / warning backups are off by default; the setting is per user
  (`%APPDATA%\NexusBackup\agent-gui.json`).
- **Untested on Windows** like the agent itself (no Windows VMs): the tray, pipe access for non-admin users and the
  Run key belong to the manual test plan below.

## Manual install (without the MSI)

As Administrator, on the server:

```
mkdir "C:\Program Files\NexusAgent"
copy nexus-agent.exe "C:\Program Files\NexusAgent\"
copy release-keys\*.pub %ProgramData%\NexusAgent\config\release-keys\   (create the dir)
cd "C:\Program Files\NexusAgent"
echo <token from the UI> | nexus-agent.exe init --token -
nexus-agent.exe install
```

`install` registers the service `NexusAgent` (LocalSystem, automatic start, arguments
`service`), sets failure actions (restart after 2 s / 10 s / 60 s, counter reset after
one day, also on non-crash failures) and starts it. Other commands: `status`, `run`
(foreground), `uninstall` (keeps config/state), `version` (or `--version`), `service-setup` and
`purge-data --yes` (used by the MSI), `init --token` again for
re-enrollment or to clear the lock after 5 failed proofs. Open TCP 7444 in the Windows
firewall for the appliance address only.

Files: `%ProgramData%\NexusAgent\` with a protected ACL — owner Administrators, full
control for SYSTEM and Administrators only, inherited (`O:BAG:SYD:PAI(A;OICI;FA;;;SY)
(A;OICI;FA;;;BA)`), re-applied to everything below at `init`, `install` and every
service start. `config\`: `agent.conf`, `token` (sha256 digest, deleted after enrollment),
`agent.key`, `enroll.crt`, `agent.crt`, `ca.crt`, `agent.id`, `release-keys\*.pub`.
`state\`: `enroll.failures`, `cache\committed.bin`, `spool\` (delete-on-close files),
`nexus-agent.log` (service log, UTC timestamps, rotated at 10 MiB to `.log.1`).

`agent.conf` keys as on Linux (`listen`, `port`, `spool_max_bytes`, `appliance_id`,
`max_connections`, `hook_timeout_secs`) plus `vss_exclude_writers = {guid},{guid}`
(writer class ids that must not take part). Hooks are not supported on Windows
(`Prepare.hooks` is answered with a note in `hook_log`); VSS writers provide
application consistency.

Privileges enabled at start: SeBackupPrivilege, SeRestorePrivilege,
SeSecurityPrivilege (SACLs; without it SACLs are neither read nor restored),
SeTakeOwnershipPrivilege. COM security is initialised once
(`RPC_C_AUTHN_LEVEL_PKT_PRIVACY`, identify impersonation, dynamic cloaking) as VSS
requesters need.

## Paths

| | form |
|---|---|
| `Prepare.paths`, restore target (from the appliance) | `/C/Users/alice` (also accepted: `C:\Users\alice`, `C:/Users/alice`, `\\?\C:\...`) |
| `Volume.mountpoint` | `/C`, `/D/mnt/data` (folder mount points) |
| `Entry.path` | `C/Users/alice/file.txt` — drive letter upper case, `/` separators |
| names | WTF-8 of the UTF-16 name (UTF-8 for every valid name; unpaired surrogates survive) |
| excludes | `C:\Users\*\AppData\Local\Temp`, `/C/...` or name patterns (`*.tmp`), matched **case-insensitively** against `/` + entry path |

Built-in excludes at volume roots: `pagefile.sys`, `hiberfil.sys`, `swapfile.sys`,
`System Volume Information`. A requested path that passes through a symlink or junction
below its volume's mount point is refused (inside a shadow copy the link would resolve
to the live file system). Folder mount points and junctions met during the walk are
recorded as links and not descended into; request the mounted volume's path explicitly.
UNC paths and device paths are refused.

## Metadata mapping (`Entry`)

| Windows | `Entry` |
|---|---|
| LastWriteTime, ChangeTime | `mtime_ns`, `ctime_ns` (Unix ns) |
| CreationTime | xattr `win.created`: FILETIME, i64 LE |
| FILE_ATTRIBUTE_* | xattr `win.attrs`: u32 LE |
| owner, group, DACL, SACL | xattr `win.sd`: self-relative SECURITY_DESCRIPTOR as returned by `GetKernelObjectSecurity` (SACL only with SeSecurityPrivilege) |
| symlink / junction / volume mount point | `Kind::Symlink`, `link_target` = print name (else substitute name), xattr `win.reparse`: raw REPARSE_DATA_BUFFER |
| other reparse points (dedup, WOF/compression, cloud files, HSM) | read as normal files (data reparse points) |
| file id (`FileIdInfo`, 128 bit) | `inode`: low 64 bits; folded through BLAKE3 if the high half is used (ReFS) |
| hard links (link count > 1, same volume + file id) | first path seen carries the data, later ones `Kind::Hardlink` to it |
| named `$DATA` stream | separate entry `<path>:<stream>` right after its file or directory, `Kind::File`, xattr `win.ads` (empty value), size = stream size, times and inode of the base file |
| — | `mode` synthesised for appliance-side tools: dirs 0755, files 0644, read-only files 0444; `uid`/`gid` 0 |

ADS as entries (not xattrs) was chosen because streams can be large (xattrs are capped
at 64 KiB per entry) and so they deduplicate, use `Want`, and are cached like files.
On the appliance a stream shows up as a file named `file.txt:Zone.Identifier` (valid on
Linux; downloads via `nexus-agentctl files` contain it as such).

## Backup

1. `Prepare`: paths are parsed, grouped by volume (`GetVolumePathNameW` +
   `GetVolumeNameForVolumeMountPointW`), checked for links (above). Per volume the USN
   journal is queried **before** the snapshot (`FSCTL_QUERY_USN_JOURNAL`; an NTFS/ReFS
   volume without an active journal gets one: 256 MiB, 32 MiB delta; FAT/exFAT have
   none). Then one VSS shadow copy set for all NTFS/ReFS volumes:
   `CreateVssBackupComponents → InitializeForBackup → SetContext(VSS_CTX_BACKUP) →
   DisableWriterClasses(vss_exclude_writers) → SetBackupState(no component selection,
   bootable state false, VSS_BT_COPY) → GatherWriterMetadata → StartSnapshotSet →
   AddToSnapshotSet per volume → PrepareForBackup → DoSnapshotSet →
   GatherWriterStatus → GetSnapshotProperties` (device
   `\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyN`, read with backup semantics).
   `IVssBackupComponents` is not projected by the `windows` crate; its vtable is
   declared in `win/vss.rs` in vsbackup.h order (checked against mingw-w64's header).
2. **Writer selection:** non-component mode — every writer that is not excluded by
   class id takes part (freezes/thaws); `VSS_BT_COPY` never truncates SQL Server /
   Exchange logs, so log chains of other backup products stay intact. Writer status
   after the snapshot goes to `Prepared.hook_log` (summary: `[ok]`, `[FAILED]`,
   `[EXCLUDED]`, state, HRESULT; application writers that did not take part are flagged
   "application data is only crash-consistent") and, structured, to `WritersReport`
   (protocol v1.1, served on `Writers { job }`). `Prepared.consistent` is false if a
   volume could not be snapshotted or an application writer (SQL Server, Exchange,
   NTDS by class id or name) failed.
3. Volumes without a shadow copy (FAT/exFAT, VSS failure) are read live: files whose
   write/change time, id or size changed while read are `inconsistent`, chunk data is
   spooled as on Linux.
4. `Scan`: per volume the change set is the set of file ids with a journal record
   from the USN stored with the committed metadata cache (`JournalMark`, cache format 2)
   to the journal's current end (`FSCTL_READ_USN_JOURNAL`, `USN_RECORD_V2/V3`). A file
   (or stream, by its base file's id) is `unchanged` only if size, mtime, ctime and file
   id match the cache **and** its id has no record. Journal recreated, wrapped (stored
   USN < FirstUsn), records deleted while reading, more than 4 M changed files, or no
   base → that volume is read in full. The new cache stores the journal position queried
   before this snapshot (records between that query and the snapshot are read again
   next time — a superset, never a gap). Volumes without a journal: metadata comparison
   only (like Linux).
5. `Want`: chunks are re-read from the shadow copy (or spool) and verified, also for
   unchanged files.
6. `Release`: `BackupComplete` on success (writers mark the backup), `AbortBackup`
   otherwise; the set is deleted and the non-persistent shadow copies disappear (also
   when the process dies — no journal needed, unlike Linux).
7. `PrepareEx` (protocol v1.3): include roots are given as Windows paths (`C:\Users\alice`,
   normalised to `/C/Users/alice`) and compared case-insensitively; regex excludes match
   the `/C/…` form case-insensitively; `cross_mounts` / `skip_fstypes` are ignored (the
   listed volumes are walked, mounted folders are reparse points and never followed).
   `Limits::nice` > 0 puts the session thread into background mode
   (`SetThreadPriority(THREAD_MODE_BACKGROUND_BEGIN)`: lowest CPU, very low I/O and memory
   priority); `bwlimit` paces the `Want` data in agent-core. Certificate renewal
   (`RenewCert`) and the atomic key/certificate swap are shared agent-core code.

## Restore

Target `/D/restore` (or `D:\restore`); a drive root (also via a link) needs
`overwrite = Always`; `confirm` must be non-empty and is logged. Entry names are
checked for Windows: no `< > : " / \ | ? *` or control characters, no trailing dot or
space, no reserved device names (`CON`, `NUL.txt`, `COM1`, ...), ≤ 255 UTF-16 units; `:`
only as the stream separator of an entry carrying `win.ads`.

Confinement (`confine.rs`, `win/restore.rs`): every directory below the target is
opened one component at a time with `FILE_FLAG_OPEN_REPARSE_POINT` and checked; a
reparse point or non-directory ends the operation. The whole chain is held open with
`FILE_LIST_DIRECTORY` access and without `FILE_SHARE_DELETE` (attribute-only handles do
not take part in share checks), so no verified directory can be renamed or replaced by
a junction while the entry is written. Everything written is re-checked with
`GetFinalPathNameByHandleW` to lie below the target's final path.

Files are written as `.nexus-restore.<pid>.<n>` next to the destination, then:
security descriptor (validated by `SdInfo::parse` first; on failure retried without
owner/group/SACL and reported), read-only flag of an existing destination cleared,
rename over the destination by handle (`FileRenameInfo`, `ReplaceIfExists`: a symlink
or junction at the destination is replaced, never followed; a directory in the way is
an error), then attributes (`READONLY|HIDDEN|SYSTEM|ARCHIVE|TEMPORARY|NOT_CONTENT_INDEXED`)
and creation/write times. Symlinks and junctions are recreated from `win.reparse`
(validated) with `FSCTL_SET_REPARSE_POINT` on a new empty file/directory; link targets
without `win.reparse` (a Linux backup) become symlinks (`/` → `\`). Streams are written
into the restored (or kept) base file after it is in place; the base's times are
re-applied afterwards. Hard links: `CreateHardLinkW` to a temp name + rename.
Directory metadata last, deepest first; the security descriptor of a directory that
already existed is only replaced with `overwrite = Always` ("restore security
descriptors when the overwrite policy allows"). Devices, FIFOs and sockets (Linux
backups) are errors. EFS-encrypted files are not supported (read fails → error).

Files from other machines (Phase 15b: another Windows host, Linux hosts, NAS shares,
TrueNAS, plugin file trees, VM/CT files) use the same protocol and checks. The appliance
does not send devices, sockets or FIFOs there and keeps only `win.*` xattrs (security
descriptors of another Windows host are applied as above, retried without
owner/group/SACL if they do not apply); entries without `win.*` metadata get default
attributes and inherit the target directory's ACL. Names that are invalid on Windows
(`:` , `?`, trailing dots, reserved device names, …, common on Linux/NAS shares) are
reported as errors per entry and fail the job; the other files are written.

## Self-update

MSI installs: `package-managed` next to `nexus-agent.exe` turns self-update off (`Update`
is refused, "installed from a msi package …") unless `self_update = on` in `agent.conf`; a
self-update would replace a file the MSI owns. Update them with a newer MSI.

Same `Update` message and checks as Linux (`agent_core::update::check_candidate`:
cosign blob signature with a key from `config\release-keys\*.pub`, embedded version
strictly newer, PE32+ x86-64 image); Authenticode is not required. Install:
`<exe>.new` written and flushed, running `<exe>` renamed to `<exe>.prev`, `.new` renamed
to `<exe>`; then exit code 75 → the service control manager restarts the service
(failure actions). If the running image cannot be renamed, the replacement is scheduled
with `MoveFileEx(MOVEFILE_DELAY_UNTIL_REBOOT)` and reported as "takes effect after the
next reboot". Refused while jobs or a restore run.

## Tests (Linux, `cargo test -p agent-windows`)

- `paths.rs`: WTF-8 round trip incl. unpaired surrogates and malformed input; path
  parsing/formatting (`/C/x` ↔ `C:\x`), refusal of UNC/device/relative/`..`; Windows
  name rules; ADS entry paths; exclude normalisation; `is_beneath`.
- `meta.rs`: FILETIME ↔ Unix ns, synthesised mode, file-id folding, xattr accessors;
  security descriptor parsing (byte fixture per MS-DTYP of
  `O:BAG:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)`), truncation/offset/ACL-size
  corruptions refused, SECURITY_INFORMATION flags incl. SACL without privilege; reparse
  buffer build/parse round trip (symlink, junction), non-link tags, malformed lengths,
  Linux link targets; stream names.
- `usn.rs`: USN_RECORD_V2/V3 parsing from byte fixtures **built after the documented
  layout** (not captured on Windows), V4 skipped, malformed buffers; journal data;
  continuity (same / recreated / wrapped / ahead); the unchanged decision.
- `confine.rs`: walk on a simulated case-insensitive namespace — junction anywhere in
  the path refused (nothing created behind it), files in the way, missing dirs created
  only on request, a junction swapped in after `mkdir`.
- `scan.rs`: the generic walk over a simulated source (metadata from a map, data from
  temp files): entries, SD/attrs/times, ADS order and data, links not followed, data
  reparse points read, hard links, case-insensitive excludes, include roots in Windows
  form + case-insensitive regex excludes (`include_roots_and_regex_excludes`), `Want` of every chunk;
  USN + cache decisions (record forces a read, streams follow their file id, reset =
  full read, metadata change); live-mode inconsistency; unreadable objects are errors.
- `writers.rs`: state names, application writers, `vss_exclude_writers` parsing,
  summary and consistency.
- `update.rs`: PE detection, format gate, install swap + `.prev`, rename-at-reboot
  fallback.
- `agent-core`: restore stream bookkeeping on an in-memory file system, overwrite
  policy, cache format 1 → 2, chunk locator, update checks (cosign fixture).
- The cross-compile (with clippy `-D warnings` for the Windows target) is the test for
  everything in `src/win/`.

## Untested (no Windows VMs — user decision 2026-10-09)

Everything in `src/win/` has only been compiled, never executed:

- service install/uninstall/start/stop, failure-action restart, log redirection;
- ACL application on `%ProgramData%\NexusAgent`;
- privilege enabling; COM security initialisation;
- the hand-written `IVssBackupComponents` vtable and the whole VSS sequence (snapshot
  creation, device path, writer status, BackupComplete/AbortBackup, cleanup on crash),
  `vss_exclude_writers`;
- real behaviour of SQL Server, Exchange and AD (NTDS) writers (freeze/thaw, COPY
  backups, failure reporting), and whether "participated" matches what an admin
  expects (non-component mode: every non-excluded writer is asked to freeze);
- USN journal ioctls (query/create/read, V2 vs V3 records actually returned, journal
  ids of ReFS volumes), and the assumption that USN record file ids equal `FileIdInfo`
  ids (NTFS: 64-bit FRN zero-extended; ReFS: 128-bit);
- `FILE_STREAM_INFO` enumeration, `GetKernelObjectSecurity` sizes, reparse point
  reads/writes, `FileRenameInfo` with a full `\\?\` path, `GetFinalPathNameByHandleW`
  forms, held-handle share semantics as the confinement relies on them;
- volume enumeration and folder mount points, `GetVolumePathNameW` for paths through
  mount points;
- restore of security descriptors with foreign SIDs, SACLs, read-only files, streams on
  directories, hard links, junctions;
- self-update by rename of the running image and the reboot fallback;
- the MSI (install, major upgrade, uninstall, PURGE, the two custom actions);
- background mode (`THREAD_MODE_BACKGROUND_BEGIN`) of the session thread for `Limits::nice`,
  and the certificate swap (`agent.key`/`agent.crt` renames over existing files) on NTFS;

- interoperability with `agent-conn` over a real network (the protocol code is shared
  and tested by the Linux interop test).

## Manual test plan (Windows Server 2016, 2019, 2022, 2025)

Per version, on a VM with an NTFS system volume, an NTFS data volume mounted as `D:`, a
ReFS volume (2016+: `E:`), a FAT32/exFAT USB/VHD volume, and an NTFS volume mounted in
a folder (`C:\mnt\data`); one VM with SQL Server (Express is enough), one domain
controller (NTDS), Exchange on 2019 if available.

1. **Install:** copy, `init --token -`, `install` (MSI: step 11); `sc qc NexusAgent`, `sc qfailure
   NexusAgent` (3 restarts), `icacls %ProgramData%\NexusAgent` (only SYSTEM +
   Administrators, protected), non-admin user cannot read `config\agent.key`.
2. **Enrollment:** enroll from the appliance; wrong token 5× → locked; `status` shows the
   lock; `init` again clears it; MITM test as in the Linux e2e (proxy with own cert) fails.
3. **Backup C:\Users and D:\:** job log shows the shadow copy set, writer summary;
   `vssadmin list shadows` during the backup shows the set, after `Release` it is gone;
   kill the service during a scan → shadow copies gone (`vssadmin list shadows`).
4. **Writers:** SQL Server DB under load (insert loop) → `SqlServerWriter [ok]`, restore
   the .mdf/.ldf to another path and attach; check SQL error log shows a COPY_ONLY
   backup, log chain unaffected (`msdb.dbo.backupset`). Stop the SQL VSS Writer service →
   writer missing / `consistent=false`; `vss_exclude_writers` with the SQL writer id →
   `[EXCLUDED]`. DC: NTDS writer participates; restore of `C:\Windows\NTDS` files.
   Exchange (2019): writer status reported.
5. **Incremental + USN:** second backup without changes → nearly everything
   `unchanged`, `Want` count 0; modify, rename, add a stream to a file, touch only the
   ADS → exactly those re-read; `fsutil usn deletejournal /d D:` between backups →
   job log "USN journal was recreated", full read; tiny journal (`fsutil usn
   createjournal m=1048576 a=65536 D:`) + many changes → "wrapped", full read; FAT32
   volume → no journal, metadata comparison, live read, `consistent=false`.
6. **Metadata:** files with explicit DACLs, inherited ACLs, a SACL (audit), owner not
   Administrators, hidden/system/read-only/not-indexed attributes, creation time,
   hard links, symlinks (file + dir, relative + absolute), junctions, folder mount point,
   `Zone.Identifier` streams and a 100 MB ADS, names with emoji / unpaired surrogates
   (created via PowerShell), paths > 260 chars, a dedup'ed file (Data Deduplication role,
   Server editions) and a compressed (WOF/NTFS) file, an EFS file (expect an error).
   Compare after restore with `icacls`, `Get-Item -Stream *`, `fsutil file queryfileid`,
   `fsutil reparsepoint query`, `dir /al`, `Get-FileHash`.
7. **Restore confinement:** pre-create in the target a junction `a -> C:\Windows` and a
   symlink `b -> C:\Windows\win.ini`; restore entries `a\x`, `b` with `Always` →
   nothing written under `C:\Windows`, `b` replaced by a file, errors reported.
   Race: a script that continuously replaces a target subdirectory by a junction during
   a large restore → no write outside the target. Restore to `D:\` without `Always` →
   refused. Overwrite policies Never/IfOlder/Always on existing files, read-only
   destinations.
8. **Self-update:** signed newer build → service restarts with the new version
   (`HelloReply`), `.prev` kept; unsigned / older / ELF / wrong key → refused; update
   while a backup runs → refused (409).
9. **Service:** `sc stop` → stopped, no restart; `taskkill /f` → restarted by SCM;
   reboot → starts automatically; log rotation at 10 MiB.
10. **Performance:** 1 M small files on D:, second run with 1 % changed: scan time and
    memory; journal read time; compare with the Linux agent on similar data.
11. **MSI:** `msiexec /i nexus-agent-<v>-x64.msi /qn /l*v i.log` → Apps & features entry,
    `sc qc NexusAgent` (auto, LocalSystem, `service`), `sc qfailure NexusAgent` (3 restarts,
    set by `service-setup`), `icacls %ProgramData%\NexusAgent` (protected, SYSTEM +
    Administrators), the service started and stopped again ("not initialised" in
    `state\nexus-agent.log`, exit 0, no restarts); `init --token -` + `sc start` → enroll;
    `Update agent` from the appliance → refused ("installed from a msi package"); install a
    newer MSI → service restarted with the new version, still enrolled; an older MSI →
    refused; `msiexec /x … /qn` → service and Program Files gone, `%ProgramData%\NexusAgent`
    kept; reinstall → enrolled again; `msiexec /x … /qn PURGE=1` → `%ProgramData%\NexusAgent`
    gone. Deploy once through a GPO (computer software installation) and once through Intune.
12. **Desktop UI:** after the MSI, log on as a non-admin user (also over RDP): tray icon appears
    (Run key), tooltip shows the state; the Start menu entry opens the window; a second start
    does not create a second tray icon; "Request backup now" queues a request (shown as
    *Requested*, started by the next appliance poll), a second request within 10 minutes is
    refused; stop the service → icon "not connected to the service"; enable notifications and
    let a backup fail → toast; light/dark follow the Windows setting; keyboard-only operation
    (arrows, T, B, R, N, Esc); uninstall while the GUI runs.
