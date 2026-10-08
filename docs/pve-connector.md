# PVE Connector — Contract between node plugin, SSH helper and appliance

Status: v1 (2026-10-08). PVE 9.x only. API facts: `docs/pve-backup-provider-api.md`.

## Components on each PVE node (package `nexusbackup-pve`, built with dpkg-deb)
| Path | What |
|---|---|
| `/usr/share/perl5/PVE/Storage/Custom/NexusBackupPlugin.pm` | storage plugin, type `nexusbackup`, `api()` returns 11 |
| `/usr/share/perl5/PVE/BackupProvider/Plugin/NexusBackup.pm` | backup provider plugin |
| `/usr/lib/nexusbackup/helper` | SSH forced command (Perl, no deps beyond PVE's) |
| user/group `nexusbackup` | unprivileged system user, shell `/bin/sh` (needed for forced command), no password |
| `/run/nexusbackup/jobs/` | rendezvous dir, `0750 root:nexusbackup` (tmpfiles.d) |
| `/var/lib/nexusbackup/<storeid>/index.json` | catalog pushed by the appliance, `0640 root:nexusbackup`, written by helper via group write on dir `0770 root:nexusbackup` |

`authorized_keys` of `nexusbackup`:
`restrict,command="/usr/lib/nexusbackup/helper" ssh-ed25519 AAAA… nexus-appliance`
No forwarding of any kind. NBD data flows over the session's stdio.

storage.cfg:
```
nexusbackup: nexus
	nexus-fleecing-storage local-lvm
	content backup
```
Fleecing is mandatory for provider VM backups; the appliance passes
`fleecing=enabled=1,storage=<fleecing-storage>` when triggering vzdump.

## Names
- archive name (returned by `backup_init`): `nexus-<vmid>-<unixtime>`; volname `backup/nexus-<vmid>-<unixtime>`; `parse_volname` returns vmid as owner.
- Appliance snapshot: source `vm-<vmid>`, time `<unixtime>`, one fixed index per device named like the device (`drive-scsi0`, …), plus dynamic index `config` with files `qemu-server.conf` and (optional) `firewall.fw`.

## VM backup flow
1. Appliance: `GET /cluster/resources?type=vm` → node of vmid. `POST /nodes/<node>/vzdump vmid=<id> storage=<storeid> mode=snapshot fleecing=enabled=1,storage=<fs>` → UPID.
2. Plugin `backup_vm_query_incremental`: for each device return `use` if `index.json` lists a previous archive of this vmid that contains that device, else `new`.
3. Plugin `backup_vm` (runs as root):
   - `chgrp nexusbackup` + `chmod g+x` on the backup-access directory, `chgrp nexusbackup` + `chmod g+rw` on the NBD socket (dir is created by qemu-server with 0700; it is removed at teardown).
   - write `/run/nexusbackup/jobs/<vmid>.json` atomically (tmp + rename, mode 0640 root:nexusbackup):
     ```json
     {"vmid":100,"archive":"nexus-100-1760000000","nbd_socket":"/run/qemu-server/…-nbd.backup-access",
      "devices":[{"name":"drive-scsi0","size":34359738368,"bitmap_mode":"reuse","bitmap_name":"snapshot-access:nexus"}],
      "config":"<guest config text>","firewall":"<text or null>"}
     ```
   - wait (1 s poll) for `/run/nexusbackup/jobs/<vmid>.done`; content `ok` → remove both files, return; `fail <msg>` or timeout (storage option `nexus-job-timeout`, default 21600 s) or Perl die (task abort) → remove files, die.
4. Appliance, over SSH (`ssh nexusbackup@<node> <cmd>`):
   - `job <vmid>` → prints the job JSON (exit 1 if not present yet; appliance polls while the task runs).
   - per device: `nbd <vmid>` → helper connects to `nbd_socket` and pipes stdio; appliance does the NBD handshake with export = device name and meta context `qemu:dirty-bitmap:<bitmap_name>`.
   - Reads only dirty extents (clean extents are unreadable on snapshot-access exports). Chunks with clean parts are completed from the previous snapshot's chunk. `bitmap_mode` `new`/`none` ⇒ whole device dirty, no base needed.
   - Commits the snapshot durably, **then** `done <vmid> ok` (QEMU commits the bitmap only when `backup_vm` returns normally; the snapshot must exist before that). On any failure before commit: `done <vmid> fail <reason>`.
5. Appliance waits for the task, then pushes the catalog: `put-index <storeid>` with `index.json` on stdin, to **every** node of the cluster (so `list_volumes` / "Show Configuration" work on all nodes).
6. Plugin `prune_backups` must never die (retention is the appliance's job): every archive is marked `keep`.
7. `free_image` (GUI/CLI delete) dies with "deletion is managed by the NexusBackup appliance" — nodes can never delete backups (pull model, retention locks). `update_volume_attribute` for notes/protected: die with the same message in v1.
8. `backup_cleanup(success=0)` after a successful `backup_vm` must not cause the appliance to drop the snapshot (bitmap is already committed; see API doc §2 ordering gotcha). The appliance keeps every snapshot it committed.

Storage plugin properties are global across plugins, hence the `nexus-` prefix.

## index.json (appliance → nodes)
```json
{"version":1,"archives":[{"volname":"backup/nexus-100-1760000000","vmid":100,"ctime":1760000000,
  "size":34359738368,"devices":["drive-scsi0"],"device_sizes":{"drive-scsi0":34359738368},"config":"<qemu-server.conf>","firewall":null,
  "notes":"","protected":false}]}
```
Plugin uses it for `list_volumes`, `archive_get_guest_config`, `archive_get_firewall_config`, `volume_size_info`, `backup_vm_query_incremental`, `status` (total/used from the last appliance push or 0). Missing/unreadable index ⇒ empty list, never die.

## Helper command set (complete)
| Command | Effect |
|---|---|
| `job <vmid>` | print job JSON or exit 1 |
| `nbd <vmid>` | pipe stdio ⇄ job's NBD socket |
| `done <vmid> ok` / `done <vmid> fail <msg>` | write the done file |
| `put-index <storeid>` | atomically replace `/var/lib/nexusbackup/<storeid>/index.json` from stdin (max 64 MiB, must parse as JSON) |
| anything else | exit 2, log to syslog |
Arguments are validated: vmid `^\d{1,9}$`, storeid `^[a-z][a-z0-9\-_.]{1,99}$`.

## VM restore flow (full restore, v1.1)
PVE only accepts a regular file or block device as `qemu-img-path`, so the node
attaches the appliance's NBD export to `/dev/nbdX` with the node's own `qemu-nbd`.
1. Appliance: `POST /nodes/<node>/qemu vmid=<target> archive=<storeid>:backup/nexus-<vmid>-<t> storage=<target storage> [force=1] [unique=1]` → UPID.
2. Plugin `restore_get_mechanism` → `('qemu-img', 'qemu')`; `restore_vm_init` → `{ <device> => { size } }` from index.json (devices + sizes; index.json archive entries get a `device_sizes` map `{name: bytes}`).
3. Plugin `restore_vm_volume_init($volname, $device)`:
   - writes `/run/nexusbackup/restore/<archive>.json` = `{"archive":"nexus-100-1760000000","device":"drive-scsi0","socket":"/run/nexusbackup/restore/<archive>.<device>.sock"}` (one device at a time; PVE restores volumes sequentially),
   - waits for the socket to appear (same timeout option), `modprobe nbd`, picks a free `/dev/nbdX` (size 0 in `/sys/block/nbdX/size`), runs
     `qemu-nbd -c /dev/nbdX -r --image-opts driver=raw,file.driver=nbd,file.server.type=unix,file.server.path=<socket>,file.export=<device>`,
   - returns `{ 'qemu-img-path' => '/dev/nbdX' }`.
4. Appliance polls `restore-job <archive>` (prints the JSON, exit 1 if none) and runs `restore-serve <archive> <device>`: the helper creates the listening socket (dir `/run/nexusbackup/restore` 0770 root:nexusbackup, socket 0660), accepts exactly one connection and pipes it ⇄ stdio. The appliance runs `nbd::server` over the SSH stdio, serving the device from the snapshot's fixed index (read-only).
5. Plugin `restore_vm_volume_cleanup`: `qemu-nbd -d /dev/nbdX`, remove JSON + socket. The appliance's server sees EOF and polls for the next device until the restore task stops.
6. `restore_vm_cleanup`: remove leftovers. Live restore is impossible for providers (PVE refuses).

Helper additions: `restore-job <archive>`, `restore-serve <archive> <device>`; archive `^nexus-\d{1,9}-\d{1,12}$`, device `^[a-z0-9\-]{1,64}$`.

## Not in v1
Containers (directory mechanism, mapped-root `backup_container`), trim of read regions (fleecing shrink).
