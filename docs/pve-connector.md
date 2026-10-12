# PVE Connector — Contract between node plugin, SSH helper and appliance

Status: v1 (2026-10-08). PVE 9.x only. API facts: `docs/pve-backup-provider-api.md`.

## Components on each PVE node (package `nexusbackup-pve`, built with dpkg-deb)
| Path | What |
|---|---|
| `/usr/share/perl5/PVE/Storage/Custom/NexusBackupPlugin.pm` | storage plugin, type `nexusbackup`, `api()` returns 11 |
| `/usr/share/perl5/PVE/BackupProvider/Plugin/NexusBackup.pm` | backup provider plugin |
| `/usr/lib/nexusbackup/helper` | SSH forced command (Perl, no deps beyond PVE's) |
| user/group `nexusbackup` | unprivileged system user, shell `/bin/sh` (needed for forced command), no password |
| `/run/nexusbackup/jobs/`, `/run/nexusbackup/restore/` | rendezvous dirs, `1770 root:nexusbackup` (tmpfiles.d; sticky so the helper cannot replace root's files) |
| `/var/lib/nexusbackup/<storeid>/index.json` | catalog pushed by the appliance, `0640 nexusbackup:nexusbackup` (written by the helper) |
| `/var/tmp/nexusbackup/<archive>/` | container restore staging dir (root only, parent `0700`), removed by `restore_container_cleanup` |
| `/run/nexusbackup/ir/` | instant recovery: the helper's listening NBD sockets `<vmid>.<archive>.<device>.sock`, `1770 root:nexusbackup` (tmpfiles.d) |
| `/var/lib/nexusbackup/ir/<storeid>/<vmid>/<archive>.<device>.qcow2` | instant recovery overlays (guest writes), created by the plugin as root; every level `0700 root` (checked before use) |

`authorized_keys` of `nexusbackup`:
`restrict,command="/usr/lib/nexusbackup/helper" ssh-ed25519 AAAA… nexus-appliance`
No forwarding of any kind. NBD data flows over the session's stdio.

storage.cfg:
```
nexusbackup: nexus
	nexus-fleecing-storage local-lvm
	content backup,images
```
`images` is only needed for instant recovery: the storage then holds the IR overlay volumes
(`alloc_image` still refuses, so the GUI cannot create ordinary disks on it).
Fleecing is mandatory for provider VM backups; the appliance passes
`fleecing=enabled=1,storage=<fleecing-storage>` when triggering vzdump.

## Names
- archive name (returned by `backup_init`): `nexus-<vmid>-<unixtime>`; volname `backup/nexus-<vmid>-<unixtime>`; `parse_volname` returns vmid as owner.
- instant recovery volume: `ir/<target vmid>/<archive>.<device>.qcow2` (vtype `images`, format `qcow2`, owner = target vmid, e.g. `nexus:ir/903/nexus-100-1760000000.drive-scsi0.qcow2`).
- Appliance snapshot: source `vm-<vmid>`, time `<unixtime>`, one fixed index per device named like the device (`drive-scsi0`, …), plus dynamic index `config` with files `qemu-server.conf` and (optional) `firewall.fw`.
- Container snapshot: source `ct-<vmid>`, time `<unixtime>`, dynamic index `root.tar` with one entry `root.tar` (size = tar stream length, FastCDC chunks), plus dynamic index `config` with `pct.conf` and (optional) `firewall.fw`.

## VM backup flow
1. Appliance: `GET /cluster/resources?type=vm` → node of vmid. `POST /nodes/<node>/vzdump vmid=<id> storage=<storeid> mode=snapshot fleecing=enabled=1,storage=<fs>` → UPID.
2. Plugin `backup_vm_query_incremental`: for each device return `use` if the **newest** archive of this vmid in `index.json` contains that device (in its `devices` list), else `new`. Only the newest counts: the appliance builds an incremental on top of its newest snapshot, so a disk that was excluded there and is included again must start with a fresh bitmap.
3. Plugin `backup_vm` (runs as root):
   - `chgrp nexusbackup` + `chmod g+rw` on the NBD socket and hard-link it to `/run/nexusbackup/jobs/<vmid>.nbd` (same tmpfs); `nbd_socket` in the job JSON is that link. qemu-server's directories (`/run/qemu-server` is `0750 root:www-data`) stay untouched.
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

### Excluded disks (Phase 15e)
A group can exclude VM disks (`groups.exclude_disks`, disk keys such as `scsi1`, for all guests of the group
or per vmid). The scheduler passes them to `nexus-pve` as device names:
`"exclude_disks": {"101": ["drive-scsi1"]}`, `"exclude_disks_mode": "placeholder" | "omit"`.
- The provider API has no per-disk selection: vzdump still exports every disk without `backup=0` (and the
  fleecing image still covers writes to an excluded disk for the duration of the job). The appliance simply
  does not read the excluded devices (`excluded disk scsi1 of VM 101 (<bytes>): not backed up` in the job log)
  and records them in the snapshot's config index as `excluded-disks.json`
  (`{"mode":"placeholder","disks":[{"device":"drive-scsi1","key":"scsi1","size":8589934592}]}`).
- Disks with `backup=0` are left out by PVE itself, as before; the appliance reports them from the guest
  config (`disk scsi2 of VM 101 has backup=0: skipped by PVE`).
- Incremental: an excluded disk is not in the snapshot's `devices`, so the next backup after it is included
  again reads it fully (`new` bitmap, step 2).
- Restore, mode `placeholder` (default): the catalog keeps the disk's config and `#qmdump#map` lines and lists
  the device in `device_sizes` only (never in `devices`); PVE allocates the disk with its original size and
  options and the appliance serves zeros for it: the restored VM has an empty disk in the same slot (format it
  or restore its content separately). Mode `omit`: the catalog config drops the disk's line and its
  `#qmdump#map` line, the restored VM has no such disk.
- Instant recovery always leaves excluded disks out (there is nothing to serve); file-level restore lists only
  the backed-up disks.
- Containers: `exclude_disks` does not apply (a note in the job log); mount points with `backup=0` are skipped
  by vzdump.

### Parallel guests (Phase 15f)
`"parallel": N` (group `parallel_guests`, 1..=8, default 1 = one guest after the other) lets `backup-all` back
up up to N guests at once. The nodes of all guests come from one `/cluster/resources` call; each free worker
takes the next guest on the node with the fewest running backups, so the load spreads over the cluster (at most
N at once, hence at most N per node). PVE may serialise vzdump runs on one node (global vzdump lock with
`lockwait`): guests of the same node then wait for each other inside their vzdump task, which is harmless but
gives no speed-up. Every worker opens its own store handle (per-snapshot `nexus-stats` stay exact); the output
lines stay whole lines, so `committed …`, `nexus-stats …` and `backup of guest … failed` parse as before and
retries (13b) re-run exactly the failed guests. Every vzdump task is reported (`upid: …`); a cancelled job stops
all of them (`task-stop` per reported UPID, newest first). The plugin host does the same for plugin groups
(`"parallel"` in its job config, one sandboxed plugin process per guest).

## index.json (appliance → nodes)
```json
{"version":1,"archives":[{"volname":"backup/nexus-100-1760000000","vmid":100,"type":"qemu","ctime":1760000000,
  "size":34359738368,"devices":["drive-scsi0"],"device_sizes":{"drive-scsi0":34359738368},"config":"<qemu-server.conf>","firewall":null,
  "notes":"","protected":false},
 {"volname":"backup/nexus-200-1760000100","vmid":200,"type":"lxc","ctime":1760000100,"size":679413760,
  "devices":[],"device_sizes":{},"config":"<pct.conf>","firewall":null,"notes":"","protected":false}]}
```
`type` is `qemu` or `lxc`; a missing `type` (catalogs from before container support) means `qemu`.
It becomes `subtype` in `list_volumes`, selects the restore mechanism and filters `prune_backups` by guest type.
For containers `size` is the tar stream length and `config` is the raw `pct.conf` (what vzdump hands to
`backup_container`; `pct restore` / "Show Configuration" parse it with `parse_pct_config`).
Plugin uses it for `list_volumes`, `archive_get_guest_config`, `archive_get_firewall_config`, `volume_size_info`, `backup_vm_query_incremental`, `status` (total/used from the last appliance push or 0). Missing/unreadable index ⇒ empty list, never die.

## Helper command set (complete)
| Command | Effect |
|---|---|
| `job <vmid>` | print job JSON or exit 1 |
| `nbd <vmid>` | pipe stdio ⇄ job's NBD socket |
| `done <vmid> ok` / `done <vmid> fail <msg>` | write the done file (`fail` requires a message) |
| `put-index <storeid>` | atomically replace `/var/lib/nexusbackup/<storeid>/index.json` from stdin (max 64 MiB, JSON object with `archives` array; optional top-level `total`/`used` feed `status`) |
| `restore-job <archive>` | print the pending restore request JSON or exit 1 (VM and container) |
| `restore-serve <archive> <device>` | VM restore: listen on `/run/nexusbackup/restore/<archive>.<device>.sock`, accept one connection, pipe it ⇄ stdio |
| `ct-stream <vmid>` | container backup: requires a job with `type` `lxc`; connect to `/run/nexusbackup/jobs/<vmid>.ct.sock` (path derived, not read from the job) and pipe stdio ⇄ socket |
| `ct-restore-serve <archive>` | container restore: requires a request with `type` `lxc`; listen on `/run/nexusbackup/restore/<archive>.ct.sock` (tmp name + rename, `0660`), accept one connection (600 s), pipe it ⇄ stdio |
| `ir-serve <vmid> <archive> <device>` | instant recovery: listen on `/run/nexusbackup/ir/<vmid>.<archive>.<device>.sock` (tmp name + `0660` + rename over any older socket), print `listening`, wait for one connection without timeout (ends with exit 0 on stdin EOF, exit 1 if the appliance sends data first), close the listener, print `accepted`, pipe the connection ⇄ stdio. Removes the path only while it is still its own socket |
| anything else | exit 2, log to syslog |
Arguments are validated: vmid `^\d{1,9}$`, storeid `^[a-z][a-z0-9\-_.]{1,99}$`, archive `^nexus-\d{1,9}-\d{1,12}$`, device `^[a-z0-9\-]{1,64}$`.

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

`restore-serve` binds under a temporary name, sets 0660, then renames, so the plugin never sees an unready socket; it accepts one connection (600 s timeout).

Helper additions: `restore-job <archive>`, `restore-serve <archive> <device>`; archive `^nexus-\d{1,9}-\d{1,12}$`, device `^[a-z0-9\-]{1,64}$`.

## Container backup flow
`backup_container` runs as the container's mapped root (e.g. uid 100000) inside a new user
namespace, in a child forked by `PVE::LXC::Namespaces::run_in_userns` (`run_fork`). That
process cannot traverse `/run/nexusbackup` (`0750 root:nexusbackup`), its changes to `$self`
are lost, and `backup_container_prepare` does not get the guest config. Hence:
1. Appliance: `GET /cluster/resources?type=vm` → node and `type` (`lxc`). `POST /nodes/<node>/vzdump vmid=<id> storage=<storeid> mode=snapshot` (no fleecing: it is a VM-only feature).
2. Plugin `backup_get_mechanism` → `directory`.
3. Plugin `backup_container_prepare` (real root, parent process):
   - creates the **listening** socket `/run/nexusbackup/jobs/<vmid>.ct.sock` (`chgrp nexusbackup`, `0660`) and keeps the fd in `$self`; the forked child inherits it, so the mapped root never needs a path,
   - creates a pipe through which the child reports the stream size (for `archive-size`),
   - writes `/run/nexusbackup/jobs/<vmid>.json` atomically (`0640 root:nexusbackup`):
     `{"type":"lxc","vmid":200,"archive":"nexus-200-1760000100","socket":"/run/nexusbackup/jobs/200.ct.sock","firewall":"<text or null>"}`.
4. Appliance polls `job <vmid>`, checks `type` is `lxc`, runs `ct-stream <vmid>`. The helper's connect succeeds at once (listen backlog).
5. Plugin `backup_container` (child, mapped root): accepts (deadline = `nexus-job-timeout`), then sends records `tag(1 byte) len(u32 BE) payload`:
   - `C` the raw `pct.conf` (once, first),
   - `D` tar data (≤ 1 MiB per record) from
     `tar --create --file=- --numeric-owner --xattrs --xattrs-include=* --acls --sparse --one-file-system --preserve-permissions --warning=no-file-ignored --directory=<info.directory> --no-anchored [--exclude=lost+found (unprivileged)] [--exclude=<pattern>…] --anchored [--exclude=.<anchored pattern>…] -- <info.sources>`
     (same exclude semantics as vzdump's own tar; `sources` contains `.` and `./<mp>` for mount points),
   - `E` `ok`, or `fail <msg>` if tar exited non-zero (then the child dies).
   Container uids/gids are container-relative in the stream (tar runs inside the user namespace).
6. Appliance: chunks the `D` payloads (FastCDC) into `root.tar`, stores `pct.conf` (+ `firewall.fw` from the job) in `config`, commits the snapshot, **then** writes `ok\n` to the helper's stdin (on any error before commit: `fail <msg>\n`, and the SSH session is killed so a still-sending node cannot block). This in-band answer replaces the `done` file for containers: the child cannot reach the rendezvous dir, and the parent is blocked in `run_fork`.
7. Child: reads one answer line (same deadline): `ok` → reports the size through the pipe and returns; `fail …`, EOF or timeout → dies (vzdump marks the guest failed).
8. Plugin `backup_cleanup` (parent): closes the listening socket (pending connections are reset, so a helper never hangs), removes job file and socket, reads the size. `job_cleanup` removes leftovers.

No side can block forever: the child's accept and answer waits use the job timeout; the helper ends when the socket closes; the appliance's read ends when the node closes or the SSH session dies.

## Container restore flow
1. Appliance: `POST /nodes/<node>/lxc vmid=<target> ostemplate=<storeid>:backup/nexus-<vmid>-<t> restore=1 unprivileged=1 unique=1 storage=<target storage>` → UPID. PVE refuses privileged restores from providers; `unique=1` regenerates MAC addresses.
2. PVE reads the config via `archive_get_guest_config` (catalog), allocates the rootfs, then
   calls `restore_get_mechanism` → `('directory', 'lxc')` (catalog `type`; unknown archives fall back to `('qemu-img', 'qemu')`).
3. Plugin `restore_container_init` (root, `perl -T` API worker):
   - creates `/var/tmp/nexusbackup` (`0700`) and `/var/tmp/nexusbackup/<archive>`,
   - writes `/run/nexusbackup/restore/<archive>.json` = `{"archive":"nexus-200-1760000100","type":"lxc","socket":"/run/nexusbackup/restore/<archive>.ct.sock"}`,
   - waits for the socket (job timeout), connects, reads `u64 BE length`, pipes exactly that many bytes into
     `tar --extract --file=- --numeric-owner --xattrs --xattrs-include=* --acls --preserve-permissions --directory=<staging>`
     (as real root; the stream holds container-relative ids). Short stream, read timeout or tar failure → staging removed, die,
   - returns `{ 'archive-directory' => <staging> }`.
4. Appliance polls `restore-job <archive>`, checks `type` `lxc`, runs `ct-restore-serve <archive>` and writes `u64 BE size` + the `root.tar` entry's chunks to its stdin, then waits for the PVE task.
5. PVE runs `tar cpf - --directory=<staging> .` into its own extractor inside the new container's user namespace (ids get shifted there).
6. `restore_container_cleanup`: `rm -rf --one-file-system` the staging dir, remove request and socket.

The staging dir needs free space on the node's `/var/tmp` equal to the container's data.

## Instant recovery flow (VMs)
The VM boots on the node from qcow2 overlays whose backing file is the appliance's read-only
NBD export; guest writes go into the overlays on the node; a live `qm disk move` (drive-mirror)
then copies each disk to real storage and frees the overlay. The appliance stays read-only and
initiates every connection; the key stays `restrict`ed.

Lab-verified PVE 9.2 behaviour this relies on:
- qemu-server generates `-blockdev` for a qcow2 volume without a `backing` key (unless the storage
  reports snapshot method `mixed`), so QEMU opens the backing file named in the qcow2 header.
  PVE only rejects backing files for *untrusted* images (imports), not on VM start or disk move.
- `qemu-img info` (PVE's `file_size_info`) does not open the backing file.
- The backing file is `json:{"driver":"raw","file":{"driver":"nbd","server":{"type":"unix","path":"/run/nexusbackup/ir/<vmid>.<archive>.<device>.sock"},"export":"<device>","reconnect-delay":60,"open-timeout":60}}`
  (a plain `json:{"driver":"nbd",…}` with backing format raw fails: "A block device must be specified for file").
  QEMU holds one NBD connection per disk; after a server outage it reconnects by itself and
  re-runs paused requests (`reconnect-delay`), `open-timeout` bridges short listener gaps at open.
- `qm disk move <vmid> <disk> <storage> --delete 1` on the running VM mirrors through the backing
  chain, switches to the new volume, drops the NBD connection and calls `free_image` on the overlay.

Steps (`nexus-pve <cfg> instant-recover <vmid> <time> <node> <target> <storage> [--link-down]`):
1. Appliance reads `qemu-server.conf` from the snapshot and rewrites it (`crate::ir::ir_config`):
   every disk with a `#qmdump#map:<key>:<device>:…` line becomes `<storeid>:ir/<target>/<archive>.<device>.qcow2`
   (options kept, `size=` dropped); disks without a map line (`backup=0`) and disks excluded by the group (`excluded-disks.json`) are left out; the cloud-init
   drive is recreated as `<storage>:cloudinit`; ISO CD-ROMs are kept; NIC MACs are dropped (PVE assigns
   new ones), `--link-down` adds `link_down=1` to every NIC; `vmgenid` (root-only via the API) and a
   UUID-only `smbios1` are dropped so PVE generates new ones; `meta`, `lock`, `parent`, `onboot`,
   `unusedN`, snapshot sections and the description are dropped. Templates and VMs with
   `tpmstate0` (swtpm needs a local raw image) are refused.
2. Appliance refuses an existing target vmid, pushes the catalog (the plugin sizes overlays from it).
3. Per device the appliance keeps one idle `ir-serve <target> <archive> <device>` SSH session; it reads
   `listening`, then waits for `accepted`, hands that session to an NBD server thread
   (`nbd::server::serve` over the snapshot's fixed index) and immediately starts the next listener.
   So every connection QEMU makes (VM start, reconnect, offline move via `qemu-img convert`) is
   served, sequential or concurrent, each over its own session.
4. Once all sockets are published: `POST /nodes/<node>/qemu` with the rewritten config, then
   `POST /nodes/<node>/qemu/<target>/status/start`.
   Plugin `activate_volume` (root) creates the overlay if missing: checks that `ir/`, `ir/<storeid>/`,
   `ir/<storeid>/<vmid>/` are real directories owned by root without group/other write, takes the
   size from the catalog (`device_sizes`, untainted), runs `qemu-img create -f qcow2 -u -F raw -b <json above>`
   into a temp name and renames. An existing overlay (guest writes) is reused; a symlink is refused.
   The backing path is derived from the volume name only, never from the catalog or the appliance.
5. Per disk: `POST /nodes/<node>/qemu/<target>/move_disk disk=<key> storage=<storage> delete=1`,
   waited for one after another. A failed move is reported, but serving continues.
6. Appliance polls `GET /nodes/<node>/qemu/<target>/config` (5 s) until no value references
   `<storeid>:ir/<target>/` (including `unusedN`), or the VM is gone; then it kills all its sessions.
   Idle helpers see stdin EOF and remove their own socket; nothing else is left on the node.
7. Plugin `free_image` deletes only `ir/` overlays (and the empty vmid dir); backups stay undeletable.
   `list_images`/`list_volumes` (content `images`) report the overlays of this storage on this node.

`nexus-pve <cfg> ir-serve <node> <target>` resumes serving for a VM that still references IR
volumes (derives archive and devices from its config) and returns once they are gone.

Lab (nested PVE 9.2.2, Debian 13 VM, 4 GiB disk, appliance and node on one host, SSH via localhost):
VM running 4.4–4.5 s after the command started (catalog push, listener, create, start); live move to
local-lvm 24–30 s for 4 GiB (~140–170 MiB/s through the SSH relay while the guest boots). With
`--link-down` the guest's login prompt appeared after 160 s, because cloud-init waits for
`systemd-networkd-wait-online` (2 min) before getty; without cloud-init the prompt came within seconds.

### Failure modes
| Event | Behaviour |
|---|---|
| Appliance dies / network to the node breaks | The SSH sessions end (a session whose appliance end died ends at the next request QEMU sends); QEMU loses the NBD connection and keeps reconnecting. Reads of blocks that are not in the overlay are held up to `reconnect-delay` (60 s) and re-run after a reconnect; after that they fail with EIO until a server is back (the guest may then remount read-only or crash). Data already in the overlay is unaffected. Restart with `nexus-pve <cfg> ir-serve <node> <target>`. Lab (SIGKILL of the appliance): (a) monitor reads of uncopied blocks blocked 16 s and finished once `ir-serve` was back (started 11 s after the kill); (b) killed during the drive-mirror: the mirror stalled at 18.6 %, continued after `ir-serve` reconnected, the task ended OK and the moved disk matched the snapshot except 11 MiB written by the guest. |
| Disk move fails | Reported by `instant-recover` (non-zero exit at the end), the appliance keeps serving; retry `qm disk move … --delete 1` (GUI/CLI) or destroy the VM. |
| Node reboot (not tested) | `/run/nexusbackup/ir` is recreated empty; the overlay (guest writes) survives in `/var/lib/nexusbackup/ir`. Starting the VM needs the appliance serving (`ir-serve <node> <target>`), otherwise the open fails after `open-timeout`. The overlay must not be removed manually while the VM references it. |
| Double serving (two appliance processes) | Each new listener renames its socket over the path; QEMU connects to whichever listener is current; old idle listeners never take the path back. Both serve identical read-only data, so this is harmless. |
| VM stopped/destroyed during IR | Not possible while a move runs (the move holds the config lock; `qm stop` times out). Otherwise `qm destroy` frees the overlays via `free_image` and the appliance stops once the VM is gone (lab-verified with `ir-serve`). |
| Overlay growth | Guest writes accumulate on the node's root file system until the move finishes. |

### Privileges
No root-only operation is needed. The token needs on `/vms/<target>`: `VM.Allocate`, `VM.Config.Disk`,
`VM.Config.CDROM`, `VM.Config.CPU`, `VM.Config.Memory`, `VM.Config.Network`, `VM.Config.HWType`,
`VM.Config.Options`, `VM.Config.Cloudinit`, `VM.PowerMgmt`, `VM.Audit` (PVEVMAdmin covers them);
`Datastore.AllocateSpace` on the target storage (disk move, cloud-init drive); `SDN.Use` on the bridge's
zone. Using the IR volumes needs no privilege on the NexusBackup storage: PVE allows a VM to use
volumes it owns (`check_volume_access`, owner = target vmid). `vmgenid` can only be set by root,
hence it is never sent. Lab token: PVEVMAdmin + PVEDatastoreAdmin + PVEAuditor on `/`,
PVESDNUser on `/sdn/zones/localnetwork` (unchanged).

## Known issues
- `api()` returns 11 → every PVE CLI call prints "implementing an older storage API" (current APIVER 14). Decide: return `PVE::Storage::APIVER` within a tested range.
- vzdump `bwlimit` is not enforced (plugin logs a warning); bandwidth limiting belongs on the appliance side.
- Token privileges for API restore additionally need `SDN.Use` on the guest's bridge zone (e.g. `PVESDNUser` on `/sdn/zones/localnetwork`).

- Container restore stages the full tree under `/var/tmp/nexusbackup` (needs that much free space on the node's root fs).
- Container backups are always full reads (tar of the snapshot); dedup happens in the appliance's chunk store.
- Provider log lines (`$log_function`) go to the vzdump task log/syslog, not to the per-guest log stored by `backup_handle_log_file`.

## Not in v1
Trim of read regions (fleecing shrink), container file-level restore.
