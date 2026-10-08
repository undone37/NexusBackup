# Proxmox VE Backup Provider API – Reference for NexusBackup

Research date: 2026-10-08. Everything below was read from the sources, not recalled from memory.
Where something is an inference and not verified in code, it says so.

## Sources (exact revisions read)

| Repo (git.proxmox.com) | Branch | Commit | Files |
|---|---|---|---|
| pve-storage | master (PVE 9.x, libpve-storage-perl 9.1.12) | `3e57b21058a84c3ee4686a0d30c3255c2603e997` | `src/PVE/BackupProvider/Plugin/Base.pm`, `src/PVE/Storage.pm`, `src/PVE/Storage/Plugin.pm`, `ApiChangeLog` |
| pve-storage | stable-8 (PVE 8.4, 8.3.9) | `9aab8f6f52b314fda5e2aceef6472ffd21b7d5b3` | same |
| pve-storage-plugin-examples | master | `c21d18f0948f278032ef6e635358a281172ad2e0` | `backup-provider-directory/src/PVE/BackupProvider/Plugin/DirectoryExample.pm`, `.../Storage/Custom/BackupProviderDirExamplePlugin.pm`, `backup-provider-borg/...` (`Borg.pm`, `BorgBackupPlugin.pm`) |
| qemu-server | master | `80e0590e144359fd136a2ba1e3f44716bfc535b0` | `src/PVE/VZDump/QemuServer.pm` (`archive_external`), `src/PVE/QemuServer.pm` (`restore_external_archive`), `src/PVE/QemuServer/QemuImage.pm`, `src/PVE/API2/Qemu.pm` |
| qemu-server | stable-bookworm (8.x) | `5ccd363e5908aa5a7b969797babdff1df5159475` | `archive_external` is byte-identical to master |
| pve-manager | master / stable-8 | `ac0c87dd3711…` / `5aee9c09` | `PVE/VZDump.pm`, `PVE/API2/VZDump.pm` |
| pve-container | master | `de0ddd657525…` | `src/PVE/VZDump/LXC.pm`, `src/PVE/LXC/Create.pm` |
| pve-guest-common | master | `191c23e385e5…` | `src/PVE/VZDump/Common.pm` (vzdump parameter schema) |
| pve-qemu | master | `cb85b70c40df…` | `debian/patches/pve/0042-PVE-backup-implement-backup-access-setup-and-teardow.patch` (QMP `backup-access-setup`/`-teardown`) |

URLs:
- https://git.proxmox.com/?p=pve-storage.git;a=blob_plain;f=src/PVE/BackupProvider/Plugin/Base.pm;hb=HEAD
- https://git.proxmox.com/?p=pve-storage.git;a=blob_plain;f=src/PVE/BackupProvider/Plugin/Base.pm;hb=refs/heads/stable-8
- https://git.proxmox.com/?p=pve-storage.git;a=blob_plain;f=ApiChangeLog;hb=HEAD
- https://git.proxmox.com/?p=pve-storage-plugin-examples.git;a=summary
- https://git.proxmox.com/?p=qemu-server.git;a=blob;f=src/PVE/VZDump/QemuServer.pm;hb=HEAD
- https://git.proxmox.com/?p=pve-manager.git;a=blob;f=PVE/VZDump.pm;hb=HEAD
- https://pve.proxmox.com/wiki/Storage_Plugin_Development
- https://pve.proxmox.com/wiki/Roadmap (8.4 highlight "Support for external backup providers"; 9.1: "fix backups with fleecing failing for VMs with TPM state", bug 6882)
- QEMU NBD dirty-bitmap meta context: https://qemu.readthedocs.io/en/master/interop/nbd.html

The feature landed on 2025-04-04 (pve-storage `ff971ae`, qemu-server `98209f99`/`cc4a8b81`, pve-manager `ebfd6dd7`, pve-container `be485a5`/`5022cfc`) and shipped in PVE 8.4.

## 0. Version matrix

| PVE | libpve-storage-perl | APIVER | APIAGE | Accepted plugin `api()` range |
|---|---|---|---|---|
| 8.4 (8.3.4 to 8.3.9) | stable-8 | 11 | 2 | 9..11 |
| 9.0 (9.0.0) | | 11 | 2 | 9..11 |
| 9.0 (9.0.13) | | 12 | 3 | 9..12 |
| 9.1 (9.1.0) | | 13 | 4 | 9..13 |
| current master (9.1.12) | | 16 | 7 | 9..16 |

Backup-provider support arrived in APIVER **11**. **Have `api()` return 11.** That loads on every 8.4 and 9.x version (min = APIVER-APIAGE = 9). The only cost is a "implementing an older storage API" warning on 9.x. The example plugins do the same: return `PVE::Storage::APIVER` when it is between min and max, otherwise max.

**The Base.pm API is identical on 8.4 and 9.x.** `diff` between stable-8 and master shows only POD typo fixes (commit `67d8cc7`). The caller code is also identical (`archive_external` in qemu-server is byte-identical; vzdump call order is the same). Differences between versions:
- 9.0 regression (blockdev switch): backup with TPM state plus fleecing failed. Fixed in qemu-server `cd82e3f2` (9.1, bug #6882). 8.4 is not affected.
- Storage API v12+ (9.x) added `qemu_blockdev_options()`, `volume_qemu_snapshot_method()` and others. A backup-only storage does not need them, because it never holds images.

## 1. Backup provider methods (`PVE::BackupProvider::Plugin::Base`)

All methods are instance methods. The base class `die`s with "implement me in subclass".

| Method | Params | Returns / notes |
|---|---|---|
| `new($class, $storage_plugin, $scfg, $storeid, $log_function)` | `$log_function->($level, $msg)`, level `info`/`warn`/`err` | blessed object |
| `provider_name()` | | string (used in log lines and as the "creating <name> archive" text) |
| `job_init($start_time)` | unix ts | Called once per vzdump job, before any guest. `die` aborts the whole job. |
| `job_cleanup()` | | Called once at the end, on success and failure (on failure from an eval). |
| `backup_init($vmid, $vmtype, $start_time)` | `$vmtype` = `qemu`/`lxc` | `{ 'archive-name' => $name }`. `$name` must match `^([a-zA-Z0-9\-\.\+\=\_]|/|:)+$` (`$PVE::Storage::SAFE_CHAR_CLASS_RE` plus `/` and `:`). The resulting volid is **`"$storeid:backup/$name"`**. Your storage `parse_volname` must accept `backup/$name`. |
| `backup_cleanup($vmid, $vmtype, $success, $info)` | `$info->{error}` on failure. `$vmtype` may be undef on abort. | On success: `{ stats => { 'archive-size' => $bytes } }` |
| `backup_get_mechanism($vmid, $vmtype)` | | `'nbd'` or `'file-handle'` for qemu, `'directory'` for lxc. `die`/undef = unsupported. |
| `backup_handle_log_file($vmid, $filename)` | path to the task log of this guest | Called after `backup_cleanup`, on success and failure. |
| `backup_vm_query_incremental($vmid, $volumes)` | `$volumes->{$device}{size}` (bytes) | `{ $device => 'new' \| 'use' \| 'none' }`. A missing device means no bitmap, and any existing bitmap is discarded. undef = no incremental. |
| `backup_vm($vmid, $guest_config, $volumes, $info)` | see section 2 | Returns when done. **Returning normally = success.** |
| `backup_container_prepare($vmid, $info)` | same `$info` as `backup_container` | Runs privileged, right before `backup_container`. |
| `backup_container($vmid, $guest_config, $exclude_patterns, $info)` | see section 5 | Runs **in the container's user namespace (as mapped root uid), in a forked child**. Changes to `$self` are lost. |
| `restore_get_mechanism($volname)` | (callers also pass `$storeid` as an extra arg) | `($mechanism, $vmtype)`. `qemu-img` for qemu, `tar`/`directory` for lxc. |
| `archive_get_guest_config($volname)` | | raw config text (independent of restore_*_init, see section 3) |
| `archive_get_firewall_config($volname)` | | raw text, or undef if none, `die` on error |
| `restore_vm_init($volname)` | | `{ $device => { size => $bytes }, ... }` |
| `restore_vm_volume_init($volname, $device, $info)` | `$info` = `{}` | `{ 'qemu-img-path' => $path }` (see section 4) |
| `restore_vm_volume_cleanup($volname, $device, $info)` | | always called |
| `restore_vm_cleanup($volname)` | | always called |
| `restore_container_init($volname, $info)` | (callers pass `($volname, $storeid, {})`) | `{ 'tar-path' => $p }` or `{ 'archive-directory' => $d }` |
| `restore_container_cleanup($volname, $info)` | | always called |

There is no separate `restore_qemu_img_init`. The POD mentions it, but the real names are `restore_vm_volume_init`/`restore_vm_init`.

### Call order (pve-manager `PVE/VZDump.pm::exec_backup_task`, same in 8 and 9)

```
storage_info(): $plugin->new_backup_provider($scfg, $storeid, $log_fn)   (once per job)
getlock(/var/run/vzdump.lock)   <- ONE vzdump job per node at a time (lockwait default 180 min)
job_init($starttime)
for each guest (sequential):
    lock guest (lock: backup); mode = running ? requested : 'stop'
    [qemu] prepare
    backup_init(...)                  -> archive-name
    hook backup-start
    archive():
      [qemu] archive_external():
         start VM paused if not running (enforce_vm_running_for_backup)
         check QEMU 'backup-access-api' support
         fleecing setup (MANDATORY, see section 8)
         backup_get_mechanism($vmid,'qemu')
         backup_vm_query_incremental($vmid, {dev=>{size}})
         fs-freeze -> QMP backup-access-setup -> fs-thaw -> resume VM
         QMP nbd-server-start (unix socket) + block-export-add per device
         backup_vm($vmid, $conf, $volumes, $info)       <- may block arbitrarily long
         on normal return: teardown.success = 1
      [lxc] backup_container_prepare + backup_container (in userns)
    notes-template -> update_volume_attribute(notes)      (failure = warning)
    protected      -> update_volume_attribute(protected)  (failure = BACKUP FAILS)
    remove (default 1) -> PVE::Storage::prune_backups -> plugin->prune_backups (die = BACKUP FAILS)
    backup_cleanup($vmid,$vmtype,1,{})                    -> archive-size
    hook backup-end
  (on any error above: backup_cleanup($vmid,$vmtype,0,{error}) + hook backup-abort)
  plugin->cleanup(): QMP backup-access-teardown(success => teardown.success),
                     nbd-server-stop, detach + free fleecing images, rm /run/qemu-server/<vmid>.backup-access.<pid>/
  unlock guest
  backup_handle_log_file($vmid, $tmplog)
job_cleanup()
```

## 2. VM backup with mechanism `nbd` (the part that matters for us)

### What `backup_vm` receives

`$guest_config`: raw text of `$tmpdir/qemu-server.conf`. This is the vzdump-processed config. It includes `#qmdump#map:<virtdev>:<devname>:<storeid>:<format>:` lines, which restore needs (section 3).

`$volumes` (built by `backup_access_to_volume_info`):
```perl
$volumes = {
  'drive-scsi0' => {                       # device name == NBD export name
     size          => 34359738368,         # bytes (block node size)
     'bitmap-mode' => 'none'|'new'|'reuse',
     'nbd-path'    => '/run/qemu-server/<vmid>.backup-access.<vzdump-pid>//<vmid>-nbd.backup-access',
     'bitmap-name' => 'snapshot-access:<storeid>',   # only if bitmap-mode ne 'none'
  },
  'drive-efidisk0' => {...},
  'drive-tpmstate0-backup' => {...},       # TPM state uses this special name
};
```
- **One** NBD server (unix socket) per VM backup. All disks are exports on the same socket, and **export name = device name** (`drive-<virtdev>`, TPM: `drive-tpmstate0-backup`). EFI and TPM disks are included.
- URI form used by PVE itself: `nbd+unix:///<device>?socket=<nbd-path>`.
- Dirty bitmap meta context: **`qemu:dirty-bitmap:snapshot-access:<storeid>`**. The bitmap name is the QMP target-id `"snapshot-access:$storeid"`, so bitmaps are per (VM, disk, PVE storage ID). PVE uses `nbdinfo <uri> --map=qemu:dirty-bitmap:<name>`. In the extents, flag bit 0 (value 1) = dirty.
- Exports are created `writable => true` **only to allow discard (NBD_CMD_TRIM)**. After reading a region, trim it so the fleecing image shrinks.
- Bitmap granularity is `PROXMOX_BACKUP_DEFAULT_CHUNK_SIZE`, which is 4 MiB (inferred from proxmox-backup-qemu's constant, not re-checked).
- The socket lives in a directory created `0700` and owned by root. Only root (or a process with CAP_DAC_OVERRIDE) can connect.

`$info`:
- `'bandwidth-limit'` = bytes/s (vzdump `bwlimit` KiB/s * 1024). The provider is expected to honour it.
- `'firewall-config'` = raw `/etc/pve/firewall/<vmid>.fw` content, present only if it exists.

### Snapshot-access semantics (Base.pm POD + QEMU patch)
- The export is a point-in-time snapshot from `backup-access-setup`. Guest writes after that point are copy-before-write'd into the fleecing image.
- **With a bitmap, only the dirty areas are readable.** READ, and also BLOCK_STATUS on `base:allocation`, outside dirty areas returns an **error**. If the bitmap is completely clean, nothing is readable, and you can only query the bitmap. So: first query `qemu:dirty-bitmap:...`, then read only the dirty extents. Do zero-detection on the data you read, not via base:allocation.
- With `bitmap-mode` `none`, the whole image is readable.

### Deciding incremental (`backup_vm_query_incremental`)
- Input is `{ $device => { size } }`. Return `use` (re-use the existing bitmap, or create it if missing), `new` (always recreate), or `none`/absent (no bitmap, and an existing one is removed).
- QEMU then reports the **effective** state, mapped as follows:

| QEMU bitmap-action | `bitmap-mode` given to backup_vm | meaning |
|---|---|---|
| `not-used`, `not-used-removed` | `none` | full read, no bitmap |
| `new` | `new` | new bitmap created **fully dirty**, so effectively a full read through the bitmap |
| `invalid` | `new` | |
| `missing-recreated` | `new` | you asked `use`, but the bitmap was gone (VM restarted, disk re-attached and so on). Fully dirty. |
| `used` | `reuse` | only blocks changed since the last *successful* backup to this storage ID are dirty |

- **The authority is `bitmap-mode` in `backup_vm`, not your query answer.** With `reuse`, the appliance must apply the delta onto exactly the last backup that PVE considered successful for that storage ID. With `new`, it must read every dirty extent (the whole disk). The appliance can still dedupe against its previous copy. If the size changed, the docs suggest answering `new`.

### Bitmap lifetime (how PVE "knows" the previous backup succeeded)
- QEMU does not know. **qemu-server tells it in `backup-access-teardown(success)`**. `success` is 1 if and only if `backup_vm` returned without dying. It is set immediately after `backup_vm` returns.
- teardown success: the backup-access bitmap is cleared and replaced by the background bitmap (writes since setup). The next `reuse` contains only the new writes.
- teardown failure: the background bitmap is merged into the backup-access bitmap. The next `reuse` covers everything since the last successful backup.
- The bitmaps are **in-memory, non-persistent** QEMU dirty bitmaps. They are lost on VM shutdown, host reboot, or a stop-mode backup of a stopped VM (the VM is started paused for the backup and stopped afterwards). Then you get `new` (full) next time. Whether they survive live migration is **unverified**: qemu-server enables the `dirty-bitmaps` migration capability when QEMU reports `pbs-dirty-bitmap-migration`, but the backup-access name tracking is not obviously migrated. Test this and treat `new` as normal.
- **Ordering gotcha:** teardown runs in `plugin->cleanup`, *after* `backup_cleanup`, protection, notes and prune. If anything fails **after** `backup_vm` returned (prune_backups dies, setting `protected` fails, `backup_cleanup` dies), vzdump reports the guest backup as failed and calls `backup_cleanup(success=0)`, **but QEMU still gets `success=true` and clears the bitmap**. Consequence for our design: the appliance must commit the snapshot durably *before* `backup_vm` returns, and must **never discard** a snapshot just because `backup_cleanup(success=0)` arrives after a successful `backup_vm`. The plugin must remember "backup_vm returned OK" and tell the appliance to keep the snapshot.
- Corollary: `backup_vm` must `die` if the appliance did not finish and commit (aborted SSH session, read error, timeout). Then the dirty bits are preserved.

### Failure handling
- `backup_vm` dies: logged, VM resumed, teardown(success=false), `backup_cleanup(0, {error})`, fleecing images freed.
- vzdump installs `$SIG{INT,TERM,QUIT,HUP,PIPE} = sub { die "interrupted by signal\n" }` around `archive_external`. The task stop button and `vzdump --stop` therefore arrive as a Perl `die` inside your blocking wait. Make the wait loop interruptible (no `alarm` misuse; sysread/select get EINTR, then the handler runs) and clean up in an eval/finally.

### May `backup_vm` block for a long time? Yes.
Nothing in qemu-server/vzdump puts a timeout on `backup_vm` (the QMP calls around it have 60 s timeouts; `backup_vm` itself has none). PVE's own `file-handle` path and the example plugin read the export synchronously inside `backup_vm`. The NBD server and exports stay up until `backup_vm` returns. A plugin that publishes `nbd-path` plus export names plus bitmap name to a rendezvous location, then blocks until an external reader (our appliance, via SSH forced-command helper bridging stdio to the unix socket) reports completion, is consistent with the API contract. Side effects of blocking:
- The guest stays locked (`lock: backup`): no config changes, migration or snapshots.
- The per-node vzdump lock is held: other backup jobs on that node queue (lockwait 3 h default, then fail). Guests within a job run sequentially.
- The fleecing image grows with guest writes for the whole duration. Discard what you read.
- No other backup (for example to PBS) of that VM can run concurrently ("only one regular backup or one active backup access at a time").

## 3. Config / metadata

- VM: `$guest_config` (raw `qemu-server.conf` from vzdump, including `#qmdump#map` lines). Firewall: `$info->{'firewall-config'}`.
- CT: `$guest_config` (raw `pct.conf`). Firewall: `$info->{'firewall-config'}`. Exclude patterns: `$exclude_patterns`.
- The task log arrives via `backup_handle_log_file($vmid, $file)` (store it for the GUI/report).
- Notes: vzdump `notes-template` leads to `PVE::Storage::update_volume_attribute($cfg, "$storeid:backup/$archive", 'notes', $text)`. Protection: `'protected', 1`. Both go to the **storage plugin's** `update_volume_attribute`/`get_volume_attribute`.
- Restore (VM, `restore_external_archive`):
  1. `archive_get_guest_config` writes the config to tmp. The `#qmdump#map:<virtdev>:<devname>:...` lines are parsed and **each `<devname>` must be a key returned by `restore_vm_init`** ("archive does not contain data for drive ...").
  2. `archive_get_firewall_config` (if defined) is copied to `/etc/pve/firewall/<vmid>.fw`.
  3. Volumes are allocated with the sizes from `restore_vm_init`, `qemu-img convert` runs per volume, and the config is rewritten and merged.
- `archive_get_guest_config` is **also called independently of any restore**: `PVE::Storage::extract_vzdump_config`, used by the GUI "Show Configuration" (`GET /nodes/{node}/vzdump/extractconfig`) and by the restore API for its early permission check. It is called with `($volname, $storeid)`. **It must work at any time without the appliance actively connected**, so keep a local copy of config/firewall/log per backup on the PVE node. The plugin already receives them in `backup_vm`/`backup_container`.

## 4. VM restore

- Only mechanism: **`qemu-img`**. Return `{ 'qemu-img-path' => $path }`. PVE runs `qemu-img convert -p -n -f raw <path> <target>` (format forced `raw`, no detection, `-r <bwlimit>K` if set).
- **Contradiction between POD and code:** the POD says the path "could also be an NBD URI". The code (8.x and 9.x) does this:
  1. `PVE::Storage::file_size_info($path, undef, 'raw', 1)` calls `File::stat::stat($path)` first and **dies** for an untrusted path that can't be stat'ed ("failed to stat").
  2. `QemuImage::convert` only accepts a source that is a volid or satisfies `-f $path || -b $path`. Otherwise it dies with "is not a valid volid nor path for qemu-img convert".

  So an `nbd+unix://` URI **does not work**. Return a regular file or a block device:
  - `nbdfuse <mountdir>/<file> 'nbd+unix:///<export>?socket=...'` gives a FUSE regular file. qemu-server itself uses this technique for `file-handle` backup (needs `libnbd-bin`). Or
  - `qemu-nbd -c /dev/nbdN 'nbd:unix:<sock>:exportname=<x>'` gives a block device (needs the `nbd` kernel module). The example plugin does this, and pve-manager adds `/dev/nbd*` to the LVM global filter.
  Clean up in `restore_vm_volume_cleanup`.
- `restore_vm_init` sizes are used to allocate target volumes and must equal the size of the device behind `qemu-img-path`.
- The source is "untrusted": backing files and qcow2 data-file are refused (it is raw anyway).
- **Live restore is not supported** for backup providers: `die "live restore from backup provider is not implemented"` (both 8.x and 9.x).
- During restore the plugin runs inside the PVE restore worker. For our no-outbound design, the appliance must start the restore via the API and also connect in via SSH to serve the NBD data. The plugin's `restore_vm_volume_init` has to wait for the appliance-provided socket (rendezvous), then attach nbdfuse/qemu-nbd.
- Privileges for restore: `POST /nodes/{node}/qemu` with `archive=<storeid>:backup/<name>`, `vmid`, optional `storage`, `unique`, `force`. It needs VM.Allocate (or VM.Backup if overwriting an existing VM) plus `Datastore.AllocateSpace` on target storages. To access the archive: `Datastore.Allocate` on the backup storage, **or** `Datastore.AllocateSpace` on it plus `VM.Backup` on `/vms/<ownervm>`. The latter requires `parse_volname` to return the owner vmid as the 3rd element.

## 5. Containers

- Backup mechanism: only **`directory`** (PVE dies on anything else).
  `$info = { directory => $snapdir, sources => [ '.', 'mp0path', ... ], 'backup-user-id' => $root_uid, 'firewall-config' => ..., 'bandwidth-limit' => ... }`.
  `backup_container_prepare` runs privileged first (for example chown the target or hand out credentials). `backup_container` then runs via `PVE::LXC::Namespaces::run_in_userns` as the mapped root (100000 by default) in a fork. The directory is the snapshot/suspend copy of the rootfs plus mount points (`--one-file-system` semantics are up to you; the example uses tar with `--sparse --numeric-owner --acls --xattrs`).
- Privileged CTs: you get a warning at backup time, and restore **refuses** privileged restore ("refusing to restore privileged container backup from external source"). Restore must target `unprivileged: 1`.
- Restore mechanisms:
  - `tar`: `{ 'tar-path' => $p }`, must be a regular file (`-f`). It may be compressed.
  - `directory`: `{ 'archive-directory' => $d }`, must be a directory. PVE pipes `tar cpf - --directory=$d .` into its extractor (in the userns).
  For pull-model restore, `directory` could be a FUSE/sshfs-like mount provided via the appliance connection. `tar` needs a local or FIFO-less regular file, so it effectively has to be staged.

## 6. Storage plugin side

Install: `/usr/share/perl5/PVE/Storage/Custom/<Name>.pm`, `package PVE::Storage::Custom::<Name>; use base qw(PVE::Storage::Plugin);`. It is loaded by every PVE daemon. After install, restart `pvedaemon pveproxy pvestatd pvescheduler` (and `pve-ha-lrm`/`pve-ha-crm` if used). Ship it as a .deb. License: the plugin code must be AGPLv3-compatible (README of the examples repo); the appliance itself does not need to be.

Required pieces (from `BackupProviderDirExamplePlugin.pm` + Plugin.pm):
```perl
sub api { 11 }                          # see section 0
sub type { 'nexusbackup' }              # storage.cfg type
sub plugindata { {
    content  => [ { backup => 1, none => 1 }, { backup => 1 } ],
    features => { 'backup-provider' => 1 },          # REQUIRED
    'sensitive-properties' => { },                   # e.g. { 'secret' => 1 } -> /etc/pve/priv/storage/
} }
sub properties { { 'nexus-...' => { type => 'string', ... } } }   # only NEW keys (must be globally unique across plugins)
sub options { { path => { fixed => 1 }?, nodes => {optional=>1}, disable => {optional=>1},
                'prune-backups' => {optional=>1}, 'max-protected-backups' => {optional=>1}, ... } }
sub new_backup_provider { my ($class, $scfg, $storeid, $log_function) = @_;
    return PVE::BackupProvider::Plugin::Nexus->new($class, $scfg, $storeid, $log_function); }
```
Note: the example storage plugin declares `new_backup_provider($class, $scfg, $storeid, $bandwidth_limit, $log_function)`. That is **wrong**: the caller passes only `($scfg, $storeid, $log_function)`. It happens to work by argument shifting. Use the 4-arg signature from Plugin.pm.

Storage methods to implement for a backup-only store (the example dies or no-ops the rest):
- `parse_volname($volname)`: for `backup/<archive-name>` return `('backup', $name, $vmid)` (vmid = owner, needed for permissions).
- `path($scfg, $volname, $storeid, $snap)`: return something (`($path, $vmid, 'backup')`). It is not used for data.
- `list_volumes($storeid, $scfg, $vmid, $content_types)`: return entries `{ volid => "$storeid:backup/<name>", vmid, format => '<anything e.g. directory>', ctime, size, subtype => 'qemu'|'lxc', content => 'backup', notes?, protected? }`. The GUI backup list, prune and max-backups use this. **It must be answerable locally** (we make no outbound calls). Keep an index on the node, synchronised by the appliance over SSH.
- `volume_size_info` (`wantarray ? ($size,$format,$used,$parent,$ctime) : $size`), `get_volume_attribute`/`update_volume_attribute` (`notes`, `protected`), `free_image` (delete backup, which the GUI calls via `vdisk_free`), `prune_backups($scfg,$storeid,$keep,$vmid,$type,$dryrun,$logfunc)` returning a list of `{volid, ctime, mark => 'keep'|'remove'|'protected', type, vmid}`.
- **prune_backups must not die.** vzdump `remove` defaults to 1, so it is called after **every** backup. A die makes the guest backup fail *after* the bitmap was already committed (section 2). If retention lives on the appliance, return a list with all `keep` marks.
- `activate_storage`/`deactivate_storage`/`activate_volume`/`deactivate_volume`/`status` (`status` returns `($total,$free,$used,$active)`; return fake/cached values, quickly, without network), `alloc_image`/`create_base`/`clone_image`/`volume_resize`/`volume_snapshot*` (die), `volume_has_feature` (0), `list_images` (`[]`).
- `pvestatd` calls `status`/`activate_storage` every ~10 s on every node. Keep them local and cheap.

storage.cfg example:
```
nexusbackup: nexus
        path /var/lib/nexusbackup/nexus      # if you keep 'path' (the example does)
        content backup
        nodes pve1,pve2                       # optional
        prune-backups keep-all=1
```
`content backup` is required: vzdump checks `$scfg->{content}->{backup}`. The storage is cluster-wide config, but `list_volumes` runs on whichever node asks. If the index is node-local, node B won't see backups made on node A unless the appliance syncs the index to all nodes.

## 7. Triggering via REST API

`POST /api2/json/nodes/{node}/vzdump`. It returns the **UPID string** (`data`). Main parameters (pve-guest-common `VZDump/Common.pm`):
`vmid` (comma list) | `all=1` + `exclude`; `storage=<our storeid>`; `mode=snapshot|suspend|stop` (default snapshot); `fleecing=enabled=1,storage=<local thin storage>` (**required for VMs with providers**); `notes-template` (`{{guestname}}`, `{{vmid}}`, `{{node}}`, `{{cluster}}`); `protected=1`; `remove=0|1`; `prune-backups`; `bwlimit` (KiB/s); `lockwait` (minutes); `notification-mode`, `mailto`, `mailnotification`; `stopwait`, `ionice`, `performance`, `pool`, `exclude-path`, `pbs-change-detection-mode` (PBS only). `compress`, `dumpdir`, `tmpdir`, `script`, `stdout`: not relevant (stdout is refused for providers; dumpdir, tmpdir and script are root@pam only).

Privileges (API token with privilege separation: grant ACLs to the *token*):
- `VM.Backup` on `/vms/{vmid}` (or pool)
- `Datastore.AllocateSpace` on `/storage/<backup storeid>` **and** on `/storage/<fleecing storeid>`
- `Datastore.Allocate` on the backup storage if passing `prune-backups`
- `Sys.Modify` on `/` for `bwlimit`, `performance`, `ionice`; `Sys.Modify` on `/nodes/{node}` for `stop`
- Suggested role: `PVEBackupUser`-like (VM.Backup + Datastore.AllocateSpace + Datastore.Audit) with ACLs on `/vms`, `/storage/nexus`, `/storage/<fleece>`.

**Gotcha:** the call must go to the node where the guest runs. If the requested vmids are on another node and `all` is not set, the API returns the literal string **`"OK"` instead of a UPID** and does nothing. Resolve the node first via `GET /cluster/resources?type=vm`.

Polling:
- `GET /nodes/{node}/tasks/{upid}/status` gives `{ status => 'running'|'stopped', exitstatus => 'OK' | '<error text>' | 'job errors', ... }`.
- `GET /nodes/{node}/tasks/{upid}/log?start=N&limit=M` gives `[ {n, t}, ... ]`.
- `DELETE /nodes/{node}/tasks/{upid}` stops the task (SIGTERM, which becomes a `die` in `backup_vm`).
- Tasks owned by the token are readable by it; otherwise `Sys.Audit` on `/nodes/{node}` is needed.
- The node is embedded in the UPID: `UPID:<node>:<pid>:<pstart>:<starttime>:vzdump:<vmid>:<user>:`.

Alternatively, PVE backup jobs (`/cluster/backup`) can run the schedule on the PVE side. That fits less well with the appliance-driven pull model, but works because the plugin just waits for the appliance.

## 8. Limitations / gotchas

1. **Fleecing is mandatory for VM backup with providers.** `archive_external` does `die "cannot setup backup access without fleecing"` unless `fleecing` `enabled=1,storage=<id>` is set (job, `/etc/vzdump.conf`, or API param). Templates can't use fleecing, so **VM templates cannot be backed up via a provider.** Fleecing images (`vm-<vmid>-fleece-<n>`, qcow2 when the storage supports it) are allocated for **all** disks including EFI and TPM, at full virtual size (thin). They grow with guest writes during the backup window and are freed afterwards. Use a fast local thin or sparse storage and discard after reading.
2. Requires QEMU with `backup-access-api` (query-proxmox-support). A VM started before the upgrade to a supporting pve-qemu must be restarted.
3. `mode`: all three modes end up in the same `archive_external`. snapshot = live with fs-freeze (guest agent) around setup. A stopped VM is forced to `stop` mode: QEMU is started paused, there is no bitmap continuity, so the backup is full (`new`).
4. Bitmaps are per storage ID (`snapshot-access:<storeid>`). Two provider storages, or renaming the storage, give independent or new bitmaps. They are lost on VM restart. Your query result can't force `reuse`.
5. The bitmap is committed on `backup_vm` return, before post-steps. See the ordering gotcha in section 2 (prune, protected, backup_cleanup errors).
6. Only one backup or backup-access per VM at a time. Only one vzdump job per node at a time (global lock).
7. NBD socket is root-only, under `/run/qemu-server/<vmid>.backup-access.<pid>/`. The path is only known inside `backup_vm`, so the plugin must hand it to the SSH-side helper. The helper must run as root, or the plugin must create a relay socket with suitable permissions.
8. Reads outside dirty areas fail with an error. A fully clean bitmap means zero readable bytes. The appliance must handle "nothing to read" as success.
9. Restore: `qemu-img-path` must be a regular file or a block device (no URI despite the POD). No live-restore. CT restore only as unprivileged.
10. `archive_get_guest_config`, `list_volumes`, `status` and attributes are called from GUI/API/pvestatd at arbitrary times. They need local data and no network.
11. `backup_container` runs as an unprivileged uid inside the userns, in a fork. It cannot reach root-only sockets unless `backup_container_prepare` prepares access.
12. The 9.0.x TPM+fleecing regression (bug 6882) is fixed in 9.1 (qemu-server `cd82e3f2`). Require at least qemu-server from 9.1 on PVE 9.
13. The example `DirectoryExample.pm` says itself that it is proof-of-concept only. It uses `/dev/nbdX` and qcow2 backing chains, and its restore path explicitly side-steps the backing-file safety check. Don't copy its restore approach blindly.
