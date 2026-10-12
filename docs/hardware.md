# Disks, SMART and the data array (Phase 16a/b)

User-facing procedure: manual [02 Installation → Data disks](../manual/02-installation.md#data-disks) and
[15 Troubleshooting → Replacing a disk](../manual/15-troubleshooting-faq.md#replacing-a-disk).

## Pieces

| Piece | Where | Role |
|---|---|---|
| `nexus-disks` | `os/greenboot/usr/libexec/nexus/nexus-disks` (Python, stdlib) | root helper: inventory, SMART, md arrays; executes the layout requests |
| `nexus-disks.timer` / `.path` / `.service` | `os/greenboot/usr/lib/systemd/system/` | scan every 5 minutes (SMART hourly); a request file starts it at once |
| control dir | `/var/lib/nexus/disks` (2771 root:nexus-webapi, `os/etc/tmpfiles.d/nexus-disks.conf`) | `req-<id>.json` (web-api), `status.json`, `ops.json` (0644), `state.json` |
| rules | `crates/catalog/src/hardware.rs` | issues per disk / array, alert keys, summary (shared by web-api and scheduler) |
| API | `crates/web-api/src/hardware.rs` | `GET /hardware`, rescan, self-test, layout requests (approval) |
| alerts + audit | `crates/scheduler/src/disks.rs` | `disk` alerts from `status.json`, `hardware.op` audit from `ops.json` |
| UI | `web/src/pages/Hardware.svelte`, dashboard tile | Configuration → Hardware |
| image | `os/Containerfile` | `smartmontools` (~2.3 MB) and `mdadm` (~1.1 MB) from AlmaLinux BaseOS; `smartd` disabled (one poller) |

## Status file

`nexus-disks` writes `status.json` on every run:

- `disks[]`: `lsblk -J -b -O` (whole disks; loop, rom and zram left out) with `smart` from `smartctl -j -a -n standby`
  (ATA attributes 5/197/198, SCSI grown defects, the NVMe health log, self-test state and the last result). A disk in
  standby is not woken: its last reading is kept. SMART is refreshed hourly, on **Rescan**, and on every run while a
  self-test is running.
- roles: `system` (a mounted file system or swap below the disk, or a member of an array that has one), `data` /
  `metadata` (member of the md array named `nexus-data` / `nexus-metadata`), `in_use` (partitions, a signature found
  by `lsblk` or `wipefs`, LVM, another array, or SMART failing), `empty`.
- `arrays[]`: `/proc/mdstat` (members, action, progress, finish estimate) and `mdadm --detail` (level, state words,
  device counts, name, UUID, used device size, bitmap, member states active / spare / rebuilding / faulty / removed).
  Normalised `state`: clean, degraded, recovering, resyncing, reshaping, failed, inactive; `degraded` separately.
- `store`: the array the store is mounted from, whether it is a mount point, whether it holds files (directories
  only = empty; `None` when it cannot be read).

The parsers are tested against recorded output (`os/greenboot/tests/fixtures/disks/`: lsblk JSON in the key set of
util-linux 2.40/2.41, smartctl 7.4 JSON for an ATA disk with pending sectors, an NVMe, a virtio disk without SMART and
a disk in standby, `/proc/mdstat` with recovery / reshape / DELAYED / inactive arrays, `mdadm --detail` of a degraded
RAID6 rebuilding and two RAID1).

## Rules and alerts

`catalog::hardware` decides, for the web-api (issues, summary) and the scheduler (alerts):

| Condition | Severity | Alert key |
|---|---|---|
| SMART health failed | critical | `disk:<serial>` (one per disk, worst issue decides, issues joined) |
| pending + reallocated + offline-uncorrectable sectors > 0 | warning (critical when the count grew since the last scan: scheduler setting `disk_sector_counts`) | |
| NVMe critical warning ≠ 0, wear (`percentage_used`) ≥ 90 %, media errors > 0 | warning | |
| temperature > 55 °C (HDD) / > 70 °C (SSD, NVMe) | warning | |
| last self-test failed | warning | |
| array failed / inactive, or degraded | critical | `disk:md:<uuid>` |
| rebuild / resync / reshape running | info (progress in the message) | `disk:md:<uuid>:sync` |
| no status for 30 minutes | warning | `disk:monitor` |

The scheduler checks every tick (30 s); a status that asks for an open alert again updates its message in place
(progress) without counting a repeat; severity only rises while open; an alert the status no longer asks for is
resolved (audited `alert.resolve`). Operations the helper finished (`ops.json`: done, refused, error) are audited once
as `hardware.op` (actor `nexus-disks`, with the requester, quorum id, params, outcome; ids kept in the setting
`disk_ops_audited`).

`nexus-diag`'s `smart` check reads the same `status.json` (it never opens a disk).

## Layout operations

| Request | Who | Gate | Helper |
|---|---|---|---|
| `scan` | admin, operator | audited `hardware.scan` | full rescan incl. SMART |
| `selftest {disk, type short\|long}` | admin | audited `hardware.selftest`; SMART must be available | `smartctl -t` |
| `create_array {role: data, level, disks}` | admin | typed serials of all disks, approval `disks.create_array` | below |
| `add_spare {array, disk}` | admin | typed serial, approval `disks.add_spare` | `mdadm --manage --add` (on a degraded array the rebuild starts) |
| `replace {array, disk, failed?}` | admin | typed serial, approval `disks.replace` | faulty member: `--remove` then `--add`; working member: `--add` + `--replace old --with new`; none named: `--remove failed` + `--add` |
| `grow {array, disk}` | admin | typed serial, approval `disks.grow`; raid5/6, clean, mounted | `--add`, bitmap off, `--grow --raid-devices=n+1`; once the reshape has finished (checked from the next run on): bitmap back, `xfs_growfs` (op `growfs`) |

Arrays are addressed by their md UUID in the request (kernel names like `md127` may change across reboots); disks by
serial. The web-api checks the preconditions against the current status (empty disks, size ≥ the array's used device
size, no system arrays, store empty) and the helper checks them again right before it acts (`wipefs` once more). With
approvals disabled the request is written at once (audited `"approvals": "disabled"`); otherwise on approval
(`quorum::execute` marks `disks.*` executed, `hardware::after_approve` writes the request with the quorum id).

### Creating the data array

1. Refuse unless: role `data`, no array named `nexus-data`, the store is not a mount point and holds no files, no
   mount unit exists yet, enough disks for the level (raid1 2, raid5 3, raid6 4, raid10 4 and even), every disk
   `empty` with no `wipefs` signature.
2. `mdadm --create /dev/md/nexus-data --run --name=nexus-data --metadata=1.2 --level=<l> --raid-devices=<n>
   --bitmap=internal <disks>`.
3. `mkfs.xfs -L nexus-data -p <protofile>`: the protofile gives the file system's root directory the store's owner
   and mode (0700 `nexus-chunkstore`), so nothing has to be changed after mounting.
4. `blkid -p` → file-system UUID; stop `nexus-scheduler` and `nexus-replicad` (those that were running); check the
   store is still empty.
5. Write `/etc/systemd/system/var-lib-nexus-chunkstore.mount` (`What=/dev/disk/by-uuid/<uuid>`, XFS,
   `noatime,nodev,nosuid,noexec,context=system_u:object_r:nexus_store_t:s0`, `Before=` and `RequiredBy=` the scheduler
   and replicad so the store never falls back to the root file system), `daemon-reload`, `enable --now`; start the
   stopped services again.

bootc keeps `/etc` across updates and `/var` is never replaced, so the unit and the mount survive OS updates and
rollbacks. Arrays assemble at boot through mdadm's udev rules (no `mdadm.conf` needed); the mount refers to the
file-system UUID, so a changed md device name does not matter.

**Why only an empty store.** Moving an existing store means copying the live chunk files with the services stopped,
verifying, and relabelling — a long offline operation with its own failure modes. The helper's policy does not allow
it to read store files at all. Decision for 16b: create the data array before the first backup; moving a store is not
supported (documented in the manual).

**Metadata tier (follow-up).** The catalog (`/var/lib/nexus/catalog`) on an NVMe mirror would need the same mount
procedure for the live catalog database, which every service has open, and a helper allowed to write it (the policy
forbids that). The API refuses `role: metadata`; NVMe disks are shown and monitored.

## Confinement

`nexus-disks.service`: root, `CapabilityBoundingSet=CAP_SYS_RAWIO CAP_SYS_ADMIN CAP_DAC_READ_SEARCH`,
`ProtectSystem=strict` with `ReadWritePaths=` its control dir, `/etc/systemd/system`, `/run/mdadm` and the store
(xfs_growfs on the mount point), the catalog / keys / credentials inaccessible, `PrivateNetwork=yes`,
`IPAddressDeny=any`, `KillMode=process` (a grow's background process survives). Not `PrivateDevices=` or
`ProtectKernelTunables=` (real disks; mdadm writes `/sys/block/md*/md/*`).

SELinux `nexus_disks_t` (`os/selinux/nexus.te`): all tools run in the domain (`fsadm_exec_t`, `mdadm_exec_t`,
`bin_t`); raw read/write of `fixed_disk_device_t` (block and NVMe character devices), sysfs, udev database,
`/proc/mdstat`, mdadm's map; the store's directories listed (getattr only for files) and the grow ioctl on its mount
point; the mount unit is created as `nexus_unit_file_t` (type transition by name), nothing else in
`/etc/systemd/system`; `systemctl` daemon-reload / start / stop / enable on `nexus_unit_file_t` only. `mount_t` may
relabel the XFS superblock to `nexus_store_t` (the `context=` mount). `neverallow`: inet sockets; reading or writing
keys, catalog, credentials, downloads or store files; the keyd / scheduler / replicad sockets; and nobody but the
helper and the web-api writes its control dir. The neverallow check of the image build passes.

## Lab

`lab/appliance/run.sh` takes `EXTRA_DISKS=N` (virtio disks with serials `NXLAB-D<i>`) and `NVME=N` (QEMU NVMe with
serials `NXLAB-NVME<i>`, whose SMART log smartctl reads). `lab/appliance/disks.sh all` on a freshly set-up appliance:
inventory, NVMe self-test, RAID6 from four disks (typed serials, approval), `mdadm --fail` of a member inside the VM →
critical `disk` alert, replace with the fifth disk (approval) → rebuild, alerts resolved, `hardware.op` audited.
Then `lab/appliance/e2e.sh check` for AVCs.
