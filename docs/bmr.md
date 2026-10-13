# Bare-metal recovery and P2V of Linux hosts (Phase 19a)

A Linux host backed up by `nexus-agent` can be rebuilt on empty disks: on the same machine after a disk loss,
on new hardware, or as a new Proxmox VE VM ("Restore as PVE VM", P2V). The pieces:

| piece | where |
|---|---|
| machine layout, recorded with every backup | `crates/agent-linux/src/layout.rs`, `GetLayout` (protocol v1.5) |
| layout file in the host snapshot | `.nexus-system/layout.json` (`crates/agent-conn/src/backup.rs`) |
| rescue ISO `nexus-rescue-<version>.iso` | `restore-vm/rescue/` (build.sh, mkrescue.sh, init) |
| rescue agent (console, check-in, recreate, finish) | `crates/agent-linux/src/rescue/` (`nexus-agent rescue`) |
| recovery driver on the appliance | `crates/agent-conn/src/rescue.rs`, `nexus-agentctl … rescue` |
| sessions, recovery tokens, check-in, P2V | `crates/web-api/src/rescue.rs`, catalog v29 `rescue_sessions` |
| `bmr` / `p2v` jobs, firewall | `crates/scheduler/src/bmr.rs` |
| PVE VM + config disk | `crates/pve/src/p2v.rs` (`nexus-pve … p2v`, `p2v-cleanup`) |

## Layout

At the start of every backup the appliance asks agents with the capability `layout` for the machine layout
(`GetLayout` → `Layout { json }`, at most 1 MiB) and stores it as `.nexus-system/layout.json` (mode 0600, root) in
the `host-<agent>` tree snapshot. The backup does not depend on it: a layout that cannot be produced or parsed is
logged ("layout note", "no machine layout") and left out. The file is visible in the file browser and can be
downloaded like any other file.

The agent builds it from `lsblk -J -b`, `sfdisk -J <disk>`, `lvm pvs|vgs|lvs --reportformat json --units b`,
`findmnt -J`, `blkid -o export`, `/proc/swaps`, `ip -j addr`, `/etc/os-release`, `/proc/cmdline`, `/etc/fstab` and
`/sys/firmware/efi`. Numbers given as strings by older util-linux / LVM are accepted. It records:

- **disks** holding a mounted block-device file system or a swap area (removable disks are noted, loop, zram and
  optical devices skipped): size, logical sector size, model, partition table (`gpt`/`dos`), disk id, partitions
  with start, size, type, GUID, name, bootable flag and attributes;
- **LVM**: the VGs on those disks with extent size, PVs (device, UUID) and LVs (size, segment type, thin pool and
  its metadata size, `/dev/mapper` path). Hidden LVs and the agent's own `nexus-snap-*` snapshots are skipped;
- **md RAID** and **LUKS** (detected only, see Limitations);
- **file systems**: device, type, version (FAT12/16/32), UUID, label, mounts (mount point, options — btrfs
  `subvol=`). Mounts below `/run/nexus-agent` (the agent's snapshot mounts) are skipped;
- swap partitions / LVs, firmware (`uefi`/`bios`), boot loader (`grub2`, `systemd-boot`), kernel command line,
  host name, OS (`PRETTY_NAME`, `ID`, `ID_LIKE`), network interfaces with addresses, the raw `/etc/fstab`, and
  warnings for what could not be recorded.

For bare-metal recovery the backup must cover the whole system: the paths `/` with "include nested mounts"
(cross_mounts) or every local file system, including `/boot` and the EFI system partition. What was not backed
up is recreated empty.

## Recovery token and session

Agents → *Bare-metal recovery* → *Issue recovery token* (admin or operator): a rescue session with a one-time
token (128 bit, base32, valid 4 h, shown once). The catalog keeps the token's **digest sealed to the scheduler**
(like enrollment tokens) and its public **lookup key** `sha256("nexus-rescue-lookup\0" ‖ sha256(token))`. A new
token cancels the agent's sessions that have not started. States: `issued` → `waiting` (console checked in) →
`running` → `done` | `failed`; `cancelled`, `expired` (token lifetime over before the start).

## Recovery steps

1. Boot the machine from `nexus-rescue-<version>.iso` (USB stick or virtual CD; BIOS and UEFI; for UEFI systems
   boot the ISO in UEFI mode so the boot entry can be written).
2. Console: network (DHCP, static or "none"), appliance address (`host[:port]`, HTTPS port of the web UI), the
   recovery token, then the **target disks**, one per disk of the original machine in its order (the web UI shows
   them), confirmed by typing their names again. Nothing is written yet.
3. The rescue agent starts its listener (port 7444) in enrollment mode with the token and **checks in**:
   `POST /api/v1/rescue/checkin {lookup, host, port, disks, version}` — the address the appliance should connect
   to (its own address towards the appliance, or `advertise` from the config disk for NAT / port forwarding) and
   the disks with sizes. The check-in repeats every 15 s until the appliance has enrolled the agent.
4. Web UI: the session shows the address and the disks; pick the snapshot and *Start recovery* → job `bmr`. The
   scheduler opens the firewall for the rescue address (`rescue_targets`), and `nexus-agentctl rescue`
   - checks that the snapshot has a layout (before spending the token),
   - enrolls the rescue agent like an agent (token proofs bound to the TLS session, a certificate from the
     appliance CA for the session id; `rescue-enrolled` pins it, the token is void from then on),
   - `RescueApply { layout }`: the rescue agent maps the original disks in order onto the confirmed target disks
     (each at least as large, same sector size, else refused), releases and wipes the targets, recreates the
     partition tables (`sfdisk`, same start/size/type/GUID/name; extra space stays unallocated), the LVM PVs (same
     UUID), VGs and LVs (thin pools with their metadata size first, then linear volumes, then thin volumes), file
     systems and swap **with their original UUIDs and labels** (`mkfs.ext4 -U`, `mkfs.xfs -m uuid=`,
     `mkfs.btrfs -U` plus the btrfs subvolumes of the mounts, `mkfs.vfat -i`, `mkswap -U`) and mounts them below
     `/mnt/nexus-target`,
   - restores the whole snapshot there with the full metadata of the original host (owners, modes, setuid bits,
     devices, ACLs, SELinux labels; overwrite always),
   - `RescueFinish`: removes `.nexus-system`, recreates `/dev`, `/proc`, `/sys`, `/run`, `/tmp`, replaces UUIDs in
     `/etc/fstab`, `/etc/crypttab` and `/etc/default/grub` if a file system could not keep its UUID, warns about
     fstab entries by hardware id, then in a chroot of the restored system: the initramfs
     (`update-initramfs -u -k all`, `dracut -f --regenerate-all` or `mkinitcpio -P`) and the boot loader —
     `grub-install` (BIOS: onto the boot disk; UEFI Debian family: with the NVRAM entry and the removable fallback
     `EFI/BOOT/BOOTX64.EFI`), RHEL family UEFI: `efibootmgr` entry for the restored shim/grub plus the fallback
     copy, `bootctl install` for systemd-boot — then `update-grub` / `grub2-mkconfig`. SELinux systems get
     `/.autorelabel` (the first boot relabels and reboots once). Everything is unmounted and synced,
   - reboots the machine into the restored system (unless "reboot when done" was off).
5. The session ends `done`; the job log has every command the rescue agent ran (`rescue: "$ …"`).

## Restore as PVE VM (P2V)

Agents → *Bare-metal recovery* → *Restore as PVE VM*: snapshot, a PVE source of the tenant, node, storage, the
rescue ISO volume (upload `nexus-rescue-<version>.iso` to an ISO storage once), bridge, memory, cores. A session
with the snapshot preselected and the job `p2v`:

1. `nexus-agentctl … layout` reads the layout from the snapshot;
2. `nexus-pve … p2v` uploads a config disk (ISO 9660, label `NEXUSCFG`, `rescue.json` with the appliance address,
   the recovery token — unsealed only into the job's 0600 files — DHCP, `disks: ["auto"]`, `confirm: true`) to the
   ISO storage, creates the VM (q35, virtio-scsi, one disk per original disk rounded up to GiB, OVMF + EFI disk
   without pre-enrolled keys if the original booted UEFI, the rescue ISO on `ide2`, the config disk on `ide3`, boot
   order `scsi0;ide2`) and starts it;
3. the rescue system finds the config disk, configures the network, takes every non-removable disk in name order
   and checks in — the appliance starts the `bmr` job at once (no human in the loop, the snapshot was chosen
   with the VM);
4. after the recovery `nexus-pve … p2v-cleanup` detaches and deletes the config disk; the VM reboots from its
   restored disk (the empty disk fell through to the CD before).

The appliance address defaults to the address the browser used; set it explicitly if the VM network reaches the
appliance under another name. Optionally pin the web certificate (`appliance_sha256`).

## Security

- **The recovery token is the right to receive the host's complete file system.** It is short-lived (4 h),
  one-time (void after enrollment, after a new token, on cancel or expiry), shown once, and only its sealed digest
  and a lookup hash are stored. Issuing, check-ins (also rejected ones), starts, cancels and P2V requests are
  audited; issuing needs admin or operator, in the tenant scope of the user. Vault mode refuses recoveries.
- **The check-in is a hint, not an authentication.** It runs over HTTPS without certificate verification unless a
  fingerprint is pinned, and carries only the lookup key, never the token. A forged or replayed check-in can at
  most point the appliance at another address: the enrollment then fails, because only the holder of the token
  can produce the agent-side proof bound to that TLS session (docs/agent-protocol.md "Enrollment"). Unknown lookup
  keys count against the client IP (login rate limiter: 5 in 15 min → 15 min lockout).
- **The appliance initiates every recovery connection** (pull model): the rescue address is added to the outbound
  allow-list only while its session is `waiting` or `running`.
- **P2V puts the plaintext token on PVE storage** (the config disk) for the few minutes until the VM checks in;
  PVE administrators can read it — they can read the restored VM disk anyway. The disk is deleted after the
  recovery; the token is spent at enrollment either way. A P2V session starts unattended at the check-in, so the
  first enrollment with the token wins: keep the ISO storage private.
- **Destructive only for the target**: the console operator confirms the disks by typing their names (P2V: the new
  VM's empty disks). The rescue agent takes no backups, restores only into `/mnt/nexus-target` and only after
  `RescueApply`, refuses updates, and keeps all state in RAM.

## Limitations

- Not recreated (the plan is refused with a clear message): file systems or LVM PVs on **LUKS** or **md RAID**,
  **ZFS** (root or data pools), file system types without a known mkfs (ext2/3/4, xfs, btrfs, vfat, swap are
  supported). Recover such hosts by installing a minimal system by hand and restoring files with "Restore files to
  a host".
- Target disks must be the same size or larger with the same logical sector size; the extra space stays
  unallocated (grow partitions / PVs afterwards). Fewer, smaller or differently ordered disks are not mapped.
- LVM: striped, mirrored, RAID and cache LVs are recreated as linear volumes; LVM snapshots are not recreated;
  the VG UUID changes (names and LV device paths stay).
- btrfs: only the subvolumes named in mounts are recreated; snapper / default-subvolume setups need manual work.
- Secure Boot: the rescue ISO is not signed; boot it with Secure Boot off (the restored system keeps its signed
  shim).
- Windows bare-metal recovery is out of scope (Phase 23).

## Tests

- `crates/agent-linux/src/layout.rs`: parsers with fixtures (`tests/fixtures/layout/deb-lvm`: GPT, ESP, LVM thin
  pool, whole-disk PV, snapshot LV and mount skipped, removable disk; `fedora-btrfs`: util-linux 2.32 string
  numbers, dos label, btrfs subvolumes, LUKS, md RAID1);
- `crates/agent-linux/src/rescue/plan.rs`: layout → commands (sfdisk scripts, LVM order and sizes, mkfs with UUIDs,
  mounts), refusals (too few / smaller disks, sector size, LUKS, no root), btrfs subvolumes, NVMe names;
- `crates/agent-linux/tests/rescue.rs`: backup with layout through the real agent, refusal on a non-rescue agent,
  enrollment of a rescue agent with the recovery token (not with the host's token), the full message sequence;
- `crates/web-api/tests/rescue.rs`, `crates/scheduler/src/tests/bmr.rs`, `crates/pve/src/p2v.rs` (VM parameters,
  config ISO cross-checked with xorriso);
- `lab/linux/bmr.sh`: the end-to-end QEMU lab (below).

## Lab

`lab/linux/bmr.sh` (QEMU/KVM, no root): backs up the `deb-lvm` lab VM through the dev control plane
(`lab/linux/e2e.sh`), boots a blank VM with two empty disks from the rescue ISO plus a config disk (built with
xorriso; `advertise` = the host-forwarded agent port), lets the recovery run unattended, boots the restored VM and
compares the host name and a sha256 sample of files. See the script header.

Result 2026-10-13 (dev box, KVM, under heavy load): `deb-lvm` (Debian 13 cloud image, BIOS; root on a linear LV of a
whole-disk PV, a thin pool with an XFS thin volume, PostgreSQL LV, ESP + BIOS boot partition on `vda`) — rescue
check-in 17 s after boot, recovery (recreate + 1.7 GB restore + initramfs + grub) 63 s, first boot of the restored
system 13 s, host name equal, sha256 of 2724 files (`/etc` without `/etc/lvm`, `/usr/bin`, `/usr/lib/modules`, the
lab data incl. names with spaces and newlines) equal, all LVs and mounts present, PostgreSQL answers. Found and fixed
on the way:

- the agent unit's `ProtectKernelModules=yes` hid `/usr/lib/modules` from the agent: **every backup lacked the kernel
  modules** and a recovered system could not mount its root (removed; module loading stays blocked by the missing
  `CAP_SYS_MODULE` and the `@module` syscall filter);
- `update-initramfs` / `dracut` in the chroot built a host-only image for the rescue system's tmpfs root (no disk or
  device-mapper drivers): now generic (`MODULES=most` for that run, `dracut --no-hostonly`, `mkinitcpio -S autodetect`);
- LVM's devices file (`/etc/lvm/devices/system.devices`) names PVs by hardware id: re-created for the new disks
  (`vgimportdevices -a`) or removed;
- thin pools are created without `-Wy` (unsupported for thin pools); the rescue's LVM skips `thin_check` for the fresh
  pools.

UEFI boot of the rescue ISO, network, config disk and disk detection were checked separately (OVMF); a UEFI source
machine and a real PVE cluster (P2V) are still to be run by the lead.
