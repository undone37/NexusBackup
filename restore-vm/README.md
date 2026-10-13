# Restore micro-VM

Single-file restore from VM disk images (plan §8, threat model T10). The disks
of a snapshot are served read-only from the chunk store over NBD and attached
to a small QEMU VM. Its agent mounts the guest file systems read-only and
sends listings and tar streams back over virtio-serial. Foreign file systems
are never mounted by the appliance kernel, only by the VM's kernel.

```
chunk store ── ImageReader ── NBD server (unix socket, per disk, read-only)
                                   │
            qemu-system-x86_64 ── virtio-blk (read-only) ── guest kernel: ext4/xfs/ntfs3/btrfs/vfat/exfat/iso9660, LVM, md, ZFS
                                   │
appliance ── unix socket ── virtio-serial "org.nexusbackup.agent" ── agent (PID 1)
```

## Build

```
restore-vm/build.sh        # no root, no host packages; needs podman, rustup, cargo
```

- The agent (`restore-vm/agent`, a workspace crate) is built as a static
  `x86_64-unknown-linux-musl` binary. The script adds the rustup target if it
  is missing.
- `Containerfile` builds a `debian:trixie` (main + contrib) builder image. It
  contains `linux-image-amd64` and the ZFS module, which `zfs-dkms` builds for
  exactly that kernel. It also contains the userland: kmod, util-linux
  (blkid), lvm2, mdadm, zfsutils-linux and yara (Phase 21e malware scan). The fixture overlay additionally
  gets busybox, sfdisk, e2fsprogs, xfsprogs, ntfs-3g, btrfs-progs and
  dosfstools. Podman caches the layers.
- `mkinitrd.sh` runs in the container with `--network none`. It copies the
  binaries with their shared libraries and the needed modules (dependencies
  resolved by `modprobe --show-depends`, then `depmod`). It writes a sorted
  cpio with fixed mtimes and compresses it with zstd.

Output in `target/restore-vm/`:

| file | size | content |
|---|---|---|
| `vmlinuz` | 12 MB | Debian 13 kernel 6.12.111+deb13-amd64 |
| `initrd.img` | 12 MB | agent as `/init`, modules, lvm/zfs/mdadm/blkid/kmod |
| `fixture-overlay.img` | 8.7 MB | tests only: mkfs tools + `fixture.sh`, appended to `initrd.img` |
| `manifest.txt` | | kernel, ZFS module version, base image digest, package versions, sha256 of all outputs |

Build time: about 3 minutes cold (base image pull, apt, ZFS DKMS compile) and
about 16 s with the cached builder layers. With the same builder image the
outputs are bit-for-bit reproducible (`SOURCE_DATE_EPOCH` = kernel mtime). To
pin the base, pass `BASE=docker.io/library/debian:trixie@sha256:…`. The apt
versions are not pinned (no snapshot.debian.org), but `manifest.txt` records
them.

## Use

```
NEXUS_RESTORE_VM_DIR=target/restore-vm nexus-pve cfg.json files <vmid> <time> mounts
nexus-pve cfg.json files <vmid> <time> ls /vda1/etc
nexus-pve cfg.json files <vmid> <time> get out.zip /vda1/etc/fstab /lvm/vg0-root/home
```

All disk indexes of the snapshot are attached in manifest order (virtio serial
= index name, reported as `disk` by `mounts`). The mountpoints are:

- `/vdXN`: partition or whole-disk file system
- `/lvm/<dm name>`: LVM LVs, activated read-only (`read_only_volume_list`)
- `/zfs/<dataset with / → +>`: every pool is imported with `readonly=on`,
  `cachefile=none` and an altroot, and every dataset is mounted at a fixed
  path. The datasets' own mountpoints are ignored.

Rust API: `pve::restorevm::with_vm(&store, &[(name, &index)…], &cfg, |vm| …)`
with `vm.mounts()`, `vm.ls(path)`, `vm.tar(paths)` (streaming `Read` plus
`finish()`) and `vm.extract(paths, Format::Tar|Zip, file)`. The zip is built
on the appliance from the agent's tar stream (`pve::files::extract`).

## Agent protocol

Each request is one JSON line. Each reply is one JSON line:
`{"ok":…}` or `{"err":"…"}`.

- `{"cmd":"mounts"}` lists every detected file system: device, disk, fstype,
  label, uuid, size, mountpoint, error.
- `{"cmd":"ls","path":"/vda1/etc"}` lists entries with name, kind, size, mode,
  mtime, uid, gid and link. `/` and `/lvm` are virtual directories.
- `{"cmd":"tar","paths":[…]}` replies `{"ok":"tar"}`, then sends
  `[u32 BE len][bytes]` frames of a GNU tar (zero-length frame = end), then
  `{"ok":{"entries":N,"errors":[…]}}`. GNU headers handle long names, binary
  size encoding (files over 8 GiB) and non-UTF-8 names. Unreadable files are
  zero-filled and listed in `errors`, so the archive stays valid.
- `{"cmd":"rules","rules":[{"name","text"}…]}` compiles YARA rules with `yarac`
  (Phase 21e, docs/malware-scan.md; one namespace per file).
- `{"cmd":"scan","limits":{max_size,file_timeout,budget,threads}}` scans every
  mounted file system with `yara --scan-list` (symlinks never followed) and
  replies `{"ok":{files,skipped,errors,matches,matches_total,complete,seconds}}`.
- `{"cmd":"scantar","limits":{…}}` replies `{"ok":"send"}`; the appliance then
  sends `[u32 BE len][bytes]` frames of a tar (zero-length frame = end) of a
  file-tree or container snapshot, and the agent replies with the report.
- `{"cmd":"quit"}` powers off.

## Isolation properties

- **Read-only on every layer.** The NBD server rejects writes (`EPERM`) and
  announces `READ_ONLY`. QEMU attaches the disks with `read-only=on`.
  Journals are never replayed: ext* `noload`, XFS `norecovery`, btrfs
  `rescue=nologreplay`. LVM writes no metadata (`backup=0`, read-only
  activation). ZFS imports with `readonly=on`. All mounts use
  `ro,nosuid,nodev,noexec`.
- **No network.** The VM is started with `-nodefaults -nic none` and has no
  network driver or userland. The only channels are the NBD sockets (QEMU to
  the appliance, read requests only) and the agent port.
- **QEMU sandbox.** `-sandbox on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny`
  (seccomp). `PR_SET_PDEATHSIG` kills QEMU when the appliance process dies.
  `RLIMIT_CORE=0` prevents dumps of guest memory. The sockets and the console
  log live in a private 0700 directory under `$XDG_RUNTIME_DIR` (or the temp
  dir), which is removed afterwards.
- **Resource limits.** Default 1 GiB RAM, 2 vCPUs, KVM when `/dev/kvm` is
  usable, else TCG.
- **Agent input validation.** Requests are at most 8 MiB (YARA rules), strict JSON.
  Paths must be absolute and must not contain `.`, `..` or NUL; they are at
  most 4096 bytes. A path must lie inside a mountpoint. The part below the
  mountpoint is opened with `openat2(RESOLVE_IN_ROOT|RESOLVE_NO_MAGICLINKS)`,
  so symlinks in guest data (`/etc/x -> /`) resolve inside that file system
  and never into the VM. Tree walks never follow symlinks (`lstat`,
  `O_NOFOLLOW`).
- **Appliance-side validation.** Replies are capped at 256 MiB per line and
  16 MiB per frame. The tar stream goes through the `tar` crate and
  `pve::files::extract`, which rejects `..`. A tar stream that is not
  finished marks the session unusable, and QEMU is then killed.
- **Timeouts.** 120 s from start until the agent reports ready, 30 s for QEMU
  to connect the agent port. Every read from the agent has a 300 s idle
  timeout. Shutdown sends `quit`, waits 10 s, then kills QEMU (also on drop
  and on panic).

### Still missing

- QEMU runs as the calling user, in the caller's SELinux domain. The appliance
  should start it under a dedicated user with its own SELinux domain
  (svirt-like, MCS category per session), access to `/dev/kvm` and its socket
  directory only, ideally through a small privileged launcher (see
  `os/README.md`; the appliance image needs `qemu-kvm`).
- There is no seccomp or Landlock filter beyond `-sandbox on`, no cgroup
  limits (CPU, memory, pids, I/O) on the QEMU process and no session time
  limit. A malicious image can keep the VM busy until a timeout fires.
- The guest kernel is the stock Debian kernel with many modules. A guest file
  system exploit owns the VM, and from there only the virtio devices and the
  agent channel are reachable. A QEMU escape is the remaining risk, mitigated
  only by the sandbox above.
- Not covered: encrypted volumes (LUKS, ZFS native encryption, BitLocker),
  Windows dynamic disks/Storage Spaces, thin-provisioned LVs inside guests
  (untested), ZFS zvols inside pools, duplicate pool or VG names across disks.
- `ls` shows non-UTF-8 names lossily. Tar of the parent directory keeps the
  exact bytes.
- The fixture overlay contains mkfs tools. It is a separate file and is never
  passed to production boots.

## Tests

```
restore-vm/build.sh
cargo test --release -p pve --test restore_vm -- --nocapture
```

The test skips when `target/restore-vm` or `/dev/kvm` is missing. On its
first run it boots the micro-VM with the fixture overlay and writable scratch
disks, so no root is needed. It creates:

- disk0 (GPT): ext4 with a 100 MiB + 12345 B file, xfs, ntfs, btrfs, vfat, and
  an LVM PV with VG `vgtest` and ext4 LV `data`
- disk1: ZFS pool `tank` with dataset `tank/data`, also containing the large file

The images are cached in `target/restore-vm-fixtures/`. The test stores them
into a temporary chunk store and runs the real flow (NBD from the store, VM
read-only). It asserts `mounts`, `ls` (unicode names, symlinks, absolute
symlinks staying inside the file system), rejection of bad paths, tar of
single files and directories from several file systems, and the large file as
tar (sha256) and as part of a zip (sha256).

Unit tests: path validation and framing in the agent (`cargo test -p
restorevm-agent`), and tar→zip in `pve::files`.

Measured on the dev box (KVM, release build):

| step | time / rate |
|---|---|
| fixture creation | 8 s |
| ready (`mounts`) | 5.7–6 s, of which `zpool import` takes about 3.2 s |
| `get` of the large file as tar | about 300 MiB/s |
| `get` as zip (deflate) | about 40 MiB/s, limited by deflate |
