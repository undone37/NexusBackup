#!/usr/bin/env bash
# Runs inside the builder container (see build.sh): assembles the restore
# micro-VM initramfs from the container's Debian packages.
#   /src  restore-vm/ (read-only)    /out  target/restore-vm/ (agent already there)
# Outputs: vmlinuz, initrd.img (agent as /init), fixture-overlay.img (mkfs tools
# + fixture.sh, tests only; appended to initrd.img), manifest.txt.
set -euo pipefail
trap 'echo "mkinitrd.sh: failed at line $LINENO" >&2' ERR
KVER=$(basename /boot/vmlinuz-* | sed 's/^vmlinuz-//')
export SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-$(stat -c %Y /boot/vmlinuz-"$KVER")}
work=$(mktemp -d)

# modules (with dependencies) for disks, file systems, device mapper, md, ZFS
MODS="virtio_blk ext4 xfs btrfs ntfs3 vfat exfat isofs nls_cp437 nls_utf8
	dm_mod dm_snapshot dm_thin_pool dm_mirror raid1 raid10 raid456 zfs"

# copy a binary and its shared libraries into the tree $1 (merged /usr layout)
copy_bin() {
	local root=$1 bin
	shift
	for bin in "$@"; do
		bin=$(command -v "$bin")
		cp -a --parents "$bin" "$root"
		if [[ -L $bin ]]; then cp --parents "$(readlink -f "$bin")" "$root"; fi
		{ ldd "$(readlink -f "$bin")" 2>/dev/null || true; } | { grep -o '/[^ ]*' || true; } | while read -r lib; do
			cp -L --parents -n "$lib" "$root"
		done
	done
}

skeleton() {
	mkdir -p "$1"/{usr/bin,usr/sbin,usr/lib/x86_64-linux-gnu,usr/lib64,dev,proc,sys,run,tmp,mnt,etc}
	ln -s usr/bin "$1/bin"
	ln -s usr/sbin "$1/sbin"
	ln -s usr/lib "$1/lib"
	ln -s usr/lib64 "$1/lib64"
}

# deterministic cpio: sorted names, fixed mtime, root owner
pack() {
	(cd "$1" && find . -mindepth 1 -print0 | LC_ALL=C sort -z |
		xargs -0 touch -h -d "@$SOURCE_DATE_EPOCH" &&
		find . -mindepth 1 | LC_ALL=C sort |
		cpio -o -H newc -R 0:0 --reproducible --quiet) | zstd -q -19 -T0 >"$2"
}

# --- main image ---
r=$work/root
skeleton "$r"
install -m 0755 /out/agent "$r/init"
copy_bin "$r" modprobe blkid lvm zpool zfs mdadm
mkdir -p "$r/etc/lvm" "$r/lib/modules/$KVER"
touch "$r/etc/lvm/lvm.conf"
echo "nexus-restore-vm" >"$r/etc/hostname"
for m in $MODS; do
	modprobe -S "$KVER" --show-depends "$m" | awk '$1 == "insmod" {print $2}'
done | sort -u | while read -r ko; do
	cp --parents "$ko" "$r"
done
cp /lib/modules/"$KVER"/modules.{order,builtin,builtin.modinfo} "$r/lib/modules/$KVER/"
depmod -b "$r" "$KVER"
pack "$r" /out/initrd.img
cp /boot/vmlinuz-"$KVER" /out/vmlinuz

# --- fixture overlay (tests only: create file systems on writable disks) ---
f=$work/fixture
skeleton "$f"
copy_bin "$f" busybox sfdisk mkfs.ext4 mkfs.xfs mkntfs mkfs.btrfs mkfs.vfat lvm zpool zfs blkid
install -m 0755 /src/fixture.sh "$f/fixture.sh"
pack "$f" /out/fixture-overlay.img

# --- manifest ---
{
	echo "kernel $KVER"
	echo "built $(date -u -d "@$SOURCE_DATE_EPOCH" +%FT%TZ) (SOURCE_DATE_EPOCH)"
	echo "base-image ${BASE_DIGEST:-unknown}"
	modinfo -k "$KVER" -F version zfs | sed 's/^/zfs-module /'
	echo "modules: $MODS"
	echo "packages:"
	dpkg-query -W -f '  ${Package} ${Version}\n' linux-image-"$KVER" zfs-dkms zfsutils-linux lvm2 mdadm \
		util-linux kmod libc6 busybox-static e2fsprogs xfsprogs ntfs-3g btrfs-progs dosfstools fdisk
	echo "sha256:"
	(cd /out && sha256sum vmlinuz initrd.img fixture-overlay.img agent | sed 's/^/  /')
} >/out/manifest.txt
rm -rf "$work"
