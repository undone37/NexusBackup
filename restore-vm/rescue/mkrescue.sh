#!/usr/bin/env bash
# Runs inside the builder container (see build.sh): assembles the rescue initramfs
# and the hybrid ISO.
#   /src  restore-vm/rescue/ (read-only)   /out  target/rescue/ (nexus-agent already there)
# Outputs: nexus-rescue-$VERSION.iso, vmlinuz, initrd.img, manifest.txt
set -euo pipefail
trap 'echo "mkrescue.sh: failed at line $LINENO" >&2' ERR
KVER=$(basename /boot/vmlinuz-* | sed 's/^vmlinuz-//')
export SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-$(stat -c %Y /boot/vmlinuz-"$KVER")}
work=$(mktemp -d)
r=$work/root

copy_bin() { # binaries + their shared libraries into $r (merged /usr)
	local bin
	for bin in "$@"; do
		bin=$(command -v "$bin")
		cp -a --parents "$bin" "$r"
		if [[ -L $bin ]]; then cp --parents "$(readlink -f "$bin")" "$r"; fi
		{ ldd "$(readlink -f "$bin")" 2>/dev/null || true; } | { grep -o '/[^ ]*' || true; } | while read -r lib; do
			cp -L --parents -n "$lib" "$r"
		done
	done
}

mkdir -p "$r"/{usr/bin,usr/sbin,usr/lib/x86_64-linux-gnu,usr/lib64,dev,proc,sys,run,tmp,mnt,etc/lvm,root}
ln -s usr/bin "$r/bin"
ln -s usr/sbin "$r/sbin"
ln -s usr/lib "$r/lib"
ln -s usr/lib64 "$r/lib64"
# busybox first (sh, udhcpc, chroot, sleep, …); the real tools below replace its applets
cp /bin/busybox "$r/usr/bin/busybox"
for a in $(/bin/busybox --list); do
	[ -e "$r/usr/bin/$a" ] || ln -s busybox "$r/usr/bin/$a"
done
for t in lsblk blkid wipefs sfdisk sgdisk partx mount umount findmnt chroot sync \
	mkfs.ext4 mke2fs tune2fs e2fsck mkfs.xfs xfs_admin mkfs.btrfs btrfs mkfs.vfat fatlabel mkswap \
	lvm ip modprobe; do
	rm -f "$r/usr/bin/$t" "$r/usr/sbin/$t"
	copy_bin "$t"
done
cp /etc/mke2fs.conf "$r/etc/"
install -m 0755 /out/nexus-agent "$r/usr/sbin/nexus-agent"
install -m 0755 /src/init "$r/init"
install -D -m 0755 /src/udhcpc.script "$r/usr/share/nexus-rescue/udhcpc.script"
# no udev in the rescue system: LVM creates its device nodes itself
cat >"$r/etc/lvm/lvm.conf" <<-'EOF'
	devices { obtain_device_list_from_udev = 0 }
	activation { udev_sync = 0 udev_rules = 0 }
	global { use_lvmetad = 0 thin_check_executable = "" }
EOF
echo nexus-rescue >"$r/etc/hostname"
printf '127.0.0.1 localhost nexus-rescue\n' >"$r/etc/hosts"
printf 'root:x:0:0:root:/root:/bin/sh\n' >"$r/etc/passwd"
printf 'root:x:0:\n' >"$r/etc/group"
# kernel modules: storage, file systems, network, device mapper (no graphics, sound, wireless)
mkdir -p "$r/usr/lib/modules/$KVER"
(cd "/usr/lib/modules/$KVER" && find kernel \( -path 'kernel/drivers/gpu' -o -path 'kernel/sound' \
	-o -path 'kernel/drivers/net/wireless' -o -path 'kernel/drivers/media' -o -path 'kernel/drivers/infiniband' \
	-o -path 'kernel/drivers/staging' -o -path 'kernel/net/bluetooth' -o -path 'kernel/drivers/bluetooth' \
	-o -path 'kernel/drivers/iio' -o -path 'kernel/drivers/hid' -o -path 'kernel/net/wireless' \
	-o -path 'kernel/net/mac80211' \) -prune -o -type f -print |
	cpio -pdm --quiet "$r/usr/lib/modules/$KVER")
cp /usr/lib/modules/"$KVER"/modules.{order,builtin,builtin.modinfo} "$r/usr/lib/modules/$KVER/"
depmod -b "$r" "$KVER"

(cd "$r" && find . -mindepth 1 -print0 | LC_ALL=C sort -z | xargs -0 touch -h -d "@$SOURCE_DATE_EPOCH" &&
	find . -mindepth 1 | LC_ALL=C sort | cpio -o -H newc -R 0:0 --reproducible --quiet) | zstd -q -19 -T0 >/out/initrd.img
cp /boot/vmlinuz-"$KVER" /out/vmlinuz

iso=$work/iso
mkdir -p "$iso/boot/grub"
cp /out/vmlinuz /out/initrd.img "$iso/boot/"
cat >"$iso/boot/grub/grub.cfg" <<-EOF
	set timeout=5
	insmod all_video
	serial --unit=0 --speed=115200
	terminal_input console serial
	terminal_output console serial
	menuentry "NexusBackup bare-metal recovery $VERSION" {
	  linux /boot/vmlinuz console=ttyS0,115200 console=tty0 loglevel=4
	  initrd /boot/initrd.img
	}
	menuentry "NexusBackup bare-metal recovery $VERSION (serial console)" {
	  linux /boot/vmlinuz console=tty0 console=ttyS0,115200 loglevel=4
	  initrd /boot/initrd.img
	}
EOF
grub-mkrescue -o "/out/nexus-rescue-$VERSION.iso" "$iso" -- -volid NEXUS_RESCUE 2>/dev/null
{
	echo "nexus-rescue $VERSION"
	echo "kernel $KVER"
	echo "built $(date -u -d "@$SOURCE_DATE_EPOCH" +%FT%TZ) (SOURCE_DATE_EPOCH)"
	echo "base-image ${BASE_DIGEST:-unknown}"
	echo "packages:"
	dpkg-query -W -f '  ${Package} ${Version}\n' linux-image-"$KVER" util-linux fdisk gdisk lvm2 e2fsprogs \
		xfsprogs btrfs-progs dosfstools busybox-static iproute2 grub-pc-bin grub-efi-amd64-bin
	echo "sha256:"
	(cd /out && sha256sum "nexus-rescue-$VERSION.iso" vmlinuz initrd.img nexus-agent | sed 's/^/  /')
} >/out/manifest.txt
rm -rf "$work"
