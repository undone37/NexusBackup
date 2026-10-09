#!/bin/busybox sh
# Test fixture builder, run by the agent inside the micro-VM when booted with
# the fixture overlay and `nexus.fixture=1` (crates/pve/tests/restore_vm.rs).
# Disks (writable): vda 1100M (GPT: ext4, xfs, ntfs, btrfs, vfat, LVM PV with
# VG vgtest / LV data ext4), vdb 256M (ZFS pool tank, dataset tank/data),
# vdc = seed (the large file payload, `nexus.bigsize` bytes).
set -eu
mkdir -p /bb && /usr/bin/busybox --install -s /bb
export PATH=/usr/sbin:/usr/bin:/bb
big=$(sed -n 's/.*nexus.bigsize=\([0-9]*\).*/\1/p' /proc/cmdline)
cat >/etc/lvm/lvm.conf <<EOF
activation { udev_sync = 0 udev_rules = 0 monitoring = 0 }
devices { obtain_device_list_from_udev = 0 }
global { use_lvmpolld = 0 }
EOF

sfdisk -q /dev/vda <<EOF
label: gpt
size=320M, name=ext4
size=320M, name=xfs
size=64M, name=ntfs
size=128M, name=btrfs
size=32M, name=vfat
name=lvm
EOF
sleep 1
mkfs.ext4 -q -L fx-ext4 /dev/vda1
mkfs.xfs -q -L fx-xfs /dev/vda2
mkntfs -q -f -L fx-ntfs /dev/vda3
mkfs.btrfs -q -L fx-btrfs /dev/vda4
mkfs.vfat -n FXVFAT /dev/vda5 >/dev/null
lvm pvcreate -q /dev/vda6
lvm vgcreate -q vgtest /dev/vda6
lvm lvcreate -q -y -n data -L 100M vgtest
mkfs.ext4 -q -L fx-lvm /dev/vgtest/data
printf "label: gpt\n,\n" | sfdisk -q /dev/vdb
sleep 1
# a partition, not the whole disk: whole-disk labeling waits for udev
zpool create -f -o cachefile=none -O mountpoint=/fx/tank tank /dev/vdb1
zfs create tank/data

# common content: text, unicode names, nested dirs, relative + absolute symlinks
populate() {
	d=$1
	echo "hello from $2" >"$d/hello.txt"
	mkdir -p "$d/dir/sub"
	printf 'unicode content\n' >"$d/dir/sub/ünïcödé ✓.txt"
	head -c 70000 /dev/zero | tr '\0' 'x' >"$d/dir/70k.txt"
	ln -s hello.txt "$d/link-to-hello" 2>/dev/null || true
	ln -s /etc/passwd "$d/abs-link" 2>/dev/null || true
	ln -s / "$d/rootlink" 2>/dev/null || true
}
mnt() {
	mkdir -p "/fx/$1"
	mount -t "$2" ${4:+-o "$4"} "$3" "/fx/$1"
}
mnt ext4 ext4 /dev/vda1
mnt xfs xfs /dev/vda2
mnt ntfs ntfs3 /dev/vda3
mnt btrfs btrfs /dev/vda4
mnt vfat vfat /dev/vda5 iocharset=utf8
mnt lvm ext4 /dev/vgtest/data
for fs in ext4 xfs ntfs btrfs vfat lvm; do populate "/fx/$fs" "$fs"; done
populate /fx/tank/data zfs
echo "pool root" >/fx/tank/root.txt
head -c "$big" /dev/vdc >/fx/ext4/big.bin
head -c "$big" /dev/vdc >/fx/tank/data/big.bin

for fs in ext4 xfs ntfs btrfs vfat lvm; do umount "/fx/$fs"; done
lvm vgchange -q -an vgtest
zpool export tank
sync
echo "FIXTURE OK"
