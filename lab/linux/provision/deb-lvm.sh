#!/bin/bash
# Debian 13: root moved onto LVM (thick LV, ext4), PostgreSQL on its own thick LV
# (ext4), an XFS LV in a thin pool. The original root partition stays mounted at
# /srv/plain (ext4 without LVM). Phase 1 copies root and asks for a reboot.
. /var/tmp/nexus-lab/common.sh

if [ "${1:-}" != after-reboot ]; then
	say "packages"
	apt-get update -q
	apt-get install -y -q lvm2 thin-provisioning-tools xfsprogs rsync acl attr libcap2-bin >/dev/null
	say "LVM on the data disk"
	pvcreate -q "$DATA_DISK"
	vgcreate -q vgdata "$DATA_DISK"
	lvcreate -q -y -L 3G -n root vgdata
	lvcreate -q -y -L 768M -n pg vgdata
	lvcreate -q -y -L 2G -T vgdata/pool
	lvcreate -q -y -V 1536M -T vgdata/pool -n xfs
	mkfs.ext4 -q -L root /dev/vgdata/root
	mkfs.ext4 -q -L pg /dev/vgdata/pg
	mkfs.xfs -q -L xfs /dev/vgdata/xfs
	vgs
	lvs
	say "copy root onto vgdata/root"
	update-initramfs -u >/dev/null # lvm2 hook: activate the root LV at boot
	install -d /mnt/newroot
	mount /dev/vgdata/root /mnt/newroot
	rsync -aHAXx --numeric-ids / /mnt/newroot/
	oldroot=$(findmnt -no SOURCE /)
	olduuid=$(blkid -s UUID -o value "$oldroot")
	sed -i -E 's@^[^#[:space:]]+[[:space:]]+/[[:space:]].*@/dev/mapper/vgdata-root / ext4 rw,errors=remount-ro 0 1@' /mnt/newroot/etc/fstab
	echo "UUID=$olduuid /srv/plain ext4 defaults 0 2" >>/mnt/newroot/etc/fstab
	mkdir -p /mnt/newroot/srv/plain
	cat /mnt/newroot/etc/fstab
	umount /mnt/newroot
	# grub (BIOS, on the first disk) keeps loading kernel + initrd from the old
	# partition; only the kernel's root changes
	sed -i -E 's@root=(PARTUUID|UUID)=[^ ]+@root=/dev/mapper/vgdata-root@g' /boot/grub/grub.cfg
	grep -m2 'root=' /boot/grub/grub.cfg
	touch /run/nexus-lab-reboot
	exit 0
fi

say "after reboot: $(findmnt -no SOURCE,FSTYPE /)"
[ "$(findmnt -no SOURCE /)" = /dev/mapper/vgdata-root ] || {
	echo "root is not on LVM"
	exit 1
}
say "PostgreSQL on vgdata/pg"
move_onto /var/lib/postgresql /dev/mapper/vgdata-pg ext4
apt-get install -y -q postgresql >/dev/null
systemctl enable --now postgresql >/dev/null 2>&1
su - postgres -c "createdb sample"
su - postgres -c "psql -q -d sample -c \"CREATE TABLE t AS SELECT g AS id, md5(g::text) AS v FROM generate_series(1, 200000) g\""
su - postgres -c "psql -At -d sample -c 'SELECT count(*) FROM t'"
say "XFS (thin LV) on /srv/xfs"
mkdir -p /srv/xfs
echo "/dev/mapper/vgdata-xfs /srv/xfs xfs defaults 0 2" >>/etc/fstab
systemctl daemon-reload
mount /srv/xfs
say "sample data"
mkdata /srv/xfs/data
mkdata /home/lab/data
chown -R lab:lab /home/lab/data/docs
findmnt -t ext4,xfs -o TARGET,SOURCE,FSTYPE
df -h / /srv/xfs /var/lib/postgresql /srv/plain
