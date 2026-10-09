#!/bin/bash
# AlmaLinux 10 (SELinux enforcing): LVM on the data disk with XFS LVs for /srv/xfs,
# /var/lib/mysql (MariaDB with sample data) and /var/backups (hook dumps).
. /var/tmp/nexus-lab/common.sh

say "packages"
dnf -y -q install lvm2 acl attr rsync mariadb-server >/dev/null
say "LVM (thick) with XFS on the data disk"
pvcreate -q "$DATA_DISK"
vgcreate -q vgdata "$DATA_DISK"
lvcreate -q -y -L 1536M -n xfs vgdata
lvcreate -q -y -L 1G -n mysql vgdata
lvcreate -q -y -L 512M -n backups vgdata
for lv in xfs mysql backups; do mkfs.xfs -q -L "$lv" "/dev/vgdata/$lv"; done
lvs
mkdir -p /srv/xfs /var/lib/mysql /var/backups
echo "/dev/mapper/vgdata-xfs /srv/xfs xfs defaults 0 0" >>/etc/fstab
echo "/dev/mapper/vgdata-mysql /var/lib/mysql xfs defaults 0 0" >>/etc/fstab
echo "/dev/mapper/vgdata-backups /var/backups xfs defaults 0 0" >>/etc/fstab
systemctl daemon-reload
mount -a
chown mysql:mysql /var/lib/mysql
chmod 0755 /var/lib/mysql
restorecon -R /srv/xfs /var/lib/mysql /var/backups
say "MariaDB"
systemctl enable --now mariadb >/dev/null 2>&1
mariadb -e "CREATE DATABASE sample; USE sample; CREATE TABLE t (id INT PRIMARY KEY, v CHAR(32)) ENGINE=InnoDB;
	INSERT INTO t SELECT seq, MD5(seq) FROM seq_1_to_200000;"
mariadb -N -e "SELECT COUNT(*) FROM sample.t"
say "sample data"
mkdata /srv/xfs/data
mkdata /home/lab/data
chown -R lab:lab /home/lab/data/docs
getenforce
findmnt -t xfs -o TARGET,SOURCE,FSTYPE
