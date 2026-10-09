#!/bin/bash
# Ubuntu 24.04: zfsutils-linux (the kernel ships the module), pool `tank` on the data
# disk with POSIX ACLs and SA xattrs; datasets tank/data (/srv/zfs) and tank/home (/home).
. /var/tmp/nexus-lab/common.sh

say "packages"
apt-get update -q >/dev/null
apt-get install -y -q zfsutils-linux acl attr libcap2-bin >/dev/null
modprobe zfs
say "pool tank"
zpool create -f -o ashift=12 -O acltype=posixacl -O xattr=sa -O compression=lz4 -O mountpoint=none tank "$DATA_DISK"
zfs create -o mountpoint=/srv/zfs tank/data
# /home onto ZFS: copy, then mount the dataset over it
zfs create -o mountpoint=/mnt/newhome tank/home
cp -a /home/. /mnt/newhome/
zfs set mountpoint=/home tank/home
zfs list -o name,mountpoint,used
say "sample data"
mkdata /srv/zfs/data
mkdata /home/lab/data
chown -R lab:lab /home/lab/data/docs
findmnt -t zfs -o TARGET,SOURCE,FSTYPE
