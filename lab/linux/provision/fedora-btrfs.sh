#!/bin/bash
# Fedora 44 Cloud (SELinux enforcing): btrfs root with the subvolumes root (/), home
# (/home) and var (/var) as shipped. /srv/btrfs is a *nested* subvolume of the root
# subvolume (not a mount point): a snapshot of / does not contain it.
. /var/tmp/nexus-lab/common.sh

say "packages"
dnf -y -q install acl attr >/dev/null
say "subvolumes"
btrfs subvolume create /srv/btrfs
btrfs subvolume list /
say "sample data"
mkdata /srv/btrfs/data
mkdata /home/lab/data
chown -R lab:lab /home/lab/data/docs
getenforce
findmnt -t btrfs -o TARGET,SOURCE,FSTYPE,OPTIONS
