#!/usr/bin/env bash
# Provisions the NAS lab VM (root, idempotent; lab/nas/vm.sh provision):
# kernel with nfsd/cifs modules, nfs-kernel-server + Samba, LVM data disk
# (VG nas: LV share 10G ext4 -> /srv/share, LV many 12G ext4 -> /srv/many, LV store
# 7G ext4 -> /var/lib/nexus-lab for the dev control plane (lab/nas/devcp.sh),
# the rest free for LVM snapshots used as NAS snapshots).
# env: SMB_PASSWORD (Samba password of nexusbackup)
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
say() { printf '== %s\n' "$*"; }
DISK=/dev/disk/by-id/virtio-nexus-data

# the cloud kernel (linux-image-cloud-amd64) lacks fs modules like cifs/nfsd
if ! modinfo nfsd >/dev/null 2>&1 || ! modinfo cifs >/dev/null 2>&1; then
	say "installing linux-image-amd64 (cloud kernel lacks nfsd/cifs)"
	apt-get update -q
	apt-get install -y -q linux-image-amd64 >/dev/null
	apt-get purge -y -q 'linux-image-*cloud*' >/dev/null 2>&1 || true
	touch /run/nexus-lab-reboot
	exit 0
fi

say "packages"
apt-get update -q >/dev/null
apt-get install -y -q --no-install-recommends nfs-kernel-server samba acl attr lvm2 python3 jq curl rsync \
	cifs-utils nfs-common e2fsprogs >/dev/null

say "LVM data disk"
if ! vgs nas >/dev/null 2>&1; then
	pvcreate -q "$DISK"
	vgcreate -q nas "$DISK"
fi
lvs nas/share >/dev/null 2>&1 || { lvcreate -q -y -L 10G -n share nas; mkfs.ext4 -q -i 4096 /dev/nas/share; }
lvs nas/many >/dev/null 2>&1 || { lvcreate -q -y -L 12G -n many nas; mkfs.ext4 -q -i 2048 /dev/nas/many; }
mkdir -p /srv/share /srv/many
grep -q '/srv/share ' /etc/fstab || echo '/dev/nas/share /srv/share ext4 defaults 0 2' >>/etc/fstab
grep -q '/srv/many ' /etc/fstab || echo '/dev/nas/many /srv/many ext4 defaults 0 2' >>/etc/fstab
# the dev control plane's state + chunk store (one chunk file per small file:
# a million files need a million inodes; the root fs has about one million in total)
lvs nas/store >/dev/null 2>&1 || { lvcreate -q -y -L 7G -n store nas; mkfs.ext4 -q -i 2048 /dev/nas/store; }
mkdir -p /var/lib/nexus-lab
grep -q '/var/lib/nexus-lab ' /etc/fstab || echo '/dev/nas/store /var/lib/nexus-lab ext4 defaults 0 2' >>/etc/fstab
systemctl daemon-reload
mountpoint -q /srv/share || mount /srv/share
mountpoint -q /srv/many || mount /srv/many
mountpoint -q /var/lib/nexus-lab || mount /var/lib/nexus-lab
chown lab: /var/lib/nexus-lab

say "NFS (v3 + v4.x, mountd on 20048)"
cat >/etc/nfs.conf.d/nexus-lab.conf <<-'EOF'
	[mountd]
	port=20048
	[nfsd]
	vers3=y
	vers4.0=y
	vers4.1=y
	vers4.2=y
EOF
# The appliance connector runs unprivileged: the read-only exports map every
# request to root so it can read all files; `insecure` because QEMU user
# networking NATs the client's source ports above 1023. Explicit fsids: LVM
# snapshots of the share carry the same ext4 UUID, and with uuid-derived fsids
# mountd may resolve the share's file handles to a mounted snapshot.
cat >/etc/exports <<-'EOF'
	/srv/share *(ro,crossmnt,all_squash,anonuid=0,anongid=0,insecure,no_subtree_check,fsid=101)
	/srv/many *(ro,all_squash,anonuid=0,anongid=0,insecure,no_subtree_check,fsid=102)
EOF
systemctl enable -q nfs-server
systemctl restart nfs-server
exportfs -ra

say "Samba"
id nexusbackup >/dev/null 2>&1 || useradd -M -s /usr/sbin/nologin nexusbackup
cat >/etc/samba/smb.conf <<-'EOF'
	[global]
	   workgroup = NEXUSLAB
	   server role = standalone server
	   server min protocol = SMB2_10
	   server signing = mandatory
	   server smb encrypt = desired
	   vfs objects = acl_xattr
	   map to guest = never
	   load printers = no
	   disable spoolss = yes
	   log level = 1

	[share]
	   path = /srv/share
	   read only = yes
	   browseable = no
	   valid users = nexusbackup
	   admin users = nexusbackup

	[many]
	   path = /srv/many
	   read only = yes
	   browseable = no
	   valid users = nexusbackup
	   admin users = nexusbackup
EOF
testparm -s >/dev/null 2>&1
if [ -n "${SMB_PASSWORD:-}" ]; then
	printf '%s\n%s\n' "$SMB_PASSWORD" "$SMB_PASSWORD" | smbpasswd -s -a nexusbackup >/dev/null
fi
systemctl enable -q smbd
systemctl restart smbd
systemctl disable -q --now nmbd 2>/dev/null || true

install -d -m 0755 /var/tmp/nexus-lab
say "done: $(uname -r); exports: $(exportfs -s | tr '\n' ' ')"
