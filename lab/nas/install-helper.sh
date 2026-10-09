#!/usr/bin/env bash
# Runs as root inside the NAS lab VM (the dev control plane lives there, see
# devcp.sh): installs nexus-nasmount with the real systemd units from
# os/systemd (socket-activated, CAP_SYS_ADMIN only), serving the dev user.
#   install-helper.sh <dir with nexus-nasmount + units> <dev user>
set -euo pipefail
src=$1
user=$2
install -d -m 0755 /usr/libexec/nexus
install -m 0755 "$src/nexus-nasmount" /usr/libexec/nexus/nexus-nasmount
install -m 0644 "$src/nexus-nasmount.socket" "$src/nexus-nasmount@.service" /etc/systemd/system/
getent group nexus-chunkstore >/dev/null || groupadd -r nexus-chunkstore
usermod -a -G nexus-chunkstore "$user"
# lab only: the dev user instead of nexus-chunkstore
install -d /etc/systemd/system/nexus-nasmount@.service.d
printf '[Service]\nEnvironment=NEXUS_NASMOUNT_ALLOW_USER=%s\n' "$user" >/etc/systemd/system/nexus-nasmount@.service.d/lab.conf
systemctl daemon-reload
systemctl enable nexus-nasmount.socket
systemctl restart nexus-nasmount.socket
systemctl --no-pager status nexus-nasmount.socket | head -5
ls -l /run/nexus-nasmount/
