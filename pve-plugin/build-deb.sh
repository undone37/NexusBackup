#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
#
# Build nexusbackup-pve_<version>_all.deb (PVE node side of NexusBackup).
# Usage: pve-plugin/build-deb.sh [version]     (default 0.1.0)
# Output: target/deb/nexusbackup-pve_<version>_all.deb
set -eu
umask 022

VERSION="${1:-0.1.0}"
SRC="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$SRC/.." && pwd)"
OUT="$ROOT/target/deb"
STAGE="$ROOT/target/deb/stage-nexusbackup-pve"

case "$VERSION" in
    [0-9]*) ;;
    *) echo "invalid version '$VERSION'" >&2; exit 1 ;;
esac

rm -rf "$STAGE"
mkdir -p "$OUT" "$STAGE/DEBIAN"

install -D -m 0644 "$SRC/PVE/Storage/Custom/NexusBackupPlugin.pm" \
    "$STAGE/usr/share/perl5/PVE/Storage/Custom/NexusBackupPlugin.pm"
install -D -m 0644 "$SRC/PVE/BackupProvider/Plugin/NexusBackup.pm" \
    "$STAGE/usr/share/perl5/PVE/BackupProvider/Plugin/NexusBackup.pm"
install -D -m 0755 "$SRC/helper" "$STAGE/usr/lib/nexusbackup/helper"
install -D -m 0755 "$SRC/rollback" "$STAGE/usr/lib/nexusbackup/rollback"
install -D -m 0644 "$ROOT/LICENSE" "$STAGE/usr/share/doc/nexusbackup-pve/copyright"
install -D -m 0644 "$ROOT/docs/pve-connector.md" "$STAGE/usr/share/doc/nexusbackup-pve/pve-connector.md"

mkdir -p "$STAGE/usr/lib/tmpfiles.d"
cat > "$STAGE/usr/lib/tmpfiles.d/nexusbackup-pve.conf" <<'EOF'
# NexusBackup rendezvous dir between backup_vm (root) and the SSH helper.
# Sticky + group-writable: the helper (nexusbackup) may create <vmid>.done,
# but cannot replace or remove the job files written by root.
d /run/nexusbackup      0750 root nexusbackup -
d /run/nexusbackup/jobs 1770 root nexusbackup -
# Restore requests (root) and the helper's listening NBD sockets (nexusbackup).
d /run/nexusbackup/restore 1770 root nexusbackup -
# Instant recovery: the helper's listening NBD sockets, the backing files of the
# qcow2 overlays the storage plugin keeps in /var/lib/nexusbackup/ir (root only).
d /run/nexusbackup/ir 1770 root nexusbackup -
# In-place rollback (Phase 30): qemu-nbd sockets and per-disk locks of the root service.
d /run/nexusbackup/rollback 0700 root root -
EOF

# In-place rollback (Phase 30): the root side, one process per connection of the
# SSH helper (user nexusbackup); see pve-plugin/rollback and docs/pve-connector.md.
mkdir -p "$STAGE/usr/lib/systemd/system"
cat > "$STAGE/usr/lib/systemd/system/nexusbackup-rollback.socket" <<'EOF'
[Unit]
Description=NexusBackup in-place rollback (root side, for the SSH helper)

[Socket]
ListenStream=/run/nexusbackup/rollback.sock
SocketUser=root
SocketGroup=nexusbackup
SocketMode=0660
Accept=yes
MaxConnections=16

[Install]
WantedBy=sockets.target
EOF
cat > "$STAGE/usr/lib/systemd/system/nexusbackup-rollback@.service" <<'EOF'
[Unit]
Description=NexusBackup in-place rollback request
Documentation=file:///usr/share/doc/nexusbackup-pve/pve-connector.md

[Service]
Type=oneshot
ExecStart=/usr/lib/nexusbackup/rollback
StandardInput=socket
StandardOutput=socket
StandardError=journal
# writes VM volumes through qemu-nbd (Ceph RBD volumes need the network)
NoNewPrivileges=yes
ProtectHome=yes
PrivateTmp=yes
EOF

cat > "$STAGE/DEBIAN/control" <<EOF
Package: nexusbackup-pve
Version: $VERSION
Architecture: all
Maintainer: NexusBackup <noreply@nexusbackup.invalid>
Section: admin
Priority: optional
Depends: libpve-storage-perl (>= 9.0), libjson-perl, perl, openssh-server, passwd, systemd, qemu-server, kmod
Description: NexusBackup storage and backup provider plugin for Proxmox VE 9
 Pull-model backup provider: Proxmox VE exposes the VM disks via NBD, the
 NexusBackup appliance reads them over SSH through a forced-command helper.
 The node never connects to the appliance.
EOF

cat > "$STAGE/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e

reload_pve() {
    # Every PVE daemon loads storage plugins at startup; reload so they pick
    # up (or drop) PVE::Storage::Custom::NexusBackupPlugin.
    for s in pvedaemon pveproxy pvestatd pvescheduler; do
        systemctl try-reload-or-restart "$s.service" >/dev/null 2>&1 || true
    done
}

if [ "$1" = configure ]; then
    if ! getent group nexusbackup >/dev/null; then
        groupadd --system nexusbackup
    fi
    if ! getent passwd nexusbackup >/dev/null; then
        useradd --system --gid nexusbackup --home-dir /var/lib/nexusbackup \
            --no-create-home --shell /bin/sh --comment "NexusBackup appliance access" nexusbackup
    fi
    # '*' = no password, but not locked ('!'), so key login works.
    usermod --password '*' nexusbackup

    # Home: must not be group/world-writable (sshd StrictModes).
    install -d -o root -g nexusbackup -m 0750 /var/lib/nexusbackup
    # ~/.ssh and authorized_keys belong to root so the account cannot alter
    # its own forced command. Key line:
    #   restrict,command="/usr/lib/nexusbackup/helper" ssh-ed25519 AAAA... nexus-appliance
    install -d -o root -g root -m 0755 /var/lib/nexusbackup/.ssh
    if [ ! -e /var/lib/nexusbackup/.ssh/authorized_keys ]; then
        install -o root -g root -m 0644 /dev/null /var/lib/nexusbackup/.ssh/authorized_keys
    fi
    # Per-storage state dirs (/var/lib/nexusbackup/<storeid>, 1770 root:nexusbackup)
    # are created by the plugin's activate_storage.

    systemd-tmpfiles --create /usr/lib/tmpfiles.d/nexusbackup-pve.conf || true
    # Phase 30: the in-place rollback service (idle until the appliance asks)
    systemctl daemon-reload >/dev/null 2>&1 || true
    systemctl enable --now nexusbackup-rollback.socket >/dev/null 2>&1 || true

    reload_pve
fi

exit 0
EOF

cat > "$STAGE/DEBIAN/prerm" <<'EOF'
#!/bin/sh
set -e
if [ "$1" = remove ]; then
    systemctl disable --now nexusbackup-rollback.socket >/dev/null 2>&1 || true
fi
exit 0
EOF

cat > "$STAGE/DEBIAN/postrm" <<'EOF'
#!/bin/sh
set -e

case "$1" in
    remove)
        for s in pvedaemon pveproxy pvestatd pvescheduler; do
            systemctl try-reload-or-restart "$s.service" >/dev/null 2>&1 || true
        done
        ;;
    purge)
        rm -rf /run/nexusbackup
        # The nexusbackup user and /var/lib/nexusbackup (catalogs, task logs,
        # authorized_keys) are kept on purge; remove them manually if wanted.
        ;;
esac

exit 0
EOF

chmod 0644 "$STAGE/usr/lib/tmpfiles.d/nexusbackup-pve.conf" "$STAGE/DEBIAN/control" \
    "$STAGE/usr/lib/systemd/system/nexusbackup-rollback.socket" "$STAGE/usr/lib/systemd/system/nexusbackup-rollback@.service"
chmod 0755 "$STAGE/DEBIAN/postinst" "$STAGE/DEBIAN/prerm" "$STAGE/DEBIAN/postrm"

DEB="$OUT/nexusbackup-pve_${VERSION}_all.deb"
dpkg-deb --build --root-owner-group "$STAGE" "$DEB"
rm -rf "$STAGE"
echo "$DEB"
