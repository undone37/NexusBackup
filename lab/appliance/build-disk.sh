#!/usr/bin/env bash
# Turns a bootc container image into a bootable qcow2 disk without root on the
# host: bootc-image-builder and `bootc install --via-loopback` need loop devices
# and mounts (root). Instead an installer VM (the plain bootc base image as an
# ext4 root, built with `mke2fs -d <tarball>`) boots under unprivileged QEMU/KVM
# and runs `bootc install to-disk` onto a virtio disk, as root inside the VM.
#   build-disk.sh [image] [out.qcow2]
#     image     default localhost/nexus-os-lab:dev
#     out       default $LAB/appliance/appliance.qcow2
# env: LAB (/home/ah/nexus-lab), SIZE (disk size, 24G), TARGET_IMGREF (recorded
#      upgrade source, default = image)
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
IMG=${1:-localhost/nexus-os-lab:dev}
LAB=${LAB:-/home/ah/nexus-lab}
OUT=${2:-$LAB/appliance/appliance.qcow2}
SIZE=${SIZE:-24G}
work=$LAB/appliance/work
mkdir -p "$work" "$(dirname "$OUT")"
t0=$(date +%s)
log() { printf '[%4ss] %s\n' $(($(date +%s) - t0)) "$*" >&2; }

inst=localhost/nexus-lab-installer:latest
podman build -q -t "$inst" -f "$here/Containerfile.installer" "$here" >/dev/null
# rebuild the installer root only when the installer image changed
iid=$(podman image inspect --format '{{.Id}}' "$inst")
if [ "$(cat "$work/installer.id" 2>/dev/null)" != "$iid" ]; then
	log "installer root fs"
	rm -f "$work/installer.raw" "$work/installer.tar"
	c=$(podman create "$inst")
	podman export -o "$work/installer.tar" "$c"
	podman rm -f "$c" >/dev/null
	truncate -s 12G "$work/installer.raw"
	/sbin/mke2fs -q -F -t ext4 -L root -d "$work/installer.tar" "$work/installer.raw"
	rm -f "$work/installer.tar"
	podman run --rm -v "$work:/out:Z" "$inst" sh -c \
		'k=$(ls /usr/lib/modules | head -1); cp /usr/lib/modules/$k/vmlinuz /out/installer.vmlinuz; cp /usr/lib/modules/$k/initramfs.img /out/installer.initrd; chmod 0644 /out/installer.*'
	echo "$iid" >"$work/installer.id"
fi

log "exporting $IMG"
rm -rf "$work/img" "$work/ociimg.raw"
mkdir -p "$work/img"
podman save -q --format oci-archive -o "$work/img/image.tar" "$IMG"
echo "$IMG" >"$work/img/imgref"
echo "${TARGET_IMGREF:-$IMG}" >"$work/img/target-imgref"
sz=$(($(stat -c %s "$work/img/image.tar") / 1048576 + 512))
truncate -s "${sz}M" "$work/ociimg.raw"
/sbin/mke2fs -q -F -t ext4 -d "$work/img" "$work/ociimg.raw"
rm -rf "$work/img"

log "installing onto $OUT ($SIZE)"
rm -f "$OUT.tmp"
qemu-img create -q -f qcow2 "$OUT.tmp" "$SIZE"
# the installer gets a throw-away overlay so its root stays pristine
rm -f "$work/installer.overlay.qcow2"
qemu-img create -q -f qcow2 -F raw -b "$work/installer.raw" "$work/installer.overlay.qcow2"
timeout 1800 qemu-system-x86_64 -name nexus-installer -machine q35,accel=kvm -cpu host -smp 4 -m 3072 \
	-nodefaults -display none -no-reboot \
	-kernel "$work/installer.vmlinuz" -initrd "$work/installer.initrd" \
	-append "root=LABEL=root rw console=ttyS0,115200n8 enforcing=0 systemd.unit=multi-user.target" \
	-drive file="$work/installer.overlay.qcow2",if=none,id=r,format=qcow2,cache=unsafe -device virtio-blk-pci,drive=r \
	-drive file="$work/ociimg.raw",if=none,id=i,format=raw,readonly=on -device virtio-blk-pci,drive=i,serial=ociimg \
	-drive file="$OUT.tmp",if=none,id=t,format=qcow2,cache=unsafe,discard=unmap -device virtio-blk-pci,drive=t,serial=target \
	-serial file:"$work/install.log" -nic none
rm -f "$work/installer.overlay.qcow2" "$work/ociimg.raw"
if ! grep -q ': NEXUS-INSTALL-OK' "$work/install.log"; then
	grep -E 'NEXUS-INSTALL|error|Error' "$work/install.log" | tail -n 30 >&2
	log "install failed, full log: $work/install.log"
	exit 1
fi
mv "$OUT.tmp" "$OUT"
log "done: $OUT ($(du -h "$OUT" | cut -f1) allocated)"
