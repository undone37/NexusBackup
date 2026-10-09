#!/bin/bash
# Runs inside the installer VM (see build-disk.sh). Disks by virtio serial:
#   ociimg  ext4 with image.tar (oci-archive), imgref, target-imgref
#   target  the appliance disk
set -uxo pipefail
fail() {
	echo "NEXUS-INSTALL-FAILED: $*"
	sync
	systemctl poweroff
	exit 1
}
for _ in $(seq 60); do
	[ -e /dev/disk/by-id/virtio-ociimg ] && [ -e /dev/disk/by-id/virtio-target ] && break
	sleep 1
done
mkdir -p /run/img
mount -o ro /dev/disk/by-id/virtio-ociimg /run/img || fail "mount ociimg"
img=$(cat /run/img/imgref)
podman load -q -i /run/img/image.tar || fail "podman load"
podman image exists "$img" || fail "image $img not in the archive"
target=$(readlink -f /dev/disk/by-id/virtio-target)
# The image's own policy.json only accepts signed images from its update
# repository; the local source image (containers-storage) is checked with the
# installer's default policy instead. The installed system keeps the image's policy.
podman run --rm --privileged --pid=host --security-opt label=type:unconfined_t \
	-v /dev:/dev -v /var/lib/containers:/var/lib/containers \
	-v /etc/containers/policy.json:/etc/containers/policy.json:ro \
	"$img" bootc install to-disk --wipe --filesystem xfs \
	--karg console=tty0 --karg console=ttyS0,115200n8 \
	--target-imgref "$(cat /run/img/target-imgref)" "$target" || fail "bootc install"
sync
echo "NEXUS-INSTALL-OK"
systemctl poweroff
