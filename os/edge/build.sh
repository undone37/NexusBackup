#!/bin/bash
# Local build of the edge proxy OS image (Phase 26, docs/edge.md) and its disk images.
#
#   os/edge/build.sh [--test-key] [--qcow2] [--iso] [--lab-disk OUT.qcow2]
#
#   (always)     podman build -f os/edge/Containerfile -t $IMAGE   (default localhost/nexus-edge-os:dev)
#   --test-key   pin release/testkey (lab: updates signed with the TEST key); default release/keys
#   --qcow2      bootc-image-builder qcow2 -> target/edge/qcow2/disk.qcow2   (needs sudo: loop devices)
#   --iso        bootc-image-builder anaconda-iso -> target/edge/bootiso/install.iso   (needs sudo)
#   --lab-disk   rootless qcow2 through lab/appliance/build-disk.sh (installer VM, no sudo)
#
# The image is not built in CI yet (docs/edge.md "Status"); release builds use the same
# Containerfile with the release keys.
set -euo pipefail
cd "$(dirname "$0")/../.."

IMAGE=${IMAGE:-localhost/nexus-edge-os:dev}
BIB=${BIB:-quay.io/centos-bootc/bootc-image-builder:latest}
keys=release/keys
qcow2=0
iso=0
lab_disk=
while [ $# -gt 0 ]; do
	case $1 in
	--test-key) keys=release/testkey ;;
	--qcow2) qcow2=1 ;;
	--iso) iso=1 ;;
	--lab-disk)
		lab_disk=${2:?--lab-disk needs an output path}
		shift
		;;
	*)
		sed -n '2,14p' "$0" | sed 's/^# \{0,1\}//' >&2
		exit 2
		;;
	esac
	shift
done

podman build -f os/edge/Containerfile --build-arg RELEASE_KEYS="$keys" \
	--build-arg NEXUS_VERSION="$(git describe --tags --always 2>/dev/null || echo 0.0.0-dev)" -t "$IMAGE" .

bib() { # bib TYPE
	mkdir -p target/edge
	# bootc-image-builder reads the image from root's container storage
	podman save --format oci-archive -o target/edge/image.tar "$IMAGE"
	sudo podman load -q -i target/edge/image.tar >/dev/null
	rm -f target/edge/image.tar
	local cfg=()
	# the installer kickstart of the appliance ISO (locked root, interactive disk choice)
	[ "$1" = anaconda-iso ] && cfg=(-v "$PWD/release/iso/config.toml:/config.toml:ro")
	sudo podman run --rm --privileged --security-opt label=type:unconfined_t \
		"${cfg[@]}" -v "$PWD/target/edge:/output" \
		-v /var/lib/containers/storage:/var/lib/containers/storage \
		"$BIB" --type "$1" --rootfs xfs --use-librepo=false "$IMAGE"
	sudo chown -R "$USER" target/edge
}
[ $qcow2 = 1 ] && bib qcow2
[ $iso = 1 ] && bib anaconda-iso
if [ -n "$lab_disk" ]; then
	SIZE=${SIZE:-8G} lab/appliance/build-disk.sh "$IMAGE" "$lab_disk"
fi
echo "edge image: $IMAGE" >&2
