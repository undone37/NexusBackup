#!/bin/bash
# Local build of the VMware hot-add proxy image (#35, os/proxy/Containerfile) and its OVA.
#
#   os/proxy/build.sh [--test-key] [--ova OUT.ova]
#
#   (always)    podman build -f os/proxy/Containerfile -t $IMAGE   (default localhost/nexus-proxy-os:dev)
#   --test-key  pin release/testkey (lab: agent updates signed with the TEST key); default release/keys
#   --ova       rootless disk (lab/appliance/build-disk.sh, $SIZE, default 10G), converted to a streamOptimized
#               VMDK, with os/proxy/nexus-proxy.ovf filled in and a SHA-256 manifest, as one OVA (OVF first)
#
# Deploy: vSphere "Deploy OVF Template", set the property nexus.token (Agents -> New agent on the appliance, the
# proxy's address), power on; the appliance enrols the agent. Lab: lab/pvehost/esxi_ova.py.
set -euo pipefail
cd "$(dirname "$0")/../.."
IMAGE=${IMAGE:-localhost/nexus-proxy-os:dev}
keys=release/keys
ova=
while [ $# -gt 0 ]; do
	case $1 in
	--test-key) keys=release/testkey ;;
	--ova)
		ova=${2:?--ova needs an output path}
		shift
		;;
	*)
		sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//' >&2
		exit 2
		;;
	esac
	shift
done
version=$(git describe --tags --always 2>/dev/null || echo 0.0.0-dev)
podman build -f os/proxy/Containerfile --build-arg RELEASE_KEYS="$keys" --build-arg NEXUS_VERSION="$version" -t "$IMAGE" .
echo "proxy image: $IMAGE" >&2
[ -n "$ova" ] || exit 0

work=target/proxy
rm -rf "$work" && mkdir -p "$work"
SIZE=${SIZE:-10G} lab/appliance/build-disk.sh "$IMAGE" "$work/disk.qcow2"
qemu-img convert -O vmdk -o subformat=streamOptimized "$work/disk.qcow2" "$work/disk.vmdk"
rm -f "$work/disk.qcow2"
os/proxy/ova.sh "$work/disk.vmdk" "$version" "$ova"
rm -f "$work/disk.vmdk"
