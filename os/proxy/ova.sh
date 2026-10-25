#!/bin/bash
# Packs a streamOptimized VMDK of the hot-add proxy image into an OVA (#35): os/proxy/nexus-proxy.ovf filled in, a
# SHA-256 manifest, the descriptor first (as OVA requires). Used by os/proxy/build.sh --ova (lab disk) and by
# .github/workflows/iso.yml (bootc-image-builder --type vmdk).
#   os/proxy/ova.sh DISK.vmdk VERSION OUT.ova
set -euo pipefail
[ $# = 3 ] || { sed -n '2,5p' "$0" >&2; exit 2; }
vmdk=$1 version=$2 out=$3
here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d "${TMPDIR:-/var/tmp}/ova.XXXXXX")
trap 'rm -rf "$work"' EXIT
cp --reflink=auto "$vmdk" "$work/nexus-proxy-disk1.vmdk"
# the disk's virtual size: the capacity field of a streamOptimized VMDK's header (sectors, offset 12, little endian)
capacity=$(($(od -An -t u8 -j 12 -N 8 "$work/nexus-proxy-disk1.vmdk" | tr -d ' ') * 512))
[ "$capacity" -gt 0 ] || { echo "ova.sh: $vmdk is not a VMDK" >&2; exit 1; }
sed -e "s|@VERSION@|$version|" -e "s|@VMDK@|nexus-proxy-disk1.vmdk|" \
	-e "s|@VMDK_BYTES@|$(stat -c %s "$work/nexus-proxy-disk1.vmdk")|" -e "s|@CAPACITY@|$capacity|" \
	"$here/nexus-proxy.ovf" >"$work/nexus-proxy.ovf"
(cd "$work" && for f in nexus-proxy.ovf nexus-proxy-disk1.vmdk; do
	echo "SHA256($f)= $(sha256sum "$f" | cut -d' ' -f1)"
done >nexus-proxy.mf)
tar -C "$work" -cf "$out" nexus-proxy.ovf nexus-proxy.mf nexus-proxy-disk1.vmdk
echo "OVA $out ($(du -h "$out" | cut -f1)), version $version, disk $capacity bytes" >&2
