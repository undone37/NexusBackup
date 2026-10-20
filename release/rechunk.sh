#!/bin/bash
# Rebuilds an image's layers from its final file tree (bootc-base-imagectl rechunk, rpm-ostree), so files the
# Containerfile removes from base-image layers are really gone (the installer ISO must stay below GitHub's
# 2 GiB asset limit) and the layers are content-based chunks, which keeps later updates small. The tool runs
# from the AlmaLinux bootc base image (POLICY_CHECK_IMAGE, release/config.env), not from our image: our
# policy.json rejects the tool's own intermediate oci copy. The version label is checked to survive.
#
#   release/rechunk.sh FROM TO      e.g. localhost/nexus-os:release localhost/nexus-os:release-chunked
set -euo pipefail
. "$(dirname "$0")/lib.sh"
[ $# = 2 ] || { echo "usage: $0 FROM TO" >&2; exit 2; }
from=$1 to=$2
# the storage under its own path (its database records it), told to the tool through a storage.conf
storage=$(podman info --format '{{.Store.GraphRoot}}')
driver=$(podman info --format '{{.Store.GraphDriverName}}')
conf=$(mktemp)
trap 'rm -f "$conf"' EXIT
printf '[storage]\ndriver = "%s"\ngraphroot = "%s"\nrunroot = "/run/containers/storage"\n' "$driver" "$storage" >"$conf"
podman run --rm --privileged --security-opt label=disable -v "$storage:$storage" -v "$conf:/etc/containers/storage.conf:ro" \
	"$POLICY_CHECK_IMAGE" /usr/libexec/bootc-base-imagectl rechunk "$from" "$to"
want=$(podman image inspect --format '{{index .Labels "org.opencontainers.image.version"}}' "$from")
have=$(podman image inspect --format '{{index .Labels "org.opencontainers.image.version"}}' "$to")
[ -n "$want" ] && [ "$want" = "$have" ] || { echo "rechunk lost the version label ($want -> $have)" >&2; exit 1; }
echo "rechunked $from -> $to: $(podman image inspect --format '{{len .RootFS.Layers}} layers, {{.Size}} bytes' "$to")" >&2
