#!/usr/bin/env bash
# Builds the bare-metal recovery ISO target/rescue/nexus-rescue-<version>.iso
# (docs/bmr.md; no root, no host packages; needs podman, rustup, cargo):
#   1. nexus-agent as a static musl binary (crates/agent-linux/dist/build-bundle.sh)
#   2. a podman builder image from debian:trixie (Containerfile; layer-cached)
#   3. kernel + initramfs (agent in rescue mode, tools, modules) and a hybrid
#      BIOS + UEFI ISO made by grub-mkrescue (mkrescue.sh, --network none)
# env: BASE=<image ref> to pin the base image; SKIP_AGENT=1 reuses the built agent.
set -euo pipefail
trap 'echo "build.sh: failed at line $LINENO" >&2' ERR
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
out=$root/target/rescue
BASE=${BASE:-docker.io/library/debian:trixie}
IMG=localhost/nexus-rescue-builder:trixie
version=$(sed -n 's/^version = "\(.*\)"/\1/p' "$root/crates/agent-linux/Cargo.toml" | head -1)
t0=$(date +%s)
mkdir -p "$out"

agent=$root/target/x86_64-unknown-linux-musl/release/nexus-agent
if [ -z "${SKIP_AGENT:-}" ] || [ ! -x "$agent" ]; then
	"$root/crates/agent-linux/dist/build-bundle.sh" --test-key >/dev/null
fi
install -m 0755 "$agent" "$out/nexus-agent"

podman build -q --build-arg BASE="$BASE" -t "$IMG" -f "$here/Containerfile" "$here" >/dev/null
digest=$(podman image inspect --format '{{.Digest}}' "$BASE" 2>/dev/null || echo unknown)
podman run --rm --network none -e BASE_DIGEST="$BASE@$digest" -e VERSION="$version" \
	-v "$here:/src:ro,Z" -v "$out:/out:Z" "$IMG" bash /src/mkrescue.sh

echo "rescue ISO built in $(($(date +%s) - t0))s:"
ls -l "$out/nexus-rescue-$version.iso"
