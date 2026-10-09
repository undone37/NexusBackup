#!/usr/bin/env bash
# Builds the restore micro-VM into target/restore-vm/ (no root, no host packages):
#   1. the agent as a static musl binary (rustup target x86_64-unknown-linux-musl)
#   2. a podman builder image from debian:trixie with the kernel, zfs-dkms built
#      for exactly that kernel, and the userland (Containerfile; layer-cached)
#   3. kernel + initramfs + fixture overlay + manifest.txt (mkinitrd.sh)
# env: BASE=<image ref> to pin the base image (e.g. debian:trixie@sha256:…).
set -euo pipefail
trap 'echo "build.sh: failed at line $LINENO" >&2' ERR
here=$(cd "$(dirname "$0")" && pwd)
root=$(dirname "$here")
out=$root/target/restore-vm
BASE=${BASE:-docker.io/library/debian:trixie}
IMG=localhost/nexus-restore-vm-builder:trixie
t0=$(date +%s)
mkdir -p "$out"

rustup target list --installed | grep -x x86_64-unknown-linux-musl >/dev/null ||
	rustup target add x86_64-unknown-linux-musl
cargo build --manifest-path "$root/Cargo.toml" -q --release -p restorevm-agent \
	--target x86_64-unknown-linux-musl
install -m 0755 "$root/target/x86_64-unknown-linux-musl/release/nexus-restore-agent" "$out/agent"

podman build -q --build-arg BASE="$BASE" -t "$IMG" -f "$here/Containerfile" "$here" >/dev/null
digest=$(podman image inspect --format '{{.Digest}}' "$BASE" 2>/dev/null || echo unknown)
podman run --rm --network none -e BASE_DIGEST="$BASE@$digest" \
	-v "$here:/src:ro,Z" -v "$out:/out:Z" "$IMG" bash /src/mkinitrd.sh

echo "restore-vm built in $(($(date +%s) - t0))s:"
ls -l "$out"/{vmlinuz,initrd.img,fixture-overlay.img,agent}
