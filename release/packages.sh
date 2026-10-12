#!/bin/bash
# Agent packages for the release page: nexus-agent .deb + .rpm (x86_64, aarch64) and the
# Windows agent as an MSI, plus SHA256SUMS. Everything runs in rootless podman containers
# (official Rust image, nfpm, Fedora msitools); nothing is installed on the host.
#
#   release/packages.sh [--test-key] [--no-arm64] [--no-msi]
#
#   --test-key  pin release/testkey/TEST-cosign.pub (lab builds); default: release/keys/*.pub
#   --no-arm64  skip the aarch64 build
#   --no-msi    skip the Windows agent and its MSI
#
# Output: target/packages/{nexus-agent_<v>_amd64.deb, nexus-agent-<v>-1.x86_64.rpm,
# nexus-agent_<v>_arm64.deb, nexus-agent-<v>-1.aarch64.rpm, nexus-agent-<v>-x64.msi, SHA256SUMS}.
# The version is the agent's crate version (what self-update compares). Not signed here:
# the release manager signs the files with release/sign.sh sign-blobs (docs/release.md).
# Checks: release/test-packages.sh.
set -euo pipefail
cd "$(dirname "$0")/.."

RUST_IMAGE=${RUST_IMAGE:-docker.io/library/rust:1.93-slim-trixie}
NFPM_IMAGE=${NFPM_IMAGE:-docker.io/goreleaser/nfpm:v2.48.0@sha256:7d4cea73774728a1448af2dc248785fd17882005b0539f43d07f78a69db59368}
MSITOOLS_BASE=${MSITOOLS_BASE:-registry.fedoraproject.org/fedora:43}

test_key=0
arm64=1
msi=1
for a in "$@"; do
	case $a in
	--test-key) test_key=1 ;;
	--no-arm64) arm64=0 ;;
	--no-msi) msi=0 ;;
	*)
		sed -n '2,16p' "$0" | sed 's/^# \{0,1\}//' >&2
		exit 2
		;;
	esac
done

die() {
	echo "packages.sh: $*" >&2
	exit 1
}

# cached builder image, tagged by the hash of its definition (as crates/agent-windows/build.sh)
builder() { # builder NAME CONTAINERFILE -> prints the tag
	local tag
	tag=localhost/$1:$(printf '%s' "$2" | sha256sum | cut -c1-12)
	podman image exists "$tag" || printf '%s\n' "$2" | podman build -q -t "$tag" -f - . >/dev/null
	echo "$tag"
}

if [ $test_key = 1 ]; then
	keys=(release/testkey/TEST-cosign.pub)
	key_names=(TEST-KEY-DO-NOT-SHIP.pub)
else
	shopt -s nullglob
	keys=(release/keys/*.pub)
	shopt -u nullglob
	[ ${#keys[@]} -gt 0 ] || die "no release keys in release/keys (use --test-key for lab builds)"
	key_names=()
	for k in "${keys[@]}"; do key_names+=("$(basename "$k")"); done
fi

version=$(sed -n 's/^version = "\(.*\)"/\1/p' crates/agent-linux/Cargo.toml | head -1)
wversion=$(sed -n 's/^version = "\(.*\)"/\1/p' crates/agent-windows/Cargo.toml | head -1)
out=target/packages
rm -rf "$out"
mkdir -p "$out"

# --- Linux: static musl binaries --------------------------------------------------------
# The only C/asm in the tree (ring, blake3) is freestanding: gcc builds it for musl
# (x86_64) and the aarch64 GNU cross compiler for aarch64-musl; Rust links its
# self-contained musl.
linux_img=$(builder nexus-agent-linux-build "FROM $RUST_IMAGE
RUN apt-get update && apt-get install -y --no-install-recommends gcc-aarch64-linux-gnu libc6-dev-arm64-cross file \\
    && rm -rf /var/lib/apt/lists/* && rustup target add x86_64-unknown-linux-musl aarch64-unknown-linux-musl")
targets=(x86_64-unknown-linux-musl)
[ $arm64 = 1 ] && targets+=(aarch64-unknown-linux-musl)
lrun() {
	podman run --rm --security-opt label=disable -v "$PWD:/src" -w /src \
		-v nexus-cargo-registry:/usr/local/cargo/registry \
		-e CARGO_TARGET_DIR=/src/target/linux-container \
		-e CC_x86_64_unknown_linux_musl=gcc \
		-e CC_aarch64_unknown_linux_musl=aarch64-linux-gnu-gcc \
		-e CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=aarch64-linux-gnu-gcc \
		-e CARGO_PROFILE_RELEASE_LTO=true \
		-e CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1 \
		-e CARGO_PROFILE_RELEASE_OPT_LEVEL=s \
		-e CARGO_PROFILE_RELEASE_STRIP=symbols \
		"$linux_img" "$@"
}
for t in "${targets[@]}"; do
	lrun cargo build --locked -p agent-linux --release --target "$t"
done

# self-update sends the binary in one protocol frame (agent-proto MAX_FRAME = 8 MiB)
limit=$((8 * 1024 * 1024 - 4096))
for t in "${targets[@]}"; do
	bin=target/linux-container/$t/release/nexus-agent
	case $t in
	x86_64-*) arch=amd64 elf='x86-64' ;;
	aarch64-*) arch=arm64 elf='ARM aarch64' ;;
	esac
	size=$(stat -c %s "$bin")
	[ "$size" -lt "$limit" ] || die "$bin is $size bytes, self-update frame limit is $limit"
	desc=$(lrun file -b "$bin")
	[[ $desc == *static* && $desc == *"$elf"* ]] || die "$bin: $desc"
	grep -aq "NEXUS-AGENT-VERSION=$version" "$bin" || die "$bin carries no version marker $version"

	stage=$out/stage-$arch
	mkdir -p "$stage/release-keys" "$stage/hooks.d/pre"
	install -m 0755 "$bin" "$stage/nexus-agent"
	sed 's|/usr/local/sbin/nexus-agent|/usr/bin/nexus-agent|g' crates/agent-linux/dist/nexus-agent.service \
		>"$stage/nexus-agent.service"
	install -m 0644 crates/agent-linux/dist/pkg/nfpm.yaml "$stage/"
	install -m 0755 crates/agent-linux/dist/pkg/{postinst,prerm,postrm}.sh "$stage/"
	install -m 0644 crates/agent-linux/dist/pkg/lintian-overrides "$stage/"
	cat >"$stage/changelog.yml" <<-EOF
		- semver: $version-1
		  date: $(git log -1 --format=%cI 2>/dev/null || date -u +%FT%TZ)
		  packager: NexusBackup maintainers <undone37@users.noreply.github.com>
		  changes:
		    - note: "nexus-agent $version, see https://github.com/undone37/NexusBackup/releases"
	EOF
	install -m 0644 docs/agent-linux.md "$stage/README.md"
	install -m 0644 crates/agent-linux/dist/hooks.d/pre/*.example "$stage/hooks.d/pre/"
	for e in crates/agent-linux/dist/hooks.d/pre/*.example; do
		grep -q "src: hooks.d/pre/$(basename "$e")$" crates/agent-linux/dist/pkg/nfpm.yaml ||
			die "$(basename "$e") is not listed in crates/agent-linux/dist/pkg/nfpm.yaml"
	done
	for i in "${!keys[@]}"; do install -m 0644 "${keys[$i]}" "$stage/release-keys/${key_names[$i]}"; done
	{
		echo "Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/"
		echo "Upstream-Name: NexusBackup"
		echo "Source: https://github.com/undone37/NexusBackup"
		echo
		echo "Files: *"
		echo "Copyright: NexusBackup contributors"
		echo "License: AGPL-3.0-only"
		sed 's/^$/./; s/^/ /' LICENSE
	} >"$stage/copyright"
	for p in deb rpm; do
		echo "$p" >"$stage/package-managed"
		podman run --rm --security-opt label=disable -v "$PWD/$stage:/stage" -v "$PWD/$out:/out" -w /stage \
			-e PKG_ARCH="$arch" -e PKG_VERSION="$version" \
			"$NFPM_IMAGE" pkg --config /stage/nfpm.yaml --packager "$p" --target /out/
	done
	rm -rf "$stage"
done

# --- Windows: nexus-agent.exe + MSI ------------------------------------------------------
if [ $msi = 1 ]; then
	if [ $test_key = 1 ]; then
		crates/agent-windows/build.sh --test-key
	else
		crates/agent-windows/build.sh
	fi
	stage=$out/stage-msi
	mkdir -p "$stage"
	cp target/agent-dist/windows/nexus-agent.exe crates/agent-windows/dist/nexus-agent.wxs "$stage/"
	cp target/agent-dist/windows/release-keys/*.pub "$stage/"
	install -m 0644 docs/agent-windows.md "$stage/README.md"
	echo msi >"$stage/package-managed.msi"
	# one component per pinned key (names vary: rotation, TEST key)
	n=0
	for f in keys keyrefs; do printf '<?xml version="1.0" encoding="utf-8"?>\n<Include>\n' >"$stage/$f.wxi"; done
	for k in "$stage"/*.pub; do
		n=$((n + 1))
		echo "  <Component Id=\"Key$n\" Guid=\"*\" Win64=\"yes\"><File Id=\"Key$n\" Name=\"$(basename "$k")\" Source=\"$(basename "$k")\" KeyPath=\"yes\"/></Component>" >>"$stage/keys.wxi"
		echo "  <ComponentRef Id=\"Key$n\"/>" >>"$stage/keyrefs.wxi"
	done
	for f in keys keyrefs; do echo '</Include>' >>"$stage/$f.wxi"; done
	msi_img=$(builder nexus-msitools "FROM $MSITOOLS_BASE
RUN dnf -y install --setopt=install_weak_deps=False msitools && dnf clean all")
	name=nexus-agent-$wversion-x64.msi
	podman run --rm --security-opt label=disable -v "$PWD/$stage:/stage" -w /stage "$msi_img" \
		wixl -a x64 -D Version="$wversion" -o "/stage/$name" nexus-agent.wxs
	mv "$stage/$name" "$out/"
	rm -rf "$stage"
fi

(cd "$out" && shopt -s nullglob && sha256sum -- *.deb *.rpm *.msi >SHA256SUMS)
cat "$out/SHA256SUMS"
echo "packages in $out (check them with release/test-packages.sh)"
