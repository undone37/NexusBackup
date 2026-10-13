#!/bin/bash
# Build nexus-agent-gui (desktop UI) in rootless podman containers; nothing is installed on
# the host.
#
#   crates/agent-gui/build.sh [--no-arm64] [--no-windows] [--clippy]
#
#   --no-arm64    skip Linux aarch64
#   --no-windows  skip Windows x86_64 (mingw-w64, same builder image as crates/agent-windows/build.sh)
#   --clippy      also run clippy -D warnings for the Windows target (CI)
#
# Linux: glibc build on Debian 11 (glibc 2.31: Debian 11+, Ubuntu 20.04+, RHEL/Alma 9, Fedora,
# SUSE 15.4+); it links only libc/libm/libgcc_s, X11/Wayland/xkbcommon are loaded at run time.
# Output: target/agent-dist/gui/{linux-amd64,linux-arm64}/nexus-agent-gui, windows/nexus-agent-gui.exe
set -euo pipefail
cd "$(dirname "$0")/../.."

RUST_IMAGE=${RUST_IMAGE:-docker.io/library/rust:1.93-slim-trixie}
GUI_LINUX_IMAGE=${GUI_LINUX_IMAGE:-docker.io/library/rust:1.93-slim-bullseye}
arm64=1
windows=1
clippy=0
for a in "$@"; do
	case $a in
	--no-arm64) arm64=0 ;;
	--no-windows) windows=0 ;;
	--clippy) clippy=1 ;;
	*)
		sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//' >&2
		exit 2
		;;
	esac
done

die() {
	echo "agent-gui/build.sh: $*" >&2
	exit 1
}

builder() { # builder NAME CONTAINERFILE -> prints the tag (as release/packages.sh)
	local tag
	tag=localhost/$1:$(printf '%s' "$2" | sha256sum | cut -c1-12)
	podman image exists "$tag" || printf '%s\n' "$2" | podman build -q -t "$tag" -f - . >/dev/null
	echo "$tag"
}

release_env=(
	-e CARGO_PROFILE_RELEASE_LTO=true
	-e CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1
	-e CARGO_PROFILE_RELEASE_OPT_LEVEL=s
	-e CARGO_PROFILE_RELEASE_STRIP=symbols
)
out=target/agent-dist/gui
rm -rf "$out"

# --- Linux -----------------------------------------------------------------------------
limg=$(builder nexus-agent-gui-linux-build "FROM $GUI_LINUX_IMAGE
RUN apt-get update && apt-get install -y --no-install-recommends gcc-aarch64-linux-gnu libc6-dev-arm64-cross file binutils \\
    && rm -rf /var/lib/apt/lists/* && rustup target add aarch64-unknown-linux-gnu")
lrun() {
	podman run --rm --security-opt label=disable -v "$PWD:/src" -w /src \
		-v nexus-cargo-registry:/usr/local/cargo/registry \
		-e CARGO_TARGET_DIR=/src/target/gui-linux-container \
		-e CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc \
		-e CC_aarch64_unknown_linux_gnu=aarch64-linux-gnu-gcc \
		"${release_env[@]}" "$limg" "$@"
}
targets=(x86_64-unknown-linux-gnu)
[ $arm64 = 1 ] && targets+=(aarch64-unknown-linux-gnu)
for t in "${targets[@]}"; do
	lrun cargo build --locked -p agent-gui --release --target "$t" --bin nexus-agent-gui
	case $t in
	x86_64-*) arch=amd64 elf='x86-64' objdump=objdump ;;
	aarch64-*) arch=arm64 elf='ARM aarch64' objdump=aarch64-linux-gnu-objdump ;;
	esac
	bin=target/gui-linux-container/$t/release/nexus-agent-gui
	desc=$(lrun file -b "$bin")
	[[ $desc == *"$elf"* && $desc == *dynamically* ]] || die "$bin: $desc"
	# only glibc: display libraries are opened at run time (dlopen), no -dev packages needed
	needed=$(lrun "$objdump" -p "$bin" | sed -n 's/^ *NEEDED *//p' | sort -u | tr '\n' ' ')
	for n in $needed; do
		case $n in
		libc.so.6 | libm.so.6 | libgcc_s.so.1 | ld-linux-*.so.* | libdl.so.2 | libpthread.so.0 | librt.so.1) ;;
		*) die "$bin needs $n" ;;
		esac
	done
	mkdir -p "$out/linux-$arch"
	install -m 0755 "$bin" "$out/linux-$arch/nexus-agent-gui"
	echo "linux-$arch: $(stat -c %s "$bin") bytes; needs: $needed"
done

# --- Windows -----------------------------------------------------------------------------
if [ $windows = 1 ]; then
	TARGET=x86_64-pc-windows-gnu
	# identical to crates/agent-windows/build.sh: the cached builder image is shared
	containerfile="FROM $RUST_IMAGE
RUN apt-get update && apt-get install -y --no-install-recommends gcc-mingw-w64-x86-64 binutils-mingw-w64-x86-64 \\
    && rm -rf /var/lib/apt/lists/* && rustup target add $TARGET && rustup component add clippy"
	wtag=localhost/nexus-agent-windows-build:$(printf '%s' "$containerfile" | sha256sum | cut -c1-12)
	podman image exists "$wtag" || printf '%s\n' "$containerfile" | podman build -t "$wtag" -f - .
	wrun() {
		podman run --rm --security-opt label=disable -v "$PWD:/src" -w /src \
			-v nexus-cargo-registry:/usr/local/cargo/registry \
			-e CARGO_TARGET_DIR=/src/target/windows-container \
			-e CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER=x86_64-w64-mingw32-gcc \
			-e CC_x86_64_pc_windows_gnu=x86_64-w64-mingw32-gcc \
			-e AR_x86_64_pc_windows_gnu=x86_64-w64-mingw32-ar \
			-e RUSTFLAGS="-C target-feature=+crt-static" \
			"${release_env[@]}" "$wtag" "$@"
	}
	if [ $clippy = 1 ]; then
		wrun cargo clippy --locked -p agent-gui --target "$TARGET" --all-targets -- -D warnings
	fi
	wrun cargo build --locked -p agent-gui --release --target "$TARGET" --bin nexus-agent-gui
	bin=target/windows-container/$TARGET/release/nexus-agent-gui.exe
	dlls=$(wrun x86_64-w64-mingw32-objdump -p "$bin" | sed -n 's/^\s*DLL Name: //p' | tr 'A-Z' 'a-z' | sort -u)
	# Windows system DLLs only; no mingw runtime (libgcc, libwinpthread) next to the exe
	for d in $dlls; do
		case $d in
		lib*.dll) die "unexpected DLL import: $d" ;;
		esac
	done
	mkdir -p "$out/windows"
	install -m 0644 "$bin" "$out/windows/nexus-agent-gui.exe"
	echo "windows: $(stat -c %s "$bin") bytes; imports: $(echo $dlls)"
fi
echo "output: $out"
