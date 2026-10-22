#!/bin/bash
# Cross-compile nexus-agent.exe (x86_64-pc-windows-gnu) in a rootless podman container
# (official Rust image + mingw-w64); nothing is installed on the host.
#
#   crates/agent-windows/build.sh [--test-key] [--sign] [--clippy]
#
#   --test-key  pin release/testkey/TEST-cosign.pub (lab builds); default: release/keys/*.pub
#   --sign      sign the binary for self-update: release/sign.sh sign-blob (COSIGN_KEY,
#               COSIGN_PASSWORD as for image signing; offline, --network none)
#   --clippy    also run clippy -D warnings for the Windows target (CI)
#
# Output: target/agent-dist/windows/{nexus-agent.exe,nexus-agent.exe.sig,nexus-agent.version,
# release-keys/,README.md}. No size limit: agents since 0.1.0 (protocol v1.8) take updates in 1 MiB chunks.
set -euo pipefail
cd "$(dirname "$0")/../.."

RUST_IMAGE=${RUST_IMAGE:-docker.io/library/rust:1.93-slim-trixie}
TARGET=x86_64-pc-windows-gnu
test_key=0
sign=0
clippy=0
for a in "$@"; do
	case $a in
	--test-key) test_key=1 ;;
	--sign) sign=1 ;;
	--clippy) clippy=1 ;;
	*)
		sed -n '2,14p' "$0" | sed 's/^# \{0,1\}//' >&2
		exit 2
		;;
	esac
done

# builder image: rust + mingw-w64 (gcc for ring/blake3 C parts, dlltool for raw-dylib)
containerfile="FROM $RUST_IMAGE
RUN apt-get update && apt-get install -y --no-install-recommends gcc-mingw-w64-x86-64 binutils-mingw-w64-x86-64 \\
    && rm -rf /var/lib/apt/lists/* && rustup target add $TARGET && rustup component add clippy"
tag=localhost/nexus-agent-windows-build:$(printf '%s' "$containerfile" | sha256sum | cut -c1-12)
if ! podman image exists "$tag"; then
	printf '%s\n' "$containerfile" | podman build -t "$tag" -f - .
fi

run() {
	podman run --rm --security-opt label=disable \
		-v "$PWD:/src" -w /src \
		-v nexus-cargo-registry:/usr/local/cargo/registry \
		-e CARGO_TARGET_DIR=/src/target/windows-container \
		-e CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER=x86_64-w64-mingw32-gcc \
		-e CC_x86_64_pc_windows_gnu=x86_64-w64-mingw32-gcc \
		-e AR_x86_64_pc_windows_gnu=x86_64-w64-mingw32-ar \
		-e RUSTFLAGS="-C target-feature=+crt-static" \
		-e CARGO_PROFILE_RELEASE_LTO=true \
		-e CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1 \
		-e CARGO_PROFILE_RELEASE_OPT_LEVEL=${OPT_LEVEL:-s} \
		-e CARGO_PROFILE_RELEASE_STRIP=symbols \
		"$tag" "$@"
}

if [ $clippy = 1 ]; then
	run cargo clippy --locked -p agent-windows --target "$TARGET" --all-targets -- -D warnings
fi
run cargo build --locked -p agent-windows --release --target "$TARGET"

bin=target/windows-container/$TARGET/release/nexus-agent-windows.exe
version=$(sed -n 's/^version = "\(.*\)"/\1/p' crates/agent-windows/Cargo.toml | head -1)
size=$(stat -c %s "$bin")
# only system DLLs may be imported (no libgcc / winpthread DLLs next to the exe)
dlls=$(run x86_64-w64-mingw32-objdump -p "$bin" | sed -n 's/^\s*DLL Name: //p' | tr 'A-Z' 'a-z' | sort -u)
for d in $dlls; do
	case $d in
	kernel32.dll | advapi32.dll | ntdll.dll | ole32.dll | oleaut32.dll | vssapi.dll | ws2_32.dll | userenv.dll | \
		bcrypt.dll | bcryptprimitives.dll | api-ms-win-*.dll | msvcrt.dll | secur32.dll | crypt32.dll | user32.dll) ;;
	*)
		echo "unexpected DLL import: $d" >&2
		exit 1
		;;
	esac
done

out=target/agent-dist/windows
rm -rf "$out"
mkdir -p "$out/release-keys"
install -m 0644 "$bin" "$out/nexus-agent.exe"
install -m 0644 docs/agent-windows.md "$out/README.md"
if [ $test_key = 1 ]; then
	install -m 0644 release/testkey/TEST-cosign.pub "$out/release-keys/TEST-KEY-DO-NOT-SHIP.pub"
else
	shopt -s nullglob
	keys=(release/keys/*.pub)
	[ ${#keys[@]} -gt 0 ] || {
		echo "no release keys in release/keys (use --test-key for lab builds)" >&2
		exit 1
	}
	install -m 0644 "${keys[@]}" "$out/release-keys/"
fi
if [ $sign = 1 ]; then
	release/sign.sh sign-blob "$out/nexus-agent.exe" "$out/nexus-agent.exe.sig"
fi
echo "$version" >"$out/nexus-agent.version"
echo "nexus-agent.exe $version: $size bytes ($((size / 1024)) KiB); imports: $(echo $dlls)"
echo "output: $out"
