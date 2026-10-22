#!/bin/bash
# Build the static (musl) nexus-agent and assemble the install bundle.
#
#   crates/agent-linux/dist/build-bundle.sh [--test-key] [--sign]
#
#   --test-key  pin release/testkey/TEST-cosign.pub (lab builds); default: release/keys/*.pub
#   --sign      sign the binary for self-update: release/sign.sh sign-blob (COSIGN_KEY,
#               COSIGN_PASSWORD as for image signing; offline, --network none)
#
# Output: target/agent-dist/nexus-agent-<version>-x86_64/ and .tar.gz
# No musl cross compiler is needed: the only C/asm in the tree (ring, blake3) is
# freestanding, so the host gcc builds it for the musl target.
set -euo pipefail
cd "$(dirname "$0")/../../.."

TARGET=x86_64-unknown-linux-musl
test_key=0
sign=0
for a in "$@"; do
	case $a in
	--test-key) test_key=1 ;;
	--sign) sign=1 ;;
	*)
		sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//' >&2
		exit 2
		;;
	esac
done

rustup target list --installed | grep -qx "$TARGET" || rustup target add "$TARGET"
cc=gcc
command -v musl-gcc >/dev/null && cc=musl-gcc
CC_x86_64_unknown_linux_musl=$cc \
	CARGO_PROFILE_RELEASE_LTO=true \
	CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1 \
	CARGO_PROFILE_RELEASE_OPT_LEVEL=s \
	CARGO_PROFILE_RELEASE_STRIP=symbols \
	cargo build --locked -p agent-linux --release --target "$TARGET"

bin=target/$TARGET/release/nexus-agent
version=$(sed -n 's/^version = "\(.*\)"/\1/p' crates/agent-linux/Cargo.toml | head -1)
size=$(stat -c %s "$bin")
file "$bin" | grep -q 'static' || {
	echo "$bin is not statically linked" >&2
	exit 1
}

name=nexus-agent-$version-x86_64
out=target/agent-dist/$name
rm -rf "$out"
mkdir -p "$out/release-keys" "$out/hooks.d/pre"
install -m 0755 "$bin" "$out/nexus-agent"
install -m 0644 crates/agent-linux/dist/nexus-agent.service "$out/"
install -m 0755 crates/agent-linux/dist/install.sh "$out/"
install -m 0644 crates/agent-linux/dist/hooks.d/pre/*.example "$out/hooks.d/pre/"
install -m 0644 docs/agent-linux.md "$out/README.md"
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
	release/sign.sh sign-blob "$out/nexus-agent" "$out/nexus-agent.sig"
fi
# the appliance's update dir expects nexus-agent + .sig + .version (agent-conn `agent_update`);
# the agent itself trusts only the version embedded in the signed binary
echo "$version" >"$out/nexus-agent.version"
tar -C target/agent-dist -czf "target/agent-dist/$name.tar.gz" "$name"
echo "bundle: target/agent-dist/$name.tar.gz (binary $size bytes)"
