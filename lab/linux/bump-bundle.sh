#!/usr/bin/env bash
# Build a signed agent bundle with a different version (self-update tests): copies the
# working tree to target/agent-bump/src, sets crates/agent-linux to VERSION there and
# runs dist/build-bundle.sh --test-key --sign in the copy.
#   bump-bundle.sh VERSION      -> target/agent-bump/src/target/agent-dist/nexus-agent-VERSION-x86_64/
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
ver=${1:?version, e.g. 0.1.1}
src=$repo/target/agent-bump/src
mkdir -p "$src"
# keep $src/target (build cache); refresh the sources
find "$src" -mindepth 1 -maxdepth 1 ! -name target -exec rm -rf {} +
git -C "$repo" ls-files -z --cached --others --exclude-standard | tar -C "$repo" --null -T - -cf - | tar -C "$src" -xf -
python3 -I - "$src" "$ver" <<-'PY'
	import re, sys
	src, ver = sys.argv[1], sys.argv[2]
	p = f"{src}/crates/agent-linux/Cargo.toml"
	s = open(p).read()
	open(p, "w").write(re.sub(r'(?m)^version = "[^"]*"', f'version = "{ver}"', s, count=1))
	p = f"{src}/Cargo.lock"
	s = open(p).read()
	s, n = re.subn(r'(name = "agent-linux"\nversion = )"[^"]*"', rf'\1"{ver}"', s)
	assert n == 1, "agent-linux not in Cargo.lock"
	open(p, "w").write(s)
PY
COSIGN_KEY=$repo/release/testkey/TEST-cosign.key COSIGN_PASSWORD=nexus-test-key \
	"$src/crates/agent-linux/dist/build-bundle.sh" --test-key --sign
ls -l "$src/target/agent-dist/nexus-agent-$ver-x86_64"
