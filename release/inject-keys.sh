#!/bin/bash
# Replace the development TEST key in os/etc with the real release public key(s) from
# release/keys/*.pub (one key normally, two during a rotation; docs: release/keygen.md),
# then run check-trust.sh --release. Run by the release workflow on a clean checkout
# before the image build; it edits the working tree only.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

shopt -s nullglob
keys=("$RELEASE_DIR"/keys/*.pub)
[ ${#keys[@]} -ge 1 ] && [ ${#keys[@]} -le 2 ] ||
	die "need 1 or 2 public keys in release/keys/ (found ${#keys[@]})"

dir=$REPO_ROOT/os/etc/pki/nexus/cosign
pol=$REPO_ROOT/os/etc/containers/policy.json
repo=$(os_etc_repo)
rm -f "$dir"/*.pub
paths=()
for k in "${keys[@]}"; do
	n=$(basename "$k")
	[[ $n =~ ^[A-Za-z0-9._-]+\.pub$ ]] && [[ $n != *TEST* ]] || die "bad key file name $n"
	install -m 0644 "$k" "$dir/$n"
	paths+=("/etc/pki/nexus/cosign/$n")
done
jq --arg r "$repo" --args '.transports.docker[$r][0].keyPaths = $ARGS.positional' "${paths[@]}" \
	<"$pol" >"$pol.new"
mv "$pol.new" "$pol"
echo "pinned: ${paths[*]}"
"$RELEASE_DIR/check-trust.sh" --release
