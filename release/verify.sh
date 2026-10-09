#!/bin/bash
# Verify a signed appliance image the way the appliance will, without any transparency
# log or other online service (only the registry is contacted).
#
#   release/verify.sh IMAGE@sha256:...            cosign verify against the pinned key(s)
#   release/verify.sh --policy IMAGE@sha256:...   additionally fetch the image through
#       containers/image (skopeo in the appliance base image) with the appliance's
#       policy.json + registries.d: exactly the check bootc performs. Downloads all layers.
#
# Keys: VERIFY_KEYS="a.pub b.pub" or, by default, the keys pinned in
# os/etc/containers/policy.json. Succeeds if any key verifies (rotation overlap).
# NEXUS_ALLOW_HTTP=1 for a plain-HTTP test registry.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

policy=0
if [ "${1:-}" = --policy ]; then
	policy=1
	shift
fi
[ $# = 1 ] || die "usage: verify.sh [--policy] IMAGE@sha256:..."
ref=$1
require_digest_ref "$ref"
require_trusted_repo "$ref"

if [ -n "${VERIFY_KEYS:-}" ]; then
	read -ra keys <<<"$VERIFY_KEYS"
else
	mapfile -t keys < <(pinned_keys)
fi
[ ${#keys[@]} -gt 0 ] || die "no keys"

ok=
for k in "${keys[@]}"; do
	# shellcheck disable=SC2046
	if out=$(tool_run -v "$(realpath "$k"):/key.pub:ro" -- "$COSIGN_IMAGE" verify \
		--key /key.pub --insecure-ignore-tlog=true $(http_flags) "$ref" 2>/dev/null); then
		# cosign checks the digest itself; assert it once more on the signed payload
		echo "$out" | jq -e --arg d "${ref#*@}" 'all(.[]; .critical.image."docker-manifest-digest" == $d)' >/dev/null ||
			die "payload digest mismatch"
		echo "cosign: $ref verified with $(basename "$k")"
		ok=1
		break
	fi
	echo "cosign: not signed by $(basename "$k")" >&2
done
[ -n "$ok" ] || die "cosign: $ref has no valid signature from a pinned key"

if [ $policy = 1 ]; then
	t=$(mktemp -d)
	trap 'rm -rf "$t"' EXIT
	render_trust "$t"
	tls=()
	[ "${NEXUS_ALLOW_HTTP:-0}" = 1 ] && tls=(--src-tls-verify=false)
	tool_run -v "$t/etc/containers:/trust:ro" -v "$t/etc/pki/nexus:/etc/pki/nexus:ro" -- \
		"$POLICY_CHECK_IMAGE" skopeo copy --quiet --policy /trust/policy.json \
		--registries.d /trust/registries.d "${tls[@]}" "docker://$ref" dir:/tmp/img
	echo "policy: $ref accepted by the appliance policy"
fi
