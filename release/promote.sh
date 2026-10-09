#!/bin/bash
# Point a channel tag (default: stable) at a signed release digest. Appliances follow
# <repo>:<tag> (NEXUS_UPDATE_TAG in /etc/nexus/update.conf), so this is the moment a
# release goes out. Refuses unless release/verify.sh accepts the digest, and copies
# through containers/image with the appliance policy, so an unsigned digest cannot be
# promoted even if verify.sh were skipped.
#
#   release/promote.sh IMAGE@sha256:... [TAG...]
set -euo pipefail
. "$(dirname "$0")/lib.sh"

[ $# -ge 1 ] || die "usage: promote.sh IMAGE@sha256:... [TAG...]"
ref=$1
shift
tags=("$@")
[ ${#tags[@]} -gt 0 ] || tags=(stable)
require_digest_ref "$ref"
require_trusted_repo "$ref"

"$(dirname "$0")/verify.sh" "$ref"

t=$(mktemp -d)
trap 'rm -rf "$t"' EXIT
render_trust "$t"
tls=()
[ "${NEXUS_ALLOW_HTTP:-0}" = 1 ] && tls=(--src-tls-verify=false --dest-tls-verify=false)
auth=()
auth_file >/dev/null && auth=(--authfile /auth/config.json)
for tag in "${tags[@]}"; do
	[[ $tag =~ ^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$ ]] || die "bad tag $tag"
	# --preserve-digests: the tag must name exactly the signed manifest.
	# --remove-signatures: the signature already sits at sha256-<digest>.sig.
	tool_run -v "$t/etc/containers:/trust:ro" -v "$t/etc/pki/nexus:/etc/pki/nexus:ro" -- \
		"$POLICY_CHECK_IMAGE" skopeo copy --quiet --preserve-digests --remove-signatures \
		--policy /trust/policy.json --registries.d /trust/registries.d "${auth[@]}" "${tls[@]}" \
		"docker://$ref" "docker://$NEXUS_IMAGE_REPO:$tag"
	echo "promoted $ref -> $NEXUS_IMAGE_REPO:$tag"
done
