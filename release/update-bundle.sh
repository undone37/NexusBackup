#!/bin/bash
# Offline update bundle of a released image (docs/release.md "Offline update bundle", plan.md Phase 36):
# the image as an OCI layout plus the image's cosign signature, for appliances without access to the
# registry. The appliance (nexus-update) trusts only that signature: it must verify with a pinned
# release key, name NEXUS_IMAGE_REPO and the manifest digest of the bundled image.
#
#   release/update-bundle.sh OUT.tar --image REPO@sha256:...
#       a published release: the image and its signature (the .sig tag that release/sign.sh attached)
#       from the registry, nothing is signed again
#   release/update-bundle.sh OUT.tar --oci-dir DIR
#       an OCI layout (e.g. `podman save --format oci-dir -o DIR <image>`, lab builds): the signature
#       payload is created here and signed offline with COSIGN_KEY (release/sign.sh sign-blob)
#
# Layout of OUT.tar: bundle.json {format, repository, version, digest}, image/ (OCI layout, one manifest
# with the ref name "nexus"), signature/payload.json + signature/payload.sig, SHA256SUMS of every other file.
# GitHub release assets are limited to 2 GiB: a larger bundle is uploaded to the appliance directly.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

[ $# = 3 ] || die "usage: $0 OUT.tar --image REPO@sha256:... | --oci-dir DIR"
out=$(realpath -m "$1")
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/b/signature"
repo=$NEXUS_IMAGE_REPO

case $2 in
--image)
	ref=$3
	require_digest_ref "$ref"
	require_trusted_repo "$ref"
	digest=${ref##*@}
	# the image exactly as signed: same manifest bytes, so the same digest
	tool_run -v "$work/b:/b" -- "$SKOPEO_IMAGE" copy --quiet --preserve-digests "docker://$ref" oci:/b/image:nexus
	# the signature as release/sign.sh attached it: the .sig tag's layer is the payload, its
	# annotation the base64 signature
	tool_run -v "$work:/w" -- "$SKOPEO_IMAGE" copy --quiet "docker://${ref%@*}:sha256-${digest#sha256:}.sig" dir:/w/sig
	sig_manifest="$work/sig/manifest.json"
	layer=$(jq -er '.layers[0].digest' "$sig_manifest")
	jq -er '.layers[0].annotations["dev.cosignproject.cosign/signature"]' "$sig_manifest" >"$work/b/signature/payload.sig"
	cp "$work/sig/${layer#sha256:}" "$work/b/signature/payload.json"
	;;
--oci-dir)
	[ -f "$3/index.json" ] || die "$3 is not an OCI layout (no index.json)"
	cp -r "$3" "$work/b/image"
	[ "$(jq '.manifests | length' "$work/b/image/index.json")" = 1 ] || die "$3 must hold exactly one image"
	# the ref name is not signed (index.json is outside the manifest): name it "nexus" for nexus-update
	jq '.manifests[0].annotations["org.opencontainers.image.ref.name"] = "nexus"' "$3/index.json" >"$work/b/image/index.json"
	digest=$(jq -er '.manifests[0].digest' "$work/b/image/index.json")
	jq -nc --arg r "$repo" --arg d "$digest" \
		'{critical: {identity: {"docker-reference": $r}, image: {"docker-manifest-digest": $d}, type: "cosign container image signature"}, optional: null}' \
		>"$work/b/signature/payload.json"
	"$(dirname "$0")/sign.sh" sign-blob "$work/b/signature/payload.json" "$work/b/signature/payload.sig"
	;;
*) die "unknown source $2" ;;
esac

blob() { echo "$work/b/image/blobs/sha256/${1#sha256:}"; }
[ "sha256:$(sha256sum "$(blob "$digest")" | cut -d' ' -f1)" = "$digest" ] || die "manifest does not match $digest"
config=$(jq -er '.config.digest' "$(blob "$digest")")
version=$(jq -er '.config.Labels["org.opencontainers.image.version"]' "$(blob "$config")") ||
	die "the image has no org.opencontainers.image.version label"
jq -e --arg d "$digest" --arg r "$repo" \
	'.critical.image["docker-manifest-digest"] == $d and (.critical.identity["docker-reference"] | split("@")[0] | split(":")[0]) == ($r | split(":")[0])' \
	"$work/b/signature/payload.json" >/dev/null || die "the signature payload does not name $repo and $digest"
jq -n --arg r "$repo" --arg v "$version" --arg d "$digest" '{format: 1, repository: $r, version: $v, digest: $d}' >"$work/b/bundle.json"
(cd "$work/b" && find . -type f ! -name SHA256SUMS | sed 's|^\./||' | LC_ALL=C sort | xargs -d '\n' sha256sum >SHA256SUMS)
tar -C "$work/b" -cf "$out" .
echo "bundle $out: $repo $version ($digest), $(du -h "$out" | cut -f1)" >&2
