#!/bin/bash
# End-to-end check of the signing chain against a throwaway local registry
# (rootless podman only, nothing installed, no sudo):
#
#   registry:2 on 127.0.0.1:$PORT, repo 127.0.0.1:$PORT/nexusbackup/appliance
#   image A  signed with the TEST key (pinned in os/etc) via `sign.sh sign`
#   image B  signed with the TEST key via the air-gapped path (payload / sign-payload / attach)
#   image C  signed with a freshly generated throwaway key that is NOT pinned
#   image D  unsigned
#   image G  signed with the throwaway key AND the TEST key (rotation overlap)
#   image F  carries a copy of A's signature (replay onto another digest)
#   image E  in another repository of the same registry (no policy scope -> default reject)
#
# Then release/verify.sh (cosign) and `podman pull` inside the appliance base image
# with the appliance's policy.json + registries.d installed as /etc/containers:
# expected A, B, G accepted; C, D, E, F rejected. Exit 0 only if every expectation holds.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
PORT=${PORT:-5055}
export NEXUS_IMAGE_REPO=127.0.0.1:$PORT/nexusbackup/appliance NEXUS_ALLOW_HTTP=1
. "$here/lib.sh"

work=$(mktemp -d)
reg=nexus-test-registry-$PORT
cleanup() {
	podman rm -f "$reg" >/dev/null 2>&1 || true
	rm -rf "$work"
}
trap cleanup EXIT

echo "== registry on 127.0.0.1:$PORT"
podman run -d --rm --name "$reg" -p "127.0.0.1:$PORT:5000" docker.io/library/registry:2 >/dev/null
for _ in $(seq 50); do curl -fs "http://127.0.0.1:$PORT/v2/" >/dev/null && break || sleep 0.2; done

push() { # name repo -> digest ref
	mkdir -p "$work/$1"
	echo "nexus test image $1 $(date +%s%N)" >"$work/$1/payload"
	printf 'FROM scratch\nCOPY payload /payload\n' >"$work/$1/Containerfile"
	podman build -q -t "localhost/nexus-signtest-$1" "$work/$1" >/dev/null
	podman push -q --tls-verify=false --digestfile "$work/$1.digest" "localhost/nexus-signtest-$1" "docker://$2:$1"
	podman rmi -f "localhost/nexus-signtest-$1" >/dev/null
	echo "$2@$(cat "$work/$1.digest")"
}

echo "== build + push test images"
A=$(push a "$NEXUS_IMAGE_REPO")
B=$(push b "$NEXUS_IMAGE_REPO")
C=$(push c "$NEXUS_IMAGE_REPO")
D=$(push d "$NEXUS_IMAGE_REPO")
E=$(push e "127.0.0.1:$PORT/someone/else")
printf '  %s\n' "$A" "$B" "$C" "$D" "$E"

echo "== throwaway key (generate-key-pair, offline)"
mkdir -p "$work/throwaway"
NEXUS_TOOL_NET=none tool_run -v "$work/throwaway:/k" -w /k -e COSIGN_PASSWORD=throwaway -- \
	"$COSIGN_IMAGE" generate-key-pair >/dev/null 2>&1
ls "$work/throwaway"

echo "== sign A (one step, pinned TEST key)"
COSIGN_KEY=$here/testkey/TEST-cosign.key COSIGN_PASSWORD=nexus-test-key "$here/sign.sh" sign "$A" 2>&1 | tail -1

echo "== sign B (air-gapped: payload -> offline sign-payload -> attach)"
"$here/sign.sh" payload "$B" "$work/b.json" 2>/dev/null
COSIGN_KEY=$here/testkey/TEST-cosign.key COSIGN_PASSWORD=nexus-test-key \
	"$here/sign.sh" sign-payload "$work/b.json" "$work/b.sig" 2>/dev/null
"$here/sign.sh" attach "$B" "$work/b.json" "$work/b.sig" 2>&1 | tail -1

echo "== sign C with the throwaway (not pinned) key"
COSIGN_KEY=$work/throwaway/cosign.key COSIGN_PASSWORD=throwaway "$here/sign.sh" sign "$C" 2>&1 | tail -1

echo "== sign G with BOTH keys (throwaway first, then TEST): key-rotation overlap"
G=$(push g "$NEXUS_IMAGE_REPO")
COSIGN_KEY=$work/throwaway/cosign.key COSIGN_PASSWORD=throwaway "$here/sign.sh" sign "$G" 2>&1 | tail -1
COSIGN_KEY=$here/testkey/TEST-cosign.key COSIGN_PASSWORD=nexus-test-key "$here/sign.sh" sign "$G" 2>&1 | tail -1

echo "== replay: copy A's signature onto image F (sig tag sha256-<F>.sig)"
F=$(push f "$NEXUS_IMAGE_REPO")
sigtag() { local d=${1#*@sha256:}; echo "$NEXUS_IMAGE_REPO:sha256-$d.sig"; }
podman run --rm --network host "$POLICY_CHECK_IMAGE" skopeo copy --quiet --insecure-policy \
	--src-tls-verify=false --dest-tls-verify=false "docker://$(sigtag "$A")" "docker://$(sigtag "$F")"

fail=0
expect() { # want(accept|reject) label cmd...
	local want=$1 label=$2 got
	shift 2
	if "$@" >"$work/out" 2>&1; then got=accept; else got=reject; fi
	if [ "$got" = "$want" ]; then
		printf '  ok    %-34s %s\n' "$label" "$got"
	else
		printf '  FAIL  %-34s %s (want %s)\n' "$label" "$got" "$want"
		sed 's/^/        /' "$work/out"
		fail=1
	fi
	# the reason, without the long image reference
	grep -ohE 'Source image rejected: [^"]*|no valid signature from a pinned key' "$work/out" | head -1 |
		cut -c1-150 | sed 's/^/        /' || true
}

echo "== release/verify.sh (cosign, pinned keys from os/etc)"
expect accept "verify A" "$here/verify.sh" "$A"
expect accept "verify B (air-gapped)" "$here/verify.sh" "$B"
expect reject "verify C (wrong key)" "$here/verify.sh" "$C"
expect reject "verify D (unsigned)" "$here/verify.sh" "$D"
expect reject "verify F (replayed signature)" "$here/verify.sh" "$F"
expect accept "verify C with throwaway key" env VERIFY_KEYS="$work/throwaway/cosign.pub" "$here/verify.sh" "$C"

echo "== podman pull inside the appliance base image with the appliance policy"
render_trust "$work/trust"
pull() { # ref: podman pull as the appliance would (its /etc/containers replaced by ours)
	podman run --rm --privileged --network host --security-opt label=disable \
		-v "$work/trust/etc/containers/policy.json:/etc/containers/policy.json:ro" \
		-v "$work/trust/etc/containers/registries.d/nexus-appliance.yaml:/etc/containers/registries.d/nexus-appliance.yaml:ro" \
		-v "$work/trust/etc/pki/nexus:/etc/pki/nexus:ro" \
		"$POLICY_CHECK_IMAGE" podman --storage-driver vfs pull -q --tls-verify=false "docker://$1"
}
expect accept "podman pull A (signed)" pull "$A"
expect accept "podman pull B (air-gapped)" pull "$B"
expect reject "podman pull C (wrong key)" pull "$C"
expect reject "podman pull D (unsigned)" pull "$D"
expect reject "podman pull E (other repo)" pull "$E"
expect reject "podman pull F (replayed signature)" pull "$F"
expect accept "podman pull G (dual-signed)" pull "$G"
expect accept "podman pull A by tag :a" pull "$NEXUS_IMAGE_REPO:a"
expect reject "podman pull D by tag :d" pull "$NEXUS_IMAGE_REPO:d"

echo "== release/verify.sh --policy (skopeo, same policy)"
expect accept "verify --policy A" "$here/verify.sh" --policy "$A"
expect reject "verify --policy C" env VERIFY_KEYS="$work/throwaway/cosign.pub" "$here/verify.sh" --policy "$C"

echo "== release/promote.sh (channel tag)"
expect accept "promote A -> :stable" "$here/promote.sh" "$A" stable
expect reject "promote D (unsigned) -> :stable" "$here/promote.sh" "$D" stable
expect accept "podman pull :stable (= A)" pull "$NEXUS_IMAGE_REPO:stable"
got=$(podman run --rm --network host "$POLICY_CHECK_IMAGE" skopeo inspect --tls-verify=false \
	--format '{{.Digest}}' "docker://$NEXUS_IMAGE_REPO:stable")
[ "$got" = "${A#*@}" ] && echo "  ok    :stable digest is A's" || { echo "  FAIL  :stable is $got"; fail=1; }

[ $fail = 0 ] && echo "ALL EXPECTATIONS MET" || echo "SOME EXPECTATIONS FAILED"
exit $fail
