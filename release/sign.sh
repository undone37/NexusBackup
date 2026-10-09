#!/bin/bash
# Sign a released appliance image with the offline release key (docs/release.md).
# cosign runs from its official image via podman; nothing is installed on the host.
# No transparency log (--tlog-upload=false): appliances verify against the pinned
# public key only and never talk to Rekor/Fulcio.
#
# One step, on a machine that holds the key and can reach the registry:
#   release/sign.sh sign IMAGE@sha256:...
#
# Air-gapped key (the key never touches a networked machine):
#   online:   release/sign.sh payload IMAGE@sha256:... payload.json
#   offline:  release/sign.sh sign-payload payload.json payload.sig     (runs with --network none)
#   online:   release/sign.sh attach IMAGE@sha256:... payload.json payload.sig
#
# Key selection (environment):
#   COSIGN_KEY=/path/to/cosign.key   encrypted key file from `cosign generate-key-pair`
#                                    (default ./cosign.key); passphrase from
#                                    COSIGN_PASSWORD or prompted on the terminal
#   COSIGN_PKCS11_URI='pkcs11:token=...;slot-id=0;id=%01?module-path=/usr/lib64/...so&pin-value=...'
#                                    HSM/smartcard instead of a key file. The official cosign
#                                    image is built without PKCS#11: set COSIGN_IMAGE to a
#                                    cosign build with `-tags pkcs11key` and COSIGN_PKCS11_RUN
#                                    to the extra podman options it needs (module, device).
#   NEXUS_ALLOW_HTTP=1               plain-HTTP registry (local test registry only)
#   NEXUS_IMAGE_REPO                 trusted repository (default from release/config.env)
set -euo pipefail
. "$(dirname "$0")/lib.sh"

key_opts() { # podman options + cosign --key argument for the selected key
	if [ -n "${COSIGN_PKCS11_URI:-}" ]; then
		# shellcheck disable=SC2206
		KEY_PODMAN=(${COSIGN_PKCS11_RUN:-})
		KEY_ARG=$COSIGN_PKCS11_URI
	else
		local k=${COSIGN_KEY:-./cosign.key}
		[ -f "$k" ] || die "key file $k not found (set COSIGN_KEY)"
		KEY_PODMAN=(-v "$(realpath "$k"):/key/cosign.key:ro")
		KEY_ARG=/key/cosign.key
	fi
	[ -n "${COSIGN_PASSWORD+x}" ] && KEY_PODMAN+=(-e COSIGN_PASSWORD)
	return 0
}

cmd=${1:-}
case $cmd in
sign)
	[ $# = 2 ] || die "usage: sign IMAGE@sha256:..."
	require_digest_ref "$2"
	require_trusted_repo "$2"
	key_opts
	# shellcheck disable=SC2046
	tool_run "${KEY_PODMAN[@]}" -- "$COSIGN_IMAGE" sign --yes --tlog-upload=false \
		--key "$KEY_ARG" $(http_flags) "$2"
	echo "signed $2" >&2
	;;
payload)
	[ $# = 3 ] || die "usage: payload IMAGE@sha256:... OUT.json"
	require_digest_ref "$2"
	require_trusted_repo "$2"
	# shellcheck disable=SC2046
	tool_run -- "$COSIGN_IMAGE" generate $(http_flags) "$2" >"$3"
	grep -q "\"docker-manifest-digest\":\"${2#*@}\"" "$3" || die "payload does not name ${2#*@}"
	echo "payload for $2 written to $3; carry it to the offline machine" >&2
	;;
sign-payload)
	[ $# = 3 ] || die "usage: sign-payload PAYLOAD.json OUT.sig"
	[ -f "$2" ] || die "$2 not found"
	key_opts
	in=$(realpath "$2")
	out_dir=$(realpath "$(dirname "$3")")
	# Show what is being signed: the operator compares the digest with the CI output.
	echo "signing payload:" >&2
	cat "$in" >&2
	echo >&2
	NEXUS_TOOL_NET=none tool_run "${KEY_PODMAN[@]}" -v "$in:/in/payload.json:ro" \
		-v "$out_dir:/out" -- "$COSIGN_IMAGE" sign-blob --yes --tlog-upload=false \
		--key "$KEY_ARG" --output-signature "/out/$(basename "$3")" /in/payload.json >/dev/null
	echo "signature written to $3; carry it back with the payload" >&2
	;;
attach)
	[ $# = 4 ] || die "usage: attach IMAGE@sha256:... PAYLOAD.json PAYLOAD.sig"
	require_digest_ref "$2"
	require_trusted_repo "$2"
	grep -q "\"docker-manifest-digest\":\"${2#*@}\"" "$3" || die "$3 is not the payload for $2"
	# shellcheck disable=SC2046
	tool_run -v "$(realpath "$3"):/in/payload.json:ro" -v "$(realpath "$4"):/in/payload.sig:ro" -- \
		"$COSIGN_IMAGE" attach signature $(http_flags) --payload /in/payload.json \
		--signature /in/payload.sig "$2"
	echo "signature attached to $2; run release/verify.sh before promoting" >&2
	;;
*)
	sed -n '2,/^set -euo/p' "$0" | sed '$d; s/^# \{0,1\}//' >&2
	exit 2
	;;
esac
