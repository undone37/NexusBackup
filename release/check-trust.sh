#!/bin/bash
# Consistency check of what the appliance trusts (os/etc), run by CI before building.
#
#   release/check-trust.sh            development tree (the TEST key is allowed)
#   release/check-trust.sh --release  release build: only keys from release/keys/ (image
#                                     and plugin keys), no TEST key anywhere in os/etc
#
# Checks: policy.json default is reject, nothing anywhere is insecureAcceptAnything,
# the only scope is NEXUS_IMAGE_REPO (release/config.env) with sigstoreSigned +
# matchRepository; registries.d and update.conf name the same repository; every
# pinned key exists and is an EC/RSA public key; no unreferenced key files; at least
# one project plugin key (pki/nexus/plugin-keys), all PEM public keys (--release: exactly
# the release keys, never the TEST key).
set -euo pipefail
. "$(dirname "$0")/lib.sh"

release=0
[ "${1:-}" = --release ] && release=1
repo=$(sed -n 's/^NEXUS_IMAGE_REPO=//p' "$RELEASE_DIR/config.env")
etc=$REPO_ROOT/os/etc
pol=$etc/containers/policy.json
err=0
bad() {
	echo "check-trust: $*" >&2
	err=1
}

jq -e . "$pol" >/dev/null || die "$pol is not valid JSON"
jq -e '.default == [{"type": "reject"}]' "$pol" >/dev/null || bad "policy default must be [{type: reject}]"
jq -e '[.. | objects | select(.type? == "insecureAcceptAnything")] | length == 0' "$pol" >/dev/null ||
	bad "policy contains insecureAcceptAnything"
jq -e --arg r "$repo" '(.transports | keys) == ["docker"] and (.transports.docker | keys) == [$r]' "$pol" >/dev/null ||
	bad "policy must have exactly one scope: docker $repo"
jq -e --arg r "$repo" '.transports.docker[$r] | length > 0 and all(.[];
	.type == "sigstoreSigned" and (.keyPaths | length) > 0 and .signedIdentity.type == "matchRepository"
	and (has("rekorPublicKeyPath") or has("rekorPublicKeyPaths") or has("fulcio") | not))' "$pol" >/dev/null ||
	bad "rules for $repo must be sigstoreSigned + keyPaths + matchRepository, no rekor/fulcio"

grep -qx "  $repo:" "$etc/containers/registries.d/nexus-appliance.yaml" &&
	grep -qx "    use-sigstore-attachments: true" "$etc/containers/registries.d/nexus-appliance.yaml" ||
	bad "registries.d/nexus-appliance.yaml must enable sigstore attachments for $repo"
[ "$(sed -n 's/^NEXUS_IMAGE_REPO=//p' "$etc/nexus/update.conf")" = "$repo" ] ||
	bad "os/etc/nexus/update.conf NEXUS_IMAGE_REPO differs from release/config.env ($repo)"

mapfile -t keys < <(jq -r '.. | objects | .keyPaths? // empty | .[]' "$pol" | sort -u)
for k in "${keys[@]}"; do
	[[ $k == /etc/pki/nexus/cosign/*.pub ]] || bad "key $k must live in /etc/pki/nexus/cosign/"
	f=$etc/${k#/etc/}
	if [ ! -f "$f" ]; then
		bad "pinned key $k missing in os/etc"
	elif ! sed -n '/-----BEGIN PUBLIC KEY-----/,/-----END PUBLIC KEY-----/p' "$f" |
		openssl pkey -pubin -noout 2>/dev/null; then
		bad "$k is not a PEM public key"
	fi
done
for f in "$etc"/pki/nexus/cosign/*; do
	printf '%s\n' "${keys[@]}" | grep -qx "/etc/${f#"$etc"/}" || bad "unreferenced key file ${f#"$REPO_ROOT"/}"
done

# Project plugin keys (docs/plugin-system.md): at least one PEM public key, file names
# safe for the installer's key listing.
pkeys=("$etc"/pki/nexus/plugin-keys/*)
[ -e "${pkeys[0]}" ] || bad "no project plugin key in os/etc/pki/nexus/plugin-keys"
for f in "${pkeys[@]}"; do
	[ -e "$f" ] || continue
	n=$(basename "$f")
	[[ $n =~ ^[A-Za-z0-9._-]+\.pub$ ]] || bad "plugin key file name $n (want <name>.pub)"
	sed -n '/-----BEGIN PUBLIC KEY-----/,/-----END PUBLIC KEY-----/p' "$f" | openssl pkey -pubin -noout 2>/dev/null ||
		bad "plugin key $n is not a PEM public key"
done

if [ $release = 1 ]; then
	if grep -rlq "NEXUS TEST KEY" "$etc" || printf '%s\n' "${keys[@]}" | grep -q TEST; then
		bad "release build still pins the TEST key (run release/inject-keys.sh)"
	fi
	want=$(cat "$RELEASE_DIR"/keys/*.pub 2>/dev/null | sha256sum || true)
	have=$(for k in "${keys[@]}"; do cat "$etc/${k#/etc/}"; done | sha256sum)
	[ "$want" = "$have" ] || bad "pinned keys differ from release/keys/*.pub"
	# plugin keys: no TEST key (by name, marker or key material), exactly the release keys
	testpem=$(sed -n '/-----BEGIN/,/-----END/p' "$RELEASE_DIR/testkey/TEST-cosign.pub")
	for f in "${pkeys[@]}"; do
		[ -e "$f" ] || continue
		if [[ $(basename "$f") == *TEST* ]] || grep -q "NEXUS TEST KEY" "$f" ||
			[ "$(sed -n '/-----BEGIN/,/-----END/p' "$f")" = "$testpem" ]; then
			bad "release build ships the TEST plugin key ${f#"$REPO_ROOT"/} (run release/inject-keys.sh)"
		fi
	done
	have=$(for f in "${pkeys[@]}"; do [ ! -e "$f" ] || cat "$f"; done | sha256sum)
	[ "$want" = "$have" ] || bad "plugin keys differ from release/keys/*.pub"
fi

[ $err = 0 ] && echo "check-trust: ok ($repo, ${#keys[@]} key(s)$([ $release = 1 ] && echo ', release'))"
exit $err
