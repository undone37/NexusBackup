# Shared helpers for release/*.sh (sourced, not executed).
# shellcheck shell=bash

RELEASE_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(dirname "$RELEASE_DIR")

# Load release/config.env; variables already set in the environment win.
while IFS='=' read -r k v; do
	[[ $k =~ ^[A-Z_][A-Z0-9_]*$ ]] || continue
	[ -n "${!k+x}" ] || export "$k=$v"
done <"$RELEASE_DIR/config.env"

die() {
	echo "${0##*/}: $*" >&2
	exit 1
}

# IMAGE@sha256:<64 hex> only: signing or verifying a tag is a time-of-check/time-of-use gap.
require_digest_ref() {
	[[ $1 =~ ^[a-z0-9.:-]+(/[a-z0-9._-]+)+@sha256:[0-9a-f]{64}$ ]] ||
		die "need IMAGE@sha256:<digest>, got '$1'"
}

repo_of() { echo "${1%@*}"; }

# The repository the reference points into must be the one appliances trust.
require_trusted_repo() {
	[ "$(repo_of "$1")" = "$NEXUS_IMAGE_REPO" ] ||
		die "$(repo_of "$1") is not NEXUS_IMAGE_REPO ($NEXUS_IMAGE_REPO)"
}

# Registry credentials: podman's auth file, mounted read-only as the docker config
# cosign/oras read. REGISTRY_AUTH_FILE overrides the default location.
auth_file() {
	local f=${REGISTRY_AUTH_FILE:-${XDG_RUNTIME_DIR:-/run/user/$(id -u)}/containers/auth.json}
	[ -f "$f" ] && echo "$f"
}

# tool_run [podman-run-options...] -- IMAGE [ARGS...]
# --user 0 is the invoking user under rootless podman. NEXUS_TOOL_NET (default host)
# lets a 127.0.0.1 test registry be reached; offline steps set NEXUS_TOOL_NET=none.
tool_run() {
	local opts=()
	while [ "$1" != -- ]; do
		opts+=("$1")
		shift
	done
	shift
	local args=(--rm --user 0 --network "${NEXUS_TOOL_NET:-host}" --security-opt label=disable)
	local af
	if af=$(auth_file); then
		args+=(-v "$af:/auth/config.json:ro" -e DOCKER_CONFIG=/auth)
	fi
	[ -t 0 ] && [ -t 1 ] && args+=(-it)
	# extra podman options, e.g. NEXUS_TOOL_ARGS=--add-host=nexus-lab-registry:127.0.0.1
	# shellcheck disable=SC2206
	[ -n "${NEXUS_TOOL_ARGS:-}" ] && args+=(${NEXUS_TOOL_ARGS})
	podman run "${args[@]}" "${opts[@]}" "$@"
}

# Repository literal used in the os/etc trust files (equal to config.env unless a fork
# overrides NEXUS_IMAGE_REPO in the environment, e.g. the local test registry).
os_etc_repo() { sed -n 's/^NEXUS_IMAGE_REPO=//p' "$REPO_ROOT/os/etc/nexus/update.conf"; }

# render_trust DIR: the appliance's policy.json, registries.d and pinned keys, with the
# repository replaced by $NEXUS_IMAGE_REPO. Layout: DIR/etc/containers/..., DIR/etc/pki/...
render_trust() {
	local d=$1 from
	from=$(os_etc_repo)
	mkdir -p "$d/etc/containers/registries.d" "$d/etc/pki/nexus"
	sed "s|\"$from\"|\"$NEXUS_IMAGE_REPO\"|" "$REPO_ROOT/os/etc/containers/policy.json" \
		>"$d/etc/containers/policy.json"
	sed "s|^  $from:|  $NEXUS_IMAGE_REPO:|" "$REPO_ROOT/os/etc/containers/registries.d/nexus-appliance.yaml" \
		>"$d/etc/containers/registries.d/nexus-appliance.yaml"
	cp -r "$REPO_ROOT/os/etc/pki/nexus/cosign" "$d/etc/pki/nexus/"
	grep -q "\"$NEXUS_IMAGE_REPO\"" "$d/etc/containers/policy.json" || die "render_trust: repo not substituted"
}

# Public keys the appliance pins: keyPaths of the repo's policy, mapped into os/etc.
pinned_keys() {
	jq -r --arg r "$(os_etc_repo)" '.transports.docker[$r][] | select(.type=="sigstoreSigned") | .keyPaths[]' \
		"$REPO_ROOT/os/etc/containers/policy.json" | sed "s|^/etc/|$REPO_ROOT/os/etc/|"
}

# cosign flags for a plain-HTTP test registry (NEXUS_ALLOW_HTTP=1, local demo only)
http_flags() {
	[ "${NEXUS_ALLOW_HTTP:-0}" = 1 ] && echo "--allow-http-registry --allow-insecure-registry"
	return 0
}
