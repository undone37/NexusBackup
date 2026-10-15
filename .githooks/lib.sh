# Shared by the hooks in .githooks (sourced). Enable the hooks once per clone:
#   git config core.hooksPath .githooks
# Skip them for one commit / push with --no-verify (CI runs the same checks).
fail() {
	printf '%s: %s\n' "${0##*/}" "$*" >&2
	exit 1
}
step() { printf '%s: %s\n' "${0##*/}" "$*" >&2; }

# has PATTERN FILE...: true if one of the files matches the extended regex
has() {
	local re=$1
	shift
	printf '%s\n' "$@" | grep -Eq "$re"
}

# prettier from web/node_modules (pinned in web/package.json), never a download
prettier() {
	[ -x web/node_modules/.bin/prettier ] || fail "web/node_modules missing: (cd web && npm ci --ignore-scripts)"
	(cd web && node_modules/.bin/prettier "$@")
}
