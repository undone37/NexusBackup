#!/usr/bin/env bash
# nexusctl fleet against two appliances of the PVE lab host (#75, plan.md Phase 39 L15): the appliance VMs of
# deploy.sh (LAB dirs $LABS, each with its own CA and tunnel port), read-scoped API tokens, the overview over both
# plus an address where no appliance answers, the static HTML report; a write-scoped token is refused.
#
#   fleet.sh tokens   a read token (1 day) on every appliance, files in $OUT (0600), the fleet config
#   fleet.sh run      `nexusctl fleet --check` and `--html`: both appliances answer, the third is unreachable
#   fleet.sh write    a token with operator scope (it can change things) in the config: refused by nexusctl
#
# env: LABS ("~/nexus-lab/pvehost:28444:10.2.34.211 ~/nexus-lab/pvehost2:28445:10.2.34.212": LAB dir, tunnel port,
#      address), NEXUSCTL (target/release/nexusctl), OUT (~/nexus-lab/scratch/fleet)
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
LABS=${LABS:-"$HOME/nexus-lab/pvehost:28444:10.2.34.211 $HOME/nexus-lab/pvehost2:28445:10.2.34.212"}
NEXUSCTL=${NEXUSCTL:-$repo/target/release/nexusctl}
OUT=${OUT:-$HOME/nexus-lab/scratch/fleet}
mkdir -p "$OUT"
chmod 700 "$OUT"
T0=$(date +%s)
log() { printf '[%4ss] %s\n' $(($(date +%s) - T0)) "$*" >&2; }
die() {
	log "FAIL: $*"
	exit 1
}

token() { # token LAB PORT SCOPE NAME -> the token
	(
		export LAB=$1 PORT=$2
		ROOT=$LAB/appliance/root
		S=$ROOT/run/api
		# shellcheck disable=SC1091
		. "$ROOT/secrets.env"
		# shellcheck source=lab/e2e/api-lib.sh
		. "$repo/lab/e2e/api-lib.sh"
		login admin "$ADMIN_PW" "$ADMIN_TOTP" 2>/dev/null
		code=$(fresh_code admin "$ADMIN_TOTP")
		api admin POST /auth/tokens "$(jq -nc --arg n "$4" --arg s "$3" --arg p "$ADMIN_PW" --arg t "$code" \
			'{name:$n, scope:$s, days:1, current_password:$p, current_totp:$t}')" | jq -r '.token // empty'
		[ "$(status)" = 201 ] || [ "$(status)" = 200 ] || die "token on $LAB: HTTP $(status) $(cat "$S/body")"
	)
}

config() { # config SCOPE: the fleet config with tokens of that scope
	local i=0 lab port addr apps='[]'
	for e in $LABS; do
		IFS=: read -r lab port addr <<<"$e"
		i=$((i + 1))
		apps=$(jq -c --arg n "lab$i" --arg u "https://$addr:8443" --arg t "$OUT/lab$i-$1.token" \
			--arg c "$lab/appliance/root/etc/nexus/tls/cert.pem" '. + [{name:$n, url:$u, token_file:$t, ca:$c}]' <<<"$apps")
	done
	# an address where no appliance answers: reported as unreachable, the others still are
	apps=$(jq -c --arg c "$OUT/lab1-$1.token" '. + [{name:"gone", url:"https://192.0.2.1:8443", token_file:$c}]' <<<"$apps")
	jq -n --argjson a "$apps" '{appliances: $a}' >"$OUT/fleet-$1.json"
}

step_tokens() {
	local i=0 lab port addr s
	for e in $LABS; do
		IFS=: read -r lab port addr <<<"$e"
		i=$((i + 1))
		for s in read operator; do
			(umask 077 && token "$lab" "$port" "$s" "fleet-lab-$s-$(date +%s)" >"$OUT/lab$i-$s.token")
			[ -s "$OUT/lab$i-$s.token" ] || die "no $s token from $lab"
		done
		log "lab$i ($addr): read and write tokens"
	done
	config read
	config operator
}

step_run() {
	local rc=0
	"$NEXUSCTL" fleet --config "$OUT/fleet-read.json" --check >"$OUT/check.txt" 2>&1 || rc=$?
	cat "$OUT/check.txt" >&2
	grep -qi "lab1" "$OUT/check.txt" && grep -qi "lab2" "$OUT/check.txt" || die "an appliance is missing in the overview"
	grep -qiE "gone.*(unreachable|not reach|error|timed out|connect)" "$OUT/check.txt" || die "the unreachable appliance is not reported as such"
	"$NEXUSCTL" fleet --config "$OUT/fleet-read.json" --html "$OUT/fleet.html" >/dev/null 2>&1 || true
	[ -s "$OUT/fleet.html" ] || die "no HTML report"
	log "fleet overview: both appliances, the unreachable one reported (--check exit $rc), HTML report $OUT/fleet.html"
}

step_write() {
	local rc=0
	"$NEXUSCTL" fleet --config "$OUT/fleet-operator.json" --check >"$OUT/write.txt" 2>&1 || rc=$?
	grep -qiE "read|scope" "$OUT/write.txt" || die "an operator-scoped token was not refused: $(head -c 400 "$OUT/write.txt")"
	log "operator-scoped tokens refused (exit $rc): $(grep -iE 'read|scope' "$OUT/write.txt" | head -2 | tr '\n' ' ' | cut -c1-200)"
}

for s in "${@:-tokens run write}"; do
	for x in $s; do
		log "== $x"
		"step_$x"
	done
done
