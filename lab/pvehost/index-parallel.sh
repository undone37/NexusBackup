#!/usr/bin/env bash
# Several groups with index-files on, backed up at once (#71, plan.md Phase 39 L11: "several groups at once"), on
# the appliance VM through the tunnel of deploy.sh: one backup job per group started together (groups of different
# PVE sources run in parallel), then every backup's file_index job; prints when each job ran, so the overlap shows,
# and checks that the instant search finds a known file (/etc/os-release; on Windows desktop.ini: the default scope
# leaves the system folders out) in every new snapshot.
#
#   index-parallel.sh GROUP...   default: index-debian-13 (pve-test) thin-220 (the nested node, thin-guest.sh)
#
# env: LAB, PORT (as deploy.sh)
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
export LAB=${LAB:-$HOME/nexus-lab/pvehost}
export PORT=${PORT:-28444}
ROOT=$LAB/appliance/root
S=$ROOT/run/api
mkdir -p "$S"
# shellcheck disable=SC1091
. "$ROOT/secrets.env"
# shellcheck source=lab/e2e/api-lib.sh
. "$repo/lab/e2e/api-lib.sh"
login admin "$ADMIN_PW" "$ADMIN_TOTP"
[ $# -gt 0 ] || set -- index-debian-13 thin-220

declare -A job
for name in "$@"; do
	g=$(api admin GET /groups | jq -r --arg n "$name" '.[] | select(.name == $n) | .id')
	[ -n "$g" ] || die "no group $name"
	api admin PUT "/groups/$g/index-files" '{"enabled":true}' >/dev/null
	job[$name]=$(api admin POST /jobs "$(jq -nc --argjson g "$g" '{kind:"backup", tenant:"lab", params:{group_id:$g}}')" | jq -r .id)
	expect 202 "backup $name"
done
log "backups started: $(for n in "$@"; do printf '%s=%s ' "$n" "${job[$n]}"; done)"
t0=$(date +%s)
declare -A src stamp
for name in "$@"; do
	j=$(wait_job admin "${job[$name]}" 3600)
	[ "$(jq -r .state <<<"$j")" = ok ] || die "$name backup: $(jq -r '.log // ""' <<<"$j" | tail -n 8)"
	read -r src[$name] stamp[$name] <<<"$(jq -r '.log // ""' <<<"$j" | sed -n 's|^committed \([a-z]*-[0-9]*\)/\([0-9]*\).*|\1 \2|p' | tail -1)"
	log "$name backup: job ${job[$name]} ran $(jq -r '"\(.started - '"$t0"') .. \(.finished - '"$t0"') s"' <<<"$j") after the start; ${src[$name]}/${stamp[$name]}"
done
for name in "$@"; do
	idx=
	for _ in $(seq 60); do
		idx=$(api admin GET '/jobs?limit=40' | jq -r --arg s "${src[$name]}" --argjson t "${stamp[$name]}" \
			'[.[] | select(.kind == "file_index" and .params.source == $s and .params.time == $t)][0].id // empty')
		[ -n "$idx" ] && break
		sleep 5
	done
	[ -n "$idx" ] || die "$name: no file_index job"
	j=$(wait_job admin "$idx" 3600)
	[ "$(jq -r .state <<<"$j")" = ok ] || die "$name file_index: $(jq -r '.log // ""' <<<"$j" | tail -n 8)"
	log "$name file_index: job $idx ran $(jq -r '"\(.started - '"$t0"') .. \(.finished - '"$t0"') s"' <<<"$j"), $(jq -c '.result | {entries, elapsed_ms}' <<<"$j")"
done
for name in "$@"; do
	hits=0 tn=
	tn=$(api admin GET /groups | jq -r --arg n "$name" '.[] | select(.name == $n) | .tenant')
	for _ in $(seq 24); do
		for f in os-release desktop.ini; do
			hits=$(api admin GET "/files/search?tenant=$tn&q=$f&source=${src[$name]}" |
				jq --argjson t "${stamp[$name]}" --arg f "$f" '[.hits[]? | select((.path | ascii_downcase | endswith($f)) and ([.versions[]?.times[]?] | any(. == $t)))] | length')
			[ "$hits" -gt 0 ] && break 2
		done
		sleep 5
	done
	[ "$hits" -gt 0 ] || die "$name: no system file found in ${src[$name]}/${stamp[$name]}"
	log "$name: instant search finds $f in ${src[$name]}/${stamp[$name]}"
done
