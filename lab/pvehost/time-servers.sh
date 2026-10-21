#!/usr/bin/env bash
# Settings > Time on the appliance VM of the PVE lab host (docs/control-plane.md "Time servers"), through
# the tunnel of lab/pvehost/deploy.sh: change the time servers through the API (approved by the security
# officer if approvals are on), wait until nexus-time applied them and chronyd uses them, check the
# firewall set, the refusal of plain NTP without the opt-in, then restore the previous list.
#
#   time-servers.sh [check]       the whole run (default)
#   time-servers.sh status        GET /settings/time
#
# env: LAB (~/nexus-lab/pvehost), PORT (28444), SERVERS (JSON list for the test, default two of the
# image's NTS servers)
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
export LAB=${LAB:-$HOME/nexus-lab/pvehost}
export ROOT=$LAB/appliance/root PORT=${PORT:-28444} CONSOLE=$LAB/appliance/console.sock
S=$LAB/appliance/run-time
mkdir -p "$S"
eval "$(ROOT=$ROOT PORT=$PORT "$repo/lab/e2e/m5.sh" env)"
# shellcheck source=lab/e2e/api-lib.sh
# shellcheck disable=SC1090
. "$repo/lab/e2e/api-lib.sh"
con() { "$repo/lab/appliance/con.py" run "$1"; }
SERVERS=${SERVERS:-'[{"host":"ptbtime1.ptb.de","nts":true},{"host":"nts.netnod.se","nts":true}]'}

get_time() { api admin GET /settings/time; }

put_time() { # put_time SERVERS ALLOW_NTP: request, approve if needed, wait for the helper's outcome
	local body r q before
	before=$(get_time | jq '.last.time // 0')
	body=$(jq -nc --argjson s "$1" --argjson a "$2" '{servers: $s, allow_ntp: $a}')
	r=$(api admin PUT /settings/time "$body")
	[ "$(status)" = 200 ] || [ "$(status)" = 202 ] || die "PUT /settings/time: HTTP $(status) $r"
	q=$(jq -r '.quorum_id // empty' <<<"$r")
	if [ -n "$q" ] && [ "$(status)" = 202 ]; then
		login so "$SO_PW" "$SO_TOTP"
		api so POST "/quorum/$q/approve" '{}' >/dev/null
		expect 200 "approve time.servers"
	fi
	for _ in $(seq 60); do
		get_time | jq -e --argjson t "$before" '.last.time > $t' >/dev/null && break
		sleep 2
	done
	get_time | jq -c '.last'
}

step_check() {
	login admin "$ADMIN_PW" "$ADMIN_TOTP"
	local old
	old=$(get_time | jq -c '.servers')
	log "configured: $old"

	log "plain NTP without the opt-in is refused at once"
	api admin PUT /settings/time '{"servers":[{"host":"ntp.internal.example","nts":false}],"allow_ntp":false}' >/dev/null
	expect 400 "plain NTP without allow_ntp"

	log "switching to $SERVERS"
	put_time "$SERVERS" false | grep -q '"result":"applied"' || die "not applied: $(get_time | jq -c .last)"
	# chronyd restarted with the new list (the helper reads the sources 15 s after the restart)
	for _ in $(seq 30); do
		get_time | jq -e --argjson want "$SERVERS" '([.sources[].name] | sort) == ([$want[].host] | sort)' >/dev/null && break
		sleep 5
	done
	get_time | jq -e --argjson want "$SERVERS" '([.sources[].name] | sort) == ([$want[].host] | sort)' >/dev/null ||
		die "chronyd does not use the new servers: $(get_time | jq -c '[.sources[].name]')"
	log "chronyd uses them: $(get_time | jq -c '[.sources[] | {name, state, nts}]')"
	for _ in $(seq 30); do
		get_time | jq -e '[.sources[] | select(.state == "selected" or .state == "combined")] | length > 0' >/dev/null && break
		sleep 10
	done
	log "tracking: $(get_time | jq -c '.tracking')"
	con 'cat /etc/nexus/time/chrony.conf; nft list set inet nexus nts_servers_v4 | grep elements; ausearch -m avc -ts recent 2>/dev/null | grep -c "type=AVC" || true' | tail -12

	log "restoring $old"
	put_time "$old" false | grep -q '"result":"applied"' || die "restore not applied"
	log "done: $(get_time | jq -c '{servers, synced: .tracking.synced}')"
}

cmd=${1:-check}
case $cmd in
check) step_check ;;
status) login admin "$ADMIN_PW" "$ADMIN_TOTP" && get_time | jq . ;;
*) sed -n 2,11p "$0" && exit 2 ;;
esac
