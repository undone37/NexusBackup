#!/usr/bin/env bash
# Fault injection on the appliance VM of the PVE lab (plan.md Phase 44): a backup of a guest of group $GROUP (VM 242
# by default: 40 GB, ours) is interrupted, then the outcome is checked against what must happen.
#
#   faults.sh group     the group $GROUP with guest $VMID (deploy.sh groups)
#   faults.sh reboot    the appliance reboots while the backup reads: after the restart the job is failed (not left
#                       "running"), no snapshot of that run exists, and the next backup succeeds
#   faults.sh netloss   the appliance's traffic to the PVE host is dropped for $LOSS seconds while the backup reads:
#                       the job either finishes after the outage or fails with a clear error; a retry succeeds
#
# env: as deploy.sh (LAB ~/nexus-lab/pvehost, PORT 28444, PVE_HOST); GROUP (fault), VMID (242), LOSS (120),
#      AFTER (bytes read before the fault, 3000000000)
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
export LAB=${LAB:-$HOME/nexus-lab/pvehost}
export PORT=${PORT:-28444}
PVE_HOST=${PVE_HOST:-10.2.34.200}
GROUP=${GROUP:-fault}
VMID=${VMID:-242}
LOSS=${LOSS:-120}
AFTER=${AFTER:-3000000000}
ROOT=$LAB/appliance/root
S=$ROOT/run/api
export CONSOLE=$LAB/appliance/console.sock
con() { "$here/../appliance/con.py" "$@"; }
mkdir -p "$S"
# shellcheck disable=SC1091
. "$ROOT/secrets.env"
# shellcheck source=lab/e2e/api-lib.sh
. "$repo/lab/e2e/api-lib.sh"

gid() { api admin GET /groups | jq -r --arg n "$GROUP" '.[] | select(.name == $n) | .id'; }
snaps() { api admin GET '/snapshots?tenant=lab' | jq -c --arg s "vm-$VMID" '[.[] | select(.source == $s) | .time]'; }

# starts a backup of the group and returns once it has read $AFTER bytes (or ran 5 minutes)
start_and_wait() {
	local r id done=0
	local g
	g=$(gid)
	r=$(api admin POST /jobs "$(jq -nc --argjson g "$g" '{kind:"backup", tenant:"lab", params:{group_id:$g}}')")
	expect 202 "backup of $GROUP"
	id=$(jq -r .id <<<"$r")
	for _ in $(seq 300); do
		r=$(api admin GET "/jobs/$id")
		done=$(jq -r '.progress.done // 0' <<<"$r")
		[ "${done%.*}" -ge "$AFTER" ] 2>/dev/null && break
		[ "$(jq -r .state <<<"$r")" = running ] || [ "$(jq -r .state <<<"$r")" = queued ] || die "job $id ended before the fault: $(jq -r .state <<<"$r")"
		sleep 1
	done
	log "job $id has read $done bytes"
	echo "$id"
}

# the newest backup job of the group after $1, waited for
next_job() {
	local id g jobs
	g=$(gid) # not inside the pipeline below: both calls would write api-lib's one response file at once
	for _ in $(seq 120); do
		jobs=$(api admin GET '/jobs?tenant=lab&limit=50')
		id=$(jq -r --argjson g "$g" --argjson a "$1" \
			'[.[] | select(.kind == "backup" and .params.group_id == $g and .id > $a)] | sort_by(.id) | .[0].id // empty' <<<"$jobs")
		[ -n "$id" ] && break
		sleep 5
	done
	[ -n "$id" ] || return 1
	wait_job admin "$id" 3600
}

step_group() {
	LAB_GROUPS="$GROUP:$VMID" "$here/deploy.sh" groups
}

step_reboot() {
	login admin "$ADMIN_PW" "$ADMIN_TOTP"
	local before id j
	before=$(snaps)
	id=$(start_and_wait)
	log "rebooting the appliance during job $id"
	con run 'systemd-run --on-active=2 systemctl reboot >/dev/null' 30 >/dev/null || true
	sleep 30
	for _ in $(seq 60); do
		curl -sk -m 5 -o /dev/null "https://127.0.0.1:$PORT/api/v1/auth/me" 2>/dev/null && break
		sleep 10
	done
	sleep 20
	login admin "$ADMIN_PW" "$ADMIN_TOTP"
	j=$(api admin GET "/jobs/$id")
	log "after the reboot: job $id $(jq -r .state <<<"$j"): $(jq -r .log <<<"$j" | tail -3 | tr '\n' ' ' | cut -c1-250)"
	log "snapshots of vm-$VMID: before $before, now $(snaps)"
	j=$(next_job "$id") || die "no retry or next backup of $GROUP"
	log "next backup job $(jq -r .id <<<"$j"): $(jq -r .state <<<"$j") in $(jq '.finished - .started' <<<"$j") s; snapshots now $(snaps)"
}

step_netloss() {
	login admin "$ADMIN_PW" "$ADMIN_TOTP"
	local id j
	id=$(start_and_wait)
	log "dropping the appliance's traffic to $PVE_HOST for $LOSS s during job $id"
	# one console line: insert, wait, delete by handle (in the background on the appliance)
	con run "nft insert rule inet nexus output ip daddr $PVE_HOST drop comment \\\"fault-netloss\\\"; systemd-run --on-active=$LOSS sh -c 'nft -a list chain inet nexus output | grep fault-netloss | sed \"s/.*handle //\" | xargs -r -I{} nft delete rule inet nexus output handle {}' >/dev/null" 30 >/dev/null
	j=$(wait_job admin "$id" 3600)
	log "job $id: $(jq -r .state <<<"$j") after $(jq '.finished - .started' <<<"$j") s: $(jq -r .log <<<"$j" | grep -iE 'error|fail|retry|timed' | tail -2 | tr '\n' ' ' | cut -c1-250)"
	log "egress rules left: $(con run 'nft list chain inet nexus output | grep -c fault-netloss' 30 | grep -E '^[0-9]+$' | tail -1)"
	if [ "$(jq -r .state <<<"$j")" != ok ]; then
		j=$(next_job "$id") || die "no retry of $GROUP"
		log "retry job $(jq -r .id <<<"$j"): $(jq -r .state <<<"$j") in $(jq '.finished - .started' <<<"$j") s"
	fi
	log "snapshots of vm-$VMID: $(snaps)"
}

for s in "$@"; do
	"step_$s"
done
