#!/usr/bin/env bash
# The nightly regression suite (plan.md Phase 44): the lab scripts in a row against the PVE lab host and the appliance
# VM 201, each with a time limit, the result per step in $OUT/<date>.json (and the full log next to it). Runs on the
# regression VM (lab/pvehost/regress.sh, systemd timer), not on a workstation; the lab VMs a step needs are started
# before it and stopped after it.
#
#   nightly.sh [steps]   default: tunnel exact reboot patroni esxi8
#     tunnel    deploy.sh tunnel: console socket and API of the appliance
#     exact     verify.sh cleanup exact cleanup: VM 200 backed up, restored as VM 211, byte-identical, VM 211 removed
#     reboot    faults.sh reboot: the appliance reboots during a backup of VM 242; retry and a new snapshot
#     patroni   VMs 260-263 started, patroni.sh writer scenario nowriter (PITR around a switchover and a failover), stopped
#     esxi8     VM 251 started, esxi.sh up hotadd (CBT + hot-add on ESXi 8), stopped
#
# env: OUT (~/nexus-lab/regress), PVE_HOST (10.2.34.200), SSH_KEY (~/nexus-lab/pve-lab-key), LIMIT (minutes per
#      step, 90), PG_VERSION (18)
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
OUT=${OUT:-$HOME/nexus-lab/regress}
PVE_HOST=${PVE_HOST:-10.2.34.200}
SSH_KEY=${SSH_KEY:-$HOME/nexus-lab/pve-lab-key}
LIMIT=${LIMIT:-90}
export PG_VERSION=${PG_VERSION:-18}
mkdir -p "$OUT"
stamp=$(date -u +%Y-%m-%dT%H%M)
LOG=$OUT/$stamp.log
JSON=$OUT/$stamp.json
results=()
pve() { ssh -n -i "$SSH_KEY" -o BatchMode=yes "root@$PVE_HOST" "$@"; }
vms() { # start|shutdown IDs...
	local a=$1 id
	shift
	for id in "$@"; do
		if [ "$a" = start ]; then
			pve "qm status $id | grep -q running || qm start $id" >/dev/null 2>&1
		else
			pve "qm shutdown $id --timeout 180 >/dev/null 2>&1 || qm stop $id" >/dev/null 2>&1
		fi
	done
}

# step NAME: runs s_NAME with the time limit, records ok/failed, seconds and the last lines
step() {
	local name=$1 t0 rc tail
	t0=$(date +%s)
	printf '\n===== %s %s\n' "$name" "$(date -u +%FT%TZ)" >>"$LOG"
	# timeout runs programs, not shell functions: the script runs the step itself
	timeout --kill-after=60 "$((LIMIT * 60))" "$0" __run "$name" >>"$LOG" 2>&1
	rc=$?
	tail=$(tail -n 8 "$LOG" | cut -c1-300)
	results+=("$(jq -nc --arg n "$name" --argjson rc "$rc" --argjson s "$(($(date +%s) - t0))" --arg t "$tail" \
		'{step:$n, ok:($rc == 0), rc:$rc, seconds:$s, tail:$t}')")
	printf '%s: %s (%ss)\n' "$name" "$([ "$rc" = 0 ] && echo ok || echo "FAILED rc=$rc")" "$(($(date +%s) - t0))"
}

s_tunnel() { "$here/deploy.sh" tunnel; }
s_exact() { "$here/verify.sh" cleanup exact cleanup; } # the restored VM 211 must not be left from an earlier run
s_reboot() { AFTER=500000000 "$here/faults.sh" reboot; }
s_patroni() {
	local rc
	vms start 260 261 262 263
	sleep 120
	"$here/patroni.sh" ip status writer scenario
	rc=$?
	"$here/patroni.sh" nowriter
	vms shutdown 260 261 262 263
	return $rc
}
s_esxi8() {
	local rc
	vms start 251
	ESXI=8 "$here/esxi.sh" ip up hotadd
	rc=$?
	vms shutdown 251
	return $rc
}

if [ "${1:-}" = __run ]; then
	"s_$2"
	exit
fi

steps=("$@")
[ ${#steps[@]} -gt 0 ] || steps=(tunnel exact reboot patroni esxi8)
commit=$(git -C "$repo" rev-parse --short HEAD 2>/dev/null || echo unknown)
echo "nightly $stamp, commit $commit" | tee -a "$LOG"
for s in "${steps[@]}"; do
	step "$s"
done
printf '%s\n' "${results[@]}" | jq -s --arg c "$commit" --arg d "$stamp" \
	'{date:$d, commit:$c, ok:(all(.[]; .ok)), steps:.}' >"$JSON"
echo "summary: $JSON ($(jq -r 'if .ok then "all passed" else "FAILED: " + ([.steps[] | select(.ok | not) | .step] | join(", ")) end' "$JSON"))"
jq -e .ok "$JSON" >/dev/null
