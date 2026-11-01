#!/usr/bin/env bash
# Scan back in the real restore VM (#70, manual chapter 11 "Scan back to the last clean snapshot") on the appliance
# VM 201: a lab YARA rule that matches a marker, the marker written into a running lab VM, two backups with it, then
# a scan back from the newest snapshot. Every YARA scan of a VM snapshot runs in the restore micro-VM. Expected: the
# marked snapshots flagged, the newest clean one the recommended restore point. Through the tunnel of
# lab/pvehost/deploy.sh.
#
#   scan-back.sh run       rule, marker, two backups, scan back, result
#   scan-back.sh clean     marker removed from the guest, the lab rule deleted
#
# env: LAB (~/nexus-lab/pvehost), PORT (28444), VMID (225, running, guest agent), GROUP (31: a group with VMID),
#      TENANT (lab), PVE_HOST, SSH_KEY
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
LAB=${LAB:-$HOME/nexus-lab/pvehost}
ROOT=${ROOT:-$LAB/appliance/root}
PORT=${PORT:-28444}
VMID=${VMID:-225}
GROUP=${GROUP:-31}
TENANT=${TENANT:-lab}
PVE_HOST=${PVE_HOST:-10.2.34.200}
SSH_KEY=${SSH_KEY:-$HOME/nexus-lab/pve-lab-key}
RULE=lab-scan-back-70
# the marker is built at run time so this file itself never matches the rule
MARK="NEXUS-LAB-$((70 * 1)) SCAN BACK MARKER"
S=$LAB/scratch/scan-back
mkdir -p "$S"
export T0
T0=$(date +%s)
eval "$(ROOT=$ROOT PORT=$PORT "$repo/lab/e2e/m5.sh" env)"
# shellcheck source=lab/e2e/api-lib.sh
# shellcheck disable=SC1090
. "$repo/lab/e2e/api-lib.sh"
pve() { ssh -n -i "$SSH_KEY" -o BatchMode=yes "root@$PVE_HOST" "$@"; }
guest() { pve "qm guest exec $VMID --timeout 120 -- sh -c '$1'" | jq -r '."out-data" // empty'; }

backup() {
	local r j
	r=$(api admin POST /jobs "$(jq -nc --arg t "$TENANT" --argjson g "$GROUP" '{kind:"backup", tenant:$t, params:{group_id:$g}}')")
	expect 202 "backup"
	j=$(wait_job admin "$(jq -r .id <<<"$r")" 3600)
	[ "$(jq -r .state <<<"$j")" = ok ] || die "backup: $(jq -r .log <<<"$j" | tail -n 20)"
	jq -r .log <<<"$j" | sed -n 's/^committed \(vm-[0-9]*\/[0-9]*\).*/\1/p' | tail -1
}

step_run() {
	login admin "$ADMIN_PW" "$ADMIN_TOTP"
	api admin PUT "/scan/rules/$RULE.yar" "$(jq -nc --arg m "$MARK" '{text: ("rule nexus_lab_scan_back_70 { strings: $m = \"" + $m + "\" condition: $m }")}')" >/dev/null
	expect 200 "upload the lab rule"
	log "rule $RULE.yar uploaded"
	local clean bad1 bad2 r j
	clean=$(api admin GET "/snapshots?tenant=$TENANT" | jq -r --arg s "vm-$VMID" '[.[] | select(.source == $s)] | max_by(.time) | "\(.source)/\(.time)"')
	[ "$clean" != "null/null" ] || die "no snapshot of vm-$VMID to start from"
	guest "printf \"%s\\n\" \"$MARK\" > /root/scan-back-marker.txt && sync && cat /root/scan-back-marker.txt" >/dev/null
	bad1=$(backup)
	sleep 2
	guest "date >> /root/scan-back-marker.txt && sync" >/dev/null
	bad2=$(backup)
	log "snapshots: clean $clean, marked $bad1 and $bad2"
	r=$(api admin POST "/snapshots/$TENANT/vm-$VMID/${bad2#*/}/scan-back" '{"budget_min":20,"max":5}')
	expect 202 "scan back"
	j=$(wait_job admin "$(jq -r .id <<<"$r")" 7200)
	log "scan back job $(jq -r .id <<<"$j"): $(jq -r .state <<<"$j") in $(jq '.finished - .started' <<<"$j") s"
	jq -c .result <<<"$j" >"$S/result.json"
	jq -r .log <<<"$j" | grep -iE 'scan|match|clean|recommend|restore vm|micro' | tail -n 12 | while read -r l; do log "  $l"; done
	local rec
	rec=$(jq -r '.result.recommended // .result.clean // empty | if type == "object" then "\(.source)/\(.time)" else . end' <<<"$j")
	log "recommended restore point: ${rec:-none} (expected $clean)"
	[ "$rec" = "$clean" ] || [ "${rec#*/}" = "${clean#*/}" ] || die "scan back did not end at $clean: $(cat "$S/result.json")"
}

step_clean() {
	guest "rm -f /root/scan-back-marker.txt && sync" >/dev/null || true
	login admin "$ADMIN_PW" "$ADMIN_TOTP"
	api admin DELETE "/scan/rules/$RULE.yar" >/dev/null || true
	log "marker removed, rule deleted (HTTP $(status)); the flagged snapshots stay until retention"
}

case ${1:-} in
run | clean) "step_$1" ;;
*) sed -n '2,13p' "$0" >&2 && exit 2 ;;
esac
