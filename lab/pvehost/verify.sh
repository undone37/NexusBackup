#!/usr/bin/env bash
# Checks against the appliance VM on the PVE lab host (after lab/pvehost/deploy.sh):
#
#   verify.sh [steps]   default: exact windows
#     exact    VM $EXACT_VM (stopped for the test, started again afterwards) backed up, restored as VM $EXACT_TARGET,
#              both disks compared on the host (sha256 of the zvols): the restore is byte-identical, including the
#              regions the appliance did not transfer (zero / unallocated)
#     windows  group "windows" (VM 101 by default, deploy.sh) backed up twice (full, then incremental): durations, bytes read vs logical,
#              warnings; then a restore test of $RT_VM (boot in an isolated network, guest agent answers)
#     cleanup  remove the VMs this script restored (only names ending in -verify)
# (cloud-init CD-ROMs are generated per VM and not compared)
# env: as deploy.sh (PVE_HOST, NODE, SSH_KEY, LAB, PORT); EXACT_VM (200), EXACT_TARGET (211), RT_VM (101),
#      STORAGE (vmpool)
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
PVE_HOST=${PVE_HOST:-10.2.34.200}
NODE=${NODE:-pve-test}
SSH_KEY=${SSH_KEY:-$HOME/nexus-lab/pve-lab-key}
export LAB=${LAB:-$HOME/nexus-lab/pvehost}
export PORT=${PORT:-28444}
ROOT=$LAB/appliance/root
EXACT_VM=${EXACT_VM:-200}
EXACT_TARGET=${EXACT_TARGET:-211}
RT_VM=${RT_VM:-101}
STORAGE=${STORAGE:-vmpool}
S=$ROOT/run/api
pve() { ssh -i "$SSH_KEY" -o BatchMode=yes "root@$PVE_HOST" "$@" 2> >(grep -v 'older storage API' >&2); }
# shellcheck disable=SC1091
. "$ROOT/secrets.env"
# shellcheck source=lab/e2e/api-lib.sh
. "$repo/lab/e2e/api-lib.sh"
login admin "$ADMIN_PW" "$ADMIN_TOTP"
R=$S/verify.results
touch "$R"
result() {
	grep -v "^$1=" "$R" >"$R.tmp" || true
	echo "$1=$2" >>"$R.tmp"
	mv "$R.tmp" "$R"
	log "result $1=$2"
}
group_id() { api admin GET /groups | jq -r --arg n "$1" '.[] | select(.name==$n) | .id'; }
backup_group() { # name -> job json
	local r
	r=$(api admin POST /jobs "$(jq -nc --argjson g "$(group_id "$1")" '{kind:"backup", tenant:"lab", params:{group_id:$g}}')")
	expect 202 "backup $1"
	wait_job admin "$(jq -r .id <<<"$r")" 14400
}
stats() { jq -r .log <<<"$1" | grep '^nexus-stats ' | sed 's/^nexus-stats //' | jq -c '{source, read, logical, new_stored}'; }
wait_snapshot() { # source time
	for _ in $(seq 90); do
		api admin GET "/snapshots?tenant=lab" | jq -e --arg s "$1" --argjson t "$2" '.[] | select(.source==$s and .time==$t and .local)' >/dev/null && return 0
		sleep 2
	done
	die "snapshot $1/$2 not in the catalog as local"
}
zvol_sha() { # vmid -> "key sha" per disk (scsi/virtio/sata disks, sorted by key)
	pve "qm config $1 | grep -v media=cdrom | sed -n 's/^\(\(scsi\|virtio\|sata\)[0-9]*\): $STORAGE:\([^,]*\),.*/\1 \3/p' | sort |
		while read -r k v; do echo \"\$k \$(sha256sum /dev/zvol/$STORAGE/\$v | cut -c1-16)\"; done"
}

step_exact() {
	api admin GET /groups | jq -e '.[] | select(.name=="lab-arm64")' >/dev/null || die "group lab-arm64 missing (deploy.sh groups)"
	pve "qm config $EXACT_TARGET >/dev/null 2>&1" && die "VM $EXACT_TARGET exists; remove it first (cleanup)"
	pve "qm shutdown $EXACT_VM --timeout 300 >/dev/null 2>&1 || qm stop $EXACT_VM >/dev/null"
	local j t r
	j=$(backup_group lab-arm64)
	[ "$(jq -r .state <<<"$j")" = ok ] || die "backup: $(jq -r .log <<<"$j" | tail -n 20)"
	stats "$j" | sed 's/^/  /' >&2
	jq -r .log <<<"$j" | grep -E 'not transferred' | sed 's/^/  /' >&2 || true
	t=$(jq -r .result.time <<<"$j")
	wait_snapshot "vm-$EXACT_VM" "$t"
	r=$(api admin POST /jobs "$(jq -nc --argjson t "$t" --arg n "$NODE" --argjson v "$EXACT_VM" --argjson to "$EXACT_TARGET" --arg st "$STORAGE" \
		'{kind:"restore", tenant:"lab", params:{source:("vm-" + ($v|tostring)), time:$t, node:$n, target:$to, storage:$st, name:"exact-verify", start:false, link_down:true}}')")
	expect 202 "restore"
	j=$(wait_job admin "$(jq -r .id <<<"$r")" 14400)
	[ "$(jq -r .state <<<"$j")" = ok ] || die "restore: $(jq -r .log <<<"$j" | tail -n 20)"
	local a b
	a=$(zvol_sha "$EXACT_VM")
	b=$(zvol_sha "$EXACT_TARGET")
	pve "qm start $EXACT_VM >/dev/null"
	log "original: $(tr '\n' ' ' <<<"$a")"
	log "restored: $(tr '\n' ' ' <<<"$b")"
	[ -n "$a" ] && [ "$(awk '{print $2}' <<<"$a")" = "$(awk '{print $2}' <<<"$b")" ] || die "restored disks differ"
	result exact "VM $EXACT_VM restored byte-identical ($(wc -l <<<"$a") disk(s))"
}

step_windows() {
	local j n
	for n in full incremental; do
		j=$(backup_group windows)
		[ "$(jq -r .state <<<"$j")" = ok ] || die "$n backup: $(jq -r .log <<<"$j" | tail -n 20)"
		log "$n: $(jq '.finished - .started' <<<"$j") s, warnings $(jq -r '.result.warnings // 0' <<<"$j")"
		stats "$j" | sed 's/^/  /' >&2
		result "windows_$n" "$(jq '.finished - .started' <<<"$j") s, read $(stats "$j" | jq -s 'map(.read) | add') of $(stats "$j" | jq -s 'map(.logical) | add') bytes"
	done
	local t r c
	t=$(jq -r --arg s "vm-$RT_VM" '.result.snapshots[] | select(.source==$s) | .time' <<<"$j")
	wait_snapshot "vm-$RT_VM" "$t"
	c='{"boot_timeout":900}'
	r=$(api admin POST /jobs "$(jq -nc --argjson t "$t" --arg s "vm-$RT_VM" --arg n "$NODE" --arg st "$STORAGE" --argjson c "$c" \
		'{kind:"restore_test", tenant:"lab", params:{source:$s, time:$t, node:$n, storage:$st, checks:$c}}')")
	expect 202 "restore test"
	j=$(wait_job admin "$(jq -r .id <<<"$r")" 7200)
	jq -r .log <<<"$j" | tail -n 8 | sed 's/^/  /' >&2
	[ "$(jq -r .state <<<"$j")" = ok ] || die "restore test: $(jq -r .state <<<"$j")"
	result restore_test "vm-$RT_VM boots in isolation, $(jq -c '.result.checks // .result' <<<"$j" | cut -c1-200)"
}

step_cleanup() {
	pve "for v in \$(qm list | awk 'NR>1 && \$2 ~ /-verify\$/ {print \$1}'); do qm stop \$v >/dev/null 2>&1; qm destroy \$v --purge 1 >/dev/null && echo removed \$v; done"
}

steps=("$@")
[ ${#steps[@]} -gt 0 ] || steps=(exact windows)
for s in "${steps[@]}"; do
	log "== $s"
	"step_$s"
done
cat "$R"
