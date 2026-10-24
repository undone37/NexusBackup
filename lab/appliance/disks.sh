#!/usr/bin/env bash
# Disks lab (Phase 16a/b, docs/hardware.md) against an installed appliance VM (SELinux enforcing)
# booted with extra disks and right after first boot (the store must still be empty):
#   EXTRA_DISKS=5 NVME=1 lab/appliance/e2e.sh boot && lab/appliance/e2e.sh setup
#   (e2e.sh boot calls run.sh start, which reads EXTRA_DISKS / NVME; delete $LAB/appliance/extra
#   for blank disks)
#   disks.sh inventory  nexus-disks reports the 5 virtio disks (NXLAB-D1..5) as empty, the system
#                       disk as system, the NVMe with SMART (health passed, wear %, temperature)
#   disks.sh selftest   SMART short self-test on the NVMe (admin, audited); the helper reports it
#   disks.sh create     RAID6 from NXLAB-D1..4 (typed serials, approval by the security officer):
#                       md array nexus-data, XFS, mounted at /var/lib/nexus/chunkstore with the
#                       store's owner, mode and SELinux label, scheduler running again; resync ends
#   disks.sh fail       mdadm --fail on one member inside the VM: array degraded, critical `disk`
#                       alert raised by the scheduler
#   disks.sh replace    replace the failed member with NXLAB-D5 (approval): rebuild runs and ends,
#                       the alerts resolve, hardware.op audited
#   disks.sh all        inventory selftest create fail replace
# Afterwards: lab/appliance/e2e.sh check (0 nexus AVCs; nexus-disks runs as nexus_disks_t).
# env: ROOT (installed root with secrets.env + etc/nexus/tls/cert.pem; default $LAB/appliance/root),
#      LAB (/home/ah/nexus-lab), PORT (web-api port forward, 28443), CONSOLE (serial console socket)
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
LAB=${LAB:-/home/ah/nexus-lab}
export ROOT=${ROOT:-$LAB/appliance/root}
export PORT=${PORT:-28443}
export CONSOLE=${CONSOLE:-$LAB/appliance/console.sock}
T0=$(date +%s)
con() { "$here/con.py" "$@"; }

apienv() {
	S=$ROOT/run/disks
	mkdir -p "$S"
	# shellcheck disable=SC1091
	. "$ROOT/secrets.env"
	# shellcheck source=lab/e2e/api-lib.sh
	. "$repo/lab/e2e/api-lib.sh"
	login admin "$ADMIN_PW" "$ADMIN_TOTP"
	login so "$SO_PW" "$SO_TOTP"
}

hw() { api admin GET /hardware; }

# rescan now and wait until the helper has written a status newer than the request
rescan() {
	local before after
	before=$(hw | jq -r '.scanned // 0')
	sleep 1.1 # `scanned` has second resolution: a scan in the same second as the last one looks old
	api admin POST /hardware/scan '{}' >/dev/null
	expect 202 "POST /hardware/scan"
	for _ in $(seq 60); do
		after=$(hw | jq -r '.scanned // 0')
		[ "$after" -gt "$before" ] && return 0
		sleep 2
	done
	die "nexus-disks did not rescan (journalctl -u nexus-disks)"
}

# wait_op ID [timeout s] -> the operation JSON once done/refused/error
wait_op() {
	local id=$1 to=${2:-300} o
	for _ in $(seq "$to"); do
		o=$(hw | jq -c --arg id "$id" '.ops[] | select(.id == $id or .quorum_id == ($id | tonumber? // -1))')
		case $(jq -r '.state // empty' <<<"$o" 2>/dev/null) in
		done | refused | error) echo "$o"; return 0 ;;
		esac
		sleep 1
	done
	die "operation $id did not finish: $o"
}

# approve the pending quorum request in the last answer (security officer)
approve() {
	local q
	q=$(jq -r .quorum_id "$S/body")
	[ "$q" != null ] || die "no quorum_id: $(cat "$S/body")"
	api so POST "/quorum/$q/approve" '{}' >/dev/null
	expect 200 "approve quorum #$q"
	log "quorum #$q approved by so"
	echo "$q"
}

open_alert() { api admin GET '/alerts?state=open' | jq -c --arg k "$1" '[.[] | select(.key == $k)][0] // empty'; }

wait_alert() { # KEY SEVERITY
	local a
	for _ in $(seq 60); do
		a=$(open_alert "$1")
		[ -n "$a" ] && [ "$(jq -r .severity <<<"$a")" = "$2" ] && { log "alert $1: $(jq -r .message <<<"$a")"; return 0; }
		sleep 3
	done
	die "no open $2 alert $1"
}

wait_resolved() {
	for _ in $(seq 60); do
		[ -z "$(open_alert "$1")" ] && { log "alert $1 resolved"; return 0; }
		sleep 3
	done
	die "alert $1 still open: $(open_alert "$1")"
}

array() { hw | jq -c '[.arrays[] | select(.md_name == "nexus-data")][0] // empty'; }

wait_clean() {
	local a
	for _ in $(seq 120); do
		rescan
		a=$(array)
		log "array: $(jq -r '"\(.name) \(.state) \(.progress // "-") %"' <<<"$a")"
		[ "$(jq -r '.state + " " + (.degraded | tostring)' <<<"$a")" = "clean false" ] && return 0
		sleep 5
	done
	die "array not clean: $a"
}

inventory() {
	apienv
	rescan
	local h
	h=$(hw)
	jq -e '.available and (.stale | not) and .tools.smartctl and .tools.mdadm' <<<"$h" >/dev/null ||
		die "status: $(jq -c '{available, stale, tools}' <<<"$h")"
	for i in 1 2 3 4 5; do
		[ "$(jq -r --arg s "NXLAB-D$i" '.disks[] | select(.serial == $s) | .role' <<<"$h")" = empty ] ||
			die "NXLAB-D$i not empty: $(jq -c --arg s "NXLAB-D$i" '.disks[] | select(.serial == $s)' <<<"$h")"
	done
	jq -e '[.disks[] | select(.role == "system")] | length >= 1' <<<"$h" >/dev/null || die "no system disk"
	jq -e '.disks[] | select(.serial == "NXLAB-NVME1") | .smart | .available and .health == "passed" and (.percentage_used != null)' \
		<<<"$h" >/dev/null || die "NVMe SMART: $(jq -c '.disks[] | select(.serial == "NXLAB-NVME1") | .smart' <<<"$h")"
	jq -e '.store.empty == true' <<<"$h" >/dev/null || die "the store is not empty: run this right after first boot"
	log "inventory ok: $(jq -r '[.disks[] | "\(.name)=\(.role)"] | join(" ")' <<<"$h"), summary $(jq -r .summary.state <<<"$h")"
}

selftest() {
	apienv
	api admin POST /hardware/selftest '{"disk":"NXLAB-NVME1","type":"short"}' >/dev/null
	expect 202 "POST /hardware/selftest"
	local id o
	id=$(jq -r .id "$S/body")
	o=$(wait_op "$id" 120)
	# QEMU's NVMe emulation may not implement the device self-test command: report, do not fail
	log "self-test: $(jq -r '.state + ": " + (.detail // .error)' <<<"$o")"
	[ "$(jq -r .state <<<"$o")" != refused ] || die "self-test refused: $o"
	[ "$(api admin GET '/audit?action=hardware.selftest' | jq length)" -ge 1 ] || die "hardware.selftest not audited"
}

create() {
	apienv
	local body q o a
	body='{"role":"data","level":"raid6","disks":["NXLAB-D1","NXLAB-D2","NXLAB-D3","NXLAB-D4"],"confirm":"NXLAB-D1 NXLAB-D2 NXLAB-D3"}'
	api admin POST /hardware/arrays "$body" >/dev/null
	expect 400 "create without all serials typed"
	body=$(jq -c '.confirm = "NXLAB-D4 NXLAB-D3 NXLAB-D2 NXLAB-D1"' <<<"$body")
	api admin POST /hardware/arrays "$body" >/dev/null
	expect 202 "POST /hardware/arrays"
	q=$(approve)
	o=$(wait_op "$q" 600)
	[ "$(jq -r .state <<<"$o")" = "done" ] || die "create_array: $o"
	log "create_array: $(jq -r .detail <<<"$o")"
	rescan
	a=$(array)
	[ -n "$a" ] || die "no nexus-data array: $(hw | jq -c .arrays)"
	jq -e '.level == "raid6" and .role == "data" and (.mounts | index("/var/lib/nexus/chunkstore")) and .fs.type == "xfs"' \
		<<<"$a" >/dev/null || die "array: $a"
	[ "$(hw | jq -r .store.array)" = "$(jq -r .name <<<"$a")" ] || die "store not on the array"
	# the helper restarts the scheduler after mounting the store: give it a moment (activating -> active)
	con run 'for _ in $(seq 30); do systemctl is-active -q nexus-scheduler.service && break; sleep 2; done' >/dev/null
	# the serial console wraps at 80 columns: FSTYPE on a line of its own
	con run 'findmnt -no FSTYPE /var/lib/nexus/chunkstore; findmnt -no SOURCE,OPTIONS /var/lib/nexus/chunkstore; stat -c "%U %a %C" /var/lib/nexus/chunkstore;
		systemctl is-active nexus-scheduler.service; systemctl is-enabled var-lib-nexus-chunkstore.mount;
		ls -Z /etc/systemd/system/var-lib-nexus-chunkstore.mount' | tee "$S/mount.txt"
	grep -q '^xfs$' "$S/mount.txt" || die "store is not XFS"
	grep -q '^nexus-chunkstore 700 system_u:object_r:nexus_store_t:s0' "$S/mount.txt" || die "store owner/mode/label"
	grep -qx active "$S/mount.txt" || die "scheduler not running"
	grep -q nexus_unit_file_t "$S/mount.txt" || die "mount unit label"
	wait_clean
	log "data array $(jq -r .name <<<"$a") created, mounted and in sync"
}

fail() {
	apienv
	local a dev serial
	a=$(array)
	serial=NXLAB-D3
	dev=$(hw | jq -r --arg s "$serial" '.disks[] | select(.serial == $s) | .name')
	con run "mdadm /dev/$(jq -r .name <<<"$a") --fail /dev/$dev && cat /proc/mdstat"
	rescan
	a=$(array)
	jq -e '.degraded' <<<"$a" >/dev/null || die "array not degraded: $a"
	echo "$serial" >"$S/failed"
	wait_alert "disk:md:$(jq -r .uuid <<<"$a")" critical
}

replace() {
	apienv
	local a failed name q o uuid
	a=$(array)
	name=$(jq -r .name <<<"$a")
	uuid=$(jq -r .uuid <<<"$a")
	failed=$(cat "$S/failed" 2>/dev/null || echo NXLAB-D3)
	api admin POST "/hardware/arrays/$name/replace" \
		"$(jq -nc --arg f "$failed" '{disk: "NXLAB-D5", failed: $f, confirm: "NXLAB-D5"}')" >/dev/null
	expect 202 "POST /hardware/arrays/$name/replace"
	q=$(approve)
	o=$(wait_op "$q" 300)
	[ "$(jq -r .state <<<"$o")" = "done" ] || die "replace: $o"
	log "replace: $(jq -r .detail <<<"$o")"
	wait_clean
	jq -e '[.members[] | select(.serial == "NXLAB-D5" and .state == "active")] | length == 1' <<<"$(array)" >/dev/null ||
		die "NXLAB-D5 not active: $(array)"
	wait_resolved "disk:md:$uuid"
	wait_resolved "disk:md:$uuid:sync"
	[ "$(api admin GET '/audit?action=hardware.op' | jq length)" -ge 2 ] || die "hardware.op not audited"
	log "failed member replaced, rebuilt, alerts resolved"
}

case ${1:-} in
inventory | selftest | create | fail | replace) "$1" ;;
all) inventory && selftest && create && fail && replace ;;
*) sed -n '2,20p' "$0" >&2; exit 2 ;;
esac
