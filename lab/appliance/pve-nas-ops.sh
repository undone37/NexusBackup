#!/usr/bin/env bash
# Phase 22b lab (PVE, NAS and store operations) against the appliance VM after `lab/appliance/e2e.sh api`
# (tenant lab, PVE source pve1 and group lab-guests [100, 200] from lab/e2e/m5-api.sh; ids in $ROOT/run/api/ids).
#   pve-nas-ops.sh priority   restore priority on: a GC job stays queued (scheduler hold), the warning
#                             restore_priority is open, GET shows the banner data; off: the GC runs, audit has
#                             restore_priority.on/.off (expiry: set hours=1 and wait, or see the scheduler test)
#   pve-nas-ops.sh limits     source max_parallel 1, storage_caps local-lvm=1, read limit 20 MB/s: "back up now"
#                             of the group logs "parallel guests capped", VM 100's read rate stays near 20 MB/s
#                             (bytes read / duration from the job log); limits removed afterwards
#   pve-nas-ops.sh identity   new vmgenid + SMBIOS UUID on VM 100 (qm set), backup: alert vmid_reused, snapshot
#                             meta.identity.changed = true with the old values in `previous`
#   pve-nas-ops.sh disk       instant disk recovery: drive-scsi0 of the newest vm-100 snapshot attached to VM 100
#                             as scsi5 (hot-plug, VM running), moved to local-lvm; the job ends ok, qm config shows
#                             scsi5 on local-lvm and no ir/ volume; scsi5 is removed again
#   pve-nas-ops.sh all        priority limits identity disk
# Not scripted (need the NAS / TrueNAS labs, lab/nas and lab/truenas):
#   - NAS: create two SMB sources on the lab share with overlapping include roots -> "overlaps" on Sources;
#     Split one by two roots (password again) -> two sources + copied groups, audit source.split; make one file
#     unreadable (chmod 000 as the share owner on the Samba side), back up -> job page "Skipped files (CSV)"
#     lists it; read_limit 5 MB/s on the share source -> transfer rate in the job log ~5 MB/s.
#   - TrueNAS: a periodic snapshot task (auto-%Y-%m-%d_%H-%M, every 15 min) on the lab dataset, source with
#     "Use existing snapshots" prefix auto-, re-paste the authorized_keys line; run 1 = full read of the newest
#     auto- snapshot, no nexus-* snapshot appears; run 2 before the next periodic snapshot = dataset skipped
#     ("no new snapshot"); run 3 after it = incremental (zfs diff between the two auto- snapshots).
# Afterwards: lab/appliance/e2e.sh check (0 nexus AVCs; nexus-pve reads guest configs and PUTs a VM config:
# no new SELinux rules expected, the API calls go to the already allowed PVE endpoint).
# env: ROOT ($LAB/appliance/root), LAB (/home/ah/nexus-lab), PORT (28443)
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
LAB=${LAB:-/home/ah/nexus-lab}
export ROOT=${ROOT:-$LAB/appliance/root}
export PORT=${PORT:-28443}
T0=$(date +%s)
S=$ROOT/run/api
# shellcheck disable=SC1091
. "$ROOT/secrets.env"
# shellcheck source=lab/e2e/api-lib.sh
. "$repo/lab/e2e/api-lib.sh"
# shellcheck disable=SC1091
. "$S/ids" # SRC POL GRP
pve() { ssh -o BatchMode=yes -p 10022 -i "$LAB/lab_ed25519" -o UserKnownHostsFile="$LAB/known_hosts" root@localhost "$@"; }

backup_now() {
	local id
	id=$(api admin POST /jobs "$(jq -nc --argjson g "$GRP" '{kind:"backup", tenant:"lab", params:{group_id:$g}}')" | jq -r .id)
	expect 202 "backup now"
	wait_job admin "$id" 1800
}

source_cfg() { api admin GET /sources | jq -c --argjson s "$SRC" '.[] | select(.id == $s) | .config | del(.token_secret_set)'; }

priority() {
	login admin "$ADMIN_PW" "$ADMIN_TOTP"
	api admin PUT /restore-priority '{"hours": 1, "reason": "lab 22b"}' | jq -e '.active == true' >/dev/null
	expect 200 "restore priority on"
	local id
	id=$(api admin POST /jobs '{"kind":"gc","tenant":"lab","params":{}}' | jq -r .id)
	expect 202 "queue gc"
	sleep 45
	[ "$(api admin GET "/jobs/$id" | jq -r .state)" = queued ] || die "gc started during restore priority"
	api admin GET '/alerts?state=open' | jq -e 'any(.[]; .kind == "restore_priority")' >/dev/null || die "no restore_priority warning"
	api admin DELETE /restore-priority | jq -e '.active == false' >/dev/null
	[ "$(wait_job admin "$id" 600 | jq -r .state)" = ok ] || die "gc after restore priority"
	api admin GET '/audit?action=restore_priority.on' | jq -e 'length >= 1' >/dev/null || die "audit restore_priority.on"
	api admin GET '/audit?action=restore_priority.off' | jq -e 'length >= 1' >/dev/null || die "audit restore_priority.off"
	log "restore priority: held and released"
}

limits() {
	login admin "$ADMIN_PW" "$ADMIN_TOTP"
	local cfg name
	cfg=$(source_cfg)
	name=$(api admin GET /sources | jq -r --argjson s "$SRC" '.[] | select(.id == $s) | .name')
	api admin PUT "/sources/$SRC" "$(jq -nc --arg n "$name" --argjson c "$cfg" \
		'{name:$n, config:($c + {max_parallel:1, storage_caps:{"local-lvm":1}, read_limit:{bwlimit:20000000, timezone:"UTC"}})}')" >/dev/null
	expect 200 "set limits"
	local j
	j=$(backup_now)
	[ "$(jq -r .state <<<"$j")" = ok ] || die "backup with limits: $(jq -r .log <<<"$j" | tail -5)"
	jq -r .log <<<"$j" | grep -E 'nexus-stats|committed|capped' | head -20
	log "check: read bytes / seconds of vm-100 in the lines above stay near 20 MB/s (full read) or the run is short (incremental)"
	api admin PUT "/sources/$SRC" "$(jq -nc --arg n "$name" --argjson c "$cfg" '{name:$n, config:$c}')" >/dev/null
	expect 200 "remove limits"
}

identity() {
	login admin "$ADMIN_PW" "$ADMIN_TOTP"
	pve "qm set 100 --vmgenid 1 && qm set 100 --smbios1 uuid=\$(cat /proc/sys/kernel/random/uuid)"
	pve "qm config 100 | grep -E '^(vmgenid|smbios1)'"
	local j
	j=$(backup_now)
	[ "$(jq -r .state <<<"$j")" = ok ] || die "backup after the identity change"
	api admin GET '/alerts?state=open' | jq -e 'any(.[]; .kind == "vmid_reused" and (.key | endswith("/vm-100")))' >/dev/null ||
		die "no vmid_reused alert"
	api admin GET '/snapshots?tenant=lab&source=vm-100' | jq -e 'max_by(.time).meta.identity | .changed == true and .previous.vmgenid != null' >/dev/null ||
		die "snapshot meta.identity not recorded"
	log "identity change detected"
}

disk() {
	login admin "$ADMIN_PW" "$ADMIN_TOTP"
	local t id j
	t=$(api admin GET '/snapshots?tenant=lab&source=vm-100' | jq -r 'map(select(.local)) | max_by(.time).time')
	pve "qm start 100 >/dev/null 2>&1 || true"
	id=$(api admin POST /jobs "$(jq -nc --argjson t "$t" '{kind:"instant_disk", tenant:"lab",
		params:{source:"vm-100", time:$t, device:"drive-scsi0", node:"pve1", target:100, key:"scsi5", move_to:"local-lvm"}}')" | jq -r .id)
	expect 202 "instant disk"
	j=$(wait_job admin "$id" 1800)
	jq -r .log <<<"$j" | tail -8
	[ "$(jq -r .state <<<"$j")" = ok ] || die "instant disk recovery failed"
	pve "qm config 100 | grep -E '^scsi5: local-lvm:'" || die "scsi5 not on local-lvm"
	if pve "qm config 100 | grep -q ':ir/'"; then die "an ir/ volume is still referenced"; fi
	pve "qm set 100 --delete scsi5 && qm config 100 | awk -F': ' '/^unused[0-9]+: local-lvm/ {print \$1}' | xargs -r -n1 qm set 100 --delete"
	log "instant disk recovery: attached, moved, removed"
}

case ${1:-all} in
priority | limits | identity | disk) "$1" ;;
all) priority && limits && identity && disk ;;
*)
	sed -n '2,20p' "$0"
	exit 2
	;;
esac
