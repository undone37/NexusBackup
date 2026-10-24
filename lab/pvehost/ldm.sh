#!/usr/bin/env bash
# Windows dynamic disks (LDM) made by Windows itself (#53, #71: plan.md Phase 39 C3, L11) on the PVE lab host, through
# the appliance VM and the tunnel of deploy.sh: a full clone of the Windows lab VM $SRC_VMID gets a second disk that
# Windows converts to GPT and dynamic, with a simple NTFS volume and $FILES test files; the clone is backed up in a
# group with index-files on. Checked: the file index lists the files of the dynamic volume, the restore micro-VM
# mounts it (files_list).
#
#   ldm.sh clone     VM $CLONE: full clone of $SRC_VMID on $STORAGE plus a 4 GiB SATA disk, started
#   ldm.sh disk      in the guest: disk 1 -> GPT, dynamic, simple NTFS volume X:, $FILES files in X:\ldm
#   ldm.sh backup    group "ldm-$CLONE" with the clone (index-files on), backup, the file_index result
#   ldm.sh browse    files_list of / and of the dynamic volume in the restore micro-VM
#   ldm.sh cleanup   VM $CLONE destroyed
#
# env: as vmware-e2e.sh (LAB, PORT, PVE_HOST, SSH_KEY, NODE pve-test); SRC_VMID (242), CLONE (297),
#      STORAGE (vmpool), FILES (50), OUT (~/nexus-lab/scratch/ldm)
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
export LAB=${LAB:-$HOME/nexus-lab/pvehost}
export PORT=${PORT:-28444}
PVE_HOST=${PVE_HOST:-10.2.34.200}
SSH_KEY=${SSH_KEY:-$HOME/nexus-lab/pve-lab-key}
NODE=${NODE:-pve-test}
SRC_VMID=${SRC_VMID:-242}
CLONE=${CLONE:-297}
STORAGE=${STORAGE:-vmpool}
FILES=${FILES:-50}
OUT=${OUT:-$HOME/nexus-lab/scratch/ldm}
ROOT=$LAB/appliance/root
S=$ROOT/run/api
mkdir -p "$S" "$OUT"
# shellcheck disable=SC1091
. "$ROOT/secrets.env"
# shellcheck source=lab/e2e/api-lib.sh
. "$repo/lab/e2e/api-lib.sh"
[ "$CLONE" -ge 200 ] || die "CLONE $CLONE: only VMs from 200 are ours"
pve() { ssh -n -i "$SSH_KEY" -o BatchMode=yes "root@$PVE_HOST" "$@"; }
case " ${*:-all} " in " clone " | " disk " | " cleanup " | " clone disk ") ;; *) login admin "$ADMIN_PW" "$ADMIN_TOTP" ;; esac
gexec() { # gexec POWERSHELL: run in the guest (encoded: no quoting through two shells); its JSON answer
	local enc
	enc=$(printf '%s' "$1" | iconv -t UTF-16LE | base64 -w0)
	pve "qm guest exec $CLONE --timeout 900 -- powershell -NoProfile -EncodedCommand $enc"
}
wait_ga() {
	for _ in $(seq 120); do
		pve "qm agent $CLONE ping" >/dev/null 2>&1 && return
		sleep 5
	done
	die "VM $CLONE: no guest agent"
}

step_clone() {
	pve "qm status $CLONE" >/dev/null 2>&1 && die "VM $CLONE exists (step cleanup)"
	pve "qm status $SRC_VMID | grep -q stopped || qm shutdown $SRC_VMID --timeout 180 --forceStop 1"
	pve "qm clone $SRC_VMID $CLONE --full 1 --storage $STORAGE --name ldm-$SRC_VMID >/dev/null &&
		qm set $CLONE --sata1 $STORAGE:4 --net0 \$(qm config $CLONE | sed -n 's/^net0: //p'),link_down=1 >/dev/null && qm start $CLONE"
	wait_ga
	log "VM $CLONE: clone of $SRC_VMID with a 4 GiB second disk, guest agent up"
}

step_disk() {
	local r
	# diskpart from a script file: GPT first, then dynamic (a GPT dynamic disk, #53), one simple volume
	r=$(gexec "\$s = @'
select disk 1
attributes disk clear readonly
online disk noerr
convert gpt
convert dynamic
create volume simple
format fs=ntfs quick label=DYN
assign letter=X
'@
Set-Content -Path C:\\ldm-diskpart.txt -Value \$s -Encoding ascii
diskpart /s C:\\ldm-diskpart.txt | Out-String | Write-Output
New-Item -ItemType Directory -Force X:\\ldm | Out-Null
1..$FILES | ForEach-Object { Set-Content -Path ('X:\\ldm\\file-' + \$_ + '.txt') -Value ('dynamic volume file ' + \$_) }
(Get-ChildItem X:\\ldm).Count")
	jq -r '."out-data" // ""' <<<"$r" | tr -d '\r' | grep -vE '^\s*$' | tail -8 >&2
	[ "$(jq -r .exitcode <<<"$r")" = 0 ] || die "diskpart in the guest: $(jq -r '."err-data" // ""' <<<"$r" | tail -5)"
	jq -r '."out-data" // ""' <<<"$r" | tr -d '\r' | grep -qx "$FILES" || die "not $FILES files on X:"
	log "disk 1: GPT dynamic, simple NTFS volume X: with $FILES files"
}

step_backup() {
	local g src pol j time idx
	g=$(api admin GET /groups | jq -r --arg n "ldm-$CLONE" '.[] | select(.name == $n) | .id')
	if [ -z "$g" ]; then
		src=$(api admin GET /sources | jq -r --arg n "$NODE" '.[] | select(.name == $n) | .id')
		pol=$(api admin GET /policies | jq -r '.[] | select(.name == "daily") | .id')
		g=$(api admin POST /groups "$(jq -nc --argjson s "$src" --argjson p "$pol" --arg n "ldm-$CLONE" --argjson v "$CLONE" \
			'{tenant:"lab", source_id:$s, policy_id:$p, name:$n, guests:[$v]}')" | jq -r .id)
		expect 201 "group ldm-$CLONE"
	fi
	api admin PUT "/groups/$g/index-files" '{"enabled":true}' >/dev/null
	expect 200 "index-files on"
	j=$(api admin POST /jobs "$(jq -nc --argjson g "$g" '{kind:"backup", tenant:"lab", params:{group_id:$g}}')")
	expect 202 "backup"
	j=$(wait_job admin "$(jq -r .id <<<"$j")" 3600)
	[ "$(jq -r .state <<<"$j")" = ok ] || die "backup: $(jq -r '.log // ""' <<<"$j" | tail -n 10)"
	time=$(jq -r '.log // ""' <<<"$j" | sed -n "s|^committed vm-$CLONE/\([0-9]*\).*|\1|p" | tail -1)
	echo "$time" >"$OUT/time"
	log "backup vm-$CLONE/$time ($(jq -r '.finished - .started' <<<"$j") s)"
	idx=
	for _ in $(seq 60); do
		idx=$(api admin GET '/jobs?limit=30' | jq -r --arg s "vm-$CLONE" --argjson t "$time" \
			'[.[] | select(.kind == "file_index" and .params.source == $s and .params.time == $t)][0].id // empty')
		[ -n "$idx" ] && break
		sleep 5
	done
	[ -n "$idx" ] || die "no file_index job after the backup"
	j=$(wait_job admin "$idx" 3600)
	jq '.result' <<<"$j" >"$OUT/index.json"
	[ "$(jq -r .state <<<"$j")" = ok ] || die "file_index: $(jq -r '.log // ""' <<<"$j" | tail -n 15)"
	log "file_index: $(jq -c '{entries, complete, elapsed_ms, micro_vm, volumes: [.volumes[]? | {fs, entries, browse, device, skipped: (.skipped // .error // null)}]}' "$OUT/index.json" | cut -c1-600)"
	jq -e --argjson n "$FILES" '[.volumes[]? | select(.fs == "ntfs" and .entries >= $n and .entries < 1000)] | length > 0' "$OUT/index.json" >/dev/null ||
		die "no small NTFS volume with the $FILES files in the index (the dynamic volume)"
	log "the dynamic volume is indexed"
}

step_browse() {
	local time j p mnt=
	time=$(cat "$OUT/time")
	j=$(api admin POST /jobs "$(jq -nc --arg s "vm-$CLONE" --argjson t "$time" '{kind:"files_list", tenant:"lab", params:{source:$s, time:$t, path:"/"}}')")
	expect 202 "files_list /"
	j=$(wait_job admin "$(jq -r .id <<<"$j")" 900)
	[ "$(jq -r .state <<<"$j")" = ok ] || die "files_list /: $(jq -r '.log // ""' <<<"$j" | tail -n 15)"
	log "mounts: $(jq -r '[.result.entries[].name] | join(" ")' <<<"$j")"
	# the mount that holds ldm/
	for p in $(jq -r '.result.entries[].name' <<<"$j"); do
		j=$(api admin POST /jobs "$(jq -nc --arg s "vm-$CLONE" --argjson t "$time" --arg p "/$p" '{kind:"files_list", tenant:"lab", params:{source:$s, time:$t, path:$p}}')")
		j=$(wait_job admin "$(jq -r .id <<<"$j")" 900)
		jq -e '[.result.entries[]?.name] | index("ldm")' <<<"$j" >/dev/null && mnt=$p && break
	done
	[ -n "$mnt" ] || die "no mount with ldm/ in the restore micro-VM"
	j=$(api admin POST /jobs "$(jq -nc --arg s "vm-$CLONE" --argjson t "$time" --arg p "/$mnt/ldm" '{kind:"files_list", tenant:"lab", params:{source:$s, time:$t, path:$p}}')")
	j=$(wait_job admin "$(jq -r .id <<<"$j")" 900)
	[ "$(jq -r '.result.entries | length' <<<"$j")" = "$FILES" ] || die "/$mnt/ldm: $(jq -r '.result.entries | length' <<<"$j") entries"
	log "restore micro-VM: /$mnt/ldm holds the $FILES files of the dynamic volume"
}

step_cleanup() {
	pve "qm stop $CLONE >/dev/null 2>&1; qm destroy $CLONE --purge >/dev/null 2>&1" || true
	log "VM $CLONE removed"
}

for s in "${@:-clone disk backup browse}"; do
	for x in $s; do
		log "== $x"
		"step_$x"
	done
done
