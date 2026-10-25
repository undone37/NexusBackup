#!/usr/bin/env bash
# Instant rollback (restore --replace --rollback, manual chapter 6 "Roll back in place") of a running VM on the PVE
# lab host (#72, plan.md Phase 39 L12), through the appliance VM and the tunnel of deploy.sh. An agent test VM
# (agent-vms.sh, ZFS storage vmpool) in group "rollback-<VM>": backup while it runs, junk and a marker written in
# the guest, then the rollback to that snapshot (approved by the security officer when approvals are on). The
# rolled-back disk must equal a plain restore of the same snapshot to a new VM ($CHECK) byte for byte, and the
# guest boots without the marker.
#
#   rollback.sh vm        $VM from clean-os, started, its address
#   rollback.sh clone     (CLONE=<vmid>) a full clone of $VM on $STORAGE as $FORMAT instead, started
#   rollback.sh group     group "rollback-<VM>" with the VM on the PVE source $NODE, policy "daily"
#   rollback.sh backup    backup of the group with the VM running (snapshot A; keeps the dirty bitmap)
#   rollback.sh change    $JUNK_MB of random data and a marker file in the guest
#   rollback.sh rollback  restore of snapshot A onto the VM with rollback (no start; $SPARE is the fallback VMID a
#                         replace needs and must stay unused), the job log
#   rollback.sh compare   snapshot A restored as VM $CHECK (not started); qemu-img compare of both disks
#   rollback.sh boot      the VM started: no marker, no junk
#   rollback.sh cleanup   VM $CHECK destroyed, the VM reset to clean-os (stopped)
#
# env: as vmware-e2e.sh (LAB, PORT, PVE_HOST, SSH_KEY, NODE pve-test); VM (debian-12), VM_KEY, CHECK (291),
#      SPARE (293), STORAGE (vmpool), JUNK_MB (300), OUT (~/nexus-lab/scratch/rollback); dir storage:
#      CLONE=294 STORAGE=local FORMAT=qcow2; Windows: CLONE=295 SRC_VMID=242 STORAGE=vmpool FORMAT=raw WINDOWS=1
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
export LAB=${LAB:-$HOME/nexus-lab/pvehost}
export PORT=${PORT:-28444}
PVE_HOST=${PVE_HOST:-10.2.34.200}
SSH_KEY=${SSH_KEY:-$HOME/nexus-lab/pve-lab-key}
VM_KEY=${VM_KEY:-$HOME/nexus-lab/lab_ed25519}
NODE=${NODE:-pve-test}
VM=${VM:-debian-12}
CHECK=${CHECK:-291}
# a replace names a new VMID: the full-replace fallback restores there (unused when the rollback runs in place)
SPARE=${SPARE:-293}
STORAGE=${STORAGE:-vmpool}
JUNK_MB=${JUNK_MB:-300}
OUT=${OUT:-$HOME/nexus-lab/scratch/rollback}
ROOT=$LAB/appliance/root
S=$ROOT/run/api
mkdir -p "$S" "$OUT"
# shellcheck disable=SC1091
. "$ROOT/secrets.env"
# shellcheck source=lab/e2e/api-lib.sh
. "$repo/lab/e2e/api-lib.sh"
[ "$CHECK" -ge 200 ] && [ "$SPARE" -ge 200 ] || die "CHECK $CHECK / SPARE $SPARE: only VMs from 200 are ours"
JUMP="ssh -i $SSH_KEY -o BatchMode=yes -W %h:%p root@$PVE_HOST"
SSHO=(-i "$VM_KEY" -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR
	-o ProxyCommand="$JUMP" -o ConnectTimeout=10)
vm() { ssh "${SSHO[@]}" "root@$(cat "$OUT/ip")" "$@"; }
pve() { ssh -n -i "$SSH_KEY" -o BatchMode=yes "root@$PVE_HOST" "$@"; }
# CLONE=<vmid>: a full clone of the agent VM on $STORAGE in $FORMAT (dir storages: qcow2), step clone
vmid() { [ -n "${CLONE:-}" ] && echo "$CLONE" || "$here/agent-vms.sh" list | awk -v n="$VM" '$2 == n {print $1}'; }
case " ${*:-all} " in " vm " | " cleanup " | " vm cleanup ") ;; *) login admin "$ADMIN_PW" "$ADMIN_TOTP" ;; esac
GROUP=rollback-$VM${CLONE:+-$CLONE}
FORMAT=${FORMAT:-qcow2}
# WINDOWS=1 (with CLONE and SRC_VMID, e.g. 242): a Windows guest, changed and checked through the QEMU guest agent
WINDOWS=${WINDOWS:-}
gexec() { # gexec POWERSHELL: run in the Windows guest (encoded: no quoting through two shells), true on exit 0
	local enc
	enc=$(printf '%s' "$1" | iconv -t UTF-16LE | base64 -w0)
	pve "qm guest exec $(vmid) --timeout 900 -- powershell -NoProfile -EncodedCommand $enc" | jq -e '.exitcode == 0' >/dev/null
}
wait_ga() {
	for _ in $(seq 120); do
		pve "qm agent $(vmid) ping" >/dev/null 2>&1 && return
		sleep 5
	done
	die "VM $(vmid): no guest agent"
}

step_vm() {
	"$here/agent-vms.sh" reset "$VM" </dev/null
	pve "qm start $(vmid)"
	local ip=
	for _ in $(seq 60); do
		ip=$("$here/agent-vms.sh" ip "$VM" </dev/null | awk '{print $3}')
		[ -n "$ip" ] && [ "$ip" != - ] && break
		sleep 5
	done
	[ -n "$ip" ] && [ "$ip" != - ] || die "$VM: no address"
	echo "$ip" >"$OUT/ip"
	log "$VM ($(vmid)): $ip, running"
}

step_clone() {
	local src ip=
	[ -n "${CLONE:-}" ] && [ "$CLONE" -ge 200 ] || die "CLONE: the VMID of the clone (from 200)"
	pve "qm status $CLONE" >/dev/null 2>&1 && die "VM $CLONE exists (step cleanup)"
	src=${SRC_VMID:-$("$here/agent-vms.sh" list | awk -v n="$VM" '$2 == n {print $1}')}
	pve "qm status $src | grep -q stopped || qm shutdown $src --timeout 120 --forceStop 1"
	pve "qm clone $src $CLONE --full 1 --storage $STORAGE --format $FORMAT --name rb-$src-$FORMAT >/dev/null && qm start $CLONE"
	if [ -n "$WINDOWS" ]; then
		wait_ga
		echo - >"$OUT/ip"
		log "VM $CLONE: full clone of VM $src on $STORAGE ($FORMAT), guest agent up"
		return
	fi
	for _ in $(seq 60); do
		# the guest agent answers some seconds after the start: a failing call is a retry, not the end
		ip=$(pve "qm guest cmd $CLONE network-get-interfaces 2>/dev/null" | jq -r '[.[] | select(.name != "lo") | ."ip-addresses"[]? | select(."ip-address-type" == "ipv4") | ."ip-address"][0] // empty' || true)
		[ -n "$ip" ] && break
		sleep 5
	done
	[ -n "$ip" ] || die "VM $CLONE: no address"
	echo "$ip" >"$OUT/ip"
	log "VM $CLONE: full clone of $VM on $STORAGE ($FORMAT), $ip, running"
}

step_group() {
	local src pol
	api admin GET /groups | jq -e --arg n "$GROUP" '.[] | select(.name == $n)' >/dev/null && {
		log "group $GROUP exists"
		return
	}
	src=$(api admin GET /sources | jq -r --arg n "$NODE" '.[] | select(.name == $n) | .id')
	pol=$(api admin GET /policies | jq -r '.[] | select(.name == "daily") | .id')
	[ -n "$src" ] && [ -n "$pol" ] || die "no PVE source $NODE or policy daily (deploy.sh source groups)"
	api admin POST /groups "$(jq -nc --argjson s "$src" --argjson p "$pol" --arg n "$GROUP" --argjson v "$(vmid)" \
		'{tenant:"lab", source_id:$s, policy_id:$p, name:$n, guests:[$v]}')" >/dev/null
	expect 201 "group $GROUP"
	log "group $GROUP: VM $(vmid)"
}

step_backup() {
	local g j
	g=$(api admin GET /groups | jq -r --arg n "$GROUP" '.[] | select(.name == $n) | .id')
	j=$(api admin POST /jobs "$(jq -nc --argjson g "$g" '{kind:"backup", tenant:"lab", params:{group_id:$g}}')")
	expect 202 "backup"
	j=$(wait_job admin "$(jq -r .id <<<"$j")" 3600)
	[ "$(jq -r .state <<<"$j")" = ok ] || die "backup: $(jq -r '.log // ""' <<<"$j" | tail -n 15)"
	jq -r '.log // ""' <<<"$j" | sed -n "s|^committed vm-$(vmid)/\([0-9]*\).*|\1|p" | tail -1 >"$OUT/a.time"
	[ -s "$OUT/a.time" ] || die "backup: no committed line for vm-$(vmid)"
	log "snapshot A: vm-$(vmid)/$(cat "$OUT/a.time") ($(jq -r '.finished - .started' <<<"$j") s)"
}

step_change() {
	if [ -n "$WINDOWS" ]; then
		gexec "\$r=[Security.Cryptography.RandomNumberGenerator]::Create(); \$b=New-Object byte[] 1048576; \$f=[IO.File]::Create('C:\\nexus-junk.bin'); for(\$i=0;\$i -lt $JUNK_MB;\$i++){\$r.GetBytes(\$b); \$f.Write(\$b,0,\$b.Length)}; \$f.Close(); Set-Content C:\\nexus-marker.txt rolled-back-if-missing" ||
			die "guest exec: junk and marker not written"
		log "guest: ${JUNK_MB} MB junk and C:\\nexus-marker.txt written"
		return
	fi
	vm "head -c ${JUNK_MB}M /dev/urandom > /root/junk.bin && echo rolled-back-if-missing > /root/marker && sync"
	log "guest: ${JUNK_MB} MB junk and /root/marker written"
}

step_rollback() {
	local r q j id t0=$SECONDS
	pve "qm status $SPARE" >/dev/null 2>&1 && die "VM $SPARE exists (the fallback VMID must be free)"
	r=$(api admin POST /jobs "$(jq -nc --argjson t "$(cat "$OUT/a.time")" --argjson v "$SPARE" --arg s "vm-$(vmid)" \
		--arg n "$NODE" --arg st "$STORAGE" \
		'{kind:"restore", tenant:"lab", params:{source:$s, time:$t, node:$n, target:$v, storage:$st, replace:true,
		  rollback:true, start:false}}')")
	[ "$(status)" = 202 ] || [ "$(status)" = 200 ] || die "rollback: HTTP $(status) $(cat "$S/body")"
	q=$(jq -r '.quorum_id // empty' <<<"$r")
	if [ -n "$q" ] && [ "$(jq -r '.state // empty' <<<"$r")" != approved ]; then
		login so "$SO_PW" "$SO_TOTP"
		api so POST "/quorum/$q/approve" '{}' >/dev/null
		expect 200 "approve restore.replace"
		log "approved by the security officer (quorum $q)"
	fi
	id=$(jq -r '.id // empty' <<<"$r")
	for _ in $(seq 30); do
		[ -n "$id" ] && break
		id=$(api admin GET '/jobs?limit=10' | jq -r --arg s "vm-$(vmid)" \
			'[.[] | select(.kind == "restore" and .params.source == $s)][0].id // empty')
		sleep 2
	done
	[ -n "$id" ] || die "no restore job after the approval"
	j=$(wait_job admin "$id" 7200)
	jq -r '.log // ""' <<<"$j" | grep -iE "rollback|paused|backed up|blocks|written|full replace|chunk" | tail -12 >&2 || true
	[ "$(jq -r .state <<<"$j")" = ok ] || die "rollback job $id: $(jq -r '.log // ""' <<<"$j" | tail -n 20)"
	log "rollback job $id ok in $((SECONDS - t0)) s"
	pve "qm status $SPARE" >/dev/null 2>&1 && die "VM $SPARE was created: the job fell back to a full replace"
	pve "qm config $(vmid) | grep -E '^(lock|tags)' || echo 'no lock, no tag'" >&2
}

step_compare() {
	local j a b
	pve "qm status $CHECK" >/dev/null 2>&1 && die "VM $CHECK exists (step cleanup)"
	j=$(api admin POST /jobs "$(jq -nc --argjson t "$(cat "$OUT/a.time")" --argjson v "$CHECK" --arg s "vm-$(vmid)" \
		--arg n "$NODE" --arg st "$STORAGE" \
		'{kind:"restore", tenant:"lab", params:{source:$s, time:$t, node:$n, target:$v, storage:$st, start:false}}')")
	expect 202 "restore to $CHECK"
	j=$(wait_job admin "$(jq -r .id <<<"$j")" 7200)
	[ "$(jq -r .state <<<"$j")" = ok ] || die "restore to $CHECK: $(jq -r '.log // ""' <<<"$j" | tail -n 15)"
	pve "qm status $(vmid)" | grep -q stopped || die "VM $(vmid) is not stopped"
	# the first disk of both VMs, whatever the storage (zvol, qcow2 file): qemu-img compares the guest view
	local pa pb
	disk() { pve "pvesm path \$(qm config $1 | grep -E '^(scsi|sata|virtio|ide)[0-9]+: ' | grep -v media=cdrom | head -1 | sed 's/^[a-z0-9]*: \([^,]*\).*/\1/')"; }
	pa=$(disk "$(vmid)")
	pb=$(disk "$CHECK")
	pve "qemu-img compare -q '$pa' '$pb'" || die "the rolled-back disk differs from a plain restore of snapshot A"
	log "qemu-img compare: the rolled-back disk ($pa) equals a plain restore of snapshot A ($pb)"
}

step_boot() {
	pve "qm start $(vmid)"
	if [ -n "$WINDOWS" ]; then
		wait_ga
		gexec "if ((Test-Path C:\\nexus-marker.txt) -or (Test-Path C:\\nexus-junk.bin)) { exit 1 }" ||
			die "marker or junk still in the guest"
		log "VM $(vmid) (Windows) boots after the rollback; marker and junk gone"
		return
	fi
	local ok=
	for _ in $(seq 60); do
		vm true 2>/dev/null && ok=1 && break
		sleep 5
	done
	[ -n "$ok" ] || die "$VM does not answer after the rollback"
	vm "test ! -e /root/marker && test ! -e /root/junk.bin" || die "marker or junk still in the guest"
	log "$VM boots after the rollback; marker and junk gone"
}

step_cleanup() {
	pve "qm stop $CHECK >/dev/null 2>&1; qm destroy $CHECK --purge >/dev/null 2>&1" || true
	[ -z "${CLONE:-}" ] || pve "qm stop $CLONE >/dev/null 2>&1; qm destroy $CLONE --purge >/dev/null 2>&1" || true
	# a clone leaves its source as it was; only the agent VM itself was changed
	[ -n "${CLONE:-}" ] || "$here/agent-vms.sh" reset "$VM" </dev/null
	log "VM $CHECK removed${CLONE:+, clone $CLONE removed}${CLONE:-, $VM reset to clean-os}"
}

first=vm
[ -z "${CLONE:-}" ] || first=clone
for s in "${@:-$first group backup change rollback compare boot}"; do
	for x in $s; do
		log "== $x"
		"step_$x"
	done
done
