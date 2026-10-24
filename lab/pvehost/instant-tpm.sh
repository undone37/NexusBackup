#!/usr/bin/env bash
# Instant recovery with the disk move of a VM with a vTPM (#78, plan.md Phase 39 L18: the TPM state fix of
# 2026-10-15) on the PVE lab host, through the appliance VM and the tunnel of deploy.sh. The newest snapshot of
# $SRC_VMID (default 101, the maintainer's Windows member server with a vTPM: only read, never written; the copy
# gets new MACs, its NICs stay disconnected) is recovered as VM $TARGET on $STORAGE and started; the job moves
# the disks while it runs. Checked: the job, the TPM state and every disk on $STORAGE (no overlay left), the VM
# running (guest agent if present, a screen capture in $OUT).
#
#   instant-tpm.sh recover   instant recovery of the newest vm-$SRC_VMID snapshot as VM $TARGET (link_down, start)
#   instant-tpm.sh check     the VM's disks and TPM state on $STORAGE, running, screen capture
#   instant-tpm.sh cleanup   VM $TARGET stopped and destroyed
#
# env: as vmware-e2e.sh (LAB, PORT, PVE_HOST, SSH_KEY, NODE pve-test); SRC_VMID (101), TARGET (296),
#      STORAGE (vmpool), OUT (~/nexus-lab/scratch)
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
export LAB=${LAB:-$HOME/nexus-lab/pvehost}
export PORT=${PORT:-28444}
PVE_HOST=${PVE_HOST:-10.2.34.200}
SSH_KEY=${SSH_KEY:-$HOME/nexus-lab/pve-lab-key}
NODE=${NODE:-pve-test}
SRC_VMID=${SRC_VMID:-101}
TARGET=${TARGET:-296}
STORAGE=${STORAGE:-vmpool}
OUT=${OUT:-$HOME/nexus-lab/scratch}
ROOT=$LAB/appliance/root
S=$ROOT/run/api
mkdir -p "$S"
# shellcheck disable=SC1091
. "$ROOT/secrets.env"
# shellcheck source=lab/e2e/api-lib.sh
. "$repo/lab/e2e/api-lib.sh"
[ "$TARGET" -ge 200 ] || die "TARGET $TARGET: only VMs from 200 are ours"
pve() { ssh -n -i "$SSH_KEY" -o BatchMode=yes "root@$PVE_HOST" "$@"; }
case " ${*:-all} " in " cleanup ") ;; *) login admin "$ADMIN_PW" "$ADMIN_TOTP" ;; esac

step_recover() {
	local time j t0=$SECONDS
	pve "qm status $TARGET" >/dev/null 2>&1 && die "VM $TARGET exists (step cleanup)"
	time=$(api admin GET '/snapshots?tenant=lab' | jq -r --arg s "vm-$SRC_VMID" '[.[] | select(.source == $s and .local)] | max_by(.time) | .time // empty')
	[ -n "$time" ] || die "no local snapshot of vm-$SRC_VMID"
	j=$(api admin POST /jobs "$(jq -nc --arg s "vm-$SRC_VMID" --argjson t "$time" --arg n "$NODE" --argjson v "$TARGET" \
		--arg st "$STORAGE" \
		'{kind:"instant_recover", tenant:"lab", params:{source:$s, time:$t, node:$n, target:$v, storage:$st,
		  start:true, link_down:true}}')")
	expect 202 "instant_recover"
	log "instant recovery of vm-$SRC_VMID/$time as VM $TARGET (job $(jq -r .id <<<"$j"))"
	j=$(wait_job admin "$(jq -r .id <<<"$j")" 7200)
	jq -r '.log // ""' <<<"$j" | grep -iE "tpm|moved|move|running|started|overlay" | tail -12 >&2 || true
	[ "$(jq -r .state <<<"$j")" = ok ] || die "instant_recover: $(jq -r '.log // ""' <<<"$j" | tail -n 20)"
	log "instant recovery ok in $((SECONDS - t0)) s"
}

step_check() {
	local cfg bad
	cfg=$(pve "qm config $TARGET")
	grep -E '^(tpmstate0|efidisk0|scsi[0-9]+|sata[0-9]+|virtio[0-9]+|ide[0-9]+|net[0-9]+): ' <<<"$cfg" >&2
	grep -q "^tpmstate0: $STORAGE:" <<<"$cfg" || die "the TPM state is not on $STORAGE"
	bad=$(grep -E '^(efidisk0|scsi[0-9]+|sata[0-9]+|virtio[0-9]+|ide[0-9]+): ' <<<"$cfg" | grep -v media=cdrom | grep -v ": $STORAGE:" || true)
	[ -z "$bad" ] || die "disks not on $STORAGE: $bad"
	grep -E '^net[0-9]+: ' <<<"$cfg" | grep -vq link_down=1 && die "a NIC is connected"
	pve "qm status $TARGET" | grep -q running || die "VM $TARGET is not running"
	# the guest agent if the guest has it (VM 101 has none); always a screen capture after a key press
	# (Windows turns the display off)
	local ga=no
	pve "qm agent $TARGET ping" >/dev/null 2>&1 && ga=yes
	pve "qm sendkey $TARGET shift; sleep 3; rm -f /tmp/instant-tpm.ppm; echo 'screendump /tmp/instant-tpm.ppm' | qm monitor $TARGET >/dev/null && cat /tmp/instant-tpm.ppm && rm -f /tmp/instant-tpm.ppm" >"$OUT/instant-tpm.ppm"
	python3 -c "from PIL import Image; Image.open('$OUT/instant-tpm.ppm').save('$OUT/instant-tpm.png')"
	log "VM $TARGET runs from $STORAGE (TPM state included), NICs disconnected, guest agent: $ga; screen: $OUT/instant-tpm.png"
}

step_cleanup() {
	pve "qm stop $TARGET >/dev/null 2>&1; qm destroy $TARGET --purge >/dev/null 2>&1" || true
	log "VM $TARGET removed"
}

for s in "${@:-recover check}"; do
	for x in $s; do
		log "== $x"
		"step_$x"
	done
done
