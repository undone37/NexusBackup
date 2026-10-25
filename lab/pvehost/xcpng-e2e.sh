#!/usr/bin/env bash
# XCP-ng end to end on the appliance VM of the PVE lab (#40 M3, docs/xcpng-design.md): an xcpng source for the
# nested XCP-ng host (lab/pvehost/xcpng.sh), its inventory, a group with the running Debian guest (xcpng.sh guest),
# a full and an incremental backup, the snapshot restored as a new Proxmox VE VM on the lab host, booted (screen
# capture) and removed again. Through the tunnel of deploy.sh.
#
#   xcpng-e2e.sh source     the source "xcp" (the host's certificate pinned, the host for NBD)
#   xcpng-e2e.sh inventory  inventory job, the VMs with their UUIDs
#   xcpng-e2e.sh group      group "xcpng" with the VM named $VM, policy "daily"
#   xcpng-e2e.sh backup     backup of the group, the new xcp-<uuid> snapshot (the second one is incremental)
#   xcpng-e2e.sh files      the newest snapshot's files: listing of / (the mounts) and /<mount>/etc
#   xcpng-e2e.sh restore    the newest snapshot as VM $TARGET on $NODE ($STORAGE, NICs link_down), started
#   xcpng-e2e.sh check      the VM runs; a screen capture after $BOOT seconds ($OUT/xcpng-e2e.png)
#   xcpng-e2e.sh cleanup    stop and destroy VM $TARGET (ours: ID from 200)
#   xcpng-e2e.sh pool       the newest snapshot back into the pool as "$VM (e2e)", started there for $BOOT seconds
#                           (it must stay running), then removed with its disks
#
# env: as deploy.sh (LAB ~/nexus-lab/pvehost, PORT 28444, PVE_HOST, NODE pve-test); LAB_X (~/nexus-lab/xcpng:
#      root.pw), XCP (10.2.34.218), VM (nexus-deb), TARGET (292), STORAGE (vmpool), BOOT (60), OUT (~/nexus-lab/scratch)
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
export LAB=${LAB:-$HOME/nexus-lab/pvehost}
export PORT=${PORT:-28444}
PVE_HOST=${PVE_HOST:-10.2.34.200}
SSH_KEY=${SSH_KEY:-$HOME/nexus-lab/pve-lab-key}
NODE=${NODE:-pve-test}
LAB_X=${LAB_X:-$HOME/nexus-lab/xcpng}
XCP=${XCP:-10.2.34.218}
VM=${VM:-nexus-deb}
TARGET=${TARGET:-292}
STORAGE=${STORAGE:-vmpool}
BOOT=${BOOT:-60}
OUT=${OUT:-$HOME/nexus-lab/scratch}
SRC=xcp GROUP=xcpng
ROOT=$LAB/appliance/root
S=$ROOT/run/api
mkdir -p "$S" "$OUT"
# shellcheck disable=SC1091
. "$ROOT/secrets.env"
# shellcheck source=lab/e2e/api-lib.sh
. "$repo/lab/e2e/api-lib.sh"
pve() { ssh -n -i "$SSH_KEY" -o BatchMode=yes "root@$PVE_HOST" "$@"; }
[ "$TARGET" -ge 200 ] || die "TARGET $TARGET: only VMs from 200 are ours"
login admin "$ADMIN_PW" "$ADMIN_TOTP"
src_id() { api admin GET /sources | jq -r --arg n "$1" '.[] | select(.name == $n) | .id'; }

step_source() {
	[ -z "$(src_id "$SRC")" ] || {
		log "source $SRC exists"
		return
	}
	local ca
	ca=$(openssl s_client -connect "$XCP:443" </dev/null 2>/dev/null | openssl x509)
	api admin POST /sources "$(jq -nc --arg h "$XCP" --arg ca "$ca" --rawfile pw "$LAB_X/root.pw" --arg n "$SRC" \
		'{tenant:"lab", kind:"xcpng", name:$n, config:{host:$h, ca_pem:$ca, user:"root", password:($pw | rtrimstr("\n"))}}')" >/dev/null
	expect 201 "create source $SRC"
	log "source $SRC: $XCP"
}

step_inventory() {
	local sid j
	sid=$(src_id "$SRC")
	j=$(api admin POST /jobs "$(jq -nc --argjson s "$sid" '{kind:"inventory", tenant:"lab", params:{source_id:$s}}')")
	expect 202 "inventory"
	j=$(wait_job admin "$(jq -r .id <<<"$j")" 600)
	[ "$(jq -r .state <<<"$j")" = ok ] || die "inventory job: $(jq -c '{state, error, log}' <<<"$j" | cut -c1-600)"
	api admin GET "/sources/$sid/inventory" | jq -r '.guests[] | select(.gone == null) | "  \(.guest)  \(.name)"' >&2
}

step_group() {
	local sid pol uuid
	sid=$(src_id "$SRC")
	uuid=$(api admin GET "/sources/$sid/inventory" | jq -r --arg n "$VM" '[.guests[] | select(.name == $n and .gone == null)][0].guest // empty')
	[ -n "$uuid" ] || die "no VM $VM in the inventory of $SRC (step inventory)"
	echo "$uuid" >"$S/xcpng-uuid"
	api admin GET /groups | jq -e --arg g "$GROUP" '.[] | select(.name == $g)' >/dev/null && {
		log "group $GROUP exists ($VM = $uuid)"
		return
	}
	pol=$(api admin GET /policies | jq -r '.[] | select(.name == "daily") | .id')
	[ -n "$pol" ] || die "no policy daily (deploy.sh groups)"
	api admin POST /groups "$(jq -nc --argjson s "$sid" --argjson p "$pol" --arg u "$uuid" --arg g "$GROUP" \
		'{tenant:"lab", source_id:$s, policy_id:$p, name:$g, guests:[$u]}')" >/dev/null
	expect 201 "group $GROUP"
	log "group $GROUP: $VM ($uuid)"
}

step_backup() {
	local g j uuid t0=$(date +%s)
	uuid=$(cat "$S/xcpng-uuid")
	g=$(api admin GET /groups | jq -r --arg g "$GROUP" '.[] | select(.name == $g) | .id')
	j=$(api admin POST /jobs "$(jq -nc --argjson g "$g" '{kind:"backup", tenant:"lab", params:{group_id:$g}}')")
	expect 202 "backup"
	j=$(wait_job admin "$(jq -r .id <<<"$j")" 10800)
	[ "$(jq -r .state <<<"$j")" = ok ] || die "backup job $(jq -r .id <<<"$j"): $(jq -c '{state, error, log}' <<<"$j" | cut -c1-800)"
	jq -r ".log // \"\"" <<<"$j" | grep -E "committed|consistency|NBD|bytes|full read" | tail -8 >&2 || true
	jq -r '.log // ""' <<<"$j" | sed -n "s|^committed xcp-$uuid/\([0-9]*\).*|\1|p" | tail -1 >"$S/xcpng-time"
	[ -s "$S/xcpng-time" ] || die "no committed line for xcp-$uuid in the job log"
	log "backup ok in $(($(date +%s) - t0)) s: xcp-$uuid/$(cat "$S/xcpng-time")"
}

step_files() {
	local uuid time p j mnt=
	uuid=$(cat "$S/xcpng-uuid")
	time=$(cat "$S/xcpng-time")
	for p in / /etc; do
		p=${mnt:+/$mnt}$p
		j=$(api admin POST /jobs "$(jq -nc --arg s "xcp-$uuid" --argjson t "$time" --arg p "$p" \
			'{kind:"files_list", tenant:"lab", params:{source:$s, time:$t, path:$p}}')")
		expect 202 "files_list $p"
		j=$(wait_job admin "$(jq -r .id <<<"$j")" 900)
		[ "$(jq -r .state <<<"$j")" = ok ] || die "files_list $p: $(jq -r '.log // ""' <<<"$j" | tail -n 15)"
		log "files_list $p: $(jq -r '[.result.entries[].name] | length' <<<"$j") entries: $(jq -r '[.result.entries[].name][:12] | join(" ")' <<<"$j")"
		[ -n "$mnt" ] || mnt=$(jq -r '.result.entries[0].name // empty' <<<"$j")
	done
}

step_restore() {
	local j pve_src uuid time t0=$(date +%s)
	uuid=$(cat "$S/xcpng-uuid")
	time=$(cat "$S/xcpng-time")
	pve_src=$(src_id "$NODE")
	[ -n "$pve_src" ] || die "no PVE source $NODE (deploy.sh source)"
	pve "qm status $TARGET" >/dev/null 2>&1 && die "VM $TARGET exists (step cleanup)"
	j=$(api admin POST /jobs "$(jq -nc --arg s "xcp-$uuid" --argjson t "$time" --argjson p "$pve_src" --arg n "$NODE" \
		--argjson v "$TARGET" --arg st "$STORAGE" \
		'{kind:"restore", tenant:"lab", params:{source:$s, time:$t, source_id:$p, node:$n, target:$v, storage:$st,
		  bridge:"vmbr0", link_down:true, start:true}}')")
	expect 202 "restore"
	j=$(wait_job admin "$(jq -r .id <<<"$j")" 10800)
	jq -r ".log // \"\"" <<<"$j" | grep -E "note:|restored|serve|error" | tail -8 >&2 || true
	[ "$(jq -r .state <<<"$j")" = ok ] || die "restore job $(jq -r .id <<<"$j"): $(jq -c '{state, error}' <<<"$j")"
	log "restore ok in $(($(date +%s) - t0)) s: VM $TARGET"
	pve "qm config $TARGET" | grep -E "^(name|memory|cores|sockets|ostype|bios|scsihw|scsi|sata|net|boot)" >&2
}

step_check() {
	pve "qm status $TARGET" | grep -q running || die "VM $TARGET is not running"
	log "VM $TARGET runs; screen capture in ${BOOT}s"
	sleep "$BOOT"
	pve "rm -f /tmp/xcpng-e2e.ppm; echo 'screendump /tmp/xcpng-e2e.ppm' | qm monitor $TARGET >/dev/null && cat /tmp/xcpng-e2e.ppm && rm -f /tmp/xcpng-e2e.ppm" >"$OUT/xcpng-e2e.ppm"
	python3 -c "from PIL import Image; Image.open('$OUT/xcpng-e2e.ppm').save('$OUT/xcpng-e2e.png')" &&
		log "screen: $OUT/xcpng-e2e.png"
}

xcp() { ssh -i "$SSH_KEY" -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
	-o LogLevel=ERROR "root@$XCP" "$@"; }

step_pool() {
	local j uuid time vm t0=$(date +%s)
	uuid=$(cat "$S/xcpng-uuid")
	time=$(cat "$S/xcpng-time")
	j=$(api admin POST /jobs "$(jq -nc --arg s "xcp-$uuid" --argjson t "$time" --argjson p "$(src_id "$SRC")" \
		--arg n "$VM (e2e)" '{kind:"restore", tenant:"lab", params:{source:$s, time:$t, source_id:$p, name:$n}}')")
	expect 202 "restore into the pool"
	j=$(wait_job admin "$(jq -r .id <<<"$j")" 3600)
	[ "$(jq -r .state <<<"$j")" = ok ] || die "pool restore $(jq -r .id <<<"$j"): $(jq -c '{state, error, log}' <<<"$j" | cut -c1-800)"
	vm=$(jq -r .result.vm <<<"$j")
	log "restored into the pool in $(($(date +%s) - t0)) s: $vm"
	xcp "xe vm-param-list uuid=$vm | grep -E ' (name-label|memory-static-max|VCPUs-max|power-state) '; xe vm-start uuid=$vm" >&2
	sleep "$BOOT"
	xcp "xe vm-param-get uuid=$vm param-name=power-state" | grep -q running || die "the restored VM does not run"
	log "the restored VM runs after ${BOOT}s"
	xcp "xe vm-shutdown uuid=$vm force=true && xe vm-uninstall uuid=$vm force=true >/dev/null" && log "removed $vm"
}

step_cleanup() {
	pve "qm stop $TARGET >/dev/null 2>&1; qm destroy $TARGET --purge >/dev/null 2>&1" || true
	log "VM $TARGET removed"
}

for s in "${@:-source inventory group backup backup restore check}"; do
	for x in $s; do
		log "== $x"
		"step_$x"
	done
done
