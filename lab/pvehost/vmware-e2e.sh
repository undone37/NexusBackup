#!/usr/bin/env bash
# VMware end to end on the appliance VM of the PVE lab (plan.md Phase 41 M3, #32-#34): a VMware source for the lab
# vCenter (lab/pvehost/vcenter.sh), its inventory, a group with one VM, a backup over NFC, the snapshot restored as a
# new Proxmox VE VM on the lab host, booted (screen capture) and removed again. Through the tunnel of deploy.sh.
#
#   vmware-e2e.sh proxy      (TRANSPORT=hotadd) agent "nx-proxy" on the appliance, this tree's agent on the proxy VM
#                            nx-proxy of ESXI_PROXY_LAB (esxi.sh proxy) initialised with its token, enrolled
#   vmware-e2e.sh source     the source "vc" (vCenter certificate pinned, the ESXi hosts for NFC); TRANSPORT=hotadd:
#                            "vc-hot" reading through nx-proxy (#80, #88)
#   vmware-e2e.sh inventory  inventory job, the VMs with their UUIDs
#   vmware-e2e.sh group      group "vmware" ("vmware-hot") with the VM named $VM (first match), policy "daily"
#   vmware-e2e.sh backup     backup of the group, the new vmw-<uuid> snapshot
#   vmware-e2e.sh files      the newest snapshot's files (#83): listing of / (the mounts) and /<mount>/etc in the
#                            restore micro-VM, then the file index of the snapshot
#   vmware-e2e.sh restore    the newest snapshot as VM $TARGET on $NODE ($STORAGE, NICs link_down), started
#   vmware-e2e.sh check      the VM runs; a screen capture after $BOOT seconds ($OUT/vmware-e2e.png)
#   vmware-e2e.sh cleanup    stop and destroy VM $TARGET (ours: ID from 200)
#
# env: as deploy.sh (LAB ~/nexus-lab/pvehost, PORT 28444, PVE_HOST, NODE pve-test); VC_LAB (~/nexus-lab/vcenter),
#      ESXI_LABS (~/nexus-lab/esxi ~/nexus-lab/esxi8), VM (nx-cbt), TARGET (290), STORAGE (vmpool), BOOT (90),
#      OUT (~/nexus-lab/scratch), TRANSPORT (nfc, hotadd), ESXI_PROXY_LAB (~/nexus-lab/esxi: the ESXi 7 host of nx-cbt)
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
export LAB=${LAB:-$HOME/nexus-lab/pvehost}
export PORT=${PORT:-28444}
PVE_HOST=${PVE_HOST:-10.2.34.200}
SSH_KEY=${SSH_KEY:-$HOME/nexus-lab/pve-lab-key}
NODE=${NODE:-pve-test}
VC_LAB=${VC_LAB:-$HOME/nexus-lab/vcenter}
ESXI_LABS=${ESXI_LABS:-"$HOME/nexus-lab/esxi $HOME/nexus-lab/esxi8"}
VM=${VM:-nx-cbt}
TARGET=${TARGET:-290}
STORAGE=${STORAGE:-vmpool}
BOOT=${BOOT:-90}
OUT=${OUT:-$HOME/nexus-lab/scratch}
TRANSPORT=${TRANSPORT:-nfc}
ESXI_PROXY_LAB=${ESXI_PROXY_LAB:-$HOME/nexus-lab/esxi}
case $TRANSPORT in
nfc) SRC=vc GROUP=vmware ;;
hotadd) SRC=vc-hot GROUP=vmware-hot ;;
*) echo "TRANSPORT: nfc or hotadd" >&2 && exit 2 ;;
esac
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

step_proxy() {
	local r id tok j
	id=$(api admin GET /agents | jq -r '.[] | select(.name == "nx-proxy") | .id')
	if [ -n "$id" ]; then
		log "agent nx-proxy exists ($id)"
		return
	fi
	local ip
	LAB=$ESXI_PROXY_LAB "$here/esxi.sh" up >/dev/null
	ip=$(LAB=$ESXI_PROXY_LAB "$here/esxi.sh" ssh "vim-cmd vmsvc/get.guest \$(vim-cmd vmsvc/getallvms | awk '\$2==\"nx-proxy\" {print \$1}') | sed -n 's/^ *ipAddress = \"\([0-9.]*\)\".*/\1/p' | head -1")
	[ -n "$ip" ] || die "nx-proxy has no address (VMware Tools)"
	r=$(api admin POST /agents "$(jq -nc --arg h "$ip" '{tenant:"lab", name:"nx-proxy", host:$h, port:7444}')")
	expect 201 "create agent nx-proxy"
	id=$(jq -r .id <<<"$r")
	tok=$(jq -r .token <<<"$r")
	PROXY_TOKEN=$tok LAB=$ESXI_PROXY_LAB "$here/esxi.sh" proxy >/dev/null
	r=$(api admin POST "/agents/$id/enroll")
	expect 202 "enroll nx-proxy"
	j=$(wait_job admin "$(jq -r .id <<<"$r")" 600)
	[ "$(jq -r .state <<<"$j")" = ok ] || die "enroll nx-proxy: $(jq -r .log <<<"$j" | tail -n 20)"
	log "agent nx-proxy $id enrolled ($(cat "$ESXI_PROXY_LAB/proxy.ip"))"
}

step_source() {
	[ -z "$(src_id "$SRC")" ] || {
		log "source $SRC exists"
		return
	}
	local vc ca hosts pw extra='{}'
	if [ "$TRANSPORT" = hotadd ]; then
		local agent pvm
		agent=$(api admin GET /agents | jq -r '.[] | select(.name == "nx-proxy") | .id')
		[ -n "$agent" ] || die "no agent nx-proxy (step proxy)"
		[ -n "$(src_id vc)" ] || die "no source vc for the proxy VM's UUID (TRANSPORT=nfc steps source inventory)"
		pvm=$(api admin GET "/sources/$(src_id vc)/inventory" | jq -r '[.guests[] | select(.name == "nx-proxy" and .gone == null)][0].guest // empty')
		[ -n "$pvm" ] || die "nx-proxy not in the inventory of vc"
		extra=$(jq -nc --arg a "$agent" --arg v "$pvm" '{transport:"hotadd", proxy_vm:$v, proxy_agent:$a}')
	fi
	vc=$(cat "$VC_LAB/ip")
	ca=$(openssl s_client -connect "$vc:443" </dev/null 2>/dev/null | openssl x509)
	pw=$(sed -n 's/^SSO_PW=//p' "$VC_LAB/secrets.env")
	# shellcheck disable=SC2086
	hosts=$(for d in $ESXI_LABS; do cat "$d/ip"; done | jq -Rsc 'split("\n") | map(select(. != ""))')
	api admin POST /sources "$(jq -nc --arg h "$vc" --arg ca "$ca" --arg pw "$pw" --argjson hosts "$hosts" --arg n "$SRC" \
		--argjson x "$extra" \
		'{tenant:"lab", kind:"vmware", name:$n, config:({host:$h, port:443, ca_pem:$ca, user:"administrator@vsphere.local",
		  password:$pw, datacenter:"nx-lab", transport:"nfc", nfc_hosts:$hosts} + $x)}')" >/dev/null
	expect 201 "create source $SRC"
	log "source $SRC: $vc, NFC hosts $hosts, $(jq -c . <<<"$extra")"
}

step_inventory() {
	local sid j
	sid=$(src_id "$SRC")
	j=$(api admin POST /jobs "$(jq -nc --argjson s "$sid" '{kind:"inventory", tenant:"lab", params:{source_id:$s}}')")
	expect 202 "inventory"
	j=$(wait_job admin "$(jq -r .id <<<"$j")" 600)
	[ "$(jq -r .state <<<"$j")" = ok ] || die "inventory job: $(jq -c '{state, error}' <<<"$j")"
	api admin GET "/sources/$sid/inventory" | jq -r '.guests[] | select(.gone == null) | "  \(.guest)  \(.name)"' >&2
}

step_group() {
	local sid pol uuid
	sid=$(src_id "$SRC")
	uuid=$(api admin GET "/sources/$sid/inventory" | jq -r --arg n "$VM" '[.guests[] | select(.name == $n and .gone == null)][0].guest // empty')
	[ -n "$uuid" ] || die "no VM $VM in the inventory of $SRC (step inventory)"
	echo "$uuid" >"$S/vmware-uuid"
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
	uuid=$(cat "$S/vmware-uuid")
	g=$(api admin GET /groups | jq -r --arg g "$GROUP" '.[] | select(.name == $g) | .id')
	j=$(api admin POST /jobs "$(jq -nc --argjson g "$g" '{kind:"backup", tenant:"lab", params:{group_id:$g}}')")
	expect 202 "backup"
	j=$(wait_job admin "$(jq -r .id <<<"$j")" 10800)
	[ "$(jq -r .state <<<"$j")" = ok ] || die "backup job $(jq -r .id <<<"$j"): $(jq -c '{state, error}' <<<"$j")"
	jq -r ".log // \"\"" <<<"$j" | grep -E "committed|consistency|NFC|bytes|block-read|prepared|SCSI" | tail -8 >&2 || true
	api admin GET '/snapshots?tenant=lab' | jq -r --arg s "vmw-$uuid" '[.[] | select(.source == $s)] | max_by(.time) | .time' >"$S/vmware-time"
	log "backup ok in $(($(date +%s) - t0)) s: vmw-$uuid/$(cat "$S/vmware-time")"
}

step_files() {
	local uuid time p j mnt=
	uuid=$(cat "$S/vmware-uuid")
	time=$(cat "$S/vmware-time")
	# the root lists the guest's mounts (vda1, ...); /etc of the first one
	for p in / /etc; do
		p=${mnt:+/$mnt}$p
		j=$(api admin POST /jobs "$(jq -nc --arg s "vmw-$uuid" --argjson t "$time" --arg p "$p" \
			'{kind:"files_list", tenant:"lab", params:{source:$s, time:$t, path:$p}}')")
		expect 202 "files_list $p"
		j=$(wait_job admin "$(jq -r .id <<<"$j")" 900)
		[ "$(jq -r .state <<<"$j")" = ok ] || die "files_list $p: $(jq -r '.log // ""' <<<"$j" | tail -n 15)"
		log "files_list $p: $(jq -r '[.result.entries[].name] | length' <<<"$j") entries: $(jq -r '[.result.entries[].name][:12] | join(" ")' <<<"$j")"
		[ -n "$mnt" ] || mnt=$(jq -r '.result.entries[0].name // empty' <<<"$j")
	done
	# the file index (sandboxed parser, no micro-VM): queued after a backup of a group with index-files on
	local g id
	g=$(api admin GET /groups | jq -r --arg g "$GROUP" '.[] | select(.name == $g) | .id')
	api admin PUT "/groups/$g/index-files" '{"enabled":true}' >/dev/null
	expect 200 "index-files on"
	step_backup
	id=$(api admin GET '/jobs?limit=20' | jq -r '[.[] | select(.kind == "file_index")][0].id // empty')
	[ -n "$id" ] || die "no file_index job after the backup"
	j=$(wait_job admin "$id" 1800)
	[ "$(jq -r .state <<<"$j")" = ok ] || die "file_index $id: $(jq -r '.log // ""' <<<"$j" | tail -n 15)"
	log "file_index: $(jq -c '.result // {}' <<<"$j" | cut -c1-200)"
}

step_restore() {
	local j pve_src uuid time t0=$(date +%s)
	uuid=$(cat "$S/vmware-uuid")
	time=$(cat "$S/vmware-time")
	pve_src=$(src_id "$NODE")
	[ -n "$pve_src" ] || die "no PVE source $NODE (deploy.sh source)"
	pve "qm status $TARGET" >/dev/null 2>&1 && die "VM $TARGET exists (step cleanup)"
	j=$(api admin POST /jobs "$(jq -nc --arg s "vmw-$uuid" --argjson t "$time" --argjson p "$pve_src" --arg n "$NODE" \
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
	pve "rm -f /tmp/vmware-e2e.ppm; echo 'screendump /tmp/vmware-e2e.ppm' | qm monitor $TARGET >/dev/null && cat /tmp/vmware-e2e.ppm && rm -f /tmp/vmware-e2e.ppm" >"$OUT/vmware-e2e.ppm"
	python3 -c "from PIL import Image; Image.open('$OUT/vmware-e2e.ppm').save('$OUT/vmware-e2e.png')" &&
		log "screen: $OUT/vmware-e2e.png"
}

step_cleanup() {
	pve "qm stop $TARGET >/dev/null 2>&1; qm destroy $TARGET --purge >/dev/null 2>&1" || true
	log "VM $TARGET removed"
}

for s in "${@:-source inventory group backup restore check}"; do
	for x in $s; do
		log "== $x"
		"step_$x"
	done
done
