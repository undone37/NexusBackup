#!/usr/bin/env bash
# The appliance as a VM on a real Proxmox VE host (the PVE lab host), protecting that host's guests.
#
#   deploy.sh [steps]   default: upload create tunnel setup source
#     upload   the disk built by `LAB=$LAB SIZE=300G lab/appliance/e2e.sh disk` -> the host's import storage
#     create   VM $VMID (q35, virtio, serial console, NIC on $BRIDGE), disk imported to $STORAGE, started
#     tunnel   ssh forwards from the workstation: the VM's serial console (unix socket) and the web API
#              (127.0.0.1:$PORT -> $ADDR:8443); restart after a reboot of the workstation
#     setup    first boot through nexus-setup --script (lab/appliance/e2e.sh setup) with a static address
#     source   tenant "lab", the node key + known_hosts on the appliance, the PVE source for the host
#              (API token from $LAB/api-token.out, node key $LAB/appliance_ed25519, see manual/04)
#     groups   policy "daily", groups windows (101) and lab-arm64 (200); LAB_GROUPS overrides
#     stop     stop the tunnels
# The host side (plugin package, storage `nexus`, user nexusbackup with the forced-command key, API token
# nexus@pve!backup) is set up as in manual/04 "Proxmox VE"; state.md lists what was done on the lab host.
# env: PVE_HOST (10.2.34.200), NODE (pve-test), SSH_KEY (~/nexus-lab/pve-lab-key), VMID (201),
#      ADDR (10.2.34.211/24), GW (10.2.34.254), DNS (10.2.34.253), BRIDGE (vmbr0), STORAGE (vmpool),
#      LAB (~/nexus-lab/pvehost), PORT (28444), MEM (8192), CPUS (4)
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
PVE_HOST=${PVE_HOST:-10.2.34.200}
NODE=${NODE:-pve-test}
SSH_KEY=${SSH_KEY:-$HOME/nexus-lab/pve-lab-key}
VMID=${VMID:-201}
ADDR=${ADDR:-10.2.34.211/24}
GW=${GW:-10.2.34.254}
DNS=${DNS:-10.2.34.253}
BRIDGE=${BRIDGE:-vmbr0}
STORAGE=${STORAGE:-vmpool}
export LAB=${LAB:-$HOME/nexus-lab/pvehost}
export PORT=${PORT:-28444}
export ROOT=$LAB/appliance/root CONSOLE=$LAB/appliance/console.sock
MEM=${MEM:-8192}
CPUS=${CPUS:-4}
D=$LAB/appliance
mkdir -p "$D"
pve() { ssh -i "$SSH_KEY" -o BatchMode=yes "root@$PVE_HOST" "$@"; }
T0=$(date +%s)
log() { printf '[%4ss] %s\n' $(($(date +%s) - T0)) "$*" >&2; }
die() {
	log "FAIL: $*"
	exit 1
}

step_upload() {
	[ -f "$D/appliance.qcow2" ] || die "no disk: LAB=$LAB SIZE=300G lab/appliance/e2e.sh disk"
	pve 'mkdir -p /var/lib/vz/import'
	scp -q -i "$SSH_KEY" "$D/appliance.qcow2" "root@$PVE_HOST:/var/lib/vz/import/nexus-appliance.qcow2"
	log "uploaded $(du -h "$D/appliance.qcow2" | cut -f1)"
}

step_create() {
	# only ever replaces its own VM
	if pve "qm status $VMID" >/dev/null 2>&1; then
		[ "$(pve "qm config $VMID" | sed -n 's/^name: //p')" = nexus-appliance ] || die "VM $VMID exists and is not nexus-appliance"
		pve "qm stop $VMID --skiplock 1 >/dev/null 2>&1; qm destroy $VMID --purge 1 >/dev/null"
	fi
	pve "qm create $VMID --name nexus-appliance --machine q35 --cpu host --cores $CPUS --memory $MEM --balloon 0 \
		--scsihw virtio-scsi-single --virtio0 $STORAGE:0,import-from=local:import/nexus-appliance.qcow2,discard=on,iothread=1 \
		--net0 virtio,bridge=$BRIDGE --serial0 socket --vga std --rng0 source=/dev/urandom --boot order=virtio0 \
		--onboot 1 --description 'NexusBackup appliance (lab, lab/pvehost/deploy.sh)' >/dev/null && qm start $VMID && qm status $VMID"
}

step_tunnel() {
	step_stop
	rm -f "$CONSOLE"
	ssh -i "$SSH_KEY" -o BatchMode=yes -o ExitOnForwardFailure=yes -o StreamLocalBindUnlink=yes -f -N -M -S "$D/tunnel.ctl" \
		-L "$CONSOLE:/var/run/qemu-server/$VMID.serial0" -L "127.0.0.1:$PORT:${ADDR%/*}:8443" "root@$PVE_HOST"
	log "tunnel up: console $CONSOLE, API https://127.0.0.1:$PORT"
}

step_stop() {
	[ -S "$D/tunnel.ctl" ] && ssh -S "$D/tunnel.ctl" -O exit "root@$PVE_HOST" 2>/dev/null || true
}

step_setup() {
	"$repo/lab/appliance/con.py" wait 900
	NETWORK_JSON=$(jq -nc --arg a "${ADDR%/*}" --argjson p "${ADDR#*/}" --arg g "$GW" --arg d "$DNS" \
		'{method:"static", address:$a, prefix:$p, gateway:$g, dns:[$d]}') NIC=${NIC:-ens18} PVE=0 "$repo/lab/appliance/e2e.sh" setup
}

step_source() {
	local con="$repo/lab/appliance/con.py"
	"$con" put "$LAB/appliance_ed25519" "/etc/nexus/ssh/$NODE" 0600 >/dev/null
	"$con" put "$LAB/known_hosts" /etc/nexus/ssh/known_hosts 0644 >/dev/null
	"$con" run "chown nexus-chunkstore: /etc/nexus/ssh/$NODE && restorecon -RF /etc/nexus/ssh" >/dev/null
	pve 'cat /etc/pve/pve-root-ca.pem' >"$LAB/pve-root-ca.pem"
	local S=$ROOT/run/api tok cfg
	mkdir -p "$S"
	# shellcheck disable=SC1091
	. "$ROOT/secrets.env"
	# shellcheck source=lab/e2e/api-lib.sh
	. "$repo/lab/e2e/api-lib.sh"
	login admin "$ADMIN_PW" "$ADMIN_TOTP"
	api admin GET /tenants | jq -e '.[] | select(.name=="lab")' >/dev/null ||
		{ api admin POST /tenants '{"name":"lab"}' >/dev/null && expect 201 "create tenant"; }
	tok=$(grep -o '"value" *: *"[^"]*"' "$LAB/api-token.out" | head -1 | sed 's/.*: *"\(.*\)"/\1/')
	[ -n "$tok" ] || die "no token secret in $LAB/api-token.out"
	cfg=$(jq -nc --rawfile ca "$LAB/pve-root-ca.pem" --arg tok "$tok" --arg n "$NODE" --arg h "$PVE_HOST" \
		'{host:$n, port:8006, connect_addr:($h + ":8006"), ca_pem:$ca, token_id:"nexus@pve!backup", token_secret:$tok,
		  nodes:{($n):{host:$h, port:22, key:("/etc/nexus/ssh/" + $n), known_hosts:"/etc/nexus/ssh/known_hosts"}},
		  storage:"nexus", fleecing_storage:"local-zfs"}')
	api admin POST /sources "$(jq -nc --argjson c "$cfg" --arg n "$NODE" '{tenant:"lab", kind:"pve", name:$n, config:$c}')" >/dev/null
	expect 201 "create source"
	log "PVE source $NODE created"
}

# policy "daily" and the lab groups: windows = one Windows VM (101: member server with a vTPM), lab-arm64 = VM 200 (env LAB_GROUPS overrides:
# "name:vmid,vmid name:vmid")
step_groups() {
	local S=$ROOT/run/api src pol g name ids
	# shellcheck disable=SC1091
	. "$ROOT/secrets.env"
	# shellcheck source=lab/e2e/api-lib.sh
	. "$repo/lab/e2e/api-lib.sh"
	login admin "$ADMIN_PW" "$ADMIN_TOTP"
	src=$(api admin GET /sources | jq -r --arg n "$NODE" '.[] | select(.name==$n) | .id')
	[ -n "$src" ] || die "no source $NODE (step source)"
	pol=$(api admin GET /policies | jq -r '.[] | select(.name=="daily") | .id')
	[ -n "$pol" ] || pol=$(api admin POST /policies '{"name":"daily","schedule":"daily 22:00","gfs":{"daily":7,"weekly":4,"monthly":3,"yearly":1},"offsite":false}' | jq -r .id)
	for g in ${LAB_GROUPS:-windows:101 lab-arm64:200}; do
		name=${g%%:*} ids=${g#*:}
		api admin GET /groups | jq -e --arg n "$name" '.[] | select(.name==$n)' >/dev/null && continue
		api admin POST /groups "$(jq -nc --argjson s "$src" --argjson p "$pol" --arg n "$name" --arg ids "$ids" \
			'{tenant:"lab", source_id:$s, policy_id:$p, name:$n, guests:($ids | split(",") | map(tonumber))}')" >/dev/null
		expect 201 "group $name"
		log "group $name: $ids"
	done
}

steps=("$@")
[ ${#steps[@]} -gt 0 ] || steps=(upload create tunnel setup source groups)
for s in "${steps[@]}"; do
	log "== $s"
	"step_$s"
done
