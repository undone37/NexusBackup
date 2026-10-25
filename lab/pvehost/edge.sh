#!/usr/bin/env bash
# Edge proxy on the PVE lab host (Phase 26, docs/edge.md; #66 "an edge-connected laptop updated on reconnect"):
# the edge bootc image (lab build: serial root autologin) as VM $VMID next to the appliance VM 201 (tunnel of
# deploy.sh), an agent test VM that reaches the appliance only through the edge (7444 dropped in the VM), and an
# agent rollout while that agent is offline: it must be updated through the edge once it is back.
#
#   edge.sh create      $DISK (lab/appliance/build-disk.sh of the edge lab image) imported as VM $VMID, started, its
#                       serial console tunnelled to $LAB_EDGE/console.sock, its DHCP address in $LAB_EDGE/ip
#   edge.sh enroll      edge "pve-edge" (control 7445, public 443 on its address) created, token typed on the
#                       console, enrolled, online
#   edge.sh assign      agent $AGENT_NAME reaches the appliance through the edge (rendezvous)
#   edge.sh block       7444 dropped in the agent VM ($VM_IP): only the edge path is left
#   edge.sh rollout     the agent stopped, a rollout to $VERSION for it created (it waits: unreachable), the agent
#                       started again: the rollout updates it through the edge
#   edge.sh unblock     the drop removed
#   edge.sh destroy     VM $VMID destroyed, the tunnel closed
#
# env: LAB, PORT (as deploy.sh); PVE_HOST, SSH_KEY; VMID (286), DISK (~/nexus-lab/edge-pve/edge.qcow2),
#      LAB_EDGE (~/nexus-lab/edge-pve), AGENT_NAME (clean-debian-13), VM_IP (10.2.34.5), VM_KEY, VERSION (0.1.21)
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
export LAB=${LAB:-$HOME/nexus-lab/pvehost}
export PORT=${PORT:-28444}
PVE_HOST=${PVE_HOST:-10.2.34.200}
SSH_KEY=${SSH_KEY:-$HOME/nexus-lab/pve-lab-key}
VMID=${VMID:-286}
LAB_EDGE=${LAB_EDGE:-$HOME/nexus-lab/edge-pve}
DISK=${DISK:-$LAB_EDGE/edge.qcow2}
AGENT_NAME=${AGENT_NAME:-clean-debian-13}
VM_IP=${VM_IP:-10.2.34.5}
VM_KEY=${VM_KEY:-$HOME/nexus-lab/lab_ed25519}
VERSION=${VERSION:-0.1.21}
ROOT=$LAB/appliance/root
S=$ROOT/run/api
mkdir -p "$S" "$LAB_EDGE"
# shellcheck disable=SC1091
. "$ROOT/secrets.env"
# shellcheck source=lab/e2e/api-lib.sh
. "$repo/lab/e2e/api-lib.sh"
[ "$VMID" -ge 200 ] || die "VMID $VMID: only VMs from 200 are ours"
pve() { ssh -n -i "$SSH_KEY" -o BatchMode=yes "root@$PVE_HOST" "$@"; }
econ() { CONSOLE=$LAB_EDGE/console.sock "$repo/lab/appliance/con.py" "$@"; }
vm() { ssh -i "$VM_KEY" -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR \
	-o ConnectTimeout=10 "root@$VM_IP" "$@"; }
agent_id() { api admin GET /agents | jq -r --arg n "$AGENT_NAME" '.[] | select(.name == $n) | .id'; }
edge_id() { api admin GET /edges | jq -r '.[] | select(.name == "pve-edge") | .id'; }

tunnel() {
	[ -S "$LAB_EDGE/tunnel.ctl" ] && ssh -S "$LAB_EDGE/tunnel.ctl" -O exit "root@$PVE_HOST" 2>/dev/null || true
	rm -f "$LAB_EDGE/console.sock"
	ssh -i "$SSH_KEY" -o BatchMode=yes -o ExitOnForwardFailure=yes -o StreamLocalBindUnlink=yes -f -N -M \
		-S "$LAB_EDGE/tunnel.ctl" -L "$LAB_EDGE/console.sock:/var/run/qemu-server/$VMID.serial0" "root@$PVE_HOST"
}

step_create() {
	pve "qm status $VMID" >/dev/null 2>&1 && die "VM $VMID exists (step destroy)"
	pve "mkdir -p /var/lib/vz/import"
	scp -q -i "$SSH_KEY" "$DISK" "root@$PVE_HOST:/var/lib/vz/import/nexus-edge.qcow2"
	pve "qm create $VMID --name nexus-edge --machine q35 --cpu host --cores 2 --memory 2048 --balloon 0 \
		--scsihw virtio-scsi-single --scsi0 vmpool:0,import-from=local:import/nexus-edge.qcow2,discard=on \
		--net0 virtio,bridge=vmbr0 --serial0 socket --vga std --boot order=scsi0 \
		--description 'NexusBackup edge proxy (lab, lab/pvehost/edge.sh)' >/dev/null && rm /var/lib/vz/import/nexus-edge.qcow2 &&
		qm start $VMID"
	tunnel
	econ wait 900
	local ip=
	for _ in $(seq 60); do
		# the console answers only once the autologin shell is up (kernel messages before)
		ip=$(econ run "ip -4 -o addr show scope global | awk '{print \$4}' | cut -d/ -f1 | head -1" 60 2>/dev/null | tail -1 | tr -d '\r' || true)
		[[ $ip =~ ^[0-9.]+$ ]] && break
		sleep 5
	done
	[[ $ip =~ ^[0-9.]+$ ]] || die "edge: no address"
	echo "$ip" >"$LAB_EDGE/ip"
	log "edge VM $VMID up at $ip"
}

step_enroll() {
	local ip r id tok j fp
	ip=$(cat "$LAB_EDGE/ip")
	login admin "$ADMIN_PW" "$ADMIN_TOTP"
	for id in $(edge_id); do api admin DELETE "/edges/$id" >/dev/null; done
	r=$(api admin POST /edges "$(jq -nc --arg h "$ip" '{name:"pve-edge", host:$h, port:7445, public_host:$h, public_port:443}')")
	expect 201 "create edge"
	id=$(jq -r .id <<<"$r")
	tok=$(jq -r .token <<<"$r")
	econ run "printf '%s\n' '$tok' | runuser -u nexus-edge -- nexus-edge init --token - && systemctl restart nexus-edge" >&2
	fp=$(econ run 'runuser -u nexus-edge -- nexus-edge status' | grep -oE '[0-9a-f]{64}' | head -1)
	r=$(api admin POST "/edges/$id/enroll")
	expect 202 "enroll edge"
	j=$(wait_job admin "$(jq -r .id <<<"$r")" 300)
	[ "$(jq -r .state <<<"$j")" = ok ] || die "edge_enroll: $(jq -r '.log // ""' <<<"$j" | tail -n 20)"
	api admin GET /edges | jq -e --arg id "$id" --arg fp "$fp" '.[] | select(.id == $id) | .cert_sha256 == $fp' >/dev/null ||
		die "pinned edge certificate differs from the console fingerprint $fp"
	for _ in $(seq 60); do
		api admin GET /edges | jq -e --arg id "$id" '.[] | select(.id == $id) | .online and .version != null' >/dev/null && break
		sleep 2
	done
	api admin GET /edges | jq -e --arg id "$id" '.[] | select(.id == $id) | .online' >/dev/null || die "edge not online"
	log "edge pve-edge ($id, $ip) enrolled and online"
}

step_assign() {
	local a e
	login admin "$ADMIN_PW" "$ADMIN_TOTP"
	a=$(agent_id)
	e=$(edge_id)
	[ -n "$a" ] && [ -n "$e" ] || die "need agent $AGENT_NAME and edge pve-edge"
	api admin PUT "/agents/$a/edge" "$(jq -nc --arg e "$e" '{edge_id:$e}')" >/dev/null
	expect 200 "assign edge"
	for _ in $(seq 90); do
		api admin GET /edges | jq -e --arg id "$e" --arg a "$a" '.[] | select(.id == $id) | .health.agents_online | index($a) != null' \
			>/dev/null && break
		sleep 2
	done
	api admin GET /edges | jq -e --arg id "$e" --arg a "$a" '.[] | select(.id == $id) | .health.agents_online | index($a) != null' \
		>/dev/null || die "agent never reached the edge"
	log "agent $AGENT_NAME ($a) meets the appliance at the edge"
}

step_block() {
	vm 'command -v nft >/dev/null || DEBIAN_FRONTEND=noninteractive apt-get install -y -qq nftables >/dev/null
		nft list table inet nexuslab >/dev/null 2>&1 || { nft add table inet nexuslab &&
		nft add chain inet nexuslab in "{ type filter hook input priority -10; }" && nft add rule inet nexuslab in tcp dport 7444 drop; }'
	log "7444 dropped in $VM_IP: only the edge path is left"
}

step_unblock() {
	vm 'nft delete table inet nexuslab 2>/dev/null || true'
	log "7444 open again in $VM_IP"
}

step_rollout() {
	local a r rid st before t0
	login admin "$ADMIN_PW" "$ADMIN_TOTP"
	a=$(agent_id)
	before=$(vm '/usr/local/sbin/nexus-agent version' | awk '{print $2}')
	vm 'systemctl stop nexus-agent'
	log "agent $AGENT_NAME ($before) stopped: the laptop is away"
	r=$(api admin POST /agent-rollouts "$(jq -nc --arg v "$VERSION" --arg a "$a" \
		'{version:$v, scope:{agents:[$a]}, canary:1, soak_minutes:0, concurrency:1}')")
	expect 201 "create rollout"
	rid=$(jq -r .id <<<"$r")
	sleep 120
	st=$(api admin GET "/agent-rollouts/$rid" | jq -c '{state, items: [.items[]? | {state, error}]}')
	log "rollout $rid after 2 min with the agent away: $st"
	t0=$SECONDS
	vm 'systemctl start nexus-agent'
	log "agent started again (7444 still dropped)"
	for _ in $(seq 90); do
		[ "$(vm '/usr/local/sbin/nexus-agent version' | awk '{print $2}')" = "$VERSION" ] &&
			api admin GET "/agent-rollouts/$rid" | jq -e '.state == "done" or .state == "completed" or ([.items[]? | .state] | all(. == "ok"))' >/dev/null && break
		sleep 10
	done
	st=$(api admin GET "/agent-rollouts/$rid" | jq -c '{state, items: [.items[]? | {state, error}]}')
	[ "$(vm '/usr/local/sbin/nexus-agent version' | awk '{print $2}')" = "$VERSION" ] || die "not updated: $st"
	log "updated $before -> $VERSION through the edge $((SECONDS - t0)) s after it came back; rollout: $st;" \
		"agent: $(api admin GET /agents | jq -c --arg a "$a" '.[] | select(.id == $a) | {version, via}')"
}

step_destroy() {
	pve "qm status $VMID >/dev/null 2>&1 || exit 0; qm stop $VMID >/dev/null 2>&1; qm destroy $VMID --purge 1 >/dev/null"
	[ -S "$LAB_EDGE/tunnel.ctl" ] && ssh -S "$LAB_EDGE/tunnel.ctl" -O exit "root@$PVE_HOST" 2>/dev/null || true
	log "edge VM $VMID destroyed"
}

[ $# -gt 0 ] || set -- create enroll assign block rollout unblock
for s in "$@"; do
	"step_$s"
done
