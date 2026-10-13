#!/usr/bin/env bash
# Network lab (Phase 22a, docs/control-plane.md "Network interfaces") against an installed appliance VM
# (SELinux enforcing) booted with three extra NICs on one QEMU hub, after first boot:
#   EXTRA_NICS=3 lab/appliance/e2e.sh boot && lab/appliance/e2e.sh setup
#   (NIC 1 + 2 become bond0, NIC 3 is moved into the netns `peer` inside the guest: the "switch" and a
#   data-network host 10.20.0.9 on VLAN 20, MTU 9000)
#   network.sh status   nexus-net reports the three NICs (by MAC), the console management interface
#   network.sh peer     console: netns peer with NIC 3, VLAN 20, 10.20.0.9/24, MTU 9000
#   network.sh apply    bond0 (NIC 1+2, active-backup, MTU 9000) + bond0.20 (VLAN 20, role data,
#                       10.20.0.5/24, no gateway) through approval: keyfiles 0600 with the NetworkManager
#                       label, bond and VLAN up with MTU 9000 (the 9000-byte path: see mtu)
#   network.sh egress   an NFS source on 10.20.0.9: the firewall file binds it to bond0.20
#                       (bound_out_v4 holds `10.20.0.9 . tcp . 2049 . "bond0.20"`)
#   network.sh mtu      path-MTU check: ok at 9000; with a 1500-byte limit in the peer: mismatch
#                       (path ~1500) and the diagnostics check network.mtu warns
#   network.sh mgmt     give ens-mgmt (the console NIC, DHCP) the management role: not confirmed ->
#                       rolled back after 120 s (console profile back); again and confirmed -> kept
#   network.sh all      status peer apply egress mtu mgmt
# Afterwards: lab/appliance/e2e.sh check (0 nexus AVCs; nexus-net runs as nexus_net_t).
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
MAC1=52:54:00:4e:58:01 MAC2=52:54:00:4e:58:02 MAC3=52:54:00:4e:58:03

apienv() {
	S=$ROOT/run/network
	mkdir -p "$S"
	# shellcheck disable=SC1091
	. "$ROOT/secrets.env"
	# shellcheck source=lab/e2e/api-lib.sh
	. "$repo/lab/e2e/api-lib.sh"
	login admin "$ADMIN_PW" "$ADMIN_TOTP"
	login so "$SO_PW" "$SO_TOTP"
}

net() { api admin GET /network; }
nic() { net | jq -r --arg m "$1" '.devices[] | select(.mac == $m and .kind == "nic") | .name'; }

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

# wait_op QUORUM_ID [timeout s] [states] -> the operation JSON once in one of the states
wait_op() {
	local q=$1 to=${2:-120} states=${3:-done refused error rolled_back} o st
	for _ in $(seq "$to"); do
		o=$(net | jq -c --argjson q "$q" '[.ops[] | select(.quorum_id == $q)][0] // empty')
		st=$(jq -r '.state // empty' <<<"$o" 2>/dev/null)
		for w in $states; do [ "$st" = "$w" ] && { echo "$o"; return 0; }; done
		sleep 1
	done
	die "operation of quorum #$q not in [$states]: $o"
}

# request CONFIG_JSON -> quorum id (approved)
request() {
	api admin PUT /network "$(jq -nc --argjson c "$1" '{config: $c}')" >/dev/null
	expect 202 "PUT /network"
	approve
}

status() {
	apienv
	local n
	for _ in $(seq 60); do
		n=$(net)
		jq -e '.available' <<<"$n" >/dev/null && break
		sleep 5
	done
	jq -e '.available and (.stale | not)' <<<"$n" >/dev/null || die "no nexus-net status: $(jq -c '{available, stale}' <<<"$n")"
	for m in $MAC1 $MAC2 $MAC3; do [ -n "$(nic "$m")" ] || die "NIC $m not reported: $(jq -c .devices <<<"$n")"; done
	jq -e '.management.source == "console" and (.management.ifname | length > 0)' <<<"$n" >/dev/null ||
		die "management: $(jq -c .management <<<"$n")"
	log "nexus-net: $(jq -r '[.devices[] | "\(.name)(\(.kind))"] | join(" ")' <<<"$n"), management $(jq -r .management.ifname <<<"$n")"
}

peer() {
	apienv
	local p
	p=$(nic $MAC3)
	con run "ip netns add peer 2>/dev/null || true; ip link set $p netns peer;
		ip -n peer link set $p mtu 9000 up; ip -n peer link add link $p name v20 type vlan id 20;
		ip -n peer link set v20 mtu 9000 up; ip -n peer addr add 10.20.0.9/24 dev v20; ip -n peer -br addr" |
		tee "$S/peer.txt"
	grep -q '10.20.0.9/24' "$S/peer.txt" || die "peer netns"
}

apply() {
	apienv
	local a b cfg q o
	a=$(nic $MAC1)
	b=$(nic $MAC2)
	cfg=$(jq -nc --arg a "$a" --arg b "$b" '{interfaces: [
		{name: "bond0", kind: "bond", ports: [$a, $b], mode: "active-backup", mtu: 9000},
		{name: "bond0.20", kind: "vlan", parent: "bond0", vlan_id: 20, role: "data", mtu: 9000,
		 addresses: ["10.20.0.5/24"]}], offsite_role: "management"}')
	# refusals first: a gateway on a data interface, an unknown NIC
	api admin PUT /network "$(jq -c '{config: (.interfaces[1].gateway = "10.20.0.1")}' <<<"$cfg")" >/dev/null
	expect 400 "gateway on the data interface"
	api admin PUT /network "$(jq -c '{config: (.interfaces[0].ports = ["nosuch0"])}' <<<"$cfg")" >/dev/null
	expect 400 "unknown NIC"
	q=$(request "$cfg")
	o=$(wait_op "$q" 120)
	[ "$(jq -r .state <<<"$o")" = "done" ] || die "apply: $o"
	log "apply: $(jq -r .detail <<<"$o")"
	con run 'ls -lZ /etc/NetworkManager/system-connections/; nmcli -t -f NAME,DEVICE,STATE connection show --active;
		ip -br addr show bond0.20; cat /sys/class/net/bond0/bonding/mode; ip -d link show bond0.20 | grep -o "mtu [0-9]*"' | tee "$S/apply.txt"
	grep -q 'nexus-bond0.20.nmconnection' "$S/apply.txt" || die "keyfile missing"
	grep -E 'nexus-bond0.nmconnection' "$S/apply.txt" | grep -q '^-rw-------.*NetworkManager_etc_rw_t' || die "keyfile mode/label"
	grep -q '10.20.0.5/24' "$S/apply.txt" || die "bond0.20 has no address"
	grep -q 'active-backup' "$S/apply.txt" || die "bond mode"
	# no ping from the console here: default-deny egress drops it (the peer is no source yet);
	# the 9000-byte path is checked by nexus-net's own probe in the mtu step
	grep -q '^mtu 9000' "$S/apply.txt" || die "bond0.20 MTU is not 9000"
	[ "$(api admin GET '/audit?action=network.op' | jq length)" -ge 1 ] || die "network.op not audited"
	log "bond0 + VLAN 20 applied, jumbo frames to the peer"
}

egress() {
	apienv
	local t
	t=$(api admin GET /tenants | jq -r '.[0].name // empty')
	if [ -z "$t" ]; then
		api admin POST /tenants '{"name":"nettest"}' >/dev/null
		t=nettest
	fi
	api admin POST /sources "$(jq -nc --arg t "$t" '{tenant: $t, kind: "nfs", name: "peer-nfs",
		config: {host: "10.20.0.9", export: "/srv/nfs", version: "4.2"}}')" >/dev/null
	case $(status) in 200 | 201) ;; *) die "NFS source: $(cat "$S/body")" ;; esac
	for _ in $(seq 30); do
		con run 'nft list set inet nexus bound_out_v4' >"$S/bound.txt" || true
		grep -q '10.20.0.9 . tcp . 2049 . "bond0.20"' "$S/bound.txt" && break
		sleep 5
	done
	grep -q '10.20.0.9 . tcp . 2049 . "bond0.20"' "$S/bound.txt" || die "not bound: $(cat "$S/bound.txt")"
	con run 'nft list set inet nexus allowed_out_v4; nft list set inet nexus probe_v4' | tee "$S/unbound.txt"
	! grep -q '10.20.0.9 . tcp . 2049 ' "$S/unbound.txt" || die "10.20.0.9 also unbound"
	grep -q '10.20.0.9' "$S/unbound.txt" || die "10.20.0.9 not in probe_v4"
	log "NFS source 10.20.0.9 bound to bond0.20"
}

mtu_run() { # -> the result for 10.20.0.9 after a fresh check
	local before r
	before=$(net | jq -r '.mtu.ts // 0')
	api admin POST /network/mtu-check '{}' >/dev/null
	expect 202 "POST /network/mtu-check"
	for _ in $(seq 60); do
		r=$(net)
		[ "$(jq -r '.mtu.ts // 0' <<<"$r")" -gt "$before" ] && break
		sleep 2
	done
	jq -c '.mtu.results[] | select(.addr == "10.20.0.9")' <<<"$r"
}

mtu() {
	apienv
	local r id d
	r=$(mtu_run)
	jq -e '.result == "ok" and .mtu == 9000 and .dev == "bond0.20"' <<<"$r" >/dev/null || die "MTU check: $r"
	log "path MTU ok: $r"
	# a 1500-byte link somewhere on the path: drop larger frames in the peer
	con run 'ip netns exec peer nft add table inet lab; ip netns exec peer nft add chain inet lab in "{ type filter hook input priority 0; }";
		ip netns exec peer nft add rule inet lab in meta length gt 1500 drop'
	r=$(mtu_run)
	jq -e '.result == "mismatch" and .path_mtu >= 1400 and .path_mtu <= 1500' <<<"$r" >/dev/null || die "no mismatch: $r"
	log "mismatch detected: $r"
	id=$(api so POST /diagnostics/checks '{}' | jq -r .id)
	expect 202 "run checks"
	for _ in $(seq 120); do
		d=$(api so GET "/diagnostics/$id")
		[ "$(jq -r .state <<<"$d")" = "done" ] && break
		sleep 1
	done
	jq -e '.checks[] | select(.id == "network.mtu") | .status == "warn"' <<<"$d" >/dev/null ||
		die "network.mtu: $(jq -c '.checks[] | select(.id == "network.mtu")' <<<"$d")"
	con run 'ip netns exec peer nft delete table inet lab'
}

mgmt() {
	apienv
	local m cfg q o n
	n=$(net)
	m=$(jq -r .management.ifname <<<"$n")
	cfg=$(jq -c --arg m "$m" '.config | .interfaces += [{name: $m, kind: "ethernet", role: "management", dhcp: true}]' <<<"$n")
	q=$(request "$cfg")
	o=$(wait_op "$q" 120 "confirming done refused error")
	[ "$(jq -r .state <<<"$o")" = confirming ] || die "expected a pending confirmation: $o"
	log "management change applied, waiting for the automatic rollback (120 s)"
	o=$(wait_op "$q" 200)
	[ "$(jq -r .state <<<"$o")" = rolled_back ] || die "not rolled back: $o"
	[ "$(net | jq -r .management.source)" = console ] || die "management not back to the console profile"
	con run 'grep -c "written by nexus-net" /etc/NetworkManager/system-connections/nexus-mgmt.nmconnection || true' | tee "$S/mgmt.txt"
	grep -qx 0 "$S/mgmt.txt" || die "nexus-mgmt not restored"
	# again, confirmed this time
	q=$(request "$cfg")
	o=$(wait_op "$q" 120 "confirming done refused error")
	n=$(net)
	api admin POST /network/confirm "$(jq -c '{id: .pending.id, keep: true}' <<<"$n")" >/dev/null
	expect 202 "confirm"
	o=$(wait_op "$q" 60)
	[ "$(jq -r .state <<<"$o")" = "done" ] || die "confirm: $o"
	[ "$(net | jq -r .management.source)" = config ] || die "management not from the configuration"
	log "management change: rolled back unconfirmed, kept when confirmed"
}

case ${1:-} in
status | peer | apply | egress | mtu | mgmt) "$1" ;;
all) status && peer && apply && egress && mtu && mgmt ;;
*) sed -n '2,22p' "$0" >&2; exit 2 ;;
esac
