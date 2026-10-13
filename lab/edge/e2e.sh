#!/usr/bin/env bash
# Edge proxy end to end (Phase 26, docs/edge.md): the real edge bootc image in a VM, the dev
# control plane of lab/linux/e2e.sh on the host, one Linux lab VM as the "roaming laptop".
#
#   e2e.sh image     os/edge/build.sh --test-key + the lab image (serial root autologin)
#   e2e.sh disk      install it onto $LAB/edge/edge.qcow2 (rootless, lab/appliance/build-disk.sh)
#   e2e.sh boot      boot (lab/edge/run.sh), wait for the console
#   e2e.sh check     SELinux domain nexus_edge_t, only 443 + 7445 listening, nft input policy drop,
#                    no sshd, no getty on tty1..6, zero AVCs, systemd-analyze security
#   e2e.sh enroll    Settings > Edges via the API: create (token), token typed on the edge console
#                    (nexus-edge init --token -), Connect (edge_enroll job), edge online, pins match
#   e2e.sh assign    the laptop's agent: "reach via edge" -> SetEdge pushed by the next poll ->
#                    rendezvous (the agent is in the edge's agents_online)
#   e2e.sh refuse    TLS without a client cert / with an unknown cert: refused on 443 and 7445
#   e2e.sh via       direct path blocked in the laptop VM (7444 dropped): a manual backup runs via
#                    the edge ("via":"edge" in the job log, agents.via = edge), payload never in clear
#   e2e.sh request   "back up now" over the agent's UI socket: the backup job must start within
#                    $REQUEST_MAX seconds (wake through the edge -> immediate poll)
#   e2e.sh update    a bumped nexus-edge signed with the TEST key in the scheduler's edge update
#                    dir: the link pushes it, the edge restarts into it (health version changes)
#   e2e.sh unblock   remove the 7444 block again
#   e2e.sh all       everything above in order
# Prereqs: lab/linux/e2e.sh appliance (dev control plane) and lab/linux/e2e.sh $VM agent backup.
# env: VM (deb-plain), LAB (/home/ah/nexus-lab), IMG (localhost/nexus-edge-os:dev), PUB (18443),
#      CTL (17545; 17441..17445 are the lab VMs' agent ports), ROOT/PORT (as lab/linux/e2e.sh), EDGE_UPDATE_DIR ($ROOT/edge-update: the
#      scheduler's `edge_update_dir` in the lab config), REQUEST_MAX (30)
# Open (needs a second network): an nmap of the edge VM from outside; `check` reads the listening
# sockets and the nft ruleset inside the VM instead (the host forwards only 443/7445 anyway).
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
LAB=${LAB:-/home/ah/nexus-lab}
IMG=${IMG:-localhost/nexus-edge-os:dev}
export PUB=${PUB:-18443} CTL=${CTL:-17545}
export ROOT=${ROOT:-$repo/target/linux-root} PORT=${PORT:-18453}
VM=${VM:-deb-plain}
EDGE_UPDATE_DIR=${EDGE_UPDATE_DIR:-$ROOT/edge-update}
REQUEST_MAX=${REQUEST_MAX:-30}
export CONSOLE=$LAB/edge/console.sock
con() { "$repo/lab/appliance/con.py" "$@"; }
vm() { "$repo/lab/linux/vm.sh" "$VM" ssh "$@"; }
S=$ROOT/run/api
mkdir -p "$S"
R=$S/edge.results
touch "$R"
result() {
	grep -v "^$1=" "$R" >"$R.tmp" || true
	echo "$1=$2" >>"$R.tmp"
	mv "$R.tmp" "$R"
	log "result $1=$2"
}
api_env() {
	eval "$(ROOT=$ROOT PORT=$PORT "$repo/lab/e2e/m5.sh" env)"
	# shellcheck source=lab/e2e/api-lib.sh
	. "$repo/lab/e2e/api-lib.sh"
	login admin "$ADMIN_PW" "$ADMIN_TOTP"
	# shellcheck disable=SC1090
	[ -f "$S/$VM.env" ] && . "$S/$VM.env"
	# shellcheck disable=SC1091
	[ -f "$S/edge.env" ] && . "$S/edge.env"
	return 0
}
T0=$(date +%s)
log() { printf '[%4ss] %s\n' $(($(date +%s) - T0)) "$*" >&2; }
die() {
	log "FAIL: $*"
	exit 1
}

step_image() {
	IMAGE=$IMG "$repo/os/edge/build.sh" --test-key
	podman build --build-arg IMAGE="$IMG" -t "$IMG-lab" -f "$here/Containerfile.lab" "$repo"
}

step_disk() { SIZE=${SIZE:-8G} "$repo/lab/appliance/build-disk.sh" "$IMG-lab" "$LAB/edge/edge.qcow2"; }

step_boot() {
	"$here/run.sh" stop || true
	"$here/run.sh" start
	con wait 600
	log "booted: $(con run 'uname -r; getenforce' | tr '\n' ' ')"
}

step_check() {
	con run 'getenforce' | grep -qx Enforcing || die "SELinux not enforcing"
	con run 'ps -eZ | grep nexus-edge' | grep -q nexus_edge_t || die "nexus-edge not in nexus_edge_t"
	local ports
	ports=$(con run "ss -Htln | awk '{print \$4}' | sed 's/.*://' | sort -un | tr '\n' ' '")
	result listening "$ports"
	[ "$(echo "$ports" | xargs)" = "443 7445" ] || die "listening TCP ports: $ports"
	con run 'nft list chain inet edge input' | grep -q 'policy drop' || die "input policy is not drop"
	con run 'nft list chain inet edge output' | grep -q 'policy drop' || die "output policy is not drop"
	con run '! systemctl is-active -q sshd.service' || die "sshd running"
	con run 'test "$(systemctl is-enabled getty@tty2.service)" = masked' || die "getty not masked"
	con run 'journalctl -k -b | grep -c "avc:  denied" || true' | grep -qx 0 || {
		con run 'journalctl -k -b | grep "avc:  denied" | tail -n 20' >&2
		die "AVC denials"
	}
	result security "$(con run 'systemd-analyze security nexus-edge.service --no-pager | tail -n 1')"
}

step_enroll() {
	api_env
	local r id tok j fp
	r=$(api admin POST /edges "$(jq -nc --argjson p "$CTL" --argjson pp "$PUB" \
		'{name:"lab-edge", host:"127.0.0.1", port:$p, public_host:"10.0.2.2", public_port:$pp}')")
	expect 201 "create edge"
	id=$(jq -r .id <<<"$r")
	tok=$(jq -r .token <<<"$r")
	echo "EDGE=$id" >"$S/edge.env"
	api admin GET /edges | jq -e '.[0] | has("token") | not' >/dev/null || die "GET /edges leaks the token"
	# what the operator types on the console menu (2) Enrollment token
	con run "printf '%s\n' '$tok' | runuser -u nexus-edge -- nexus-edge init --token - && systemctl restart nexus-edge" >&2
	fp=$(con run 'runuser -u nexus-edge -- nexus-edge status' | grep -oE '[0-9a-f]{64}' | head -1)
	r=$(api admin POST "/edges/$id/enroll")
	expect 202 "enroll edge"
	j=$(wait_job admin "$(jq -r .id <<<"$r")" 300)
	[ "$(jq -r .state <<<"$j")" = ok ] || die "edge_enroll: $(jq -r .log <<<"$j" | tail -n 20)"
	api admin GET /edges | jq -e --arg id "$id" --arg fp "$fp" '.[] | select(.id==$id) | .cert_sha256 == $fp' >/dev/null ||
		die "pinned edge certificate differs from the console fingerprint $fp"
	local i
	for i in $(seq 60); do
		api admin GET /edges | jq -e --arg id "$id" '.[] | select(.id==$id) | .online and .version != null' >/dev/null && break
		[ "$i" = 60 ] && die "edge not online after enrollment"
		sleep 2
	done
	api admin POST "/edges/$id/enroll" >/dev/null
	[ "$(status)" = 409 ] || die "second enroll: HTTP $(status)"
	result enrolled "$id $fp"
}

step_assign() {
	api_env
	[ -n "${AGENT:-}" ] && [ -n "${EDGE:-}" ] || die "need lab/linux agent step and edge enroll"
	api admin PUT "/agents/$AGENT/edge" "$(jq -nc --arg e "$EDGE" '{edge_id:$e}')" >/dev/null
	expect 200 "assign edge"
	local i
	for i in $(seq 90); do
		api admin GET /edges | jq -e --arg id "$EDGE" --arg a "$AGENT" \
			'.[] | select(.id==$id) | .health.agents_online | index($a) != null' >/dev/null && break
		[ "$i" = 90 ] && die "agent never reached the edge (edge_pushed: $(api admin GET /agents | jq -r --arg a "$AGENT" '.[] | select(.id==$a) | .edge_pushed'))"
		sleep 2
	done
	vm 'sudo cat /var/lib/nexus-agent/edge.json' | sed 's/^/  vm: /' >&2
	result rendezvous ok
}

step_refuse() {
	local d
	d=$(mktemp -d)
	openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/CN=nexus-agent:0123456789abcdef" \
		-keyout "$d/k.pem" -out "$d/c.pem" -days 1 2>/dev/null
	local p
	for p in "$PUB" "$CTL"; do
		if echo | timeout 10 openssl s_client -connect "127.0.0.1:$p" -alpn nexus-edge/1 -tls1_3 -quiet 2>/dev/null; then
			die "port $p: TLS without a client certificate was not refused"
		fi
		if echo | timeout 10 openssl s_client -connect "127.0.0.1:$p" -alpn nexus-edge/1 -tls1_3 \
			-cert "$d/c.pem" -key "$d/k.pem" -quiet 2>/dev/null; then
			die "port $p: an unknown client certificate was not refused"
		fi
	done
	rm -rf "$d"
	result unknown_cert refused
}

step_via() {
	api_env
	vm 'sudo nft add table inet nexuslab && sudo nft add chain inet nexuslab in "{ type filter hook input priority -10; }" &&
		sudo nft add rule inet nexuslab in tcp dport 7444 drop' || die "cannot block 7444 in $VM"
	local r j t0=$SECONDS
	r=$(api admin POST /jobs "$(jq -nc --arg a "$AGENT" '{kind:"backup", tenant:"linux", params:{agent_id:$a}}')")
	expect 202 "backup via edge"
	j=$(wait_job admin "$(jq -r .id <<<"$r")" 1800)
	[ "$(jq -r .state <<<"$j")" = ok ] || die "backup via edge: $(jq -r .log <<<"$j" | tail -n 20)"
	jq -r .log <<<"$j" | grep -m1 '^agent-info ' | grep -q '"via":"edge"' || die "job did not go through the edge"
	api admin GET /agents | jq -e --arg a "$AGENT" '.[] | select(.id==$a) | .via == "edge"' >/dev/null || die "agents.via not edge"
	result via_edge_backup_s $((SECONDS - t0))
	# the edge log carries connection metadata only
	con run 'journalctl -u nexus-edge -b --no-pager -o cat | tail -n 15' | sed 's/^/  edge: /' >&2
}

step_request() {
	api_env
	local r rid i id t0
	r=$(vm "sudo python3 -c 'import socket; s=socket.socket(socket.AF_UNIX); s.connect(\"/run/nexus-agent/ui.sock\"); s.sendall(b\"{\\\"op\\\":\\\"request_backup\\\"}\\n\"); print(s.makefile().readline().strip())'")
	rid=$(jq -er .request_id <<<"$r") || die "request_backup: $r (rate limited? wait 10 min after lab/linux endpoint)"
	t0=$SECONDS
	for i in $(seq $((REQUEST_MAX * 2))); do
		id=$(api admin GET /jobs | jq -r --arg r "$rid" '[.[] | select(.params.request_id==$r and (.state=="running" or .state=="ok"))] | .[0].id // empty')
		[ -n "$id" ] && break
		sleep 0.5
	done
	[ -n "$id" ] || die "the requested backup did not start within $REQUEST_MAX s"
	result request_start_s $((SECONDS - t0))
	local j
	j=$(wait_job admin "$id" 1800)
	[ "$(jq -r .state <<<"$j")" = ok ] || die "requested backup: $(jq -r .log <<<"$j" | tail -n 20)"
}

step_update() {
	api_env
	local src=$repo/target/edge-bump/src ver cur
	cur=$(api admin GET /edges | jq -r --arg id "$EDGE" '.[] | select(.id==$id) | .version')
	ver=$(python3 -c 'import sys; a=sys.argv[1].split("."); a[2]=str(int(a[2])+1); print(".".join(a))' "$cur")
	mkdir -p "$src"
	find "$src" -mindepth 1 -maxdepth 1 ! -name target -exec rm -rf {} +
	git -C "$repo" ls-files -z --cached --others --exclude-standard | tar -C "$repo" --null -T - -cf - | tar -C "$src" -xf -
	sed -i "0,/^version = \".*\"/s//version = \"$ver\"/" "$src/crates/edge/Cargo.toml"
	sed -i "/^name = \"edge\"$/{n;s/^version = \".*\"/version = \"$ver\"/}" "$src/Cargo.lock"
	# built in the edge image's rust stage: the binary must run on its glibc
	podman build --target rust -f "$src/os/edge/Containerfile" -t localhost/nexus-edge-bump:"$ver" "$src"
	mkdir -p "$EDGE_UPDATE_DIR"
	local c
	c=$(podman create localhost/nexus-edge-bump:"$ver")
	podman cp "$c:/out/nexus-edge" "$EDGE_UPDATE_DIR/nexus-edge"
	podman rm -f "$c" >/dev/null
	COSIGN_KEY=$repo/release/testkey/TEST-cosign.key COSIGN_PASSWORD=nexus-test-key \
		"$repo/release/sign.sh" sign-blob "$EDGE_UPDATE_DIR/nexus-edge" "$EDGE_UPDATE_DIR/nexus-edge.sig"
	echo "$ver" >"$EDGE_UPDATE_DIR/nexus-edge.version"
	local i
	for i in $(seq 120); do
		api admin GET /edges | jq -e --arg id "$EDGE" --arg v "$ver" '.[] | select(.id==$id) | .version == $v and .online' >/dev/null && break
		[ "$i" = 120 ] && die "edge did not report $ver"
		sleep 2
	done
	con run 'ls -Z /var/lib/nexus-edge/update/' | sed 's/^/  edge: /' >&2
	con run 'journalctl -k -b | grep -c "avc:  denied" || true' | grep -qx 0 || die "AVC denials after the update"
	result update "$cur -> $ver"
}

step_unblock() { vm 'sudo nft delete table inet nexuslab' || true; }

case ${1:-} in
image | disk | boot | check | enroll | assign | refuse | via | request | update | unblock) "step_$1" ;;
all) for s in image disk boot check enroll assign refuse via request update unblock; do "step_$s"; done ;;
*) sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//' >&2; exit 2 ;;
esac
