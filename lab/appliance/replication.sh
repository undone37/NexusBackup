#!/usr/bin/env bash
# Appliance replication lab (docs/replication.md): two appliance VMs from the same
# image, both SELinux enforcing. A = primary (backs up PVE lab VM 100), B = secondary
# (pulls from A through the host: 10.0.2.2:$PORT_A is A's forwarded 8443).
#   replication.sh disks           install the lab image once, copy it for A and B
#   replication.sh boot            boot A and B (lab/appliance/run.sh)
#   replication.sh setup           nexus-setup on both (A with the PVE lab keys, B without)
#   replication.sh primary         A: tenant lab, PVE source, group [100], backup VM 100
#   replication.sh enroll          A: peer (quorum), B: replication source with code + A's fingerprint,
#                                  enrollment job; A: approve the key export
#   replication.sh sync            B: sync now, wait, report throughput (run again after `backup2`)
#   replication.sh backup2         A: second backup of VM 100 (incremental replication)
#   replication.sh restore         stop A, B: list + download /etc/hostname from vm-100 (micro-VM)
#   replication.sh check           AVCs / domains on both (lab/appliance/e2e.sh check)
#   replication.sh stop            power off both VMs
# env: IMG (localhost/nexus-os:repl-lab), LABDIR (/home/ah/nexus-lab: PVE lab keys), PORT_A (28471),
#      PORT_B (28472), MEM_A (2560), MEM_B (3072)
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
IMG=${IMG:-localhost/nexus-os:repl-lab}
LABDIR=${LABDIR:-/home/ah/nexus-lab}
PORT_A=${PORT_A:-28471}
PORT_B=${PORT_B:-28472}
MEM_A=${MEM_A:-2560}
MEM_B=${MEM_B:-3072}
LA=$LABDIR/repl-a
LB=$LABDIR/repl-b
T0=$(date +%s)
log() { printf '[%4ss] %s\n' $(($(date +%s) - T0)) "$*" >&2; }
die() {
	log "FAIL: $*"
	exit 1
}

# per-VM environment for e2e.sh / run.sh / con.py / api-lib.sh
vm() { # vm a|b -> exports LAB PORT ROOT CONSOLE MEM
	case $1 in
	a) export LAB=$LA PORT=$PORT_A MEM=$MEM_A ;;
	b) export LAB=$LB PORT=$PORT_B MEM=$MEM_B ;;
	esac
	export ROOT=$LAB/appliance/root CONSOLE=$LAB/appliance/console.sock
}
con() { "$here/con.py" "$@"; }

disks() {
	for d in "$LA" "$LB"; do
		mkdir -p "$d/appliance/work"
		# PVE lab credentials where e2e.sh / m5-api.sh expect them ($LAB/...)
		for f in appliance_ed25519 appliance_ed25519.pub lab_ed25519 lab_ed25519.pub known_hosts api-token; do
			ln -sfn "$LABDIR/$f" "$d/$f"
		done
	done
	# reuse the installer root of the shared lab if it is current (12 GB sparse)
	if [ ! -f "$LA/appliance/work/installer.raw" ] && [ -f "$LABDIR/appliance/work/installer.raw" ]; then
		cp --sparse=always "$LABDIR/appliance/work/installer."{raw,vmlinuz,initrd,id} "$LA/appliance/work/"
	fi
	LAB=$LA "$here/build-disk.sh" "$IMG" "$LA/appliance/appliance.qcow2"
	cp --sparse=always "$LA/appliance/appliance.qcow2" "$LB/appliance/appliance.qcow2"
	log "disks: $LA/appliance/appliance.qcow2, $LB/appliance/appliance.qcow2"
}

boot() {
	for x in a b; do
		(
			vm $x
			"$here/run.sh" stop || true
			"$here/run.sh" start
		)
	done
	for x in a b; do
		(
			vm $x
			con wait 600
			log "$x booted: $(con run 'getenforce; bootc status --format=humanreadable 2>/dev/null | sed -n 2p' | tr '\n' ' ')"
		)
	done
}

setup() {
	(vm a && PVE=1 "$here/e2e.sh" setup)
	(vm b && PVE=0 "$here/e2e.sh" setup)
	for x in a b; do
		(vm $x && con run 'systemctl is-active nexus-replicad nexus-web-api nexus-scheduler nexus-keyd; ls -lZ /run/nexus-replicad')
	done
}

# REST as user u on VM x (lab/e2e/api-lib.sh; state per VM)
apienv() {
	vm "$1"
	S=$ROOT/run/api
	mkdir -p "$S"
	# shellcheck disable=SC1091
	. "$ROOT/secrets.env"
	# shellcheck source=lab/e2e/api-lib.sh
	. "$repo/lab/e2e/api-lib.sh"
}

primary() {
	(
		apienv a
		login admin "$ADMIN_PW" "$ADMIN_TOTP"
		local ca tok cfg src pol grp r j
		ca=$S/pve-root-ca.pem
		ssh -o BatchMode=yes -p 10022 -i "$LABDIR/lab_ed25519" -o UserKnownHostsFile="$LABDIR/known_hosts" root@localhost \
			cat /etc/pve/pve-root-ca.pem >"$ca"
		tok=$(sed 's/^[^=]*=//' "$LABDIR/api-token" | tr -d '\n')
		api admin POST /tenants '{"name":"lab"}' >/dev/null
		expect 201 "create tenant"
		cfg=$(jq -nc --rawfile ca "$ca" --arg tok "$tok" \
			'{host:"pve1", port:18006, connect_addr:"10.0.2.2:18006", ca_pem:$ca, token_id:"nexus@pve!appliance", token_secret:$tok,
			  nodes:{pve1:{host:"10.0.2.2", port:10022, key:"/etc/nexus/ssh/pve1", known_hosts:"/etc/nexus/ssh/known_hosts"}},
			  storage:"nexus", fleecing_storage:"local-lvm"}')
		src=$(api admin POST /sources "$(jq -nc --argjson c "$cfg" '{tenant:"lab", kind:"pve", name:"pve1", config:$c}')" | jq -r .id)
		expect 201 "create source"
		pol=$(api admin POST /policies '{"name":"lab","schedule":"daily 03:33","gfs":{"daily":14,"weekly":4,"monthly":6,"yearly":2},"offsite":false}' | jq -r .id)
		expect 201 "create policy"
		grp=$(api admin POST /groups "$(jq -nc --argjson s "$src" --argjson p "$pol" '{tenant:"lab", source_id:$s, policy_id:$p, name:"vm100", guests:[100]}')" | jq -r .id)
		expect 201 "create group"
		echo "GRP=$grp" >"$S/ids"
		backup_a "$grp"
	)
}

backup_a() { # inside apienv a
	local r j
	r=$(api admin POST /jobs "$(jq -nc --argjson g "$1" '{kind:"backup", tenant:"lab", params:{group_id:$g}}')")
	expect 202 "backup job"
	j=$(wait_job admin "$(jq -r .id <<<"$r")" 1800)
	[ "$(jq -r .state <<<"$j")" = ok ] || die "backup: $(jq -r .log <<<"$j" | tail -n 20)"
	log "A: backup job $(jq -r .id <<<"$j") ok in $(jq '.finished - .started' <<<"$j") s: $(jq -c .result <<<"$j")"
}

backup2() {
	(
		apienv a
		login admin "$ADMIN_PW" "$ADMIN_TOTP"
		# shellcheck disable=SC1091
		. "$S/ids"
		ssh -o BatchMode=yes -i "$LABDIR/lab_ed25519" -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no \
			-o ProxyCommand="ssh -o BatchMode=yes -W %h:%p -p 10022 -i $LABDIR/lab_ed25519 -o UserKnownHostsFile=$LABDIR/known_hosts root@localhost" \
			debian@10.10.10.100 \
			'sudo sh -c "date > /etc/nexus-repl-marker; dd if=/dev/urandom of=/var/tmp/repl-blob bs=1M count=64 status=none; sync"' ||
			log "could not change VM 100 (continuing with an unchanged guest)"
		backup_a "$GRP"
	)
}

fingerprint() { # x -> SHA-256 of the appliance TLS certificate
	vm "$1"
	openssl x509 -in "$ROOT/etc/nexus/tls/cert.pem" -outform DER | sha256sum | cut -d' ' -f1
}

enroll() {
	local fp code
	fp=$(fingerprint a)
	code=$(
		apienv a
		login admin "$ADMIN_PW" "$ADMIN_TOTP"
		login so "$SO_PW" "$SO_TOTP"
		r=$(api admin POST /replication/peers '{"name":"dr-site","tenants":["lab"]}')
		expect 202 "create peer"
		q=$(jq -r .quorum_id <<<"$r")
		api so POST "/quorum/$q/approve" '{}' >/dev/null
		expect 200 "approve peer"
		jq -r .code <<<"$r"
	)
	log "A: peer approved, code ${code%%.*}.…, A's fingerprint $fp"
	(
		apienv b
		login admin "$ADMIN_PW" "$ADMIN_TOTP"
		r=$(api admin POST /replication/sources "$(jq -nc --arg u "10.0.2.2:$PORT_A" --arg c "$code" --arg f "$fp" \
			'{name:"primary-a", url:$u, code:$c, fingerprint:$f, tenants:["lab"], schedule:"hourly 17"}')")
		expect 201 "create replication source"
		j=$(wait_job admin "$(jq -r .job <<<"$r")" 300)
		[ "$(jq -r .state <<<"$j")" = ok ] || die "enrollment: $(jq -r .log <<<"$j" | tail -n 20)"
		log "B: enrolled: $(jq -c .result <<<"$j")"
		api admin GET /replication/sources | jq -c '.[0] | {state, cert_sha256, keyd_fingerprint}' >&2
	)
	(
		apienv a
		login admin "$ADMIN_PW" "$ADMIN_TOTP"
		login so "$SO_PW" "$SO_TOTP"
		q=$(api so GET '/quorum?state=pending' | jq -r '[.[] | select(.action=="replication.key_export")][0].id')
		[ "$q" != null ] || die "no key export request"
		log "A: key export request $q for keyd $(api so GET '/quorum?state=pending' | jq -r --argjson q "$q" '.[] | select(.id==$q) | .params.keyd_fingerprint')"
		api so POST "/quorum/$q/approve" '{}' >/dev/null
		expect 200 "approve key export"
		for _ in $(seq 120); do
			st=$(api admin GET /quorum | jq -r --argjson q "$q" '.[] | select(.id==$q) | .state')
			[ "$st" = executed ] && break
			sleep 1
		done
		[ "$st" = executed ] || die "key export not executed ($st)"
		log "A: keys exported: $(api admin GET /replication/peers | jq -c '.[0] | {state, keys, keyd_fingerprint}')"
	)
}

sync() {
	(
		apienv b
		login admin "$ADMIN_PW" "$ADMIN_TOTP"
		r=$(api admin POST /replication/sources/1/sync '{}')
		expect 202 "sync"
		for id in $(jq -r '.jobs[]' <<<"$r"); do
			j=$(wait_job admin "$id" 3600)
			[ "$(jq -r .state <<<"$j")" = ok ] || die "sync $id: $(jq -r .log <<<"$j" | tail -n 30)"
			jq -r .log <<<"$j" | grep -E '^(imported|tenant|retention)' >&2 || true
			local secs bytes
			secs=$(jq '.result.secs' <<<"$j")
			bytes=$(jq '.result.bytes_fetched' <<<"$j")
			log "B: sync job $id ok: $(jq -c '.result | {imported, chunks_fetched, chunks_present, bytes_fetched, secs}' <<<"$j")"
			log "B: throughput $(python3 -c "print(f'{$bytes/1e6/max($secs,0.001):.1f} MB/s sealed ({$bytes/1e6:.1f} MB in {$secs:.1f} s)')")"
		done
		for _ in $(seq 60); do
			api admin GET '/snapshots?tenant=lab' | jq -e 'length > 0' >/dev/null && break
			sleep 2
		done
		api admin GET '/snapshots?tenant=lab' | jq -c '.[] | {source, time, size, origin, lock_until}' >&2
	)
}

restore() {
	(vm a && "$here/run.sh" stop)
	log "A stopped"
	(
		apienv b
		login admin "$ADMIN_PW" "$ADMIN_TOTP"
		local time r j path=/etc/hostname mnt tok
		time=$(api admin GET '/snapshots?tenant=lab&source=vm-100' | jq -r '.[0].time')
		r=$(api admin POST /jobs "$(jq -nc --argjson t "$time" '{kind:"files_list", tenant:"lab", params:{source:"vm-100", time:$t, path:"/"}}')")
		expect 202 "files_list"
		j=$(wait_job admin "$(jq -r .id <<<"$r")" 900)
		[ "$(jq -r .state <<<"$j")" = ok ] || die "files_list: $(jq -r .log <<<"$j" | tail -n 30)"
		log "B: vm-100@$time / = $(jq -c '[.result.entries[].name]' <<<"$j")"
		for mnt in $(jq -r '.result.entries[] | select(.kind=="dir") | .name' <<<"$j"); do
			r=$(api admin POST /jobs "$(jq -nc --argjson t "$time" --arg p "/$mnt/etc" '{kind:"files_list", tenant:"lab", params:{source:"vm-100", time:$t, path:$p}}')")
			j=$(wait_job admin "$(jq -r .id <<<"$r")" 900)
			if jq -e '.state == "ok" and ([.result.entries[]?.name] | index("hostname") != null)' <<<"$j" >/dev/null; then
				path=/$mnt/etc/hostname
				break
			fi
		done
		r=$(api admin POST /jobs "$(jq -nc --argjson t "$time" --arg p "$path" '{kind:"files_get", tenant:"lab", params:{source:"vm-100", time:$t, paths:[$p], format:"tar"}}')")
		expect 202 "files_get"
		tok=$(jq -r .download_token <<<"$r")
		j=$(wait_job admin "$(jq -r .id <<<"$r")" 900)
		[ "$(jq -r .state <<<"$j")" = ok ] || die "files_get: $(jq -r .log <<<"$j" | tail -n 30)"
		api admin GET "/downloads/$tok" >/dev/null
		expect 200 "download"
		cp "$S/body" "$S/restored.tar"
		log "B: restored $path from the replicated snapshot (primary is off): $(tar -xOf "$S/restored.tar" --wildcards '*hostname')"
	)
}

check() {
	for x in a b; do
		(
			vm $x
			if [ -S "$CONSOLE" ] && [ -f "$LAB/appliance/qemu.pid" ] && kill -0 "$(cat "$LAB/appliance/qemu.pid")" 2>/dev/null; then
				log "== $x"
				"$here/e2e.sh" check
				con run 'echo "== AVCs/SELinux errors with a nexus context since boot:"; ausearch -m avc,user_avc,selinux_err -ts boot 2>/dev/null | grep -E "(s|t)context=[^ ]*nexus_|context=[^ ]*nexus_" | wc -l; ausearch -m avc,user_avc,selinux_err -ts boot 2>/dev/null | grep -E "context=[^ ]*nexus_" | tail -5; ps -eZ | grep -E "replica"'
			else
				log "$x is not running"
			fi
		)
	done
}

stop() {
	for x in a b; do (vm $x && "$here/run.sh" stop); done
}

[ $# -gt 0 ] || { sed -n '2,19p' "$0" >&2; exit 2; }
for step in "$@"; do
	case $step in
	disks | boot | setup | primary | enroll | sync | backup2 | restore | check | stop) "$step" ;;
	*) sed -n '2,19p' "$0" >&2; exit 2 ;;
	esac
done
