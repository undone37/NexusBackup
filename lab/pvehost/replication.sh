#!/usr/bin/env bash
# Appliance replication and vault mode on the PVE lab host (docs/replication.md, manual chapter 8; #62): VM 201 (A,
# the primary, lab/pvehost/deploy.sh) replicates tenant $TENANT to VM 202 (B, deployed with LAB=~/nexus-lab/pvehost2,
# lab/README.md), which pulls from A's address on the lab network. lab/appliance/replication.sh is the same for two
# local QEMU VMs; this one drives the PVE lab's appliance VMs through their tunnels.
#
#   replication.sh enroll   A: peer for $TENANT (approved by A's security officer); B: replication source with the
#                           code and A's certificate fingerprint, enrollment; A: the key export approved
#   replication.sh sync     B: sync now, the snapshots of $TENANT arrive
#   replication.sh vault    B: web inbound rule restricted, vault mode requested and approved; a download becomes a
#                           vault.restore request, it runs after the approval; a new tenant is refused
#   replication.sh unvault  B: switch-off approved, then `nexus-setup vault-disable` with B's recovery key on B's
#                           console
#
# env: A (~/nexus-lab/pvehost:28444:10.2.34.211), B (~/nexus-lab/pvehost2:28445:10.2.34.212): LAB dir, tunnel port,
#      address; TENANT (windows: a small tenant, the Windows agent of lab/windows/e2e.sh)
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
A=${A:-$HOME/nexus-lab/pvehost:28444:10.2.34.211}
B=${B:-$HOME/nexus-lab/pvehost2:28445:10.2.34.212}
TENANT=${TENANT:-windows}
T0=$(date +%s)
log() { printf '[%4ss] %s\n' $(($(date +%s) - T0)) "$*" >&2; }

apienv() { # apienv a|b: LAB, PORT, ROOT, S, secrets and api-lib for that appliance (in a subshell)
	local e
	[ "$1" = a ] && e=$A || e=$B
	IFS=: read -r LAB PORT ADDR <<<"$e"
	export LAB PORT CONSOLE=$LAB/appliance/console.sock
	ROOT=$LAB/appliance/root
	S=$ROOT/run/api
	mkdir -p "$S"
	# shellcheck disable=SC1091
	. "$ROOT/secrets.env"
	# shellcheck source=lab/e2e/api-lib.sh
	. "$repo/lab/e2e/api-lib.sh"
}

step_enroll() {
	local fp code addr_a
	addr_a=${A##*:}
	fp=$(openssl x509 -in "${A%%:*}/appliance/root/etc/nexus/tls/cert.pem" -outform DER | sha256sum | cut -d' ' -f1)
	code=$(
		apienv a
		login admin "$ADMIN_PW" "$ADMIN_TOTP"
		login so "$SO_PW" "$SO_TOTP"
		r=$(api admin POST /replication/peers "$(jq -nc --arg t "$TENANT" '{name:"dr-site-202", tenants:[$t]}')")
		expect 202 "create peer"
		api so POST "/quorum/$(jq -r .quorum_id <<<"$r")/approve" '{}' >/dev/null
		expect 200 "approve peer"
		jq -r .code <<<"$r"
	)
	log "A: peer for $TENANT approved, A's fingerprint $fp"
	(
		apienv b
		login admin "$ADMIN_PW" "$ADMIN_TOTP"
		r=$(api admin POST /replication/sources "$(jq -nc --arg u "$addr_a:8443" --arg c "$code" --arg f "$fp" --arg t "$TENANT" \
			'{name:"primary-201", url:$u, code:$c, fingerprint:$f, tenants:[$t], schedule:"hourly 17"}')")
		expect 201 "create replication source"
		j=$(wait_job admin "$(jq -r .job <<<"$r")" 300)
		[ "$(jq -r .state <<<"$j")" = ok ] || die "enrollment: $(jq -r '.log // ""' <<<"$j" | tail -n 20)"
		log "B: enrolled: $(jq -c .result <<<"$j")"
	)
	(
		apienv a
		login admin "$ADMIN_PW" "$ADMIN_TOTP"
		login so "$SO_PW" "$SO_TOTP"
		local q st=
		q=$(api so GET '/quorum?state=pending' | jq -r '[.[] | select(.action == "replication.key_export")][0].id')
		[ "$q" != null ] || die "no key export request"
		api so POST "/quorum/$q/approve" '{}' >/dev/null
		expect 200 "approve key export"
		for _ in $(seq 120); do
			st=$(api admin GET /quorum | jq -r --argjson q "$q" '.[] | select(.id == $q) | .state')
			[ "$st" = executed ] && break
			sleep 1
		done
		[ "$st" = executed ] || die "key export not executed ($st)"
		log "A: keys exported: $(api admin GET /replication/peers | jq -c '.[] | select(.name == "dr-site-202") | {state, keys}')"
	)
}

step_sync() {
	(
		apienv b
		login admin "$ADMIN_PW" "$ADMIN_TOTP"
		local sid r j
		sid=$(api admin GET /replication/sources | jq -r '.[] | select(.name == "primary-201") | .id')
		r=$(api admin POST "/replication/sources/$sid/sync" '{}')
		expect 202 "sync"
		for id in $(jq -r '.jobs[]' <<<"$r"); do
			j=$(wait_job admin "$id" 3600)
			[ "$(jq -r .state <<<"$j")" = ok ] || die "sync $id: $(jq -r '.log // ""' <<<"$j" | tail -n 20)"
			log "B: sync job $id: $(jq -c '.result | {imported, chunks_fetched, bytes_fetched, secs}' <<<"$j")"
		done
		for _ in $(seq 60); do
			api admin GET "/snapshots?tenant=$TENANT" | jq -e 'length > 0' >/dev/null && break
			sleep 2
		done
		log "B: $(api admin GET "/snapshots?tenant=$TENANT" | jq 'length') snapshots of $TENANT"
	)
}

step_vault() {
	(
		apienv b
		login admin "$ADMIN_PW" "$ADMIN_TOTP"
		login so "$SO_PW" "$SO_TOTP"
		local r q src t j
		approve() { [ "$(status)" != 202 ] || { api so POST "/quorum/$(jq -r .quorum_id <<<"$1")/approve" '{}' >/dev/null && expect 200 "approve $2"; }; }
		r=$(api admin PUT /firewall/inbound/web '{"allow":["10.2.34.0/24","127.0.0.1/32"]}')
		approve "$r" "web inbound restricted"
		log "B: preconditions $(api admin GET /vault | jq -c '.preconditions // .')"
		r=$(api admin PUT /vault '{"enabled":true}')
		[ "$(status)" = 202 ] || die "vault request: HTTP $(status) $(cat "$S/body")"
		approve "$r" "vault.enable"
		api admin GET /vault | jq -e '.enabled == true' >/dev/null || die "vault mode not on: $(api admin GET /vault)"
		log "B: vault mode on"
		# a download becomes a request; it runs after the approval
		src=$(api admin GET "/snapshots?tenant=$TENANT" | jq -r '.[0].source')
		t=$(api admin GET "/snapshots?tenant=$TENANT" | jq -r '.[0].time')
		r=$(api admin POST /jobs "$(jq -nc --arg tn "$TENANT" --arg s "$src" --argjson t "$t" \
			'{kind:"files_get", tenant:$tn, params:{source:$s, time:$t, paths:["/"], format:"zip"}}')")
		[ "$(status)" = 202 ] && [ -n "$(jq -r '.quorum_id // empty' <<<"$r")" ] || die "download not turned into a request: HTTP $(status) $r"
		q=$(jq -r .quorum_id <<<"$r")
		api so POST "/quorum/$q/approve" '{}' >/dev/null
		expect 200 "approve vault.restore"
		j=
		for _ in $(seq 60); do
			j=$(api admin GET "/jobs?kind=files_get&limit=5" | jq -c --arg s "$src" '[.[] | select(.params.source == $s)][0] // empty')
			[ -n "$j" ] && break
			sleep 2
		done
		[ -n "$j" ] || die "no files_get job after the approval"
		j=$(wait_job admin "$(jq -r .id <<<"$j")" 1800)
		[ "$(jq -r .state <<<"$j")" = ok ] || die "approved download: $(jq -r '.log // ""' <<<"$j" | tail -n 10)"
		log "B: the download became request $q, ran after the approval ($(jq -c '.result | {entries, size}' <<<"$j"))"
		api admin POST /tenants '{"name":"vault-new"}' >/dev/null
		[ "$(status)" != 201 ] || die "a new tenant was created in vault mode"
		log "B: a new tenant refused in vault mode (HTTP $(status): $(head -c 120 "$S/body"))"
	)
}

step_unvault() {
	(
		apienv b
		login admin "$ADMIN_PW" "$ADMIN_TOTP"
		login so "$SO_PW" "$SO_TOTP"
		local r rk
		r=$(api admin PUT /vault '{"enabled":false}')
		[ "$(status)" = 202 ] || die "switch-off request: HTTP $(status) $(cat "$S/body")"
		api so POST "/quorum/$(jq -r .quorum_id <<<"$r")/approve" '{}' >/dev/null
		expect 200 "approve vault.disable"
		rk=$("$repo/lab/appliance/con.py" run "journalctl -u nexus-setup -o cat --no-pager | sed -n 's/^RECOVERY KEY (shown once, record it now): //p' | tail -1" | tr -d '\r\n')
		[ -n "$rk" ] || die "B's recovery key not in its setup journal"
		"$repo/lab/appliance/con.py" run "echo '$rk' | /usr/libexec/nexus/nexus-setup vault-disable" 300 >&2 || die "nexus-setup vault-disable"
		for _ in $(seq 30); do
			api admin GET /vault | jq -e '.enabled == false' >/dev/null && break
			sleep 2
		done
		api admin GET /vault | jq -e '.enabled == false' >/dev/null || die "vault mode still on: $(api admin GET /vault)"
		log "B: vault mode off after the approval and the recovery key at the console"
	)
}

for s in "${@:-enroll sync vault unvault}"; do
	for x in $s; do
		log "== $x"
		"step_$x"
	done
done
