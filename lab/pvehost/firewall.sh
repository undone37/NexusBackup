#!/usr/bin/env bash
# Inbound firewall per service on the appliance VM of the PVE lab host (Phase 16c; #62, plan.md Phase 39 L2), through
# the tunnel of deploy.sh (the appliance sees the PVE host's address as the client). m5-api.sh step firewall for this
# appliance: web restricted to the client's address (still reachable), a list without it refused without the typed
# override, then with it (locked out), the console reset (`nexus-setup reset-firewall`) brings access back with the
# alert firewall_reset, the audit entry and the dropped attempts listed. The initial allow list is restored.
#
# env: as vmware-e2e.sh (LAB, PORT); CONSOLE (the appliance's serial console socket)
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
export LAB=${LAB:-$HOME/nexus-lab/pvehost}
export PORT=${PORT:-28444}
export CONSOLE=${CONSOLE:-$LAB/appliance/console.sock}
ROOT=$LAB/appliance/root
S=$ROOT/run/api
mkdir -p "$S"
# shellcheck disable=SC1091
. "$ROOT/secrets.env"
# shellcheck source=lab/e2e/api-lib.sh
. "$repo/lab/e2e/api-lib.sh"

fw_reach() { # -> HTTP code of /health, 000 when the firewall drops us
	curl -s -o /dev/null -w '%{http_code}' --max-time 5 --cacert "$ROOT/etc/nexus/tls/cert.pem" \
		--resolve "nexus-m5:$PORT:127.0.0.1" "$BASE/health" || true
}
fw_wait() { # fw_wait JQ-FILTER WHAT: poll GET /firewall (effective state, status every minute) up to 150 s
	for _ in $(seq 50); do
		api admin GET /firewall | jq -e "$1" >/dev/null && return
		sleep 3
	done
	die "firewall: $2: $(api admin GET /firewall | jq -c '{services: [.services[] | {id, allow, effective}], status_ts}')"
}
approve() { # approve QUORUM-ANSWER WHAT (approvals may be disabled: then it applied directly)
	if [ "$(status)" = 202 ]; then
		api so POST "/quorum/$(jq -r .quorum_id <<<"$1")/approve" >/dev/null
		expect 200 "approve: $2"
	else
		expect 200 "$2"
	fi
}

login admin "$ADMIN_PW" "$ADMIN_TOTP"
login so "$SO_PW" "$SO_TOTP"
r=$(api admin GET /firewall)
expect 200 "GET /firewall"
ip=$(jq -r .client_ip <<<"$r")
before=$(jq -c '.services[0].allow' <<<"$r")
log "client address as the appliance sees it: $ip; services $(jq -c '[.services[] | {id, available, allow}]' <<<"$r")"
r=$(api admin PUT /firewall/inbound/web "$(jq -nc --arg ip "$ip" '{allow: ["127.0.0.1/32", $ip]}')")
approve "$r" "web from 127.0.0.1 + $ip"
fw_wait ".services[0].effective.v4 | index(\"${ip%/*}\") != null" "web restricted to the client"
[ "$(fw_reach)" = 200 ] || die "not reachable any more with the client in the list"
log "web restricted to 127.0.0.1 and $ip: still reachable"
# lock ourselves out (typed override), then the console reset
api admin PUT /firewall/inbound/web '{"allow":["192.0.2.0/24"]}' >/dev/null
expect 409 "a list without the requester's address"
r=$(api admin PUT /firewall/inbound/web "$(jq -nc --arg ip "$ip" '{allow: ["192.0.2.0/24"], force: true, confirm: $ip}')")
approve "$r" "web from 192.0.2.0/24 only (typed override)"
for _ in $(seq 30); do
	[ "$(fw_reach)" = 000 ] && break
	sleep 2
done
[ "$(fw_reach)" = 000 ] || die "still reachable after locking the client out"
log "locked out as expected; console: nexus-setup reset-firewall"
"$repo/lab/appliance/con.py" run '/usr/libexec/nexus/nexus-setup reset-firewall' 120 >&2 || die "nexus-setup reset-firewall"
for _ in $(seq 30); do
	[ "$(fw_reach)" = 200 ] && break
	sleep 2
done
[ "$(fw_reach)" = 200 ] || die "not reachable after the console reset"
login admin "$ADMIN_PW" "$ADMIN_TOTP"
login so "$SO_PW" "$SO_TOTP"
r=$(api admin GET /firewall)
jq -e '.services[0].allow == [] and .client_allowed' <<<"$r" >/dev/null || die "after reset: $(jq -c .services[0] <<<"$r")"
api admin GET "/alerts?state=open" | jq -e 'any(.[]; .kind == "firewall_reset")' >/dev/null || die "firewall_reset alert"
api so GET "/audit?order=desc&limit=50" | jq -e 'any(.[]; .action == "firewall.reset" and .actor == "console")' >/dev/null ||
	die "firewall.reset audit entry"
fw_wait 'any(.drops[]; .port == 8443)' "blocked attempts on 8443"
log "access back after the console reset; blocked attempts: $(api admin GET /firewall | jq -c '[.drops[] | select(.port == 8443)]')"
if [ "$before" != "[]" ]; then
	r=$(api admin PUT /firewall/inbound/web "$(jq -nc --argjson a "$before" '{allow: $a}')")
	approve "$r" "restore the initial web allow list $before"
fi
log "firewall: ok"
