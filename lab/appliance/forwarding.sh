#!/usr/bin/env bash
# Audit / alert forwarding lab (Phase 14a, docs/control-plane.md "Forwarding") against an installed
# appliance VM (SELinux enforcing) that went through first boot (lab/appliance/e2e.sh boot setup,
# PVE=0 is enough; admin + security officer, approvals enabled). Receivers: the podman testbox
# lab/forwarding/testbox (rsyslog with TLS + an HTTPS JSON sink), reached by the VM at 10.0.2.2.
#   forwarding.sh testbox   start the testbox
#   forwarding.sh forward   configure both sinks over the API (syslog: lab CA; https: SHA-256 pin + Bearer
#                           header), "Send test message" until both answer ok (egress allow-list + SELinux),
#                           every audit entry 1..head arrives at rsyslog with seq + hash (hashes equal to
#                           GET /audit) and at the HTTPS sink, no gaps; alert + job events arrive; the daily
#                           audit.anchor is among them; /audit/forwarding up to date
#   forwarding.sh outage    rsyslog down + HTTPS 503: new entries wait (cursor kept, last_error recorded),
#                           both back: the backlog arrives in order, nothing skipped
#   forwarding.sh quorum    disabling the syslog sink -> 202, approved by the security officer; enabled again
#                           (direct); audit.csv with the filter action=settings. (header, prev_hash/hash)
#   forwarding.sh all       testbox forward outage quorum
#   forwarding.sh stop      remove the testbox container
# Afterwards: lab/appliance/e2e.sh check (0 nexus AVCs). The testbox listens on 16514 (rootless podman,
# an unreserved port); the default 6514 (syslog_tls_port_t) is allowed in os/selinux/nexus.te.
# env: ROOT (installed root with secrets.env + etc/nexus/tls/cert.pem; default $LAB/appliance/root),
#      LAB (/home/ah/nexus-lab), PORT (web-api port forward, 28443), APPL_HOST (10.0.2.2: the host from the VM)
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
LAB=${LAB:-/home/ah/nexus-lab}
export ROOT=${ROOT:-$LAB/appliance/root}
export PORT=${PORT:-28443}
APPL_HOST=${APPL_HOST:-10.0.2.2}
TB=$repo/lab/forwarding/testbox/run.sh
T0=$(date +%s)

apienv() {
	S=$ROOT/run/forwarding
	mkdir -p "$S"
	# shellcheck disable=SC1091
	. "$ROOT/secrets.env"
	# shellcheck source=lab/e2e/api-lib.sh
	. "$repo/lab/e2e/api-lib.sh"
	eval "$("$TB" env)"
	login admin "$ADMIN_PW" "$ADMIN_TOTP"
	login so "$SO_PW" "$SO_TOTP"
}

testbox() { "$TB" start; }

# the forwarding setting as the lab uses it (enabled = $1 for the syslog sink)
settings() {
	jq -nc --arg h "$APPL_HOST" --argjson sp "$FWD_SYSLOG_PORT" --arg ca "$(cat "$FWD_CA")" \
		--arg url "https://$APPL_HOST:$FWD_HTTPS_PORT/ingest" --arg pin "$FWD_PIN" --arg tok "Bearer $FWD_TOKEN" \
		--argjson on "${1:-true}" --argjson keep "${2:-false}" \
		'{syslog: {enabled: $on, host: $h, port: $sp, ca_pem: $ca, app_name: "nexus-lab"},
		  https: {url: $url, pin_sha256: $pin, batch_max: 50, headers: {Authorization: (if $keep then null else $tok end)}}}'
}

head_seq() { api admin GET '/audit?order=desc&limit=1' | jq -r '.[0].seq'; }

# seqs (sorted, unique) the receivers got
syslog_seqs() { grep -o ' audit \[nexus@32473 seq="[0-9]*"' "$FWD_SYSLOG_LOG" 2>/dev/null | grep -o '[0-9]*"$' | tr -d '"' | sort -nu; }
https_seqs() { jq -r '.[] | select(.type == "audit") | .seq' "$FWD_HTTPS_LOG" 2>/dev/null | sort -nu; }

# wait until both receivers have every seq 1..$1 (no gaps)
wait_all() {
	local want=$1 s h
	for _ in $(seq 120); do
		s=$(syslog_seqs | awk -v w="$want" '$1 <= w' | wc -l)
		h=$(https_seqs | awk -v w="$want" '$1 <= w' | wc -l)
		[ "$s" -ge "$want" ] && [ "$h" -ge "$want" ] && return 0
		sleep 2
	done
	die "receivers have $s (syslog) / $h (https) of audit entries 1..$want"
}

forward() {
	apienv
	local r head
	r=$(api admin PUT /settings/forwarding "$(settings true)")
	expect 200 "PUT /settings/forwarding"
	[ "$(jq -r '.https.headers.Authorization' <<<"$r")" = null ] || die "header value shown: $r"
	log "forwarding configured: syslog $APPL_HOST:$FWD_SYSLOG_PORT (CA), https (pin)"
	# the scheduler adds the sinks to the egress allow-list on its next tick (<= 30 s)
	for _ in $(seq 20); do
		r=$(api admin POST /settings/forwarding/test '{}')
		expect 200 "forwarding test"
		jq -e '[.[] | startswith("ok")] | all' <<<"$r" >/dev/null && break
		sleep 5
	done
	jq -e '.syslog == "ok" and .https == "ok"' <<<"$r" >/dev/null || die "test from the appliance: $r"
	grep -q ' nexus-lab - test \[nexus@32473\]' "$FWD_SYSLOG_LOG" || die "test message not in syslog.log"
	log "test message delivered to both sinks"
	api admin POST /tenants '{"name":"fwd"}' >/dev/null
	head=$(head_seq)
	wait_all "$head"
	# "seq hash" of every entry: on the appliance, at rsyslog, at the HTTPS sink
	api admin GET "/audit?after=0&limit=1000" | jq -r '.[] | "\(.seq) \(.hash)"' | sort -u >"$S/hashes"
	sed -n 's/.* audit \[nexus@32473 seq="\([0-9]*\)" hash="\([0-9a-f]*\)".*/\1 \2/p' "$FWD_SYSLOG_LOG" | sort -u >"$S/syslog-hashes"
	jq -r '.[] | select(.type == "audit") | "\(.seq) \(.hash)"' "$FWD_HTTPS_LOG" | sort -u >"$S/https-hashes"
	for f in syslog-hashes https-hashes; do
		[ -z "$(comm -23 "$S/hashes" "$S/$f")" ] || die "$f: missing or different: $(comm -23 "$S/hashes" "$S/$f" | head -n 3)"
	done
	grep -q 'action="audit.anchor"' "$FWD_SYSLOG_LOG" || die "no audit.anchor forwarded"
	log "audit entries 1..$head at both sinks with equal hashes, no gaps; audit.anchor included"
	# job events: the forward_test jobs above
	grep -q ' job \[nexus@32473 .*kind="forward_test"' "$FWD_SYSLOG_LOG" || die "no job event forwarded"
	jq -se 'any(.[][]; .type == "job")' "$FWD_HTTPS_LOG" >/dev/null || die "no job event at the HTTPS sink"
	grep -q ' alert \[nexus@32473 ' "$FWD_SYSLOG_LOG" || log "note: no alert event (none raised on this appliance yet)"
	r=$(api so GET /audit/forwarding)
	log "status: $(jq -c '[.sinks[] | {sink, audit_seq, last_error}] + [{head: .head_seq}]' <<<"$r")"
}

outage() {
	apienv
	local head r
	"$TB" syslog-down
	"$TB" https-fail on
	for i in 1 2 3; do api admin POST /tenants "{\"name\":\"fwd-out-$i\"}" >/dev/null; done
	head=$(head_seq)
	sleep 30
	r=$(api so GET /audit/forwarding)
	jq -e 'all(.sinks[]; .last_error != null and .audit_seq < '"$head"')' <<<"$r" >/dev/null ||
		die "during the outage: $(jq -c . <<<"$r")"
	log "outage: cursors kept, errors recorded: $(jq -c '[.sinks[] | {sink, audit_seq, last_error}]' <<<"$r")"
	"$TB" syslog-up
	"$TB" https-fail off
	# back off is at most 5 min; the 30 s outage leaves it at 40 s or less
	wait_all "$head"
	r=$(api so GET /audit/forwarding)
	log "after the outage: backlog delivered, no gaps: $(jq -c '[.sinks[] | {sink, audit_seq, failing_since}]' <<<"$r")"
}

quorum() {
	apienv
	local r q
	r=$(api admin PUT /settings/forwarding "$(settings false true)")
	expect 202 "disabling an enabled sink needs approval"
	q=$(jq -r .quorum_id <<<"$r")
	api so POST "/quorum/$q/approve" '{}' >/dev/null
	expect 200 "approve settings.forwarding"
	[ "$(api so GET /settings/forwarding | jq -r .syslog.enabled)" = false ] || die "syslog sink still enabled"
	log "syslog sink disabled via quorum #$q"
	api admin PUT /settings/forwarding "$(settings true true)" >/dev/null
	expect 200 "enabling applies directly"
	curl -s --cacert "$ROOT/etc/nexus/tls/cert.pem" --resolve "nexus-m5:$PORT:127.0.0.1" -b "$S/so.jar" \
		-o "$S/audit.csv" -w '%{http_code}' "$BASE/audit.csv?action=settings." >"$S/status"
	expect 200 "audit.csv"
	head -n 1 "$S/audit.csv" | grep -q '^seq,ts,actor,action,target,details,prev_hash,hash' || die "csv header"
	grep -q ',settings.forwarding,' "$S/audit.csv" || die "csv rows"
	log "audit.csv: $(($(wc -l <"$S/audit.csv") - 1)) settings.* rows with hashes"
}

all() { testbox && forward && outage && quorum; }
stop() { "$TB" stop; }

[ $# -gt 0 ] || { sed -n '2,22p' "$0" >&2; exit 2; }
for step in "$@"; do
	case $step in
	testbox | forward | outage | quorum | all | stop) "$step" ;;
	*) sed -n '2,22p' "$0" >&2; exit 2 ;;
	esac
done
