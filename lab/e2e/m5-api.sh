#!/usr/bin/env bash
# M5 flow over the REST API only (what the UI does): curl with cookie jar +
# X-CSRF-Token, TLS verified against the appliance certificate.
#   lab/e2e/m5.sh setup && lab/e2e/m5.sh start && lab/e2e/m5-api.sh [step...]
# steps (default: all): config wait-backup check restore verify quorum audit
# Lab inputs (env, defaults = dev machine, see lab/README.md):
#   LAB (/home/ah/nexus-lab), LAB_CA (default: fetched from the node), LAB_TOKEN_SECRET (file;
#   default: secret part of $LAB/api-token), LAB_SSH_KEY (private key whose public half is in the
#   node's /var/lib/nexusbackup/.ssh/authorized_keys with command="/usr/lib/nexusbackup/helper"),
#   LAB_KNOWN_HOSTS, TESTBOX (SFTP testbox dir, crates/offsite/testbox/run.sh start),
#   OFFSITE_KEY, OFFSITE_HOST_KEY (known_hosts line of the testbox)
# Appliance VM (lab/appliance/e2e.sh): the paths/addresses the *appliance* uses differ from the host's:
#   APPL_HOST (how the appliance reaches the dev host: 127.0.0.1, or 10.0.2.2 from the VM),
#   APPL_SSH_KEY, APPL_KNOWN_HOSTS, APPL_OFFSITE_KEY (paths on the appliance; default = host paths)
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
eval "$("$here/m5.sh" env)"
S=$ROOT/run/api # cookie jars, csrf tokens, state
mkdir -p "$S"
LAB=${LAB:-/home/ah/nexus-lab}
if [ -z "${LAB_CA:-}" ]; then
	LAB_CA=$S/pve-root-ca.pem
	ssh -o BatchMode=yes -p 10022 -i "$LAB/lab_ed25519" -o UserKnownHostsFile="$LAB/known_hosts" root@localhost \
		cat /etc/pve/pve-root-ca.pem >"$LAB_CA"
fi
if [ -z "${LAB_TOKEN_SECRET:-}" ]; then # api-token = "<token id>=<secret>"
	LAB_TOKEN_SECRET=$S/pve-token-secret
	sed 's/^[^=]*=//' "$LAB/api-token" >"$LAB_TOKEN_SECRET"
fi
LAB_SSH_KEY=${LAB_SSH_KEY:-/home/ah/nexus-lab/appliance_ed25519}
[ -r "$LAB_SSH_KEY" ] || { echo "LAB_SSH_KEY $LAB_SSH_KEY not readable" >&2; exit 1; }
LAB_KNOWN_HOSTS=${LAB_KNOWN_HOSTS:-$LAB/known_hosts}
TESTBOX=${TESTBOX:-$(git -C "$here" worktree list --porcelain | sed -n "1s/^worktree //p")/target/offsite-testbox}
OFFSITE_KEY=${OFFSITE_KEY:-$TESTBOX/client_ed25519}
APPL_HOST=${APPL_HOST:-127.0.0.1}
APPL_SSH_KEY=${APPL_SSH_KEY:-$LAB_SSH_KEY}
APPL_KNOWN_HOSTS=${APPL_KNOWN_HOSTS:-$LAB_KNOWN_HOSTS}
APPL_OFFSITE_KEY=${APPL_OFFSITE_KEY:-$OFFSITE_KEY}
APPL_NODE_HOST=$APPL_HOST
[ "$APPL_HOST" = 127.0.0.1 ] && APPL_NODE_HOST=localhost # the lab known_hosts names [localhost]:10022
OFFSITE_HOST_KEY=${OFFSITE_HOST_KEY:-"[$APPL_HOST]:2223 $(cut -d' ' -f1,2 "$TESTBOX/hostkey/ssh_host_ed25519_key.pub")"}
BASE=https://nexus-m5:$PORT/api/v1
T0=$(date +%s)

log() { printf '[%4ss] %s\n' $(($(date +%s) - T0)) "$*" >&2; }
die() { log "FAIL: $*"; exit 1; }

# api USER METHOD PATH [JSON] -> body on stdout, HTTP status in $S/status
api() {
	local u=$1 m=$2 p=$3 d=${4:-}
	local args=(-s --cacert "$ROOT/etc/nexus/tls/cert.pem" --resolve "nexus-m5:$PORT:127.0.0.1"
		-b "$S/$u.jar" -c "$S/$u.jar" -X "$m" -o "$S/body" -w '%{http_code}')
	[ "$m" = GET ] || args+=(-H "X-CSRF-Token: $(cat "$S/$u.csrf" 2>/dev/null)")
	[ -z "$d" ] || args+=(-H 'Content-Type: application/json' --data-binary "$d")
	curl "${args[@]}" "$BASE$p" >"$S/status"
	cat "$S/body"
}
status() { cat "$S/status"; }
expect() { [ "$(status)" = "$1" ] || die "$2: HTTP $(status) $(cat "$S/body")"; }

# login USER PASSWORD TOTP_SECRET (waits for a fresh TOTP step: codes are single-use)
login() {
	local u=$1 pw=$2 sec=$3 code
	code=$(python3 "$here/totp.py" "$sec")
	if [ -f "$S/$u.lastcode" ] && [ "$(cat "$S/$u.lastcode")" = "$code" ]; then
		sleep $((30 - $(date +%s) % 30 + 1))
		code=$(python3 "$here/totp.py" "$sec")
	fi
	echo "$code" >"$S/$u.lastcode"
	rm -f "$S/$u.jar"
	api "$u" POST /auth/login "$(jq -nc --arg n "$u" --arg p "$pw" --arg t "$code" '{name:$n,password:$p,totp:$t}')" |
		jq -r .csrf >"$S/$u.csrf"
	expect 200 "login $u"
	log "logged in as $u"
}

# wait_job USER ID [timeout s] -> final job JSON
wait_job() {
	local u=$1 id=$2 to=${3:-900} j st
	for _ in $(seq "$to"); do
		j=$(api "$u" GET "/jobs/$id")
		st=$(jq -r .state <<<"$j")
		case $st in ok | failed | cancelled)
			echo "$j"
			return
			;;
		esac
		sleep 1
	done
	die "job $id still $st after ${to}s"
}

step_config() {
	login admin "$ADMIN_PW" "$ADMIN_TOTP"
	api admin POST /tenants "$(jq -nc --arg k "$APPL_OFFSITE_KEY" --arg hk "$OFFSITE_HOST_KEY" --arg h "$APPL_HOST" \
		'{name:"lab", offsite:{remote:{type:"sftp", host:$h, port:2223, user:"tenant", key_file:$k, host_key:$hk, base_dir:"m5"}, uploaders:4}}')" >/dev/null
	expect 201 "create tenant"
	local cfg
	cfg=$(jq -nc --rawfile ca "$LAB_CA" --arg tok "$(tr -d '\n' <"$LAB_TOKEN_SECRET")" --arg key "$APPL_SSH_KEY" --arg kh "$APPL_KNOWN_HOSTS" \
		--arg addr "$APPL_HOST:18006" --arg nh "$APPL_NODE_HOST" \
		'{host:"pve1", port:18006, connect_addr:$addr, ca_pem:$ca, token_id:"nexus@pve!appliance", token_secret:$tok,
		  nodes:{pve1:{host:$nh, port:10022, key:$key, known_hosts:$kh}}, storage:"nexus", fleecing_storage:"local-lvm"}')
	SRC=$(api admin POST /sources "$(jq -nc --argjson c "$cfg" '{tenant:"lab", kind:"pve", name:"pve1", config:$c}')" | jq -r .id)
	expect 201 "create source"
	api admin GET "/sources" | jq -e '.[0].config.token_secret_set == true and (.[0].config.token_secret == null)' >/dev/null ||
		die "token secret leaked or not set"
	# daily schedule (UTC) at the next full minute that is >= 40 s away
	local at
	at=$(date -u -d "@$((($(date +%s) + 100) / 60 * 60))" +%H:%M)
	POL=$(api admin POST /policies "$(jq -nc --arg s "daily $at" '{name:"lab-daily", schedule:$s, gfs:{daily:14,weekly:4,monthly:6,yearly:2}, offsite:true}')" | jq -r .id)
	expect 201 "create policy"
	GRP=$(api admin POST /groups "$(jq -nc --argjson s "$SRC" --argjson p "$POL" '{tenant:"lab", source_id:$s, policy_id:$p, name:"lab-guests", guests:[100,200]}')" | jq -r .id)
	expect 201 "create group"
	echo "SRC=$SRC POL=$POL GRP=$GRP AT=$at" >"$S/ids"
	log "tenant lab, source $SRC, policy $POL (daily $at UTC), group $GRP [100, 200]"
}

# re-run: move the policy's daily time to the next full minute >= 40 s away, so
# wait-backup sees a new scheduled backup (keeps gfs/offsite, so no quorum)
step_reschedule() {
	login admin "$ADMIN_PW" "$ADMIN_TOTP"
	# shellcheck disable=SC1091
	. "$S/ids"
	local at pol
	at=$(date -u -d "@$((($(date +%s) + 100) / 60 * 60))" +%H:%M)
	pol=$(api admin GET /policies | jq -c --argjson id "$POL" --arg s "daily $at" '.[] | select(.id==$id) | {name, schedule: $s, gfs, offsite}')
	api admin PUT "/policies/$POL" "$pol" >/dev/null
	expect 200 "reschedule policy"
	log "policy $POL now daily $at UTC"
}

step_wait_backup() {
	login admin "$ADMIN_PW" "$ADMIN_TOTP"
	log "waiting for the scheduled backup"
	local b="" seen
	# jobs of earlier runs (reschedule) do not count
	seen=$(api admin GET "/jobs?kind=backup" | jq '[.[] | select(.requested_by=="scheduler") | .id] | max // 0')
	for _ in $(seq 300); do
		b=$(api admin GET "/jobs?kind=backup" | jq -r --argjson s "$seen" '[.[] | select(.requested_by=="scheduler" and .id > $s)][0].id // empty')
		[ -n "$b" ] && break
		sleep 1
	done
	[ -n "$b" ] || die "scheduler queued no backup"
	log "backup job $b queued by the scheduler"
	local j
	j=$(wait_job admin "$b" 1800)
	[ "$(jq -r .state <<<"$j")" = ok ] || die "backup job $b: $(jq -r .log <<<"$j" | tail -n 20)"
	log "backup job $b ok in $(jq '.finished - .started' <<<"$j") s; result $(jq -c .result <<<"$j")"
	for k in retention offsite; do
		local id=""
		for _ in $(seq 120); do
			id=$(api admin GET "/jobs?kind=$k" | jq -r '[.[] | select(.requested_by=="scheduler")][0].id // empty')
			[ -n "$id" ] && break
			sleep 1
		done
		[ -n "$id" ] || die "no $k job after the backup"
		j=$(wait_job admin "$id" 1800)
		[ "$(jq -r .state <<<"$j")" = ok ] || die "$k job $id: $(jq -r .log <<<"$j" | tail -n 20)"
		log "$k job $id ok in $(jq '.finished - .started' <<<"$j") s"
	done
}

step_check() {
	login admin "$ADMIN_PW" "$ADMIN_TOTP"
	local snaps=""
	for _ in $(seq 120); do
		snaps=$(api admin GET "/snapshots?tenant=lab")
		jq -e '[.[] | select(.local and .offsite) | .source] | (index("vm-100") != null and index("ct-200") != null)' <<<"$snaps" >/dev/null && break
		sleep 2
	done
	jq -r '.[] | "  \(.source) \(.time) local=\(.local) offsite=\(.offsite) size=\(.size) lock_until=\(.lock_until)"' <<<"$snaps" >&2
	jq -e '[.[] | select(.local and .offsite) | .source] | (index("vm-100") != null and index("ct-200") != null)' <<<"$snaps" >/dev/null ||
		die "snapshots not local+offsite for both guests"
	log "snapshots: local + offsite for vm-100 and ct-200"
	curl -sf --cacert "$ROOT/etc/nexus/tls/cert.pem" --resolve "nexus-m5:$PORT:127.0.0.1" \
		-H "Authorization: Bearer $(cat "$ROOT/etc/nexus/metrics-token")" "https://nexus-m5:$PORT/metrics" >"$S/metrics" ||
		die "metrics"
	grep -E '^nexus_(snapshots|last_successful|jobs)' "$S/metrics" >&2
	log "alerts: $(api admin GET /alerts | jq -c '[.[] | {severity, kind, message}]')"
}

step_restore() {
	local opw r osec
	if [ -f "$S/op.env" ]; then # re-run: operator exists
		. "$S/op.env"
		opw=$OP_PW osec=$OP_TOTP
	else
		login admin "$ADMIN_PW" "$ADMIN_TOTP"
		opw="op-$(head -c 12 /dev/urandom | base64 | tr -d '/+=')"
		r=$(api admin POST /users "$(jq -nc --arg p "$opw" '{name:"op", password:$p, role:"operator"}')")
		expect 201 "create operator"
		osec=$(jq -r '.totp_uri' <<<"$r" | sed -n 's/.*[?&]secret=\([A-Z2-7]*\).*/\1/p')
		[ -n "$osec" ] || die "no TOTP URI for the operator: $r"
		printf "OP_PW='%s'\nOP_TOTP='%s'\n" "$opw" "$osec" >"$S/op.env"
	fi
	login op "$opw" "$osec"
	local snaps
	snaps=$(api op GET "/snapshots?tenant=lab")
	for src in ct-200 vm-100; do
		local time t0 j id tok
		time=$(jq -r --arg s "$src" '[.[] | select(.source==$s and .local)][0].time' <<<"$snaps")
		t0=$(date +%s)
		r=$(api op POST /jobs "$(jq -nc --arg s "$src" --argjson t "$time" '{kind:"files_list", tenant:"lab", params:{source:$s, time:$t, path:"/"}}')")
		expect 202 "files_list $src"
		j=$(wait_job op "$(jq -r .id <<<"$r")" 600)
		[ "$(jq -r .state <<<"$j")" = ok ] || die "files_list $src: $(jq -r .log <<<"$j" | tail -n 20)"
		log "files_list $src@$time / in $(($(date +%s) - t0)) s: $(jq -c '[.result.entries[].name]' <<<"$j")"
		# VM: the micro-VM shows one directory per mounted file system
		local path=/etc/hostname
		if [ "$src" = vm-100 ]; then
			local mnt
			for mnt in $(jq -r '.result.entries[] | select(.kind=="dir") | .name' <<<"$j"); do
				r=$(api op POST /jobs "$(jq -nc --arg s "$src" --argjson t "$time" --arg p "/$mnt/etc" '{kind:"files_list", tenant:"lab", params:{source:$s, time:$t, path:$p}}')")
				local j2
				j2=$(wait_job op "$(jq -r .id <<<"$r")" 600)
				if jq -e '.state == "ok" and ([.result.entries[]?.name] | index("hostname") != null)' <<<"$j2" >/dev/null; then
					path=/$mnt/etc/hostname
					break
				fi
			done
		fi
		t0=$(date +%s)
		r=$(api op POST /jobs "$(jq -nc --arg s "$src" --argjson t "$time" --arg p "$path" '{kind:"files_get", tenant:"lab", params:{source:$s, time:$t, paths:[$p], format:"tar"}}')")
		expect 202 "files_get $src"
		id=$(jq -r .id <<<"$r")
		tok=$(jq -r .download_token <<<"$r")
		j=$(wait_job op "$id" 600)
		[ "$(jq -r .state <<<"$j")" = ok ] || die "files_get $src: $(jq -r .log <<<"$j" | tail -n 20)"
		api op GET "/downloads/$tok" >/dev/null
		expect 200 "download $src"
		cp "$S/body" "$S/$src.tar"
		log "files_get $src:$path in $(($(date +%s) - t0)) s, result $(jq -c .result <<<"$j"), tar: $(tar -tf "$S/$src.tar" | tr '\n' ' ')"
		log "  content of hostname: $(tar -xOf "$S/$src.tar" --wildcards '*hostname')"
		# only the requester may fetch it
		api admin GET "/downloads/$tok" >/dev/null
		expect 404 "download by another user"
	done
}

step_verify() {
	login admin "$ADMIN_PW" "$ADMIN_TOTP"
	local r j
	r=$(api admin POST /jobs '{"kind":"verify","tenant":"lab","params":{}}')
	expect 202 "verify job"
	j=$(wait_job admin "$(jq -r .id <<<"$r")" 1800)
	[ "$(jq -r .state <<<"$j")" = ok ] || die "verify: $(jq -r .log <<<"$j" | tail -n 20)"
	log "verify job ok in $(jq '.finished - .started' <<<"$j") s: $(jq -r .log <<<"$j" | grep -vE '^\$' | tr '\n' ' ')"
	api admin GET "/snapshots?tenant=lab" | jq -e 'all(.[]; .verified != null)' >/dev/null || die "snapshots not marked verified"
}

step_quorum() {
	login admin "$ADMIN_PW" "$ADMIN_TOTP"
	# shellcheck disable=SC1091
	. "$S/ids"
	local pol r q
	pol=$(api admin GET /policies | jq -c --argjson id "$POL" '.[] | select(.id==$id) | {name, schedule, gfs, offsite}')
	r=$(api admin PUT "/policies/$POL" "$(jq -c '.gfs.daily = 7' <<<"$pol")")
	expect 202 "weakening policy must need quorum"
	q=$(jq -r .quorum_id <<<"$r")
	log "policy daily 14->7: 202 quorum $q"
	api admin GET /policies | jq -e --argjson id "$POL" '.[] | select(.id==$id) | .gfs.daily == 14' >/dev/null || die "applied before approval"
	api admin POST "/quorum/$q/approve" >/dev/null
	expect 403 "admin may not approve"
	log "admin approving: 403 $(jq -r .error "$S/body")"
	login so "$SO_PW" "$SO_TOTP"
	api so POST "/quorum/$q/approve" >/dev/null
	expect 200 "so approves"
	api admin GET /policies | jq -e --argjson id "$POL" '.[] | select(.id==$id) | .gfs.daily == 7' >/dev/null || die "not applied after approval"
	log "approved by so: daily = 7, quorum state $(api so GET /quorum | jq -r --argjson q "$q" '.[] | select(.id==$q) | .state')"
	# The requester (admin) cannot approve their own request. A security officer
	# never is a requester (no CRUD rights; the API refuses), so this is the
	# reachable case; quorum.rs additionally refuses requested_by == approver.
	r=$(api admin PUT "/policies/$POL" "$(jq -c '.gfs.daily = 7 | .gfs.weekly = 2' <<<"$pol")")
	expect 202 "second weakening"
	q=$(jq -r .quorum_id <<<"$r")
	api admin POST "/quorum/$q/approve" >/dev/null
	expect 403 "requester approving own request"
	api so POST "/quorum/$q/reject" >/dev/null
	expect 200 "so rejects"
	log "requester approving own request #$q: 403; rejected by so"
}

step_audit() {
	login so "$SO_PW" "$SO_TOTP"
	api so GET /audit/verify | jq -c . >&2
	api so GET /audit/verify | jq -e .ok >/dev/null || die "audit chain"
	api so GET "/audit?order=desc&limit=15" | jq -r '.[] | "  #\(.seq) \(.actor) \(.action) \(.target)"' >&2
}

steps=("$@")
[ ${#steps[@]} -gt 0 ] || steps=(config wait-backup check restore verify quorum audit)
for s in "${steps[@]}"; do
	log "== $s"
	"step_${s//-/_}"
done
log "done"
