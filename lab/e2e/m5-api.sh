#!/usr/bin/env bash
# M5 flow over the REST API only (what the UI does): curl with cookie jar +
# X-CSRF-Token, TLS verified against the appliance certificate.
#   lab/e2e/m5.sh setup && lab/e2e/m5.sh start && lab/e2e/m5-api.sh [step...]
# steps (default: all): config wait-backup check restore verify quorum phase13 legal-hold phase14d2 access diag audit
#   (not in the default: restore-test, recovery-plan (Phase 25, boot guests on pve1); offsite-fetch, Phase 17d: removes a local snapshot on disk, raises an inventory alert)
#   (not in the default: console, console-check; lab/appliance/console-gate.sh runs them; firewall: appliance VM
#   only, uses lab/appliance/con.py for the console reset)
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
# shellcheck source=lab/e2e/api-lib.sh
. "$here/api-lib.sh"

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
	# review H-2: the catalog holds the token only sealed to the scheduler, the TOTP seeds encrypted
	# (appliance VM: the catalog is inside the VM; lab/appliance/e2e.sh check verifies it there)
	[ ! -f "$ROOT/var/lib/nexus/catalog/catalog.db" ] && log "catalog not on this host: secret check runs in the appliance" ||
	python3 - "$ROOT/var/lib/nexus/catalog/catalog.db" "$LAB_TOKEN_SECRET" <<-'PY' || die "plaintext secret in the catalog"
		import json, sqlite3, sys
		db = sqlite3.connect(f"file:{sys.argv[1]}?mode=ro", uri=True)
		tok = open(sys.argv[2]).read().strip()
		for (c,) in db.execute("SELECT config FROM sources"):
		    assert tok not in c and json.loads(c)["token_secret"].startswith("sealed:v1:"), "source"
		for (s,) in db.execute("SELECT totp_secret FROM users"):
		    assert s.startswith("enc:v1:"), "totp seed"
	PY
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
		# self-enrollment (plan §2 "User onboarding"): the admin gets a one-time code, the
		# operator sets their own password and authenticator
		r=$(api admin POST /users '{"name":"op", "role":"operator"}')
		expect 201 "create operator"
		local code
		code=$(jq -r '.activation.code' <<<"$r")
		r=$(api anon POST /auth/activate/begin "$(jq -nc --arg c "$code" '{name:"op", code:$c}')")
		expect 200 "activation begin"
		osec=$(jq -r '.totp_secret' <<<"$r")
		api anon POST /auth/activate/complete "$(jq -nc --arg c "$code" --arg p "$opw" --arg t "$(python3 "$api_lib/totp.py" "$osec")" \
			'{name:"op", code:$c, password:$p, totp:$t}')" >/dev/null
		expect 200 "activation complete"
		# the activation used this TOTP step: login() must wait for the next one
		python3 "$api_lib/totp.py" "$osec" >"${ROOT:-$S}/run/lastcode-op"
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

# Phase 13 on the real appliance: storage figures from the connectors' stats, guest inventory +
# auto-protect, pause, cancelling a running backup, alert lifecycle fields, locked snapshot delete.
step_phase13() {
	login admin "$ADMIN_PW" "$ADMIN_TOTP"
	local src grp pol r j id
	src=$(api admin GET /sources | jq -r '.[0].id')
	grp=$(api admin GET /groups | jq -r '.[0].id')
	pol=$(api admin GET /groups | jq -r '.[0].policy_id')
	# 13d: the first backups wrote backup_stats
	r=$(api admin GET /storage)
	jq -e '.totals.dedup != null and .totals.compression != null and .totals.logical > 0' <<<"$r" >/dev/null ||
		die "storage figures: $(jq -c .totals <<<"$r")"
	log "storage: $(jq -c '.totals | {logical, data_in, stored, dedup, compression}' <<<"$r")"
	# 13c: inventory refresh through the real PVE API, then an `all` group minus an exclusion
	r=$(api admin POST /jobs "$(jq -nc --argjson s "$src" '{kind:"inventory", tenant:"lab", params:{source_id:$s}}')")
	j=$(wait_job admin "$(jq -r .id <<<"$r")" 300)
	[ "$(jq -r .state <<<"$j")" = ok ] || die "inventory job: $(jq -r .log <<<"$j" | tail -5)"
	r=$(api admin GET "/sources/$src/inventory")
	jq -e '[.guests[] | select(.gone == null) | .guest] | (index("100") != null and index("200") != null)' <<<"$r" >/dev/null ||
		die "inventory: $(jq -c '[.guests[] | {guest, tags}]' <<<"$r")"
	log "inventory: $(jq -c '[.guests[] | {guest, name, tags}]' <<<"$r")"
	id=$(api admin POST /groups "$(jq -nc --argjson s "$src" --argjson p "$pol" \
		'{tenant:"lab", source_id:$s, policy_id:$p, name:"auto", guests:[], mode:"all", exclude:["200"]}')" | jq -r .id)
	expect 201 "create auto group"
	api admin GET /groups | jq -e --argjson id "$id" '.[] | select(.id == $id) | .resolved_guests == [100]' >/dev/null ||
		die "auto group resolution: $(api admin GET /groups | jq -c --argjson id "$id" '.[] | select(.id == $id)')"
	log "auto group #$id (all minus 200) resolves to [100]"
	# 13b: pause it indefinitely (no scheduled runs), visible on the group
	api admin POST "/groups/$id/pause" '{}' >/dev/null
	expect 200 "pause group"
	api admin GET /groups | jq -e --argjson id "$id" '.[] | select(.id == $id) | .paused_until == -1' >/dev/null || die "not paused"
	log "auto group paused indefinitely"
	# 13b: cancel a running backup; no snapshot may appear for it. Only ct-200 (a full
	# vzdump read, ~1 min): vm-100's incremental finishes within seconds and is committed
	# per guest before a cancel could reach it
	local before
	before=$(api admin GET "/snapshots?tenant=lab" | jq '[.[] | select(.source == "ct-200") | .time] | max')
	r=$(api admin POST /jobs "$(jq -nc --argjson g "$grp" '{kind:"backup", tenant:"lab", params:{group_id:$g, guests:[200]}}')")
	id=$(jq -r .id <<<"$r")
	for _ in $(seq 120); do
		[ "$(api admin GET "/jobs/$id" | jq -r .state)" = running ] && break
		sleep 1
	done
	sleep 5
	api admin POST "/jobs/$id/cancel" >/dev/null
	expect 200 "cancel running job"
	j=$(wait_job admin "$id" 180)
	[ "$(jq -r .state <<<"$j")" = cancelled ] || die "job $id: $(jq -r .state <<<"$j")"
	sleep 5
	[ "$(api admin GET "/snapshots?tenant=lab" | jq '[.[] | select(.source == "ct-200") | .time] | max')" = "$before" ] ||
		die "a cancelled backup left a snapshot"
	log "running backup #$id cancelled, no snapshot committed"
	# 13f: lifecycle fields on alerts; 13a: a locked snapshot cannot be deleted
	api admin GET "/alerts?state=all" | jq -e 'all(.[]; has("count") and has("resolved_at"))' >/dev/null || die "alert lifecycle fields"
	r=$(api admin GET "/snapshots?tenant=lab" | jq -r '[.[] | select(.local)][0] | "\(.source)/\(.time)"')
	api admin DELETE "/snapshots/lab/$r" >/dev/null
	expect 409 "delete of a locked snapshot"
	log "locked snapshot lab/$r: delete refused (409)"
}

# Phase 15c: the security officer holds the oldest vm-100 snapshot (admin may not); a retention run
# keeps it; delete is refused; the release needs a second approver; everything is audited.
step_legal_hold() {
	login admin "$ADMIN_PW" "$ADMIN_TOTP"
	login so "$SO_PW" "$SO_TOTP"
	local t r j
	t=$(api so GET "/snapshots?tenant=lab&source=vm-100" | jq -r '[.[] | select(.local and .hold == null) | .time] | min') # rerun-safe: one not held yet
	api admin POST "/snapshots/lab/vm-100/$t/hold" '{"reason":"lab"}' >/dev/null
	expect 403 "admin may not set a legal hold"
	api so POST "/snapshots/lab/vm-100/$t/hold" '{"reason":"lab case 15c"}' >/dev/null
	expect 201 "so sets a legal hold"
	api so GET "/snapshots?held=true" | jq -e --argjson t "$t" '.[] | select(.source == "vm-100" and .time == $t) | .hold.state == "active"' >/dev/null ||
		die "held snapshot not listed"
	# manual retention: whole tenant ({}) or one {source}
	r=$(api admin POST /jobs '{"kind":"retention","tenant":"lab","params":{"source":"vm-100"}}')
	expect 202 "retention job"
	j=$(wait_job admin "$(jq -r .id <<<"$r")" 300)
	[ "$(jq -r .state <<<"$j")" = ok ] || die "retention job: $(jq -r .log <<<"$j" | tail -5)"
	sleep 5
	api so GET "/snapshots?tenant=lab&source=vm-100" | jq -e --argjson t "$t" 'any(.[]; .time == $t and .local)' >/dev/null ||
		die "held snapshot vm-100/$t gone after retention"
	api admin DELETE "/snapshots/lab/vm-100/$t" >/dev/null
	expect 409 "delete of a held snapshot"
	r=$(api admin DELETE "/snapshots/lab/vm-100/$t/hold")
	expect 202 "release request"
	api admin POST "/quorum/$(jq -r .quorum_id <<<"$r")/approve" >/dev/null
	expect 403 "requester may not approve the release"
	api so POST "/quorum/$(jq -r .quorum_id <<<"$r")/approve" >/dev/null
	expect 200 "so approves the release"
	api so GET "/holds?tenant=lab" | jq -e --argjson t "$t" 'any(.[]; .time == $t and .state == "released" and .approved_by == "so")' >/dev/null ||
		die "hold not released: $(api so GET '/holds?tenant=lab' | jq -c '.[0]')"
	api so GET "/audit?order=desc&limit=50" | jq -e '[.[].action] | index("snapshot.hold") != null and index("snapshot.hold_release") != null' >/dev/null ||
		die "legal hold not audited"
	log "legal hold on lab/vm-100/$t: set by so, kept by retention, delete refused, released with approval"
}

# Phase 14d on the real appliance: login banner, own sessions, session timeouts (loosening needs the
# security officer), the management allow-list through the firewall (our own address stays allowed)
# and back to "any", dormant-account setting, approver warning.
step_access() {
	login admin "$ADMIN_PW" "$ADMIN_TOTP"
	login so "$SO_PW" "$SO_TOTP"
	local r q ip
	api admin PUT /settings/banner '{"banner":"Lab appliance.\nAuthorised use only."}' >/dev/null
	expect 200 "set login banner"
	rm -f "$S/anon.jar"
	api anon GET /auth/banner | jq -e '.banner == "Lab appliance.\nAuthorised use only."' >/dev/null || die "public banner"
	r=$(api admin GET /auth/sessions)
	jq -e 'map(select(.current)) | length == 1' <<<"$r" >/dev/null || die "own sessions: $r"
	log "own sessions: $(jq -c 'map({id, ip, current})' <<<"$r")"
	api admin PUT /settings/session '{"idle_min":20,"absolute_h":12}' >/dev/null
	expect 200 "tighten session timeouts"
	r=$(api admin PUT /settings/session '{"idle_min":30,"absolute_h":12}')
	expect 202 "loosening session timeouts needs approval"
	api so POST "/quorum/$(jq -r .quorum_id <<<"$r")/approve" >/dev/null
	expect 200 "so approves longer timeouts"
	api admin GET /settings/security | jq -e '.session == {"idle_min":30,"absolute_h":12}' >/dev/null || die "session timeouts"
	# management allow-list: only our own address; the firewall must keep us in
	ip=$(api admin GET /settings/security | jq -r .client_ip)
	r=$(api admin PUT /settings/mgmt-allow '{"mgmt_allow":["192.0.2.0/24"]}')
	expect 409 "a list without the requester's address"
	r=$(api admin PUT /settings/mgmt-allow "$(jq -nc --arg ip "$ip" '{mgmt_allow:[$ip, "192.0.2.0/24"]}')")
	expect 202 "allow-list change needs approval"
	api so POST "/quorum/$(jq -r .quorum_id <<<"$r")/approve" >/dev/null
	expect 200 "so approves the allow-list"
	sleep 15 # scheduler tick + nexus-nft-sync
	rm -f "$S/anon.jar"
	api anon GET /health >/dev/null
	expect 200 "still reachable from $ip with the allow-list"
	log "management allow-list [$ip, 192.0.2.0/24] applied, web-api still reachable"
	r=$(api admin PUT /settings/mgmt-allow '{"mgmt_allow":[]}')
	expect 202 "opening the allow-list needs approval"
	api so POST "/quorum/$(jq -r .quorum_id <<<"$r")/approve" >/dev/null
	expect 200 "so approves any address"
	api admin PUT /settings/dormant '{"days":90}' >/dev/null
	expect 200 "dormant accounts on"
	api admin PUT /settings/dormant '{"days":0}' >/dev/null
	expect 200 "dormant accounts off"
	# two approvers (admin, so): the warning is on
	api admin GET /settings/approvals | jq -e '.enabled == false or .few_approvers == true' >/dev/null || die "few_approvers"
	log "access settings ok"
}

# Phase 14d (2): API tokens (scope, allow-list, revoke, audit actor) and the web certificate import through
# nexus-tls (CSR on the appliance, signed by a throwaway lab CA, served without restart, reverted).
step_phase14d2() {
	login admin "$ADMIN_PW" "$ADMIN_TOTP"
	local r tok id d=$S/phase14d2
	mkdir -p "$d"
	r=$(api admin POST /auth/tokens "$(jq -nc --arg p "$ADMIN_PW" --arg t "$(fresh_code admin "$ADMIN_TOTP")" \
		'{name:"lab-read", scope:"read", days:1, current_password:$p, current_totp:$t}')")
	expect 201 "create token"
	tok=$(jq -r .token <<<"$r")
	id=$(jq -r .id <<<"$r")
	bearer() { # METHOD PATH [JSON]: no cookie, no CSRF header
		curl -s --cacert "$ROOT/etc/nexus/tls/cert.pem" --resolve "nexus-m5:$PORT:127.0.0.1" -H "Authorization: Bearer $tok" \
			-X "$1" ${3:+-H 'Content-Type: application/json' --data-binary "$3"} -o "$S/body" -w '%{http_code}' "$BASE$2" >"$S/status"
	}
	bearer GET /dashboard
	expect 200 "read token: GET /dashboard"
	bearer POST /jobs '{"kind":"verify","tenant":"lab","params":{}}'
	expect 403 "read token: POST /jobs"
	bearer GET /settings/approvals
	expect 403 "token: settings"
	api admin GET "/audit?order=desc&limit=30" | jq -e 'any(.[]; .action == "token.create" and .actor == "admin")' >/dev/null ||
		die "token.create not audited"
	api admin DELETE "/auth/tokens/$id" >/dev/null
	expect 200 "revoke token"
	bearer GET /dashboard
	expect 401 "revoked token"
	log "API token: read scope enforced, revoked"

	r=$(api admin POST /certificate/csr '{"cn":"nexus-m5","sans":[]}')
	expect 200 "CSR (nexus-tls)"
	jq -r .csr_pem <<<"$r" >"$d/req.csr"
	openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$d/ca.key" -out "$d/ca.pem" -days 2 \
		-subj /CN=nexus-lab-ca -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign 2>/dev/null
	printf 'extendedKeyUsage=serverAuth\nkeyUsage=critical,digitalSignature\n' >"$d/ext"
	openssl x509 -req -in "$d/req.csr" -CA "$d/ca.pem" -CAkey "$d/ca.key" -CAcreateserial -days 1 -copy_extensions copy \
		-extfile "$d/ext" -out "$d/leaf.pem" 2>/dev/null
	grep -q "DNS:nexus-m5" <(openssl x509 -in "$d/leaf.pem" -noout -ext subjectAltName 2>/dev/null) ||
		die "the signed certificate lacks the CSR's SAN"
	# the leaf alone (root not included: accepted with a warning)
	r=$(api admin POST /certificate/install "$(jq -nc --rawfile c "$d/leaf.pem" '{chain_pem:$c}')")
	expect 200 "install certificate"
	log "installed: $(jq -c '{sha256: .chain[0].sha256, warnings}' <<<"$r")"
	# served right away (no restart), verified against the lab CA; the identity no longer verifies
	curl -sf --cacert "$d/ca.pem" --resolve "nexus-m5:$PORT:127.0.0.1" "https://nexus-m5:$PORT/health" >/dev/null ||
		die "imported certificate not served"
	! curl -sf --cacert "$ROOT/etc/nexus/tls/cert.pem" --resolve "nexus-m5:$PORT:127.0.0.1" "https://nexus-m5:$PORT/health" >/dev/null ||
		die "still the self-signed certificate"
	log "imported certificate served without a restart"
	API_CA=$d/ca.pem api admin POST /certificate/revert '{}' >/dev/null
	expect 200 "revert certificate"
	curl -sf --cacert "$ROOT/etc/nexus/tls/cert.pem" --resolve "nexus-m5:$PORT:127.0.0.1" "https://nexus-m5:$PORT/health" >/dev/null ||
		die "self-signed certificate not back after revert"
	api admin GET /certificate | jq -e '.active == "self_signed"' >/dev/null || die "certificate status after revert"
	log "reverted to the self-signed certificate"
}

# Phase 14b on the real appliance (nexus-diag, root, nexus_diag_t): self-checks and a redacted
# support bundle through Settings -> Diagnostics. Dev mode (no appliance) has no nexus-diag: skipped.
step_diag() {
	if [ "$APPL_HOST" = 127.0.0.1 ]; then
		log "diag: needs the appliance VM (lab/appliance/e2e.sh api diag), skipped"
		return
	fi
	login admin "$ADMIN_PW" "$ADMIN_TOTP"
	login so "$SO_PW" "$SO_TOTP"
	local id r
	wait_diag() { # <user> <id> -> the finished result
		for _ in $(seq 180); do
			r=$(api "$1" GET "/diagnostics/$2")
			case $(jq -r .state <<<"$r") in done | error) echo "$r"; return ;; esac
			sleep 1
		done
		die "diagnostics $2 did not finish: $r"
	}
	id=$(api so POST /diagnostics/checks '{}' | jq -r .id)
	expect 202 "run checks (security officer)"
	r=$(wait_diag so "$id")
	[ "$(jq -r .state <<<"$r")" = "done" ] || die "checks: $(jq -c . <<<"$r")"
	jq -r '.checks[] | "  \(.status)\t\(.severity)\t\(.id): \(.detail)"' <<<"$r" >&2
	# a healthy lab appliance: nothing that would block an update, and every check really ran
	jq -e '[.checks[] | select(.status == "fail" and .severity >= 3)] == []' <<<"$r" >/dev/null ||
		die "blocking checks failed: $(jq -c '[.checks[] | select(.status == "fail")]' <<<"$r")"
	jq -e '[.checks[] | select(.detail | startswith("check could not run"))] == []' <<<"$r" >/dev/null ||
		die "checks that crashed (SELinux denial?): $(jq -c '[.checks[] | select(.detail | startswith("check could not run"))]' <<<"$r")"
	for c in time.sync egress keyd audit.chain catalog.integrity selinux systemd.failed; do
		jq -e --arg c "$c" '.checks[] | select(.id == $c) | .status == "pass"' <<<"$r" >/dev/null ||
			die "check $c: $(jq -c --arg c "$c" '.checks[] | select(.id == $c)' <<<"$r")"
	done
	api so POST /diagnostics/bundle '{}' >/dev/null
	expect 403 "support bundle as security officer"
	id=$(api admin POST /diagnostics/bundle "$(jq -nc --argjson u "$(date +%s)" '{since: ($u - 3600), until: $u}')" | jq -r .id)
	expect 202 "create support bundle"
	r=$(wait_diag admin "$id")
	[ "$(jq -r .state <<<"$r")" = "done" ] || die "bundle: $(jq -c . <<<"$r")"
	api admin GET "/diagnostics/$id/download" >/dev/null # body lands in $S/body
	expect 200 "download support bundle"
	local t=$S/bundle
	rm -rf "$t" && mkdir -p "$t" && tar -xzf "$S/body" -C "$t"
	t=$(find "$t" -mindepth 1 -maxdepth 1 -type d -name 'nexus-support-*') # the bundle's top directory
	for f in manifest.json checks.json journal-nexus.txt avc.txt nft-drops.txt chrony.txt catalog-stats.json update-status.json; do
		[ -s "$t/$f" ] || die "bundle lacks $f"
	done
	grep -q 'nexus-web-api' "$t/journal-nexus.txt" || die "bundle journal has no nexus-web-api lines"
	grep -q 'Reference ID' "$t/chrony.txt" || die "bundle chrony.txt: $(head -5 "$t/chrony.txt")"
	! grep -rqE 'BEGIN [A-Z ]*PRIVATE KEY|nx_session=[0-9a-f]{16}' "$t" || die "unredacted secret in the bundle"
	log "support bundle $id: $(jq -r .bundle.bytes <<<"$r") bytes, $(find "$t" -type f | wc -l) files"
	api so GET "/diagnostics/$id/download" >/dev/null
	expect 403 "bundle download by the security officer"
}

# 14c: console.unlock through the quorum, the code shown once ($S/console-code for
# lab/appliance/console-gate.sh, which types it at a lab instance of the gate)
step_console() {
	login admin "$ADMIN_PW" "$ADMIN_TOTP"
	local r id
	r=$(api admin POST /console/unlock '{"hours":1,"reason":"lab: console gate e2e"}')
	id=$(jq -r .quorum_id <<<"$r")
	if [ "$(status)" = 202 ]; then
		api admin POST "/console/unlock/$id/code" >/dev/null
		expect 409 "code before the approval"
		login so "$SO_PW" "$SO_TOTP"
		api so POST "/quorum/$id/approve" >/dev/null
		expect 200 "so approves console.unlock"
		api so POST "/console/unlock/$id/code" >/dev/null
		expect 403 "the code is for the requester only"
	else
		expect 200 "console.unlock with approvals disabled"
	fi
	api admin POST "/console/unlock/$id/code" | jq -r .code >"$S/console-code"
	expect 200 "fetch the code"
	echo "$id" >"$S/console-id"
	api admin POST "/console/unlock/$id/code" >/dev/null
	expect 409 "the code is shown once"
	api admin GET /console/unlock | jq -e --argjson id "$id" '.[] | select(.id == $id) | .status == "issued"' >/dev/null ||
		die "request $id not issued"
	log "console.unlock #$id approved, code shown once ($S/console-code)"
}

# after lab/appliance/console-gate.sh: the code was used, the banner is gone, the alerts are open
step_console_check() {
	login admin "$ADMIN_PW" "$ADMIN_TOTP"
	local id
	id=$(cat "$S/console-id")
	api admin GET /console/unlock | jq -e --argjson id "$id" '.[] | select(.id == $id) | .status == "used"' >/dev/null ||
		die "request $id: $(api admin GET /console/unlock | jq -c --argjson id "$id" '.[] | select(.id == $id)')"
	api admin GET /auth/me | jq -e '.console_shell == null' >/dev/null || die "console banner still set"
	api admin GET "/alerts?state=open" | jq -e '[.[] | select(.kind == "console_root_shell")] | length >= 2' >/dev/null ||
		die "console_root_shell alerts missing"
	log "console request #$id used, banner cleared, console_root_shell alerts open"
}

# 16c (appliance VM only, lab/appliance: needs con.py): inbound firewall per service. Restrict web to
# 127.0.0.1 + 10.0.2.2 (the VM sees the host as 10.0.2.2), still reachable; then a list without the host
# (typed override) locks us out; `nexus-setup reset-firewall` on the console brings access back.
fw_reach() { # -> HTTP code of /health, 000 when the firewall drops us
	curl -s -o /dev/null -w '%{http_code}' --max-time 5 --cacert "${API_CA:-$ROOT/etc/nexus/tls/cert.pem}" \
		--resolve "nexus-m5:$PORT:127.0.0.1" "$BASE/health" || true
}
fw_wait() { # fw_wait JQ-FILTER WHAT: poll GET /firewall (effective state, status every minute) up to 150 s
	for _ in $(seq 50); do
		api admin GET /firewall | jq -e "$1" >/dev/null && return
		sleep 3
	done
	die "firewall: $2: $(api admin GET /firewall | jq -c '{services: [.services[] | {id, allow, effective}], status_ts}')"
}
step_firewall() {
	login admin "$ADMIN_PW" "$ADMIN_TOTP"
	login so "$SO_PW" "$SO_TOTP"
	local r ip approve
	approve() { # approve QUORUM-ANSWER WHAT (approvals may be disabled: then it applied directly)
		if [ "$(status)" = 202 ]; then
			api so POST "/quorum/$(jq -r .quorum_id <<<"$1")/approve" >/dev/null
			expect 200 "so approves $2"
		else
			expect 200 "$2 (approvals disabled)"
		fi
	}
	r=$(api admin GET /firewall)
	expect 200 "GET /firewall"
	ip=$(jq -r .client_ip <<<"$r")
	jq -e '[.services[].id] == ["web","icmp","ssh"] and (.services[2].available | not)' <<<"$r" >/dev/null ||
		die "firewall services: $(jq -c .services <<<"$r")"
	log "client address as the appliance sees it: $ip; outbound: $(jq -c .outbound <<<"$r")"
	api admin PUT /firewall/inbound/ssh '{"allow":[]}' >/dev/null
	expect 409 "ssh is not running"
	r=$(api admin PUT /firewall/inbound/web "$(jq -nc --arg ip "$ip" '{allow: ["127.0.0.1/32", "10.0.2.2/32", $ip]}')")
	approve "$r" "web from 127.0.0.1 + 10.0.2.2"
	fw_wait '.services[0].effective.v4 | index("10.0.2.2") != null' "web restricted to the host"
	[ "$(fw_reach)" = 200 ] || die "not reachable any more with the host in the list"
	log "web restricted to 127.0.0.1, 10.0.2.2: still reachable"
	# lock ourselves out (typed override), then the console reset
	api admin PUT /firewall/inbound/web '{"allow":["192.0.2.0/24"]}' >/dev/null
	expect 409 "a list without the requester's address"
	r=$(api admin PUT /firewall/inbound/web "$(jq -nc --arg ip "$ip" '{allow: ["192.0.2.0/24"], force: true, confirm: $ip}')")
	approve "$r" "web from 192.0.2.0/24 only (typed override)"
	for _ in $(seq 30); do
		[ "$(fw_reach)" = 000 ] && break
		sleep 2
	done
	[ "$(fw_reach)" = 000 ] || die "still reachable after locking the host out"
	log "locked out as expected; console: nexus-setup reset-firewall"
	"$here/../appliance/con.py" run '/usr/libexec/nexus/nexus-setup reset-firewall' 120 >&2 || die "nexus-setup reset-firewall"
	for _ in $(seq 30); do
		[ "$(fw_reach)" = 200 ] && break
		sleep 2
	done
	[ "$(fw_reach)" = 200 ] || die "not reachable after the console reset"
	r=$(api admin GET /firewall)
	jq -e '.services[0].allow == [] and .client_allowed' <<<"$r" >/dev/null || die "after reset: $(jq -c .services[0] <<<"$r")"
	api admin GET "/alerts?state=open" | jq -e 'any(.[]; .kind == "firewall_reset")' >/dev/null || die "firewall_reset alert"
	api so GET "/audit?order=desc&limit=50" | jq -e 'any(.[]; .action == "firewall.reset" and .actor == "console")' >/dev/null ||
		die "firewall.reset audit entry"
	# our dropped attempts show up as blocked (status refreshed every minute)
	fw_wait 'any(.drops[]; .port == 8443)' "blocked attempts on 8443"
	log "access back after the console reset; blocked attempts: $(api admin GET /firewall | jq -c '[.drops[] | select(.port == 8443)]')"
}

# Phase 17d: an offsite-only snapshot fetched back through the UI's job kinds. Its local copy is
# removed on disk like local retention would (real retention waits for the 14-day locks), which
# raises the "disappeared from the local store while locked" alert: local harness only, not in the
# default list. Then `offsite_list` shows it offsite only, `offsite_restore` fetches it (locked
# locally for 7 days), and the file browser lists it like any local snapshot.
step_offsite_fetch() {
	login admin "$ADMIN_PW" "$ADMIN_TOTP"
	local t other r j now
	r=$(api admin GET "/snapshots?tenant=lab&source=vm-100")
	t=$(jq -r '[.[] | select(.local and .offsite and .hold == null) | .time] | min' <<<"$r")
	other=$(jq -r --argjson t "$t" '[.[] | select(.local and .time != $t) | .time] | max' <<<"$r")
	[ "$t" != null ] || die "no local+offsite vm-100 snapshot"
	rm -rf "$ROOT/var/lib/nexus/chunkstore/lab/snapshots/vm-100/$t"
	# a finished retention job marks the tenant dirty: the refresh sees the snapshot offsite only
	r=$(api admin POST /jobs '{"kind":"retention","tenant":"lab","params":{"source":"vm-100"}}')
	expect 202 "retention job"
	wait_job admin "$(jq -r .id <<<"$r")" 600 >/dev/null
	for _ in $(seq 60); do
		api admin GET "/snapshots?tenant=lab&source=vm-100" |
			jq -e --argjson t "$t" 'any(.[]; .time == $t and (.local | not) and .offsite)' >/dev/null && break
		sleep 2
	done
	api admin GET "/snapshots?tenant=lab&source=vm-100" |
		jq -e --argjson t "$t" 'any(.[]; .time == $t and (.local | not) and .offsite)' >/dev/null || die "vm-100/$t not offsite only"
	log "vm-100/$t is offsite only"
	r=$(api admin POST /jobs '{"kind":"offsite_list","tenant":"lab","params":{}}')
	expect 202 "offsite_list job"
	j=$(wait_job admin "$(jq -r .id <<<"$r")" 600)
	[ "$(jq -r .state <<<"$j")" = ok ] || die "offsite_list: $(jq -r .log <<<"$j" | tail -n 5)"
	jq -e --argjson t "$t" '.result.snapshots | any(.[]; .source == "vm-100" and .time == $t and (.local | not) and .remote and .inventory)' \
		<<<"$j" >/dev/null || die "listing: $(jq -c .result <<<"$j")"
	log "offsite listing: $(jq -c '[.result.snapshots[] | {source, time, local, remote}]' <<<"$j")"
	if [ "$other" != null ]; then
		api admin POST /jobs "$(jq -nc --argjson t "$other" '{kind:"offsite_restore", tenant:"lab", params:{source:"vm-100", time:$t}}')" >/dev/null
		expect 409 "fetch of a snapshot that is local"
	fi
	r=$(api admin POST /jobs "$(jq -nc --argjson t "$t" '{kind:"offsite_restore", tenant:"lab", params:{source:"vm-100", time:$t}}')")
	expect 202 "offsite_restore job"
	j=$(wait_job admin "$(jq -r .id <<<"$r")" 1800)
	[ "$(jq -r .state <<<"$j")" = ok ] || die "offsite_restore: $(jq -r .log <<<"$j" | tail -n 10)"
	now=$(date +%s)
	for _ in $(seq 60); do
		api admin GET "/snapshots?tenant=lab&source=vm-100" |
			jq -e --argjson t "$t" --argjson n "$now" 'any(.[]; .time == $t and .local and .lock_until >= $n + 6 * 86400)' >/dev/null && break
		sleep 2
	done
	api admin GET "/snapshots?tenant=lab&source=vm-100" |
		jq -e --argjson t "$t" --argjson n "$now" 'any(.[]; .time == $t and .local and .lock_until >= $n + 6 * 86400)' >/dev/null ||
		die "vm-100/$t not local again with a 7-day lock: $(api admin GET "/snapshots?tenant=lab&source=vm-100" | jq -c .)"
	log "fetched back in $(jq '.finished - .started' <<<"$j") s, local again, locked for 7 days"
	r=$(api admin POST /jobs "$(jq -nc --argjson t "$t" '{kind:"files_list", tenant:"lab", params:{source:"vm-100", time:$t, path:"/"}}')")
	expect 202 "files_list of the fetched snapshot"
	j=$(wait_job admin "$(jq -r .id <<<"$r")" 900)
	[ "$(jq -r .state <<<"$j")" = ok ] || die "files_list: $(jq -r .log <<<"$j" | tail -n 10)"
	log "fetched snapshot browsable: $(jq -c '[.result.entries[]?.name]' <<<"$j")"
}

step_audit() {
	login so "$SO_PW" "$SO_TOTP"
	api so GET /audit/verify | jq -c . >&2
	api so GET /audit/verify | jq -e .ok >/dev/null || die "audit chain"
	api so GET "/audit?order=desc&limit=15" | jq -r '.[] | "  #\(.seq) \(.actor) \(.action) \(.target)"' >&2
}

# Phase 25: restore tests on the PVE lab (pve1, single node). vm-100 boots isolated from instant-recovery
# overlays, ct-200 is restored to local-lvm with its links down; both are checked and destroyed again.
# RT_AGENT=1: vm-100 has the QEMU guest agent (then also ping + tcp/22 inside the guest); default: running only.
# Checks: results rows, no nxtest- guest left on the node, the restore_test alert of a failing test (bad command)
# and its resolution, a cancel in the middle still destroys the guest.
rt_leftovers() {
	ssh -o BatchMode=yes -p 10022 -i "$LAB/lab_ed25519" -o UserKnownHostsFile="$LAB/known_hosts" root@localhost \
		"qm list; pct list" | grep -c nxtest- || true
}
rt_run() { # rt_run SOURCE CHECKS-JSON -> job JSON
	local src=$1 checks=$2 time r
	time=$(api admin GET "/snapshots?tenant=lab&source=$src" | jq '[.[] | select(.local)] | max_by(.time).time')
	r=$(api admin POST /jobs "$(jq -nc --arg s "$src" --argjson t "$time" --argjson c "$checks" \
		'{kind:"restore_test", tenant:"lab", params:{source:$s, time:$t, node:"pve1", storage:"local-lvm", checks:$c}}')")
	expect 202 "restore_test $src"
	wait_job admin "$(jq -r .id <<<"$r")" 1800
}
step_restore_test() {
	login admin "$ADMIN_PW" "$ADMIN_TOTP"
	local vmc='{"agent":false}' j t0
	[ "${RT_AGENT:-0}" = 1 ] && vmc='{"ports":[22],"command":["true"]}'
	for spec in "vm-100 $vmc" 'ct-200 {}'; do
		set -- $spec
		t0=$(date +%s)
		j=$(rt_run "$1" "$2")
		[ "$(jq -r .state <<<"$j")" = ok ] || die "restore test $1: $(jq -r .log <<<"$j" | tail -n 20)"
		log "restore test $1 passed in $(($(date +%s) - t0)) s: $(api admin GET "/restore-tests?source=$1&limit=1" | jq -c '.[0] | {state, target, name, boot_secs, checks: [.checks[] | .name]}')"
	done
	[ "$(rt_leftovers)" = 0 ] || die "nxtest- guests left on pve1"
	# a failing check raises restore_test:lab/vm-100, the next pass resolves it
	j=$(rt_run vm-100 '{"boot_timeout":30,"ports":[1]}')
	[ "$(jq -r .state <<<"$j")" = failed ] || die "the failing restore test passed"
	api admin GET "/alerts?state=open" | jq -e 'any(.[]; .key == "restore_test:lab/vm-100")' >/dev/null || die "no restore_test alert"
	j=$(rt_run vm-100 "$vmc")
	api admin GET "/alerts?state=open" | jq -e 'all(.[]; .key != "restore_test:lab/vm-100")' >/dev/null || die "restore_test alert not resolved"
	# cancel while the guest runs: it is destroyed anyway
	local time r id
	time=$(api admin GET "/snapshots?tenant=lab&source=vm-100" | jq '[.[] | select(.local)] | max_by(.time).time')
	r=$(api admin POST /jobs "$(jq -nc --argjson t "$time" '{kind:"restore_test", tenant:"lab", params:{source:"vm-100", time:$t, node:"pve1", storage:"local-lvm", checks:{boot_timeout:900}}}')")
	id=$(jq -r .id <<<"$r")
	for _ in $(seq 120); do [ "$(rt_leftovers)" -gt 0 ] && break; sleep 1; done
	api admin POST "/jobs/$id/cancel" >/dev/null
	j=$(wait_job admin "$id" 600)
	[ "$(jq -r .state <<<"$j")" = cancelled ] || die "cancel: $(jq -r .state <<<"$j")"
	[ "$(rt_leftovers)" = 0 ] || die "the cancelled test left its guest"
	log "restore tests ok (failure alert raised and resolved, cancel cleaned up)"
}

# Phase 25: a recovery plan on the lab (vm-100 in wave 1, ct-200 in wave 2 after 10 s): readiness, isolated test
# run, DR report. The real execution is not run here (it would restore over the lab's VMIDs 100/200: those
# exist, so it fails by design); to try it, set targets to free VMIDs and approve as so.
step_recovery_plan() {
	login admin "$ADMIN_PW" "$ADMIN_TOTP"
	local src r id run j
	src=$(api admin GET /sources | jq '[.[] | select(.tenant == "lab" and .kind == "pve")][0].id')
	r=$(api admin POST /recovery-plans "$(jq -nc --argjson s "$src" '{tenant:"lab", name:"lab-dr", source_id:$s, node:"pve1",
		storage:"local-lvm", rpo_hours:48, steps:[{source:"vm-100", wave:1, checks:{agent:false}}, {source:"ct-200", wave:2, delay:10}]}')")
	expect 201 "create recovery plan"
	id=$(jq -r .id <<<"$r")
	for _ in $(seq 300); do
		r=$(api admin GET /recovery-plans | jq --argjson id "$id" '.[] | select(.id == $id)')
		[ "$(jq -r '.readiness != null' <<<"$r")" = true ] && break
		sleep 2
	done
	[ "$(jq -r .readiness.ok <<<"$r")" = true ] || die "plan not ready: $(jq -c .readiness <<<"$r")"
	log "readiness: $(jq -c '[.readiness.checks[] | .name]' <<<"$r")"
	r=$(api admin POST "/recovery-plans/$id/test")
	expect 202 "test run"
	run=$(jq -r .run_id <<<"$r")
	j=$(wait_job admin "$(jq -r .job_id <<<"$r")" 3600)
	[ "$(jq -r .state <<<"$j")" = ok ] || die "test run: $(jq -r .log <<<"$j" | tail -n 30)"
	[ "$(rt_leftovers)" = 0 ] || die "test run left guests"
	api admin GET "/recovery-runs/$run/report" >"$S/dr-report.html"
	expect 200 "DR report"
	grep -q "Recovery plan test run: lab-dr" "$S/dr-report.html" || die "DR report content"
	log "recovery plan test run ok in $(jq '.finished - .started' <<<"$j") s; report $S/dr-report.html"
}

steps=("$@")
[ ${#steps[@]} -gt 0 ] || steps=(config wait-backup check restore verify quorum phase13 legal-hold phase14d2 access diag audit)
for s in "${steps[@]}"; do
	log "== $s"
	"step_${s//-/_}"
done
log "done"
