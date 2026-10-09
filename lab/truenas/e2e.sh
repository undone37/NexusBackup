#!/usr/bin/env bash
# TrueNAS end to end through the control plane, REST only (what the UI does).
# Prerequisites: lab/truenas/vm.sh start; provision.py; the dev control plane
# (lab/e2e/m5.sh setup && lab/e2e/m5.sh start), or the appliance VM (APPL_HOST=10.0.2.2).
#   e2e.sh [step...]   steps (default all): data config backup1 modify backup2 snapshots download rotation probe
# Lab inputs ($LAB/truenas, written by provision.py): cert.pem, api-key, known_hosts, nexus_ed25519(.pub).
# env: APPL_HOST (how the appliance reaches the dev host: 127.0.0.1 or 10.0.2.2 from the appliance VM),
#      FROM (the appliance address TrueNAS sees; QEMU user networking: 10.0.2.2)
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
e2e=$(cd "$here/../e2e" && pwd)
eval "$("$e2e/m5.sh" env)"
S=$ROOT/run/truenas
mkdir -p "$S"
LAB=${LAB:-/home/ah/nexus-lab}
D=$LAB/truenas
APPL_HOST=${APPL_HOST:-127.0.0.1}
FROM=${FROM:-10.0.2.2}
# shellcheck source=lab/e2e/api-lib.sh
. "$e2e/api-lib.sh"
ids() { [ -f "$S/ids" ] && . "$S/ids"; }

step_data() {
	python3 "$here/sh.py" "$here/data.sh" init
	log "test data created on TrueNAS"
}

step_config() {
	login admin "$ADMIN_PW" "$ADMIN_TOTP"
	api admin POST /tenants '{"name":"nas","offsite":{}}' >/dev/null
	expect 201 "create tenant"
	local cfg hk
	hk=$(awk '!/^#/ {print $2" "$3; exit}' "$D/known_hosts")
	cfg=$(jq -nc --rawfile ca "$D/cert.pem" --arg tok "$(tr -d '\n' <"$D/api-key")" --rawfile key "$D/nexus_ed25519" \
		--arg pub "$(cat "$D/nexus_ed25519.pub")" --arg hk "$hk" --arg h "$APPL_HOST" --arg from "$FROM" \
		'{host:"truenas.local", port:18444, connect_addr:($h+":18444"), ca_pem:$ca, user:"nexusbackup", token_secret:$tok,
		  ssh:{host:$h, port:12222, user:"nexusbackup", host_key:$hk, key_pem:$key, public_key:$pub, from:$from},
		  datasets:["tank/data","tank/smb"], recursive:true}')
	local out
	out=$(api admin POST /sources "$(jq -nc --argjson c "$cfg" '{tenant:"nas", kind:"truenas", name:"truenas1", config:$c}')")
	expect 201 "create source"
	SRC=$(jq -r .id <<<"$out")
	jq -e '.config.token_secret_set and .config.ssh.key_pem_set and .config.token_secret == null and .config.ssh.key_pem == null' \
		<<<"$out" >/dev/null || die "secrets leaked or not set"
	# the admin pastes the returned line into the TrueNAS user's "SSH public key" field
	jq -r .config.authorized_keys <<<"$out" >"$D/authorized_keys"
	python3 "$here/provision.py" | tail -1
	log "authorized_keys line ($(wc -c <"$D/authorized_keys") bytes) installed on TrueNAS"
	[ ! -f "$ROOT/var/lib/nexus/catalog/catalog.db" ] ||
		python3 - "$ROOT/var/lib/nexus/catalog/catalog.db" "$D/api-key" <<-'PY' || die "plaintext secret in the catalog"
			import json, sqlite3, sys
			db = sqlite3.connect(f"file:{sys.argv[1]}?mode=ro", uri=True)
			key = open(sys.argv[2]).read().strip()
			for (k, c) in db.execute("SELECT kind, config FROM sources"):
			    v = json.loads(c)
			    if k == "truenas":
			        assert key not in c and "PRIVATE KEY" not in c
			        assert v["token_secret"].startswith("sealed:v1:") and v["ssh"]["key_pem"].startswith("sealed:v1:")
		PY
	local at
	at=$(date -u -d "@$((($(date +%s) + 100) / 60 * 60))" +%H:%M)
	POL=$(api admin POST /policies "$(jq -nc --arg s "daily $at" '{name:"nas-daily", schedule:$s, gfs:{daily:14,weekly:4,monthly:6,yearly:1}, offsite:false}')" | jq -r .id)
	expect 201 "create policy"
	GRP=$(api admin POST /groups "$(jq -nc --argjson s "$SRC" --argjson p "$POL" '{tenant:"nas", source_id:$s, policy_id:$p, name:"nas-all", guests:[]}')" | jq -r .id)
	expect 201 "create group"
	echo "SRC=$SRC POL=$POL GRP=$GRP" >"$S/ids"
	log "tenant nas, truenas source $SRC, policy $POL (daily $at UTC), group $GRP $(api admin GET "/groups" | jq -c ".[] | select(.id==$GRP) | .guests")"
}

# waits for the next scheduled backup of the group (after job id $1) and its retention follow-up
wait_scheduled() {
	local after=$1 id j
	for _ in $(seq 300); do
		id=$(api admin GET "/jobs?kind=backup&limit=20" | jq -r --argjson g "$GRP" --argjson a "$after" \
			'[.[] | select(.params.group_id==$g and .id>$a and .requested_by=="scheduler")] | min_by(.id) | .id // empty')
		[ -n "$id" ] && break
		sleep 2
	done
	[ -n "$id" ] || die "no scheduled backup job"
	j=$(wait_job admin "$id" 1800)
	jq -r .log <<<"$j" | grep -E '^(committed|dataset|failed|deleting|skipping)' >&2 || true
	[ "$(jq -r .state <<<"$j")" = ok ] || die "backup job $id: $(jq -r .log <<<"$j" | tail -5)"
	jq -c '.result.snapshots' <<<"$j" >&2
	echo "$id"
}

step_backup1() {
	ids
	login admin "$ADMIN_PW" "$ADMIN_TOTP"
	local id
	id=$(wait_scheduled 0)
	echo "B1=$id" >>"$S/ids"
	log "scheduled backup 1 (job $id): $(api admin GET "/jobs/$id" | jq -c '[.result.snapshots[] | {source, transferred_bytes}]')"
}

step_modify() {
	python3 "$here/sh.py" "$here/data.sh" modify
	log "TrueNAS data modified (edits, renames of a file and a directory, deletes, new files, new hard link, chmod/chown, xattr + ACL changes)"
}

step_backup2() {
	ids
	login admin "$ADMIN_PW" "$ADMIN_TOTP"
	# move the daily slot to the next minute (not a weakening change: no quorum)
	local at
	at=$(date -u -d "@$((($(date +%s) + 100) / 60 * 60))" +%H:%M)
	api admin PUT "/policies/$POL" "$(jq -nc --arg s "daily $at" '{name:"nas-daily", schedule:$s, gfs:{daily:14,weekly:4,monthly:6,yearly:1}, offsite:false}')" >/dev/null
	expect 200 "move schedule"
	log "policy $POL now daily $at UTC"
	local id
	id=$(wait_scheduled "$B1")
	echo "B2=$id" >>"$S/ids"
	log "scheduled backup 2 (job $id): $(api admin GET "/jobs/$id" | jq -c '[.result.snapshots[] | {source, transferred_bytes}]')"
	# the retention follow-up of each backup ran
	local r
	r=$(api admin GET "/jobs?kind=retention&limit=20" | jq -r --argjson g "$GRP" '[.[] | select(.params.group_id==$g)] | length')
	[ "$r" -ge 1 ] || die "no retention follow-up"
}

step_snapshots() {
	ids
	login admin "$ADMIN_PW" "$ADMIN_TOTP"
	for _ in $(seq 60); do
		n=$(api admin GET "/snapshots?tenant=nas" | jq '[.[] | select(.source | startswith("nas-"))] | length')
		[ "$n" -ge 6 ] && break
		sleep 2
	done
	api admin GET "/snapshots?tenant=nas" | jq -r '.[] | "\(.source) \(.time) \(.size)"' | sort >&2
	[ "$n" -ge 6 ] || die "expected 2 snapshots of 3 datasets, got $n"
}

step_download() {
	ids
	login admin "$ADMIN_PW" "$ADMIN_TOTP"
	python3 "$here/sh.py" "$here/data.sh" sums >"$S/sums.txt"
	local src="nas-$SRC-tank.data" t id tok j
	t=$(api admin GET "/snapshots?tenant=nas&source=$src" | jq -r 'max_by(.time) | .time')
	j=$(api admin POST /jobs "$(jq -nc --arg s "$src" --argjson t "$t" '{kind:"files_list", tenant:"nas", params:{source:$s, time:$t, path:"/docs"}}')")
	expect 202 "files_list"
	j=$(wait_job admin "$(jq -r .id <<<"$j")" 300)
	jq -e '.state == "ok" and ([.result.entries[].name] | index("README.txt") != null)' <<<"$j" >/dev/null ||
		die "listing /docs: $(jq -c '.result' <<<"$j")"
	for fmt in tar zip; do
		j=$(api admin POST /jobs "$(jq -nc --arg s "$src" --argjson t "$t" --arg f "$fmt" '{kind:"files_get", tenant:"nas", params:{source:$s, time:$t, paths:["/"], format:$f}}')")
		expect 202 "files_get $fmt"
		id=$(jq -r .id <<<"$j")
		tok=$(jq -r .download_token <<<"$j")
		j=$(wait_job admin "$id" 600)
		[ "$(jq -r .state <<<"$j")" = ok ] || die "files_get $fmt: $(jq -r .log <<<"$j" | tail -3)"
		curl -s --cacert "$ROOT/etc/nexus/tls/cert.pem" --resolve "nexus-m5:$PORT:127.0.0.1" -b "$S/admin.jar" \
			-o "$S/dl.$fmt" "$BASE/downloads/$tok"
		python3 "$here/compare.py" "$S/dl.$fmt" "$S/sums.txt" data || die "download ($fmt) differs from TrueNAS"
	done
	log "tar + zip downloads of $src/$t match the files on TrueNAS"
}

step_rotation() {
	ids
	python3 "$here/tn.py" call pool.snapshot.query '[["snapshot_name","^","nexus-"]]' '{"select":["id"]}' |
		jq -r '.[].id' | sort >"$S/tn-snaps"
	cat "$S/tn-snaps" >&2
	local want
	want=$(api admin GET "/jobs/$B2" | jq -r '.result.snapshots[0].time')
	for ds in tank/data tank/data/projects tank/smb; do
		[ "$(grep -c "^$ds@nexus-$SRC-" "$S/tn-snaps")" = 1 ] || die "$ds: expected exactly one nexus-$SRC snapshot"
		grep -qx "$ds@nexus-$SRC-$want" "$S/tn-snaps" || die "$ds: reference is not the last backup ($want)"
	done
	! grep -q "^tank/other@" "$S/tn-snaps" || die "unselected dataset snapshotted"
	log "TrueNAS keeps exactly the last backed-up snapshot (nexus-$SRC-$want) per dataset"
}

step_probe() {
	python3 "$here/probe.py"
}

steps=${*:-data config backup1 modify backup2 snapshots download rotation probe}
for s in $steps; do
	log "== $s"
	"step_$s"
done
log "TrueNAS e2e passed"
