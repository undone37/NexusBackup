#!/usr/bin/env bash
# NAS shares end to end through the control plane, REST only (what the UI does):
# NFS (v4.2 and v3) and SMB (3.1.1, signed + encrypted) sources on the NAS lab VM.
#
#   e2e.sh [step...]   default: data config backup1 download modify backup2 churn snapshot many alerts summary
#
# Steps:
#   data      fresh /srv/share (data.sh init)
#   config    tenant `nas`, sources nfs1 (NFS 4.2 /srv/share), smb1 (SMB 3.1.1 share, seal),
#             many1 (NFS 3 /srv/many, 1M small files), policy (daily, first slot ~2 min ahead), groups
#   backup1   the scheduled backup of nfs1, manual backups of smb1 (full); job results + rates
#   download  tar + zip of / from nfs1 and smb1 compared by sha256 with the files on the server
#             (compare.py; SMB: names Samba cannot represent excluded); xattrs/ACLs in the tar
#   modify    data.sh modify (edits, renames, deletes, new files, links, chmod/chown, xattr/ACL-only)
#   backup2   incremental backups of nfs1 + smb1 (metadata cache: only changed files read)
#   churn     a writer changes files during the backup: consistent=false, files marked inconsistent
#   snapshot  LVM snapshot mounted as /srv/share/.snapshot/<name>; nfs1 with snapshot_dir .snapshot
#             reads the newest snapshot: consistent=true
#   many      many1: full, unchanged, after data.sh many-modify (files/s, bytes)
#   alerts    backup_inconsistent alert raised for the churn run
#   summary   table of the measured runs ($S/results)
#
# Targets: the dev control plane in the NAS VM (default, lab/nas/devcp.sh: shares over the
# VM's loopback) or the appliance VM (APPL=1: ROOT=$LAB/appliance/root, PORT=28443; shares
# through QEMU user networking at 10.0.2.2 and the forwarded ports 12049/12048/10445).
# env: APPL (0|1), LAB (/home/ah/nexus-lab)
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
e2e=$(cd "$here/../e2e" && pwd)
LAB=${LAB:-/home/ah/nexus-lab}
APPL=${APPL:-0}
if [ "$APPL" = 1 ]; then
	export ROOT=${ROOT:-$LAB/appliance/root} PORT=${PORT:-28443}
	eval "$("$e2e/m5.sh" env)"
	NAS_HOST=10.0.2.2 NFS_PORT=12049 MOUNTD=12048 SMB_PORT=10445
else
	eval "$("$here/devcp.sh" env)"
	NAS_HOST=127.0.0.1 NFS_PORT=2049 MOUNTD=20048 SMB_PORT=445
fi
S=$ROOT/run/nas
mkdir -p "$S"
# shellcheck source=lab/e2e/api-lib.sh
. "$e2e/api-lib.sh"
ids() { [ -f "$S/ids" ] && . "$S/ids"; }
vmdata() { "$here/vm.sh" data "$@"; }
note() { echo "$*" >>"$S/results"; log "$*"; }

src_nfs() {
	jq -nc --arg h "$NAS_HOST" --argjson p "$NFS_PORT" \
		'{host:$h, port:$p, version:"4.2", export:"/srv/share", excludes:["*.tmp"]}'
}

step_data() {
	vmdata init >&2
	log "fresh test data in /srv/share (data.sh init)"
}

step_config() {
	login admin "$ADMIN_PW" "$ADMIN_TOTP"
	: >"$S/results"
	: >"$S/committed"
	api admin POST /tenants '{"name":"nas","offsite":{}}' >/dev/null
	expect 201 "create tenant"
	local out nfs smb many pw
	out=$(api admin POST /sources "$(jq -nc --argjson c "$(src_nfs)" '{tenant:"nas", kind:"nfs", name:"nfs1", config:$c}')")
	expect 201 "create nfs source"
	nfs=$(jq -r .id <<<"$out")
	pw=$(tr -d '\n' <"$LAB/nas/smb-password")
	out=$(api admin POST /sources "$(jq -nc --arg h "$NAS_HOST" --argjson p "$SMB_PORT" --arg pw "$pw" \
		'{tenant:"nas", kind:"smb", name:"smb1", config:{host:$h, port:$p, share:"share", user:"nexusbackup",
		  password:$pw, version:"3.1.1", sign:true, seal:true}}')")
	expect 201 "create smb source"
	smb=$(jq -r .id <<<"$out")
	jq -e '.config.password_set and .config.password == null' <<<"$out" >/dev/null || die "SMB password leaked or not set"
	out=$(api admin POST /sources "$(jq -nc --arg h "$NAS_HOST" --argjson p "$NFS_PORT" --argjson m "$MOUNTD" \
		'{tenant:"nas", kind:"nfs", name:"many1", config:{host:$h, port:$p, mount_port:$m, version:"3", export:"/srv/many", threads:32}}')")
	expect 201 "create nfs many source"
	many=$(jq -r .id <<<"$out")
	if [ -f "$ROOT/var/lib/nexus/catalog/catalog.db" ]; then
		python3 - "$ROOT/var/lib/nexus/catalog/catalog.db" "$pw" <<-'PY' || die "plaintext secret in the catalog"
			import json, sqlite3, sys
			db = sqlite3.connect(f"file:{sys.argv[1]}?mode=ro", uri=True)
			for (k, c) in db.execute("SELECT kind, config FROM sources WHERE kind = 'smb'"):
			    assert sys.argv[2] not in c and json.loads(c)["password"].startswith("sealed:v1:")
		PY
	fi
	local at later pol pol2 g1 g2 g3
	at=$(date -u -d "@$((($(date +%s) + 100) / 60 * 60))" +%H:%M)
	# the other groups run manually in this test: their slot is just behind us (next run tomorrow)
	later=$(date -u -d "@$(($(date +%s) - 3600))" +%H:%M)
	pol=$(api admin POST /policies "$(jq -nc --arg s "daily $at" '{name:"nas-daily", schedule:$s, gfs:{daily:14,weekly:4,monthly:6,yearly:1}, offsite:false}')" | jq -r .id)
	expect 201 "create policy"
	pol2=$(api admin POST /policies "$(jq -nc --arg s "daily $later" '{name:"nas-manual", schedule:$s, gfs:{daily:14,weekly:4,monthly:6,yearly:1}, offsite:false}')" | jq -r .id)
	expect 201 "create policy 2"
	group() { api admin POST /groups "$(jq -nc --argjson s "$1" --argjson p "$3" --arg n "$2" '{tenant:"nas", source_id:$s, policy_id:$p, name:$n, guests:[]}')" | jq -r .id; }
	g1=$(group "$nfs" g-nfs1 "$pol")
	expect 201 "group nfs1"
	g2=$(group "$smb" g-smb1 "$pol2")
	expect 201 "group smb1"
	g3=$(group "$many" g-many1 "$pol2")
	expect 201 "group many1"
	echo "NFS=$nfs SMB=$smb MANY=$many POL=$pol G_NFS=$g1 G_SMB=$g2 G_MANY=$g3" >"$S/ids"
	log "tenant nas: sources nfs1=$nfs smb1=$smb many1=$many, policy $pol (daily $at UTC), groups $g1 $g2 $g3"
}

# backup GROUP -> job id (manual)
backup() {
	local j
	j=$(api admin POST /jobs "$(jq -nc --argjson g "$1" '{kind:"backup", tenant:"nas", params:{group_id:$g}}')")
	expect 202 "backup group $1"
	jq -r .id <<<"$j"
}

# finished JOB [label] -> prints the committed line, records duration/rates
finished() {
	local id=$1 label=${2:-} j
	j=$(wait_job admin "$id" 7200)
	jq -r .log <<<"$j" | grep -E '^(mounted|reading|committed|inconsistent|no snapshot|error)' | head -20 >&2 || true
	[ "$(jq -r .state <<<"$j")" = ok ] || die "job $id: $(jq -r .log <<<"$j" | tail -12)"
	if [ -n "$label" ]; then
		local c secs
		c=$(jq -r .log <<<"$j" | grep '^committed ' | head -1)
		secs=$(jq -r '.finished - .started' <<<"$j")
		note "$label | job ${secs}s | consistent=$(jq -r .result.consistent <<<"$j") | ${c#committed }"
	fi
	echo "$j" >"$S/job-$id.json"
	jq -r '.result.snapshots[]? | "\(.source) \(.time)"' <<<"$j" >>"$S/committed"
}

step_backup1() {
	ids
	login admin "$ADMIN_PW" "$ADMIN_TOTP"
	local id
	for _ in $(seq 200); do
		id=$(api admin GET "/jobs?kind=backup&limit=20" | jq -r --argjson g "$G_NFS" \
			'[.[] | select(.params.group_id==$g and .requested_by=="scheduler")] | min_by(.id) | .id // empty')
		[ -n "$id" ] && break
		sleep 2
	done
	[ -n "$id" ] || die "no scheduled backup of g-nfs1"
	log "scheduled backup of nfs1: job $id"
	finished "$id" "nfs1 full (NFS 4.2)"
	local s
	s=$(backup "$G_SMB")
	finished "$s" "smb1 full (SMB 3.1.1 sign+seal)"
	# the retention follow-up of the scheduled backup ran
	for _ in $(seq 60); do
		[ "$(api admin GET "/jobs?kind=retention&limit=20" | jq --argjson g "$G_NFS" '[.[] | select(.params.group_id==$g and .state=="ok")] | length')" -ge 1 ] && break
		sleep 2
	done
}

latest() {
	api admin GET "/snapshots?tenant=nas&source=$1" | jq -r 'max_by(.time) | .time'
}

# download SOURCE FMT OUT
download() {
	local j id tok t want
	# the newest snapshot this script committed for the source (the snapshot list is
	# refreshed by the scheduler a few seconds after the backup)
	want=$(awk -v s="$1" '$1 == s {t = $2} END {print t}' "$S/committed" 2>/dev/null)
	for _ in $(seq 90); do
		t=$(latest "$1")
		[ -n "$t" ] && [ "$t" != null ] && { [ -z "$want" ] || [ "$t" = "$want" ]; } && break
		sleep 2
	done
	[ -z "$want" ] || [ "$t" = "$want" ] || die "snapshot $1/$want not listed"
	j=$(api admin POST /jobs "$(jq -nc --arg s "$1" --argjson t "$t" --arg f "$2" '{kind:"files_get", tenant:"nas", params:{source:$s, time:$t, paths:["/"], format:$f}}')")
	expect 202 "files_get $1 $2"
	id=$(jq -r .id <<<"$j")
	tok=$(jq -r .download_token <<<"$j")
	j=$(wait_job admin "$id" 1800)
	[ "$(jq -r .state <<<"$j")" = ok ] || die "files_get $1 $2: $(jq -r .log <<<"$j" | tail -3)"
	curl -s --cacert "$ROOT/etc/nexus/tls/cert.pem" --resolve "nexus-m5:$PORT:127.0.0.1" -b "$S/admin.jar" \
		-o "$3" "$BASE/downloads/$tok"
	# dev control plane: the downloads (1 GiB sparse file expanded) would fill the lab disk
	# before they expire; the appliance keeps them until the TTL
	[ "$APPL" = 1 ] || "$here/vm.sh" ssh rm -f "/var/lib/nexus-lab/m5-root/var/lib/nexus/downloads/$tok.$2"
}

step_download() {
	ids
	login admin "$ADMIN_PW" "$ADMIN_TOTP"
	vmdata sums share >"$S/sums-share.txt"
	vmdata xattrs >"$S/xattrs.txt"
	local t j
	t=$(latest "share-$NFS")
	j=$(api admin POST /jobs "$(jq -nc --arg s "share-$NFS" --argjson t "$t" '{kind:"files_list", tenant:"nas", params:{source:$s, time:$t, path:"/docs"}}')")
	expect 202 "files_list"
	j=$(wait_job admin "$(jq -r .id <<<"$j")" 300)
	jq -e '.state == "ok" and ([.result.entries[].name] | index("README.txt") != null)' <<<"$j" >/dev/null ||
		die "listing /docs: $(jq -c '.result' <<<"$j")"
	for fmt in tar zip; do
		download "share-$NFS" "$fmt" "$S/nfs.$fmt"
		python3 "$here/compare.py" "$S/nfs.$fmt" "$S/sums-share.txt" share | tail -1 >&2 || die "NFS download ($fmt) differs"
		download "share-$SMB" "$fmt" "$S/smb.$fmt"
		python3 "$here/compare.py" "$S/smb.$fmt" "$S/sums-share.txt" share --smb | tail -1 >&2 || die "SMB download ($fmt) differs"
	done
	python3 "$here/xattrs.py" "$S/nfs.tar" "$S/xattrs.txt" nfs >&2 || die "NFS xattrs/ACLs"
	python3 "$here/xattrs.py" "$S/smb.tar" "$S/xattrs.txt" smb >&2 || die "SMB xattrs/ACLs"
	note "downloads: tar + zip of nfs1 and smb1 match the server (sha256), xattrs/ACLs checked"
}

step_modify() {
	vmdata modify >&2
	log "share modified (edits, renames, deletes, new files, links, chmod/chown, xattr + ACL changes)"
}

step_backup2() {
	ids
	login admin "$ADMIN_PW" "$ADMIN_TOTP"
	local a b
	a=$(backup "$G_NFS")
	finished "$a" "nfs1 incremental after modify"
	b=$(backup "$G_SMB")
	finished "$b" "smb1 incremental after modify"
	vmdata sums share >"$S/sums-share.txt"
	download "share-$NFS" tar "$S/nfs2.tar"
	python3 "$here/compare.py" "$S/nfs2.tar" "$S/sums-share.txt" share | tail -1 >&2 || die "NFS download after modify differs"
	download "share-$SMB" zip "$S/smb2.zip"
	# small/f3 got new content of the same size and its old mtime back: NFS sees the new
	# ctime; Samba reports the mtime as ChangeTime, so over SMB the file looks unchanged
	# (documented limitation of metadata-based change detection against Samba)
	python3 "$here/compare.py" "$S/smb2.zip" "$S/sums-share.txt" share --smb --allow small/f3 | grep -E "allowed|files compared" >&2 ||
		die "SMB download after modify differs"
	note "SMB/Samba: same-size rewrite with restored mtime (small/f3) not detected (Samba ChangeTime = mtime); NFS: detected via ctime"
	a=$(backup "$G_NFS")
	finished "$a" "nfs1 no changes"
}

step_churn() {
	ids
	login admin "$ADMIN_PW" "$ADMIN_TOTP"
	vmdata churn 600 >&2
	sleep 3
	local id j n
	id=$(backup "$G_NFS")
	finished "$id" "nfs1 during writes (churn)"
	vmdata churn-stop >&2
	j=$(cat "$S/job-$id.json")
	[ "$(jq -r .result.consistent <<<"$j")" = false ] || die "churn backup reported consistent"
	n=$(jq -r .log <<<"$j" | sed -n 's/^inconsistent .*; \([0-9]*\) files changed while read.*/\1/p')
	[ "${n:-0}" -ge 1 ] || die "no file marked inconsistent during the churn"
	note "churn: $n files changed while read -> marked inconsistent, consistent=false"
	echo "CHURN_JOB=$id" >>"$S/ids"
}

step_snapshot() {
	ids
	login admin "$ADMIN_PW" "$ADMIN_TOTP"
	vmdata snap nightly-1 >&2
	local cfg id j
	cfg=$(src_nfs | jq -c '. + {snapshot_dir:".snapshot", snapshot_prefix:"nightly-"}')
	api admin PUT "/sources/$NFS" "$(jq -nc --argjson c "$cfg" '{name:"nfs1", config:$c}')" >/dev/null
	expect 200 "nfs1: snapshot_dir"
	vmdata churn 600 >&2
	id=$(backup "$G_NFS")
	finished "$id" "nfs1 from NAS snapshot (writes on the live share)"
	vmdata churn-stop >&2
	j=$(cat "$S/job-$id.json")
	jq -r .log <<<"$j" | grep -q 'NAS snapshot nightly-1' || die "snapshot not used"
	[ "$(jq -r .result.consistent <<<"$j")" = true ] || die "snapshot backup not consistent"
	# back to the live share
	api admin PUT "/sources/$NFS" "$(jq -nc --argjson c "$(src_nfs)" '{name:"nfs1", config:$c}')" >/dev/null
	expect 200 "nfs1: live"
	vmdata snap-rm nightly-1 >&2
	note "snapshot: newest .snapshot/nightly-1 read while the live share changed: consistent=true"
}

step_many() {
	ids
	login admin "$ADMIN_PW" "$ADMIN_TOTP"
	local id
	id=$(backup "$G_MANY")
	finished "$id" "many1 full (NFS 3, 1M files)"
	id=$(backup "$G_MANY")
	finished "$id" "many1 unchanged"
	vmdata many-modify >&2
	id=$(backup "$G_MANY")
	finished "$id" "many1 after 1000 changed/1000 new/1000 deleted"
}

step_alerts() {
	ids
	login admin "$ADMIN_PW" "$ADMIN_TOTP"
	local n
	for _ in $(seq 30); do
		n=$(api admin GET /alerts | jq '[.[] | select(.kind=="backup_inconsistent" and (.message | contains("share-")))] | length')
		[ "$n" -ge 1 ] && break
		sleep 2
	done
	[ "$n" -ge 1 ] || die "no backup_inconsistent alert for a share"
	note "alerts: $n backup_inconsistent alert(s) for share snapshots"
}

step_summary() {
	cat "$S/results"
}

steps=${*:-data config backup1 download modify backup2 churn snapshot many alerts summary}
for s in $steps; do
	log "== $s"
	"step_$s"
done
log "NAS e2e passed"
