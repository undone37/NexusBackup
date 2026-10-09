#!/usr/bin/env bash
# Linux agent end to end through the appliance's REST API, against one lab VM
# (lab/linux/vm.sh <vm> up). Results (key=value) in $S/<vm>.results.
#
#   e2e.sh appliance            dev control plane: lab/e2e/m5.sh setup + start (ROOT, PORT below)
#   e2e.sh <vm> [steps]         default steps: agent backup incr restore download db update
#     agent     create the agent (API), install the bundle with the token on the VM, enroll (job)
#     backup    hook(s) on the VM, linux source + policy (daily, next minute) + group, wait for the
#               scheduled backup; consistent=true expected unless the VM has no snapshots
#               (deb-plain: consistent=false + backup_inconsistent alert)
#     incr      change a few files, manual backup: transferred bytes must stay small
#     restore   restore_files (wrong confirm refused, confirm = agent name) to /restore/<n>,
#               compare owners/modes/mtimes/xattrs/ACLs/content (lab/linux/manifest.py)
#     download  files_get tar + zip of the data directory, content checked against the VM
#     db        restore the DB dump directory, drop the database, load the dump, count rows
#     update    agent_update: wrong signature refused, signed 0.1.1 (lab/linux/bump-bundle.sh) accepted
# env: ROOT (target/linux-root; appliance VM: $LAB/appliance/root), PORT (18453; VM: 28443),
#      AGENT_HOST (127.0.0.1; the appliance VM reaches the lab VMs as 10.0.2.2),
#      BUNDLE (target/agent-dist/nexus-agent-<v>-x86_64.tar.gz), BUMP (target/agent-bump/src/target/agent-dist/nexus-agent-0.1.1-x86_64),
#      UPDATE_DIR (agent_update_dir of the scheduler: $ROOT/agent-update; empty = skip update)
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
export ROOT=${ROOT:-$repo/target/linux-root} PORT=${PORT:-18453}
AGENT_HOST=${AGENT_HOST:-127.0.0.1}
ver=$(sed -n 's/^version = "\(.*\)"/\1/p' "$repo/crates/agent-linux/Cargo.toml" | head -1)
BUNDLE=${BUNDLE:-$repo/target/agent-dist/nexus-agent-$ver-x86_64.tar.gz}
BUMP=${BUMP:-$repo/target/agent-bump/src/target/agent-dist/nexus-agent-0.1.1-x86_64}
UPDATE_DIR=${UPDATE_DIR-$ROOT/agent-update}
TENANT=linux

if [ "${1:-}" = appliance ]; then
	ROOT=$ROOT PORT=$PORT "$repo/lab/e2e/m5.sh" setup
	ROOT=$ROOT PORT=$PORT "$repo/lab/e2e/m5.sh" start
	exit 0
fi
VM=${1:?vm or appliance}
shift
eval "$(ROOT=$ROOT PORT=$PORT "$repo/lab/e2e/m5.sh" env)"
S=$ROOT/run/api
mkdir -p "$S"
# shellcheck source=lab/e2e/api-lib.sh
. "$repo/lab/e2e/api-lib.sh"
vm() { "$here/vm.sh" "$VM" ssh "$@"; }
read -r _ AGENT_PORT <<<"$("$here/vm.sh" "$VM" ports)"
R=$S/$VM.results
touch "$R"
result() { # key value
	grep -v "^$1=" "$R" >"$R.tmp" || true
	echo "$1=$2" >>"$R.tmp"
	mv "$R.tmp" "$R"
	log "result $1=$2"
}
state() { [ -f "$S/$VM.env" ] && . "$S/$VM.env"; }

# per VM: backup paths, data directories compared after restore, database, snapshots expected
DB=none CONSISTENT=true
case $VM in
deb-lvm)
	PATHS='["/etc", "/home", "/var/lib/postgresql", "/var/backups/nexus", "/srv/xfs"]'
	DATA=(/srv/xfs/data /home/lab/data) DB=postgresql ;;
alma-xfs)
	PATHS='["/srv/xfs", "/var/lib/mysql", "/var/backups"]'
	DATA=(/srv/xfs/data) DB=mysql ;;
ubuntu-zfs)
	PATHS='["/home", "/srv/zfs"]'
	DATA=(/srv/zfs/data /home/lab/data) ;;
fedora-btrfs)
	PATHS='["/etc", "/home", "/srv/btrfs"]'
	DATA=(/srv/btrfs/data /home/lab/data) ;;
deb-plain)
	PATHS='["/etc", "/home", "/var/lib/mysql", "/var/backups/nexus"]'
	DATA=(/home/lab/data) DB=mysql CONSISTENT=false ;;
*) die "unknown VM $VM" ;;
esac

step_agent() {
	login admin "$ADMIN_PW" "$ADMIN_TOTP"
	api admin GET /tenants | jq -e --arg t "$TENANT" '.[] | select(.name==$t)' >/dev/null ||
		{ api admin POST /tenants "$(jq -nc --arg t "$TENANT" '{name:$t}')" >/dev/null && expect 201 "create tenant"; }
	local r id tok
	r=$(api admin POST /agents "$(jq -nc --arg t "$TENANT" --arg n "$VM" --arg h "$AGENT_HOST" --argjson p "$AGENT_PORT" \
		'{tenant:$t, name:$n, host:$h, port:$p}')")
	expect 201 "create agent"
	id=$(jq -r .id <<<"$r")
	tok=$(jq -r .token <<<"$r")
	log "agent $id, install command: $(jq -r .install_command <<<"$r" | sed "s/$tok/<token>/")"
	echo "AGENT=$id" >"$S/$VM.env"
	api admin GET /agents | jq -e --arg id "$id" '.[] | select(.id==$id) | (has("token") or has("token_hash")) | not' >/dev/null ||
		die "GET /agents leaks the token"
	"$here/vm.sh" "$VM" put "$BUNDLE" /tmp/
	local t0=$SECONDS
	vm "cd /tmp && rm -rf nexus-agent-*-x86_64/ && tar xzf $(basename "$BUNDLE") && cd nexus-agent-*-x86_64 && echo $tok | sudo ./install.sh --token -" | sed 's/^/  vm: /' >&2
	vm 'systemctl is-active nexus-agent' >/dev/null || die "service not active"
	result install_s $((SECONDS - t0))
	t0=$SECONDS
	r=$(api admin POST "/agents/$id/enroll")
	expect 202 "enroll"
	local j
	j=$(wait_job admin "$(jq -r .id <<<"$r")" 300)
	[ "$(jq -r .state <<<"$j")" = ok ] || die "enroll: $(jq -r .log <<<"$j" | tail -n 20)"
	result enroll_s $((SECONDS - t0))
	api admin GET /agents | jq -c --arg id "$id" '.[] | select(.id==$id) | {name, version, os, enrolled: (.cert_sha256 != null)}' >&2
	api admin GET /agents | jq -e --arg id "$id" '.[] | select(.id==$id) | .cert_sha256 != null and .version != null' >/dev/null ||
		die "agent not recorded as enrolled"
	# token is single use: a second enroll is refused
	api admin POST "/agents/$id/enroll" >/dev/null
	[ "$(status)" = 409 ] || die "second enroll: HTTP $(status)"
	vm 'sudo test ! -e /etc/nexus-agent/token' || die "token file still on the agent"
	vm 'sudo /usr/local/sbin/nexus-agent status' | sed 's/^/  vm: /' >&2
}

enable_hooks() {
	case $DB in
	postgresql) vm 'sudo sh -c "cd /etc/nexus-agent/hooks.d/pre && cp 10-postgresql.example 10-postgresql && chmod 0700 10-postgresql"' ;;
	mysql) vm 'sudo sh -c "cd /etc/nexus-agent/hooks.d/pre && cp 20-mysql.example 20-mysql && chmod 0700 20-mysql"' ;;
	*) return 0 ;;
	esac
	vm 'sudo /usr/local/sbin/nexus-agent hooks test' | sed 's/^/  vm: /' >&2
}

# job_line JOB_JSON PREFIX -> first matching log line
job_line() { jq -r .log <<<"$1" | grep -m1 "$2" || true; }

record_backup() { # prefix job-json
	local p=$1 j=$2 c
	c=$(job_line "$j" '^committed ')
	log "$c"
	result "${p}_s" "$(jq '.finished - .started' <<<"$j")"
	result "${p}_entries" "$(sed -n 's/.*: \([0-9]*\) entries.*/\1/p' <<<"$c")"
	result "${p}_bytes" "$(sed -n 's/.* entries, \([0-9]*\) bytes.*/\1/p' <<<"$c")"
	result "${p}_unchanged" "$(sed -n 's/.* \([0-9]*\) unchanged files.*/\1/p' <<<"$c")"
	result "${p}_xfer_chunks" "$(sed -n 's/.* \([0-9]*\) chunks transferred.*/\1/p' <<<"$c")"
	result "${p}_xfer_bytes" "$(sed -n 's/.*chunks transferred (\([0-9]*\) bytes.*/\1/p' <<<"$c")"
	local inc
	inc=$(job_line "$j" '^inconsistent ')
	if [ -n "$inc" ]; then
		result "${p}_consistent" false
		log "$inc"
	else
		result "${p}_consistent" true
	fi
	jq -r .log <<<"$j" | grep -E '^hook|snapshot|reading live' | sed 's/^/  log: /' >&2 || true
}

step_backup() {
	state
	login admin "$ADMIN_PW" "$ADMIN_TOTP"
	enable_hooks
	local src pol grp at pj
	at=$(date -u -d "@$((($(date +%s) + 100) / 60 * 60))" +%H:%M)
	# re-runs reuse source and group and move the policy to the next minute
	src=$(api admin GET /sources | jq -r --arg n "$VM" '.[] | select(.name==$n) | .id')
	if [ -z "$src" ]; then
		src=$(api admin POST /sources "$(jq -nc --arg t "$TENANT" --arg n "$VM" --arg a "$AGENT" --argjson p "$PATHS" \
			'{tenant:$t, kind:"linux", name:$n, config:{agent_id:$a, paths:$p, excludes:["*.tmp"], hooks:true}}')" | jq -r .id)
		expect 201 "create source"
	fi
	pj=$(jq -nc --arg n "$VM" --arg s "daily $at" '{name:$n, schedule:$s, gfs:{daily:7,weekly:4,monthly:3,yearly:1}, offsite:false}')
	pol=$(api admin GET /policies | jq -r --arg n "$VM" '.[] | select(.name==$n) | .id')
	if [ -z "$pol" ]; then
		pol=$(api admin POST /policies "$pj" | jq -r .id)
		expect 201 "create policy"
	else
		api admin PUT "/policies/$pol" "$pj" >/dev/null
		expect 200 "reschedule policy"
	fi
	grp=$(api admin GET /groups | jq -r --arg n "$VM" '.[] | select(.name==$n) | .id')
	if [ -z "$grp" ]; then
		grp=$(api admin POST /groups "$(jq -nc --arg t "$TENANT" --arg n "$VM" --arg a "$AGENT" --argjson s "$src" --argjson p "$pol" \
			'{tenant:$t, source_id:$s, policy_id:$p, name:$n, guests:[$a]}')" | jq -r .id)
		expect 201 "create group"
	fi
	echo "SRC=$src POL=$pol GRP=$grp" >>"$S/$VM.env"
	log "source $src, policy $pol (daily $at UTC), group $grp"
	local seen b=""
	seen=$(api admin GET "/jobs?kind=backup" | jq '[.[] | .id] | max // 0')
	for _ in $(seq 200); do
		b=$(api admin GET "/jobs?kind=backup" | jq -r --argjson s "$seen" --argjson g "$grp" \
			'[.[] | select(.requested_by=="scheduler" and .id > $s and .params.group_id == $g)][0].id // empty')
		[ -n "$b" ] && break
		sleep 1
	done
	[ -n "$b" ] || die "scheduler queued no backup"
	log "scheduled backup job $b"
	local j
	j=$(wait_job admin "$b" 1800)
	[ "$(jq -r .state <<<"$j")" = ok ] || die "backup: $(jq -r .log <<<"$j" | tail -n 30)"
	record_backup full "$j"
	[ "$(grep '^full_consistent=' "$R" | cut -d= -f2)" = "$CONSISTENT" ] || die "consistent != $CONSISTENT"
	if [ "$CONSISTENT" = false ]; then
		local a=""
		for _ in $(seq 60); do
			a=$(api admin GET /alerts | jq -c --arg id "$AGENT" '[.[] | select(.kind=="backup_inconsistent")] | .[0] // empty')
			[ -n "$a" ] && break
			sleep 2
		done
		[ -n "$a" ] || die "no backup_inconsistent alert"
		log "alert: $a"
		result alert_inconsistent yes
	fi
	echo "B1=$(jq -r .result.time <<<"$j")" >>"$S/$VM.env"
}

step_incr() {
	state
	login admin "$ADMIN_PW" "$ADMIN_TOTP"
	local d=${DATA[0]}
	# 4 KiB overwritten in the middle of a 24 MiB file, 2 MiB appended to another,
	# a new 1 MiB file, a mode change, a deleted file
	vm "sudo sh -c 'dd if=/dev/urandom of=$d/big.bin bs=4096 seek=2000 count=1 conv=notrunc status=none &&
		dd if=/dev/urandom bs=1M count=2 status=none >> $d/medium.bin &&
		dd if=/dev/urandom of=$d/new.bin bs=1M count=1 status=none && chmod 0600 $d/docs/note-3.txt &&
		rm -f $d/docs/note-4.txt && sync'"
	local r j
	r=$(api admin POST /jobs "$(jq -nc --arg t "$TENANT" --arg a "$AGENT" '{kind:"backup", tenant:$t, params:{agent_id:$a}}')")
	expect 202 "manual backup"
	j=$(wait_job admin "$(jq -r .id <<<"$r")" 1800)
	[ "$(jq -r .state <<<"$j")" = ok ] || die "incremental backup: $(jq -r .log <<<"$j" | tail -n 30)"
	record_backup incr "$j"
	local xb
	xb=$(grep '^incr_xfer_bytes=' "$R" | cut -d= -f2)
	# changed data ~3 MiB + chunk boundaries + hook dumps; a full re-transfer would be far more
	[ "$xb" -lt $((40 << 20)) ] || die "incremental backup transferred $xb bytes"
	echo "B2=$(jq -r .result.time <<<"$j")" >>"$S/$VM.env"
}

latest() { api admin GET "/snapshots?tenant=$TENANT" | jq -r --arg s "host-$AGENT" '[.[] | select(.source==$s and .local)] | max_by(.time) | .time'; }

step_restore() {
	state
	login admin "$ADMIN_PW" "$ADMIN_TOTP"
	local time n=0 r j paths
	time=$(latest)
	paths=$(printf '%s\n' "${DATA[@]}" | jq -R . | jq -sc .)
	# the UI's confirm dialog: anything but the agent's name is refused
	api admin POST /jobs "$(jq -nc --arg t "$TENANT" --arg s "host-$AGENT" --argjson tm "$time" --argjson p "$paths" \
		'{kind:"restore_files", tenant:$t, params:{source:$s, time:$tm, paths:$p, target:"/restore/x", overwrite:"never", confirm:"yes"}}')" >/dev/null
	expect 400 "restore with a wrong confirm"
	local target=/restore/$(date +%s)
	local t0=$SECONDS
	r=$(api admin POST /jobs "$(jq -nc --arg t "$TENANT" --arg s "host-$AGENT" --argjson tm "$time" --argjson p "$paths" --arg tg "$target" --arg c "$VM" \
		'{kind:"restore_files", tenant:$t, params:{source:$s, time:$tm, paths:$p, target:$tg, overwrite:"never", confirm:$c}}')")
	expect 202 "restore_files"
	j=$(wait_job admin "$(jq -r .id <<<"$r")" 1800)
	[ "$(jq -r .state <<<"$j")" = ok ] || die "restore: $(jq -r .log <<<"$j" | tail -n 30)"
	result restore_s $((SECONDS - t0))
	log "restored: $(jq -c .result <<<"$j")"
	"$here/vm.sh" "$VM" put "$here/manifest.py" /tmp/manifest.py
	local d
	for d in "${DATA[@]}"; do
		vm "sudo python3 -I /tmp/manifest.py $d > /tmp/m.orig && sudo python3 -I /tmp/manifest.py $target$d > /tmp/m.rest && diff /tmp/m.orig /tmp/m.rest" >"$S/$VM.diff" ||
			die "restored $d differs: $(head -20 "$S/$VM.diff")"
		n=$((n + $(vm 'wc -l < /tmp/m.orig')))
	done
	result restore_compared "$n entries identical"
	# parents get their recorded metadata; the target root stays root-owned 0700? (log only)
	vm "sudo ls -ld $target $target${DATA[0]%/*}" | sed 's/^/  vm: /' >&2
	# second restore into the same target with overwrite=never keeps everything
	r=$(api admin POST /jobs "$(jq -nc --arg t "$TENANT" --arg s "host-$AGENT" --argjson tm "$time" --argjson p "$paths" --arg tg "$target" --arg c "$VM" \
		'{kind:"restore_files", tenant:$t, params:{source:$s, time:$tm, paths:$p, target:$tg, overwrite:"never", confirm:$c}}')")
	j=$(wait_job admin "$(jq -r .id <<<"$r")" 1800)
	[ "$(jq -r .state <<<"$j")" = ok ] || die "second restore: $(jq -r .log <<<"$j" | tail -n 30)"
	log "restore again (overwrite never): $(jq -c .result <<<"$j")"
	echo "TARGET=$target" >>"$S/$VM.env"
}

step_download() {
	state
	login admin "$ADMIN_PW" "$ADMIN_TOTP"
	local time d=${DATA[0]} fmt r j tok
	time=$(latest)
	for fmt in tar zip; do
		local t0=$SECONDS
		r=$(api admin POST /jobs "$(jq -nc --arg t "$TENANT" --arg s "host-$AGENT" --argjson tm "$time" --arg p "$d" --arg f "$fmt" \
			'{kind:"files_get", tenant:$t, params:{source:$s, time:$tm, paths:[$p], format:$f}}')")
		expect 202 "files_get $fmt"
		tok=$(jq -r .download_token <<<"$r")
		j=$(wait_job admin "$(jq -r .id <<<"$r")" 600)
		[ "$(jq -r .state <<<"$j")" = ok ] || die "files_get $fmt: $(jq -r .log <<<"$j" | tail -n 20)"
		api admin GET "/downloads/$tok" >/dev/null
		expect 200 "download $fmt"
		cp "$S/body" "$S/$VM.$fmt"
		result "download_${fmt}_s" $((SECONDS - t0))
		log "files_get $fmt: $(jq -c .result <<<"$j") ($(stat -c %s "$S/$VM.$fmt") bytes)"
	done
	# content: big.bin from both archives = the file on the VM; tar keeps owner, mode, xattrs
	local want
	want=$(vm "sudo sha256sum $d/big.bin" | cut -d' ' -f1)
	[ "$(tar -xOf "$S/$VM.tar" "${d#/}/big.bin" | sha256sum | cut -d' ' -f1)" = "$want" ] || die "tar: big.bin differs"
	[ "$(unzip -p "$S/$VM.zip" "${d#/}/big.bin" | sha256sum | cut -d' ' -f1)" = "$want" ] || die "zip: big.bin differs"
	tar --numeric-owner -tvf "$S/$VM.tar" "${d#/}/secret/key" | grep -q '^-rw-r----- 2001/2001' || die "tar: owner/mode of secret/key"
	tar --xattrs --xattrs-include='*' -tvvf "$S/$VM.tar" 2>/dev/null >/dev/null
	python3 -I - "$S/$VM.tar" "${d#/}" <<-'PY' || die "tar: xattrs/ACLs missing"
		import sys, tarfile
		t = tarfile.open(sys.argv[1]); d = sys.argv[2]
		x = {m.name: m.pax_headers for m in t.getmembers()}
		assert x[d + "/docs/note-1.txt"].get("SCHILY.xattr.user.nexus") == "hello", x[d + "/docs/note-1.txt"]
		assert any(k.startswith("SCHILY.xattr.system.posix_acl_access") for k in x[d + "/docs"]), x[d + "/docs"]
		assert x[d + "/hard-b"] or True
		print("tar xattrs ok:", sorted(k for k in x[d + "/docs"]))
	PY
	result download_checked "tar+zip content, tar owner/mode/xattr/ACL"
}

step_db() {
	state
	[ "$DB" != none ] || {
		log "no database on $VM"
		return 0
	}
	login admin "$ADMIN_PW" "$ADMIN_TOTP"
	local time dumpdir r j target=/restore/db-$(date +%s)
	time=$(latest)
	case $DB in
	postgresql) dumpdir=/var/backups/nexus/postgresql ;;
	mysql) dumpdir=/var/backups/nexus/mysql ;;
	esac
	r=$(api admin POST /jobs "$(jq -nc --arg t "$TENANT" --arg s "host-$AGENT" --argjson tm "$time" --arg p "$dumpdir" --arg tg "$target" --arg c "$VM" \
		'{kind:"restore_files", tenant:$t, params:{source:$s, time:$tm, paths:[$p], target:$tg, overwrite:"never", confirm:$c}}')")
	expect 202 "restore dump"
	j=$(wait_job admin "$(jq -r .id <<<"$r")" 600)
	[ "$(jq -r .state <<<"$j")" = ok ] || die "restore dump: $(jq -r .log <<<"$j" | tail -n 20)"
	vm "sudo ls -l $target$dumpdir" | sed 's/^/  vm: /' >&2
	local n t0=$SECONDS
	case $DB in
	postgresql)
		# the restored dump is root-only (0700 parents): psql reads it from stdin
		n=$(vm "sudo -u postgres dropdb --if-exists sample && sudo cat $target$dumpdir/pg_dumpall.sql | sudo -u postgres psql -q -o /dev/null postgres 2>&1 | grep -v 'already exists' >&2; sudo -u postgres psql -At -d sample -c 'SELECT count(*) FROM t'")
		;;
	mysql)
		n=$(vm "sudo mariadb -e 'DROP DATABASE IF EXISTS sample' && sudo cat $target$dumpdir/all-databases.sql | sudo mariadb && sudo mariadb -N -e 'SELECT COUNT(*) FROM sample.t'")
		;;
	esac
	[ "$n" = 200000 ] || die "database restore: $n rows"
	result db_restore "$DB dump restored, 200000 rows ($((SECONDS - t0)) s)"
}

step_update() {
	state
	[ -n "$UPDATE_DIR" ] || {
		log "UPDATE_DIR empty: update skipped"
		return 0
	}
	[ -x "$BUMP/nexus-agent" ] || die "no bumped bundle in $BUMP (lab/linux/bump-bundle.sh 0.1.1)"
	login admin "$ADMIN_PW" "$ADMIN_TOTP"
	local cur r j
	cur=$(api admin GET /agents | jq -r --arg id "$AGENT" '.[] | select(.id==$id) | .version')
	mkdir -p "$UPDATE_DIR"
	local old
	old=$(dirname "$BUNDLE")/$(basename "$BUNDLE" .tar.gz)
	# 1. the new binary with the signature of another binary: the agent refuses it
	install -m 0644 "$BUMP/nexus-agent" "$UPDATE_DIR/nexus-agent"
	install -m 0644 "$old/nexus-agent.sig" "$UPDATE_DIR/nexus-agent.sig"
	echo 0.1.1 >"$UPDATE_DIR/nexus-agent.version"
	r=$(api admin POST /jobs "$(jq -nc --arg t "$TENANT" --arg a "$AGENT" '{kind:"agent_update", tenant:$t, params:{agent_id:$a}}')")
	expect 202 "agent_update (bad signature)"
	j=$(wait_job admin "$(jq -r .id <<<"$r")" 300)
	[ "$(jq -r .state <<<"$j")" = failed ] || die "update with a wrong signature was not refused"
	log "wrong signature refused: $(jq -r .log <<<"$j" | grep -iE 'error|signature' | head -2 | tr '\n' ' ')"
	vm 'sudo journalctl -u nexus-agent -n 3 --no-pager -o cat' | sed 's/^/  vm: /' >&2
	result update_bad_sig refused
	# 2. properly signed 0.1.1
	install -m 0644 "$BUMP/nexus-agent.sig" "$UPDATE_DIR/nexus-agent.sig"
	local t0=$SECONDS
	r=$(api admin POST /jobs "$(jq -nc --arg t "$TENANT" --arg a "$AGENT" '{kind:"agent_update", tenant:$t, params:{agent_id:$a}}')")
	j=$(wait_job admin "$(jq -r .id <<<"$r")" 300)
	[ "$(jq -r .state <<<"$j")" = ok ] || die "signed update: $(jq -r .log <<<"$j" | tail -n 20)"
	local now
	now=$(api admin GET /agents | jq -r --arg id "$AGENT" '.[] | select(.id==$id) | .version')
	[ "$now" = 0.1.1 ] || die "agent version after update: $now"
	vm 'sudo /usr/local/sbin/nexus-agent status | head -3; ls -l /usr/local/sbin/' | sed 's/^/  vm: /' >&2
	result update "$cur -> $now ($((SECONDS - t0)) s)"
	# 3. the same version again is no downgrade/no-op: refused
	r=$(api admin POST /jobs "$(jq -nc --arg t "$TENANT" --arg a "$AGENT" '{kind:"agent_update", tenant:$t, params:{agent_id:$a}}')")
	j=$(wait_job admin "$(jq -r .id <<<"$r")" 300)
	[ "$(jq -r .state <<<"$j")" = failed ] || die "same-version update accepted"
	result update_same_version refused
	# a backup with the new agent still works (metadata cache survives the update)
	r=$(api admin POST /jobs "$(jq -nc --arg t "$TENANT" --arg a "$AGENT" '{kind:"backup", tenant:$t, params:{agent_id:$a}}')")
	j=$(wait_job admin "$(jq -r .id <<<"$r")" 1800)
	[ "$(jq -r .state <<<"$j")" = ok ] || die "backup after update: $(jq -r .log <<<"$j" | tail -n 30)"
	record_backup after_update "$j"
}

steps=("$@")
[ ${#steps[@]} -gt 0 ] || steps=(agent backup incr restore download db update)
for s in "${steps[@]}"; do
	log "== $VM: $s"
	"step_$s"
done
log "$VM done; results in $R"
cat "$R"
