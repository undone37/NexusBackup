#!/usr/bin/env bash
# SQL Server plugin end to end (#41) on the appliance VM of the PVE lab (deploy.sh tunnel: APP_LAB ~/nexus-lab/pvehost,
# APP_PORT 28444), against either lab: ON=win (lab/windows/mssql.sh, VM 268, SQL Server 2022 on Windows Server 2022)
# or ON=docker (lab/pvehost/mssql-docker.sh, VM 269, the SQL Server 2022 image in Docker on Debian 13). The plugin
# `mssql` must be installed (PLUGIN=mssql lab/appliance/plugins.sh install).
#
#   mssql-e2e.sh source    tenant mssql, plugin source for $ON, group with labdb, validate, guests
#   mssql-e2e.sh backup    one policy backup of the group
#   mssql-e2e.sh logruns   log schedule `every 5m`, waits for $N (2) log runs, removes the schedule
#   mssql-e2e.sh mark      remember now and the rows of labdb.dbo.ticks up to it ($LAB/marks)
#   mssql-e2e.sh pitr      a backup (so a snapshot reaches the mark), then a point-in-time restore of the newest
#                          snapshot to the last mark into labdb_pitr; the rows up
#                          to the mark compared, none after it; labdb_pitr dropped
#   mssql-e2e.sh verify    restore test (verify) of the newest snapshot with an SQL check
#   mssql-e2e.sh foreign   a log backup outside the plugin (to the instance's default backup folder), then a log run:
#                          must be a full with chain_break (log_chain alert)
#
# env: ON (docker | win), N
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
ON=${ON:-docker}
case $ON in
docker) LAB=${LAB:-$HOME/nexus-lab/mssql-docker} ;;
win) LAB=${LAB:-$HOME/nexus-lab/mssql-win} ;;
*) echo "ON must be docker or win" >&2 && exit 1 ;;
esac
export PORT=${APP_PORT:-28444}
APP_LAB=${APP_LAB:-$HOME/nexus-lab/pvehost}
ROOT=$APP_LAB/appliance/root S=$APP_LAB/appliance/root/run/api
mkdir -p "$S"
T0=$(date +%s)
log() { printf '[%4ss] %s\n' $(($(date +%s) - T0)) "$*" >&2; }
die() {
	log "FAIL: $*"
	exit 1
}
# shellcheck disable=SC1091
. "$ROOT/secrets.env"
# shellcheck source=lab/e2e/api-lib.sh
. "$repo/lab/e2e/api-lib.sh"
login admin "$ADMIN_PW" "$ADMIN_TOTP" >/dev/null
# SQL on the lab instance (first column of every row)
q() {
	case $ON in
	docker) "$here/mssql-docker.sh" sql "SET NOCOUNT ON; $1" | sed 's/[[:space:]]*$//' ;;
	win) "$repo/lab/windows/mssql.sh" sql "$1" | tr -d '\r' ;;
	esac
}
job() { # KIND PARAMS [timeout] -> final job JSON (dies unless ok)
	local r j
	r=$(api admin POST /jobs "$(jq -nc --arg k "$1" --argjson p "$2" '{kind:$k, tenant:"mssql", params:$p}')")
	expect 202 "$1 job"
	j=$(wait_job admin "$(jq -r .id <<<"$r")" "${3:-3600}")
	[ "$(jq -r .state <<<"$j")" = ok ] || die "$1: $(jq -r .log <<<"$j" | tail -n 30)"
	echo "$j"
}
snap() { # newest snapshot of labdb
	api admin GET '/snapshots?tenant=mssql' | jq -c --arg p "plugin-mssql-$(jq -r .source "$LAB/e2e.json")-labdb" '[.[] | select(.source == $p)] | sort_by(.time) | .[-1]'
}

step_source() {
	local cfg src pol g
	api admin POST /tenants '{"name":"mssql"}' >/dev/null
	case $ON in
	docker)
		# shellcheck disable=SC1091
		. "$LAB/secrets.env"
		cfg=$(jq -nc --arg h "$(cat "$LAB/host")" --arg key "$(cat "$LAB/nexus_ed25519")" --arg hk "$(cut -d' ' -f1-2 "$LAB/host_key")" --arg pw "$SA_PASSWORD" \
			'{platform:"linux", host:$h, port:22, user:"nexus", ssh_key:$key, ssh_host_key:$hk, container:"mssql1", container_cli:"docker", sql_user:"sa", sql_password:$pw}')
		;;
	win)
		cfg=$(jq -nc --arg h "$(cat "$LAB/host")" --arg key "$(cat "$LAB/nexus_ed25519")" --arg hk "$(cut -d' ' -f1-2 "$LAB/host_key")" \
			'{platform:"windows", host:$h, port:22, user:"nexus", ssh_key:$key, ssh_host_key:$hk}')
		;;
	esac
	src=$(api admin POST /sources "$(jq -nc --argjson c "$cfg" --arg n "mssql-$ON-$(date +%s)" '{tenant:"mssql", kind:"plugin:mssql", name:$n, config:$c}')" | jq -r .id)
	expect 201 "create source"
	log "validate: $(job plugin_validate "$(jq -nc --argjson s "$src" '{source_id:$s}')" 300 | jq -c .result)"
	log "guests: $(job plugin_guests "$(jq -nc --argjson s "$src" '{source_id:$s}')" 300 | jq -c '.result.guests // .result' | head -c 300)"
	pol=$(api admin GET /policies | jq -r '.[] | select(.name == "mssql") | .id' | head -1)
	if [ -z "$pol" ]; then
		pol=$(api admin POST /policies '{"name":"mssql","schedule":"daily 03:51","gfs":{"daily":14,"weekly":0,"monthly":0,"yearly":0},"offsite":false}' | jq -r .id)
		expect 201 "create policy"
	fi
	g=$(api admin POST /groups "$(jq -nc --argjson s "$src" --argjson p "$pol" '{tenant:"mssql", source_id:$s, policy_id:$p, name:("labdb-" + ($s|tostring)), guests:["labdb"]}')" | jq -r .id)
	expect 201 "group"
	jq -n --argjson s "$src" --argjson g "$g" '{source:$s, group:$g}' >"$LAB/e2e.json"
	log "source $src, group $g"
}

step_backup() {
	local j
	j=$(job backup "$(jq -c '{group_id: .group}' "$LAB/e2e.json")")
	log "backup: job $(jq -r .id <<<"$j") in $(jq '.finished - .started' <<<"$j") s"
	jq -r .log <<<"$j" | grep -E 'plugin\[|summary' | head -6 | cut -c1-300 | sed 's/^/    /' >&2
}

step_logruns() {
	local g n0 n end
	g=$(jq -r .group "$LAB/e2e.json")
	cnt() { api admin GET "/jobs?kind=backup&limit=200" | jq --argjson g "$g" '[.[] | select(.params.group_id == $g and .params.mode == "log" and (.state == "ok" or .state == "failed"))] | length'; }
	n0=$(cnt)
	api admin PUT "/groups/$g/log-schedule" '{"schedule":"every 5m"}' >/dev/null
	expect 200 "log schedule"
	log "log schedule every 5m on group $g; waiting for ${N:-2} log runs"
	end=$(($(date +%s) + 1800))
	while n=$(cnt) && [ $((n - n0)) -lt "${N:-2}" ] && [ "$(date +%s)" -lt "$end" ]; do sleep 30; done
	api admin PUT "/groups/$g/log-schedule" '{"schedule":null}' >/dev/null
	api admin GET "/jobs?kind=backup&limit=200" | jq -r --argjson g "$g" --argjson n "${N:-2}" '[.[] | select(.params.group_id == $g and .params.mode == "log")] | sort_by(.id) | .[-$n:][] |
		"    job \(.id) \(.state) \(.finished - .started) s: \(.result.snapshots[0].meta // .result.failed)"' >&2
	[ $((n - n0)) -ge "${N:-2}" ] || die "only $((n - n0)) log runs in 30 minutes"
}

step_mark() {
	local at n
	at=$(date -u '+%Y-%m-%d %H:%M:%S')
	sleep 1
	n=$(q "SELECT COUNT(*) FROM labdb.dbo.ticks WHERE t <= '$at'" | head -1)
	echo "$at+00|$n" >>"$LAB/marks"
	log "mark $at UTC: $n ticks"
}

step_pitr() {
	local m at n s j have after
	m=$(tail -1 "$LAB/marks")
	at=${m%|*} n=${m#*|}
	step_backup
	s=$(snap)
	q "IF DB_ID('labdb_pitr') IS NOT NULL BEGIN ALTER DATABASE labdb_pitr SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE labdb_pitr END" >/dev/null || true
	j=$(job plugin_restore "$(jq -nc --argjson s "$s" --arg t "$at" '{source:$s.source, time:$s.time, restore:"pitr", params:{database:"labdb_pitr", target_time:$t}}')")
	log "pitr to $at from snapshot $(jq -r .time <<<"$s") in $(jq '.finished - .started' <<<"$j") s: $(jq -r .result.summary <<<"$j" | head -c 200)"
	have=$(q "SELECT COUNT(*) FROM labdb_pitr.dbo.ticks WHERE t <= '${at%+00}'" | head -1)
	after=$(q "SELECT COUNT(*) FROM labdb_pitr.dbo.ticks WHERE t > '${at%+00}'" | head -1)
	log "labdb_pitr: $have rows up to the mark (wanted $n), $after after it"
	q "ALTER DATABASE labdb_pitr SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE labdb_pitr" >/dev/null || true
	[ "$have" = "$n" ] && [ "$after" -le 1 ] || die "the restored database does not end at the mark"
}

step_verify() {
	local s j
	s=$(snap)
	j=$(job plugin_restore "$(jq -nc --argjson s "$s" '{source:$s.source, time:$s.time, restore:"verify", params:{sql:"SELECT COUNT(*) FROM dbo.ticks"}}')")
	log "restore test in $(jq '.finished - .started' <<<"$j") s: $(jq -r .result.summary <<<"$j" | head -c 300)"
}

step_foreign() {
	q "BACKUP LOG labdb TO DISK = N'nexus-foreign-test.trn' WITH INIT" >/dev/null
	log "log backup outside the plugin taken"
	N=1 step_logruns
	local s
	s=$(snap)
	jq -e '.meta.chain_break' <<<"$s" >/dev/null || die "no chain_break in the newest snapshot: $(jq -c .meta <<<"$s")"
	log "chain_break: $(jq -r .meta.chain_break <<<"$s")"
	log "alert: $(api admin GET /alerts | jq -c '[.[] | select(.kind == "log_chain")][0] | {severity, message: (.message[0:200])}')"
}

for s in "$@"; do
	"step_$s"
done
