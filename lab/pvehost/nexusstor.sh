#!/usr/bin/env bash
# NexusStor integration lab (#137, docs/nexusstor-design.md): VM 201 backs up a vStor of a paired NexusStor
# (lab VM 292, installed from NexusStor's lab/build-iso.sh with a VM kickstart; pool tank, vStor acme with
# test data and the pairing `nexusbackup-lab` made on its side). The plugin `nexusstor` must be installed on
# VM 201 (LAB=~/nexus-lab/pvehost PORT=28444 PLUGIN=nexusstor lab/appliance/plugins.sh install).
# Through the tunnel of lab/pvehost/deploy.sh.
#
#   nexusstor.sh source    tenant `nexusstor`, a plugin:nexusstor source from the pairing token in $TOKEN_FILE
#                          (single use, 15 minutes); plugin_validate (pairs on first contact), plugin_guests
#   nexusstor.sh backup    policy + group (guest $VSTOR), full backup; then a change on NexusStor (a file
#                          added, one changed, one removed) and an incremental backup
#   nexusstor.sh verify    files of the latest snapshot downloaded (tar) and compared by SHA-256 with the
#                          vStor's data root on NexusStor; NexusStor's held snapshots and the pairing's
#                          last contact
#   nexusstor.sh all       source backup verify
#
# env: LAB (~/nexus-lab/pvehost), PORT (28444), NST (10.2.34.221: NexusStor's management address, root by
#      NST_KEY), NST_KEY (~/nexus-lab/nexusstor/root_ed25519), TOKEN_FILE (~/nexus-lab/scratch/nst-api/token),
#      VSTOR (acme)
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
LAB=${LAB:-$HOME/nexus-lab/pvehost}
ROOT=${ROOT:-$LAB/appliance/root}
PORT=${PORT:-28444}
NST=${NST:-10.2.34.221}
NST_KEY=${NST_KEY:-$HOME/nexus-lab/nexusstor/root_ed25519}
TOKEN_FILE=${TOKEN_FILE:-$HOME/nexus-lab/scratch/nst-api/token}
VSTOR=${VSTOR:-acme}
export TENANT=nexusstor
S=$LAB/scratch/nexusstor
mkdir -p "$S"
export T0
T0=$(date +%s)
eval "$(ROOT=$ROOT PORT=$PORT "$repo/lab/e2e/m5.sh" env)"
# shellcheck source=lab/e2e/api-lib.sh
# shellcheck disable=SC1090
. "$repo/lab/e2e/api-lib.sh"
nst() { ssh -n -i "$NST_KEY" -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
	-o LogLevel=ERROR "root@$NST" "$@"; }
job() {
	local r j
	r=$(api admin POST /jobs "$(jq -nc --arg k "$1" --arg t "$TENANT" --argjson p "$2" '{kind:$k, tenant:$t, params:$p}')")
	expect 202 "$1 job"
	j=$(wait_job admin "$(jq -r .id <<<"$r")" "${3:-900}")
	[ "$(jq -r .state <<<"$j")" = ok ] || die "$1: $(jq -r .log <<<"$j" | tail -n 30)"
	echo "$j"
}
backup() {
	local j
	j=$(job backup "$(jq -nc --argjson g "$1" '{group_id:$g}')" 1800)
	log "backup job $(jq -r .id <<<"$j") ok in $(jq '.finished - .started' <<<"$j") s: $(jq -c .result <<<"$j")"
	jq -r .log <<<"$j" | grep -E 'plugin\[|nexusstor' | tail -n 6 | while read -r l; do log "  $l"; done
}
src_id() { api admin GET "/sources?tenant=$TENANT" | jq -r '[.[] | select(.name == "nexusstor-lab")][0].id // empty'; }

step_source() {
	login admin "$ADMIN_PW" "$ADMIN_TOTP"
	api admin POST /tenants "{\"name\":\"$TENANT\"}" >/dev/null
	case $(status) in 201 | 409) ;; *) die "tenant: HTTP $(status) $(cat "$S/body")" ;; esac
	local src j
	src=$(src_id)
	if [ -z "$src" ]; then
		src=$(api admin POST /sources "$(jq -nc --arg t "$TENANT" --rawfile tok "$TOKEN_FILE" \
			'{tenant:$t, kind:"plugin:nexusstor", name:"nexusstor-lab", config:{token:($tok | rtrimstr("\n"))}}')" | jq -r .id)
		expect 201 "create source"
	fi
	log "source $src: $(api admin GET "/sources?tenant=$TENANT" | jq -c --argjson s "$src" '.[] | select(.id == $s) | {kind, host: .config.host, port: .config.port, fingerprint: (.config.fingerprint // "" | .[0:16])}')"
	j=$(job plugin_validate "$(jq -nc --argjson s "$src" '{source_id:$s}')" 300)
	jq -e '.result.valid == true' <<<"$j" >/dev/null || die "plugin_validate: $(jq -c .result <<<"$j")"
	log "plugin_validate: $(jq -c .result <<<"$j"); $(jq -r .log <<<"$j" | grep -o 'paired[^"]*' | head -1)"
	j=$(job plugin_guests "$(jq -nc --argjson s "$src" '{source_id:$s}')" 300)
	log "plugin_guests: $(jq -c '[.result.guests[] | {id, title, size}]' <<<"$j")"
}

step_backup() {
	login admin "$ADMIN_PW" "$ADMIN_TOTP"
	local src pol grp
	src=$(src_id)
	[ -n "$src" ] || die "no source: run the source step first"
	pol=$(api admin GET /policies | jq -r '[.[] | select(.name == "nexusstor-lab")][0].id // empty')
	if [ -z "$pol" ]; then
		pol=$(api admin POST /policies '{"name":"nexusstor-lab","schedule":"daily 04:47","gfs":{"daily":14,"weekly":4,"monthly":6,"yearly":2},"offsite":false}' | jq -r .id)
		expect 201 "create policy"
	fi
	grp=$(api admin GET "/groups?tenant=$TENANT" | jq -r '[.[] | select(.name == "vstors")][0].id // empty')
	if [ -z "$grp" ]; then
		grp=$(api admin POST /groups "$(jq -nc --arg t "$TENANT" --argjson s "$src" --argjson p "$pol" --arg v "$VSTOR" \
			'{tenant:$t, source_id:$s, policy_id:$p, name:"vstors", guests:[$v]}')" | jq -r .id)
		expect 201 "create group"
	fi
	backup "$grp"
	nst "set -e; d=/var/tank/vstors/$VSTOR/data; u=\$(stat -c %u \$d/README.txt)
		printf 'added after the first backup\n' > \$d/docs/2026/report-4.txt
		printf 'plan v2\n' > \$d/projects/plan.txt
		rm -f \$d/docs/2026/report-2.txt
		chown \$u:\$u \$d/docs/2026/report-4.txt \$d/projects/plan.txt"
	log "NexusStor: report-4 added, plan.txt changed, report-2 removed"
	sleep 2 # the second snapshot needs a later time stamp
	backup "$grp"
}

step_verify() {
	login admin "$ADMIN_PW" "$ADMIN_TOTP"
	local snaps snap time j ents paths r
	snaps=$(api admin GET "/snapshots?tenant=$TENANT" | jq -c '[.[] | select(.source | startswith("plugin-nexusstor-"))] | sort_by(.time)')
	log "snapshots: $(jq -c '[.[] | {source, time, size}]' <<<"$snaps")"
	[ "$(jq length <<<"$snaps")" -ge 2 ] || die "want two snapshots"
	snap=$(jq -r '.[-1].source' <<<"$snaps")
	time=$(jq -r '.[-1].time' <<<"$snaps")
	j=$(job files_list "$(jq -nc --arg s "$snap" --argjson t "$time" '{source:$s, time:$t, path:"/"}')")
	ents=$(jq -c '[.result.entries[].name | select(. != ".nexus-streams")]' <<<"$j")
	log "$snap@$time / = $ents"
	paths=$(jq -c '[.[] | "/" + .]' <<<"$ents")
	r=$(api admin POST /jobs "$(jq -nc --arg t "$TENANT" --arg s "$snap" --argjson ti "$time" --argjson p "$paths" \
		'{kind:"files_get", tenant:$t, params:{source:$s, time:$ti, paths:$p, format:"tar"}}')")
	expect 202 "files_get"
	j=$(wait_job admin "$(jq -r .id <<<"$r")" 900)
	[ "$(jq -r .state <<<"$j")" = ok ] || die "files_get: $(jq -r .log <<<"$j" | tail -n 20)"
	api admin GET "/downloads/$(jq -r .download_token <<<"$r")" >/dev/null
	expect 200 "download"
	rm -rf "$S/restored" && mkdir -p "$S/restored"
	tar --xattrs --xattrs-include='user.*' -xf "$S/body" -C "$S/restored"
	# the tree has one folder per dataset dir of the inventory; the data root's files are under one of them
	local root
	root=$(cd "$S/restored" && dirname "$(find . -name README.txt | head -1)")
	[ -n "$root" ] && [ "$root" != . ] || root=.
	(cd "$S/restored/$root" && find . -type f -exec sha256sum {} + | LC_ALL=C sort -k2) >"$S/restored.sha256"
	nst "cd /var/tank/vstors/$VSTOR/data && find . -type f ! -path './.zfs/*' -exec sha256sum {} + | LC_ALL=C sort -k2" >"$S/source.sha256"
	if diff -u "$S/source.sha256" "$S/restored.sha256" >"$S/diff.txt"; then
		log "restored files = vStor data: $(wc -l <"$S/source.sha256") files, SHA-256 equal (folder $root of the tree)"
	else
		die "restored files differ: $(head -20 "$S/diff.txt")"
	fi
	# the user xattr the test data put on README.txt (NFSv4 ACLs travel as system.nfs4_acl the same way)
	log "README.txt xattr user.nexus.label: $(python3 -c 'import os, sys; print(os.getxattr(sys.argv[1], "user.nexus.label").decode())' \
		"$(find "$S/restored" -name README.txt | head -1)" 2>&1 | tail -1)"
	log "NexusStor: $(nst "s=\$(zfs list -H -t snapshot -o name -r tank/vstors/$VSTOR | grep @nexusbackup-); echo \$(echo \"\$s\" | wc -l) snapshots, \$(zfs holds -H \$s | grep -c nexusbackup) held")"
}

case ${1:-} in
source | backup | verify) "step_$1" ;;
all) step_source && step_backup && step_verify ;;
*) sed -n '2,19p' "$0" >&2 && exit 2 ;;
esac
