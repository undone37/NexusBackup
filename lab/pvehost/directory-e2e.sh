#!/usr/bin/env bash
# Tenant directory end to end on the appliance VM of the PVE lab (#52): the lab tenant's directory set to the Samba
# AD DC (lab/pvehost/samba-ad.sh), synced; VM $VMID (an NTFS disk whose file Finance/budget-2027.xlsx belongs to
# the domain user jdoe, made with ntfs-3g's user mapping, state.md) backed up and indexed; file search names the
# owner jdoe and finds the file by that name. Through the tunnel of deploy.sh.
#
#   directory-e2e.sh directory  PUT /tenants/lab/directory, the sync job's result
#   directory-e2e.sh group      group "ntfs-owner" with VM $VMID on the PVE source $NODE
#   directory-e2e.sh backup     backup of the group, then its file_index job
#   directory-e2e.sh search     the file by name: owner SID and name; and by owner=jdoe
#   directory-e2e.sh remove     the directory removed again, synced (the names leave the index)
#
# env: as deploy.sh (LAB ~/nexus-lab/pvehost, PORT 28444, NODE pve-test); LAB_S (~/nexus-lab/samba), DC
#      (10.2.34.219), VMID (291)
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
export LAB=${LAB:-$HOME/nexus-lab/pvehost}
export PORT=${PORT:-28444}
NODE=${NODE:-pve-test}
LAB_S=${LAB_S:-$HOME/nexus-lab/samba}
DC=${DC:-10.2.34.219}
VMID=${VMID:-291}
GROUP=ntfs-owner
ROOT=$LAB/appliance/root
S=$ROOT/run/api
mkdir -p "$S"
# shellcheck disable=SC1091
. "$ROOT/secrets.env"
# shellcheck source=lab/e2e/api-lib.sh
. "$repo/lab/e2e/api-lib.sh"
login admin "$ADMIN_PW" "$ADMIN_TOTP"

wait_ok() {
	local j
	j=$(wait_job admin "$1" "${2:-1800}")
	[ "$(jq -r .state <<<"$j")" = ok ] || die "job $1: $(jq -c '{kind, state, error, log}' <<<"$j" | cut -c1-800)"
	printf '%s' "$j"
}

step_directory() {
	local r
	r=$(api admin PUT /tenants/lab/directory "$(jq -nc --arg h "$DC" --rawfile ca "$LAB_S/ldaps.pem" \
		--rawfile pw "$LAB_S/bind.pw" '{directory: {host: $h, ca_pem: $ca, bind_dn: "nexus-ldap@nxlab.test",
		password: ($pw | rtrimstr("\n")), base_dn: "DC=nxlab,DC=test"}}')")
	expect 200 "directory"
	log "directory_sync: $(wait_ok "$(jq -r .job <<<"$r")" 600 | jq -c .result)"
}

step_group() {
	local sid pol
	api admin GET /groups | jq -e --arg g "$GROUP" '.[] | select(.name == $g)' >/dev/null && {
		log "group $GROUP exists"
		return
	}
	sid=$(api admin GET /sources | jq -r --arg n "$NODE" '.[] | select(.name == $n) | .id')
	pol=$(api admin GET /policies | jq -r '.[] | select(.name == "daily") | .id')
	api admin POST /groups "$(jq -nc --argjson s "$sid" --argjson p "$pol" --argjson v "$VMID" --arg g "$GROUP" \
		'{tenant:"lab", source_id:$s, policy_id:$p, name:$g, guests:[$v]}')" >/dev/null
	expect 201 "group $GROUP"
	log "group $GROUP: VM $VMID"
}

step_backup() {
	local g j id
	g=$(api admin GET /groups | jq -r --arg g "$GROUP" '.[] | select(.name == $g) | .id')
	j=$(api admin POST /jobs "$(jq -nc --argjson g "$g" '{kind:"backup", tenant:"lab", params:{group_id:$g}}')")
	expect 202 "backup"
	wait_ok "$(jq -r .id <<<"$j")" 1800 >/dev/null
	log "backup ok"
	for _ in $(seq 1 60); do
		id=$(api admin GET '/jobs?limit=20' | jq -r --arg s "vm-$VMID" \
			'[.[] | select(.kind == "file_index" and .params.source == $s)][0].id // empty')
		[ -n "$id" ] && break
		sleep 5
	done
	[ -n "$id" ] || die "no file_index job for vm-$VMID"
	log "file_index: $(wait_ok "$id" 1800 | jq -c '.result // {}' | cut -c1-200)"
}

step_search() {
	local r
	for _ in $(seq 1 30); do
		r=$(api admin GET "/files/search?tenant=lab&q=budget-2027")
		[ "$(jq '.hits | length' <<<"$r")" -gt 0 ] && break
		sleep 5
	done
	jq -c '.hits[0] | {path, owner: .versions[0].owner, owner_name: .versions[0].owner_name}' <<<"$r" >&2
	[ "$(jq -r '.hits[0].versions[0].owner_name' <<<"$r")" = jdoe ] || die "owner not named jdoe"
	r=$(api admin GET "/files/search?tenant=lab&q=budget&owner=jdoe")
	[ "$(jq '.hits | length' <<<"$r")" -gt 0 ] || die "nothing found by owner=jdoe"
	log "found by owner=jdoe: $(jq -r '[.hits[].path] | join(" ")' <<<"$r")"
}

step_remove() {
	local r
	r=$(api admin PUT /tenants/lab/directory '{"directory": null}')
	expect 200 "remove directory"
	log "directory_sync after removal: $(wait_ok "$(jq -r .job <<<"$r")" 600 | jq -c .result)"
}

for s in "${@:-directory group backup search}"; do
	for x in $s; do
		log "== $x"
		"step_$x"
	done
done
