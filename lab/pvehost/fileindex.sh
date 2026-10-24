#!/usr/bin/env bash
# File index of real guests (#71, plan.md Phase 39 L11) on the appliance VM through the tunnel of deploy.sh: agent
# test VMs (agent-vms.sh) backed up as Proxmox VE VMs in a group with index-files on; the file_index job after the
# backup reports the volumes it parsed (file system, entries, time) and the instant search must find a file every
# guest has (/etc/os-release) in that snapshot.
#
#   fileindex.sh [names]   default: alma-10 (XFS on LVM), leap-16 (btrfs), debian-13 (ext4); one after the other
#
# Each VM is reset to clean-os and started, then group "index-<name>" (PVE source $NODE, policy daily) is backed
# up; the VM is reset again (stopped) afterwards. Results: $OUT/<name>.json (the file_index result).
# env: as vmware-e2e.sh (LAB, PORT, PVE_HOST, SSH_KEY, NODE pve-test), OUT (~/nexus-lab/scratch/fileindex)
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
export LAB=${LAB:-$HOME/nexus-lab/pvehost}
export PORT=${PORT:-28444}
PVE_HOST=${PVE_HOST:-10.2.34.200}
SSH_KEY=${SSH_KEY:-$HOME/nexus-lab/pve-lab-key}
NODE=${NODE:-pve-test}
OUT=${OUT:-$HOME/nexus-lab/scratch/fileindex}
ROOT=$LAB/appliance/root
S=$ROOT/run/api
mkdir -p "$S" "$OUT"
# shellcheck disable=SC1091
. "$ROOT/secrets.env"
# shellcheck source=lab/e2e/api-lib.sh
. "$repo/lab/e2e/api-lib.sh"
pve() { ssh -n -i "$SSH_KEY" -o BatchMode=yes "root@$PVE_HOST" "$@"; }
login admin "$ADMIN_PW" "$ADMIN_TOTP"

run_vm() { # run_vm name
	local name=$1 id g src pol j time idx t0 hits
	id=$("$here/agent-vms.sh" list | awk -v n="$name" '$2 == n {print $1}')
	[ -n "$id" ] || die "no agent VM $name"
	log "== $name (VM $id)"
	"$here/agent-vms.sh" reset "$name" </dev/null
	pve "qm start $id"
	sleep 60 # boot: a crash-consistent snapshot of a booting guest is fine, a settled one is closer to real use
	g=$(api admin GET /groups | jq -r --arg n "index-$name" '.[] | select(.name == $n) | .id')
	if [ -z "$g" ]; then
		src=$(api admin GET /sources | jq -r --arg n "$NODE" '.[] | select(.name == $n) | .id')
		pol=$(api admin GET /policies | jq -r '.[] | select(.name == "daily") | .id')
		g=$(api admin POST /groups "$(jq -nc --argjson s "$src" --argjson p "$pol" --arg n "index-$name" --argjson v "$id" \
			'{tenant:"lab", source_id:$s, policy_id:$p, name:$n, guests:[$v]}')" | jq -r .id)
		expect 201 "group index-$name"
	fi
	api admin PUT "/groups/$g/index-files" '{"enabled":true}' >/dev/null
	expect 200 "index-files on"
	j=$(api admin POST /jobs "$(jq -nc --argjson g "$g" '{kind:"backup", tenant:"lab", params:{group_id:$g}}')")
	expect 202 "backup"
	j=$(wait_job admin "$(jq -r .id <<<"$j")" 3600)
	[ "$(jq -r .state <<<"$j")" = ok ] || die "$name backup: $(jq -r '.log // ""' <<<"$j" | tail -n 10)"
	time=$(jq -r '.log // ""' <<<"$j" | sed -n "s|^committed vm-$id/\([0-9]*\).*|\1|p" | tail -1)
	log "$name: backup vm-$id/$time ($(jq -r '.finished - .started' <<<"$j") s)"
	idx=
	for _ in $(seq 60); do
		idx=$(api admin GET '/jobs?limit=30' | jq -r --arg s "vm-$id" --argjson t "$time" \
			'[.[] | select(.kind == "file_index" and .params.source == $s and .params.time == $t)][0].id // empty')
		[ -n "$idx" ] && break
		sleep 5
	done
	[ -n "$idx" ] || die "$name: no file_index job after the backup"
	t0=$SECONDS
	j=$(wait_job admin "$idx" 3600)
	[ "$(jq -r .state <<<"$j")" = ok ] || die "$name file_index: $(jq -r '.log // ""' <<<"$j" | tail -n 15)"
	jq '.result' <<<"$j" >"$OUT/$name.json"
	log "$name: file_index $(jq -c '{entries, complete, elapsed_ms, micro_vm, volumes: [.volumes[]? | {fs: (.fs // .kind // .type), entries, browse}]}' "$OUT/$name.json" | cut -c1-400) (waited $((SECONDS - t0)) s)"
	hits=0
	for _ in $(seq 24); do
		hits=$(api admin GET "/files/search?tenant=lab&q=os-release&source=vm-$id" | jq '[.hits[]? | select(.path | endswith("/etc/os-release"))] | length')
		[ "$hits" -gt 0 ] && break
		sleep 5
	done
	[ "$hits" -gt 0 ] || die "$name: /etc/os-release not found by the instant search"
	log "$name: instant search finds /etc/os-release"
	"$here/agent-vms.sh" reset "$name" </dev/null
}

for n in ${@:-alma-10 leap-16 debian-13}; do
	run_vm "$n"
done
