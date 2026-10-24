#!/usr/bin/env bash
# Scheduled malware scan and IOC hash hunt with a real Linux agent (#69, plan.md Phase 39 L9) on the appliance VM
# through the tunnel of deploy.sh: the enrolled agent "clean-$VM" (clean-restore.sh vm enrol, or agent-release.sh)
# backs up $DATA in group "threat-$VM" with file hashes on; the tree holds a file with the YARA marker of the rule
# "lab-marker" and a file whose SHA-256 is on the uploaded IOC list "lab-ioc".
#
#   threat.sh setup    test tree on the VM, group (file hashes on, scheduled scan $SCAN_AT UTC daily), YARA rule
#
# Windows (WINDOWS=VMID): the agent of lab/windows/e2e.sh on that VM (AGENT_NAME = its host name, the files in
# C:\nexus-lab\data, written through the guest agent).
#   threat.sh backup   backup of the group (the file index records the SHA-256 of every file)
#   threat.sh scan     waits for the scheduled scan of the new snapshot: matches, alert scan_hit
#   threat.sh hunt     IOC list with the file's SHA-256, hunt: the file found, alert hash_hunt_hit
#
# env: as vmware-e2e.sh (LAB, PORT, PVE_HOST, SSH_KEY); VM (debian-13), VM_IP (from clean-restore.sh), VM_KEY,
#      TENANT (lab; windows for the agent of lab/windows/e2e.sh), DATA (/srv/clean: the source's path), SCAN_AT (now + 4 minutes, HH:MM UTC)
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
export LAB=${LAB:-$HOME/nexus-lab/pvehost}
export PORT=${PORT:-28444}
PVE_HOST=${PVE_HOST:-10.2.34.200}
SSH_KEY=${SSH_KEY:-$HOME/nexus-lab/pve-lab-key}
VM_KEY=${VM_KEY:-$HOME/nexus-lab/lab_ed25519}
VM=${VM:-debian-13}
VM_IP=${VM_IP:-$(cat "$HOME/nexus-lab/scratch/clean-restore/ip" 2>/dev/null || true)}
DATA=${DATA:-/srv/clean} # the path of source clean-$VM (clean-restore.sh)
SCAN_AT=${SCAN_AT:-$(date -u -d '+4 min' +%H:%M)}
OUT=$HOME/nexus-lab/scratch/threat
ROOT=$LAB/appliance/root
S=$ROOT/run/api
mkdir -p "$S" "$OUT"
# shellcheck disable=SC1091
. "$ROOT/secrets.env"
# shellcheck source=lab/e2e/api-lib.sh
. "$repo/lab/e2e/api-lib.sh"
SSHO=(-i "$VM_KEY" -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR
	-o ProxyCommand="ssh -i $SSH_KEY -o BatchMode=yes -W %h:%p root@$PVE_HOST" -o ConnectTimeout=15)
vm() { ssh "${SSHO[@]}" "root@$VM_IP" "$@"; }
login admin "$ADMIN_PW" "$ADMIN_TOTP"
WINDOWS=${WINDOWS:-}
TENANT=${TENANT:-lab}
NAME=${AGENT_NAME:-clean-$VM}
[ -z "$WINDOWS" ] || DATA=${WIN_DATA:-C:\\nexus-lab\\data}
GROUP=threat-${WINDOWS:+win-}$VM
gid() { api admin GET /groups | jq -r --arg n "$GROUP" '.[] | select(.name == $n) | .id'; }
agent() { api admin GET /agents | jq -r --arg n "$NAME" '.[] | select(.name == $n) | .id'; }

step_setup() {
	local a src pol g
	a=$(agent)
	[ -n "$a" ] || die "no agent $NAME (clean-restore.sh vm enrol)"
	if [ -n "$WINDOWS" ]; then
		"$repo/lab/windows/gexec.py" "$WINDOWS" "New-Item -ItemType Directory -Force '$DATA\\docs' | Out-Null
			Set-Content -NoNewline -Path '$DATA\\docs\\invoice.pdf.exe' -Value 'lab ioc file, not malware (windows)'
			Set-Content -Path '$DATA\\docs\\dropper.txt' -Value 'NEXUS-LAB-MARKER-7f3a'
			(Get-FileHash -Algorithm SHA256 '$DATA\\docs\\invoice.pdf.exe').Hash.ToLower()" | tr -d '\r' | tail -1 >"$OUT/ioc.sha256"
	else
	vm "rm -rf $DATA && mkdir -p $DATA/docs && for i in \$(seq 1 20); do echo \"report \$i\" > $DATA/docs/report-\$i.txt; done
		printf 'lab ioc file, not malware\\n' > $DATA/docs/invoice.pdf.exe
		echo 'NEXUS-LAB-MARKER-7f3a' > $DATA/docs/dropper.txt; sync; sha256sum $DATA/docs/invoice.pdf.exe" |
		awk '{print $1}' >"$OUT/ioc.sha256"
	fi
	log "test tree $DATA: IOC file SHA-256 $(cat "$OUT/ioc.sha256"), marker file dropper.txt"
	src=$(api admin GET /sources | jq -r --arg n "$NAME" '.[] | select(.name == $n) | .id')
	[ -n "$src" ] || die "no source $NAME"
	g=$(gid)
	if [ -z "$g" ]; then
		pol=$(api admin GET /policies | jq -r '.[] | select(.name == "daily") | .id')
		g=$(api admin POST /groups "$(jq -nc --argjson s "$src" --argjson p "$pol" --arg n "$GROUP" --arg a "$a" \
			--arg tn "$TENANT" '{tenant:$tn, source_id:$s, policy_id:$p, name:$n, guests:[$a], timezone:"UTC"}')" | jq -r .id)
		expect 201 "group $GROUP"
	fi
	api admin PUT "/groups/$g/file-hashes" '{"enabled":true}' >/dev/null
	expect 200 "file hashes on"
	api admin PUT "/groups/$g/threat-scan" "$(jq -nc --arg s "daily $SCAN_AT" '{schedule:$s, budget_min:30}')" >/dev/null
	expect 200 "scheduled scan"
	api admin PUT /scan/rules/lab-marker "$(jq -nc --arg t 'rule lab_marker { strings: $m = "NEXUS-LAB-MARKER-7f3a" condition: $m }' '{text:$t}')" >/dev/null
	expect 200 "YARA rule"
	log "group $GROUP ($g): file hashes on, scheduled scan daily $SCAN_AT UTC"
}

step_backup() {
	local j
	j=$(api admin POST /jobs "$(jq -nc --argjson g "$(gid)" --arg tn "$TENANT" '{kind:"backup", tenant:$tn, params:{group_id:$g}}')")
	expect 202 "backup"
	j=$(wait_job admin "$(jq -r .id <<<"$j")" 1800)
	[ "$(jq -r .state <<<"$j")" = ok ] || die "backup: $(jq -r '.log // ""' <<<"$j" | tail -n 10)"
	jq -r '.log // ""' <<<"$j" | sed -n "s|^committed host-$(agent)/\([0-9]*\).*|\1|p" | tail -1 >"$OUT/time"
	log "backup host-$(agent)/$(cat "$OUT/time")"
}

step_scan() {
	local id= j t a
	t=$(cat "$OUT/time")
	# the agent id first: an api call inside the pipeline below would race it for the shared $S/body
	a=$(agent)
	log "waiting for the scheduled scan ($SCAN_AT UTC) of host-$a/$t"
	for _ in $(seq 120); do
		id=$(api admin GET '/jobs?limit=40' | jq -r --arg s "host-$a" --argjson t "$t" \
			'[.[] | select(.requested_by == "scheduler" and .params.source == $s and .params.time == $t and (.kind | test("scan")))][0].id // empty' 2>/dev/null || true)
		[ -n "$id" ] && break
		sleep 10
	done
	[ -n "$id" ] || die "no scheduled scan job for the snapshot"
	j=$(wait_job admin "$id" 1800)
	log "scheduled scan job $id: $(jq -c '.result | {matches_total, files, complete}' <<<"$j")"
	jq -e '.result.matches_total >= 1' <<<"$j" >/dev/null || die "the scheduled scan found no match"
	api admin GET /alerts | jq -e '[.[] | select(.kind == "scan_hit")] | length > 0' >/dev/null || die "no scan_hit alert"
	log "scan_hit alert raised"
}

step_hunt() {
	local r j
	api admin PUT /hash-lists/lab-ioc "$(jq -nc --arg h "$(cat "$OUT/ioc.sha256")" '{text: ("# lab IOC list (threat.sh)\n" + $h + "\n")}')" >/dev/null
	expect 200 "hash list"
	r=$(api admin POST /hunts "$(jq -nc --arg tn "$TENANT" '{tenant:$tn, lists:["lab-ioc"]}')")
	expect 202 "hunt"
	j=$(wait_job admin "$(jq -r .id <<<"$r")" 1800)
	[ "$(jq -r .state <<<"$j")" = ok ] || die "hunt: $(jq -r '.log // ""' <<<"$j" | tail -n 10)"
	log "hunt: $(jq -c '.result | del(.matches) + {matches: [.matches[]? | {path, source}]}' <<<"$j" | cut -c1-500)"
	jq -e '[.result.matches[]? | select(.path | endswith("invoice.pdf.exe"))] | length > 0' <<<"$j" >/dev/null || die "the hunt did not find the IOC file"
	api admin GET /alerts | jq -e '[.[] | select(.kind == "hash_hunt_hit")] | length > 0' >/dev/null || die "no hash_hunt_hit alert"
	log "IOC file found, hash_hunt_hit alert raised"
}

for s in "${@:-setup backup scan hunt}"; do
	for x in $s; do
		log "== $x"
		"step_$x"
	done
done
