#!/usr/bin/env bash
# Clean-file restore after a simulated ransomware run (#76, plan.md Phase 39 L16), on the appliance VM of the PVE
# lab through the tunnel of deploy.sh: an agent test VM (agent-vms.sh) with a test tree, a backup, then the
# "attack" (most files renamed to *.locked with random content, a ransom note, one file with a marker string a
# YARA rule matches, some legitimate edits), a second backup, a YARA scan of it, and the clean-file restore of the
# second snapshot as a download. The archive must hold every original file (renamed ones from the first snapshot,
# the infected one from the first snapshot, the edits from the second), and no *.locked file and no ransom note.
#
#   clean-restore.sh vm        $VM from clean-os + the agent package, started; its address
#   clean-restore.sh enrol     agent and source "clean-<VM>" (paths: $DATA) on the appliance, tenant lab
#   clean-restore.sh before    the test tree ($FILES files), backup 1
#   clean-restore.sh attack    the simulated ransomware run, backup 2
#   clean-restore.sh scan      YARA rule "lab-marker" and a scan of snapshot 2
#   clean-restore.sh restore   clean-file restore of snapshot 2 (download, tar), compared with the expectation
#   clean-restore.sh tohost    the same onto the agent into /srv/restored (new directory, overwrite never)
#   clean-restore.sh cleanup   VM stopped and reset to clean-os (agent and source stay on the appliance)
#
# env: as vmware-e2e.sh (LAB ~/nexus-lab/pvehost, PORT 28444, PVE_HOST, SSH_KEY); VM (debian-13), VM_KEY
#      (~/nexus-lab/lab_ed25519), FILES (200), OUT (~/nexus-lab/scratch/clean-restore)
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
export LAB=${LAB:-$HOME/nexus-lab/pvehost}
export PORT=${PORT:-28444}
PVE_HOST=${PVE_HOST:-10.2.34.200}
SSH_KEY=${SSH_KEY:-$HOME/nexus-lab/pve-lab-key}
VM_KEY=${VM_KEY:-$HOME/nexus-lab/lab_ed25519}
VM=${VM:-debian-13}
FILES=${FILES:-200}
OUT=${OUT:-$HOME/nexus-lab/scratch/clean-restore}
DATA=/srv/clean
ROOT=$LAB/appliance/root
S=$ROOT/run/api
mkdir -p "$S" "$OUT"
# shellcheck disable=SC1091
. "$ROOT/secrets.env"
# shellcheck source=lab/e2e/api-lib.sh
. "$repo/lab/e2e/api-lib.sh"
JUMP="ssh -i $SSH_KEY -o BatchMode=yes -W %h:%p root@$PVE_HOST"
SSHO=(-i "$VM_KEY" -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR
	-o ProxyCommand="$JUMP")
vm() { ssh "${SSHO[@]}" "root@$(cat "$OUT/ip")" "$@"; }
pve() { ssh -n -i "$SSH_KEY" -o BatchMode=yes "root@$PVE_HOST" "$@"; }
# vm and cleanup alone need no API (no login, which would use up a TOTP code)
case " ${*:-all} " in " vm " | " cleanup " | " vm cleanup ") ;; *) login admin "$ADMIN_PW" "$ADMIN_TOTP" ;; esac
NAME=clean-$VM
agent_id() { api admin GET /agents | jq -r --arg n "$NAME" '.[] | select(.name == $n) | .id'; }
SRC() { echo "host-$(agent_id)"; }

backup() { # backup label: the job, the snapshot time into $OUT/<label>.time
	local j
	j=$(api admin POST /jobs "$(jq -nc --arg a "$(agent_id)" '{kind:"backup", tenant:"lab", params:{agent_id:$a}}')")
	expect 202 "backup $1"
	j=$(wait_job admin "$(jq -r .id <<<"$j")" 1800)
	[ "$(jq -r .state <<<"$j")" = ok ] || die "backup $1: $(jq -r '.log // ""' <<<"$j" | tail -n 15)"
	jq -r '.log // ""' <<<"$j" | sed -n "s|^committed $(SRC)/\([0-9]*\).*|\1|p" | tail -1 >"$OUT/$1.time"
	[ -s "$OUT/$1.time" ] || die "backup $1: no committed line"
	log "backup $1: $(SRC)/$(cat "$OUT/$1.time")"
}

step_vm() {
	local id
	id=$("$here/agent-vms.sh" ip "$VM" </dev/null | awk '{print $2}')
	[ -n "$id" ] || die "no agent VM $VM (agent-vms.sh list)"
	"$here/agent-vms.sh" reset "$VM" </dev/null
	pve "qm start $id"
	"$here/agent-vms.sh" agent "$VM" </dev/null
	"$here/agent-vms.sh" ip "$VM" </dev/null | awk '{print $3}' >"$OUT/ip"
	[ "$(cat "$OUT/ip")" != - ] || die "$VM: no address"
	log "$VM: $(cat "$OUT/ip"), $(vm 'nexus-agent version' | head -1)"
}

step_enrol() {
	local r id tok j
	if [ -z "$(agent_id)" ]; then
		r=$(api admin POST /agents "$(jq -nc --arg n "$NAME" --arg h "$(cat "$OUT/ip")" '{tenant:"lab", name:$n, host:$h, port:7444}')")
		expect 201 "create agent"
	fi
	id=$(agent_id)
	# a reset VM lost its identity: a new token, then enrol again
	r=$(api admin POST "/agents/$id/token")
	expect 200 "agent token"
	tok=$(jq -r .token <<<"$r")
	vm "nexus-agent init --token - >/dev/null && systemctl enable --now nexus-agent >/dev/null 2>&1 && systemctl restart nexus-agent" <<<"$tok"
	r=$(api admin POST "/agents/$id/enroll")
	expect 202 "enroll"
	j=$(wait_job admin "$(jq -r .id <<<"$r")" 300)
	[ "$(jq -r .state <<<"$j")" = ok ] || die "enroll: $(jq -r '.log // ""' <<<"$j" | tail -n 15)"
	if ! api admin GET /sources | jq -e --arg n "$NAME" '.[] | select(.name == $n)' >/dev/null; then
		api admin POST /sources "$(jq -nc --arg n "$NAME" --arg a "$id" --arg d "$DATA" \
			'{tenant:"lab", kind:"linux", name:$n, config:{agent_id:$a, paths:[$d], hooks:false}}')" >/dev/null
		expect 201 "create source"
	fi
	log "agent $NAME ($id) enrolled, source $NAME"
}

step_before() {
	vm "rm -rf $DATA && mkdir -p $DATA/docs $DATA/sheets && for i in \$(seq 1 $FILES); do
		d=docs; [ \$((i % 3)) = 0 ] && d=sheets
		printf 'document %s\nline two of %s\n' \$i \$i > $DATA/\$d/file-\$i.txt; done; sync"
	backup before
}

step_attack() {
	# keep files 1-20 untouched, edit 21-30 legitimately, file 31 gets the marker (infected), the rest is
	# encrypted and renamed; a ransom note in each directory
	vm "set -e; cd $DATA
		for f in docs/file-2[1-9].txt docs/file-30.txt sheets/file-2[1-9].txt sheets/file-30.txt; do
			[ -e \$f ] && echo 'legitimate edit after backup 1' >> \$f; done
		f=\$(ls */file-31.txt); echo 'NEXUS-LAB-MARKER-7f3a' >> \$f
		for f in */file-*.txt; do
			n=\${f##*/file-}; n=\${n%.txt}; [ \$n -le 31 ] && continue
			head -c 4096 /dev/urandom > \$f.locked && rm \$f
		done
		for d in docs sheets; do echo 'Your files are encrypted. Pay.' > \$d/HOW_TO_DECRYPT.txt; done; sync"
	backup after
}

step_scan() {
	local r j
	api admin PUT /scan/rules/lab-marker "$(jq -nc --arg t 'rule lab_marker { strings: $m = "NEXUS-LAB-MARKER-7f3a" condition: $m }' '{text:$t}')" >/dev/null
	expect 200 "YARA rule"
	r=$(api admin POST "/snapshots/lab/$(SRC)/$(cat "$OUT/after.time")/scan" '{"budget_min":30}')
	[ "$(status)" = 202 ] || [ "$(status)" = 200 ] || die "scan: HTTP $(status) $(cat "$S/body")"
	j=$(wait_job admin "$(jq -r '.id // .job' <<<"$r")" 1800)
	[ "$(jq -r .state <<<"$j")" = ok ] || die "scan: $(jq -r '.log // ""' <<<"$j" | tail -n 15)"
	log "scan: $(jq -c '.result // {}' <<<"$j" | cut -c1-300)"
}

step_restore() {
	local r j tok
	r=$(api admin POST /jobs "$(jq -nc --arg s "$(SRC)" --argjson t "$(cat "$OUT/after.time")" --arg d "$DATA" \
		'{kind:"synthetic_restore", tenant:"lab", params:{source:$s, time:$t, paths:[$d], depth:5, mode:"download", format:"tar"}}')")
	expect 202 "synthetic_restore"
	tok=$(jq -r .download_token <<<"$r")
	j=$(wait_job admin "$(jq -r .id <<<"$r")" 1800)
	[ "$(jq -r .state <<<"$j")" = ok ] || die "synthetic_restore: $(jq -r '.log // ""' <<<"$j" | tail -n 15)"
	log "result: $(jq -c '.result | del(.download_token, .report_token)' <<<"$j" | cut -c1-400)"
	curl -s --cacert "$ROOT/etc/nexus/tls/cert.pem" --resolve "nexus-m5:$PORT:127.0.0.1" -b "$S/admin.jar" \
		-o "$OUT/clean.tar" "$BASE/downloads/$tok"
	rm -rf "$OUT/x" && mkdir -p "$OUT/x" && tar -xf "$OUT/clean.tar" -C "$OUT/x"
	check "$OUT/x"
	log "clean-file restore (download): all $FILES files as expected, no *.locked, no ransom note"
}

check() { # check DIR: the clean tree below DIR, from the numbering of step before / attack
	local bad=0 i d f got want
	for i in $(seq 1 "$FILES"); do
		d=docs
		[ $((i % 3)) = 0 ] && d=sheets
		f=$(find "$OUT/x" -path "*/$d/file-$i.txt" | head -1)
		want=$(printf 'document %s\nline two of %s\n' "$i" "$i")
		[ "$i" -ge 21 ] && [ "$i" -le 30 ] && want=$(printf '%s\nlegitimate edit after backup 1' "$want")
		got=$(cat "$f" 2>/dev/null || echo MISSING)
		[ "$got" = "$want" ] || {
			bad=$((bad + 1))
			[ $bad -le 5 ] && log "file-$i: $(head -c 80 <<<"$got" | tr '\n' '|')"
		}
	done
	[ -z "$(find "$OUT/x" -name '*.locked' -o -name 'HOW_TO_DECRYPT.txt')" ] || {
		bad=$((bad + 1))
		log "ransomware leftovers in the archive: $(find "$OUT/x" -name '*.locked' -o -name 'HOW_TO_DECRYPT.txt' | head -3 | tr '\n' ' ')"
	}
	[ $bad = 0 ] || die "$bad deviations from the expected clean tree"
}

step_tohost() {
	local r j
	vm "rm -rf /srv/restored"
	r=$(api admin POST /jobs "$(jq -nc --arg s "$(SRC)" --argjson t "$(cat "$OUT/after.time")" --arg d "$DATA" --arg n "$NAME" \
		'{kind:"synthetic_restore", tenant:"lab", params:{source:$s, time:$t, paths:[$d], depth:5, mode:"host",
		  target:"/srv/restored", overwrite:"never", confirm:$n}}')")
	expect 202 "synthetic_restore to host"
	j=$(wait_job admin "$(jq -r .id <<<"$r")" 1800)
	[ "$(jq -r .state <<<"$j")" = ok ] || die "synthetic_restore to host: $(jq -r '.log // ""' <<<"$j" | tail -n 15)"
	log "result: $(jq -c '.result | del(.download_token, .report_token)' <<<"$j" | cut -c1-400)"
	rm -rf "$OUT/h" && mkdir -p "$OUT/h"
	vm "tar -C /srv/restored -cf - ." | tar -xf - -C "$OUT/h"
	check "$OUT/h"
	log "clean-file restore (to the host): all $FILES files as expected in /srv/restored"
}

step_cleanup() {
	"$here/agent-vms.sh" reset "$VM" </dev/null
	log "$VM reset to clean-os (stopped)"
}

for s in "${@:-vm enrol before attack scan restore tohost}"; do
	for x in $s; do
		log "== $x"
		"step_$x"
	done
done
