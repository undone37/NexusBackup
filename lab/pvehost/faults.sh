#!/usr/bin/env bash
# Fault injection on the appliance VM of the PVE lab (plan.md Phase 44): a backup of a guest of group $GROUP (VM 242
# by default: 40 GB, ours) is interrupted, then the outcome is checked against what must happen.
#
#   faults.sh group     the group $GROUP with guest $VMID (deploy.sh groups)
#   faults.sh reboot    the appliance reboots while the backup reads: after the restart the job is failed (not left
#                       "running"), no snapshot of that run exists, and the next backup succeeds
#   faults.sh netloss   the appliance's traffic to the PVE host is dropped for $LOSS seconds while the backup reads:
#                       the job either finishes after the outage or fails with a clear error; a retry succeeds
#   faults.sh dgroup    the group $FGROUP with guest $FVM (a Debian agent VM: random data is written into it)
#   faults.sh full      /var (store and catalog share it) filled up to $FILL_LEFT bytes before a backup of $FVM that
#                       has $FULL_MB MiB of new random data: the job fails with a clear error, no snapshot of it, the
#                       capacity alert, the API answers; space freed: the next backup and a verification succeed
#   faults.sh corrupt   a chunk of a new snapshot of $FVM (64 MiB of new random data) in today's verification share
#                       overwritten in the store: verify finds it (verify + snapshot_damaged alerts, snapshot marked
#                       damaged), a restore of the snapshot fails naming it and leaves no guest behind; the next
#                       backup stores the data again: after another verification both alerts resolve
#   faults.sh clock     the appliance's clock jumps $JUMP_MIN minutes ahead (chronyd stopped): critical clock_skew;
#                       back and chronyd started: resolved (or info, when the clock still lags from a power-off)
#
# env: as deploy.sh (LAB ~/nexus-lab/pvehost, PORT 28444, PVE_HOST); GROUP (fault), VMID (242), LOSS (120),
#      AFTER (bytes read before the fault, 3000000000); FGROUP (fault-data), FVM (225), FULL_MB (2048), FILL_LEFT
#      (536870912), RESTORE_TARGET (212, removed again), NODE (pve-test), STORAGE (vmpool), JUMP_MIN (15)
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
export LAB=${LAB:-$HOME/nexus-lab/pvehost}
export PORT=${PORT:-28444}
PVE_HOST=${PVE_HOST:-10.2.34.200}
GROUP=${GROUP:-fault}
VMID=${VMID:-242}
LOSS=${LOSS:-120}
AFTER=${AFTER:-3000000000}
FGROUP=${FGROUP:-fault-data}
FVM=${FVM:-225}
FULL_MB=${FULL_MB:-2048}
FILL_LEFT=${FILL_LEFT:-536870912}
RESTORE_TARGET=${RESTORE_TARGET:-212}
NODE=${NODE:-pve-test}
STORAGE=${STORAGE:-vmpool}
JUMP_MIN=${JUMP_MIN:-15}
SSH_KEY=${SSH_KEY:-$HOME/nexus-lab/pve-lab-key}
ROOT=$LAB/appliance/root
S=$ROOT/run/api
export CONSOLE=$LAB/appliance/console.sock
con() { "$here/../appliance/con.py" "$@"; }
mkdir -p "$S"
# shellcheck disable=SC1091
. "$ROOT/secrets.env"
# shellcheck source=lab/e2e/api-lib.sh
. "$repo/lab/e2e/api-lib.sh"

gid() { api admin GET /groups | jq -r --arg n "$GROUP" '.[] | select(.name == $n) | .id'; }
snaps() { api admin GET '/snapshots?tenant=lab' | jq -c --arg s "vm-$VMID" '[.[] | select(.source == $s) | .time]'; }

# starts a backup of the group and returns once it has read $AFTER bytes (or ran 5 minutes)
start_and_wait() {
	local r id done=0
	local g
	g=$(gid)
	r=$(api admin POST /jobs "$(jq -nc --argjson g "$g" '{kind:"backup", tenant:"lab", params:{group_id:$g}}')")
	expect 202 "backup of $GROUP"
	id=$(jq -r .id <<<"$r")
	for _ in $(seq 300); do
		r=$(api admin GET "/jobs/$id")
		done=$(jq -r '.progress.done // 0' <<<"$r")
		[ "${done%.*}" -ge "$AFTER" ] 2>/dev/null && break
		[ "$(jq -r .state <<<"$r")" = running ] || [ "$(jq -r .state <<<"$r")" = queued ] || die "job $id ended before the fault: $(jq -r .state <<<"$r")"
		sleep 1
	done
	log "job $id has read $done bytes"
	echo "$id"
}

# the newest backup job of the group after $1, waited for
next_job() {
	local id g jobs
	g=$(gid) # not inside the pipeline below: both calls would write api-lib's one response file at once
	for _ in $(seq 120); do
		jobs=$(api admin GET '/jobs?tenant=lab&limit=50')
		id=$(jq -r --argjson g "$g" --argjson a "$1" \
			'[.[] | select(.kind == "backup" and .params.group_id == $g and .id > $a)] | sort_by(.id) | .[0].id // empty' <<<"$jobs")
		[ -n "$id" ] && break
		sleep 5
	done
	[ -n "$id" ] || return 1
	wait_job admin "$id" 3600
}

step_group() {
	LAB_GROUPS="$GROUP:$VMID" "$here/deploy.sh" groups
}

pve() { ssh -n -i "$SSH_KEY" -o BatchMode=yes "root@$PVE_HOST" "$@" 2> >(grep -v 'older storage API' >&2); }
# a shell command in VM $FVM through the guest agent
guest() { pve "qm guest exec $FVM --timeout 600 -- sh -c $(printf '%q' "$1")" >/dev/null; }
# a console command's output without the echo and prompt noise: the lines matching $2
conval() { con run "$1" 120 | tr -d '\r' | grep -E "$2" || true; }
open_alert() { api admin GET '/alerts?state=open' | jq -c --arg k "$1" '[.[] | select(.key == $k)][0] // empty'; }
wait_alert() { # KEY SEVERITY [tries of 5 s]
	local a
	for _ in $(seq "${3:-60}"); do
		a=$(open_alert "$1")
		[ -n "$a" ] && [ "$(jq -r .severity <<<"$a")" = "$2" ] && { log "alert $1 ($2): $(jq -r .message <<<"$a" | cut -c1-200)"; return 0; }
		sleep 5
	done
	die "no open $2 alert $1"
}
wait_resolved() {
	for _ in $(seq "${2:-60}"); do
		[ -z "$(open_alert "$1")" ] && { log "alert $1 resolved"; return 0; }
		sleep 5
	done
	die "alert $1 still open: $(open_alert "$1")"
}
# a job of kind $1 with params $2 (tenant lab), waited for; the final job JSON whatever its state
run_job() {
	local r
	r=$(api admin POST /jobs "$(jq -nc --arg k "$1" --argjson p "$2" '{kind:$k, tenant:"lab", params:$p}')")
	expect 202 "$1 job"
	wait_job admin "$(jq -r .id <<<"$r")" "${3:-3600}"
}
backup_now() { run_job backup "$(jq -nc --argjson g "$(gid)" '{group_id:$g}')"; }
newest() { api admin GET "/snapshots?tenant=lab&source=vm-$VMID" | jq -c 'max_by(.time)'; }

step_dgroup() {
	LAB_GROUPS="$FGROUP:$FVM" "$here/deploy.sh" groups
}

step_full() {
	GROUP=$FGROUP VMID=$FVM
	login admin "$ADMIN_PW" "$ADMIN_TOTP"
	local j before free
	j=$(backup_now)
	[ "$(jq -r .state <<<"$j")" = ok ] || die "baseline backup: $(jq -r .state <<<"$j")"
	guest "dd if=/dev/urandom of=/root/nexus-fault bs=1M count=$FULL_MB status=none && sync"
	before=$(snaps)
	free=$(conval "df -B1 --output=avail /var | tail -n 1" '^[0-9]+$' | tail -n 1)
	[ -n "$free" ] || die "free space of /var unknown"
	con run "fallocate -l $((free - FILL_LEFT)) /var/nexus-fault-fill" 120 >/dev/null
	log "/var filled: $(conval 'df -h --output=avail,pcent /var | tail -n 1' '%')"
	j=$(backup_now)
	log "backup with a full /var: $(jq -r .state <<<"$j") after $(jq '.finished - .started' <<<"$j") s: $(jq -r .log <<<"$j" | grep -iE 'space|error|fail' | tail -n 3 | tr '\n' ' ' | cut -c1-400)"
	[ "$(jq -r .state <<<"$j")" = failed ] || die "the backup did not fail: $(jq -r .state <<<"$j")"
	[ "$(snaps)" = "$before" ] || die "a snapshot was committed: before $before, now $(snaps)"
	# the scheduler checks every tick (#48); images before that with the 15-minute refresh
	local t0=$SECONDS
	wait_alert capacity warning 200
	log "capacity alert after $((SECONDS - t0)) s"
	con run "rm -f /var/nexus-fault-fill" 60 >/dev/null
	log "space freed: $(conval 'df -h --output=avail,pcent /var | tail -n 1' '%')"
	j=$(backup_now)
	[ "$(jq -r .state <<<"$j")" = ok ] || die "backup after freeing space: $(jq -r .state <<<"$j"): $(jq -r .log <<<"$j" | tail -n 5)"
	log "next backup ok in $(jq '.finished - .started' <<<"$j") s; snapshots $(snaps)"
	j=$(run_job verify '{}')
	log "verify: $(jq -r .state <<<"$j"): $(jq -r .log <<<"$j" | grep -o 'local verify.*' | head -n 1)"
	[ "$(jq -r .state <<<"$j")" = ok ] || die "verify after the full store"
	wait_resolved capacity 200
	guest "rm -f /root/nexus-fault"
}

step_corrupt() {
	GROUP=$FGROUP VMID=$FVM
	login admin "$ADMIN_PW" "$ADMIN_TOTP"
	local j s t start part chunk n b path share r
	guest "dd if=/dev/urandom of=/root/nexus-fault-c bs=1M count=64 status=none && sync"
	start=$(date +%s)
	j=$(backup_now)
	[ "$(jq -r .state <<<"$j")" = ok ] || die "backup: $(jq -r .state <<<"$j")"
	t=$(newest | jq .time)
	# today's verification share (scheduler: unix day % 7 of the chunk id's first byte)
	part=$(($(date +%s) / 86400 % 7))
	for n in $(conval "find /var/lib/nexus/chunkstore/lab/chunks -type f -newermt @$((start - 5)) ! -name '*.*' -printf '%f\\n'" '^[0-9a-f]{64}$'); do
		b=$((16#${n:0:2}))
		[ $((b % 7)) = "$part" ] && { chunk=$n; break; }
	done
	[ -n "${chunk:-}" ] || die "no new chunk of vm-$VMID/$t in share $part"
	path=/var/lib/nexus/chunkstore/lab/chunks/${chunk:0:4}/$chunk
	con run "printf NEXUS-FAULT-CORRUPT | dd of=$path bs=1 seek=200 conv=notrunc status=none" 60 >/dev/null
	log "chunk $chunk of vm-$VMID/$t overwritten (share $((part + 1))/7)"
	j=$(run_job verify '{}')
	share=$(jq -r .log <<<"$j" | grep -o 'local verify.*' | head -n 1)
	log "verify: $(jq -r .state <<<"$j"): $share"
	grep -q "share $((part + 1))/7" <<<"$share" || die "verify read another share"
	wait_alert verify:lab critical 24
	wait_alert snapshot_damaged:lab critical 24
	s=$(api admin GET "/snapshots?tenant=lab&source=vm-$VMID" | jq -c --argjson t "$t" '.[] | select(.time == $t)')
	[ "$(jq -r '.damaged // 0' <<<"$s")" -ge 1 ] || die "vm-$VMID/$t not marked damaged: $s"
	log "vm-$VMID/$t damaged: $(jq -r .damaged <<<"$s") chunk(s)"
	j=$(run_job restore "$(jq -nc --arg s "vm-$VMID" --argjson t "$t" --arg n "$NODE" --argjson to "$RESTORE_TARGET" --arg st "$STORAGE" \
		'{source:$s, time:$t, node:$n, target:$to, storage:$st, name:"corrupt-verify", start:false, link_down:true}')")
	r=$(jq -r .log <<<"$j" | grep -iE 'chunk|corrupt|error' | tail -n 2 | tr '\n' ' ' | cut -c1-400)
	log "restore of the damaged snapshot: $(jq -r .state <<<"$j"): $r"
	# the restore removes what PVE created of the guest (#48); images before that left a stub configuration
	if pve "qm status $RESTORE_TARGET" >/dev/null 2>&1; then
		log "guest $RESTORE_TARGET left behind by the failed restore: removed"
		pve "qm destroy $RESTORE_TARGET --purge" >/dev/null
	fi
	[ "$(jq -r .state <<<"$j")" = failed ] || die "the restore of a damaged snapshot did not fail"
	j=$(backup_now)
	log "next backup: $(jq -r .state <<<"$j") in $(jq '.finished - .started' <<<"$j") s, read $(jq -r '.result.bytes_read // .progress.done // "?"' <<<"$j")"
	# the data is stored again; the next verification sees the snapshot whole and the share clean
	j=$(run_job verify '{}')
	log "verify again: $(jq -r .state <<<"$j"): $(jq -r .log <<<"$j" | grep -o 'local verify.*' | head -n 1)"
	wait_resolved snapshot_damaged:lab 24
	wait_resolved verify:lab 24
	guest "rm -f /root/nexus-fault-c"
}

step_clock() {
	login admin "$ADMIN_PW" "$ADMIN_TOTP"
	log "clock $JUMP_MIN min ahead (chronyd stopped)"
	con run "systemctl stop chronyd && date -s '+$JUMP_MIN min' >/dev/null" 60 >/dev/null
	wait_alert clock_skew critical 36
	con run "date -s '-$JUMP_MIN min' >/dev/null; systemctl start chronyd; sleep 5; chronyc -a makestep >/dev/null" 60 >/dev/null
	log "clock back: $(conval 'chronyc tracking | grep -E "System time"' 'System')"
	# the jump alert resolves; a lag after an earlier power-off may remain as info (#48: de-escalated)
	local a
	for _ in $(seq 36); do
		a=$(open_alert clock_skew)
		[ -z "$a" ] || [ "$(jq -r .severity <<<"$a")" = info ] && break
		sleep 5
	done
	[ -z "$a" ] || [ "$(jq -r .severity <<<"$a")" = info ] || die "clock_skew still $(jq -r .severity <<<"$a"): $(jq -r .message <<<"$a")"
	if [ -n "$a" ]; then
		log "after the jump: $(jq -r '.severity + ": " + .message' <<<"$a" | cut -c1-160)"
	else
		log "after the jump: no clock_skew alert"
	fi
}

step_reboot() {
	login admin "$ADMIN_PW" "$ADMIN_TOTP"
	local before id j
	before=$(snaps)
	id=$(start_and_wait)
	log "rebooting the appliance during job $id"
	con run 'systemd-run --on-active=2 systemctl reboot >/dev/null' 30 >/dev/null || true
	sleep 30
	for _ in $(seq 60); do
		curl -sk -m 5 -o /dev/null "https://127.0.0.1:$PORT/api/v1/auth/me" 2>/dev/null && break
		sleep 10
	done
	sleep 20
	login admin "$ADMIN_PW" "$ADMIN_TOTP"
	j=$(api admin GET "/jobs/$id")
	log "after the reboot: job $id $(jq -r .state <<<"$j"): $(jq -r .log <<<"$j" | tail -3 | tr '\n' ' ' | cut -c1-250)"
	log "snapshots of vm-$VMID: before $before, now $(snaps)"
	j=$(next_job "$id") || die "no retry or next backup of $GROUP"
	log "next backup job $(jq -r .id <<<"$j"): $(jq -r .state <<<"$j") in $(jq '.finished - .started' <<<"$j") s; snapshots now $(snaps)"
}

step_netloss() {
	login admin "$ADMIN_PW" "$ADMIN_TOTP"
	local id j
	id=$(start_and_wait)
	log "dropping the appliance's traffic to $PVE_HOST for $LOSS s during job $id"
	# one console line: insert, wait, delete by handle (in the background on the appliance)
	con run "nft insert rule inet nexus output ip daddr $PVE_HOST drop comment \\\"fault-netloss\\\"; systemd-run --on-active=$LOSS sh -c 'nft -a list chain inet nexus output | grep fault-netloss | sed \"s/.*handle //\" | xargs -r -I{} nft delete rule inet nexus output handle {}' >/dev/null" 30 >/dev/null
	j=$(wait_job admin "$id" 3600)
	log "job $id: $(jq -r .state <<<"$j") after $(jq '.finished - .started' <<<"$j") s: $(jq -r .log <<<"$j" | grep -iE 'error|fail|retry|timed' | tail -2 | tr '\n' ' ' | cut -c1-250)"
	log "egress rules left: $(con run 'nft list chain inet nexus output | grep -c fault-netloss' 30 | grep -E '^[0-9]+$' | tail -1)"
	if [ "$(jq -r .state <<<"$j")" != ok ]; then
		j=$(next_job "$id") || die "no retry of $GROUP"
		log "retry job $(jq -r .id <<<"$j"): $(jq -r .state <<<"$j") in $(jq '.finished - .started' <<<"$j") s"
	fi
	log "snapshots of vm-$VMID: $(snaps)"
}

for s in "$@"; do
	"step_$s"
done
