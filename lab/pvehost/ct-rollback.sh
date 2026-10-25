#!/usr/bin/env bash
# Instant rollback of a container (restore-ct --replace --rollback, manual chapter 6 "Roll back in place
# (containers)", #55) on the PVE lab host, through the appliance VM and the tunnel of deploy.sh. An unprivileged
# Debian container $CT in group "ctrollback-$CT": backup (snapshot A), files changed, added, removed and re-moded
# in it, then the rollback to snapshot A (approved by the security officer when approvals are on). The rolled-back
# tree must equal a plain restore of snapshot A as container $CHECK: type, mode, owner, size, mtime and content
# of every file.
#
#   ct-rollback.sh ct        container $CT from the newest Debian standard template on $STORAGE, started
#   ct-rollback.sh group     group "ctrollback-$CT" on the PVE source $NODE, policy "daily"
#   ct-rollback.sh backup    backup of the group (snapshot A)
#   ct-rollback.sh change    in the container: a changed, an added, a removed and a re-moded file, $JUNK_MB of junk
#   ct-rollback.sh rollback  restore of snapshot A onto $CT with rollback ($SPARE: the fallback ID, must stay unused)
#   ct-rollback.sh compare   snapshot A restored as $CHECK; both trees listed on the node and compared
#   ct-rollback.sh cleanup   $CHECK and $CT destroyed, the group deleted
#
# env: as rollback.sh (LAB, PORT, PVE_HOST, SSH_KEY, NODE pve-test); CT (265), CHECK (266), SPARE (267),
#      STORAGE (vmpool), JUNK_MB (50), OUT (~/nexus-lab/scratch/ct-rollback)
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
export LAB=${LAB:-$HOME/nexus-lab/pvehost}
export PORT=${PORT:-28444}
PVE_HOST=${PVE_HOST:-10.2.34.200}
SSH_KEY=${SSH_KEY:-$HOME/nexus-lab/pve-lab-key}
NODE=${NODE:-pve-test}
CT=${CT:-265}
CHECK=${CHECK:-266}
SPARE=${SPARE:-267}
STORAGE=${STORAGE:-vmpool}
JUNK_MB=${JUNK_MB:-50}
OUT=${OUT:-$HOME/nexus-lab/scratch/ct-rollback}
ROOT=$LAB/appliance/root
S=$ROOT/run/api
mkdir -p "$S" "$OUT"
# shellcheck disable=SC1091
. "$ROOT/secrets.env"
# shellcheck source=lab/e2e/api-lib.sh
. "$repo/lab/e2e/api-lib.sh"
for id in "$CT" "$CHECK" "$SPARE"; do
	[ "$id" -ge 200 ] || die "guest $id: only guests from 200 are ours"
done
pve() { ssh -n -i "$SSH_KEY" -o BatchMode=yes "root@$PVE_HOST" "$@"; }
GROUP=ctrollback-$CT
case " ${*:-all} " in " ct " | " cleanup ") ;; *) login admin "$ADMIN_PW" "$ADMIN_TOTP" ;; esac

step_ct() {
	pve "pct status $CT" >/dev/null 2>&1 && die "CT $CT exists (step cleanup)"
	# shellcheck disable=SC2016
	pve 'pveam update >/dev/null; t=$(pveam available --section system | awk "{print \$2}" | grep "^debian-13-standard_.*_amd64" | sort -V | tail -1)
		[ -f /var/lib/vz/template/cache/$t ] || pveam download local $t >/dev/null
		pct create '"$CT"' local:vztmpl/$t --hostname ctrb'"$CT"' --memory 512 --cores 1 --rootfs '"$STORAGE"':4 \
			--unprivileged 1 --features nesting=1 --net0 name=eth0,bridge=vmbr0,ip=dhcp >/dev/null && pct start '"$CT"
	log "CT $CT: unprivileged Debian 13 on $STORAGE, running"
}

step_group() {
	local src pol
	api admin GET /groups | jq -e --arg n "$GROUP" '.[] | select(.name == $n)' >/dev/null && {
		log "group $GROUP exists"
		return
	}
	src=$(api admin GET /sources | jq -r --arg n "$NODE" '.[] | select(.name == $n) | .id')
	pol=$(api admin GET /policies | jq -r '.[] | select(.name == "daily") | .id')
	[ -n "$src" ] && [ -n "$pol" ] || die "no PVE source $NODE or policy daily (deploy.sh source groups)"
	api admin POST /groups "$(jq -nc --argjson s "$src" --argjson p "$pol" --arg n "$GROUP" --argjson v "$CT" \
		'{tenant:"lab", source_id:$s, policy_id:$p, name:$n, guests:[$v]}')" >/dev/null
	expect 201 "group $GROUP"
	log "group $GROUP: CT $CT"
}

step_backup() {
	local g j
	g=$(api admin GET /groups | jq -r --arg n "$GROUP" '.[] | select(.name == $n) | .id')
	j=$(api admin POST /jobs "$(jq -nc --argjson g "$g" '{kind:"backup", tenant:"lab", params:{group_id:$g}}')")
	expect 202 "backup"
	j=$(wait_job admin "$(jq -r .id <<<"$j")" 3600)
	[ "$(jq -r .state <<<"$j")" = ok ] || die "backup: $(jq -r '.log // ""' <<<"$j" | tail -n 15)"
	jq -r '.log // ""' <<<"$j" | sed -n "s|^committed ct-$CT/\([0-9]*\).*|\1|p" | tail -1 >"$OUT/a.time"
	[ -s "$OUT/a.time" ] || die "backup: no committed line for ct-$CT"
	log "snapshot A: ct-$CT/$(cat "$OUT/a.time") ($(jq -r '.finished - .started' <<<"$j") s)"
}

step_change() {
	pve "pct exec $CT -- sh -c 'echo changed >> /etc/motd; rm -f /etc/issue.net; chmod 600 /etc/hostname;
		echo rolled-back-if-missing > /root/marker; mkdir -p /opt/junk; head -c ${JUNK_MB}M /dev/urandom > /opt/junk/a.bin;
		rm -rf /usr/share/doc/apt; sync'"
	log "CT $CT: /etc/motd changed, /etc/issue.net and /usr/share/doc/apt removed, /etc/hostname 0600, /root/marker and ${JUNK_MB} MB junk added"
}

step_rollback() {
	local r q j id t0=$SECONDS
	pve "pct status $SPARE" >/dev/null 2>&1 && die "guest $SPARE exists (the fallback ID must be free)"
	r=$(api admin POST /jobs "$(jq -nc --argjson t "$(cat "$OUT/a.time")" --argjson v "$SPARE" --arg s "ct-$CT" \
		--arg n "$NODE" --arg st "$STORAGE" \
		'{kind:"restore_ct", tenant:"lab", params:{source:$s, time:$t, node:$n, target:$v, storage:$st, replace:true,
		  rollback:true, start:true}}')")
	[ "$(status)" = 202 ] || [ "$(status)" = 200 ] || die "rollback: HTTP $(status) $(cat "$S/body")"
	q=$(jq -r '.quorum_id // empty' <<<"$r")
	if [ -n "$q" ] && [ "$(jq -r '.state // empty' <<<"$r")" != approved ]; then
		login so "$SO_PW" "$SO_TOTP"
		api so POST "/quorum/$q/approve" '{}' >/dev/null
		expect 200 "approve restore.replace"
		log "approved by the security officer (quorum $q)"
	fi
	id=$(jq -r '.id // empty' <<<"$r")
	for _ in $(seq 30); do
		[ -n "$id" ] && break
		id=$(api admin GET '/jobs?limit=10' | jq -r --arg s "ct-$CT" \
			'[.[] | select(.kind == "restore_ct" and .params.source == $s)][0].id // empty')
		sleep 2
	done
	[ -n "$id" ] || die "no restore job after the approval"
	j=$(wait_job admin "$id" 7200)
	jq -r '.log // ""' <<<"$j" | grep -iE "rollback|differ|node |full replace|rolled-back" | tail -8 >&2 || true
	[ "$(jq -r .state <<<"$j")" = ok ] || die "rollback job $id: $(jq -r '.log // ""' <<<"$j" | tail -n 20)"
	log "rollback job $id ok in $((SECONDS - t0)) s"
	pve "pct status $SPARE" >/dev/null 2>&1 && die "guest $SPARE was created: the job fell back to a full replace"
	pve "pct config $CT | grep -E '^(lock|tags)' || echo 'no lock, no tag'; pct status $CT" >&2
}

# list CTID: one line per file of the stopped container's tree (as the host sees it, mapped ids alike)
listing() {
	pve "pct mount $1 >/dev/null && cd /var/lib/lxc/$1/rootfs && find . -xdev ! -path './dev/*' ! -path './lost+found*' \
		\( -type f -printf '%y %m %U %G %s %Ts %p ' -exec sh -c 'sha256sum < \"\$1\" | cut -c1-16' _ {} \; \) -o \
		\( ! -type f ! -type d -printf '%y %m %U %G %p %l\n' \) -o \( -type d -printf '%y %m %U %G %p\n' \) | sort;
		cd /; pct unmount $1"
}

step_compare() {
	local j
	pve "pct status $CHECK" >/dev/null 2>&1 && die "guest $CHECK exists (step cleanup)"
	j=$(api admin POST /jobs "$(jq -nc --argjson t "$(cat "$OUT/a.time")" --argjson v "$CHECK" --arg s "ct-$CT" \
		--arg n "$NODE" --arg st "$STORAGE" \
		'{kind:"restore_ct", tenant:"lab", params:{source:$s, time:$t, node:$n, target:$v, storage:$st, start:false}}')")
	expect 202 "restore to $CHECK"
	j=$(wait_job admin "$(jq -r .id <<<"$j")" 7200)
	[ "$(jq -r .state <<<"$j")" = ok ] || die "restore to $CHECK: $(jq -r '.log // ""' <<<"$j" | tail -n 15)"
	pve "pct status $CT | grep -q stopped || pct shutdown $CT --timeout 120 --forceStop 1"
	listing "$CT" >"$OUT/rolled-back.txt"
	listing "$CHECK" >"$OUT/restored.txt"
	if ! diff -u "$OUT/restored.txt" "$OUT/rolled-back.txt" >"$OUT/diff.txt"; then
		head -40 "$OUT/diff.txt" >&2
		die "the rolled-back tree differs from a plain restore of snapshot A ($OUT/diff.txt)"
	fi
	grep -q ' ./root/marker' "$OUT/rolled-back.txt" && die "the marker survived the rollback"
	log "the rolled-back tree equals a plain restore of snapshot A ($(wc -l <"$OUT/restored.txt") entries)"
}

step_cleanup() {
	local id
	for id in "$CHECK" "$SPARE" "$CT"; do
		pve "pct status $id >/dev/null 2>&1 || exit 0; pct unlock $id; pct stop $id >/dev/null 2>&1 || true; pct destroy $id --purge 1 >/dev/null"
	done
	login admin "$ADMIN_PW" "$ADMIN_TOTP"
	id=$(api admin GET /groups | jq -r --arg n "$GROUP" '.[] | select(.name == $n) | .id')
	[ -z "$id" ] || api admin DELETE "/groups/$id" >/dev/null
	log "CT $CT, $CHECK destroyed, group $GROUP deleted"
}

for s in ${*:-ct group backup change rollback compare}; do
	"step_$s"
done
