#!/usr/bin/env bash
# Offsite copy to an SFTP target and fetch back (Phase 17d, m5-api.sh step offsite-fetch; #62) on the PVE lab
# appliance VM 201 through the tunnel of deploy.sh. The target is an SFTP-only account on the lab VM $SFTP_VM
# (OpenSSH's internal-sftp, nothing installed); the key is placed on the appliance by hand (manual chapter 4,
# "Appliance SSH keys": generating keys from the UI is still being integrated).
#
#   offsite.sh target   key /etc/nexus/ssh/$KEY on the appliance (console), account $USER_ on $SFTP_VM with that
#                       key (restrict, internal-sftp), offsite target of tenant $TENANT
#   offsite.sh upload   offsite job of $TENANT: its snapshots local + offsite
#   offsite.sh fetch    the newest snapshot's local copy removed in the store (console), offsite only after the
#                       refresh; offsite_list; offsite_restore: local again, locked 7 days; files_list of it
#
# env: as vmware-e2e.sh (LAB, PORT); TENANT (windows), SFTP_VM (10.2.34.99, the regression VM 280), USER_ (nexusoff),
#      KEY (offsite-280), VM_KEY (~/nexus-lab/lab_ed25519: root on $SFTP_VM), BASE_DIR (nexus-201)
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
export LAB=${LAB:-$HOME/nexus-lab/pvehost}
export PORT=${PORT:-28444}
export CONSOLE=${CONSOLE:-$LAB/appliance/console.sock}
TENANT=${TENANT:-windows}
SFTP_VM=${SFTP_VM:-10.2.34.99}
USER_=${USER_:-nexusoff}
KEY=${KEY:-offsite-280}
VM_KEY=${VM_KEY:-$HOME/nexus-lab/lab_ed25519}
BASE_DIR=${BASE_DIR:-nexus-201}
ROOT=$LAB/appliance/root
S=$ROOT/run/api
mkdir -p "$S"
# shellcheck disable=SC1091
. "$ROOT/secrets.env"
# shellcheck source=lab/e2e/api-lib.sh
. "$repo/lab/e2e/api-lib.sh"
con() { "$repo/lab/appliance/con.py" run "$@"; }
sftpvm() { ssh -i "$VM_KEY" -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR \
	-o ConnectTimeout=10 "root@$SFTP_VM" "$@"; }
login admin "$ADMIN_PW" "$ADMIN_TOTP"

step_target() {
	local pub hk r
	# one line per console call (the console helper sends a command as one line)
	con "test -f /etc/nexus/ssh/$KEY || ssh-keygen -q -t ed25519 -N '' -C nexusbackup-$KEY@nexus -f /etc/nexus/ssh/$KEY" >/dev/null
	con "chown nexus-chunkstore:nexus-chunkstore /etc/nexus/ssh/$KEY /etc/nexus/ssh/$KEY.pub; chmod 600 /etc/nexus/ssh/$KEY; restorecon /etc/nexus/ssh/$KEY /etc/nexus/ssh/$KEY.pub" >/dev/null
	pub=$(con "cut -d' ' -f1,2 /etc/nexus/ssh/$KEY.pub" | tr -d '\r' | grep '^ssh-ed25519 ' || true)
	[ -n "$pub" ] || die "no public key from the appliance"
	sftpvm "id $USER_ >/dev/null 2>&1 || useradd -m -s /bin/sh $USER_
		install -d -o $USER_ -g $USER_ -m 700 ~$USER_/.ssh ~$USER_/data
		echo 'restrict,command=\"internal-sftp -d /home/$USER_/data\" $pub nexusbackup-$KEY' > ~$USER_/.ssh/authorized_keys
		chown $USER_: ~$USER_/.ssh/authorized_keys && chmod 600 ~$USER_/.ssh/authorized_keys
		rm -rf ~$USER_/data/$BASE_DIR"
	hk=$(ssh-keyscan -t ed25519 "$SFTP_VM" 2>/dev/null | grep -v '^#' | head -1)
	[ -n "$hk" ] || die "no host key of $SFTP_VM"
	r=$(api admin PUT "/tenants/$TENANT" "$(jq -nc --arg h "$SFTP_VM" --arg u "$USER_" --arg k "/etc/nexus/ssh/$KEY" --arg hk "$hk" --arg b "$BASE_DIR" \
		'{offsite:{remote:{type:"sftp", host:$h, port:22, user:$u, key_file:$k, host_key:$hk, base_dir:$b}, uploaders:4}}')")
	if [ "$(status)" = 202 ]; then
		login so "$SO_PW" "$SO_TOTP"
		api so POST "/quorum/$(jq -r .quorum_id <<<"$r")/approve" '{}' >/dev/null
		expect 200 "approve the offsite target"
	else
		expect 200 "offsite target of $TENANT"
	fi
	log "tenant $TENANT: offsite target sftp://$USER_@$SFTP_VM/$BASE_DIR (key $KEY)"
}

step_upload() {
	local r j
	r=$(api admin POST /jobs "$(jq -nc --arg t "$TENANT" '{kind:"offsite", tenant:$t, params:{}}')")
	expect 202 "offsite job"
	j=$(wait_job admin "$(jq -r .id <<<"$r")" 3600)
	[ "$(jq -r .state <<<"$j")" = ok ] || die "offsite: $(jq -r '.log // ""' <<<"$j" | tail -n 15)"
	log "offsite upload ok in $(jq '.finished - .started' <<<"$j") s: $(jq -c '.result // {}' <<<"$j" | cut -c1-300)"
	for _ in $(seq 60); do
		api admin GET "/snapshots?tenant=$TENANT" | jq -e 'any(.[]; .local and .offsite)' >/dev/null && break
		sleep 5
	done
	api admin GET "/snapshots?tenant=$TENANT" | jq -e 'any(.[]; .local and .offsite)' >/dev/null || die "no snapshot local + offsite"
	log "snapshots of $TENANT local + offsite: $(api admin GET "/snapshots?tenant=$TENANT" | jq '[.[] | select(.local and .offsite)] | length')"
}

step_fetch() {
	local s src t r j now
	s=$(api admin GET "/snapshots?tenant=$TENANT" | jq -c '[.[] | select(.local and .offsite)] | max_by(.time)')
	src=$(jq -r .source <<<"$s")
	t=$(jq -r .time <<<"$s")
	[ "$t" != null ] || die "no local+offsite snapshot"
	con "rm -rf /var/lib/nexus/chunkstore/$TENANT/snapshots/$src/$t" >/dev/null
	r=$(api admin POST /jobs "$(jq -nc --arg tn "$TENANT" --arg s "$src" '{kind:"retention", tenant:$tn, params:{source:$s}}')")
	expect 202 "retention job"
	wait_job admin "$(jq -r .id <<<"$r")" 600 >/dev/null
	for _ in $(seq 60); do
		api admin GET "/snapshots?tenant=$TENANT&source=$src" |
			jq -e --argjson t "$t" 'any(.[]; .time == $t and (.local | not) and .offsite)' >/dev/null && break
		sleep 2
	done
	api admin GET "/snapshots?tenant=$TENANT&source=$src" |
		jq -e --argjson t "$t" 'any(.[]; .time == $t and (.local | not) and .offsite)' >/dev/null || die "$src/$t not offsite only"
	log "$src/$t is offsite only (local copy removed in the store)"
	r=$(api admin POST /jobs "$(jq -nc --arg tn "$TENANT" '{kind:"offsite_list", tenant:$tn, params:{}}')")
	expect 202 "offsite_list job"
	j=$(wait_job admin "$(jq -r .id <<<"$r")" 600)
	[ "$(jq -r .state <<<"$j")" = ok ] || die "offsite_list: $(jq -r '.log // ""' <<<"$j" | tail -n 5)"
	jq -e --arg s "$src" --argjson t "$t" '.result.snapshots | any(.[]; .source == $s and .time == $t and (.local | not) and .remote)' <<<"$j" >/dev/null ||
		die "listing: $(jq -c .result <<<"$j" | cut -c1-300)"
	r=$(api admin POST /jobs "$(jq -nc --arg tn "$TENANT" --arg s "$src" --argjson t "$t" '{kind:"offsite_restore", tenant:$tn, params:{source:$s, time:$t}}')")
	expect 202 "offsite_restore job"
	j=$(wait_job admin "$(jq -r .id <<<"$r")" 1800)
	[ "$(jq -r .state <<<"$j")" = ok ] || die "offsite_restore: $(jq -r '.log // ""' <<<"$j" | tail -n 10)"
	now=$(date +%s)
	for _ in $(seq 60); do
		api admin GET "/snapshots?tenant=$TENANT&source=$src" |
			jq -e --argjson t "$t" --argjson n "$now" 'any(.[]; .time == $t and .local and .lock_until >= $n + 6 * 86400)' >/dev/null && break
		sleep 2
	done
	api admin GET "/snapshots?tenant=$TENANT&source=$src" |
		jq -e --argjson t "$t" --argjson n "$now" 'any(.[]; .time == $t and .local and .lock_until >= $n + 6 * 86400)' >/dev/null ||
		die "$src/$t not local again with a 7-day lock"
	log "fetched back in $(jq '.finished - .started' <<<"$j") s, local again, locked for 7 days"
	r=$(api admin POST /jobs "$(jq -nc --arg tn "$TENANT" --arg s "$src" --argjson t "$t" '{kind:"files_list", tenant:$tn, params:{source:$s, time:$t, path:"/"}}')")
	expect 202 "files_list of the fetched snapshot"
	j=$(wait_job admin "$(jq -r .id <<<"$r")" 900)
	[ "$(jq -r .state <<<"$j")" = ok ] || die "files_list: $(jq -r '.log // ""' <<<"$j" | tail -n 10)"
	log "fetched snapshot browsable: $(jq -c '[.result.entries[]?.name]' <<<"$j" | cut -c1-200)"
}

for s in "${@:-target upload fetch}"; do
	for x in $s; do
		log "== $x"
		"step_$x"
	done
done
