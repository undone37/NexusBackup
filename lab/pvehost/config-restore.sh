#!/usr/bin/env bash
# Configuration backup of the PVE lab appliance VM 201 (A) and its restore on a fresh appliance VM 203 (B) from the
# offsite target (docs/control-plane.md "Configuration backup", manual chapter 14 "New appliance from a configuration
# backup"; #62). lab/appliance/config-restore.sh is the same for local QEMU VMs. The offsite target is the SFTP account
# of lab/pvehost/offsite.sh on the regression VM; B gets a DHCP address (the OS network configuration is not part of
# the restore, so B never takes over A's address). After the restore B acts as A (same sources and schedules): keep
# the run short and remove B (step cleanup).
#
#   config-restore.sh backup    A: config backup now, uploaded to the offsite target of $TENANT, A's recovery key
#   config-restore.sh fresh     B: VM 203 from the lab disk, booted, no first-boot setup; its DHCP address, tunnel
#   config-restore.sh restore   B: a restore key the SFTP account accepts, `nexus-setup restore-config --offsite` with
#                               A's recovery key; A's admin signs in on B; the tenant keys come back from offsite
#                               (config_rekey), $TENANT's snapshots show offsite
#   config-restore.sh cleanup   B stopped and destroyed, the restore key removed from the SFTP account
#
# env: A_LAB (~/nexus-lab/pvehost), A_PORT (28444), B_LAB (~/nexus-lab/pvehost3), B_PORT (28446), DISK (the lab disk,
#      ~/nexus-lab/pvehost2/appliance/appliance.qcow2), TENANT (windows), SFTP_VM (10.2.34.99), USER_ (nexusoff),
#      BASE_DIR (nexus-201), VM_KEY, PVE_HOST, SSH_KEY
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
A_LAB=${A_LAB:-$HOME/nexus-lab/pvehost}
A_PORT=${A_PORT:-28444}
B_LAB=${B_LAB:-$HOME/nexus-lab/pvehost3}
B_PORT=${B_PORT:-28446}
DISK=${DISK:-$HOME/nexus-lab/pvehost2/appliance/appliance.qcow2}
TENANT=${TENANT:-windows}
SFTP_VM=${SFTP_VM:-10.2.34.99}
USER_=${USER_:-nexusoff}
BASE_DIR=${BASE_DIR:-nexus-201}
VM_KEY=${VM_KEY:-$HOME/nexus-lab/lab_ed25519}
PVE_HOST=${PVE_HOST:-10.2.34.200}
SSH_KEY=${SSH_KEY:-$HOME/nexus-lab/pve-lab-key}
VMID_B=203
T0=$(date +%s)
log() { printf '[%4ss] %s\n' $(($(date +%s) - T0)) "$*" >&2; }
die() {
	log "FAIL: $*"
	exit 1
}
pve() { ssh -n -i "$SSH_KEY" -o BatchMode=yes "root@$PVE_HOST" "$@"; }
sftpvm() { ssh -i "$VM_KEY" -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR \
	-o ConnectTimeout=10 "root@$SFTP_VM" "$@"; }
mkdir -p "$B_LAB/appliance/root/run/api" "$B_LAB/appliance/root/etc/nexus/tls"
apienv() { # apienv a|b (in a subshell): the appliance's API as A's admin (B holds A's configuration after the restore)
	export LAB PORT
	[ "$1" = a ] && LAB=$A_LAB PORT=$A_PORT || LAB=$B_LAB PORT=$B_PORT
	ROOT=$LAB/appliance/root
	S=$ROOT/run/api
	mkdir -p "$S"
	# shellcheck disable=SC1091
	. "$A_LAB/appliance/root/secrets.env"
	# shellcheck source=lab/e2e/api-lib.sh
	. "$repo/lab/e2e/api-lib.sh"
}
conb() { CONSOLE=$B_LAB/appliance/console.sock "$repo/lab/appliance/con.py" "$@"; }

step_backup() {
	(
		apienv a
		login admin "$ADMIN_PW" "$ADMIN_TOTP"
		r=$(api admin POST /settings/config-backup/run)
		expect 202 "config backup: run now"
		j=$(wait_job admin "$(jq -r .job_id <<<"$r")" 600)
		[ "$(jq -r .state <<<"$j")" = ok ] || die "config_backup: $(jq -r '.log // ""' <<<"$j" | tail -n 10)"
		st=
		for _ in $(seq 120); do
			st=$(api admin GET /settings/config-backup | jq -r --arg t "$TENANT" '.targets[] | select(.tenant == $t) | .last.state // "none"')
			[ "$st" = ok ] && break
			[ "$st" = failed ] && die "config_upload failed: $(api admin GET /settings/config-backup | jq -c .targets)"
			sleep 2
		done
		[ "$st" = ok ] || die "config_upload to the offsite target of $TENANT: $st"
		log "A: configuration backup uploaded: $(api admin GET /settings/config-backup | jq -c '{appliance_id, latest}')"
	)
	CONSOLE=$A_LAB/appliance/console.sock "$repo/lab/appliance/con.py" run \
		'journalctl -u nexus-setup -o cat --no-pager | sed -n "s/^RECOVERY KEY[^:]*: //p" | tail -n 1' | tr -d '\r\n' >"$A_LAB/appliance/root/recovery.key"
	chmod 600 "$A_LAB/appliance/root/recovery.key"
	[ -s "$A_LAB/appliance/root/recovery.key" ] || die "A's recovery key not found in its setup journal"
	log "A: recovery key saved for the lab"
}

step_fresh() {
	local ip=
	pve "qm status $VMID_B" >/dev/null 2>&1 && die "VM $VMID_B exists (step cleanup)"
	scp -q -i "$SSH_KEY" "$DISK" "root@$PVE_HOST:/var/lib/vz/import/nexus-appliance-b.qcow2"
	pve "qm create $VMID_B --name nexus-appliance-restore --machine q35 --cpu host --cores 4 --memory 8192 --balloon 0 \
		--scsihw virtio-scsi-single --scsi0 vmpool:0,import-from=local:import/nexus-appliance-b.qcow2,discard=on,iothread=1,ssd=1 \
		--net0 virtio,bridge=vmbr0 --serial0 socket --vga std --rng0 source=/dev/urandom --boot order=scsi0 \
		--description 'NexusBackup appliance (lab: config restore, lab/pvehost/config-restore.sh)' >/dev/null &&
		qm start $VMID_B && rm -f /var/lib/vz/import/nexus-appliance-b.qcow2"
	# the serial console through the PVE host (as deploy.sh tunnel)
	rm -f "$B_LAB/appliance/console.sock"
	ssh -i "$SSH_KEY" -o BatchMode=yes -o ExitOnForwardFailure=yes -o StreamLocalBindUnlink=yes -f -N -M \
		-S "$B_LAB/appliance/tunnel.ctl" -L "$B_LAB/appliance/console.sock:/var/run/qemu-server/$VMID_B.serial0" "root@$PVE_HOST"
	conb wait 600
	for _ in $(seq 30); do
		ip=$(conb run "ip -4 -o addr show scope global | awk '{print \$4}' | cut -d/ -f1 | head -1" | tr -d '\r' | grep -E '^[0-9.]+$' || true)
		[ -n "$ip" ] && break
		sleep 5
	done
	[ -n "$ip" ] || die "B has no address (DHCP)"
	echo "$ip" >"$B_LAB/appliance/ip"
	ssh -S "$B_LAB/appliance/tunnel.ctl" -O forward -L "127.0.0.1:$B_PORT:$ip:8443" "root@$PVE_HOST"
	log "B (VM $VMID_B) booted, not set up, DHCP address $ip, tunnel 127.0.0.1:$B_PORT"
}

step_restore() {
	local hk
	# a restore key the SFTP account accepts (next to the appliance's offsite key)
	rm -f "$B_LAB/appliance/restore.key" "$B_LAB/appliance/restore.key.pub"
	ssh-keygen -q -t ed25519 -N '' -C nexus-restore-lab -f "$B_LAB/appliance/restore.key"
	sftpvm "grep -v nexus-restore-lab ~$USER_/.ssh/authorized_keys > /tmp/ak; echo 'restrict,command=\"internal-sftp -d /home/$USER_/data\" $(cut -d' ' -f1,2 "$B_LAB/appliance/restore.key.pub") nexus-restore-lab' >> /tmp/ak; install -o $USER_ -g $USER_ -m 600 /tmp/ak ~$USER_/.ssh/authorized_keys; rm /tmp/ak"
	hk=$(ssh-keyscan -t ed25519 "$SFTP_VM" 2>/dev/null | grep -v '^#' | head -1)
	jq -n --arg h "$SFTP_VM" --arg u "$USER_" --arg hk "$hk" --arg b "$BASE_DIR" \
		'{remote:{type:"sftp", host:$h, port:22, user:$u, key_file:"/root/restore.key", host_key:$hk, base_dir:$b}}' >"$B_LAB/appliance/target.json"
	conb run 'systemctl stop nexus-setup.service; true' >/dev/null
	conb put "$B_LAB/appliance/restore.key" /root/restore.key 0600 >/dev/null
	conb put "$A_LAB/appliance/root/recovery.key" /root/rk 0600 >/dev/null
	conb put "$B_LAB/appliance/target.json" /root/target.json 0600 >/dev/null
	conb run 'nexus-setup restore-config --offsite /root/target.json < /root/rk; echo "exit $?"' 600 | tail -n 8 >&2
	conb run 'rm -f /root/rk /root/restore.key /root/target.json; ls /var/lib/nexus/setup-done; systemctl is-active nexus-keyd nexus-web-api nexus-scheduler' 120 | tail -n 4 >&2
	# B now serves A's certificate (restored) behind its own tunnel
	cp "$A_LAB/appliance/root/etc/nexus/tls/cert.pem" "$B_LAB/appliance/root/etc/nexus/tls/cert.pem"
	(
		apienv b
		for _ in $(seq 60); do
			curl -s -o /dev/null --max-time 5 --cacert "$ROOT/etc/nexus/tls/cert.pem" --resolve "nexus-m5:$PORT:127.0.0.1" "$BASE/health" && break
			sleep 5
		done
		login admin "$ADMIN_PW" "$ADMIN_TOTP"
		log "B: A's admin signs in on B"
		j=
		for _ in $(seq 60); do
			j=$(api admin GET '/jobs?kind=config_rekey&limit=5' | jq -c '[.[] | select(.state == "ok" or .state == "failed")][0] // empty')
			[ -n "$j" ] && break
			sleep 10
		done
		[ -n "$j" ] || die "no finished config_rekey job on B"
		[ "$(jq -r .state <<<"$j")" = ok ] || die "config_rekey: $(jq -c . <<<"$j" | cut -c1-400)"
		log "B: tenant keys restored from offsite (config_rekey job $(jq -r .id <<<"$j"))"
		for _ in $(seq 60); do
			api admin GET "/snapshots?tenant=$TENANT" | jq -e 'any(.[]; .offsite)' >/dev/null && break
			sleep 5
		done
		api admin GET "/snapshots?tenant=$TENANT" | jq -e 'any(.[]; .offsite)' >/dev/null || die "no offsite snapshot of $TENANT on B"
		log "B: $TENANT's snapshots: $(api admin GET "/snapshots?tenant=$TENANT" | jq -c '[.[] | {time, local, offsite}]')"
	)
}

step_cleanup() {
	pve "qm stop $VMID_B >/dev/null 2>&1; qm destroy $VMID_B --purge >/dev/null 2>&1" || true
	ssh -S "$B_LAB/appliance/tunnel.ctl" -O exit "root@$PVE_HOST" 2>/dev/null || true
	sftpvm "grep -v nexus-restore-lab ~$USER_/.ssh/authorized_keys > /tmp/ak; install -o $USER_ -g $USER_ -m 600 /tmp/ak ~$USER_/.ssh/authorized_keys; rm /tmp/ak" || true
	rm -f "$B_LAB/appliance/restore.key" "$B_LAB/appliance/restore.key.pub" "$A_LAB/appliance/root/recovery.key"
	log "VM $VMID_B removed, restore key removed from the SFTP account"
}

for s in "${@:-backup fresh restore cleanup}"; do
	for x in $s; do
		log "== $x"
		"step_$x"
	done
done
