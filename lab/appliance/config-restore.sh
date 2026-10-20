#!/usr/bin/env bash
# Appliance configuration backup and restore on a replacement appliance (docs/control-plane.md
# "Configuration backup", manual chapter 14 "New appliance from a configuration backup").
# VM A = the standard lab appliance (lab/appliance/e2e.sh all: tenant lab with the SFTP testbox
# as offsite target, backups uploaded); VM B = a fresh install of the same lab image.
#   config-restore.sh backup    A: Settings -> Run now (config_backup + config_upload), the bundle on
#                               the testbox (config/<id>/<t>.bundle), download it, A's recovery key
#                               from the setup journal (lab only)
#   config-restore.sh fresh     B: install + boot a fresh appliance (no first boot setup)
#   config-restore.sh restore   B: nexus-setup restore-config --offsite (the testbox, a key the box
#                               accepts) with A's recovery key; services up; A's admin signs in on B;
#                               config_rekey restores tenant lab's keys; its snapshots show offsite
#   config-restore.sh restore-file  as restore, from the downloaded bundle instead of the testbox
#   config-restore.sh check     B: AVCs, domains (e2e.sh check)
#   config-restore.sh stop      power off B
# Not covered here (by hand, at the VM console): the wizard path, "b" on the overview (TUI).
# env: LAB (A's lab dir, /home/ah/nexus-lab), PORT (A: 28443), LAB_B ($LAB/cfg-b), PORT_B (28444),
#      IMG (localhost/nexus-os:dev; the lab image is $IMG-lab), TESTBOX (as e2e.sh)
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
LAB=${LAB:-/home/ah/nexus-lab}
LAB_A=$LAB
PORT_A=${PORT:-28443}
LAB_B=${LAB_B:-$LAB/cfg-b}
PORT_B=${PORT_B:-28444}
IMG=${IMG:-localhost/nexus-os:dev}
TESTBOX=${TESTBOX:-$(git -C "$repo" worktree list --porcelain | sed -n "1s/^worktree //p")/target/offsite-testbox}
T0=$(date +%s)
log() { printf '[%4ss] %s\n' $(($(date +%s) - T0)) "$*" >&2; }
die() {
	log "FAIL: $*"
	exit 1
}
con() { "$here/con.py" "$@"; }
vm() { # vm a|b -> LAB PORT ROOT CONSOLE for run.sh / con.py / api-lib.sh
	case $1 in
	a) export LAB=$LAB_A PORT=$PORT_A ;;
	b) export LAB=$LAB_B PORT=$PORT_B ;;
	esac
	export ROOT=$LAB/appliance/root CONSOLE=$LAB/appliance/console.sock
}
apienv() {
	vm "$1"
	S=$ROOT/run/api
	mkdir -p "$S"
	# shellcheck disable=SC1091
	. "$ROOT/secrets.env"
	# shellcheck source=lab/e2e/api-lib.sh
	. "$repo/lab/e2e/api-lib.sh"
}
A_ROOT=$LAB_A/appliance/root

backup() {
	(
		apienv a
		login admin "$ADMIN_PW" "$ADMIN_TOTP"
		r=$(api admin POST /settings/config-backup/run)
		expect 202 "config backup: run now"
		j=$(wait_job admin "$(jq -r .job_id <<<"$r")" 600)
		[ "$(jq -r .state <<<"$j")" = ok ] || die "config_backup: $(jq -r .log <<<"$j" | tail -n 20)"
		log "A: bundle: $(jq -c .result <<<"$j")"
		for _ in $(seq 120); do
			st=$(api admin GET /settings/config-backup | jq -r '.targets[] | select(.tenant=="lab") | .last.state // "none"')
			[ "$st" = ok ] && break
			[ "$st" = failed ] && die "config_upload failed: $(api admin GET /settings/config-backup | jq -c .targets)"
			sleep 1
		done
		[ "$st" = ok ] || die "config_upload to the testbox: $st"
		api admin GET /settings/config-backup | jq -c '{appliance_id, last_success, latest, targets}' >&2
		api admin GET /settings/config-backup/download >"$A_ROOT/config.bundle"
		expect 200 "download"
		head -c 8 "$A_ROOT/config.bundle" | grep -q NXCFGB1 || die "download is not a bundle"
		log "A: downloaded $(stat -c %s "$A_ROOT/config.bundle") bytes"
		# the download is audited, the sealed bundle holds no plaintext key file
		api admin GET '/audit?action=download.get' | jq -e '[.[] | select(.target | startswith("config_backup/"))] | length >= 1' >/dev/null ||
			log "WARN: no download.get audit entry found (check the audit filter syntax)"
	)
	find "$TESTBOX" -path '*/config/*' -name '*.bundle' -printf '%p %s\n' 2>/dev/null | tail -n 3 >&2 || true
	vm a
	con run 'journalctl -u nexus-setup -o cat --no-pager | sed -n "s/^RECOVERY KEY[^:]*: //p" | tail -n 1' | tr -d '\r\n' >"$A_ROOT/recovery.key"
	[ -s "$A_ROOT/recovery.key" ] || die "A's recovery key not found in the setup journal"
	log "A: recovery key saved for the lab ($A_ROOT/recovery.key)"
}

fresh() {
	vm b
	mkdir -p "$LAB_B/appliance/work"
	# reuse A's installer root if it is current (as replication.sh does)
	if [ ! -f "$LAB_B/appliance/work/installer.raw" ] && [ -f "$LAB_A/appliance/work/installer.raw" ]; then
		cp --sparse=always "$LAB_A/appliance/work/installer."{raw,vmlinuz,initrd,id} "$LAB_B/appliance/work/"
	fi
	for f in appliance_ed25519 appliance_ed25519.pub lab_ed25519 lab_ed25519.pub known_hosts api-token; do
		ln -sfn "$LAB_A/$f" "$LAB_B/$f"
	done
	"$here/build-disk.sh" "$IMG-lab" "$LAB_B/appliance/appliance.qcow2"
	"$here/run.sh" stop || true
	"$here/run.sh" start
	con wait 600
	log "B booted: $(con run 'getenforce; ls /var/lib/nexus/setup-done 2>&1' | tr '\n' ' ')"
}

# restore on B: $1 = offsite | file
restore_b() {
	vm b
	mkdir -p "$ROOT/etc/nexus/tls" "$ROOT/run/api"
	# the wizard owns the setup lock on tty1: stop it (the lab console shell is root)
	con run 'systemctl stop nexus-setup.service; systemctl is-active nexus-setup.service || true' >/dev/null
	con put "$TESTBOX/client_ed25519" /root/restore.key 0600 >/dev/null
	con put "$A_ROOT/recovery.key" /root/rk 0600 >/dev/null
	local hk
	hk="[10.0.2.2]:2223 $(cut -d' ' -f1,2 "$TESTBOX/hostkey/ssh_host_ed25519_key.pub")"
	if [ "$1" = offsite ]; then
		jq -n --arg hk "$hk" '{remote:{type:"sftp", host:"10.0.2.2", port:2223, user:"tenant", key_file:"/root/restore.key", host_key:$hk, base_dir:"m5"}}' >"$ROOT/target.json"
		con put "$ROOT/target.json" /root/target.json 0600 >/dev/null
		con run 'nexus-setup restore-config --offsite /root/target.json < /root/rk; echo "exit $?"' 600
	else
		con put "$A_ROOT/config.bundle" /root/config.bundle 0600 >/dev/null
		con run 'nexus-setup restore-config /root/config.bundle < /root/rk; echo "exit $?"' 600
	fi
	con run 'rm -f /root/rk /root/restore.key; ls -l /var/lib/nexus/setup-done; systemctl is-active nexus-keyd nexus-web-api nexus-scheduler nexus-replicad
ls -lZ /var/lib/nexus/webapi /var/lib/nexus/scheduler /etc/nexus/ssh /etc/nexus/tls /var/lib/nexus/keyd' 120
	# B now has A's TLS identity: the host trusts it with A's certificate
	cp "$A_ROOT/etc/nexus/tls/cert.pem" "$ROOT/etc/nexus/tls/cert.pem"
	cp "$A_ROOT/secrets.env" "$ROOT/secrets.env"
	(
		apienv b
		login admin "$ADMIN_PW" "$ADMIN_TOTP"
		api admin GET /tenants | jq -c '[.[] | .name]' >&2
		for _ in $(seq 300); do
			st=$(api admin GET /jobs | jq -r '[.[] | select(.kind=="config_rekey")][0].state // "none"')
			case $st in ok | failed | cancelled) break ;; esac
			sleep 2
		done
		if [ "$st" != ok ]; then
			j=$(api admin GET /jobs | jq -r '[.[] | select(.kind=="config_rekey")][0].id')
			die "config_rekey: $st: $(api admin GET "/jobs/$j" | jq -r .log | tail -15)"
		fi
		log "B: tenant keys restored from the offsite escrow"
		api admin GET '/snapshots?tenant=lab' | jq -r '.[] | "  \(.source) \(.time) local=\(.local) offsite=\(.offsite)"' >&2
		api admin GET '/snapshots?tenant=lab' | jq -e '[.[] | select(.offsite)] | length > 0' >/dev/null ||
			die "no offsite snapshots of tenant lab on B"
		api admin GET '/audit?action=setup.restore_config' | jq -c '.[0].details' >&2 || true
	)
	log "restore on B ok: fetch a snapshot back (Snapshots -> Fetch from offsite) and restore it as usual"
}

check() {
	vm b
	"$here/e2e.sh" check
}

case ${1:-} in
backup | fresh | check) "$1" ;;
restore) restore_b offsite ;;
restore-file) restore_b file ;;
stop) vm b && "$here/run.sh" stop ;;
*) sed -n '2,17p' "$0" >&2; exit 2 ;;
esac
