#!/usr/bin/env bash
# Appliance end to end in a real VM (no root on the host): the bootc image with
# its real units, users, SELinux enforcing and firewall, driven like M5.
#   e2e.sh image     build localhost/nexus-os:dev (os/Containerfile) + the lab image
#   e2e.sh disk      install the lab image onto $LAB/appliance/appliance.qcow2
#   e2e.sh boot      boot it (lab/appliance/run.sh), wait for the console shell
#   e2e.sh setup     first boot: nexus-setup --script through the real nexus-setup.service
#                    (DHCP on the VM NIC, real nmcli/hostnamectl/systemctl), lab keys in place
#   e2e.sh api [steps]  lab/e2e/m5-api.sh against the VM (PVE lab + SFTP testbox via 10.0.2.2)
#   e2e.sh check     domains (ps -eZ), AVCs, firewall sets, systemd-analyze security
#   e2e.sh all       everything above in order
# env: IMG (localhost/nexus-os:dev; the lab image is $IMG-lab), LAB (/home/ah/nexus-lab), PORT (28443), ROOT (host-side state: $LAB/appliance/root)
# Prereqs: lab/pve/start.sh (pve1 on 127.0.0.1:18006/10022), crates/offsite/testbox/run.sh start.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
LAB=${LAB:-/home/ah/nexus-lab}
export PORT=${PORT:-28443}
IMG=${IMG:-localhost/nexus-os:dev}
export ROOT=${ROOT:-$LAB/appliance/root}
con() { "$here/con.py" "$@"; }
T0=$(date +%s)
log() { printf '[%4ss] %s\n' $(($(date +%s) - T0)) "$*" >&2; }
TESTBOX=${TESTBOX:-$(git -C "$repo" worktree list --porcelain | sed -n "1s/^worktree //p")/target/offsite-testbox}

image() {
	log "building $IMG"
	podman build -f "$repo/os/Containerfile" -t "$IMG" "$repo"
	podman build --build-arg IMAGE="$IMG" -t "$IMG-lab" -f "$here/Containerfile.lab" "$here"
	podman image ls --format '{{.Repository}}:{{.Tag}} {{.Size}}' | grep -F "${IMG%:*}"
}

disk() { "$here/build-disk.sh" "$IMG-lab"; }

boot() {
	"$here/run.sh" stop || true
	"$here/run.sh" start
	log "waiting for the console"
	con wait 600
	log "booted: $(con run 'uname -r; getenforce; bootc status --format=humanreadable 2>/dev/null | head -3' | tr '\n' ' ')"
}

setup() {
	mkdir -p "$ROOT/etc/nexus/tls" "$ROOT/run/api"
	umask 077
	local as so ap sp nic
	as=$(python3 "$repo/lab/e2e/totp.py" --new)
	so=$(python3 "$repo/lab/e2e/totp.py" --new)
	ap="admin-$(head -c 12 /dev/urandom | base64 | tr -d '/+=')"
	sp="so-$(head -c 12 /dev/urandom | base64 | tr -d '/+=')"
	printf "ADMIN_PW='%s'\nADMIN_TOTP='%s'\nSO_PW='%s'\nSO_TOTP='%s'\n" "$ap" "$as" "$sp" "$so" >"$ROOT/secrets.env"
	nic=$(con run 'ls /sys/class/net | grep -v ^lo | head -1' | tr -d '\n')
	log "management NIC $nic"
	local ac sc
	ac=$(python3 "$repo/lab/e2e/totp.py" "$as")
	sc=$(python3 "$repo/lab/e2e/totp.py" "$so")
	# setup consumes these codes: the first API login must wait for the next step
	echo "$ac" >"$ROOT/run/api/admin.lastcode"
	echo "$sc" >"$ROOT/run/api/so.lastcode"
	jq -n --arg nic "$nic" --arg ap "$ap" --arg as "$as" --arg ac "$ac" --arg sp "$sp" --arg so "$so" --arg sc "$sc" \
		'{network: {nic: $nic, method: "dhcp", hostname: "nexus-m5"},
		  admin: {name: "admin", password: $ap, totp_secret: $as, totp_code: $ac},
		  security_officer: {name: "so", password: $sp, totp_secret: $so, totp_code: $sc}}' >"$ROOT/answers.json"

	log "lab keys: PVE node key + known_hosts, SFTP testbox key"
	con run 'install -d -m 0700 /run/nexus-lab' >/dev/null
	con put "$LAB/appliance_ed25519" /etc/nexus/ssh/pve1 0600 >/dev/null
	con put "$TESTBOX/client_ed25519" /etc/nexus/ssh/offsite 0600 >/dev/null
	ssh -o BatchMode=yes -p 10022 -i "$LAB/lab_ed25519" -o UserKnownHostsFile="$LAB/known_hosts" root@localhost \
		cat /etc/ssh/ssh_host_ed25519_key.pub | awk '{print "[10.0.2.2]:10022 " $1 " " $2}' >"$ROOT/known_hosts"
	con put "$ROOT/known_hosts" /etc/nexus/ssh/known_hosts 0644 >/dev/null
	con run 'chown nexus-chunkstore: /etc/nexus/ssh/pve1 /etc/nexus/ssh/offsite && restorecon -RF /etc/nexus/ssh && ls -lZ /etc/nexus/ssh'

	log "first boot: nexus-setup.service with --script (drop-in in /run, lab only)"
	con put "$ROOT/answers.json" /etc/nexus/lab-answers.json 0600 >/dev/null
	rm -f "$ROOT/answers.json"
	con run 'mkdir -p /run/systemd/system/nexus-setup.service.d && printf "[Service]\nExecStart=\nExecStart=/usr/libexec/nexus/nexus-setup --script /etc/nexus/lab-answers.json\nStandardInput=null\nStandardOutput=journal\nTTYReset=no\nTTYVHangup=no\nTTYVTDisallocate=no\n" > /run/systemd/system/nexus-setup.service.d/lab.conf && systemctl daemon-reload' >/dev/null
	local t0
	t0=$(date +%s)
	con run 'systemctl restart nexus-setup.service; echo "setup exit: $?"; rm -f /etc/nexus/lab-answers.json; rm -rf /run/systemd/system/nexus-setup.service.d; systemctl daemon-reload' 300
	log "setup took $(($(date +%s) - t0)) s"
	con run 'journalctl -u nexus-setup -o cat --no-pager | grep -v "^RECOVERY\|^ *[0-9A-Z]\{4\}-" | tail -n 25; ls -l /var/lib/nexus /etc/nexus /etc/nexus/tls; systemctl is-active nexus-keyd nexus-web-api nexus-scheduler'
	con get /etc/nexus/tls/cert.pem >"$ROOT/etc/nexus/tls/cert.pem"
	con get /etc/nexus/metrics-token >"$ROOT/etc/nexus/metrics-token"
	curl -sf --cacert "$ROOT/etc/nexus/tls/cert.pem" --resolve "nexus-m5:$PORT:127.0.0.1" "https://nexus-m5:$PORT/health" &&
		log "web-api reachable from the host with TLS (cert verified)"
}

api() {
	APPL_HOST=10.0.2.2 APPL_SSH_KEY=/etc/nexus/ssh/pve1 APPL_KNOWN_HOSTS=/etc/nexus/ssh/known_hosts \
		APPL_OFFSITE_KEY=/etc/nexus/ssh/offsite TESTBOX=$TESTBOX "$repo/lab/e2e/m5-api.sh" "$@"
}

check() {
	con run 'getenforce; echo "== domains"; ps -e -o label,user,pid,comm | grep -E "nexus|keyd|qemu" | grep -v grep
echo "== permissive types in the loaded policy (nexus: none expected)"; cd /tmp && semodule -E permissivedomains >/dev/null && grep -c typepermissive permissivedomains.cil; grep nexus permissivedomains.cil; rm -f permissivedomains.cil; semodule -l | grep -i nexus
echo "== AVCs since boot (ausearch)"; ausearch -m avc,user_avc,selinux_err -ts boot 2>&1 | tail -n 20
echo "== nft sets"; nft list set inet nexus allowed_out_v4; nft list set inet nexus dns_servers_v4; nft list set inet nexus nts_servers_v4
echo "== security"; for u in nexus-keyd nexus-web-api nexus-scheduler nexus-setup nexus-nft-sync; do printf "%s " $u; systemd-analyze security $u.service 2>/dev/null | tail -1; done' 300
}

case ${1:-} in
image | disk | boot | setup | check) "$1" ;;
api) shift; api "$@" ;;
all)
	image
	disk
	boot
	setup
	api
	check
	;;
*) sed -n '2,14p' "$0" >&2; exit 2 ;;
esac
