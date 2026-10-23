#!/usr/bin/env bash
# PegaProx with the NexusBackup plugin (plan.md Phase 43, integrations/pegaprox) on the PVE lab host: a Debian 13
# VM (clone of the agent VM 225) runs PegaProx from source in a venv, manages pve-test through a read-only PVE
# user, and shows the backups of the appliance VM 201 (deploy.sh lab).
#
#   pegaprox.sh vm        clone and start VM $VMID, host name, new machine id and ssh host keys
#   pegaprox.sh install   PegaProx $REF in /opt/pegaprox (venv), unit pegaprox.service on port 5000 (HTTPS, self-signed)
#   pegaprox.sh setup     first administrator through the setup API (password in $LAB/secrets.env)
#   pegaprox.sh cluster   PVE user pegaprox-lab@pve (role PVEAuditor, read-only) with an API token on the host,
#                         pve-test added as cluster
#   pegaprox.sh plugin    the plugin copied in, config.json (appliance URL, token, certificate pin, cluster
#                         mapping), enabled; TOKEN_SCOPE read (default) or backup, ALLOW_BACKUP 0/1
#   pegaprox.sh check     the plugin's API as the administrator: clusters, guests with their state
#   pegaprox.sh backup    "Back up now" of BACKUP_VMID (200) through the plugin (needs TOKEN_SCOPE=backup ALLOW_BACKUP=1)
#   pegaprox.sh destroy   stop and remove the VM (the PVE user and token stay: `pveum user delete pegaprox-lab@pve`)
#
# env: PVE_HOST (10.2.34.200), SSH_KEY (~/nexus-lab/pve-lab-key), VM_KEY (~/nexus-lab/lab_ed25519), LAB
#      (~/nexus-lab/pegaprox), VMID (270), SRC (225), REF (v1.4.0), APP_LAB (~/nexus-lab/pvehost), APP_PORT (28444),
#      APP_URL (https://10.2.34.211:8443: as PegaProx reaches the appliance), TENANT (lab), SOURCE_ID (1)
set -euo pipefail
PVE_HOST=${PVE_HOST:-10.2.34.200}
SSH_KEY=${SSH_KEY:-$HOME/nexus-lab/pve-lab-key}
VM_KEY=${VM_KEY:-$HOME/nexus-lab/lab_ed25519}
LAB=${LAB:-$HOME/nexus-lab/pegaprox}
VMID=${VMID:-270}
SRC=${SRC:-225}
REF=${REF:-v1.4.0}
APP_LAB=${APP_LAB:-$HOME/nexus-lab/pvehost}
APP_URL=${APP_URL:-https://10.2.34.211:8443}
TENANT=${TENANT:-lab}
SOURCE_ID=${SOURCE_ID:-1}
here=$(cd "$(dirname "$0")" && pwd)
T0=$(date +%s)
log() { printf '[%4ss] %s\n' $(($(date +%s) - T0)) "$*" >&2; }
die() {
	log "FAIL: $*"
	exit 1
}
pve() { ssh -n -i "$SSH_KEY" -o BatchMode=yes "root@$PVE_HOST" "$@" 2> >(grep -v 'older storage API' >&2); }
mkdir -p "$LAB" && chmod 700 "$LAB"
secret() {
	touch "$LAB/secrets.env" && chmod 600 "$LAB/secrets.env"
	grep -q "^$1=" "$LAB/secrets.env" || echo "$1=Px$(head -c 18 /dev/urandom | base64 | tr -dc 'a-zA-Z0-9')7!" >>"$LAB/secrets.env"
	sed -n "s/^$1=//p" "$LAB/secrets.env"
}
ip_() { cat "$LAB/ip"; }
on() {
	ssh -i "$VM_KEY" -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=no \
		-o UserKnownHostsFile=/dev/null -o LogLevel=ERROR "root@$(ip_)" "$@"
}
# PegaProx's API with a session (cookie jar in $LAB) and the headers its CSRF check wants
pp() { # METHOD PATH [JSON]
	local u="https://$(ip_):5000"
	curl -sk -m 60 -b "$LAB/cookies" -c "$LAB/cookies" -X "$1" -H 'Content-Type: application/json' \
		-H 'X-Requested-With: XMLHttpRequest' -H "Origin: $u" -H "Referer: $u/" \
		${3:+--data-binary "$3"} "$u$2"
}

step_vm() {
	if ! pve "qm status $VMID" >/dev/null 2>&1; then
		log "cloning $SRC to $VMID (pegaprox)"
		pve "qm clone $SRC $VMID --full --name pegaprox --storage vmpool >/dev/null &&
			qm set $VMID --memory 2048 --tags nexus-pegaprox-lab --description 'PegaProx lab (lab/pvehost/pegaprox.sh)' >/dev/null &&
			qm start $VMID"
	fi
	local a end=$(($(date +%s) + 600))
	until a=$(pve "qm guest cmd $VMID network-get-interfaces 2>/dev/null" |
		jq -r '[.[] | select(.name != "lo") | .["ip-addresses"][]? | select(.["ip-address-type"] == "ipv4") | .["ip-address"]][0] // empty') && [ -n "$a" ]; do
		[ "$(date +%s)" -lt "$end" ] || die "no address after 10 minutes"
		sleep 10
	done
	echo "$a" >"$LAB/ip"
	on "[ \"\$(hostname)\" = pegaprox ] && exit 0; hostnamectl set-hostname pegaprox
		sed -i 's/^127.0.1.1 .*/127.0.1.1 pegaprox/' /etc/hosts
		rm -f /etc/machine-id /var/lib/dbus/machine-id; systemd-machine-id-setup >/dev/null
		apt-get -qq purge 'nexus-agent*' >/dev/null 2>&1 || true
		rm -f /etc/ssh/ssh_host_*; dpkg-reconfigure -f noninteractive openssh-server >/dev/null 2>&1; systemctl restart ssh" </dev/null
	log "pegaprox: $a"
}

step_install() {
	on "set -e; export DEBIAN_FRONTEND=noninteractive
		apt-get -qq update && apt-get -qq install -y git python3-venv python3-dev build-essential >/dev/null
		[ -d /opt/pegaprox ] || git -c advice.detachedHead=false clone -q --depth 1 --branch $REF \
			https://github.com/PegaProx/project-pegaprox.git /opt/pegaprox
		[ -x /opt/pegaprox/venv/bin/python ] || python3 -m venv /opt/pegaprox/venv
		/opt/pegaprox/venv/bin/pip install -q -r /opt/pegaprox/requirements.txt
		cat > /etc/systemd/system/pegaprox.service <<EOF
[Unit]
Description=PegaProx (lab)
After=network-online.target
[Service]
WorkingDirectory=/opt/pegaprox
Environment=PEGAPROX_PLUGINS_DIR=/opt/pegaprox/plugins
ExecStart=/opt/pegaprox/venv/bin/python pegaprox_multi_cluster.py
Restart=on-failure
[Install]
WantedBy=multi-user.target
EOF
		systemctl daemon-reload; systemctl enable --now pegaprox >/dev/null 2>&1; systemctl restart pegaprox" </dev/null
	local end=$(($(date +%s) + 600))
	until curl -sk -m 5 -o /dev/null "https://$(ip_):5000/"; do
		[ "$(date +%s)" -lt "$end" ] || die "PegaProx does not answer on 5000: $(on 'journalctl -u pegaprox -n 20 --no-pager' </dev/null)"
		sleep 10
	done
	log "PegaProx $REF answers on https://$(ip_):5000"
}

step_setup() {
	local r
	r=$(pp POST /api/auth/setup "$(jq -nc --arg p "$(secret ADMIN_PW)" '{username:"labadmin", password:$p, display_name:"Lab admin"}')")
	log "setup: $(jq -c '{success, error, code}' <<<"$r" 2>/dev/null || echo "$r" | head -c 200)"
}

login() {
	pp POST /api/auth/login "$(jq -nc --arg p "$(secret ADMIN_PW)" '{username:"labadmin", password:$p}')" >/dev/null
}

step_cluster() {
	# read-only on the host, through an API token (its secret is printed once, never on a command line)
	if [ ! -s "$LAB/pve-token.json" ]; then
		pve 'pveum user list --output-format json | grep -q "\"pegaprox-lab@pve\"" ||
			pveum user add pegaprox-lab@pve --comment "PegaProx lab (read-only)"
			pveum acl modify / --users pegaprox-lab@pve --roles PVEAuditor
			pveum user token remove pegaprox-lab@pve pp >/dev/null 2>&1 || true
			pveum user token add pegaprox-lab@pve pp --privsep 0 --output-format json' >"$LAB/pve-token.json"
		chmod 600 "$LAB/pve-token.json"
	fi
	login
	if pp GET /api/clusters | jq -e '.[]? | select(.name == "pve-test")' >/dev/null 2>&1; then
		log "cluster pve-test exists"
		return
	fi
	local r
	# PegaProx wants a password field also with a token
	r=$(pp POST /api/clusters "$(jq -nc --arg h "$PVE_HOST" --slurpfile t "$LAB/pve-token.json" \
		'{name:"pve-test", host:$h, user:"pegaprox-lab@pve", pass:"unused-token-auth", ssl_verification:false,
		  api_token_user:$t[0]["full-tokenid"], api_token_secret:$t[0].value}')")
	log "cluster: $(echo "$r" | head -c 300)"
}

step_plugin() {
	local scope=${TOKEN_SCOPE:-read} cid pin tok
	login
	cid=$(pp GET /api/clusters | jq -r '[.[]? | select(.name == "pve-test") | .id][0] // empty')
	[ -n "$cid" ] || die "no cluster pve-test in PegaProx (pegaprox.sh cluster)"
	pin=$(openssl x509 -in "$APP_LAB/appliance/root/etc/nexus/tls/cert.pem" -outform der | sha256sum | cut -d' ' -f1)
	tok=$(app_token "$scope")
	on "rm -rf /opt/pegaprox/plugins/nexusbackup; mkdir -p /opt/pegaprox/plugins" </dev/null
	tar -C "$here/../../integrations/pegaprox" -cf - nexusbackup | on "tar -C /opt/pegaprox/plugins -xf -"
	jq -n --arg url "$APP_URL" --arg tok "$tok" --arg pin "$pin" --arg cid "$cid" --arg t "$TENANT" \
		--argjson s "$SOURCE_ID" --argjson b "$([ "${ALLOW_BACKUP:-0}" = 1 ] && echo true || echo false)" \
		'{appliances:[{url:$url, token:$tok, cert_sha256:$pin, clusters:{($cid):{tenant:$t, source_id:$s}}}],
		  allow_backup:$b, cache_seconds:30}' | on "umask 077; cat > /opt/pegaprox/plugins/nexusbackup/config.json"
	pp POST /api/plugins/rescan >/dev/null
	log "enable: $(pp POST /api/plugins/nexusbackup/enable | head -c 200)"
	log "plugin: $(pp GET /api/plugins | jq -c '.[] | select(.id == "nexusbackup") | {enabled, loaded, error, has_frontend, frontend_route}')"
}

# a NexusBackup API token of the appliance admin with SCOPE, created once per scope and kept in $LAB
app_token() {
	local f="$LAB/token-$1"
	if [ ! -s "$f" ]; then
		(
			export PORT=${APP_PORT:-28444}
			ROOT=$APP_LAB/appliance/root S=$APP_LAB/appliance/root/run/api
			# shellcheck disable=SC1091
			. "$ROOT/secrets.env"
			# shellcheck source=lab/e2e/api-lib.sh
			. "$here/../e2e/api-lib.sh"
			login admin "$ADMIN_PW" "$ADMIN_TOTP" 2>/dev/null
			api admin POST /auth/tokens "$(jq -nc --arg s "$1" --arg p "$ADMIN_PW" --arg t "$(fresh_code admin "$ADMIN_TOTP")" \
				'{name:("pegaprox-" + $s), scope:$s, days:30, current_password:$p, current_totp:$t}')" | jq -r '.token // empty' >"$f"
		)
		chmod 600 "$f"
	fi
	[ -s "$f" ] || die "no NexusBackup token with scope $1"
	cat "$f"
}

step_check() {
	local cid r
	login
	cid=$(pp GET /api/clusters | jq -r '[.[]? | select(.name == "pve-test") | .id][0] // empty')
	log "clusters: $(pp GET /api/plugins/nexusbackup/api/clusters | head -c 300)"
	r=$(pp GET "/api/plugins/nexusbackup/api/vms?cluster=$cid")
	log "summary: $(jq -c .summary <<<"$r" 2>/dev/null || echo "$r" | head -c 300)"
	jq -r '.vms[]? | "  \(.vmid) \(.name): \(.state)  last \(.last_backup.time // "-")  group \(.group.name // "-")"' <<<"$r" | head -30 >&2
}

step_backup() { # VMID (default 200): "Back up now" through PegaProx, then the job on the appliance
	local cid r vm=${BACKUP_VMID:-200}
	login
	cid=$(pp GET /api/clusters | jq -r '[.[]? | select(.name == "pve-test") | .id][0] // empty')
	# a GET must not start anything
	log "GET backup: $(pp GET /api/plugins/nexusbackup/api/backup | head -c 120)"
	r=$(pp POST /api/plugins/nexusbackup/api/backup "$(jq -nc --arg c "$cid" --argjson v "$vm" '{cluster:$c, vmid:$v}')")
	log "POST backup of $vm: $r"
}

step_destroy() {
	pve "qm stop $VMID 2>/dev/null; qm destroy $VMID --purge 2>/dev/null" || true
	rm -f "$LAB/ip" "$LAB/cookies"
	log "VM $VMID removed"
}

for s in "$@"; do
	"step_$s"
done
