#!/usr/bin/env bash
# M5 end-to-end harness: the appliance's control plane as the current user
# under a scratch root (no root, no sudo, no host packages).
#   m5.sh setup   fresh scratch root + nexus-setup --script (admin + security officer with TOTP,
#                 keyd init, TLS, metrics token, setup-done); secrets in $ROOT/secrets.env (0600)
#   m5.sh start   keyd serve, nexus-web-api (https://127.0.0.1:$PORT), nexus-scheduler (tick 5 s)
#   m5.sh stop    stop the three processes
#   m5.sh env     print exports for lab/e2e/m5-api.sh
#   m5.sh all     setup + start + lab/e2e/m5-api.sh + lab/e2e/m5-ui.mjs (headless Chrome)
# Then: lab/e2e/m5-api.sh (REST flow against the nested PVE lab + SFTP testbox).
# env: ROOT (default target/m5-root), PORT (18443), BIN (target/release),
#      NEXUS_RESTORE_VM_DIR (default target/restore-vm, built by restore-vm/build.sh).
# Logs: $ROOT/log/*.log. Build first:
#   (cd web && npm ci --ignore-scripts && npm run build)
#   cargo build --release -p keyd -p pve -p offsite -p web-api -p scheduler -p setup -p agent-conn
# Linux agents (lab/linux/e2e.sh): signed agent bundles for `agent_update` go to $ROOT/agent-update.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
ROOT=${ROOT:-$repo/target/m5-root}
PORT=${PORT:-18443}
BIN=${BIN:-$repo/target/release}
RVM=${NEXUS_RESTORE_VM_DIR:-$repo/target/restore-vm}
[ -f "$RVM/vmlinuz" ] || RVM=$(git -C "$repo" worktree list --porcelain | sed -n "1s/^worktree //p")/target/restore-vm # main checkout
lib=$ROOT/var/lib/nexus
etc=$ROOT/etc/nexus

setup() {
	if [ -e "$ROOT" ]; then
		stop || true
		chmod -R u+w "$ROOT" 2>/dev/null || true
		rm -rf "$ROOT"
	fi
	mkdir -p "$ROOT/log" "$ROOT/run" "$etc" "$lib/catalog"
	umask 077
	local as so ap sp
	as=$(python3 "$here/totp.py" --new)
	so=$(python3 "$here/totp.py" --new)
	ap="admin-$(head -c 12 /dev/urandom | base64 | tr -d '/+=')"
	sp="so-$(head -c 12 /dev/urandom | base64 | tr -d '/+=')"
	cat >"$ROOT/secrets.env" <<-EOF
		ADMIN_PW='$ap'
		ADMIN_TOTP='$as'
		SO_PW='$sp'
		SO_TOTP='$so'
	EOF
	# answers on tmpfs-like scratch, deleted right after use
	local ans=$ROOT/run/answers.json
	cat >"$ans" <<-EOF
		{"network": {"nic": "eth0", "method": "static", "address": "192.0.2.10", "prefix": 24, "hostname": "nexus-m5"},
		 "admin": {"name": "admin", "password": "$ap", "totp_secret": "$as", "totp_code": "$(python3 "$here/totp.py" "$as")"},
		 "security_officer": {"name": "so", "password": "$sp", "totp_secret": "$so", "totp_code": "$(python3 "$here/totp.py" "$so")"}}
	EOF
	"$BIN/nexus-setup" --root "$ROOT" --dry-run --script "$ans" |
		sed 's/^RECOVERY KEY.*/RECOVERY KEY: (shown once, discarded by m5.sh)/' | tee "$ROOT/log/setup.log"
	rm -f "$ans"
	cat >"$etc/scheduler.json" <<-EOF
		{"catalog": "$lib/catalog/catalog.db", "store_base": "$lib/chunkstore",
		 "offsite_state_base": "$lib/offsite", "escrow_base": "$lib/escrow",
		 "keyd_socket": "run/keyd.sock", "downloads": "$lib/downloads",
		 "runtime_dir": "$ROOT/run/scheduler", "state_dir": "$lib/scheduler",
		 "pve_bin": "$BIN/nexus-pve", "offsite_bin": "$BIN/nexus-offsite",
		 "agentctl_bin": "$BIN/nexus-agentctl", "agent_update_dir": "$ROOT/agent-update",
		 "alerts_config": "$etc/alerts.json", "tick_secs": 5, "refresh_secs": 60}
	EOF
}

start() {
	[ -f "$RVM/vmlinuz" ] || echo "warning: no restore micro-VM in $RVM (restore-vm/build.sh): VM file restore will fail" >&2
	cd "$ROOT" # keyd socket path is relative: the unix socket path limit is 108 bytes
	nohup "$BIN/keyd" serve "$lib/keyd" run/keyd.sock "$(id -u)" >log/keyd.log 2>&1 &
	echo $! >run/keyd.pid
	for _ in $(seq 50); do [ -S run/keyd.sock ] && break; sleep 0.1; done
	NEXUS_WEBAPI_LISTEN=127.0.0.1:$PORT NEXUS_CATALOG=$lib/catalog/catalog.db \
		NEXUS_TLS_CERT=$etc/tls/cert.pem NEXUS_TLS_KEY=$etc/tls/key.pem \
		NEXUS_SETUP_DONE=$lib/setup-done NEXUS_METRICS_TOKEN=$etc/metrics-token \
		NEXUS_DOWNLOADS=$lib/downloads NEXUS_TOTP_KEY=$lib/webapi/totp.key \
		NEXUS_SECRETS_PUB=$lib/catalog/secrets.pub \
		nohup "$BIN/nexus-web-api" >log/web-api.log 2>&1 &
	echo $! >run/web-api.pid
	NEXUS_RESTORE_VM_DIR=$RVM nohup "$BIN/nexus-scheduler" --config "$etc/scheduler.json" >log/scheduler.log 2>&1 &
	echo $! >run/scheduler.pid
	# secret writes need the scheduler's public key (published at its start)
	for _ in $(seq 50); do [ -s "$lib/catalog/secrets.pub" ] && break; sleep 0.1; done
	for _ in $(seq 50); do
		curl -skf "https://127.0.0.1:$PORT/health" >/dev/null && break
		sleep 0.1
	done
	echo "keyd $(cat run/keyd.pid), web-api $(cat run/web-api.pid) on https://127.0.0.1:$PORT, scheduler $(cat run/scheduler.pid)"
}

stop() {
	for p in scheduler web-api keyd; do
		[ -f "$ROOT/run/$p.pid" ] && kill "$(cat "$ROOT/run/$p.pid")" 2>/dev/null || true
		rm -f "$ROOT/run/$p.pid"
	done
}

case ${1:-} in
setup) setup ;;
start) start ;;
stop) stop ;;
all)
	setup
	start
	"$here/m5-api.sh"
	export ROOT PORT
	node --experimental-websocket "$here/m5-ui.mjs" "$ROOT/ui" 2>&1 | grep -v ExperimentalWarning
	;;
env)
	echo "export ROOT='$ROOT' PORT=$PORT"
	sed 's/^/export /' "$ROOT/secrets.env"
	;;
*)
	sed -n '2,16p' "$0" >&2
	exit 2
	;;
esac
