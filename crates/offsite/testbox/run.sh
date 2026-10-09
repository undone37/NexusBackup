#!/usr/bin/env bash
# Storage-Box-like SFTP server in rootless podman, for crates/offsite/tests/sftp.rs.
#   run.sh start    build image (cached), generate keys, start on 127.0.0.1:$PORT
#   run.sh stop     remove the container (keys stay)
#   run.sh restart  restart the container (same keys, same data)
#   run.sh drop     kill all SFTP sessions of the tenant (simulates dropped connections)
#   run.sh env      print `export NEXUS_TESTBOX_*=...` lines for the tests
# Usage: crates/offsite/testbox/run.sh start && eval "$(crates/offsite/testbox/run.sh env)"
#        cargo test -p offsite --test sftp
# env: PORT (default 2223), MAX_CONN (default 10), BASE=<image ref>.
# Keys live in target/offsite-testbox/ (not in git).
# Connection limit vs Hetzner: Hetzner documents "max. 10 simultaneous
# connections" per account but not how an 11th fails. Here an 11th
# *authenticated* connection is refused at publickey auth (keys-cmd.sh counts
# live sessions; racy under simultaneous logins), MaxSessions 1 allows one
# channel per connection, and MaxStartups 10 caps connections that are still
# authenticating. sshd has no global cap on authenticated connections, hence
# the key command.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)
dir=$root/target/offsite-testbox
PORT=${PORT:-2223}
MAX_CONN=${MAX_CONN:-10}
BASE=${BASE:-docker.io/library/debian:trixie}
IMG=localhost/nexus-offsite-testbox:latest
NAME=nexus-offsite-testbox

keys() {
	mkdir -p "$dir/hostkey"
	chmod 755 "$dir/hostkey"
	[ -f "$dir/hostkey/ssh_host_ed25519_key" ] ||
		ssh-keygen -q -t ed25519 -N '' -C testbox-host -f "$dir/hostkey/ssh_host_ed25519_key"
	[ -f "$dir/client_ed25519" ] || ssh-keygen -q -t ed25519 -N '' -C testbox-client -f "$dir/client_ed25519"
	install -m 0644 "$dir/client_ed25519.pub" "$dir/hostkey/client.pub"
}

known_hosts() {
	echo "[127.0.0.1]:$PORT $(cut -d' ' -f1,2 "$dir/hostkey/ssh_host_ed25519_key.pub")"
}

wait_ready() {
	for _ in $(seq 50); do
		ssh-keyscan -T 1 -p "$PORT" 127.0.0.1 2>/dev/null | grep -q ssh-ed25519 && return 0
		sleep 0.2
	done
	echo "run.sh: server did not come up; podman logs $NAME:" >&2
	podman logs "$NAME" >&2 || true
	return 1
}

case ${1:-} in
start)
	keys
	podman build -q --build-arg BASE="$BASE" -t "$IMG" -f "$here/Containerfile" "$here" >/dev/null
	podman rm -f "$NAME" >/dev/null 2>&1 || true
	podman run -d --name "$NAME" -e MAX_CONN="$MAX_CONN" -p "127.0.0.1:$PORT:22" \
		-v "$dir/hostkey:/etc/ssh/hostkey:ro,Z" "$IMG" >/dev/null
	wait_ready
	echo "testbox up on 127.0.0.1:$PORT (max $MAX_CONN connections); known_hosts line:"
	known_hosts
	;;
stop) podman rm -f "$NAME" >/dev/null 2>&1 || true ;;
restart)
	podman stop -t 2 "$NAME" >/dev/null
	# pasta may still hold the published port for a moment after stop
	for _ in $(seq 50); do
		podman start "$NAME" >/dev/null 2>&1 && break
		sleep 0.2
	done
	wait_ready
	;;
drop) podman exec "$NAME" pkill -u tenant || true ;;
env)
	[ -f "$dir/hostkey/ssh_host_ed25519_key.pub" ] || {
		echo "run.sh: no keys yet, run '$0 start' first" >&2
		exit 1
	}
	cat <<-EOF
		export NEXUS_TESTBOX_HOST=127.0.0.1
		export NEXUS_TESTBOX_PORT=$PORT
		export NEXUS_TESTBOX_USER=tenant
		export NEXUS_TESTBOX_KEY='$dir/client_ed25519'
		export NEXUS_TESTBOX_KNOWN_HOSTS='$(known_hosts)'
		export NEXUS_TESTBOX_MAX_CONN=$MAX_CONN
		export NEXUS_TESTBOX_CTL='$here/run.sh'
	EOF
	;;
*)
	sed -n '2,18p' "$0" >&2
	exit 2
	;;
esac
