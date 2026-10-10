#!/usr/bin/env bash
# PostgreSQL testbox in rootless podman, for plugins/postgresql/tests/pg.rs.
#   run.sh start   build the image (cached), generate keys + TLS cert (once), start
#                  `main` (the source; TLS, role `nexus` with REPLICATION, CREATEDB +
#                  pg_read_all_data, sshd for postgres on $SSH_PORT) on 127.0.0.1:$PORT
#                  and `alt` (alternate restore server) on 127.0.0.1:$ALT_PORT
#   run.sh stop    remove both containers (all data goes with them)
#   run.sh env     print `export NEXUS_PG_*=...` lines
# The test starts the testbox itself when podman is available (NEXUS_PG_TESTBOX=skip
# disables it). env: PG (major version, default 17), PORT (15432), ALT_PORT (15433),
# SSH_PORT (12222). Keys, cert and passwords live in target/pg-testbox/ (not in git).
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)
dir=$root/target/pg-testbox
PG=${PG:-17}
PORT=${PORT:-15432}
ALT_PORT=${ALT_PORT:-15433}
SSH_PORT=${SSH_PORT:-12222}
IMG=localhost/nexus-pg-testbox:$PG
NAME=nexus-pg-testbox

secrets() {
	mkdir -p "$dir/box"
	chmod 700 "$dir"
	[ -f "$dir/box/ssh_host_ed25519_key" ] ||
		ssh-keygen -q -t ed25519 -N '' -C pg-testbox-host -f "$dir/box/ssh_host_ed25519_key"
	[ -f "$dir/client_ed25519" ] || ssh-keygen -q -t ed25519 -N '' -C pg-testbox-client -f "$dir/client_ed25519"
	install -m 0644 "$dir/client_ed25519.pub" "$dir/box/client_ed25519.pub"
	if [ ! -f "$dir/ca.crt" ]; then # a CA and a server certificate it signed (verify-full)
		openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 3650 \
			-subj /CN=pg-testbox-ca -keyout "$dir/ca.key" -out "$dir/ca.crt" 2>/dev/null
		openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj /CN=pg-testbox \
			-keyout "$dir/box/server.key" -out "$dir/server.csr" 2>/dev/null
		openssl x509 -req -in "$dir/server.csr" -CA "$dir/ca.crt" -CAkey "$dir/ca.key" -CAcreateserial -days 3650 \
			-extfile <(echo "subjectAltName=IP:127.0.0.1,DNS:localhost") -out "$dir/box/server.crt" 2>/dev/null
	fi
	[ -f "$dir/postgres.secret" ] || head -c 24 /dev/urandom | base64 | tr -d '/+=' >"$dir/postgres.secret"
	[ -f "$dir/nexus.secret" ] || head -c 24 /dev/urandom | base64 | tr -d '/+=' >"$dir/nexus.secret"
}

run() { # name, publish args…
	local n=$1
	shift
	podman rm -f "$n" >/dev/null 2>&1 || true
	podman run -d --name "$n" "$@" -v "$dir/box:/testbox:ro,Z" \
		-e POSTGRES_PASSWORD="$(cat "$dir/postgres.secret")" -e NEXUS_PASSWORD="$(cat "$dir/nexus.secret")" \
		"$IMG" >/dev/null
}

ready() {
	for _ in $(seq 150); do
		# the init-time server listens on the socket only: TCP = the final server
		podman exec "$1" pg_isready -q -h 127.0.0.1 -p 5432 2>/dev/null && return 0
		sleep 0.2
	done
	echo "run.sh: $1 did not come up; podman logs $1:" >&2
	podman logs "$1" >&2 || true
	return 1
}

case ${1:-} in
start)
	secrets
	podman build -q --build-arg BASE="docker.io/library/postgres:$PG" -t "$IMG" -f "$here/Containerfile" "$here" >/dev/null
	run "$NAME" -p "127.0.0.1:$PORT:5432" -p "127.0.0.1:$SSH_PORT:22"
	run "$NAME-alt" -p "127.0.0.1:$ALT_PORT:5432"
	ready "$NAME"
	ready "$NAME-alt"
	echo "pg-testbox up: PostgreSQL $PG on 127.0.0.1:$PORT (ssh $SSH_PORT), alternate on 127.0.0.1:$ALT_PORT"
	;;
stop) podman rm -f "$NAME" "$NAME-alt" >/dev/null 2>&1 || true ;;
env)
	[ -f "$dir/nexus.secret" ] || {
		echo "run.sh: not started yet, run '$0 start' first" >&2
		exit 1
	}
	cat <<-EOF
		export NEXUS_PG_CONTAINER=$NAME
		export NEXUS_PG_PORT=$PORT
		export NEXUS_PG_ALT_PORT=$ALT_PORT
		export NEXUS_PG_SSH_PORT=$SSH_PORT
		export NEXUS_PG_PASSWORD='$(cat "$dir/nexus.secret")'
		export NEXUS_PG_SUPER_PASSWORD='$(cat "$dir/postgres.secret")'
		export NEXUS_PG_SSH_KEY='$dir/client_ed25519'
		export NEXUS_PG_SSH_HOST_KEY='$(cut -d' ' -f1,2 "$dir/box/ssh_host_ed25519_key.pub")'
		export NEXUS_PG_CA='$dir/ca.crt'
	EOF
	;;
*)
	sed -n '2,12p' "$0" >&2
	exit 2
	;;
esac
