#!/usr/bin/env bash
# PostgreSQL testbox in rootless podman, for plugins/postgresql/tests/pg.rs.
#   run.sh start   build the image (cached), generate keys + TLS cert (once), start
#                  `main` (the source; TLS, role `nexus` with REPLICATION, CREATEDB +
#                  pg_read_all_data, sshd for postgres on $SSH_PORT) on 127.0.0.1:$PORT
#                  and `alt` (alternate restore server) on 127.0.0.1:$ALT_PORT; main also
#                  publishes 127.0.0.1:$REPLICA_PORT → 5433 for a streaming replica the HA
#                  test starts inside it (pg_basebackup -R, pg_ctl -o "-p 5433")
#   run.sh stop    remove both containers (all data goes with them)
#   run.sh env     print `export NEXUS_PG_*=...` lines
# The test starts the testbox itself when podman is available (NEXUS_PG_TESTBOX=skip
# disables it). env: PG (major version, default 17), PORT (15432), ALT_PORT (15433),
# SSH_PORT (12222), REPLICA_PORT (15434), NAME (container name, nexus-pg-testbox).
# Keys, cert and passwords live in target/pg-testbox/ (not in git).
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)
dir=$root/target/pg-testbox
PG=${PG:-17}
# git worktrees and CI runner checkouts (parallel test runs) get their own container names and ports, so one run
# cannot remove or reuse another's testbox; the main checkout keeps the defaults (lab scripts).
k=0
case $root in */worktrees/* | */_work/*) k=$(($(printf %s "$root" | cksum | cut -d' ' -f1) % 400 + 1)) ;; esac
# CI: ports per workflow run too; a container stuck in "stopping" keeps its port forwarder, which
# accepts and drops connections (mysql tests: "ssh 127.0.0.1:27257: Disconnected")
[ -z "${GITHUB_RUN_ID:-}" ] || k=$(($(printf %s "$root$GITHUB_RUN_ID" | cksum | cut -d' ' -f1) % 400 + 1))
PORT=${PORT:-$((15432 + k * 10))}
ALT_PORT=${ALT_PORT:-$((15433 + k * 10))}
SSH_PORT=${SSH_PORT:-$([ $k = 0 ] && echo 12222 || echo $((12225 + k * 10)))}
REPLICA_PORT=${REPLICA_PORT:-$((15434 + k * 10))}
IMG=localhost/nexus-pg-testbox:$PG
NAME=${NAME:-nexus-pg-testbox$([ $k = 0 ] || echo "-w$k")}
# CI: one container name per workflow run. A container stuck in "stopping" (state from before a runner
# restart, SIGKILL -> EPERM) can neither be removed nor reused; a fresh name sidesteps it, and the
# containers of earlier runs are removed below whenever podman lets us.
if [ -n "${GITHUB_RUN_ID:-}" ]; then
	BASE_NAME=$NAME
	NAME=$NAME-r$GITHUB_RUN_ID
	# any -w<k>: k depends on the run id too, so earlier runs have other prefixes
	podman ps -a --format '{{.Names}}' 2>/dev/null | grep -E "^${BASE_NAME%-w*}(-w[0-9]+)?-r[0-9]+" | grep -v "^$NAME" |
		while read -r old; do podman rm -f -t 0 "$old" >/dev/null 2>&1 || true; done || true
fi

# remove container $1 whatever state it is in (hung after a cancelled CI run: conmon gone, storage-only
# leftovers); prints podman's view if the name is still taken
podman_purge() {
	podman stop -t 0 "$1" >/dev/null 2>&1 || true
	podman container cleanup "$1" >/dev/null 2>&1 || true
	podman rm -f -t 0 "$1" >/dev/null 2>&1 || true
	podman rm --storage "$1" >/dev/null 2>&1 || true
	if podman container exists "$1" 2>/dev/null || podman ps -a --external --format '{{.Names}}' 2>/dev/null | grep -qx "$1"; then
		echo "run.sh: container $1 still exists after removal:" >&2
		podman ps -a --external --filter "name=^$1\$" --format '{{.ID}} {{.Status}} {{.Names}}' >&2 || true
		podman rm -f -t 0 "$1" >&2 || true
		podman rm --storage "$1" >&2 || true
	fi
}

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
			-extfile <(echo "subjectAltName=IP:127.0.0.1,IP:10.0.2.2,DNS:localhost") -out "$dir/box/server.crt" 2>/dev/null
	fi
	[ -f "$dir/postgres.secret" ] || head -c 24 /dev/urandom | base64 | tr -d '/+=' >"$dir/postgres.secret"
	[ -f "$dir/nexus.secret" ] || head -c 24 /dev/urandom | base64 | tr -d '/+=' >"$dir/nexus.secret"
}

# The box directory is mounted into both containers: ",z" (shared SELinux label). ",Z" gave each
# container a private label in turn, so on an SELinux host (the AlmaLinux CI runner) the first one
# lost access to its sshd host key ("kex_exchange_identification: Connection closed").
run() { # name, publish args…
	local n=$1
	shift
	podman_purge "$n"
	podman run -d --name "$n" --label nexus.checkout="$root" "$@" -v "$dir/box:/testbox:ro,z" \
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

# containers of checkouts that no longer exist (deleted worktrees) are removed at every start
prune() {
	podman ps -a --filter label=nexus.checkout --format '{{.Names}} {{.Labels}}' 2>/dev/null |
		sed -n 's/^\([^ ]*\) .*nexus\.checkout:\([^] ,]*\).*/\1 \2/p' |
		while read -r n path; do [ -d "$path" ] || podman rm -f "$n" >/dev/null 2>&1 || true; done
}

case ${1:-} in
start)
	prune
	secrets
	podman build -q --build-arg BASE="docker.io/library/postgres:$PG" -t "$IMG" -f "$here/Containerfile" "$here" >/dev/null
	run "$NAME" -p "127.0.0.1:$PORT:5432" -p "127.0.0.1:$SSH_PORT:22" -p "127.0.0.1:$REPLICA_PORT:5433"
	run "$NAME-alt" -p "127.0.0.1:$ALT_PORT:5432"
	ready "$NAME"
	ready "$NAME-alt"
	echo "pg-testbox up: PostgreSQL $PG on 127.0.0.1:$PORT (ssh $SSH_PORT), alternate on 127.0.0.1:$ALT_PORT"
	;;
prune) prune ;;
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
		export NEXUS_PG_REPLICA_PORT=$REPLICA_PORT
		export NEXUS_PG_PASSWORD='$(cat "$dir/nexus.secret")'
		export NEXUS_PG_SUPER_PASSWORD='$(cat "$dir/postgres.secret")'
		export NEXUS_PG_SSH_KEY='$dir/client_ed25519'
		export NEXUS_PG_SSH_HOST_KEY='$(cut -d' ' -f1,2 "$dir/box/ssh_host_ed25519_key.pub")'
		export NEXUS_PG_CA='$dir/ca.crt'
	EOF
	;;
*)
	sed -n '2,15p' "$0" >&2
	exit 2
	;;
esac
