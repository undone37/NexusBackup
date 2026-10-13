#!/usr/bin/env bash
# MySQL/MariaDB testbox in rootless podman, for plugins/mysql/tests/mysql.rs.
#   run.sh start   build both images (cached), generate keys + TLS cert (once), start
#                  `<name>-mariadb` (MariaDB 11, mariadb-backup) on 127.0.0.1:$MARIADB_PORT and
#                  `<name>-mysql` (MySQL 8.4, Percona XtraBackup 8.4) on 127.0.0.1:$MYSQL_PORT;
#                  both: binlog on (ROW), TLS (testbox CA), account `nexus` (backup privileges +
#                  what dump restores need), sshd for the OS user mysql (key auth) on the *_SSH_PORT
#   run.sh stop    remove both containers (all data goes with them)
#   run.sh env     print `export NEXUS_MY_*=...` lines
# The test starts the testbox itself when podman is available (NEXUS_MY_TESTBOX=skip disables
# it). env: MARIADB_PORT (23306), MARIADB_SSH_PORT (23307), MYSQL_PORT (23308), MYSQL_SSH_PORT
# (23309), NAME (container name prefix, nexus-my-testbox). Keys, cert and passwords live in
# target/my-testbox/ (not in git).
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)
dir=$root/target/my-testbox
# git worktrees and CI runner checkouts (parallel test runs) get their own container names and ports, so one run
# cannot remove or reuse another's testbox; the main checkout keeps the defaults (lab scripts).
k=0
case $root in */worktrees/* | */_work/*) k=$(($(printf %s "$root" | cksum | cut -d' ' -f1) % 400 + 1)) ;; esac
# CI: ports per workflow run too; a container stuck in "stopping" keeps its port forwarder, which
# accepts and drops connections (mysql tests: "ssh 127.0.0.1:27257: Disconnected")
[ -z "${GITHUB_RUN_ID:-}" ] || k=$(($(printf %s "$root$GITHUB_RUN_ID" | cksum | cut -d' ' -f1) % 400 + 1))
MARIADB_PORT=${MARIADB_PORT:-$((23306 + k * 10))}
MARIADB_SSH_PORT=${MARIADB_SSH_PORT:-$((23307 + k * 10))}
MYSQL_PORT=${MYSQL_PORT:-$((23308 + k * 10))}
MYSQL_SSH_PORT=${MYSQL_SSH_PORT:-$((23309 + k * 10))}
NAME=${NAME:-nexus-my-testbox$([ $k = 0 ] || echo "-w$k")}
# CI: one container name per workflow run. A container stuck in "stopping" (state from before a runner
# restart, SIGKILL -> EPERM) can neither be removed nor reused; a fresh name sidesteps it, and the
# containers of earlier runs are removed below whenever podman lets us.
if [ -n "${GITHUB_RUN_ID:-}" ]; then
	BASE_NAME=$NAME
	NAME=$NAME-r$GITHUB_RUN_ID
	podman ps -a --format '{{.Names}}' 2>/dev/null | grep -E "^$BASE_NAME-r[0-9]+" | grep -v "^$NAME" |
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
		ssh-keygen -q -t ed25519 -N '' -C my-testbox-host -f "$dir/box/ssh_host_ed25519_key"
	[ -f "$dir/client_ed25519" ] || ssh-keygen -q -t ed25519 -N '' -C my-testbox-client -f "$dir/client_ed25519"
	install -m 0644 "$dir/client_ed25519.pub" "$dir/box/client_ed25519.pub"
	if [ ! -f "$dir/ca.crt" ]; then # a CA and a server certificate it signed (verify-full)
		openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 3650 \
			-subj /CN=my-testbox-ca -keyout "$dir/ca.key" -out "$dir/ca.crt" 2>/dev/null
		openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj /CN=my-testbox \
			-keyout "$dir/box/server.key" -out "$dir/server.csr" 2>/dev/null
		openssl x509 -req -in "$dir/server.csr" -CA "$dir/ca.crt" -CAkey "$dir/ca.key" -CAcreateserial -days 3650 \
			-extfile <(echo "subjectAltName=IP:127.0.0.1,IP:10.0.2.2,DNS:localhost") -out "$dir/box/server.crt" 2>/dev/null
	fi
	[ -f "$dir/root.secret" ] || head -c 24 /dev/urandom | base64 | tr -d '/+=' >"$dir/root.secret"
	[ -f "$dir/nexus.secret" ] || head -c 24 /dev/urandom | base64 | tr -d '/+=' >"$dir/nexus.secret"
}

run() { # flavor, db port, ssh port
	local n=$NAME-$1
	podman_purge "$n"
	podman run -d --name "$n" --label nexus.checkout="$root" -p "127.0.0.1:$2:3306" -p "127.0.0.1:$3:22" -v "$dir/box:/testbox:ro,Z" \
		-e MARIADB_ROOT_PASSWORD="$(cat "$dir/root.secret")" -e MYSQL_ROOT_PASSWORD="$(cat "$dir/root.secret")" \
		-e NEXUS_PASSWORD="$(cat "$dir/nexus.secret")" "localhost/nexus-my-testbox:$1" >/dev/null
}

ready() {
	local admin=mysqladmin
	[ "$1" = mariadb ] && admin=mariadb-admin
	for _ in $(seq 300); do
		# the init-time server listens on the socket only: TCP = the final server
		podman exec "$NAME-$1" "$admin" --protocol=tcp -h127.0.0.1 -P3306 -uroot -p"$(cat "$dir/root.secret")" \
			ping >/dev/null 2>&1 && return 0
		sleep 0.3
	done
	echo "run.sh: $NAME-$1 did not come up; podman logs:" >&2
	podman logs "$NAME-$1" >&2 || true
	return 1
}

# the plugin reaches the server over SSH: a key login must work (CI on AlmaLinux: "Disconnected");
# on failure the client's and the container's view go to stderr
ssh_ok() { # flavor port
	local o=(-i "$dir/client_ed25519" -p "$2" -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10)
	for _ in $(seq 20); do
		ssh "${o[@]}" mysql@127.0.0.1 true 2>/dev/null && return 0
		sleep 0.5
	done
	echo "run.sh: ssh to $NAME-$1 (port $2) fails:" >&2
	ssh -v "${o[@]}" mysql@127.0.0.1 true 2>&1 | tail -n 25 >&2 || true
	podman exec "$NAME-$1" sh -c 'ps -ef | grep -v grep | grep sshd; ls -ln /testbox /home/mysql/.ssh; id mysql' >&2 || true
	podman logs --tail 30 "$NAME-$1" >&2 || true
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
	for f in mariadb mysql; do
		podman build -q -t "localhost/nexus-my-testbox:$f" -f "$here/Containerfile.$f" "$here" >/dev/null
	done
	run mariadb "$MARIADB_PORT" "$MARIADB_SSH_PORT"
	run mysql "$MYSQL_PORT" "$MYSQL_SSH_PORT"
	ready mariadb
	ready mysql
	ssh_ok mariadb "$MARIADB_SSH_PORT"
	ssh_ok mysql "$MYSQL_SSH_PORT"
	echo "my-testbox up: MariaDB on 127.0.0.1:$MARIADB_PORT (ssh $MARIADB_SSH_PORT), MySQL on 127.0.0.1:$MYSQL_PORT (ssh $MYSQL_SSH_PORT)"
	;;
prune) prune ;;
stop) podman rm -f "$NAME-mariadb" "$NAME-mysql" >/dev/null 2>&1 || true ;;
env)
	[ -f "$dir/nexus.secret" ] || {
		echo "run.sh: not started yet, run '$0 start' first" >&2
		exit 1
	}
	cat <<-EOF
		export NEXUS_MY_CONTAINER=$NAME
		export NEXUS_MY_MARIADB_PORT=$MARIADB_PORT
		export NEXUS_MY_MARIADB_SSH_PORT=$MARIADB_SSH_PORT
		export NEXUS_MY_MYSQL_PORT=$MYSQL_PORT
		export NEXUS_MY_MYSQL_SSH_PORT=$MYSQL_SSH_PORT
		export NEXUS_MY_PASSWORD='$(cat "$dir/nexus.secret")'
		export NEXUS_MY_ROOT_PASSWORD='$(cat "$dir/root.secret")'
		export NEXUS_MY_SSH_KEY='$dir/client_ed25519'
		export NEXUS_MY_SSH_HOST_KEY='$(cut -d' ' -f1,2 "$dir/box/ssh_host_ed25519_key.pub")'
		export NEXUS_MY_CA='$dir/ca.crt'
	EOF
	;;
*)
	sed -n '2,14p' "$0" >&2
	exit 2
	;;
esac
