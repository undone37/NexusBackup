#!/usr/bin/env bash
# MinIO (S3 with Object Lock) in rootless podman, for crates/offsite/tests/s3.rs.
#   run.sh start   generate a TLS cert (once), start MinIO on https://127.0.0.1:$PORT,
#                  create bucket `nexus` WITH Object Lock (versioning on), a
#                  lifecycle rule for noncurrent versions, and user `appliance`
#                  restricted by policy.json (no DeleteObjectVersion, no bucket changes)
#   run.sh stop    remove the container; all data (and every lock) goes with it
#   run.sh env     print `export NEXUS_S3_*=...` lines for the tests
# Usage: crates/offsite/testbox-s3/run.sh start && eval "$(crates/offsite/testbox-s3/run.sh env)"
#        cargo test -p offsite --test s3
# env: PORT (default 9443), IMG (MinIO image incl. `mc`; upstream stopped
# publishing images in 2025, pgsty/minio is a maintained community build).
# Cert, key and credentials live in target/offsite-testbox-s3/ (not in git).
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)
dir=$root/target/offsite-testbox-s3
PORT=${PORT:-9443}
IMG=${IMG:-docker.io/pgsty/minio:RELEASE.2026-08-04T00-00-00Z}
NAME=nexus-offsite-testbox-s3
ROOT_USER=nexusadmin
APP_USER=appliance

secrets() {
	mkdir -p "$dir/certs"
	chmod 700 "$dir"
	[ -f "$dir/certs/public.crt" ] ||
		openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 3650 \
			-subj /CN=nexus-s3-testbox -addext "subjectAltName=IP:127.0.0.1,DNS:localhost" \
			-keyout "$dir/certs/private.key" -out "$dir/certs/public.crt" 2>/dev/null
	chmod 644 "$dir/certs/private.key" # read by the container user (rootless, test only)
	[ -f "$dir/root.secret" ] || head -c 24 /dev/urandom | base64 | tr -d '/+=' >"$dir/root.secret"
	[ -f "$dir/app.secret" ] || head -c 24 /dev/urandom | base64 | tr -d '/+=' >"$dir/app.secret"
}

mc() { podman exec "$NAME" mc --insecure "$@"; }

case ${1:-} in
start)
	secrets
	podman rm -f "$NAME" >/dev/null 2>&1 || true
	podman run -d --name "$NAME" -p "127.0.0.1:$PORT:9000" \
		-e MINIO_ROOT_USER=$ROOT_USER -e MINIO_ROOT_PASSWORD="$(cat "$dir/root.secret")" \
		-v "$dir/certs:/certs:ro,Z" -v "$here/policy.json:/policy.json:ro,Z" \
		"$IMG" server /data --certs-dir /certs --address :9000 >/dev/null
	for _ in $(seq 100); do
		mc alias set local https://127.0.0.1:9000 $ROOT_USER "$(cat "$dir/root.secret")" >/dev/null 2>&1 && break
		sleep 0.2
	done
	mc ready local >/dev/null
	mc mb --with-lock local/nexus >/dev/null
	# noncurrent versions (left behind by deletes = delete markers) expire one
	# day after they became noncurrent, never before their lock ends; lone
	# delete markers and stale multipart uploads are cleaned up too
	mc ilm rule add --noncurrent-expire-days 1 --expire-delete-marker local/nexus >/dev/null
	mc admin policy create local nexus-appliance /policy.json >/dev/null
	mc admin user add local $APP_USER "$(cat "$dir/app.secret")" >/dev/null
	mc admin policy attach local nexus-appliance --user $APP_USER >/dev/null
	echo "MinIO up on https://127.0.0.1:$PORT: bucket nexus (Object Lock, versioning), user $APP_USER"
	;;
stop) podman rm -f "$NAME" >/dev/null 2>&1 || true ;;
env)
	[ -f "$dir/app.secret" ] || {
		echo "run.sh: not started yet, run '$0 start' first" >&2
		exit 1
	}
	cat <<-EOT
		export NEXUS_S3_ENDPOINT=https://127.0.0.1:$PORT
		export NEXUS_S3_REGION=us-east-1
		export NEXUS_S3_BUCKET=nexus
		export NEXUS_S3_ACCESS_KEY=$APP_USER
		export NEXUS_S3_SECRET_KEY='$(cat "$dir/app.secret")'
		export NEXUS_S3_ADMIN_ACCESS_KEY=$ROOT_USER
		export NEXUS_S3_ADMIN_SECRET_KEY='$(cat "$dir/root.secret")'
		export NEXUS_S3_CA='$dir/certs/public.crt'
	EOT
	;;
*)
	sed -n '2,13p' "$0" >&2
	exit 2
	;;
esac
