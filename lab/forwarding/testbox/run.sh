#!/usr/bin/env bash
# Forwarding testbox in rootless podman (lab only), for lab/appliance/forwarding.sh:
# rsyslog with TLS (RFC 5425) on 127.0.0.1:$SYSLOG_PORT and an HTTPS JSON sink on
# 127.0.0.1:$HTTPS_PORT/ingest (Bearer $TOKEN), both with a lab CA certificate for
# fwd.nexus-lab, 10.0.2.2 (the host as seen from the appliance VM) and 127.0.0.1.
#   run.sh start         build the image (once), create the certificates (once), start the container
#   run.sh stop          remove the container (output files stay in $DIR)
#   run.sh syslog-down   stop rsyslogd in the container (the appliance must keep the backlog)
#   run.sh syslog-up     start it again
#   run.sh https-fail on|off   the HTTPS sink answers 503 while on
#   run.sh env           print FWD_* variables (CA path, server certificate SHA-256, ports, token, output files)
# Output: $DIR/out/syslog.log (RFC 5424 lines), $DIR/out/https.jsonl (one POST body per line).
# env: SYSLOG_PORT (16514), HTTPS_PORT (18445), DIR (target/forwarding-testbox).
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../../.." && pwd)
DIR=${DIR:-$repo/target/forwarding-testbox}
SYSLOG_PORT=${SYSLOG_PORT:-16514}
HTTPS_PORT=${HTTPS_PORT:-18445}
IMG=localhost/nexus-fwd-testbox:1
NAME=nexus-fwd-testbox
TOKEN=lab-forwarding-token # test-only

certs() {
	mkdir -p "$DIR/certs" "$DIR/out"
	[ -f "$DIR/certs/ca.crt" ] && return 0
	openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 3650 \
		-subj /CN=forwarding-testbox-ca -keyout "$DIR/certs/ca.key" -out "$DIR/certs/ca.crt" 2>/dev/null
	openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj /CN=fwd.nexus-lab \
		-keyout "$DIR/certs/tls.key" -out "$DIR/certs/tls.csr" 2>/dev/null
	openssl x509 -req -in "$DIR/certs/tls.csr" -CA "$DIR/certs/ca.crt" -CAkey "$DIR/certs/ca.key" -CAcreateserial \
		-days 3650 -extfile <(echo "subjectAltName=DNS:fwd.nexus-lab,IP:10.0.2.2,IP:127.0.0.1") \
		-out "$DIR/certs/tls.crt" 2>/dev/null
	chmod 0644 "$DIR/certs/tls.key" # read by the container's user (lab-only key)
}

case ${1:-} in
start)
	certs
	podman image exists "$IMG" || podman build -q -t "$IMG" "$here" >/dev/null
	podman rm -f "$NAME" >/dev/null 2>&1 || true
	podman run -d --name "$NAME" -e TOKEN=$TOKEN \
		-p "127.0.0.1:$SYSLOG_PORT:6514" -p "127.0.0.1:$HTTPS_PORT:8443" \
		-v "$DIR/certs:/certs:ro,Z" -v "$DIR/out:/out:Z" "$IMG" >/dev/null
	for _ in $(seq 60); do
		curl -fsS --cacert "$DIR/certs/ca.crt" -o /dev/null -X POST -H "Authorization: Bearer $TOKEN" \
			--data '[]' "https://127.0.0.1:$HTTPS_PORT/ingest" 2>/dev/null && exit 0
		sleep 0.5
	done
	podman logs "$NAME" >&2
	exit 1
	;;
stop) podman rm -f "$NAME" >/dev/null 2>&1 || true ;;
syslog-down) podman exec "$NAME" sh -c 'kill "$(cat /tmp/rsyslogd.pid)"; rm -f /tmp/rsyslogd.pid' ;;
syslog-up) podman exec "$NAME" rsyslogd -f /etc/rsyslog-lab.conf -i /tmp/rsyslogd.pid ;;
https-fail)
	case ${2:-} in
	on) touch "$DIR/out/https.fail" ;;
	off) rm -f "$DIR/out/https.fail" ;;
	*) exit 2 ;;
	esac
	;;
env)
	certs
	fp=$(openssl x509 -in "$DIR/certs/tls.crt" -noout -fingerprint -sha256 | cut -d= -f2)
	cat <<EOF
export FWD_CA=$DIR/certs/ca.crt
export FWD_PIN=$fp
export FWD_SYSLOG_PORT=$SYSLOG_PORT
export FWD_HTTPS_PORT=$HTTPS_PORT
export FWD_TOKEN=$TOKEN
export FWD_SYSLOG_LOG=$DIR/out/syslog.log
export FWD_HTTPS_LOG=$DIR/out/https.jsonl
EOF
	;;
*)
	sed -n '2,14p' "$0" >&2
	exit 2
	;;
esac
