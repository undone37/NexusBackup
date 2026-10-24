#!/usr/bin/env bash
# Forwarding receivers on a lab VM instead of the podman testbox (#62: the PVE lab appliance cannot reach the
# workstation's loopback): the same commands as testbox/run.sh, for lab/appliance/forwarding.sh with
# TB=lab/forwarding/vm.sh. Plain Python on the VM (syslog_tls.py, testbox/sink.py), nothing installed; the
# receivers' output is mirrored to the workstation every 2 s, where forwarding.sh reads it.
#   vm.sh start | stop | reset | syslog-down | syslog-up | https-fail on|off | env
# env: RECV (10.2.34.99, the regression VM 280), VM_KEY (~/nexus-lab/lab_ed25519: root there), SYSLOG_PORT
#      (16514), HTTPS_PORT (18445), DIR (~/nexus-lab/scratch/forwarding-vm: certificates, mirrored output)
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
RECV=${RECV:-10.2.34.99}
VM_KEY=${VM_KEY:-$HOME/nexus-lab/lab_ed25519}
SYSLOG_PORT=${SYSLOG_PORT:-16514}
HTTPS_PORT=${HTTPS_PORT:-18445}
DIR=${DIR:-$HOME/nexus-lab/scratch/forwarding-vm}
TOKEN=lab-forwarding-token # test-only
R=/root/nexus-fwd # on the VM
opts=(-i "$VM_KEY" -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR)
vm() { ssh "${opts[@]}" "root@$RECV" "$@"; }

certs() {
	mkdir -p "$DIR/certs" "$DIR/out"
	[ -f "$DIR/certs/ca.crt" ] && return 0
	openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 3650 \
		-subj /CN=forwarding-lab-ca -keyout "$DIR/certs/ca.key" -out "$DIR/certs/ca.crt" 2>/dev/null
	openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj /CN=fwd.nexus-lab \
		-keyout "$DIR/certs/tls.key" -out "$DIR/certs/tls.csr" 2>/dev/null
	openssl x509 -req -in "$DIR/certs/tls.csr" -CA "$DIR/certs/ca.crt" -CAkey "$DIR/certs/ca.key" -CAcreateserial \
		-days 3650 -extfile <(echo "subjectAltName=DNS:fwd.nexus-lab,IP:$RECV") -out "$DIR/certs/tls.crt" 2>/dev/null
}

# one receiver in the background on the VM, its PID in $R/<name>.pid
run() { # NAME SCRIPT PORT
	# `cd` on its own: an `&` after `cd && …` would background a subshell that keeps the SSH session open
	vm "cd $R; OUT_DIR=$R/out CERT_DIR=$R/certs TOKEN=$TOKEN PORT=$3 setsid python3 -I $R/$2 >$R/$1.err 2>&1 </dev/null & echo \$! >$R/$1.pid"
}
kill_one() { vm "test -f $R/$1.pid && kill \$(cat $R/$1.pid) 2>/dev/null; rm -f $R/$1.pid"; }

case ${1:-} in
start)
	certs
	"$0" stop
	# the output stays: the appliance never sends again what a sink acknowledged (forwarding.sh empties its
	# local copies, the mirror refills them); `vm.sh reset` for a fresh start, with new ports for the appliance
	vm "mkdir -p $R/certs $R/out"
	scp -q "${opts[@]}" "$DIR/certs/tls.crt" "$DIR/certs/tls.key" "root@$RECV:$R/certs/"
	scp -q "${opts[@]}" "$here/syslog_tls.py" "$here/testbox/sink.py" "root@$RECV:$R/"
	run syslog syslog_tls.py "$SYSLOG_PORT"
	run https sink.py "$HTTPS_PORT"
	# the mirror: whole copies of the VM's files every 2 s
	(while :; do
		vm "cat $R/out/syslog.log 2>/dev/null" >"$DIR/out/.syslog" && cat "$DIR/out/.syslog" >"$DIR/out/syslog.log"
		vm "cat $R/out/https.jsonl 2>/dev/null" >"$DIR/out/.https" && cat "$DIR/out/.https" >"$DIR/out/https.jsonl"
		sleep 2
	done) </dev/null >/dev/null 2>&1 &
	echo $! >"$DIR/mirror.pid"
	for _ in $(seq 30); do
		curl -fsS --cacert "$DIR/certs/ca.crt" -o /dev/null -X POST -H "Authorization: Bearer $TOKEN" \
			--data '[]' "https://$RECV:$HTTPS_PORT/ingest" 2>/dev/null && exit 0
		sleep 1
	done
	vm "cat $R/*.err" >&2
	exit 1
	;;
stop)
	[ -f "$DIR/mirror.pid" ] && kill "$(cat "$DIR/mirror.pid")" 2>/dev/null || true
	rm -f "$DIR/mirror.pid"
	kill_one syslog
	kill_one https
	;;
reset)
	"$0" stop
	vm "rm -f $R/out/*"
	rm -f "$DIR/out/"*
	;;
syslog-down) kill_one syslog ;;
syslog-up) run syslog syslog_tls.py "$SYSLOG_PORT" ;;
https-fail)
	case ${2:-} in
	on) vm "touch $R/out/https.fail" ;;
	off) vm "rm -f $R/out/https.fail" ;;
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
	sed -n '2,9p' "$0" >&2
	exit 2
	;;
esac
