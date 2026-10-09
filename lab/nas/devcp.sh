#!/usr/bin/env bash
# The dev control plane (lab/e2e/m5.sh: keyd, web-api, scheduler as a normal user
# under a scratch root) INSIDE the NAS lab VM: mounting a share needs root for
# nexus-nasmount, which the dev host does not have. The helper runs there with the
# real systemd units (os/systemd/nexus-nasmount.*: socket activation, CAP_SYS_ADMIN
# only); the shares are mounted over the VM's loopback (no network latency: the
# appliance VM run measures the network path). The REST API is forwarded to the
# host (127.0.0.1:18453), so lab/nas/e2e.sh drives it from the host.
#
#   devcp.sh deploy   copy target/release binaries + lab/e2e into the VM, install nexus-nasmount
#   devcp.sh setup    m5.sh setup in the VM; certificate + secrets to the host-side ROOT
#   devcp.sh start    m5.sh start in the VM (web-api on 0.0.0.0:18443 -> host 127.0.0.1:18453)
#   devcp.sh stop
#   devcp.sh env      exports for lab/nas/e2e.sh
#   devcp.sh all      deploy setup start
# Build first: cargo build --release -p keyd -p web-api -p scheduler -p setup -p nas
#              (+ web/dist for the UI: cd web && npm ci --ignore-scripts && npm run build)
# env: ROOT (host side, default target/nas-devcp), LAB (/home/ah/nexus-lab)
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
VM=$here/vm.sh
R=/var/lib/nexus-lab
ROOT=${ROOT:-$repo/target/nas-devcp}
PORT=18453

deploy() {
	local st=$repo/target/nas-deploy
	rm -rf "$st" "$st.tar"
	mkdir -p "$st/bin" "$st/e2e" "$st/rvm"
	for b in keyd nexus-web-api nexus-scheduler nexus-setup nexus-nas nexus-nasmount; do
		cp "$repo/target/release/$b" "$st/bin/"
	done
	# m5.sh only warns without the restore micro-VM (not needed for shares)
	: >"$st/rvm/vmlinuz"
	cp "$repo/lab/e2e/m5.sh" "$repo/lab/e2e/totp.py" "$st/e2e/"
	cp "$repo/os/systemd/nexus-nasmount.socket" "$repo/os/systemd/nexus-nasmount@.service" "$here/install-helper.sh" "$st/bin/"
	tar -C "$st" -cf "$st.tar" .
	"$VM" put "$st.tar" /tmp/nas-deploy.tar
	"$VM" ssh "set -e; rm -rf $R/cp; mkdir -p $R/cp; tar -C $R/cp -xf /tmp/nas-deploy.tar; sudo bash $R/cp/bin/install-helper.sh $R/cp/bin lab"
}

incp() {
	"$VM" ssh "cd $R && ROOT=$R/m5-root BIN=$R/cp/bin PORT=18443 LISTEN=0.0.0.0 NEXUS_RESTORE_VM_DIR=$R/cp/rvm bash $R/cp/e2e/m5.sh $1"
}

setup() {
	incp setup
	rm -rf "$ROOT"
	mkdir -p "$ROOT/etc/nexus/tls" "$ROOT/run"
	"$VM" ssh "cat $R/m5-root/etc/nexus/tls/cert.pem" >"$ROOT/etc/nexus/tls/cert.pem"
	(
		umask 077
		"$VM" ssh "cat $R/m5-root/secrets.env" >"$ROOT/secrets.env"
	)
	echo "host-side ROOT $ROOT (certificate + secrets), API https://nexus-m5:$PORT (127.0.0.1)"
}

case ${1:-} in
deploy) deploy ;;
setup) setup ;;
start) incp start ;;
stop) incp stop ;;
env)
	echo "export ROOT='$ROOT' PORT=$PORT"
	sed 's/^/export /' "$ROOT/secrets.env"
	;;
all)
	deploy
	setup
	incp start
	;;
*) sed -n '2,19p' "$0" >&2; exit 2 ;;
esac
