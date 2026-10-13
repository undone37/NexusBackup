#!/usr/bin/env bash
# Linux agent from its package on a remote host over SSH (e.g. the emulated aarch64 VM on the PVE lab host),
# against the dev control plane (lab/linux/e2e.sh appliance): install the .deb/.rpm, enroll, back up, restore
# to /restore/<n>, compare with lab/linux/manifest.py.
#
#   remote.sh HOST [steps]      default: install enroll backup restore
# env: SSH_USER (lab), SSH_KEY (~/nexus-lab/pve-lab-key), PKG (package matching the host's arch, default:
#      target/packages/nexus-agent_<v>-1_<dpkg arch>.deb), ROOT/PORT (as lab/linux/e2e.sh), DATA (/etc /home)
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
export ROOT=${ROOT:-$repo/target/linux-root} PORT=${PORT:-18453}
HOST=${1:?host}
shift
SSH_USER=${SSH_USER:-lab}
SSH_KEY=${SSH_KEY:-$HOME/nexus-lab/pve-lab-key}
DATA=${DATA:-/etc /home}
TENANT=linux
eval "$(ROOT=$ROOT PORT=$PORT "$repo/lab/e2e/m5.sh" env)"
S=$ROOT/run/api
mkdir -p "$S"
# shellcheck source=lab/e2e/api-lib.sh
. "$repo/lab/e2e/api-lib.sh"
ssh_() { ssh -i "$SSH_KEY" -o BatchMode=yes -o StrictHostKeyChecking=accept-new "$SSH_USER@$HOST" "$@"; }
R=$S/remote-$HOST.results
touch "$R"
result() {
	grep -v "^$1=" "$R" >"$R.tmp" || true
	echo "$1=$2" >>"$R.tmp"
	mv "$R.tmp" "$R"
	log "result $1=$2"
}
# shellcheck disable=SC1090
state() { [ -f "$S/remote-$HOST.env" ] && . "$S/remote-$HOST.env"; return 0; }
ver=$(sed -n 's/^version = "\(.*\)"/\1/p' "$repo/crates/agent-linux/Cargo.toml" | head -1)

step_install() {
	local arch pkg
	arch=$(ssh_ 'dpkg --print-architecture 2>/dev/null || uname -m')
	pkg=${PKG:-$repo/target/packages/nexus-agent_${ver}-1_${arch}.deb}
	[ -f "$pkg" ] || die "no package $pkg (release/packages.sh --test-key)"
	scp -q -i "$SSH_KEY" "$pkg" "$SSH_USER@$HOST:/tmp/"
	ssh_ "sudo apt-get install -y -q /tmp/$(basename "$pkg") >/dev/null 2>&1 || sudo dnf install -y /tmp/$(basename "$pkg") >/dev/null"
	ssh_ 'nexus-agent --version; file -L /usr/bin/nexus-agent 2>/dev/null | cut -d, -f1-2 || true' | sed 's/^/  host: /' >&2
	result install "$(basename "$pkg") on $(ssh_ 'uname -m')"
}

step_enroll() {
	login admin "$ADMIN_PW" "$ADMIN_TOTP"
	local r id tok j name
	name=$(ssh_ hostname)
	api admin GET /tenants | jq -e --arg t "$TENANT" '.[] | select(.name==$t)' >/dev/null ||
		{ api admin POST /tenants "$(jq -nc --arg t "$TENANT" '{name:$t}')" >/dev/null && expect 201 "create tenant"; }
	r=$(api admin POST /agents "$(jq -nc --arg t "$TENANT" --arg n "$name" --arg h "$HOST" '{tenant:$t, name:$n, host:$h, port:7444}')")
	expect 201 "create agent"
	id=$(jq -r .id <<<"$r")
	tok=$(jq -r .token <<<"$r")
	printf 'AGENT=%s\nNAME=%s\n' "$id" "$name" >"$S/remote-$HOST.env"
	ssh_ "echo $tok | sudo nexus-agent init --token - >/dev/null && sudo systemctl restart nexus-agent"
	r=$(api admin POST "/agents/$id/enroll")
	expect 202 "enroll"
	j=$(wait_job admin "$(jq -r .id <<<"$r")" 600)
	[ "$(jq -r .state <<<"$j")" = ok ] || die "enroll: $(jq -r .log <<<"$j" | tail -n 20)"
	result enroll "$(api admin GET /agents | jq -c --arg id "$id" '.[] | select(.id==$id) | {version, os}')"
}

step_backup() {
	state
	login admin "$ADMIN_PW" "$ADMIN_TOTP"
	local src r j paths
	paths=$(printf '%s\n' $DATA | jq -R . | jq -sc .)
	src=$(api admin GET /sources | jq -r --arg n "$NAME" '.[] | select(.name==$n) | .id')
	if [ -z "$src" ]; then
		api admin POST /sources "$(jq -nc --arg t "$TENANT" --arg n "$NAME" --arg a "$AGENT" --argjson p "$paths" \
			'{tenant:$t, kind:"linux", name:$n, config:{agent_id:$a, paths:$p}}')" >/dev/null
		expect 201 "create source"
	fi
	r=$(api admin POST /jobs "$(jq -nc --arg t "$TENANT" --arg a "$AGENT" '{kind:"backup", tenant:$t, params:{agent_id:$a}}')")
	expect 202 "backup"
	j=$(wait_job admin "$(jq -r .id <<<"$r")" 3600)
	[ "$(jq -r .state <<<"$j")" = ok ] || die "backup: $(jq -r .log <<<"$j" | tail -n 30)"
	log "$(jq -r .log <<<"$j" | grep -m1 '^committed ')"
	echo "LAST=$(jq -r .result.time <<<"$j")" >>"$S/remote-$HOST.env"
	result backup "$(jq '.finished - .started' <<<"$j") s"
}

step_restore() {
	state
	login admin "$ADMIN_PW" "$ADMIN_TOTP"
	local t r j paths i n=0 d
	paths=$(printf '%s\n' $DATA | jq -R . | jq -sc .)
	for i in $(seq 90); do
		api admin GET "/snapshots?tenant=$TENANT" | jq -e --arg s "host-$AGENT" --argjson t "$LAST" '.[] | select(.source==$s and .time==$t)' >/dev/null && break
		[ "$i" = 90 ] && die "snapshot $LAST not in the catalog"
		sleep 2
	done
	t=/restore/$(date +%s)
	r=$(api admin POST /jobs "$(jq -nc --arg t "$TENANT" --arg s "host-$AGENT" --argjson tm "$LAST" --argjson p "$paths" --arg tg "$t" --arg c "$NAME" \
		'{kind:"restore_files", tenant:$t, params:{source:$s, time:$tm, paths:$p, target:$tg, overwrite:"never", confirm:$c}}')")
	expect 202 "restore_files"
	j=$(wait_job admin "$(jq -r .id <<<"$r")" 3600)
	[ "$(jq -r .state <<<"$j")" = ok ] || die "restore: $(jq -r .log <<<"$j" | tail -n 30)"
	scp -q -i "$SSH_KEY" "$here/manifest.py" "$SSH_USER@$HOST:/tmp/manifest.py"
	for d in $DATA; do
		ssh_ "sudo python3 -I /tmp/manifest.py $d > /tmp/m.orig && sudo python3 -I /tmp/manifest.py $t$d > /tmp/m.rest && diff /tmp/m.orig /tmp/m.rest" >"$S/remote-$HOST.diff" ||
			die "restored $d differs: $(head -20 "$S/remote-$HOST.diff")"
		n=$((n + $(ssh_ 'wc -l < /tmp/m.orig')))
	done
	result restore "$n entries identical"
}

steps=("$@")
[ ${#steps[@]} -gt 0 ] || steps=(install enroll backup restore)
for s in "${steps[@]}"; do
	log "== $HOST: $s"
	"step_$s"
done
cat "$R"
