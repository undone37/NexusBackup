#!/usr/bin/env bash
# The installed agent package (.deb / .rpm) on the agent test VMs of lab/pvehost/agent-vms.sh, against
# the dev control plane (lab/linux/e2e.sh appliance): per VM init with a token, enrol, back up /etc and a
# test tree, report the snapshot method and consistency the agent chose for that file system, an
# incremental run, restore the tree and compare it (owners, modes, times, xattrs, ACLs, capabilities,
# links, content: lab/linux/manifest.py). The other release paths (agent updates, the bundle) stay with
# lab/linux/e2e.sh.
#
#   agent-matrix.sh [names]     default: every VM of agent-vms.sh; one after the other
#   agent-matrix.sh summary     the result table of the last runs
#
# Each VM starts from its snapshot clean-os plus the package (agent-vms.sh reset + agent), so a run never
# depends on an earlier one. Results: $S/<name>.results (key=value), summary in $S/summary.txt.
# env: ROOT/PORT of the dev control plane (target/linux-root, 18453), TAG (agent-vms.sh), APPL_ADDR (the
#      appliance address the VMs see, for their firewall rule; default: this host's source address to the VM)
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
export ROOT=${ROOT:-$repo/target/linux-root} PORT=${PORT:-18453}
VMS=$here/agent-vms.sh
eval "$(ROOT=$ROOT PORT=$PORT "$repo/lab/e2e/m5.sh" env)"
S=$ROOT/run/matrix
mkdir -p "$S"
# shellcheck source=lab/e2e/api-lib.sh
# shellcheck disable=SC1090
. "$repo/lab/e2e/api-lib.sh"
TENANT=matrix
RUN=$(date +%s)
DATA=/srv/data
PVE_HOST=${PVE_HOST:-10.2.34.200}
SSH_KEY=${SSH_KEY:-$HOME/nexus-lab/pve-lab-key}
VM_KEY=${VM_KEY:-$HOME/nexus-lab/lab_ed25519}
JUMP="ssh -i $SSH_KEY -o BatchMode=yes -W %h:%p root@$PVE_HOST"
SSHO=(-i "$VM_KEY" -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR
	-o ProxyCommand="$JUMP")

vm() { ssh "${SSHO[@]}" "root@$IP" "$@"; }
put() { scp -q "${SSHO[@]}" "$1" "root@$IP:$2"; }
result() { echo "$1=$2" >>"$S/$NAME.results"; }

run_vm() { # run_vm name
	NAME=$1
	: >"$S/$NAME.results"
	log "== $NAME: clean OS + package"
	"$VMS" reset "$NAME" </dev/null
	ssh -i "$SSH_KEY" -o BatchMode=yes "root@$PVE_HOST" "qm start $(id_of "$NAME")" </dev/null
	"$VMS" agent "$NAME" </dev/null
	IP=$("$VMS" ip "$NAME" </dev/null | awk '{print $3}')
	[ -n "$IP" ] && [ "$IP" != - ] || die "$NAME: no address"
	result os "$(vm '. /etc/os-release; echo "$PRETTY_NAME"')"
	result fs "$(vm "findmnt -n -o FSTYPE,SOURCE --target /srv | tr -s ' ' ' '")"
	result version "$(vm 'nexus-agent version' | head -1)"

	log "$NAME ($IP): test tree"
	# test tools; right after the first boot the package manager can fail once (repositories, DNS): 3 tries
	local try
	for try in 1 2 3; do
		vm 'if command -v apt-get >/dev/null; then DEBIAN_FRONTEND=noninteractive apt-get install -y -q attr acl libcap2-bin python3
			elif command -v dnf >/dev/null; then dnf -y -q install attr acl libcap python3
			else zypper --non-interactive -q install attr acl libcap-progs python3; fi >/tmp/tools.log 2>&1 &&
			command -v setfattr setfacl python3 >/dev/null' && break
		[ $try = 3 ] && die "$NAME: test tools not installed: $(vm 'tail -5 /tmp/tools.log')"
		sleep 30
	done
	put "$repo/lab/linux/provision/common.sh" /tmp/common.sh
	put "$repo/lab/linux/manifest.py" /tmp/manifest.py
	vm "bash -c '. /tmp/common.sh; mkdata $DATA'"

	# manual chapter 4: allow TCP 7444 from the appliance's address in the host firewall (firewalld runs
	# by default on Alma, Rocky and Leap; ufw on Ubuntu is inactive by default)
	local appl
	appl=${APPL_ADDR:-$(ip route get "$IP" | sed -n 's/.* src \([0-9.]*\).*/\1/p')}
	vm "if systemctl -q is-active firewalld; then firewall-cmd -q --permanent --add-rich-rule='rule family=ipv4 source address=$appl port port=7444 protocol=tcp accept' && firewall-cmd -q --reload && echo firewalld; fi" |
		while read -r f; do result firewall "$f: TCP 7444 from $appl"; done

	log "$NAME: agent, init, enrol"
	local r id tok j t0 an
	an=$NAME-$RUN # one agent and source per run: names are unique
	r=$(api admin POST /agents "$(jq -nc --arg t "$TENANT" --arg n "$an" --arg h "$IP" '{tenant:$t, name:$n, host:$h, port:7444}')")
	expect 201 "create agent"
	id=$(jq -r .id <<<"$r")
	tok=$(jq -r .token <<<"$r")
	t0=$SECONDS
	vm "nexus-agent init --token - && systemctl enable --now nexus-agent" <<<"$tok" >/dev/null
	r=$(api admin POST "/agents/$id/enroll")
	expect 202 "enroll"
	j=$(wait_job admin "$(jq -r .id <<<"$r")" 300)
	[ "$(jq -r .state <<<"$j")" = ok ] || die "$NAME: enroll: $(jq -r .log <<<"$j" | tail -n 15)"
	result enroll_s $((SECONDS - t0))

	log "$NAME: backup"
	api admin POST /sources "$(jq -nc --arg t "$TENANT" --arg n "$an" --arg a "$id" \
		'{tenant:$t, kind:"linux", name:$n, config:{agent_id:$a, paths:["/etc", "/srv/data"], excludes:["*.tmp"], hooks:false}}')" >/dev/null
	expect 201 "create source"
	backup() { # backup label -> job JSON in $S/<name>.<label>.json
		local b
		b=$(api admin POST /jobs "$(jq -nc --arg t "$TENANT" --arg a "$id" '{kind:"backup", tenant:$t, params:{agent_id:$a}}')")
		expect 202 "backup"
		wait_job admin "$(jq -r .id <<<"$b")" 1800 >"$S/$NAME.$1.json"
		[ "$(jq -r .state "$S/$NAME.$1.json")" = ok ] || die "$NAME: $1: $(jq -r .log "$S/$NAME.$1.json" | tail -n 20)"
	}
	t0=$SECONDS
	backup full
	result full_s $((SECONDS - t0))
	result full "$(jq -c '.result | {entries, transferred_bytes, consistent}' "$S/$NAME.full.json")"
	result snapshot "$(jq -r '.log' "$S/$NAME.full.json" | grep -iE 'snapshot|reading live|consistent' | head -3 | tr '\n' ' ' | cut -c1-200)"
	vm "dd if=/dev/urandom of=$DATA/big.bin bs=4096 seek=2000 count=1 conv=notrunc status=none; echo changed > $DATA/docs/note-5.txt; sync"
	t0=$SECONDS
	backup incr
	result incr_s $((SECONDS - t0))
	result incr "$(jq -c '.result | {entries, transferred_bytes, unchanged_files}' "$S/$NAME.incr.json")"

	log "$NAME: restore"
	local time target
	target=/restore/$(date +%s)
	time=$(jq -r .result.time "$S/$NAME.incr.json")
	r=$(api admin POST /jobs "$(jq -nc --arg t "$TENANT" --arg s "host-$id" --argjson tm "$time" --arg tg "$target" --arg c "$an" \
		'{kind:"restore_files", tenant:$t, params:{source:$s, time:$tm, paths:["/srv/data"], target:$tg, overwrite:"never", confirm:$c}}')")
	expect 202 "restore_files"
	j=$(wait_job admin "$(jq -r .id <<<"$r")" 1800)
	[ "$(jq -r .state <<<"$j")" = ok ] || die "$NAME: restore: $(jq -r .log <<<"$j" | tail -n 20)"
	if vm "python3 -I /tmp/manifest.py $DATA > /tmp/m.orig && python3 -I /tmp/manifest.py $target$DATA > /tmp/m.rest && diff /tmp/m.orig /tmp/m.rest" >"$S/$NAME.diff"; then
		result restore "identical ($(vm 'wc -l < /tmp/m.orig') entries)"
	else
		result restore "DIFFERS: $(head -c 300 "$S/$NAME.diff" | tr '\n' ' ')"
	fi
	log "$NAME: $(tr '\n' ' ' <"$S/$NAME.results" | cut -c1-400)"
}

id_of() { "$VMS" list | awk -v n="$1" '$2 == n {print $1}'; }

summary() {
	{
		printf '%-15s %-34s %-18s %-9s %-10s %s\n' VM OS FS FULL INCR RESTORE
		for f in "$S"/*.results; do
			[ -s "$f" ] || continue
			g() { sed -n "s/^$1=//p" "$f" | head -1; }
			printf '%-15s %-34s %-18s %-9s %-10s %s\n' "$(basename "$f" .results)" "$(g os | cut -c1-34)" "$(g fs | cut -d' ' -f1)" \
				"$(g full_s)s" "$(g incr | jq -r '(.transferred_bytes / 1048576 | floor | tostring) + " MiB"' 2>/dev/null)" "$(g restore | cut -c1-40)"
		done
	} | tee "$S/summary.txt"
}

if [ "${1:-}" = summary ]; then summary; exit; fi
login admin "$ADMIN_PW" "$ADMIN_TOTP"
api admin GET /tenants | jq -e --arg t "$TENANT" '.[] | select(.name==$t)' >/dev/null ||
	{ api admin POST /tenants "$(jq -nc --arg t "$TENANT" '{name:$t}')" >/dev/null && expect 201 "create tenant"; }
names=("$@")
[ ${#names[@]} -gt 0 ] || mapfile -t names < <("$VMS" list | awk '{print $2}')
failed=()
for n in "${names[@]}"; do
	(run_vm "$n") || failed+=("$n")
	# stop it again: 14 VMs do not fit the host's memory together with the other labs
	ssh -i "$SSH_KEY" -o BatchMode=yes "root@$PVE_HOST" "qm shutdown $(id_of "$n") --timeout 120 --forceStop 1" </dev/null || true
done
summary
[ ${#failed[@]} -eq 0 ] || die "failed: ${failed[*]}"
