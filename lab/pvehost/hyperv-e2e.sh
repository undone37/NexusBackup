#!/usr/bin/env bash
# Hyper-V host backups end to end (#39 M1, docs/hyperv-design.md) on the appliance VM of the PVE lab: this tree's
# Windows agent on the nested Hyper-V host (lab/windows/hyperv.sh, VM 296), enrolled with the appliance, then a
# backup job {agent_id, hyperv_vm} of its test VM: recovery checkpoint, the frozen disk read with block reads,
# snapshot hv-<vm id>, reference point. Through the tunnel of deploy.sh; Windows driven through the guest agent.
#
#   hyperv-e2e.sh agent    agent "nx-hyperv" on the appliance; nexus-agent.exe (target/agent-dist/windows, built by
#                          crates/agent-windows/build.sh --test-key) on the host: init with the token, service,
#                          firewall rule for TCP 7444; enrolled
#   hyperv-e2e.sh backup   backup job of the VM named $VM; the snapshot, the checkpoints left on the host (none)
#
# env: as deploy.sh (LAB ~/nexus-lab/pvehost, PORT 28444); VMID (296), VM (nx-rct), AGENT (nx-hyperv)
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
export LAB=${LAB:-$HOME/nexus-lab/pvehost}
export PORT=${PORT:-28444}
VMID=${VMID:-296}
VM=${VM:-nx-rct}
AGENT=${AGENT:-nx-hyperv}
EXE=${EXE:-$repo/target/agent-dist/windows/nexus-agent.exe}
ROOT=$LAB/appliance/root
S=$ROOT/run/api
mkdir -p "$S"
# shellcheck disable=SC1091
. "$ROOT/secrets.env"
# shellcheck source=lab/e2e/api-lib.sh
. "$repo/lab/e2e/api-lib.sh"
[ "$VMID" -ge 200 ] || die "VMID $VMID: only VMs from 200 are ours"
win() { "$repo/lab/windows/gexec.py" "$VMID" "$1"; }
login admin "$ADMIN_PW" "$ADMIN_TOTP"
agent_id() { api admin GET /agents | jq -r --arg n "$AGENT" '.[] | select(.name == $n) | .id'; }

step_agent() {
	local id r tok ip j
	id=$(agent_id)
	if [ -n "$id" ]; then
		log "agent $AGENT exists ($id)"
		return
	fi
	[ -f "$EXE" ] || die "$EXE missing (crates/agent-windows/build.sh --test-key)"
	ip=$(win "(Get-NetIPAddress -AddressFamily IPv4 | Where-Object IPAddress -like '10.2.*' | Select-Object -First 1).IPAddress" | tr -d '\r')
	[ -n "$ip" ] || die "no 10.2.x address on VM $VMID"
	r=$(api admin POST /agents "$(jq -nc --arg h "$ip" --arg n "$AGENT" '{tenant:"lab", name:$n, host:$h, port:7444}')")
	expect 201 "create agent $AGENT"
	id=$(jq -r .id <<<"$r")
	tok=$(jq -r .token <<<"$r")
	win 'New-Item -ItemType Directory -Force C:\nx\agent | Out-Null' >/dev/null
	"$repo/lab/windows/gexec.py" "$VMID" --put "$EXE" 'C:\nx\agent\nexus-agent.exe' >/dev/null
	win "& C:\\nx\\agent\\nexus-agent.exe init --token $tok; & C:\\nx\\agent\\nexus-agent.exe install; Start-Service NexusAgent;
	     if (-not (Get-NetFirewallRule -DisplayName nexus-agent -ErrorAction SilentlyContinue)) {
	       New-NetFirewallRule -DisplayName nexus-agent -Direction Inbound -Protocol TCP -LocalPort 7444 -Action Allow | Out-Null }
	     (Get-Service NexusAgent).Status" >&2
	r=$(api admin POST "/agents/$id/enroll")
	expect 202 "enroll $AGENT"
	j=$(wait_job admin "$(jq -r .id <<<"$r")" 600)
	[ "$(jq -r .state <<<"$j")" = ok ] || die "enroll $AGENT: $(jq -r .log <<<"$j" | tail -n 20)"
	log "agent $AGENT $id enrolled ($ip)"
}

step_backup() {
	local id vm r j
	id=$(agent_id)
	[ -n "$id" ] || die "no agent $AGENT (step agent)"
	vm=$(win "(Get-VM $VM).Id.ToString().ToUpper()" | tr -d '\r')
	[ -n "$vm" ] || die "no VM $VM on the host"
	r=$(api admin POST /jobs "$(jq -nc --arg a "$id" --arg v "$vm" '{kind:"backup", tenant:"lab", params:{agent_id:$a, hyperv_vm:$v}}')")
	expect 202 "backup job"
	j=$(wait_job admin "$(jq -r .id <<<"$r")" 3600)
	jq -r .log <<<"$j" | tail -n 15 >&2
	[ "$(jq -r .state <<<"$j")" = ok ] || die "backup: $(jq -r .state <<<"$j")"
	# the catalog lists the new snapshot after the scheduler's next refresh
	local snaps='[]'
	for _ in $(seq 1 30); do
		snaps=$(api admin GET "/snapshots?tenant=lab" | jq -c --arg s "hv-${vm,,}" '[.[] | select(.source == $s) | {time, size}]')
		[ "$snaps" != '[]' ] && break
		sleep 5
	done
	log "snapshots: $snaps"
	log "checkpoints left on the host: $(win "@(Get-VMSnapshot $VM).Count; @(Get-Disk).Count" | tr -d '\r' | paste -sd' ')"
}

case ${1:?step} in
agent) step_agent ;;
backup) step_backup ;;
*) die "unknown step $1" ;;
esac
