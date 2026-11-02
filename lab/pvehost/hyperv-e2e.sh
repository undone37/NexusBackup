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
#   hyperv-e2e.sh group    (#39 M3) source "hv-host" of kind hyperv, its inventory, group "hv-vms" with $VM, a group
#                          backup through the scheduler
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
TARGET=${TARGET:-245}
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

# #39 M3: the source kind, its inventory and a group backup through the scheduler
step_group() {
	local id sid vm r j pid gid
	id=$(agent_id)
	[ -n "$id" ] || die "no agent $AGENT (step agent)"
	sid=$(api admin GET /sources | jq -r '.[] | select(.name == "hv-host") | .id')
	if [ -z "$sid" ]; then
		r=$(api admin POST /sources "$(jq -nc --arg a "$id" '{tenant:"lab", kind:"hyperv", name:"hv-host", config:{agent_id:$a}}')")
		expect 201 "create source hv-host"
		sid=$(jq -r .id <<<"$r")
	fi
	r=$(api admin POST /jobs "$(jq -nc --argjson s "$sid" '{kind:"inventory", tenant:"lab", params:{source_id:$s}}')")
	expect 202 "inventory job"
	j=$(wait_job admin "$(jq -r .id <<<"$r")" 600)
	[ "$(jq -r .state <<<"$j")" = ok ] || die "inventory: $(jq -r .log <<<"$j" | tail -n 10)"
	vm=$(api admin GET "/sources/$sid/inventory" | jq -r --arg n "$VM" '[.guests[] | select(.name == $n and .gone == null)][0].guest // empty')
	[ -n "$vm" ] || die "$VM not in the inventory of hv-host"
	log "inventory: $VM = $vm"
	pid=$(api admin GET /policies | jq -r '.[0].id')
	gid=$(api admin GET /groups | jq -r '.[] | select(.name == "hv-vms") | .id')
	if [ -z "$gid" ]; then
		r=$(api admin POST /groups "$(jq -nc --argjson s "$sid" --argjson p "$pid" --arg v "$vm" '{tenant:"lab", source_id:$s, policy_id:$p, name:"hv-vms", guests:[$v]}')")
		expect 201 "create group hv-vms"
		gid=$(jq -r .id <<<"$r")
	fi
	r=$(api admin POST /jobs "$(jq -nc --argjson g "$gid" '{kind:"backup", tenant:"lab", params:{group_id:$g}}')")
	expect 202 "group backup job"
	j=$(wait_job admin "$(jq -r .id <<<"$r")" 3600)
	jq -r .log <<<"$j" | grep -E "scsi|result" | tail -n 4 >&2
	[ "$(jq -r .state <<<"$j")" = ok ] || die "group backup: $(jq -r .state <<<"$j")"
	log "group backup of $VM ok"
}

# #39 M3: the newest hv- snapshot of $VM as PVE VM $TARGET (NICs link_down, not started), its config, removed again
step_restore() {
	local vm src time pve_src j
	pve() { ssh -n -i "${SSH_KEY:-$HOME/nexus-lab/pve-lab-key}" -o BatchMode=yes "root@${PVE_HOST:-10.2.34.200}" "$@"; }
	[ "$TARGET" -ge 200 ] || die "TARGET $TARGET: only VMs from 200 are ours"
	pve "qm status $TARGET" >/dev/null 2>&1 && die "VM $TARGET exists"
	vm=$(win "(Get-VM $VM).Id.ToString().ToLower()" | tr -d '\r')
	src="hv-$vm"
	time=$(api admin GET "/snapshots?tenant=lab" | jq -r --arg s "$src" '[.[] | select(.source == $s) | .time] | max // empty')
	[ -n "$time" ] || die "no snapshot of $src"
	pve_src=$(api admin GET /sources | jq -r '.[] | select(.kind == "pve" and .name == "pve-test") | .id')
	j=$(api admin POST /jobs "$(jq -nc --arg s "$src" --argjson t "$time" --argjson p "$pve_src" --argjson v "$TARGET" \
		'{kind:"restore", tenant:"lab", params:{source:$s, time:$t, source_id:$p, node:"pve-test", target:$v,
		  storage:"vmpool", bridge:"vmbr0", link_down:true}}')")
	expect 202 "restore"
	j=$(wait_job admin "$(jq -r .id <<<"$j")" 3600)
	jq -r ".log // \"\"" <<<"$j" | grep -E "note:|restored|error" | tail -6 >&2 || true
	[ "$(jq -r .state <<<"$j")" = ok ] || die "restore: $(jq -c '{state, error}' <<<"$j")"
	pve "qm config $TARGET" | grep -E "^(name|memory|cores|bios|efidisk|sata|net|boot)" >&2
	pve "qm destroy $TARGET --purge 1 >/dev/null" && log "VM $TARGET restored and removed again"
}

# #39 M4: the newest hv- snapshot of $VM back onto the Hyper-V host as VM nx-rct-restored, checked, removed again
step_restore_back() {
	local vm src time sid j
	vm=$(win "(Get-VM $VM).Id.ToString().ToLower()" | tr -d '\r')
	src="hv-$vm"
	time=$(api admin GET "/snapshots?tenant=lab" | jq -r --arg s "$src" '[.[] | select(.source == $s) | .time] | max // empty')
	[ -n "$time" ] || die "no snapshot of $src"
	sid=$(api admin GET /sources | jq -r '.[] | select(.kind == "hyperv" and .name == "hv-host") | .id')
	[ -n "$sid" ] || die "no source hv-host (step group)"
	j=$(api admin POST /jobs "$(jq -nc --arg s "$src" --argjson t "$time" --argjson p "$sid" \
		'{kind:"restore", tenant:"lab", params:{source:$s, time:$t, source_id:$p, name:"nx-rct-restored"}}')")
	expect 202 "restore onto Hyper-V"
	j=$(wait_job admin "$(jq -r .id <<<"$j")" 3600)
	jq -r ".log // \"\"" <<<"$j" | grep -E "blocks written|restored|error" | tail -4 >&2 || true
	[ "$(jq -r .state <<<"$j")" = ok ] || die "restore onto Hyper-V: $(jq -c '{state, error}' <<<"$j")"
	win '$v = Get-VM nx-rct-restored; "$($v.Name) gen $($v.Generation) mem $($v.MemoryStartup / 1MB) MB cpus $($v.ProcessorCount) state $($v.State)";
	     Get-VMHardDiskDrive -VM $v | ForEach-Object { "$($_.ControllerType)$($_.ControllerNumber)-$($_.ControllerLocation) $((Get-VHD $_.Path).Size) bytes" };
	     $dir = Split-Path (Get-VMHardDiskDrive -VM $v | Select-Object -First 1).Path; Remove-VM -VM $v -Force; Remove-Item -Recurse -Force $dir; "removed"' >&2
	log "restored onto Hyper-V and removed again"
}

case ${1:?step} in
agent) step_agent ;;
restore-back) step_restore_back ;;
restore) step_restore ;;
backup) step_backup ;;
group) step_group ;;
*) die "unknown step $1" ;;
esac
