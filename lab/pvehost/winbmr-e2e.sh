#!/usr/bin/env bash
# Windows bare-metal recovery end to end (#19 M1, docs/bmr.md "Windows"): this tree's Windows agent on a lab Windows
# Server 2022 VM (default VM 293, a clone of VM 242: SeaBIOS, MBR, System Reserved + C:), a backup with volume images
# (VSS), then a P2V restore through the appliance onto a new PVE VM (the rescue ISO of this tree writes the partition
# table, the MBR boot code and the images), which must boot Windows (its guest agent answers). Through the tunnel of
# deploy.sh; Windows driven through the guest agent.
#
#   winbmr-e2e.sh agent     agent "$AGENT" on the appliance; nexus-agent.exe (crates/agent-windows/build.sh --test-key)
#                           on VM $VMID: init with the token, service, firewall rule for TCP 7444; enrolled
#   winbmr-e2e.sh backup    backup job {agent_id, images: true}: the file tree plus an image per partition
#   winbmr-e2e.sh iso       the rescue ISO (target/rescue/nexus-rescue-*.iso, restore-vm/rescue/build.sh) to local:iso
#   winbmr-e2e.sh p2v       P2V of the newest snapshot as VM $TARGET (SATA, e1000e), the rescue check-in, the
#                           recovery started and awaited; the VM booted from its disk until its guest agent answers
#   winbmr-e2e.sh recover   (part of p2v) the rescue check-in, the recovery, the boot check
#   winbmr-e2e.sh clean     VM $TARGET removed
#
# env: as deploy.sh (LAB ~/nexus-lab/pvehost, PORT 28444); VMID (293), AGENT (nx-winbmr), TARGET (272),
#      PVE_SOURCE (the appliance's PVE source of pve-test, by name: pve-test), STORAGE (vmpool),
#      APPLIANCE (10.2.34.211:8443: the address the rescue system checks in with)
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
export LAB=${LAB:-$HOME/nexus-lab/pvehost}
export PORT=${PORT:-28444}
VMID=${VMID:-293}
AGENT=${AGENT:-nx-winbmr}
TARGET=${TARGET:-272}
STORAGE=${STORAGE:-vmpool}
PVE_HOST=${PVE_HOST:-10.2.34.200}
SSH_KEY=${SSH_KEY:-$HOME/nexus-lab/pve-lab-key}
EXE=${EXE:-$repo/target/agent-dist/windows/nexus-agent.exe}
ROOT=$LAB/appliance/root
S=$ROOT/run/api
mkdir -p "$S"
# shellcheck disable=SC1091
. "$ROOT/secrets.env"
# shellcheck source=lab/e2e/api-lib.sh
. "$repo/lab/e2e/api-lib.sh"
for v in "$VMID" "$TARGET"; do
	[ "$v" -ge 200 ] || die "VM $v: only VMs from 200 are ours"
done
win() { "$repo/lab/windows/gexec.py" "$VMID" "$1"; }
pve() { ssh -n -i "$SSH_KEY" -o BatchMode=yes "root@$PVE_HOST" "$@" 2> >(grep -v 'older storage API' >&2); }
login admin "$ADMIN_PW" "$ADMIN_TOTP"
agent_id() { api admin GET /agents | jq -r --arg n "$AGENT" '.[] | select(.name == $n) | .id'; }

step_agent() {
	local id r tok ip j
	pve "qm start $VMID 2>/dev/null || true"
	for _ in $(seq 60); do win 'exit 0' >/dev/null 2>&1 && break; sleep 10; done
	id=$(agent_id)
	if [ -n "$id" ]; then
		# the binary the existing service runs (a clone may carry an older agent at another path)
		"$repo/lab/windows/gexec.py" "$VMID" --put "$EXE" 'C:\nx\agent\nexus-agent.new.exe' >/dev/null
		win '$p = ((sc.exe qc NexusAgent | Select-String BINARY_PATH).ToString() -split ":", 2)[1].Trim().Split(" ")[0]
		     Stop-Service NexusAgent -ErrorAction SilentlyContinue; Copy-Item -Force C:\nx\agent\nexus-agent.new.exe $p
		     Start-Service NexusAgent; "${p}: $((Get-Service NexusAgent).Status)"' >&2
		log "agent $AGENT exists ($id): binary replaced"
		if [ "$(api admin GET /agents | jq -r --arg a "$id" '.[] | select(.id == $a) | .cert_sha256 // empty')" = "" ]; then
			r=$(api admin POST "/agents/$id/enroll")
			expect 202 "enroll $AGENT"
			j=$(wait_job admin "$(jq -r .id <<<"$r")" 600)
			[ "$(jq -r .state <<<"$j")" = ok ] || die "enroll $AGENT: $(jq -r .log <<<"$j" | tail -n 20)"
			log "agent $AGENT enrolled"
		fi
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
	local id r j
	id=$(agent_id)
	[ -n "$id" ] || die "no agent $AGENT (step agent)"
	# the agent's source (kind linux covers Windows agents): a small file tree; the images carry the machine
	if ! api admin GET /sources | jq -e --arg a "$id" '.[] | select(.kind == "linux" and .config.agent_id == $a)' >/dev/null; then
		api admin POST /sources "$(jq -nc --arg a "$id" --arg n "$AGENT" \
			'{tenant:"lab", kind:"linux", name:$n, config:{agent_id:$a, paths:["C:\\Users"]}}')" >/dev/null
		expect 201 "agent source"
	fi
	r=$(api admin POST /jobs "$(jq -nc --arg a "$id" '{kind:"backup", tenant:"lab", params:{agent_id:$a, images:true}}')")
	expect 202 "backup job"
	j=$(wait_job admin "$(jq -r .id <<<"$r")" 7200)
	jq -r .log <<<"$j" | grep -E 'layout|image |committed|warning|error' | head -20 | sed 's/^/    /' >&2
	[ "$(jq -r .state <<<"$j")" = ok ] || die "backup: $(jq -r .log <<<"$j" | tail -n 30)"
	log "backup job $(jq -r .id <<<"$j") in $(jq '.finished - .started' <<<"$j") s"
}

step_iso() {
	local iso
	iso=$(ls -t "$repo"/target/rescue/nexus-rescue-*.iso 2>/dev/null | head -1)
	[ -n "$iso" ] || die "no rescue ISO (restore-vm/rescue/build.sh)"
	scp -q -i "$SSH_KEY" -o BatchMode=yes "$iso" "root@$PVE_HOST:/var/lib/vz/template/iso/nexus-rescue-winbmr.iso"
	log "rescue ISO $(basename "$iso") as local:iso/nexus-rescue-winbmr.iso"
}

step_p2v() {
	local id snap src r j sess end
	id=$(agent_id)
	snap=$(api admin GET '/snapshots?tenant=lab' | jq -r --arg s "host-$id" '[.[] | select(.source == $s)] | sort_by(.time) | .[-1].time')
	[ -n "$snap" ] && [ "$snap" != null ] || die "no snapshot of host-$id"
	src=$(api admin GET /sources | jq -r '.[] | select(.kind == "pve" and .name == "'"${PVE_SOURCE:-pve-test}"'") | .id' | head -1)
	[ -n "$src" ] || die "no PVE source ${PVE_SOURCE:-pve-test}"
	pve "qm status $TARGET >/dev/null 2>&1" && die "VM $TARGET exists (step clean)"
	r=$(api admin POST "/agents/$id/p2v" "$(jq -nc --arg ap "${APPLIANCE:-10.2.34.211:8443}" --argjson t "$snap" --argjson s "$src" --argjson v "$TARGET" --arg st "$STORAGE" \
		'{time:$t, source_id:$s, node:"pve-test", vmid:$v, name:"winbmr-p2v", storage:$st, iso:"local:iso/nexus-rescue-winbmr.iso",
		  bridge:"vmbr0", memory:4096, cores:2, appliance:$ap}')")
	expect 202 "p2v job"
	j=$(wait_job admin "$(jq -r .p2v_job <<<"$r")" 1800)
	[ "$(jq -r .state <<<"$j")" = ok ] || die "p2v: $(jq -r .log <<<"$j" | tail -n 30)"
	log "VM $TARGET created (rescue session $(jq -r .session <<<"$r"))"
	step_recover
}

step_recover() {
	local id snap r j sess end
	id=$(agent_id)
	snap=$(api admin GET '/snapshots?tenant=lab' | jq -r --arg s "host-$id" '[.[] | select(.source == $s)] | sort_by(.time) | .[-1].time')
	log "waiting for the rescue check-in"
	end=$(($(date +%s) + 900))
	until sess=$(api admin GET /rescue | jq -r --arg a "$id" '[.[] | select(.agent_id == $a and .state == "waiting")] | .[-1].id // empty') && [ -n "$sess" ]; do
		[ "$(date +%s)" -lt "$end" ] || die "no rescue check-in within 15 minutes"
		sleep 15
	done
	log "rescue session $sess; starting the recovery of snapshot $snap"
	r=$(api admin POST "/rescue/$sess/start" "$(jq -nc --argjson t "$snap" '{time:$t, reboot:true}')")
	expect 202 "rescue start"
	j=$(wait_job admin "$(jq -r .id <<<"$r")" 7200)
	jq -r .log <<<"$j" | grep -E 'image|boot code|partition|warning|error|finished' | head -20 | sed 's/^/    /' >&2
	[ "$(jq -r .state <<<"$j")" = ok ] || die "recovery: $(jq -r .log <<<"$j" | tail -n 30)"
	log "recovery job $(jq -r .id <<<"$j") in $(jq '.finished - .started' <<<"$j") s; booting from the disk"
	pve "qm set $TARGET --boot order=sata0 >/dev/null; qm set $TARGET --delete ide2 >/dev/null 2>&1 || true; qm stop $TARGET >/dev/null 2>&1; qm start $TARGET"
	end=$(($(date +%s) + 900))
	local t0
	t0=$(date +%s)
	until pve "qm guest cmd $TARGET ping" >/dev/null 2>&1; do
		[ "$(date +%s)" -lt "$end" ] || die "the restored Windows did not answer within 15 minutes (console: qm terminal / VNC)"
		sleep 10
	done
	log "restored Windows boots: guest agent answers after $(($(date +%s) - t0)) s; $(pve "qm guest cmd $TARGET get-host-name" | jq -r '.["host-name"]')"
}

step_clean() {
	pve "qm stop $TARGET >/dev/null 2>&1; qm destroy $TARGET --purge >/dev/null 2>&1" || true
	log "VM $TARGET removed"
}

for s in "$@"; do
	"step_$s"
done
