#!/usr/bin/env bash
# Windows agent update of a manual install (binary swap) with a release whose exe does not start (#120, #67
# "watchdog revert of a manual install"), on a clone of a lab Windows VM driven through the guest agent (gexec.py),
# against the appliance VM 201 (tunnel of lab/pvehost/deploy.sh).
#
#   swap-probe.sh install VMID EXE     EXE (crates/agent-windows/build.sh --test-key, version V0) as C:\nexus-agent.exe
#                                      (the VM's manual install), a new identity: agent "win-swap-VMID" (tenant windows)
#                                      created, init --token (stdin), the TEST release key pinned, enrolled
#   swap-probe.sh broken EXE V OUT     OUT = TEST-signed release V whose windows-x64/nexus-agent.exe is EXE cut to
#                                      1 MiB (PE headers intact, the loader refuses it) plus the version marker of V
#   swap-probe.sh update VMID TAR      TAR uploaded and pushed: the update must fail with "does not start", the
#                                      service keeps running the old version, no .prev
#
# env: LAB, PORT (as deploy.sh)
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
export LAB=${LAB:-$HOME/nexus-lab/pvehost}
export PORT=${PORT:-28444}
ROOT=$LAB/appliance/root
S=$ROOT/run/api
mkdir -p "$S"
# shellcheck disable=SC1091
. "$ROOT/secrets.env"
# shellcheck source=lab/e2e/api-lib.sh
. "$repo/lab/e2e/api-lib.sh"
win() { "$here/gexec.py" "$VMID" "$1"; }

step_install() {
	local exe=${1:?EXE} host r id tok j name
	name=win-swap-$VMID
	login admin "$ADMIN_PW" "$ADMIN_TOTP"
	win 'New-Item -ItemType Directory -Force C:\nexus-lab | Out-Null' >/dev/null
	"$here/gexec.py" "$VMID" --put "$exe" 'C:\nexus-lab\nexus-agent.exe' >/dev/null
	"$here/gexec.py" "$VMID" --put "$repo/release/testkey/TEST-cosign.pub" 'C:\nexus-lab\TEST-KEY-DO-NOT-SHIP.pub' >/dev/null
	# the clone's identity is its source's: a new one (config emptied, the TEST release key pinned)
	win 'Stop-Service NexusAgent -Force; Start-Sleep 2; Copy-Item -Force C:\nexus-lab\nexus-agent.exe C:\nexus-agent.exe
		Remove-Item -Force -ErrorAction SilentlyContinue C:\nexus-agent.exe.prev
		$c = "$env:ProgramData\NexusAgent\config"; Get-ChildItem $c -Exclude release-keys | Remove-Item -Recurse -Force
		New-Item -ItemType Directory -Force "$c\release-keys" | Out-Null; Remove-Item "$c\release-keys\*" -Force -ErrorAction SilentlyContinue
		Copy-Item C:\nexus-lab\TEST-KEY-DO-NOT-SHIP.pub "$c\release-keys\"
		Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:ProgramData\NexusAgent\state\update-*"
		if (-not (Get-NetFirewallRule -DisplayName "NexusAgent 7444 (lab)" -ErrorAction SilentlyContinue)) {
			New-NetFirewallRule -DisplayName "NexusAgent 7444 (lab)" -Direction Inbound -Protocol TCP -LocalPort 7444 -RemoteAddress 10.2.34.211 -Action Allow | Out-Null }
		& C:\nexus-agent.exe version' >&2
	host=$(win '(Get-NetIPAddress -AddressFamily IPv4 | ? { $_.IPAddress -notlike "127.*" -and $_.PrefixOrigin -ne "WellKnown" } | Select -First 1).IPAddress' | tr -d '\r\n')
	id=$(api admin GET /agents | jq -r --arg n "$name" '.[] | select(.name == $n) | .id')
	if [ -z "$id" ]; then
		r=$(api admin POST /agents "$(jq -nc --arg n "$name" --arg h "$host" '{tenant:"windows", name:$n, host:$h, port:7444}')")
		expect 201 "create agent"
		id=$(jq -r .id <<<"$r")
	fi
	r=$(api admin POST "/agents/$id/token")
	expect 200 "agent token"
	tok=$(jq -r .token <<<"$r")
	# the token goes in on stdin, as the manual says (not on the command line)
	win "Set-Content C:\\nexus-lab\\tok -NoNewline '$tok'; Get-Content C:\\nexus-lab\\tok | & C:\\nexus-agent.exe init --token -; Remove-Item C:\\nexus-lab\\tok; Start-Service NexusAgent; Start-Sleep 2; (Get-Service NexusAgent).Status" >&2
	r=$(api admin POST "/agents/$id/enroll")
	expect 202 "enroll"
	j=$(wait_job admin "$(jq -r .id <<<"$r")" 300)
	[ "$(jq -r .state <<<"$j")" = ok ] || die "enroll: $(jq -r '.log // ""' <<<"$j" | tail -n 15)"
	log "agent $name ($id, $host) enrolled: $(api admin GET /agents | jq -c --arg id "$id" '.[] | select(.id == $id) | {version, os}')"
}

step_broken() {
	local exe=${1:?EXE} v=${2:?V} out=${3:?OUT} w f
	w=$(mktemp -d "$HOME/nexus-lab/scratch/swap-probe.XXXXXX")
	f=$w/$v/windows-x64/nexus-agent.exe
	mkdir -p "${f%/*}"
	{ head -c 1048576 "$exe"; printf '\0NEXUS-AGENT-VERSION=%s\0' "$v"; } >"$f"
	jq -n --arg v "$v" --argjson size "$(stat -c %s "$f")" --arg sha "$(sha256sum "$f" | cut -d' ' -f1)" \
		'{format:1, version:$v, protocol:"1.8", min_appliance:"", released:(now | todate), notes:"lab: exe that does not start (#120)",
		  artifacts:[{name:"windows-x64/nexus-agent.exe", kind:"binary", os:"windows", arch:"x86_64", version:$v, size:$size, sha256:$sha}]}' \
		>"$w/$v/manifest.json"
	(cd "$repo" && COSIGN_KEY=release/testkey/TEST-cosign.key COSIGN_PASSWORD=nexus-test-key release/sign.sh sign-agent-release "$w/$v") >&2
	tar -C "$w" -cf "$out" "$v"
	rm -rf "$w"
	log "$out: release $v, its exe cut to 1 MiB, TEST-signed"
}

step_update() {
	local tar=${1:?TAR} v id j before
	v=$(tar -tf "$tar" | awk -F/ 'NR == 1 {print $1}')
	RELEASE_TAR=$tar "$repo/lab/pvehost/agent-release.sh" upload </dev/null
	login admin "$ADMIN_PW" "$ADMIN_TOTP"
	id=$(api admin GET /agents | jq -r --arg n "win-swap-$VMID" '.[] | select(.name == $n) | .id')
	before=$(win '& C:\nexus-agent.exe version' | tr -d '\r')
	j=$(api admin POST /jobs "$(jq -nc --arg a "$id" --arg v "$v" '{kind:"agent_update", tenant:"windows", params:{agent_id:$a, version:$v}}')")
	expect 202 "agent_update"
	j=$(wait_job admin "$(jq -r .id <<<"$j")" 900)
	jq -r '.log // ""' <<<"$j" | grep -E "^update-(plan|result) " | cut -c1-300 >&2 || true
	[ "$(jq -r .state <<<"$j")" != ok ] || die "the broken release was installed"
	jq -r '.log // ""' <<<"$j" | grep -q "does not start" || die "refused for another reason: $(jq -r '.log // ""' <<<"$j" | tail -n 5)"
	win "if (Test-Path C:\\nexus-agent.exe.prev) { 'prev exists' }; (Get-Service NexusAgent).Status; & C:\\nexus-agent.exe version" >&2
	[ "$(win '& C:\nexus-agent.exe version' | tr -d '\r')" = "$before" ] || die "the installed binary changed"
	[ "$(win '(Get-Service NexusAgent).Status' | tr -d '\r\n')" = Running ] || die "the service is not running"
	log "release $v refused before the swap; the service still runs $before"
}

case ${1:-} in
install) VMID=${2:?VMID} step_install "${3:-}" ;;
broken) step_broken "${2:-}" "${3:-}" "${4:-}" ;;
update) VMID=${2:?VMID} step_update "${3:-}" ;;
*) sed -n '2,15p' "$0" >&2 && exit 2 ;;
esac
