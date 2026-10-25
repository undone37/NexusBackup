#!/usr/bin/env bash
# Windows agent update with the desktop UI running (#67, plan.md Phase 39 L7), on a lab Windows VM with the MSI
# installed and enrolled (e2e.sh), driven through the guest agent (gexec.py), against the appliance VM 201 (tunnel of
# lab/pvehost/deploy.sh). A local user `desk` is logged on automatically, so the tray program (Run key) runs in an
# interactive session while the appliance pushes a newer release in-band (MSI major upgrade with /qn).
#
#   gui-update.sh desk VMID     local user desk (password in $LAB_W/desk.pw), autologon, restart, the tray program runs
#   gui-update.sh gui VMID      tray program processes (session, start time), file versions, pending renames, screen
#   gui-update.sh update VMID   release $TO pushed to agent $AGENT_NAME (agent-release.sh update), then `gui`
#   gui-update.sh reboot VMID   restart (pending file renames applied), `gui` again
#
# env: LAB, PORT (as deploy.sh); TO (0.1.22, uploaded already: agent-release.sh upload), AGENT_NAME (winsrv-2022),
#      LAB_W (~/nexus-lab/windows), OUT (~/nexus-lab/scratch/gui-update)
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
step=${1:?step} VMID=${2:?VMID}
[ "$VMID" -ge 200 ] || { echo "VMID $VMID: only VMs from 200 are ours" >&2; exit 1; }
TO=${TO:-0.1.22}
export AGENT_NAME=${AGENT_NAME:-winsrv-2022}
LAB_W=${LAB_W:-$HOME/nexus-lab/windows}
OUT=${OUT:-$HOME/nexus-lab/scratch/gui-update}
PVE_HOST=${PVE_HOST:-10.2.34.200}
SSH_KEY=${SSH_KEY:-$HOME/nexus-lab/pve-lab-key}
mkdir -p "$LAB_W" "$OUT"
T0=$(date +%s)
log() { printf '[%4ss] %s\n' $(($(date +%s) - T0)) "$*" >&2; }
win() { "$here/gexec.py" "$VMID" "$1"; }
pve() { ssh -n -i "$SSH_KEY" -o BatchMode=yes "root@$PVE_HOST" "$@"; }

wait_agent() {
	for _ in $(seq 1 90); do
		win 'exit 0' >/dev/null 2>&1 && return
		sleep 5
	done
	log "FAIL: no guest agent"
	exit 1
}

shot() {
	pve "rm -f /tmp/gu.ppm; echo 'screendump /tmp/gu.ppm' | qm monitor $VMID >/dev/null && cat /tmp/gu.ppm && rm -f /tmp/gu.ppm" >"$OUT/$1.ppm"
	python3 -c "from PIL import Image; Image.open('$OUT/$1.ppm').save('$OUT/$1.png')" && rm -f "$OUT/$1.ppm"
	log "screen: $OUT/$1.png"
}

step_desk() {
	[ -f "$LAB_W/desk.pw" ] || (umask 077 && printf 'Nx1-%s\n' "$(head -c 15 /dev/urandom | base64 | tr -d '/+=')" >"$LAB_W/desk.pw")
	"$here/gexec.py" "$VMID" --put "$LAB_W/desk.pw" 'C:\nexus-lab\desk.pw' >/dev/null
	win '$pw = (Get-Content C:\nexus-lab\desk.pw -Raw).Trim(); Remove-Item C:\nexus-lab\desk.pw
		$s = ConvertTo-SecureString $pw -AsPlainText -Force
		if (-not (Get-LocalUser desk -ErrorAction SilentlyContinue)) { New-LocalUser desk -Password $s -PasswordNeverExpires | Out-Null }
		else { Set-LocalUser desk -Password $s }
		$k = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
		Set-ItemProperty $k AutoAdminLogon "1"; Set-ItemProperty $k DefaultUserName "desk"
		Set-ItemProperty $k DefaultDomainName "."; Set-ItemProperty $k DefaultPassword $pw
		shutdown /r /t 5 | Out-Null; "autologon desk set, restarting"' >&2
	sleep 60
	wait_agent
	sleep 45
	step_gui desk
}

step_gui() {
	win '$p = Get-Process nexus-agent-gui -IncludeUserName -ErrorAction SilentlyContinue
		if (-not $p) { "no tray program running" }
		foreach ($x in $p) { "pid $($x.Id) session $($x.SessionId) user $($x.UserName) since $($x.StartTime) file $($x.MainModule.FileVersionInfo.FileVersion)" }
		$d = "C:\Program Files\NexusBackup Agent"
		foreach ($f in "nexus-agent.exe", "nexus-agent-gui.exe") { "$f $((Get-Item "$d\$f").VersionInfo.FileVersion)" }
		"service: $((Get-Service NexusAgent).Status), $(& "$d\nexus-agent.exe" version | Select-Object -First 1)"
		$r = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name PendingFileRenameOperations -ErrorAction SilentlyContinue).PendingFileRenameOperations
		"pending renames: $(@($r | Where-Object { $_ -match "NexusBackup" }).Count)"' >&2
	shot "win-${1:-now}"
}

step_update() {
	RELEASE_TAR=$HOME/nexus-lab/scratch/nexus-agent-release-$TO-signed.tar VMID=$VMID TENANT=windows \
		"$repo/lab/pvehost/agent-release.sh" update
	sleep 10
	step_gui after
}

step_reboot() {
	win 'shutdown /r /t 5 | Out-Null; "restarting"' >&2
	sleep 60
	wait_agent
	sleep 45
	step_gui rebooted
}

"step_$step"
