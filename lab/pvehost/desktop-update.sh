#!/usr/bin/env bash
# Linux agent update with the desktop UI running (#66, plan.md Phase 39 L6): an agent test VM (agent-vms.sh) with a
# desktop session (XFCE, LightDM logs in user `desk`, a member of nexus-agent-ui), the packaged agent and desktop
# package of release $FROM; the appliance pushes release $TO, whose desktop package is newer. Shows what the running
# tray program does across the agent's restart and the package replacing its binary.
#
#   desktop-update.sh vm       $VM back to clean-os, XFCE + LightDM autologin, the $FROM packages, rebooted
#   desktop-update.sh enrol    the agent enrolled as $AGENT_NAME (clean-restore.sh enrol)
#   desktop-update.sh gui      the tray program of `desk`: process, version, its UI socket; a screen capture
#   desktop-update.sh update   $TO uploaded and pushed (agent-release.sh upload update), then `gui` again
#   desktop-update.sh relogin  `desk` logged in again (LightDM restarted): the new tray program
#
# env: as agent-release.sh (LAB, PORT); VM (debian-13), FROM (0.1.21), TO (0.1.22), REL (~/nexus-lab/scratch: the
#      nexus-agent-release-<v>-signed.tar files), VM_KEY, OUT (~/nexus-lab/scratch/desktop-update)
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
VM=${VM:-debian-13}
FROM=${FROM:-0.1.21}
TO=${TO:-0.1.22}
REL=${REL:-$HOME/nexus-lab/scratch}
VM_KEY=${VM_KEY:-$HOME/nexus-lab/lab_ed25519}
OUT=${OUT:-$HOME/nexus-lab/scratch/desktop-update}
PVE_HOST=${PVE_HOST:-10.2.34.200}
SSH_KEY=${SSH_KEY:-$HOME/nexus-lab/pve-lab-key}
export AGENT_NAME=${AGENT_NAME:-clean-$VM}
mkdir -p "$OUT"
T0=$(date +%s)
log() { printf '[%4ss] %s\n' $(($(date +%s) - T0)) "$*" >&2; }
die() {
	log "FAIL: $*"
	exit 1
}
SSHO=(-i "$VM_KEY" -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ConnectTimeout=10)
ip() { "$here/agent-vms.sh" ip "$VM" 2>/dev/null | awk '{print $3}'; }
vm() { ssh "${SSHO[@]}" "root@$VM_IP" "$@"; }
vmid() { "$here/agent-vms.sh" list 2>/dev/null | awk -v n="$VM" '$2 == n {print $1}'; }
pve() { ssh -n -i "$SSH_KEY" -o BatchMode=yes "root@$PVE_HOST" "$@"; }

wait_ssh() {
	for _ in $(seq 1 60); do
		VM_IP=$(ip) && [ -n "$VM_IP" ] && vm true 2>/dev/null && return
		sleep 5
	done
	die "$VM: no SSH"
}

step_vm() {
	"$here/agent-vms.sh" reset "$VM" >/dev/null
	pve "qm start $(vmid)"
	wait_ssh
	vm 'export DEBIAN_FRONTEND=noninteractive; apt-get -qq update && apt-get -qq install -y --no-install-recommends \
		xserver-xorg xfce4 xfce4-panel xfce4-session lightdm lightdm-gtk-greeter dbus-x11 \
		libayatana-appindicator3-1 >/dev/null 2>&1; id desk >/dev/null 2>&1 || useradd -m -s /bin/bash desk
		mkdir -p /etc/lightdm/lightdm.conf.d
		printf "[Seat:*]\nautologin-user=desk\nautologin-session=xfce\n" >/etc/lightdm/lightdm.conf.d/50-autologin.conf
		systemctl set-default graphical.target >/dev/null'
	local d=$REL/pkgs-$FROM
	mkdir -p "$d"
	tar -C "$d" -xf "$REL/nexus-agent-release-$FROM-signed.tar" --wildcards "*/linux-x86_64/*.deb"
	scp -q "${SSHO[@]}" "$d"/"$FROM"/linux-x86_64/*.deb "root@$VM_IP:/tmp/"
	vm 'apt-get -qq install -y /tmp/nexus-agent_*.deb /tmp/nexus-agent-desktop_*.deb >/dev/null 2>&1 &&
		usermod -aG nexus-agent-ui desk && dpkg-query -W nexus-agent nexus-agent-desktop | tr "\t\n" "  "; reboot' || true
	sleep 20
	wait_ssh
	log "$VM ($VM_IP): desktop session, $(vm 'dpkg-query -W -f="\${Package} \${Version}  " nexus-agent nexus-agent-desktop')"
}

step_enrol() {
	# clean-restore.sh takes the address from its output directory
	mkdir -p "$HOME/nexus-lab/scratch/clean-restore"
	ip >"$HOME/nexus-lab/scratch/clean-restore/ip"
	VM="$VM" "$here/clean-restore.sh" enrol
}

shot() {
	pve "rm -f /tmp/du.ppm; echo 'screendump /tmp/du.ppm' | qm monitor $(vmid) >/dev/null && cat /tmp/du.ppm && rm -f /tmp/du.ppm" >"$OUT/$1.ppm"
	python3 -c "from PIL import Image; Image.open('$OUT/$1.ppm').save('$OUT/$1.png')" && rm -f "$OUT/$1.ppm"
	log "screen: $OUT/$1.png"
}

step_gui() {
	wait_ssh
	vm 'p=$(pgrep -u desk -x nexus-agent-gui || true); [ -n "$p" ] || { echo "no tray program of desk"; exit 0; }
		for x in $p; do echo "pid $x since $(ps -o lstart= -p $x), exe $(readlink /proc/$x/exe)"; done
		echo "installed: $(/usr/bin/nexus-agent-gui --version 2>/dev/null), agent $(nexus-agent version | head -1)"
		echo "UI socket peers: $(ss -xp 2>/dev/null | grep -c nexus-agent-gui)"' >&2
	shot "gui-${1:-before}"
}

step_update() {
	RELEASE_TAR="$REL/nexus-agent-release-$TO-signed.tar" VM_IP=$(ip) VM="$VM" "$here/agent-release.sh" upload update
	sleep 15
	step_gui after
	vm 'dpkg-query -W -f="\${Package} \${Version}\n" nexus-agent nexus-agent-desktop' >&2
}

step_relogin() {
	wait_ssh
	vm 'systemctl restart lightdm'
	sleep 25
	step_gui relogin
}

for s in "${@:-vm enrol gui update relogin}"; do
	for x in $s; do
		log "== $x"
		"step_$x"
	done
done
