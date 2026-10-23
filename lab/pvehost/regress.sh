#!/usr/bin/env bash
# The regression VM on the PVE lab host (plan.md Phase 44, maintainer 2026-10-23: a timer on a lab VM): a Debian 13
# clone of the agent VM 225 with a clone of this repository and the lab files the scripts need, running
# lab/pvehost/nightly.sh every night through a systemd timer. Results stay on the VM ($LAB/regress there);
# `regress.sh results` copies them here.
#
#   regress.sh vm        clone and start VM $VMID (nx-regress), host name, machine id, ssh host keys
#   regress.sh install   packages, /opt/nexusbackup (git clone of $REPO), the pyvmomi venv for the ESXi steps
#   regress.sh files     the lab files from this workstation: keys, the appliance's secrets and certificate, the
#                        Patroni and ESXi 8 state (not the appliance disk image, not bundles or work trees)
#   regress.sh timer     nexus-nightly.service + .timer ($WHEN, UTC): git pull, then nightly.sh
#   regress.sh run       start the service now (the suite takes about 2 hours)
#   regress.sh results   the result files from the VM into $LAB/regress, the newest summary printed
#   regress.sh destroy   stop and remove the VM
#
# env: PVE_HOST (10.2.34.200), SSH_KEY (~/nexus-lab/pve-lab-key), VM_KEY (~/nexus-lab/lab_ed25519), LAB (~/nexus-lab),
#      VMID (280), SRC (225), REPO (https://github.com/undone37/NexusBackup.git), WHEN (01:30)
set -euo pipefail
PVE_HOST=${PVE_HOST:-10.2.34.200}
SSH_KEY=${SSH_KEY:-$HOME/nexus-lab/pve-lab-key}
VM_KEY=${VM_KEY:-$HOME/nexus-lab/lab_ed25519}
LAB=${LAB:-$HOME/nexus-lab}
VMID=${VMID:-280}
SRC=${SRC:-225}
REPO=${REPO:-https://github.com/undone37/NexusBackup.git}
WHEN=${WHEN:-01:30}
T0=$(date +%s)
log() { printf '[%4ss] %s\n' $(($(date +%s) - T0)) "$*" >&2; }
die() {
	log "FAIL: $*"
	exit 1
}
pve() { ssh -n -i "$SSH_KEY" -o BatchMode=yes "root@$PVE_HOST" "$@"; }
mkdir -p "$LAB/regress"
ip_() { cat "$LAB/regress/ip"; }
on() {
	ssh -i "$VM_KEY" -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=no \
		-o UserKnownHostsFile=/dev/null -o LogLevel=ERROR "root@$(ip_)" "$@"
}

step_vm() {
	if ! pve "qm status $VMID" >/dev/null 2>&1; then
		log "cloning $SRC to $VMID (nx-regress)"
		pve "qm clone $SRC $VMID --full --name nx-regress --storage vmpool >/dev/null &&
			qm set $VMID --memory 2048 --onboot 1 --tags nexus-regress --description 'nightly lab regression runs (lab/pvehost/regress.sh)' >/dev/null &&
			qm start $VMID"
	fi
	local a end=$(($(date +%s) + 600))
	until a=$(pve "qm guest cmd $VMID network-get-interfaces 2>/dev/null" |
		jq -r '[.[] | select(.name != "lo") | .["ip-addresses"][]? | select(.["ip-address-type"] == "ipv4") | .["ip-address"]][0] // empty') && [ -n "$a" ]; do
		[ "$(date +%s)" -lt "$end" ] || die "no address after 10 minutes"
		sleep 10
	done
	echo "$a" >"$LAB/regress/ip"
	on "[ \"\$(hostname)\" = nx-regress ] && exit 0; hostnamectl set-hostname nx-regress
		sed -i 's/^127.0.1.1 .*/127.0.1.1 nx-regress/' /etc/hosts
		rm -f /etc/machine-id /var/lib/dbus/machine-id; systemd-machine-id-setup >/dev/null
		apt-get -qq purge 'nexus-agent*' >/dev/null 2>&1 || true
		rm -f /etc/ssh/ssh_host_*; dpkg-reconfigure -f noninteractive openssh-server >/dev/null 2>&1; systemctl restart ssh" </dev/null
	log "nx-regress: $a"
}

step_install() {
	on "set -e; export DEBIAN_FRONTEND=noninteractive
		apt-get -qq update && apt-get -qq install -y git jq curl openssl python3 python3-venv python3-pil genisoimage >/dev/null
		[ -d /opt/nexusbackup/.git ] || git clone -q $REPO /opt/nexusbackup
		git -C /opt/nexusbackup pull -q --ff-only
		mkdir -p /root/nexus-lab/esxi
		[ -x /root/nexus-lab/esxi/venv/bin/python ] || { python3 -m venv /root/nexus-lab/esxi/venv
			/root/nexus-lab/esxi/venv/bin/pip install -q pyvmomi; }
		git -C /opt/nexusbackup log --oneline -1" </dev/null
}

step_files() {
	# what the lab scripts read below ~/nexus-lab (the appliance disk image and build trees stay here)
	tar -C "$LAB" -czf - \
		--exclude='pvehost/appliance/appliance.qcow2' --exclude='pvehost/appliance/work' \
		--exclude='pvehost/appliance/bundles' --exclude='pvehost/appliance/run-offline' --exclude='pvehost/bundle' \
		--exclude='pvehost/appliance/*.sock' --exclude='pvehost/appliance/tunnel.ctl' \
		--exclude='esxi/venv' --exclude='*/cookies' \
		pve-lab-key pve-lab-key.pub lab_ed25519 lab_ed25519.pub pvehost patroni esxi8 esxi/netrc esxi/root.password \
		esxi/esxi_ecdsa esxi/esxi_ecdsa.pub esxi/ip 2>/dev/null |
		on "umask 077; mkdir -p /root/nexus-lab; tar -C /root/nexus-lab -xzf -"
	on 'du -sh /root/nexus-lab; ls /root/nexus-lab' </dev/null
}

step_timer() {
	on "cat > /etc/systemd/system/nexus-nightly.service <<EOF
[Unit]
Description=NexusBackup nightly lab regression (lab/pvehost/nightly.sh)
After=network-online.target
[Service]
Type=oneshot
Environment=HOME=/root
ExecStartPre=/usr/bin/git -C /opt/nexusbackup pull -q --ff-only
ExecStart=/opt/nexusbackup/lab/pvehost/nightly.sh
TimeoutStartSec=8h
EOF
		cat > /etc/systemd/system/nexus-nightly.timer <<EOF
[Unit]
Description=NexusBackup nightly lab regression
[Timer]
OnCalendar=*-*-* $WHEN:00 UTC
Persistent=false
[Install]
WantedBy=timers.target
EOF
		systemctl daemon-reload; systemctl enable --now nexus-nightly.timer >/dev/null 2>&1
		systemctl list-timers nexus-nightly.timer --no-pager | head -2" </dev/null
}

step_run() {
	on 'systemctl start --no-block nexus-nightly.service; systemctl is-active nexus-nightly.service' </dev/null || true
}

step_results() {
	on 'tar -C /root/nexus-lab -czf - regress' </dev/null | tar -C "$LAB" -xzf -
	local f
	f=$(ls -1 "$LAB"/regress/*.json 2>/dev/null | tail -1)
	[ -n "$f" ] || die "no results yet"
	jq -r '"\(.date) commit \(.commit): \(if .ok then "all passed" else "FAILED" end)", (.steps[] | "  \(.step): \(if .ok then "ok" else "FAILED rc=\(.rc)" end) (\(.seconds) s)")' "$f"
}

step_destroy() {
	pve "qm stop $VMID 2>/dev/null; qm destroy $VMID --purge 2>/dev/null" || true
	rm -f "$LAB/regress/ip"
	log "VM $VMID removed"
}

for s in "$@"; do
	"step_$s"
done
