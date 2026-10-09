#!/usr/bin/env bash
# NAS server lab VM for the NAS connector (docs/nas-connector.md): Debian 13 cloud
# image with nfs-kernel-server + Samba and test data on LVM (no root on the host,
# QEMU/KVM user networking, cloud-init NoCloud seed ISO).
#
#   vm.sh fetch       checksum-verified Debian 13 genericcloud image (shared with lab/linux)
#   vm.sh create      fresh overlay + 32 GB data disk + seed ISO (destroys the old VM)
#   vm.sh start       boot daemonized, wait for ssh + cloud-init
#   vm.sh provision   lab/nas/provision.sh as root (kernel modules, NFS, Samba, LVM)
#   vm.sh data ARGS   lab/nas/data.sh ARGS as root (init, many, modify, sums, snap, ...)
#   vm.sh ssh [cmd]   ssh as the lab user (passwordless sudo)
#   vm.sh put SRC DST scp to the VM
#   vm.sh stop        ACPI power-off via QMP (kill after 90 s)
#   vm.sh up          fetch + create + start + provision
#   vm.sh status      state and ports
#
# Ports on 127.0.0.1 (the appliance VM reaches them as 10.0.2.2:<port>):
#   ssh 2250, NFS 12049 (-> 2049), mountd 12048 (-> 20048), SMB 10445 (-> 445),
#   dev control plane API 18453 (-> 18443)
# Samba password of `nexusbackup`: $LAB/nas/smb-password (0600, written by provision)
# env: LAB (/home/ah/nexus-lab), MEM (3072), CPUS (4), LAB_KEY ($LAB/lab_ed25519)
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
LAB=${LAB:-/home/ah/nexus-lab}
V=$LAB/nas
LAB_KEY=${LAB_KEY:-$LAB/lab_ed25519}
MEM=${MEM:-3072}
CPUS=${CPUS:-4}
USER_NAME=lab
NAME=nas
URL=https://cloud.debian.org/images/cloud/trixie/latest/debian-13-genericcloud-amd64.qcow2
SUMS=https://cloud.debian.org/images/cloud/trixie/latest/SHA512SUMS
IMG=$LAB/linux/images/$(basename "$URL")
SSH_PORT=2250
FWD="hostfwd=tcp:127.0.0.1:$SSH_PORT-:22,hostfwd=tcp:127.0.0.1:12049-:2049,hostfwd=tcp:127.0.0.1:12048-:20048,hostfwd=tcp:127.0.0.1:10445-:445,hostfwd=tcp:127.0.0.1:18453-:18443"

log() { printf '[%s] %s\n' "$(date +%T)" "$*" >&2; }
die() {
	log "FAIL: $*"
	exit 1
}
ssh_opts() {
	echo -o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=no \
		-o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -i "$LAB_KEY"
}
# shellcheck disable=SC2046
vssh() { ssh $(ssh_opts) -p "$SSH_PORT" "$USER_NAME@127.0.0.1" "$@"; }
# shellcheck disable=SC2046
vput() { scp -q $(ssh_opts) -P "$SSH_PORT" "$1" "$USER_NAME@127.0.0.1:$2"; }
running() { [ -f "$V/qemu.pid" ] && kill -0 "$(cat "$V/qemu.pid")" 2>/dev/null; }

fetch() {
	mkdir -p "$(dirname "$IMG")"
	[ -f "$IMG" ] && [ -f "$IMG.ok" ] && return 0
	log "downloading $URL"
	curl -fL --retry 3 -o "$IMG.part" "$URL"
	curl -fsL --retry 3 -o "$IMG.sums" "$SUMS"
	local want
	want=$(grep -F "$(basename "$URL")" "$IMG.sums" | grep -oE '\b[0-9a-f]{128}\b' | head -1)
	[ "$(sha512sum "$IMG.part" | cut -d' ' -f1)" = "$want" ] || die "checksum mismatch"
	mv "$IMG.part" "$IMG"
	touch "$IMG.ok"
}

create() {
	fetch
	stop || true
	rm -rf "$V/vm"
	mkdir -p "$V/vm/seed"
	qemu-img create -q -f qcow2 -F qcow2 -b "$IMG" "$V/vm/root.qcow2" 16G
	qemu-img create -q -f qcow2 "$V/vm/data.qcow2" 32G
	cat >"$V/vm/seed/meta-data" <<-EOT
		instance-id: $NAME-$(date +%s)
		local-hostname: $NAME
	EOT
	cat >"$V/vm/seed/user-data" <<-EOT
		#cloud-config
		hostname: $NAME
		users:
		  - name: $USER_NAME
		    shell: /bin/bash
		    sudo: ALL=(ALL) NOPASSWD:ALL
		    lock_passwd: true
		    ssh_authorized_keys:
		      - $(cat "$LAB_KEY.pub")
		ssh_pwauth: false
		package_update: false
		package_upgrade: false
		growpart: {mode: auto, devices: ['/']}
	EOT
	if command -v genisoimage >/dev/null; then
		genisoimage -quiet -output "$V/vm/seed.iso" -volid cidata -joliet -rock "$V/vm/seed/user-data" "$V/vm/seed/meta-data"
	else
		xorriso -as mkisofs -quiet -output "$V/vm/seed.iso" -volid cidata -joliet -rock "$V/vm/seed/user-data" "$V/vm/seed/meta-data"
	fi
	log "created $V/vm (root overlay 16G, data disk 32G)"
}

start() {
	[ -f "$V/vm/root.qcow2" ] || create
	if running; then
		log "$NAME already running (pid $(cat "$V/qemu.pid"))"
	else
		# keep a VGA device: Debian 13's cloud kernel triple-faults right after grub without one
		qemu-system-x86_64 -name "lab-$NAME" -machine q35,accel=kvm -cpu host -smp "$CPUS" -m "$MEM" \
			-nodefaults -display none -device VGA \
			-drive file="$V/vm/root.qcow2",if=none,id=d0,format=qcow2,cache=unsafe,discard=unmap \
			-device virtio-blk-pci,drive=d0,bootindex=1 \
			-drive file="$V/vm/data.qcow2",if=none,id=d1,format=qcow2,cache=unsafe,discard=unmap \
			-device virtio-blk-pci,drive=d1,serial=nexus-data \
			-drive file="$V/vm/seed.iso",if=virtio,format=raw,readonly=on \
			-nic user,model=virtio-net-pci,"$FWD" \
			-serial file:"$V/serial.log" \
			-object rng-random,id=rng0,filename=/dev/urandom -device virtio-rng-pci,rng=rng0 \
			-qmp unix:"$V/qmp.sock",server=on,wait=off \
			-daemonize -pidfile "$V/qemu.pid"
		log "$NAME started (pid $(cat "$V/qemu.pid"), ${MEM} MB)"
	fi
	local t0=$SECONDS
	until vssh true 2>/dev/null; do
		[ $((SECONDS - t0)) -lt 600 ] || die "no ssh after 600 s (see $V/serial.log)"
		running || die "qemu exited (see $V/serial.log)"
		sleep 3
	done
	vssh 'cloud-init status --wait >/dev/null 2>&1 || true'
	log "$NAME up: $(vssh 'uname -r; . /etc/os-release; echo $PRETTY_NAME' | tr '\n' ' ')"
}

stop() {
	running || {
		rm -f "$V/qemu.pid"
		return 0
	}
	local pid
	pid=$(cat "$V/qemu.pid")
	python3 "$here/../pve/qmp.py" "$V/qmp.sock" system_powerdown >/dev/null 2>&1 || true
	for _ in $(seq 90); do
		kill -0 "$pid" 2>/dev/null || break
		sleep 1
	done
	kill "$pid" 2>/dev/null || true
	rm -f "$V/qemu.pid"
	log "$NAME stopped"
}

run_provision() {
	vssh "sudo SMB_PASSWORD='$(cat "$V/smb-password")' bash /var/tmp/nexus-lab/provision.sh" 2>&1 | sed "s/^/[$NAME] /"
}

provision() {
	mkdir -p "$V"
	if [ ! -s "$V/smb-password" ]; then
		(umask 077 && head -c 18 /dev/urandom | base64 | tr -d '/+=' >"$V/smb-password")
	fi
	vssh 'sudo install -d -m 0755 /var/tmp/nexus-lab'
	vput "$here/provision.sh" /tmp/provision.sh
	vput "$here/data.sh" /tmp/data.sh
	vssh 'sudo install -m 0755 /tmp/provision.sh /tmp/data.sh /var/tmp/nexus-lab/'
	local t0=$SECONDS
	run_provision
	if vssh 'test -f /run/nexus-lab-reboot' 2>/dev/null; then
		log "rebooting (kernel with nfsd/cifs modules)"
		local boot b
		boot=$(vssh cat /proc/sys/kernel/random/boot_id)
		vssh 'sudo systemctl reboot' || true
		sleep 5
		until b=$(vssh cat /proc/sys/kernel/random/boot_id 2>/dev/null) && [ -n "$b" ] && [ "$b" != "$boot" ]; do
			running || die "qemu exited during the reboot"
			sleep 3
		done
		run_provision
	fi
	log "provisioned in $((SECONDS - t0)) s"
}

data() {
	vput "$here/data.sh" /tmp/data.sh
	vssh 'sudo install -m 0755 /tmp/data.sh /var/tmp/nexus-lab/data.sh'
	vssh "sudo bash /var/tmp/nexus-lab/data.sh $(printf '%q ' "$@")"
}

case ${1:-} in
fetch) fetch ;;
create) create ;;
start) start ;;
stop) stop ;;
provision) provision ;;
data) shift; data "$@" ;;
ssh) shift; vssh "$@" ;;
put) shift; vput "$@" ;;
up) create; start; provision ;;
status)
	st=stopped
	running && st="running (pid $(cat "$V/qemu.pid"))"
	echo "nas: $st; ssh 127.0.0.1:$SSH_PORT, nfs 12049, mountd 12048, smb 10445, api 18453 (10.0.2.2:<port> from the appliance VM)"
	;;
*) sed -n '2,21p' "$0" | sed 's/^# \{0,1\}//'; exit 2 ;;
esac
