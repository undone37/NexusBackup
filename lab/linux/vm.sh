#!/usr/bin/env bash
# Small Linux test VMs from official cloud images for the Linux agent (no root on the
# host, QEMU/KVM user networking, cloud-init NoCloud seed ISO built with genisoimage /
# xorriso). Run them one at a time (1.5–2 GB RAM each).
#
#   vm.sh <vm> fetch       download + checksum-verify the cloud image (cached)
#   vm.sh <vm> create      fresh overlay disk + data disk + seed ISO (destroys the old VM)
#   vm.sh <vm> start       boot daemonized, wait for ssh + cloud-init
#   vm.sh <vm> provision   run lab/linux/provision/<vm>.sh as root (storage, DB, sample data)
#   vm.sh <vm> ssh [cmd]   ssh as the lab user (sudo works without password)
#   vm.sh <vm> put SRC DST scp to the VM
#   vm.sh <vm> stop        ACPI power-off via QMP (kill after 90 s)
#   vm.sh <vm> up          fetch + create + start + provision
#   vm.sh list             the VMs, their ports and state
#
# VMs (distro / storage under test):
#   deb-lvm      Debian 13, root moved onto LVM (ext4), data disk: thick LV ext4 (/var/lib/postgresql),
#                thin pool with an XFS LV (/srv/xfs); PostgreSQL with sample data
#   alma-xfs     AlmaLinux 10 (SELinux enforcing), data disk: LVM with XFS LVs (/srv/xfs, /var/lib/mysql);
#                MariaDB with sample data
#   ubuntu-zfs   Ubuntu 24.04, zfsutils-linux, pool `tank` on the data disk (/srv/zfs, /home)
#   fedora-btrfs Fedora 44 Cloud (btrfs root with root/home subvolumes, SELinux enforcing), /srv/btrfs subvolume
#   deb-plain    Debian 13 unchanged: ext4 on a partition, no LVM (fallback mode); MariaDB
#
# Ports on 127.0.0.1 (the appliance VM reaches them as 10.0.2.2:<port>):
#   ssh 2220+N, agent 17440+N  (N = 1..5 in the order above)
# env: LAB (/home/ah/nexus-lab), MEM (per VM default), CPUS (2), LAB_KEY ($LAB/lab_ed25519)
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
LAB=${LAB:-/home/ah/nexus-lab}
D=$LAB/linux
LAB_KEY=${LAB_KEY:-$LAB/lab_ed25519}
CPUS=${CPUS:-2}
USER_NAME=lab

# name -> "N image-url checksum-url mem datadisk-GB"
declare -A VMS=(
	[deb-lvm]="1 https://cloud.debian.org/images/cloud/trixie/latest/debian-13-genericcloud-amd64.qcow2 https://cloud.debian.org/images/cloud/trixie/latest/SHA512SUMS 1536 8"
	[alma-xfs]="2 https://repo.almalinux.org/almalinux/10/cloud/x86_64/images/AlmaLinux-10-GenericCloud-latest.x86_64.qcow2 https://repo.almalinux.org/almalinux/10/cloud/x86_64/images/CHECKSUM 1536 6"
	[ubuntu-zfs]="3 https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img https://cloud-images.ubuntu.com/noble/current/SHA256SUMS 2048 6"
	[fedora-btrfs]="4 https://download.fedoraproject.org/pub/fedora/linux/releases/44/Cloud/x86_64/images/Fedora-Cloud-Base-Generic-44-1.7.x86_64.qcow2 https://download.fedoraproject.org/pub/fedora/linux/releases/44/Cloud/x86_64/images/Fedora-Cloud-44-1.7-x86_64-CHECKSUM 1536 0"
	[deb-plain]="5 https://cloud.debian.org/images/cloud/trixie/latest/debian-13-genericcloud-amd64.qcow2 https://cloud.debian.org/images/cloud/trixie/latest/SHA512SUMS 1536 0"
)

log() { printf '[%s] %s\n' "$(date +%T)" "$*" >&2; }
die() {
	log "FAIL: $*"
	exit 1
}

vm_load() {
	[ -n "${VMS[$1]:-}" ] || die "unknown VM $1 (vm.sh list)"
	NAME=$1
	read -r N URL SUMS DEFMEM DATAGB <<<"${VMS[$1]}"
	MEM=${MEM:-$DEFMEM}
	SSH_PORT=$((2220 + N))
	AGENT_PORT=$((17440 + N))
	IMG=$D/images/$(basename "$URL")
	V=$D/$NAME
}

ssh_opts() {
	echo -o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=no \
		-o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -i "$LAB_KEY"
}

fetch() {
	mkdir -p "$D/images"
	[ -f "$IMG" ] && [ -f "$IMG.ok" ] && return 0
	log "downloading $URL"
	curl -fL --retry 3 -o "$IMG.part" "$URL"
	curl -fsL --retry 3 -o "$IMG.sums" "$SUMS"
	local f want got
	f=$(basename "$URL")
	want=$(grep -F "$f" "$IMG.sums" | grep -oE '\b[0-9a-f]{128}\b|\b[0-9a-f]{64}\b' | head -1)
	[ -n "$want" ] || die "no checksum for $f in $SUMS"
	if [ ${#want} = 128 ]; then got=$(sha512sum "$IMG.part" | cut -d' ' -f1); else got=$(sha256sum "$IMG.part" | cut -d' ' -f1); fi
	[ "$got" = "$want" ] || die "checksum mismatch for $f"
	mv "$IMG.part" "$IMG"
	touch "$IMG.ok"
	log "verified $f"
}

create() {
	fetch
	stop || true
	rm -rf "$V"
	mkdir -p "$V/seed"
	qemu-img create -q -f qcow2 -F qcow2 -b "$IMG" "$V/root.qcow2" 12G
	[ "$DATAGB" = 0 ] || qemu-img create -q -f qcow2 "$V/data.qcow2" "${DATAGB}G"
	cat >"$V/seed/meta-data" <<-EOF
		instance-id: $NAME-$(date +%s)
		local-hostname: $NAME
	EOF
	cat >"$V/seed/user-data" <<-EOF
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
	EOF
	if command -v genisoimage >/dev/null; then
		genisoimage -quiet -output "$V/seed.iso" -volid cidata -joliet -rock "$V/seed/user-data" "$V/seed/meta-data"
	else
		xorriso -as mkisofs -quiet -output "$V/seed.iso" -volid cidata -joliet -rock "$V/seed/user-data" "$V/seed/meta-data"
	fi
	log "created $V (root overlay 12G, data disk ${DATAGB} GB)"
}

running() { [ -f "$V/qemu.pid" ] && kill -0 "$(cat "$V/qemu.pid")" 2>/dev/null; }

start() {
	[ -f "$V/root.qcow2" ] || create
	if running; then
		log "$NAME already running (pid $(cat "$V/qemu.pid"))"
	else
		local data=()
		[ -f "$V/data.qcow2" ] && data=(-drive file="$V/data.qcow2",if=none,id=d1,format=qcow2,cache=unsafe,discard=unmap
			-device virtio-blk-pci,drive=d1,serial=nexus-data)
		# keep a VGA device: Debian 13's cloud kernel triple-faults right after grub without one
		qemu-system-x86_64 -name "lab-$NAME" -machine q35,accel=kvm -cpu host -smp "$CPUS" -m "$MEM" \
			-nodefaults -display none -device VGA \
			-drive file="$V/root.qcow2",if=none,id=d0,format=qcow2,cache=unsafe,discard=unmap \
			-device virtio-blk-pci,drive=d0,bootindex=1 \
			"${data[@]}" \
			-drive file="$V/seed.iso",if=virtio,format=raw,readonly=on \
			-nic user,model=virtio-net-pci,hostfwd=tcp:127.0.0.1:"$SSH_PORT"-:22,hostfwd=tcp:127.0.0.1:"$AGENT_PORT"-:7444 \
			-serial file:"$V/serial.log" \
			-object rng-random,id=rng0,filename=/dev/urandom -device virtio-rng-pci,rng=rng0 \
			-qmp unix:"$V/qmp.sock",server=on,wait=off \
			-daemonize -pidfile "$V/qemu.pid"
		log "$NAME started (pid $(cat "$V/qemu.pid"), ${MEM} MB), ssh :$SSH_PORT, agent :$AGENT_PORT"
	fi
	local t0=$SECONDS
	until vssh true 2>/dev/null; do
		[ $((SECONDS - t0)) -lt 600 ] || die "$NAME: no ssh after 600 s (see $V/serial.log)"
		running || die "$NAME: qemu exited (see $V/serial.log)"
		sleep 3
	done
	vssh 'cloud-init status --wait >/dev/null 2>&1 || true'
	log "$NAME up after $((SECONDS - t0)) s: $(vssh 'uname -r; . /etc/os-release; echo $PRETTY_NAME' | tr '\n' ' ')"
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

# shellcheck disable=SC2046
vssh() { ssh $(ssh_opts) -p "$SSH_PORT" "$USER_NAME@127.0.0.1" "$@"; }
# shellcheck disable=SC2046
vput() { scp -q $(ssh_opts) -P "$SSH_PORT" "$1" "$USER_NAME@127.0.0.1:$2"; }

provision() {
	local p=$here/provision/$NAME.sh
	[ -f "$p" ] || die "no $p"
	vssh 'mkdir -p /var/tmp/nexus-lab'
	vput "$here/provision/common.sh" /var/tmp/nexus-lab/common.sh
	vput "$p" /var/tmp/nexus-lab/provision.sh
	local t0=$SECONDS
	vssh 'sudo bash /var/tmp/nexus-lab/provision.sh' 2>&1 | sed "s/^/[$NAME] /"
	# provision scripts may reboot the VM (root moved onto LVM)
	if vssh 'test -f /run/nexus-lab-reboot' 2>/dev/null; then
		log "$NAME: rebooting"
		local boot
		boot=$(vssh cat /proc/sys/kernel/random/boot_id)
		vssh 'sudo systemctl reboot' || true
		until [ "$(vssh cat /proc/sys/kernel/random/boot_id 2>/dev/null)" != "" ] &&
			[ "$(vssh cat /proc/sys/kernel/random/boot_id 2>/dev/null)" != "$boot" ]; do
			running || die "$NAME: qemu exited during the reboot"
			sleep 3
		done
		start
		vssh 'sudo bash /var/tmp/nexus-lab/provision.sh after-reboot' 2>&1 | sed "s/^/[$NAME] /"
	fi
	log "$NAME provisioned in $((SECONDS - t0)) s"
}

case ${1:-} in
list)
	for n in deb-lvm alma-xfs ubuntu-zfs fedora-btrfs deb-plain; do
		vm_load "$n"
		st=stopped
		running && st="running (pid $(cat "$V/qemu.pid"))"
		printf '%-13s ssh 127.0.0.1:%s agent 127.0.0.1:%s (10.0.2.2:%s)  %s\n' "$n" "$SSH_PORT" "$AGENT_PORT" "$AGENT_PORT" "$st"
	done
	;;
"" | -h | --help) sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//' ;;
*)
	vm_load "$1"
	cmd=${2:-}
	shift 2 || true
	case $cmd in
	fetch) fetch ;;
	create) create ;;
	start) start ;;
	stop) stop ;;
	provision) provision ;;
	ssh) vssh "$@" ;;
	put) vput "$@" ;;
	up)
		create
		start
		provision
		;;
	ports) echo "$SSH_PORT $AGENT_PORT" ;;
	*) die "unknown command $cmd" ;;
	esac
	;;
esac
