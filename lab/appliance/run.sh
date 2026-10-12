#!/usr/bin/env bash
# Boots the appliance disk under unprivileged QEMU/KVM (daemonized).
#   run.sh start [disk.qcow2]   boot (BIOS, serial console on a unix socket)
#   run.sh stop                 ACPI power-off via QMP, then kill after 60 s
#   run.sh console              attach to the serial console (socat, ^] quits)
# Network: QEMU user networking (guest 10.0.2.15/24 via DHCP, gateway/host alias
# 10.0.2.2 = the host's 127.0.0.1, so the nested PVE lab is 10.0.2.2:18006 /
# 10.0.2.2:10022 and the SFTP testbox 10.0.2.2:2223). Management port 8443 is
# forwarded to 127.0.0.1:$PORT (28443).
# env: LAB (/home/ah/nexus-lab), PORT (28443), MEM (3072), CPUS (4), TPM=1 (swtpm),
#      EXTRA_DISKS=N: N virtio data disks (serial NXLAB-D<i>, EXTRA_GB each, default 2),
#      NVME=N: N emulated NVMe drives (serial NXLAB-NVME<i>, SMART log works: lab/appliance/disks.sh);
#      their qcow2 files persist in $LAB/appliance/extra (delete them for blank disks)
set -euo pipefail
LAB=${LAB:-/home/ah/nexus-lab}
D=$LAB/appliance
PORT=${PORT:-28443}
MEM=${MEM:-3072}
CPUS=${CPUS:-4}

start() {
	local disk=${1:-$D/appliance.qcow2}
	[ -f "$disk" ] || { echo "no disk $disk (lab/appliance/build-disk.sh)" >&2; exit 1; }
	rm -f "$D/console.sock" "$D/qmp.sock"
	: >"$D/serial.log"
	local tpm=() extra=()
	if [ "${EXTRA_DISKS:-0}" -gt 0 ] || [ "${NVME:-0}" -gt 0 ]; then
		mkdir -p "$D/extra"
		for i in $(seq 1 "${EXTRA_DISKS:-0}"); do
			[ -f "$D/extra/d$i.qcow2" ] || qemu-img create -q -f qcow2 "$D/extra/d$i.qcow2" "${EXTRA_GB:-2}G"
			extra+=(-drive file="$D/extra/d$i.qcow2",if=none,id=x$i,format=qcow2,cache=unsafe
				-device virtio-blk-pci,drive=x$i,serial=NXLAB-D$i)
		done
		for i in $(seq 1 "${NVME:-0}"); do
			[ -f "$D/extra/nvme$i.qcow2" ] || qemu-img create -q -f qcow2 "$D/extra/nvme$i.qcow2" "${EXTRA_GB:-2}G"
			extra+=(-drive file="$D/extra/nvme$i.qcow2",if=none,id=nv$i,format=qcow2,cache=unsafe
				-device nvme,drive=nv$i,serial=NXLAB-NVME$i)
		done
	fi
	if [ "${TPM:-0}" = 1 ]; then
		mkdir -p "$D/tpm"
		swtpm socket --tpm2 --tpmstate dir="$D/tpm" --ctrl type=unixio,path="$D/swtpm.sock" \
			--daemon --pid file="$D/swtpm.pid"
		tpm=(-chardev socket,id=chrtpm,path="$D/swtpm.sock" -tpmdev emulator,id=tpm0,chardev=chrtpm
			-device tpm-tis,tpmdev=tpm0)
	fi
	qemu-system-x86_64 -name nexus-appliance -machine q35,accel=kvm -cpu host -smp "$CPUS" -m "$MEM" \
		-nodefaults -display none -vga none \
		-drive file="$disk",if=none,id=d0,format=qcow2,cache=unsafe,discard=unmap \
		-device virtio-blk-pci,drive=d0,bootindex=1 \
		-nic user,model=virtio-net-pci,hostfwd=tcp:127.0.0.1:"$PORT"-:8443 \
		-chardev socket,id=ser0,path="$D/console.sock",server=on,wait=off,logfile="$D/serial.log" \
		-serial chardev:ser0 \
		-object rng-random,id=rng0,filename=/dev/urandom -device virtio-rng-pci,rng=rng0 \
		"${tpm[@]}" "${extra[@]}" \
		-qmp unix:"$D/qmp.sock",server=on,wait=off \
		-daemonize -pidfile "$D/qemu.pid"
	echo "started (pid $(cat "$D/qemu.pid")), serial log $D/serial.log, https://127.0.0.1:$PORT"
}

stop() {
	[ -f "$D/qemu.pid" ] || return 0
	local pid
	pid=$(cat "$D/qemu.pid")
	printf '{"execute":"qmp_capabilities"}\n{"execute":"system_powerdown"}\n' |
		socat - UNIX-CONNECT:"$D/qmp.sock" >/dev/null 2>&1 || true
	for _ in $(seq 60); do kill -0 "$pid" 2>/dev/null || break; sleep 1; done
	kill "$pid" 2>/dev/null || true
	rm -f "$D/qemu.pid"
	[ -f "$D/swtpm.pid" ] && kill "$(cat "$D/swtpm.pid")" 2>/dev/null || true
}

case ${1:-} in
start) shift; start "$@" ;;
stop) stop ;;
console) exec socat -,raw,echo=0,escape=0x1d UNIX-CONNECT:"$D/console.sock" ;;
*) sed -n '2,14p' "$0" >&2; exit 2 ;;
esac
