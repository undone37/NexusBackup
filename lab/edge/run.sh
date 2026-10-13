#!/usr/bin/env bash
# Boots the edge proxy disk under unprivileged QEMU/KVM (daemonized), like lab/appliance/run.sh.
#   run.sh start [disk.qcow2]   boot (serial console on $LAB/edge/console.sock)
#   run.sh stop                 ACPI power-off via QMP, then kill after 60 s
#   run.sh console              attach to the serial console (socat, ^] quits)
# Network: QEMU user networking (guest 10.0.2.15). Forwards on the host:
#   127.0.0.1:$PUB (18443) -> 443  public agent port (lab VMs reach it as 10.0.2.2:$PUB)
#   127.0.0.1:$CTL (17445) -> 7445 control port (the dev control plane on the host dials it)
# env: LAB (/home/ah/nexus-lab), PUB, CTL, MEM (1024), CPUS (2)
set -euo pipefail
LAB=${LAB:-/home/ah/nexus-lab}
D=$LAB/edge
PUB=${PUB:-18443}
CTL=${CTL:-17445}
MEM=${MEM:-1024}
CPUS=${CPUS:-2}

start() {
	local disk=${1:-$D/edge.qcow2}
	[ -f "$disk" ] || { echo "no disk $disk (lab/edge/e2e.sh disk)" >&2; exit 1; }
	rm -f "$D/console.sock" "$D/qmp.sock"
	: >"$D/serial.log"
	qemu-system-x86_64 -name nexus-edge -machine q35,accel=kvm -cpu host -smp "$CPUS" -m "$MEM" \
		-nodefaults -display none -vga none \
		-drive file="$disk",if=none,id=d0,format=qcow2,cache=unsafe,discard=unmap \
		-device virtio-blk-pci,drive=d0,bootindex=1 \
		-nic user,model=virtio-net-pci,hostfwd=tcp:127.0.0.1:"$PUB"-:443,hostfwd=tcp:127.0.0.1:"$CTL"-:7445 \
		-chardev socket,id=ser0,path="$D/console.sock",server=on,wait=off,logfile="$D/serial.log" \
		-serial chardev:ser0 \
		-object rng-random,id=rng0,filename=/dev/urandom -device virtio-rng-pci,rng=rng0 \
		-qmp unix:"$D/qmp.sock",server=on,wait=off \
		-daemonize -pidfile "$D/qemu.pid"
	echo "started (pid $(cat "$D/qemu.pid")), serial log $D/serial.log, public 127.0.0.1:$PUB, control 127.0.0.1:$CTL"
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
}

mkdir -p "$D"
case ${1:-} in
start) shift; start "$@" ;;
stop) stop ;;
console) exec socat -,raw,echo=0,escape=0x1d UNIX-CONNECT:"$D/console.sock" ;;
*) sed -n '2,9p' "$0" >&2; exit 2 ;;
esac
