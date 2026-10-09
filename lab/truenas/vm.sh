#!/usr/bin/env bash
# TrueNAS Community lab VM (QEMU/KVM, no host root).
#
#   vm.sh fetch              download + sha256-verify the ISO (VERSION, default 25.10.7)
#   vm.sh install            fresh disks, boot the ISO, unattended install (install.py), power off
#   vm.sh start | stop | status
#
# Ports (127.0.0.1 only): https://localhost:18444 (API/UI), ssh -p 12222, installer 18080 (install only)
# 3 disks: boot (20 GB), data1 + data2 (8 GB each, mirror pool "tank"). State in $LAB/truenas.
set -euo pipefail
LAB="${LAB:-/home/ah/nexus-lab}"
D="$LAB/truenas"
VERSION="${VERSION:-25.10.7}"
ISO="$D/iso/TrueNAS-SCALE-$VERSION.iso"
MEM="${MEM:-8192}"
CPUS="${CPUS:-4}"
PID="$D/vm.pid"
HERE="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "$D"

running() { [ -f "$PID" ] && kill -0 "$(cat "$PID")" 2>/dev/null; }

qemu() { # extra args...
  qemu-system-x86_64 -name truenas \
    -machine q35,accel=kvm -cpu host -smp "$CPUS" -m "$MEM" \
    -drive file="$D/boot.qcow2",if=none,id=boot,format=qcow2,cache=writeback,discard=unmap \
    -device virtio-blk-pci,drive=boot,serial=NXBOOT,bootindex=1 \
    -drive file="$D/data1.qcow2",if=none,id=d1,format=qcow2,cache=writeback,discard=unmap \
    -device virtio-blk-pci,drive=d1,serial=NXDATA1 \
    -drive file="$D/data2.qcow2",if=none,id=d2,format=qcow2,cache=writeback,discard=unmap \
    -device virtio-blk-pci,drive=d2,serial=NXDATA2 \
    -device virtio-net-pci,netdev=n0 \
    -display none -serial file:"$D/serial.log" \
    -qmp unix:"$D/vm.qmp",server,nowait \
    -daemonize -pidfile "$PID" "$@"
}

case "${1:-}" in
fetch)
  mkdir -p "$D/iso"
  base="https://download.sys.truenas.net/TrueNAS-SCALE-Goldeye/$VERSION/TrueNAS-SCALE-$VERSION.iso"
  [ -f "$ISO.sha256" ] || curl -fsS -o "$ISO.sha256" "$base.sha256"
  [ -f "$ISO" ] || curl -fS -C - -o "$ISO.part" "$base" && { [ -f "$ISO" ] || mv "$ISO.part" "$ISO"; }
  echo "$(cut -c1-64 "$ISO.sha256")  $ISO" | sha256sum -c
  ;;
install)
  running && { echo "VM running; stop it first" >&2; exit 1; }
  [ -f "$ISO" ] || "$0" fetch
  rm -f "$D"/{boot,data1,data2}.qcow2
  qemu-img create -q -f qcow2 "$D/boot.qcow2" 20G
  qemu-img create -q -f qcow2 "$D/data1.qcow2" 8G
  qemu-img create -q -f qcow2 "$D/data2.qcow2" 8G
  qemu -cdrom "$ISO" -boot once=d \
    -netdev user,id=n0,hostfwd=tcp:127.0.0.1:18080-:8080
  echo "installer booting (pid $(cat "$PID")); driving it over its JSON-RPC API ..."
  python3 -I "$HERE/install.py" ws://127.0.0.1:18080/ws "$(cat "$LAB/truenas/admin-password" 2>/dev/null || true)"
  python3 "$HERE/../pve/qmp.py" "$D/vm.qmp" quit >/dev/null || true
  for _ in $(seq 1 30); do running || break; sleep 1; done
  rm -f "$PID"
  echo "installed; start with: $0 start"
  ;;
start)
  running && { echo "truenas already running (pid $(cat "$PID"))"; exit 0; }
  qemu -netdev user,id=n0,hostfwd=tcp:127.0.0.1:18444-:443,hostfwd=tcp:127.0.0.1:12222-:22
  echo "truenas started (pid $(cat "$PID")); waiting for the API ..."
  for _ in $(seq 1 120); do
    if curl -ksf -o /dev/null https://127.0.0.1:18444/api/docs/ 2>/dev/null \
       || curl -ksf -o /dev/null https://127.0.0.1:18444/ 2>/dev/null; then
      echo "truenas up: https://localhost:18444  ssh -p 12222"
      exit 0
    fi
    sleep 5
  done
  echo "timed out waiting for the API (see $D/serial.log)" >&2; exit 1
  ;;
stop)
  running || { echo "truenas not running"; rm -f "$PID"; exit 0; }
  P="$(cat "$PID")"
  python3 "$HERE/../pve/qmp.py" "$D/vm.qmp" system_powerdown >/dev/null || true
  for _ in $(seq 1 90); do
    kill -0 "$P" 2>/dev/null || { echo "truenas stopped"; rm -f "$PID"; exit 0; }
    sleep 2
  done
  echo "timeout, killing truenas" >&2; kill "$P"; rm -f "$PID"
  ;;
status)
  running && echo "running (pid $(cat "$PID"))" || echo "stopped"
  ;;
*)
  sed -n '2,9p' "$0"; exit 2
  ;;
esac
