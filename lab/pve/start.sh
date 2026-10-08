#!/usr/bin/env bash
# Boot the installed PVE lab VM headless and daemonized.
# Ports: https://localhost:18006 (web/API), ssh -p 10022 root@localhost
set -euo pipefail
LAB="${LAB:-/home/ah/nexus-lab}"
PID="$LAB/pve1.pid"
MEM="${MEM:-6144}"
CPUS="${CPUS:-4}"

if [ -f "$PID" ] && kill -0 "$(cat "$PID")" 2>/dev/null; then
  echo "pve1 already running (pid $(cat "$PID"))"; exit 0
fi
[ -f "$LAB/pve1.qcow2" ] || { echo "no $LAB/pve1.qcow2 - run build.sh first" >&2; exit 1; }

qemu-system-x86_64 -name pve1 \
  -machine q35,accel=kvm -cpu host -smp "$CPUS" -m "$MEM" \
  -drive file="$LAB/pve1.qcow2",if=virtio,format=qcow2,cache=writeback,discard=unmap \
  -netdev user,id=n0,hostfwd=tcp:127.0.0.1:18006-:8006,hostfwd=tcp:127.0.0.1:10022-:22 \
  -device virtio-net-pci,netdev=n0 \
  -display none -serial file:"$LAB/pve1.serial.log" \
  -qmp unix:"$LAB/pve1.qmp",server,nowait \
  -daemonize -pidfile "$PID"
echo "pve1 started (pid $(cat "$PID")); waiting for ssh on :10022 ..."

for _ in $(seq 1 120); do
  if ssh -p 10022 -i "$LAB/lab_ed25519" -o BatchMode=yes -o ConnectTimeout=3 \
       -o StrictHostKeyChecking=no -o UserKnownHostsFile="$LAB/known_hosts" \
       root@localhost true 2>/dev/null; then
    echo "pve1 up: https://localhost:18006  ssh -p 10022 -i $LAB/lab_ed25519 root@localhost"
    exit 0
  fi
  sleep 5
done
echo "timed out waiting for ssh (see $LAB/pve1.serial.log)" >&2; exit 1
