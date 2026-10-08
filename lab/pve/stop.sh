#!/usr/bin/env bash
# Cleanly shut down the PVE lab VM (ACPI powerdown via QMP), hard-kill after timeout.
set -euo pipefail
LAB="${LAB:-/home/ah/nexus-lab}"
PID="$LAB/pve1.pid"

if ! { [ -f "$PID" ] && kill -0 "$(cat "$PID")" 2>/dev/null; }; then
  echo "pve1 not running"; rm -f "$PID"; exit 0
fi
P="$(cat "$PID")"
python3 "$(dirname "$0")/qmp.py" "$LAB/pve1.qmp" system_powerdown >/dev/null
echo "powerdown sent to pve1 (pid $P), waiting ..."
for _ in $(seq 1 90); do
  kill -0 "$P" 2>/dev/null || { echo "pve1 stopped"; rm -f "$PID"; exit 0; }
  sleep 2
done
echo "timeout, killing pve1" >&2; kill "$P"; rm -f "$PID"
