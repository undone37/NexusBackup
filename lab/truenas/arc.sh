#!/usr/bin/env bash
# Lab only: cap the ZFS ARC (runtime, not persistent) so the TrueNAS VM's RSS stays small
# next to other lab VMs.   arc.sh [bytes]   (default 1 GiB)
set -euo pipefail
echo "${1:-1073741824}" | sudo -n tee /sys/module/zfs/parameters/zfs_arc_max >/dev/null
grep -E '^(c_max|size) ' /proc/spl/kstat/zfs/arcstats
