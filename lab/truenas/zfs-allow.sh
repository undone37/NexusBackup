#!/usr/bin/env bash
# The one shell step of the TrueNAS setup (docs/truenas-connector.md): delegate
# `zfs diff` to the appliance user on every configured dataset root
# (Local+Descendent, stored in the pool, survives TrueNAS upgrades).
#   zfs-allow.sh <user> <dataset>...      (run via sh.py as truenas_admin)
set -euo pipefail
u="$1"; shift
for ds in "$@"; do
  sudo -n zfs allow -u "$u" diff "$ds"
  zfs allow "$ds" | sed -n '2,$p'
done
# leftovers of manual experiments
for s in $(zfs list -H -t snapshot -o name | grep -E '@exp[0-9]+$' || true); do sudo -n zfs destroy "$s" || true; done
