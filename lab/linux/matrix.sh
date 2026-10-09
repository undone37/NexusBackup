#!/usr/bin/env bash
# The whole Linux agent matrix, one VM at a time: fresh VM (vm.sh up), root snapshot
# tests, e2e.sh (all steps) against the dev control plane, VM stopped again.
#   matrix.sh [vm...]     default: all five; summary in target/linux-root/matrix.txt
# Needs: the bundles (build-bundle.sh --test-key --sign, bump-bundle.sh 0.1.1) and the
# release binaries; starts a fresh control plane (e2e.sh appliance).
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
vms=("$@")
[ ${#vms[@]} -gt 0 ] || vms=(deb-lvm alma-xfs ubuntu-zfs fedora-btrfs deb-plain)
out=$repo/target/linux-root.matrix.txt
"$here/e2e.sh" appliance >/dev/null
: >"$out"
for vm in "${vms[@]}"; do
	t0=$SECONDS
	"$here/vm.sh" "$vm" up >"$repo/target/linux-root/log/$vm.up.log" 2>&1 || {
		echo "$vm: provisioning FAILED" | tee -a "$out"
		continue
	}
	echo "== $vm: provisioned in $((SECONDS - t0)) s" | tee -a "$out"
	"$here/snapshot-tests.sh" "$vm" 2>&1 | tee -a "$out" || true
	if "$here/e2e.sh" "$vm" >"$repo/target/linux-root/log/$vm.e2e.log" 2>&1; then
		echo "$vm: e2e ok" | tee -a "$out"
	else
		echo "$vm: e2e FAILED: $(grep FAIL "$repo/target/linux-root/log/$vm.e2e.log" | head -3)" | tee -a "$out"
	fi
	sed "s/^/  /" "$repo/target/linux-root/run/api/$vm.results" | tee -a "$out"
	"$here/vm.sh" "$vm" ssh 'uname -r; . /etc/os-release; echo $PRETTY_NAME; findmnt -no SOURCE,FSTYPE /' 2>/dev/null | sed 's/^/  /' | tee -a "$out" || true
	"$here/vm.sh" "$vm" stop
done
"$here/e2e.sh" stop
echo "summary: $out"
