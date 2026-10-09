#!/usr/bin/env bash
# Root-only snapshot provider tests of the Linux agent (crates/agent-linux,
# `#[ignore]` tests) inside a running lab VM, with the static musl test binary.
#   snapshot-tests.sh <vm>
# The volumes per VM are the ones lab/linux/provision/<vm>.sh creates.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
vm=${1:?vm}
case $vm in
deb-lvm) tests=("NEXUS_TEST_LVM=/ lvm_snapshot" "NEXUS_TEST_LVM=/var/lib/postgresql lvm_snapshot" "NEXUS_TEST_LVM=/srv/xfs lvm_snapshot") ;;
alma-xfs) tests=("NEXUS_TEST_LVM=/srv/xfs lvm_snapshot" "NEXUS_TEST_LVM=/var/lib/mysql lvm_snapshot") ;;
ubuntu-zfs) tests=("NEXUS_TEST_ZFS=/srv/zfs zfs_snapshot" "NEXUS_TEST_ZFS=/home zfs_snapshot") ;;
fedora-btrfs) tests=("NEXUS_TEST_BTRFS=/home btrfs_snapshot" "NEXUS_TEST_BTRFS=/ btrfs_snapshot") ;;
*)
	echo "no snapshot provider on $vm" >&2
	exit 0
	;;
esac
cd "$repo"
bin=$(CC_x86_64_unknown_linux_musl=gcc cargo test -q -p agent-linux --lib --no-run --target x86_64-unknown-linux-musl \
	--message-format=json 2>/dev/null | jq -r 'select(.executable != null and .target.kind == ["lib"]) | .executable' | tail -1)
[ -x "$bin" ] || {
	echo "no test binary" >&2
	exit 1
}
"$here/vm.sh" "$vm" put "$bin" /tmp/nexus-agent-tests
for t in "${tests[@]}"; do
	read -r env name <<<"$t"
	t0=$(date +%s%N)
	if out=$("$here/vm.sh" "$vm" ssh "cd /tmp && sudo $env ./nexus-agent-tests --ignored --exact snapshot::tests::$name 2>&1"); then
		printf '%s %s %s: ok (%d ms)\n' "$vm" "$env" "$name" $((($(date +%s%N) - t0) / 1000000))
	else
		echo "$out"
		printf '%s %s %s: FAILED\n' "$vm" "$env" "$name"
		exit 1
	fi
done
