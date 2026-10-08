#!/usr/bin/env bash
# Power-loss test for the chunk store commit protocol. Not part of `cargo test`
# (needs KVM). No root needed: qemu-system-x86_64, /dev/kvm access, mke2fs
# (or mkfs.xfs / mkfs.btrfs), the host kernel (/boot/vmlinuz-$KVER) and modules.
#
#   crates/chunkstore/tests/powerloss/run.sh [ROUNDS]     # default 5
#   env: KVER (default `uname -r`), FS=ext4|xfs|btrfs (default ext4)
#
# Per round: boot the guest in write mode (writer kill -9'd and restarted at
# random inside the guest), SIGKILL QEMU after a random time = power cut: the
# guest page cache is lost, only what the guest wrote out reaches disk.img.
# Then boot in check mode (journal replay) and verify every committed snapshot,
# including all the host saw reported as COMMITTED on the serial console.
# Limitation: writes the guest already submitted to the virtual disk survive
# even without a flush (no volatile disk write cache is simulated).
set -euo pipefail
ROUNDS=${1:-5} KVER=${KVER:-$(uname -r)} FS=${FS:-ext4}
root=$(cd "$(dirname "$0")/../../../.." && pwd)
work=$(mktemp -d) && trap 'rm -rf "$work"' EXIT

(cd "$root" && RUSTFLAGS="-C target-feature=+crt-static" cargo build -q --release \
	-p chunkstore --example powerloss --target x86_64-unknown-linux-gnu)
mkdir -p "$work"/initrd/{dev,proc,mnt,lib}
cp "$root/target/x86_64-unknown-linux-gnu/release/examples/powerloss" "$work/initrd/init"
case $FS in
ext4) mods="lib/crc16 fs/mbcache fs/jbd2/jbd2 crypto/crc32c_generic fs/ext4/ext4" opts=noauto_da_alloc
	/usr/sbin/mke2fs -q -t ext4 -F "$work/disk.img" 256M ;;
btrfs) mods="crypto/xor lib/raid6/raid6_pq crypto/crc32c_generic lib/libcrc32c fs/btrfs/btrfs" opts=
	truncate -s 256M "$work/disk.img" && /usr/sbin/mkfs.btrfs -q "$work/disk.img" ;;
xfs) mods="crypto/crc32c_generic lib/libcrc32c fs/xfs/xfs" opts=
	truncate -s 512M "$work/disk.img" && /usr/sbin/mkfs.xfs -q "$work/disk.img" ;;
esac
for m in $mods drivers/block/virtio_blk; do
	cp "/lib/modules/$KVER/kernel/$m.ko.xz" "$work/initrd/lib/"
	basename "$m" >>"$work/initrd/modules"
done
(cd "$work/initrd" && find . | cpio -o -H newc -R 0:0 --quiet) >"$work/initrd.cpio"

q=(qemu-system-x86_64 -enable-kvm -cpu host -m 512 -smp 2 -nodefaults -display none -no-reboot
	-kernel "/boot/vmlinuz-$KVER" -initrd "$work/initrd.cpio" -serial "file:$work/log"
	-drive "file=$work/disk.img,if=virtio,format=raw,cache=writeback")
cmdline="console=ttyS0 quiet panic=-1 pl.fs=$FS pl.opts=$opts"

for r in $(seq 1 "$ROUNDS"); do
	"${q[@]}" -append "$cmdline pl.mode=write" &
	pid=$!
	for _ in $(seq 300); do grep -q COMMITTED "$work/log" 2>/dev/null && break; sleep 0.1; done
	sleep "$((RANDOM % 4 + 1)).$((RANDOM % 10))"
	kill -9 "$pid" || { echo "writer guest died early:"; tail -30 "$work/log"; exit 1; }
	{ wait "$pid"; } 2>/dev/null || true
	if grep -aq FAIL "$work/log"; then echo "round $r: writer failed:"; tail -30 "$work/log"; exit 1; fi
	committed=$(grep -ao 'COMMITTED [0-9]*' "$work/log" | awk '{print $2}' | sort -n | tail -1) || true
	timeout 120 "${q[@]}" -append "$cmdline pl.mode=check pl.committed=${committed:-0}" || true
	res=$(grep -aoE '(PASS|FAIL) .*' "$work/log" || echo "FAIL no result")
	echo "round $r: $res"
	if [[ $res != PASS* ]]; then tail -30 "$work/log"; exit 1; fi
	[[ $FS != ext4 ]] || /usr/sbin/e2fsck -fn "$work/disk.img" >/dev/null 2>&1 || { echo "e2fsck: fs inconsistent"; exit 1; }
done
echo "powerloss: $ROUNDS rounds PASS"
