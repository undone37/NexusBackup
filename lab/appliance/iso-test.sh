#!/usr/bin/env bash
# Installs the release installer ISO (.github/workflows/iso.yml) into a UEFI QEMU VM and boots the result.
#   iso-test.sh nexusbackup-X-x86_64.iso
# The ISO's own kickstart leaves disk selection interactive; the test adds a kickstart (on a second CD,
# label OEMDRV) that %includes it and wipes the virtual disk, and runs Anaconda in cmdline mode, so the
# install is unattended. Then it boots the installed disk and screenshots tty1, which must show the
# first-boot wizard (nexus-setup). Logs + screenshot in $LAB/iso-test/.
# env: LAB (/home/ah/nexus-lab), SIZE (disk size, 32G)
set -euo pipefail
ISO=$(realpath "$1")
LAB=${LAB:-/home/ah/nexus-lab}
D=$LAB/iso-test
SIZE=${SIZE:-32G}
rm -rf "$D" && mkdir -p "$D/oem"
t0=$(date +%s)
log() { printf '[%4ss] %s\n' $(($(date +%s) - t0)) "$*" >&2; }

vol=$(isoinfo -d -i "$ISO" | sed -n 's/^Volume id: //p')
ks=$(xorriso -indev "$ISO" -ls / 2>/dev/null | tr -d "'" | grep -E '\.ks$' | grep -v base | head -1)
[ -n "$ks" ] || { echo "no kickstart in $ISO" >&2; exit 1; }
xorriso -osirrox on -indev "$ISO" -extract /images/pxeboot/vmlinuz "$D/vmlinuz" \
	-extract /images/pxeboot/initrd.img "$D/initrd.img" -extract "/$ks" "$D/iso.ks" >/dev/null 2>&1
chmod u+w "$D"/*
log "ISO $vol, kickstart /$ks:"
sed 's/^/    /' "$D/iso.ks" >&2
cat >"$D/oem/ks.cfg" <<EOF
%include /run/install/repo/$ks
zerombr
clearpart --all --initlabel
autopart --type=plain --fstype=xfs --nohome
poweroff
EOF
genisoimage -quiet -o "$D/oem.iso" -V OEMDRV -r "$D/oem"
cp /usr/share/OVMF/OVMF_VARS_4M.fd "$D/vars.fd"
qemu-img create -q -f qcow2 "$D/disk.qcow2" "$SIZE"
uefi=(-drive if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd
	-drive if=pflash,format=raw,file="$D/vars.fd")
common=(-machine q35,accel=kvm -cpu host -smp 4 -m 4096 -nodefaults -no-reboot "${uefi[@]}"
	-drive file="$D/disk.qcow2",if=none,id=d0,format=qcow2,cache=unsafe -device virtio-blk-pci,drive=d0,bootindex=1
	-object rng-random,id=rng0,filename=/dev/urandom -device virtio-rng-pci,rng=rng0 -nic user,model=virtio-net-pci)

log "installing (Anaconda, cmdline mode)"
timeout 2400 qemu-system-x86_64 -name nexus-iso-install "${common[@]}" -display none -vga none \
	-drive file="$ISO",media=cdrom,readonly=on -drive file="$D/oem.iso",media=cdrom,readonly=on \
	-kernel "$D/vmlinuz" -initrd "$D/initrd.img" \
	-append "inst.stage2=hd:LABEL=$vol inst.ks=hd:LABEL=OEMDRV:/ks.cfg inst.cmdline console=ttyS0,115200n8" \
	-serial file:"$D/install.log"
grep -qE 'reboot: Power down|Power down' "$D/install.log" && ! grep -qiE 'installation failed|traceback|kernel panic' "$D/install.log" ||
	{ grep -iE 'error|fail|traceback' "$D/install.log" | tail -20 >&2; log "install failed: $D/install.log"; exit 1; }

log "first boot of the installed disk"
qemu-system-x86_64 -name nexus-iso-boot "${common[@]}" -display none -vga std \
	-serial file:"$D/boot.log" -qmp unix:"$D/qmp.sock",server=on,wait=off &
qpid=$!
trap 'kill $qpid 2>/dev/null || true' EXIT
qmp() { printf '{"execute":"qmp_capabilities"}\n%s\n' "$1" | socat -t5 - UNIX-CONNECT:"$D/qmp.sock" >/dev/null; }
sleep 150
qmp '{"execute":"screendump","arguments":{"filename":"'"$D"'/tty1.png","format":"png"}}'
qmp '{"execute":"quit"}'
wait $qpid 2>/dev/null || true
log "done: $D/tty1.png (expect the nexus-setup wizard), logs install.log boot.log"
