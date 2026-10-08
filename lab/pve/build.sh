#!/usr/bin/env bash
# Build the nested PVE 9.x lab VM: download + verify ISO, prepare an unattended
# ISO (inside a container), install headless into $LAB/pve1.qcow2.
# No host packages, no sudo. Re-runnable; pass FORCE=1 to reinstall the disk.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
LAB="${LAB:-/home/ah/nexus-lab}"
ISO_BASE="https://enterprise.proxmox.com/iso"
DISK="$LAB/pve1.qcow2"
DISK_SIZE="${DISK_SIZE:-64G}"
AIA_IMAGE="localhost/pve-aia:trixie"
CTR="${CTR:-podman}"

mkdir -p "$LAB"
cd "$LAB"

# 1. Latest PVE 9.x ISO (amd64) + SHA256 check against published SHA256SUMS
curl -fsSL "$ISO_BASE/SHA256SUMS" -o SHA256SUMS
ISO="$(grep -oE 'proxmox-ve_9\.[0-9]+-[0-9]+\.iso$' SHA256SUMS | sort -V | tail -1)"
[ -n "$ISO" ] || { echo "no PVE 9.x ISO found in SHA256SUMS" >&2; exit 1; }
echo "==> ISO: $ISO"
if ! grep -E "  $ISO\$" SHA256SUMS | sha256sum -c --status 2>/dev/null; then
  curl -fL -C - -o "$ISO" "$ISO_BASE/$ISO" || curl -fL -o "$ISO" "$ISO_BASE/$ISO"
  grep -E "  $ISO\$" SHA256SUMS | sha256sum -c
fi

# 2. Lab credentials (outside git)
[ -f lab_ed25519 ] || ssh-keygen -q -t ed25519 -N '' -C nexus-lab -f lab_ed25519
[ -f root-password ] || { head -c 18 /dev/urandom | base64 | tr -d '/+=' > root-password; chmod 600 root-password; }

sed -e "s|@ROOT_PASSWORD@|$(cat root-password)|" \
    -e "s|@ROOT_SSH_KEY@|$(cat lab_ed25519.pub)|" \
    "$HERE/answer.toml.in" > answer.toml
chmod 600 answer.toml

# 3. Auto-install ISO via proxmox-auto-install-assistant in a container
if ! $CTR image exists "$AIA_IMAGE" 2>/dev/null; then
  $CTR build -t "$AIA_IMAGE" -f "$HERE/Containerfile.assistant" "$HERE"
fi
AUTO_ISO="${ISO%.iso}-auto.iso"
$CTR run --rm -v "$LAB:/lab:Z" -w /lab "$AIA_IMAGE" \
  proxmox-auto-install-assistant validate-answer answer.toml
rm -f "$AUTO_ISO"
$CTR run --rm -v "$LAB:/lab:Z" -w /lab "$AIA_IMAGE" \
  proxmox-auto-install-assistant prepare-iso "$ISO" --fetch-from iso \
    --answer-file answer.toml --output "$AUTO_ISO"

# 4. Unattended install (answer file powers the VM off when done)
if [ -f "$DISK" ] && [ "${FORCE:-0}" != 1 ]; then
  echo "==> $DISK exists, skipping install (FORCE=1 to reinstall)"; exit 0
fi
rm -f "$DISK"
qemu-img create -f qcow2 "$DISK" "$DISK_SIZE"
echo "==> installing, log: $LAB/pve1.install.log (takes ~5-15 min)"
timeout 3600 qemu-system-x86_64 \
  -machine q35,accel=kvm -cpu host -smp 4 -m 4096 \
  -drive file="$DISK",if=virtio,format=qcow2,cache=unsafe,discard=unmap \
  -cdrom "$AUTO_ISO" -boot once=d \
  -netdev user,id=n0 -device virtio-net-pci,netdev=n0 \
  -display none -serial file:"$LAB/pve1.install.log" -no-reboot \
  -qmp unix:"$LAB/install.qmp",server,nowait   # screendump via QMP for debugging
echo "==> install finished: $DISK"
