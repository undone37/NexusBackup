#!/usr/bin/env bash
# Provision the running PVE lab VM over SSH (idempotent):
#  - pve-no-subscription repo, enterprise repos disabled
#  - NAT bridge vmbr1 (10.10.10.1/24) for nested guests
#  - VM 100 (Debian 13 genericcloud, cloud-init, 10.10.10.100) and CT 200 (10.10.10.200)
#  - API token nexus@pve!appliance -> $LAB/api-token
set -euo pipefail
LAB="${LAB:-/home/ah/nexus-lab}"
KEY="$LAB/lab_ed25519"
SSH_OPTS=(-i "$KEY" -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile="$LAB/known_hosts")
pve() { ssh -p 10022 "${SSH_OPTS[@]}" root@localhost "$@"; }

scp -P 10022 "${SSH_OPTS[@]}" "$KEY.pub" root@localhost:/root/lab_ed25519.pub >/dev/null

pve bash -s <<'REMOTE'
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

echo "==> apt repos: enterprise off, no-subscription on"
for f in /etc/apt/sources.list.d/pve-enterprise.sources /etc/apt/sources.list.d/ceph.sources; do
  [ -f "$f" ] && ! grep -q '^Enabled: no' "$f" && echo 'Enabled: no' >> "$f"
done
cat > /etc/apt/sources.list.d/proxmox.sources <<'EOF'
Types: deb
URIs: http://download.proxmox.com/debian/pve
Suites: trixie
Components: pve-no-subscription
Signed-By: /usr/share/keyrings/proxmox-archive-keyring.gpg
EOF
apt-get update -qq

echo "==> kernel console on ttyS0 (-> pve1.serial.log, effective after reboot)"
if ! grep -q 'console=ttyS0' /etc/default/grub; then
  sed -i 's/^GRUB_CMDLINE_LINUX="\(.*\)"/GRUB_CMDLINE_LINUX="\1 console=tty0 console=ttyS0,115200"/' /etc/default/grub
  update-grub >/dev/null 2>&1
fi

echo "==> NAT bridge vmbr1 10.10.10.1/24"
if ! grep -q '^auto vmbr1' /etc/network/interfaces; then
  cat >> /etc/network/interfaces <<'EOF'

auto vmbr1
iface vmbr1 inet static
	address 10.10.10.1/24
	bridge-ports none
	bridge-stp off
	bridge-fd 0
	post-up   echo 1 > /proc/sys/net/ipv4/ip_forward
	post-up   iptables -t nat -A POSTROUTING -s 10.10.10.0/24 -o vmbr0 -j MASQUERADE
	post-down iptables -t nat -D POSTROUTING -s 10.10.10.0/24 -o vmbr0 -j MASQUERADE
EOF
  ifreload -a
fi

echo "==> VM 100 (Debian 13 genericcloud)"
if ! qm status 100 >/dev/null 2>&1; then
  IMG=/var/lib/vz/template/iso/debian-13-genericcloud-amd64.qcow2
  mkdir -p "$(dirname "$IMG")"
  if [ ! -f "$IMG" ]; then
    curl -fsSL -o "$IMG.part" \
      https://cloud.debian.org/images/cloud/trixie/latest/debian-13-genericcloud-amd64.qcow2
    mv "$IMG.part" "$IMG"
  fi
  qm create 100 --name testvm100 --memory 1024 --cores 1 --cpu host \
    --net0 virtio,bridge=vmbr1 --scsihw virtio-scsi-pci \
    --scsi0 "local-lvm:0,import-from=$IMG,discard=on" \
    --ide2 local-lvm:cloudinit --boot order=scsi0 --serial0 socket --vga serial0 \
    --ciuser debian --sshkeys /root/lab_ed25519.pub \
    --ipconfig0 ip=10.10.10.100/24,gw=10.10.10.1 --nameserver 10.0.2.3
  qm disk resize 100 scsi0 4G
fi
qm set 100 --onboot 1 >/dev/null
qm status 100 | grep -q running || qm start 100

echo "==> CT 200 (Debian 13 standard)"
if ! pct status 200 >/dev/null 2>&1; then
  pveam update >/dev/null
  TPL="$(pveam available --section system | awk '{print $2}' | grep '^debian-13-standard_.*_amd64' | sort -V | tail -1)"
  [ -f "/var/lib/vz/template/cache/$TPL" ] || pveam download local "$TPL"
  pct create 200 "local:vztmpl/$TPL" --hostname ct200 --memory 512 --cores 1 \
    --rootfs local-lvm:2 --unprivileged 1 --features nesting=1 --ssh-public-keys /root/lab_ed25519.pub \
    --net0 name=eth0,bridge=vmbr1,ip=10.10.10.200/24,gw=10.10.10.1 --nameserver 10.0.2.3
fi
pct set 200 --onboot 1
pct status 200 | grep -q running || pct start 200

echo "==> API user/token nexus@pve!appliance"
pveum user list --output-format json | grep -q '"nexus@pve"' || pveum user add nexus@pve --comment "NexusBackup appliance (lab)"
# Lab only: broad roles. Least-privilege set for the appliance is TBD.
for role in PVEVMAdmin PVEDatastoreAdmin PVEAuditor; do
  pveum acl modify / --users nexus@pve --roles "$role"
done
if ! pveum user token list nexus@pve --output-format json | grep -q '"appliance"'; then
  pveum user token add nexus@pve appliance --privsep 1 --output-format json > /root/api-token.json
fi
for role in PVEVMAdmin PVEDatastoreAdmin PVEAuditor; do
  pveum acl modify / --tokens 'nexus@pve!appliance' --roles "$role"
done
# API restore attaches the guest NIC to a bridge: needs SDN.Use on the zone.
pveum acl modify /sdn/zones/localnetwork --users nexus@pve --roles PVESDNUser
pveum acl modify /sdn/zones/localnetwork --tokens 'nexus@pve!appliance' --roles PVESDNUser
REMOTE

# Fetch the token secret once (it is only shown at creation time)
if [ ! -s "$LAB/api-token" ]; then
  pve cat /root/api-token.json | python3 -c \
    'import json,sys; d=json.load(sys.stdin); print(d["full-tokenid"]+"="+d["value"])' > "$LAB/api-token"
  chmod 600 "$LAB/api-token"
  pve rm -f /root/api-token.json
fi

echo "==> verify"
curl -sfk -H "Authorization: PVEAPIToken=$(cat "$LAB/api-token")" \
  https://localhost:18006/api2/json/version; echo
pve 'pveversion; qm list; pct list'
echo "waiting for VM 100 to boot (ssh via jump host) ..."
JUMP="ssh -p 10022 ${SSH_OPTS[*]} -W %h:%p root@localhost"
ok=0
for _ in $(seq 1 60); do
  if ssh "${SSH_OPTS[@]}" -o ConnectTimeout=5 -o ProxyCommand="$JUMP" \
       debian@10.10.10.100 'echo "VM100 booted: $(uname -sr), up $(cut -d. -f1 /proc/uptime)s"' 2>/dev/null; then
    ok=1; break
  fi
  sleep 5
done
[ "$ok" = 1 ] || { echo "VM 100 not reachable via ssh" >&2; exit 1; }
pve 'pct exec 200 -- sh -c "echo CT200: \$(cat /etc/debian_version) \$(hostname)"'
