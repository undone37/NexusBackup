#!/usr/bin/env bash
# A nested Proxmox VE node as VM $VMID on the PVE lab host (maintainer 2026-10-24: storage pve-test lacks, such as
# LVM-thin, without changing pve-test itself), installed unattended and added to the appliance as a second PVE
# source. Uses: #72 (instant rollback on LVM-thin and Ceph RBD), several sources and groups.
#
#   pvenested.sh iso      answer file + proxmox-auto-install-assistant (on pve-test) -> local:iso/$ISO_OUT
#   pvenested.sh vm       VM $VMID: $CORES cores (host CPU: nested KVM), $MEM MB, $DISK GB on $STORAGE, the ISO;
#                         installs itself (ext4 on LVM: local-lvm is LVM-thin), waits for SSH
#   pvenested.sh node     the nexusbackup-pve package of this tree, storage "nexus", the appliance's key for the
#                         nexusbackup user, API user and token nexus@pve!backup (manual chapter 4)
#   pvenested.sh source   PVE source "$NAME" (tenant lab) on the appliance, fleecing storage local-lvm
#   pvenested.sh guest    on the node: VM $GUEST from the Debian 13 cloud image on local-lvm (LVM-thin), static
#                         $GUEST_ADDR, root with ~/nexus-lab/lab_ed25519, qemu-guest-agent; left stopped (the source
#                         of rollback.sh's clone step: PVE_HOST=$IP NODE=$NAME SRC_VMID=$GUEST STORAGE=local-lvm)
#   pvenested.sh ceph     a mini Ceph cluster on the node (pveceph, maintainer 2026-10-25): three ${OSD_GB} GB disks on
#                         $STORAGE as OSDs, one monitor and manager, a CRUSH rule over OSDs (one host), pool and RBD
#                         storage "rbd" (images), OSD memory target 1 GiB
#   pvenested.sh destroy  VM $VMID destroyed (the source stays: delete it in the UI)
#
# Secrets stay in ~/nexus-lab: $LAB/pve-nested.env (root password, token secret; created by step iso / node).
# env: LAB (~/nexus-lab/pvehost), PORT (28444), PVE_HOST (10.2.34.200), SSH_KEY (~/nexus-lab/pve-lab-key), VMID (284),
#      NAME (pve-nested), ADDR (10.2.34.216/24; .211 and .212 are the lab appliances), GW (10.2.34.254), DNS (10.2.34.253), STORAGE (vmpool), DISK (96),
#      MEM (12288), CORES (4), ISO (proxmox-ve_9.2-1.iso), ISO_OUT (proxmox-ve-nested-auto.iso), GUEST (205),
#      GUEST_ADDR (10.2.34.217/24), OSD_GB (16)
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
export LAB=${LAB:-$HOME/nexus-lab/pvehost}
export PORT=${PORT:-28444}
PVE_HOST=${PVE_HOST:-10.2.34.200}
SSH_KEY=${SSH_KEY:-$HOME/nexus-lab/pve-lab-key}
VMID=${VMID:-284}
NAME=${NAME:-pve-nested}
ADDR=${ADDR:-10.2.34.216/24}
GW=${GW:-10.2.34.254}
DNS=${DNS:-10.2.34.253}
STORAGE=${STORAGE:-vmpool}
DISK=${DISK:-96}
MEM=${MEM:-12288}
CORES=${CORES:-4}
ISO=${ISO:-proxmox-ve_9.2-1.iso}
ISO_OUT=${ISO_OUT:-proxmox-ve-nested-auto.iso}
GUEST=${GUEST:-205}
OSD_GB=${OSD_GB:-16}
GUEST_ADDR=${GUEST_ADDR:-10.2.34.217/24}
VM_KEY=${VM_KEY:-$HOME/nexus-lab/lab_ed25519}
ENV=$LAB/pve-nested.env
export ROOT=$LAB/appliance/root CONSOLE=$LAB/appliance/console.sock
IP=${ADDR%/*}
[ "$VMID" -ge 200 ] || { echo "VMID $VMID: only VMs from 200 are ours" >&2; exit 1; }
T0=$(date +%s)
log() { printf '[%4ss] %s\n' $(($(date +%s) - T0)) "$*" >&2; }
die() {
	log "FAIL: $*"
	exit 1
}
pve() { ssh -n -i "$SSH_KEY" -o BatchMode=yes "root@$PVE_HOST" "$@"; }
node() { ssh -i "$SSH_KEY" -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR \
	-o ConnectTimeout=10 "root@$IP" "$@"; }

step_iso() {
	local hash pub
	[ -f "$ENV" ] || { umask 077 && printf 'ROOT_PW=%s\n' "$(head -c 18 /dev/urandom | base64 | tr -d '/+=')" >"$ENV"; }
	# shellcheck disable=SC1090
	. "$ENV"
	hash=$(openssl passwd -6 "$ROOT_PW")
	pub=$(cat "$SSH_KEY.pub")
	pve "command -v proxmox-auto-install-assistant >/dev/null || DEBIAN_FRONTEND=noninteractive apt-get install -y -qq proxmox-auto-install-assistant >/dev/null"
	# stdin carries the file: not pve() (ssh -n)
	ssh -i "$SSH_KEY" -o BatchMode=yes "root@$PVE_HOST" "cat > /root/nested-answer.toml" <<EOF
[global]
keyboard = "de"
country = "de"
fqdn = "$NAME.lab.local"
mailto = "root@localhost"
timezone = "Europe/Berlin"
root-password-hashed = "$hash"
root-ssh-keys = ["$pub"]

[network]
source = "from-answer"
cidr = "$ADDR"
dns = "$DNS"
gateway = "$GW"
filter.ID_NET_NAME = "*"

[disk-setup]
filesystem = "ext4"
disk-list = ["sda"]
EOF
	pve "proxmox-auto-install-assistant validate-answer /root/nested-answer.toml >/dev/null &&
		proxmox-auto-install-assistant prepare-iso /var/lib/vz/template/iso/$ISO --fetch-from iso \
			--answer-file /root/nested-answer.toml --output /var/lib/vz/template/iso/$ISO_OUT >/dev/null && rm /root/nested-answer.toml
		test -s /var/lib/vz/template/iso/$ISO_OUT" || die "no auto-install ISO"
	log "local:iso/$ISO_OUT: $ISO with the answer file ($NAME, $ADDR, ext4 on LVM)"
}

step_vm() {
	pve "qm status $VMID" >/dev/null 2>&1 && die "VM $VMID exists (step destroy)"
	pve "qm create $VMID --name $NAME --machine q35 --cpu host --cores $CORES --memory $MEM --balloon 0 \
		--scsihw virtio-scsi-single --scsi0 $STORAGE:$DISK,iothread=1,discard=on --net0 virtio,bridge=vmbr0 \
		--ide2 local:iso/$ISO_OUT,media=cdrom --boot 'order=scsi0;ide2' --ostype l26 --serial0 socket >/dev/null &&
		qm start $VMID"
	log "VM $VMID started from the auto-install ISO; installing"
	for _ in $(seq 120); do
		node true 2>/dev/null && break
		sleep 10
	done
	node true || die "no SSH on $IP after 20 minutes"
	pve "qm set $VMID --ide2 none,media=cdrom >/dev/null"
	log "$NAME: $(node 'pveversion; lvs --noheadings -o lv_name,lv_attr,lv_size pve | tr -s " "' | tr '\n' ';')"
}

step_node() {
	local deb tok
	deb=$(ls "$repo"/target/deb/nexusbackup-pve_*_all.deb 2>/dev/null | sort -V | tail -1)
	[ -n "$deb" ] || die "build the package first: pve-plugin/build-deb.sh"
	# no subscription: the no-subscription repository, and up to date (the ISO's pve-common 9.1 rejects the keys of
	# Ceph 20 in an RBD storage's keyring: "Not a proper rbd authentication file"; 9.2 accepts them)
	node "test -f /etc/apt/sources.list.d/pve-no-subscription.sources || {
		sed -i 's/^Types:/Enabled: no\nTypes:/' /etc/apt/sources.list.d/pve-enterprise.sources
		printf 'Types: deb\nURIs: http://download.proxmox.com/debian/pve\nSuites: trixie\nComponents: pve-no-subscription\nSigned-By: /usr/share/keyrings/proxmox-archive-keyring.gpg\n' \
			> /etc/apt/sources.list.d/pve-no-subscription.sources; }
		apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get -y -qq -o Dpkg::Options::=--force-confold dist-upgrade >/dev/null"
	scp -q -i "$SSH_KEY" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR "$deb" "root@$IP:/root/"
	node "apt-get install -y -qq /root/$(basename "$deb") >/dev/null 2>&1 || dpkg -i /root/$(basename "$deb") >/dev/null"
	node "install -d -o root -g root -m 0755 /var/lib/nexusbackup/.ssh
		echo 'restrict,command=\"/usr/lib/nexusbackup/helper\" $(cut -d' ' -f1,2 "$LAB/appliance_ed25519.pub") nexus-appliance' \
			> /var/lib/nexusbackup/.ssh/authorized_keys
		chown root:root /var/lib/nexusbackup/.ssh/authorized_keys; chmod 0644 /var/lib/nexusbackup/.ssh/authorized_keys
		pvesm status | grep -q '^nexus ' || pvesm add nexusbackup nexus --nexus-fleecing-storage local-lvm --content backup,images
		pveum user list --output-format json | grep -q '\"nexus@pve\"' || pveum user add nexus@pve
		for role in PVEVMAdmin PVEDatastoreAdmin PVEAuditor; do pveum acl modify / --users nexus@pve --roles \$role; done
		pveum acl modify /sdn/zones/localnetwork --users nexus@pve --roles PVESDNUser
		pveum role list --output-format json | grep -q NexusSysModify || pveum role add NexusSysModify -privs Sys.Modify
		pveum acl modify / --users nexus@pve --roles NexusSysModify"
	if ! grep -q '^TOKEN=' "$ENV"; then
		tok=$(node "pveum user token add nexus@pve backup --privsep 1 --output-format json" | jq -r .value)
		[ -n "$tok" ] && [ "$tok" != null ] || die "no token secret"
		echo "TOKEN=$tok" >>"$ENV"
	fi
	node "for role in PVEVMAdmin PVEDatastoreAdmin PVEAuditor NexusSysModify; do pveum acl modify / --tokens 'nexus@pve!backup' --roles \$role; done
		pveum acl modify /sdn/zones/localnetwork --tokens 'nexus@pve!backup' --roles PVESDNUser"
	log "$NAME: $(node 'dpkg -l nexusbackup-pve | tail -1 | tr -s " " | cut -d" " -f2,3; pvesm status | grep -E "^(nexus|local-lvm) " | tr -s " " | cut -d" " -f1-3' | tr '\n' ';')"
}

step_source() {
	local cfg con="$repo/lab/appliance/con.py" ca kh id
	S=$ROOT/run/api
	mkdir -p "$S"
	# shellcheck disable=SC1090
	. "$ENV"
	ca=$(node 'cat /etc/pve/pve-root-ca.pem')
	# the node's host key next to pve-test's in the appliance's known_hosts
	kh=$(ssh-keyscan -t ed25519 "$IP" 2>/dev/null | grep -v '^#')
	[ -n "$kh" ] || die "no host key of $IP"
	"$con" run "grep -v '^$IP ' /etc/nexus/ssh/known_hosts > /etc/nexus/ssh/known_hosts.new; echo '$kh' >> /etc/nexus/ssh/known_hosts.new; cat /etc/nexus/ssh/known_hosts.new > /etc/nexus/ssh/known_hosts; rm /etc/nexus/ssh/known_hosts.new" >/dev/null
	"$con" put "$LAB/appliance_ed25519" "/etc/nexus/ssh/$NAME" 0600 >/dev/null
	"$con" run "chown nexus-chunkstore: /etc/nexus/ssh/$NAME && restorecon -RF /etc/nexus/ssh" >/dev/null
	# shellcheck disable=SC1091
	. "$ROOT/secrets.env"
	# shellcheck source=lab/e2e/api-lib.sh
	. "$repo/lab/e2e/api-lib.sh"
	login admin "$ADMIN_PW" "$ADMIN_TOTP"
	cfg=$(jq -nc --arg ca "$ca" --arg tok "$TOKEN" --arg n "$NAME" --arg h "$IP" \
		'{host:$n, port:8006, connect_addr:($h + ":8006"), ca_pem:$ca, token_id:"nexus@pve!backup", token_secret:$tok,
		  nodes:{($n):{host:$h, port:22, key:("/etc/nexus/ssh/" + $n), known_hosts:"/etc/nexus/ssh/known_hosts"}},
		  storage:"nexus", fleecing_storage:"local-lvm"}')
	id=$(api admin GET /sources | jq -r --arg n "$NAME" '.[] | select(.name == $n) | .id')
	if [ -n "$id" ]; then
		api admin PUT "/sources/$id" "$(jq -nc --argjson c "$cfg" --arg n "$NAME" '{name:$n, config:$c}')" >/dev/null
		expect 200 "update source $NAME"
		log "PVE source $NAME updated ($IP)"
		return
	fi
	api admin POST /sources "$(jq -nc --argjson c "$cfg" --arg n "$NAME" '{tenant:"lab", kind:"pve", name:$n, config:$c}')" >/dev/null
	expect 201 "create source $NAME"
	log "PVE source $NAME created"
}

step_guest() {
	local gip=${GUEST_ADDR%/*}
	node "qm status $GUEST" >/dev/null 2>&1 && die "VM $GUEST exists on $NAME"
	scp -q -i "$SSH_KEY" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR "$VM_KEY.pub" "root@$IP:/root/lab_ed25519.pub"
	node "test -f /root/deb13.qcow2 || wget -q -O /root/deb13.qcow2 https://cloud.debian.org/images/cloud/trixie/latest/debian-13-genericcloud-amd64.qcow2
		qm create $GUEST --name deb13-base --memory 1024 --cores 1 --cpu host --net0 virtio,bridge=vmbr0 \
			--scsihw virtio-scsi-single --scsi0 local-lvm:0,import-from=/root/deb13.qcow2,discard=on \
			--ide2 local-lvm:cloudinit --boot order=scsi0 --serial0 socket --vga serial0 --agent 1 \
			--ciuser root --sshkeys /root/lab_ed25519.pub --ipconfig0 ip=$GUEST_ADDR,gw=$GW --nameserver $DNS >/dev/null
		qm disk resize $GUEST scsi0 4G >/dev/null && qm start $GUEST"
	local ssho=(-i "$VM_KEY" -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ConnectTimeout=10)
	for _ in $(seq 60); do
		ssh "${ssho[@]}" "root@$gip" true 2>/dev/null && break
		sleep 5
	done
	ssh "${ssho[@]}" "root@$gip" 'apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq qemu-guest-agent >/dev/null && sync' ||
		die "VM $GUEST: no SSH or no guest agent package"
	node "qm shutdown $GUEST --timeout 120 --forceStop 1"
	log "VM $GUEST on $NAME: Debian 13 on local-lvm, $GUEST_ADDR, guest agent; stopped"
}

step_ceph() {
	local d
	for d in 1 2 3; do
		pve "qm config $VMID | grep -q '^scsi$d:' || qm set $VMID --scsi$d $STORAGE:$OSD_GB,serial=NXOSD$d >/dev/null"
	done
	node "pveceph status >/dev/null 2>&1 || {
		yes | pveceph install --repository no-subscription >/dev/null 2>&1 || exit 1
		pveceph init --network ${IP%.*}.0/24 >/dev/null && pveceph mon create >/dev/null && pveceph mgr create >/dev/null; }
		ceph config set osd osd_memory_target 1073741824
		for s in NXOSD1 NXOSD2 NXOSD3; do
			dev=/dev/\$(lsblk -dno NAME,SERIAL | awk -v s=\$s '\$2 == s {print \$1}')
			[ \$dev != /dev/ ] || exit 1
			pvs --noheadings \$dev 2>/dev/null | grep -q ceph || pveceph osd create \$dev >/dev/null 2>&1 || exit 1
		done
		ceph osd crush rule ls | grep -qx rep-osd || ceph osd crush rule create-replicated rep-osd default osd
		# one host: every pool on the OSD rule (the manager's own pool too)
		ceph osd pool set .mgr crush_rule rep-osd >/dev/null
		pvesm status | grep -q '^rbd ' || pveceph pool create rbd --size 3 --min_size 2 --crush_rule rep-osd --pg_num 32 \
			--add_storages 1 >/dev/null
		for i in \$(seq 60); do ceph health | grep -q HEALTH_OK && break; sleep 5; done" || die "ceph setup failed"
	log "$NAME: $(node 'ceph -s --format json' | jq -r '"\(.health.status), \(.osdmap.num_up_osds) of \(.osdmap.num_osds) OSDs up, \(.pgmap.num_pgs) PGs"'); $(node "pvesm status | grep '^rbd '" | tr -s ' ')"
}

step_destroy() {
	pve "qm status $VMID >/dev/null 2>&1 || exit 0; qm stop $VMID >/dev/null 2>&1; qm destroy $VMID --purge 1 >/dev/null"
	log "VM $VMID destroyed"
}

[ $# -gt 0 ] || set -- iso vm node source
for s in "$@"; do
	"step_$s"
done
