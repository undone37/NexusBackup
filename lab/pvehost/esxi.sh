#!/usr/bin/env bash
# Nested ESXi on the PVE lab host for the VMware transport spike (Phase 41, docs/vmware-transport-spike.md).
# The installer ISO on the host is remastered with a kickstart file (unattended install, SSH on, DHCP); the
# remastered ISO holds the root password and is deleted from the host after the install. State (root
# password, address) in $LAB.
#
#   esxi.sh install     remaster the ISO, create VM $VMID, install, wait for the API, delete the ISO copy
#   esxi.sh ip          the host's address (from the PVE host's neighbour table, by the VM's MAC; a nested
#                       ESXi may not answer the PVE host's ARP: then ESXI_IP=<address> esxi.sh ip records it)
#   esxi.sh api         a SOAP login against the host (checks the credentials and the API)
#   esxi.sh datastore   a second disk (128 GB) as VMFS datastore datastore1 (ESXi 7 gives the whole first disk
#                       to its system partition OSDATA); reboots the VM once to see the disk
#   esxi.sh ssh CMD     a command on the ESXi shell (lab ECDSA key in $LAB: ESXi's FIPS sshd refuses ed25519)
#   esxi.sh destroy     stop and remove VM $VMID (ours: IDs from 200, AGENTS.md "Labs")
#
# env: PVE_HOST (10.2.34.200), SSH_KEY (~/nexus-lab/pve-lab-key), LAB (~/nexus-lab/esxi), VMID (250),
#      ISO_NAME (VMware-VMvisor-Installer-7.0U3g-20328353.x86_64.iso: ESXi 8 no longer supports this host's
#      Haswell CPU), STORAGE (vmpool), BRIDGE (vmbr0)
set -euo pipefail
PVE_HOST=${PVE_HOST:-10.2.34.200}
SSH_KEY=${SSH_KEY:-$HOME/nexus-lab/pve-lab-key}
LAB=${LAB:-$HOME/nexus-lab/esxi}
VMID=${VMID:-250}
ISO_NAME=${ISO_NAME:-VMware-VMvisor-Installer-7.0U3g-20328353.x86_64.iso}
STORAGE=${STORAGE:-vmpool}
BRIDGE=${BRIDGE:-vmbr0}
ISO=/var/lib/vz/template/iso
KS_ISO=nexus-esxi-ks-$VMID.iso
T0=$(date +%s)
log() { printf '[%4ss] %s\n' $(($(date +%s) - T0)) "$*" >&2; }
die() {
	log "FAIL: $*"
	exit 1
}
pve() { ssh -i "$SSH_KEY" -o BatchMode=yes "root@$PVE_HOST" "$@"; }
mkdir -p "$LAB" && chmod 700 "$LAB"

mac() { pve "qm config $VMID" | sed -n 's/^net0: e1000e=\([0-9A-Fa-f:]*\),.*/\1/p' | tr 'A-F' 'a-f'; }

step_ip() {
	local m a
	# a nested ESXi often does not answer the PVE host's ARP (it is still reachable through the router):
	# ESXI_IP from outside, kept in $LAB/ip
	if [ -n "${ESXI_IP:-}" ]; then
		echo "$ESXI_IP" >"$LAB/ip"
		echo "$ESXI_IP"
		return
	fi
	m=$(mac)
	[ -n "$m" ] || die "VM $VMID has no e1000e NIC"
	local find="ip neigh show dev $BRIDGE | awk -v m=$m 'tolower(\$3) == m && \$1 ~ /^[0-9.]+\$/ {print \$1; exit}'"
	a=$(pve "$find")
	if [ -z "$a" ]; then
		# the host has not talked to it yet: one ping to every address of the bridge's /24 fills the table
		pve "net=\$(ip -4 -o addr show $BRIDGE | awk '{print \$4}' | cut -d. -f1-3)
			for i in \$(seq 1 254); do ping -c1 -W1 \$net.\$i >/dev/null 2>&1 & done; wait" || true
		a=$(pve "$find")
	fi
	[ -n "$a" ] || return 1
	echo "$a" >"$LAB/ip"
	echo "$a"
}

step_install() {
	pve "qm status $VMID" >/dev/null 2>&1 && die "VM $VMID exists (esxi.sh destroy first)"
	pve "test -f $ISO/$ISO_NAME" || die "$ISO/$ISO_NAME missing on the host"
	# ESXi wants a complex password: upper, lower, digit, symbol
	local pw
	pw="Nx$(head -c 12 /dev/urandom | base64 | tr -dc 'a-zA-Z0-9' | head -c 12)7!"
	printf '%s\n' "$pw" >"$LAB/root.password"
	chmod 600 "$LAB/root.password"
	log "remastering $ISO_NAME with a kickstart file"
	# the kickstart goes over stdin: the password never appears in a command line on the host
	{
		printf 'vmaccepteula\ninstall --firstdisk --overwritevmfs\nrootpw %s\n' "$pw"
		printf 'network --bootproto=dhcp --device=vmnic0\nreboot\n'
		printf '%%firstboot --interpreter=busybox\nvim-cmd hostsvc/enable_ssh\nvim-cmd hostsvc/start_ssh\n'
	} | pve "set -e; w=\$(mktemp -d); trap 'umount \$w/src 2>/dev/null || true; rm -rf \$w' EXIT
		mkdir \$w/src \$w/iso; mount -o loop,ro $ISO/$ISO_NAME \$w/src; cp -a \$w/src/. \$w/iso/; umount \$w/src
		chmod -R u+w \$w/iso; cat > \$w/iso/ks.cfg
		for f in \$w/iso/boot.cfg \$w/iso/efi/boot/boot.cfg; do
			[ -f \$f ] && sed -i 's|^kernelopt=.*|kernelopt=runweasel ks=cdrom:/KS.CFG|' \$f
		done
		genisoimage -quiet -relaxed-filenames -J -R -o $ISO/$KS_ISO -b isolinux.bin -c boot.cat \
			-no-emul-boot -boot-load-size 4 -boot-info-table \$w/iso"
	log "creating VM $VMID"
	pve "qm create $VMID --name nx-esxi7 --memory 16384 --cores 4 --cpu host --ostype other \
		--sata0 $STORAGE:96 --net0 e1000e,bridge=$BRIDGE --ide2 local:iso/$KS_ISO,media=cdrom \
		--boot 'order=sata0;ide2' --serial0 socket"
	pve "qm start $VMID"
	log "installing (about 10 minutes)"
	local end=$((T0 + 1800)) a=
	until a=$(step_ip 2>/dev/null) && curl -sk -m 5 -o /dev/null "https://$a/sdk/vimServiceVersions.xml"; do
		[ "$(date +%s)" -lt "$end" ] || die "no ESXi API after 30 minutes (VM console: qm terminal $VMID)"
		sleep 20
	done
	pve "qm set $VMID --ide2 none,media=cdrom && rm -f $ISO/$KS_ISO"
	log "ESXi up at $a (root password in $LAB/root.password; the ISO copy is deleted)"
}

step_api() {
	local a pw
	a=$(cat "$LAB/ip")
	pw=$(cat "$LAB/root.password")
	# RetrieveServiceContent, then Login with the session manager it names
	curl -sk -m 20 -c "$LAB/cookies" -H 'Content-Type: text/xml' -H 'SOAPAction: urn:vim25/7.0' \
		"https://$a/sdk" --data-binary @- <<EOF | grep -o '<fullName>[^<]*' | sed 's/<fullName>/API: /'
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:urn="urn:vim25"><soapenv:Body>
<urn:RetrieveServiceContent><urn:_this type="ServiceInstance">ServiceInstance</urn:_this></urn:RetrieveServiceContent>
</soapenv:Body></soapenv:Envelope>
EOF
	curl -sk -m 20 -b "$LAB/cookies" -c "$LAB/cookies" -H 'Content-Type: text/xml' -H 'SOAPAction: urn:vim25/7.0' \
		"https://$a/sdk" --data-binary @- <<EOF | grep -o '<userName>[^<]*' | sed 's/<userName>/logged in as /'
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:urn="urn:vim25"><soapenv:Body>
<urn:Login><urn:_this type="SessionManager">ha-sessionmgr</urn:_this><urn:userName>root</urn:userName>
<urn:password>$pw</urn:password></urn:Login></soapenv:Body></soapenv:Envelope>
EOF
}

esx() {
	ssh -i "$LAB/esxi_ecdsa" -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=no \
		-o UserKnownHostsFile=/dev/null -o LogLevel=ERROR "root@$(cat "$LAB/ip")" "$@"
}

step_ssh() {
	esx "$SSH_CMD"
}

step_datastore() {
	if esx 'test -d /vmfs/volumes/datastore1'; then
		log "datastore1 exists"
		return
	fi
	if ! pve "qm config $VMID" | grep -q '^sata1:'; then
		pve "qm set $VMID --sata1 $STORAGE:128 >/dev/null"
		# SATA is not hot-pluggable: the disk appears after a stop and start of the VM, not a guest reboot
		pve "qm shutdown $VMID --timeout 180 || qm stop $VMID; qm start $VMID"
		log "second disk added, ESXi restarted"
		sleep 60
		until esx true 2>/dev/null; do sleep 10; done
	fi
	# the disk without partitions is the new one
	esx 'set -e
		for d in $(ls /vmfs/devices/disks/ | grep "^t10" | grep -v ":"); do
			if [ "$(partedUtil getptbl /vmfs/devices/disks/$d 2>/dev/null | wc -l)" -le 2 ]; then dev=$d; fi
		done
		[ -n "$dev" ] || { echo "no empty disk"; exit 1; }
		end=$(( $(partedUtil getUsableSectors /vmfs/devices/disks/$dev | cut -d" " -f2) ))
		partedUtil mklabel /vmfs/devices/disks/$dev gpt
		partedUtil setptbl /vmfs/devices/disks/$dev gpt "1 2048 $end AA31E02A400F11DB9590000C2911D1B8 0"
		vmkfstools -C vmfs6 -S datastore1 /vmfs/devices/disks/$dev:1 >/dev/null
		echo "datastore1 on $dev"'
}

step_destroy() {
	pve "qm stop $VMID 2>/dev/null; qm destroy $VMID --purge 2>/dev/null; rm -f $ISO/$KS_ISO" || true
	rm -f "$LAB/ip"
	log "VM $VMID removed"
}

if [ "${1:-}" = ssh ]; then
	SSH_CMD="${*:2}"
	step_ssh
	exit
fi
for s in "${@:-install}"; do
	"step_$s"
done
