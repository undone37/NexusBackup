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
#   esxi.sh guest       Debian 12 test guest $GUEST (nx-cbt) on datastore1 for the CBT tests (netinst remastered with a
#                       preseed file on the PVE host, root login with the lab ECDSA key only (random
#                       root password, not kept); CBT on in the .vmx)
#   esxi.sh cbt         CBT test on nx-cbt: full read of a snapshot from the appliance, then the guest writes
#                       (WRITE_MB new, a part of the old data overwritten), incremental read of the changed
#                       extents only, checked against a full read (esxi_cbt.py, cbt_read.py; a temporary egress
#                       rule on the appliance, removed afterwards). CONSOLE: the appliance's serial socket
#                       (con.py: one command line per call)
#   esxi.sh hotadd      the same CBT test, the data read on a proxy VM (GUEST=nx-proxy esxi.sh guest first)
#                       that gets the snapshot's base disk hot-added read-only (/folder cannot read the disk
#                       of a running VM: hostd "Failed to lock file")
#   esxi.sh ssh CMD     a command on the ESXi shell (lab ECDSA key in $LAB: ESXi's FIPS sshd refuses ed25519)
#   esxi.sh destroy     stop and remove VM $VMID (ours: IDs from 200, AGENTS.md "Labs")
#
# env: ESXI (7 or 8), PVE_HOST (10.2.34.200), SSH_KEY (~/nexus-lab/pve-lab-key), LAB (~/nexus-lab/esxi, esxi8),
#      VMID (250, 251),
#      ISO_NAME (7.0U3g; with ESXI=8 the Dell 8.0U3 image on the host), STORAGE (vmpool), BRIDGE (vmbr0)
set -euo pipefail
PVE_HOST=${PVE_HOST:-10.2.34.200}
SSH_KEY=${SSH_KEY:-$HOME/nexus-lab/pve-lab-key}
# ESXI=8: ESXi 8.0U3 as VM 251 with its own state; the lab host's Haswell CPU is below ESXi 8's minimum, so
# the installer and the installed host boot with allowLegacyCPU=true
ESXI=${ESXI:-7}
if [ "$ESXI" = 8 ]; then
	LAB=${LAB:-$HOME/nexus-lab/esxi8}
	VMID=${VMID:-251}
	ISO_NAME=${ISO_NAME:-VMware-VMvisor-Installer-8.0.0.update03-24280767.x86_64-Dell_Customized-A02.iso}
	KOPT=" allowLegacyCPU=true"
else
	LAB=${LAB:-$HOME/nexus-lab/esxi}
	VMID=${VMID:-250}
	ISO_NAME=${ISO_NAME:-VMware-VMvisor-Installer-7.0U3g-20328353.x86_64.iso}
	KOPT=
fi
GUEST=${GUEST:-nx-cbt}
# esxi_cbt.py reads LAB (the host's address and password); one pyvmomi venv for both labs
export LAB
PY=${PY:-$HOME/nexus-lab/esxi/venv/bin/python}
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
	# root's SSH key (ECDSA: ESXi's FIPS sshd refuses ed25519), installed at the first boot
	[ -f "$LAB/esxi_ecdsa" ] || ssh-keygen -q -t ecdsa -b 384 -N '' -C nexus-lab-esxi -f "$LAB/esxi_ecdsa"
	log "remastering $ISO_NAME with a kickstart file"
	# the kickstart goes over stdin: the password never appears in a command line on the host
	{
		# ESXi 8 on an older CPU: the kickstart turns the CPU warning into an error unless forced
		printf 'vmaccepteula\ninstall --firstdisk --overwritevmfs%s\nrootpw %s\n' \
			"$([ -n "$KOPT" ] && echo ' --forceunsupportedinstall')" "$pw"
		printf 'network --bootproto=dhcp --device=vmnic0\nreboot\n'
		# the installed host needs the installer's CPU override as well (ESXi 8 on an older CPU)
		[ -z "$KOPT" ] || printf '%%post --interpreter=busybox\nfor f in /vmfs/volumes/*/boot.cfg /altbootbank/boot.cfg; do if [ -f "$f" ]; then sed -i "s|^kernelopt=.*|&%s|" "$f"; fi; done\nexit 0\n' "$KOPT"
		printf '%%firstboot --interpreter=busybox\nvim-cmd hostsvc/enable_ssh\nvim-cmd hostsvc/start_ssh\n'
		printf 'echo "%s" >> /etc/ssh/keys-root/authorized_keys\n' "$(cat "$LAB/esxi_ecdsa.pub")"
	} | pve "set -e; w=\$(mktemp -d); trap 'umount \$w/src 2>/dev/null || true; rm -rf \$w' EXIT
		mkdir \$w/src \$w/iso; mount -o loop,ro $ISO/$ISO_NAME \$w/src; cp -a \$w/src/. \$w/iso/; umount \$w/src
		chmod -R u+w \$w/iso; cat > \$w/iso/ks.cfg
		for f in \$w/iso/boot.cfg \$w/iso/efi/boot/boot.cfg; do
			[ -f \$f ] && sed -i 's|^kernelopt=.*|kernelopt=runweasel ks=cdrom:/KS.CFG$KOPT|' \$f
		done
		genisoimage -quiet -relaxed-filenames -J -R -o $ISO/$KS_ISO -b isolinux.bin -c boot.cat \
			-no-emul-boot -boot-load-size 4 -boot-info-table \$w/iso"
	log "creating VM $VMID"
	pve "qm create $VMID --name nx-esxi$ESXI --memory 16384 --cores 4 --cpu host --ostype other \
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
	# the disk without partitions is the new one (rescan first: ESXi 8 lists a new disk late)
	esx 'set -e
		esxcli storage core adapter rescan --all; sleep 5
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

guest_ip() { esx "vim-cmd vmsvc/get.guest \$(vim-cmd vmsvc/getallvms | awk '\$2==\"$GUEST\" {print \$1}') | sed -n 's/^ *ipAddress = \"\([0-9.]*\)\".*/\1/p' | head -1" </dev/null; }

guest() {
	ssh -i "$LAB/esxi_ecdsa" -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=no \
		-o UserKnownHostsFile=/dev/null -o LogLevel=ERROR "root@$(guest_ip)" "$@"
}

step_guest() {
	if esx "vim-cmd vmsvc/getallvms | grep -q ' $GUEST '" && [ -n "$(guest_ip)" ]; then
		log "$GUEST exists: $(guest_ip)"
		return
	fi
	local pw dsurl=https://$(cat "$LAB/ip")/folder/iso/debian-ks.iso
	pw=$(cat "$LAB/root.password")
	# one ISO for every guest (the preseed has no per-guest data)
	if ! esx 'test -f /vmfs/volumes/datastore1/iso/debian-ks.iso'; then
		log "remastering the Debian netinst with a preseed file"
		{
			cat <<EOF
d-i debian-installer/locale string en_US.UTF-8
d-i keyboard-configuration/xkb-keymap select us
d-i netcfg/choose_interface select auto
d-i netcfg/get_hostname string nx-guest
d-i netcfg/get_domain string lab
d-i mirror/country string manual
d-i mirror/http/hostname string deb.debian.org
d-i mirror/http/directory string /debian
d-i mirror/http/proxy string
d-i passwd/root-login boolean true
d-i passwd/make-user boolean false
d-i passwd/root-password-crypted password $(openssl passwd -6 "$(head -c 24 /dev/urandom | base64)")
d-i clock-setup/utc boolean true
d-i time/zone string UTC
d-i partman-auto/disk string /dev/sda
d-i partman-auto/method string regular
d-i partman-auto/choose_recipe select atomic
d-i partman-partitioning/confirm_write_new_label boolean true
d-i partman/choose_partition select finish
d-i partman/confirm boolean true
d-i partman/confirm_nooverwrite boolean true
d-i apt-setup/cdrom/set-first boolean false
tasksel tasksel/first multiselect standard, ssh-server
d-i pkgsel/include string open-vm-tools
popularity-contest popularity-contest/participate boolean false
d-i grub-installer/only_debian boolean true
d-i grub-installer/bootdev string /dev/sda
d-i preseed/late_command string mkdir -p /target/root/.ssh; echo '$(cat "$LAB/esxi_ecdsa.pub")' > /target/root/.ssh/authorized_keys; chmod 700 /target/root/.ssh; chmod 600 /target/root/.ssh/authorized_keys
d-i finish-install/reboot_in_progress note
d-i cdrom-detect/eject boolean true
EOF
		} | pve "set -e; w=\$(mktemp -d); trap 'umount \$w/src 2>/dev/null || true; rm -rf \$w' EXIT
			mkdir \$w/src \$w/iso; mount -o loop,ro $ISO/debian-12.15.0-amd64-netinst.iso \$w/src; cp -a \$w/src/. \$w/iso/
			umount \$w/src; chmod -R u+w \$w/iso; cat > \$w/iso/preseed.cfg
			sed -i 's/^default .*/default install/; s/^timeout .*/timeout 1/' \$w/iso/isolinux/isolinux.cfg
			sed -i 's|append vga=788|append auto=true priority=critical preseed/file=/cdrom/preseed.cfg vga=788|' \$w/iso/isolinux/txt.cfg
			genisoimage -quiet -r -J -o /root/debian-ks.iso -b isolinux/isolinux.bin -c isolinux/boot.cat \
				-no-emul-boot -boot-load-size 4 -boot-info-table \$w/iso"
		esx 'mkdir -p /vmfs/volumes/datastore1/iso'
		log "uploading the ISO to datastore1"
		# the password goes over stdin (netrc), not into a command line on the host
		printf 'machine %s login root password %s\n' "$(cat "$LAB/ip")" "$pw" |
			pve "curl -sfk --netrc-file /dev/stdin -T /root/debian-ks.iso '$dsurl?dcPath=ha-datacenter&dsName=datastore1'; rm -f /root/debian-ks.iso"
	fi
	# a failed earlier attempt: start over
	esx "G=$GUEST; "'id=$(vim-cmd vmsvc/getallvms | awk "\$2 == \"$G\" {print \$1}"); [ -z "$id" ] || { vim-cmd vmsvc/power.off $id >/dev/null 2>&1; vim-cmd vmsvc/unregister $id; }
		rm -rf /vmfs/volumes/datastore1/$G; mkdir -p /vmfs/volumes/datastore1/iso /vmfs/volumes/datastore1/$G'
	esx "G=$GUEST; "'set -e; cd /vmfs/volumes/datastore1/$G
		vmkfstools -c 16G -d thin $G.vmdk >/dev/null
		cat > $G.vmx <<EOF
.encoding = "UTF-8"
config.version = "8"
virtualHW.version = "19"
displayName = "$G"
guestOS = "debian11-64"
memSize = "2048"
numvcpus = "2"
uuid.action = "create"
pciBridge0.present = "TRUE"
pciBridge4.present = "TRUE"
pciBridge4.virtualDev = "pcieRootPort"
pciBridge4.functions = "8"
pciBridge5.present = "TRUE"
pciBridge5.virtualDev = "pcieRootPort"
pciBridge5.functions = "8"
pciBridge6.present = "TRUE"
pciBridge6.virtualDev = "pcieRootPort"
pciBridge6.functions = "8"
pciBridge7.present = "TRUE"
pciBridge7.virtualDev = "pcieRootPort"
pciBridge7.functions = "8"
ctkEnabled = "TRUE"
scsi0.present = "TRUE"
scsi0.virtualDev = "pvscsi"
scsi0:0.present = "TRUE"
scsi0:0.fileName = "$G.vmdk"
scsi0:0.ctkEnabled = "TRUE"
ide1:0.present = "TRUE"
ide1:0.deviceType = "cdrom-image"
ide1:0.fileName = "/vmfs/volumes/datastore1/iso/debian-ks.iso"
ethernet0.present = "TRUE"
ethernet0.virtualDev = "vmxnet3"
ethernet0.networkName = "VM Network"
ethernet0.addressType = "generated"
EOF
		id=$(vim-cmd vmsvc/getallvms | awk "\$2 == \"$G\" {print \$1}")
		[ -n "$id" ] || id=$(vim-cmd solo/registervm /vmfs/volumes/datastore1/$G/$G.vmx)
		vim-cmd vmsvc/power.on $id >/dev/null || true
		# vim-cmd exits 0 on a failed power-on
		vim-cmd vmsvc/power.getstate $id | grep -q "Powered on" || { tail -20 vmware.log; exit 1; }' ||
		die "$GUEST does not power on"
	log "installing Debian in $GUEST (about 10 minutes)"
	local end=$(($(date +%s) + 2400)) a=
	# ESXi's own firewall blocks outgoing ssh: probe from here
	until a=$(guest_ip) && [ -n "$a" ] && guest true 2>/dev/null; do
		[ "$(date +%s)" -lt "$end" ] || die "$GUEST has no address with ssh after 40 minutes"
		sleep 30
	done
	log "$GUEST up at $a"
}

step_cbt() {
	local here py=$PY con w=${WRITE_MB:-1024} s1 s2 url
	here=$(dirname "$0")
	con() { CONSOLE=${CONSOLE:-$HOME/nexus-lab/pvehost/appliance/console.sock} "$here/../appliance/con.py" "$@"; }
	log "guest: $w MB of data as the first state"
	guest "dd if=/dev/urandom of=/root/data.bin bs=1M count=$w status=none && sync"
	s1=$("$py" "$here/esxi_cbt.py" snap cbt1)
	echo "$s1" >"$LAB/cbt1.json"
	url="https://$(cat "$LAB/ip")/folder/$(jq -r '.base | sub("^\\[[^]]*\\] "; "") | sub("\\.vmdk$"; "-flat.vmdk")' <<<"$s1")?dcPath=ha-datacenter&dsName=datastore1"
	log "snapshot cbt1: $(jq -r '.bytes' <<<"$s1") bytes allocated"
	con put "$LAB/netrc" /run/esxi.netrc 0600 >/dev/null
	con put "$here/cbt_read.py" /run/cbt_read.py 0700 >/dev/null
	con put "$LAB/cbt1.json" /run/cbt1.json 0600 >/dev/null
	con run "rm -f /var/tmp/cbt.blocks; nft -a list chain inet nexus output | grep -q spike-esxi || nft insert rule inet nexus output ip daddr $(cat "$LAB/ip") tcp dport 443 accept comment \\\"spike-esxi\\\"" 60 >/dev/null
	log "full read: $(con run "python3 /run/cbt_read.py '$url' /run/esxi.netrc /run/cbt1.json /var/tmp/cbt.blocks" 3600 | grep '^{')"
	"$py" "$here/esxi_cbt.py" remove cbt1
	log "guest: $((w / 2)) MB new, every tenth MB of the old data overwritten"
	guest "dd if=/dev/urandom of=/root/new.bin bs=1M count=$((w / 2)) status=none
		for i in \$(seq 0 10 $((w - 1))); do dd if=/dev/urandom of=/root/data.bin bs=1M count=1 seek=\$i conv=notrunc status=none; done; sync"
	s2=$("$py" "$here/esxi_cbt.py" snap cbt2 "$(jq -r .change_id <<<"$s1")")
	echo "$s2" >"$LAB/cbt2.json"
	log "snapshot cbt2: $(jq -r '.bytes' <<<"$s2") bytes changed in $(jq '.extents | length' <<<"$s2") extents"
	con put "$LAB/cbt2.json" /run/cbt2.json 0600 >/dev/null
	log "incremental read and check: $(con run "python3 /run/cbt_read.py '$url' /run/esxi.netrc /run/cbt2.json /var/tmp/cbt.blocks" 3600 | grep '^{')"
	"$py" "$here/esxi_cbt.py" remove cbt2
	con run 'nft -a list chain inet nexus output | grep spike-esxi | sed "s/.*handle //" | xargs -r -I{} nft delete rule inet nexus output handle {}; rm -f /run/esxi.netrc /run/cbt_read.py /run/cbt1.json /run/cbt2.json /var/tmp/cbt.blocks; echo "egress rules left: $(nft list chain inet nexus output | grep -c spike-esxi)"' 60 | grep "rules left"
}

step_hotadd() {
	local here py=$PY w=${WRITE_MB:-1024} s1 s2 dev
	here=$(dirname "$0")
	cbt() { "$py" "$here/esxi_cbt.py" "$@"; }
	on() { GUEST=$1 guest "${@:2}"; }
	# the disk at SCSI 0:1 of the proxy, after a rescan (pvscsi hot-plug)
	disk() { on nx-proxy 'for h in /sys/class/scsi_host/host*/scan; do echo "- - -" >$h; done; sleep 2; lsblk -dno NAME,HCTL | awk "\$2 ~ /^[0-9]+:0:1:0\$/ {print \"/dev/\" \$1}"'; }
	read_on_proxy() { # extents json -> result line
		on nx-proxy "cat > /root/ext.json" <"$1"
		on nx-proxy "python3 /root/cbt_read.py $dev - /root/ext.json /root/blocks.json 4"
	}
	on nx-proxy "cat > /root/cbt_read.py; rm -f /root/blocks.json" <"$here/cbt_read.py"
	log "guest: $w MB of data as the first state"
	on nx-cbt "dd if=/dev/urandom of=/root/data.bin bs=1M count=$w status=none && sync"
	s1=$(cbt snap cbt1)
	echo "$s1" >"$LAB/cbt1.json"
	cbt attach nx-proxy cbt1
	dev=$(disk)
	[ -n "$dev" ] || die "the hot-added disk does not show up on nx-proxy"
	log "snapshot cbt1 hot-added as $dev on nx-proxy; full read: $(read_on_proxy "$LAB/cbt1.json")"
	cbt detach nx-proxy
	cbt remove cbt1
	log "guest: $((w / 2)) MB new, every tenth MB of the old data overwritten"
	on nx-cbt "dd if=/dev/urandom of=/root/new.bin bs=1M count=$((w / 2)) status=none
		for i in \$(seq 0 10 $((w - 1))); do dd if=/dev/urandom of=/root/data.bin bs=1M count=1 seek=\$i conv=notrunc status=none; done; sync"
	s2=$(cbt snap cbt2 "$(jq -r .change_id <<<"$s1")")
	echo "$s2" >"$LAB/cbt2.json"
	log "snapshot cbt2: $(jq -r '.bytes' <<<"$s2") bytes changed in $(jq '.extents | length' <<<"$s2") extents"
	cbt attach nx-proxy cbt2
	dev=$(disk)
	log "incremental read and check: $(read_on_proxy "$LAB/cbt2.json")"
	cbt detach nx-proxy
	cbt remove cbt2
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
