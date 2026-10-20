#!/usr/bin/env bash
# Server test VMs on the PVE lab host: TrueNAS SCALE (connector tests) and Windows Server 2022 (Windows
# agent tests without touching the maintainer's VMs). Installed unattended from the ISOs on the host,
# offline snapshot `clean-os` right after the install, like lab/pvehost/agent-vms.sh.
#
#   server-vms.sh install [names]   create, install, snapshot clean-os, start
#   server-vms.sh reset [names]     rollback to clean-os (stopped)
#   server-vms.sh ip [names]        address (TrueNAS: from its traffic on the host; Windows: guest agent)
#   server-vms.sh list
# names: default all of the table below. VMs 240-242 (ours, see AGENTS.md "Labs").
#
# TrueNAS: the live ISO's installer API (JSON-RPC over WebSocket, port 8080) is driven by
# lab/truenas/install.py, as in the local TrueNAS lab; its DHCP address is read from the VM's first
# IP packet on its tap interface (no guest agent in the installer). Boot disk 20 GB, two 8 GB disks
# for the pool, each with a serial number (TrueNAS refuses pool disks without one). State per VM in $LAB/<name>/truenas/ (admin password).
# Windows Server 2022 Evaluation: autounattend.xml on a small extra CD (generated per run, deleted
# from the host after the install: it holds the Administrator password), SATA disk and e1000 NIC so
# setup needs no drivers; the first logon installs the virtio-win guest tools (drivers, among them
# virtio-serial, which the QEMU guest agent needs to reach PVE, and the agent itself), OpenSSH with
# the lab key for Administrator, and shuts down. State in $LAB/<name>/ (Administrator password).
#
# env: PVE_HOST (10.2.34.200), SSH_KEY (~/nexus-lab/pve-lab-key), LAB (~/nexus-lab/server-vms),
#      VM_KEY (~/nexus-lab/lab_ed25519), BRIDGE (vmbr0), STORAGE (vmpool)
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
PVE_HOST=${PVE_HOST:-10.2.34.200}
SSH_KEY=${SSH_KEY:-$HOME/nexus-lab/pve-lab-key}
LAB=${LAB:-$HOME/nexus-lab/server-vms}
VM_KEY=${VM_KEY:-$HOME/nexus-lab/lab_ed25519}
BRIDGE=${BRIDGE:-vmbr0}
STORAGE=${STORAGE:-vmpool}
ISO=/var/lib/vz/template/iso

# id name kind iso
VMS="
240 truenas-2510 truenas TrueNAS-SCALE-25.10.7.iso
241 truenas-27 truenas TrueNAS-27.0.0-RC.1.iso
242 winsrv-2022 windows SERVER_EVAL_x64FRE_en-us.iso
"
VIRTIO_ISO=virtio-win-0.1.302.iso

pve() { ssh -i "$SSH_KEY" -o BatchMode=yes "root@$PVE_HOST" "$@"; }
T0=$(date +%s)
log() { printf '[%5ss] %s\n' $(($(date +%s) - T0)) "$*" >&2; }
die() {
	log "FAIL: $*"
	exit 1
}
rows() {
	if [ $# -eq 0 ]; then grep . <<<"$VMS"; else
		for n in "$@"; do grep -E "^[0-9]+ $n " <<<"$VMS" || die "unknown VM $n"; done
	fi
}

fresh() { # fresh id name: only ever replaces its own VM
	if pve "qm status $1" >/dev/null 2>&1; then
		[ "$(pve "qm config $1" | sed -n 's/^name: //p')" = "nx-$2" ] || die "VM $1 exists and is not nx-$2"
		pve "qm stop $1 --skiplock 1 >/dev/null 2>&1; qm destroy $1 --purge 1 >/dev/null"
	fi
}

wait_off() { # wait_off id name minutes
	local t=0
	while [ "$(pve "qm status $1" | awk '{print $2}')" != stopped ]; do
		sleep 30
		t=$((t + 30))
		[ $t -lt $(($3 * 60)) ] || die "$2 ($1): still running after $3 min"
	done
}

snapshot() { # snapshot id name: offline snapshot, then start
	pve "qm snapshot $1 clean-os --description 'OS install only' && qm start $1"
	log "$2 ($1): snapshot clean-os, started"
}

tap_ip() { # tap_ip id: source address of the VM's first IPv4 packet (up to 10 min)
	local mac
	mac=$(pve "qm config $1" | sed -n 's/^net0: [a-z0-9]*=\([0-9A-Fa-f:]*\),.*/\1/p' | tr 'A-F' 'a-f')
	# "hh:mm:ss.us IP 10.2.34.47.68 > ...": field 3, without the port if there is one
	pve "timeout 600 tcpdump -l -n -i tap${1}i0 -c 1 'ether src $mac and ip and not src host 0.0.0.0' 2>/dev/null" |
		awk '{n = split($3, a, "."); print (n == 5 ? a[1] "." a[2] "." a[3] "." a[4] : $3)}'
}

agent_ip() { # agent_ip id: first global IPv4 from the guest agent (up to 10 min)
	local t=0 a=
	while [ $t -lt 600 ]; do
		a=$(pve "qm guest cmd $1 network-get-interfaces 2>/dev/null" | python3 -c 'import json,sys
for i in json.load(sys.stdin):
    for a in i.get("ip-addresses", []):
        if a["ip-address-type"] == "ipv4" and not a["ip-address"].startswith(("127.", "169.254.")):
            print(a["ip-address"]); raise SystemExit' 2>/dev/null || true)
		[ -n "$a" ] && { echo "$a"; return; }
		sleep 10
		t=$((t + 10))
	done
	return 1
}

# ---------------------------------------------------------------- TrueNAS

install_truenas() { # id name iso
	local id=$1 name=$2 iso=$3 ip
	fresh "$id" "$name"
	pve "qm create $id --name nx-$name --ostype l26 --machine q35 --cpu host --cores 2 --memory 8192 --balloon 0 \
		--scsihw virtio-scsi-single --scsi0 $STORAGE:20,discard=on,serial=NX${id}D0 \
		--scsi1 $STORAGE:8,discard=on,serial=NX${id}D1 --scsi2 $STORAGE:8,discard=on,serial=NX${id}D2 --net0 virtio,bridge=$BRIDGE --ide2 local:iso/$iso,media=cdrom \
		--boot 'order=ide2;scsi0' --serial0 socket --tags nexus-server-lab \
		--description 'TrueNAS test VM (lab/pvehost/server-vms.sh); snapshot clean-os = fresh install'"
	pve "qm start $id"
	log "$name ($id): installer booting"
	ip=$(tap_ip "$id")
	[ -n "$ip" ] || die "$name: no address seen on tap${id}i0"
	log "$name ($id): installer at $ip"
	local t=0
	until curl -s -o /dev/null --max-time 3 "http://$ip:8080/"; do
		sleep 5
		t=$((t + 5))
		[ $t -lt 600 ] || die "$name: installer API on $ip:8080 did not come up"
	done
	mkdir -p "$LAB/$name"
	LAB="$LAB/$name" python3 -I "$here/../truenas/install.py" "ws://$ip:8080/ws" \
		"$(cat "$LAB/$name/truenas/admin-password" 2>/dev/null || true)"
	pve "qm stop $id && qm set $id --ide2 none,media=cdrom --boot order=scsi0 >/dev/null"
	snapshot "$id" "$name"
}

# ---------------------------------------------------------------- Windows Server

unattend() { # unattend name password -> autounattend.xml on stdout
	local key
	key=$(cat "$VM_KEY.pub")
	cat <<EOF
<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
  <settings pass="windowsPE">
    <component name="Microsoft-Windows-International-Core-WinPE" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <SetupUILanguage><UILanguage>en-US</UILanguage></SetupUILanguage>
      <InputLocale>en-US</InputLocale><SystemLocale>en-US</SystemLocale><UILanguage>en-US</UILanguage><UserLocale>en-US</UserLocale>
    </component>
    <component name="Microsoft-Windows-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <DiskConfiguration>
        <Disk wcm:action="add">
          <DiskID>0</DiskID><WillWipeDisk>true</WillWipeDisk>
          <CreatePartitions>
            <CreatePartition wcm:action="add"><Order>1</Order><Type>Primary</Type><Extend>true</Extend></CreatePartition>
          </CreatePartitions>
          <ModifyPartitions>
            <ModifyPartition wcm:action="add"><Order>1</Order><PartitionID>1</PartitionID><Format>NTFS</Format><Label>System</Label><Letter>C</Letter><Active>true</Active></ModifyPartition>
          </ModifyPartitions>
        </Disk>
      </DiskConfiguration>
      <ImageInstall>
        <OSImage>
          <InstallFrom><MetaData wcm:action="add"><Key>/IMAGE/INDEX</Key><Value>2</Value></MetaData></InstallFrom>
          <InstallTo><DiskID>0</DiskID><PartitionID>1</PartitionID></InstallTo>
        </OSImage>
      </ImageInstall>
      <UserData><AcceptEula>true</AcceptEula><FullName>Nexus Lab</FullName><Organization>Nexus Lab</Organization></UserData>
    </component>
  </settings>
  <settings pass="specialize">
    <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <ComputerName>$1</ComputerName>
      <TimeZone>UTC</TimeZone>
    </component>
    <component name="Microsoft-Windows-TerminalServices-LocalSessionManager" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <fDenyTSConnections>false</fDenyTSConnections>
    </component>
  </settings>
  <settings pass="oobeSystem">
    <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <OOBE><HideEULAPage>true</HideEULAPage><HideWirelessSetupInOOBE>true</HideWirelessSetupInOOBE><ProtectYourPC>3</ProtectYourPC></OOBE>
      <UserAccounts><AdministratorPassword><Value>$2</Value><PlainText>true</PlainText></AdministratorPassword></UserAccounts>
      <AutoLogon><Username>Administrator</Username><Password><Value>$2</Value><PlainText>true</PlainText></Password><Enabled>true</Enabled><LogonCount>1</LogonCount></AutoLogon>
      <FirstLogonCommands>
        <SynchronousCommand wcm:action="add"><Order>1</Order>
          <CommandLine>powershell -NoProfile -ExecutionPolicy Bypass -Command "\$t = Get-PSDrive -PSProvider FileSystem | ForEach-Object { Join-Path \$_.Root 'virtio-win-guest-tools.exe' } | Where-Object { Test-Path \$_ } | Select-Object -First 1; if (\$t) { Start-Process \$t -Wait -ArgumentList '/install', '/quiet', '/norestart' }"</CommandLine>
        </SynchronousCommand>
        <SynchronousCommand wcm:action="add"><Order>2</Order>
          <CommandLine>powershell -NoProfile -ExecutionPolicy Bypass -Command "Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0; Set-Service sshd -StartupType Automatic; Start-Service sshd; Set-Content -Path C:\ProgramData\ssh\administrators_authorized_keys -Value '$key'; icacls C:\ProgramData\ssh\administrators_authorized_keys /inheritance:r /grant 'Administrators:F' /grant 'SYSTEM:F'; New-NetFirewallRule -Name sshd-lab -DisplayName 'OpenSSH (lab)' -Protocol TCP -LocalPort 22 -Action Allow; Enable-NetFirewallRule -Name FPS-ICMP4-ERQ-In; Set-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem LongPathsEnabled 1"</CommandLine>
        </SynchronousCommand>
        <SynchronousCommand wcm:action="add"><Order>3</Order><CommandLine>shutdown /s /t 30</CommandLine></SynchronousCommand>
      </FirstLogonCommands>
    </component>
  </settings>
</unattend>
EOF
}

install_windows() { # id name iso
	local id=$1 name=$2 iso=$3 pw
	fresh "$id" "$name"
	mkdir -p "$LAB/$name" && chmod 700 "$LAB" "$LAB/$name"
	[ -s "$LAB/$name/admin-password" ] || (umask 077 && printf 'Nx-%s!' "$(openssl rand -hex 10)" >"$LAB/$name/admin-password")
	pw=$(cat "$LAB/$name/admin-password")
	unattend "$name" "$pw" | pve "rm -rf /tmp/nx-ua-$id && mkdir -p /tmp/nx-ua-$id && cat >/tmp/nx-ua-$id/autounattend.xml && \
		genisoimage -quiet -J -r -V UNATTEND -o $ISO/nx-unattend-$id.iso /tmp/nx-ua-$id && rm -rf /tmp/nx-ua-$id"
	pve "qm create $id --name nx-$name --ostype win11 --machine q35 --cpu host --cores 2 --memory 4096 --balloon 0 \
		--sata0 $STORAGE:40 --net0 e1000,bridge=$BRIDGE --ide0 local:iso/$iso,media=cdrom \
		--ide2 local:iso/$VIRTIO_ISO,media=cdrom --sata1 local:iso/nx-unattend-$id.iso,media=cdrom \
		--boot 'order=sata0;ide0' --agent enabled=1 --tags nexus-server-lab \
		--description 'Windows Server 2022 test VM (lab/pvehost/server-vms.sh); snapshot clean-os = fresh install'"
	pve "qm start $id"
	log "$name ($id): installing (setup, reboots, first logon, then shutdown)"
	wait_off "$id" "$name" 90
	pve "qm set $id --delete sata1 --ide0 none,media=cdrom --ide2 none,media=cdrom >/dev/null && rm -f $ISO/nx-unattend-$id.iso"
	snapshot "$id" "$name"
	log "$name ($id): $(agent_ip "$id" || echo 'no address from the guest agent')"
}

step_install() {
	while read -r id name kind iso <&3; do
		pve "[ -f $ISO/$iso ]" || die "$name: $iso not on the host"
		"install_$kind" "$id" "$name" "$iso"
	done 3< <(rows "$@")
}

step_reset() {
	while read -r id name _ _ <&3; do
		pve "qm stop $id --skiplock 1 >/dev/null 2>&1; qm rollback $id clean-os"
		log "$name ($id): back to clean-os (stopped)"
	done 3< <(rows "$@")
}

step_ip() {
	while read -r id name kind _ <&3; do
		if [ "$kind" = windows ]; then echo "$name $id $(agent_ip "$id" || echo -)"; else echo "$name $id $(tap_ip "$id" || echo -)"; fi
	done 3< <(rows "$@")
}

cmd=${1:-}
shift || true
case $cmd in
install | reset | ip) "step_$cmd" "$@" ;;
list) grep . <<<"$VMS" ;;
*) sed -n '2,10p' "$0" && exit 2 ;;
esac
