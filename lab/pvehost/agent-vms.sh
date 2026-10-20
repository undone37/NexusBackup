#!/usr/bin/env bash
# Small Linux test VMs on the PVE lab host for the agent: one per distribution release, installed
# unattended from the ISOs on the host, an offline snapshot `clean-os` right after the OS install,
# then the agent package. `reset` rolls a VM back to the clean OS.
#
#   agent-vms.sh install [names]   prepare, serve the answer files, create and install, snapshot, agent
#   agent-vms.sh agent [names]     (re)install the agent package (VM running, guest agent up)
#   agent-vms.sh reset [names]     rollback to `clean-os` (VM stopped afterwards)
#   agent-vms.sh ip [names]        addresses from the guest agent
#   agent-vms.sh list              the VM table below
# names: default all, e.g. `ubuntu-2404 debian-13`. VMs: ID 220-233 (ours, see AGENTS.md "Labs").
#
# How the install runs without a console: the installer kernel and initrd are copied out of the ISO
# and booted directly (qm --args -kernel/-initrd/-append) with the answer file URL on the command
# line: Ubuntu autoinstall (cloud-init NoCloud), Debian preseed, Alma/Rocky kickstart, openSUSE Agama
# profile. The answer files come from a temporary HTTP server on the host (python3, stopped by PID).
# Every installer powers the VM off at the end; then the kernel arguments and the ISO are removed,
# the snapshot is taken and the VM boots from its disk. Network: DHCP on $BRIDGE.
#
# env: PVE_HOST (10.2.34.200), SSH_KEY (~/nexus-lab/pve-lab-key), LAB (~/nexus-lab/agent-vms: VM
#      password, packages), VM_KEY (~/nexus-lab/lab_ed25519: root and user `nexus` on the VMs),
#      BRIDGE (vmbr0), STORAGE (vmpool), PORT (8099), PARALLEL (4 installs at a time),
#      TAG (v0.1.0-alpha: release of the agent packages)
set -euo pipefail
PVE_HOST=${PVE_HOST:-10.2.34.200}
SSH_KEY=${SSH_KEY:-$HOME/nexus-lab/pve-lab-key}
LAB=${LAB:-$HOME/nexus-lab/agent-vms}
VM_KEY=${VM_KEY:-$HOME/nexus-lab/lab_ed25519}
BRIDGE=${BRIDGE:-vmbr0}
STORAGE=${STORAGE:-vmpool}
PORT=${PORT:-8099}
PARALLEL=${PARALLEL:-4}
TAG=${TAG:-v0.1.0-alpha}
HD=/var/lib/vz/nexus-agent-lab # on the host: kernels, initrds, answer files
ISO=/var/lib/vz/template/iso

# id name family iso (family: ubuntu, debian[:suite], el, suse)
VMS="
220 ubuntu-2204 ubuntu ubuntu-22.04.5-live-server-amd64.iso
221 ubuntu-2404 ubuntu ubuntu-24.04.5-live-server-amd64.iso
222 ubuntu-2604 ubuntu ubuntu-26.04.1-live-server-amd64.iso
223 ubuntu-2610 ubuntu ubuntu-26.10-live-server-amd64.iso
224 debian-12 debian debian-12.15.0-amd64-netinst.iso
225 debian-13 debian debian-13.7.0-amd64-netinst.iso
226 debian-testing debian:testing debian-testing-amd64-netinst.iso
227 alma-8 el AlmaLinux-8.10-x86_64-minimal.iso
228 alma-9 el AlmaLinux-9.8-x86_64-minimal.iso
229 alma-10 el AlmaLinux-10.2-x86_64-minimal.iso
230 rocky-8 el Rocky-8.10-x86_64-minimal.iso
231 rocky-9 el Rocky-9.8-x86_64-minimal.iso
232 rocky-10 el Rocky-10.2-x86_64-minimal.iso
233 leap-16 suse Leap-16.0-online-installer-x86_64.install.iso
"

pve() { ssh -i "$SSH_KEY" -o BatchMode=yes "root@$PVE_HOST" "$@"; }
T0=$(date +%s)
log() { printf '[%5ss] %s\n' $(($(date +%s) - T0)) "$*" >&2; }
die() {
	log "FAIL: $*"
	exit 1
}
rows() { # rows [names] -> "id name family iso" lines
	if [ $# -eq 0 ]; then
		grep . <<<"$VMS"
	else
		for n in "$@"; do grep -E "^[0-9]+ $n " <<<"$VMS" || die "unknown VM $n"; done
	fi
}

secrets() {
	mkdir -p "$LAB" && chmod 700 "$LAB"
	[ -s "$LAB/password" ] || (umask 077 && openssl rand -base64 18 >"$LAB/password")
	HASH=$(openssl passwd -6 -stdin <"$LAB/password")
	KEY=$(cat "$VM_KEY.pub")
}

# ---------------------------------------------------------------- answer files

answers() { # answers name family -> files in $LAB/http/<name>/
	local name=$1 family=$2 d="$LAB/http/$1"
	mkdir -p "$d"
	case $family in
	ubuntu)
		printf 'instance-id: %s\n' "$name" >"$d/meta-data"
		: >"$d/vendor-data" # optional for cloud-init, but asked for (and retried) when missing
		cat >"$d/user-data" <<EOF
#cloud-config
autoinstall:
  version: 1
  identity: {hostname: $name, username: nexus, password: '$HASH'}
  ssh: {install-server: true, allow-pw: false, authorized-keys: ['$KEY']}
  storage: {layout: {name: direct}}
  packages: [qemu-guest-agent]
  late-commands:
    - mkdir -p -m 700 /target/root/.ssh
    - sh -c "echo '$KEY' > /target/root/.ssh/authorized_keys && chmod 600 /target/root/.ssh/authorized_keys"
  shutdown: poweroff
EOF
		;;
	debian*)
		local suite=${family#debian}
		cat >"$d/preseed.cfg" <<EOF
d-i debian-installer/locale string en_US.UTF-8
d-i keyboard-configuration/xkb-keymap select us
d-i netcfg/choose_interface select auto
d-i netcfg/get_hostname string $name
d-i netcfg/get_domain string lab
d-i mirror/country string manual
d-i mirror/http/hostname string deb.debian.org
d-i mirror/http/directory string /debian
d-i mirror/http/proxy string
${suite:+d-i mirror/suite string ${suite#:}}
d-i passwd/root-login boolean false
d-i passwd/user-fullname string Nexus Lab
d-i passwd/username string nexus
d-i passwd/user-password-crypted password $HASH
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
d-i apt-setup/disable-cdrom-entries boolean true
tasksel tasksel/first multiselect standard, ssh-server
d-i pkgsel/include string qemu-guest-agent sudo
popularity-contest popularity-contest/participate boolean false
d-i grub-installer/only_debian boolean true
d-i grub-installer/bootdev string /dev/sda
d-i preseed/late_command string mkdir -p -m 700 /target/root/.ssh; echo '$KEY' > /target/root/.ssh/authorized_keys; chmod 600 /target/root/.ssh/authorized_keys
d-i finish-install/reboot_in_progress note
d-i debian-installer/exit/poweroff boolean true
EOF
		;;
	el)
		cat >"$d/ks.cfg" <<EOF
text
lang en_US.UTF-8
keyboard us
timezone UTC --utc
network --bootproto=dhcp --device=link --activate --hostname=$name
rootpw --lock
user --name=nexus --groups=wheel --iscrypted --password=$HASH
sshkey --username=root "$KEY"
sshkey --username=nexus "$KEY"
ignoredisk --only-use=sda
zerombr
clearpart --all --initlabel
# not autopart: it gives the whole volume group to the volumes, and LVM snapshots need free extents
# (the agent snapshots 10 % of the volume by default): root 10 GB, swap 1 GB, about 4 GB of 16 GB stay free
reqpart --add-boot
part pv.01 --size=1 --grow
volgroup vg pv.01
logvol swap --vgname=vg --name=swap --size=1024
logvol / --vgname=vg --name=root --fstype=xfs --size=10240
bootloader --location=mbr
selinux --enforcing
firstboot --disable
poweroff
%packages
@^minimal-environment
%end
%post
dnf -y install qemu-guest-agent && systemctl enable qemu-guest-agent
%end
EOF
		;;
	suse)
		cat >"$d/profile.json" <<EOF
{
  "product": {"id": "openSUSE_Leap"},
  "localization": {"language": "en_US.UTF-8", "keyboard": "us", "timezone": "UTC"},
  "hostname": {"static": "$name"},
  "root": {"sshPublicKey": "$KEY"},
  "user": {"fullName": "Nexus Lab", "userName": "nexus", "password": "$HASH", "hashedPassword": true},
  "software": {"packages": ["qemu-guest-agent", "openssh-server"]}
}
EOF
		;;
	esac
}

# kernel command line of the installer for a VM
cmdline() { # cmdline name family label
	local u="http://$PVE_HOST:$PORT/$1"
	case $2 in
	ubuntu) echo "autoinstall ds=nocloud-net;s=$u/ ---" ;;
	debian*) echo "auto=true priority=critical url=$u/preseed.cfg hostname=$1 domain=lab interface=auto ---" ;;
	el) echo "inst.repo=hd:LABEL=$3 inst.ks=$u/ks.cfg inst.text ip=dhcp" ;;
	suse) echo "root=live:CDLABEL=$3 inst.auto=$u/profile.json inst.finish=poweroff" ;;
	esac
}

# ---------------------------------------------------------------- host side

serve() {
	pve "mkdir -p $HD/http"
	tar -C "$LAB/http" -cf - . | pve "tar -C $HD/http -xf -"
	if pve "[ -s $HD/http.pid ] && kill -0 \$(cat $HD/http.pid) 2>/dev/null"; then return; fi
	# the whole background job redirected (and exec): nothing may hold the ssh session open
	pve "(cd $HD/http && exec setsid python3 -m http.server $PORT --bind $PVE_HOST) </dev/null >$HD/http.log 2>&1 & echo \$! >$HD/http.pid"
	sleep 1
	pve "curl -fsS -o /dev/null http://$PVE_HOST:$PORT/" || die "answer file server did not start"
	log "answer files served on $PVE_HOST:$PORT (pid $(pve "cat $HD/http.pid"))"
}

unserve() {
	pve "[ -s $HD/http.pid ] && kill \$(cat $HD/http.pid) 2>/dev/null; rm -f $HD/http.pid" || true
	log "answer file server stopped"
}

kernel() { # kernel name family iso -> kernel and initrd under $HD/<name>/
	local k i
	case $2 in
	ubuntu) k=/casper/vmlinuz i=/casper/initrd ;;
	debian*) k=/install.amd/vmlinuz i=/install.amd/initrd.gz ;;
	el) k=/images/pxeboot/vmlinuz i=/images/pxeboot/initrd.img ;;
	suse) k=/boot/x86_64/loader/linux i=/boot/x86_64/loader/initrd ;;
	esac
	pve "mkdir -p $HD/$1 && isoinfo -R -x $k -i $ISO/$3 >$HD/$1/kernel && isoinfo -R -x $i -i $ISO/$3 >$HD/$1/initrd"
}

label() { pve "isoinfo -d -i $ISO/$1 | sed -n 's/^Volume id: //p'"; }

create() { # create id name family iso
	local id=$1 name=$2 family=$3 iso=$4
	pve "[ -f $ISO/$iso ]" || die "$name: $iso not on the host (yet)"
	if pve "qm status $id" >/dev/null 2>&1; then
		[ "$(pve "qm config $id" | sed -n 's/^name: //p')" = "ag-$name" ] || die "VM $id exists and is not ag-$name"
		pve "qm stop $id --skiplock 1 >/dev/null 2>&1; qm destroy $id --purge 1 >/dev/null"
	fi
	kernel "$name" "$family" "$iso"
	local mem=2048
	[ "$family" = suse ] && mem=4096 # the Agama live system needs more than 2 GB
	local lbl args
	lbl=$(label "$iso")
	args="-kernel $HD/$name/kernel -initrd $HD/$name/initrd -append '$(cmdline "$name" "$family" "$lbl")'"
	pve "qm create $id --name ag-$name --ostype l26 --machine q35 --cpu host --cores 2 --memory $mem --balloon 0 \
		--scsihw virtio-scsi-single --scsi0 $STORAGE:16,discard=on,iothread=1 --net0 virtio,bridge=$BRIDGE \
		--ide2 local:iso/$iso,media=cdrom --boot order=scsi0 --agent enabled=1 --serial0 socket \
		--tags nexus-agent-lab --description 'agent test VM (lab/pvehost/agent-vms.sh); snapshot clean-os = OS only'"
	pve "qm set $id --args \"$args\"" >/dev/null
	pve "qm start $id"
	log "$name ($id): installing"
}

wait_off() { # wait_off id name: the installer powers off (60 min at most)
	local t=0
	while [ "$(pve "qm status $1" | awk '{print $2}')" != stopped ]; do
		sleep 30
		t=$((t + 30))
		[ $t -lt 3600 ] || die "$2 ($1): install still running after 60 min"
	done
}

finish() { # finish id name: boot from disk, offline snapshot, start
	pve "qm set $1 --delete args --ide2 none,media=cdrom >/dev/null && qm snapshot $1 clean-os --description 'OS install only, before the agent' && qm start $1"
	log "$2 ($1): installed, snapshot clean-os, booting"
}

# ---------------------------------------------------------------- guest side

ip_of() { # ip_of id -> first global IPv4 from the guest agent (waits up to 5 min)
	local t=0 a=
	while [ $t -lt 300 ]; do
		a=$(pve "qm guest cmd $1 network-get-interfaces 2>/dev/null" |
			python3 -c 'import json,sys
for i in json.load(sys.stdin):
    for a in i.get("ip-addresses", []):
        if a["ip-address-type"] == "ipv4" and not a["ip-address"].startswith("127."):
            print(a["ip-address"]); raise SystemExit' 2>/dev/null || true)
		[ -n "$a" ] && { echo "$a"; return; }
		sleep 10
		t=$((t + 10))
	done
	return 1
}

# the VMs are reached through the PVE host, with the lab key for the host
JUMP="ssh -i $SSH_KEY -o BatchMode=yes -W %h:%p root@$PVE_HOST"

vm() { # vm ip cmd...
	local ip=$1
	shift
	ssh -i "$VM_KEY" -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR \
		-o ProxyCommand="$JUMP" "root@$ip" "$@"
}

packages() {
	mkdir -p "$LAB/pkg"
	local v=${TAG#v}
	v=${v%%-*}
	DEB=$LAB/pkg/nexus-agent_${v}-1_amd64.deb RPM=$LAB/pkg/nexus-agent-${v}-1.x86_64.rpm
	[ -s "$DEB" ] && [ -s "$RPM" ] && return
	gh release download "$TAG" -D "$LAB/pkg" --clobber -p "$(basename "$DEB")" -p "$(basename "$RPM")"
}

# right after the first boot, name resolution may not be up yet (seen on Leap 16): 3 tries
retry() {
	local i
	for i in 1 2 3; do
		"$@" && return
		[ $i = 3 ] || sleep 30
	done
	return 1
}

agent() { # agent id name family
	local ip
	ip=$(ip_of "$1") || die "$2 ($1): no address from the guest agent"
	case $3 in
	ubuntu | debian*)
		scp -q -i "$VM_KEY" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR \
			-o ProxyCommand="$JUMP" "$DEB" "root@$ip:/root/"
		retry vm "$ip" "DEBIAN_FRONTEND=noninteractive apt-get install -y /root/$(basename "$DEB") >/dev/null" ;;
	el | suse)
		scp -q -i "$VM_KEY" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR \
			-o ProxyCommand="$JUMP" "$RPM" "root@$ip:/root/"
		if [ "$3" = suse ]; then
			retry vm "$ip" "zypper --non-interactive --no-gpg-checks install /root/$(basename "$RPM") >/dev/null"
		else
			retry vm "$ip" "dnf -y install /root/$(basename "$RPM") >/dev/null"
		fi ;;
	esac
	log "$2 ($1, $ip): $(vm "$ip" 'nexus-agent --version 2>/dev/null || rpm -q nexus-agent 2>/dev/null || dpkg-query -W nexus-agent')"
}

# ---------------------------------------------------------------- steps

install_one() { # install_one id name family iso
	create "$@"
	wait_off "$1" "$2"
	finish "$1" "$2"
	agent "$1" "$2" "$3"
}

step_install() {
	secrets
	packages
	local r
	while read -r id name family iso; do answers "$name" "$family"; done < <(rows "$@")
	serve
	trap unserve EXIT
	# PARALLEL installs at a time; each in its own log
	mkdir -p "$LAB/log"
	local pids=() names=()
	while read -r id name family iso <&3; do
		while [ "$(jobs -rp | wc -l)" -ge "$PARALLEL" ]; do sleep 10; done
		# no stdin: ssh in the job would read the rest of the VM list
		(install_one "$id" "$name" "$family" "$iso") </dev/null >"$LAB/log/$name.log" 2>&1 &
		pids+=($!) names+=("$name")
		sleep 5
	done 3< <(rows "$@")
	r=0
	for i in "${!pids[@]}"; do
		if wait "${pids[$i]}"; then log "${names[$i]}: ok"; else
			log "${names[$i]}: FAILED ($LAB/log/${names[$i]}.log)"
			r=1
		fi
	done
	return $r
}

step_agent() {
	packages
	while read -r id name family iso <&3; do agent "$id" "$name" "$family"; done 3< <(rows "$@")
}

step_reset() {
	while read -r id name _ _ <&3; do
		pve "qm stop $id --skiplock 1 >/dev/null 2>&1; qm rollback $id clean-os"
		log "$name ($id): back to clean-os (stopped)"
	done 3< <(rows "$@")
}

step_ip() {
	while read -r id name _ _ <&3; do echo "$name $id $(ip_of "$id" || echo -)"; done 3< <(rows "$@")
}

cmd=${1:-}
shift || true
case $cmd in
install | agent | reset | ip) "step_$cmd" "$@" ;;
list) grep . <<<"$VMS" ;;
*) sed -n '2,12p' "$0" && exit 2 ;;
esac
