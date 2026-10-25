#!/usr/bin/env bash
# Nested XCP-ng 8.3 on the PVE lab host (#40, docs/xcpng-design.md "Lab plan"), installed unattended.
#
#   xcpng.sh iso    $ISO with the default boot entry pointing at an answer file (local ext SR on sda, static
#                   $ADDR, the root password hash, the lab key for root by a post-install script) -> $ISO_OUT;
#                   the answer file and script are served from $HTTP_VM for the install only
#   xcpng.sh vm     VM $VMID (CPU type host: nested HVM; SATA disk, e1000 NIC) installs itself, waits for SSH
#   xcpng.sh xapi   the XAPI facts of the design before any connector code, on a test VDI written from dom0: CBT
#                   enabled, snapshot S1, its NBD export info, S1 reduced to CBT metadata (data_destroy), 4 MiB
#                   written at 512 MiB, snapshot S2, list_changed_blocks(S1, S2) = exactly that range
#   xcpng.sh testvm VM "nexus-m1" (template "Other install media", halted) whose 1 GiB disk starts with 64 MiB of
#                   known data: its UUID and the SHA-256 of that data in $LAB_X/testvm.json (crates/xcpng/tests/lab.rs)
#   xcpng.sh testwrite  4 MiB of new data at 512 MiB of nexus-m1's disk (the next backup is incremental): their
#                   SHA-256 added to $LAB_X/testvm.json as changed_sha256
#   xcpng.sh guest  VM "nexus-deb" (the newest Debian template, BIOS, 1 GiB, 2 vCPUs, a NIC on the management
#                   network) whose disk is the Debian 13 cloud image, started; its UUID in $LAB_X/guest.json
#                   (lab/pvehost/xcpng-e2e.sh)
#   xcpng.sh destroy
#
# Secrets in $LAB_X (~/nexus-lab/xcpng): root.pw. env: PVE_HOST, SSH_KEY (also root's key on the XCP-ng host),
#   VMID (287), ADDR (10.2.34.218), GW (10.2.34.254), DNS (10.2.34.253), ISO (xcp-ng-8.3.0-20260806.iso),
#   ISO_OUT (xcp-ng-8.3-auto.iso), HTTP_VM (10.2.34.99: VM 280, port 8000)
set -euo pipefail
PVE_HOST=${PVE_HOST:-10.2.34.200}
SSH_KEY=${SSH_KEY:-$HOME/nexus-lab/pve-lab-key}
VMID=${VMID:-287}
ADDR=${ADDR:-10.2.34.218}
GW=${GW:-10.2.34.254}
DNS=${DNS:-10.2.34.253}
ISO=${ISO:-xcp-ng-8.3.0-20260806.iso}
ISO_OUT=${ISO_OUT:-xcp-ng-8.3-auto.iso}
HTTP_VM=${HTTP_VM:-10.2.34.99}
LAB_X=${LAB_X:-$HOME/nexus-lab/xcpng}
VM_KEY=${VM_KEY:-$HOME/nexus-lab/lab_ed25519}
[ "$VMID" -ge 200 ] || { echo "VMID $VMID: only VMs from 200 are ours" >&2; exit 1; }
T0=$(date +%s)
log() { printf '[%4ss] %s\n' $(($(date +%s) - T0)) "$*" >&2; }
die() {
	log "FAIL: $*"
	exit 1
}
pve() { ssh -n -i "$SSH_KEY" -o BatchMode=yes "root@$PVE_HOST" "$@"; }
web() { ssh -i "$VM_KEY" -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR "root@$HTTP_VM" "$@"; }
xcp() { ssh -i "$SSH_KEY" -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR \
	-o ConnectTimeout=10 "root@$ADDR" "$@"; }

step_iso() {
	mkdir -p "$LAB_X"
	[ -f "$LAB_X/root.pw" ] || (umask 077 && head -c 18 /dev/urandom | base64 | tr -d '/+=' >"$LAB_X/root.pw")
	local hash
	hash=$(openssl passwd -6 "$(cat "$LAB_X/root.pw")")
	web 'mkdir -p /srv/xcp-answer'
	web "cat > /srv/xcp-answer/answer.xml" <<EOF
<?xml version="1.0"?>
<installation srtype="ext">
  <primary-disk>sda</primary-disk>
  <keymap>de</keymap>
  <root-password type="hash">$hash</root-password>
  <source type="local"/>
  <admin-interface name="eth0" proto="static">
    <ipaddr>$ADDR</ipaddr>
    <subnet>255.255.255.0</subnet>
    <gateway>$GW</gateway>
  </admin-interface>
  <name-server>$DNS</name-server>
  <timezone>Europe/Berlin</timezone>
  <hostname>xcp-lab</hostname>
  <script stage="filesystem-populated" type="url">http://$HTTP_VM:8000/post.sh</script>
</installation>
EOF
	web "cat > /srv/xcp-answer/post.sh" <<EOF
#!/bin/sh
# \$1: the installed root file system
mkdir -p "\$1/root/.ssh" && chmod 700 "\$1/root/.ssh"
echo '$(cat "$SSH_KEY.pub")' >> "\$1/root/.ssh/authorized_keys" && chmod 600 "\$1/root/.ssh/authorized_keys"
EOF
	pve "set -e; cd /root/xcpcfg; xorriso -osirrox on -indev /var/lib/vz/template/iso/$ISO -extract /boot/isolinux/isolinux.cfg orig.cfg >/dev/null 2>&1
		chmod u+w orig.cfg
		awk '/^LABEL install\$/ {f=1} f && /APPEND/ {sub(\" --- /install.img\", \" answerfile=http://$HTTP_VM:8000/answer.xml install --- /install.img\"); f=0} {print}' orig.cfg > isolinux.cfg
		grep -q 'answerfile=' isolinux.cfg
		rm -f /var/lib/vz/template/iso/$ISO_OUT
		xorriso -indev /var/lib/vz/template/iso/$ISO -outdev /var/lib/vz/template/iso/$ISO_OUT \
			-map isolinux.cfg /boot/isolinux/isolinux.cfg -boot_image any replay >/dev/null 2>&1
		test -s /var/lib/vz/template/iso/$ISO_OUT"
	log "local:iso/$ISO_OUT: $ISO booting into the answer file on $HTTP_VM"
}

step_vm() {
	local pid
	pve "qm status $VMID" >/dev/null 2>&1 && die "VM $VMID exists (step destroy)"
	# the answer file only while the installer needs it (it holds the root password hash)
	pid=$(web 'cd /srv/xcp-answer && (python3 -m http.server 8000 >/dev/null 2>&1 & echo $!)')
	pve "qm create $VMID --name nx-xcpng --cpu host --cores 4 --memory 8192 --balloon 0 --sata0 vmpool:100,discard=on \
		--net0 e1000,bridge=vmbr0 --ide2 local:iso/$ISO_OUT,media=cdrom --boot 'order=sata0;ide2' --ostype l26 \
		--serial0 socket >/dev/null && qm start $VMID"
	log "VM $VMID installing XCP-ng"
	for _ in $(seq 120); do
		xcp true 2>/dev/null && break
		sleep 10
	done
	web "kill $pid; rm -rf /srv/xcp-answer"
	xcp true || die "no SSH on $ADDR after 20 minutes"
	pve "qm set $VMID --ide2 none,media=cdrom >/dev/null"
	local v
	v=$(xcp '. /etc/xensource-inventory; echo "$PRODUCT_VERSION_TEXT, SR $(xe sr-list type=ext params=name-label --minimal)"')
	log "XCP-ng up: $v"
}

# python on dom0 (3.6, XenAPI over the local socket); the test VDI's state between the steps in /root/cbt-test.json
XAPI_PRE='import base64, json, subprocess, XenAPI
s = XenAPI.xapi_local()
s.xenapi.login_with_password("root", "", "1.0", "nexus-lab")
x = s.xenapi
def sh(*a):
    return subprocess.check_output(a, universal_newlines=True).strip()  # dom0: Python 3.6
def write(vdi, offset_mib, mib, seed):
    dom0 = x.host.get_control_domain(x.host.get_all()[0])
    vbd = x.VBD.create({"VM": dom0, "VDI": vdi, "userdevice": "autodetect", "bootable": False, "mode": "RW",
                        "type": "Disk", "empty": False, "other_config": {}, "qos_algorithm_type": "",
                        "qos_algorithm_params": {}})
    x.VBD.plug(vbd)
    try:
        dev = "/dev/" + x.VBD.get_device(vbd)
        sh("sh", "-c", "openssl enc -aes-128-ctr -md sha256 -nosalt -pass pass:%s < /dev/zero 2>/dev/null | "
           "dd of=%s bs=1M seek=%d count=%d iflag=fullblock oflag=direct 2>/dev/null" % (seed, dev, offset_mib, mib))
    finally:
        x.VBD.unplug(vbd)
        x.VBD.destroy(vbd)
def cleanup():
    for old in x.VDI.get_by_name_label("nexus-cbt-test"):
        for b in x.VDI.get_VBDs(old):
            if x.VBD.get_currently_attached(b):
                x.VBD.unplug(b)
            x.VBD.destroy(b)
        x.VDI.destroy(old)
'

step_xapi() {
	local t
	# 1: a 1 GiB VDI with 64 MiB of known data, CBT on, snapshot S1, the NBD purpose on the management network
	xcp "python3 -c '$XAPI_PRE
cleanup()
sr = [r for r in x.SR.get_all() if x.SR.get_type(r) == \"ext\"][0]
vdi = x.VDI.create({\"name_label\": \"nexus-cbt-test\", \"name_description\": \"\", \"SR\": sr, \"virtual_size\": str(1 << 30),
                   \"type\": \"user\", \"sharable\": False, \"read_only\": False, \"other_config\": {}, \"xenstore_data\": {},
                   \"sm_config\": {}, \"tags\": []})
write(vdi, 0, 64, \"a\")
x.VDI.enable_cbt(vdi)
s1 = x.VDI.snapshot(vdi, {})
x.VDI.set_name_label(s1, \"nexus-cbt-test\")
for n in x.network.get_all():
    if \"nbd\" not in x.network.get_purpose(n) and x.network.get_PIFs(n):
        x.network.add_purpose(n, \"nbd\")
info = x.VDI.get_nbd_info(s1)[0]
open(\"/root/nbd-cert.pem\", \"w\").write(info[\"cert\"])
json.dump({\"vdi\": x.VDI.get_uuid(vdi), \"s1\": x.VDI.get_uuid(s1), \"export\": info[\"exportname\"],
           \"address\": info[\"address\"], \"port\": info[\"port\"], \"subject\": info[\"subject\"]}, open(\"/root/cbt-test.json\", \"w\"))
print(\"cbt\", x.VDI.get_cbt_enabled(vdi), \"| S1\", x.VDI.get_type(s1), \"| nbd\", info[\"address\"], info[\"port\"], info[\"subject\"])
'" >&2
	# 2: read S1 over NBD with TLS (the host's certificate pinned) from the PVE host, compare with the data written;
	#    the export from a session over HTTPS as the connector would have (xapi-nbd refuses the local-socket root
	#    session of step 1)
	t=$(xcp 'cat /root/cbt-test.json')
	t=$(python3 -I "$(dirname "$0")/xapi_nbd.py" "$ADDR" "$(jq -r .s1 <<<"$t")" <"$LAB_X/root.pw")
	# qemu's NBD client cannot: xapi-nbd answers only NBD_OPT_EXPORT_NAME and denies the NBD_OPT_LIST qemu
	# checks first; libnbd's nbdcopy on $HTTP_VM (the host name of the certificate's subject mapped there)
	xcp 'cat /root/nbd-cert.pem' | web "rm -rf /tmp/nbdtls && mkdir -p /tmp/nbdtls && cat > /tmp/nbdtls/ca-cert.pem"
	web "sed -i '/ $(jq -r .subject <<<"$t")\$/d' /etc/hosts; echo '$(jq -r .address <<<"$t") $(jq -r .subject <<<"$t")' >> /etc/hosts"
	local uri
	uri="nbds://$(jq -r .subject <<<"$t"):$(jq -r .port <<<"$t")/$(jq -rn --arg e "$(jq -r .export <<<"$t")" '$e | @uri')?tls-certificates=/tmp/nbdtls"
	web "t0=\$(date +%s.%N); nbdcopy '$uri' - | head -c 64M | sha256sum | cut -c1-16; nbdcopy '$uri' /dev/null && awk -v a=\$t0 -v b=\$(date +%s.%N) 'BEGIN {printf \"full 1 GiB in %.1f s\\n\", b - a}';
		openssl enc -aes-128-ctr -md sha256 -nosalt -pass pass:a < /dev/zero 2>/dev/null | head -c 64M | sha256sum | cut -c1-16;
		rm -rf /tmp/nbdtls" >&2
	# 3: S1 reduced to CBT metadata, 4 MiB written at 512 MiB, snapshot S2, the changed blocks between them
	xcp "python3 -c '$XAPI_PRE
t = json.load(open(\"/root/cbt-test.json\"))
vdi, s1 = x.VDI.get_by_uuid(t[\"vdi\"]), x.VDI.get_by_uuid(t[\"s1\"])
x.VDI.data_destroy(s1)
print(\"S1 after data_destroy:\", x.VDI.get_type(s1))
write(vdi, 512, 4, \"b\")
s2 = x.VDI.snapshot(vdi, {})
x.VDI.set_name_label(s2, \"nexus-cbt-test\")
bm = base64.b64decode(x.VDI.list_changed_blocks(s1, s2))
bits = [i for i in range(len(bm) * 8) if bm[i // 8] & (0x80 >> (i % 8))]
print(\"changed 64 KiB blocks:\", len(bits), \"KiB\", bits[0] * 64 if bits else None, \"..\", (bits[-1] + 1) * 64 if bits else None,
      \"(expected 64 at 524288..528384)\")
cleanup()
'" >&2
}

step_testvm() {
	xcp "python3 -c '$XAPI_PRE
for v in x.VM.get_by_name_label(\"nexus-m1\"):
    for b in x.VM.get_VBDs(v):
        d = x.VBD.get_VDI(b)
        if d != \"OpaqueRef:NULL\":
            x.VDI.destroy(d)
    x.VM.destroy(v)
tpl = [t for t in x.VM.get_by_name_label(\"Other install media\") if x.VM.get_is_a_template(t)][0]
vm = x.VM.clone(tpl, \"nexus-m1\")
x.VM.provision(vm)
x.VM.set_is_a_template(vm, False)
sr = [r for r in x.SR.get_all() if x.SR.get_type(r) == \"ext\"][0]
vdi = x.VDI.create({\"name_label\": \"nexus-m1 disk\", \"name_description\": \"\", \"SR\": sr, \"virtual_size\": str(1 << 30),
                   \"type\": \"user\", \"sharable\": False, \"read_only\": False, \"other_config\": {}, \"xenstore_data\": {},
                   \"sm_config\": {}, \"tags\": []})
write(vdi, 0, 64, \"c\")
x.VBD.create({\"VM\": vm, \"VDI\": vdi, \"userdevice\": \"0\", \"bootable\": True, \"mode\": \"RW\", \"type\": \"Disk\",
              \"empty\": False, \"other_config\": {}, \"qos_algorithm_type\": \"\", \"qos_algorithm_params\": {}})
sha = sh(\"sh\", \"-c\", \"openssl enc -aes-128-ctr -md sha256 -nosalt -pass pass:c < /dev/zero 2>/dev/null | head -c 64M | sha256sum\").split()[0]
print(json.dumps({\"vm\": x.VM.get_uuid(vm), \"sha256\": sha}))
'" | tail -1 >"$LAB_X/testvm.json"
	log "test VM nexus-m1: $(cat "$LAB_X/testvm.json")"
}

step_testwrite() {
	local seed=$RANDOM sha
	sha=$(xcp "python3 -c '$XAPI_PRE
vm = x.VM.get_by_name_label(\"nexus-m1\")[0]
vdi = [x.VBD.get_VDI(b) for b in x.VM.get_VBDs(vm) if x.VBD.get_userdevice(b) == \"0\"][0]
write(vdi, 512, 4, \"$seed\")
print(sh(\"sh\", \"-c\", \"openssl enc -aes-128-ctr -md sha256 -nosalt -pass pass:$seed < /dev/zero 2>/dev/null | head -c 4M | sha256sum\").split()[0])
'" | tail -1)
	jq --arg s "$sha" '.changed_sha256 = $s' "$LAB_X/testvm.json" >"$LAB_X/testvm.json.new"
	mv "$LAB_X/testvm.json.new" "$LAB_X/testvm.json"
	log "4 MiB written at 512 MiB of nexus-m1: $sha"
}

step_guest() {
	xcp 'test -s /var/tmp/deb13.qcow2 || curl -sfL -o /var/tmp/deb13.qcow2 \
		https://cloud.debian.org/images/cloud/trixie/latest/debian-13-genericcloud-amd64.qcow2'
	xcp "python3 -c '$XAPI_PRE
for v in x.VM.get_by_name_label(\"nexus-deb\"):
    if x.VM.get_power_state(v) != \"Halted\":
        x.VM.hard_shutdown(v)
    for b in x.VM.get_VBDs(v):
        d = x.VBD.get_VDI(b)
        if d != \"OpaqueRef:NULL\":
            x.VDI.destroy(d)
    x.VM.destroy(v)
deb = [t for t in x.VM.get_all() if x.VM.get_is_a_template(t) and x.VM.get_name_label(t).startswith(\"Debian \")
       and x.VM.get_name_label(t).split()[-1].isdigit()]
tpl = max(deb, key=lambda t: int(x.VM.get_name_label(t).split()[-1]))
vm = x.VM.clone(tpl, \"nexus-deb\")
x.VM.set_is_a_template(vm, False)
g = str(1 << 30)
x.VM.set_memory_limits(vm, g, g, g, g)
x.VM.set_VCPUs_max(vm, \"2\")
x.VM.set_VCPUs_at_startup(vm, \"2\")
x.VM.set_HVM_boot_params(vm, {\"order\": \"c\", \"firmware\": \"bios\"})
sr = [r for r in x.SR.get_all() if x.SR.get_type(r) == \"ext\"][0]
vdi = x.VDI.create({\"name_label\": \"nexus-deb disk\", \"name_description\": \"\", \"SR\": sr, \"virtual_size\": str(3 << 30),
                   \"type\": \"user\", \"sharable\": False, \"read_only\": False, \"other_config\": {}, \"xenstore_data\": {},
                   \"sm_config\": {}, \"tags\": []})
dom0 = x.host.get_control_domain(x.host.get_all()[0])
vbd = x.VBD.create({\"VM\": dom0, \"VDI\": vdi, \"userdevice\": \"autodetect\", \"bootable\": False, \"mode\": \"RW\",
                    \"type\": \"Disk\", \"empty\": False, \"other_config\": {}, \"qos_algorithm_type\": \"\",
                    \"qos_algorithm_params\": {}})
x.VBD.plug(vbd)
try:
    sh(\"qemu-img\", \"convert\", \"-n\", \"-O\", \"raw\", \"/var/tmp/deb13.qcow2\", \"/dev/\" + x.VBD.get_device(vbd))
finally:
    x.VBD.unplug(vbd)
    x.VBD.destroy(vbd)
x.VBD.create({\"VM\": vm, \"VDI\": vdi, \"userdevice\": \"0\", \"bootable\": True, \"mode\": \"RW\", \"type\": \"Disk\",
              \"empty\": False, \"other_config\": {}, \"qos_algorithm_type\": \"\", \"qos_algorithm_params\": {}})
pif = [p for p in x.PIF.get_all() if x.PIF.get_management(p)][0]
x.VIF.create({\"device\": \"0\", \"network\": x.PIF.get_network(pif), \"VM\": vm, \"MAC\": \"\", \"MTU\": \"1500\",
              \"other_config\": {}, \"qos_algorithm_type\": \"\", \"qos_algorithm_params\": {},
              \"locking_mode\": \"network_default\", \"ipv4_allowed\": [], \"ipv6_allowed\": []})
x.VM.start(vm, False, False)
print(json.dumps({\"vm\": x.VM.get_uuid(vm), \"template\": x.VM.get_name_label(tpl)}))
'" | tail -1 >"$LAB_X/guest.json"
	log "guest nexus-deb running: $(cat "$LAB_X/guest.json")"
}

step_destroy() {
	pve "qm status $VMID >/dev/null 2>&1 || exit 0; qm stop $VMID >/dev/null 2>&1; qm destroy $VMID --purge 1 >/dev/null"
	log "VM $VMID destroyed"
}

[ $# -gt 0 ] || set -- iso vm xapi
for s in "$@"; do
	"step_$s"
done
