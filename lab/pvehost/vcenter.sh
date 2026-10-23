#!/usr/bin/env bash
# vCenter Server (VCSA 8.0.3, size tiny) for the VMware connector (plan.md Phase 41) on the nested ESXi 8 (VM 251,
# esxi.sh ESXI=8), with a static address. The CLI installer runs on the regression VM (regress.sh) from the ISO
# on the PVE host's local storage, attached there as CD-ROM; vCenter then manages both nested hosts (VM 250,
# ESXi 7, and VM 251 itself). Passwords are generated into $LAB/secrets.env.
#
#   vcenter.sh datastore   a VMFS datastore ($DATASTORE) on ESXi 8's second disk (sata1 of VM 251, 600 GB thin)
#   vcenter.sh deploy      vcsa-deploy install (about 45 minutes; needs VCSA_IP, optionally VCSA_NAME as FQDN)
#   vcenter.sh cert        vCenter's certificate into $LAB/vcenter.pem
#   vcenter.sh hosts       datacenter nx-lab with both ESXi hosts (their certificates pinned by thumbprint)
#   vcenter.sh status      version and hosts through the API
#   vcenter.sh destroy     power off and delete the appliance VM on ESXi 8 (the datastore stays)
#
# env: VCSA_IP (static, required for deploy), VCSA_NAME (FQDN with a DNS record; default: the IP), PREFIX (24),
#      GATEWAY (10.2.34.254), DNS (10.2.34.253), NTP (pool.ntp.org), LAB (~/nexus-lab/vcenter), DATASTORE
#      (datastore2), ISO (VMware-VCSA-all-8.0.3-25413364.iso), VM_NAME (nx-vcsa), PVE_HOST, SSH_KEY, VM_KEY
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
PVE_HOST=${PVE_HOST:-10.2.34.200}
SSH_KEY=${SSH_KEY:-$HOME/nexus-lab/pve-lab-key}
VM_KEY=${VM_KEY:-$HOME/nexus-lab/lab_ed25519}
LAB=${LAB:-$HOME/nexus-lab/vcenter}
E7=$HOME/nexus-lab/esxi
E8=$HOME/nexus-lab/esxi8
PREFIX=${PREFIX:-24}
GATEWAY=${GATEWAY:-10.2.34.254}
DNS=${DNS:-10.2.34.253}
NTP=${NTP:-pool.ntp.org}
DATASTORE=${DATASTORE:-datastore2}
ISO=${ISO:-VMware-VCSA-all-8.0.3-25413364.iso}
VM_NAME=${VM_NAME:-nx-vcsa}
RVM=280
T0=$(date +%s)
log() { printf '[%4ss] %s\n' $(($(date +%s) - T0)) "$*" >&2; }
die() {
	log "FAIL: $*"
	exit 1
}
mkdir -p "$LAB" && chmod 700 "$LAB"
pve() { ssh -n -i "$SSH_KEY" -o BatchMode=yes "root@$PVE_HOST" "$@"; }
# the regression VM, where the installer and the API calls run
rvm() {
	ssh -i "$VM_KEY" -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=no \
		-o UserKnownHostsFile=/dev/null -o LogLevel=ERROR "root@$(cat "$HOME/nexus-lab/regress/ip")" "$@"
}
esx8() {
	ssh -i "$E8/esxi_ecdsa" -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=no \
		-o UserKnownHostsFile=/dev/null -o LogLevel=ERROR "root@$(cat "$E8/ip")" "$@"
}
secret() { sed -n "s/^$1=//p" "$LAB/secrets.env"; }
vcsa_ip() { cat "$LAB/ip" 2>/dev/null || die "no $LAB/ip: run deploy first"; }

step_datastore() {
	esx8 "set -e
		esxcli storage core adapter rescan --all
		vmkfstools -P /vmfs/volumes/$DATASTORE >/dev/null 2>&1 && { echo '$DATASTORE exists'; exit 0; }
		# the 600 GB disk: the local disk without partitions
		d=\$(for x in \$(ls /vmfs/devices/disks/ | grep -v ':'); do
			[ \"\$(partedUtil getptbl /vmfs/devices/disks/\$x 2>/dev/null | sed -n '3p')\" = '' ] && echo \$x; done | head -1)
		[ -n \"\$d\" ] || { echo 'no empty disk'; exit 1; }
		partedUtil mklabel /vmfs/devices/disks/\$d gpt >/dev/null
		end=\$(( \$(partedUtil getUsableSectors /vmfs/devices/disks/\$d | awk '{print \$2}') ))
		partedUtil setptbl /vmfs/devices/disks/\$d gpt \"1 2048 \$end AA31E02A400F11DB9590000C2911D1B8 0\" >/dev/null
		vmkfstools -C vmfs6 -S $DATASTORE /vmfs/devices/disks/\$d:1 >/dev/null
		echo \"$DATASTORE on \$d\"" </dev/null
	esx8 "df -h | grep -E 'Filesystem|$DATASTORE'" </dev/null
}

step_deploy() {
	[ -n "${VCSA_IP:-}" ] || die "VCSA_IP is not set (a free static address)"
	[ -s "$LAB/secrets.env" ] || {
		# the appliance's policy: 8 to 20 characters with upper and lower case, a digit and a special character
		umask 077
		printf 'ROOT_PW=%sAa1.\nSSO_PW=%sAa1.\n' "$(openssl rand -hex 6)" "$(openssl rand -hex 6)" >"$LAB/secrets.env"
	}
	echo "$VCSA_IP" >"$LAB/ip"
	pve "qm config $RVM | grep -q '$ISO' || qm set $RVM --ide2 local:iso/$ISO,media=cdrom >/dev/null"
	jq -n --arg esx "$(cat "$E8/ip")" --arg epw "$(cat "$E8/root.password")" --arg ds "$DATASTORE" \
		--arg name "$VM_NAME" --arg ip "$VCSA_IP" --arg sys "${VCSA_NAME:-$VCSA_IP}" --argjson prefix "$PREFIX" \
		--arg gw "$GATEWAY" --arg dns "$DNS" --arg ntp "$NTP" --arg rpw "$(secret ROOT_PW)" --arg spw "$(secret SSO_PW)" '{
			__version: "2.13.0",
			new_vcsa: {
				esxi: {hostname: $esx, username: "root", password: $epw, deployment_network: "VM Network", datastore: $ds},
				appliance: {thin_disk_mode: true, deployment_option: "tiny", name: $name},
				network: {ip_family: "ipv4", mode: "static", system_name: $sys, ip: $ip, prefix: ($prefix | tostring),
					gateway: $gw, dns_servers: [$dns]},
				os: {password: $rpw, ntp_servers: $ntp, ssh_enable: true},
				sso: {password: $spw, domain_name: "vsphere.local"}
			},
			ceip: {settings: {ceip_enabled: false}}
		}' | rvm "umask 077; cat > /root/vcsa.json"
	# ponytail: --no-ssl-certificate-verification towards the nested ESXi on the lab network (its certificate is
	# self-signed and new per install); the installer takes no pinned thumbprint for the target host
	rvm "set -e; mkdir -p /mnt/vcsa; mountpoint -q /mnt/vcsa || mount -o ro /dev/sr0 /mnt/vcsa
		cd /mnt/vcsa/vcsa-cli-installer/lin64
		./vcsa-deploy install --accept-eula --no-ssl-certificate-verification --log-dir /root/vcsa-log /root/vcsa.json \
			> /root/vcsa-deploy.log 2>&1; rc=\$?
		shred -u /root/vcsa.json; tail -15 /root/vcsa-deploy.log; exit \$rc" </dev/null
	step_cert
}

step_cert() {
	rvm "openssl s_client -connect $(vcsa_ip):443 </dev/null 2>/dev/null | openssl x509" >"$LAB/vcenter.pem"
	openssl x509 -in "$LAB/vcenter.pem" -noout -subject -enddate
}

# pyvmomi in the regression VM's venv; the passwords over stdin
py() {
	local script=$1
	shift
	{
		printf '%s\n' "$(secret SSO_PW)" "$(cat "$E7/root.password")" "$(cat "$E8/root.password")"
	} | rvm "VC=$(vcsa_ip) E7=$(cat "$E7/ip") E8=$(cat "$E8/ip") /root/nexus-lab/esxi/venv/bin/python3 -I -c '$script'"
}

PY_CONNECT='
import os, ssl, sys, hashlib
from pyVim.connect import SmartConnect
from pyVmomi import vim
sso, pw7, pw8 = (sys.stdin.readline().strip() for _ in range(3))
# ponytail: the lab vCenter is reached by IP on the lab network; certificate checks are left to the connector tests
si = SmartConnect(host=os.environ["VC"], user="administrator@vsphere.local", pwd=sso, sslContext=ssl._create_unverified_context())
c = si.RetrieveContent()
'

step_hosts() {
	py "$PY_CONNECT"'
def thumb(h):
    return ":".join("%02X" % b for b in hashlib.sha1(ssl.PEM_cert_to_DER_cert(ssl.get_server_certificate((h, 443)))).digest())
dc = next((d for d in c.rootFolder.childEntity if d.name == "nx-lab"), None) or c.rootFolder.CreateDatacenter(name="nx-lab")
have = {h.name for cr in dc.hostFolder.childEntity for h in getattr(cr, "host", [])}
for ip, pw in ((os.environ["E7"], pw7), (os.environ["E8"], pw8)):
    if ip in have:
        print(ip, "already added"); continue
    spec = vim.host.ConnectSpec(hostName=ip, userName="root", password=pw, sslThumbprint=thumb(ip), force=True)
    t = dc.hostFolder.AddStandaloneHost_Task(spec=spec, addConnected=True)
    while t.info.state in ("queued", "running"):
        import time; time.sleep(2)
    print(ip, t.info.state, t.info.error.msg if t.info.error else "")
'
}

step_status() {
	py "$PY_CONNECT"'
print(c.about.fullName)
for dc in c.rootFolder.childEntity:
    for cr in dc.hostFolder.childEntity:
        for h in getattr(cr, "host", []):
            print(dc.name, h.name, h.summary.config.product.fullName, h.runtime.connectionState, len(h.vm), "VMs")
'
}

step_destroy() {
	esx8 "id=\$(vim-cmd vmsvc/getallvms | awk '\$2 == \"$VM_NAME\" {print \$1}'); [ -n \"\$id\" ] || exit 0
		vim-cmd vmsvc/power.off \$id >/dev/null 2>&1 || true; vim-cmd vmsvc/destroy \$id >/dev/null && echo \"$VM_NAME removed\"" </dev/null
	rm -f "$LAB/ip" "$LAB/vcenter.pem"
}

for s in "$@"; do
	"step_$s"
done
