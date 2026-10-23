#!/usr/bin/env bash
# The lab tests of crates/vmware (tests/lab.rs) on the regression VM (regress.sh) against the nested ESXi of
# esxi.sh: builds the test binary here, copies it there and runs it with the host's certificate (fetched there),
# the root password over stdin and the proxy agent of `esxi.sh proxy`. The store of the test goes to /var/tmp on
# the VM.
#
#   vmware-lab.sh [test name filter]
#
# env: LAB (~/nexus-lab/esxi; ~/nexus-lab/esxi8 for ESXi 8), VM_KEY (~/nexus-lab/lab_ed25519)
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
LAB=${LAB:-$HOME/nexus-lab/esxi}
VM_KEY=${VM_KEY:-$HOME/nexus-lab/lab_ed25519}
O=(-i "$VM_KEY" -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR)
R=$(cat "$HOME/nexus-lab/regress/ip")
E=$(cat "$LAB/ip")
bin=$(cd "$here/../.." && cargo test -q -p vmware --test lab --no-run --message-format=json 2>/dev/null |
	jq -r 'select(.profile.test == true and .target.name == "lab") | .executable' | tail -1)
[ -x "$bin" ] || { echo "no test binary" >&2; exit 1; }
scp -q "${O[@]}" "$bin" "root@$R:/root/vmware-lab"
proxy=$(LAB=$LAB "$here/esxi.sh" ssh "vim-cmd vmsvc/get.guest \$(vim-cmd vmsvc/getallvms | awk '\$2==\"nx-proxy\" {print \$1}') | sed -n 's/^ *ipAddress = \"\([0-9.]*\)\".*/\1/p' | head -1" 2>/dev/null || true)
# vCenter for the NFC read test (lab/pvehost/vcenter.sh), if deployed
VC_LAB=$HOME/nexus-lab/vcenter
vc=""
[ -s "$VC_LAB/ip" ] && [ -s "$VC_LAB/secrets.env" ] && vc=$(cat "$VC_LAB/ip")
{
	printf 'NEXUS_ESXI_PASSWORD=%s\n' "$(cat "$LAB/root.password")"
	[ -s "$LAB/proxy.token" ] && [ -n "$proxy" ] && printf 'NEXUS_PROXY=%s\nNEXUS_PROXY_TOKEN=%s\n' "$proxy" "$(cat "$LAB/proxy.token")"
	[ -n "$vc" ] && printf 'NEXUS_VC=%s\nNEXUS_VC_PASSWORD=%s\n' "$vc" "$(sed -n 's/^SSO_PW=//p' "$VC_LAB/secrets.env")"
} | ssh "${O[@]}" "root@$R" "umask 077; cat > /root/vmware-lab.env
	openssl s_client -connect $E:443 </dev/null 2>/dev/null | openssl x509 > /root/esxi.pem
	${vc:+openssl s_client -connect $vc:443 </dev/null 2>/dev/null | openssl x509 > /root/vc.pem}
	set -a; . /root/vmware-lab.env; rm -f /root/vmware-lab.env; mkdir -p /var/tmp/vmware-lab
	NEXUS_ESXI=$E NEXUS_ESXI_CERT=/root/esxi.pem ${vc:+NEXUS_VC_CERT=/root/vc.pem} NEXUS_TMP=/var/tmp/vmware-lab timeout 3600 /root/vmware-lab --nocapture --test-threads 1 ${1:-} 2>&1"
