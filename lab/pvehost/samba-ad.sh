#!/usr/bin/env bash
# A Samba AD domain controller on the PVE lab host for the tenant directory (#52): LDAPS (the certificate Samba
# makes itself), a read-only bind account and a few users and groups, so `directory_sync` has a directory to read.
# A privileged Debian 13 container (Samba AD needs xattrs and ACLs).
#
#   samba-ad.sh ct       container $CTID ($ADDR), samba provisioned as $REALM, started
#   samba-ad.sh users    bind account nexus-ldap, users jdoe and asmith, group "Finance" (their SIDs in $LAB_S/sids.txt)
#   samba-ad.sh cert     the LDAPS certificate to pin -> $LAB_S/ldaps.pem
#   samba-ad.sh destroy
#
# Secrets in $LAB_S (~/nexus-lab/samba): admin.pw, bind.pw. env: PVE_HOST, SSH_KEY, CTID (289), ADDR (10.2.34.219),
#   GW (10.2.34.254), DNS (10.2.34.253: the lab's; Samba's own DNS is not needed), REALM (NXLAB.TEST), DOMAIN (NXLAB)
set -euo pipefail
PVE_HOST=${PVE_HOST:-10.2.34.200}
SSH_KEY=${SSH_KEY:-$HOME/nexus-lab/pve-lab-key}
CTID=${CTID:-289}
ADDR=${ADDR:-10.2.34.219}
GW=${GW:-10.2.34.254}
DNS=${DNS:-10.2.34.253}
REALM=${REALM:-NXLAB.TEST}
DOMAIN=${DOMAIN:-NXLAB}
LAB_S=${LAB_S:-$HOME/nexus-lab/samba}
[ "$CTID" -ge 200 ] || { echo "CTID $CTID: only IDs from 200 are ours" >&2; exit 1; }
T0=$(date +%s)
log() { printf '[%4ss] %s\n' $(($(date +%s) - T0)) "$*" >&2; }
pve() { ssh -i "$SSH_KEY" -o BatchMode=yes "root@$PVE_HOST" "$@"; }
ct() { pve "pct exec $CTID -- bash -c $(printf '%q' "$1")"; }

step_ct() {
	mkdir -p "$LAB_S"
	for f in admin.pw bind.pw; do
		[ -f "$LAB_S/$f" ] || (umask 077 && printf 'Nx1-%s\n' "$(head -c 15 /dev/urandom | base64 | tr -d '/+=')" >"$LAB_S/$f")
	done
	pve "pct status $CTID >/dev/null 2>&1" && { log "CT $CTID exists"; return; }
	pve "pct create $CTID local:vztmpl/debian-13-standard_13.6-1_amd64.tar.zst --hostname dc-samba \
		--unprivileged 0 --features nesting=1 --cores 2 --memory 2048 --rootfs vmpool:8 \
		--net0 name=eth0,bridge=vmbr0,ip=$ADDR/24,gw=$GW --nameserver $DNS --searchdomain ${REALM,,} >/dev/null &&
		pct start $CTID"
	ct "export DEBIAN_FRONTEND=noninteractive; apt-get -qq update && apt-get -qq install -y samba winbind krb5-user \
		ldb-tools >/dev/null && systemctl disable --now smbd nmbd winbind >/dev/null 2>&1; rm -f /etc/samba/smb.conf"
	# the password on stdin of the provisioning, never on a command line
	pve "pct exec $CTID -- bash -c 'read -r pw; samba-tool domain provision --realm=$REALM --domain=$DOMAIN \
		--server-role=dc --dns-backend=SAMBA_INTERNAL --adminpass=\"\$pw\" >/dev/null'" <"$LAB_S/admin.pw"
	ct "cp /var/lib/samba/private/krb5.conf /etc/krb5.conf; systemctl unmask samba-ad-dc >/dev/null 2>&1;
		systemctl enable --now samba-ad-dc >/dev/null 2>&1; sleep 5; ss -ltn | grep -q ':636 ' && echo ldaps up"
	log "CT $CTID: Samba AD $REALM at $ADDR"
}

step_users() {
	pve "pct exec $CTID -- bash -c 'read -r pw; samba-tool user show nexus-ldap >/dev/null 2>&1 ||
		samba-tool user create nexus-ldap \"\$pw\" >/dev/null'" <"$LAB_S/bind.pw"
	ct "for u in jdoe asmith; do samba-tool user show \$u >/dev/null 2>&1 ||
		samba-tool user create \$u --random-password >/dev/null; done
		samba-tool group show Finance >/dev/null 2>&1 || samba-tool group add Finance >/dev/null
		samba-tool group addmembers Finance asmith >/dev/null 2>&1 || true
		for a in jdoe asmith Finance nexus-ldap; do echo \"\$(wbinfo -n $DOMAIN\\\\\$a 2>/dev/null | cut -d' ' -f1) \$a\"; done" \
		>"$LAB_S/sids.txt"
	log "users: $(tr '\n' ' ' <"$LAB_S/sids.txt")"
}

step_cert() {
	ct "openssl x509 -in /var/lib/samba/private/tls/cert.pem" >"$LAB_S/ldaps.pem"
	log "LDAPS certificate: $(openssl x509 -in "$LAB_S/ldaps.pem" -noout -subject)"
}

step_destroy() {
	pve "pct status $CTID >/dev/null 2>&1 || exit 0; pct stop $CTID >/dev/null 2>&1; pct destroy $CTID --purge 1 >/dev/null"
	log "CT $CTID destroyed"
}

[ $# -gt 0 ] || set -- ct users cert
for s in "$@"; do
	"step_$s"
done
