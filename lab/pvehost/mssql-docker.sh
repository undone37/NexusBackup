#!/usr/bin/env bash
# SQL Server on Linux in Docker (#41) on the PVE lab host: a Debian 13 clone (agent VM 225) with Docker from the
# Debian packages and Microsoft's SQL Server 2022 image (Developer edition, licence accepted by the maintainer on
# 2026-11-02; ACCEPT_EULA=Y), a database labdb (FULL) with a table that gets a row per second, for the mssql plugin.
#
#   mssql-docker.sh vms      clone 225 to $ID, a second disk for /var/lib/docker, start, new host keys
#   mssql-docker.sh static   fixed address $ADDR (ifupdown), kept in $LAB/host
#   mssql-docker.sh install  docker.io, the image, container mssql1 (port 1433 on localhost only)
#   mssql-docker.sh db       labdb (FULL), table ticks, transient unit nexus-ticks inserts one row per second
#   mssql-docker.sh sshkey   $LAB/nexus_ed25519 for the appliance as user nexus (member of group docker); prints the
#                            host key line
#   mssql-docker.sh sql SQL  runs SQL in the container as sa
#   mssql-docker.sh ssh CMD  a command as root on the VM
#   mssql-docker.sh destroy  stop and remove the VM
#
# env: PVE_HOST, SSH_KEY, VM_KEY as patroni.sh; LAB (~/nexus-lab/mssql-docker), ID (269), ADDR (10.2.34.246),
#      IMAGE (mcr.microsoft.com/mssql/server:2022-latest)
set -euo pipefail
PVE_HOST=${PVE_HOST:-10.2.34.200}
SSH_KEY=${SSH_KEY:-$HOME/nexus-lab/pve-lab-key}
VM_KEY=${VM_KEY:-$HOME/nexus-lab/lab_ed25519}
LAB=${LAB:-$HOME/nexus-lab/mssql-docker}
STORAGE=${STORAGE:-vmpool}
ID=${ID:-269}
ADDR=${ADDR:-10.2.34.246}
IMAGE=${IMAGE:-mcr.microsoft.com/mssql/server:2022-latest}
SRC=225
T0=$(date +%s)
log() { printf '[%4ss] %s\n' $(($(date +%s) - T0)) "$*" >&2; }
die() {
	log "FAIL: $*"
	exit 1
}
pve() { ssh -n -i "$SSH_KEY" -o BatchMode=yes "root@$PVE_HOST" "$@" 2> >(grep -v 'older storage API' >&2); }
mkdir -p "$LAB" && chmod 700 "$LAB"
host() { cat "$LAB/host" 2>/dev/null || echo "$ADDR"; }
sshv() {
	local a=$1
	shift
	ssh -i "$VM_KEY" -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
		-o LogLevel=ERROR -o ServerAliveInterval=5 -o ServerAliveCountMax=3 "root@$a" "$@"
}
on() { sshv "$(host)" "$@"; }
guest_ip() {
	pve "qm guest cmd $ID network-get-interfaces 2>/dev/null" |
		jq -r '[.[] | select(.name != "lo") | .["ip-addresses"][]? | select(.["ip-address-type"] == "ipv4") | .["ip-address"]][0] // empty'
}
sa() { # SQL on stdin as sa in the container
	# shellcheck disable=SC1091
	. "$LAB/secrets.env"
	{ echo "$SA_PASSWORD"; cat; } | on "IFS= read -r p; docker exec -i -e SQLCMDPASSWORD=\"\$p\" mssql1 /opt/mssql-tools18/bin/sqlcmd -S localhost -U sa -C -b -h -1 -W"
}

step_vms() {
	if pve "qm status $ID" >/dev/null 2>&1; then
		log "VM $ID exists"
	else
		log "cloning $SRC to $ID"
		pve "qm clone $SRC $ID --full --name mssql-docker --storage $STORAGE >/dev/null &&
			qm set $ID --memory 6144 --cores 4 --scsi1 $STORAGE:30,discard=on,iothread=1 --tags nexus-mssql-lab \
				--description 'SQL Server on Docker lab (lab/pvehost/mssql-docker.sh)' >/dev/null && qm start $ID"
	fi
	local a="" end=$(($(date +%s) + 600))
	until a=$(guest_ip) && [ -n "$a" ]; do
		[ "$(date +%s)" -lt "$end" ] || die "no address after 10 minutes"
		sleep 10
	done
	echo "$a" >"$LAB/host"
	on "set -e; [ \"\$(hostname)\" = mssql-docker ] && exit 0
		hostnamectl set-hostname mssql-docker; sed -i 's/^127.0.1.1 .*/127.0.1.1 mssql-docker/' /etc/hosts
		rm -f /etc/machine-id /var/lib/dbus/machine-id; systemd-machine-id-setup >/dev/null
		apt-get -qq purge 'nexus-agent*' >/dev/null 2>&1 || true
		rm -f /etc/ssh/ssh_host_*; dpkg-reconfigure -f noninteractive openssh-server >/dev/null 2>&1; systemctl restart ssh
		d=\$(lsblk -dpno NAME,TYPE | awk '\$2==\"disk\"{print \$1}' | while read -r x; do lsblk -no MOUNTPOINT \$x | grep -q . || echo \$x; done | head -1)
		[ -n \"\$d\" ] && mkfs.ext4 -q \$d && mkdir -p /var/lib/docker &&
			echo \"UUID=\$(blkid -s UUID -o value \$d) /var/lib/docker ext4 defaults 0 2\" >>/etc/fstab && systemctl daemon-reload && mount /var/lib/docker"
	log "mssql-docker: $(host), $(on 'df -h /var/lib/docker | tail -1')"
}

step_static() {
	local cur ifc
	cur=$(guest_ip)
	[ -n "$cur" ] || die "no address from the guest agent"
	if [ "$cur" != "$ADDR" ]; then
		ifc=$(sshv "$cur" "ip -o -4 route show default | awk '{print \$5}'")
		# the session dies with the old address (keepalive ends it); the address check below decides
		sshv "$cur" "sed -i 's/^iface $ifc inet dhcp\$/iface $ifc inet static\\n\\taddress $ADDR\\/24\\n\\tgateway ${GW:-10.2.34.254}/' /etc/network/interfaces &&
			grep -q 'address $ADDR' /etc/network/interfaces && nohup sh -c 'sleep 1; ip addr flush dev $ifc; ifdown $ifc; ifup $ifc' >/dev/null 2>&1 &" || true
		for _ in $(seq 30); do
			[ "$(guest_ip)" = "$ADDR" ] && break
			sleep 2
		done
		[ "$(guest_ip)" = "$ADDR" ] || die "no $ADDR after the change"
		log "$cur -> $ADDR"
	fi
	echo "$ADDR" >"$LAB/host"
}

step_install() {
	[ -s "$LAB/secrets.env" ] || echo "SA_PASSWORD=Nx$(openssl rand -hex 10)!" >"$LAB/secrets.env"
	# shellcheck disable=SC1091
	. "$LAB/secrets.env"
	on "set -e; command -v docker >/dev/null || { apt-get -qq update && DEBIAN_FRONTEND=noninteractive apt-get -qq install -y docker.io >/dev/null; }
		systemctl enable --now docker >/dev/null 2>&1
		docker image inspect $IMAGE >/dev/null 2>&1 || docker pull -q $IMAGE >/dev/null
		docker inspect mssql1 >/dev/null 2>&1 || docker run -d --name mssql1 --restart unless-stopped -e ACCEPT_EULA=Y -e MSSQL_PID=Developer \
			-e MSSQL_SA_PASSWORD='$SA_PASSWORD' -p 127.0.0.1:1433:1433 -v mssql1-data:/var/opt/mssql $IMAGE >/dev/null"
	log "container started; waiting for SQL Server"
	local end=$(($(date +%s) + 300))
	until echo "SELECT @@VERSION" | sa >/dev/null 2>&1; do
		[ "$(date +%s)" -lt "$end" ] || die "SQL Server did not answer within 5 minutes"
		sleep 5
	done
	log "$(echo "SET NOCOUNT ON; SELECT CAST(SERVERPROPERTY('ProductVersion') AS nvarchar(40)) + ' ' + CAST(SERVERPROPERTY('Edition') AS nvarchar(80))" | sa | head -1)"
}

step_db() {
	sa <<'EOF'
SET NOCOUNT ON;
IF DB_ID('labdb') IS NULL CREATE DATABASE labdb;
ALTER DATABASE labdb SET RECOVERY FULL;
EOF
	sa <<'EOF'
SET NOCOUNT ON; USE labdb;
IF OBJECT_ID('dbo.ticks') IS NULL CREATE TABLE dbo.ticks (id int IDENTITY PRIMARY KEY, t datetime2 NOT NULL DEFAULT sysutcdatetime());
EOF
	# shellcheck disable=SC1091
	. "$LAB/secrets.env"
	on "systemctl is-active -q nexus-ticks || systemd-run -q --unit nexus-ticks /bin/bash -c 'while :; do printf \"INSERT INTO labdb.dbo.ticks DEFAULT VALUES;\\nGO\\n\"; sleep 1; done |
		docker exec -i -e SQLCMDPASSWORD=$SA_PASSWORD mssql1 /opt/mssql-tools18/bin/sqlcmd -S localhost -U sa -C >/dev/null'"
	sleep 3
	log "labdb: $(echo "SET NOCOUNT ON; SELECT recovery_model_desc FROM sys.databases WHERE name = 'labdb'; SELECT COUNT(*) FROM labdb.dbo.ticks" | sa | tr '\n' ' ')"
}

step_notick() {
	on "systemctl stop nexus-ticks 2>/dev/null || true"
}

step_sshkey() {
	[ -f "$LAB/nexus_ed25519" ] || ssh-keygen -q -t ed25519 -N '' -C nexus-mssql-lab -f "$LAB/nexus_ed25519"
	on "id nexus >/dev/null 2>&1 || useradd -m -s /bin/bash nexus; usermod -aG docker nexus
		install -d -m 700 -o nexus -g nexus ~nexus/.ssh
		echo '$(cat "$LAB/nexus_ed25519.pub")' >~nexus/.ssh/authorized_keys; chown nexus:nexus ~nexus/.ssh/authorized_keys; chmod 600 ~nexus/.ssh/authorized_keys"
	on "cat /etc/ssh/ssh_host_ed25519_key.pub" >"$LAB/host_key"
	cat "$LAB/host_key"
}

step_destroy() {
	pve "qm stop $ID 2>/dev/null; qm destroy $ID --purge 2>/dev/null" || true
	rm -f "$LAB/host"
	log "VM removed"
}

case "${1:-}" in
ssh)
	on "${*:2}"
	exit
	;;
sql)
	printf '%s\n' "${*:2}" | sa
	exit
	;;
esac
for s in "$@"; do
	"step_$s"
done
