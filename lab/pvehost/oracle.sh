#!/usr/bin/env bash
# Oracle lab on the PVE lab host (#42): Oracle AI Database Free on an AlmaLinux 9 clone, archive log mode, for the
# oracle plugin's RMAN backups and point-in-time restores. The licence of Oracle Database Free was accepted by the
# maintainer (2026-11-02); the RPMs come from Oracle (download.oracle.com, yum.oracle.com), checked by SHA-256.
#
#   oracle.sh vms       clone ag-alma-9 (228) to $ID, a second disk for /opt/oracle, start, new host keys
#   oracle.sh static    fixed address $ADDR (NetworkManager), then the address is kept in $LAB/host
#   oracle.sh install   preinstall + database RPM, `configure` (CDB FREE, PDB FREEPDB1; password in $LAB/secrets.env)
#   oracle.sh archlog   archive log mode, block change tracking, a table lab.ticks in FREEPDB1
#   oracle.sh sshkey    $LAB/ora_ed25519 for the appliance as user oracle; prints the host key line
#   oracle.sh ticks     one row per second into lab.ticks (transient unit nexus-ticks); notick stops it
#   oracle.sh sql SQL   runs SQL as sysdba in FREEPDB1 (output on stdout)
#   oracle.sh source    on the appliance (APP_LAB ~/nexus-lab/pvehost, APP_PORT 28444): tenant ora, plugin source
#                       (plugin `oracle` installed: PLUGIN=oracle lab/appliance/plugins.sh install), group, validate
#   oracle.sh backup    one backup of the group (policy run)
#   oracle.sh logruns   log schedule `every 5m` on the group, waits for $N (2) log runs, removes the schedule
#   oracle.sh mark      remember now and the row count of lab.ticks as a restore target ($LAB/marks)
#   oracle.sh pitr      point-in-time restore of the database to the last mark from the newest snapshot; the
#                       ticks up to the mark compared with the count at the mark
#   oracle.sh breaklog  switches the log and deletes the new archived log from disk (outside RMAN): the next
#                       run must be a level 0 with chain_break in its meta (log_chain alert)
#   oracle.sh ssh CMD   a command as root on the VM
#   oracle.sh destroy   stop and remove the VM
#
# env: PVE_HOST (10.2.34.200), SSH_KEY (~/nexus-lab/pve-lab-key), VM_KEY (~/nexus-lab/lab_ed25519),
#      LAB (~/nexus-lab/oracle), STORAGE (vmpool), ID (267), ADDR (10.2.34.245), GW (10.2.34.254)
set -euo pipefail
PVE_HOST=${PVE_HOST:-10.2.34.200}
SSH_KEY=${SSH_KEY:-$HOME/nexus-lab/pve-lab-key}
VM_KEY=${VM_KEY:-$HOME/nexus-lab/lab_ed25519}
LAB=${LAB:-$HOME/nexus-lab/oracle}
STORAGE=${STORAGE:-vmpool}
ID=${ID:-267}
ADDR=${ADDR:-10.2.34.245}
SRC=228
RPM=oracle-ai-database-free-26ai-23.26.3-1.el9.x86_64.rpm
RPM_SHA256=895fc9df794685b515c4ac83f104dbdfb657eb0e92c41e45c58302fb8fd53e44
PRE=oracle-ai-database-preinstall-26ai-1.0-1.el9.x86_64.rpm
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
	ssh -i "$VM_KEY" -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=no \
		-o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ServerAliveInterval=5 -o ServerAliveCountMax=3 "root@$a" "$@"
}
on() { sshv "$(host)" "$@"; }
guest_ip() {
	pve "qm guest cmd $ID network-get-interfaces 2>/dev/null" |
		jq -r '[.[] | select(.name != "lo") | .["ip-addresses"][]? | select(.["ip-address-type"] == "ipv4") | .["ip-address"]][0] // empty'
}
# the environment of the database owner (the RPM's paths)
ORAENV='export ORACLE_SID=FREE ORAENV_ASK=NO; export ORACLE_HOME=$(ls -d /opt/oracle/product/*/dbhomeFree | head -1); export PATH=$ORACLE_HOME/bin:$PATH'

step_vms() {
	if pve "qm status $ID" >/dev/null 2>&1; then
		log "VM $ID exists"
	else
		log "cloning $SRC to $ID"
		pve "qm clone $SRC $ID --full --name ora-free --storage $STORAGE >/dev/null &&
			qm set $ID --memory 8192 --cores 4 --scsi1 $STORAGE:40,discard=on,iothread=1 --tags nexus-ora-lab \
				--description 'Oracle lab (lab/pvehost/oracle.sh)' >/dev/null && qm start $ID"
	fi
	local a="" end=$(($(date +%s) + 600))
	until a=$(guest_ip) && [ -n "$a" ]; do
		[ "$(date +%s)" -lt "$end" ] || die "no address after 10 minutes"
		sleep 10
	done
	echo "$a" >"$LAB/host"
	on "set -e; [ \"\$(hostname)\" = ora-free ] && exit 0
		hostnamectl set-hostname ora-free
		rm -f /etc/machine-id; systemd-machine-id-setup >/dev/null
		dnf -q -y remove 'nexus-agent*' >/dev/null 2>&1 || true
		rm -f /etc/ssh/ssh_host_*; ssh-keygen -A >/dev/null; systemctl restart sshd
		d=\$(lsblk -dpno NAME,SERIAL,TYPE | awk '\$NF==\"disk\"{print \$1}' | while read -r x; do lsblk -no MOUNTPOINT \$x | grep -q . || echo \$x; done | head -1)
		[ -n \"\$d\" ] && mkfs.xfs -q \$d && mkdir -p /opt/oracle &&
			echo \"UUID=\$(blkid -s UUID -o value \$d) /opt/oracle xfs defaults 0 0\" >>/etc/fstab && systemctl daemon-reload && mount /opt/oracle"
	log "ora-free: $(host), $(on 'df -h /opt/oracle | tail -1')"
}

step_static() {
	local cur
	cur=$(guest_ip)
	[ -n "$cur" ] || die "no address from the guest agent"
	if [ "$cur" != "$ADDR" ]; then
		sshv "$cur" "c=\$(nmcli -g NAME,DEVICE c show --active | awk -F: '\$2 != \"lo\" {print \$1; exit}')
			nmcli c mod \"\$c\" ipv4.method manual ipv4.addresses $ADDR/24 ipv4.gateway ${GW:-10.2.34.254} \
				ipv4.dns \"\$(awk '/^nameserver/ {print \$2; exit}' /etc/resolv.conf)\" &&
			nohup sh -c \"sleep 1; nmcli c up '\$c'\" >/dev/null 2>&1 &" || true # the session dies with the old address
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
	[ -s "$LAB/secrets.env" ] || echo "ORA_PASSWORD=Nx$(openssl rand -hex 10)" >"$LAB/secrets.env"
	# shellcheck disable=SC1091
	. "$LAB/secrets.env"
	on "set -e; cd /opt/oracle
		[ -f $PRE ] || curl -sSfLO https://yum.oracle.com/repo/OracleLinux/OL9/appstream/x86_64/getPackage/$PRE
		[ -f $RPM ] || curl -sSfLO https://download.oracle.com/otn-pub/otn_software/db-free/$RPM
		echo '$RPM_SHA256  $RPM' | sha256sum -c --quiet
		rpm -q oracle-ai-database-preinstall-26ai >/dev/null || dnf -q -y install ./$PRE >/dev/null
		# the RPM refuses an ORACLE_BASE (/opt/oracle, the second disk) not owned by oracle:oinstall
		chown oracle:oinstall /opt/oracle
		rpm -q oracle-ai-database-free-26ai >/dev/null || dnf -q -y install ./$RPM >/dev/null"
	log "RPMs installed"
	if ! on "ls /opt/oracle/oradata/FREE/system01.dbf" >/dev/null 2>&1; then
		log "configure (creates the database, about 15 minutes)"
		on "s=\$(ls /etc/init.d/oracle-free-* | head -1); printf '%s\n%s\n' '$ORA_PASSWORD' '$ORA_PASSWORD' | \$s configure >/opt/oracle/configure.log 2>&1 ||
			{ tail -20 /opt/oracle/configure.log; exit 1; }; systemctl enable \$(basename \$s) >/dev/null 2>&1 || chkconfig \$(basename \$s) on"
	fi
	log "database: $(on "su - oracle -c '$ORAENV; echo \"select status from v\\\$instance;\" | sqlplus -S / as sysdba'" | tr -s '\n ' ' ')"
}

sysdba() { # SQL on stdin, as sysdba in the CDB
	on "su - oracle -c '$ORAENV; sqlplus -S -L / as sysdba'"
}

step_archlog() {
	if ! sysdba <<<"select log_mode from v\$database;" | grep -q NOARCHIVELOG; then
		log "archive log mode already on"
	else
		sysdba <<'EOF'
whenever sqlerror exit failure
shutdown immediate
startup mount
alter database archivelog;
alter database open;
alter pluggable database all open;
alter pluggable database all save state;
EOF
		log "archive log mode on"
	fi
	sysdba <<'EOF'
whenever sqlerror continue
set feedback off
alter database enable block change tracking using file '/opt/oracle/oradata/FREE/bct.dbf';
alter session set container = FREEPDB1;
create user lab identified by "LabTicks1" quota unlimited on users;
grant create session, create table to lab;
create table lab.ticks (id number generated always as identity primary key, t timestamp default systimestamp);
EOF
	log "$(sysdba <<<"set heading off feedback off
select log_mode from v\$database;
select status from v\$block_change_tracking;" | tr -s '\n ' ' ')"
}

step_sshkey() {
	[ -f "$LAB/ora_ed25519" ] || ssh-keygen -q -t ed25519 -N '' -C nexus-oracle-lab -f "$LAB/ora_ed25519"
	on "install -d -m 700 -o oracle -g oinstall ~oracle ~oracle/.ssh &&
		grep -qF '$(cut -d' ' -f2 "$LAB/ora_ed25519.pub")' ~oracle/.ssh/authorized_keys 2>/dev/null ||
		{ echo '$(cat "$LAB/ora_ed25519.pub")' >>~oracle/.ssh/authorized_keys; chown oracle:oinstall ~oracle/.ssh/authorized_keys; chmod 600 ~oracle/.ssh/authorized_keys; }"
	on "cat /etc/ssh/ssh_host_ed25519_key.pub" >"$LAB/host_key"
	cat "$LAB/host_key"
}

step_ticks() {
	on "systemctl is-active -q nexus-ticks || systemd-run -q --unit nexus-ticks -p User=oracle /bin/bash -c '$ORAENV
		while :; do printf \"insert into lab.ticks (t) values (systimestamp);\\ncommit;\\n\"; sleep 1; done | sqlplus -S lab/LabTicks1@localhost:1521/FREEPDB1 >/dev/null'"
	log "ticks running"
}

step_notick() {
	on "systemctl stop nexus-ticks 2>/dev/null || true"
}

APP_LAB=${APP_LAB:-$HOME/nexus-lab/pvehost}
apienv() {
	export PORT=${APP_PORT:-28444}
	ROOT=$APP_LAB/appliance/root S=$APP_LAB/appliance/root/run/api
	mkdir -p "$S"
	# shellcheck disable=SC1091
	. "$ROOT/secrets.env"
	# shellcheck source=lab/e2e/api-lib.sh
	. "$(dirname "$0")/../e2e/api-lib.sh"
	login admin "$ADMIN_PW" "$ADMIN_TOTP"
}
job() { # KIND PARAMS [timeout] -> final job JSON (dies unless ok)
	local r j
	r=$(api admin POST /jobs "$(jq -nc --arg k "$1" --argjson p "$2" '{kind:$k, tenant:"ora", params:$p}')")
	expect 202 "$1 job"
	j=$(wait_job admin "$(jq -r .id <<<"$r")" "${3:-3600}")
	[ "$(jq -r .state <<<"$j")" = ok ] || die "$1: $(jq -r .log <<<"$j" | tail -n 30)"
	echo "$j"
}
ticks() { printf 'set heading off feedback off\nalter session set container = FREEPDB1;\n%s\n' "$1" | sysdba | tr -d ' \n'; }

step_source() {
	apienv
	local cfg src pol g
	api admin POST /tenants '{"name":"ora"}' >/dev/null
	cfg=$(jq -nc --arg h "$(host)" --arg key "$(cat "$LAB/ora_ed25519")" --arg hk "$(cut -d' ' -f1-2 "$LAB/host_key")" \
		'{host:$h, port:22, user:"oracle", ssh_key:$key, ssh_host_key:$hk, sid:"FREE", full_every_days:7}')
	src=$(api admin POST /sources "$(jq -nc --argjson c "$cfg" --arg n "ora-free-$(date +%s)" '{tenant:"ora", kind:"plugin:oracle", name:$n, config:$c}')" | jq -r .id)
	expect 201 "create source"
	log "validate: $(job plugin_validate "$(jq -nc --argjson s "$src" '{source_id:$s}')" 300 | jq -c .result)"
	pol=$(api admin GET /policies | jq -r '.[] | select(.name == "ora") | .id' | head -1)
	if [ -z "$pol" ]; then
		pol=$(api admin POST /policies '{"name":"ora","schedule":"daily 03:47","gfs":{"daily":14,"weekly":0,"monthly":0,"yearly":0},"offsite":false}' | jq -r .id)
		expect 201 "create policy"
	fi
	g=$(api admin POST /groups "$(jq -nc --argjson s "$src" --argjson p "$pol" '{tenant:"ora", source_id:$s, policy_id:$p, name:("db-" + ($s|tostring)), guests:[]}')" | jq -r .id)
	expect 201 "group"
	jq -n --argjson s "$src" --argjson g "$g" '{source:$s, group:$g}' >"$LAB/state.json"
	log "source $src, group $g"
}

step_backup() {
	apienv
	local j
	j=$(job backup "$(jq -c --arg m "${MODE:-}" '{group_id: .group} + (if $m == "" then {} else {mode: $m} end)' "$LAB/state.json")")
	log "backup${MODE:+ ($MODE)}: job $(jq -r .id <<<"$j") in $(jq '.finished - .started' <<<"$j") s: $(jq -c .result <<<"$j")"
	jq -r .log <<<"$j" | grep -iE 'level|archived|chain|warn|pieces' | head -8 | sed 's/^/    /' >&2
}

step_logruns() {
	apienv
	local g n0 n
	g=$(jq -r .group "$LAB/state.json")
	n0=$(api admin GET "/jobs?kind=backup&limit=200" | jq --argjson g "$g" '[.[] | select(.params.group_id == $g and .params.mode == "log")] | length')
	api admin PUT "/groups/$g/log-schedule" '{"schedule":"every 5m"}' >/dev/null
	expect 200 "log schedule"
	log "log schedule every 5m on group $g; waiting for ${N:-2} log runs"
	local end=$(($(date +%s) + 1800))
	while :; do
		n=$(api admin GET "/jobs?kind=backup&limit=200" | jq --argjson g "$g" '[.[] | select(.params.group_id == $g and .params.mode == "log" and (.state == "ok" or .state == "failed"))] | length')
		[ $((n - n0)) -ge "${N:-2}" ] && break
		[ "$(date +%s)" -lt "$end" ] || break
		sleep 30
	done
	api admin PUT "/groups/$g/log-schedule" '{"schedule":null}' >/dev/null
	api admin GET "/jobs?kind=backup&limit=200" | jq -r --argjson g "$g" '[.[] | select(.params.group_id == $g and .params.mode == "log")] | sort_by(.id) | .[-('"${N:-2}"'):][] |
		"    job \(.id) \(.state) \(.finished - .started) s: \(.result.snapshots[0].meta.recoverable // .result.failed)"' >&2
	[ $((n - n0)) -ge "${N:-2}" ] || die "only $((n - n0)) log runs in 30 minutes"
}

step_mark() {
	local at n
	at=$(date -u '+%Y-%m-%d %H:%M:%S+00')
	sleep 1
	n=$(ticks "select count(*) from lab.ticks where t <= to_timestamp('${at%+00}', 'YYYY-MM-DD HH24:MI:SS');")
	echo "$at|$n" >>"$LAB/marks"
	log "mark $at: $n ticks"
}

step_pitr() {
	apienv
	local m at n s j have
	m=$(tail -1 "$LAB/marks")
	at=${m%|*} n=${m#*|}
	s=$(api admin GET '/snapshots?tenant=ora' | jq -c --arg p "plugin-oracle-$(jq -r .source "$LAB/state.json")" '[.[] | select(.source == $p)] | sort_by(.time) | .[-1]')
	j=$(job plugin_restore "$(jq -nc --argjson s "$s" --arg t "$at" '{source:$s.source, time:$s.time, restore:"pitr", params:{target_time:$t, confirm:"FREE"}}')")
	log "pitr to $at from snapshot $(jq -r .time <<<"$s") in $(jq '.finished - .started' <<<"$j") s: $(jq -c .result <<<"$j")"
	have=$(ticks "select count(*) from lab.ticks where t <= to_timestamp('${at%+00}', 'YYYY-MM-DD HH24:MI:SS');")
	total=$(ticks "select count(*) from lab.ticks;")
	log "after the restore: $have ticks up to the mark (wanted $n), $total in all"
	[ "$have" = "$n" ] && [ "$total" -le $((n + 2)) ] || die "the restored database does not end at the mark"
}

step_breaklog() {
	local f
	f=$(printf 'set heading off feedback off\nalter system archive log current;\nselect name from v$archived_log where name is not null and deleted = %s order by sequence# desc fetch first 1 rows only;\n' "'NO'" | sysdba | grep '^/' | head -1)
	[ -n "$f" ] || die "no archived log found"
	on "rm -f '$f'"
	log "deleted $f"
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
	printf 'set linesize 200 pagesize 100\nalter session set container = FREEPDB1;\n%s\n' "${*:2}" | sysdba
	exit
	;;
esac
for s in "$@"; do
	"step_$s"
done
