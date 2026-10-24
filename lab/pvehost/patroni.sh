#!/usr/bin/env bash
# PostgreSQL HA lab on the PVE lab host: a three-node Patroni cluster (etcd, PostgreSQL) deployed with autobase
# from a control VM, for the postgresql plugin's backups, restores and PITR across a failover (state.md "Lab:
# PostgreSQL HA cluster"). The VMs are full clones of the Debian agent VMs (agent-vms.sh: root login with the
# lab key, qemu-guest-agent; ZFS cannot full-clone a snapshot, so the current state, without the agent package);
# Ansible and autobase are installed on the control VM only.
#
#   patroni.sh vms        clone and start the VMs, set host names, new machine ids and ssh host keys
#   patroni.sh ip         the VMs' addresses (guest agent), kept in $LAB/hosts
#   patroni.sh control    Ansible (pip, in a venv) and autobase $AUTOBASE_REF on the control VM
#   patroni.sh deploy     inventory + vars (passwords in $LAB/secrets.env), autobase's deploy_pgcluster playbook;
#                         database labdb, role nexus_backup (pg_read_all_data, REPLICATION, CREATEDB: dump restores into the cluster) for the appliance
#   patroni.sh status     patronictl list on the first node
#   patroni.sh pitrhost   PostgreSQL $PG_VERSION binaries on pg-ctl (the restore host), an SSH key for the
#                         appliance as user postgres there ($LAB/pitr_ed25519)
#   patroni.sh slot       nexusbackup as a Patroni permanent slot (on every node, advanced on the standbys):
#                         backups follow a switchover or failover without losing WAL (plugin 1.3.1)
#   patroni.sh roles      role nexus_backup and database labdb if the deploy did not get that far
#   patroni.sh nowriter   stop the writer (the backup slot keeps WAL while no backups run: stop it when idle)
#   patroni.sh writer     labdb.ticks gets a row per second from pg-ctl (transient unit nexus-ticks), through
#                         a multi-host connection string with target_session_attrs=read-write: it follows the leader
#   patroni.sh source     on the appliance (deploy.sh lab: LAB ~/nexus-lab/pvehost, PORT 28444): tenant pgha,
#                         postgresql plugin source with all three nodes, groups labdb (dump) and cluster (base + WAL)
#   patroni.sh backup     both groups once; the slot on every node afterwards
#   patroni.sh switchover the leader moves to the next node (patronictl switchover)
#   patroni.sh failover   the leader's VM is stopped hard; waits for a new leader, starts the VM again
#   patroni.sh restore    dump of labdb restored into the cluster as labdb_copy (compared), and point-in-time
#                         restores on pg-ctl to every mark (patroni.sh mark) and to the end, row counts compared
#   patroni.sh rtest      restore tests (Phase 44): verify_dir on pg-ctl, schedules on both groups, the scheduler's
#                         verify restores (dump into a throwaway database, cluster PITR started and queried) awaited
#   patroni.sh fault      fault injection (Phase 44): a ~1.3 GB table, a new source, its first (full) cluster backup,
#                         the leader's VM stopped hard while the base backup streams; the job must fail cleanly,
#                         the next run succeed and its restore test pass; the table is dropped again
#   patroni.sh mark NAME  remember now as a restore target (state in $LAB/marks)
#   patroni.sh matrix V…  per PostgreSQL version: new nodes, deploy, slot, writer, source, scenario, cleanup
#                         (e.g. `patroni.sh matrix 14 15 16 18`; results per version in the log)
#   patroni.sh scenario   marks and backups around a switchover and a hard failover, then restore (new marks)
#   patroni.sh ssh N CMD  a command as root on VM N (pg-ctl, pg1, pg2, pg3)
#   patroni.sh destroy    stop and remove the VMs (KEEP_CTL=1: the nodes only, e.g. for another PG_VERSION)
#   patroni.sh cleanpitr  stop the restored servers on pg-ctl and remove /srv/pitr/*
#
# env: PVE_HOST (10.2.34.200), SSH_KEY (~/nexus-lab/pve-lab-key), VM_KEY (~/nexus-lab/lab_ed25519),
#      LAB (~/nexus-lab/patroni: addresses, passwords), STORAGE (vmpool),
#      AUTOBASE_REF (2.11.0: release tag of github.com/vitabaks/autobase), PG_VERSION (17), APPLIANCE_IP (10.2.34.211: allowed to connect for replication)
set -euo pipefail
PVE_HOST=${PVE_HOST:-10.2.34.200}
SSH_KEY=${SSH_KEY:-$HOME/nexus-lab/pve-lab-key}
VM_KEY=${VM_KEY:-$HOME/nexus-lab/lab_ed25519}
LAB=${LAB:-$HOME/nexus-lab/patroni}
STORAGE=${STORAGE:-vmpool}
AUTOBASE_REF=${AUTOBASE_REF:-2.11.0}
PG_VERSION=${PG_VERSION:-17}
# id name memory(MB) source VM; IDs from 200 are ours (AGENTS.md "Labs"). The control VM is a Debian 13 clone:
# autobase pins ansible 14, whose ansible-core needs Python 3.12 or newer on the controller (Debian 12: 3.11)
VMS="
260 pg-ctl 2048 225
261 pg1 4096 224
262 pg2 4096 224
263 pg3 4096 224
"
T0=$(date +%s)
log() { printf '[%4ss] %s\n' $(($(date +%s) - T0)) "$*" >&2; }
die() {
	log "FAIL: $*"
	exit 1
}
pve() { ssh -n -i "$SSH_KEY" -o BatchMode=yes "root@$PVE_HOST" "$@" 2> >(grep -v 'older storage API' >&2); }
mkdir -p "$LAB" && chmod 700 "$LAB"

id_of() { awk -v n="$1" '$2 == n {print $1}' <<<"$VMS"; }
ip_of() { awk -v n="$1" '$1 == n {print $2}' "$LAB/hosts"; }
on() {
	local n=$1
	shift
	ssh -i "$VM_KEY" -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=no \
		-o UserKnownHostsFile=/dev/null -o LogLevel=ERROR "root@$(ip_of "$n")" "$@"
}

guest_ip() { # vmid -> first IPv4 of the guest agent, not loopback
	pve "qm guest cmd $1 network-get-interfaces 2>/dev/null" |
		jq -r '[.[] | select(.name != "lo") | .["ip-addresses"][]? | select(.["ip-address-type"] == "ipv4") | .["ip-address"]][0] // empty'
}

step_ip() {
	local id n a
	: >"$LAB/hosts.tmp"
	while read -r id n _; do
		[ -n "$id" ] || continue
		a=$(guest_ip "$id")
		[ -n "$a" ] || return 1
		echo "$n $a" >>"$LAB/hosts.tmp"
	done <<<"$VMS"
	mv "$LAB/hosts.tmp" "$LAB/hosts"
	cat "$LAB/hosts"
}

step_vms() {
	local id n mem src
	while read -r id n mem src; do
		[ -n "$id" ] || continue
		if pve "qm status $id" >/dev/null 2>&1; then
			log "VM $id exists"
			continue
		fi
		log "cloning $src to $id ($n)"
		pve "qm clone $src $id --full --name $n --storage $STORAGE >/dev/null &&
			qm set $id --memory $mem --tags nexus-pg-lab --description 'Patroni lab (lab/pvehost/patroni.sh)' >/dev/null &&
			qm start $id"
	done <<<"$VMS"
	log "waiting for the guest agents"
	local end=$(($(date +%s) + 600))
	until step_ip >/dev/null 2>&1; do
		[ "$(date +%s)" -lt "$end" ] || die "no addresses after 10 minutes"
		sleep 10
	done
	# clones share the machine id and the ssh host keys of the source: make them their own
	while read -r id n _; do
		[ -n "$id" ] || continue
		on "$n" "set -e; [ \"\$(hostname)\" = $n ] && exit 0
			hostnamectl set-hostname $n; sed -i 's/^127.0.1.1 .*/127.0.1.1 $n/' /etc/hosts
			rm -f /etc/machine-id /var/lib/dbus/machine-id; systemd-machine-id-setup >/dev/null
			apt-get -qq purge 'nexus-agent*' >/dev/null 2>&1 || true
			rm -f /etc/ssh/ssh_host_*; dpkg-reconfigure -f noninteractive openssh-server >/dev/null 2>&1
			systemctl restart ssh" </dev/null
		log "$n: $(ip_of "$n")"
	done <<<"$VMS"
}

step_control() {
	local n
	log "pg-ctl: git, venv, autobase $AUTOBASE_REF"
	on pg-ctl "set -e; export DEBIAN_FRONTEND=noninteractive
		apt-get -qq update && apt-get -qq install -y git python3-venv >/dev/null
		[ -d /opt/autobase ] || git -c advice.detachedHead=false clone -q --depth 1 --branch $AUTOBASE_REF \
			https://github.com/vitabaks/autobase.git /opt/autobase
		[ -x /opt/ansible/bin/ansible-playbook ] || { python3 -m venv /opt/ansible
			/opt/ansible/bin/pip install -q -r /opt/autobase/automation/requirements.txt netaddr; }
		# netaddr: the ipaddr filter (autobase's image gets it through the Azure collection's requirements)
		/opt/ansible/bin/pip install -q netaddr
		# the collections autobase names (the ansible 14 bundle lacks some, e.g. community.digitalocean)
		/opt/ansible/bin/ansible-galaxy collection install -r /opt/autobase/automation/requirements.yml >/dev/null
		/opt/ansible/bin/ansible --version | head -1
		# the control VM's own key for the nodes (the lab key stays off the VMs)
		[ -f /root/.ssh/id_ed25519 ] || ssh-keygen -q -t ed25519 -N '' -f /root/.ssh/id_ed25519" </dev/null
	for n in pg1 pg2 pg3; do
		on pg-ctl 'cat /root/.ssh/id_ed25519.pub' </dev/null | on "$n" 'k=$(cat); grep -qxF "$k" /root/.ssh/authorized_keys || echo "$k" >>/root/.ssh/authorized_keys'
	done
	log "pg-ctl can log in to pg1-3"
}

secret() { # name -> a password kept in $LAB/secrets.env
	touch "$LAB/secrets.env" && chmod 600 "$LAB/secrets.env"
	grep -q "^$1=" "$LAB/secrets.env" || echo "$1=$(head -c 18 /dev/urandom | base64 | tr -dc 'a-zA-Z0-9')" >>"$LAB/secrets.env"
	sed -n "s/^$1=//p" "$LAB/secrets.env"
}

step_deploy() {
	local p1 p2 p3 appliance=${APPLIANCE_IP:-10.2.34.211}
	p1=$(ip_of pg1) p2=$(ip_of pg2) p3=$(ip_of pg3)
	# the vars file holds the passwords: written over stdin, mode 600 on the control VM only
	on pg-ctl "umask 077; cat > /root/lab-vars.yml" <<EOF
postgresql_version: $PG_VERSION
patroni_cluster_name: nexus-lab
patroni_superuser_password: "$(secret PG_SUPERUSER)"
patroni_replication_password: "$(secret PG_REPLICATION)"
pgbouncer_install: false
# no swap file: it took 4 GB of the 16 GB lab disks (the fault test filled them); the commit ratio is raised below
swap_file_create: false
with_haproxy_load_balancing: false
dcs_type: etcd
synchronous_mode: false
# the backup role of the postgresql plugin: dumps (pg_read_all_data) and base backup + WAL (REPLICATION)
postgresql_users:
  - { name: "nexus_backup", password: "$(secret PG_BACKUP)", flags: "LOGIN,REPLICATION", role: "pg_read_all_data" }
postgresql_databases:
  - { db: "labdb", encoding: "UTF8", lc_collate: "C.UTF-8", lc_ctype: "C.UTF-8", owner: "postgres" }
postgresql_pg_hba:
  - { type: "local", database: "all", user: "postgres", address: "", method: "trust" }
  - { type: "local", database: "all", user: "all", address: "", method: "scram-sha-256" }
  - { type: "host", database: "all", user: "all", address: "127.0.0.1/32", method: "scram-sha-256" }
  - { type: "{{ host_type }}", database: "all", user: "all", address: "0.0.0.0/0", method: "scram-sha-256" }
  - { type: "{{ host_type }}", database: "replication", user: "nexus_backup", address: "$appliance/32", method: "scram-sha-256" }
EOF
	on pg-ctl "cat > /root/inventory" <<EOF
[etcd_cluster]
$p1
$p2
$p3

[master]
$p1 hostname=pg1 postgresql_exists=false

[replica]
$p2 hostname=pg2 postgresql_exists=false
$p3 hostname=pg3 postgresql_exists=false

[postgres_cluster:children]
master
replica

[all:vars]
ansible_connection=ssh
ansible_ssh_user=root
EOF
	log "autobase deploy_pgcluster (PostgreSQL $PG_VERSION, etcd, 3 nodes; about 15 minutes)"
	on pg-ctl "set -o pipefail; c=/root/.ansible/collections/ansible_collections/vitabaks
		mkdir -p \$c && ln -sfn /opt/autobase/automation \$c/autobase
		cd /opt/autobase/automation && /opt/ansible/bin/ansible-playbook -i /root/inventory -e @/root/lab-vars.yml \
			playbooks/deploy_pgcluster.yml >/root/deploy.log 2>&1; rc=\$?; tail -25 /root/deploy.log; exit \$rc" </dev/null
	# autobase sets vm.overcommit_memory = 2 (ratio 50): without the swap file a 4 GB node may commit only 2 GB,
	# and etcd, sshd and big statements fail with "Cannot allocate memory" (lab 2026-10-23)
	local n
	for n in pg1 pg2 pg3; do
		on "$n" 'echo "vm.overcommit_ratio = 100" >/etc/sysctl.d/99-nexus-lab.conf; sysctl -q -w vm.overcommit_ratio=100' </dev/null
	done
	step_status
}

step_status() {
	on pg1 'patronictl -c /etc/patroni/patroni.yml list' </dev/null
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
# psql on pg-ctl against the leader (any node: target_session_attrs) as the superuser
sql() { on pg-ctl "psql -qtAX -v ON_ERROR_STOP=1 'host=$(ip_of pg1),$(ip_of pg2),$(ip_of pg3) dbname=${2:-labdb} user=postgres sslmode=require target_session_attrs=read-write' -c \"$1\"" </dev/null; }
leader() { on pg1 'patronictl -c /etc/patroni/patroni.yml list -f json' </dev/null | jq -r '.[] | select(.Role == "Leader") | .Member'; }

step_pitrhost() {
	[ -f "$LAB/pitr_ed25519" ] || ssh-keygen -q -t ed25519 -N '' -C nexus-pitr -f "$LAB/pitr_ed25519"
	on pg-ctl "set -e; export DEBIAN_FRONTEND=noninteractive
		command -v /usr/lib/postgresql/$PG_VERSION/bin/pg_ctl >/dev/null || {
			# Debian 13 ships one major version: the others from the PostgreSQL project's repository
			apt-cache show postgresql-$PG_VERSION >/dev/null 2>&1 || {
				apt-get -qq install -y postgresql-common >/dev/null
				/usr/share/postgresql-common/pgdg/apt.postgresql.org.sh -y >/dev/null; }
			apt-get -qq install -y postgresql-$PG_VERSION postgresql-client-$PG_VERSION >/dev/null
			# no cluster of its own: restores create theirs
			pg_dropcluster --stop $PG_VERSION main 2>/dev/null || true; }
		install -d -o postgres -g postgres -m 700 /var/lib/postgresql/.ssh /srv/pitr
		echo '$(cat "$LAB/pitr_ed25519.pub")' >/var/lib/postgresql/.ssh/authorized_keys
		chown postgres:postgres /var/lib/postgresql/.ssh/authorized_keys; chmod 600 /var/lib/postgresql/.ssh/authorized_keys
		umask 077; echo '*:5432:*:postgres:$(secret PG_SUPERUSER)' >/root/.pgpass" </dev/null
	log "pg-ctl: PostgreSQL $PG_VERSION binaries, restores below /srv/pitr"
}

step_slot() {
	on pg1 "patronictl -c /etc/patroni/patroni.yml edit-config -s 'slots.nexusbackup.type=physical' --force >/dev/null" </dev/null
	sleep 15
	for n in pg1 pg2 pg3; do
		log "$n: $(on "$n" "psql -qtAX -U postgres -h /var/run/postgresql -c \"SELECT slot_name || ' ' || coalesce(restart_lsn::text, '-') FROM pg_replication_slots WHERE slot_name = 'nexusbackup'\"" </dev/null)"
	done
}

step_nowriter() {
	on pg-ctl 'systemctl stop nexus-ticks 2>/dev/null; systemctl reset-failed nexus-ticks 2>/dev/null; true' </dev/null
	log "writer stopped"
}

step_roles() { # what autobase's postgresql_users / postgresql_databases create, idempotent (after pitrhost: psql)
	sql "DO \\\$\\\$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'nexus_backup') THEN
		CREATE ROLE nexus_backup LOGIN REPLICATION PASSWORD '$(secret PG_BACKUP)'; END IF; END \\\$\\\$;
		GRANT pg_read_all_data TO nexus_backup; ALTER ROLE nexus_backup CREATEDB" postgres
	[ "$(sql "SELECT count(*) FROM pg_database WHERE datname = 'labdb'" postgres)" = 1 ] || sql 'CREATE DATABASE labdb' postgres
	log "role nexus_backup and database labdb present; pg_hba for the appliance: $(on pg1 "grep -c 'replication.*nexus_backup' /etc/postgresql/$PG_VERSION/main/pg_hba.conf" </dev/null) line(s)"
}

step_writer() {
	sql "CREATE TABLE IF NOT EXISTS ticks (id bigserial PRIMARY KEY, at timestamptz NOT NULL DEFAULT clock_timestamp(), node inet DEFAULT inet_server_addr())"
	on pg-ctl "systemctl stop nexus-ticks 2>/dev/null; systemctl reset-failed nexus-ticks 2>/dev/null
		systemd-run -q --unit nexus-ticks -p Restart=always -p RestartSec=1 /bin/sh -c 'while :; do psql -qtAX \"host=$(ip_of pg1),$(ip_of pg2),$(ip_of pg3) dbname=labdb user=postgres sslmode=require target_session_attrs=read-write connect_timeout=3\" -c \"INSERT INTO ticks DEFAULT VALUES\" >/dev/null 2>&1; sleep 1; done'" </dev/null
	sleep 5
	log "writer running: $(sql 'SELECT count(*) FROM ticks') rows"
}

step_source() {
	apienv
	local cfg src pol
	api admin POST /tenants '{"name":"pgha"}' >/dev/null
	cfg=$(jq -nc --arg h1 "$(ip_of pg1)" --arg h2 "$(ip_of pg2)" --arg h3 "$(ip_of pg3)" --arg pw "$(secret PG_BACKUP)" \
		--arg ctl "$(ip_of pg-ctl)" --arg key "$(cat "$LAB/pitr_ed25519")" \
		--arg hk "$(on pg-ctl 'cat /etc/ssh/ssh_host_ed25519_key.pub' </dev/null | cut -d' ' -f1-2)" \
		'{host:$h1, hosts:[$h2, $h3], port:5432, user:"nexus_backup", password:$pw, sslmode:"require",
		databases_include:["labdb"], ssh_host:$ctl, ssh_user:"postgres", ssh_key:$key, ssh_host_key:$hk,
		verify_dir:"/srv/pitr/verify", verify_port:5499}')
	src=$(api admin POST /sources "$(jq -nc --argjson c "$cfg" --arg n "patroni-lab-pg$PG_VERSION-$(date +%s)" '{tenant:"pgha", kind:"plugin:postgresql", name:$n, config:$c}')" | jq -r .id)
	expect 201 "create source"
	j=$(job admin plugin_validate "$(jq -nc --argjson s "$src" '{source_id:$s}')" 300)
	log "validate: $(jq -c .result <<<"$j")"
	pol=$(api admin GET /policies | jq -r '.[] | select(.name == "pgha") | .id' | head -1)
	if [ -z "$pol" ]; then
		pol=$(api admin POST /policies '{"name":"pgha","schedule":"daily 03:33","gfs":{"daily":14,"weekly":0,"monthly":0,"yearly":0},"offsite":false}' | jq -r .id)
		expect 201 "create policy"
	fi
	g1=$(api admin POST /groups "$(jq -nc --argjson s "$src" --argjson p "$pol" '{tenant:"pgha", source_id:$s, policy_id:$p, name:("labdb-" + ($s|tostring)), guests:["labdb"]}')" | jq -r .id)
	expect 201 "group labdb"
	g2=$(api admin POST /groups "$(jq -nc --argjson s "$src" --argjson p "$pol" '{tenant:"pgha", source_id:$s, policy_id:$p, name:("cluster-" + ($s|tostring)), guests:[]}')" | jq -r .id)
	expect 201 "group cluster"
	jq -n --argjson s "$src" --argjson d "$g1" --argjson c "$g2" '{source:$s, dump_group:$d, cluster_group:$c}' >"$LAB/state.json"
	log "source $src, groups labdb $g1, cluster $g2"
}

job() { # USER KIND PARAMS [timeout] -> final job JSON (dies unless ok)
	local r j
	r=$(api "$1" POST /jobs "$(jq -nc --arg k "$2" --argjson p "$3" '{kind:$k, tenant:"pgha", params:$p}')")
	expect 202 "$2 job"
	j=$(wait_job "$1" "$(jq -r .id <<<"$r")" "${4:-1800}")
	[ "$(jq -r .state <<<"$j")" = ok ] || die "$2: $(jq -r .log <<<"$j" | tail -n 30)"
	echo "$j"
}

step_backup() {
	apienv
	source_config
	local g j
	for g in dump_group cluster_group; do
		j=$(job admin backup "$(jq -c --arg g "$g" '{group_id: .[$g]}' "$LAB/state.json")")
		log "$g: job $(jq -r .id <<<"$j") in $(jq '.finished - .started' <<<"$j") s: $(jq -c .result <<<"$j")"
		jq -r .log <<<"$j" | grep -iE 'primary|standby|base backup|timeline|slot|warn' | head -8 | sed 's/^/    /' >&2
	done
	for n in pg1 pg2 pg3; do
		log "$n: slots $(on "$n" "psql -qtAX -U postgres -h /var/run/postgresql -c \"SELECT string_agg(slot_name || ':' || active || ':' || coalesce(restart_lsn::text, '-'), ' ') FROM pg_replication_slots\"" </dev/null)"
	done
}

step_mark() {
	local now
	now=$(sql "SELECT to_char(clock_timestamp() AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS') || '+00'")
	now=${now/ /T} # one field in $LAB/marks
	sleep 2 # the target second is complete
	echo "$MARK $now $(sql "SELECT count(*) FROM ticks WHERE at <= '$now'") $(sql 'SELECT timeline_id FROM pg_control_checkpoint()')" >>"$LAB/marks"
	log "mark $MARK: $(tail -1 "$LAB/marks" | cut -d' ' -f2-)"
}

step_switchover() {
	local old new
	old=$(leader)
	on pg1 "patronictl -c /etc/patroni/patroni.yml switchover --leader $old --force" </dev/null >/dev/null
	for _ in $(seq 60); do
		new=$(leader)
		[ -n "$new" ] && [ "$new" != "$old" ] && break
		sleep 2
	done
	log "switchover: $old -> $new"
}

step_failover() {
	local old new id
	old=$(leader)
	id=$(id_of "$old")
	log "stopping $old (VM $id) hard"
	pve "qm stop $id --skiplock" >/dev/null
	for _ in $(seq 90); do
		new=$(on "$( [ "$old" = pg1 ] && echo pg2 || echo pg1)" 'patronictl -c /etc/patroni/patroni.yml list -f json' </dev/null | jq -r '.[] | select(.Role == "Leader") | .Member')
		[ -n "$new" ] && [ "$new" != "$old" ] && break
		sleep 2
	done
	log "failover: $old -> $new"
	pve "qm start $id"
	for _ in $(seq 60); do on "$old" true </dev/null 2>/dev/null && break; sleep 5; done
	sleep 20
	step_status
}

step_restore() {
	apienv
	source_config
	local snaps snap s r j name at rows tl want have dir port=5440
	# the dump into the cluster as labdb_copy: ticks up to the dump compared
	# this lab's source only (one per PostgreSQL version)
	snaps=$(api admin GET '/snapshots?tenant=pgha' | jq -c --arg p "plugin-postgresql-$(jq -r .source "$LAB/state.json")" '[.[] | select(.source == $p or .source == ($p + "-labdb"))]')
	snap=$(jq -c '[.[] | select(.source | endswith("-labdb"))] | sort_by(.time) | .[-1]' <<<"$snaps")
	sql 'DROP DATABASE IF EXISTS labdb_copy WITH (FORCE)' postgres
	j=$(job admin plugin_restore "$(jq -nc --argjson s "$snap" '{source:$s.source, time:$s.time, restore:"to_target", params:{database:"labdb_copy", server:"source"}}')")
	have=$(sql "SELECT count(*) || ' ' || max(id) FROM ticks" labdb_copy)
	want=$(sql "SELECT count(*) || ' ' || max(id) FROM ticks WHERE id <= ${have#* }")
	[ "$have" = "$want" ] || die "labdb_copy: $have rows/max id, the cluster has $want up to that id"
	log "dump restore into the cluster: labdb_copy has $have (rows, max id), equal to the source"
	# point in time: every mark from the newest cluster snapshot that covers it, then the end
	snap=$(jq -c '[.[] | select(.source | endswith("-labdb") | not)] | sort_by(.time)' <<<"$snaps")
	# every mark is tried; a failed or wrong one fails the step at the end (the nightly run only logged them)
	local bad=0 n=0
	while read -r name at rows tl; do
		[ -n "$name" ] || continue
		n=$((n + 1))
		dir=/srv/pitr/$name-$(date +%s)
		# the first cluster snapshot after the mark: its WAL reaches the mark if any snapshot's does
		s=$(jq -c --argjson m "$(date -d "$at" +%s)" '[.[] | select(.time >= $m)][0]' <<<"$snap")
		r=$(api admin POST /jobs "$(jq -nc --argjson s "$s" --arg d "$dir" --arg t "$at" --argjson p $port \
			'{kind:"plugin_restore", tenant:"pgha", params:{source:$s.source, time:$s.time, restore:"pitr", params:{directory:$d, target_time:$t, port:$p, start:true}}}')")
		expect 202 "PITR job for $name"
		j=$(wait_job admin "$(jq -r .id <<<"$r")" 3600)
		if [ "$(jq -r .state <<<"$j")" != ok ]; then
			log "PITR to $name ($at, timeline $tl) from snapshot $(jq -r .time <<<"$s"): FAILED: $(jq -r .log <<<"$j" | grep -iE 'error|fatal|recover|target' | tail -3 | tr '\n' ' ')"
			port=$((port + 1))
			bad=$((bad + 1))
			continue
		fi
		have=$(on pg-ctl "sudo -u postgres psql -p $port -h /var/run/postgresql -qtAX -d labdb -c \"SELECT count(*) FROM ticks WHERE at <= '$at'\"" </dev/null)
		log "PITR to $name ($at, timeline $tl) from snapshot $(jq -r .time <<<"$s"): $have rows up to then, the cluster had $rows ($(jq '.finished - .started' <<<"$j") s)"
		[ "$have" = "$rows" ] || { log "MISMATCH at $name"; bad=$((bad + 1)); }
		on pg-ctl "sudo -u postgres /usr/lib/postgresql/$PG_VERSION/bin/pg_ctl -D $dir stop -m fast >/dev/null" </dev/null
		port=$((port + 1))
	done <"$LAB/marks"
	[ "$bad" = 0 ] || die "$bad of $n point-in-time restores failed or did not match"
}

step_scenario() {
	rm -f "$LAB/marks"
	step_backup
	sleep 20
	MARK=a1-timeline-start step_mark
	sleep 20
	step_backup
	MARK=a2-before-switchover step_mark
	sleep 10
	step_switchover
	sleep 10
	MARK=a3-after-switchover step_mark
	step_backup
	sleep 20
	MARK=a4-new-timeline step_mark
	sleep 10
	step_backup
	step_failover
	MARK=a5-after-failover step_mark
	step_backup
	sleep 20
	MARK=a6-last-timeline step_mark
	sleep 10
	step_backup
	step_restore
}

step_cleanpitr() {
	on pg-ctl 'for d in /srv/pitr/*/; do [ -f "$d/postmaster.pid" ] && kill -QUIT "$(head -1 "$d/postmaster.pid")" 2>/dev/null; done; sleep 2; rm -rf /srv/pitr/*; df -h / | tail -1' </dev/null
}

step_matrix() {
	local v
	for v in $MATRIX; do
		log "=== PostgreSQL $v"
		KEEP_CTL=1 step_destroy
		step_vms
		step_control
		# a transient download error (DNS, mirror) before initdb: the playbook can run again
		PG_VERSION=$v step_deploy || { sleep 30; PG_VERSION=$v step_deploy; }
		PG_VERSION=$v step_pitrhost
		step_roles
		step_slot
		step_writer
		PG_VERSION=$v step_source
		PG_VERSION=$v step_scenario
		step_nowriter
		step_cleanpitr
	done
}

# the source's config with the current addresses of the VMs (DHCP: pg-ctl came back on another address after
# the VMs were stopped for a day) plus $1 (jq); a changed endpoint needs the password again, so it and the SSH key
# are sent as in step_source
source_config() {
	local src cfg name
	src=$(jq -r .source "$LAB/state.json")
	cfg=$(api admin GET /sources | jq -c --argjson s "$src" --arg h1 "$(ip_of pg1)" --arg h2 "$(ip_of pg2)" \
		--arg h3 "$(ip_of pg3)" --arg ctl "$(ip_of pg-ctl)" --arg pw "$(secret PG_BACKUP)" --arg key "$(cat "$LAB/pitr_ed25519")" \
		'.[] | select(.id == $s) | .config | with_entries(select(.key | endswith("_set") | not))
		| .host = $h1 | .hosts = [$h2, $h3] | .ssh_host = $ctl | .password = $pw | .ssh_key = $key | '"${1:-.}")
	name=$(api admin GET /sources | jq -r --argjson s "$src" '.[] | select(.id == $s) | .name')
	api admin PUT "/sources/$src" "$(jq -nc --arg n "$name" --argjson c "$cfg" '{name:$n, config:$c}')" >/dev/null
	expect 200 "source $src: current addresses${1:+, $1}"
}

step_rtest() {
	apienv
	local src g id r
	src=$(jq -r .source "$LAB/state.json")
	on pg-ctl 'install -d -o postgres -g postgres -m 700 /srv/pitr/verify' </dev/null
	source_config '.verify_dir = "/srv/pitr/verify" | .verify_port = 5499'
	for g in dump_group cluster_group; do
		id=$(jq -r ".$g" "$LAB/state.json")
		api admin PUT "/restore-tests/schedules/$id" '{"every_days": 1}' >/dev/null
		expect 200 "restore test schedule of group $id"
	done
	log "schedules set; waiting for the scheduler's restore tests"
	local end=$(($(date +%s) + 1800)) n
	until n=$(api admin GET '/restore-tests?tenant=pgha' | jq --argjson s "$src" \
		'[.[] | select(.source | startswith("plugin-postgresql-\($s)"))] | length') && [ "$n" -ge 2 ]; do
		[ "$(date +%s)" -lt "$end" ] || die "no restore test results after 30 minutes"
		sleep 20
	done
	api admin GET '/restore-tests?tenant=pgha' | jq -r --argjson s "$src" \
		'.[] | select(.source | startswith("plugin-postgresql-\($s)")) | "  \(.source) \(.time): \(.state) (\(.finished - .started) s): \(.summary // .error)"' >&2
}

step_fault() {
	local old id r j st
	log "writing the table big (about 1.3 GB)"
	# in batches: autobase's strict memory overcommit refuses one 2-million-row generate_series
	sql "DROP TABLE IF EXISTS big; CREATE TABLE big (g int, pad text)"
	local b
	for b in $(seq 0 9); do
		sql "INSERT INTO big SELECT g, repeat(md5(g::text), 20) FROM generate_series($((b * 200000 + 1)), $(((b + 1) * 200000))) g"
	done
	log "big: $(sql "SELECT pg_size_pretty(pg_total_relation_size('big'))")"
	step_source
	apienv
	r=$(api admin POST /jobs "$(jq -nc --argjson g "$(jq -r .cluster_group "$LAB/state.json")" '{kind:"backup", tenant:"pgha", params:{group_id:$g}}')")
	expect 202 "cluster backup"
	id=$(jq -r .id <<<"$r")
	# stop the leader once the base backup streams (the job has read something)
	# (or after 15 s of running, when the plugin reports no progress during the base backup)
	local n=0
	for _ in $(seq 120); do
		r=$(api admin GET "/jobs/$id")
		st=$(jq -r '.progress.done // 0' <<<"$r")
		[ "${st%.*}" -gt 300000000 ] 2>/dev/null && break
		[ "$(jq -r .state <<<"$r")" = running ] && n=$((n + 1))
		[ "$n" -ge 15 ] && break
		sleep 1
	done
	old=$(leader)
	log "job $id at $st bytes: stopping the leader $old (VM $(id_of "$old")) hard"
	pve "qm stop $(id_of "$old") --skiplock" >/dev/null
	j=$(wait_job admin "$id" 1800)
	log "job $id: $(jq -r .state <<<"$j"): $(jq -r .log <<<"$j" | grep -iE 'error|fail' | tail -2 | tr '\n' ' ' | cut -c1-300)"
	log "snapshots of the source after the failed run: $(api admin GET '/snapshots?tenant=pgha' | jq --arg p "plugin-postgresql-$(jq -r .source "$LAB/state.json")" '[.[] | select(.source == $p)] | length')"
	pve "qm start $(id_of "$old")" >/dev/null
	for _ in $(seq 60); do on "$old" true </dev/null 2>/dev/null && break; sleep 5; done
	sleep 30
	step_status
	j=$(job admin backup "$(jq -c '{group_id: .cluster_group}' "$LAB/state.json")")
	log "next run: job $(jq -r .id <<<"$j") ok in $(jq '.finished - .started' <<<"$j") s: $(jq -r .log <<<"$j" | grep -E 'summary|full backup|following' | head -2 | tr '\n' ' ' | cut -c1-250)"
	local s
	s=$(api admin GET '/snapshots?tenant=pgha' | jq -c --arg p "plugin-postgresql-$(jq -r .source "$LAB/state.json")" '[.[] | select(.source == $p)] | sort_by(.time) | .[-1]')
	j=$(job admin plugin_restore "$(jq -nc --argjson s "$s" '{source:$s.source, time:$s.time, restore:"verify", params:{}}')" 3600)
	log "restore test of that snapshot: $(jq -r .state <<<"$j"): $(jq -r '.result.summary // ""' <<<"$j" | cut -c1-160)"
	sql "DROP TABLE big"
}

step_ssh() {
	on "$SSH_NODE" "$SSH_CMD"
}

step_destroy() {
	local id
	for id in $(awk -v k="${KEEP_CTL:-0}" 'NF && !(k == 1 && $2 == "pg-ctl") {print $1}' <<<"$VMS"); do
		pve "qm stop $id 2>/dev/null; qm destroy $id --purge 2>/dev/null" || true
	done
	rm -f "$LAB/hosts"
	log "VMs removed"
}

if [ "${1:-}" = ssh ]; then
	SSH_NODE=$2
	SSH_CMD="${*:3}"
	step_ssh
	exit
fi
if [ "${1:-}" = matrix ]; then
	MATRIX="${*:2}"
	step_matrix
	exit
fi
if [ "${1:-}" = mark ]; then
	MARK=$2
	step_mark
	exit
fi
for s in "$@"; do
	"step_$s"
done
