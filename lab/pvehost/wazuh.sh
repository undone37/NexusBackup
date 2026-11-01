#!/usr/bin/env bash
# Wazuh integration lab (#139, integrations/wazuh): a Wazuh manager on a lab VM (Debian 12, package
# wazuh-manager, vulnerability detection off: its feed fills a small disk) receives the appliance's syslog
# sink (transport tcp, format wazuh) on TCP 514. Through the tunnel of lab/pvehost/deploy.sh.
#
#   wazuh.sh manager     decoder + rules from integrations/wazuh, the syslog listener for the appliance only,
#                        restart; every line of samples.log through wazuh-logtest must end in its rule
#   wazuh.sh forward     the appliance's syslog sink -> the manager (plain TCP, Wazuh format; the previous
#                        setting is saved first); "Send test message" until it answers ok
#   wazuh.sh live        real records arrive: the test message (110101), a failed login (110113), and
#                        audit entries (110110 or a child), read from the manager's alerts.json
#   wazuh.sh restore     the saved forwarding setting back (a weakening goes through approval)
#   wazuh.sh all         manager forward live restore
#
# env: LAB (~/nexus-lab/pvehost), PORT (28444), WAZUH (10.2.34.5: the manager VM, root by VM_KEY),
#      VM_KEY (~/nexus-lab/lab_ed25519), APPLIANCE (10.2.34.211: VM 201 as the manager sees it)
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
LAB=${LAB:-$HOME/nexus-lab/pvehost}
ROOT=${ROOT:-$LAB/appliance/root}
PORT=${PORT:-28444}
WAZUH=${WAZUH:-10.2.34.5}
VM_KEY=${VM_KEY:-$HOME/nexus-lab/lab_ed25519}
APPLIANCE=${APPLIANCE:-10.2.34.211}
S=$LAB/scratch/wazuh
mkdir -p "$S"
export T0
T0=$(date +%s)
eval "$(ROOT=$ROOT PORT=$PORT "$repo/lab/e2e/m5.sh" env)"
# shellcheck source=lab/e2e/api-lib.sh
# shellcheck disable=SC1090
. "$repo/lab/e2e/api-lib.sh"
ssh_opts=(-i "$VM_KEY" -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR)
wz() { ssh -n "${ssh_opts[@]}" "root@$WAZUH" "$@"; }

step_manager() {
	scp -q "${ssh_opts[@]}" "$repo"/integrations/wazuh/nexusbackup_decoders.xml \
		"$repo"/integrations/wazuh/nexusbackup_rules.xml "$repo"/integrations/wazuh/samples.log "root@$WAZUH:/root/"
	wz "set -e
		command -v jq >/dev/null || DEBIAN_FRONTEND=noninteractive apt-get -qq install -y jq >/dev/null # step live
		install -o wazuh -g wazuh -m 0660 /root/nexusbackup_decoders.xml /var/ossec/etc/decoders/
		install -o wazuh -g wazuh -m 0660 /root/nexusbackup_rules.xml /var/ossec/etc/rules/
		c=/var/ossec/etc/ossec.conf
		if ! grep -q 'nexusbackup-syslog' \$c; then
			python3 - \$c $APPLIANCE <<-'PY'
			import sys
			p, ip = sys.argv[1], sys.argv[2]
			s = open(p).read()
			block = ('  <!-- nexusbackup-syslog (lab/pvehost/wazuh.sh) -->\n  <remote>\n    <connection>syslog</connection>\n'
			         '    <port>514</port>\n    <protocol>tcp</protocol>\n    <allowed-ips>' + ip + '/32</allowed-ips>\n  </remote>\n')
			i = s.index('<ossec_config>') + len('<ossec_config>\n')
			open(p, 'w').write(s[:i] + block + s[i:])
			PY
		fi
		systemctl restart wazuh-manager
		systemctl is-active -q wazuh-manager"
	local got want n=0 bad=0
	# the rule id is the first `id:` after "Phase 3" (a record's own `id` field shows up in Phase 2)
	got=$(wz "grep -v '^#' /root/samples.log | timeout 60 /var/ossec/bin/wazuh-logtest 2>&1" |
		awk '/^\*\*Phase 3/ {p = 1} p && /^\tid:/ {gsub(/[^0-9]/, ""); print; p = 0}')
	want=$(sed -n 's/^# rule //p' "$repo/integrations/wazuh/samples.log")
	while read -r w && read -r g <&3; do
		n=$((n + 1))
		[ "$w" = "$g" ] || { log "sample $n: rule $g, expected $w"; bad=$((bad + 1)); }
	done <<<"$want" 3<<<"$got"
	[ "$n" -ge 10 ] && [ "$bad" = 0 ] || die "wazuh-logtest: $bad of $n samples in the wrong rule"
	log "manager: $n samples end in their rules (wazuh-logtest); listener on tcp/514 for $APPLIANCE"
}

step_forward() {
	login admin "$ADMIN_PW" "$ADMIN_TOTP"
	[ -s "$S/forwarding.before.json" ] || api admin GET /settings/forwarding >"$S/forwarding.before.json"
	local cur want
	cur=$(cat "$S/forwarding.before.json")
	want=$(jq -c --arg h "$WAZUH" '{syslog: {enabled: true, host: $h, port: 514, transport: "tcp", format: "wazuh",
		app_name: "nexus", facility: 13}, https: (.https | if . == null then null else del(.headers) + {headers: (.headers | map_values(null))} end)}' <<<"$cur")
	api admin PUT /settings/forwarding "$want" >/dev/null
	case $(status) in
	200) log "forwarding: syslog -> $WAZUH:514 (tcp, wazuh)" ;;
	202)
		local q
		q=$(jq -r .quorum_id "$S/body")
		login so "$SO_PW" "$SO_TOTP"
		api so POST "/quorum/$q/approve" '{}' >/dev/null
		expect 200 "approve forwarding change $q"
		log "forwarding: syslog -> $WAZUH:514 (tcp, wazuh), approved (quorum $q: the previous sink was TLS)"
		;;
	*) die "PUT /settings/forwarding: HTTP $(status) $(cat "$S/body")" ;;
	esac
	local r
	for _ in $(seq 1 12); do
		api admin POST /settings/forwarding/test '{}' >/dev/null
		r=$(jq -r '.result.syslog // .syslog // empty' "$S/body")
		[ -z "$r" ] && r=$(wait_job admin "$(jq -r .id "$S/body")" 120 | jq -r '.result.syslog // empty')
		[ "$r" = ok ] && break
		log "test message: ${r:-no answer} (egress allow-list?), again in 10 s"
		sleep 10
	done
	[ "$r" = ok ] || die "test message to the manager: $r"
	log "test message: ok"
}

# alerts of a rule in the manager's alerts.json since the step started (JSON lines; a line that does not parse,
# for example one cut off when the disk was full, is skipped)
alerts() { wz "jq -cR --argjson t $1 'fromjson? | select(.rule.id == \"$2\" and (.timestamp | sub(\"\\\\.[0-9]+\"; \"\") | sub(\"[+-][0-9]{4}$\"; \"Z\") | fromdate) >= \$t)' /var/ossec/logs/alerts/alerts.json 2>/dev/null"; }

step_live() {
	local t0
	t0=$(($(date +%s) - 120))
	login admin "$ADMIN_PW" "$ADMIN_TOTP"
	api admin POST /settings/forwarding/test '{}' >/dev/null
	# a failed login for a name that does not exist (a real account would get locked after a few runs): audit
	# auth.login_failed -> rule 110113
	api nobody POST /auth/login '{"name":"wazuh-lab-probe","password":"wrong","totp":"000000"}' >/dev/null || true
	local n_test=0 n_fail=0 n_audit=0
	for _ in $(seq 1 24); do
		n_test=$(alerts "$t0" 110101 | wc -l)
		n_fail=$(alerts "$t0" 110113 | wc -l)
		n_audit=$(wz "jq -cR --argjson t $t0 'fromjson? | select(any(.rule.groups[]?; . == \"nexusbackup\") and .data.type == \"audit\" and (.timestamp | sub(\"\\\\.[0-9]+\"; \"\") | sub(\"[+-][0-9]{4}$\"; \"Z\") | fromdate) >= \$t)' /var/ossec/logs/alerts/alerts.json 2>/dev/null | wc -l")
		[ "$n_test" -ge 1 ] && [ "$n_fail" -ge 1 ] && break
		sleep 5
	done
	log "alerts.json: test message $n_test (110101), failed login $n_fail (110113), audit records $n_audit"
	[ "$n_test" -ge 1 ] && [ "$n_fail" -ge 1 ] || die "records missing in Wazuh"
	alerts "$t0" 110113 | tail -1 | jq -c '{rule: .rule.id, level: .rule.level, description: .rule.description, agent: .agent.name, location}' >&2
}

step_restore() {
	[ -s "$S/forwarding.before.json" ] || die "no saved forwarding setting"
	login admin "$ADMIN_PW" "$ADMIN_TOTP"
	local old
	old=$(jq -c '.https |= (if . == null then null else .headers |= map_values(null) end)' "$S/forwarding.before.json")
	api admin PUT /settings/forwarding "$old" >/dev/null
	case $(status) in
	200) log "forwarding restored" ;;
	202)
		local q
		q=$(jq -r .quorum_id "$S/body")
		login so "$SO_PW" "$SO_TOTP"
		api so POST "/quorum/$q/approve" '{}' >/dev/null
		expect 200 "approve restore $q"
		log "forwarding restored (quorum $q)"
		;;
	*) die "restore: HTTP $(status) $(cat "$S/body")" ;;
	esac
	rm -f "$S/forwarding.before.json"
}

case ${1:-} in
manager | forward | live | restore) "step_$1" ;;
all) step_manager && step_forward && step_live && step_restore ;;
*) sed -n '2,16p' "$0" >&2 && exit 2 ;;
esac
