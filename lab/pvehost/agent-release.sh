#!/usr/bin/env bash
# Signed agent releases on the appliance VM (#68, plan.md Phase 39 L8), through the tunnel of deploy.sh: an image
# built with a TEST-key-signed release in os/agent-release (os/agent-release/README.md) lists it as signed; a second
# signed release uploaded through the API lands in /var/lib/nexus/agent-releases; an enrolled agent test VM is
# updated to it (nexus-agentctl verifies the manifest with /etc/pki/nexus/cosign); no SELinux denial of the release
# dirs or nexus-agentctl under enforcing.
#
#   agent-release.sh list      GET /agent-releases: the image's release $SHIPPED, signed
#   agent-release.sh upload    RELEASE_TAR (nexus-agent-release-<v>-signed.tar) uploaded, listed as signed
#   agent-release.sh testkey   the image's $SHIPPED .deb (TEST key pinned) installed on the VM: the packaged agent
#                              pins the production key and refuses TEST-signed releases (checked first)
#   agent-release.sh bundle    instead of testkey: the package removed, the image's $SHIPPED bundle (tar.gz,
#                              install.sh) installed with a new token and enrolled again (update: bundle swap)
#   agent-release.sh update    agent "clean-$VM" (clean-restore.sh vm enrol) updated to the uploaded version
#   agent-release.sh selinux   AVC denials of today on the appliance (root console), none for the release path
#
# env: as vmware-e2e.sh (LAB, PORT); SHIPPED (0.1.1), RELEASE_TAR (~/nexus-lab/scratch/nexus-agent-release-0.1.2-
#      signed.tar), VM (debian-13), VM_IP (from clean-restore.sh), VM_KEY, CONSOLE (the appliance's serial console
#      socket, lab image)
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
export LAB=${LAB:-$HOME/nexus-lab/pvehost}
export PORT=${PORT:-28444}
export CONSOLE=${CONSOLE:-$LAB/appliance/console.sock}
SHIPPED=${SHIPPED:-0.1.1}
RELEASE_TAR=${RELEASE_TAR:-$HOME/nexus-lab/scratch/nexus-agent-release-0.1.2-signed.tar}
VM=${VM:-debian-13}
ROOT=$LAB/appliance/root
S=$ROOT/run/api
mkdir -p "$S"
# shellcheck disable=SC1091
. "$ROOT/secrets.env"
# shellcheck source=lab/e2e/api-lib.sh
. "$repo/lab/e2e/api-lib.sh"
case " ${*:-all} " in " selinux ") ;; *) login admin "$ADMIN_PW" "$ADMIN_TOTP" ;; esac
uploaded() { tar -tf "$RELEASE_TAR" | head -1 | cut -d/ -f1; }
PVE_HOST=${PVE_HOST:-10.2.34.200}
SSH_KEY=${SSH_KEY:-$HOME/nexus-lab/pve-lab-key}
VM_KEY=${VM_KEY:-$HOME/nexus-lab/lab_ed25519}
VM_IP=${VM_IP:-$(cat "$HOME/nexus-lab/scratch/clean-restore/ip" 2>/dev/null || true)}
SSHO=(-i "$VM_KEY" -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR
	-o ProxyCommand="ssh -i $SSH_KEY -o BatchMode=yes -W %h:%p root@$PVE_HOST")
vm() { ssh "${SSHO[@]}" "root@$VM_IP" "$@"; }

update_job() { # update_job VERSION: the agent_update job JSON
	local a r
	a=$(api admin GET /agents | jq -r --arg n "clean-$VM" '.[] | select(.name == $n) | .id')
	[ -n "$a" ] || die "no agent clean-$VM (clean-restore.sh vm enrol)"
	r=$(api admin POST /jobs "$(jq -nc --arg a "$a" --arg v "$1" '{kind:"agent_update", tenant:"lab", params:{agent_id:$a, version:$v}}')")
	expect 202 "agent_update"
	wait_job admin "$(jq -r .id <<<"$r")" 900
}

step_testkey() {
	local j deb
	# the production-key agent refuses the TEST-signed release (the agent checks the manifest itself)
	j=$(update_job "$(uploaded)")
	[ "$(jq -r .state <<<"$j")" != ok ] && jq -r '.log // ""' <<<"$j" | grep -q 'does not verify with any pinned release key' ||
		die "a production-key agent accepted a TEST-signed release: $(jq -r '.log // ""' <<<"$j" | tail -n 5)"
	log "the packaged agent (production key) refuses the TEST-signed release"
	# .deb or .rpm, whichever the VM's package manager takes
	if vm 'command -v dpkg >/dev/null'; then
		deb=$(ls "$repo"/os/agent-release/"$SHIPPED"/linux-x86_64/nexus-agent_"$SHIPPED"-1_amd64.deb)
		scp -q "${SSHO[@]}" "$deb" "root@$VM_IP:/tmp/agent.deb"
		vm "dpkg -i /tmp/agent.deb >/dev/null && systemctl restart nexus-agent && nexus-agent version | head -1"
	else
		deb=$(ls "$repo"/os/agent-release/"$SHIPPED"/linux-x86_64/nexus-agent-"$SHIPPED"-1.x86_64.rpm)
		scp -q "${SSHO[@]}" "$deb" "root@$VM_IP:/tmp/agent.rpm"
		vm "rpm -U --quiet /tmp/agent.rpm && systemctl restart nexus-agent && nexus-agent version | head -1"
	fi
}

step_list() {
	api admin GET /agent-releases | jq -c '.releases[] | {version, signed, source: (.source // .origin // null)}' >&2
	api admin GET /agent-releases | jq -e --arg v "$SHIPPED" '.releases[] | select(.version == $v) | .signed' >/dev/null ||
		die "the image's release $SHIPPED is not listed as signed"
	log "release $SHIPPED from the image: signed"
}

step_upload() {
	local v
	[ -f "$RELEASE_TAR" ] || die "no $RELEASE_TAR"
	v=$(uploaded)
	curl -s --cacert "$ROOT/etc/nexus/tls/cert.pem" --resolve "nexus-m5:$PORT:127.0.0.1" -b "$S/admin.jar" \
		-H "X-CSRF-Token: $(cat "$S/admin.csrf")" -H 'Content-Type: application/x-tar' --data-binary "@$RELEASE_TAR" \
		-o "$S/body" -w '%{http_code}' "$BASE/agent-releases" >"$S/status"
	[ "$(status)" = 201 ] || [ "$(status)" = 409 ] || die "release upload: HTTP $(status) $(cat "$S/body")"
	api admin GET /agent-releases | jq -e --arg v "$v" '.releases[] | select(.version == $v) | .signed' >/dev/null ||
		die "uploaded release $v is not listed as signed"
	log "release $v uploaded (HTTP $(cat "$S/status")): signed"
}

step_bundle() {
	local a r j tgz
	a=$(api admin GET /agents | jq -r --arg n "clean-$VM" '.[] | select(.name == $n) | .id')
	[ -n "$a" ] || die "no agent clean-$VM (clean-restore.sh vm enrol)"
	tgz=$(ls "$repo"/os/agent-release/"$SHIPPED"/linux-x86_64/nexus-agent-"$SHIPPED"-x86_64.tar.gz)
	scp -q "${SSHO[@]}" "$tgz" "root@$VM_IP:/tmp/agent.tar.gz"
	r=$(api admin POST "/agents/$a/token")
	expect 200 "agent token"
	vm "set -e; systemctl stop nexus-agent
		if command -v dpkg >/dev/null; then dpkg --purge nexus-agent >/dev/null; else rpm -e nexus-agent; fi
		rm -rf /tmp/agent && mkdir /tmp/agent && tar -xzf /tmp/agent.tar.gz -C /tmp/agent
		cd /tmp/agent/nexus-agent-$SHIPPED-x86_64 && ./install.sh --token - >/dev/null && nexus-agent version | head -1" <<<"$(jq -r .token <<<"$r")"
	r=$(api admin POST "/agents/$a/enroll")
	expect 202 "enroll"
	j=$(wait_job admin "$(jq -r .id <<<"$r")" 300)
	[ "$(jq -r .state <<<"$j")" = ok ] || die "enroll: $(jq -r '.log // ""' <<<"$j" | tail -n 15)"
	api admin GET /agents | jq -e --arg id "$a" '.[] | select(.id == $id) | .install == "bundle"' >/dev/null ||
		die "agent not reported as a bundle install"
	log "agent clean-$VM: bundle $SHIPPED installed and enrolled"
}

step_update() {
	local a v j t0=$SECONDS
	v=$(uploaded)
	a=$(api admin GET /agents | jq -r --arg n "clean-$VM" '.[] | select(.name == $n) | .id')
	j=$(update_job "$v")
	jq -r '.log // ""' <<<"$j" | grep -E "^update-plan |verified|signature|update" | tail -6 >&2 || true
	[ "$(jq -r .state <<<"$j")" = ok ] || die "agent_update: $(jq -r '.log // ""' <<<"$j" | tail -n 20)"
	api admin GET /agents | jq -e --arg id "$a" --arg v "$v" '.[] | select(.id == $id) | .version == $v' >/dev/null ||
		die "agent version after the update: $(api admin GET /agents | jq -c --arg id "$a" '.[] | select(.id == $id) | {version, update_state, update_error}')"
	log "agent clean-$VM updated to $v in $((SECONDS - t0)) s"
}

step_selinux() {
	local out
	out=$("$repo/lab/appliance/con.py" run "getenforce; ausearch -m avc -ts today 2>/dev/null | grep -o 'scontext=[^ ]* tcontext=[^ ]* tclass=[a-z_]*' | sort | uniq -c" 2>&1 |
		grep -v "READY\|END-\|ausearch\|getenforce;")
	echo "$out" >&2
	grep -q '^Enforcing' <<<"$out" || die "SELinux is not enforcing"
	! grep -qE 'nexus_agent_release_t|nexus_agentctl_t|nexus_webapi_t' <<<"$out" || die "denials in the release path"
	log "SELinux enforcing, no denial for the release dirs, nexus-agentctl or the web API"
}

for s in "${@:-list upload testkey update selinux}"; do
	for x in $s; do
		log "== $x"
		"step_$x"
	done
done
