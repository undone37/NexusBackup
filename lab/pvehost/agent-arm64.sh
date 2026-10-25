#!/usr/bin/env bash
# Agent update on aarch64 (#66, plan.md Phase 39 L6 "arm64 on the emulated aarch64 VM"): the emulated Debian 13
# aarch64 VM 200 (TCG on the PVE lab host) gets the arm64 .deb of a TEST-key release, is enrolled with the
# appliance VM 201 (tunnel of deploy.sh), and the appliance pushes a newer TEST-signed release (package update in
# band through apt-get, the aarch64 artifact chosen by the agent's arch).
#
#   agent-arm64.sh install DEB   the package installed (dpkg), the agent "arm64-vm200" created and enrolled
#   agent-arm64.sh update TAR    TAR (nexus-agent-release-<v>-signed.tar, with linux-aarch64 artifacts) uploaded,
#                                the update pushed; the agent must report <v>
#
# Build both releases with release/packages.sh --test-key --no-msi and release/sign.sh sign-agent-release (TEST key).
# env: LAB, PORT (as deploy.sh); VM_IP (10.2.34.210), VM_USER (lab, sudo), SSH_KEY (~/nexus-lab/pve-lab-key: VM 200's
#      cloud-init key), NAME (arm64-vm200)
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
export LAB=${LAB:-$HOME/nexus-lab/pvehost}
export PORT=${PORT:-28444}
VM_IP=${VM_IP:-10.2.34.210}
VM_USER=${VM_USER:-lab}
SSH_KEY=${SSH_KEY:-$HOME/nexus-lab/pve-lab-key}
NAME=${NAME:-arm64-vm200}
ROOT=$LAB/appliance/root
S=$ROOT/run/api
mkdir -p "$S"
# shellcheck disable=SC1091
. "$ROOT/secrets.env"
# shellcheck source=lab/e2e/api-lib.sh
. "$repo/lab/e2e/api-lib.sh"
SSHO=(-i "$SSH_KEY" -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ConnectTimeout=20)
vm() { ssh "${SSHO[@]}" "$VM_USER@$VM_IP" "$@"; }
agent_id() { api admin GET /agents | jq -r --arg n "$NAME" '.[] | select(.name == $n) | .id'; }
login admin "$ADMIN_PW" "$ADMIN_TOTP"

step_install() {
	local deb=${1:?DEB} r id tok j
	scp -q "${SSHO[@]}" "$deb" "$VM_USER@$VM_IP:/tmp/"
	vm "sudo dpkg -i /tmp/$(basename "$deb") >/dev/null && rm /tmp/$(basename "$deb") && nexus-agent version | head -1 && uname -m"
	if [ -z "$(agent_id)" ]; then
		api admin POST /agents "$(jq -nc --arg n "$NAME" --arg h "$VM_IP" '{tenant:"lab", name:$n, host:$h, port:7444}')" >/dev/null
		expect 201 "create agent"
	fi
	id=$(agent_id)
	r=$(api admin POST "/agents/$id/token")
	expect 200 "agent token"
	tok=$(jq -r .token <<<"$r")
	vm "sudo nexus-agent init --token - >/dev/null && sudo systemctl enable --now nexus-agent >/dev/null 2>&1 && sudo systemctl restart nexus-agent" <<<"$tok"
	r=$(api admin POST "/agents/$id/enroll")
	expect 202 "enroll"
	j=$(wait_job admin "$(jq -r .id <<<"$r")" 600)
	[ "$(jq -r .state <<<"$j")" = ok ] || die "enroll: $(jq -r '.log // ""' <<<"$j" | tail -n 15)"
	log "agent $NAME ($id) enrolled: $(api admin GET /agents | jq -c --arg id "$id" '.[] | select(.id == $id) | {version, arch, os}')"
}

step_update() {
	local tar=${1:?TAR} v id j t0=$SECONDS
	v=$(tar -tf "$tar" | awk -F/ 'NR == 1 {print $1}')
	tar -tf "$tar" | grep -q '^[^/]*/linux-aarch64/' || die "$tar has no linux-aarch64 artifacts"
	RELEASE_TAR=$tar "$here/agent-release.sh" upload </dev/null
	id=$(agent_id)
	j=$(api admin POST /jobs "$(jq -nc --arg a "$id" --arg v "$v" '{kind:"agent_update", tenant:"lab", params:{agent_id:$a, version:$v}}')")
	expect 202 "agent_update"
	j=$(wait_job admin "$(jq -r .id <<<"$j")" 1800)
	jq -r '.log // ""' <<<"$j" | grep -E "^update-(plan|result) " | cut -c1-300 >&2 || true
	[ "$(jq -r .state <<<"$j")" = ok ] || die "agent_update: $(jq -r '.log // ""' <<<"$j" | tail -n 15)"
	[ "$(vm 'nexus-agent version' | awk 'NR == 1 {print $2}')" = "$v" ] || die "the VM runs $(vm 'nexus-agent version')"
	log "agent $NAME updated to $v in $((SECONDS - t0)) s; $(vm 'dpkg -l nexus-agent | tail -1' | tr -s ' ' | cut -d' ' -f2-4)"
}

case ${1:-} in
install | update) "step_$1" "${2:-}" ;;
*) sed -n '2,13p' "$0" >&2 && exit 2 ;;
esac
