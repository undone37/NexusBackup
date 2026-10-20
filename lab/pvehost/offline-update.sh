#!/usr/bin/env bash
# Offline (air-gapped) appliance update on the appliance VM of the PVE lab host (Phase 36,
# docs/release.md "Offline update bundle"). Through the tunnel of lab/pvehost/deploy.sh.
#
#   offline-update.sh bootstrap IMAGE     one time, for an appliance whose image predates offline updates:
#                                         the OCI layout of IMAGE on an extra disk, switched to on the root
#                                         console (lab image only: it has the console autologin), reboot
#   offline-update.sh bundle IMAGE OUT    OUT = signed update bundle of IMAGE (COSIGN_KEY, default the test key)
#   offline-update.sh upload BUNDLE       upload through the API, wait for the verification result
#   offline-update.sh apply               "Install now" (approved by the security officer if approvals are on),
#                                         then wait until the appliance answers with the new version
#   offline-update.sh status              GET /updates
#
# env: LAB (~/nexus-lab/pvehost), PVE_HOST, SSH_KEY, VMID (201), PORT (28444), COSIGN_KEY
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
export LAB=${LAB:-$HOME/nexus-lab/pvehost}
PVE_HOST=${PVE_HOST:-10.2.34.200}
SSH_KEY=${SSH_KEY:-$HOME/nexus-lab/pve-lab-key}
VMID=${VMID:-201}
export ROOT=$LAB/appliance/root PORT=${PORT:-28444} CONSOLE=$LAB/appliance/console.sock
export COSIGN_KEY=${COSIGN_KEY:-$repo/release/testkey/TEST-cosign.key}
# the lab test key's documented passphrase (lab/README.md); never set for another key
[ "$COSIGN_KEY" != "$repo/release/testkey/TEST-cosign.key" ] || export COSIGN_PASSWORD=${COSIGN_PASSWORD:-nexus-test-key}
S=$LAB/appliance/run-offline
mkdir -p "$S"
eval "$(ROOT=$ROOT PORT=$PORT "$repo/lab/e2e/m5.sh" env)"
# shellcheck source=lab/e2e/api-lib.sh
# shellcheck disable=SC1090
. "$repo/lab/e2e/api-lib.sh"
pve() { ssh -i "$SSH_KEY" -o BatchMode=yes "root@$PVE_HOST" "$@"; }
con() { "$repo/lab/appliance/con.py" run "$1"; }

oci_dir() { # oci_dir IMAGE DIR: the image as an OCI layout
	rm -rf "$2"
	podman save --format oci-dir -o "$2" "$1"
}

step_bootstrap() {
	local img=$1 w=$S/bootstrap
	rm -rf "$w" && mkdir -p "$w/fs"
	oci_dir "$img" "$w/fs/image"
	local mb=$(($(du -sm "$w/fs" | cut -f1) * 13 / 10 + 256))
	log "OCI layout of $img: $(du -sh "$w/fs" | cut -f1); disk ${mb} MB"
	truncate -s "${mb}M" "$w/oci.raw"
	/usr/sbin/mke2fs -q -t ext4 -d "$w/fs" "$w/oci.raw" # not in a user PATH
	pve "mkdir -p /var/lib/vz/import"
	scp -q -i "$SSH_KEY" "$w/oci.raw" "root@$PVE_HOST:/var/lib/vz/import/nx-oci.raw"
	pve "qm set $VMID --scsi7 vmpool:0,import-from=/var/lib/vz/import/nx-oci.raw,serial=NXOCI >/dev/null && rm -f /var/lib/vz/import/nx-oci.raw"
	log "disk attached to VM $VMID; switching on the console"
	# the new image ships this policy scope; the running one does not know it yet
	con 'set -e; d=/var/lib/nexus/update-offline; install -d -m 0700 $d; for i in $(seq 30); do [ -e /dev/disk/by-id/scsi-0QEMU_QEMU_HARDDISK_NXOCI ] && break; sleep 1; done
		mkdir -p /mnt/nxoci && mount -o ro /dev/disk/by-id/scsi-0QEMU_QEMU_HARDDISK_NXOCI /mnt/nxoci
		rm -rf $d/current && mkdir -p $d/current && cp -a /mnt/nxoci/image $d/current/image && umount /mnt/nxoci
		python3 - <<-PY
		import json; p="/etc/containers/policy.json"; pol=json.load(open(p))
		pol["transports"]["oci"]={"/var/lib/nexus/update-offline/current/image":[{"type":"insecureAcceptAnything"}]}
		json.dump(pol, open(p,"w"), indent=2)
		PY
		python3 -c "import json; i=json.load(open(\"$d/current/image/index.json\")); i[\"manifests\"][0].setdefault(\"annotations\",{})[\"org.opencontainers.image.ref.name\"]=\"nexus\"; json.dump(i,open(\"$d/current/image/index.json\",\"w\"))"
		bootc switch --quiet --transport oci $d/current/image:nexus && bootc status --format humanreadable | head -20' | tail -20
	pve "qm set $VMID --delete scsi7 >/dev/null; qm unlink $VMID --idlist unused0 --force 1 >/dev/null 2>&1 || true"
	log "rebooting VM $VMID into it"
	con 'systemctl reboot' >/dev/null 2>&1 || true
	wait_up
}

wait_up() { # until the web-api answers again (reboot)
	local t=0
	sleep 20
	until curl -s -o /dev/null --max-time 5 --cacert "$ROOT/etc/nexus/tls/cert.pem" --resolve "nexus-m5:$PORT:127.0.0.1" "https://nexus-m5:$PORT/api/v1/health"; do
		sleep 10
		t=$((t + 10))
		[ $t -lt 900 ] || die "appliance not back after 15 min"
	done
	log "appliance answers again"
}

step_bundle() {
	oci_dir "$1" "$S/oci"
	"$repo/release/update-bundle.sh" "$2" --oci-dir "$S/oci"
	rm -rf "$S/oci"
}

updates() { api admin GET /updates; }

step_upload() {
	login admin "$ADMIN_PW" "$ADMIN_TOTP"
	local t0=$SECONDS code before
	before=$(updates | jq '.last_result.time // 0')
	code=$(curl -s --cacert "$ROOT/etc/nexus/tls/cert.pem" --resolve "nexus-m5:$PORT:127.0.0.1" -b "$S/admin.jar" \
		-H "X-CSRF-Token: $(cat "$S/admin.csrf")" -H 'Content-Type: application/x-tar' --data-binary "@$1" \
		-o "$S/body" -w '%{http_code}' "$BASE/updates/bundle")
	[ "$code" = 202 ] || die "upload: HTTP $code $(cat "$S/body")"
	log "uploaded $(du -h "$1" | cut -f1) in $((SECONDS - t0)) s; waiting for the verification"
	# done when nexus-update recorded a newer result (the request file goes away at once)
	for _ in $(seq 180); do
		updates | jq -e --argjson t "$before" '.last_result.request == "import" and .last_result.time > $t' >/dev/null && break
		sleep 5
	done
	updates | jq '{status, staged, offline, last_result}'
}

step_apply() {
	login admin "$ADMIN_PW" "$ADMIN_TOTP"
	local r q want
	want=$(updates | jq -r .staged.version)
	[ "$want" != null ] || die "nothing staged"
	r=$(api admin POST /updates/apply '{}')
	q=$(jq -r '.quorum_id // empty' <<<"$r")
	if [ -n "$q" ] && [ "$(jq -r '.state // empty' <<<"$r")" != approved ]; then
		login so "$SO_PW" "$SO_TOTP"
		api so POST "/quorum/$q/approve" '{}' >/dev/null
		expect 200 "approve update.apply"
	fi
	log "installing $want; the appliance reboots"
	wait_up
	login admin "$ADMIN_PW" "$ADMIN_TOTP"
	for _ in $(seq 60); do
		[ "$(updates | jq -r .booted.version)" = "$want" ] && break
		sleep 10
	done
	updates | jq '{status, booted, staged, offline, last_result}'
	[ "$(updates | jq -r .booted.version)" = "$want" ] || die "booted version is not $want"
}

cmd=${1:-}
shift || true
case $cmd in
bootstrap) step_bootstrap "$@" ;;
bundle) step_bundle "$@" ;;
upload) step_upload "$@" ;;
apply) step_apply ;;
status) login admin "$ADMIN_PW" "$ADMIN_TOTP" && updates | jq . ;;
*) sed -n '2,13p' "$0" && exit 2 ;;
esac
