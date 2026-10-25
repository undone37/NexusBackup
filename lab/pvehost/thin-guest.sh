#!/usr/bin/env bash
# Thin LVs inside a guest (#71, plan.md Phase 39 L11) on the nested PVE node (pvenested.sh), through the appliance VM
# and the tunnel of deploy.sh: a clone of the Debian template VM gets a second disk with an LVM thin pool and two
# thin LVs (ext4 and XFS, $FILES files each); the clone is backed up in a group with index-files on. Checked: the
# file index lists both thin LVs with their files, the instant search finds one of them, the restore micro-VM mounts
# them (files_list).
#
#   thin-guest.sh vm       VM $VMID: full clone of $SRC_VMID on local-lvm plus a 4 GiB disk, thin pool + LVs + files
#   thin-guest.sh backup   group "thin-$VMID" (source $NODE, index-files on), backup, the file_index result
#   thin-guest.sh browse   files_list of /lvm and of both thin LVs in the restore micro-VM
#   thin-guest.sh cleanup  VM $VMID destroyed
#
# env: as rollback.sh (LAB, PORT, SSH_KEY); PVE_HOST (10.2.34.216), NODE (pve-nested), SRC_VMID (205), VMID (220),
#      GUEST_IP (10.2.34.217: the template's cloud-init address), FILES (50), OUT (~/nexus-lab/scratch/thin-guest)
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
export LAB=${LAB:-$HOME/nexus-lab/pvehost}
export PORT=${PORT:-28444}
PVE_HOST=${PVE_HOST:-10.2.34.216}
SSH_KEY=${SSH_KEY:-$HOME/nexus-lab/pve-lab-key}
VM_KEY=${VM_KEY:-$HOME/nexus-lab/lab_ed25519}
NODE=${NODE:-pve-nested}
SRC_VMID=${SRC_VMID:-205}
VMID=${VMID:-220}
GUEST_IP=${GUEST_IP:-10.2.34.217}
FILES=${FILES:-50}
OUT=${OUT:-$HOME/nexus-lab/scratch/thin-guest}
ROOT=$LAB/appliance/root
S=$ROOT/run/api
mkdir -p "$S" "$OUT"
# shellcheck disable=SC1091
. "$ROOT/secrets.env"
# shellcheck source=lab/e2e/api-lib.sh
. "$repo/lab/e2e/api-lib.sh"
pve() { ssh -n -i "$SSH_KEY" -o BatchMode=yes "root@$PVE_HOST" "$@"; }
vm() { ssh -i "$VM_KEY" -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR \
	-o ConnectTimeout=10 "root@$GUEST_IP" "$@"; }

step_vm() {
	pve "qm status $VMID" >/dev/null 2>&1 && die "VM $VMID exists (step cleanup)"
	pve "qm clone $SRC_VMID $VMID --full 1 --storage local-lvm --name thin-guest >/dev/null &&
		qm set $VMID --scsi1 local-lvm:4 >/dev/null && qm start $VMID"
	for _ in $(seq 60); do
		vm true 2>/dev/null && break
		sleep 5
	done
	vm true || die "VM $VMID: no SSH on $GUEST_IP"
	vm "set -e; command -v lvcreate >/dev/null && command -v thin_check >/dev/null ||
			{ apt-get -o DPkg::Lock::Timeout=600 update -qq && DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=600 install -y -qq lvm2 thin-provisioning-tools xfsprogs >/dev/null; }
		d=/dev/\$(lsblk -dno NAME,SIZE | awk '\$2 == \"4G\" {print \$1}' | head -1)
		pvcreate -q \$d && vgcreate -q vgthin \$d
		lvcreate -q -L 3G -T vgthin/pool
		lvcreate -q -V 2G -T vgthin/pool -n data && lvcreate -q -V 2G -T vgthin/pool -n logs
		mkfs.ext4 -q /dev/vgthin/data && mkfs.xfs -q /dev/vgthin/logs
		mkdir -p /srv/data /srv/logs && mount /dev/vgthin/data /srv/data && mount /dev/vgthin/logs /srv/logs
		for i in \$(seq $FILES); do echo thin-ext4-\$i > /srv/data/thin-ext4-\$i.txt; echo thin-xfs-\$i > /srv/logs/thin-xfs-\$i.txt; done
		umount /srv/data /srv/logs; sync"
	log "VM $VMID: thin pool vgthin/pool, thin LVs data (ext4) and logs (XFS), $FILES files each; $(vm 'lvs --noheadings -o lv_name,lv_attr,data_percent vgthin' | tr -s ' ' | tr '\n' ';')"
}

step_backup() {
	local g src pol j time idx
	login admin "$ADMIN_PW" "$ADMIN_TOTP"
	g=$(api admin GET /groups | jq -r --arg n "thin-$VMID" '.[] | select(.name == $n) | .id')
	if [ -z "$g" ]; then
		src=$(api admin GET /sources | jq -r --arg n "$NODE" '.[] | select(.name == $n) | .id')
		pol=$(api admin GET /policies | jq -r '.[] | select(.name == "daily") | .id')
		[ -n "$src" ] && [ -n "$pol" ] || die "no PVE source $NODE or policy daily"
		g=$(api admin POST /groups "$(jq -nc --argjson s "$src" --argjson p "$pol" --arg n "thin-$VMID" --argjson v "$VMID" \
			'{tenant:"lab", source_id:$s, policy_id:$p, name:$n, guests:[$v]}')" | jq -r .id)
		expect 201 "group thin-$VMID"
	fi
	api admin PUT "/groups/$g/index-files" '{"enabled":true}' >/dev/null
	expect 200 "index-files on"
	j=$(api admin POST /jobs "$(jq -nc --argjson g "$g" '{kind:"backup", tenant:"lab", params:{group_id:$g}}')")
	expect 202 "backup"
	j=$(wait_job admin "$(jq -r .id <<<"$j")" 3600)
	[ "$(jq -r .state <<<"$j")" = ok ] || die "backup: $(jq -r '.log // ""' <<<"$j" | tail -n 10)"
	time=$(jq -r '.log // ""' <<<"$j" | sed -n "s|^committed vm-$VMID/\([0-9]*\).*|\1|p" | tail -1)
	echo "$time" >"$OUT/time"
	log "backup vm-$VMID/$time ($(jq -r '.finished - .started' <<<"$j") s)"
	idx=
	for _ in $(seq 60); do
		idx=$(api admin GET '/jobs?limit=30' | jq -r --arg s "vm-$VMID" --argjson t "$time" \
			'[.[] | select(.kind == "file_index" and .params.source == $s and .params.time == $t)][0].id // empty')
		[ -n "$idx" ] && break
		sleep 5
	done
	[ -n "$idx" ] || die "no file_index job after the backup"
	j=$(wait_job admin "$idx" 3600)
	[ "$(jq -r .state <<<"$j")" = ok ] || die "file_index: $(jq -r '.log // ""' <<<"$j" | tail -n 15)"
	jq '.result' <<<"$j" >"$OUT/index.json"
	log "file_index: $(jq -c '{entries, elapsed_ms, volumes: [.volumes[]? | {name: (.name // .device), fs, entries, skipped: (.skipped // .error // null)}]}' "$OUT/index.json" | cut -c1-700)"
	for fs in ext4 xfs; do
		jq -e --argjson n "$FILES" --arg fs "$fs" '[.volumes[]? | select(.fs == $fs and .entries >= $n and .entries < 1000)] | length > 0' \
			"$OUT/index.json" >/dev/null || die "no small $fs volume with the $FILES files (the thin LV)"
	done
	log "both thin LVs are indexed"
	local hits=0
	for _ in $(seq 24); do
		hits=$(api admin GET "/files/search?tenant=lab&q=thin-xfs-7&source=vm-$VMID" | jq '[.hits[]? | select(.path | endswith("thin-xfs-7.txt"))] | length')
		[ "$hits" -gt 0 ] && break
		sleep 5
	done
	[ "$hits" -gt 0 ] || die "thin-xfs-7.txt not found by the instant search"
	log "instant search finds thin-xfs-7.txt"
}

step_browse() {
	local time j lv n
	login admin "$ADMIN_PW" "$ADMIN_TOTP"
	time=$(cat "$OUT/time")
	j=$(api admin POST /jobs "$(jq -nc --arg s "vm-$VMID" --argjson t "$time" '{kind:"files_list", tenant:"lab", params:{source:$s, time:$t, path:"/lvm"}}')")
	j=$(wait_job admin "$(jq -r .id <<<"$j")" 900)
	[ "$(jq -r .state <<<"$j")" = ok ] || die "files_list /lvm: $(jq -r '.log // ""' <<<"$j" | tail -n 15)"
	log "/lvm: $(jq -r '[.result.entries[].name] | join(" ")' <<<"$j")"
	for lv in vgthin-data vgthin-logs; do
		j=$(api admin POST /jobs "$(jq -nc --arg s "vm-$VMID" --argjson t "$time" --arg p "/lvm/$lv" '{kind:"files_list", tenant:"lab", params:{source:$s, time:$t, path:$p}}')")
		j=$(wait_job admin "$(jq -r .id <<<"$j")" 900)
		n=$(jq -r '[.result.entries[]? | select(.name | endswith(".txt"))] | length' <<<"$j")
		[ "$n" = "$FILES" ] || die "/lvm/$lv in the micro-VM: $n of $FILES files"
		log "restore micro-VM: /lvm/$lv holds the $FILES files"
	done
}

step_cleanup() {
	pve "qm stop $VMID >/dev/null 2>&1; qm destroy $VMID --purge 1 >/dev/null 2>&1" || true
	log "VM $VMID destroyed"
}

[ $# -gt 0 ] || set -- vm backup browse cleanup
for s in "$@"; do
	"step_$s"
done
