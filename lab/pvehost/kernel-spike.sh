#!/usr/bin/env bash
# #60 spike: the restore micro-VM with its own kernel (restore-vm/kernel) on the appliance VM of the PVE lab host,
# through the tunnel of deploy.sh. The spike's vmlinuz and initrd.img go onto a small disk attached to VM $VMID,
# are copied to /var/lib/nexus/rvm-spike (labels of the shipped ones) and bind-mounted over /usr/lib/nexus/restore-vm
# (lab only, gone at the next boot). files_list of "/" for $SNAPS runs with the shipped and with the spike kernel:
# the same mounts are expected; the job times are compared.
#
#   kernel-spike.sh stage DIR   DIR (target/restore-vm-spike) onto the appliance, not yet active
#   kernel-spike.sh compare     files_list "/" of every snapshot in $SNAPS, shipped kernel, then spike kernel
#   kernel-spike.sh off         the bind mount removed (also gone after a reboot)
#
# env: as deploy.sh (LAB, PORT, PVE_HOST, SSH_KEY, VMID 201); SNAPS ("vm-225 vm-229 vm-101": newest snapshot
#      of each), OUT (~/nexus-lab/scratch/kernel-spike)
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
export LAB=${LAB:-$HOME/nexus-lab/pvehost}
export PORT=${PORT:-28444}
PVE_HOST=${PVE_HOST:-10.2.34.200}
SSH_KEY=${SSH_KEY:-$HOME/nexus-lab/pve-lab-key}
VMID=${VMID:-201}
SNAPS=${SNAPS:-vm-225 vm-229 vm-101}
OUT=${OUT:-$HOME/nexus-lab/scratch/kernel-spike}
export ROOT=$LAB/appliance/root CONSOLE=$LAB/appliance/console.sock
S=$ROOT/run/api
mkdir -p "$S" "$OUT"
# shellcheck disable=SC1091
. "$ROOT/secrets.env"
# shellcheck source=lab/e2e/api-lib.sh
. "$repo/lab/e2e/api-lib.sh"
pve() { ssh -n -i "$SSH_KEY" -o BatchMode=yes "root@$PVE_HOST" "$@"; }
con() { "$repo/lab/appliance/con.py" run "$1"; }

step_stage() {
	local dir=${1:?DIR} w=$OUT/disk
	rm -rf "$w" && mkdir -p "$w"
	# a tar stream as the whole disk: the appliance reads it from the block device (no ext4 module there)
	tar -C "$dir" -cf "$w/spike.raw" vmlinuz initrd.img manifest.txt
	truncate -s 64M "$w/spike.raw"
	pve "mkdir -p /var/lib/vz/import"
	scp -q -i "$SSH_KEY" "$w/spike.raw" "root@$PVE_HOST:/var/lib/vz/import/nx-spike.raw"
	pve "qm set $VMID --scsi7 vmpool:0,import-from=/var/lib/vz/import/nx-spike.raw,serial=NXSPIKE >/dev/null && rm -f /var/lib/vz/import/nx-spike.raw"
	# one line per console command (a failing `set -e` would end the console shell)
	con 'for i in $(seq 30); do lsblk -dno SERIAL | grep -qx NXSPIKE && break; sleep 1; done; rm -rf /var/lib/nexus/rvm-spike; cp -a /usr/lib/nexus/restore-vm /var/lib/nexus/rvm-spike' >/dev/null
	con 'tar -xf /dev/$(lsblk -dno NAME,SERIAL | awk "\$2 == \"NXSPIKE\" {print \$1}") -C /var/lib/nexus/rvm-spike && chcon --reference=/usr/lib/nexus/restore-vm/vmlinuz /var/lib/nexus/rvm-spike/* && head -1 /var/lib/nexus/rvm-spike/manifest.txt && ls -l /var/lib/nexus/rvm-spike' | tail -6 >&2
	pve "qm set $VMID --delete scsi7 >/dev/null; qm unlink $VMID --idlist unused0 --force 1 >/dev/null 2>&1 || true"
	log "spike staged in /var/lib/nexus/rvm-spike (not active)"
}

# "<tenant> <time>" of the newest snapshot of SOURCE
newest() { api admin GET "/snapshots?source=$1" | jq -r 'max_by(.time) // empty | "\(.tenant) \(.time)"'; }

# files_list "/" of every snapshot: job time and the mounts, into $OUT/$1.txt
run_lists() {
	local s t j tn
	: >"$OUT/$1.txt"
	for s in $SNAPS; do
		read -r tn t <<<"$(newest "$s")"
		[ -n "$t" ] || die "no snapshot of $s"
		j=$(api admin POST /jobs "$(jq -nc --arg s "$s" --argjson t "$t" --arg tn "$tn" '{kind:"files_list", tenant:$tn, params:{source:$s, time:$t, path:"/"}}')")
		expect 202 "files_list $s"
		j=$(wait_job admin "$(jq -r .id <<<"$j")" 900)
		[ "$(jq -r .state <<<"$j")" = ok ] || die "files_list $s ($1): $(jq -r '.log // ""' <<<"$j" | tail -n 10)"
		printf '%s %s %s s: %s\n' "$s" "$t" "$(jq -r '.finished - .started' <<<"$j")" \
			"$(jq -c '[.result.entries[]?.name] // .result' <<<"$j")" >>"$OUT/$1.txt"
	done
	log "$1: $(awk '{printf "%s %s s; ", $1, $3}' "$OUT/$1.txt")"
}

step_compare() {
	login admin "$ADMIN_PW" "$ADMIN_TOTP"
	con 'umount /usr/lib/nexus/restore-vm 2>/dev/null; head -1 /usr/lib/nexus/restore-vm/manifest.txt' | tail -1 >&2
	run_lists shipped
	con 'mount --bind /var/lib/nexus/rvm-spike /usr/lib/nexus/restore-vm && head -1 /usr/lib/nexus/restore-vm/manifest.txt' | tail -1 >&2
	run_lists spike
	con 'umount /usr/lib/nexus/restore-vm' >/dev/null
	if diff <(cut -d' ' -f1,2,5- "$OUT/shipped.txt") <(cut -d' ' -f1,2,5- "$OUT/spike.txt") >&2; then
		log "same mounts with both kernels"
	else
		die "the spike kernel lists other mounts"
	fi
}

step_off() {
	con 'umount /usr/lib/nexus/restore-vm 2>/dev/null; head -1 /usr/lib/nexus/restore-vm/manifest.txt' | tail -1 >&2
}

case ${1:-} in
stage) step_stage "${2:-$repo/target/restore-vm-spike}" ;;
compare | off) "step_$1" ;;
*) sed -n '2,13p' "$0" >&2 && exit 2 ;;
esac
