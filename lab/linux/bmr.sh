#!/usr/bin/env bash
# Bare-metal recovery end to end (docs/bmr.md) in QEMU/KVM, no root:
#
#   prerequisites: lab/linux/e2e.sh appliance            (dev control plane, REST API)
#                  lab/linux/vm.sh deb-lvm up            (LVM root, thin pool, XFS, PostgreSQL)
#                  lab/linux/e2e.sh deb-lvm agent        (agent installed + enrolled)
#                  restore-vm/rescue/build.sh            (target/rescue/nexus-rescue-<v>.iso)
#
#   bmr.sh [steps]   default: backup recover verify
#     backup   the agent's source backs up the whole system (/ with nested mounts); the job log must
#              show the layout line; a sha256 sample of files and the host name are taken from the VM
#     recover  recovery token (API) → blank VM (two empty virtio disks as large as the original ones,
#              SeaBIOS, disk before CD) with the rescue ISO and a config disk (NEXUSCFG, xorriso;
#              unattended, `advertise` = the host-forwarded rescue port) → check-in → start (API) →
#              bmr job → session done → the VM reboots into the restored system
#     verify   ssh into the restored VM: host name, the sha256 sample, PostgreSQL answers, LVM / fstab
#
# The original VM keeps running; the recovered VM is `bmr-target` (ssh 127.0.0.1:2249, rescue agent
# 127.0.0.1:17449). Results in $ROOT/run/api/bmr.results.
# env: ROOT/PORT as for e2e.sh, ISO (target/rescue/nexus-rescue-<v>.iso), LAB, MEM (2048)
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
export ROOT=${ROOT:-$repo/target/linux-root} PORT=${PORT:-18453}
LAB=${LAB:-/home/ah/nexus-lab}
ver=$(sed -n 's/^version = "\(.*\)"/\1/p' "$repo/crates/agent-linux/Cargo.toml" | head -1)
ISO=${ISO:-$repo/target/rescue/nexus-rescue-$ver.iso}
MEM=${MEM:-2048}
VM=deb-lvm
TENANT=linux
SSH_PORT=2249 RESCUE_PORT=17449
T=$LAB/linux/bmr-target
eval "$(ROOT=$ROOT PORT=$PORT "$repo/lab/e2e/m5.sh" env)"
S=$ROOT/run/api
mkdir -p "$S" "$T"
# shellcheck source=lab/e2e/api-lib.sh
. "$repo/lab/e2e/api-lib.sh"
R=$S/bmr.results
touch "$R"
result() {
	grep -v "^$1=" "$R" >"$R.tmp" || true
	echo "$1=$2" >>"$R.tmp"
	mv "$R.tmp" "$R"
	log "result $1=$2"
}
vm() { "$here/vm.sh" "$VM" ssh "$@"; }
# shellcheck disable=SC1090
. "$S/$VM.env" 2>/dev/null || die "no agent for $VM: run lab/linux/e2e.sh $VM agent first"
[ -n "${AGENT:-}" ] || die "no agent for $VM"
LAB_KEY=${LAB_KEY:-$LAB/lab_ed25519}
tssh() {
	ssh -o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
		-o LogLevel=ERROR -i "$LAB_KEY" -p "$SSH_PORT" lab@127.0.0.1 "$@"
}
SAMPLE='sudo find /etc /usr/bin /home/lab /srv/xfs -xdev -type f -size -20M 2>/dev/null | LC_ALL=C sort | head -2000 | sudo xargs -d "\n" sha256sum'

step_backup() {
	login admin "$ADMIN_PW" "$ADMIN_TOTP"
	local src cfg r j t0=$SECONDS
	src=$(api admin GET /sources | jq -r --arg a "$AGENT" '[.[] | select(.kind=="linux" and .config.agent_id==$a)][0].id')
	cfg=$(jq -nc --arg a "$AGENT" '{agent_id:$a, paths:["/"], cross_mounts:true, hooks:true,
		excludes:["/var/cache/apt/archives/*.deb", "/var/tmp/*", "/tmp/*"],
		exclude_regex:["^/srv/plain(/|$)", "^/var/lib/nexus-agent/spool(/|$)"]}')
	# /srv/plain (the image'"'"'s former root, read live: no snapshot) would fill the small root
	# file system with the agent'"'"'s spool and overflow the root LV'"'"'s thick snapshot; it is
	# recreated empty
	if [ -z "$src" ] || [ "$src" = null ]; then
		api admin POST /sources "$(jq -nc --arg t "$TENANT" --argjson c "$cfg" '{tenant:$t, kind:"linux", name:"deb-lvm-full", config:$c}')" >/dev/null
		expect 201 "create source"
	else
		api admin PUT "/sources/$src" "$(api admin GET /sources | jq -c --argjson id "$src" --argjson c "$cfg" \
			'.[] | select(.id==$id) | {name, config:(.config + $c | del(.token_secret_set))}')" >/dev/null
		expect 200 "whole-system source"
	fi
	r=$(api admin POST /jobs "$(jq -nc --arg t "$TENANT" --arg a "$AGENT" '{kind:"backup", tenant:$t, params:{agent_id:$a}}')")
	expect 202 "backup"
	j=$(wait_job admin "$(jq -r .id <<<"$r")" 1800)
	[ "$(jq -r .state <<<"$j")" = ok ] || die "backup: $(jq -r .log <<<"$j" | tail -n 20)"
	jq -r .log <<<"$j" | grep -E '^layout' | sed 's/^/  log: /' >&2 || die "no layout line in the backup log"
	TIME=$(jq -r '.result.time' <<<"$j")
	echo "TIME=$TIME" >"$S/bmr.env"
	result backup_s $((SECONDS - t0))
	result snapshot "$TIME"
	vm "$SAMPLE" >"$S/bmr.sample"
	vm hostname >"$S/bmr.hostname"
	result sample_files "$(wc -l <"$S/bmr.sample")"
}

running() { [ -f "$T/qemu.pid" ] && kill -0 "$(cat "$T/qemu.pid")" 2>/dev/null; }

step_recover() {
	# shellcheck disable=SC1091
	. "$S/bmr.env"
	[ -f "$ISO" ] || die "no rescue ISO $ISO (restore-vm/rescue/build.sh)"
	login admin "$ADMIN_PW" "$ADMIN_TOTP"
	local r id token disks t0=$SECONDS st
	r=$(api admin POST "/agents/$AGENT/rescue" '{"reboot": true}')
	expect 201 "recovery token"
	id=$(jq -r .id <<<"$r")
	token=$(jq -r .token <<<"$r")
	log "rescue session $id"
	if running; then kill "$(cat "$T/qemu.pid")" || true; sleep 2; fi
	rm -rf "${T:?}"/*
	mkdir -p "$T/cfg"
	# blank disks as large as the original ones (layout: vda 12G, vdb 8G)
	qemu-img create -q -f qcow2 "$T/disk0.qcow2" 12G
	qemu-img create -q -f qcow2 "$T/disk1.qcow2" 8G
	jq -n --arg a "10.0.2.2:$PORT" --arg t "$token" --arg adv "127.0.0.1:$RESCUE_PORT" \
		'{appliance:$a, token:$t, advertise:$adv, network:{mode:"dhcp"}, disks:["auto"], confirm:true}' >"$T/cfg/rescue.json"
	xorriso -as mkisofs -quiet -o "$T/cfg.iso" -V NEXUSCFG -J -r "$T/cfg/rescue.json"
	rm -rf "$T/cfg"
	qemu-system-x86_64 -name lab-bmr-target -machine q35,accel=kvm -cpu host -smp 2 -m "$MEM" \
		-nodefaults -display none -device VGA \
		-drive file="$T/disk0.qcow2",if=none,id=d0,format=qcow2,cache=unsafe -device virtio-blk-pci,drive=d0,bootindex=1 \
		-drive file="$T/disk1.qcow2",if=none,id=d1,format=qcow2,cache=unsafe -device virtio-blk-pci,drive=d1 \
		-drive file="$ISO",if=none,id=cd0,format=raw,media=cdrom,readonly=on -device ide-cd,drive=cd0,bus=ide.0,bootindex=2 \
		-drive file="$T/cfg.iso",if=none,id=cd1,format=raw,media=cdrom,readonly=on -device ide-cd,drive=cd1,bus=ide.1 \
		-nic user,model=virtio-net-pci,hostfwd=tcp:127.0.0.1:"$SSH_PORT"-:22,hostfwd=tcp:127.0.0.1:"$RESCUE_PORT"-:7444 \
		-serial file:"$T/serial.log" -object rng-random,id=rng0,filename=/dev/urandom -device virtio-rng-pci,rng=rng0 \
		-daemonize -pidfile "$T/qemu.pid"
	log "bmr-target started (serial log $T/serial.log)"
	# check-in → waiting
	for _ in $(seq 300); do
		st=$(api admin GET "/rescue/$id" | jq -r .state)
		[ "$st" = waiting ] && break
		running || die "the rescue VM exited (see $T/serial.log)"
		sleep 2
	done
	[ "$st" = waiting ] || die "no check-in after 600 s (see $T/serial.log)"
	disks=$(api admin GET "/rescue/$id" | jq -c '[.disks[] | "\(.path) \(.size)"]')
	log "checked in: $(api admin GET "/rescue/$id" | jq -r '"\(.host):\(.port)"') disks $disks"
	result checkin_s $((SECONDS - t0))
	r=$(api admin POST "/rescue/$id/start" "$(jq -nc --argjson t "$TIME" '{time:$t, reboot:true}')")
	expect 202 "start"
	local j
	j=$(wait_job admin "$(jq -r .id <<<"$r")" 3600)
	jq -r .log <<<"$j" | grep -E '^rescue-|rescue: "\$ (sfdisk|lvm|mkfs|grub|update)' | sed 's/^/  log: /' >&2 || true
	[ "$(jq -r .state <<<"$j")" = ok ] || die "bmr job: $(jq -r .log <<<"$j" | tail -n 30)"
	[ "$(api admin GET "/rescue/$id" | jq -r .state)" = "done" ] || die "session not done"
	result recover_s $((SECONDS - t0))
	# the rescue reboots into the restored system
	local t1=$SECONDS
	until tssh true 2>/dev/null; do
		[ $((SECONDS - t1)) -lt 600 ] || die "the restored system does not answer ssh (see $T/serial.log)"
		running || die "bmr-target exited (see $T/serial.log)"
		sleep 5
	done
	result first_boot_s $((SECONDS - t1))
}

step_verify() {
	local h
	h=$(tssh hostname)
	[ "$h" = "$(cat "$S/bmr.hostname")" ] || die "host name $h, expected $(cat "$S/bmr.hostname")"
	result hostname "$h"
	tssh "$SAMPLE" >"$S/bmr.sample.restored"
	if diff -q "$S/bmr.sample" "$S/bmr.sample.restored" >/dev/null; then
		result sample_equal true
	else
		diff "$S/bmr.sample" "$S/bmr.sample.restored" | head -20 >&2
		result sample_equal false
		die "sample differs"
	fi
	tssh 'sudo lvs --noheadings -o vg_name,lv_name,segtype; findmnt -no SOURCE,TARGET / /srv/xfs /var/lib/postgresql' | sed 's/^/  restored: /' >&2
	tssh 'sudo -u postgres psql -Atc "select count(*) from pg_database"' >/dev/null && result postgres true
	tssh 'systemctl is-system-running --wait || true' | sed 's/^/  restored: /' >&2
}

steps=${*:-backup recover verify}
for s in $steps; do
	log "== $s"
	"step_$s"
done
log "results: $(tr '\n' ' ' <"$R")"
