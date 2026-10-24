#!/usr/bin/env bash
# Standalone agent copies (Phase 38c, #30) on a Debian agent VM of the PVE lab: a repository of its own, mirrored
# to an SFTP-only account on another lab VM (OpenSSH internal-sftp, nothing installed), fetched back into an empty
# directory, opened with the recovery key and restored; the restored files compared with the originals.
#
#   agent-copy.sh sftp   key on $VM, account $USER_ on $SFTP_VM (restrict, internal-sftp, an extra key line next
#                        to the appliance's), repo init + backup of $DATA, copy, second copy (nothing new), one
#                        more backup + copy (only the new files), fetch, open, restore, diff; cleanup
#
# env: VM (10.2.34.5, ag-debian-13 / 225), SFTP_VM (10.2.34.99, the regression VM 280), USER_ (nexusoff),
#      VM_KEY (~/nexus-lab/lab_ed25519: root on both), AGENT (target/release/nexus-agent of this tree), DATA (/etc)
# S3: needs an S3 test box on a lab VM (crates/offsite/testbox-s3), not set up yet.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
VM=${VM:-10.2.34.5}
SFTP_VM=${SFTP_VM:-10.2.34.99}
USER_=${USER_:-nexusoff}
VM_KEY=${VM_KEY:-$HOME/nexus-lab/lab_ed25519}
AGENT=${AGENT:-$repo/target/release/nexus-agent}
DATA=${DATA:-/etc}
T0=$(date +%s)
log() { printf '[%4ds] %s\n' "$(($(date +%s) - T0))" "$*" >&2; }
die() { log "FAIL: $*"; exit 1; }
ssh_() { ssh -i "$VM_KEY" -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR \
	-o ConnectTimeout=10 "root@$1" "${@:2}"; }

step_sftp() {
	local pub hk out
	[ -x "$AGENT" ] || die "$AGENT: build it first (cargo build --release -p agent-linux)"
	scp -q -i "$VM_KEY" -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR \
		"$AGENT" "root@$VM:/root/nexus-agent-dev"
	ssh_ "$VM" 'rm -rf /var/tmp/nxrepo /var/tmp/nxfetch /var/tmp/nxrestore; test -f /root/.ssh/nexus-copy ||
		ssh-keygen -q -t ed25519 -N "" -C nexus-copy -f /root/.ssh/nexus-copy'
	pub=$(ssh_ "$VM" 'cut -d" " -f1,2 /root/.ssh/nexus-copy.pub')
	# an extra line: the appliance's offsite key (offsite.sh) stays
	ssh_ "$SFTP_VM" "id $USER_ >/dev/null 2>&1 || useradd -m -s /bin/sh $USER_
		install -d -o $USER_ -g $USER_ -m 700 ~$USER_/.ssh ~$USER_/data
		f=~$USER_/.ssh/authorized_keys; touch \$f; grep -v ' nexus-copy-$VM\$' \$f > \$f.new || true
		echo 'restrict,command=\"internal-sftp -d /home/$USER_/data\" $pub nexus-copy-$VM' >> \$f.new
		mv \$f.new \$f; chown $USER_: \$f; chmod 600 \$f; rm -rf ~$USER_/data/agent-copy"
	hk=$(ssh-keyscan -t ed25519 "$SFTP_VM" 2>/dev/null | grep -v '^#' | cut -d' ' -f2,3 | head -1)
	[ -n "$hk" ] || die "no host key of $SFTP_VM"
	ssh_ "$VM" "cat > /root/copy-sftp.json" <<<"$(jq -n --arg h "$SFTP_VM" --arg u "$USER_" --arg hk "$hk" \
		'{kind:"sftp", host:$h, user:$u, key_file:"/root/.ssh/nexus-copy", host_key:$hk, base_dir:"agent-copy"}')"
	ssh_ "$VM" chmod 600 /root/copy-sftp.json
	# the recovery key stays on the VM (lab data; never in a log that leaves it)
	ssh_ "$VM" '/root/nexus-agent-dev repo init /var/tmp/nxrepo | grep -A1 "RECOVERY KEY" | tail -1 > /root/nxrepo.words && test -s /root/nxrepo.words'
	out=$(ssh_ "$VM" "/root/nexus-agent-dev repo backup /var/tmp/nxrepo $DATA" | tail -1)
	log "backup: $out"
	out=$(ssh_ "$VM" '/root/nexus-agent-dev repo copy /var/tmp/nxrepo /root/copy-sftp.json')
	log "copy 1: $out"
	out=$(ssh_ "$VM" '/root/nexus-agent-dev repo copy /var/tmp/nxrepo /root/copy-sftp.json')
	log "copy 2 (nothing new): $out"
	grep -q '^0 file(s) uploaded' <<<"$out" || die "the second copy uploaded files"
	ssh_ "$VM" "echo nexus-copy-$(date +%s) > $DATA/nexus-copy-marker"
	ssh_ "$VM" "/root/nexus-agent-dev repo backup /var/tmp/nxrepo $DATA" >/dev/null
	out=$(ssh_ "$VM" '/root/nexus-agent-dev repo copy /var/tmp/nxrepo /root/copy-sftp.json')
	log "copy 3 (after one more backup): $out"
	log "on $SFTP_VM: $(ssh_ "$SFTP_VM" "find ~$USER_/data/agent-copy -type f | wc -l") files, $(ssh_ "$SFTP_VM" "du -sh ~$USER_/data/agent-copy | cut -f1")"
	out=$(ssh_ "$VM" '/root/nexus-agent-dev repo fetch /root/copy-sftp.json /var/tmp/nxfetch')
	log "fetch: $out"
	# the fetched copy opened with the 24 words, as on another machine
	out=$(ssh_ "$VM" 'HOME=/var/tmp/nxhome; mkdir -p $HOME; /root/nexus-agent-dev repo open /var/tmp/nxfetch < /root/nxrepo.words' 2>&1 | tail -1)
	log "open: $out"
	local t
	t=$(ssh_ "$VM" '/root/nexus-agent-dev repo list /var/tmp/nxfetch --json' | jq '[.[].time] | max')
	ssh_ "$VM" "/root/nexus-agent-dev repo restore /var/tmp/nxfetch $t /var/tmp/nxrestore" | tail -1 >&2
	out=$(ssh_ "$VM" "diff -r --no-dereference $DATA /var/tmp/nxrestore$DATA >/dev/null && echo identical || echo DIFFERENT")
	log "restore of the fetched copy ($t) vs $DATA: $out"
	[ "$out" = identical ] || die "restored files differ"
	ssh_ "$VM" "rm -rf /var/tmp/nxrepo /var/tmp/nxfetch /var/tmp/nxrestore /var/tmp/nxhome /root/nxrepo.words $DATA/nexus-copy-marker"
	ssh_ "$SFTP_VM" "rm -rf ~$USER_/data/agent-copy"
}

for s in "${@:-sftp}"; do
	"step_$s"
done
