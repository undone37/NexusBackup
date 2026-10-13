#!/bin/sh
# Install or upgrade the NexusBackup agent from an extracted bundle (run as root).
#
#   ./install.sh                         install/upgrade binary, unit, examples, keys
#   ./install.sh --token <T> [--port P]  ... and initialise enrollment
#   echo <T> | ./install.sh --token -    token from stdin (keeps it out of `ps`/history)
#
# Bundle layout (crates/agent-linux/dist/build-bundle.sh): nexus-agent (static musl
# binary), nexus-agent.service, hooks.d/pre/*.example, release-keys/*.pub.
# Works on any systemd distribution; nothing is downloaded.
set -eu

die() {
	echo "install.sh: $*" >&2
	exit 1
}

here=$(cd "$(dirname "$0")" && pwd)
token=
port=
while [ $# -gt 0 ]; do
	case $1 in
	--token)
		[ $# -ge 2 ] || die "--token needs a value"
		token=$2
		shift 2
		;;
	--port)
		[ $# -ge 2 ] || die "--port needs a value"
		port=$2
		shift 2
		;;
	-h | --help)
		sed -n '2,10p' "$0" | sed 's/^# \{0,1\}//'
		exit 0
		;;
	*) die "unknown argument $1" ;;
	esac
done

[ "$(id -u)" = 0 ] || die "must run as root"
[ -x "$here/nexus-agent" ] || die "nexus-agent binary missing in $here"
[ -d /run/systemd/system ] || echo "install.sh: warning: systemd not running; start 'nexus-agent run' yourself" >&2

BIN=/usr/local/sbin/nexus-agent
CONF=/etc/nexus-agent

# binary: atomic replace (a running agent keeps its old inode until restarted)
install -d -m 0755 /usr/local/sbin
install -m 0755 -o root -g root "$here/nexus-agent" "$BIN.new"
mv -f "$BIN.new" "$BIN"

# config tree: root-only; hooks must stay root-owned and not group/world-writable,
# the agent refuses to run them otherwise
install -d -m 0700 -o root -g root "$CONF" "$CONF/hooks.d" "$CONF/hooks.d/pre" "$CONF/hooks.d/post"
install -d -m 0755 -o root -g root "$CONF/release-keys"
nkeys=0
for k in "$here"/release-keys/*.pub; do
	[ -f "$k" ] || continue
	install -m 0644 -o root -g root "$k" "$CONF/release-keys/"
	nkeys=$((nkeys + 1))
done
[ "$nkeys" -gt 0 ] || echo "install.sh: warning: no release keys in the bundle; self-update stays disabled" >&2
for h in "$here"/hooks.d/pre/*.example; do
	[ -f "$h" ] || continue
	install -m 0600 -o root -g root "$h" "$CONF/hooks.d/pre/"
done

# end users of `nexus-agent tui` / `status` (socket root:nexus-agent-ui 0660)
getent group nexus-agent-ui >/dev/null 2>&1 || groupadd -r nexus-agent-ui 2>/dev/null ||
	echo "install.sh: warning: could not create the group nexus-agent-ui" >&2

# LVM snapshots need the device-mapper targets; the unit forbids module loading
if [ -x /usr/sbin/lvm ] || [ -x /sbin/lvm ]; then
	printf 'dm-snapshot\ndm-thin-pool\n' >/etc/modules-load.d/nexus-agent.conf
	modprobe dm-snapshot 2>/dev/null || true
	modprobe dm-thin-pool 2>/dev/null || true
fi

if [ -d /etc/systemd/system ]; then
	install -m 0644 -o root -g root "$here/nexus-agent.service" /etc/systemd/system/nexus-agent.service
	systemctl daemon-reload 2>/dev/null || true
fi

if [ -n "$token" ]; then
	if [ "$token" = - ]; then
		IFS= read -r token || die "no token on stdin"
	fi
	if [ -n "$port" ]; then
		printf '%s\n' "$token" | "$BIN" init --token - --port "$port"
	else
		printf '%s\n' "$token" | "$BIN" init --token -
	fi
fi

if [ -f "$CONF/agent.key" ] && [ -d /run/systemd/system ]; then
	systemctl enable nexus-agent.service
	systemctl restart nexus-agent.service
fi

"$BIN" status || true # exit 3 until the service runs
cat <<EOF

Allow TCP ${port:-7444} from the appliance only (firewalld: a rich rule with the
appliance address; ufw: 'ufw allow from <appliance> to any port ${port:-7444} proto tcp').
Database dumps: see $CONF/hooks.d/pre/*.example, then '$BIN hooks test'
(full path: /usr/local/sbin is not in sudo's secure_path on EL/Fedora).
EOF
