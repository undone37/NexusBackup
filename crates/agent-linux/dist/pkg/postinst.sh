#!/bin/sh
# nexus-agent package: after install / upgrade.
# deb: postinst configure [<old version>]   rpm: %post <count> (1 = install, 2+ = upgrade)
# The unit is installed but not enabled: without `nexus-agent init` there is nothing to serve
# (the unit also has ConditionPathExists=/etc/nexus-agent/agent.key).
set -e

case "${1:-}" in
configure) if [ -n "${2:-}" ]; then upgrade=1; else upgrade=0; fi ;;
1) upgrade=0 ;;
[0-9]*) upgrade=1 ;;
*) exit 0 ;;
esac

# LVM snapshots need the device-mapper targets; the unit forbids module loading
if { [ -x /usr/sbin/lvm ] || [ -x /sbin/lvm ]; } && [ ! -e /etc/modules-load.d/nexus-agent.conf ]; then
	mkdir -p /etc/modules-load.d
	printf 'dm-snapshot\ndm-thin-pool\n' >/etc/modules-load.d/nexus-agent.conf
	modprobe dm-snapshot 2>/dev/null || true
	modprobe dm-thin-pool 2>/dev/null || true
fi

# group for end users of `nexus-agent tui` / `status` (the socket is root:nexus-agent-ui 0660)
if command -v systemd-sysusers >/dev/null 2>&1; then
	systemd-sysusers nexus-agent.conf >/dev/null 2>&1 || true
fi
getent group nexus-agent-ui >/dev/null 2>&1 || groupadd -r nexus-agent-ui 2>/dev/null || true

systemd=0
[ -d /run/systemd/system ] && systemd=1
[ $systemd = 1 ] && systemctl daemon-reload >/dev/null 2>&1 || true

# leftovers of a bundle install (install.sh) would shadow the packaged unit and binary
if [ -e /etc/systemd/system/nexus-agent.service ] || [ -e /usr/local/sbin/nexus-agent ]; then
	echo "nexus-agent: an install.sh installation exists; remove /etc/systemd/system/nexus-agent.service" >&2
	echo "nexus-agent: and /usr/local/sbin/nexus-agent so the packaged agent is used (docs/agent-linux.md)" >&2
fi

if [ $upgrade = 1 ]; then
	[ $systemd = 1 ] && systemctl try-restart nexus-agent.service >/dev/null 2>&1 || true
	exit 0
fi

if [ -f /etc/nexus-agent/fleet-secret ] && [ ! -f /etc/nexus-agent/agent.key ]; then
	# fleet deployment (Ansible & co. put the secret there first): the agent adopts it at start
	chmod 0600 /etc/nexus-agent/fleet-secret
	if [ $systemd = 1 ]; then
		systemctl enable --now nexus-agent.service >/dev/null 2>&1 || true
	fi
	echo "nexus-agent: fleet secret found; service enabled, waiting for the appliance's scan"
	exit 0
fi

if [ -f /etc/nexus-agent/agent.key ]; then
	# reinstalled on an enrolled host (the config survives a removal): serve again
	if [ $systemd = 1 ]; then
		systemctl enable --now nexus-agent.service >/dev/null 2>&1 || true
	fi
	echo "nexus-agent: existing enrollment found in /etc/nexus-agent; service enabled"
	exit 0
fi

cat <<'EOF'

NexusBackup agent installed, not enrolled yet. With the one-time token from the
appliance (Configuration > Agents > New agent), as root:

  nexus-agent init --token -              # paste the token, press Enter
  systemctl enable --now nexus-agent

Fleet deployment: nexus-agent init --fleet-secret - (or the secret in
/etc/nexus-agent/fleet-secret, mode 0600), then systemctl enable --now nexus-agent.

Then click "Enroll" on the appliance. Allow TCP 7444 from the appliance only.
Database dump hooks: /usr/share/doc/nexus-agent/examples/hooks.d/pre/
End users see the backup status with `nexus-agent tui` once they are in the group
nexus-agent-ui (usermod -aG nexus-agent-ui <user>).
Updates come from the package manager (self-update is off for package installs).

EOF
exit 0
