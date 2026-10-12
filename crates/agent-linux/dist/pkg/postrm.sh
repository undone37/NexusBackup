#!/bin/sh
# nexus-agent package: after removal.
# deb: postrm remove | purge | upgrade ...   rpm: %postun <count> (0 = erase, 1 = upgrade)
# A removal keeps /etc/nexus-agent (agent key, certificates): reinstalling continues with
# the same enrollment. Only `apt purge` deletes the enrollment and the agent's state.
set -e

case "${1:-}" in
remove | 0)
	rm -f /etc/modules-load.d/nexus-agent.conf
	if [ -d /run/systemd/system ]; then
		systemctl daemon-reload >/dev/null 2>&1 || true
	fi
	;;
purge)
	rm -f /etc/modules-load.d/nexus-agent.conf
	rm -rf /etc/nexus-agent /var/lib/nexus-agent
	;;
esac
exit 0
