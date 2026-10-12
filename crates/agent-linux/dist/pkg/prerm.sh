#!/bin/sh
# nexus-agent package: before removal.
# deb: prerm remove | upgrade <new>   rpm: %preun <count> (0 = erase, 1 = upgrade)
# Only a real removal stops the service; an upgrade restarts it in postinst.
set -e

case "${1:-}" in
remove | 0)
	if [ -d /run/systemd/system ]; then
		systemctl disable --now nexus-agent.service >/dev/null 2>&1 || true
	fi
	;;
esac
exit 0
