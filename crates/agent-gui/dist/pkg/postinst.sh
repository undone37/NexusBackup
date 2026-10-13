#!/bin/sh
# nexus-agent-desktop package: after install / upgrade. Adds nobody to any group on purpose:
# the administrator decides who may see the backup status (docs/agent-linux.md).
set -e
case "${1:-}" in
configure | 1) ;;
*) exit 0 ;;
esac
command -v gtk-update-icon-cache >/dev/null && gtk-update-icon-cache -q /usr/share/icons/hicolor 2>/dev/null || true
cat <<'EOF'
NexusBackup desktop agent installed: nexus-agent-gui starts with the next desktop login.
Users who should see the backup status need the group nexus-agent-ui:
  usermod -aG nexus-agent-ui <user>      (then log out and in again)
GNOME shows the tray icon only with the AppIndicator extension; the application
menu entry "NexusBackup Agent" opens the window everywhere.
EOF
