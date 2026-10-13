#!/bin/bash
# In-container half of release/test-packages.sh (runs as root in a throwaway container,
# packages mounted at /pkgs).
#
#   package-checks.sh deb FILE.deb      install, check, remove (enrollment kept), purge
#   package-checks.sh rpm FILE.rpm      install, check, erase
#   package-checks.sh desktop-deb|desktop-rpm AGENT DESKTOP
#                                       nexus-agent-desktop: refused alone, installed with the agent
#   package-checks.sh lintian FILE.deb  errors fail, warnings are listed
#   package-checks.sh rpmlint FILE.rpm  errors fail, warnings are listed
set -euo pipefail

fail() {
	echo "FAIL: $*" >&2
	exit 1
}

installed() { # installed deb|rpm
	local v
	v=$(nexus-agent --version)
	echo "$v"
	[[ $v == "nexus-agent "* ]] || fail "--version: $v"
	[ "$(stat -c %a:%U /usr/bin/nexus-agent)" = 755:root ] || fail "binary mode"
	[ "$(stat -c %a:%U /etc/nexus-agent)" = 700:root ] || fail "/etc/nexus-agent mode"
	for d in hooks.d hooks.d/pre hooks.d/post; do
		[ "$(stat -c %a /etc/nexus-agent/$d)" = 700 ] || fail "$d mode"
	done
	ls /etc/nexus-agent/release-keys/*.pub >/dev/null || fail "no release keys"
	# listed, not necessarily on disk: container images install without docs
	{ dpkg -L nexus-agent 2>/dev/null || rpm -ql nexus-agent; } >/tmp/files
	grep -qx /usr/share/doc/nexus-agent/examples/hooks.d/pre/10-postgresql.example /tmp/files || fail "hook examples"
	grep -qx /usr/share/doc/nexus-agent/copyright /tmp/files || fail "copyright"
	grep -qx "ExecStart=/usr/bin/nexus-agent run" /usr/lib/systemd/system/nexus-agent.service || fail "unit ExecStart"
	! grep -q /usr/local /usr/lib/systemd/system/nexus-agent.service || fail "unit still names /usr/local"
	[ "$(cat /usr/lib/nexus-agent/package-managed)" = "$1" ] || fail "package marker"
	getent group nexus-agent-ui >/dev/null || fail "group nexus-agent-ui"
	# exit 3: the service is not running (not enrolled); root still gets the local diagnostics
	rc=0
	nexus-agent status >/tmp/status || rc=$?
	[ $rc = 3 ] || fail "status exit code $rc (want 3: service not running)"
	cat /tmp/status
	grep -q "^installed from: $1 package" /tmp/status || fail "status: package"
	grep -q "^self-update: off; installed from a $1 package" /tmp/status || fail "status: self-update"
	if command -v systemd-analyze >/dev/null; then
		# no network-online.target etc. in a container: only unit syntax/ExecStart errors matter
		systemd-analyze verify /usr/lib/systemd/system/nexus-agent.service 2>&1 | tee /tmp/verify
		! grep -iE "nexus-agent.service:.*(unknown|invalid|failed|not executable|missing)" /tmp/verify ||
			fail "systemd-analyze verify"
	fi
	! systemctl is-enabled nexus-agent.service >/dev/null 2>&1 || fail "unit enabled before enrollment"
	echo "installed: ok"
}

mode=$1 f=$2
case $mode in
deb)
	apt-get install -y -q "$f" >/tmp/install.log 2>&1 || {
		cat /tmp/install.log
		fail "apt install"
	}
	cat /tmp/install.log | sed -n '/NexusBackup agent installed/,$p'
	grep -q "nexus-agent init --token -" /tmp/install.log || fail "no enrollment hint"
	installed deb
	# reinstall of the same version = upgrade path of the maintainer scripts
	apt-get install -y -q --reinstall "$f" >/dev/null 2>&1 || fail "reinstall"
	echo fake >/etc/nexus-agent/agent.key
	dpkg -r nexus-agent >/dev/null
	[ ! -e /usr/bin/nexus-agent ] || fail "binary left after remove"
	[ -f /etc/nexus-agent/agent.key ] || fail "remove deleted the enrollment"
	dpkg -P nexus-agent >/dev/null
	[ ! -e /etc/nexus-agent ] || fail "purge left /etc/nexus-agent"
	echo "remove/purge: ok"
	;;
rpm)
	# not -q: dnf 4 then hides scriptlet output
	dnf -y install "$f" >/tmp/install.log 2>&1 || {
		cat /tmp/install.log
		fail "dnf install"
	}
	sed -n '/NexusBackup agent installed/,$p' /tmp/install.log
	grep -q "nexus-agent init --token -" /tmp/install.log || fail "no enrollment hint"
	installed rpm
	rpm -V nexus-agent || fail "rpm -V"
	echo fake >/etc/nexus-agent/agent.key
	rpm -e nexus-agent
	[ ! -e /usr/bin/nexus-agent ] || fail "binary left after erase"
	[ -f /etc/nexus-agent/agent.key ] || fail "erase deleted the enrollment"
	echo "erase: ok"
	;;
desktop-deb | desktop-rpm)
	# the desktop package alone must not install: it needs the agent
	if [ "$mode" = desktop-deb ]; then
		! dpkg -i "$3" >/dev/null 2>&1 || fail "installed without nexus-agent"
		dpkg -r nexus-agent-desktop >/dev/null 2>&1 || true
		apt-get install -y -q "$2" "$3" >/tmp/install.log 2>&1 || {
			cat /tmp/install.log
			fail "apt install"
		}
	else
		! rpm -i "$3" >/dev/null 2>&1 || fail "installed without nexus-agent"
		dnf -y install "$2" "$3" >/tmp/install.log 2>&1 || {
			cat /tmp/install.log
			fail "dnf install"
		}
	fi
	grep -q "usermod -aG nexus-agent-ui" /tmp/install.log || fail "no group hint"
	[ "$(stat -c %a:%U /usr/bin/nexus-agent-gui)" = 755:root ] || fail "binary mode"
	nexus-agent-gui --version | grep -q '^nexus-agent-gui ' || fail "--version"
	for d in /usr/share/applications/nexus-agent-gui.desktop /etc/xdg/autostart/nexus-agent-gui.desktop; do
		desktop-file-validate "$d" || fail "$d"
	done
	grep -qx "Exec=nexus-agent-gui --open" /usr/share/applications/nexus-agent-gui.desktop || fail "menu Exec"
	grep -qx "Exec=nexus-agent-gui" /etc/xdg/autostart/nexus-agent-gui.desktop || fail "autostart Exec"
	[ -f /usr/share/icons/hicolor/scalable/apps/nexus-agent-gui.svg ] || fail "icon"
	! getent group nexus-agent-ui | grep -q ':.\+$' || fail "postinst added users to nexus-agent-ui"
	echo "desktop: ok"
	;;
lintian)
	lintian --no-tag-display-limit --display-info "$f" | tee /tmp/lintian || true
	! grep -q '^E: ' /tmp/lintian || fail "lintian errors"
	echo "lintian: no errors ($(grep -c '^W: ' /tmp/lintian || true) warnings)"
	;;
rpmlint)
	# the agent filters (static binary) do not apply to the desktop package (glibc binary)
	rc=/rpmlintrc
	[[ $(basename "$f") == nexus-agent-desktop-* ]] && rc=/dev/null
	rpmlint -r "$rc" "$f" | tee /tmp/rpmlint || true
	! grep -q ': E: ' /tmp/rpmlint || fail "rpmlint errors"
	echo "rpmlint: no errors ($(grep -c ': W: ' /tmp/rpmlint || true) warnings)"
	;;
*) fail "usage: package-checks.sh deb|rpm|lintian|rpmlint FILE" ;;
esac
