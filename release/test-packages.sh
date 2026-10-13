#!/bin/bash
# Check the packages of release/packages.sh in throwaway containers (rootless podman):
#   .deb   debian:13: install, files/modes, `nexus-agent --version` and status, systemd-analyze
#          verify, reinstall, remove (enrollment kept), purge (gone); lintian (errors fail)
#   .rpm   almalinux:10 and fedora: install, the same checks, rpm -V, erase; rpmlint (errors fail)
#   desktop  nexus-agent-desktop installed with the agent (debian:13, fedora): files, .desktop
#          entries (desktop-file-validate), dependency on nexus-agent, binary --version
#   arm64  binaries run through qemu-user if the host has binfmt for aarch64, else only `file`
#   .msi   msitools: tables, service entries, custom actions, upgrade code, files
#   SHA256SUMS matches
#
#   release/test-packages.sh [DIR]      (default target/packages)
#
# Needs network for the distribution images and their tools (cached as localhost images).
# Without podman it prints SKIP and succeeds.
set -euo pipefail
cd "$(dirname "$0")/.."
command -v podman >/dev/null || {
	echo "SKIP: podman not available" >&2
	exit 0
}
dir=$(realpath "${1:-target/packages}")
[ -f "$dir/SHA256SUMS" ] || {
	echo "no $dir/SHA256SUMS: run release/packages.sh first" >&2
	exit 1
}

DEBIAN_IMAGE=${DEBIAN_IMAGE:-docker.io/library/debian:trixie}
ALMA_IMAGE=${ALMA_IMAGE:-quay.io/almalinuxorg/almalinux:10}
FEDORA_IMAGE=${FEDORA_IMAGE:-registry.fedoraproject.org/fedora:43}
MSITOOLS_BASE=${MSITOOLS_BASE:-registry.fedoraproject.org/fedora:43}

builder() { # as in release/packages.sh
	local tag
	tag=localhost/$1:$(printf '%s' "$2" | sha256sum | cut -c1-12)
	podman image exists "$tag" || printf '%s\n' "$2" | podman build -q -t "$tag" -f - . >/dev/null
	echo "$tag"
}
crun() { # crun IMAGE ARGS...: release/package-checks.sh ARGS in a throwaway container
	podman run --rm --security-opt label=disable -v "$dir:/pkgs:ro" \
		-v "$PWD/release/package-checks.sh:/checks.sh:ro" \
		-v "$PWD/crates/agent-linux/dist/pkg/rpmlintrc:/rpmlintrc:ro" "$1" bash /checks.sh "${@:2}"
}
fails=()
step() { # step NAME COMMAND...
	echo "== $1"
	if "${@:2}"; then echo "-- ok: $1"; else
		echo "-- FAILED: $1"
		fails+=("$1")
	fi
}

step "SHA256SUMS" bash -c "cd '$dir' && sha256sum -c --quiet SHA256SUMS"

shopt -s nullglob
debs=("$dir"/*.deb)
rpms=("$dir"/*.rpm)
msis=("$dir"/*.msi)
[ ${#debs[@]} -gt 0 ] && [ ${#rpms[@]} -gt 0 ] || {
	echo "no .deb/.rpm in $dir" >&2
	exit 1
}

deb_img=$(builder nexus-pkgtest-debian "FROM $DEBIAN_IMAGE
RUN apt-get update && apt-get install -y --no-install-recommends systemd lintian file desktop-file-utils && rm -rf /var/lib/apt/lists/*")
alma_img=$(builder nexus-pkgtest-alma "FROM $ALMA_IMAGE
RUN dnf -y -q install systemd file && dnf clean all")
fedora_img=$(builder nexus-pkgtest-fedora "FROM $FEDORA_IMAGE
RUN dnf -y -q install systemd rpmlint file desktop-file-utils && dnf clean all")

for f in "${debs[@]}"; do
	b=$(basename "$f")
	step "lintian $b" crun "$deb_img" lintian "/pkgs/$b"
	case $b in
	nexus-agent-desktop_*_amd64.deb)
		agent=$(basename "$(ls "$dir"/nexus-agent_*_amd64.deb)")
		step "install $b on debian:13" crun "$deb_img" desktop-deb "/pkgs/$agent" "/pkgs/$b"
		;;
	nexus-agent_*_amd64.deb) step "install $b on debian:13" crun "$deb_img" deb "/pkgs/$b" ;;
	esac
done
for f in "${rpms[@]}"; do
	b=$(basename "$f")
	step "rpmlint $b" crun "$fedora_img" rpmlint "/pkgs/$b"
	case $b in
	nexus-agent-desktop-*.x86_64.rpm)
		agent=$(basename "$(ls "$dir"/nexus-agent-[0-9]*.x86_64.rpm)")
		step "install $b on fedora" crun "$fedora_img" desktop-rpm "/pkgs/$agent" "/pkgs/$b"
		;;
	nexus-agent-*.x86_64.rpm)
		step "install $b on almalinux:10" crun "$alma_img" rpm "/pkgs/$b"
		step "install $b on fedora" crun "$fedora_img" rpm "/pkgs/$b"
		;;
	esac
done

# arm64: the static binary from the .deb; runs under qemu-user when the host can
arm64_bin() {
	local f=$1 t
	t=$(mktemp -d)
	podman run --rm --security-opt label=disable -v "$dir:/pkgs:ro" -v "$t:/out" "$deb_img" \
		sh -c "dpkg-deb -x /pkgs/$(basename "$f") /x && cp /x/usr/bin/nexus-agent /out/ && file -b /out/nexus-agent" |
		tee "$t/file"
	grep -q 'ARM aarch64' "$t/file" && grep -q static "$t/file" || return 1
	if [ -e /proc/sys/fs/binfmt_misc/qemu-aarch64 ]; then
		"$t/nexus-agent" --version | grep -q '^nexus-agent ' || return 1
		echo "ran under qemu-user: $("$t/nexus-agent" --version)"
	else
		echo "no binfmt for aarch64 on this host: --version not run"
	fi
	rm -rf "$t"
}
for f in "$dir"/nexus-agent_*_arm64.deb; do step "arm64 binary in $(basename "$f")" arm64_bin "$f"; done

# MSI tables (msitools); a real Windows install is untested (docs/agent-windows.md)
# shellcheck disable=SC2016 # expanded by the bash inside the container
msi_checks='
set -euo pipefail
m=$1
fail() { echo "FAIL: $*" >&2; exit 1; }
tables=$(msiinfo tables "$m")
for t in File Component Directory Feature ServiceInstall ServiceControl CustomAction Upgrade Property InstallExecuteSequence; do
	grep -qx "$t" <<<"$tables" || fail "table $t missing"
done
msiinfo export "$m" ServiceInstall | tee /tmp/si
grep -P "^AgentService\tNexusAgent\tNexusBackup Agent\t16\t2\t1\t" /tmp/si >/dev/null || fail "ServiceInstall: own process, auto start, normal errors"
grep -q "LocalSystem" /tmp/si && grep -qP "\tservice\t" /tmp/si || fail "ServiceInstall: LocalSystem, argument service"
msiinfo export "$m" ServiceControl | tee /tmp/sc
# Event: start on install (1) + stop on install and uninstall (2|32) + delete on uninstall (128) = 163
grep -P "^AgentServiceControl\tNexusAgent\t163\t" /tmp/sc >/dev/null || fail "ServiceControl events"
msiinfo export "$m" CustomAction | tee /tmp/ca
grep -P "^ServiceSetup\t3090\tAgentExe\tservice-setup" /tmp/ca >/dev/null || fail "ServiceSetup: deferred, no impersonation, exe from file"
grep -P "^PurgeData\t3154\tAgentExe\tpurge-data --yes" /tmp/ca >/dev/null || fail "PurgeData: deferred, no impersonation, ignore result"
grep -P "^FleetInit\t3154\tAgentExe\tinit --fleet-secret \"\[FLEETSECRET\]\"" /tmp/ca >/dev/null || fail "FleetInit: deferred, no impersonation, ignore result"
msiinfo export "$m" InstallExecuteSequence | tee /tmp/seq
grep -P "^ServiceSetup\tNOT REMOVE=\"ALL\"\t" /tmp/seq >/dev/null || fail "ServiceSetup condition"
grep -P "^PurgeData\tREMOVE=\"ALL\" AND PURGE=\"1\" AND NOT UPGRADINGPRODUCTCODE\t" /tmp/seq >/dev/null || fail "PurgeData condition"
grep -P "^FleetInit\tFLEETSECRET AND NOT REMOVE=\"ALL\"\t" /tmp/seq >/dev/null || fail "FleetInit condition"
msiinfo export "$m" Upgrade | grep -qi "F0236C93-DDCE-4B09-A197-525C84656168" || fail "UpgradeCode"
msiinfo export "$m" Property | tee /tmp/prop | grep -P "^(ProductVersion|UpgradeCode|ARPNOMODIFY|SecureCustomProperties)\t"
! grep -qi token /tmp/prop || fail "token property in the MSI"
grep -qP "^MsiHiddenProperties\tFLEETSECRET$" /tmp/prop || fail "FLEETSECRET not hidden from the MSI log"
msiinfo suminfo "$m" | grep -E "^(Template|Title|Subject)"
msiinfo suminfo "$m" | grep -q "^Template: x64;" || fail "not an x64 package"
rm -rf /tmp/x && mkdir /tmp/x && msiextract -C /tmp/x "$m" | sort | tee /tmp/files
grep -q "NexusBackup Agent/nexus-agent.exe$" /tmp/files || fail "nexus-agent.exe"
grep -q "NexusBackup Agent/package-managed$" /tmp/files || fail "package marker"
grep -q "NexusAgent/config/release-keys/.*\.pub$" /tmp/files || fail "release keys"
grep -q "NexusBackup Agent/nexus-agent-gui.exe$" /tmp/files || fail "nexus-agent-gui.exe"
msiinfo export "$m" Registry | tee /tmp/reg
grep -P "\t2\tSoftware\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\tNexusBackupAgentGui\t" /tmp/reg >/dev/null || fail "GUI Run key (HKLM)"
msiinfo export "$m" Shortcut | tee /tmp/sh
grep -P "^GuiStartMenu\tProgramMenuFolder\t[^\t]*NexusBackup Agent\tGui\t\[#GuiExe\]\t--open\t" /tmp/sh >/dev/null || fail "GUI Start menu shortcut"
echo "msi tables: ok"
'
msi_img=$(builder nexus-msitools "FROM $MSITOOLS_BASE
RUN dnf -y install --setopt=install_weak_deps=False msitools && dnf clean all")
for f in "${msis[@]}"; do
	step "MSI tables $(basename "$f")" podman run --rm --security-opt label=disable -v "$dir:/pkgs:ro" "$msi_img" \
		bash -c "$msi_checks" check "/pkgs/$(basename "$f")"
done

if [ ${#fails[@]} -gt 0 ]; then
	printf 'FAILED: %s\n' "${fails[@]}" >&2
	exit 1
fi
echo "all package checks passed"
