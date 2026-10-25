#!/bin/bash
# Agent packages for the release page: nexus-agent .deb + .rpm (x86_64, aarch64), the desktop
# UI nexus-agent-desktop .deb + .rpm (x86_64, aarch64) and the Windows agent (with its desktop
# UI) as an MSI, plus SHA256SUMS. Everything runs in rootless podman containers
# (official Rust image, nfpm, Fedora msitools); nothing is installed on the host.
#
#   release/packages.sh [--test-key] [--no-arm64] [--no-msi]
#
#   --test-key  pin release/testkey/TEST-cosign.pub (lab builds); default: release/keys/*.pub
#   --no-arm64  skip the aarch64 build
#   --no-msi    skip the Windows agent and its MSI
#
# Output: target/packages/{nexus-agent_<v>-1_amd64.deb, nexus-agent-<v>-1.x86_64.rpm,
# nexus-agent_<v>-1_arm64.deb, nexus-agent-<v>-1.aarch64.rpm, nexus-agent-desktop_<v>-1_<arch>.deb,
# nexus-agent-desktop-<v>-1.<arch>.rpm, nexus-agent-<v>-x64.msi, SHA256SUMS}.
# The version is the agent's crate version (what self-update compares). Not signed here:
# the release manager signs the files with release/sign.sh sign-blobs (docs/release.md).
# Checks: release/test-packages.sh.
set -euo pipefail
cd "$(dirname "$0")/.."

RUST_IMAGE=${RUST_IMAGE:-docker.io/library/rust:1.93-slim-trixie}
NFPM_IMAGE=${NFPM_IMAGE:-docker.io/goreleaser/nfpm:v2.48.0@sha256:7d4cea73774728a1448af2dc248785fd17882005b0539f43d07f78a69db59368}
MSITOOLS_BASE=${MSITOOLS_BASE:-registry.fedoraproject.org/fedora:43}

test_key=0
arm64=1
msi=1
for a in "$@"; do
	case $a in
	--test-key) test_key=1 ;;
	--no-arm64) arm64=0 ;;
	--no-msi) msi=0 ;;
	*)
		sed -n '2,16p' "$0" | sed 's/^# \{0,1\}//' >&2
		exit 2
		;;
	esac
done

die() {
	echo "packages.sh: $*" >&2
	exit 1
}

# cached builder image, tagged by the hash of its definition (as crates/agent-windows/build.sh)
builder() { # builder NAME CONTAINERFILE -> prints the tag
	local tag
	tag=localhost/$1:$(printf '%s' "$2" | sha256sum | cut -c1-12)
	podman image exists "$tag" || printf '%s\n' "$2" | podman build -q -t "$tag" -f - . >/dev/null
	echo "$tag"
}

if [ $test_key = 1 ]; then
	keys=(release/testkey/TEST-cosign.pub)
	key_names=(TEST-KEY-DO-NOT-SHIP.pub)
else
	shopt -s nullglob
	keys=(release/keys/*.pub)
	shopt -u nullglob
	[ ${#keys[@]} -gt 0 ] || die "no release keys in release/keys (use --test-key for lab builds)"
	key_names=()
	for k in "${keys[@]}"; do key_names+=("$(basename "$k")"); done
fi

version=$(sed -n 's/^version = "\(.*\)"/\1/p' crates/agent-linux/Cargo.toml | head -1)
wversion=$(sed -n 's/^version = "\(.*\)"/\1/p' crates/agent-windows/Cargo.toml | head -1)
out=target/packages
rm -rf "$out"
mkdir -p "$out"

# --- Linux: static musl binaries --------------------------------------------------------
# The only C/asm in the tree (ring, blake3) is freestanding: gcc builds it for musl
# (x86_64) and the aarch64 GNU cross compiler for aarch64-musl; Rust links its
# self-contained musl.
linux_img=$(builder nexus-agent-linux-build "FROM $RUST_IMAGE
RUN apt-get update && apt-get install -y --no-install-recommends gcc-aarch64-linux-gnu libc6-dev-arm64-cross file \\
    && rm -rf /var/lib/apt/lists/* && rustup target add x86_64-unknown-linux-musl aarch64-unknown-linux-musl")
targets=(x86_64-unknown-linux-musl)
[ $arm64 = 1 ] && targets+=(aarch64-unknown-linux-musl)
lrun() {
	podman run --rm --security-opt label=disable -v "$PWD:/src" -w /src \
		-v nexus-cargo-registry:/usr/local/cargo/registry \
		-e CARGO_TARGET_DIR=/src/target/linux-container \
		-e CC_x86_64_unknown_linux_musl=gcc \
		-e CC_aarch64_unknown_linux_musl=aarch64-linux-gnu-gcc \
		-e CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=aarch64-linux-gnu-gcc \
		-e CARGO_PROFILE_RELEASE_LTO=true \
		-e CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1 \
		-e CARGO_PROFILE_RELEASE_OPT_LEVEL=s \
		-e CARGO_PROFILE_RELEASE_STRIP=symbols \
		"$linux_img" "$@"
}
for t in "${targets[@]}"; do
	lrun cargo build --locked -p agent-linux --release --target "$t"
done

for t in "${targets[@]}"; do
	bin=target/linux-container/$t/release/nexus-agent
	case $t in
	x86_64-*) arch=amd64 elf='x86-64' ;;
	aarch64-*) arch=arm64 elf='ARM aarch64' ;;
	esac
	size=$(stat -c %s "$bin")
	desc=$(lrun file -b "$bin")
	[[ $desc == *static* && $desc == *"$elf"* ]] || die "$bin: $desc"
	grep -aq "NEXUS-AGENT-VERSION=$version" "$bin" || die "$bin carries no version marker $version"

	stage=$out/stage-$arch
	mkdir -p "$stage/release-keys" "$stage/hooks.d/pre"
	install -m 0755 "$bin" "$stage/nexus-agent"
	sed 's|/usr/local/sbin/nexus-agent|/usr/bin/nexus-agent|g' crates/agent-linux/dist/nexus-agent.service \
		>"$stage/nexus-agent.service"
	install -m 0644 crates/agent-linux/dist/pkg/nfpm.yaml "$stage/"
	install -m 0755 crates/agent-linux/dist/pkg/{postinst,prerm,postrm}.sh "$stage/"
	install -m 0644 crates/agent-linux/dist/pkg/lintian-overrides "$stage/"
	install -m 0644 crates/agent-linux/dist/pkg/sysusers.conf "$stage/"
	cat >"$stage/changelog.yml" <<-EOF
		- semver: $version-1
		  date: $(git log -1 --format=%cI 2>/dev/null || date -u +%FT%TZ)
		  packager: NexusBackup maintainers <undone37@users.noreply.github.com>
		  changes:
		    - note: "nexus-agent $version, see https://github.com/undone37/NexusBackup/releases"
	EOF
	install -m 0644 docs/agent-linux.md "$stage/README.md"
	install -m 0644 crates/agent-linux/dist/hooks.d/pre/*.example "$stage/hooks.d/pre/"
	for e in crates/agent-linux/dist/hooks.d/pre/*.example; do
		grep -q "src: hooks.d/pre/$(basename "$e")$" crates/agent-linux/dist/pkg/nfpm.yaml ||
			die "$(basename "$e") is not listed in crates/agent-linux/dist/pkg/nfpm.yaml"
	done
	for i in "${!keys[@]}"; do install -m 0644 "${keys[$i]}" "$stage/release-keys/${key_names[$i]}"; done
	{
		echo "Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/"
		echo "Upstream-Name: NexusBackup"
		echo "Source: https://github.com/undone37/NexusBackup"
		echo
		echo "Files: *"
		echo "Copyright: NexusBackup contributors"
		echo "License: AGPL-3.0-only"
		sed 's/^$/./; s/^/ /' LICENSE
	} >"$stage/copyright"
	for p in deb rpm; do
		echo "$p" >"$stage/package-managed"
		podman run --rm --security-opt label=disable -v "$PWD/$stage:/stage" -v "$PWD/$out:/out" -w /stage \
			-e PKG_ARCH="$arch" -e PKG_VERSION="$version" \
			"$NFPM_IMAGE" pkg --config /stage/nfpm.yaml --packager "$p" --target /out/
	done
	cp "$stage/copyright" "$out/copyright"
	sed "s/semver: $version-1/semver: @GVERSION@-1/; s/nexus-agent $version/nexus-agent-desktop @GVERSION@/" \
		"$stage/changelog.yml" >"$out/changelog-desktop.yml"
	rm -rf "$stage"
done

# --- Desktop UI: nexus-agent-gui (glibc, crates/agent-gui/build.sh) -----------------------
gui_args=()
[ $arm64 = 1 ] || gui_args+=(--no-arm64)
[ $msi = 1 ] || gui_args+=(--no-windows)
crates/agent-gui/build.sh "${gui_args[@]}"
gversion=$(sed -n 's/^version = "\(.*\)"/\1/p' crates/agent-gui/Cargo.toml | head -1)
for t in "${targets[@]}"; do
	case $t in
	x86_64-*) arch=amd64 ;;
	aarch64-*) arch=arm64 ;;
	esac
	stage=$out/stage-desktop-$arch
	mkdir -p "$stage"
	install -m 0755 target/agent-dist/gui/linux-$arch/nexus-agent-gui "$stage/"
	install -m 0644 crates/agent-gui/dist/*.desktop crates/agent-gui/dist/nexus-agent-gui.svg "$stage/"
	sed "s/@VERSION@/$version/" crates/agent-gui/dist/pkg/nfpm.yaml >"$stage/nfpm.yaml"
	install -m 0755 crates/agent-gui/dist/pkg/postinst.sh "$stage/"
	sed "s/@GVERSION@/$gversion/g" "$out/changelog-desktop.yml" >"$stage/changelog.yml"
	cp "$out/copyright" "$stage/copyright"
	for p in deb rpm; do
		podman run --rm --security-opt label=disable -v "$PWD/$stage:/stage" -v "$PWD/$out:/out" -w /stage \
			-e PKG_ARCH="$arch" -e PKG_VERSION="$gversion" \
			"$NFPM_IMAGE" pkg --config /stage/nfpm.yaml --packager "$p" --target /out/
	done
	rm -rf "$stage"
done
rm -f "$out/copyright" "$out/changelog-desktop.yml"

# --- Windows: nexus-agent.exe + MSI ------------------------------------------------------
if [ $msi = 1 ]; then
	if [ $test_key = 1 ]; then
		crates/agent-windows/build.sh --test-key
	else
		crates/agent-windows/build.sh
	fi
	stage=$out/stage-msi
	mkdir -p "$stage"
	cp target/agent-dist/windows/nexus-agent.exe target/agent-dist/gui/windows/nexus-agent-gui.exe crates/agent-gui/dist/nexus-agent-gui.ico \
		crates/agent-windows/dist/nexus-agent.wxs "$stage/"
	cp target/agent-dist/windows/release-keys/*.pub "$stage/"
	install -m 0644 docs/agent-windows.md "$stage/README.md"
	echo msi >"$stage/package-managed.msi"
	# one component per pinned key (names vary: rotation, TEST key)
	n=0
	for f in keys keyrefs; do printf '<?xml version="1.0" encoding="utf-8"?>\n<Include>\n' >"$stage/$f.wxi"; done
	for k in "$stage"/*.pub; do
		n=$((n + 1))
		echo "  <Component Id=\"Key$n\" Guid=\"*\" Win64=\"yes\"><File Id=\"Key$n\" Name=\"$(basename "$k")\" Source=\"$(basename "$k")\" KeyPath=\"yes\"/></Component>" >>"$stage/keys.wxi"
		echo "  <ComponentRef Id=\"Key$n\"/>" >>"$stage/keyrefs.wxi"
	done
	for f in keys keyrefs; do echo '</Include>' >>"$stage/$f.wxi"; done
	msi_img=$(builder nexus-msitools "FROM $MSITOOLS_BASE
RUN dnf -y install --setopt=install_weak_deps=False msitools && dnf clean all")
	name=nexus-agent-$wversion-x64.msi
	podman run --rm --security-opt label=disable -v "$PWD/$stage:/stage" -w /stage "$msi_img" \
		sh -c "wixl -a x64 -D Version=$wversion -o /stage/$name nexus-agent.wxs &&
		init=\$(msiinfo export /stage/$name InstallExecuteSequence | awk -F'\t' '\$1 == \"InstallInitialize\" {print \$3}' | tr -d '\r') &&
		msibuild /stage/$name -q \"UPDATE InstallExecuteSequence SET Sequence = \$((init + 1)) WHERE Action = 'RemoveExistingProducts'\" &&
		msibuild /stage/$name -q \"UPDATE InstallExecuteSequence SET Sequence = 2001 WHERE Action = 'PurgeData'\" &&
		msibuild /stage/$name -q \"UPDATE CustomAction SET Type = 11346 WHERE Action = 'FleetInit'\" &&
		msibuild /stage/$name -q \"UPDATE File SET Version = '$wversion.0' WHERE File = 'AgentExe'\" &&
		msibuild /stage/$name -q \"UPDATE File SET Version = '$gversion.0' WHERE File = 'GuiExe'\""
	# ^ wixl ignores After= relative to standard actions and appends RemoveExistingProducts and PurgeData after
	#   the last custom action (found on Windows Server 2022):
	#   - RemoveExistingProducts inside the install script without InstallExecute: error 2613, every install
	#     failed. Right after InstallInitialize (WiX `afterInstallInitialize`): the old version is removed in the
	#     same transaction as the new one is installed, so a failed upgrade rolls back to the old version (#96: right
	#     after InstallValidate the removal committed on its own and a 1603 left the host without an agent).
	#   - PurgeData after RemoveFiles: nexus-agent.exe was gone, error 1721, PURGE=1 never deleted anything.
	#     2001 = right after DeleteServices, before RemoveFiles (3500).
	#   wixl also drops HideTarget: FleetInit (3154 = deferred, no impersonation, exe from a file) gets
	#   msidbCustomActionTypeHideTarget (0x2000) = 11346, or the verbose log shows the fleet secret in its
	#   CustomActionSchedule line (MsiHiddenProperties does not cover expanded targets).
	#   wixl leaves File.Version empty: an existing file with a version resource (the GUI has one) beats an
	#   "unversioned" new one, so a major upgrade kept nothing and RemoveExistingProducts deleted the GUI
	#   (found with a 0.1.0 -> 0.1.1 upgrade on Windows Server 2022). Both executables get their versions.
	mv "$stage/$name" "$out/"
	rm -rf "$stage"
fi

(cd "$out" && shopt -s nullglob && sha256sum -- *.deb *.rpm *.msi >SHA256SUMS)
cat "$out/SHA256SUMS"

# --- Agent release tree for the appliance (Phase 27, docs/agent-update-plan.md) -------------
# agent-release/<version>/{linux-<arch>/..., windows-x64/...} + manifest.json (unsigned; the
# release manager signs it offline: release/sign.sh sign-agent-release) and the same as
# nexus-agent-release-<version>.tar. The appliance image ships it from os/agent-release/.
rel=$out/agent-release/$version
mkdir -p "$rel"
arts=()
add() { # add SRC NAME KIND OS ARCH VERSION
	install -D -m 0644 "$1" "$rel/$2"
	arts+=("$(printf '{"name": "%s", "kind": "%s", "os": "%s", "arch": "%s", "version": "%s", "size": %s, "sha256": "%s"}' \
		"$2" "$3" "$4" "$5" "$6" "$(stat -c %s "$1")" "$(sha256sum "$1" | cut -d' ' -f1)")")
}
for t in "${targets[@]}"; do
	case $t in
	x86_64-*) arch=x86_64 deb=amd64 ;;
	aarch64-*) arch=aarch64 deb=arm64 ;;
	esac
	d=linux-$arch
	add "target/linux-container/$t/release/nexus-agent" "$d/nexus-agent" binary linux "$arch" "$version"
	add "$out/nexus-agent_${version}-1_$deb.deb" "$d/nexus-agent_${version}-1_$deb.deb" deb linux "$arch" "$version"
	add "$out/nexus-agent-$version-1.$arch.rpm" "$d/nexus-agent-$version-1.$arch.rpm" rpm linux "$arch" "$version"
	add "$out/nexus-agent-desktop_${gversion}-1_$deb.deb" "$d/nexus-agent-desktop_${gversion}-1_$deb.deb" desktop-deb linux "$arch" "$gversion"
	add "$out/nexus-agent-desktop-$gversion-1.$arch.rpm" "$d/nexus-agent-desktop-$gversion-1.$arch.rpm" desktop-rpm linux "$arch" "$gversion"
	# the install bundle (as crates/agent-linux/dist/build-bundle.sh lays it out)
	b=$out/stage-bundle/nexus-agent-$version-$arch
	mkdir -p "$b/release-keys" "$b/hooks.d/pre"
	install -m 0755 "target/linux-container/$t/release/nexus-agent" "$b/nexus-agent"
	install -m 0644 crates/agent-linux/dist/nexus-agent.service "$b/"
	install -m 0755 crates/agent-linux/dist/install.sh "$b/"
	install -m 0644 crates/agent-linux/dist/hooks.d/pre/*.example "$b/hooks.d/pre/"
	install -m 0644 docs/agent-linux.md "$b/README.md"
	for i in "${!keys[@]}"; do install -m 0644 "${keys[$i]}" "$b/release-keys/${key_names[$i]}"; done
	echo "$version" >"$b/nexus-agent.version"
	tar --sort=name --owner=0 --group=0 --numeric-owner --mtime="@$(git log -1 --format=%ct 2>/dev/null || echo 0)" \
		-C "$out/stage-bundle" -czf "$out/stage-bundle/nexus-agent-$version-$arch.tar.gz" "nexus-agent-$version-$arch"
	add "$out/stage-bundle/nexus-agent-$version-$arch.tar.gz" "$d/nexus-agent-$version-$arch.tar.gz" bundle linux "$arch" "$version"
done
rm -rf "$out/stage-bundle"
if [ $msi = 1 ]; then
	add target/agent-dist/windows/nexus-agent.exe windows-x64/nexus-agent.exe binary windows x86_64 "$wversion"
	add "$out/nexus-agent-$wversion-x64.msi" "windows-x64/nexus-agent-$wversion-x64.msi" msi windows x86_64 "$wversion"
fi
[ "$wversion" = "$version" ] || [ $msi = 0 ] || die "Linux ($version) and Windows ($wversion) agent versions differ: one release per version"
{
	printf '{\n  "format": 1,\n  "version": "%s",\n  "protocol": "1.8",\n  "min_appliance": "",\n' "$version"
	printf '  "released": "%s",\n' "$(git log -1 --format=%cI 2>/dev/null || date -u +%FT%TZ)"
	printf '  "notes": "nexus-agent %s",\n  "artifacts": [\n' "$version"
	for i in "${!arts[@]}"; do
		sep=,
		[ "$i" = $((${#arts[@]} - 1)) ] && sep=
		printf '    %s%s\n' "${arts[$i]}" "$sep"
	done
	printf '  ]\n}\n'
} >"$rel/manifest.json"
tar --sort=name --owner=0 --group=0 --numeric-owner -C "$out/agent-release" -cf "$out/nexus-agent-release-$version.tar" "$version"
echo "agent release tree: $rel (sign it: release/sign.sh sign-agent-release $rel)"
echo "packages in $out (check them with release/test-packages.sh)"
