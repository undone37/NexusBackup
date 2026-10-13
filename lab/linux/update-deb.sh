#!/usr/bin/env bash
# Phase 27 lab: a .deb install of the Linux agent updated in-band from a signed release
# (docs/agent-update-plan.md), without lab VM or appliance: Debian 13 with systemd in a
# rootless podman container, the real agent packages and the real nexus-agentctl.
#
#   update-deb.sh [NEW_VERSION]     (default 0.1.1)
#
#  1. nexus-agent <current> and <NEW> (copy of the tree with the bumped version) as static
#     musl binaries, packaged as .deb with nfpm (crates/agent-linux/dist/pkg, as
#     release/packages.sh does; the TEST key is pinned)
#  2. release tree <NEW> (manifest.json + the .deb), signed with the TEST key by
#     release/sign.sh sign-agent-release and checked by release/verify.sh --agent-release
#  3. container: the old .deb installed, `nexus-agent init --token`, service started
#  4. nexus-agentctl enroll, then `update` with the release store: the agent receives the
#     .deb in chunks, installs it with apt-get in the transient unit nexus-agent-update,
#     the package's postinst restarts it; the reconnect check sees <NEW>
#  5. checks: update-result ok, dpkg version, update-state.json, the agent serves again;
#     a second update to the same version is refused
#  6. a signed release whose .deb cannot be installed (unmet dependency): apt-get fails in the
#     transient unit, the agent stays on <NEW> and reports `failed` with the apt output
# Output under target/update-deb/. Needs podman, cargo with x86_64-unknown-linux-musl.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
NEW=${1:-0.1.1}
W=$repo/target/update-deb
NFPM_IMAGE=${NFPM_IMAGE:-docker.io/goreleaser/nfpm:v2.48.0@sha256:7d4cea73774728a1448af2dc248785fd17882005b0539f43d07f78a69db59368}
CT=nexus-update-deb-$$
PORT=${PORT:-27444}
TOKEN=MFRGGZDFMZTWQ2LKNNWG23TPOA
ID=00000000000d0eb1
cur=$(sed -n 's/^version = "\(.*\)"/\1/p' "$repo/crates/agent-linux/Cargo.toml" | head -1)
log() { echo "update-deb: $*" >&2; }
die() {
	log "FAILED: $*"
	exit 1
}
cleanup() { podman rm -f "$CT" >/dev/null 2>&1 || true; }
trap cleanup EXIT
mkdir -p "$W"

build() { # build SRC_ROOT -> prints the binary path
	(cd "$1" && CC_x86_64_unknown_linux_musl=gcc CARGO_TARGET_DIR="$1/target" \
		cargo build -q --locked -p agent-linux --release --target x86_64-unknown-linux-musl >&2)
	echo "$1/target/x86_64-unknown-linux-musl/release/nexus-agent"
}

# --- 1. both versions --------------------------------------------------------------------------
src=$W/src-$NEW
mkdir -p "$src"
find "$src" -mindepth 1 -maxdepth 1 ! -name target -exec rm -rf {} +
git -C "$repo" ls-files -z --cached --others --exclude-standard | tar -C "$repo" --null -T - -cf - | tar -C "$src" -xf -
python3 -I - "$src" "$NEW" <<-'PY'
	import re, sys
	src, ver = sys.argv[1], sys.argv[2]
	p = f"{src}/crates/agent-linux/Cargo.toml"
	s = open(p).read()
	open(p, "w").write(re.sub(r'(?m)^version = "[^"]*"', f'version = "{ver}"', s, count=1))
	p = f"{src}/Cargo.lock"
	s = open(p).read()
	s, n = re.subn(r'(name = "agent-linux"\nversion = )"[^"]*"', rf'\1"{ver}"', s)
	assert n == 1
	open(p, "w").write(s)
PY
log "building nexus-agent $cur and $NEW (musl)"
old_bin=$(CARGO_TARGET_DIR=$repo/target build "$repo")
new_bin=$(build "$src")
(cd "$repo" && cargo build -q --locked -p agent-conn --bin nexus-agentctl)
agentctl=$repo/target/debug/nexus-agentctl

deb() { # deb BIN VERSION [DEPENDS] -> $W/pkg-VERSION/nexus-agent_VERSION-1_amd64.deb
	local st=$W/stage-$2 out=$W/pkg-$2
	rm -rf "$st" "$out"
	mkdir -p "$st/release-keys" "$st/hooks.d/pre" "$out"
	install -m 0755 "$1" "$st/nexus-agent"
	sed 's|/usr/local/sbin/nexus-agent|/usr/bin/nexus-agent|g' "$repo/crates/agent-linux/dist/nexus-agent.service" >"$st/nexus-agent.service"
	install -m 0644 "$repo/crates/agent-linux/dist/pkg/nfpm.yaml" "$repo/crates/agent-linux/dist/pkg/lintian-overrides" \
		"$repo/crates/agent-linux/dist/pkg/sysusers.conf" "$st/"
	install -m 0755 "$repo"/crates/agent-linux/dist/pkg/{postinst,prerm,postrm}.sh "$st/"
	install -m 0644 "$repo"/crates/agent-linux/dist/hooks.d/pre/*.example "$st/hooks.d/pre/"
	install -m 0644 "$repo/docs/agent-linux.md" "$st/README.md"
	install -m 0644 "$repo/LICENSE" "$st/copyright"
	install -m 0644 "$repo/release/testkey/TEST-cosign.pub" "$st/release-keys/TEST-KEY-DO-NOT-SHIP.pub"
	printf -- '- semver: %s-1\n  date: 2026-10-14T00:00:00Z\n  packager: lab\n  changes:\n    - note: lab\n' "$2" >"$st/changelog.yml"
	echo deb >"$st/package-managed"
	[ -z "${3:-}" ] || printf 'depends:\n  - %s\n' "$3" >>"$st/nfpm.yaml"
	podman run --rm --security-opt label=disable -v "$st:/stage" -v "$out:/out" -w /stage \
		-e PKG_ARCH=amd64 -e PKG_VERSION="$2" "$NFPM_IMAGE" pkg --config /stage/nfpm.yaml --packager deb --target /out/ >&2
	ls "$out"/nexus-agent_"$2"-1_amd64.deb
}
log "packaging .deb $cur and $NEW (nfpm)"
old_deb=$(deb "$old_bin" "$cur")
new_deb=$(deb "$new_bin" "$NEW")
BAD=9.9.9
bad_deb=$(deb "$new_bin" "$BAD" nexus-lab-missing-dependency)

# --- 2. signed release trees ---------------------------------------------------------------------
store=$W/store
rm -rf "$store"
release() { # release VERSION DEB: manifest, signed with the TEST key, verified
	local rel=$store/$1 name
	mkdir -p "$rel/linux-x86_64"
	cp "$2" "$rel/linux-x86_64/"
	name=linux-x86_64/$(basename "$2")
	cat >"$rel/manifest.json" <<EOF
{
  "format": 1,
  "version": "$1",
  "protocol": "1.8",
  "released": "2026-10-14T00:00:00Z",
  "notes": "lab: update-deb.sh",
  "artifacts": [
    {"name": "$name", "kind": "deb", "os": "linux", "arch": "x86_64", "version": "$1",
     "size": $(stat -c %s "$rel/$name"), "sha256": "$(sha256sum "$rel/$name" | cut -d' ' -f1)"}
  ]
}
EOF
	COSIGN_KEY=$repo/release/testkey/TEST-cosign.key COSIGN_PASSWORD=nexus-test-key \
		"$repo/release/sign.sh" sign-agent-release "$rel"
	VERIFY_KEYS=$repo/release/testkey/TEST-cosign.pub "$repo/release/verify.sh" --agent-release "$rel"
}
log "signing the releases with the TEST key"
release "$NEW" "$new_deb"
release "$BAD" "$bad_deb"

# --- 3. the host -------------------------------------------------------------------------------
img=localhost/nexus-debian-systemd:13
podman image exists "$img" || printf '%s\n' "FROM docker.io/library/debian:trixie
RUN apt-get update && apt-get install -y --no-install-recommends systemd systemd-sysv dbus ca-certificates \\
 && rm -rf /var/lib/apt/lists/*" | podman build -q -t "$img" -f - . >/dev/null
podman run -d --name "$CT" --systemd=always -p "127.0.0.1:$PORT:7444" -v "$old_deb:/tmp/old.deb:ro" "$img" /sbin/init >/dev/null
for _ in $(seq 60); do
	podman exec "$CT" systemctl is-system-running 2>/dev/null | grep -qE 'running|degraded' && break
	sleep 1
done
podman exec "$CT" sh -c 'apt-get install -y /tmp/old.deb >/tmp/install.log 2>&1' || die "installing the old .deb"
podman exec "$CT" sh -c "echo $TOKEN | nexus-agent init --token -" >/dev/null
podman exec "$CT" systemctl enable --now nexus-agent.service
sleep 2
podman exec "$CT" systemctl is-active -q nexus-agent.service || {
	podman exec "$CT" journalctl -u nexus-agent --no-pager | tail -n 30
	die "agent not running"
}

# --- 4. enroll + update --------------------------------------------------------------------------
cfgd=$W/appliance
rm -rf "$cfgd"
mkdir -p "$cfgd"
python3 -I -c 'import hashlib,sys; print(hashlib.sha256(sys.argv[1].strip().encode()).hexdigest())' "$TOKEN" >"$cfgd/token"
cat >"$cfgd/enroll.json" <<EOF
{"tenant": "lab", "ca_dir": "$cfgd/ca", "token_file": "$cfgd/token",
 "agent": {"id": "$ID", "host": "127.0.0.1", "port": $PORT}}
EOF
"$agentctl" "$cfgd/enroll.json" enroll >"$cfgd/enroll.out" 2>&1 || {
	cat "$cfgd/enroll.out"
	die "enrollment"
}
fp=$(sed -n 's/^enrolled .*"cert_sha256":"\([0-9a-f]*\)".*/\1/p' "$cfgd/enroll.out")
[ ${#fp} = 64 ] || die "no fingerprint"
upd() { # upd VERSION [extra json] -> config file
	cat >"$cfgd/update-$1.json" <<EOF
{"tenant": "lab", "ca_dir": "$cfgd/ca", "job": 1,
 "agent": {"id": "$ID", "host": "127.0.0.1", "port": $PORT, "cert_sha256": "$fp"},
 "update": {"version": "$1", "dirs": ["$store"], "keys_dir": "$repo/release/testkey"}}
EOF
	echo "$cfgd/update-$1.json"
}
log "update $cur -> $NEW (deb via the transient unit)"
t0=$SECONDS
"$agentctl" "$(upd "$NEW")" update >"$cfgd/update.out" 2>&1 || {
	cat "$cfgd/update.out"
	podman exec "$CT" journalctl -u nexus-agent-update -u nexus-agent --no-pager | tail -n 40
	die "update"
}
grep -q '^update-plan .*"mode":"chunked"' "$cfgd/update.out" || die "not the chunked path"
grep -q '^update-result .*"state":"ok"' "$cfgd/update.out" || die "no ok result"

# --- 5. checks -----------------------------------------------------------------------------------
v=$(podman exec "$CT" dpkg-query -W -f='${Version}' nexus-agent)
[ "$v" = "$NEW-1" ] || die "dpkg says $v"
st=$(podman exec "$CT" cat /var/lib/nexus-agent/update-state.json)
grep -q '"state":"ok"' <<<"$st" || die "update-state.json: $st"
podman exec "$CT" test ! -e /var/lib/nexus-agent/update-pending.json || die "pending file left"
podman exec "$CT" systemctl is-active -q nexus-agent.service || die "agent not running after the update"
podman exec "$CT" systemctl status nexus-agent-update.service >/dev/null 2>&1 && die "transient unit still loaded"
"$agentctl" "$(upd "$NEW")" update >"$cfgd/again.out" 2>&1 && die "the same version was accepted again"
grep -q 'not newer' "$cfgd/again.out" || die "unexpected refusal: $(tail -n 3 "$cfgd/again.out")"
log "ok: $cur -> $NEW in $((SECONDS - t0)) s; update-state: $st"
secs=$((SECONDS - t0))

# --- 6. a package that cannot be installed ------------------------------------------------------
log "update $NEW -> $BAD (unmet dependency: must fail and be reported)"
"$agentctl" "$(upd "$BAD")" update >"$cfgd/bad.out" 2>&1 && die "the broken package was reported as installed"
grep -q '^update-result .*"state":"failed"' "$cfgd/bad.out" || die "no failed result: $(tail -n 5 "$cfgd/bad.out")"
st=$(podman exec "$CT" cat /var/lib/nexus-agent/update-state.json)
grep -q '"state":"failed"' <<<"$st" || die "update-state.json: $st"
grep -q 'nexus-lab-missing-dependency' <<<"$st" || die "apt output missing in the state: $st"
podman exec "$CT" test ! -e /var/lib/nexus-agent/update-pending.json || die "pending file left after the failure"
v=$(podman exec "$CT" dpkg-query -W -f='${Version}' nexus-agent)
[ "$v" = "$NEW-1" ] || die "dpkg says $v after the failed update"
podman exec "$CT" systemctl is-active -q nexus-agent.service || die "agent not running after the failed update"
log "failed update reported: $(grep -o '"error":"[^"]*"' <<<"$st")"
echo "update_deb=ok from=$cur to=$NEW secs=$secs broken_package=reported"
