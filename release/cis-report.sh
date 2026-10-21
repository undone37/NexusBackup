#!/usr/bin/env bash
# Informational OpenSCAP CIS report of an appliance image (docs/release.md "CVE scan"): a
# throw-away container of the AlmaLinux bootc base image (POLICY_CHECK_IMAGE, release/config.env)
# installs openscap-scanner, openscap-utils and scap-security-guide and evaluates the CIS server level 1
# profile with oscap-chroot against the appliance image mounted read-only (--mount type=image): the
# appliance image installs nothing at run time (os/slim.sh). Nothing is installed on the host and no image is changed.
# Gate (Phase 35d): every rule in release/cis-passing.txt must still pass, else exit 4 naming the
# regressions. Other failures do not fail it: a file tree cannot show kernel, boot or service state
# (docs/cis.md has every rule with its decision). Rules that pass now but are not in the list are printed
# so the list can be extended.
#
#   release/cis-report.sh LOCAL-IMAGE [OUT-DIR]     e.g. localhost/nexus-os:release (default out/)
set -euo pipefail
. "$(dirname "$0")/lib.sh"

[ $# -ge 1 ] || die "usage: $0 LOCAL-IMAGE [OUT-DIR]"
img=$1
out=$(realpath -m "${2:-out}")
mkdir -p "$out"

# oscap exits 2 when rules fail: that is the report, not an error
podman run --rm --user 0 --network host --security-opt label=disable \
	--mount "type=image,source=$img,destination=/target,rw=false" -v "$out:/out" "$POLICY_CHECK_IMAGE" sh -ec '
	dnf -y -q install openscap-scanner openscap-utils scap-security-guide >/dev/null
	ds=$(ls /usr/share/xml/scap/ssg/content/ssg-almalinux10-ds.xml /usr/share/xml/scap/ssg/content/ssg-*10-ds.xml 2>/dev/null | head -1)
	[ -n "$ds" ] || { echo "no SCAP content for this release in scap-security-guide"; exit 3; }
	rc=0
	oscap-chroot /target xccdf eval --profile xccdf_org.ssgproject.content_profile_cis_server_l1 \
		--results /out/cis-results.xml --report /out/cis-report.html "$ds" >/out/cis.txt 2>/out/cis-oscap.log || rc=$?
	[ "$rc" -le 2 ]
	grep -c "^Result.*pass" /out/cis.txt | sed "s/^/pass: /"
	grep -c "^Result.*fail" /out/cis.txt | sed "s/^/fail: /"
	grep -c "^Result.*notapplicable" /out/cis.txt | sed "s/^/not applicable: /"
'

# rule results as "id result" lines (oscap's text output has CRLF)
tr -d '\r' <"$out/cis.txt" | awk -F'\t' '$1=="Rule"{r=$2; sub(/.*content_rule_/,"",r)} $1=="Result"{print r, $2}' >"$out/cis-results.txt"
base="$(dirname "$0")/cis-passing.txt"
regressed=$(grep -v '^#' "$base" | while read -r rule; do
	grep -qx "$rule pass" "$out/cis-results.txt" || echo "$rule"
done)
new=$(awk '$2=="pass"{print $1}' "$out/cis-results.txt" | grep -vxFf <(grep -v '^#' "$base") || true)
[ -z "$new" ] || printf 'passing, not yet in %s:\n%s\n' "$base" "$new"
[ -z "$regressed" ] || die "CIS regression, these rules passed before: $(echo $regressed)"
