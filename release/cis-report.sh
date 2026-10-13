#!/usr/bin/env bash
# Informational OpenSCAP CIS report of an appliance image (docs/release.md "CVE scan"):
# a throw-away container of the image itself installs openscap-scanner and
# scap-security-guide and evaluates the CIS server level 1 profile. Nothing is
# installed on the host and the image is not changed (podman run --rm). Never fails
# on rule results: a container cannot show kernel, boot or service state, so the
# report is a review aid, not a gate.
#
#   release/cis-report.sh LOCAL-IMAGE [OUT-DIR]     e.g. localhost/nexus-os:release (default out/)
set -euo pipefail
. "$(dirname "$0")/lib.sh"

[ $# -ge 1 ] || die "usage: $0 LOCAL-IMAGE [OUT-DIR]"
img=$1
out=$(realpath -m "${2:-out}")
mkdir -p "$out"

# oscap exits 2 when rules fail: that is the report, not an error
podman run --rm --user 0 --network host --security-opt label=disable -v "$out:/out" "$img" sh -ec '
	dnf -y -q install openscap-scanner scap-security-guide >/dev/null
	ds=$(ls /usr/share/xml/scap/ssg/content/ssg-almalinux10-ds.xml /usr/share/xml/scap/ssg/content/ssg-*10-ds.xml 2>/dev/null | head -1)
	[ -n "$ds" ] || { echo "no SCAP content for this release in scap-security-guide"; exit 3; }
	rc=0
	oscap xccdf eval --profile xccdf_org.ssgproject.content_profile_cis_server_l1 \
		--results /out/cis-results.xml --report /out/cis-report.html "$ds" >/out/cis.txt 2>/out/cis-oscap.log || rc=$?
	[ "$rc" -le 2 ]
	grep -c "^Result.*pass" /out/cis.txt | sed "s/^/pass: /"
	grep -c "^Result.*fail" /out/cis.txt | sed "s/^/fail: /"
'
