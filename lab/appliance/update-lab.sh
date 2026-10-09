#!/usr/bin/env bash
# Signed-update lab (docs/release.md "Lab test procedure") against the appliance VM.
#   update-lab.sh registry              start registry:2 on 127.0.0.1:5055
#   update-lab.sh base                  build the appliance image for R (NEXUS_IMAGE_REPO=$R)
#   update-lab.sh build VER [FAIL]      lab layer (Containerfile.update-lab) -> push $R:VER, print digest
#   update-lab.sh sign VER              cosign-sign $R@<digest of VER> with the TEST key
#   update-lab.sh promote VER           point $R:stable at it (refuses unsigned)
#   update-lab.sh unsigned-stable VER   point $R:stable at VER WITHOUT a signature check
#   update-lab.sh disk VER              install the VM disk from $R:VER (origin $R:stable)
#   update-lab.sh vm-prep               in the VM (CONSOLE=...): /etc/hosts entry for the registry
# R = nexus-lab-registry:5055/nexusbackup/appliance (same name on host and VM).
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
R=nexus-lab-registry:5055/nexusbackup/appliance
export NEXUS_IMAGE_REPO=$R NEXUS_ALLOW_HTTP=1 NEXUS_TOOL_ARGS=--add-host=nexus-lab-registry:127.0.0.1
export COSIGN_KEY=$repo/release/testkey/TEST-cosign.key COSIGN_PASSWORD=nexus-test-key
BASE_IMG=localhost/nexus-os-upd:base
digest() { cat "$here/../../target/update-lab/$1.digest"; }
mkdir -p "$repo/target/update-lab"

case ${1:-} in
registry)
	podman container exists nexus-lab-registry ||
		podman run -d --name nexus-lab-registry -p 127.0.0.1:5055:5000 docker.io/library/registry:2
	;;
base)
	podman build --build-arg NEXUS_IMAGE_REPO=$R --build-arg NEXUS_VERSION=0.0.1 \
		-f "$repo/os/Containerfile" -t $BASE_IMG "$repo"
	;;
build)
	v=$2
	podman build -q --build-arg IMAGE=$BASE_IMG --build-arg NEXUS_VERSION="$v" --build-arg FAIL="${3:-0}" \
		-t "localhost/nexus-os-upd:$v" -f "$here/Containerfile.update-lab" "$here" >/dev/null
	podman push -q --tls-verify=false --digestfile "$repo/target/update-lab/$v.digest" \
		"localhost/nexus-os-upd:$v" "docker://127.0.0.1:5055/nexusbackup/appliance:$v"
	echo "$R:$v = $(digest "$v")"
	;;
sign) "$repo/release/sign.sh" sign "$R@$(digest "$2")" ;;
promote) "$repo/release/promote.sh" "$R@$(digest "$2")" stable ;;
unsigned-stable)
	podman run --rm --network host quay.io/almalinuxorg/almalinux-bootc:10 skopeo copy --insecure-policy \
		--src-tls-verify=false --dest-tls-verify=false \
		"docker://127.0.0.1:5055/nexusbackup/appliance:$2" "docker://127.0.0.1:5055/nexusbackup/appliance:stable"
	;;
disk)
	TARGET_IMGREF=$R:stable "$here/build-disk.sh" "localhost/nexus-os-upd:$2"
	;;
vm-prep)
	"$here/con.py" run 'grep -q nexus-lab-registry /etc/hosts || echo "10.0.2.2 nexus-lab-registry" >> /etc/hosts'
	;;
*) sed -n '2,12p' "$0" >&2; exit 2 ;;
esac
