#!/bin/bash
# Strips the AlmaLinux bootc base down to what the appliance and the edge proxy run (os/Containerfile,
# os/edge/Containerfile; run after the last dnf call, both images share this list):
#
#   bash os/slim.sh [PACKAGE...]      extra packages to remove (the edge passes the NAS/disk tools)
#
# Removed: GPU, Wi-Fi and audio firmware (no graphical console, servers on cable), translations (English
# only), docs and man pages; and packages nothing of ours runs, each group with its reason below. rpm -e
# refuses if a kept package still depends on one, so the build fails instead of breaking a dependency.
# Kept on purpose: bootc, ostree, rpm-ostree (and its libdnf/librepo/libsolv), skopeo (bootc pulls signed
# images through it), podman with its runtime (bootc creates and queries its image store
# /sysroot/ostree/bootc/storage through podman on every upgrade: without it `bootc upgrade` fails, lab
# 2026-10-21), python3 standard library (nexus-update, nexus-diag, greenboot checks), grub2/shim/
# bootupd, xfsprogs/e2fsprogs/dosfstools/util-linux (`bootc install` formats from the image itself),
# erofs-utils (composefs), NetworkManager, nftables, chrony, audit, selinux, microcode, NIC firmware.
set -euo pipefail

remove=(
	# firmware for hardware an appliance does not have (linux-firmware keeps NICs and storage controllers)
	nvidia-gpu-firmware amd-gpu-firmware intel-gpu-firmware atheros-firmware mt7xxx-firmware brcmfmac-firmware
	tiwilink-firmware nxpwireless-firmware intel-audio-firmware cirrus-audio-firmware
	# Bluetooth, desktop disk management, support bundles: none of it is used (nexus-diag is the support
	# bundle); flashrom can write the system firmware. fwupd itself stays: it provides dbxtool, which shim
	# needs for the Secure Boot revocation list
	fwupd-plugin-flashrom flashrom bluez sos udisks2 libudisks2
	libblockdev libblockdev-crypto libblockdev-fs libblockdev-loop libblockdev-mdraid libblockdev-nvme
	libblockdev-part libblockdev-smart libblockdev-swap libblockdev-utils libbytesize volume_key-libs
	# crash dumps, real-time throttling, checkpointing, generic socket relay
	kdump-utils kexec-tools makedumpfile memstrack stalld criu criu-libs socat
	# cloud agents (the appliance is configured on its console)
	NetworkManager-cloud-setup WALinuxAgent-udev
	# interactive convenience and debugging tools (the root console has vi, less, journalctl, ip, ss)
	nano bash-completion man-db groff-base libpipeline net-tools lsof
	bind-utils bind-libs bind-license fstrm libmaxminddb sequoia-sq
	# domain join, central identity and sudo: local accounts only; root is reached through the console gate
	sssd-ad sssd-client sssd-common sssd-common-pac sssd-ipa sssd-krb5 sssd-krb5-common sssd-ldap
	sssd-nfs-idmap adcli adcli-selinux libipa_hbac libsss_certmap libsss_idmap libsss_nss_idmap libsss_sudo
	sudo sudo-python-plugin
	# Samba client libraries (SMB shares are kernel CIFS mounts, crate nas)
	samba-client-libs samba-common samba-common-libs libsmbclient libwbclient libldb libtalloc libtdb libtevent
	# TPM and LUKS tooling: disk encryption is not implemented yet (os/README.md, deferred with TPM)
	tpm2-tools tpm2-tss-fapi clevis clevis-dracut clevis-luks clevis-pin-tpm2 clevis-systemd jose libjose
	luksmeta libluksmeta cryptsetup
	# file systems and volume managers the appliance does not create (data array: mdadm + XFS)
	exfatprogs btrfs-progs lvm2 lvm2-libs device-mapper-persistent-data device-mapper-event
	device-mapper-event-libs
	# package management: /usr is read-only, updates are whole signed images
	dnf dnf-data python3-dnf python3-hawkey python3-libdnf python3-libcomps libcomps
	python3-setuptools python3-requests python3-urllib3 python3-idna python3-charset-normalizer python3-pyyaml
	python3-pexpect python3-ptyprocess python3-packaging python3-file-magic python3-dbus python3-rpm
	gawk-all-langpacks glibc-gconv-extra
	"$@"
)
installed() { rpm -q --qf '%{NAME}\n' "$@" 2>/dev/null | grep -v 'is not installed' || true; }
mapfile -t pkgs < <(installed "${remove[@]}")
[ ${#pkgs[@]} = 0 ] || rpm -e "${pkgs[@]}"

find /usr/share/locale -mindepth 1 -maxdepth 1 -type d ! -name en -exec rm -rf {} +
rm -rf /usr/share/doc/* /usr/share/man/* /usr/share/info/*

# what must survive
rpm -q bootc ostree rpm-ostree skopeo podman python3 linux-firmware realtek-firmware amd-ucode-firmware microcode_ctl \
	xfsprogs dosfstools e2fsprogs NetworkManager nftables chrony >/dev/null
for d in bnx2 bnx2x qed tigon cxgb4 rtl_nic intel/ice; do
	test -d "/usr/lib/firmware/$d" || { echo "slim.sh: missing NIC firmware $d" >&2; exit 1; }
done
command -v skopeo podman bootc ostree mkfs.xfs mkfs.vfat sfdisk >/dev/null
! command -v dnf sudo >/dev/null
echo "slim.sh: $(rpm -qa | wc -l) packages left" >&2
