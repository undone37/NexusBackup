# CIS AlmaLinux OS 10 Benchmark: gap analysis of the appliance (Phase 35)

What the appliance does with each recommendation of the CIS AlmaLinux OS 10 Benchmark v1.0.0, Level 1 Server
profile, as the ComplianceAsCode content (`scap-security-guide`, profile `cis_server_l1`) checks it. This document
uses the recommendation numbers and the open-source rule titles of ComplianceAsCode only, never CIS text (the
benchmark itself is licensed; the maintainer has a copy).

## Method and numbers

`release/cis-report.sh` evaluates the profile with OpenSCAP (`oscap-chroot`) against the appliance image mounted
read-only, from a container of the AlmaLinux bootc base image. A file tree shows packages, files and their
contents, not the running kernel, mounts or services: those rules were checked by hand on the booted lab appliance
(Phase 35b, VM 201, 2026-10-21: mounts, service states, root's PATH) and are marked *applied* with the lab result;
the image scan still counts them as failing (it looks for /etc/fstab lines and unit files in the tree).

| Image | pass | fail | not applicable |
|---|---|---|---|
| 0.0.16-dev (stripped, before hardening) | 161 | 116 | 42 |
| 0.0.17-dev (with the 35c hardening) | 194 | 83 | 42 |

The 194 passing rules are listed in `release/cis-passing.txt` (the baseline of the Phase 35d gate). Of the 83 that
fail in the image scan: 37 are applied (the check cannot see it in a file tree or expects another form), 35 deviate
on purpose (the reason and the compensating control below), 10 need the lab scan, 6 do not apply. Lab (VM 201,
2026-10-21): the hardened image boots, greenboot passes, the sysctl values are active, the blocked modules refuse to
load, no AVC denials, a PVE backup and restore is byte-identical.

## What the hardening changed (35c)

- `os/etc/sysctl.d/60-nexus-hardening.conf`: no forwarding, no redirects or source routing, router advertisements
  left to NetworkManager, martians logged, SYN cookies, kernel pointers and log buffer for root only, ptrace of
  descendants only, full ASLR, protected links, no setuid core dumps.
- `os/etc/modprobe.d/nexus-hardening.conf`: ATM, CAN, DCCP, RDS, SCTP, TIPC, FireWire, cramfs, freevxfs, hfs, hfsplus,
  jffs2 blocked.
- No core dumps (`coredump.conf.d`, `limits.d`), persistent compressed journal without syslog forwarding.
- sshd (not enabled) starts hardened if anyone enables it: `sshd_config.d/40-nexus-hardening.conf`, mode 0600.
- Login banners `/etc/issue`, `/etc/issue.net`; umask 027 (`login.defs`, `bashrc`, `profile`); 15-minute shell
  timeout (`profile.d`).

## Main deviations

- **Local accounts and PAM (5.3, 5.4):** no local password logins. Root is locked, no other account has a login
  shell, sshd is off; the only shell is the console gate (a one-time code after approval, or the recovery key, manual
  chapter 14). The people who use the appliance have web UI accounts with their own policy (argon2id, TOTP or
  passkeys, lockout, dormant accounts, manual chapter 9).
- **AIDE (6.1):** `/usr` is read-only and verified by bootc/ostree (composefs); a change is a new signed image.
- **firewalld (4.1):** nftables directly, default deny in and out (`os/nftables.conf`), allow-lists synced by
  nexus-nft-sync.
- **Reverse path filter (3.3):** loose instead of strict, so role interfaces with asymmetric routes keep working.
- **USB storage (3.4 / 1.1):** stays loadable: offline update bundles and the Hardware page use USB disks.
- **sudo, cron, at, sequoia-sq:** removed or never installed (os/slim.sh); systemd timers only.
- **Crypto policy module (1.6):** open: the services use rustls with their own suites; the system policy stays
  DEFAULT until the CIS module is tried against PVE and TrueNAS SSH.

## Every rule that does not pass in the image scan

| CIS references | Rule (ComplianceAsCode) | Title | Decision | Reason |
|---|---|---|---|---|
| 1.1.2.1.1 | `partition_for_tmp` | Ensure /tmp Located On Separate Partition | applied | tmpfs from tmp.mount, with the drop-in tmp.mount.d/50-nexus-noexec.conf: nosuid, nodev, noexec (lab VM 201, 2026-10-21) |
| 1.1.2.2.1 | `partition_for_dev_shm` | Ensure /dev/shm is configured | applied | tmpfs, remounted nosuid, nodev, noexec by dev-shm-noexec.service (lab VM 201, 2026-10-21) |
| 1.1.2.2.2 | `mount_option_dev_shm_nodev` | Add nodev Option to /dev/shm | applied | dev-shm-noexec.service; the check also looks for an /etc/fstab line, which a bootc appliance does not have (lab VM 201, 2026-10-21) |
| 1.1.2.2.3 | `mount_option_dev_shm_nosuid` | Add nosuid Option to /dev/shm | applied | dev-shm-noexec.service; the check also looks for an /etc/fstab line, which a bootc appliance does not have (lab VM 201, 2026-10-21) |
| 1.1.2.2.4 | `mount_option_dev_shm_noexec` | Add noexec Option to /dev/shm | applied | dev-shm-noexec.service; the check also looks for an /etc/fstab line, which a bootc appliance does not have (lab VM 201, 2026-10-21) |
| 1.2.1, 1.2, 4.1.1 | `package_firewalld_installed` | Install firewalld Package | deviates | nftables directly (os/nftables.conf): default deny in and out, loopback accepted, allow-lists synced by nexus-nft-sync |
| 1.4.1 | `grub2_password` | Set Boot Loader Password in grub2 | applied | nexus-grub-password installs the boot menu password into /boot at every boot (Phase 18); the image scan does not see /boot |
| 1.4.1, 1.4, 4.1.5 | `firewalld_loopback_traffic_trusted` | Configure Firewalld to Trust Loopback Traffic | deviates | nftables directly (os/nftables.conf): default deny in and out, loopback accepted, allow-lists synced by nexus-nft-sync |
| 1.4.2, 1.4, 3.3.2.6 | `sysctl_net_ipv6_conf_default_accept_source_route` | Disable Kernel Parameter for Accepting Source-Routed Packets on IPv6 Interfaces by Default | applied | /etc/sysctl.d/60-nexus-hardening.conf; the run-time value needs the lab scan |
| 1.4.2, 1.4, 3.3.1.7 | `sysctl_net_ipv4_icmp_echo_ignore_broadcasts` | Enable Kernel Parameter to Ignore ICMP Broadcast Echo Requests on IPv4 Interfaces | applied | /etc/sysctl.d/60-nexus-hardening.conf; the run-time value needs the lab scan |
| 1.4.2, 1.4, 3.3.1.6 | `sysctl_net_ipv4_icmp_ignore_bogus_error_responses` | Enable Kernel Parameter to Ignore Bogus ICMP Error Responses on IPv4 Interfaces | applied | /etc/sysctl.d/60-nexus-hardening.conf; the run-time value needs the lab scan |
| 1.4.3, 1.4, 3.3.1.12 | `sysctl_net_ipv4_conf_all_rp_filter` | Enable Kernel Parameter to Use Reverse Path Filtering on all IPv4 Interfaces | deviates | loose reverse path filter (2): strict filtering can drop the appliance's own traffic with role interfaces (Settings, Network) |
| 1.4.3, 1.4, 3.3.1.10 | `sysctl_net_ipv4_conf_all_secure_redirects` | Disable Kernel Parameter for Accepting Secure ICMP Redirects on all IPv4 Interfaces | applied | /etc/sysctl.d/60-nexus-hardening.conf; the run-time value needs the lab scan |
| 1.4.3, 1.4, 3.3.1.9 | `sysctl_net_ipv4_conf_default_accept_redirects` | Disable Kernel Parameter for Accepting ICMP Redirects by Default on IPv4 Interfaces | applied | /etc/sysctl.d/60-nexus-hardening.conf; the run-time value needs the lab scan |
| 1.4.3, 1.4, 3.3.1.18 | `sysctl_net_ipv4_tcp_syncookies` | Enable Kernel Parameter to Use TCP Syncookies on Network Interfaces | applied | /etc/sysctl.d/60-nexus-hardening.conf; the run-time value needs the lab scan |
| 1.4.5, 1.4, 3.3.1.4 | `sysctl_net_ipv4_conf_all_send_redirects` | Disable Kernel Parameter for Sending ICMP Redirects on all IPv4 Interfaces | applied | /etc/sysctl.d/60-nexus-hardening.conf; the run-time value needs the lab scan |
| 1.4.5, 1.4, 3.3.1.5 | `sysctl_net_ipv4_conf_default_send_redirects` | Disable Kernel Parameter for Sending ICMP Redirects on all IPv4 Interfaces by Default | applied | /etc/sysctl.d/60-nexus-hardening.conf; the run-time value needs the lab scan |
| 1.5.2 | `sysctl_fs_protected_hardlinks` | Enable Kernel Parameter to Enforce DAC on Hardlinks | applied | /etc/sysctl.d/60-nexus-hardening.conf; the run-time value needs the lab scan |
| 1.5.5 | `sysctl_kernel_dmesg_restrict` | Restrict Access to Kernel Message Buffer | applied | /etc/sysctl.d/60-nexus-hardening.conf; the run-time value needs the lab scan |
| 1.5.6 | `sysctl_kernel_kptr_restrict` | Restrict Exposed Kernel Pointer Addresses Access | applied | /etc/sysctl.d/60-nexus-hardening.conf; the run-time value needs the lab scan |
| 1.5.7 | `sysctl_kernel_yama_ptrace_scope` | Restrict usage of ptrace to descendant processes | applied | /etc/sysctl.d/60-nexus-hardening.conf; the run-time value needs the lab scan |
| 1.6.1, 1.6.2, 1.6.3, 1.6.4, 5.1.6, 5.1.15 | `configure_custom_crypto_policy_cis` | Implement Custom Crypto Policy Modules for CIS Benchmark | deviates | open: the services use rustls with their own TLS 1.3/1.2 suites (and X25519MLKEM768), SSH to sources uses russh; the system policy stays DEFAULT until the CIS policy module is tried against PVE and TrueNAS SSH |
| 2.1.9 | `service_nfs_disabled` | Disable Network File System (nfs) | applied | nfs-server disabled and inactive (the NFS client for NAS sources does not need it; lab VM 201, 2026-10-21) |
| 5.1.1 | `directory_permissions_sshd_config_d` | Verify Permissions on SSH Server config file | applied | 0700 in the image, but the release rechunk (rpm-ostree) resets the directory to the package mode 0755; `z /etc/ssh/sshd_config.d 0700` in tmpfiles.d/nexus.conf sets it at every boot (lab VM 201: 0700). The image scan counts it as failing |
| 2.2.2, 2.2, 5.4.2.4 | `ensure_root_password_configured` | Ensure Authentication Required for Single User Mode | deviates | no local password logins: root is locked, no other account has a login shell, sshd is off; the only shell is the console gate (a one-time code after approval, or the recovery key). Web UI accounts are application accounts with their own policy (argon2id, TOTP or passkeys, lockout, dormant accounts, manual chapter 9) |
| 2.2.4, 2.2, 2.1.11 | `service_rpcbind_disabled` | Disable rpcbind Service | applied | rpcbind service and socket disabled and inactive (lab VM 201, 2026-10-21) |
| 2.2.6, 2.2, 5.2.1 | `package_sudo_installed` | Install sudo Package | deviates | no sudo by design (os/slim.sh): no privilege change from a user account; root only via the console gate |
| 2.2.6, 2.2, 5.2.7 | `ensure_pam_wheel_group_empty` | Ensure the Group Used by pam_wheel.so Module Exists on System and is Empty | deviates | no local password logins: root is locked, no other account has a login shell, sshd is off; the only shell is the console gate (a one-time code after approval, or the recovery key). Web UI accounts are application accounts with their own policy (argon2id, TOTP or passkeys, lockout, dormant accounts, manual chapter 9) |
| 2.2.6, 2.2, 5.2.7 | `use_pam_wheel_group_for_su` | Enforce Usage of pam_wheel with Group Parameter for su Authentication | deviates | no local password logins: root is locked, no other account has a login shell, sshd is off; the only shell is the console gate (a one-time code after approval, or the recovery key). Web UI accounts are application accounts with their own policy (argon2id, TOTP or passkeys, lockout, dormant accounts, manual chapter 9) |
| 2.2.6, 2.2, 2.4.1.1 | `package_cron_installed` | Install the cron service | not applicable | no cron or at: systemd timers only |
| 2.4.1.1 | `service_crond_enabled` | Enable cron Service | not applicable | no cron or at: systemd timers only |
| 2.4.1.9 | `file_cron_allow_exists` | Ensure that /etc/cron.allow exists | not applicable | no cron or at: systemd timers only |
| 2.4.2.1 | `file_at_allow_exists` | Ensure that /etc/at.allow exists | not applicable | no cron or at: systemd timers only |
| 3.3.1.1, 3.3.1, 3.3, 1.5.4 | `sysctl_fs_suid_dumpable` | Disable Core Dumps for SUID programs | applied | /etc/sysctl.d/60-nexus-hardening.conf; the run-time value needs the lab scan |
| 3.3.1.1, 3.3.1, 3.3, 1.5.8 | `sysctl_kernel_randomize_va_space` | Enable Randomized Layout of Virtual Address Space | applied | /etc/sysctl.d/60-nexus-hardening.conf; the run-time value needs the lab scan |
| 3.3.1.2 | `sysctl_net_ipv4_conf_all_forwarding` | Disable Kernel Parameter for IPv4 Forwarding on all IPv4 Interfaces | applied | /etc/sysctl.d/60-nexus-hardening.conf; the run-time value needs the lab scan |
| 3.3.1.3 | `sysctl_net_ipv4_conf_default_forwarding` | Disable Kernel Parameter for IPv4 Forwarding By Default | applied | /etc/sysctl.d/60-nexus-hardening.conf; the run-time value needs the lab scan |
| 3.3.1.8 | `sysctl_net_ipv4_conf_all_accept_redirects` | Disable Accepting ICMP Redirects for All IPv4 Interfaces | applied | /etc/sysctl.d/60-nexus-hardening.conf; the run-time value needs the lab scan |
| 3.3.1.11 | `sysctl_net_ipv4_conf_default_secure_redirects` | Configure Kernel Parameter for Accepting Secure Redirects By Default | applied | /etc/sysctl.d/60-nexus-hardening.conf; the run-time value needs the lab scan |
| 3.3.1.13 | `sysctl_net_ipv4_conf_default_rp_filter` | Enable Kernel Parameter to Use Reverse Path Filtering on all IPv4 Interfaces by Default | deviates | loose reverse path filter (2): strict filtering can drop the appliance's own traffic with role interfaces (Settings, Network) |
| 3.3.1.14 | `sysctl_net_ipv4_conf_all_accept_source_route` | Disable Kernel Parameter for Accepting Source-Routed Packets on all IPv4 Interfaces | applied | /etc/sysctl.d/60-nexus-hardening.conf; the run-time value needs the lab scan |
| 3.3.1.15 | `sysctl_net_ipv4_conf_default_accept_source_route` | Disable Kernel Parameter for Accepting Source-Routed Packets on IPv4 Interfaces by Default | applied | /etc/sysctl.d/60-nexus-hardening.conf; the run-time value needs the lab scan |
| 3.3.1.16 | `sysctl_net_ipv4_conf_all_log_martians` | Enable Kernel Parameter to Log Martian Packets on all IPv4 Interfaces | applied | /etc/sysctl.d/60-nexus-hardening.conf; the run-time value needs the lab scan |
| 3.3.1.17 | `sysctl_net_ipv4_conf_default_log_martians` | Enable Kernel Parameter to Log Martian Packets on all IPv4 Interfaces by Default | applied | /etc/sysctl.d/60-nexus-hardening.conf; the run-time value needs the lab scan |
| 3.3.2.1 | `sysctl_net_ipv6_conf_all_forwarding` | Disable Kernel Parameter for IPv6 Forwarding | applied | /etc/sysctl.d/60-nexus-hardening.conf; the run-time value needs the lab scan |
| 3.3.2.2 | `sysctl_net_ipv6_conf_default_forwarding` | Disable Kernel Parameter for IPv6 Forwarding by default | applied | /etc/sysctl.d/60-nexus-hardening.conf; the run-time value needs the lab scan |
| 3.3.2.3 | `sysctl_net_ipv6_conf_all_accept_redirects` | Disable Accepting ICMP Redirects for All IPv6 Interfaces | applied | /etc/sysctl.d/60-nexus-hardening.conf; the run-time value needs the lab scan |
| 3.3.2.4 | `sysctl_net_ipv6_conf_default_accept_redirects` | Disable Kernel Parameter for Accepting ICMP Redirects by Default on IPv6 Interfaces | applied | /etc/sysctl.d/60-nexus-hardening.conf; the run-time value needs the lab scan |
| 3.3.2.5 | `sysctl_net_ipv6_conf_all_accept_source_route` | Disable Kernel Parameter for Accepting Source-Routed Packets on all IPv6 Interfaces | applied | /etc/sysctl.d/60-nexus-hardening.conf; the run-time value needs the lab scan |
| 3.3.2.7 | `sysctl_net_ipv6_conf_all_accept_ra` | Configure Accepting Router Advertisements on All IPv6 Interfaces | applied | /etc/sysctl.d/60-nexus-hardening.conf; the run-time value needs the lab scan |
| 3.3.2.8 | `sysctl_net_ipv6_conf_default_accept_ra` | Disable Accepting Router Advertisements on all IPv6 Interfaces by Default | applied | /etc/sysctl.d/60-nexus-hardening.conf; the run-time value needs the lab scan |
| 3.4.2, 3.4, 1.1.1.10 | `kernel_module_usb-storage_disabled` | Disable Modprobe Loading of USB Storage Driver | deviates | USB disks carry offline update bundles and show on the Hardware page |
| 5.3.1.1 | `accounts_password_pam_modules_in_authselect_profile` | Ensure Active Authselect Profile Includes PAM Modules | deviates | no local password logins: root is locked, no other account has a login shell, sshd is off; the only shell is the console gate (a one-time code after approval, or the recovery key). Web UI accounts are application accounts with their own policy (argon2id, TOTP or passkeys, lockout, dormant accounts, manual chapter 9) |
| 5.3.1.2 | `account_password_pam_faillock_password_auth` | Configure the Use of the pam_faillock.so Module in the /etc/pam.d/password-auth File. | deviates | no local password logins: root is locked, no other account has a login shell, sshd is off; the only shell is the console gate (a one-time code after approval, or the recovery key). Web UI accounts are application accounts with their own policy (argon2id, TOTP or passkeys, lockout, dormant accounts, manual chapter 9) |
| 5.3.1.2 | `account_password_pam_faillock_system_auth` | Configure the Use of the pam_faillock.so Module in the /etc/pam.d/system-auth File. | deviates | no local password logins: root is locked, no other account has a login shell, sshd is off; the only shell is the console gate (a one-time code after approval, or the recovery key). Web UI accounts are application accounts with their own policy (argon2id, TOTP or passkeys, lockout, dormant accounts, manual chapter 9) |
| 5.3.2.1.2 | `accounts_passwords_pam_faillock_unlock_time_with_zero` | Set Lockout Time for Failed Password Attempts | deviates | no local password logins: root is locked, no other account has a login shell, sshd is off; the only shell is the console gate (a one-time code after approval, or the recovery key). Web UI accounts are application accounts with their own policy (argon2id, TOTP or passkeys, lockout, dormant accounts, manual chapter 9) |
| 5.3.2.2.1 | `accounts_password_pam_difok` | Ensure PAM Enforces Password Requirements - Minimum Different Characters | deviates | no local password logins: root is locked, no other account has a login shell, sshd is off; the only shell is the console gate (a one-time code after approval, or the recovery key). Web UI accounts are application accounts with their own policy (argon2id, TOTP or passkeys, lockout, dormant accounts, manual chapter 9) |
| 5.3.2.2.3 | `accounts_password_pam_minclass` | Ensure PAM Enforces Password Requirements - Minimum Different Categories | deviates | no local password logins: root is locked, no other account has a login shell, sshd is off; the only shell is the console gate (a one-time code after approval, or the recovery key). Web UI accounts are application accounts with their own policy (argon2id, TOTP or passkeys, lockout, dormant accounts, manual chapter 9) |
| 5.3.2.2.4 | `accounts_password_pam_maxrepeat` | Set Password Maximum Consecutive Repeating Characters | deviates | no local password logins: root is locked, no other account has a login shell, sshd is off; the only shell is the console gate (a one-time code after approval, or the recovery key). Web UI accounts are application accounts with their own policy (argon2id, TOTP or passkeys, lockout, dormant accounts, manual chapter 9) |
| 5.3.2.2.5 | `accounts_password_pam_maxsequence` | Limit the maximum number of sequential characters in passwords | deviates | no local password logins: root is locked, no other account has a login shell, sshd is off; the only shell is the console gate (a one-time code after approval, or the recovery key). Web UI accounts are application accounts with their own policy (argon2id, TOTP or passkeys, lockout, dormant accounts, manual chapter 9) |
| 5.3.2.2.6 | `accounts_password_pam_dictcheck` | Ensure PAM Enforces Password Requirements - Prevent the Use of Dictionary Words | deviates | no local password logins: root is locked, no other account has a login shell, sshd is off; the only shell is the console gate (a one-time code after approval, or the recovery key). Web UI accounts are application accounts with their own policy (argon2id, TOTP or passkeys, lockout, dormant accounts, manual chapter 9) |
| 5.3.2.2.7 | `accounts_password_pam_enforce_root` | Ensure PAM Enforces Password Requirements - Enforce for root User | deviates | no local password logins: root is locked, no other account has a login shell, sshd is off; the only shell is the console gate (a one-time code after approval, or the recovery key). Web UI accounts are application accounts with their own policy (argon2id, TOTP or passkeys, lockout, dormant accounts, manual chapter 9) |
| 5.3.2.3.2 | `accounts_password_pam_pwhistory_enforce_for_root` | Ensure Password History Is Enforced for the Root User | deviates | no local password logins: root is locked, no other account has a login shell, sshd is off; the only shell is the console gate (a one-time code after approval, or the recovery key). Web UI accounts are application accounts with their own policy (argon2id, TOTP or passkeys, lockout, dormant accounts, manual chapter 9) |
| 5.3.2.3.3 | `accounts_password_pam_pwhistory_use_authtok` | Enforce Password History with use_authtok | deviates | no local password logins: root is locked, no other account has a login shell, sshd is off; the only shell is the console gate (a one-time code after approval, or the recovery key). Web UI accounts are application accounts with their own policy (argon2id, TOTP or passkeys, lockout, dormant accounts, manual chapter 9) |
| 5.4.2.5 | `root_path_no_dot` | Ensure that Root's Path Does Not Include Relative Paths or Null Directories | applied | root PATH /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin (lab VM 201, 2026-10-21) |
| 6.1.3 | `aide_check_audit_tools` | Configure AIDE to Verify the Audit Tools | deviates | /usr is read-only and verified by bootc/ostree (composefs); a change to it is a new signed image. /etc differences are visible with `ostree admin config-diff` (support bundle). AIDE would re-hash an immutable tree |
| 6.2.1.1 | `service_systemd-journald_enabled` | Enable systemd-journald Service | applied | journald static and active (lab VM 201, 2026-10-21) |
| 6.2.1.4 | `ensure_journald_and_rsyslog_not_active_together` | Ensure journald and rsyslog Are Not Active Together | applied | rsyslog is not installed (lab VM 201, 2026-10-21) |
| 6.2.2.1.1 | `package_systemd-journal-remote_installed` | Install systemd-journal-remote Package | deviates | logs and audit leave through the appliance's own TLS forwarding (syslog TLS / HTTPS, manual chapter 10) |
| 6.2.2.1.4 | `socket_systemd-journal-remote_disabled` | Disable systemd-journal-remote Socket | deviates | logs and audit leave through the appliance's own TLS forwarding (syslog TLS / HTTPS, manual chapter 10) |
| 6.2.2.2 | `journald_disable_forward_to_syslog` | Ensure journald ForwardToSyslog is disabled | applied | /etc/systemd/journald.conf.d/50-nexus.conf; the check reads journald.conf only (lab check) |
| 6.2.2.3 | `journald_compress` | Ensure journald is configured to compress large log files | applied | /etc/systemd/journald.conf.d/50-nexus.conf; the check reads journald.conf only (lab check) |
| 6.2.2.4 | `journald_storage` | Ensure journald is configured to write log files to persistent disk | applied | /etc/systemd/journald.conf.d/50-nexus.conf; the check reads journald.conf only (lab check) |
| 6.2.3.4 | `rsyslog_filecreatemode` | Ensure rsyslog Default File Permissions Configured | not applicable | no rsyslog in the image (journald only) |
| 6.3.3, 6.3, 1.2.1.1 | `package_sequoia-sq_installed` | Install sequoia-sq Package | not applicable | RPM signatures are not used at run time: /usr is immutable, updates are cosign-signed images |
| 8.2.6, 8.2, 5.4.1.5 | `account_disable_post_pw_expiration` | Set Account Expiration Following Inactivity | deviates | no local password logins: root is locked, no other account has a login shell, sshd is off; the only shell is the console gate (a one-time code after approval, or the recovery key). Web UI accounts are application accounts with their own policy (argon2id, TOTP or passkeys, lockout, dormant accounts, manual chapter 9) |
| 8.2.8, 8.2, 5.1.7 | `sshd_set_keepalive` | Set SSH Client Alive Count Max | applied | /etc/ssh/sshd_config.d/40-nexus-hardening.conf; sshd itself is not enabled |
| 8.2.8, 8.2, 5.1.7 | `sshd_set_idle_timeout` | Set SSH Client Alive Interval | applied | /etc/ssh/sshd_config.d/40-nexus-hardening.conf; sshd itself is not enabled |
| 8.3.1, 8.3, 5.3.2.4.1 | `no_empty_passwords` | Prevent Login to Accounts With Empty Password | deviates | no local password logins: root is locked, no other account has a login shell, sshd is off; the only shell is the console gate (a one-time code after approval, or the recovery key). Web UI accounts are application accounts with their own policy (argon2id, TOTP or passkeys, lockout, dormant accounts, manual chapter 9) |
| 8.3.4, 8.3, 5.3.2.1.1 | `accounts_passwords_pam_faillock_deny` | Lock Accounts After Failed Password Attempts | deviates | no local password logins: root is locked, no other account has a login shell, sshd is off; the only shell is the console gate (a one-time code after approval, or the recovery key). Web UI accounts are application accounts with their own policy (argon2id, TOTP or passkeys, lockout, dormant accounts, manual chapter 9) |
| 8.3.6, 8.3, 5.3.2.2.2 | `accounts_password_pam_minlen` | Ensure PAM Enforces Password Requirements - Minimum Length | deviates | no local password logins: root is locked, no other account has a login shell, sshd is off; the only shell is the console gate (a one-time code after approval, or the recovery key). Web UI accounts are application accounts with their own policy (argon2id, TOTP or passkeys, lockout, dormant accounts, manual chapter 9) |
| 8.3.7, 8.3, 5.3.2.3.1 | `accounts_password_pam_pwhistory_remember_password_auth` | Limit Password Reuse: password-auth | deviates | no local password logins: root is locked, no other account has a login shell, sshd is off; the only shell is the console gate (a one-time code after approval, or the recovery key). Web UI accounts are application accounts with their own policy (argon2id, TOTP or passkeys, lockout, dormant accounts, manual chapter 9) |
| 8.3.7, 8.3, 5.3.2.3.1 | `accounts_password_pam_pwhistory_remember_system_auth` | Limit Password Reuse: system-auth | deviates | no local password logins: root is locked, no other account has a login shell, sshd is off; the only shell is the console gate (a one-time code after approval, or the recovery key). Web UI accounts are application accounts with their own policy (argon2id, TOTP or passkeys, lockout, dormant accounts, manual chapter 9) |
| 8.3.9, 8.3, 5.4.1.1 | `accounts_maximum_age_login_defs` | Set Password Maximum Age | deviates | no local password logins: root is locked, no other account has a login shell, sshd is off; the only shell is the console gate (a one-time code after approval, or the recovery key). Web UI accounts are application accounts with their own policy (argon2id, TOTP or passkeys, lockout, dormant accounts, manual chapter 9) |
| 10.6.2, 10.6, 2.3.2 | `chronyd_specify_remote_server` | A remote time server for Chrony is configured | applied | servers in /etc/nexus/time/chrony.conf (Settings, Time), included by chrony.conf; the check does not follow `include` |
| 10.6.3, 10.6, 2.3.3 | `chronyd_run_as_chrony_user` | Ensure that chronyd is running under chrony user account | applied | chronyd drops to the chrony user by default (compiled in); the check looks for -u in OPTIONS |
| 11.5.2, 6.1.1 | `package_aide_installed` | Install AIDE | deviates | /usr is read-only and verified by bootc/ostree (composefs); a change to it is a new signed image. /etc differences are visible with `ostree admin config-diff` (support bundle). AIDE would re-hash an immutable tree |
| 11.5.2, 6.1.1 | `aide_build_database` | Build and Test AIDE Database | deviates | /usr is read-only and verified by bootc/ostree (composefs); a change to it is a new signed image. /etc differences are visible with `ostree admin config-diff` (support bundle). AIDE would re-hash an immutable tree |
| 11.5.2, 6.1.2 | `aide_periodic_cron_checking` | Configure Periodic Execution of AIDE | deviates | /usr is read-only and verified by bootc/ostree (composefs); a change to it is a new signed image. /etc differences are visible with `ostree admin config-diff` (support bundle). AIDE would re-hash an immutable tree |

## Open (Phase 35)

- 35d: the gate: `release/cis-passing.txt` as the list that must keep passing.
