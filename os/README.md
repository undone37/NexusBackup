# NexusBackup appliance OS image

bootc image on `quay.io/almalinuxorg/almalinux-bootc:10` (AlmaLinux 10.2). Note that
`quay.io/almalinux/almalinux-bootc` does not exist (the registry returns unauthorized);
the official image lives under `almalinuxorg`. See plan.md §4.2 and §12, signed updates and
rollback in docs/release.md.

## Build

```sh
podman build -f os/Containerfile -t localhost/nexus-os:dev .     # context = repository root
```

One multi-stage build, no host toolchain needed:

| Stage | Base | Output |
|---|---|---|
| `web` | `node:22-trixie-slim` | `npm ci --ignore-scripts && npm run build` → `web/dist` |
| `rust` | the bootc base (glibc of the target) + rustup `RUST_VERSION` (1.93.0) | `cargo build --release --locked` of keyd, nexus-pve, nexus-offsite, nexus-web-api (SPA embedded), nexus-scheduler, nexus-setup, nexus-nft-sync; static musl restore agent. Registry and target dir are podman cache mounts (`--build-arg JOBS=n` limits rustc jobs) |
| `restorevm` | `debian:trixie` | the `restore-vm/Containerfile` steps (keep in sync; shares its layer cache) + `mkinitrd.sh` → `vmlinuz`, `initrd.img`, `manifest.txt` |
| `selinux` | the bootc base + `selinux-policy-devel` | `nexus.pp` |
| final | the bootc base | see below; ends with `bootc container lint` |

Measured on the dev machine (16 threads, `JOBS=6`): first build 4 min 12 s (Debian
builder layers already cached; a fully cold build adds the ~3 min ZFS DKMS compile),
image 1.83 GB (base 1.49 GB; + qemu-kvm-core, audit, greenboot, binaries 40 MB, restore
VM 24 MB). After a source change only the Rust stage reruns (~1–2 min with the cache
mounts).

The build fails if the SELinux module does not compile, install or resolve its file
contexts, if `qemu-kvm` lacks the `nbd` block driver, if `chrony.conf` does not parse,
if sshd or keyd/web-api/scheduler are enabled, if the containers signature policy is
not valid JSON, or if `bootc container lint` fails.

## What is in the image

| Source | Installed as | Purpose |
|---|---|---|
| `rust` stage | `/usr/libexec/nexus/{keyd,nexus-pve,nexus-offsite,nexus-web-api,nexus-scheduler,nexus-setup,nexus-nft-sync}` | the services and the CLIs the scheduler spawns (names = cargo binary names, used by the units and the scheduler defaults) |
| `restorevm` stage | `/usr/lib/nexus/restore-vm/{vmlinuz,initrd.img,manifest.txt}` | restore micro-VM (default `image_dir` of `pve::restorevm`) |
| `qemu-kvm-core` | `/usr/libexec/qemu-kvm` | runs the micro-VM (`NEXUS_QEMU` in the scheduler unit) |
| `audit` | auditd | AVC denials and security events in `/var/log/audit` (`ausearch -m avc`) |
| `greenboot` | greenboot units | health-gated rollback (docs/release.md) |
| `sysusers.d/nexus.conf` | `/usr/lib/sysusers.d/` | users `nexus-keyd`, `nexus-chunkstore` (scheduler and its jobs), `nexus-webapi`; groups `nexus-keyd` (keyd socket), `nexus-catalog` (catalog, downloads, update control); `nexus-chunkstore` ∈ `nexus-keyd`, `nexus-catalog`, `kvm` |
| `tmpfiles.d/nexus.conf` | `/usr/lib/tmpfiles.d/` | state dirs with owner/mode: catalog 2770 root:nexus-catalog, downloads 2750 nexus-chunkstore:nexus-catalog, keyd 0700 nexus-keyd, chunkstore/offsite/escrow/scheduler 0700 nexus-chunkstore (one 0700 store per tenant below chunkstore, created by the scheduler), `/etc/nexus/ssh` 0750 root:nexus-chunkstore, `/run/nexus-nft` |
| `systemd/*.service,.path,.timer` | `/usr/lib/systemd/system/` | see "Units" |
| `systemd/10-nexus.preset` | `/usr/lib/systemd/system-preset/` | sshd off; nftables, chronyd, nexus-setup, nexus-nft-sync.{service,path,timer}, nexus-plugin-install.{service,path} on; keyd/web-api/scheduler off (nexus-setup enables them) |
| `nftables.conf` | `/etc/sysconfig/nftables.conf` | default deny in and out, allow-list sets (see "Firewall") |
| `etc/` | `/etc/` | `chrony.conf` (NTS only) and the update/signing files (containers policy, cosign key, update.conf, greenboot.conf, presets, tmpfiles for `/var/lib/nexus/update` and `/var/lib/nexus/diag`) |
| `greenboot/usr/` | `/usr/` | `nexus-update` agent, `nexus-health` check, `nexus-diag` (self-checks, support bundles), `nexus-disks` (disks, SMART, data array), `nexus-grub-password` (boot menu password) and their units; the `emergency.service` drop-in (`SYSTEMD_SULOGIN_FORCE=0`) and `lib/bootc/kargs.d/10-nexus.toml` (`rd.shell=0 rd.emergency=reboot`) (`greenboot/tests/` stays out) |
| `selinux/nexus.{te,fc}` | module `nexus` | see "SELinux" |

The root account is locked (`usermod -L`). Emergency access is through the local console only.
`bootc install` is not given an SSH key.

## Units

| Unit | User | Domain | Notes |
|---|---|---|---|
| `nexus-keyd.service` | nexus-keyd | `nexus_keyd_t` | socket `/run/nexus-keyd/keyd.sock` (dir 0750, group nexus-keyd), `PrivateNetwork`, no devices (TPM deferred) |
| `nexus-web-api.service` | nexus-webapi (+nexus-catalog) | `nexus_webapi_t` | `Type=notify`, binds only tcp:8443, catalog rw, downloads read, update control rw |
| `nexus-scheduler.service` | nexus-chunkstore (+nexus-catalog, nexus-keyd, kvm) | `nexus_scheduler_t` | spawns `nexus-pve` (`nexus_pve_t`) and `nexus-offsite` (`nexus_offsite_t`); nexus-pve spawns QEMU (`nexus_restorevm_t`); `DeviceAllow=/dev/kvm`; writes the firewall allow-list |
| `nexus-setup.service` | root | `nexus_setup_t` | first boot on tty1; capabilities CHOWN, FOWNER, DAC_OVERRIDE only |
| `nexus-nft-sync.{service,path,timer}`, `nexus-nft-status.{service,timer}` | root | `nexus_nftsync_t` → `iptables_t` | CAP_NET_ADMIN only; see "Firewall" |
| `nexus-plugin-install.{service,path}` | nexus-plugins (+nexus-catalog) | `nexus_plugininstall_t` | oneshot at boot and on `plugins-staging/.trigger`; `PrivateNetwork`; see "Plugins" |
| `nexus-grub-password.service` | root | `unconfined_service_t` (script is bin_t, like nexus-update) | oneshot at every boot and when nexus-setup starts it: copies `/etc/nexus/grub-user.cfg` (only a `GRUB2_PASSWORD=grub.pbkdf2.sha512.…` line, `nexus_grub_user_t`) to `/boot/grub2/user.cfg` (0600), remounting `/boot` rw if it is mounted ro; no mount namespace for that reason; no network (Phase 18, docs/control-plane.md "Boot menu password") |
| `nexus-diag.{service,path}` | root (+nexus-catalog) | `nexus_diag_t` → `journalctl_t`, `chronyc_t`, `iptables_t` | oneshot on `/var/lib/nexus/diag/request.json` (web-api, Settings → Diagnostics): self-checks + redacted support bundle into `/var/lib/nexus/diag/<id>/` (2770 root:nexus-webapi, pruned after 24 h); no inet sockets (`RestrictAddressFamilies=AF_UNIX AF_NETLINK`, `IPAddressDeny=any`; not `PrivateNetwork`, nft must list the host ruleset); bounding set NET_ADMIN, DAC_OVERRIDE, DAC_READ_SEARCH for the tools in their own domains (the policy grants nexus_diag_t no capability). `nexus-update` runs `nexus-diag checks` before staging/applying (in its own unconfined domain) |
| `nexus-disks.{service,path,timer}` | root (+nexus-webapi) | `nexus_disks_t` | oneshot every 5 min and on `/var/lib/nexus/disks/req-*.json` (web-api, Configuration → Hardware): inventory, SMART, md arrays into `status.json`; approved layout requests (mdadm, mkfs.xfs, xfs_growfs, the store's mount unit); `PrivateNetwork`; bounding set SYS_RAWIO, SYS_ADMIN, DAC_READ_SEARCH (docs/hardware.md) |

### Hardening scores (`systemd-analyze security`, in the booted VM, systemd 257)

| Unit | Exposure | What is left |
|---|---|---|
| `nexus-keyd.service` | **0.4 SAFE** | no `RootDirectory`, no `PrivateUsers` (the peer-uid check needs the scheduler's real uid) |
| `nexus-web-api.service` | **1.3 OK** | AF_INET/AF_INET6 on the host network (listens on 8443), supplementary group nexus-catalog, no `PrivateUsers` (group-shared catalog) |
| `nexus-scheduler.service` | **1.6 OK** | network (PVE API/SSH, SFTP, webhook/SMTP), `/dev/kvm`, `@chown` (chgrp of downloads/ to nexus-catalog; no CAP_CHOWN), supplementary groups |
| `nexus-setup.service` | **1.9 OK** | root with CAP_CHOWN/FOWNER/DAC_OVERRIDE (writes into keyd's 0700 dir and chowns to the service users), drives NetworkManager/hostnamed/systemd over D-Bus, owns tty1 |
| `nexus-nft-sync.service` | **1.8 OK** | root with CAP_NET_ADMIN on the host network namespace (it edits the host firewall), resolves the NTS names |

All five units: `NoNewPrivileges`, `ProtectSystem=strict` with explicit `ReadWritePaths`,
`ProtectHome`, `PrivateTmp`, `PrivateIPC`, `ProtectKernel*`, `ProtectControlGroups`,
`ProtectProc=invisible` (not setup), `RestrictNamespaces`, `RestrictSUIDSGID`,
`LockPersonality`, `MemoryDenyWriteExecute` (also for the scheduler: QEMU under KVM maps
no W+X memory), `SystemCallFilter=@system-service` minus `@privileged @resources`
(setup: minus `@resources`), empty or minimal `CapabilityBoundingSet`.

## SELinux (`selinux/nexus.te`, `nexus.fc`)

Enforcing, no permissive domains, no nexus process in an unconfined domain. Each
process enters its domain only through its own exec type; every transition is
NNP-safe (`nnp_transition`, because all units set `NoNewPrivileges`):

```
init_t ─ keyd ──────────> nexus_keyd_t       own state + socket; no network
init_t ─ nexus-web-api ─> nexus_webapi_t     8443 (http_port_t), catalog, downloads (read), TLS key, update control
init_t ─ nexus-scheduler > nexus_scheduler_t catalog, stores, escrow, keyd socket, alerts (http/smtp/unreserved ports)
          ├ nexus-pve ──> nexus_pve_t        PVE API (8006, unreserved) + /usr/bin/ssh in-domain (ssh_port_t), stores, downloads
          │   └ qemu-kvm > nexus_restorevm_t kernel/initrd, /dev/kvm, its two sockets + console log in nexus-pve's /tmp dir
          └ nexus-offsite > nexus_offsite_t  SFTP (telnetd_port_t 23, ssh_port_t, unreserved), stores, escrow (read)
init_t ─ nexus-setup ───> nexus_setup_t      catalog, keyd init, TLS/metrics token, setup-done; D-Bus to NM/hostnamed/systemd;
                                             enable + start only nexus_unit_file_t units
init_t ─ nexus-nft-sync > nexus_nftsync_t ─ nft ─> iptables_t (script on a pipe)
init_t ─ nexus-diag ────> nexus_diag_t       read-only: catalog, update status, web cert, audit log (ausearch), systemd state;
                                             journalctl > journalctl_t, chronyc > chronyc_t, nft > iptables_t; writes only
                                             nexus_diag_var_lib_t; neverallow: inet sockets, keyd socket, keys/stores/credentials
init_t ─ nexus-disks ───> nexus_disks_t      disks (smartctl, mdadm, mkfs.xfs, xfs_growfs in-domain), its dir, the store's
                                             mount unit, systemctl on nexus units; neverallow: inet, keys/catalog/store files
```

Data types are private: `nexus_keyd_var_lib_t` (keys; `neverallow` for everyone but keyd
and setup), `nexus_catalog_t`, `nexus_downloads_t`, `nexus_store_t`, `nexus_escrow_t`,
`nexus_webapi_secret_t` (TLS key, metrics token), `nexus_sshkey_t` (`/etc/nexus/ssh`),
`nexus_scheduler_var_run_t` (job configs with secrets; web-api has a `neverallow` on it
and on stores, keys and SSH keys), `nexus_nft_var_run_t`, `nexus_update_t`,
`nexus_restorevm_image_t`. Every rule carries a comment with its reason. The restore micro-VM (security review
H-3: QEMU parses untrusted guest disks and still shares the `nexus-chunkstore` uid)
has `neverallow`s on keys, stores, escrow, catalog, downloads, credentials, job
configs, the keyd socket and IP sockets, checked against the full policy at image
build. A dedicated uid for QEMU (small runner) is still open. Only keyd may
ever touch `tpm_device_t` (`neverallow`). The OS update agent, greenboot and bootc stay
in the base policy's domains (bootc/ostree need the unconfined service domain, like the
stock `bootc-fetch-apply-updates.service`).

AVC iterations (lab VM, see below): (1) first boot: every `NoNewPrivileges` unit needs
`nnp_transition` into its domain (setup and nft-sync ran in `init_t` and failed); (2) all
nexus domains permissive for one complete run (setup, backup VM 100 + CT 200, retention,
offsite to the SFTP testbox, file restore of CT and VM via the micro-VM, verify, quorum,
audit) to collect every denial at once: userdbd lookups and the setup lock file (setup),
self-connect to its own NBD socket and the restore-VM image dir (nexus-pve), `map` of
the initramfs (QEMU); (3) the same flow enforcing: no denials; (4) fresh image, fresh
disk, the whole flow enforcing from the first boot: no denials.

## Plugins (runtime and installer, docs/plugin-system.md)

A plugin is signed, untrusted code. Pieces in the image:

- `/usr/libexec/nexus/nexus-pluginhost` (`nexus_pluginhost_t`, job domain spawned by the
  scheduler as nexus-chunkstore): the trusted half (store, keyd, sealing, downloads). It
  starts the plugin binary in a forked child with `NO_NEW_PRIVS`, its own process group,
  `PR_SET_PDEATHSIG`, lowered rlimits, nice 10, Landlock (install dir, `/usr`, selected
  `/etc`, its private tmp; TCP connect only to the manifest's ports) and a seccomp
  allowlist, then `execveat`s `bin/plugin`. The scheduler unit therefore allows
  `SystemCallFilter=@sandbox setrlimit prlimit64 setpriority` (lowering only, no
  CAP_SYS_RESOURCE). `RestrictNamespaces=yes` stays: there are no user namespaces on the
  appliance, the host's best-effort `unshare` fails and the plugin keeps the
  nexus-chunkstore uid, so SELinux is the boundary between plugin and host. The plugin
  also inherits the scheduler's `MemoryDenyWriteExecute` (no JIT) and its address
  families (no AF_NETLINK: glibc's `AI_ADDRCONFIG` probe falls back).
- `nexus_plugin_t` is entered only from `nexus_pluginhost_t` through `nexus_plugin_exec_t`
  (`/var/lib/nexus/plugins/<id>/<version>/bin/plugin`) and is outside the `nexus_domain`
  attribute. It may read its install tree, `/usr`, generic `/etc` files, the trust store
  and `resolv.conf`, run the image's tools (incl. `/usr/bin/ssh`, `ssh_exec_t`) in-domain, manage its tmp dir
  (`nexus_plugin_tmp_t`, `/tmp/nexus-plugin-<job>-<rand>` in the scheduler's PrivateTmp,
  never executable) and make TCP connections to any port; nftables and Landlock limit the
  destinations. `neverallow`s: no nexus data (keys, stores, escrow, catalog, downloads,
  SSH keys, job configs, secrets, agent CA, replication keys, `/etc/nexus`, staging), not
  even a directory search; no connect to any nexus socket; no capabilities; no
  listen/accept; no write to its own code or data.
- `/usr/libexec/nexus/nexus-plugin-install` (`nexus-plugin-install.service`, user
  `nexus-plugins`, no network) is the only writer of the install tree (DAC: dirs 0555,
  files 0444, owner nexus-plugins; SELinux: `neverallow` on `nexus_plugin_data_t` /
  `nexus_plugin_exec_t` writes for every other nexus domain). It verifies approved
  bundles from `/var/lib/nexus/plugins-staging` (2770 nexus-webapi:nexus-plugins) against
  the project keys in `/etc/pki/nexus/plugin-keys/*.pub` and the publisher keys in the
  catalog, unpacks into `<id>/.<version>.tmp/`, renames that to `<version>/`, switches the
  `<id>/current` symlink and deletes the staged files. `bin/plugin` gets
  `nexus_plugin_exec_t` by a name type transition (created under exactly that name).
  `nexus-plugin-install.path` starts it when the web-api touches
  `plugins-staging/.trigger` after a quorum approval.
- `/usr/bin/nexus-plugin`: console tool (`verify`, `inspect` a bundle). The test plugin
  `nexus-test-plugin` is never shipped (checked at image build).
- Development images trust `plugin-keys/TEST-KEY-DO-NOT-SHIP.pub` (the TEST release key);
  `release/inject-keys.sh` replaces it with `release/keys/*.pub` and
  `release/check-trust.sh --release` refuses it.

Lab: `lab/appliance/plugins.sh` (signed example bundle, quorum install, backups,
download compared against the source dir, 0 nexus AVCs).

## Firewall (`nftables.conf`, `nexus-nft-sync`)

Inbound (Phase 16c, docs/control-plane.md "Inbound firewall"): loopback, established/related,
ND, DHCP replies, and the services 8443/tcp (`in_web_v4/v6`) and ping (`in_icmp_v4/v6`) from their
source sets (Settings -> Firewall); everything else is recorded in `in_drops_v4/v6` (24 h) and
logged rate-limited as `nexus-in-drop:`. Outbound:
default deny with `reject` (logged as `nexus-out-drop:`); allowed only to the sets
`allowed_out_v4/v6` (addr . proto . port), `dns_servers_*` (53) and `nts_servers_*`
(4460/tcp, 123/udp). The sets are filled at runtime (plan §12.1):

- `nexus-scheduler` writes `/run/nexus-nft/allowed.json` (0644) on each tick when it
  changes: every configured destination resolved to addresses (per source the PVE API
  `connect_addr` or host:8006 and every node's SSH endpoint; per tenant the SFTP box,
  default port 23; webhook URL and SMTP relay from `/etc/nexus/alerts.json`).
- `nexus-nft-sync.path` (PathChanged on that file and on `/etc/resolv.conf`) and a
  30 min timer start `nexus-nft-sync` (root, CAP_NET_ADMIN only). It accepts only IP
  literals, tcp/udp and ports from the file (max 4096 entries; no loopback, multicast or
  unspecified addresses), adds the resolvers from resolv.conf, resolves the NTS names of
  `chrony.conf` and the static `host port [proto]` lines of the optional root-owned
  `/etc/nexus/allowed-hosts`, and applies everything in one `nft -f -` transaction.
- It removes only elements it added itself (state in `/run/nexus-nft-sync/state.json`,
  `destroy element`), so the 443/tcp elements that `nexus-update` adds for a registry
  fetch survive a sync. After a reboot the first run flushes and refills.
- The file's `inbound` rules (per service: enabled, CIDRs) fill the interval sets
  `in_<service>_v4/v6` (always flushed and refilled in the same transaction; enabled + empty
  = any). `nexus-nft-status.timer` (every minute) runs `nexus-nft-sync --status`, which lists
  the table (`nft -j`) and writes `/run/nexus-nft-status/status.json` (0644) for the web UI:
  the managed sets and the recent blocked inbound attempts.

Verified in the VM: before the source existed the backup failed with "No route to
host" (rejected); after the REST config the sets held 10.0.2.2 . tcp . {18006, 10022,
2223} and backup/offsite ran; `curl https://1.1.1.1` and `10.0.2.2:8006` (not
configured) were rejected and logged.

To check `nftables.conf` without root, use a container network namespace:
`podman run --rm --cap-add NET_ADMIN -v $PWD/os/nftables.conf:/n.conf:ro,Z <image> nft -c -f /n.conf`.

## Lab VM (`lab/appliance/`, no root on the host)

bootc-image-builder and `bootc install --via-loopback` need loop devices and mounts,
i.e. root. `build-disk.sh` instead boots an installer VM under unprivileged QEMU/KVM
(the plain bootc base image as an ext4 root made with `mke2fs -d <tarball>`, with its
own kernel + initramfs) and runs `podman run --privileged … bootc install to-disk`
there, as root inside the VM, onto a virtio disk; the image arrives as an oci-archive
on a second ext4 disk. About 2 min, 1.7 GB qcow2.

```sh
lab/appliance/e2e.sh all   # image, disk, boot, setup, api (lab/e2e/m5-api.sh), check
```

`Containerfile.lab` adds only a root autologin on ttyS0 for `con.py` (drives the serial
console); never ship it. `run.sh` boots with BIOS, serial console on a unix socket,
8443 forwarded to 127.0.0.1:28443, optional `TPM=1` (swtpm). From the VM the host is
10.0.2.2 (nested PVE 18006/10022, SFTP testbox 2223). The first boot runs the real
`nexus-setup.service` (a runtime drop-in switches it to `--script` with the answers in
`/etc/nexus/lab-answers.json`, deleted afterwards): DHCP via nmcli, hostname, accounts,
keyd init, TLS, `systemctl enable --now` of the services.

## First boot (`nexus-setup`, crate `crates/setup`)

`nexus-setup.service` runs the console wizard on tty1 on every boot until
`/var/lib/nexus/setup-done` exists. It is a `Type=oneshot` ordered `Before=getty@tty1`
(the pattern of Fedora's initial-setup), so tty1 has no login prompt while setup is
pending; tty2 and later keep their gettys. Quitting the wizard (exit code 3) or an
error restarts it after 3 s. Its stderr (the audit lines) goes to the journal, not
over the TUI. `TTYVTDisallocate=yes` drops the VT contents afterwards.

Steps (docs/control-plane.md "First boot"); every step writes an audit entry with
actor `setup`, and progress is derived from those entries and the files on disk, so
a rerun continues where an interrupted one stopped:

1. **Network:** choose the management NIC (sysfs), DHCP or static (address/prefix,
   gateway, DNS) plus hostname. Applied as NetworkManager profile `nexus-mgmt`
   (`nmcli connection add … ifname <nic>`, `connection up`). IPv4 only for now.
2. **Administrator:** name, password twice (min. 12 characters, argon2id), TOTP
   enrolment (QR code in half blocks with a 2-module quiet zone so it fits 80x25,
   plus the base32 secret); the account is created only after a valid current code.
3. **Security officer:** the same flow, mandatory, and the name must differ from the
   admin. Granting `security_officer` later is itself quorum-gated (control-plane
   contract), so without one created here quorum could never be satisfied.
4. **Key service:** `keyd::init` on `/var/lib/nexus/keyd` (owned by `nexus-keyd`, 0700).
   The recovery key is shown once in 16 numbered groups; 3 random groups must be
   re-entered. It never touches disk or logs, and the screen and scrollback are
   cleared afterwards. Setup never re-initialises keyd. If a run died between
   `init` and the confirmation, the key cannot be shown again: the operator types it
   in full (checked with `keyd::check_recovery_key`) or re-installs.
5. **TLS:** self-signed ECDSA P-256, SAN = hostname + management IPs, 10 years.
   Writes `/etc/nexus/tls/cert.pem` (0644) and `key.pem` (0600, owner `nexus-webapi`)
   and shows the SHA-256 fingerprint to note.
6. **Metrics token:** `/etc/nexus/metrics-token`, 32 random bytes as hex, 0640
   `root:nexus-webapi`. An existing token is kept.
7. **Finish:** writes `/var/lib/nexus/setup-done`, then runs
   `systemctl enable --now nexus-web-api.service nexus-scheduler.service`.

Afterwards a second run is refused. `nexus-setup --force-reconfigure-network` (run as
root on a console) redoes only the network, regenerates the certificate (the SAN
changes) and restarts `nexus-web-api`. Accounts are replaced only after typing the
existing name (TUI, overview `r`) or with `"replace": true` (script mode).

Development and tests never touch the host:

```sh
nexus-setup --root /tmp/x --dry-run                         # TUI; nmcli/systemctl only printed
nexus-setup --root /tmp/x --dry-run --script answers.json   # non-interactive (crate docs: script.rs)
```

`--root` prefixes every written path. Single paths can be overridden with `--catalog`,
`--keyd-dir`, `--tls-dir`, `--metrics-token`, `--setup-done` and `--sys-class-net`, or with
`NEXUS_SETUP_<NAME>` environment variables. Script mode prints the recovery key once to
stdout (the caller's pipe, which is the only way it can be recorded) and answers the
group challenge itself. Keep answer files on tmpfs, since they contain passwords and
TOTP secrets.

## Signed update + rollback in the VM (`lab/appliance/update-lab.sh`)

docs/release.md "Lab test procedure", run on 2026-10-09 with registry:2 on
127.0.0.1:5055, `R=nexus-lab-registry:5055/nexusbackup/appliance`, the TEST cosign key,
images from `Containerfile.update-lab` (lab layer: autologin, insecure lab registry,
`/etc/nexus/allowed-hosts` = `10.0.2.2 5055` so nexus-nft-sync opens the registry,
`NEXUS_UPDATE_EGRESS=none`):

1. v1 (0.0.1) signed + promoted, installed (origin `$R:stable`): `bootc status`
   signature none; `nexus-update stage` → "switching origin … (signature enforced)",
   spec signature `containerPolicy`.
2. Unsigned v2 pushed to `:stable` (skopeo, no signature): `nexus-update stage` →
   "A signature was required, but no signature exists", nothing staged.
3. v2 signed + promoted: `echo stage > /var/lib/nexus/update/request` → staged, download-only.
   ACPI power cycle → still v1, **but the staged deployment was gone** (status `staged: null`,
   `apply` → "nothing staged"; only `UpdateVersion` remained); see open items. Staged again,
   `echo apply > …/request` → rebooted into v2, `greenboot-healthcheck` green,
   `boot_success=1`.
4. v3 = v2 + `/usr/lib/greenboot/check/required.d/00-fail.sh` (exit 1), signed + promoted,
   staged + applied → red boots, greenboot rolled back → v2 booted (rollback = v3, green);
   next tick: "update … did not stick … not applying it again", `failed_digests` = [v3].

Not run (time): maintenance window/inhibit, downgrade guard. Findings: the
registries.conf location remap (`prefix` → `location = "10.0.2.2:5055"`) pulls the image
but finds no sigstore attachment, so the lab resolves the registry name through
`/etc/hosts` instead (`update-lab.sh vm-prep`).

## Deferred (and why)

- **LUKS2 + TPM2 enrolment (§12.2):** deferred together with TPM (user decision); needs the real disk layout and a measured-boot PCR policy. keyd's unit and policy keep the TPM hooks as comments.
- **SSH key management for sources:** in the lab the PVE node key and known_hosts are placed in `/etc/nexus/ssh` (0600 nexus-chunkstore) by hand; the appliance should generate its own key pair and show the public key in the UI.
- **First-boot disk initialization (§12.5):** waits for the real disk layout.
- **Instant recovery under enforcing** was not exercised in the VM (optional in this phase); `ir-serve` uses the same ssh/NBD paths as restore.
- **Download-only staging across a power cycle** (A2, nexus-update): the staged
  download-only deployment did not survive an ACPI power-off/boot in the lab (bootc 1.16.4).
- **bootc's SELinux probe** (`chcon … invalid_bootcinstall_testlabel_t` in
  `unconfined_service_t`, `mac_admin` denied) shows up in `ausearch` on every
  nexus-update/bootc run; harmless, not a nexus domain.
- **nftables reload:** `systemctl reload nftables` empties the sets until the next nft-sync trigger (timer ≤ 30 min or any config change).

## Edge proxy image (`os/edge/`, Phase 26, docs/edge.md)

A second, minimal bootc image for the internet-facing edge proxy: only `nexus-edge` (user `nexus-edge`, SELinux domain
`nexus_edge_t` from `edge/selinux/nexus_edge.te`, 7445/tcp labelled by `nexus_edge-port.cil`), nftables (input 443 +
7445, output DNS/NTP/DHCP only), chrony and nmtui; no SSH, every getty masked, tty1 runs the fixed setup menu
`nexus-edge-setup` (network, enrollment token, control-port restriction). Release keys for pushed updates:
`/usr/share/nexus-edge/release-keys` (build arg `RELEASE_KEYS`, lab: `release/testkey`).
`os/edge/build.sh [--test-key] [--qcow2] [--iso] [--lab-disk OUT]`; the selinux stage alone:
`podman build --target selinux -f os/edge/Containerfile .` (neverallow check). VM lab: `lab/edge/e2e.sh`. Not built in
CI yet.
