# NexusBackup appliance OS image (Phase 0 skeleton)

bootc image on `quay.io/almalinuxorg/almalinux-bootc:10` (AlmaLinux 10.2). Note that
`quay.io/almalinux/almalinux-bootc` does not exist (the registry returns unauthorized);
the official image lives under `almalinuxorg`. See plan.md §4.2 and §12.

## Build

```sh
podman build -t nexus-os:dev os/
```

The build fails if the SELinux module does not compile or install, if the file contexts
do not resolve, if `chrony.conf` does not parse, if sshd is still enabled, or if
`bootc container lint` fails.

## What is in the image

| File | Installed as | Purpose |
|---|---|---|
| `Containerfile` | — | Two stages: `selinux-build` compiles `nexus.pp` with `selinux-policy-devel`; that tooling stays out of the final image |
| `selinux/nexus.{te,fc}` | module `nexus` | Domains `nexus_chunkstore_t`, `nexus_keyd_t`, `nexus_webapi_t`, each with its own exec, `var_lib` and `var_run` types. Only `nexus_keyd_t` gets `tpm_device_t` (enforced by a `neverallow`). chunkstore may connect to the keyd socket. web-api may bind `http_port_t` (8443 already has that type) |
| `sysusers.d/nexus.conf` | `/usr/lib/sysusers.d/` | Static users `nexus-keyd`, `nexus-chunkstore`, `nexus-webapi`. chunkstore is in group `nexus-keyd` so it can reach the keyd socket. keyd is in `tss` so it can open `/dev/tpmrm0` |
| `systemd/nexus-*.service` | `/usr/lib/systemd/system/` | Sandboxed units, installed but **not enabled** until the binaries in `/usr/libexec/nexus/` ship |
| `systemd/10-nexus.preset` | `/usr/lib/systemd/system-preset/` | sshd disabled, nftables and chronyd enabled. This also holds for the first-boot `preset-all`, which would otherwise re-enable sshd through `90-default.preset` |
| `nftables.conf` | `/etc/sysconfig/nftables.conf` | Default-deny in and out. Inbound: only 8443/tcp, loopback, established/related, ND, DHCP replies. Outbound: only the sets `allowed_out_v4/v6` (addr . proto . port), `dns_servers_*`, `nts_servers_*`. All sets are empty, and the control plane fills them at runtime |
| `chrony.conf` | `/etc/chrony.conf` | NTS only (`authselectmode require`, `minsources 2`), no NTP server port, no UDP command port |

The root account is locked (`usermod -L`). Emergency access is through the local console only.

### Unit hardening (`systemd-analyze security --offline=true`, systemd 257 in the image)

| Unit | Exposure | Notes |
|---|---|---|
| `nexus-chunkstore.service` | **0.4 SAFE** | `PrivateNetwork`, AF_UNIX only, `PrivateDevices` |
| `nexus-keyd.service` | **0.6 SAFE** | `PrivateNetwork`, AF_UNIX only, `DevicePolicy=closed` + `DeviceAllow=/dev/tpmrm0 rw`, `SupplementaryGroups=tss` |
| `nexus-web-api.service` | **1.1 OK** | Needs AF_INET/AF_INET6. `SocketBindAllow=tcp:8443` only, `PrivateUsers=yes` |

All three units use `ProtectSystem=strict`, `NoNewPrivileges`, `PrivateTmp`, an empty
`CapabilityBoundingSet`, `SystemCallFilter=@system-service ~@privileged @resources` and
`MemoryDenyWriteExecute`. `systemd-analyze verify` reports only the missing binaries.
The remaining score comes from not using `RootDirectory` and, for chunkstore and keyd,
not using `PrivateUsers`. `PrivateUsers` is left off because it would hide the
supplementary groups (`nexus-keyd`, `tss`) that the socket and TPM access depend on.

To check `nftables.conf` without root, use a container network namespace:
`podman run --rm --cap-add NET_ADMIN -v $PWD/os/nftables.conf:/n.conf:ro,Z <image> nft -c -f /n.conf`.

## Deferred (and why)

- **LUKS2 + TPM2 enrolment (§12.2):** this needs the real disk layout (system mirror, metadata NVMe, data RAID). It also needs measured-boot PCR policy from a signed image and Secure Boot. It belongs in first boot / disk initialization, not in the image.
- **A/B update channel with health-gated rollback:** bootc already provides the A/B deployments (`bootc upgrade` / `rollback`). The health checks (greenboot-style) need running services to check, and the update channel needs a registry plus CI.
- **Image signing:** this needs CI and key management (cosign/sigstore policy in `/etc/containers/policy.json`). Signing a local dev build proves nothing.
- **First-boot TUI (§12.5):** it depends on the web-api (admin account, MFA), keyd (recovery key) and disk initialization. None of these exist yet.
- **Filling the nftables sets and enabling the nexus units:** this is done by the control plane and by the service binaries once they exist.
- **SELinux rule completeness:** the policy has only the rules known to be needed. It still has to be refined under enforcing mode against the real binaries (AVC review, no broad allows).
- **Restore micro-VM (single-file restore from VM images, `restore-vm/`):** the image needs `qemu-kvm` (EL: `/usr/libexec/qemu-kvm`, set `NEXUS_QEMU`; check that its block layer still has the `nbd` driver and seccomp `-sandbox` support) and the `restore-vm/build.sh` output (`vmlinuz`, `initrd.img`) under `/usr/lib/nexus/restore-vm/` (`NEXUS_RESTORE_VM_DIR`). QEMU should run as its own service user in its own SELinux domain (e.g. `svirt_t`-like, sockets in a private directory, `/dev/kvm` only), not in the domain of the restore service.
