# 02 Installation and first boot

This chapter is for **administrators** who install the appliance and for the **security officer**, who must be
present at the console during first boot.

> **Status:** The appliance image and the first-boot wizard run end to end in the lab (a VM with SELinux
> enforcing). There is **no published release yet**: no signed image on the release registry, no installer ISO and
> no tested installation on physical hardware. The disk layout of plan §12.2 (mirrored system disks, NVMe metadata
> tier, RAID6 data tier), full-disk encryption with LUKS2 and TPM, and first-boot disk initialization are **not
> implemented yet**. Treat this chapter as the procedure for test installations.

## Before you start

### Hardware sizing

The reference sizing (plan §3.2 and §12.3) covers 5 tenants with 1–2 TB of raw data each and full GFS retention:

| Component | Recommendation |
|---|---|
| CPU | 8–16 cores |
| RAM | 32–64 GB. NFS/SMB shares with about 1 million files need roughly 0.6–0.7 GB per such share during a backup (the file list is held in memory) |
| System disks | 2 small SSDs, mirrored (bootc image, A/B deployments) |
| Metadata | 2 NVMe drives (≥ 1 TB), mirrored |
| Data | for example 6 × 12 TB in RAID6: about 40 TB usable for 10 TB of raw source data after two years of GFS retention |
| Network | separate NICs for management, backup and offsite traffic (at least two) |
| Firmware | TPM 2.0 and Secure Boot capable (needed later for disk encryption) |

Plan for 30–40 % headroom. The appliance raises a warning alert when the store is more than 75 % full.

### What you need

- The appliance image (a bootc container image built from `os/Containerfile`) and a way to write it to the
  system disk (see below).
- A free IPv4 address on the management network (or DHCP), a host name, and DNS servers.
- Two people for first boot, if you want approvals (four-eyes principle) from the start: the **administrator** and
  a **security officer**, each with their own authenticator app (TOTP) on a phone or hardware token.
- Paper and pen, or an offline password safe, for the **recovery key**.

## Install the image

The appliance is a bootc image based on AlmaLinux 10. It is installed with `bootc install to-disk`, which writes the
image to a disk and makes it bootable:

```sh
podman build -f os/Containerfile -t localhost/nexus-os:dev .      # build (repository root as context)
# on the target machine, as root, booted from a live system that has podman:
podman run --rm --privileged --pid=host -v /dev:/dev -v /var/lib/containers:/var/lib/containers \
  --security-opt label=type:unconfined_t localhost/nexus-os:dev \
  bootc install to-disk --wipe --filesystem xfs \
  --enforce-container-sigpolicy --target-imgref ghcr.io/undone37/nexusbackup:stable /dev/sdX
```

`--target-imgref` names the image the appliance follows for updates. `--enforce-container-sigpolicy` makes the
appliance accept only signed updates from that repository right away. Without it, the appliance switches to
signature enforcement on its first update check (see [13 Updates](13-updates.md)).

> **Status:** Only the lab procedure is tested: `lab/appliance/build-disk.sh` boots an installer VM and runs
> exactly this `bootc install to-disk` onto a virtual disk (about 2 minutes, a 1.7 GB disk image). Installation
> on physical servers, RAID set-up and the multi-disk layout are not tested.

The installed system has:

- a locked root account and **no SSH server**: emergency access is through the local console only;
- SELinux enforcing; every service in its own user, systemd sandbox and SELinux domain;
- a firewall that blocks everything except the management port (see [Network and firewall](#network-and-firewall)).

## First boot: the `nexus-setup` wizard

On first boot the console (tty1) shows the setup wizard instead of a login prompt. It runs on every boot until
setup is complete. Progress is saved after each step, so if the machine reboots or you quit the wizard (`q`), it
continues where it stopped. The overview screen lists all steps; `r` redoes the network, an account or the
certificate.

Keys in forms: Tab or Up/Down moves between fields, Left/Right chooses an option, Enter continues, Esc goes back.

### Step 1: management network

1. Choose the network card that will carry the web interface. Only this network can reach the web UI (port 8443).
2. Choose **DHCP** or **static**. For static, enter the address with prefix (for example `192.0.2.10/24`), the
   gateway and the DNS servers (comma-separated).
3. Enter the host name (for example `backup.example.com`).

The wizard creates the NetworkManager profile `nexus-mgmt`. Only IPv4 is supported for now.

### Step 2: administrator account

1. Enter a user name and a password twice (at least 12 characters).
2. Scan the QR code shown on the console with your authenticator app (issuer `NexusBackup`, TOTP SHA-1, 6 digits,
   30 s), or type the secret shown below it.
3. Type the current 6-digit code. The account is created only when the code is correct.

### Step 3: second person (security officer)

The wizard recommends a **second person**: a security officer who approves destructive or weakening changes
(see [10 Approvals and audit](10-approvals-and-audit.md)). Choose one of:

- **now (recommended):** the security officer sits down at the console and sets their own user name, password
  (different from the administrator's name) and authenticator, exactly as in step 2. With two people, approvals
  start **enabled**.
- **later:** approvals start **disabled**. Every action still takes effect and is recorded in the audit log. You can
  add a second person in the web UI (**Users**) and enable approvals afterwards under **Settings → Approvals** (see
  [09 Users and access](09-users-and-access.md)).

### Step 4: key service and recovery key

The appliance now creates its master key (KEK). All tenant keys are wrapped with it.

1. Make sure nobody else can see the screen. Press Enter to create the key.
2. The **recovery key** appears once: 16 numbered groups of 4 hex digits (0–9, A–F). Write down all groups. Do not
   photograph it.
3. Type `YES` when you have written it down.
4. Re-enter the 3 randomly chosen groups the wizard asks for. If they do not match, new groups are chosen; Esc
   shows the key again (until it is confirmed).

After confirmation the key is removed from the screen and from memory. It is **never written to disk or to a
log**. If the wizard was interrupted after the key was created but before you confirmed it, the key cannot be shown
again: type it in full (64 hex digits, dashes optional) or reinstall the appliance (nothing has been encrypted yet).

### Step 5: TLS certificate

The wizard creates a self-signed certificate (ECDSA P-256, valid for 10 years) for the host name and the management
IP addresses, and shows its **SHA-256 fingerprint**. Write it down. You compare it when your browser warns about
the certificate on first sign-in. A secondary appliance for replication also needs it (see
[08 Replication](08-replication.md)).

### Step 6: metrics token

The wizard creates `/etc/nexus/metrics-token`, the bearer token for the `/metrics` endpoint (see
[11 Alerts and monitoring](11-alerts-and-monitoring.md)). An existing token is kept.

### Step 7: finish

The summary shows the web address, the certificate fingerprint and whether approvals start enabled. Press Enter: the
wizard writes `/var/lib/nexus/setup-done` and starts the services (web API, scheduler, key service, replication
daemon). After that a second run of the wizard is refused.

### Changing the network later

Run this on the local console as root:

```sh
nexus-setup --force-reconfigure-network
```

It redoes only the network step, creates a **new TLS certificate** (the addresses in it change, so the fingerprint
changes too) and restarts the web API. Tell everybody who pinned the old fingerprint, for example the secondary
appliance of a replication.

## Store the recovery key

The recovery key is the only way to decrypt your backups if the appliance is lost. With the recovery key and the
offsite credentials you can restore on new hardware (see [14 Disaster recovery](14-disaster-recovery.md)).

- Keep at least two copies offline, in different safe places (for example a safe and a bank deposit box).
- Never store it on the appliance, in a ticket system, by e-mail or in the same place as the offsite credentials.
- Anyone with the recovery key **and** access to the offsite copy can read all tenants' data. Treat it like the
  master key of the building.
- The appliance cannot show it again. If you lose it while the appliance still works, your backups stay readable,
  but you lose the disaster-recovery path. There is no function to issue a new recovery key yet.

## First sign-in

Open `https://<host name or IP>:8443/` in a browser on the management network, for example
`https://backup.example.com:8443/`. The browser warns about the self-signed certificate: compare the fingerprint it
shows with the one you wrote down in step 5, then accept it.

Sign in with your user name, password and the current code from your authenticator app (under **or with an
appliance account**; the **Sign in with …** button appears only after single sign-on has been set up).

![Sign-in page](images/login.png)

Next steps:

1. Create tenants and offsite targets: [07 Offsite](07-offsite.md).
2. Add sources: [04 Sources](04-sources.md).
3. Create policies and protection groups: [05 Policies and groups](05-policies-and-groups.md).
4. Create accounts for the other people: [09 Users and access](09-users-and-access.md).
5. Under **Settings**: set up alert delivery ([11 Alerts](11-alerts-and-monitoring.md#delivery-by-webhook-and-e-mail))
   and, optionally, single sign-on ([09 Users and access](09-users-and-access.md#single-sign-on-oidc)).

## Network and firewall

- **Inbound:** only TCP 8443 (web UI, REST API and, for replication peers, the replication endpoint). Everything
  else is dropped.
- **Outbound:** blocked by default. The scheduler keeps an allow-list of every destination you configure (PVE API
  and node SSH, agents, TrueNAS, NFS/SMB servers, plugin endpoints, offsite targets, replication primaries, the alert
  webhook and SMTP relay). A small privileged helper (`nexus-nft-sync`) applies it to the firewall within seconds of
  a change, and every 30 minutes. DNS servers and the NTS time servers are allowed automatically. Blocked connections
  are logged with the prefix `nexus-out-drop:`.
- Extra static destinations can be listed by root on the console in `/etc/nexus/allowed-hosts`, one
  `host port [proto]` per line.
- The sources never connect to the appliance. The appliance connects to them (pull model).

> **Status:** `systemctl reload nftables` empties the allow-list until the next sync (at most 30 minutes, or the next
> configuration change). Outbound rules work with resolved IP addresses, which is fragile for endpoints behind
> rotating DNS (for example large S3 providers or CDNs).

## Known gaps after installation

These are open production items (see `state.md`, "Production gaps"):

- **Console root shell:** several maintenance tasks in this manual (update rollback and maintenance window, network
  change, SSH key files, disaster recovery, the break-glass reset of a locked-out administrator) need a root shell on
  the local console. The image locks the root password and has no documented way to get a root shell yet; the lab VMs use a lab-only console autologin. Plan how you will get emergency access
  (for example booting a rescue system) before you rely on it.

- **SSH keys for Proxmox VE nodes:** **Settings → Appliance SSH keys** shows and rotates the appliance's keys, but
  its appliance-side part is still being integrated, so the appliance does not create its own key pair yet. The PVE
  source refers to a private key file and a `known_hosts` file under `/etc/nexus/ssh/` on the appliance (for example
  `/etc/nexus/ssh/pve.key`). These files must be placed there by root on the console (owner `nexus-chunkstore`, mode
  0600). For TrueNAS sources the key is entered in the web UI instead (see [04 Sources](04-sources.md)).
- **SFTP keys for the Storage Box** are also files on the appliance; the web UI only takes the path.
- **Appliance configuration backup:** the catalog (users, sources, policies) and the keys `totp.key` and
  `secrets.key` are not backed up automatically (see [14 Disaster recovery](14-disaster-recovery.md)).
- **Disk encryption:** LUKS2 with TPM unlock is deferred. Backup data is always encrypted per chunk, but the master
  key file (`kek.local`) is protected only by file permissions and SELinux, not by a TPM.
- **Certificate renewal** for agents and TrueNAS pins is not automated.
