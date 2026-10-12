# 14 Disaster recovery

This chapter is for **administrators** and **security officers**. It explains what you need when the appliance is
lost (hardware failure, fire, ransomware on the management network) and how the backups are recovered.

> **Status:** Disaster recovery from an offsite copy is a **console/CLI procedure**, proven in lab drills only (a
> fresh store, an SFTP test box and MinIO with Object Lock; the restored VM disk was bit-identical). It is **not
> integrated** into the first-boot wizard or the web UI, it has not been run on real hardware or against a real
> Hetzner Storage Box, and it does **not** restore the appliance configuration (see
> [What is not recovered](#what-is-not-recovered)). Practise it before you depend on it.

## What protects you

| Scenario | What you need | Where the data comes from |
|---|---|---|
| Appliance lost, tenant has an offsite target | recovery key + offsite credentials (SFTP key or S3 access key) + new hardware | Storage Box or S3 bucket ([07 Offsite](07-offsite.md)) |
| Appliance lost, tenant is replicated | the secondary appliance (it has its own keys) | the secondary's local store ([08 Replication](08-replication.md)) |
| Single snapshot damaged locally | nothing extra | `verify` finds it; restore an older snapshot, or fetch it from offsite (below) |
| The only administrator lost the authenticator or password | recovery key + local console | [Break-glass](#break-glass-the-only-administrator-lost-their-authenticator) (below) |
| A root shell is needed on the appliance (repairs, rollback, the break-glass reset) | a one-time code approved by a second person, or the recovery key + local console | [Emergency root shell on the console](#emergency-root-shell-on-the-console) (below) |
| Ransomware or another incident hit a protected system; evidence must be kept | a security officer | [Incident: hold the good snapshots first](#incident-hold-the-good-snapshots-first) (below) |

### The recovery key

During first boot the key service creates the appliance master key (KEK) and shows the **recovery key** once
(16 groups of 4 hex digits, see [02 Installation](02-installation.md#step-4-key-service-and-recovery-key)).

- Every tenant's data key (DEK) is wrapped with the KEK. The KEK itself is also stored wrapped with the recovery key
  (`kek.recovery`).
- Before every offsite run the appliance writes the **key escrow** to the offsite target, below `keys/`:
  `keys/kek.recovery` and `keys/tenants/<tenant>/dek.<version>`. These files are useless without the recovery key.
  On S3 with Object Lock the escrow objects are locked at least as long as the longest-locked snapshot.
- The offsite copy is therefore **self-describing**: packs, indexes, manifests and wrapped keys. With the recovery key
  and the storage credentials it can be read without the original appliance.

Keep the recovery key offline and separate from the offsite credentials (see
[02 Installation](02-installation.md#store-the-recovery-key)). A replicated secondary has its **own** recovery key:
store that one too.

## Incident: hold the good snapshots first

When a source was encrypted or tampered with, or a legal case needs its backups, keep the snapshots before anything
else can remove them. Retention keeps running during the investigation and would otherwise prune the last good
restore points on schedule.

1. **Security officer:** on **Alerts**, **Hold last good snapshot** on the `anomaly` alert, or on **Snapshots**
   **Hold a time range…** for the affected tenant (and guest) from well before the incident until now. Give the case
   or ticket number as the reason. The holds apply at once ([06 Restores](06-restores.md#legal-hold)).
2. If the tenant is replicated, the secondary shows the holds as advice: its security officer applies them there too
   ([08 Replication](08-replication.md#legal-holds-from-the-primary)).
3. Restore from a held snapshot as usual ([06 Restores](06-restores.md)); check the audit log for what happened.
4. When the case is closed, request **Release hold** for each snapshot; a second approver confirms it. Retention then
   prunes them on its normal schedule.

## Recover a tenant from the offsite copy

Run these steps on the local console of the new machine, as root, with the appliance image installed. One run
recovers **one tenant** (each tenant has its own offsite target).

1. **Prepare an empty key directory and store.** The DR command imports the escrow into a key directory that does
   not have a different `kek.recovery` yet. It refuses to overwrite the keys of an appliance that already ran its own
   key initialization.
2. **Write a job configuration** for `nexus-offsite` (the same format the scheduler generates). Example for a
   Storage Box:

   ```json
   {
     "store": "/var/lib/nexus/chunkstore/initech",
     "tenant": "initech",
     "keyd_socket": "/run/nexus-keyd/keyd.sock",
     "escrow_dir": "/var/lib/nexus/escrow/initech",
     "state": "/var/lib/nexus/offsite/initech",
     "remote": {
       "type": "sftp",
       "host": "u123456.storagebox.example.net",
       "port": 23,
       "user": "u123456",
       "key_file": "/root/dr/initech.key",
       "host_key": "ssh-ed25519 AAAA…",
       "base_dir": "nexus"
     }
   }
   ```

   For S3 use `"type": "s3"` with `endpoint`, `region`, `bucket`, `prefix`, `access_key`, `secret_key_file` (a file
   containing the secret key), and `"lock": true` if the bucket uses Object Lock. You need the **pinned SSH host key**
   of the Storage Box; take it from your records, not from the network.
3. **Recover the keys and rebuild the offsite inventory.** The recovery key is read from standard input:

   ```sh
   /usr/libexec/nexus/nexus-offsite /root/dr/initech.json dr /var/lib/nexus/keyd
   ```

   This copies the escrow files from the target, re-seals the KEK on this machine with the recovery key, opens the
   tenant store and indexes every pack and snapshot on the target. On S3 the retention locks are read back from the
   objects, so lock extensions survive. Output: `DR: keys recovered, <n> packs and <m> snapshots indexed`. A wrong
   recovery key or a wrong tenant key is refused.
4. **Start the key service** on the recovered key directory, so the other commands can get the tenant keys:

   ```sh
   /usr/libexec/nexus/keyd serve /var/lib/nexus/keyd /run/nexus-keyd/keyd.sock nexus-chunkstore
   ```
5. **List and restore snapshots** from the target into the local store:

   ```sh
   /usr/libexec/nexus/nexus-offsite /root/dr/initech.json list
   /usr/libexec/nexus/nexus-offsite /root/dr/initech.json restore vm-100 1791939600
   ```

   `restore <source> <time>` copies one snapshot (its manifest, indexes and all chunks it needs) into the local store.
   Every chunk is verified (authenticated decryption and keyed hash) before it is written. Restore the newest snapshot
   of each guest first.
6. **Bring the data back to the sources.** Once the snapshots are in the local store of a configured tenant, use the
   normal restores ([06 Restores](06-restores.md)): full VM restore to a Proxmox VE node, file downloads, restore to
   path.

> **Status:** Steps 1–5 are the tested drill (`nexus-offsite … dr`, then `restore`, then a VM disk compared with the
> original). Step 6 requires the tenant, sources and the scheduler to be configured on the new appliance with the
> recovered key directory. How the first-boot wizard and the recovered keys fit together is **not implemented as a
> guided procedure** and has not been tested end to end. The lab drills ran the commands as a developer, not from a
> root console of an installed appliance under SELinux enforcing; the policy restricts access to key files to the
> key service and the setup wizard, so these commands may need adjustments there. If you face a real disaster, contact the project before you
> run first boot on the replacement hardware.

## Recover from a replicated secondary

If the lost appliance replicated a tenant to a second appliance, the data is already there:

1. Sign in to the **secondary** appliance. Its snapshots of the tenant are marked **Replicated from <primary>** on the
   **Snapshots** page.
2. Restore as usual: file browsing and downloads work with the secondary's keys only. For full VM restores, add the
   DR site's Proxmox VE cluster as a source of the replicated tenant (a replicated tenant accepts sources as restore
   targets, but no protection groups or agents).

![Replicated snapshots on the secondary](images/snapshots-replicated.png)

The secondary keeps its own retention and never deletes because the primary deleted. It cannot be "promoted" to a
primary: replicated tenants take no new backups on the secondary. To protect the sources again, set up a primary
(the repaired or a new appliance) and configure the tenant there.

> **Status:** Restore on a secondary with the primary powered off was tested in the two-appliance lab (file download
> from a replicated VM snapshot). A full VM restore on the secondary was not part of that test.

## Emergency root shell on the console

The appliance has no root password and no SSH server. Tasks that need root (the network change, update rollback, SSH
key files, the offsite recovery above, the break-glass reset below) are done on the **local console**: the physical
screen and keyboard, or the hypervisor's console of a virtual appliance. **tty2** (press **Alt+F2**; in a graphical
VM console **Ctrl+Alt+F2**) shows the console gate instead of a login prompt:

```
NexusBackup appliance: emergency console
...
Unlock code or recovery key:
```

It accepts one of two things.

**A one-time code (normal case).**

1. An administrator opens **Configuration → Settings → Console access**, chooses the **Shell duration** (1 to
   8 hours), enters a **Reason** and clicks **Request**.
2. With approvals enabled, another administrator or a security officer approves the request `console unlock` on the
   **Approvals** page ([10 Approvals and audit](10-approvals-and-audit.md)). With approvals disabled the request is
   approved at once (still audited and alerted).
3. The requester clicks **Show code** and confirms. The code (4 groups of 5 characters, for example
   `7K3QD-1M9ZX-ABCDE-FGHJK`) is shown **once**; the appliance keeps only its hash. Showing it raises the critical
   alert `console_unlock`. The code must be used within **24 hours of the approval**.
4. At the console, on tty2, type the code (case, spaces and dashes do not matter) and press Enter. A root shell
   opens for the approved duration. The code works once.

![Settings: Console access](images/settings-console.png)

![The one-time code, shown once](images/console-code.png)

An administrator or a security officer can **Revoke** an approved or shown code that is no longer needed; it stops
working at once.

**The recovery key (when nobody can approve or the web interface is down).** Type the recovery key (16 groups of 4
hex digits) at the same prompt, then the shell duration in hours (1 to 8, default 1). It is checked against the key
service exactly like at first boot. Use this only when the code path is impossible: the recovery key also decrypts
every backup ([The recovery key](#the-recovery-key)).

While the shell runs:

- it is a full root shell (SELinux `unconfined_t`), limited to the chosen duration: when the time is up the
  appliance ends the shell and everything started from it. Leave it earlier with `exit`;
- the critical alert `console_root_shell` is raised and delivered through the alert channels
  ([11 Alerts and monitoring](11-alerts-and-monitoring.md));
- every administrator, security officer and operator sees a red banner in the web interface ("Root shell running on
  the console: since …, ends at the latest …"), until the shell ends;
- the audit log records `console.root_shell` (who requested and approved the code, or `recovery_key`) and, at the
  end, `console.root_shell_end` with the duration. Rejected input is recorded as `console.unlock_failed`.

![The banner while a console root shell runs](images/console-shell-banner.png)

After **5** rejected attempts within **15 minutes** the gate refuses further attempts until the oldest of them is
15 minutes old (and waits a few seconds after each rejected attempt). Before first boot setup is complete the gate
only points to the setup wizard on tty1.

Everything done in the shell is the operator's responsibility and is not recorded command by command. Agree with
the approver what will be done, and close the shell as soon as the task is finished. Afterwards check the audit log
and acknowledge the alerts (administrators and security officers).

> **Status:** Implemented in Phase 14 (console gate `nexus-console-gate` on tty2, the web interface, unit and API
> tests). The appliance VM test (`lab/appliance/console-gate.sh`) drives a second instance of the gate over the
> serial console, because the lab VM has no screen for tty2. It has not been used on real hardware yet.

## Break-glass: the only administrator lost their authenticator

Normally another administrator issues a new activation code ([09 Users and access](09-users-and-access.md#lost-password-or-authenticator)).
If there is no other administrator who can sign in, reset the account on the appliance's console with the
**recovery key**. Nobody can do this over the network.

You need:

- a root shell on the appliance's local console (physical console or the hypervisor's console): with nobody else to
  approve a code, open it with the recovery key ([Emergency root shell on the console](#emergency-root-shell-on-the-console));
- the written recovery key (the same key as at setup, see [The recovery key](#the-recovery-key)).

Procedure:

1. On the console, as root, run:

   ```sh
   nexus-setup recover-admin --user admin
   ```

   `--user` names the administrator account to reset (here `admin`).
2. Enter the recovery key when asked. A wrong key is refused.
3. The command resets the account to **Pending activation**: its old password and authenticator stop working. It prints a new **one-time activation code**.
4. If approvals are enabled and at least two people could approve, the command refuses, because the reset bypasses
   the four-eyes rule. If those people really cannot help (for example a security officer exists but no other
   administrator), repeat it with `--force-solo`. The recovery is then flagged as a solo action in the audit log and
   the alert; tell the security officer.
5. In a browser, open the sign-in page, click **Activate account** and activate the account with the user name and the
   code: choose a new password and set up a new authenticator
   ([09 Users and access](09-users-and-access.md#activating-your-account)).

What the appliance records:

- the audit entry `user.break_glass`;
- a critical alert of kind `break_glass`, sent through the configured alert delivery
  ([11 Alerts and monitoring](11-alerts-and-monitoring.md));
- a red banner for every administrator in the web interface: "Break-glass recovery was used: … Check the audit log,
  then acknowledge." with **Open audit log** and **Acknowledge**. It stays until an administrator acknowledges it.

After the recovery, check the audit log for anything unexpected, acknowledge the banner, and create a second
administrator so this is not needed again.

Single sign-on accounts cannot be recovered this way: their sign-in is handled by the identity provider. If the
identity provider is unavailable, sign in with a local administrator account (see
[09 Users and access](09-users-and-access.md#single-sign-on-oidc)); if none can sign in, use the procedure above on a
local administrator account.

> **Status:** `nexus-setup recover-admin` is part of the image (unit-tested). The root shell it needs comes from the
> console gate ([above](#emergency-root-shell-on-the-console)); the two together have not been run on real hardware.
> A second administrator remains the better protection.

## What is not recovered

The offsite copy and the replica contain **backup data and tenant keys only**. They do not contain the appliance
configuration. After a total loss you must recreate by hand:

- the catalog: tenants, sources, policies, protection groups, users and their roles, the settings (approvals, alert
  delivery, single sign-on), alerts and job history, and the **audit log** (it lives only in the catalog; forwarding it off the appliance is not
  implemented yet, see [10 Approvals and audit](10-approvals-and-audit.md));
- `totp.key` (the key that encrypts the users' TOTP seeds) and `secrets.key` (the scheduler's key for source and
  offsite secrets): users must enroll again and all source passwords, API tokens and keys must be entered again;
- the agent CA: every Linux/Windows agent must be enrolled again with a new token ([04 Sources](04-sources.md));
- replication peers and plugin installations (plugins must be uploaded and approved again, [12 Plugins](12-plugins.md));
- SSH key files under `/etc/nexus/ssh/` and the offsite key files.

> **Status:** An appliance configuration backup is an open production item. Until it exists, keep an up-to-date
> written record of your configuration (sources, policies, groups, offsite targets with pinned host keys, users).

## Practise

Run a drill at least once a year and after major changes:

1. **Check the written recovery key** on the running appliance (root, local console). The key is read from standard
   input and compared with the key service; nothing is changed:

   ```sh
   /usr/libexec/nexus/keyd check-recovery /var/lib/nexus/keyd
   ```
2. **Watch the offsite checks:** every offsite job ends with an inventory check (packs or manifests missing on the
   target), and the daily verify job also reads 3 sampled packs from the target. Problems raise alerts
   ([11 Alerts and monitoring](11-alerts-and-monitoring.md)).
3. **Do a full DR drill** on spare hardware or a VM: install the image, run the procedure above for one tenant with
   the real recovery key and offsite credentials, restore one VM to a test node and boot it. Record the time it took.
4. **For replication:** restore a file from the secondary while the primary is unreachable.
5. Record the drill in your own change log (date, tenant, snapshot, result, duration).
