# 15 Troubleshooting and FAQ

Start with the job log: open **Jobs**, click the failed job and read the last lines of its **Log**. The alert of a
failed job (`job_failed`) repeats them. Each entry below lists the symptom, the cause and the fix.

## Signing in

**Sign-in fails although password and code are right.**
Each authenticator code works only once, and a code is valid for 30 seconds (one step before or after is
tolerated). Wait for the next code. Check that the clock of your phone is correct.

**"Too many attempts".**
After 5 failures for a user or from an address within 15 minutes, sign-in is locked for 15 minutes. Wait. The failures
are in the audit log (`auth.login_failed`).

**Lost authenticator or password.**
Another administrator issues a new activation code (see [09 Users and access](09-users-and-access.md#lost-password-or-authenticator)).
If you are the only administrator, use the console break-glass procedure with the recovery key
([14 Disaster recovery](14-disaster-recovery.md#break-glass-the-only-administrator-lost-their-authenticator)).

**Activation code rejected.**
The code is valid for 72 hours and only once. For administrators and security officers with approvals enabled, the
code has two parts and works only after the approval; enter both parts. Ask for a new code if it expired.

**Approvals show "Disabled" right after installation.**
First boot was finished with "second person later". Add an administrator or security officer under **Users**, let
them activate the account, then click **Enable approvals** under **Settings → Approvals**.

**The page is dark (or light) although I want the other theme.**
By default the interface follows the light/dark setting of your operating system. Click the theme button in the top
bar (sun, moon, or half sun) until its tooltip shows the theme you want: it cycles through **Theme: follow the
system**, **Theme: light** and **Theme: dark**. The choice is stored in this browser only; a private window or another
browser starts again with the system setting.

**A red "Break-glass recovery was used" banner appears.**
Someone reset an administrator account on the console with the recovery key. Open the audit log (`user.break_glass`),
make sure the recovery was planned, then click **Acknowledge**
([14 Disaster recovery](14-disaster-recovery.md#break-glass-the-only-administrator-lost-their-authenticator)).

<a id="single-sign-on"></a>
## Single sign-on

If a sign-in through the identity provider (IdP) fails, the appliance returns to its sign-in page and shows the reason
in a red box:

| Message | Meaning | Fix |
|---|---|---|
| "Your organization account has no access to this appliance (no matching group mapping). Ask an administrator." | none of the user's groups matches a group mapping (code `denied`); an existing single sign-on account is disabled | add the user to a mapped group at the IdP, or add a mapping under **Settings → Single sign-on**. Check that the IdP sends the groups claim, and in the form the mapping expects (Entra ID sends group object IDs, Keycloak group names without path) |
| "Single sign-on is turned off on this appliance." | **Allow single sign-on** is off (code `disabled`) | an administrator turns it on, or users sign in with an appliance account |
| "The sign-in took too long. Please try again." | more than 10 minutes passed between leaving for the IdP and coming back (code `expired`) | try again |
| "The sign-in could not be verified (state mismatch). Please try again." | the answer did not belong to the sign-in this browser started (code `state`): e.g. two sign-ins in parallel tabs, a bookmarked IdP page, blocked cookies, or the appliance opened under a different address than the registered redirect URI | close other sign-in tabs, allow cookies for the appliance, and always open the appliance under the address registered at the IdP |
| "The identity provider reported an error. Please try again or contact your administrator." | the IdP refused or cancelled the sign-in (code `idp`), e.g. the user cancelled, is not assigned to the application, or failed MFA | check the IdP's sign-in log |
| "The answer of the identity provider could not be verified. Contact your administrator." | the ID token failed a check (code `token`): issuer, audience (client ID), expiry, nonce or signature; or the client secret is wrong | compare **Issuer URL** and **Client ID** with the IdP, enter the client secret again (expired Entra ID secrets are a common cause), check the appliance clock, and run **Test connection** |
| "Single sign-on failed (…). Please try again or contact your administrator." | another error | the appliance's audit log and the IdP's log name the cause |

**The "Sign in with …" button is missing.**
Single sign-on is not set up or not allowed (**Settings → Single sign-on**, **Allow single sign-on**), or a change of
these settings is still waiting for approval.

**Test connection fails.**
The appliance cannot fetch `<issuer>/.well-known/openid-configuration` or the signing keys: wrong **Issuer URL** (for
Entra ID it ends in `/v2.0`, for Keycloak in `/realms/<realm>`), or the IdP is not reachable from the appliance. The
test uses the saved settings: save first.

**A single sign-on user cannot sign in with the user name and password form.**
Expected: single sign-on accounts have no appliance password or authenticator. Use **Sign in with …**.

**A single sign-on user has the wrong role or tenant.**
Role and tenants are set from the mappings at every sign-in; the highest-privileged matching mapping wins. Check the
user's groups at the IdP and the mappings, then let the user sign out and in again.

## Backups

**VM backup fails with a fleecing error (e.g. "fleecing storage … is full").**
VM backups need a fleecing storage on the node with free space. Set **Fleecing storage** in the source to fast local
thin storage (e.g. `local-lvm`) and free up space there.

**The first backup after a VM or host restart takes much longer.**
Expected: the dirty bitmap is lost when QEMU restarts, so the disk is read once completely. Only changed chunks are
stored.

**A guest shows "Overdue" on the Dashboard, or an object appears under "Objects needing attention".**
"Overdue" in the **Protection status** table: its newest snapshot is older than 26 hours (2 hours with an hourly
policy). **Breached** under **Objects needing attention**: the last good backup is older than 1.5 × the policy period
(36 hours for daily, 90 minutes for hourly). **Never**: the object is in a group but was never backed up successfully.
Look for failed backup jobs of its group, or a job of the same source that blocks the queue.

**The Dashboard says "Key figures are not available right now".**
The appliance could not compute the key figures. The **Protection status** table below still works. If it persists,
the appliance-side dashboard service may not be available on your version yet.

**A job stays "Queued" for a long time.**
Only one job per source runs at a time. A long backup or restore of the same source delays the next job. Queued jobs
can be cancelled by administrators and operators.

**Agent shows "Token expired", or Enroll is greyed out.**
Enrollment tokens are valid for 24 hours. Click **New token**, run
`sudo /usr/local/sbin/nexus-agent init --token -` on the host, paste the token, then click **Enroll**. After 5
failed proofs the agent locks enrollment; `init --token` clears the lock.

**Agent backup "not point-in-time consistent" and a `backup_inconsistent` alert.**
The volume has no LVM, ZFS or btrfs snapshot support, so it was read live. Move the data to LVM/ZFS/btrfs, or accept
the flagged backup.

**Share backup always marked inconsistent.**
No **NAS snapshot directory** is set, or no snapshot matches the **Snapshot name prefix**. Set `.zfs/snapshot`,
`.snapshot` or `~snapshot` and check the prefix. The alert for a missing snapshot is raised once per source.

**NFS backup misses files or reports unreadable entries.**
The export is not `ro,all_squash,anonuid=0,anongid=0` for the appliance's address, so only world-readable files can
be read. Fix the export. For SMB, use an account in Backup Operators (Windows) or Samba `admin users`.

**TrueNAS backups fail with a TLS error after months.**
TrueNAS renewed its certificate and the pinned one no longer matches. Paste the new certificate (or its CA) into the
source.

**TrueNAS SSH refused after you changed the datasets.**
The forced-command line in `authorized_keys` contains the datasets. Paste the new line shown in the source dialog into
the TrueNAS user's "SSH public key" field.

**PostgreSQL server disk fills with WAL.**
The replication slot of cluster backups keeps WAL while backups are not running. Run backups again, or drop the slot
(`SELECT pg_drop_replication_slot('nexusbackup')`) when you remove the source, or set `max_slot_wal_keep_size`.

**Plugin upload rejected with "signature verification failed".**
The signing key is not trusted, or the key's publisher differs from the `publisher` in the manifest. Add the
publisher key (with approval) after comparing its fingerprint with the publisher.

**A new destination cannot be reached ("No route to host", timeouts).**
The outbound allow-list is applied a few seconds after a configuration change and every 30 minutes. A reload of the
firewall empties it until the next sync. Wait, or save the configuration again to trigger a sync. Dropped connections
are logged with the prefix `nexus-out-drop:`.

## Restores

**Container restore fails with "no space" or a tar error.**
The node stages the container under `/var/tmp/nexusbackup`. Free space on the node's root file system, or restore on
another node.

**VM/CT restore fails with a permission error on the network.**
The PVE API token lacks `SDN.Use` on the bridge's zone. Grant `PVESDNUser` on `/sdn/zones/<zone>`.

**Restore fails because of the target storage.**
**Target storage** must be a PVE storage for VM disks or container volumes (e.g. `local-lvm`), not the NexusBackup
storage.

**Instant recovery refused.**
The VM has a TPM state (`tpmstate0`) or is a template. Use **Restore → Full restore to a new VM / container**.

**A plugin restore is missing from the Restore menu.**
The menu offers only the restores that apply to this kind of snapshot. PostgreSQL, for example, offers the dump
restore only on database snapshots (`plugin-postgresql-<source>-<db>`) and the point-in-time restore only on cluster
snapshots (`plugin-postgresql-<source>`). Security officers see no **Restore** menu at all.

**Instant-recovered VM hangs or gets I/O errors.**
The connection between the node and the appliance was interrupted before the disk move finished. Restore
connectivity; resuming the export is a command-line step (`nexus-pve … ir-serve`). Keep enough space on the node's
root file system for the guest's writes.

**Browse files shows no files or a mount error for a VM.**
The volume is not supported by the restore micro-VM (LUKS, BitLocker, ZFS native encryption, dynamic disks, zvols,
duplicate pool or volume-group names). Restore the whole VM instead.

**Download link gone or answers 403/404.**
Prepared downloads expire after 24 hours and can be fetched only by the user who requested them. Prepare it again.

## Alerts

**Send test under Settings → Alert delivery shows "error: …".**
The text after "error:" comes from the mail server or webhook. Common causes: wrong port or STARTTLS setting, a relay
that requires **SMTP user (optional)** and **SMTP password**, a sender address the relay does not accept, or a
webhook URL that is not HTTPS. The test uses the saved settings: save first.

## Offsite and replication

**`offsite_lag` alert.**
Snapshots have not reached the target for more than 48 hours. Check the tenant's **Offsite copy** jobs: credentials,
pinned host key, free space on the Storage Box, bucket permissions.

**S3 uploads fail intermittently with "connection refused" (e.g. AWS).**
The endpoint's DNS rotates and the allow-list does not contain the new address yet. The job is retried; prefer a
provider with stable addresses.

**Replication sync fails with "approve the key export on the primary", or a `replication_keys` alert.**
There is no key export yet, or the primary rotated the tenant key. On the primary, click **Export keys** on the peer,
compare the key service fingerprint with the secondary, and have the request approved.

**The secondary refuses the primary's certificate after a network change.**
`nexus-setup --force-reconfigure-network` on the primary created a new certificate. Compare the new fingerprint and
create the replication source again with it.

<a id="verification-failed"></a>
## Verification failed

A `verify` alert means missing or corrupt chunks in the local store or in the sampled offsite packs.

1. Do not confirm or approve garbage collections until the cause is known.
2. Read the verify job's log: it names the chunks and the affected snapshots.
3. Check the appliance's disks (hardware errors, file system).
4. Restore affected guests from an older snapshot, from the offsite copy (command line, see
   [14 Disaster recovery](14-disaster-recovery.md)) or from the replication secondary.

An `inventory` alert (packs missing on the offsite target, or a locked snapshot missing locally) can mean an attack.
Check the target's own snapshots (Storage Box) or object versions (S3) and the audit log.

## Updates

**An update does not install.**
Updates are applied only in the maintenance window or on request, are postponed while jobs run, and a version that was
rolled back is not applied again. Check **Settings → Updates** or `nexus-update status` on the console (see
[13 Updates](13-updates.md)).

**The appliance runs the old version after an update.**
The health check failed after the reboot and the appliance rolled back automatically. The reason is in the journal of
the greenboot health check.

## FAQ

**Does NexusBackup replace an archive?**
No. Backups keep restore points for weeks, months and a few years. Legal archiving (e.g. 10 years under GoBD/HGB)
belongs in an archive or DMS.

**Can I delete a single snapshot?**
Not in the web interface. Snapshots are removed by retention once their lock has expired.

**Why does a tenant's data not deduplicate against another tenant's?**
By design: each tenant has its own key and store, so tenants stay cryptographically separated.

**Can a compromised Proxmox VE node delete my backups?**
No. Nodes hold no credentials for the appliance, deleting a NexusBackup volume in PVE is refused, and retention locks
protect snapshots on the appliance.

**Can I turn approvals off?**
Yes, if another administrator or security officer approves that request. Single-administrator appliances start with
approvals disabled. Locks and secrets still protect existing backups.

**Which times are used?**
Schedules and retention periods use UTC. The web interface shows times in the browser's time zone.

**Is the appliance production-ready?**
Not yet. All functions run end to end in the lab, but real-hardware tests, a real Storage Box run, the external
penetration test, TPM/LUKS disk encryption, an appliance configuration backup and the release key ceremony are still
open. The **Status** notes in each chapter say what is lab-only.
