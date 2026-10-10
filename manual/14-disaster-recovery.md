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

## What is not recovered

The offsite copy and the replica contain **backup data and tenant keys only**. They do not contain the appliance
configuration. After a total loss you must recreate by hand:

- the catalog: tenants, sources, policies, protection groups, users and their roles, approval settings, alerts and
  job history, and the **audit log** (it lives only in the catalog; forwarding it off the appliance is not
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
