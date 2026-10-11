# 07 Offsite copies

Each tenant can have one offsite target: a **Hetzner Storage Box (SFTP)** or an **S3 object storage** bucket.
The appliance uploads the tenant's snapshots there, encrypted and deduplicated. The copy is
**self-describing**: with the storage credentials and the recovery key, a fresh appliance can restore it
without the original one ([14 Disaster recovery](14-disaster-recovery.md)).

> **Status:** The offsite engine was tested against a local SFTP container that mimics the Storage Box limits
> and against MinIO with Object Lock. A final run against a real Hetzner Storage Box and a real S3 provider is
> still pending.

## What goes offsite

- **Packs**: 32–64 MiB containers of chunks. The chunks stay byte-identical to the local ones: compressed
  and sealed with the tenant key (XChaCha20-Poly1305).
- **Snapshot files**: the sealed indexes and the manifest of every snapshot. The manifest is written last, so
  a snapshot counts as offsite only when all its data is there.
- **Key escrow** (`keys/`): the tenant's data keys, wrapped. Only the recovery key can open them.

The provider sees random names and ciphertext. Chunk IDs are keyed hashes, so the provider cannot even test
whether a known file is stored.

## When uploads run

The **Copy offsite** setting of a policy ([05 Policies and protection groups](05-policies-and-groups.md)) decides
whether a group's snapshots go offsite. After every successful backup, the scheduler runs retention for that
source, then an **Offsite copy** job for the tenant. That job:

1. uploads new packs and snapshots (resumable, nothing is ever overwritten);
2. runs the **inventory check**: are all expected packs and manifests still on the target?
3. applies offsite retention.

Daily maintenance also runs garbage collection and a sampled **verify** on the offsite copy: 3 packs are
downloaded, decrypted and checked.

Retention offsite uses the GFS settings of the tenant's policies with **Copy offsite**, taking the largest
value of each class (daily, weekly, monthly, yearly) per tenant. It is computed and locked separately from
the local retention. A deletion on
the appliance is never just mirrored to the target. Offsite locks are extend-only, like local ones.

The **Offsite** column on **Dashboard** and **Snapshots** shows which snapshots are offsite. The alert
`offsite_lag` fires when a snapshot of a tenant has not reached the target for more than 48 hours
([11 Alerts and monitoring](11-alerts-and-monitoring.md)).

## Configure the target of a tenant

Go to **Configuration → Tenants** and click **Edit** on the tenant (or **New tenant**). In **Offsite copy**,
choose the **Offsite target**: **None**, **Hetzner Storage Box (SFTP)** or **S3 object storage**.

![Tenants with their offsite targets](images/tenants.png)

Fields for both target types:

- **Bandwidth limit (KiB/s, empty = unlimited)**: covers all uploaders together.
- **Parallel uploads**: 1–8 in the form, default 4.

Changing or removing a target that is already configured needs approval by a second person while approvals
are enabled ([10 Approvals and audit](10-approvals-and-audit.md)). Setting the first target does not.

## Hetzner Storage Box (SFTP)

Plan for **one Storage Box per tenant**. A box allows 10 concurrent connections. The appliance uses 4 by
default and leaves the rest for restore and verify. Separate boxes also keep tenants isolated and billed
separately.

![Storage Box target of tenant initech](images/tenant-sftp.png)

| Field | What to enter |
|---|---|
| **SFTP host** | the box's host name, e.g. `u123456.storagebox.example.net` |
| **Port** | `23` (the Storage Box SSH port; default) |
| **SFTP user** | the box user, e.g. `u123456` |
| **Base directory** | optional directory on the box, e.g. `nexus` |
| **Pinned host key** | the box's SSH host key: a public key (`ssh-ed25519 AAAA…`) or a known_hosts line (`[host]:23 ssh-ed25519 AAAA…`). There is no trust on first use: any other key is refused. Get it out of band, e.g. `ssh-keyscan -p 23 u123456.storagebox.example.net` from a trusted machine. |
| **SSH key file on the appliance** | the path of the private key the appliance logs in with, e.g. `/etc/nexus/offsite/initech.key` |

The SSH private key never goes through the web UI: the tenant settings hold only its path, and the web API
refuses inline secrets there. Add the matching public key to the box's authorized keys (Storage Box: enable
SSH support, then `.ssh/authorized_keys` on the box).

> **Status (gap):** The appliance has no UI or API to create or install this key file yet. "SSH key management
> for sources" is an open production item in `state.md`. In the lab the key is placed on the appliance file
> system directly. Plan for this until key management is implemented.

**Immutability on a Storage Box.** A box has no object lock. The appliance never overwrites files and deletes
only through delayed GC. Protection against a compromised appliance comes from the box's own snapshots. Turn
on automated snapshots in the Hetzner console, e.g. 14 daily + 4 weekly. The appliance has no Hetzner
console credentials, so it cannot delete them. That gives about six weeks to notice an attack on the offsite
copy. The inventory check raises an alert as soon as expected packs or snapshots disappear.

## S3 object storage with Object Lock

An S3 bucket with **Object Lock in compliance mode** makes the offsite copy immutable: locked objects cannot
be deleted or overwritten by anyone, not even the provider's root account, until their lock ends.

![S3 target of tenant acme](images/tenant-s3.png)

| Field | What to enter |
|---|---|
| **Endpoint (https://host[:port])** | e.g. `https://s3.eu-central.example.net`. HTTPS only, no path. |
| **Region** | the signing region (MinIO: usually `us-east-1`) |
| **Bucket** | one bucket per tenant is recommended |
| **Key prefix** | optional; all objects live below it, e.g. `appliance1` |
| **Access key ID** / **Secret access key** | credentials restricted by the policy below. The secret is write-only: it is sealed for the scheduler and never shown again. Changing endpoint, region, bucket, access key, path style or certificate requires re-entering it. |
| **Storage class for packs (cold)** / **Storage class for indexes and manifests (hot)** | optional, e.g. `STANDARD_IA` / `STANDARD`. Only classes that can be read without a restore request. `GLACIER` and `DEEP_ARCHIVE` are refused. Mind minimum storage durations: GC and repacking delete packs. |
| **Path-style addressing (MinIO, bucket names with dots, IP endpoints)** | tick for MinIO and on-prem endpoints |
| **Object Lock (compliance mode): lock every object until its snapshot may be deleted** | tick only for buckets created with Object Lock |
| **Trusted certificate (PEM, optional)** | for on-prem endpoints: the private CA or the endpoint certificate itself (pinned). Empty = the public web PKI. |

With Object Lock, every snapshot file is locked until the snapshot may be deleted. Every pack is locked until
the latest such date of all snapshots that use it. The key escrow is locked as long as the longest snapshot
lock. Locks are extended before a new snapshot's manifest is written, and when retention promotes a snapshot
(e.g. a daily becomes a monthly). Locks are never shortened.

### Prepare the bucket

1. Use a **separate account or project** for backups. Its root credentials do not belong on the appliance.
2. Create a **new bucket with Object Lock enabled** (this also enables versioning; most providers allow it
   only at creation). **Do not set a default retention.** The appliance sets each object's date itself.
3. Add a **lifecycle rule** that removes noncurrent versions a few days after they became noncurrent, expired
   delete markers and incomplete multipart uploads. Lifecycle never removes a version while its lock runs.
4. Create a user or key **restricted to the bucket**: list, get, put, delete (current version), put/get
   object retention, multipart cleanup. Deny `DeleteObjectVersion`, `BypassGovernanceRetention` and every
   bucket-configuration change. `docs/s3-offsite.md` has the complete IAM/MinIO policy and setup steps for
   MinIO, AWS, Hetzner Object Storage and Wasabi.

Example for MinIO:

```sh
mc mb --with-lock site/nexus-acme
mc ilm rule add --noncurrent-expire-days 7 --expire-delete-marker site/nexus-acme
mc admin policy create site nexus-appliance policy.json
mc admin user add site appliance-acme '<secret>'
mc admin policy attach site nexus-appliance --user appliance-acme
```

Provider notes:

- **Hetzner Object Storage**: credentials are project-wide and cannot be restricted by a policy. Use a
  separate project for backup buckets. Storage classes are not supported, so leave both empty.
- **Wasabi**: minimum storage duration (90 days by default) applies to deleted and repacked packs.
- **AWS S3**: works, but S3's DNS rotates through many addresses. The appliance's outbound firewall
  allow-list resolves the endpoint name periodically, so an upload can hit an address that is not allowed
  yet. Prefer providers with stable addresses, or expect occasional retries. Allowing provider IP ranges is
  an open item.

## Firewall

You do not open anything by hand. The scheduler adds each tenant's offsite endpoint (SFTP host:port, or the S3
endpoint, as `<bucket>.<host>` for virtual-hosted style) to the outbound allow-list. All other outbound
traffic is dropped.

> **Status:** S3 was tested against MinIO (Object Lock compliance, restricted user, TLS): locks, refused
> overwrite and version deletion, GC skipping locked packs, DR with locks restored. A run against a real
> provider is pending.
