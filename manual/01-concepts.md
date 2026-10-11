# 01 Concepts

This chapter explains the ideas behind NexusBackup. The later chapters assume you know these terms.

## The appliance and the pull model

NexusBackup is a self-contained **backup appliance**: one machine (or VM) with its own hardened operating system,
its own storage and a web interface. It **pulls** data from the systems it protects. The appliance opens every
connection: to the Proxmox VE API and nodes, to backup agents, to TrueNAS, to NFS/SMB servers, to plugin sources
and to the offsite target. No protected system ever connects to the appliance. A compromised hypervisor or server
therefore has no credentials it could use to reach or delete the backups.

The appliance accepts exactly one inbound port: **8443** (HTTPS: web interface, REST API and the replication
endpoint for a second appliance). Outbound traffic is denied by default. The appliance adds every configured source
and target to an outbound allow-list automatically (see [02 Installation](02-installation.md)).

## Tenants

A **tenant** is a separate customer or organizational unit. Each tenant has:

- its own encryption key (data-encryption key, DEK) and its own chunk store,
- its own sources, protection groups and snapshots,
- its own offsite target (one Storage Box or S3 bucket per tenant).

Data of different tenants is never deduplicated against each other. That is deliberate: it keeps tenants
cryptographically separated. The appliance is designed for up to five tenants. Users can be limited to one tenant
(see [09 Users and access](09-users-and-access.md)).

## Forever-full snapshots

Every backup produces a **snapshot**: a complete, immutable image of the guest, host, dataset or share at that point
in time. There are no "full" and "incremental" chains to manage. Each snapshot can be restored on its own.

Internally, only data that changed since the previous backup is read and stored:

- **Proxmox VE VMs** use QEMU dirty bitmaps: only blocks written since the last backup are read. After a VM or host
  restart the bitmap is gone and the next backup reads the whole disk once (it still stores only changed data).
- **Containers, agents, TrueNAS and shares** are read file by file; unchanged files are recognized (metadata cache,
  `zfs diff`, inode/size/time comparison) and not transferred again.

This is called **incremental-forever with full logical snapshots**.

## Deduplication

Data is cut into **chunks**: fixed-size chunks for disk images (aligned to the dirty bitmap), content-defined
chunks (FastCDC) for files. Each chunk is stored once per tenant. If the same data appears in ten VMs or in a
hundred daily snapshots, it occupies space only once.

Chunk IDs are keyed hashes (BLAKE3 with a per-tenant key), so an outsider who sees the stored chunks (for example the
offsite storage provider) cannot test whether a known file is present.

Agents compute plain hashes on the host and send only chunks the appliance does not have yet; the host never holds
tenant key material.

## Encryption

The data path is always **deduplicate → compress (zstd) → encrypt (XChaCha20-Poly1305)**. Every chunk, index and
manifest is encrypted and authenticated with the tenant's key, on the appliance's disks and offsite alike.

- Tenant keys are held by the key service (`keyd`) and wrapped with the appliance's key-encryption key (KEK).
- The KEK is escrowed under the **recovery key**, which the first-boot wizard shows exactly once. With the recovery key
  and the offsite copy you can restore everything on new hardware, without the original appliance
  (see [14 Disaster recovery](14-disaster-recovery.md)).

> **Status:** The KEK is currently sealed in a file (mode 0600) on the appliance. TPM sealing and full-disk
> encryption (LUKS) are planned but not implemented. Chunks are encrypted on disk either way.

## Retention (GFS)

A **policy** defines how many restore points to keep, in the grandfather-father-son (GFS) scheme:

| Class | Keeps | Lock |
|---|---|---|
| Daily | the last snapshot of each of the last *N* days that have a snapshot | 14 days |
| Weekly | the last snapshot of each of the last *N* weeks (weeks start on Monday) | 28 days |
| Monthly | the last snapshot of each of the last *N* months | 183 days |
| Yearly | the last snapshot of each of the last *N* years | 730 days |

Rules worth knowing:

- Periods count only periods **that have a snapshot**. If a VM was off for a week, "14 daily" still keeps 14 daily
  snapshots, reaching further back.
- One snapshot can belong to several classes; it is kept as long as any class keeps it.
- Periods are computed in **UTC**.
- The default (and the plan's recommendation) is 14 daily, 4 weekly, 6 monthly, 2 yearly.
- Retention runs after every successful backup of a source. Offsite copies use the same retention.

Backups are not an archive. Legal retention for 10 years (e.g. GoBD/HGB) belongs in an archive or DMS, not in
NexusBackup.

## Retention locks and the compliance clock

When a snapshot is classified, it gets a **retention lock** (column **Locked until** on the Snapshots page). Until
then, nobody can delete it: not an administrator, not the API, not a compromised appliance process. Locks can only be
**extended**, never shortened.

Locks are measured by the **compliance clock**, not by the system time. The compliance clock moves forward with the
machine's monotonic clock and catches up with the system time only slowly (at most 1 % faster). Setting the system
date into the future, or a rogue time server, therefore cannot expire locks early. Backward time jumps are ignored.
After downtime the clock lags behind and catches up slowly; that only makes locks last longer.

## Garbage collection and verification

- **Garbage collection (GC)** removes chunks that no snapshot references any more (mark and sweep, with a one-day
  grace period). If a GC would delete more than **20 %** of a tenant's chunks, it stops and asks for approval (or for
  an administrator's confirmation when approvals are disabled), because that usually means something went wrong.
- **Verification** runs daily per tenant. Each run re-reads one seventh of the stored chunks (so the whole store is
  checked every seven days) and reports missing or corrupt chunks; with an offsite target it also downloads and
  checks a sample of offsite packs. Failures raise a critical alert. The Dashboard shows when each guest was last
  verified.

## Approvals (four-eyes principle)

Some actions are destructive or weaken protection: deleting a group, source, tenant, policy or agent, lowering
retention or switching off offsite copies, granting administrator or security-officer rights, exporting keys to a
second appliance, a very large garbage collection, installing or removing plugins.

With **approvals enabled**, such an action does not run when you click it. It becomes a **request** on the
**Approvals** page. A *different* administrator or security officer must approve it within 72 hours; otherwise it
expires. The requester can never approve their own request.

Approvals are **optional**:

- An appliance set up with an administrator *and* a security officer starts with approvals **enabled**.
- An appliance with a single administrator starts with approvals **disabled**: there is nobody who could approve.
- Any administrator can enable approvals (**Settings → Approvals**) once a second possible approver exists. Disabling
  them is itself a request that someone else must approve.
- With approvals disabled, the same actions take effect immediately but are still recorded in the audit log.
  Retention locks, write-only secrets and re-authentication protect existing backups either way.

Details: [10 Approvals and audit](10-approvals-and-audit.md).

## Roles

| Role | In short |
|---|---|
| **Administrator** | configures everything, runs backups and restores |
| **Security officer** | approves requests, reads everything incl. the audit log; does not configure and does not restore |
| **Operator** | runs backups and restores, acknowledges alerts; does not configure |
| **Tenant user** | sees one tenant and restores its data |

Every local account uses a password and a TOTP authenticator. With single sign-on (OpenID Connect), people can
instead sign in through the organization's identity provider, which then enforces multi-factor authentication; their
role and tenants follow group mappings. Details: [09 Users and access](09-users-and-access.md).

## Offsite copies

Each tenant can have one **offsite target**: a Hetzner Storage Box (SFTP) or S3-compatible object storage with
Object Lock. After backups, the appliance uploads new chunks (packed into large encrypted **packs**) and the
snapshot indexes. Offsite copies are:

- **encrypted** with the tenant key (the provider sees only ciphertext),
- **deduplicated and incremental** (only new packs are uploaded),
- **self-describing**: together with the recovery key they are enough to rebuild the data on new hardware,
- **kept with the same retention** as the local copies, with their own locks (S3 Object Lock in compliance mode
  enforces them at the provider).

Details: [07 Offsite copies](07-offsite.md).

## Replication to a second appliance

A second NexusBackup appliance (for example at a disaster-recovery site) can **pull** sealed snapshots of selected
tenants from this one. The primary holds no credentials for the secondary. Tenant keys are handed over only after an
approval, sealed to the secondary's key service. The secondary keeps its own retention and never deletes because the
primary deleted. Replicated tenants are read-only on the secondary: they receive no local backups.

Details: [08 Replication](08-replication.md).

## Jobs and the scheduler

Everything the appliance does runs as a **job**: backup, restore, file listing, download preparation, offsite copy,
retention, garbage collection, verification, agent enrollment, plugin operations, replication sync. The scheduler
starts scheduled backups when a policy is due, then runs retention and (if the policy says so) the offsite copy. It
runs at most one job per source at a time. Every job has a log on the **Jobs** page.

## Audit log

Every change made through the web interface or API, every sign-in (and failed sign-in) and every job state change is
written to an **audit log**. Each entry contains the hash of the previous entry, so a removed or altered entry breaks
the chain. Security officers can verify the chain at any time on the **Audit log** page.
