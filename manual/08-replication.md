# 08 Replication to a second appliance

Replication keeps a second, independent copy of whole tenants on another NexusBackup appliance, for example at a
disaster-recovery site.

- The **primary** holds the tenant and its backups.
- The **secondary pulls** sealed snapshots from the primary over the primary's management port (8443). It uses
  its own client certificate (mutual TLS). No new inbound port is opened.
- The primary holds **no credentials** for the secondary. A compromised primary therefore cannot reach the
  secondary or delete replicated restore points.
- Tenant keys are handed over only after a second approval, sealed so that only the secondary's key service
  can open them.

> **Status:** Replication runs in a two-VM lab (two appliance images, SELinux enforcing): enrollment through the
> real port 8443, initial sync about 181 MB/s, incremental sync, file restore on the secondary with the primary
> powered off. A lab rerun after the latest integration is still pending (`state.md`).

![Replication page: peers and sources](images/replication.png)

The **Replication** page has two parts. **Peers (this appliance is the primary)** lists the secondaries that
may pull from this appliance. **Sources (this appliance is the secondary)** lists the primaries this appliance
pulls from. One appliance can be both, for different tenants.

## Roles

| Task | Who |
|---|---|
| Create, revoke peers; request a key export; create, change, delete replication sources | **Administrator** |
| **Sync now** | Administrator, Operator |
| View the page | Administrator, Security officer, Operator (tenant users do not see it) |
| Approve peer creation, key export, revocation | another Administrator or a Security officer |

## Step 1 — On the primary: create a peer

1. Open **Configuration → Replication** and click **New peer**.
2. Enter a **Name** for the secondary (e.g. `dr-site`) and tick the **Tenants** it may pull.
3. Click **Create**.
4. The dialog **Enrollment code for …** shows two values **once**: the **Enrollment code**
   (`<peer-id>.<token>`) and **This appliance's certificate fingerprint (SHA-256) — enter it on the
   secondary**. Copy both and pass them to the secondary's administrator over a trusted channel.

![Enrollment code and certificate fingerprint, shown once](images/replication-peer-code.png)

Creating a peer exposes all data of the selected tenants, so with approvals enabled it needs a second
person's approval (**Approvals**, action `replication peer create`). The code works only after the approval
(immediately when approvals are disabled) and stays valid for 24 hours from then. The peer's state goes from
**Awaiting approval** to **Waiting for enrollment** to **Enrolled**.

## Step 2 — On the secondary: create a replication source

1. Open **Configuration → Replication** and click **New replication source**.
2. Fill in:
   - **Name**: e.g. `hq-primary`.
   - **Primary address (host:port)**: e.g. `backup-hq.example.com:8443`.
   - **Enrollment code**: the code from step 1.
   - **Primary certificate fingerprint (SHA-256)**: from step 1. The primary's console setup shows it too.
     Compare it out of band. The secondary pins this certificate and refuses any other.
   - **Tenants**: comma separated, e.g. `globex`. They must be tenants of the peer on the primary.
     Missing tenants are created on the secondary.
   - **Schedule**: `daily HH:MM` or `hourly MM`.
   - **Retention (GFS)**: **Daily**, **Weekly**, **Monthly**, **Yearly**. This is the retention on the
     secondary, independent of the primary.
   - **Bandwidth limit (MB/s, empty = unlimited)**.
3. Click **Create**. An **Enroll at primary** job runs: the secondary creates its key pair, connects to the
   primary with the pinned certificate, proves it knows the code, and receives its client certificate. The
   code works once. The token never travels in clear, and a man in the middle cannot relay the proofs.

![New replication source on the secondary](images/replication-source-new.png)

A tenant that already has local groups, agents or keys on the secondary cannot be a replicated tenant. If the
enrollment failed or the code was used up, ask the primary for a new code and click **New code** on the
source.

## Step 3 — On the primary: approve the key export

After the enrollment, the primary automatically requests the **key export** (`replication key export`) for
the peer's creator. The request names the secondary's **Key service fingerprint**. Before you approve:

- compare it with the **Key service fingerprint** shown for the source on the secondary's **Replication**
  page;
- only then approve it on **Approvals** (see [10 Approvals and audit](10-approvals-and-audit.md)).

The primary's scheduler then seals each tenant key to the secondary's key service. The secondary imports the
keys at its next sync and stores them under its own key-encryption key. Until the export is approved, syncs
fail with "approve the key export on the primary". The peer table on the primary shows the exported key
versions under **Keys exported**.

## Syncing

- The secondary runs one **Replication sync** job per tenant on the source's **Schedule**. Click
  **Sync now** to start one immediately, or **Schedule** to change the schedule.
- A sync fetches only snapshots that are missing locally **and** that the secondary's own retention keeps.
  Every chunk is verified (authenticated decryption and keyed hash) before it is stored. If anything fails
  verification, nothing of that snapshot is imported, and a `replication_verify` alert is raised.
- **Last sync** shows per tenant when the last successful sync was, and the last error if one followed it.

## Replicated tenants on the secondary

- They are **read-only copies**: the secondary refuses protection groups, agents and backups in them.
- Their snapshots appear on **Snapshots** marked **Replicated from <source>**.
- Retention is independent. **The secondary never deletes because the primary deleted**: syncs only add,
  and deletions come only from the secondary's own GFS retention. Lowering that retention later needs approval
  while approvals are enabled.
- Restores use only the secondary's keys and work while the primary is down. Browse and download work as
  usual. For full VM/CT restores, add a PVE source of the DR site to the replicated tenant as a restore
  target ([06 Restores](06-restores.md#restores-on-a-replication-secondary)).
- The secondary uploads replicated snapshots offsite only if you give the tenant an offsite target on the
  secondary (untested in the lab).

![Replicated snapshots on the secondary](images/snapshots-replicated.png)

## Key rotation on the primary

New snapshots after a tenant key rotation on the primary use a new key version. The secondary skips snapshots
whose key version it lacks and raises the critical alert `replication_keys` ("re-export the keys on the
primary"). Fix: on the primary, click **Export keys** on the peer. With approvals enabled a second person
approves it after comparing the key service fingerprint. The next sync imports the new version.

## Revoke a peer or stop replicating

- **Primary:** **Delete** on a peer revokes it (approval needed while approvals are enabled). Its certificate
  is refused on the next request, even on an open connection. Its token and key exports are dropped. A peer
  that is still awaiting approval is revoked at once, without an approval.
- **Secondary:** **Delete** on a source stops replication. The replicated snapshots stay under the
  secondary's retention.

A peer certificate cannot be renewed in place. Delete the peer and create a new one (the certificates are
valid for 10 years).

## Alerts on the secondary

| Alert | Severity | Meaning |
|---|---|---|
| `replication_lag` | warning | no successful sync of a source/tenant for more than 48 hours |
| `replication_keys` | critical | key version mismatch, no export yet, or a key export failed |
| `replication_verify` | critical | a fetched object failed verification; nothing was imported |
| `job_failed` | critical | a sync or enrollment job failed |

See [11 Alerts and monitoring](11-alerts-and-monitoring.md).

## Using the secondary for disaster recovery

If the primary is lost, the secondary already holds restorable copies of the replicated tenants, with its own
keys and its own recovery key. Restore from it as described in [06 Restores](06-restores.md). To rebuild
an appliance from an offsite copy instead, see [14 Disaster recovery](14-disaster-recovery.md).

Known limits: no bandwidth limit on the primary side (only the secondary's **Bandwidth limit**). Chained
replication (secondary to a third appliance) is not tested.
