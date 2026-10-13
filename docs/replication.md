# Appliance Replication — Contract (Phase 8)

Status: v1 (2026-10-09). Plan §3.1 ("the secondary appliance pulls from the primary; the primary holds no
credentials for the secondary"), §4.2, §9.3. Decision (plan §2, Phase 8): **the secondary pulls via a
replication endpoint on the primary's management port 8443, mTLS with an enrolled secondary's client
certificate; no new inbound port; the endpoint serves sealed data read-only.**

Crate `crates/replication` (daemon `nexus-replicad`, job CLI `nexus-replica`), web-api module
`replication.rs`, catalog v7, keyd verbs `replica-pubkey` / `export-for` / `import-sealed`.

## 1. Roles and trust

| | Primary (serves) | Secondary (pulls) |
|---|---|---|
| Holds | tenant data + DEKs; replication CA (signs peer certs); per peer: tenant scope, client-cert fingerprint, sealed DEK exports | its own client key + cert per source, the primary's TLS certificate fingerprint (pin), imported tenant DEKs (wrapped under *its own* KEK) |
| Credentials for the other side | **none** — it only verifies client certificates it issued itself | client cert/key for the primary |
| Connections | inbound only, on 8443 (no new port) | outbound to `primary:8443` (nftables allow-list) |

A compromised secondary can read what its scope allows (that is the purpose of replication) and nothing
else; it cannot write to the primary. A compromised primary cannot reach the secondary at all (no
credentials, no inbound path), so it cannot delete replicated restore points. It can stop serving or serve
garbage: every object is verified on the secondary before it is imported (AEAD + keyed hash), so the
worst case is a failed sync and an alert.

## 2. Process isolation (plan §4.2)

```
secondary nexus-replica ──TLS 1.3, ALPN nexus-replication/1, client cert──> primary :8443
                                                                              nexus-web-api (TLS, mTLS check,
                                                                              peer lookup, scope, audit, limits)
                                                                                 │ Unix socket (peer uid = web-api)
                                                                                 ▼
                                                                              nexus-replicad (read-only stores,
                                                                              replication CA, no keyd, no network)
```

- **nexus-web-api** terminates TLS. It never opens store files and never talks to keyd (unchanged rule):
  for `/replication/v1/*` it checks the client certificate's fingerprint against `replication_peers`
  (state `enrolled`, not revoked) and the tenant scope, then forwards a one-line request to
  `nexus-replicad` over `/run/nexus-replicad/replicad.sock` and streams the answer back unmodified.
  The web-api crate does not depend on `chunkstore` or `keyd` (it uses `replication` with
  `default-features = false`, i.e. only the protocol types); a test asserts this.
- **nexus-replicad** (new daemon): uid `nexus-chunkstore` (store files are 0600/0700 of that uid), own
  SELinux domain `nexus_replicad_t` with **read-only** access to `nexus_store_t`, no keyd socket
  (SELinux + `InaccessiblePaths=`), no network (`PrivateNetwork=yes`), its own state
  `/var/lib/nexus/replicad` (`nexus_replicad_var_lib_t`: replication CA key, token-sealing key). It
  accepts connections only from the web-api uid (`SO_PEERCRED`). It serves sealed bytes only: it never
  decrypts anything (it has no keys). Names in requests are validated (store charset, chunk ids = 64 hex,
  file names = `manifest` or `<name>.idx`).
- The web-api passes the peer's id and tenant scope with each request and replicad re-checks the scope.
  replicad therefore trusts the web-api for the peer identity; a compromised web-api could read sealed
  objects of every tenant through replicad — ciphertext without keys (residual risk, documented in the
  threat model; the same uid split as review H-3 would not change it).
- **No DEK ever leaves keyd in clear**. DEK export is a keyd verb that seals to the secondary keyd's
  X25519 public key (§5) and is only requested by the scheduler for an approved quorum request.

## 3. TLS on 8443: three kinds of connections

The web-api reads the ClientHello first (rustls `Acceptor`) and picks the server configuration by ALPN:

| ClientHello ALPN | Server config | Routes served |
|---|---|---|
| `nexus-replication/1` | TLS 1.3 only, **client certificate required**, verified against the replication CA (`/run/nexus-replicad/ca.pem`, EKU clientAuth) | `/replication/v1/*` except `enroll` |
| `nexus-replication-enroll/1` | TLS 1.3 only, no client certificate | `POST /replication/v1/enroll` only |
| anything else (`h2`, `http/1.1`, none) | unchanged (no CertificateRequest: browsers never see a client-cert prompt) | UI + `/api/v1` (`/replication/v1/*` answers 403) |

The CA file is re-read when it changes (replicad creates it on its first start). Without it, replication
handshakes fail and normal connections are unaffected. Chain validation alone is not trusted: every
request re-checks the fingerprint in the catalog, so **deleting (revoking) a peer takes effect on the next
request**, even on an open keep-alive connection.

## 4. Enrollment (reuses the agent pattern: one-time token + TLS-exporter-bound proofs)

1. **Primary admin** creates a peer: `POST /api/v1/replication/peers {name, tenants}` → 202
   `{quorum_id, peer, code}`. The peer is created in state `pending`; `code` = `<peer-id>.<token>`
   (peer id 16 hex, token 128 bit base32) is shown **once**. The catalog keeps only the token digest
   (`agent_proto::token_digest`) sealed to replicad's public key (`sealed:v1:`, location
   `replication-peer/<id>/token`). The request is **quorum-gated** (`replication_peer.create`): it exposes
   all data of the selected tenants. An admin or security officer other than the requester approves → state
   `approved`, token valid for 24 h from approval. With approvals disabled (docs/control-plane.md "Quorum")
   the peer is approved at once (answer 200 `{approvals: "disabled", …}`), and the key export after
   enrollment is recorded as an `approved` request of the peer's creator that the scheduler executes.
2. **Secondary admin** enters primary address (`host:port`), the code, the primary's TLS certificate
   SHA-256 fingerprint (shown by nexus-setup / the primary's UI), tenants (default: all of the peer's),
   schedule and GFS: `POST /api/v1/replication/sources`. The secondary web-api stores the token digest
   sealed to its scheduler and queues a `replica_enroll` job.
3. `nexus-replica enroll` (secondary, scheduler-spawned): creates an ECDSA P-256 key + CSR, asks the local
   keyd for its X25519 replication public key (`replica-pubkey`), connects with ALPN
   `nexus-replication-enroll/1` and **pins the primary's certificate** (SHA-256 of the leaf DER; any other
   certificate aborts before anything is sent). Exporter: `export_keying_material(32,
   "nexus-replication enroll", None)`. It sends
   `{peer_id, name, csr_pem, keyd_pub, proof = HMAC(token_digest, "secondary" ‖ 0 ‖ exporter)}`.
4. web-api → replicad (`enroll` op, with the sealed digest and the exporter of *this* TLS session): replicad
   opens the digest, checks the proof, signs the CSR (only its self-signature-checked public key is used:
   `CN=nexus-replica:<peer-id>`, EKU clientAuth, 10 years) and returns its own proof
   (`"primary"`), the certificate and the CA. The web-api records `cert_sha256`, `keyd_pub`, clears the
   token (single use), audits `replication_peer.enrolled` and **automatically requests the key export
   quorum** (§5) on behalf of the peer's creator. 5 failed proofs void the token.
5. The secondary verifies the primary's proof (constant time) before it stores anything, then saves key,
   certificate and CA (`/var/lib/nexus/scheduler/replica/<source-id>/`, 0600, `nexus_replica_key_t`).

A man in the middle has a different TLS exporter on each leg and cannot relay the proofs; without the
pinned certificate the secondary does not even send its proof. The token never travels in clear.

## 5. Keys: DEKs sealed to the secondary keyd

- The secondary's keyd has an X25519 key pair for replication, created on first use, the secret part
  wrapped under the secondary KEK (`replica-x25519`). Verb `replica-pubkey` returns the public key.
- `POST /api/v1/replication/peers/{id}/export-keys {tenants?}` (and the automatic request at enrollment)
  creates the quorum request `replication.key_export {peer_id, tenants, keyd_pub}`; the approver sees the
  keyd public key's fingerprint, which the secondary's UI also shows (compare out of band).
- On approval the **scheduler** (which already talks to keyd) executes it: for each tenant it re-checks the
  peer (enrolled, same `keyd_pub`, tenant in scope) and asks keyd
  `export-for <tenant> <peer-pubkey-hex> <quorum-id>`. keyd answers an anonymous sealed box
  (`crypto_box_seal`, X25519 + XSalsa20-Poly1305) of `NXDEKX1\0 | len(tenant) | tenant | N × (u32 LE
  version | DEK)` and logs the quorum id. The blob goes into `replication_peers.key_exports` (it is
  ciphertext for the secondary keyd only); quorum → `executed`, audit `replication.key_export`.
  The primary's KEK never leaves keyd; keyd answers `export-for` only to the scheduler uid.
- The secondary fetches `GET /replication/v1/tenants/<t>/keys` at every sync and, if it carries versions it
  does not have, hands the blob to its keyd: `import-sealed <tenant> <origin>` (origin = primary
  certificate fingerprint). keyd opens it with its replication secret key, checks the tenant name and
  stores each DEK version wrapped under **its own KEK** (`tenants/<t>/dek.<v>` + `origin`). Import is
  refused if the tenant has local (non-imported) keys, a different origin, or a version that exists with a
  different key; it is idempotent otherwise. `tenant-rotate` is refused for imported tenants.
- **Rotation on the primary** (`keyd tenant-rotate`): new snapshots are sealed with the new version. The
  primary's snapshot listing carries each manifest's key version (from the clear blob header, no
  decryption). The secondary detects versions it does not have, imports nothing for those snapshots, and
  raises the critical alert `replication_keys` ("key version mismatch: re-export keys on the primary").
  Remedy: `export-keys` on the primary (quorum) → next sync imports the new version.
- Restore and DR on the secondary use only its own keyd; the secondary's escrow/offsite and recovery key
  cover the imported DEKs like local ones.

## 6. Peer API (primary, `/replication/v1`, JSON unless noted)

| Method + path | Answer |
|---|---|
| `POST /enroll` (enroll ALPN) | `{peer_id, name, csr_pem, keyd_pub, proof}` → `{proof, cert_pem, ca_pem, tenants}`; 403 bad proof / not approved / expired / revoked |
| `GET /peer` | `{peer_id, name, tenants, keys: {tenant: [versions]}}` |
| `POST /session` `{tenant}` | `{session}` — audit `replication.session_start` (peer, tenant, remote address) |
| `POST /session/{id}/end` `{snapshots, chunks, bytes, error?}` | audit `replication.session_end` with the client's numbers **and** the bytes the primary served |
| `GET /tenants/{t}/keys` | `{tenant, versions, blob}` (base64); 404 until the export quorum was executed |
| `GET /tenants/{t}/snapshots` | `[{source, time, key_version, files: ["manifest", "<name>.idx", …], size}]` — committed snapshots (manifest present) |
| `GET /tenants/{t}/snapshots/{source}/{time}/{file}` | raw sealed file (octet-stream) |
| `POST /tenants/{t}/chunks` (octet-stream: 1..=1024 × 32-byte ids) | octet-stream, per requested id in order: `id(32) ‖ u32 BE len ‖ sealed bytes`; `len = 0xFFFFFFFF` = missing (GC'd) |

Listing exposes source names (`vm-100`, `host-<agent>`, `nas-…`) and times of the scoped tenants; that
metadata is already visible to the peer's operators and is accepted. Everything else is sealed.

**Limits**: per peer at most 8 concurrent requests (429), chunk requests ≤ 1024 ids, request bodies
≤ 64 KiB, files ≤ 256 MiB, unknown/revoked fingerprint → 403 (audited `replication.denied`, at most one
entry per fingerprint and minute). `last_seen` is updated at session start/end.

**web-api ↔ replicad** (Unix socket, one request per connection): request = one JSON line
`{op: list|file|chunks|enroll|ca, tenants: [scope], tenant, source, time, file, ids, …}`; answer = one JSON
header line `{status, error?}` followed by the raw body until EOF.

## 7. Pull sync on the secondary (`replica_sync`)

The secondary's scheduler queues, per enrolled replication source and its schedule (`daily HH:MM` /
`hourly MM`), one `replica_sync {replication_source_id, tenant}` job per tenant (exclusive per tenant,
like GC/offsite). `nexus-replica <job>/replica.json sync`:

1. mTLS connect (client cert, pinned primary certificate), `POST /session`.
2. Keys: `GET keys` → import new versions into keyd (§5). No export yet → fail ("approve the key export
   on the primary").
3. Open the tenant store `<store_base>/<tenant>` with the keyring from keyd.
4. `GET snapshots`; per source compute the GFS keep set over **local ∪ remote** times (the source's GFS);
   fetch only remote snapshots that are missing locally *and* kept. Snapshots the secondary pruned stay
   pruned (period-based GFS is monotonic: adding newer snapshots never revives an older one); an initial
   sync does not pull restore points it would prune at once. Snapshots whose key version is unknown are
   skipped and reported (`key-mismatch`).
5. Per snapshot (oldest first): fetch manifest + indexes, decode them with the tenant keyring (AEAD with
   tenant/source/time-bound AAD), collect chunk ids, fetch the missing ones in batches of 1024 over 4
   parallel connections, `insert_chunk_raw` (AEAD + keyed-hash verification **before** the chunk is
   written), then `import_snapshot_raw` (manifest last = commit). Any verification failure aborts the
   job before that snapshot's manifest is written: nothing is imported (verified chunks already written
   are unreferenced and removed by GC), alert `replication_verify` (critical).
6. Independent retention: `apply_retention` per source with the replication source's GFS (locks extended
   per class, re-sealed with the shared DEK; never shortened). **The secondary never deletes because the
   primary deleted**: sync only adds; deletions come from its own retention.
7. `POST /session/{id}/end`, stdout line `replicated {json}` → `replication_sources.status`.

Snapshots appear in the secondary's catalog (`snapshots.origin` = replication source name) and UI marked
"replicated from <source>". Restores (file download, full VM restore to a PVE node configured on the
secondary, DR) work with the secondary's keyd only; for replicated tenants without a local PVE source the
scheduler gives `nexus-pve` a store-only configuration (file listing/download, dump).

Replicated tenants take no local backups: the secondary refuses groups, agents and `backup` jobs in them,
and refuses a replication source for a tenant that has groups, agents or local keys (keyd refuses the
import into a tenant with local DEKs). A source may be added to a replicated tenant as a **restore target**
(e.g. the DR site's PVE cluster for full VM restores). The scheduler never creates a DEK for them (`ensure`
is skipped; jobs that open the store wait until the first sync imported the keys).

**Alerts (secondary)**: `replication_lag` (warning, no successful sync of a source/tenant for > 48 h; not while
the source is closed), `vault_closed` (info, while closed),
`replication_keys` (critical, key version mismatch / no export), `replication_verify` (critical,
verification failure), plus the generic `job_failed`.

### Windows and closing the vault (Phase 17a/b)
Per replication source (catalog v24, all in `timezone`, IANA, default UTC):

- `windows`: bandwidth windows `[{days, from, to, action: "pause"|"limit", rate_bytes?}]` (shared type
  `catalog::schedule::RateWindow`). `nexus-replica` gets them with `bwlimit` and `timezone` in its job config;
  the chunk workers share one `catalog::schedule::Throttle`, which re-evaluates the effective limit every 10 s
  (pause > lowest active limit > base `bwlimit`; a limit window replaces the base while active) and starts a
  new token bucket on a change. In a pause a worker waits before its next batch and then reconnects.
- `sync_window`: `[{days, from, to}]` (empty = always). Outside it the source is closed for traffic: no
  firewall target (`replication_targets`), no queued syncs, the manual sync is refused (409) and
  `plan_replica` refuses to start one. When the window closes, `Scheduler::replication_windows` cancels queued
  syncs and sets `cancel_by = 'sync_window'` on running ones (the existing cancel path: SIGTERM to the process
  group, SIGKILL after the grace period). A cancelled sync records no error. It resumes on the next run: step 5
  writes verified chunks before the manifest, so the next sync finds them (`touch_chunk`) and only fetches
  what is missing (test `bandwidth_windows_and_resume_after_cancel`).
- `closed_until` / `closed_by` / `closed_at` ("close vault now"): `POST …/close {until?}` (admin, security
  officer, direct, audited `replication_source.close`) sets `closed_until` (-1 = until reopened); a closure
  can be extended but never shortened. The web-api cancels queued syncs and requests the cancel of running
  ones at once; the scheduler drops the firewall target on its next tick and keeps the info alert
  `vault_closed:<id>` open (no `replication_lag` meanwhile). `POST …/reopen` → quorum `replication.reopen`
  (executed by the web-api on approval: `closed_until` etc. NULL).

Changing the windows: a tightening applies directly; a weakening (`Bandwidth::weaker`: more allowance at
some breakpoint of the next 8 days; `sync_widened`: open where it was closed; another time zone usually is
both) goes through quorum `replication_source.update` like a lower GFS.

### Legal holds (Phase 15c)
After the snapshots, `nexus-replica sync` fetches `GET …/tenants/{t}/holds` (`[HoldInfo {source, time, reason,
held_by, held_at}]`, the primary's active holds; 404 from older primaries = none) and reports them as `holds` in the
`replicated` line. The scheduler keeps them as advisory `legal_holds` rows (docs/control-plane.md "Legal hold"),
never enforced until a security officer of the secondary applies one. The secondary's own active holds go to
`nexus-replica` as `held` and are skipped by its retention (step 6).

### Tenant uid (Phase 19b)
`POST …/session` answers `{session, tenant_uid}`: the tenant's immutable uid on the primary (catalog v25). The
secondary records it per source and tenant in `replication_sources.status[<tenant>].primary_uid` at the first sync
that reports one (trust on first use) and passes it to every later `nexus-replica sync` (`tenant_uid` in the job
config); a primary that reports another uid for the name is a different tenant (deleted and re-created) — the sync
fetches nothing and fails as `verify-failed` (critical `replication_verify` alert). Backwards compatible: a primary
before 19b sends no uid (name only, as before); a secondary before 19b ignores the field. Tenant names on a primary
cannot be reused after deletion either (docs/control-plane.md "Tenant admins"). Decision: DEK labels, AADs, escrow
paths and `keys/tenants/<name>` stay bound to the name; the uid is an additional identity check only.

## 8. Catalog (v7)

| Table | Columns |
|---|---|
| `replication_peers` (primary) | id (16 hex), name UNIQUE, tenants (JSON), state (`pending`,`approved`,`enrolled`,`revoked`), cert_sha256 (UNIQUE when set), keyd_pub (base64), token_hash (`sealed:v1:` to replicad, NULL after enrollment), token_expires, enroll_failures, key_exports (JSON `{tenant: {versions, blob, quorum_id, created}}`), created, created_by, enrolled_at, last_seen, revoked |
| `replication_sources` (secondary) | id, name UNIQUE, url (`host:port`), peer_id, cert_pin (primary cert SHA-256), tenants (JSON), schedule, gfs (JSON), bwlimit (bytes/s), token_hash (`sealed:v1:` to the scheduler, location `replication-source/<id>/token@<url>`), state (`enrolling`,`enrolled`,`failed`), cert_sha256 (own client cert), keyd_pub, created, last_sync, status (JSON per tenant: last_ok, last_error, snapshots, bytes, key_versions) |
| `snapshots` | + `origin` (NULL = local backup, else replication source name) |

Migration 7 (applied after v6, the NAS connector's rebuild of `sources` for kinds `nfs`/`smb`) is purely additive: no table rebuild, `sources` keeps the v6 kind CHECK. The previous release (catalog v6) skips migration 7 and never reads the new tables/column (test `catalog::tests::migration_v7_adds_replication`).

## 9. Management API (`/api/v1`, session auth, RBAC, quorum, audit)

| Method + path | Role | Notes |
|---|---|---|
| `GET /replication/peers` | admin, security_officer, operator | never returns token digests or key blobs (`keys: {tenant: versions}`) |
| `POST /replication/peers {name, tenants}` | admin | → 202 `{quorum_id, peer, code}` (quorum `replication_peer.create`) |
| `POST /replication/peers/{id}/export-keys {tenants?}` | admin | → 202 `{quorum_id}` (`replication.key_export`, executed by the scheduler) |
| `DELETE /replication/peers/{id}` | admin | → 202 quorum `replication_peer.delete`: state `revoked`, token and key exports dropped, fingerprint refused immediately |
| `GET /replication/sources` | read (admin, security_officer, operator) | status per tenant, own keyd fingerprint |
| `POST /replication/sources {name, url, code, fingerprint, tenants, schedule, gfs?, bwlimit?}` | admin | → 201 + `replica_enroll` job id; creates missing tenants |
| `PUT /replication/sources/{id} {schedule?, gfs?, bwlimit?, windows?, sync_window?, timezone?}` | admin | lowering any GFS value or weakening the windows → quorum `replication_source.update` |
| `POST /replication/sources/{id}/close {until?}` | admin, security_officer | "close vault now", direct; 409 if it would shorten a closure |
| `POST /replication/sources/{id}/reopen` | admin, security_officer | → quorum `replication.reopen` (approved by another approver) |
| `POST /replication/sources/{id}/enroll` | admin | retry enrollment (needs a new code if the old one was consumed: `{code}`) |
| `POST /replication/sources/{id}/sync` | admin, operator | queues `replica_sync` for each tenant → 202 `{jobs}` |
| `DELETE /replication/sources/{id}` | admin | → quorum `replication_source.delete` (stops replication; replicated snapshots stay under retention) |

Audit actions: `replication_peer.create|enrolled|delete`, `replication.key_export`,
`replication.session_start|session_end|denied`, `replication_source.create|update|delete|close`, `replication.reopen`,
`replication_source.enrolled` (scheduler). Job kinds: `replica_enroll` (admin), `replica_sync`.

## 10. OS integration

- `nexus-replicad.service`: `User=nexus-chunkstore Group=nexus-replicad`, `RuntimeDirectory=nexus-replicad`
  (0750; socket 0660, `ca.pem`/`seal.pub` 0640), `ReadWritePaths=/var/lib/nexus/replicad`, store read-only
  (`ProtectSystem=strict`), `InaccessiblePaths=/run/nexus-keyd /var/lib/nexus/keyd /var/lib/nexus/catalog`,
  `PrivateNetwork=yes`, `RestrictAddressFamilies=AF_UNIX`. nexus-setup enables it with the other services.
  The web-api joins group `nexus-replicad`.
- SELinux: `nexus_replicad_t` (daemon: read-only `nexus_store_t`, own state, its socket; no keyd, no
  network; neverallow writes to stores); the web-api may connect only to replicad's socket
  (`nexus_replicad_var_run_t`) besides its existing rules; `nexus_replica_t` (job domain like offsite:
  store rw, keyd, connect to `http_port_t`/unreserved, its key dir `nexus_replica_key_t`, nobody else
  reads it).
- nftables: the scheduler adds every replication source's `host:port` to the outbound allow-list while it
  is open and inside its sync window (Phase 17a/b). The primary needs no rule (8443 inbound already exists).

## 11. Tests and lab results

In-process (`crates/web-api/tests/replication.rs`, two appliances in temp dirs with real keyd, replicad,
the web-api TLS server and the nexus-replica client): enrollment (incl. a TLS-terminating man in the
middle → refused, wrong code, wrong pin, single use), revocation on an open keep-alive connection, tenant
scope and path traversal, connection kinds (browser ALPN never reaches the peer API, peer ALPN without
certificate fails), incremental sync (1 changed chunk → 1 chunk transferred), tampered chunk → nothing
imported, restore on the secondary with only its keyd after the primary is gone, primary deletion not
propagated, key export only after a second person's approval, rotation → key mismatch until re-export,
web-api without replicad serves nothing. Scheduler: `replication_jobs` (enroll/sync jobs, schedule,
results, alerts, lag, no keyd `ensure`, no backups in replicated tenants). keyd: export/import rules.
Fuzz target `replication/hostile_primary` (secondary's HTTP client + chunk frames): found a lax status
parser (fixed), then 25.6 M executions clean.

Lab (`lab/appliance/replication.sh`, 2026-10-10): two appliance VMs from the same bootc image, SELinux
enforcing, QEMU user networking; the secondary reached the primary as `10.0.2.2:28471` (host forward of
the primary's 8443), the scheduler put exactly that into the nftables allow-list.
- Primary: PVE lab VM 100 (4 GiB disk) backed up (95 s, 383 MB sealed).
- Enrollment through the real 8443 with the pinned certificate; the keyd fingerprint shown in the key
  export request on the primary matched the secondary's (`8576:219c:…`).
- Initial sync: 307 chunks, 383 MB sealed in 2.1 s (**181 MB/s**, every chunk AEAD + keyed-hash verified
  on insert; both VMs on one host, loopback through QEMU user networking).
- Incremental (64 MiB written in the guest, second backup): 27 chunks / 71 MB fetched, 293 reused,
  160 MB/s.
- Primary VM powered off → file download of `/etc/hostname` from the replicated vm-100 snapshot on the
  secondary (restore micro-VM, store-only nexus-pve configuration, secondary keyd only): `testvm100`.
- Domains: `nexus_replicad_t` on both, the sync jobs left `nexus_replica_key_t` files (type transition
  of `nexus_replica_t`); **0 AVCs/SELinux errors with a nexus context on either appliance** (the base
  image logs three unrelated bootc/podman denials under `unconfined_service_t` at boot).
  `systemd-analyze security nexus-replicad`: 0.4 SAFE.

## 12. Open items
- Bandwidth limit on the primary side (per peer); the secondary has `bwlimit`.
- Re-keying a peer certificate needs delete + new peer (quorum) — no in-place renewal yet (10-year certs).
- Chained replication (secondary → tertiary) works for tenants the secondary does not hold local keys for,
  but the key export on the secondary then re-exports imported keys; not tested.
- Replicated snapshots are not offsite-uploaded by the secondary unless its tenant has an offsite target
  (works as usual, not tested in the lab).
