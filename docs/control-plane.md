# Control Plane — Contract (Phase 5)

Status: v1 (2026-10-09). Decisions: Svelte 5 + Vite SPA (assets embedded in web-api), TOTP-only MFA,
console TUI first boot. Plan §11.

## Processes and trust boundaries
| Process | User | Talks to | Never touches |
|---|---|---|---|
| `nexus-web-api` (axum, rustls, port 8443) | `nexus-webapi` | catalog DB, downloads dir (read), `secrets.pub` (read), TOTP key `/var/lib/nexus/webapi/totp.key` (0600, own) | keys, chunks, sources, plaintext source secrets |
| `nexus-scheduler` | `nexus-chunkstore` | catalog DB, keyd socket, chunk store, `nexus-pve` / `nexus-offsite` / `nexus-agentctl` / `nexus-truenas` (spawned), agent CA `/var/lib/nexus/scheduler/agent-ca/` (keys 0600), secrets key `/var/lib/nexus/scheduler/secrets.key` (0600, own) | HTTP clients |
| `nexus-setup` (console TUI, first boot) | root | keyd CLI, catalog DB, TLS files, creates the TOTP key | network until configured |
| `nexus-replicad` (docs/replication.md) | `nexus-chunkstore` (group `nexus-replicad`, domain `nexus_replicad_t`) | tenant stores **read-only**, replication CA + token-sealing key `/var/lib/nexus/replicad`, its socket `/run/nexus-replicad/replicad.sock` (web-api uid only) | keyd, catalog, network |

The web-api also connects to the replicad socket and reads `/run/nexus-replicad/ca.pem` (replication CA
certificate, verifies peer client certificates) and `seal.pub` (enrollment token digests are sealed to
replicad); it streams replicad's answers to replication peers without opening store files.

- The **catalog** is SQLite (WAL) at `/var/lib/nexus/catalog/catalog.db`, group `nexus-catalog` (both web-api and scheduler).
- The web-api only writes *intent*: config rows, job requests, quorum decisions. The scheduler executes jobs and reports state back into the catalog.
- File-restore downloads: the scheduler writes the tar/zip into `/var/lib/nexus/downloads/<token>.<ext>` (group-readable by web-api, expiring after 24 h), and web-api streams it.
- `nexus-web-api` refuses to start until `/var/lib/nexus/setup-done` exists (systemd `ConditionPathExists`).
- **Secrets at rest** (review H-2, `catalog::secret`):
  - Source/offsite credentials (`token_secret`, `key_pem`) are stored as `sealed:v1:<base64>`, sealed to the scheduler (X25519 sealed box).
    - The scheduler creates `/var/lib/nexus/scheduler/secrets.key` (0600) on first start (config `secrets_key`). It writes the public key to `/var/lib/nexus/catalog/secrets.pub` (0640, group `nexus-catalog`; config `secrets_pub`, web-api env `NEXUS_SECRETS_PUB`) at every start.
    - The web-api seals on write and never decrypts. Secret writes answer 503 while `secrets.pub` is missing.
    - Each sealed value is bound to its location: source id or tenant, field, and the endpoint fields next to it. The scheduler opens it only in memory for the 0600 job config and seals legacy plaintext at startup (audit `secret.migrate`).
  - TOTP seeds are stored as `enc:v1:<base64>` (XChaCha20-Poly1305, AAD = user name) with the web-api-only key `/var/lib/nexus/webapi/totp.key` (0600 `nexus-webapi`, env `NEXUS_TOTP_KEY`).
    - nexus-setup creates the key. The web-api creates it only if it is missing and no encrypted seed exists.
    - Legacy plaintext seeds are encrypted at web-api startup (audit `secret.migrate`).

## Catalog schema (crate `catalog`, migrations in code)
| Table | Columns (main) |
|---|---|
| `users` | id, name UNIQUE, password_hash (argon2id), totp_secret (`enc:v1:…`, legacy: base32), role, tenant (NULL = all), disabled, created, totp_last_step (v2) |
| `sessions` | id_hash (sha256 of cookie), user_id, csrf, created, last_seen |
| `tenants` | name PK, offsite (JSON: remote config, bwlimit, uploaders) |
| `sources` | id, tenant, kind (`pve`, `linux` since v4, `truenas` since v5), name, config (pve JSON: api host/port/ca_pem/token_id, token_secret (`sealed:v1:…`), nodes, storage, fleecing_storage; linux JSON: agent_id, paths, excludes, hooks; truenas JSON (docs/truenas-connector.md): host, port, connect_addr, ca_pem (pinned certificate or CA), user, token_secret (API key, sealed), ssh {host, port, user, host_key, key_pem (sealed), public_key, from}, datasets, recursive, sudo, zfs_sudo) |
| `agents` (v4) | id (16 hex), tenant, name, host, port, cert_sha256, enrolled_at, token_hash (`sealed:v1:` token digest, NULL after enrollment), token_expires, last_seen, version, os |
| `policies` | id, name, schedule (`daily HH:MM`, `hourly MM`), gfs (JSON {daily,weekly,monthly,yearly}), offsite (bool) |
| `groups` | id, tenant, source_id, policy_id, name, guests (JSON [vmid]; linux source: [agent_id]) |
| `jobs` | id, kind, tenant, params (JSON), state (`queued`,`running`,`ok`,`failed`,`cancelled`), requested_by, created, started, finished, log, result (JSON, NULL until finished ok; v3) |
| `snapshots` | tenant, source (`vm-100`/`ct-200`/`host-<agent_id>`), time, size, local, offsite, lock_until, verified — refreshed by scheduler |
| `quorum` | id, action, params (JSON), requested_by, created, decided_by, decided_at, state (`pending`,`approved`,`rejected`,`executed`,`expired`) |
| `audit` | seq PK, ts, actor, action, target, details (JSON), prev_hash, hash |
| `alerts` | id, ts, severity, kind, message, acked_by |
| `replication_peers` (v6, primary) | id (16 hex), name, tenants (JSON), state (`pending`,`approved`,`enrolled`,`revoked`), cert_sha256, keyd_pub, token_hash (`sealed:v1:` to replicad), token_expires, enroll_failures, key_exports (JSON, DEKs sealed to the peer's keyd), created, created_by, enrolled_at, last_seen, revoked |
| `replication_sources` (v6, secondary) | id, name, url (`host:port`), peer_id, cert_pin, tenants (JSON), schedule, gfs, bwlimit, token_hash (`sealed:v1:` to the scheduler), state (`enrolling`,`enrolled`,`failed`), cert_sha256, keyd_pub, created, last_sync, status (JSON per tenant) |

`snapshots.origin` (v6): NULL for local backups, else the replication source the snapshot came from.

Job kinds: `backup` {group_id | vmid}, `restore` {source, time, node, target, storage}, `restore_ct`, `instant_recover`, `files_list` {source,time,path}, `files_get` {source,time,paths,format} (also for `host-<agent_id>` snapshots), `offsite`, `retention`, `gc`, `verify`; Linux agents (docs/agent-protocol.md): `backup` {agent_id}, `restore_files` {source: host-<id>, time, paths, target, overwrite: never|if_older|always, confirm, agent_id}, `agent_update` {agent_id}, `agent_enroll` {agent_id}; TrueNAS (docs/truenas-connector.md): `backup` {group_id} (guests = datasets), `files_list` / `files_get` / `retention` {source: nas-<source-id>-<pool.dataset>} (download only, no `restore_files`); replication (docs/replication.md): `replica_enroll` {replication_source_id}, `replica_sync` {replication_source_id, tenant} (secondary, spawn `nexus-replica`; not accepted by `POST /jobs`).

Catalog migrations stay backward compatible for one release (docs/release.md): v4 adds `agents` and rebuilds `sources` with the wider kind CHECK (same rows and ids, run with foreign keys off and checked with `foreign_key_check`); the previous release skips the unknown migration and fails jobs of `linux` sources as unsupported. v5 rebuilds `sources` the same way for kind `truenas`.

## Audit log
`hash = sha256(prev_hash || seq || ts || actor || action || target || details)`, hex; `prev_hash` of seq 1 = 64×"0".
Every mutating API call and every job state change appends one entry (`catalog::Catalog::audit`). `GET /api/v1/audit/verify` recomputes the chain. Entries are forwarded to syslog (RFC 5424 via the local journal; TLS forwarding is configured in the OS).

## Roles (RBAC)
| Capability | admin | security_officer | operator | tenant_user |
|---|---|---|---|---|
| read everything (own tenant for tenant_user) | ✓ | ✓ | ✓ | own |
| sources, policies, groups, tenants, users CRUD | ✓ | — | — | — |
| run backups / restores / file restore (incl. `restore_files`) | ✓ | — | ✓ | own (restores only) |
| agents CRUD, enrollment, `agent_update` | ✓ | — | — | — |
| replication peers / sources: create, key export request, revoke/delete, settings | ✓ | — | — | — |
| replication peers / sources: read; replication source "sync now" | ✓ | read | ✓ | — |
| approve/reject quorum requests | — | ✓ | — | — |
| audit log, verify chain | ✓ | ✓ | — | — |

**Quorum (four-eyes)** — these never execute directly; they create a `quorum` row that a *different* user with role `security_officer` must approve within 72 h: weakening a policy (any GFS value lowered, offsite disabled), deleting a group/source/tenant/policy/agent, deleting snapshots manually, GC deleting > 20 % of chunks (raised by the scheduler), granting `admin`/`security_officer`, disabling a user who is the last admin/security_officer; replication (docs/replication.md): creating a replication peer (`replication_peer.create`, exposes the tenants' data), exporting DEKs to a peer (`replication.key_export`, executed by the scheduler), revoking a peer, deleting an enrolled replication source, lowering a replication source's GFS.

## REST API (`/api/v1`, JSON)
Auth: `POST /auth/login {name, password, totp}` → `Set-Cookie: nx_session=…; HttpOnly; Secure; SameSite=Strict; Path=/` + body `{csrf, user}`. Every non-GET request needs header `X-CSRF-Token`. `POST /auth/logout`, `GET /auth/me` → `{user, csrf}` (lets the SPA recover its CSRF token after a reload; same-origin + SameSite=Strict keeps it from other sites). Sessions expire after 30 min idle / 12 h absolute. Login rate limit: 5 failures per user or IP per 15 min → 15 min lockout (audited).

| Method + path | Role | Notes |
|---|---|---|
| `GET /health` | none | `{ok}` |
| `GET /metrics` | bearer token from `/etc/nexus/metrics-token` | Prometheus text |
| `GET/POST /tenants`, `PUT/DELETE /tenants/{name}` | admin (DELETE → quorum) | |
| `GET/POST /sources`, `PUT/DELETE /sources/{id}` | admin (DELETE → quorum) | secrets write-only (never returned) |
| `GET/POST /policies`, `PUT/DELETE /policies/{id}` | admin (weakening PUT / DELETE → quorum) | |
| `GET/POST /groups`, `PUT/DELETE /groups/{id}` | admin (DELETE → quorum) | |
| `GET/POST /users`, `PUT /users/{id}` | admin (privileged role grants → quorum) | POST returns the TOTP provisioning URI once; `password` / `reset_totp` on PUT need re-authentication (see Clarifications) |
| `GET /agents`, `POST /agents`, `DELETE /agents/{id}` | read / admin (DELETE → quorum) | POST `{tenant, name, host, port=7444}` → 201 agent + one-time `token` + `install_command` (shown once) |
| `POST /agents/{id}/token`, `POST /agents/{id}/enroll` | admin | new one-time token (200 `{token, install_command, token_expires}`); enroll → 202 `{id}` of an `agent_enroll` job, 409 without a valid token |
| `GET /snapshots?tenant=&source=` | read | local/offsite/lock/verified per snapshot |
| `GET /jobs?state=&kind=`, `GET /jobs/{id}` (incl. log) | read | `result` = structured job result (see Clarifications) |
| `POST /jobs` `{kind, tenant, params}` | per kind (see RBAC) | returns job id; 202 |
| `POST /jobs/{id}/cancel` | operator/admin | queued only |
| `GET /downloads/{token}` | requester only | streams file, deleted after 24 h |
| `GET /quorum`, `POST /quorum/{id}/approve`, `POST /quorum/{id}/reject` | security_officer (approve: not the requester) | |
| `GET /audit?after=&before=&order=&limit=`, `GET /audit/verify` | admin, security_officer | oldest first after `after` (default); newest first with `before` or `order=desc` |
| `GET /alerts`, `POST /alerts/{id}/ack` | read / operator+ | |
| `GET/POST /replication/peers`, `POST /replication/peers/{id}/export-keys`, `DELETE /replication/peers/{id}` | read / admin (POST, export, DELETE → quorum) | POST answers 202 `{quorum_id, peer, code}`: the enrollment code is shown once |
| `GET/POST /replication/sources`, `PUT/DELETE /replication/sources/{id}`, `POST /replication/sources/{id}/enroll`, `POST /replication/sources/{id}/sync` | read / admin (sync: operator too) | details in docs/replication.md §9 |

Peer API `/replication/v1/*` (not under `/api/v1`): only on TLS connections with the replication ALPN and an enrolled client certificate (docs/replication.md §3, §6).

Errors: `{error: "message"}` with 400/401/403/404/409/429, and 503 for secret writes while the scheduler's public key is missing. Quorum-gated requests answer **202** `{quorum_id}`.

Headers on every response: `Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Strict-Transport-Security: max-age=31536000`. The SPA is served from `/` (index.html fallback for client routes), assets from `/assets/*` (embedded at build time from `web/dist`).

### Clarifications (web-api v1)
- `/health` and `/metrics` answer under `/api/v1/` and at the root. `/metrics` series: `nexus_jobs{state}`, `nexus_snapshots{tenant,location=local|offsite}`, `nexus_last_successful_backup_timestamp_seconds{tenant,group}` (max `finished` of `ok` backup jobs whose params carry that `group_id`, 0 = never — so the scheduler queues scheduled backups as `{group_id}`), `nexus_failed_logins_total`, `nexus_audit_entries`, `nexus_quorum_pending`.
- `POST /auth/login` is the only non-GET without `X-CSRF-Token` (no session yet); all JSON bodies require `Content-Type: application/json`, unknown fields are rejected.
- Names (`[A-Za-z0-9._-]{1,64}`) must not start with a dot (threat model T11). Opaque JSON blobs (`tenants.offsite`, `sources.config.nodes`) must not contain inline secrets (keys containing `secret`/`password`/`passphrase`/`private` are refused) — secrets live in files referenced by path; the only inline secret is `token_secret`, which is never returned (`token_secret_set: bool` instead; omitted on PUT = keep).
- File restore: the web-api adds `download_token` (64 hex) to `files_get` params and returns it in the 202 body; the scheduler writes `/var/lib/nexus/downloads/<token>.<format>` (`format` = `tar`|`zip`). `GET /downloads/{token}` serves it only to the job's `requested_by`, only if younger than 24 h; the scheduler deletes it.
- Quorum execution: on approval the web-api itself applies `tenant.delete`, `source.delete`, `policy.delete`, `policy.update`, `group.delete`, `group.update`, `user.update` (state → `executed`). Any other action (e.g. `gc` raised by the scheduler with `requested_by = "scheduler"`) only becomes `approved`; the scheduler executes it and sets `executed`. Pending requests older than 72 h become `expired` (audited).
- Also quorum-gated: moving a group to a policy that is weaker in any dimension (`group.update`); creating an admin/security_officer (account is created *disabled*, the quorum request enables it; the TOTP URI is returned at creation); re-enabling such an account; demoting as well as disabling the last enabled admin/security_officer; resetting another admin's/security_officer's password or TOTP. Quorum params never expose password hashes or TOTP secrets.
- Re-authentication (review M-5): `PUT /users/{id}` with `password` or `reset_totp: true` (own account or another user's) must also carry `current_password` and `current_totp` of the *acting* user.
  - Missing fields → 400.
  - Wrong password or code, or a replayed code (the TOTP step is consumed as at login) → 403, audited as `auth.reauth_failed` (actor = acting user, details `reason`, `for`).
  - Failures count toward the login rate limiter (per user and per IP). A lockout answers 429 and also blocks login.
- Job results (`jobs.result`, written by the scheduler when a job finishes `ok`, returned as `result` by `GET /jobs` and `GET /jobs/{id}`): `files_list` → `{"entries": [{name, kind, size, mtime, mode?, link?}, …]}` (the JSON `nexus-pve … ls` prints); `files_get` → `{"download_token", "format", "entries": n, "size": bytes, "expires": unix}`; `backup` → `{"snapshots": [{"source", "time"}, …]}` plus top-level `source`/`time` when exactly one guest was committed. Other kinds: `null`.
- Audit paging: `GET /audit?after=<seq>` returns entries with `seq > after` oldest first; `?order=desc` (no cursor) starts at the newest entry, `?before=<seq>` returns `seq < before` newest first (pages backwards; `order=asc` with `before` is 400). `limit` defaults to 500, max 1000.
- Agents (docs/agent-protocol.md): `GET /agents` never returns the token digest; the token (128 bit, base32, 26 characters, 24 h) appears only in the answer of `POST /agents` / `POST /agents/{id}/token` (install command `/usr/local/sbin/nexus-agent init --token <T>`: full path, as `/usr/local/sbin` is not in sudo's `secure_path` on EL/Fedora) and is stored as its digest sealed to the scheduler (503 while `secrets.pub` is missing). Audit: `agent.create`, `agent.token`, `agent.delete` (quorum), `agent.enrolled` (scheduler). An agent used by a linux source cannot be deleted (409); a tenant with agents cannot be deleted. A linux source's `agent_id` must be an agent of the same tenant; `paths` 1..=64 absolute paths without `.`/`..`, `excludes` ≤ 256 patterns. `restore_files`: `confirm` must equal the target agent's name (400 otherwise; the agent journals it); the web-api adds `agent_id` (default: the snapshot's agent). `agent_update` / `agent_enroll` are admin-only job kinds. Job results: agent `backup` → `{snapshots, source, time, consistent, transferred_bytes}`, `restore_files` → `{target, files, dirs, bytes, errors}`, `agent_enroll` → `{agent_id, cert_sha256, appliance_id}`.
- TrueNAS sources (docs/truenas-connector.md): `token_secret` (API key) and `ssh.key_pem` are write-only and sealed (`token_secret_set`, `ssh.key_pem_set` instead); omitted on PUT = keep, refused when the endpoint fields they are bound to change. GET adds `authorized_keys`: the line (with the forced command) to paste into the TrueNAS user's "SSH public key" field. Datasets: 1..=64 non-overlapping names of `[A-Za-z0-9_-]` components. Groups of a TrueNAS source list datasets of that source as guests (empty = all). Backup results carry `transferred_bytes` per `nas-` snapshot.
- `GET /quorum` is readable by admin, security_officer and operator. Tenant-scoped users (`users.tenant` set) see only their tenant's rows in every list (`users` included); `alerts` has no tenant column, so they get an empty list.

## Scheduler
Tick every 30 s: (1) queue `backup` jobs for groups whose policy schedule is due (once per period); after each successful backup: `retention` for that source, then `offsite` if the policy says so; (2) run queued jobs FIFO, at most one per source at a time, by spawning `nexus-pve` / `nexus-offsite` / `nexus-agentctl` / `nexus-truenas` with a generated config (0600, in a private runtime dir) and capturing output into `jobs.log`; (3) refresh `snapshots`; (4) daily `gc` + `verify`; a GC that needs quorum raises a `quorum` request and an alert; (5) alerts: failed job, offsite lag > 48 h, verify failure, inventory anomaly, capacity > 75 %, agent backup without a consistent view (`backup_inconsistent`, warning). Agent jobs are exclusive per agent (`agent:<id>`); agent backups are refused before they start if the agent is not enrolled; `agent-info`/`enrolled` lines of `nexus-agentctl` update `agents` (last_seen, version, os; fingerprint, token cleared). The firewall allow-list includes every agent's host:port and the API (`connect_addr`, else host:port) and SSH endpoint of every TrueNAS source. TrueNAS backups are exclusive per source; the job dir gets the pinned certificate, API key, SSH key and a `known_hosts` built from the pinned host key (0600); retention after a TrueNAS backup covers each dataset of the group and its child datasets (`nas-<id>-<pool.ds>` and the prefix `nas-<id>-<pool.ds>.`). Alert delivery: webhook URL + SMTP from `/etc/nexus/alerts.json`.

Replication (docs/replication.md): on the primary the scheduler executes approved `replication.key_export` requests (keyd `export-for`, blob into `replication_peers.key_exports`, quorum → `executed`). On the secondary it queues `replica_sync` per enrolled replication source and tenant on the source's schedule (exclusive per tenant, `tenant:<t>`), spawns `nexus-replica` (`enrolled` / `replicated` / `key-mismatch` / `verify-failed` lines update `replication_sources` and raise `replication_keys` / `replication_verify` alerts), raises `replication_lag` (no successful sync for 48 h), adds every primary's `host:port` to the firewall allow-list, never asks keyd to `ensure` a replicated tenant, and refuses backups into replicated tenants. File restores of replicated VM/CT snapshots without a local PVE source use a store-only `nexus-pve` configuration.

## First boot (`nexus-setup`, console TUI)
Network (NetworkManager, static/DHCP on the management NIC) → admin account + TOTP enrollment (QR in terminal, code confirmation) → `keyd init`: recovery key shown once, re-entry of 3 random groups required → TLS certificate (self-signed, SAN = hostname + IPs; fingerprint shown) → metrics token → `/var/lib/nexus/setup-done` → enable `nexus-web-api`, `nexus-scheduler`, `nexus-keyd`, `nexus-replicad`.

Tenant keys: tenants are created in the UI; the scheduler asks keyd `ensure <tenant>` (keyd creates DEK v1 on first use, only for the chunkstore uid) and refreshes the wrapped escrow files via `escrow <tenant>` before each offsite run.
