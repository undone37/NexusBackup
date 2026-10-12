# Control Plane — Contract (Phase 5)

Status: v1 (2026-10-09). Decisions: Svelte 5 + Vite SPA (assets embedded in web-api), TOTP-only MFA,
console TUI first boot. Plan §11.

## Processes and trust boundaries
| Process | User | Talks to | Never touches |
|---|---|---|---|
| `nexus-web-api` (axum, rustls, port 8443) | `nexus-webapi` | catalog DB, downloads dir (read), `secrets.pub` (read), TOTP key `/var/lib/nexus/webapi/totp.key` (0600, own), OS update control dir `/var/lib/nexus/update` (request file, status.json), the OIDC identity provider (HTTPS out: discovery, JWKS, token endpoint; Phase 12) | keys, chunks, sources, plaintext source secrets, `/etc/nexus/ssh` |
| `nexus-scheduler` | `nexus-chunkstore` | catalog DB, keyd socket, chunk store, `nexus-pve` / `nexus-offsite` / `nexus-agentctl` / `nexus-truenas` / `nexus-nas` / `nexus-replica` (spawned), agent CA `/var/lib/nexus/scheduler/agent-ca/` (keys 0600), secrets key `/var/lib/nexus/scheduler/secrets.key` (0600, own) | HTTP clients |
| `nexus-nasmount` (socket-activated per connection, docs/nas-connector.md) | root, `CAP_SYS_ADMIN` only | its socket `/run/nexus-nasmount/mount.sock` (group `nexus-chunkstore`): one request, one detached read-only NFS/CIFS mount whose fd goes back to `nexus-nas` | files, catalog, keys, chunks; it never attaches a mount anywhere |
| `nexus-setup` (console TUI, first boot) | root | keyd CLI, catalog DB, TLS files, creates the TOTP key | network until configured |
| `nexus-console-gate` (tty2, Phase 14c) | root, domain `nexus_consolegate_t` | catalog DB (audit, alerts, banner setting), keyd files (recovery key check, read), `/var/lib/nexus/console-unlock` (read + delete), PID 1 (transient scope); starts the root shell (`unconfined_t`) | network |
| `nexus-tls` (oneshot, `nexus-tls.path`, Phase 14d) | root, no capabilities, group `nexus-webapi` | its request dir `/var/lib/nexus/tls` (0770 root:nexus-webapi), `/etc/nexus/tls/web.pem*` and `pending/` | network, catalog, the identity certificate/key `cert.pem`/`key.pem` (SELinux `nexus_tls_t`) |
| `nexus-disks` (oneshot, `nexus-disks.timer` + `.path`, Phase 16, docs/hardware.md) | root, CAP_SYS_RAWIO / SYS_ADMIN / DAC_READ_SEARCH, group `nexus-webapi` | block devices (smartctl, mdadm, mkfs.xfs, xfs_growfs), its dir `/var/lib/nexus/disks` (2771 root:nexus-webapi), the store's mount unit in `/etc/systemd/system`, stop/start of the scheduler and replicad around the mount | network, catalog, keys, store contents (SELinux `nexus_disks_t`) |
| `nexus-replicad` (docs/replication.md) | `nexus-chunkstore` (group `nexus-replicad`, domain `nexus_replicad_t`) | tenant stores **read-only**, replication CA + token-sealing key `/var/lib/nexus/replicad`, its socket `/run/nexus-replicad/replicad.sock` (web-api uid only) | keyd, catalog, network |

The web-api also connects to the replicad socket and reads `/run/nexus-replicad/ca.pem` (replication CA
certificate, verifies peer client certificates) and `seal.pub` (enrollment token digests are sealed to
replicad); it streams replicad's answers to replication peers without opening store files.

- The **catalog** is SQLite (WAL) at `/var/lib/nexus/catalog/catalog.db`, group `nexus-catalog` (both web-api and scheduler).
- The web-api only writes *intent*: config rows, job requests, quorum decisions. The scheduler executes jobs and reports state back into the catalog.
- File-restore downloads: the scheduler writes the tar/zip into `/var/lib/nexus/downloads/<token>.<ext>` (group-readable by web-api, expiring after 24 h), and web-api streams it.
- `nexus-web-api` refuses to start until `/var/lib/nexus/setup-done` exists (systemd `ConditionPathExists`).
- **Secrets at rest** (review H-2, `catalog::secret`):
  - Source/offsite credentials (`token_secret`, `key_pem`, SMB `password` / `keytab`) are stored as `sealed:v1:<base64>`, sealed to the scheduler (X25519 sealed box).
  - Source/offsite credentials (`token_secret`, `key_pem`, the S3 `secret_key`) are stored as `sealed:v1:<base64>`, sealed to the scheduler (X25519 sealed box).
    - The scheduler creates `/var/lib/nexus/scheduler/secrets.key` (0600) on first start (config `secrets_key`). It writes the public key to `/var/lib/nexus/catalog/secrets.pub` (0640, group `nexus-catalog`; config `secrets_pub`, web-api env `NEXUS_SECRETS_PUB`) at every start.
    - The web-api seals on write and never decrypts. Secret writes answer 503 while `secrets.pub` is missing.
    - Each sealed value is bound to its location: source id or tenant, field, and the endpoint fields next to it. The scheduler opens it only in memory for the 0600 job config and seals legacy plaintext at startup (audit `secret.migrate`).
  - TOTP seeds are stored as `enc:v1:<base64>` (XChaCha20-Poly1305, AAD = user name) with the web-api-only key `/var/lib/nexus/webapi/totp.key` (0600 `nexus-webapi`, env `NEXUS_TOTP_KEY`).
    - nexus-setup creates the key. The web-api creates it only if it is missing and no encrypted seed exists.
    - Legacy plaintext seeds are encrypted at web-api startup (audit `secret.migrate`).
  - OIDC client secret (`settings.oidc.client_secret`, Phase 12): `enc:v1:` with the same web-api key but its own AAD (`nexus webapi v1\0oidc/client_secret`), because the web-api itself sends it to the IdP's token endpoint (client_secret_basic). Write-only in the API, `<redacted>` in quorum params.
  - SMTP password of the alert delivery (`settings.alerts.smtp.password`, Phase 12): sealed to the scheduler like source secrets (owner `settings/alerts`, bound to the SMTP host, port and user). Phase 13f: webhook header values of the notification rules (`settings.alert_rules`), sealed at `settings/alert_rules/<rule>/<header>@<url>`.

## Catalog schema (crate `catalog`, migrations in code)
| Table | Columns (main) |
|---|---|
| `users` | id, name UNIQUE, password_hash (argon2id; `!pending-activation` while pending), totp_secret (`enc:v1:…`, legacy: base32; empty until the person enrolls), role, tenant (NULL = all), disabled, created, totp_last_step (v2), activation_hash + activation_expires (v9: digest of the one-time activation code, NULL = active; see Self-enrollment), auth (v10: `local` or `oidc`; OIDC accounts have password_hash `!oidc` and no TOTP seed), oidc_sub (v10: `<issuer>\|<sub>`, unique where set); v15 (table rebuilt): role CHECK adds `viewer` and `tenant_admin` (reserved for Phase 18c, refused by the API), can_download (NULL = role default: admin/operator/tenant_user yes, others no), expires (NULL = never), last_login |
| `settings` (v9) | key PK, value: `approvals_enabled` (`true`/`false`), `gc_confirm/<tenant>` (JSON `{job, reason, created}`: a large GC waiting for an admin's confirmation while approvals are disabled); Phase 12: `oidc` (OIDC settings incl. mappings, client secret `enc:v1:`), `oidc_endpoints` (token + JWKS URL of the last discovery, for the allow-list), `alerts` (alert delivery, SMTP password sealed), `ssh_keys` (public halves published by the scheduler), `capacity` (store file system `{total, used, free, at}`, scheduler), `break_glass` (`{at, user, alert, forced_solo}` until the alert is acknowledged) |
| `backup_stats` (v11) | tenant, source, time, read, logical, new_chunks, new_plain, new_stored; PK (tenant, source, time); one row per committed snapshot from the connectors' `nexus-stats` lines (docs/storage-accounting.md). Also v11: `tenants.quota_bytes` (nullable soft quota) |
| `capacity_samples` (v10) | day (`YYYY-MM-DD` UTC), tenant, used (bytes in the tenant's store), logical (sizes of its local snapshots); PK (day, tenant); one row per tenant and day, written by the scheduler's refresh |
| `sessions` | id_hash (sha256 of cookie), user_id, csrf, created, last_seen; v15 (rebuilt): id (numeric, listed and revoked by it; the digest never leaves the server), ip, user_agent |
| `tenants` | name PK, offsite (JSON: remote config, bwlimit, uploaders) |
| `sources` | id, tenant, kind (`pve`, `linux` since v4, `truenas` since v5, `nfs`/`smb` since v6), name, config (pve JSON: api host/port/ca_pem/token_id, token_secret (`sealed:v1:…`), nodes, storage, fleecing_storage; linux JSON: agent_id, paths, excludes, hooks; truenas JSON (docs/truenas-connector.md): host, port, connect_addr, ca_pem (pinned certificate or CA), user, token_secret (API key, sealed), ssh {host, port, user, host_key, key_pem (sealed), public_key, from}, datasets, recursive, sudo, zfs_sudo; nfs/smb JSON (docs/nas-connector.md): host, port, version, NFS export/mount_port, SMB share/user/domain/sec/sign/seal/password (sealed)/keytab (sealed)/principal, snapshot_dir/snapshot_prefix/snapshot_order, excludes, threads, xattrs, timeout_secs) |
| `tenants` | name PK, offsite (JSON: `remote` = `{type: "sftp", host, port, user, key_file, host_key, base_dir}` or `{type: "s3", endpoint, region, bucket, prefix, access_key, secret_key (sealed), path_style, ca_pem, storage_class_packs, storage_class_meta, lock}` (docs/s3-offsite.md), bwlimit (bytes/s), uploaders) |
| `sources` | id, tenant, kind (`pve`, `linux` since v4, `truenas` since v5), name, config (pve JSON: api host/port/ca_pem/token_id, token_secret (`sealed:v1:…`), nodes, storage, fleecing_storage; linux JSON: agent_id, paths, excludes, hooks; truenas JSON (docs/truenas-connector.md): host, port, connect_addr, ca_pem (pinned certificate or CA), user, token_secret (API key, sealed), ssh {host, port, user, host_key, key_pem (sealed), public_key, from}, datasets, recursive, sudo, zfs_sudo) |
| `agents` (v4) | id (16 hex), tenant, name, host, port, cert_sha256, enrolled_at, token_hash (`sealed:v1:` token digest, NULL after enrollment), token_expires, last_seen, version, os; v21: cert_issued / cert_expires (validity of the presented certificate, from `agent-cert` lines), cert_sha256_next (renewed certificate issued but not confirmed: a second accepted pin), limits (JSON `{bwlimit, nice}`) |
| `policies` | id, name, schedule (`daily HH:MM`, `hourly MM`, `every Nh [at MM]`, `Mon,Wed HH:MM` / `Mon-Fri HH:MM`, `monthly D HH:MM`; `catalog::schedule`), gfs (JSON {daily,weekly,monthly,yearly}), offsite (bool); v14: retry (JSON {count, delay_min}, default 3 × 5 min), blackout (JSON [{days, from, to, abort}]), sla_minutes (NULL = none) |
| `groups` | id, tenant, source_id, policy_id, name, guests (JSON [vmid]; linux source: [agent_id]; truenas: [dataset]; nfs/smb: []), mode (v13: `explicit` = guests; `all` = every present inventory guest of the source; `tags` = those with any tag of `selector`), selector (v13, JSON [tag]), exclude (v13, JSON [guest id], always wins). Resolution: `catalog::inventory::resolve`, used by the scheduler (`groups()`: queueing, plans, retention, offsite lag) and the web-api (dashboard, inventory) alike. A truenas group saved without datasets is `all` (resolved at run time, no longer frozen at save time); v14: timezone (IANA, default `UTC`), paused_until (NULL / unix time / -1 = indefinitely); v18: index_files (0/1, pve groups: index the files in VM/CT disks after each backup, docs/file-index.md) |
| `inventory` (v13) | source_id (FK, ON DELETE CASCADE), guest (vmid / dataset / plugin guest id), name, kind, tags (JSON, e.g. `pool:x`, `tag:y`, `node:n`, `type:qemu`, `type:user`, `license:none`), seen, gone (NULL = present; set when a listing no longer contains the guest, row kept); PK (source_id, guest). Written by the scheduler from `inventory` / `plugin_guests` results. Groups of mode `all` / `tags` leave out guests tagged `license:none` or `site:team` unless the selector names that tag (`catalog::inventory::DEFAULT_OFF`: unlicensed Microsoft 365 users; team/group sites, backed up by their team / group guest) |
| `jobs` | id, kind, tenant, params (JSON), state (`queued`,`running`,`ok`,`failed`,`cancelled`), requested_by, created, started, finished, log, result (JSON, NULL until finished ok; v3; a failed group backup: `{failed_guests}`); v14: not_before (retry delay), attempt, retry_of (first job of the chain), cancel_by (cancel request of a running job), sla_alerted |
| `snapshots` | tenant, source (`vm-100`/`ct-200`/`host-<agent_id>`/`nas-<id>-<dataset>`/`share-<id>`), time, size, local, offsite, lock_until, verified — refreshed by scheduler |
| `legal_holds` (v18) | id, tenant, source, time, state (`active`, `released`, `advisory`, `withdrawn`), reason, held_by, held_at, origin (replication source of an advisory), released_by (requester), approved_by, released_at; one open (`active`/`advisory`) row per snapshot (partial unique index), the rest is history. Not a foreign key: the snapshot row is rebuilt by the refresh. See "Legal hold" |
| `quorum` | id, action, params (JSON), requested_by, created, decided_by, decided_at, state (`pending`,`approved`,`rejected`,`executed`,`expired`) |
| `audit` | seq PK, ts, actor, action, target, details (JSON), prev_hash, hash |
| `forward_events` (v16) | seq PK AUTOINCREMENT, ts, type (`alert`,`job`), payload (JSON of the row at that moment) — outbox written by triggers on `alerts` (raised / escalated / acknowledged / resolved) and `jobs` (state → ok/failed/cancelled); pruned when every enabled sink has it and it is older than a day |
| `forward_state` (v16) | sink PK (`syslog`,`https`), dest, audit_seq, event_seq (last delivered), last_ok, last_error, last_error_ts, failing_since |
| `alerts` | id, ts (first seen), severity, kind, message (latest), acked_by; v12 (13f lifecycle): key (dedup key, one open alert per key), tenant, count, last_ts, resolved_at, resolved_by, note, auto (resolved by the scheduler), notified_ts (last delivery; NULL = due) |
| `replication_peers` (v7, primary) | id (16 hex), name, tenants (JSON), state (`pending`,`approved`,`enrolled`,`revoked`), cert_sha256, keyd_pub, token_hash (`sealed:v1:` to replicad), token_expires, enroll_failures, key_exports (JSON, DEKs sealed to the peer's keyd), created, created_by, enrolled_at, last_seen, revoked |
| `replication_sources` (v7, secondary) | id, name, url (`host:port`), peer_id, cert_pin, tenants (JSON), schedule, gfs, bwlimit, token_hash (`sealed:v1:` to the scheduler), state (`enrolling`,`enrolled`,`failed`), cert_sha256, keyd_pub, created, last_sync, status (JSON per tenant) |

`snapshots.origin` (v7): NULL for local backups, else the replication source the snapshot came from. `snapshots.consistency` (v20): `application`/`crash`/`inconsistent`/`unknown`/NULL; `policies.require_consistency` (v20): JSON `{mode, level}` (see Consistency).

Plugins (v8, docs/plugin-system.md): `plugins` = one row per uploaded (id, version): name, publisher, sha256 (bundle), bin_sha256 (`bin/plugin`, checked by nexus-pluginhost before every start), size, manifest (as signed), signer (key name + `sha256:<fingerprint>`), state (`pending`,`approved`,`installed`,`failed`,`rejected`,`removing`,`removed`), current (one per id), enabled, quorum_id, uploaded_by/at, installed_at, error; `plugin_keys` = publisher keys added with quorum: fingerprint (`sha256:<hex>` of the SPKI), publisher, public_key (PEM), added_by, approved_by, added_at. `sources.kind` additionally accepts `plugin:<kind>` (rebuild like v4–v6); the config of such a source is the plugin's config object, its manifest `secret_fields` sealed (`sealed:v1:`, location like every other secret) and write-only (`<field>_set` in GET).

Job kinds: `backup` {group_id | vmid}, `restore` {source, time, node, target, storage, + options of "Restore options"}, `restore_ct`, `instant_recover`, `files_list` {source,time,path}, `files_get` {source,time,paths,format} (also for `host-<agent_id>` snapshots), `offsite`, `retention`, `gc`, `verify`; Linux agents (docs/agent-protocol.md): `backup` {agent_id}, `restore_files` {source, time, paths, target, overwrite: never|if_older|always, confirm, agent_id} (source: any file snapshot of the tenant: `host-`, `nas-`, `share-`, `plugin-` of a plugin with a `download` restore, `vm-`, `ct-`; see "Restore to a host"), `agent_update` {agent_id}, `agent_enroll` {agent_id}, `agent_renew` {agent_id} (Phase 15f); TrueNAS (docs/truenas-connector.md): `backup` {group_id} (guests = datasets), `files_list` / `files_get` / `retention` {source: nas-<source-id>-<pool.dataset>} (and `restore_files` onto an agent); NFS/SMB shares (docs/nas-connector.md): `backup` {group_id} (no guests), `files_list` / `files_get` / `retention` {source: share-<source-id>} (and `restore_files` onto an agent). Plugins (docs/plugin-system.md, docs/plugin-sdk.md): `backup` {group_id} of a `plugin:<kind>` source (guests = guest ids of the kind, or none = the whole source), `plugin_backup` {source_id, guests?} (admin/operator), `plugin_validate` {source_id} → result `{valid, field?, message?}`, `plugin_guests` {source_id} → `{guests: [{id, title, size?}]}` (admin/operator), `plugin_restore` {source: plugin-…, time, restore, params} → `{restore, files, streams, bytes, summary}`, `plugin_mount` {source, time, params, minutes 1..1440} → `{info, reads, bytes, summary}` (also tenant users), `files_list` / `files_get` / `retention` {source: `plugin-<plugin>-<source>[-<guest>]`} (the generic download; streams below `.nexus-streams/`); a backup's follow-up retention is `{source_id, plugin: true}`. Replication (docs/replication.md): `replica_enroll` {replication_source_id}, `replica_sync` {replication_source_id, tenant} (secondary, spawn `nexus-replica`; not accepted by `POST /jobs`). File index (Phase 15g, docs/file-index.md; not accepted by `POST /jobs`): `file_search` {query, source?, from?, to?, case_sensitive, limit} (queued by `POST /search`), `file_index` {} (tenant-wide backfill of missing name indexes, daily with gc/verify) or {source: vm-…|ct-…, time} (after a backup of a group with `index_files`).

Catalog migrations stay backward compatible for one release (docs/release.md): v4 adds `agents` and rebuilds `sources` with the wider kind CHECK (same rows and ids, run with foreign keys off and checked with `foreign_key_check`); the previous release skips the unknown migration and fails jobs of `linux` sources as unsupported. v5 rebuilds `sources` the same way for kind `truenas`, v6 for kinds `nfs` and `smb`. v7 (replication) is purely additive: two new tables and the nullable column `snapshots.origin`; the v6 release skips it and never reads them. v8 (plugins) adds `plugins` / `plugin_keys` and rebuilds `sources` for `plugin:<kind>` (as v4–v6); the v7 release skips it and fails jobs of plugin sources as unsupported. v9 (optional approvals, self-enrollment) is purely additive and independent of v8: table `settings` (existing catalogs get `approvals_enabled = true`, i.e. the previous behaviour; nexus-setup writes the value for a new appliance) and the nullable columns `users.activation_hash`, `users.activation_expires`; earlier releases skip it (a pending account cannot log in there either). v10 (Phase 12) is purely additive: table `capacity_samples`, columns `users.auth` (NOT NULL DEFAULT `local`, CHECK `local`/`oidc`) and `users.oidc_sub` (nullable, unique index); the v9 release skips it, its user queries keep working, and OIDC accounts cannot log in there (no valid password hash, no TOTP seed). Test: `catalog` `migration_v10_from_v9`.

## Audit log
`hash = sha256(prev_hash || seq || ts || actor || action || target || details)`, hex; `prev_hash` of seq 1 = 64×"0".
Every mutating API call and every job state change appends one entry (`catalog::Catalog::audit`). `GET /api/v1/audit/verify` recomputes the chain. Each entry is also logged to the journal (`nexus-audit seq=… hash=…`, without details). Once per UTC day the scheduler appends `audit.anchor` (actor `scheduler`, target `audit/chain`, details `{head_seq, head_hash}` of the newest entry).

### Forwarding (Phase 14a)
Setting `forwarding` (`catalog::forwarding`): `{syslog: {enabled, host, port=6514, ca_pem?, pin_sha256?, app_name="nexus", facility=13}?, https: {enabled, url (https), headers {name: sealed value}, batch_max=100, ca_pem?, pin_sha256?}?}`. Header values are sealed to the scheduler at `settings/forwarding/https/<header>@<url>` and write-only (null in GET; null in PUT = keep, refused when the URL changes). TLS trust: `ca_pem` (CA → chain + host name verified; a certificate in it also counts as an exact pin), `pin_sha256` (SHA-256 of the leaf DER), neither = web PKI roots; no insecure mode. Weakening (an enabled sink disabled or removed; host/port/url, ca_pem, pin_sha256 or headers of an enabled sink changed) → quorum `settings.forwarding` (`{forwarding, old}`, executed by the web-api, refused when the setting changed since the request); anything else applies directly (audit `settings.forwarding`, headers null).

Scheduler thread `forward.rs` (every `forward_poll_secs`, default 5): per enabled sink, cursor row in `forward_state` (reset to 0/0 when `dest` changes, so a new destination gets the whole chain), up to 20 batches per round of audit entries `seq > audit_seq` first, then outbox events `seq > event_seq`; the cursor advances only after the batch was delivered (at least once, in order per stream, never skipped). Syslog: one TLS connection per batch (≤ 200 messages), RFC 5424 `<PRI>1 TIMESTAMP HOST APP - MSGID [nexus@32473 …] MSG` with RFC 5425 octet counting (`LEN SP MSG`), MSGID `audit` (SD `seq hash actor action target`), `alert` (`outbox_seq id event severity kind key tenant`), `job` (`outbox_seq id kind tenant state requested_by`), `test`; delivered = close_notify sent and the receiver closed without a reset. `32473` is the documentation PEN (RFC 5612), constant `catalog::forwarding::PEN`. HTTPS: POST of a JSON array (`{type: audit, seq, ts, actor, action, target, details, prev_hash, hash, host}`, `{type: alert|job, …payload, outbox_seq, event_ts, host[, alert_url]}`), 2xx = delivered. Failure: `last_error`, `failing_since` recorded, retry after 10 s doubling to 5 min; the tick raises `forwarding:<sink>` (warning, kind `forwarding`) after 15 min and resolves it once `failing_since` is cleared (delivered) or the sink is disabled. The allow-list gets every configured sink (syslog host:port, URL host:port). SELinux: `nexus_scheduler_t` may connect to `syslog_tls_port_t` (6514) besides http and unreserved ports. Job `forward_test` (appliance, in-process): one test record to every configured sink → `{syslog?, https?: "ok" | "error: …"}`.

## Roles (RBAC)
| Capability | admin | security_officer | operator | tenant_user | viewer (v15) |
|---|---|---|---|---|---|
| read everything (own tenant for tenant_user) | ✓ | ✓ | ✓ | own | snapshots, jobs, storage, dashboard, sources, groups, policies, agents, users, alerts (unscoped only): own tenant or all |
| sources, policies, groups, tenants, users CRUD | ✓ | — | — | — | — |
| run backups / restores / file restore (incl. `restore_files`) | ✓ | — | ✓ | own (restores only) | — (no job kind at all) |
| download restored files (`files_get`, `GET /downloads/…`): also needs `can_download` | ✓ | — | ✓ | own | — |
| agents CRUD, enrollment, `agent_update` | ✓ | — | — | — | — |
| replication peers / sources: create, key export request, revoke/delete, settings | ✓ | — | — | — | — |
| replication peers / sources: read; replication source "sync now" | ✓ | read | ✓ | — | — |
| approve/reject quorum requests (never own requests) | ✓ | ✓ | — | — | — |
| approvals setting: read / enable / request disabling | read, ✓ | read | read | — | — |
| confirm a large GC while approvals are disabled | ✓ | — | — | — | — |
| audit log, verify chain | ✓ | ✓ | — | — | — |
| dashboard KPIs (`GET /dashboard`) | ✓ | ✓ | ✓ | own tenant | own tenant or all |
| report CSV downloads (`GET /reports/{type}.csv`) | ✓ | ✓ | ✓ | own tenant | own tenant or all |
| scheduled reports: read / change, send now | read, ✓ | read | — | — | — |
| OIDC / alert delivery / security settings: read / change, test | read, ✓ | read | — | — | — |
| inbound firewall (16c, `GET /firewall`, `PUT /firewall/inbound/{service}`): read / request a change (quorum) | read, ✓ | read | — | — | — |
| appliance SSH keys: read / rotate (quorum), retire | read, ✓ | read | read | — | — |
| OS updates: read / check, apply (quorum) | read, ✓ | read | read | — | — |
| acknowledge the break-glass alert (other alerts: operator+) | ✓ | ✓ | — | — | — |
| legal hold (15c): set (one snapshot, a range, apply an advisory) / request a release | request release | set, request release | — | — | — |
| own sessions: list, end (`/auth/sessions`) | ✓ | ✓ | ✓ | ✓ | ✓ |
| all sessions: list, end one / a user's / all others (re-auth) | ✓ | — | — | — | — |
| console access (14c): request + show own code / list, revoke codes; acknowledge `console_*` alerts | ✓, ✓ | list, revoke; ack | — | — | — |

Viewers (Phase 14d) are read-only like a tenant user who cannot restore; with a tenant they see that tenant, without
one all tenants (an auditor or a wall display). They are deliberately kept out of the appliance-plane reads that
operators have (approvals, replication, plugin keys, SSH keys, updates, settings): those name every tenant, and a
viewer's purpose is the backup state, not the appliance's configuration.

**Quorum (four-eyes, optional — plan §2 "Approval system", user decision 2026-10-10)** — while approvals are **enabled** (`settings.approvals_enabled`), these never execute directly; they create a `quorum` row that a *different* user with role `admin` or `security_officer` (never the requester) must approve within 72 h: weakening a policy (any GFS value lowered, offsite disabled), deleting a group/source/tenant/policy/agent, deleting snapshots manually (`snapshot.delete`, executed by the scheduler), GC deleting > 20 % of chunks (raised by the scheduler), granting `admin`/`security_officer`, disabling a user who is the last admin/security_officer, a new activation code for an admin/security_officer; replication (docs/replication.md): creating a replication peer (`replication_peer.create`, exposes the tenants' data), exporting DEKs to a peer (`replication.key_export`, executed by the scheduler), revoking a peer, deleting an enrolled replication source, lowering a replication source's GFS; Phase 12: changing the OIDC settings (`oidc.update`: it changes who can log in), rotating an appliance SSH key (`ssh_key.rotate`, executed by the scheduler), applying an OS update now (`update.apply`); Phase 14d: longer session timeouts (`security.session`; shorter ones apply directly) and every change of the management allow-list (`security.mgmt_allow`; since Phase 16c `firewall.inbound`, below); Phase 16c: every change of an inbound firewall rule (`firewall.inbound`).

While approvals are **disabled**, the same requests execute directly and are audited under their action name with `"approvals": "disabled"` (answer 200 `{approvals: "disabled", executed: true, …}`; for actions the scheduler executes — the replication key export — an `approved` quorum row decided by the requester is created as the work item and the answer carries `executed: false, quorum_id, state: "approved"`). Retention locks, write-only secrets, re-authentication and every other protection are unaffected. A GC over the valve does not run silently: the scheduler records `settings.gc_confirm/<tenant>`, audits `gc.confirm_required` and raises a `gc_confirm` alert; an admin confirms it with `POST /gc/approve-large` (audited `gc.approve_large`), which queues a `gc` job `{approved: true, confirmed_by}` that the scheduler honours only while approvals are still disabled. The last enabled admin cannot be disabled or demoted at all.
- **Enabling** approvals: any admin, immediately (audit `approvals.enable`); refused (409) unless a second possible approver exists — otherwise nothing could ever be approved again.
- **Disabling**: quorum request `approvals.disable`, approved by one other admin or security officer (requester + 1); one pending request at a time.
- **Possible approvers** = enabled admins and security officers whose account is activated. With approvals enabled, a user change (disable, demote, new activation code — directly or on approval) that would leave fewer than two possible approvers is refused (409).
- **Default**: setup with an admin and a security officer → enabled; a single admin → disabled. Existing catalogs migrating to v9 → enabled.
- **Recommendation**: `GET /settings/approvals` returns `recommend: true` when approvals are disabled and at least two possible approvers exist; the dashboard shows a banner (dismissible per browser session) linking to the Approvals page.
- **Few approvers** (Phase 14d): `few_approvers: true` while approvals are enabled and fewer than three possible approvers (enabled, activated, unexpired admins and security officers) exist: one absence blocks every approval. Settings → Approvals and the dashboard (admin, security officer) warn. Way out when it happened: manual chapter 10 "When approvers are unavailable" (last step: `nexus-setup disable-approvals`, below).

## REST API (`/api/v1`, JSON)
Auth: `POST /auth/login {name, password, totp}` → `Set-Cookie: nx_session=…; HttpOnly; Secure; SameSite=Strict; Path=/` + body `{csrf, user}`. Every non-GET request needs header `X-CSRF-Token`. `POST /auth/logout`, `GET /auth/me` → `{user, csrf}` (lets the SPA recover its CSRF token after a reload; same-origin + SameSite=Strict keeps it from other sites). Sessions expire after 30 min idle / 12 h absolute by default (setting `session`, see "Access"). Login rate limit: 5 failures per user or IP per 15 min → 15 min lockout (audited).

| Method + path | Role | Notes |
|---|---|---|
| `GET /health` | none | `{ok}` |
| `GET /metrics` | bearer token from `/etc/nexus/metrics-token` | Prometheus text |
| `GET/POST /tenants`, `PUT/DELETE /tenants/{name}` | admin (DELETE → quorum) | |
| `GET/POST /sources`, `PUT/DELETE /sources/{id}` | admin (DELETE → quorum) | secrets write-only (never returned) |
| `GET/POST /policies`, `PUT/DELETE /policies/{id}` | admin (weakening PUT / DELETE → quorum) | |
| `GET/POST /groups`, `PUT/DELETE /groups/{id}` | admin (DELETE → quorum) | `timezone`; GET adds `paused_until`, `maintenance_until` (of the source), `blackout_active` |
| `POST /groups/{id}/pause {until?}`, `POST /groups/{id}/resume` | operator/admin | no approval, audited `group.pause` / `group.resume`; no `until` = indefinitely (-1); `until` within 366 days |
| `POST /sources/{id}/maintenance {until?}`, `POST /sources/{id}/maintenance/end` | operator/admin | as pause, for all groups of the source; audited `source.maintenance` / `source.maintenance_end` |
| `GET/POST /groups`, `PUT/DELETE /groups/{id}` | admin (DELETE → quorum) | v13: optional `mode` (`explicit` default, `all`, `tags`), `selector` (tags, 1..=50 for `tags`), `exclude` (guest ids); `all`/`tags` only for sources with an inventory (pve, truenas, plugin kinds that list guests) and without `guests` |
| `GET /sources/{id}/inventory` | any role, own tenant | v13: `{source_id, kind, inventory, refreshed, guests: [{guest, name, kind, tags, seen, gone, groups}]}`; refresh = job `inventory {source_id}` (admin, operator) |
| `GET/POST /users`, `PUT /users/{id}` | admin (privileged role grants → quorum) | POST `{name, role, tenant?}` (no password) returns a one-time activation code (see Self-enrollment); PUT: `password` / `reset_totp` for the own account, `new_activation: true` for other accounts, all with re-authentication (see Clarifications) |
| `POST /auth/activate/begin`, `POST /auth/activate/complete` | none (like login, no CSRF header) | Self-enrollment; rate-limited and audited like login |
| `GET /settings/approvals`, `PUT /settings/approvals {enabled}` | read: admin, security_officer, operator; PUT: admin | GET → `{enabled, possible_approvers, recommend, pending_disable}`; PUT enable → 200, disable → 202 `{quorum_id}` (`approvals.disable`), 409 when enabling without a second possible approver |
| `GET /gc/pending`, `POST /gc/approve-large {tenant}` | read: admin, security_officer, operator; POST: admin | approvals disabled only: GCs waiting for confirmation `[{tenant, job, reason, created}]`; confirming → 202 `{job_id}`, 409 when approvals are enabled or nothing is waiting |
| `GET /agents`, `POST /agents`, `DELETE /agents/{id}` | read / admin (DELETE → quorum) | POST `{tenant, name, host, port=7444}` → 201 agent + one-time `token` + `install_command` (shown once) |
| `POST /agents/{id}/token`, `POST /agents/{id}/enroll` | admin | new one-time token (200 `{token, install_command, token_expires}`); enroll → 202 `{id}` of an `agent_enroll` job, 409 without a valid token. On an enrolled agent this is the re-enrollment (same id; audit `agent.token` with `reenroll: true`) |
| `PUT /agents/{id}/limits` | admin | `{bwlimit (0 or ≥ 65536 bytes/s), nice (0..=19)}` → 200 agent; audit `agent.limits` (Phase 15f) |
| `GET /snapshots?tenant=&source=&held=` | read | local/offsite/lock/verified per snapshot; `hold`: the open legal hold (row of `GET /holds`) or null; `held=true`: only snapshots with one; v19: `consistency` (see Consistency) |
| `DELETE /snapshots/{tenant}/{source}/{time}` | admin | → quorum `snapshot.delete` (executed by the scheduler as job `snapshot_delete`, audit `snapshot.delete`); 409 while `lock_until` > now, when only the offsite copy is left, for a replicated snapshot (`origin` set) or under a legal hold |
| `POST /snapshots/{tenant}/{source}/{time}/hold {reason}`, `DELETE …/hold` | POST: security_officer; DELETE: security_officer, admin | legal hold (see "Legal hold"): POST holds at once (201 `{id, advisory_from?, primary_held_by?}`, audit `snapshot.hold`; applies an advisory; 404 no snapshot row, 409 already held); DELETE → quorum `snapshot.hold_release` (web-api execute arm; 404 not held, 409 a release is already requested) |
| `POST /holds {tenant, source?, from, to, reason}`, `GET /holds?tenant=&state=` | POST: security_officer; GET: read (tenant-scoped) | POST holds every snapshot row of the tenant (source) with `from ≤ time ≤ to` → `{held, snapshots}` (one audit `snapshot.hold` on `tenant/<t>` listing them); GET: holds and their history, newest first, with `release_quorum` (pending release request) |
| `GET /jobs?state=&kind=`, `GET /jobs/{id}` (incl. log) | read | `result` = structured job result (see Clarifications) |
| `POST /search {tenant, query, source?, from?, to?, case_sensitive?, limit?}` | admin, operator, tenant_user (own tenant) | 15g, docs/file-index.md: 202 `{id}` of a `file_search` job; query 1..=256 characters (glob, no wildcard = substring), `limit` 1..=2000 (default 500); audited `file.search` with the parameters; not for API tokens |
| `PUT /groups/{id}/index-files {enabled}` | admin | 15g: index the files in the VM/CT disks of a pve group after each backup (`groups.index_files`, v18; GET /groups rows carry `index_files`); 400 for other sources (their snapshots are always indexed); audited `group.index_files` |
| `POST /jobs` `{kind, tenant, params}` | per kind (see RBAC) | returns job id; 202. Restores with `replace: true` → quorum `restore.replace` instead (see Restore options) |
| `POST /restores` `{tenant, items: [{source, time}], node, storage, target_base, name_prefix?, pool?, start?, link_down?}` | admin, operator, tenant_user (own tenant); not for API tokens | 15a: one `restore` / `restore_ct` job per item (target `target_base + i`), all validated first, 1..=100 distinct guests; 202 `{ids}`; audited once `job.create_many` |
| `POST /jobs/{id}/cancel` | operator/admin | queued → `cancelled` at once; running → `{state: "cancelling"}`, sets `jobs.cancel_by` (the scheduler stops it, see Run control); 409 otherwise and for a running restore with `replace` (15a: it could be mid-swap) |
| `GET /downloads/{token}` | requester only | streams file, deleted after 24 h |
| `GET /quorum`, `POST /quorum/{id}/approve`, `POST /quorum/{id}/reject` | admin, security_officer (approve: not the requester) | approve → `{id, state}`, plus `activation` (part 2 of a split activation code) for a `user.update` that creates or resets a privileged account |
| `GET /audit?after=&before=&order=&limit=&actor=&action=&target=&from=&to=`, `GET /audit/verify` | admin, security_officer | oldest first after `after` (default); newest first with `before` or `order=desc`; filters (14a): `actor` exact, `action` prefix, `target` substring, `from`/`to` unix seconds inclusive, empty = any |
| `GET /alerts?state=open\|resolved\|all&id=&acked=`, `POST /alerts/{id}/ack`, `POST /alerts/{id}/resolve` | read / operator+ (`break_glass`: admin, security_officer) | 13f: rows carry `first_ts`, `last_ts`, `count`, `tenant`, `hint`, `resolved_*`, `note`, `auto`; ack/resolve take an optional `{note}`; resolve also acknowledges; both audited |
| `GET/POST /replication/peers`, `POST /replication/peers/{id}/export-keys`, `DELETE /replication/peers/{id}` | read / admin (POST, export, DELETE → quorum) | POST answers 202 `{quorum_id, peer, code}`: the enrollment code is shown once |
| `GET/POST /replication/sources`, `PUT/DELETE /replication/sources/{id}`, `POST /replication/sources/{id}/enroll`, `POST /replication/sources/{id}/sync` | read / admin (sync: operator too) | details in docs/replication.md §9 |
| `GET /plugins`, `POST /plugins`, `POST /plugins/{id}/enable`, `POST /plugins/{id}/disable`, `POST /plugins/{id}/activate`, `DELETE /plugins/{id}` | read: everyone / admin (upload, disable, activate, DELETE → quorum; enable direct) | upload: raw bundle (`application/octet-stream`, ≤ 128 MiB) + `X-Plugin-Signature` → 202 `{quorum_id, plugin, upgrade_from}`; DELETE 409 while sources of its kinds exist (docs/plugin-system.md) |
| `GET/POST /plugin-keys`, `DELETE /plugin-keys/{fingerprint}` | admin, security_officer, operator read / admin (POST, DELETE → quorum) | project keys (image) are listed `builtin` and cannot be removed |
| `GET /dashboard?days=7` or `30` | all (tenant users: own tenant) | Phase 12 KPIs (docs/phase12-contract.md §1), cached ≤ 60 s per scope; plus `break_glass` and `console_shell` (14c); `capacity.dedup` / `capacity.compression` from `backup_stats` |
| `GET /storage` | all (tenant users: own tenant) | storage accounting per tenant and group, growth 7/30/90 d (docs/storage-accounting.md) |
| `GET /reports/{protection,failed,sla,storage}.csv?from=&to=&tenant=` | all (also `viewer` once it exists; tenant users: own tenant, another `tenant` → 403) | Phase 14e, see Reports; `from` / `to` = `YYYY-MM-DD` (UTC, `to` inclusive) or unix seconds, default the last 7 days, at most 400 days; `text/csv; charset=utf-8`, `Content-Disposition: attachment; filename="nexus-<type>[-<tenant>]-<day>.csv"`; audited `report.export {type, from, to, tenant, rows}` |
| `GET` / `PUT /settings/reports`, `POST /settings/reports/{name}/send` | read: admin, security_officer; write, send: admin | setting `reports`: `{reports: [{name, types, schedule, timezone, recipients, tenant}]}`; GET adds `last` (latest `report_send` job) per report and `smtp` (server configured); PUT replaces the list (direct, audited `settings.reports`; non-empty list needs the SMTP server of `alerts`); send → 202 `{job_id}` (one period up to now), 409 while one is queued or running |
| `PUT /tenants/{name}/quota` `{quota_bytes}` | admin | soft quota (null = none); direct, audited `tenant.quota` |
| `GET /console/unlock`, `POST /console/unlock` `{hours 1..8, reason}`, `POST /console/unlock/{id}/code`, `DELETE /console/unlock/{id}` | read + revoke: admin, security_officer; request + code: admin (code: the requester only); appliance-wide accounts only | 14c, see "Console root shell": POST → quorum `console.unlock` (approved, never executed by anyone); `/code` shows the code once (`console.unlock_code`, critical alert `console_unlock`), 409 when pending, already shown, revoked or > 24 h after the approval; DELETE revokes an approved or shown code (`console.unlock_revoke`). List rows: `{id, hours, reason, requested_by, created, decided_by, decided_at, code_expires, status}` with status `pending/rejected/expired/approved/issued/used/revoked` |
| `GET` / `PUT /settings/anomaly` | read: admin, security_officer; write: admin | anomaly thresholds; weakening is gated (`settings.anomaly`) |
| `GET` / `PUT /settings/forwarding`, `POST /settings/forwarding/test` | read: admin, security_officer; write / test: admin | syslog / HTTPS sinks (see Audit log → Forwarding); weakening is gated (`settings.forwarding`); test = job `forward_test`, waits ≤ 45 s (else 202 `{job_id}`) |
| `GET /audit/forwarding` | admin, security_officer | `{head_seq, sinks: [{sink, dest, enabled, audit_seq, event_seq, last_ok, last_error, last_error_ts, failing_since}]}` per configured sink |
| `GET /audit.csv?actor=&action=&target=&from=&to=&after=&before=` | admin, security_officer | the filtered entries oldest first, streamed in pages of 1000, columns `seq,ts,actor,action,target,details,prev_hash,hash` (RFC 4180 quoting, values unchanged); audited `audit.export` with the filters; `order`/`limit` → 400 |
| `GET /auth/oidc`, `GET /auth/oidc/start?next=`, `GET /auth/oidc/callback` | none | OIDC sign-in (§2, see Clarifications) |
| `GET/PUT /settings/oidc`, `POST /settings/oidc/test` | read: admin, security_officer / admin (PUT → quorum `oidc.update`) | client secret write-only (`client_secret_set`); GET adds `redirect_uri` to register at the IdP; test → `{discovery, jwks}` |
| `GET/PUT /settings/alerts`, `POST /settings/alerts/test` | read: admin, security_officer / admin | §3, 13f: `{smtp, rules: [{name, min_severity, kinds, tenants, channels: {email, webhook: {url, headers, template}}}], reminder_hours, retention_days}` (settings `alerts`, `alert_rules`, `alert_reminder_hours`, `alert_retention_days`); the pre-13f body `{webhook_url, smtp.to, min_severity}` is still accepted as one rule `default`; SMTP password and header values write-only, sealed to the scheduler; templates must render to JSON; test `{rule?}` → `{webhook?, email?}` for one rule, `{"<rule>/<channel>": …}` for all (scheduler job `alert_test`; 202 `{job_id}` if it takes over 45 s) |
| `GET /ssh-keys`, `POST /ssh-keys/{name}/rotate`, `POST /ssh-keys/{name}/retire` | admin, operator, security_officer read / admin (rotate → quorum `ssh_key.rotate`) | §4; only key files below `/etc/nexus/ssh` that PVE node or SFTP offsite configurations use; after a rotation the entry shows the new key and the old one as `previous` (still in use) until retire → 202 `{job_id}` (`ssh_key_retire`); 409 without a rotation |
| `GET /updates`, `POST /updates/check`, `POST /updates/apply` | admin, security_officer, operator read / admin (apply → quorum `update.apply`) | §5; check/apply write the request file for `nexus-update.path` (apply = install now: stage if needed, reboot outside the window); status `checking` while a request waits, `blocked` (+ `blocked: [check]`) when failed pre-update checks refused the last stage/apply (docs/release.md) |
| `GET/PUT/DELETE /updates/registry` | admin, security_officer, operator read / admin write | pull credential for a private image repository: `{username, token}` stored as `<update dir>/pull-auth.json` (0600); GET returns only `{configured, username}`; `nexus-update` writes `/run/ostree/auth.json` only during a fetch and removes it; audited `update.registry_auth` / `update.registry_auth_removed` |
| `GET /diagnostics`, `GET /diagnostics/{id}`, `POST /diagnostics/checks`, `POST /diagnostics/bundle {since?, until?}`, `GET /diagnostics/{id}/download` | admin, security_officer (not tenant-scoped); bundle + download: admin | 14b: POST writes `request.json` `{id, kind, by, since, until}` into `/var/lib/nexus/diag` for `nexus-diag.path` (one at a time: 409 while a request younger than 10 min waits), 202 `{id, state: "queued"}`, audited `diag.checks` / `diag.bundle`; results `{id, kind, by, state queued\|running\|done\|error, since, until, created, finished, error, expires, checks: [{id, title, status pass\|warn\|fail\|skip, severity 1–4, detail, manual}], bundle: {bytes, url}}`; a bundle is visible to and downloadable by its requester only, for 24 h (`download.get`, target `diag/<id>`); range ≤ 31 days, default the last 24 h |
| `GET /hardware`, `POST /hardware/scan`, `POST /hardware/selftest {disk, type}`, `POST /hardware/arrays {role, level, disks, confirm}`, `POST /hardware/arrays/{md}/spare\|replace\|grow {disk, failed?, confirm}` | GET: admin, security_officer, operator, viewer (not tenant-scoped; API tokens with read scope); scan: admin, operator; the rest: admin | Phase 16 (docs/hardware.md): the status of `nexus-disks` with issues and a summary, recent operations (queued requests included); scan / self-test write `req-<id>.json` into `/var/lib/nexus/disks` (202 `{id, state: "queued"}`, audited `hardware.scan` / `hardware.selftest`); layout requests need the typed serial numbers (`confirm`) and go through approval (`disks.create_array`, `disks.add_spare`, `disks.replace`, `disks.grow`), checked against the status (empty disks, size, no system arrays, store empty for create); the request file is written on approval |

Peer API `/replication/v1/*` (not under `/api/v1`): only on TLS connections with the replication ALPN and an enrolled client certificate (docs/replication.md §3, §6).

Errors: `{error: "message"}` with 400/401/403/404/409/429, and 503 for secret writes while the scheduler's public key is missing. Quorum-gated requests answer **202** `{quorum_id}` while approvals are enabled, otherwise 200 `{approvals: "disabled", executed, …}` (see Quorum).

Headers on every response: `Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Strict-Transport-Security: max-age=31536000`. The SPA is served from `/` (index.html fallback for client routes), assets from `/assets/*` (embedded at build time from `web/dist`).

### Clarifications (web-api v1)
- `/health` and `/metrics` answer under `/api/v1/` and at the root. `/metrics` series: `nexus_jobs{state}`, `nexus_snapshots{tenant,location=local|offsite}`, `nexus_last_successful_backup_timestamp_seconds{tenant,group}` (max `finished` of `ok` backup jobs whose params carry that `group_id`, 0 = never — so the scheduler queues scheduled backups as `{group_id}`), `nexus_failed_logins_total`, `nexus_audit_entries`, `nexus_quorum_pending`.
- `POST /auth/login` is the only non-GET without `X-CSRF-Token` (no session yet); all JSON bodies require `Content-Type: application/json`, unknown fields are rejected.
- Names (`[A-Za-z0-9._-]{1,64}`) must not start with a dot (threat model T11). Opaque JSON blobs (`tenants.offsite`, `sources.config.nodes`) must not contain inline secrets (keys containing `secret`/`password`/`passphrase`/`private` are refused) — secrets live in files referenced by path; the only inline secret is `token_secret`, which is never returned (`token_secret_set: bool` instead; omitted on PUT = keep).
- File restore: the web-api adds `download_token` (64 hex) to `files_get` params and returns it in the 202 body; the scheduler writes `/var/lib/nexus/downloads/<token>.<format>` (`format` = `tar`|`zip`). `GET /downloads/{token}` serves it only to the job's `requested_by`, only if younger than 24 h; the scheduler deletes it.
- Quorum execution: on approval the web-api itself applies `tenant.delete`, `source.delete`, `policy.delete`, `policy.update`, `group.delete`, `group.update`, `user.update`, `approvals.disable` (state → `executed`). Any other action (e.g. `gc` raised by the scheduler with `requested_by = "scheduler"`) only becomes `approved`; the scheduler executes it and sets `executed`. Pending requests older than 72 h become `expired` (audited).
- Also quorum-gated: moving a group to a policy that is weaker in any dimension (`group.update`); creating an admin/security_officer (account is created *disabled*, the quorum request enables it); re-enabling such an account; demoting as well as disabling the last enabled admin/security_officer; a new activation code for another admin/security_officer. Quorum params never expose password hashes, TOTP secrets or activation code digests (`<redacted>`).
- Self-enrollment (plan §2 "User onboarding", user decision 2026-10-10; `crates/web-api/src/activation.rs`): the admin never sets or learns another user's credentials.
  - `POST /users` creates the account *pending activation* (no usable password, no TOTP seed) and answers `activation: {name, code, part, parts, expires, path}` once: `code` = 128 bit base32 (26 characters; case, spaces and dashes are ignored), valid 72 h, stored as SHA-256 digest; `path` = `/#/activate?name=<name>` (the code never goes into a URL).
  - The person opens the login page → "Activate account": `POST /auth/activate/begin {name, code}` → `{name, totp_uri, totp_secret}` (a fresh seed, stored encrypted, shown only here); `POST /auth/activate/complete {name, code, password, totp}` sets the password (min. 12 characters), proves the authenticator (the TOTP step is consumed) and clears the activation in one conditional update — the code is used up. Failures (unknown name, wrong/expired code, disabled account, wrong TOTP, replay) answer the same 401, are audited `auth.activate_failed` and count toward the login rate limiter per user and per IP (lockout → 429). Success is audited `user.activation_begin` / `user.activate`.
  - **Privileged accounts with approvals enabled (split code):** creating an admin/security_officer or issuing a new code for one goes through quorum. The requesting admin receives **part 1** at request time (`parts: 2`, `expires: null`); the **approver** receives **part 2** in the approve answer (validity 72 h from approval). The new user enters both parts one after the other. Neither the requesting admin nor the approver alone can activate the account, so the requester cannot create a sock-puppet approver. Old credentials of a reset privileged account stay valid until the approval. With approvals enabled, an account still waiting for activation with a code one admin knows in full cannot be promoted to or re-enabled as admin/security_officer (409): it must be activated by its owner first.
  - With approvals disabled, privileged accounts are created directly and the admin receives the whole code (single administrator; see the accepted residual in docs/threat-model.md T2).
  - `PUT /users/{id} {new_activation: true}` (another account only, with re-authentication): old password and TOTP stop working immediately (direct path) and the account is pending again with a new code. `password` / `reset_totp` change only the acting user's own credentials.
  - The user list shows `pending_activation` and `activation_expires` (null while part 2 is not issued).
- Re-authentication (review M-5): `PUT /users/{id}` with `password` or `reset_totp: true` (own account) or `new_activation: true` (another user's) must also carry `current_password` and `current_totp` of the *acting* user.
  - Missing fields → 400.
  - Wrong password or code, or a replayed code (the TOTP step is consumed as at login) → 403, audited as `auth.reauth_failed` (actor = acting user, details `reason`, `for`).
  - Failures count toward the login rate limiter (per user and per IP). A lockout answers 429 and also blocks login.
- Job results (`jobs.result`, written by the scheduler when a job finishes `ok`, returned as `result` by `GET /jobs` and `GET /jobs/{id}`): `files_list` → `{"entries": [{name, kind, size, mtime, mode?, link?}, …]}` (the JSON `nexus-pve … ls` prints); `files_get` → `{"download_token", "format", "entries": n, "size": bytes, "expires": unix}`; `backup` → `{"snapshots": [{"source", "time"}, …]}` plus top-level `source`/`time` when exactly one guest was committed; `file_search` → `{"matches": [{source, path, kind, size, mtime, times}], scanned, unindexed, truncated, elapsed_ms}`; `file_index` → `{built, skipped}` (backfill) or `{entries, complete}` (VM/CT). Other kinds: `null`.
- Audit paging: `GET /audit?after=<seq>` returns entries with `seq > after` oldest first; `?order=desc` (no cursor) starts at the newest entry, `?before=<seq>` returns `seq < before` newest first (pages backwards; `order=asc` with `before` is 400). `limit` defaults to 500, max 1000.
- Agents (docs/agent-protocol.md): `GET /agents` never returns the token digest; the token (128 bit, base32, 26 characters, 24 h) appears only in the answer of `POST /agents` / `POST /agents/{id}/token` (install command `/usr/local/sbin/nexus-agent init --token <T>`: full path, as `/usr/local/sbin` is not in sudo's `secure_path` on EL/Fedora) and is stored as its digest sealed to the scheduler (503 while `secrets.pub` is missing). Audit: `agent.create`, `agent.token`, `agent.delete` (quorum), `agent.enrolled` (scheduler). An agent used by a linux source cannot be deleted (409); a tenant with agents cannot be deleted. A linux source's `agent_id` must be an agent of the same tenant; `paths` 1..=64 absolute paths without `.`/`..`, `excludes` ≤ 256 patterns. `restore_files`: `confirm` must equal the target agent's name (400 otherwise; the agent journals it); the web-api adds `agent_id` (default for `host-` snapshots: the snapshot's agent; required for every other source, 400 otherwise). Source and target agent must belong to the job's tenant (snapshot lookup and agent lookup are both tenant-scoped; the scheduler checks the agent's tenant again); plugin snapshots only if the plugin offers `download`. `agent_update` / `agent_enroll` are admin-only job kinds. Job results: agent `backup` → `{snapshots, source, time, consistent, transferred_bytes}`, `restore_files` → `{target, files, dirs, bytes, errors}`, `agent_enroll` → `{agent_id, cert_sha256, appliance_id}`.
- Tenant offsite (docs/s3-offsite.md): an S3 remote is validated strictly (unknown fields refused; `https://host[:port]` only; bucket/region/prefix syntax; `ca_pem` certificates only; no `GLACIER`/`DEEP_ARCHIVE` storage class). Its `secret_key` is the one inline secret allowed in `tenants.offsite`: required on create, sealed to the scheduler (503 while `secrets.pub` is missing), never returned (`secret_key_set: true`), omitted on PUT = keep, refused when endpoint, region, bucket, access_key, path_style or ca_pem change. Quorum lists and audit entries redact sealed secrets (`<redacted>`) at any depth.
- TrueNAS sources (docs/truenas-connector.md): `token_secret` (API key) and `ssh.key_pem` are write-only and sealed (`token_secret_set`, `ssh.key_pem_set` instead); omitted on PUT = keep, refused when the endpoint fields they are bound to change. GET adds `authorized_keys`: the line (with the forced command) to paste into the TrueNAS user's "SSH public key" field. Datasets: 1..=64 non-overlapping names of `[A-Za-z0-9_-]` components. Groups of a TrueNAS source list datasets of that source as guests (empty = all). Backup results carry `transferred_bytes` per `nas-` snapshot.
- NFS/SMB sources (docs/nas-connector.md): one share per source. The config is validated with the mount helper's own request checks (host name/IP, export path, share name, user, domain, versions, `seal` needs SMB 3; no option separators or control characters anywhere). SMB `password` (or `keytab` as base64 with `sec: "krb5"` + `principal`) is write-only and sealed (`password_set`, `keytab_set`); omitted on PUT = keep, refused when `host`, `port`, `user`, `sec` or `principal` change. Groups of a share source have no guests. Backup results carry `consistent` (NAS snapshot used, no file changed while read, nothing unreadable) and `transferred_bytes` for the `share-` snapshot.
- OIDC (Phase 12, docs/phase12-contract.md §2, `crates/web-api/src/oidc.rs`): authorization code + PKCE S256, `state` (one use, ≤ 10 min, in memory) bound to the browser by the HttpOnly cookie `nx_oidc` (SameSite=Lax, Path `/api/v1/auth/oidc`), `nonce`. Discovery `<issuer>/.well-known/openid-configuration` (its `issuer` must equal the configured one; endpoints https, http only for loopback issuers), JWKS cached 1 h and fetched again on an unknown `kid` (forced fetches at most every 10 s). ID token: RS256 / ES256 / PS256 only (`none` and HMAC refused before any key lookup), `iss`, `aud` (several audiences need `azp` = client id), `exp` / `iat` / `nbf` with 60 s skew, `nonce`, `sub`. Claims from the ID token only: `username_claim` (taken as it is, may contain `@`; ≤ 128 printable characters without whitespace), `groups_claim` (array or string; a leading `/` of Keycloak full paths is ignored). Mapping: the highest privileged matching mapping wins (admin > security_officer > operator > tenant_user; unscoped before scoped, then configured order); `tenants` holds one tenant for tenant_user mappings and none for every other role (an account has one tenant or all); default scopes `openid profile email`. Account per `<issuer>|<sub>`: created on first login (`user.oidc_created`), role/tenant refreshed at every login (`user.oidc_updated`); no matching mapping → disabled + sessions ended + denied; a disabled OIDC account is refused (`account_disabled`) and stays disabled until an admin enables it; a name that exists already (local account or another subject) is refused (`denied`, reason `name_conflict`), never taken over. OIDC accounts cannot log in locally, have no password/TOTP (re-authentication, which needs them, is refused for them), and their role/tenant/credentials cannot be changed through `PUT /users` (only `disabled`). Errors → 302 `/#/login?oidc_error=<code>`: `disabled` (single sign-on off), `account_disabled` (the account was disabled by an admin or by a login without matching mapping; only an admin re-enables it), `expired` (pending login older than 10 min), `state` (unknown/used state, or not started in this browser), `idp` (IdP error, discovery failure), `token` (token request or ID token refused), `denied` (no mapping, name conflict, unusable name, rate limit); every refusal is audited `auth.oidc_denied` with the detailed reason and counts toward the per-address login rate limiter. Redirect URI = `https://<Host>/api/v1/auth/oidc/callback` (the IdP compares it with its registration); `next` must be a same-origin path, a fragment allowed (`/`, `/#/jobs`; not `//…` or `/\…`), else `/`.
- Appliance jobs (Phase 12) carry tenant `-` and are queued by the settings endpoints only (`POST /jobs` refuses them): `alert_test` → result `{webhook?, smtp?}` (`"ok"` / `"error: …"`), `ssh_key_rotate` {name, quorum_id} → `{name, next}`, `ssh_key_retire` {name} → `{name, old, new}`, `report_send` {name, from, to} → `{name, types, tenant, recipients, from, to, attachments, rows}` (Phase 14e). Tenant users never see them.
- Break-glass (§7): `nexus-setup recover-admin` raises the alert `break_glass` (critical) and writes `settings.break_glass`; the UI shows its banner while that alert is unacknowledged. `GET /auth/me` and `GET /dashboard` additionally return `break_glass: {at, user, alert, forced_solo}` (admin, security_officer, operator). Only an admin or security officer can acknowledge that alert (`POST /alerts/{id}/ack`, which also removes the setting).
- `GET /quorum` is readable by admin, security_officer and operator. Tenant-scoped users (`users.tenant` set) see only their tenant's rows in every list (`users` included); most alerts have no tenant and may name other tenants, so they get an empty alert list.

## API tokens (Phase 14d, `crates/web-api/src/tokens.rs`, catalog v15)
- Format `nxt_<prefix>_<secret>`: prefix 8 hex (finds the row), secret 256 bit hex. `api_tokens.hash` = SHA-256 of
  the secret: the secret is random and long, so a fast hash suffices (no KDF); the secret is returned once, by
  `POST /auth/tokens`, and never stored. `expires` is mandatory (1–365 days); the owner (`user_id`, ON DELETE
  CASCADE), `scope` (`read` | `operator`), `last_used` / `last_ip` (written at most once a minute).
- `Authorization: Bearer nxt_…` is handled by a middleware in front of the router (other bearer tokens, e.g. the
  metrics token, pass untouched). Valid = known prefix, constant-time hash match, not expired, user enabled and not
  pending activation. It then puts `TokenAuth` (user with capped role + token) into the request; `Ctx` uses it
  instead of the cookie (no session, **no CSRF header**: a browser never adds this header by itself).
- Effective role: `operator` scope → admin/operator users act as `operator`, tenant users stay `tenant_user`;
  `read` scope (and any security officer token) keeps the user's role but only GET. Default deny: only the routes
  on the token allow-list are reachable (`tokens::READ` for GET, `tokens::OPERATE` for POST with operator scope:
  `/jobs`, `/jobs/{id}/cancel`, group pause/resume, source maintenance, alert ack, replication sync); everything
  else answers 403 "API tokens cannot use this endpoint". Never on the list: approvals, settings, users, tokens,
  plugins and keys, certificate, downloads, replication keys/peers, updates, deletes, login/logout. `POST /jobs`
  also refuses `files_get` and `plugin_mount` for tokens.
- Audit: `AppState::audit` records the actor as `<user> via token <name>` during a token request (task-local);
  `jobs.requested_by` and quorum `requested_by` stay the plain user name (four-eyes comparisons).
- `GET /auth/tokens` own (`?all=true`: admin, all users), `POST /auth/tokens {name, scope, days, current_password,
  current_totp}` (re-authentication like a password change; OIDC accounts instead need a session ≤ 15 min old;
  at most 20 per user) → 201 with `token`, `DELETE /auth/tokens/{id}` own or (admin) any. Audited `token.create`,
  `token.revoke`.

## Web certificate (Phase 14d, crate `webtls`, `crates/web-api/src/certs.rs`)
- `/etc/nexus/tls/cert.pem` + `key.pem`: the self-signed **identity** from nexus-setup. Replication secondaries pin
  its SHA-256 (`replication_sources.cert_pin`), and connections with a replication ALPN always get it.
- `/etc/nexus/tls/web.pem`: an imported chain + its key in one file (one rename swaps both), served to every other
  connection by `tls::WebCert` (rustls `ResolvesServerCert`: one `stat` per handshake, reload on mtime/size/inode
  change, a broken file keeps the current certificate, missing file = identity). HTTP/2 ALPN unchanged. So an
  import breaks no pin; agents never see this certificate (they verify the appliance's agent-CA client cert).
- `nexus-tls` handles `request.json` (`{id, op: csr|install|revert, …}`, written by the web-api with a temp file +
  rename) and answers in `result.json`; the web-api waits up to 30 s (503 otherwise). `csr {cn, sans}`: new P-256
  key into `pending/key.pem` (0600 root, SELinux `nexus_tls_pending_t`; never leaves the helper), CSR returned and
  kept as `csr.pem` + `pending.json` for the UI. `install {chain_pem}`: `webtls::validate` (leaf key = pending
  key, leaf first and each certificate signed by the next, intermediates are CAs, all valid now, leaf not a CA,
  EKU serverAuth and KU digitalSignature if present, SANs cover every requested name, wildcards one label), then
  `web.pem.prev` = old `web.pem`, `web.pem` written atomically (0640 root:nexus-webapi). `revert` swaps `web.pem`
  and `web.pem.prev` (no previous = remove, i.e. back to the identity).
- `GET /certificate` (admin, security_officer): active, chain (subject, issuer, SANs, validity, SHA-256), identity,
  pending CSR, pins. `POST /certificate/csr|install|revert` (admin), audited `tls.csr`, `tls.install`,
  `tls.revert`. The web-api publishes `{web, identity}` dates to the setting `tls_status` (start, hourly, after a
  change) for the scheduler's expiry alerts.

## Expiry alerts (Phase 14d, `crates/scheduler/src/expiry.rs`)
With every full refresh (15 min): kind `cert_expiry`, key `cert_expiry:<what>` (`web`, `identity`, `agent:<id>`,
`agent_ca`, `replication_peer:<id>`, `oidc_secret`, `token:<id>`); info ≤ 90 days, warning ≤ 30, critical ≤ 7 or
expired; raised once per level (escalated in place), resolved when no longer due. Agent and peer certificates are
not stored (only fingerprints): their dates are enrollment + 10 years (agent-conn / replication `ca.rs`; agents: `agents.cert_expires` once a session reported it, Phase 15f); the agent
CA's first enrollment is remembered in the setting `agent_ca_created`. The IdP secret date is the optional
`settings.oidc.client_secret_expires`. Tokens: info during their last 7 days.

## Scheduler
Inventory (Phase 13c, `crates/scheduler/src/inventory.rs`): every tick, a source of kind pve / truenas / plugin
(enabled plugin whose kind lists guests; not in replicated tenants) whose last `inventory` or `plugin_guests` job is
older than `inventory_secs` (default 3600, 0 = off) gets an `inventory` job (key `inventory:<source>`, so it never
waits behind a backup): pve `nexus-pve <cfg> inventory` (`/cluster/resources?type=vm`, templates left out), truenas
the configured datasets (in process, no NAS call), plugins the host's `guests` op (v1.5 `TaggedGuests`). The result
replaces the source's `inventory` rows (`gone` set, rows kept; audit `inventory.update` with added/gone); guests an
`all`/`tags` group newly selects are audited as `group.auto_protect`. A failed listing keeps the last inventory and
raises one `inventory_refresh` warning per source while it is open. An `all`/`tags` group that resolves to nothing has
nothing to back up (never "the whole plugin source").

Tick every 30 s: (1) queue `backup` jobs for groups whose policy schedule is due (once per period); after each successful backup: `retention` for that source, then `offsite` if the policy says so; (2) run queued jobs FIFO, at most one per source at a time, by spawning `nexus-pve` / `nexus-offsite` / `nexus-agentctl` / `nexus-truenas` / `nexus-nas` with a generated config (0600, in a private runtime dir) and capturing output into `jobs.log`; (3) refresh `snapshots`; (4) daily `gc` + `verify` + `file_index` (name index backfill, docs/file-index.md); the `gc` job first prunes *orphaned* sources (in the tenant's store but in none of its groups) with the GFS of setting `orphan_gfs` (JSON like `policies.gfs`, default 14/4/6/2), raises an `orphaned` info alert once per source and audits `retention.orphans` when it deleted something (not for replicated tenants: they follow the replication source's GFS); a GC that needs quorum raises a `quorum` request and an alert (approvals disabled: a `gc_confirm/<tenant>` setting and a `gc_confirm` alert instead, see Quorum); (5) alerts: failed job, offsite lag > 48 h, verify failure, inventory anomaly, capacity > 75 %, agent or share backup without a consistent view (`backup_inconsistent`, warning). Agent jobs are exclusive per agent (`agent:<id>`); agent backups are refused before they start if the agent is not enrolled; `agent-info`/`enrolled` lines of `nexus-agentctl` update `agents` (last_seen, version, os; fingerprint, token cleared). The firewall allow-list includes every agent's host:port, the API (`connect_addr`, else host:port) and SSH endpoint of every TrueNAS source, and each tenant's offsite endpoint (SFTP host:port; S3 endpoint host:port, `<bucket>.<host>` for virtual-hosted style). Offsite jobs get the S3 secret key and CA as 0600 files in the job dir (`secret_key_file`, `ca_file`). TrueNAS backups are exclusive per source; the job dir gets the pinned certificate, API key, SSH key and a `known_hosts` built from the pinned host key (0600); retention after a TrueNAS backup covers each dataset of the group and its child datasets (`nas-<id>-<pool.ds>` and the prefix `nas-<id>-<pool.ds>.`). Share backups (`nexus-nas <job>/nas.json backup`) are exclusive per source; the SMB password/keytab goes into a 0600 job file, the connector gets the mount from `nexus-nasmount` (socket `nas_mount_socket`); the allow-list gets the NFS port (and mountd for NFSv3) resp. the SMB port of every share source; retention covers `share-<id>`. Alert lifecycle (13f, `scheduler/src/lifecycle.rs`): alerts are raised under a key; a repeat while open bumps `count`/`last_ts` (latest message kept), a higher severity is delivered again, open unacknowledged alerts are re-delivered after `alert_reminder_hours` (default 24, 0 = never); success paths resolve their key (`auto`, audited `alert.resolve`): job ok → `job_failed:<tenant>/<kind>/<group|source|agent|replication_source|vmid>[/<guest>]`, verify ok → `verify:<tenant>`, offsite ok → `inventory:<tenant>`, offsite caught up → `offsite_lag:<tenant>`, store under the threshold → `capacity`, `gc_large` approved / approved GC ok → `gc_quorum:<tenant>` / `gc_confirm:<tenant>`, sync ok → `replication_lag:<source>:<tenant>`; resolved alerts are pruned per severity (`alert_retention_days`, default info 14, warning/critical 180). Delivery (`notified_ts` NULL or reminder due): notification rules from `settings.alert_rules` (else the pre-13f `alerts` setting as one rule) route by min severity, kinds and tenants to e-mail recipients (one SMTP server, setting `alerts`) and webhooks (default payload `{id, ts, first_ts, last_ts, count, severity, kind, message, hint, tenant, host, alert_url}` or a `{{field}}` template rendered with JSON-string escaping; sealed headers); test alerts go through every rule; else `/etc/nexus/alerts.json` (fallback, one rule; the allow-list follows whichever is in use, every rule's webhook host included). Phase 12: every full refresh writes the store file system's figures (`settings.capacity`) and, once per tenant and day, a `capacity_samples` row (bytes below the tenant's store, sum of its local snapshot sizes); the allow-list also gets the OIDC issuer and the token/JWKS hosts of the last discovery; at start and every full refresh the scheduler publishes the public halves of the SSH keys the configuration uses (`settings.ssh_keys`: PVE `nodes.*.key` and SFTP `remote.key_file` paths directly below `/etc/nexus/ssh`; a hand-placed private key gets its `.pub`); approved `snapshot.delete` requests become `snapshot_delete` jobs (`{source, time, quorum_id}`, refused by the store while locked); approved `ssh_key.rotate` requests become `ssh_key_rotate` jobs (a new ed25519 key `<name>.next` in OpenSSH format, the old key stays in use), `ssh_key_retire` renames the new key over the old one (requests decided by their own requester only while approvals are still disabled).

Replication (docs/replication.md): on the primary the scheduler executes approved `replication.key_export` requests (keyd `export-for`, blob into `replication_peers.key_exports`, quorum → `executed`); a request decided by its own requester (recorded that way while approvals are disabled) is executed only while approvals are still disabled. On the secondary it queues `replica_sync` per enrolled replication source and tenant on the source's schedule (exclusive per tenant, `tenant:<t>`), spawns `nexus-replica` (`enrolled` / `replicated` / `key-mismatch` / `verify-failed` lines update `replication_sources` and raise `replication_keys` / `replication_verify` alerts), raises `replication_lag` (no successful sync for 48 h), adds every primary's `host:port` to the firewall allow-list, never asks keyd to `ensure` a replicated tenant, and refuses backups into replicated tenants. File restores of replicated VM/CT snapshots without a local PVE source use a store-only `nexus-pve` configuration.

## Restore to a host (Phase 15b, `crates/scheduler/src/restore_files.rs`)
`restore_files` puts files of any file snapshot of a tenant onto a path of an enrolled agent of the same tenant
(plan key `agent:<id>`; RBAC as for the other restores: admin, operator, tenant_user in its tenant; never viewer,
security officer; audited `job.create`, the agent journals the typed
confirmation). Sources:
- file trees (`host-`, `nas-`, `share-`, `plugin-`): one step `nexus-agentctl <cfg> restore` (config `restore.source`)
  reads the tree from the store (plugin snapshots with their streams below `.nexus-streams/`, the file browser's view)
  and streams it to the agent;
- `vm-<id>` / `ct-<id>`: step 1 `nexus-pve <cfg> files|ct-files <vmid> <time> get <downloads>/restore-<job>-<rand>.tar
  <paths>` (restore micro-VM, resp. the CT tar stream; same sanitising as downloads), step 2 `nexus-agentctl restore`
  with `restore.tar` = that file (bridged into restore entries, then removed; `Plan::download` removes it if the job
  fails). The staging name is no download token, so `GET /downloads/{token}` never serves it; expiry of the
  downloads directory removes leftovers after `download_ttl_secs`. No new SELinux rules: `nexus_pve_t` and
  `nexus_agentctl_t` both manage `nexus_downloads_t` files already.
Metadata onto another host than the snapshot's own (docs/agent-protocol.md "Restore to another host"): owners are not
mapped, setuid/setgid/sticky cleared, devices/sockets skipped, only xattrs the target can store.

## Run control (Phase 13b)
- **Schedules** (`catalog::schedule`, shared by web-api validation and scheduler): evaluated in the group's
  `timezone` (chrono-tz). DST: a slot in the spring-forward gap runs after it with the pre-gap offset (02:30 → 03:30),
  a slot in the repeated hour runs at its first occurrence. Due = the latest slot ≤ now is newer than the last
  scheduled job of the group (one catch-up run). Replication sources and daily maintenance stay UTC.
- **Hold**: `queue_scheduled` starts no run while the group is paused, its source in maintenance or a blackout window
  of the policy is active; the missed slot runs once afterwards. The scheduler raises `paused` (warning, once per
  pause) for pauses / maintenance > 7 days or indefinite.
- **Retries**: a failed `backup` with `group_id` (scheduled or manual) with `attempt < 1 + retry.count` and the group
  not paused gets a new queued job: params + `guests` = the group's guests without a `committed <source>/…` line in
  the log (unknown → the job's params unchanged), `not_before = now + delay_min`, `attempt + 1`, `retry_of` = first
  job; audited `job.retry`; `start_jobs` skips jobs whose `not_before` is in the future. `job_failed` only after the
  last attempt ("failed after N attempts"). The planner restricts a group to `params.guests`.
- **Blackout abort**: every tick, running group backups whose policy has an `abort` window that began after the
  job's `started` get `cancel_by = 'blackout'` (audited `job.cancel`, actor scheduler).
- **SLA**: running group backups older than `sla_minutes` raise `sla_missed` (warning) once (`jobs.sla_alerted`).
- **Cancel**: every poll (2 s) the scheduler reads running jobs with `cancel_by`; the worker's registry
  (`run::Cancels`) marks the job and sends SIGTERM to the connector's process group (CLIs run with
  `process_group(0)`), SIGKILL after `cancel_grace_secs` (30). Before the next step and after a CLI exits the worker
  checks the mark → outcome `Cancelled`, state `cancelled`, no alert, no retry, no follow-up. A connector that printed
  `upid: <UPID>` (nexus-pve for vzdump and restores) gets `<bin> <config> task-stop <UPID>` afterwards
  (`DELETE /nodes/{node}/tasks/{upid}`, skipped if the task already ended). No partial snapshot: chunk store
  `commit_snapshot` writes the indexes first and the manifest last (atomic rename), snapshots without a manifest are
  not listed, and unreferenced chunks go with the next GC after its grace period. In-process steps (retention, GC,
  verify) are not interrupted.

## Restore options (Phase 15a, `crates/pve/src/restore.rs`, `crates/scheduler/src/restore.rs`)
- `restore` / `restore_ct` / `instant_recover` params: `source, time, node, target, storage` plus optional `name`
  or `name_prefix` (not both; PVE name characters, 1..=63, no leading `-`/`.`), `pool`, `start` (bool; instant
  recovery: default true), `link_down` (bool), and for full restores `replace` (bool) with `keep_original_links`.
  Default name: `<backed-up name>-restore` (`name` / `hostname` of the snapshot's config).
- The scheduler turns them into `nexus-pve` flags (`--name`, `--name-prefix`, `--pool`, `--start`, `--link-down`,
  `--replace`, `--keep-original-links`; instant recovery `--no-start`). `name`/`pool` go into the PVE restore call
  (qemu: `override_conf`), `link_down=1` is set on every `netN` by a config update before the first start, so `start`
  is passed to PVE only without link_down/replace; otherwise nexus-pve starts the guest itself.
- **Replace** (`restore.replace`): the web-api never creates the job; it stores a quorum request
  `{tenant, kind, params}` (admin/operator only, never a token). The scheduler's poller queues the approved request
  as a restore job with `replace: true, quorum_id, requested_by` (a job with `replace` but no `quorum_id` fails);
  the job's end marks the request `executed`. Order and rollback: see the module doc of `crates/pve/src/restore.rs`
  (restore to the new VMID with `unique=0`, `onboot=0`; stop original; rename it `<name>-replaced-<YYYYmmddHHMM>`,
  `onboot=0`, NICs `link_down=1`; restored guest gets the original's name + onboot; start). Any failure after the
  restore reverts the original's changed keys and restarts it if it ran. The original is never deleted; the VMID
  changes.
- Results: `restore` / `restore_ct` jobs get `result` from the `restored {json}` line:
  `{target, name, started, link_down, replaced?, original_renamed_to?}`.

## Consistency (Phase 15d, catalog v20, `crates/scheduler/src/consistency.rs`)
- `snapshots.consistency`: `application` (quiesced: guest-agent fs-freeze + fs-thaw, VSS writers, hooks, plugin
  declaring `backup.consistent: "application"`, or the guest was stopped), `crash` (point in time without quiesce),
  `inconsistent` (read live), `unknown`; NULL for rows from before v19 and rows the scheduler did not write
  (replicated, offsite-only).
- VMs / CTs: `nexus-pve` reads the vzdump task log after the backup (`crates/pve/src/consistency.rs`, lines quoted
  from qemu-server / pve-container) and prints `consistency <source>/<time>: <level> (<reason>)`. Agents, shares,
  TrueNAS and plugins: derived from the existing `inconsistent …` lines and the source (hooks / Windows / manifest).
- The scheduler adds `consistency` to each entry of a backup job's `result.snapshots` (and to the top level for a
  single snapshot) and upserts it into `snapshots` right after the job (the refresh fills in the rest).
- Policy `require_consistency` `{mode: off|warn|fail, level: application|crash}` (default off/crash): for backups
  with `group_id`, a snapshot below `level` raises warning `consistency` (key `consistency:<tenant>/<source>`,
  resolved by the next snapshot that meets it); `fail` also turns the job `failed` (log line
  `[scheduler] consistency below the policy minimum …`, normal retries). Relaxing the requirement is a weakening
  policy change (quorum).
- Reports: the protection report's `consistency` column shows the level (legacy `consistent` flag → `crash` /
  `inconsistent`); `GET /dashboard` adds `consistency: {application, crash, inconsistent, unknown}` = counts over the
  newest local snapshot per source.
## Disk and file selection, agent limits and renewal (Phase 15e/f, catalog v21)
- **Groups**: `exclude_disks` (`{"*": [disk keys], "<vmid>": [disk keys]}`, PVE sources only, keys like `scsi1`),
  `exclude_disks_mode` (`placeholder` | `omit`), `parallel_guests` (1..=8). The scheduler (`scheduler/src/selection.rs`)
  passes nexus-pve `exclude_disks` per vmid as device names (`drive-scsi1`), the mode and `parallel`; plugin groups get
  `parallel` in the plugin host's job config (docs/pve-connector.md, docs/plugin-system.md). Adding an excluded disk is a
  weakening `group.update` (approval).
- **Policies**: `file_filters` `{exclude, exclude_regex}`, appended to the excludes of every agent and NFS/SMB source of
  the policy's groups (web-api validates regexes with the agents' compiler, `agent_core::filter::check_regex`). Adding
  an entry is a weakening `policy.update` (approval); the quorum execute arms store the new fields too.
- **Sources**: linux `include`, `exclude_regex`, `cross_mounts`, `skip_fstypes`; nfs/smb `include`, `exclude_regex`.
  nexus-agentctl gets `backup.excludes` (source + policy globs), `backup.filters` and `backup.limits` (from
  `agents.limits`) and sends them in `PrepareEx` (docs/agent-protocol.md v1.3); nexus-nas gets `include` /
  `exclude_regex` in nas.json.
- **Agent certificates**: every agent session reports `agent-cert {agent_id, cert_sha256, not_before, not_after}`;
  the scheduler (`scheduler/src/renewal.rs`) updates `cert_issued` / `cert_expires` when the fingerprint is the pinned
  or the pending one (promoting the pending one). Every full refresh queues `agent_renew` `{agent_id, auto: true}` for
  agents with less than 30 days or 10 % of the lifetime left (not while a renewal / enrollment of the agent is queued,
  running or failed within 24 h). `renew-issued` sets `cert_sha256_next`, `renewed` makes it the pin (audit
  `agent.cert_renewed`, resolves `cert_expiry:agent:<id>`). `agent_renew` is an admin job kind ("Renew certificate
  now"). Expiry alerts use `cert_expires` (fallback: enrollment + 10 years).
- **Cancel** of a parallel PVE run stops every task the connector reported (`upid:` lines, newest first).

## Reports (Phase 14e)

- **Crate `reports`** (shared by web-api and scheduler, no web-api dependency): `generate(conn, kind, scope, from, to,
  now) → Table {columns, rows}` and `Table::csv()`. The protected-object enumeration (`reports::protection::objects`
  / `assess`, RPO = schedule period, breach when the last snapshot is older than RPO × 1.5) and the storage
  accounting (`reports::storage::compute`) moved there from the web-api; `GET /dashboard` and `GET /storage` call
  them, so dashboard, Storage page and reports cannot drift apart.
- **Reports**: `protection` (one row per protected object: tenant, groups, object, kind, source, rpo_hours,
  last_good, age_hours, status, local / offsite / verified of the last snapshot, consistency from the `consistent`
  flag of the backup job result that wrote it, else `unknown`; current state); `failed` (jobs with `state = failed`
  and `finished` in `[from, to)`: job, tenant, kind, target, created, finished, attempt, first log line matching
  error / failed / fatal, else the last line, ≤ 300 chars); `sla` (`rpo_breach`: per object the intervals from
  `backup + 1.5 × RPO` to the next good backup or now, from snapshot times in `snapshots` ∪ the `snapshots[]` of ok
  backup job results, so retention does not open false gaps; an object paused now has no open breach;
  `sla_missed`: those alerts with `ts` in the range, joined to the job and group); `storage` (tenant rows, then group
  rows of `GET /storage`; current state).
- **CSV**: RFC 4180 (comma, CRLF, quoting of `,` `"` CR LF), UTF-8 without BOM, ISO 8601 UTC times, bytes as
  integers, ratios with 3 decimals, hours with 1; text cells starting with `= + - @` TAB CR get a leading `'`
  (CSV injection).
- **Scheduled** (setting `reports`, array of `{name [A-Za-z0-9._-]{1,64}, types (each once), schedule (catalog
  schedule grammar without the hourly forms), timezone (IANA, default UTC), recipients (1..=16), tenant?}`): the
  scheduler's `queue_reports` (each tick) queues the appliance job `report_send {name, from, to}` (tenant `-`) when
  the schedule is due (same period rule and first-sight wait as groups; `last_run` = newest `report_send` queued by
  the scheduler for the name; not while one is queued/running); `from` = the previous slot, `to` = this slot. The job
  composes on the scheduler thread (`reports::compose`: subject `[NexusBackup <host>] report <name>: <from day> –
  <to day>`, inline-styled HTML with up to 20 rows per report, all values HTML-escaped, a text part, one CSV
  attachment `<name>-<type>-<day>.csv` per type) and sends in the job thread (`alerts::send_message`, the SMTP server
  of setting `alerts` with its sealed password; already in the egress allow-list via `firewall::alert_targets`).
  Result `{name, types, tenant, recipients, from, to, attachments, rows}`. Ok → audit `report.sent` and resolve
  `report:<name>`; failed (or an invalid schedule at queue time) → warning alert `report` under key
  `report:<name>` instead of `job_failed`. `POST /jobs` refuses the kind.

## Access (Phase 14d, `web-api/src/access.rs`, `catalog::access`, `scheduler/src/accounts.rs`)
- **User fields**: `POST /users` and `PUT /users/{id}` take `can_download` (bool) and `expires` (unix time or null). `User` JSON carries `can_download` (effective), `expires`, `last_login`. Expired accounts: login refused (`auth.login_failed` reason `expired`, OIDC `account_disabled`), the next request of an open session answers 401 `account expired` and ends all its sessions, the scheduler's refresh ends them too; they are no possible approvers. The last enabled admin without expiry cannot get one (409). Changes end the user's sessions, audited `user.update`.
- **Sessions**: `GET /auth/sessions` (own; `[{id, user_id, user, ip, user_agent, created, last_seen, current}]`), `DELETE /auth/sessions/{id}` (own, else 404), admin: `GET /sessions[?user=ID]`, `DELETE /sessions/{id}`, `POST /users/{id}/sessions/revoke`, `POST /sessions/revoke-all {current_password, current_totp}` (re-authenticated; every session except the caller's). Audited `session.revoke`, `session.revoke_user`, `session.revoke_all`. Login stores the client address (`ClientIp`) and the user agent (≤ 256 printable characters) and sets `users.last_login`.
- **Settings** (`settings` table, admin writes, admin + security officer read `GET /settings/security` → `{session, dormant_days, login_banner, mgmt_allow, client_ip, client_allowed, pending: {session, mgmt_allow}}`):
  - `session` `{idle_min 5–120, absolute_h 1–24}` (`PUT /settings/session`): read on every request (open sessions included); a longer value in either field is quorum `security.session`, shorter applies directly (audited `security.session`).
  - `dormant_days` (`PUT /settings/dormant {days}`; 0 = off, the default, else 30–3650; audited `security.dormant`): the scheduler's refresh disables accounts with `COALESCE(last_login, created)` older than that (activated, unexpired, enabled accounts), never the last enabled local admin and, with approvals enabled, never an approver if fewer than two would remain; audited `user.dormant_disabled` (actor `scheduler`), info alert `account_dormant:<name>`. v15 backfills `last_login` with the upgrade time.
  - `login_banner` (`PUT /settings/banner {banner}`; ≤ 2000 characters, no control characters except newline and tab; audited `security.login_banner`); public `GET /auth/banner` → `{banner}`; the login page shows it as text (newlines kept, never HTML).
  - `mgmt_allow` (`PUT /settings/mgmt-allow {mgmt_allow: [cidr], force?, confirm?}`): since Phase 16c the source list of the inbound firewall's `web` service (see "Inbound firewall"); the route is an alias of `PUT /firewall/inbound/web` (quorum `firewall.inbound`), `GET /settings/security` keeps `mgmt_allow` / `client_allowed` / `pending.mgmt_allow` (web). Requests `security.mgmt_allow` made before the update still execute (into `web`).
- **API tokens** (`tokens.rs`): a token of an expired or disabled (also dormant-disabled) user is refused (401) like its sessions; a viewer cannot create an `operator` token and a viewer token in the catalog stays read-only (`effective` keeps the role, no writes); tokens never download (`can_download` is cleared for token requests).
- **Console recovery**: `nexus-setup reset-firewall` (see "Inbound firewall"; `reset-mgmt-allow` is an alias). `nexus-setup disable-approvals` (root + recovery key, like `recover-admin`) switches approvals off when nobody else can approve any more: audited `approvals.break_glass`, critical alert `break_glass` (banner for admins until acknowledged).

## Inbound firewall (Phase 16c, `web-api/src/firewall.rs`, `catalog::firewall`, `nftsync`)
Outbound stays automatic (scheduler allow-list, `scheduler/src/firewall.rs`); inbound is configured per service.
- **Registry** (`catalog::firewall::SERVICES`, fixed): `web` 8443/tcp (web UI, REST API, `/metrics` and replication: one TLS listener, ALPN selects replication, and nftables cannot see inside TLS, so they are restricted together; lock-out relevant; cannot be switched off), `icmp` (ICMP/ICMPv6 echo request, rate-limited 10/s; off by default), `ssh` 22/tcp (reserved, `available: false`: no SSH server; shown, not configurable). Backup agents and sources are pulled (outbound), so they need no inbound rule. Fixed rules, not services: loopback, established/related, IPv6 neighbour discovery, DHCP replies.
- **Setting** `inbound` = `{services: {<id>: {allow: [cidr], enabled?}}}`; a missing entry = defaults (any address; `enabled` from the registry). Without the setting, the 14d `mgmt_allow` is `web`'s list (migration on read); every write mirrors `web` back into `mgmt_allow`. ≤ 64 CIDRs per service, canonical network form, duplicates merged; unknown services and invalid entries are dropped on read.
- `GET /firewall` (admin, security officer; not tenant-scoped; closed to API tokens) → `{services: [{id, ports, lockout, available, can_disable, enabled, allow, effective: {v4, v6} | null, pending}], client_ip, client_allowed, status_ts, status_stale (> 5 min), outbound: {endpoints, dns, nts} | null, drops: [{src, proto, port, last_seen, packets}]}`. `effective`, `outbound` and `drops` come from the status file of `nexus-nft-sync` (`/run/nexus-nft-status/status.json`, env `NEXUS_NFT_STATUS`); the web-api never runs nft and never reads the journal.
- `PUT /firewall/inbound/{service} {allow, enabled?, force?, confirm?}` (admin): 404 unknown service, 409 reserved service, 400 invalid CIDR / too many / `enabled: false` for `web`; unchanged → 200 `{service, rule}`; otherwise quorum `firewall.inbound` (params `{service, rule, old, requested_from}`; refused on approval if the service's rule changed since). For lock-out relevant services a list that does not contain the requester's address is refused (409) unless `force` and `confirm` = that address.
- **Applying**: the scheduler writes `inbound: {<id>: {enabled, allow}}` for every available service into `allowed.json` (`nftsync::write_allowed`); `nexus-nft-sync` validates it (known service ids, CIDR literals, ≤ 64 each; a file with anything else is refused as a whole) and flushes + refills the interval sets `in_<id>_v4/v6` of `os/nftables.conf` in the same transaction as the outbound sets: enabled + empty list → `0.0.0.0/0` / `::/0`, enabled + list → the list, disabled → empty. Without `inbound` in the file the sets are left alone; the image starts with `web` = any, `icmp` = empty.
- **Blocked attempts**: after the service rules the input chain records every dropped unicast TCP/UDP packet in the dynamic sets `in_drops_v4/v6` (`saddr . l4proto . dport`, 24 h timeout refreshed per packet, packet counter, 256 elements each) and logs rate-limited with the prefix `nexus-in-drop:`. `nexus-nft-sync --status` (`nexus-nft-status.timer`, every minute; also after every sync) lists the table (`nft -j`) and writes the status file (0644 in `/run/nexus-nft-status`, 0755 root, SELinux `nexus_nftstatus_var_run_t`: nft-sync writes, web-api reads): the managed sets and the drops, newest first (`last_seen` = now − (timeout − expires)).
- **Console recovery**: `nexus-setup reset-firewall` (root; alias `reset-mgmt-allow`) clears every service's list (the switches stay), mirrors `mgmt_allow = []`, loads the `in_*` sets at once (`nft -f -`), audits `firewall.reset` (actor `console`, `{old: {service: [cidr]}}`) and raises the warning alert `firewall_reset`.

## Legal hold (Phase 15c, `web-api/src/holds.rs`, `catalog::holds`, catalog v18)
A legal hold keeps one snapshot regardless of retention until its release is approved. It is kept in the catalog,
not in the store: the store's retention lock (`Manifest.lock_until`) can only grow, so it could never be released.
- **Set:** security officers only (an additive protection: immediate, no quorum), one snapshot or a time range
  (`POST /holds`); audited `snapshot.hold`. Admins cannot set holds; they (and security officers) request releases.
- **Release:** quorum action `snapshot.hold_release` (`{tenant, source, time, hold_id}`), approved by another admin or
  security officer, executed by the web-api (state `released`, `released_by` = requester, `approved_by`); audited
  `snapshot.hold_release`. With approvals disabled it executes at once like every gated action.
- **Enforcement (scheduler):** `Plan.held` = the tenant's active holds, read when a job is planned. Retention steps
  (`Step::Retention`, the orphan sweep `Step::Orphans`) call `Store::apply_retention_held` (held snapshots are never
  deleted and count as kept; they still take part in the GFS selection); `Step::Delete` fails for a held snapshot (an
  approved `snapshot.delete` requested before the hold); `offsite.json` carries `held: [[source, time]]` for the
  offsite retention (`Target::apply_retention`); `replica.json` carries them for the secondary's own retention. GC is
  mark-and-sweep over the existing snapshots, so a snapshot retention keeps keeps its chunks (locally and offsite).
  A hold set while a retention job runs applies from the next job.
- **Replication:** the primary serves its active holds per tenant on `GET /replication/v1/tenants/{t}/holds`
  (`[{source, time, reason, held_by, held_at}]`; primaries before 15c answer 404 = none). The secondary stores them as
  `advisory` rows (`origin` = the replication source; only for snapshots it has) with a warning
  `legal_hold_advisory:<tenant>/<source>/<time>` (audit `snapshot.hold_advisory`); advisories are never enforced. Its
  security officer applies one with `POST …/hold` (the row becomes `active`, set by them, the alert resolves); an
  advisory the primary no longer reports becomes `withdrawn` (audit `snapshot.hold_withdrawn`, alert resolved). A hold
  applied on the secondary stays until released there.
- **Alerts:** `GET /alerts` rows carry `snapshot` `{tenant, source, time}` for `anomaly` (the "last snapshot before"
  named in the message) and `legal_hold_advisory`; the UI offers **Hold last good snapshot** / **Apply hold** there.
- API tokens: `GET /holds` is readable with `read` scope; setting and releasing are closed to tokens.

## Break-glass (`nexus-setup recover-admin`, Phase 12 §7)
Console only (root): `nexus-setup recover-admin [--user NAME] [--force-solo]` asks for the recovery key (checked against keyd's `kek.recovery` as at first boot), resets a local admin account to pending activation (old password and authenticator invalid at once, sessions ended, account enabled) and prints a new one-time activation code (72 h). Without `--user` the only local admin is chosen. With approvals enabled and at least two possible approvers it refuses unless `--force-solo` (recorded in the alert, the audit entry and the banner). Audited `user.break_glass` (actor `console`), critical alert `break_glass`, setting `break_glass`.

## Console root shell (Phase 14c)
Root's password is locked and there is no sshd; the only root shell is the console gate `nexus-console-gate`
(crates/setup, `nexus-console-gate.service` on tty2, which replaces getty@tty2/autovt@tty2, both masked). It accepts:
- a one-time code: `console.unlock` quorum request (admin; another admin or security officer approves; with approvals
  disabled it is approved at once). The requester fetches the code once (`POST /console/unlock/{id}/code`, quorum
  `approved` → `executed`); the web-api writes `{id, hash, hours, requested_by, approved_by, reason, issued,
  expires}` to `/var/lib/nexus/console-unlock/<id>.json` (0700 nexus-webapi; tmp + rename), `hash` = SHA-256 of the
  normalized code (Crockford base32, 4×5 characters = 100 bits; `catalog::console`), `expires` = approval + 24 h. The
  gate deletes the file when the code is used (one-time) and expired files on every round;
- the recovery key (keyd `check_recovery_key`, as `recover-admin`), with a duration of 1–8 h asked at the console.

Failures: audited `console.unlock_failed`; 5 per 15 min, 2/4/8/16 s delay after the 1st–4th (state in
`/run/nexus-console-gate`, kept across restarts of the gate). Success: audit `console.root_shell` (actor `console`,
target `console-unlock/<id>` or `console`; method, hours, until, requester/approver), critical alert
`console_root_shell`, setting `console_shell_active` `{at, until, method, unlock, requested_by, alert, unit}`
(`GET /auth/me` and `GET /dashboard` return it as `console_shell` to appliance-wide roles: the UI banner). The shell
is `systemd-run --scope --unit nexus-console-shell-<at> -p RuntimeMaxSec=<hours> -- /bin/bash --login` on tty2:
systemd stops the scope (every process in it) when the time is up, and the gate stops it when bash exits. Then
`console.root_shell_end` (`how`: exit / timeout / …) and the setting is removed; a gate that restarts during a shell
clears the setting (`how: "gate restarted"`) and stops the old scope (TTYVHangup= already hung up its terminal).
`console_unlock` / `console_root_shell` alerts are acknowledged by admin or security officer only.

SELinux: the gate runs as `nexus_consolegate_t` (catalog, keyd files read, unlock files read + unlink, tty, PID 1
over the private socket for the transient scope); executing bash transitions to `unconfined_t` (role system_r).
neverallow: no other nexus domain transitions to `unconfined_t`; only `nexus_webapi_t` creates or writes the unlock
files, only it and the gate read them. The unit is deliberately unsandboxed (the shell inherits the unit's
namespaces and capability bounding set).

## First boot (`nexus-setup`, console TUI)
Network (NetworkManager, static/DHCP on the management NIC) → admin account + TOTP enrollment (QR in terminal, code confirmation) → second person: "create it now (recommended)" = security officer account + TOTP, entered at the console by that person, or "later" (audit `setup.second_person_later`; script mode `"second_person_later": true`) → `keyd init`: recovery key shown once, re-entry of 3 random groups required → TLS certificate (self-signed, SAN = hostname + IPs; fingerprint shown) → metrics token → `/var/lib/nexus/setup-done` (writes `settings.approvals_enabled`: enabled with two people, **disabled with a single administrator** — the TUI and the script output say so; audit `setup.approvals`) → enable `nexus-web-api`, `nexus-scheduler`, `nexus-keyd`, `nexus-replicad` (`nexus-nasmount.socket` is enabled by the image preset).

Tenant keys: tenants are created in the UI; the scheduler asks keyd `ensure <tenant>` (keyd creates DEK v1 on first use, only for the chunkstore uid) and refreshes the wrapped escrow files via `escrow <tenant>` before each offsite run.
