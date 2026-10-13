//! Catalog (plan §11.3, docs/control-plane.md): SQLite in WAL mode shared by
//! web-api (intent) and scheduler (execution), plus the hash-chained audit log.

use anyhow::{bail, Result};
use rusqlite::{params, Connection, OptionalExtension};
use sha2::{Digest, Sha256};
use std::path::Path;
use std::sync::{Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

pub mod access;
pub mod alerting;
pub mod auth;
pub mod console;
pub mod firewall;
pub mod fleet;
pub mod forwarding;
pub mod hardware;
pub mod holds;
pub mod inventory;
pub mod network;
pub mod priority;
pub mod schedule;
pub mod secret;
pub mod tenancy;
pub mod tenant_key;
pub mod tenants;
pub mod vault;
pub use rusqlite;

const SCHEMA_V1: &str = r#"
CREATE TABLE users (
  id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL,
  totp_secret TEXT NOT NULL, role TEXT NOT NULL CHECK (role IN ('admin','security_officer','operator','tenant_user')),
  tenant TEXT, disabled INTEGER NOT NULL DEFAULT 0, created INTEGER NOT NULL);
CREATE TABLE sessions (
  id_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id), csrf TEXT NOT NULL,
  created INTEGER NOT NULL, last_seen INTEGER NOT NULL);
CREATE TABLE tenants (name TEXT PRIMARY KEY, offsite TEXT NOT NULL DEFAULT '{}');
CREATE TABLE sources (
  id INTEGER PRIMARY KEY, tenant TEXT NOT NULL REFERENCES tenants(name), kind TEXT NOT NULL CHECK (kind IN ('pve')),
  name TEXT NOT NULL, config TEXT NOT NULL, UNIQUE (tenant, name));
CREATE TABLE policies (
  id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE, schedule TEXT NOT NULL, gfs TEXT NOT NULL,
  offsite INTEGER NOT NULL DEFAULT 1);
CREATE TABLE groups (
  id INTEGER PRIMARY KEY, tenant TEXT NOT NULL REFERENCES tenants(name), source_id INTEGER NOT NULL REFERENCES sources(id),
  policy_id INTEGER NOT NULL REFERENCES policies(id), name TEXT NOT NULL, guests TEXT NOT NULL, UNIQUE (tenant, name));
CREATE TABLE jobs (
  id INTEGER PRIMARY KEY, kind TEXT NOT NULL, tenant TEXT NOT NULL, params TEXT NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('queued','running','ok','failed','cancelled')),
  requested_by TEXT NOT NULL, created INTEGER NOT NULL, started INTEGER, finished INTEGER, log TEXT NOT NULL DEFAULT '');
CREATE INDEX jobs_state ON jobs(state, id);
CREATE TABLE snapshots (
  tenant TEXT NOT NULL, source TEXT NOT NULL, time INTEGER NOT NULL, size INTEGER NOT NULL DEFAULT 0,
  local INTEGER NOT NULL, offsite INTEGER NOT NULL, lock_until INTEGER NOT NULL DEFAULT 0, verified INTEGER,
  PRIMARY KEY (tenant, source, time));
CREATE TABLE quorum (
  id INTEGER PRIMARY KEY, action TEXT NOT NULL, params TEXT NOT NULL, requested_by TEXT NOT NULL, created INTEGER NOT NULL,
  decided_by TEXT, decided_at INTEGER,
  state TEXT NOT NULL CHECK (state IN ('pending','approved','rejected','executed','expired')));
CREATE TABLE audit (
  seq INTEGER PRIMARY KEY, ts INTEGER NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL, target TEXT NOT NULL,
  details TEXT NOT NULL, prev_hash TEXT NOT NULL, hash TEXT NOT NULL);
CREATE TRIGGER audit_no_update BEFORE UPDATE ON audit BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;
CREATE TRIGGER audit_no_delete BEFORE DELETE ON audit BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;
CREATE TABLE alerts (
  id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, severity TEXT NOT NULL, kind TEXT NOT NULL, message TEXT NOT NULL, acked_by TEXT);
"#;

/// v2: TOTP replay protection (last accepted 30 s step per user).
const SCHEMA_V2: &str = "ALTER TABLE users ADD COLUMN totp_last_step INTEGER NOT NULL DEFAULT 0;";

/// v3: structured job results (JSON, NULL until the job finished ok).
const SCHEMA_V3: &str = "ALTER TABLE jobs ADD COLUMN result TEXT;";

/// v4: Linux agents (docs/agent-protocol.md). New table `agents`; source kind
/// `linux` — SQLite cannot alter a CHECK, so `sources` is rebuilt (same ids,
/// rows and constraints, wider CHECK). Runs with foreign keys off (see
/// `Catalog::open`) and is checked with `foreign_key_check` before commit.
/// Backward compatible for one release (docs/release.md): the previous
/// release skips unknown migrations (`user_version` 4 > 3), never reads
/// `agents`, and treats `linux` sources as unsupported (their jobs fail with
/// an alert, nothing else changes).
/// `agents.token_hash` holds the enrollment token digest sealed to the
/// scheduler (`sealed:v1:`, `catalog::secret`), cleared after enrollment.
const SCHEMA_V4: &str = r#"
CREATE TABLE agents (
  id TEXT PRIMARY KEY, tenant TEXT NOT NULL REFERENCES tenants(name), name TEXT NOT NULL, host TEXT NOT NULL,
  port INTEGER NOT NULL, cert_sha256 TEXT, enrolled_at INTEGER, token_hash TEXT, token_expires INTEGER,
  last_seen INTEGER, version TEXT, os TEXT, UNIQUE (tenant, name));
CREATE TABLE sources_v4 (
  id INTEGER PRIMARY KEY, tenant TEXT NOT NULL REFERENCES tenants(name), kind TEXT NOT NULL CHECK (kind IN ('pve','linux')),
  name TEXT NOT NULL, config TEXT NOT NULL, UNIQUE (tenant, name));
INSERT INTO sources_v4 (id, tenant, kind, name, config) SELECT id, tenant, kind, name, config FROM sources;
DROP TABLE sources;
ALTER TABLE sources_v4 RENAME TO sources;
"#;

/// v5: TrueNAS sources (docs/truenas-connector.md): kind `truenas`, same
/// rebuild as v4 (ids, rows, constraints kept; foreign keys checked). The
/// previous release skips it and fails jobs of `truenas` sources as unsupported.
const SCHEMA_V5: &str = r#"
CREATE TABLE sources_v5 (
  id INTEGER PRIMARY KEY, tenant TEXT NOT NULL REFERENCES tenants(name),
  kind TEXT NOT NULL CHECK (kind IN ('pve','linux','truenas')),
  name TEXT NOT NULL, config TEXT NOT NULL, UNIQUE (tenant, name));
INSERT INTO sources_v5 (id, tenant, kind, name, config) SELECT id, tenant, kind, name, config FROM sources;
DROP TABLE sources;
ALTER TABLE sources_v5 RENAME TO sources;
"#;

/// v6: NAS shares (docs/nas-connector.md): kinds `nfs` and `smb`, same
/// rebuild as v4/v5 (ids, rows, constraints kept; foreign keys checked). The
/// previous release skips it and fails jobs of share sources as unsupported.
const SCHEMA_V6: &str = r#"
CREATE TABLE sources_v6 (
  id INTEGER PRIMARY KEY, tenant TEXT NOT NULL REFERENCES tenants(name),
  kind TEXT NOT NULL CHECK (kind IN ('pve','linux','truenas','nfs','smb')),
  name TEXT NOT NULL, config TEXT NOT NULL, UNIQUE (tenant, name));
INSERT INTO sources_v6 (id, tenant, kind, name, config) SELECT id, tenant, kind, name, config FROM sources;
DROP TABLE sources;
ALTER TABLE sources_v6 RENAME TO sources;
"#;

/// v7: appliance replication (docs/replication.md). Primary: `replication_peers`
/// (enrolled secondaries, tenant scope, client-cert fingerprint, enrollment
/// token digest sealed to nexus-replicad, DEK exports sealed to the peer's keyd).
/// Secondary: `replication_sources` (primary address + certificate pin, tenants,
/// schedule, GFS, enrollment token digest sealed to the scheduler, sync status).
/// `snapshots.origin`: NULL = local backup, else the replication source name.
/// Purely additive (no table rebuild; `sources` keeps v6's kind CHECK). The
/// previous release (v6) skips it and never reads the new tables/column.
const SCHEMA_V7: &str = r#"
CREATE TABLE replication_peers (
  id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, tenants TEXT NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('pending','approved','enrolled','revoked')),
  cert_sha256 TEXT, keyd_pub TEXT, token_hash TEXT, token_expires INTEGER,
  enroll_failures INTEGER NOT NULL DEFAULT 0, key_exports TEXT NOT NULL DEFAULT '{}',
  created INTEGER NOT NULL, created_by TEXT NOT NULL, enrolled_at INTEGER, last_seen INTEGER, revoked INTEGER);
CREATE UNIQUE INDEX replication_peers_cert ON replication_peers(cert_sha256) WHERE cert_sha256 IS NOT NULL;
CREATE TABLE replication_sources (
  id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE, url TEXT NOT NULL, peer_id TEXT NOT NULL,
  cert_pin TEXT NOT NULL, tenants TEXT NOT NULL, schedule TEXT NOT NULL, gfs TEXT NOT NULL DEFAULT '{}',
  bwlimit INTEGER, token_hash TEXT,
  state TEXT NOT NULL CHECK (state IN ('enrolling','enrolled','failed')),
  cert_sha256 TEXT, keyd_pub TEXT, created INTEGER NOT NULL, last_sync INTEGER, status TEXT NOT NULL DEFAULT '{}');
ALTER TABLE snapshots ADD COLUMN origin TEXT;
"#;

/// v8: plugin system (docs/plugin-system.md). `plugins`: one row per uploaded
/// (id, version) with the bundle / binary digests, the manifest as signed, the key
/// that verified it, its lifecycle state and whether it is the `current` (active)
/// version of its id; `plugin_keys`: publisher keys added with quorum (project keys
/// come from the image). `sources.kind` additionally accepts `plugin:<kind>`: the
/// same rebuild as v4–v6 (ids, rows, constraints kept; foreign keys checked). The
/// previous release (v7) skips it and fails jobs of plugin sources as unsupported.
const SCHEMA_V8: &str = r#"
CREATE TABLE plugins (
  id TEXT NOT NULL, version TEXT NOT NULL, name TEXT NOT NULL, publisher TEXT NOT NULL,
  sha256 TEXT NOT NULL, bin_sha256 TEXT NOT NULL, size INTEGER NOT NULL, manifest TEXT NOT NULL, signer TEXT NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('pending','approved','installed','failed','rejected','removing','removed')),
  current INTEGER NOT NULL DEFAULT 0 CHECK (current IN (0,1)),
  enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0,1)),
  quorum_id INTEGER, uploaded_by TEXT NOT NULL, uploaded_at INTEGER NOT NULL, installed_at INTEGER, error TEXT,
  PRIMARY KEY (id, version));
CREATE UNIQUE INDEX plugins_current ON plugins(id) WHERE current = 1;
CREATE TABLE plugin_keys (
  fingerprint TEXT PRIMARY KEY, publisher TEXT NOT NULL, public_key TEXT NOT NULL,
  added_by TEXT NOT NULL, approved_by TEXT, added_at INTEGER NOT NULL);
CREATE TABLE sources_v8 (
  id INTEGER PRIMARY KEY, tenant TEXT NOT NULL REFERENCES tenants(name),
  kind TEXT NOT NULL CHECK (kind IN ('pve','linux','truenas','nfs','smb')
    OR (kind GLOB 'plugin:[a-z0-9]*' AND kind NOT GLOB 'plugin:*[^a-z0-9-]*' AND length(kind) <= 39)),
  name TEXT NOT NULL, config TEXT NOT NULL, UNIQUE (tenant, name));
INSERT INTO sources_v8 (id, tenant, kind, name, config) SELECT id, tenant, kind, name, config FROM sources;
DROP TABLE sources;
ALTER TABLE sources_v8 RENAME TO sources;
"#;

/// v9: optional approval system and self-enrollment (plan §2 "Approval system",
/// "User onboarding"). `settings`: appliance-wide key/value settings;
/// `approvals_enabled` starts `true` for existing catalogs (keeps the quorum
/// behaviour; nexus-setup writes the value for a new appliance). `users`:
/// one-time activation code digest (`activation_hash`, `sha256hex(code)`, or
/// `sha256hex(part1):sha256hex(part2)` for split codes, `sha256hex(part1):?`
/// while the second part is not issued yet) and its expiry. A pending account
/// has `activation_hash` set and no usable password/TOTP. Purely additive: the
/// previous release skips it (pending accounts cannot log in there either: their
/// password hash is not a valid hash).
const SCHEMA_V9: &str = r#"
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
INSERT OR IGNORE INTO settings (key, value) VALUES ('approvals_enabled', 'true');
ALTER TABLE users ADD COLUMN activation_hash TEXT;
ALTER TABLE users ADD COLUMN activation_expires INTEGER;
"#;

/// v10 (Phase 12, docs/phase12-contract.md): daily capacity samples per tenant
/// (written by the scheduler's refresh, read by `GET /dashboard`) and OIDC users
/// (`users.auth` = `local` | `oidc`, `users.oidc_sub` = the IdP's `iss` + `sub`).
/// Purely additive: the previous release skips it; OIDC accounts cannot log in
/// there (their password hash is not a valid hash, no TOTP seed).
const SCHEMA_V10: &str = r#"
CREATE TABLE IF NOT EXISTS capacity_samples (
  day TEXT NOT NULL, tenant TEXT NOT NULL, used INTEGER NOT NULL, logical INTEGER NOT NULL,
  PRIMARY KEY (day, tenant));
ALTER TABLE users ADD COLUMN auth TEXT NOT NULL DEFAULT 'local' CHECK (auth IN ('local','oidc'));
ALTER TABLE users ADD COLUMN oidc_sub TEXT;
CREATE UNIQUE INDEX IF NOT EXISTS users_oidc_sub ON users(oidc_sub) WHERE oidc_sub IS NOT NULL;
"#;

/// v11 (Phase 13d, docs/storage-accounting.md): per-snapshot backup statistics
/// (`nexus-stats` lines of the connectors, parsed by the scheduler) and a soft
/// storage quota per tenant (NULL = none; only alerts, never blocks a backup).
/// Purely additive: the previous release skips it.
const SCHEMA_V11: &str = r#"
CREATE TABLE IF NOT EXISTS backup_stats (
  tenant TEXT NOT NULL, source TEXT NOT NULL, time INTEGER NOT NULL,
  read INTEGER NOT NULL, logical INTEGER NOT NULL, new_chunks INTEGER NOT NULL,
  new_plain INTEGER NOT NULL, new_stored INTEGER NOT NULL,
  PRIMARY KEY (tenant, source, time));
ALTER TABLE tenants ADD COLUMN quota_bytes INTEGER;
"#;

/// v12 (Phase 13f, alert lifecycle): an alert is raised under a `key`; a repeat
/// while it is open (`resolved_at` NULL) bumps `count` / `last_ts` instead of
/// adding a row, the success path resolves it (`auto` = 1, by the scheduler),
/// people acknowledge (seen, still open) or resolve it with a `note`.
/// `notified_ts` = last delivery (NULL = due; replaces the scheduler's cursor
/// file). Backfill: key = kind:message (capacity, offsite_lag and gc_quorum get
/// the keys the scheduler now uses), acknowledged alerts count as resolved
/// (that is what an ack meant before), everything counts as delivered. Purely
/// additive: the previous release skips it and keeps inserting and
/// acknowledging rows (count 1, key NULL).
const SCHEMA_V12: &str = r#"
ALTER TABLE alerts ADD COLUMN key TEXT;
ALTER TABLE alerts ADD COLUMN tenant TEXT;
ALTER TABLE alerts ADD COLUMN count INTEGER NOT NULL DEFAULT 1;
ALTER TABLE alerts ADD COLUMN last_ts INTEGER;
ALTER TABLE alerts ADD COLUMN resolved_at INTEGER;
ALTER TABLE alerts ADD COLUMN resolved_by TEXT;
ALTER TABLE alerts ADD COLUMN note TEXT;
ALTER TABLE alerts ADD COLUMN auto INTEGER NOT NULL DEFAULT 0;
ALTER TABLE alerts ADD COLUMN notified_ts INTEGER;
UPDATE alerts SET last_ts = ts, key = kind || ':' || substr(message, 1, 200),
  notified_ts = CAST(strftime('%s', 'now') AS INTEGER);
UPDATE alerts SET key = 'capacity' WHERE kind = 'capacity';
UPDATE alerts SET key = 'offsite_lag:' || substr(message, 24, instr(message, ' lags') - 24)
  WHERE kind = 'offsite_lag' AND message LIKE 'offsite copy of tenant % lags%';
UPDATE alerts SET key = 'gc_quorum:' || substr(message, 15, instr(message, ' needs') - 15)
  WHERE kind = 'gc_quorum' AND message LIKE 'GC for tenant % needs%';
UPDATE alerts SET resolved_at = ts, resolved_by = acked_by WHERE acked_by IS NOT NULL;
CREATE INDEX IF NOT EXISTS alerts_open ON alerts(key) WHERE resolved_at IS NULL;
"#;

/// v13 (Phase 13c, auto-protect): `inventory` = the guests the scheduler last
/// listed per source (PVE `/cluster/resources`, TrueNAS datasets, plugin
/// `ListGuests`), with tags (`pool:x`, `tag:y`, `node:n`, `type:qemu`, …);
/// guests no longer listed keep their row with `gone` set. `groups.mode`:
/// `explicit` (the `guests` list, as before), `all` (every inventory guest of the
/// source) or `tags` (guests with any tag in `selector`); `exclude` (guest ids)
/// always wins. See [`inventory`]. Purely additive: the previous release skips it
/// and treats every group as explicit (an `all`/`tags` group has `guests = []`
/// there: nothing to back up, a failed job and an alert).
const SCHEMA_V13: &str = r#"
CREATE TABLE IF NOT EXISTS inventory (
  source_id INTEGER NOT NULL REFERENCES sources(id) ON DELETE CASCADE, guest TEXT NOT NULL,
  name TEXT NOT NULL DEFAULT '', kind TEXT NOT NULL DEFAULT '', tags TEXT NOT NULL DEFAULT '[]',
  seen INTEGER NOT NULL, gone INTEGER, PRIMARY KEY (source_id, guest));
ALTER TABLE groups ADD COLUMN mode TEXT NOT NULL DEFAULT 'explicit' CHECK (mode IN ('explicit','all','tags'));
ALTER TABLE groups ADD COLUMN selector TEXT NOT NULL DEFAULT '[]';
ALTER TABLE groups ADD COLUMN exclude TEXT NOT NULL DEFAULT '[]';
"#;

/// v14 (Phase 13b, run control, docs/control-plane.md "Run control"):
/// `policies.retry` (`{count, delay_min}`), `policies.blackout`
/// (`[{days, from, to, abort}]`, evaluated in the group's time zone),
/// `policies.sla_minutes` (NULL = no run-time SLA); `groups.paused_until` and
/// `sources.maintenance_until` (NULL = active, unix time, -1 = indefinitely);
/// `groups.timezone` (IANA name the schedule is evaluated in); `jobs.not_before`
/// (retry delay), `jobs.attempt`, `jobs.retry_of` (first job of the chain),
/// `jobs.cancel_by` (cancel request of a running job: web-api writes it, the
/// scheduler stops the child and sets `cancelled`), `jobs.sla_alerted`.
/// Purely additive: the previous release skips it and never reads the columns.
const SCHEMA_V14: &str = r#"
ALTER TABLE policies ADD COLUMN retry TEXT NOT NULL DEFAULT '{"count":3,"delay_min":5}';
ALTER TABLE policies ADD COLUMN blackout TEXT NOT NULL DEFAULT '[]';
ALTER TABLE policies ADD COLUMN sla_minutes INTEGER;
ALTER TABLE groups ADD COLUMN paused_until INTEGER;
ALTER TABLE groups ADD COLUMN timezone TEXT NOT NULL DEFAULT 'UTC';
ALTER TABLE sources ADD COLUMN maintenance_until INTEGER;
ALTER TABLE jobs ADD COLUMN not_before INTEGER;
ALTER TABLE jobs ADD COLUMN attempt INTEGER NOT NULL DEFAULT 1;
ALTER TABLE jobs ADD COLUMN retry_of INTEGER;
ALTER TABLE jobs ADD COLUMN cancel_by TEXT;
ALTER TABLE jobs ADD COLUMN sla_alerted INTEGER NOT NULL DEFAULT 0;
"#;

/// v15 (Phase 14d, API tokens, docs/control-plane.md "API tokens"): one row per
/// token `nxt_<prefix>_<secret>`. `prefix` (8 hex) finds the row, `hash` is the
/// SHA-256 (hex) of the 256-bit random secret (high entropy: a plain hash is
/// enough, no password KDF needed); the secret itself is never stored.
/// `scope` caps what the token may do (`read` or `operator`, never more than
/// the owner's role), `expires` is mandatory (at most 365 days). Deleting the
/// user deletes their tokens. Purely additive.
const SCHEMA_V15: &str = r#"
CREATE TABLE IF NOT EXISTS api_tokens (
  id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name TEXT NOT NULL, prefix TEXT NOT NULL UNIQUE, hash TEXT NOT NULL,
  scope TEXT NOT NULL CHECK (scope IN ('read','operator')), expires INTEGER NOT NULL,
  created INTEGER NOT NULL, last_used INTEGER, last_ip TEXT, UNIQUE (user_id, name));
"#;

/// v16 (Phase 14a, forwarding, docs/control-plane.md "Forwarding"): the
/// forwarder follows `audit` by `seq`; alert and job events have no such
/// sequence (alert rows change, jobs finish out of id order), so triggers write
/// them to the outbox `forward_events` (strictly increasing `seq`, payload =
/// the row as JSON at that moment): alert raised / escalated / acknowledged /
/// resolved, job finished. `forward_state`: per sink (`syslog`, `https`) the
/// destination, the last delivered audit seq and event seq, and the delivery
/// status. Purely additive: the previous release skips it; the triggers keep
/// filling the outbox there (pruned again after the upgrade).
const SCHEMA_V16: &str = r#"
CREATE TABLE IF NOT EXISTS forward_events (
  seq INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL, type TEXT NOT NULL CHECK (type IN ('alert','job')),
  payload TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS forward_state (
  sink TEXT PRIMARY KEY, dest TEXT NOT NULL, audit_seq INTEGER NOT NULL DEFAULT 0, event_seq INTEGER NOT NULL DEFAULT 0,
  last_ok INTEGER, last_error TEXT, last_error_ts INTEGER, failing_since INTEGER);
CREATE TRIGGER IF NOT EXISTS forward_alert_raised AFTER INSERT ON alerts BEGIN
  INSERT INTO forward_events (ts, type, payload) VALUES (CAST(strftime('%s','now') AS INTEGER), 'alert',
    json_object('event','raised','id',NEW.id,'ts',NEW.ts,'severity',NEW.severity,'kind',NEW.kind,'key',NEW.key,
                'message',NEW.message,'tenant',NEW.tenant));
END;
CREATE TRIGGER IF NOT EXISTS forward_alert_escalated AFTER UPDATE OF severity ON alerts
  WHEN NEW.severity <> OLD.severity BEGIN
  INSERT INTO forward_events (ts, type, payload) VALUES (CAST(strftime('%s','now') AS INTEGER), 'alert',
    json_object('event','escalated','id',NEW.id,'ts',NEW.ts,'severity',NEW.severity,'kind',NEW.kind,'key',NEW.key,
                'message',NEW.message,'tenant',NEW.tenant,'count',NEW.count));
END;
CREATE TRIGGER IF NOT EXISTS forward_alert_acked AFTER UPDATE OF acked_by ON alerts
  WHEN OLD.acked_by IS NULL AND NEW.acked_by IS NOT NULL BEGIN
  INSERT INTO forward_events (ts, type, payload) VALUES (CAST(strftime('%s','now') AS INTEGER), 'alert',
    json_object('event','acknowledged','id',NEW.id,'ts',NEW.ts,'severity',NEW.severity,'kind',NEW.kind,'key',NEW.key,
                'message',NEW.message,'tenant',NEW.tenant,'by',NEW.acked_by));
END;
CREATE TRIGGER IF NOT EXISTS forward_alert_resolved AFTER UPDATE OF resolved_at ON alerts
  WHEN OLD.resolved_at IS NULL AND NEW.resolved_at IS NOT NULL BEGIN
  INSERT INTO forward_events (ts, type, payload) VALUES (CAST(strftime('%s','now') AS INTEGER), 'alert',
    json_object('event','resolved','id',NEW.id,'ts',NEW.ts,'severity',NEW.severity,'kind',NEW.kind,'key',NEW.key,
                'message',NEW.message,'tenant',NEW.tenant,'by',NEW.resolved_by,'auto',NEW.auto,'note',NEW.note,
                'count',NEW.count));
END;
CREATE TRIGGER IF NOT EXISTS forward_job_finished AFTER UPDATE OF state ON jobs
  WHEN NEW.state IN ('ok','failed','cancelled') AND OLD.state NOT IN ('ok','failed','cancelled') BEGIN
  INSERT INTO forward_events (ts, type, payload) VALUES (CAST(strftime('%s','now') AS INTEGER), 'job',
    json_object('id',NEW.id,'kind',NEW.kind,'tenant',NEW.tenant,'state',NEW.state,'requested_by',NEW.requested_by,
                'created',NEW.created,'started',NEW.started,'finished',NEW.finished,'attempt',NEW.attempt));
END;
"#;

/// v17 (Phase 14d, access, docs/control-plane.md "Access"): `users` rebuilt for a
/// wider role CHECK (`viewer`: read-only; `tenant_admin`: reserved for Phase 18c,
/// not accepted by the web-api yet) plus `can_download` (NULL = the role's
/// default, see [`access::role_can_download`]; 0/1 = set by an admin), `expires`
/// (no login from then on; NULL = never) and `last_login` (dormant accounts;
/// backfilled with the migration time for activated accounts, so that a later
/// `dormant_days` counts from the upgrade). `sessions` rebuilt with a numeric
/// `id` (listed and revoked by it; the cookie digest never leaves the server),
/// the client `ip` and `user_agent`. Same rebuild procedure as v4 (ids, rows and
/// constraints kept; foreign keys checked). `users` is never renamed away: a
/// rename would rewrite the `api_tokens` (v15) foreign key to the old name; the new
/// table is renamed to `users` instead, so `api_tokens.user_id` stays valid. The previous release skips it and
/// treats `viewer` accounts like unknown roles (every role check fails).
const SCHEMA_V17: &str = r#"
CREATE TABLE users_v17 (
  id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, totp_secret TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('admin','security_officer','operator','tenant_user','viewer','tenant_admin')),
  tenant TEXT, disabled INTEGER NOT NULL DEFAULT 0, created INTEGER NOT NULL,
  totp_last_step INTEGER NOT NULL DEFAULT 0, activation_hash TEXT, activation_expires INTEGER,
  auth TEXT NOT NULL DEFAULT 'local' CHECK (auth IN ('local','oidc')), oidc_sub TEXT,
  can_download INTEGER CHECK (can_download IN (0,1)), expires INTEGER, last_login INTEGER);
INSERT INTO users_v17 (id, name, password_hash, totp_secret, role, tenant, disabled, created, totp_last_step,
  activation_hash, activation_expires, auth, oidc_sub, last_login)
  SELECT id, name, password_hash, totp_secret, role, tenant, disabled, created, totp_last_step,
  activation_hash, activation_expires, auth, oidc_sub,
  CASE WHEN activation_hash IS NULL THEN CAST(strftime('%s', 'now') AS INTEGER) END FROM users;
CREATE TABLE sessions_v17 (
  id INTEGER PRIMARY KEY, id_hash TEXT NOT NULL UNIQUE, user_id INTEGER NOT NULL REFERENCES users(id),
  csrf TEXT NOT NULL, created INTEGER NOT NULL, last_seen INTEGER NOT NULL,
  ip TEXT NOT NULL DEFAULT '', user_agent TEXT NOT NULL DEFAULT '');
INSERT INTO sessions_v17 (id_hash, user_id, csrf, created, last_seen)
  SELECT id_hash, user_id, csrf, created, last_seen FROM sessions;
DROP TABLE sessions;
DROP TABLE users;
ALTER TABLE users_v17 RENAME TO users;
ALTER TABLE sessions_v17 RENAME TO sessions;
CREATE UNIQUE INDEX IF NOT EXISTS users_oidc_sub ON users(oidc_sub) WHERE oidc_sub IS NOT NULL;
CREATE INDEX IF NOT EXISTS sessions_user ON sessions(user_id);
"#;

/// v18 (Phase 15c, docs/control-plane.md "Legal hold"): one row per hold and
/// its history. `active` holds keep a snapshot from retention (local, orphan
/// sweep, offsite, replica), GC and `snapshot.delete` until a release is
/// approved (`released`). On a replication secondary, holds the primary reports
/// arrive as `advisory` rows (`origin` = the replication source): not applied
/// until a security officer applies them (→ `active`), `withdrawn` when the
/// primary no longer reports them. At most one open (`active`/`advisory`) row
/// per snapshot. The previous release ignores the table (no holds enforced).
const SCHEMA_V18: &str = r#"
CREATE TABLE legal_holds (
  id INTEGER PRIMARY KEY, tenant TEXT NOT NULL, source TEXT NOT NULL, time INTEGER NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('active','released','advisory','withdrawn')),
  reason TEXT NOT NULL, held_by TEXT NOT NULL, held_at INTEGER NOT NULL, origin TEXT,
  released_by TEXT, approved_by TEXT, released_at INTEGER);
CREATE UNIQUE INDEX legal_holds_open ON legal_holds(tenant, source, time) WHERE state IN ('active','advisory');
CREATE INDEX legal_holds_snapshot ON legal_holds(tenant, source, time);
"#;
/// v19 (Phase 15g, file index, docs/file-index.md): `groups.index_files` — after
/// each backup of the group, the files in its VM/CT disks are listed (restore
/// micro-VM / container tar) into the snapshot's sealed name index, so the file
/// search covers them. File-tree snapshots are always indexed. Purely additive.
const SCHEMA_V19: &str = "ALTER TABLE groups ADD COLUMN index_files INTEGER NOT NULL DEFAULT 0;";

/// v20 (Phase 15d, consistency, docs/control-plane.md "Consistency"):
/// `snapshots.consistency` (`application` = quiesced: guest-agent freeze, VSS
/// writers, hooks, or the guest was stopped; `crash` = point-in-time snapshot
/// without quiesce; `inconsistent` = read live; `unknown`; NULL = before v19 /
/// not recorded, e.g. replicated or offsite-only rows). Set by the scheduler from
/// the backup job's log. `policies.require_consistency` (JSON
/// `{"mode": "off"|"warn"|"fail", "level": "application"|"crash"}`). Purely
/// additive: the previous release skips both columns.
const SCHEMA_V20: &str = r#"
ALTER TABLE snapshots ADD COLUMN consistency TEXT
  CHECK (consistency IN ('application','crash','inconsistent','unknown'));
ALTER TABLE policies ADD COLUMN require_consistency TEXT NOT NULL DEFAULT '{"mode":"off","level":"crash"}';
"#;

/// v21 (Phase 15e/15f, disk/file selection and agents, docs/control-plane.md):
/// `groups.exclude_disks` (PVE: `{"*": ["scsi1"], "<vmid>": ["virtio2"]}`, disk
/// keys not backed up), `groups.exclude_disks_mode` (`placeholder`: a restore
/// recreates them empty with their size and config; `omit`: left out of the
/// restored config), `groups.parallel_guests` (1..=8 guests at once, PVE and
/// plugin groups); `policies.file_filters` (`{exclude, exclude_regex}` applied to
/// every file source of the policy's groups); `agents.cert_issued` /
/// `cert_expires` (validity of the current agent certificate, reported by every
/// session), `agents.cert_sha256_next` (a renewed certificate issued but not yet
/// confirmed: sessions accept either), `agents.limits` (`{bwlimit, nice}`, sent
/// with every backup). Purely additive: the previous release skips it and never
/// reads the columns (excluded disks are backed up again, guests run one by one).
const SCHEMA_V21: &str = r#"
ALTER TABLE groups ADD COLUMN exclude_disks TEXT NOT NULL DEFAULT '{}';
ALTER TABLE groups ADD COLUMN exclude_disks_mode TEXT NOT NULL DEFAULT 'placeholder'
  CHECK (exclude_disks_mode IN ('placeholder','omit'));
ALTER TABLE groups ADD COLUMN parallel_guests INTEGER NOT NULL DEFAULT 1 CHECK (parallel_guests BETWEEN 1 AND 8);
ALTER TABLE policies ADD COLUMN file_filters TEXT NOT NULL DEFAULT '{}';
ALTER TABLE agents ADD COLUMN cert_issued INTEGER;
ALTER TABLE agents ADD COLUMN cert_expires INTEGER;
ALTER TABLE agents ADD COLUMN cert_sha256_next TEXT;
ALTER TABLE agents ADD COLUMN limits TEXT NOT NULL DEFAULT '{}';
"#;

/// v22 (Phase 17f, tenant deactivation, docs/control-plane.md "Tenant
/// deactivation"): `tenants.disabled` (+ when, by whom, why). A deactivated
/// tenant takes no backups, offsite copies or replication syncs, its accounts
/// and their API tokens are refused, its alerts are suppressed (one info
/// `tenant_disabled`); retention keeps running. Purely additive: the previous
/// release ignores the columns (the tenant runs again).
const SCHEMA_V22: &str = r#"
ALTER TABLE tenants ADD COLUMN disabled INTEGER NOT NULL DEFAULT 0 CHECK (disabled IN (0, 1));
ALTER TABLE tenants ADD COLUMN disabled_at INTEGER;
ALTER TABLE tenants ADD COLUMN disabled_by TEXT;
ALTER TABLE tenants ADD COLUMN disabled_reason TEXT;
"#;

/// v23 (Phase 18b): `snapshots.meta` — the plugin's snapshot metadata (protocol
/// v1.8 `SnapshotMeta`, a JSON object, e.g. PostgreSQL's recoverable range), set
/// from the backup job's result. Generic: any plugin may use it. Additive (the
/// previous release never reads it; the snapshot refresh keeps it).
const SCHEMA_V23: &str = "ALTER TABLE snapshots ADD COLUMN meta TEXT;";

/// v24 (Phase 17a/b, docs/replication.md "Windows and closing the vault"):
/// `replication_sources.windows` (bandwidth windows `[{days, from, to, action:
/// pause|limit, rate_bytes?}]`), `sync_window` (`[{days, from, to}]`: syncs and the
/// firewall target only inside; empty = always), `timezone` (of both, IANA),
/// `closed_until` ("close vault now": NULL = open, -1 = until reopened, else a
/// unix time), `closed_by` / `closed_at`. Purely additive: the previous release
/// skips the columns (it would sync around the clock again).
const SCHEMA_V24: &str = r#"
ALTER TABLE replication_sources ADD COLUMN windows TEXT NOT NULL DEFAULT '[]';
ALTER TABLE replication_sources ADD COLUMN sync_window TEXT NOT NULL DEFAULT '[]';
ALTER TABLE replication_sources ADD COLUMN timezone TEXT NOT NULL DEFAULT 'UTC';
ALTER TABLE replication_sources ADD COLUMN closed_until INTEGER;
ALTER TABLE replication_sources ADD COLUMN closed_by TEXT;
ALTER TABLE replication_sources ADD COLUMN closed_at INTEGER;
"#;

/// v25 (Phase 19b, tenant admins, docs/control-plane.md "Tenant admins"):
/// `tenant_policies` (the policies the provider assigned to a tenant: a
/// tenant_admin's groups use only these), `policies.tier` (bronze / silver /
/// gold from the templates, shown in SLA reports), `tenants.uid` (random
/// 128 bit, set once by a trigger for every new row, backfilled here; name and
/// uid are immutable: DEK labels, AADs and escrow paths stay bound to the name),
/// `tenant_tombstones` (deleted names are never handed out again),
/// `sessions.impersonating` / `impersonating_role` ("view as tenant") and
/// `audit_tenants` (the tenant an audit entry concerns, beside the hash chain:
/// the chain format is unchanged; backfilled from `details.tenant` and
/// `tenant/<name>` targets). The previous release ignores all of it (renames are
/// impossible there too; a deleted name could be re-created).
const SCHEMA_V25: &str = r#"
CREATE TABLE tenant_policies (
  tenant TEXT NOT NULL REFERENCES tenants(name), policy_id INTEGER NOT NULL REFERENCES policies(id),
  PRIMARY KEY (tenant, policy_id));
ALTER TABLE policies ADD COLUMN tier TEXT CHECK (tier IN ('bronze','silver','gold'));
ALTER TABLE tenants ADD COLUMN uid TEXT;
UPDATE tenants SET uid = lower(hex(randomblob(16))) WHERE uid IS NULL;
CREATE UNIQUE INDEX tenants_uid ON tenants(uid);
CREATE TRIGGER tenants_uid_new AFTER INSERT ON tenants WHEN NEW.uid IS NULL
  BEGIN UPDATE tenants SET uid = lower(hex(randomblob(16))) WHERE name = NEW.name; END;
CREATE TRIGGER tenants_immutable BEFORE UPDATE OF name, uid ON tenants
  WHEN OLD.uid IS NOT NULL AND (NEW.name IS NOT OLD.name OR NEW.uid IS NOT OLD.uid)
  BEGIN SELECT RAISE(ABORT, 'tenant name and uid are immutable'); END;
CREATE TABLE tenant_tombstones (
  name TEXT PRIMARY KEY, uid TEXT, deleted_at INTEGER NOT NULL, deleted_by TEXT NOT NULL);
ALTER TABLE sessions ADD COLUMN impersonating TEXT;
ALTER TABLE sessions ADD COLUMN impersonating_role TEXT CHECK (impersonating_role IN ('viewer','tenant_admin'));
CREATE TABLE audit_tenants (seq INTEGER PRIMARY KEY, tenant TEXT NOT NULL);
CREATE INDEX audit_tenants_tenant ON audit_tenants(tenant, seq);
INSERT INTO audit_tenants (seq, tenant)
  SELECT seq, t FROM (SELECT seq, COALESCE(
      CASE WHEN json_valid(details) AND json_type(details, '$.tenant') = 'text' THEN json_extract(details, '$.tenant') END,
      CASE WHEN target LIKE 'tenant/%' THEN substr(target, 8) END) AS t FROM audit)
  WHERE t IS NOT NULL;
"#;

/// v26 (Phase 24a, docs/endpoint-ui.md): endpoint status of the agents.
/// `agents.reachable` (last poll answered: 1/0, NULL = never polled), `last_poll`,
/// `poll_failures` (consecutive, for the backoff), `power` (`{on_battery,
/// battery_percent, metered, network_name}` from the last `PollReply`),
/// `ui_policy` (`{accent, header, hide_backup_now, hide_tray}`) with
/// `ui_policy_version` (bumped on change) and `ui_policy_seen` (version the agent
/// stored), `laptop` (`{min_battery, skip_metered, run_missed, retry_hours}`),
/// `missed_at` (a scheduled run was skipped or failed; queued again when the
/// agent is reachable and fit, within `retry_hours`), `last_request` (`{id,
/// queued_at, received, jobs}` of the last "back up now" request from the
/// endpoint). `agent_sessions`: one summary per (agent, job) for the endpoint UI,
/// `delivered` once the agent acknowledged it. Purely additive: the previous
/// release ignores the columns and the table.
const SCHEMA_V26: &str = r#"
ALTER TABLE agents ADD COLUMN reachable INTEGER;
ALTER TABLE agents ADD COLUMN last_poll INTEGER;
ALTER TABLE agents ADD COLUMN poll_failures INTEGER NOT NULL DEFAULT 0;
ALTER TABLE agents ADD COLUMN power TEXT;
ALTER TABLE agents ADD COLUMN ui_policy TEXT NOT NULL DEFAULT '{}';
ALTER TABLE agents ADD COLUMN ui_policy_version INTEGER NOT NULL DEFAULT 0;
ALTER TABLE agents ADD COLUMN ui_policy_seen INTEGER;
ALTER TABLE agents ADD COLUMN laptop TEXT NOT NULL DEFAULT '{}';
ALTER TABLE agents ADD COLUMN missed_at INTEGER;
ALTER TABLE agents ADD COLUMN last_request TEXT;
CREATE TABLE agent_sessions (
  agent_id TEXT NOT NULL, job_id INTEGER NOT NULL, tenant TEXT NOT NULL, summary TEXT NOT NULL,
  created INTEGER NOT NULL, delivered INTEGER, PRIMARY KEY (agent_id, job_id));
CREATE INDEX agent_sessions_pending ON agent_sessions(agent_id) WHERE delivered IS NULL;
"#;

/// v27 (Phase 24d, fleet enrollment, `catalog::fleet`): `fleets` (reusable,
/// time-limited fleet secrets: digest sealed to the scheduler, expiry, max uses,
/// auto-accept, agent port, address ranges to scan, default template group and
/// hostname rules, revocation), `fleet_candidates` (agents a scan found awaiting
/// enrollment: endpoint, reported hostname / OS / version, decision) and
/// `agents.fleet_id` (enrolled with that fleet's secret instead of a token).
/// Purely additive: the previous release ignores the tables and the column.
const SCHEMA_V27: &str = r#"
CREATE TABLE fleets (
  id TEXT PRIMARY KEY, tenant TEXT NOT NULL REFERENCES tenants(name), name TEXT NOT NULL,
  secret_hash TEXT NOT NULL, created INTEGER NOT NULL, created_by TEXT NOT NULL, expires INTEGER NOT NULL,
  max_uses INTEGER, uses INTEGER NOT NULL DEFAULT 0, revoked INTEGER NOT NULL DEFAULT 0,
  auto_accept INTEGER NOT NULL DEFAULT 0, port INTEGER NOT NULL, ranges TEXT NOT NULL DEFAULT '[]',
  default_group TEXT, group_rules TEXT NOT NULL DEFAULT '[]', last_scan INTEGER);
CREATE TABLE fleet_candidates (
  id INTEGER PRIMARY KEY, fleet_id TEXT NOT NULL REFERENCES fleets(id), host TEXT NOT NULL, port INTEGER NOT NULL,
  hostname TEXT NOT NULL, os TEXT NOT NULL, version TEXT NOT NULL, first_seen INTEGER NOT NULL,
  last_seen INTEGER NOT NULL,
  state TEXT NOT NULL DEFAULT 'awaiting' CHECK (state IN ('awaiting','accepted','rejected')),
  agent_id TEXT, decided_by TEXT, UNIQUE (fleet_id, host, port));
ALTER TABLE agents ADD COLUMN fleet_id TEXT;
"#;

/// v28 (Phase 21a, docs/ransomware-signals.md): the anomaly flag of a
/// snapshot (`snapshots.anomaly` = the reasons, NULL = clean; set by the
/// scheduler's change-rate and file-level checks; a security officer clears it
/// with a note: `anomaly_cleared_by/_at`, `anomaly_note`, the reason stays) and
/// the file-level change counts of a backup against the previous snapshot
/// (`backup_stats.files_added/_changed/_deleted`, NULL = not computed: no name
/// index). Purely additive: the previous release ignores the columns.
const SCHEMA_V28: &str = r#"
ALTER TABLE snapshots ADD COLUMN anomaly TEXT;
ALTER TABLE snapshots ADD COLUMN anomaly_at INTEGER;
ALTER TABLE snapshots ADD COLUMN anomaly_cleared_by TEXT;
ALTER TABLE snapshots ADD COLUMN anomaly_cleared_at INTEGER;
ALTER TABLE snapshots ADD COLUMN anomaly_note TEXT;
ALTER TABLE backup_stats ADD COLUMN files_added INTEGER;
ALTER TABLE backup_stats ADD COLUMN files_changed INTEGER;
ALTER TABLE backup_stats ADD COLUMN files_deleted INTEGER;
"#;

/// v31 (Phase 21c, passkeys, docs/control-plane.md "Passkeys"): `passkeys`
/// holds the WebAuthn credentials registered as a second factor: credential id
/// (base64url, unique appliance-wide), COSE algorithm (-7 ES256, -8 EdDSA), the
/// raw public key (uncompressed P-256 point or Ed25519 key), the relying party ID
/// it was registered for and the signature counter. Purely additive: the
/// previous release ignores the table (passkey users sign in with TOTP there).
const SCHEMA_V31: &str = r#"
CREATE TABLE passkeys (
  id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  cred_id TEXT NOT NULL UNIQUE, name TEXT NOT NULL, alg INTEGER NOT NULL CHECK (alg IN (-7, -8)),
  public_key BLOB NOT NULL, rp_id TEXT NOT NULL, sign_count INTEGER NOT NULL DEFAULT 0,
  created INTEGER NOT NULL, last_used INTEGER);
CREATE INDEX passkeys_user ON passkeys(user_id);
"#;

/// v29 (Phase 19a, docs/bmr.md): `rescue_sessions` — bare-metal recovery / P2V of a
/// Linux agent's host. `id` is the rescue agent's temporary agent id; `lookup` the
/// public lookup key of the one-time recovery token (`agent_proto::rescue_lookup`);
/// `token_hash` its digest sealed to the scheduler (NULL once the rescue agent is
/// enrolled); `state` issued → waiting (checked in) → running → done | failed |
/// cancelled | expired; `host`/`port`/`disks` from the rescue console's check-in;
/// `snapshot_time` the chosen snapshot; `p2v` the PVE VM parameters (NULL = bare
/// metal). Purely additive: the previous release never reads it. (v30 is reserved; ordered before v31.)
const SCHEMA_V29: &str = r#"
CREATE TABLE rescue_sessions (
    id            TEXT PRIMARY KEY,
    tenant        TEXT NOT NULL,
    agent_id      TEXT NOT NULL,
    lookup        TEXT NOT NULL UNIQUE,
    token_hash    TEXT,
    token_expires INTEGER NOT NULL,
    state         TEXT NOT NULL DEFAULT 'issued',
    host          TEXT,
    port          INTEGER,
    disks         TEXT NOT NULL DEFAULT '[]',
    checked_in    INTEGER,
    cert_sha256   TEXT,
    snapshot_time INTEGER,
    reboot        INTEGER NOT NULL DEFAULT 1,
    step          TEXT,
    job_id        INTEGER,
    p2v           TEXT,
    message       TEXT,
    created       INTEGER NOT NULL,
    created_by    TEXT NOT NULL
);
CREATE INDEX rescue_sessions_agent ON rescue_sessions (agent_id);
"#;

/// v32 (Phase 21d, health check with repair): snapshots that reference chunks
/// which failed verify (`damaged` = number of distinct bad chunks, NULL =
/// healthy; `damaged_at` = first detection). Set and cleared by the scheduler
/// after verify and `chunk_repair` jobs. Purely additive.
const SCHEMA_V32: &str = r#"
ALTER TABLE snapshots ADD COLUMN damaged INTEGER;
ALTER TABLE snapshots ADD COLUMN damaged_at INTEGER;
"#;

/// v33 (Phase 21e, docs/malware-scan.md): the opt-in YARA scan. `yara_rules`
/// (admin-supplied rule files, appliance-wide, no feed: name, text, sha256,
/// uploader) and `snapshot_scans` (one row per finished `snapshot_scan` job:
/// counts, `complete` = within the time budget, `matches` = `[{rule, path}]`
/// (at most 1000 kept, `matches_total` counts all), `rules` = sha256 over the
/// rule set used). A hit also sets `snapshots.anomaly` (v28). Purely additive:
/// the previous release ignores both tables.
const SCHEMA_V33: &str = r#"
CREATE TABLE yara_rules (
  name TEXT PRIMARY KEY, text TEXT NOT NULL, sha256 TEXT NOT NULL,
  uploaded_by TEXT NOT NULL, uploaded_at INTEGER NOT NULL);
CREATE TABLE snapshot_scans (
  job_id INTEGER PRIMARY KEY, tenant TEXT NOT NULL, source TEXT NOT NULL, time INTEGER NOT NULL,
  finished INTEGER NOT NULL, rules TEXT NOT NULL, files INTEGER NOT NULL, skipped INTEGER NOT NULL,
  errors INTEGER NOT NULL, complete INTEGER NOT NULL, matches_total INTEGER NOT NULL,
  matches TEXT NOT NULL DEFAULT '[]');
CREATE INDEX snapshot_scans_snapshot ON snapshot_scans(tenant, source, time);
"#;

/// v34 (Phase 25, docs/control-plane.md "Restore tests and recovery plans"):
/// `restore_tests` (one row per tested guest snapshot: passed / failed /
/// cancelled / skipped, the checks as JSON, the job and the recovery run it
/// belonged to), `restore_test_schedules` (per PVE group: test the newest
/// snapshot of each guest every N days on a node / storage, isolated bridge,
/// checks), `recovery_plans` (ordered guests in waves with delays and checks,
/// target node / storage, test bridge, network map for a real execution, RPO,
/// the last readiness check) and `recovery_runs` (test runs and approved
/// executions with the plan as run and the per-guest results; kept when the
/// plan is deleted: the DR report). Purely additive.
const SCHEMA_V34: &str = r#"
CREATE TABLE restore_tests (
  id INTEGER PRIMARY KEY, tenant TEXT NOT NULL, source TEXT NOT NULL, time INTEGER NOT NULL,
  job_id INTEGER NOT NULL, run_id INTEGER,
  state TEXT NOT NULL CHECK (state IN ('passed','failed','cancelled','skipped')),
  started INTEGER NOT NULL, finished INTEGER NOT NULL, details TEXT NOT NULL DEFAULT '{}',
  UNIQUE (job_id, source));
CREATE INDEX restore_tests_source ON restore_tests(tenant, source, finished);
CREATE TABLE restore_test_schedules (
  group_id INTEGER PRIMARY KEY REFERENCES groups(id) ON DELETE CASCADE,
  every_days INTEGER NOT NULL CHECK (every_days BETWEEN 1 AND 365), node TEXT NOT NULL, storage TEXT NOT NULL,
  bridge TEXT, checks TEXT NOT NULL DEFAULT '{}', last_run INTEGER);
CREATE TABLE recovery_plans (
  id INTEGER PRIMARY KEY, tenant TEXT NOT NULL REFERENCES tenants(name), name TEXT NOT NULL,
  source_id INTEGER NOT NULL REFERENCES sources(id), node TEXT NOT NULL, storage TEXT NOT NULL,
  test_bridge TEXT, network_map TEXT NOT NULL DEFAULT '{}', steps TEXT NOT NULL DEFAULT '[]',
  rpo_hours INTEGER NOT NULL DEFAULT 24, readiness TEXT, readiness_at INTEGER,
  created INTEGER NOT NULL, created_by TEXT NOT NULL, UNIQUE (tenant, name));
CREATE TABLE recovery_runs (
  id INTEGER PRIMARY KEY, plan_id INTEGER NOT NULL, tenant TEXT NOT NULL,
  mode TEXT NOT NULL CHECK (mode IN ('test','execute')),
  state TEXT NOT NULL DEFAULT 'running' CHECK (state IN ('running','passed','failed','cancelled')),
  requested_by TEXT NOT NULL, quorum_id INTEGER, job_id INTEGER, plan TEXT NOT NULL,
  results TEXT NOT NULL DEFAULT '[]', started INTEGER NOT NULL, finished INTEGER);
CREATE INDEX recovery_runs_plan ON recovery_runs(plan_id, id);
"#;

/// v37 (Phase 23a, service-provider operations): `tenant_idps` — a tenant's own
/// OIDC identity provider (`settings` = the same JSON as the appliance-wide
/// `settings.oidc`, mappings limited to tenant roles of this tenant; `domains` =
/// e-mail domains whose users the login page sends to it; `endpoints` = token
/// and JWKS endpoints of the last discovery, for the firewall allow-list), and
/// `capacity_samples.offsite` (logical bytes of the tenant's snapshots with an
/// offsite copy that day, for the monthly usage export; NULL = not sampled).
/// Purely additive: the previous release ignores both.
const SCHEMA_V37: &str = r#"
CREATE TABLE tenant_idps (
  tenant TEXT PRIMARY KEY REFERENCES tenants(name), settings TEXT NOT NULL,
  domains TEXT NOT NULL DEFAULT '[]', endpoints TEXT);
ALTER TABLE capacity_samples ADD COLUMN offsite INTEGER;
"#;

/// v39 (Phase 26, docs/edge.md): edge proxies for roaming agents. `edges`
/// (appliance-wide, admin-managed): the control address the appliance dials
/// (`host:port`), the public address agents dial (`public_host:public_port`), the
/// pinned edge certificate after enrollment, the sealed one-time enrollment token
/// (location `catalog::secret::edge_token_location`), and what the control link
/// reports (`last_seen`, `version`, `health` JSON, `log` = JSON array of the newest
/// lines). Per agent: `edge_id` (reach via this edge; direct first, then the edge),
/// `via` (route of the last successful session: `direct` | `edge`) and
/// `edge_pushed` (edge setting the agent confirmed with `EdgeSet`, protocol v1.7).
/// Purely additive: the previous release ignores the table and the columns.
const SCHEMA_V39: &str = r#"
CREATE TABLE edges (
  id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE,
  host TEXT NOT NULL, port INTEGER NOT NULL DEFAULT 7445,
  public_host TEXT NOT NULL, public_port INTEGER NOT NULL DEFAULT 443,
  cert_sha256 TEXT, token_hash TEXT, token_expires INTEGER, enrolled_at INTEGER,
  last_seen INTEGER, version TEXT, health TEXT, log TEXT,
  created INTEGER NOT NULL, created_by TEXT NOT NULL);
ALTER TABLE agents ADD COLUMN edge_id TEXT;
ALTER TABLE agents ADD COLUMN via TEXT;
ALTER TABLE agents ADD COLUMN edge_pushed TEXT;
"#;

/// v40 (live job progress, docs/control-plane.md "Live progress"): while a
/// job runs, the scheduler writes its output so far to `jobs.live_log` and the
/// aggregated `progress {json}` lines of the connector to `jobs.progress`
/// (about every 2 s). The final output is appended to `jobs.log` as before and
/// both columns are cleared when the job ends. Purely additive: the previous
/// release ignores them (and shows the log only at the end).
const SCHEMA_V40: &str = r#"
ALTER TABLE jobs ADD COLUMN live_log TEXT;
ALTER TABLE jobs ADD COLUMN progress TEXT;
"#;

/// v43 (Phase 28, docs/commvault-comparison.md Tier 1):
/// - scheduled threat scans: `groups.scan_schedule` (schedule grammar of the
///   policies, NULL = off; the newest local snapshot of each of the group's
///   sources gets a `snapshot_scan` when due) and `groups.scan_budget_min`
///   (NULL = the scanner's default); `snapshots.scan_state` = the verdict of the
///   newest finished YARA scan (`clean` | `hit` | `incomplete`, NULL = unscanned),
///   filled from `snapshot_scans` here;
/// - IOC hash hunting: `groups.file_hashes` (record SHA-256 per file in the name
///   index) and `hash_lists` (uploaded IOC lists, appliance-wide: normalised
///   lower-case hex, one per line);
/// - tenant lockdown: `tenant_lockdowns` (one row per tenant, the lockdown as
///   JSON, `active`);
/// - new-device sign-in notice: `login_devices` (account, fingerprint of
///   user-agent family + client network prefix) and `users.email` (where the
///   notice is mailed; from the profile or the OIDC `email` claim).
///
/// Purely additive: the previous release ignores the columns and tables.
const SCHEMA_V43: &str = r#"
ALTER TABLE groups ADD COLUMN scan_schedule TEXT;
ALTER TABLE groups ADD COLUMN scan_budget_min INTEGER;
ALTER TABLE groups ADD COLUMN file_hashes INTEGER NOT NULL DEFAULT 0;
ALTER TABLE snapshots ADD COLUMN scan_state TEXT;
UPDATE snapshots SET scan_state = (
  SELECT CASE WHEN x.matches_total > 0 THEN 'hit' WHEN x.complete = 1 THEN 'clean' ELSE 'incomplete' END
  FROM snapshot_scans x WHERE x.tenant = snapshots.tenant AND x.source = snapshots.source
    AND x.time = snapshots.time ORDER BY x.job_id DESC LIMIT 1);
CREATE TABLE hash_lists (
  name TEXT PRIMARY KEY, hashes TEXT NOT NULL, count INTEGER NOT NULL, sha256 TEXT NOT NULL,
  uploaded_by TEXT NOT NULL, uploaded_at INTEGER NOT NULL);
CREATE TABLE tenant_lockdowns (
  tenant TEXT PRIMARY KEY, active INTEGER NOT NULL, state TEXT NOT NULL);
CREATE TABLE login_devices (
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, fingerprint TEXT NOT NULL,
  family TEXT NOT NULL, prefix TEXT NOT NULL, first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL,
  PRIMARY KEY (user_id, fingerprint));
ALTER TABLE users ADD COLUMN email TEXT;
"#;

const MIGRATIONS: &[&str] = &[
    SCHEMA_V1, SCHEMA_V2, SCHEMA_V3, SCHEMA_V4, SCHEMA_V5, SCHEMA_V6, SCHEMA_V7, SCHEMA_V8, SCHEMA_V9, SCHEMA_V10,
    SCHEMA_V11, SCHEMA_V12, SCHEMA_V13, SCHEMA_V14, SCHEMA_V15, SCHEMA_V16, SCHEMA_V17, SCHEMA_V18, SCHEMA_V19,
    SCHEMA_V20, SCHEMA_V21, SCHEMA_V22, SCHEMA_V23, SCHEMA_V24, SCHEMA_V25, SCHEMA_V26, SCHEMA_V27, SCHEMA_V28,
    SCHEMA_V29, SCHEMA_V31, SCHEMA_V32, SCHEMA_V33, SCHEMA_V34, SCHEMA_V37, SCHEMA_V39, SCHEMA_V40, SCHEMA_V43,
];

/// Placeholder password hash of accounts without a password (pending
/// activation): not a PHC string, so no password ever verifies against it.
pub const NO_PASSWORD: &str = "!pending-activation";

/// Placeholder password hash of OIDC accounts (v10): they never log in locally.
pub const OIDC_PASSWORD: &str = "!oidc";

/// Appliance setting (v9 `settings`).
pub fn setting(c: &Connection, key: &str) -> rusqlite::Result<Option<String>> {
    c.query_row("SELECT value FROM settings WHERE key = ?1", [key], |r| r.get(0))
        .optional()
}

pub fn set_setting(c: &Connection, key: &str, value: &str) -> rusqlite::Result<()> {
    c.execute(
        "INSERT INTO settings (key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        params![key, value],
    )?;
    Ok(())
}

/// Whether quorum approvals are on. A missing row counts as on (fail safe).
pub fn approvals_enabled(c: &Connection) -> rusqlite::Result<bool> {
    Ok(setting(c, "approvals_enabled")?.is_none_or(|v| v != "false"))
}

/// Users who could approve a quorum request: enabled, activated, unexpired
/// admins and security officers.
pub fn possible_approvers(c: &Connection) -> rusqlite::Result<Vec<String>> {
    c.prepare(
        "SELECT name FROM users WHERE role IN ('admin','security_officer') AND disabled = 0
         AND activation_hash IS NULL AND (expires IS NULL OR expires > ?1) ORDER BY name",
    )?
    .query_map([now()], |r| r.get(0))?
    .collect()
}

pub fn now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64
}

fn chain_hash(prev: &str, seq: i64, ts: i64, actor: &str, action: &str, target: &str, details: &str) -> String {
    let mut h = Sha256::new();
    for part in [prev, &seq.to_string(), &ts.to_string(), actor, action, target, details] {
        h.update((part.len() as u64).to_le_bytes()); // length-prefixed: no ambiguity between fields
        h.update(part.as_bytes());
    }
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

pub struct Catalog {
    conn: Mutex<Connection>,
}

impl Catalog {
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "FULL")?;
        conn.busy_timeout(std::time::Duration::from_secs(10))?;
        // Migrations may rebuild tables (SQLite's 12-step ALTER procedure): foreign
        // keys off while they run (the pragma is a no-op inside a transaction),
        // integrity checked with foreign_key_check before each commit.
        conn.pragma_update(None, "foreign_keys", "OFF")?;
        let version: i64 = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
        for (i, m) in MIGRATIONS.iter().enumerate().skip(version as usize) {
            let tx = conn.unchecked_transaction()?;
            tx.execute_batch(m)?;
            let broken: i64 = tx.query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |r| r.get(0))?;
            if broken > 0 {
                bail!(
                    "catalog migration {} would break {broken} foreign key references",
                    i + 1
                );
            }
            tx.pragma_update(None, "user_version", (i + 1) as i64)?;
            tx.commit()?;
        }
        conn.pragma_update(None, "foreign_keys", "ON")?;
        Ok(Catalog { conn: Mutex::new(conn) })
    }

    pub fn open_memory() -> Result<Self> {
        let c = Catalog {
            conn: Mutex::new(Connection::open_in_memory()?),
        };
        for m in MIGRATIONS {
            c.conn().execute_batch(m)?;
        }
        Ok(c)
    }

    /// Exclusive access for queries. Keep critical sections short.
    pub fn conn(&self) -> MutexGuard<'_, Connection> {
        self.conn.lock().unwrap()
    }

    /// Appends one audit entry inside its own IMMEDIATE transaction (serialises
    /// writers across processes) and logs it to syslog via stderr/journal.
    pub fn audit(&self, actor: &str, action: &str, target: &str, details: &serde_json::Value) -> Result<i64> {
        let mut c = self.conn();
        let tx = c.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let (seq, prev): (i64, String) = tx
            .query_row("SELECT seq, hash FROM audit ORDER BY seq DESC LIMIT 1", [], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .optional()?
            .unwrap_or((0, "0".repeat(64)));
        let (seq, ts, details) = (seq + 1, now(), details.to_string());
        let hash = chain_hash(&prev, seq, ts, actor, action, target, &details);
        tx.execute(
            "INSERT INTO audit (seq, ts, actor, action, target, details, prev_hash, hash) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
            params![seq, ts, actor, action, target, details, prev, hash],
        )?;
        if let Some(t) = tenancy::audit_tenant(&tx, actor, target, &details)? {
            tx.execute(
                "INSERT INTO audit_tenants (seq, tenant) VALUES (?1, ?2)",
                params![seq, t],
            )?;
        }
        tx.commit()?;
        // ponytail: journald picks this up and forwards it (rsyslog/TLS configured in the OS image)
        eprintln!("<6>nexus-audit seq={seq} actor={actor} action={action} target={target} hash={hash}");
        Ok(seq)
    }

    /// Recomputes the whole chain; returns the number of entries or the first broken seq.
    pub fn verify_audit(&self) -> Result<i64> {
        let c = self.conn();
        let mut stmt =
            c.prepare("SELECT seq, ts, actor, action, target, details, prev_hash, hash FROM audit ORDER BY seq")?;
        let mut rows = stmt.query([])?;
        let (mut prev, mut expect) = ("0".repeat(64), 1i64);
        while let Some(r) = rows.next()? {
            let (seq, ts): (i64, i64) = (r.get(0)?, r.get(1)?);
            let (actor, action, target, details): (String, String, String, String) =
                (r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?);
            let (p, h): (String, String) = (r.get(6)?, r.get(7)?);
            if seq != expect || p != prev || h != chain_hash(&prev, seq, ts, &actor, &action, &target, &details) {
                bail!("audit chain broken at seq {seq}");
            }
            prev = h;
            expect += 1;
        }
        Ok(expect - 1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn migrates_and_reopens() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("c.db");
        Catalog::open(&p)
            .unwrap()
            .audit("setup", "init", "-", &json!({}))
            .unwrap();
        let c = Catalog::open(&p).unwrap();
        assert_eq!(c.verify_audit().unwrap(), 1);
        let v: i64 = c.conn().pragma_query_value(None, "user_version", |r| r.get(0)).unwrap();
        assert_eq!(v, MIGRATIONS.len() as i64);
    }

    /// v4 rebuilds `sources` (wider kind CHECK): rows, ids, foreign keys and
    /// constraints survive; linux sources and agents become possible.
    #[test]
    fn migration_v4_keeps_pve_sources() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("c.db");
        {
            // a v3 catalog as the previous release left it
            let c = Connection::open(&p).unwrap();
            c.pragma_update(None, "foreign_keys", "ON").unwrap();
            for (i, m) in MIGRATIONS[..3].iter().enumerate() {
                c.execute_batch(m).unwrap();
                c.pragma_update(None, "user_version", (i + 1) as i64).unwrap();
            }
            c.execute_batch(
                r#"INSERT INTO tenants (name) VALUES ('acme');
                 INSERT INTO sources (id, tenant, kind, name, config) VALUES (7, 'acme', 'pve', 'cluster', '{"host":"pve1"}');
                 INSERT INTO policies (id, name, schedule, gfs) VALUES (1, 'p', 'daily 22:00', '{}');
                 INSERT INTO groups (id, tenant, source_id, policy_id, name, guests) VALUES (3, 'acme', 7, 1, 'g', '[100]');"#,
            )
            .unwrap();
            assert!(c
                .execute(
                    "INSERT INTO sources (tenant, kind, name, config) VALUES ('acme', 'linux', 'x', '{}')",
                    []
                )
                .is_err());
        }
        let c = Catalog::open(&p).unwrap();
        let v: i64 = c.conn().pragma_query_value(None, "user_version", |r| r.get(0)).unwrap();
        assert_eq!(v, MIGRATIONS.len() as i64);
        let fk: i64 = c.conn().pragma_query_value(None, "foreign_keys", |r| r.get(0)).unwrap();
        assert_eq!(fk, 1, "foreign keys back on");
        let row: (i64, String, String, String) = c
            .conn()
            .query_row("SELECT id, kind, name, config FROM sources", [], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
            })
            .unwrap();
        assert_eq!(row, (7, "pve".into(), "cluster".into(), r#"{"host":"pve1"}"#.into()));
        let conn = c.conn();
        // the group still references source 7: deleting a referenced source is refused
        assert!(conn.execute("DELETE FROM sources WHERE id = 7", []).is_err());
        conn.execute(
            "INSERT INTO sources (tenant, kind, name, config) VALUES ('acme', 'linux', 'web01', '{}')",
            [],
        )
        .unwrap();
        let ins = |sql: &str| conn.execute(sql, []).is_err();
        assert!(ins(
            "INSERT INTO sources (tenant, kind, name, config) VALUES ('acme', 'esx', 'e', '{}')"
        ));
        assert!(
            ins("INSERT INTO sources (tenant, kind, name, config) VALUES ('acme', 'pve', 'cluster', '{}')"),
            "UNIQUE (tenant, name) kept"
        );
        assert!(
            ins("INSERT INTO sources (tenant, kind, name, config) VALUES ('nope', 'pve', 'n', '{}')"),
            "tenant foreign key kept"
        );
        assert!(!ins(
            "INSERT INTO agents (id, tenant, name, host, port) VALUES ('0123456789abcdef', 'acme', 'web01', 'h', 7444)"
        ));
        assert!(ins(
            "INSERT INTO agents (id, tenant, name, host, port) VALUES ('x', 'nope', 'a', 'h', 1)"
        ));
        let sql: String = conn
            .query_row("SELECT sql FROM sqlite_master WHERE name = 'groups'", [], |r| r.get(0))
            .unwrap();
        assert!(sql.contains("REFERENCES sources(id)"), "{sql}");
        drop(conn);
        drop(c);
        // the previous release (3 migrations) runs none on the v4 file and can read it
        let old = Connection::open(&p).unwrap();
        let v: i64 = old.pragma_query_value(None, "user_version", |r| r.get(0)).unwrap();
        assert_eq!(MIGRATIONS[..3].iter().skip(v as usize).count(), 0);
        let n: i64 = old
            .query_row(
                "SELECT COUNT(*) FROM sources s JOIN groups g ON g.source_id = s.id",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(n, 1);
    }

    /// v5 rebuilds `sources` again (kind `truenas`): pve + linux rows, ids and
    /// references survive; the previous release (4 migrations) can still read the file.
    #[test]
    fn migration_v5_adds_truenas_sources() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("c.db");
        {
            let c = Connection::open(&p).unwrap();
            c.pragma_update(None, "foreign_keys", "ON").unwrap();
            for (i, m) in MIGRATIONS[..4].iter().enumerate() {
                c.execute_batch(m).unwrap();
                c.pragma_update(None, "user_version", (i + 1) as i64).unwrap();
            }
            c.execute_batch(
                r#"INSERT INTO tenants (name) VALUES ('acme');
                 INSERT INTO sources (id, tenant, kind, name, config) VALUES (7, 'acme', 'pve', 'cluster', '{}');
                 INSERT INTO sources (id, tenant, kind, name, config) VALUES (9, 'acme', 'linux', 'web', '{"agent_id":"a"}');
                 INSERT INTO policies (id, name, schedule, gfs) VALUES (1, 'p', 'daily 22:00', '{}');
                 INSERT INTO groups (id, tenant, source_id, policy_id, name, guests) VALUES (3, 'acme', 9, 1, 'g', '["a"]');"#,
            )
            .unwrap();
            assert!(c
                .execute(
                    "INSERT INTO sources (tenant, kind, name, config) VALUES ('acme', 'truenas', 'n', '{}')",
                    []
                )
                .is_err());
        }
        let c = Catalog::open(&p).unwrap();
        let conn = c.conn();
        let rows: Vec<(i64, String)> = conn
            .prepare("SELECT id, kind FROM sources ORDER BY id")
            .unwrap()
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(rows, vec![(7, "pve".into()), (9, "linux".into())]);
        assert!(
            conn.execute("DELETE FROM sources WHERE id = 9", []).is_err(),
            "group reference kept"
        );
        conn.execute(
            "INSERT INTO sources (tenant, kind, name, config) VALUES ('acme', 'truenas', 'nas1', '{}')",
            [],
        )
        .unwrap();
        assert!(conn
            .execute(
                "INSERT INTO sources (tenant, kind, name, config) VALUES ('acme', 'cifs', 'x', '{}')",
                []
            )
            .is_err());
        drop(conn);
        drop(c);
        let old = Connection::open(&p).unwrap();
        let v: i64 = old.pragma_query_value(None, "user_version", |r| r.get(0)).unwrap();
        assert_eq!(MIGRATIONS[..4].iter().skip(v as usize).count(), 0);
    }

    /// v6 rebuilds `sources` again (kinds `nfs`, `smb`): earlier rows, ids and
    /// references survive; the previous release (5 migrations) can still read the file.
    #[test]
    fn migration_v6_adds_share_sources() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("c.db");
        {
            let c = Connection::open(&p).unwrap();
            c.pragma_update(None, "foreign_keys", "ON").unwrap();
            for (i, m) in MIGRATIONS[..5].iter().enumerate() {
                c.execute_batch(m).unwrap();
                c.pragma_update(None, "user_version", (i + 1) as i64).unwrap();
            }
            c.execute_batch(
                r#"INSERT INTO tenants (name) VALUES ('acme');
                 INSERT INTO sources (id, tenant, kind, name, config) VALUES (7, 'acme', 'pve', 'cluster', '{}');
                 INSERT INTO sources (id, tenant, kind, name, config) VALUES (8, 'acme', 'truenas', 'tn', '{}');
                 INSERT INTO sources (id, tenant, kind, name, config) VALUES (9, 'acme', 'linux', 'web', '{"agent_id":"a"}');
                 INSERT INTO policies (id, name, schedule, gfs) VALUES (1, 'p', 'daily 22:00', '{}');
                 INSERT INTO groups (id, tenant, source_id, policy_id, name, guests) VALUES (3, 'acme', 8, 1, 'g', '["tank/a"]');"#,
            )
            .unwrap();
            for k in ["nfs", "smb"] {
                assert!(c
                    .execute(
                        "INSERT INTO sources (tenant, kind, name, config) VALUES ('acme', ?1, 'n', '{}')",
                        [k]
                    )
                    .is_err());
            }
        }
        let c = Catalog::open(&p).unwrap();
        let conn = c.conn();
        let rows: Vec<(i64, String)> = conn
            .prepare("SELECT id, kind FROM sources ORDER BY id")
            .unwrap()
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(
            rows,
            vec![(7, "pve".into()), (8, "truenas".into()), (9, "linux".into())]
        );
        assert!(
            conn.execute("DELETE FROM sources WHERE id = 8", []).is_err(),
            "group reference kept"
        );
        for k in ["nfs", "smb"] {
            conn.execute(
                "INSERT INTO sources (tenant, kind, name, config) VALUES ('acme', ?1, ?1, '{}')",
                [k],
            )
            .unwrap();
        }
        assert!(conn
            .execute(
                "INSERT INTO sources (tenant, kind, name, config) VALUES ('acme', 'cifs', 'x', '{}')",
                []
            )
            .is_err());
        drop(conn);
        drop(c);
        let old = Connection::open(&p).unwrap();
        let v: i64 = old.pragma_query_value(None, "user_version", |r| r.get(0)).unwrap();
        assert_eq!(MIGRATIONS[..5].iter().skip(v as usize).count(), 0);
    }

    /// v7 adds the replication tables and `snapshots.origin` on top of v6 (NAS
    /// kinds): a catalog written by the v6 release (share sources, snapshots)
    /// migrates without losing rows or the nfs/smb CHECK, and the v6 release can
    /// still read the file afterwards (it skips migration 7, its queries work).
    #[test]
    fn migration_v7_adds_replication() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("c.db");
        {
            // a v6 catalog as the previous release (NAS connector) left it
            let c = Connection::open(&p).unwrap();
            c.pragma_update(None, "foreign_keys", "ON").unwrap();
            for (i, m) in MIGRATIONS[..6].iter().enumerate() {
                c.execute_batch(m).unwrap();
                c.pragma_update(None, "user_version", (i + 1) as i64).unwrap();
            }
            c.execute_batch(
                r#"INSERT INTO tenants (name) VALUES ('acme');
                 INSERT INTO sources (id, tenant, kind, name, config) VALUES (7, 'acme', 'pve', 'cluster', '{}');
                 INSERT INTO sources (id, tenant, kind, name, config) VALUES (8, 'acme', 'nfs', 'filer', '{}');
                 INSERT INTO sources (id, tenant, kind, name, config) VALUES (9, 'acme', 'smb', 'share', '{}');
                 INSERT INTO policies (id, name, schedule, gfs) VALUES (1, 'p', 'daily 22:00', '{}');
                 INSERT INTO groups (id, tenant, source_id, policy_id, name, guests) VALUES (3, 'acme', 9, 1, 'g', '["/"]');
                 INSERT INTO snapshots (tenant, source, time, local, offsite) VALUES ('acme', 'vm-100', 5, 1, 0);"#,
            )
            .unwrap();
            assert!(c.execute("SELECT 1 FROM replication_peers", []).is_err());
        }
        let c = Catalog::open(&p).unwrap();
        let conn = c.conn();
        let v: i64 = conn.pragma_query_value(None, "user_version", |r| r.get(0)).unwrap();
        assert_eq!(v, MIGRATIONS.len() as i64);
        let rows: Vec<(i64, String)> = conn
            .prepare("SELECT id, kind FROM sources ORDER BY id")
            .unwrap()
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(rows, vec![(7, "pve".into()), (8, "nfs".into()), (9, "smb".into())]);
        assert!(
            conn.execute("DELETE FROM sources WHERE id = 9", []).is_err(),
            "group reference kept"
        );
        let ok = |sql: &str| conn.execute(sql, []).is_ok();
        for k in ["pve", "linux", "truenas", "nfs", "smb"] {
            assert!(ok(&format!(
                "INSERT INTO sources (tenant, kind, name, config) VALUES ('acme', '{k}', 'new-{k}', '{{}}')"
            )));
        }
        assert!(!ok(
            "INSERT INTO sources (tenant, kind, name, config) VALUES ('acme', 'cifs', 'x', '{}')"
        ));
        let origin: Option<String> = conn
            .query_row("SELECT origin FROM snapshots WHERE source = 'vm-100'", [], |r| r.get(0))
            .unwrap();
        assert_eq!(origin, None);
        assert!(ok(
            "INSERT INTO snapshots (tenant, source, time, local, offsite, origin) VALUES ('acme', 'vm-100', 6, 1, 0, 'prim')"
        ));
        assert!(ok(
            "INSERT INTO replication_peers (id, name, tenants, state, created, created_by) \
             VALUES ('0123456789abcdef', 'dr', '[\"acme\"]', 'pending', 1, 'admin')"
        ));
        assert!(!ok(
            "INSERT INTO replication_peers (id, name, tenants, state, created, created_by) \
             VALUES ('x', 'y', '[]', 'bogus', 1, 'admin')"
        ));
        assert!(ok(
            "UPDATE replication_peers SET cert_sha256 = 'aa' WHERE id = '0123456789abcdef'"
        ));
        assert!(
            !ok(
                "INSERT INTO replication_peers (id, name, tenants, state, cert_sha256, created, created_by) \
                 VALUES ('1', 'z', '[]', 'enrolled', 'aa', 1, 'a')"
            ),
            "one peer per certificate"
        );
        assert!(ok(
            "INSERT INTO replication_sources (name, url, peer_id, cert_pin, tenants, schedule, state, created) \
             VALUES ('prim', 'h:8443', 'p', 'aa', '[]', 'daily 01:00', 'enrolling', 1)"
        ));
        drop(conn);
        drop(c);
        // the v6 release: nothing left to migrate, its column lists still work
        let old = Connection::open(&p).unwrap();
        let v: i64 = old.pragma_query_value(None, "user_version", |r| r.get(0)).unwrap();
        assert_eq!(MIGRATIONS[..6].iter().skip(v as usize).count(), 0);
        let n: i64 = old
            .query_row("SELECT COUNT(*) FROM snapshots WHERE tenant = 'acme'", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 2);
        old.execute(
            "INSERT INTO snapshots (tenant, source, time, size, local, offsite, lock_until, verified) \
             VALUES ('acme', 'vm-100', 7, 0, 1, 0, 0, NULL)",
            [],
        )
        .unwrap();
        let kinds: i64 = old
            .query_row("SELECT COUNT(*) FROM sources WHERE kind IN ('nfs', 'smb')", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(kinds, 4);
    }

    /// v8 rebuilds `sources` again (kinds `plugin:<kind>`) on top of v7: a catalog
    /// written by the v7 release (all earlier kinds, groups, replication rows)
    /// migrates without losing rows, ids or references; the plugin tables exist;
    /// the v7 release can still read the file afterwards.
    #[test]
    fn migration_v8_adds_plugins() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("c.db");
        {
            let c = Connection::open(&p).unwrap();
            c.pragma_update(None, "foreign_keys", "ON").unwrap();
            for (i, m) in MIGRATIONS[..7].iter().enumerate() {
                c.execute_batch(m).unwrap();
                c.pragma_update(None, "user_version", (i + 1) as i64).unwrap();
            }
            c.execute_batch(
                r#"INSERT INTO tenants (name) VALUES ('acme');
                 INSERT INTO sources (id, tenant, kind, name, config) VALUES (7, 'acme', 'pve', 'cluster', '{"token_secret":"sealed:v1:x"}');
                 INSERT INTO sources (id, tenant, kind, name, config) VALUES (8, 'acme', 'truenas', 'tn', '{}');
                 INSERT INTO sources (id, tenant, kind, name, config) VALUES (9, 'acme', 'smb', 'share', '{}');
                 INSERT INTO sources (id, tenant, kind, name, config) VALUES (10, 'acme', 'linux', 'web', '{"agent_id":"a"}');
                 INSERT INTO sources (id, tenant, kind, name, config) VALUES (11, 'acme', 'nfs', 'filer', '{}');
                 INSERT INTO policies (id, name, schedule, gfs) VALUES (1, 'p', 'daily 22:00', '{}');
                 INSERT INTO groups (id, tenant, source_id, policy_id, name, guests) VALUES (3, 'acme', 8, 1, 'g', '["tank/a"]');
                 INSERT INTO replication_sources (name, url, peer_id, cert_pin, tenants, schedule, state, created)
                   VALUES ('prim', 'h:8443', 'p', 'aa', '[]', 'daily 01:00', 'enrolled', 1);"#,
            )
            .unwrap();
            assert!(c
                .execute(
                    "INSERT INTO sources (tenant, kind, name, config) VALUES ('acme', 'plugin:postgresql', 'pg', '{}')",
                    []
                )
                .is_err());
        }
        let c = Catalog::open(&p).unwrap();
        let conn = c.conn();
        let v: i64 = conn.pragma_query_value(None, "user_version", |r| r.get(0)).unwrap();
        assert_eq!(v, MIGRATIONS.len() as i64);
        let rows: Vec<(i64, String, String)> = conn
            .prepare("SELECT id, kind, config FROM sources ORDER BY id")
            .unwrap()
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(rows.len(), 5);
        assert_eq!(rows[0], (7, "pve".into(), r#"{"token_secret":"sealed:v1:x"}"#.into()));
        assert!(
            conn.execute("DELETE FROM sources WHERE id = 8", []).is_err(),
            "group reference kept"
        );
        let ok = |sql: &str| conn.execute(sql, []).is_ok();
        for k in ["plugin:postgresql", "plugin:files", "plugin:a1-b2"] {
            assert!(ok(&format!(
                "INSERT INTO sources (tenant, kind, name, config) VALUES ('acme', '{k}', 'n-{k}', '{{}}')"
            )));
        }
        for k in [
            "plugin:",
            "plugin:Pg",
            "plugin:-x",
            "plugin:a b",
            "plugin:x/y",
            "plugins:x",
            "esx",
        ] {
            assert!(
                !ok(&format!(
                    "INSERT INTO sources (tenant, kind, name, config) VALUES ('acme', '{k}', 'bad', '{{}}')"
                )),
                "{k}"
            );
        }
        assert!(!ok(&format!(
            "INSERT INTO sources (tenant, kind, name, config) VALUES ('acme', 'plugin:{}', 'long', '{{}}')",
            "a".repeat(33)
        )));
        assert!(ok(
            "INSERT INTO plugins (id, version, name, publisher, sha256, bin_sha256, size, manifest, signer, state, uploaded_by, uploaded_at) \
             VALUES ('pg', '1.0.0', 'PG', 'nexusbackup', 'a', 'b', 1, '{}', 'k', 'pending', 'admin', 1)"
        ));
        assert!(!ok(
            "INSERT INTO plugins (id, version, name, publisher, sha256, bin_sha256, size, manifest, signer, state, uploaded_by, uploaded_at) \
             VALUES ('pg', '1.0.1', 'PG', 'nexusbackup', 'a', 'b', 1, '{}', 'k', 'bogus', 'admin', 1)"
        ));
        assert!(ok("UPDATE plugins SET current = 1 WHERE id = 'pg'"));
        assert!(ok(
            "INSERT INTO plugins (id, version, name, publisher, sha256, bin_sha256, size, manifest, signer, state, uploaded_by, uploaded_at) \
             VALUES ('pg', '1.0.1', 'PG', 'nexusbackup', 'a', 'b', 1, '{}', 'k', 'pending', 'admin', 1)"
        ));
        assert!(
            !ok("UPDATE plugins SET current = 1 WHERE id = 'pg' AND version = '1.0.1'"),
            "one current version per id"
        );
        assert!(ok(
            "INSERT INTO plugin_keys (fingerprint, publisher, public_key, added_by, added_at) VALUES ('f', 'acme', 'pem', 'admin', 1)"
        ));
        drop(conn);
        drop(c);
        // the v7 release: nothing left to migrate, its queries still work
        let old = Connection::open(&p).unwrap();
        let v: i64 = old.pragma_query_value(None, "user_version", |r| r.get(0)).unwrap();
        assert_eq!(MIGRATIONS[..7].iter().skip(v as usize).count(), 0);
        let n: i64 = old
            .query_row(
                "SELECT COUNT(*) FROM sources s JOIN groups g ON g.source_id = s.id",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(n, 1);
        let n: i64 = old
            .query_row("SELECT COUNT(*) FROM replication_sources", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 1);
    }

    /// v9 (approvals setting, activation columns) on top of a v7 catalog as the
    /// release before the plugin system left it: it needs nothing v8 creates.
    /// Existing users stay active, approvals stay on (current behaviour), and
    /// the v7 release can still read users afterwards.
    #[test]
    fn migration_v9_from_v7_keeps_approvals_on() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("c.db");
        {
            let c = Connection::open(&p).unwrap();
            c.pragma_update(None, "foreign_keys", "ON").unwrap();
            for (i, m) in MIGRATIONS[..7].iter().enumerate() {
                c.execute_batch(m).unwrap();
                c.pragma_update(None, "user_version", (i + 1) as i64).unwrap();
            }
            c.execute_batch(
                "INSERT INTO users (name, password_hash, totp_secret, role, created) VALUES ('admin', 'h', 's', 'admin', 1);
                 INSERT INTO users (name, password_hash, totp_secret, role, created) VALUES ('so', 'h', 's', 'security_officer', 1);",
            )
            .unwrap();
        }
        let c = Catalog::open(&p).unwrap();
        {
            let conn = c.conn();
            let v: i64 = conn.pragma_query_value(None, "user_version", |r| r.get(0)).unwrap();
            assert_eq!(v, MIGRATIONS.len() as i64);
            assert!(approvals_enabled(&conn).unwrap());
            assert_eq!(possible_approvers(&conn).unwrap(), vec!["admin", "so"]);
            set_setting(&conn, "approvals_enabled", "false").unwrap();
            assert!(!approvals_enabled(&conn).unwrap());
            conn.execute(
                "UPDATE users SET activation_hash = 'x', activation_expires = 5 WHERE name = 'so'",
                [],
            )
            .unwrap();
            assert_eq!(possible_approvers(&conn).unwrap(), vec!["admin"]);
            conn.execute("DELETE FROM settings", []).unwrap();
            assert!(approvals_enabled(&conn).unwrap(), "a missing row counts as enabled");
        }
        drop(c);
        // reopening runs nothing again; the v7 release reads the file
        let c = Catalog::open(&p).unwrap();
        drop(c);
        let old = Connection::open(&p).unwrap();
        let v: i64 = old.pragma_query_value(None, "user_version", |r| r.get(0)).unwrap();
        assert_eq!(MIGRATIONS[..7].iter().skip(v as usize).count(), 0);
        let n: i64 = old
            .query_row("SELECT COUNT(*) FROM users WHERE disabled = 0", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 2);
    }

    /// v10 (capacity samples, OIDC users) on top of a v9 catalog: existing users
    /// become `local`, OIDC subjects are unique, samples have one row per day and
    /// tenant, and the v9 release can still read and write users afterwards.
    #[test]
    fn migration_v10_from_v9() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("c.db");
        {
            let c = Connection::open(&p).unwrap();
            c.pragma_update(None, "foreign_keys", "ON").unwrap();
            for (i, m) in MIGRATIONS[..9].iter().enumerate() {
                c.execute_batch(m).unwrap();
                c.pragma_update(None, "user_version", (i + 1) as i64).unwrap();
            }
            c.execute_batch(
                "INSERT INTO users (name, password_hash, totp_secret, role, created) VALUES ('admin', 'h', 's', 'admin', 1);
                 INSERT INTO settings (key, value) VALUES ('approvals_enabled', 'false')
                   ON CONFLICT(key) DO UPDATE SET value = excluded.value;",
            )
            .unwrap();
        }
        let c = Catalog::open(&p).unwrap();
        {
            let conn = c.conn();
            let v: i64 = conn.pragma_query_value(None, "user_version", |r| r.get(0)).unwrap();
            assert_eq!(v, MIGRATIONS.len() as i64);
            let auth: String = conn
                .query_row("SELECT auth FROM users WHERE name = 'admin'", [], |r| r.get(0))
                .unwrap();
            assert_eq!(auth, "local");
            assert!(!approvals_enabled(&conn).unwrap(), "settings kept");
            let ok = |sql: &str| conn.execute(sql, []).is_ok();
            assert!(ok(
                "INSERT INTO users (name, password_hash, totp_secret, role, created, auth, oidc_sub) \
                 VALUES ('kc-alice', '!oidc', '', 'operator', 2, 'oidc', 'https://idp|1')"
            ));
            assert!(
                !ok(
                    "INSERT INTO users (name, password_hash, totp_secret, role, created, auth, oidc_sub) \
                     VALUES ('kc-bob', '!oidc', '', 'operator', 2, 'oidc', 'https://idp|1')"
                ),
                "one account per subject"
            );
            assert!(!ok(
                "INSERT INTO users (name, password_hash, totp_secret, role, created, auth) VALUES ('x', 'h', '', 'operator', 2, 'saml')"
            ));
            assert!(ok(
                "INSERT INTO capacity_samples (day, tenant, used, logical) VALUES ('2026-10-11', 'acme', 1, 2)"
            ));
            assert!(!ok(
                "INSERT INTO capacity_samples (day, tenant, used, logical) VALUES ('2026-10-11', 'acme', 3, 4)"
            ));
        }
        drop(c);
        // the v9 release: nothing left to migrate, its user queries still work
        let old = Connection::open(&p).unwrap();
        let v: i64 = old.pragma_query_value(None, "user_version", |r| r.get(0)).unwrap();
        assert_eq!(MIGRATIONS[..9].iter().skip(v as usize).count(), 0);
        old.execute(
            "INSERT INTO users (name, password_hash, totp_secret, role, tenant, disabled, created, activation_hash, activation_expires) \
             VALUES ('op', 'h', '', 'operator', NULL, 0, 3, NULL, NULL)",
            [],
        )
        .unwrap();
        let n: i64 = old
            .query_row("SELECT COUNT(*) FROM users WHERE activation_hash IS NULL", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(n, 3);
    }

    /// v29 (rescue sessions) on top of the previous catalog: the table exists and
    /// the lookup key is unique.
    #[test]
    fn migration_v29_rescue_sessions() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("c.db");
        let before = MIGRATIONS.iter().position(|m| *m == SCHEMA_V29).unwrap();
        {
            let c = Connection::open(&p).unwrap();
            for (i, m) in MIGRATIONS[..before].iter().enumerate() {
                c.execute_batch(m).unwrap();
                c.pragma_update(None, "user_version", (i + 1) as i64).unwrap();
            }
        }
        let c = Catalog::open(&p).unwrap();
        let conn = c.conn();
        let ins = "INSERT INTO rescue_sessions (id, tenant, agent_id, lookup, token_expires, created, created_by) \
                   VALUES (?1, 't', '0123456789abcdef', ?2, 1, 1, 'admin')";
        conn.execute(ins, ["a", "l1"]).unwrap();
        assert!(conn.execute(ins, ["b", "l1"]).is_err(), "lookup is unique");
        let (state, disks, reboot): (String, String, bool) = conn
            .query_row("SELECT state, disks, reboot FROM rescue_sessions", [], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?))
            })
            .unwrap();
        assert_eq!((state.as_str(), disks.as_str(), reboot), ("issued", "[]", true));
    }

    /// v34 (restore tests, recovery plans) on top of the previous catalog: empty
    /// tables; a group's schedule goes with the group; the previous release
    /// still writes policies.
    #[test]
    fn migration_v34_recovery() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("c.db");
        let before = MIGRATIONS.iter().position(|m| *m == SCHEMA_V34).unwrap();
        {
            let c = Connection::open(&p).unwrap();
            for (i, m) in MIGRATIONS[..before].iter().enumerate() {
                c.execute_batch(m).unwrap();
                c.pragma_update(None, "user_version", (i + 1) as i64).unwrap();
            }
            c.execute_batch(
                "INSERT INTO tenants (name) VALUES ('t');
                 INSERT INTO sources (id, tenant, kind, name, config) VALUES (1, 't', 'pve', 's', '{}');
                 INSERT INTO policies (id, name, schedule, gfs) VALUES (1, 'p', 'daily 22:00', '{}');
                 INSERT INTO groups (id, tenant, source_id, policy_id, name, guests) VALUES (1, 't', 1, 1, 'g', '[100]');",
            )
            .unwrap();
        }
        let c = Catalog::open(&p).unwrap();
        {
            let conn = c.conn();
            conn.execute_batch(
                "INSERT INTO restore_test_schedules (group_id, every_days, node, storage) VALUES (1, 7, 'pve1', 'local-lvm');
                 INSERT INTO restore_tests (tenant, source, time, job_id, state, started, finished)
                   VALUES ('t', 'vm-100', 5, 1, 'passed', 6, 7);
                 INSERT INTO recovery_plans (tenant, name, source_id, node, storage, created, created_by)
                   VALUES ('t', 'dr', 1, 'pve1', 'local-lvm', 1, 'a');
                 INSERT INTO recovery_runs (plan_id, tenant, mode, requested_by, plan, started) VALUES (1, 't', 'test', 'a', '{}', 1);",
            )
            .unwrap();
            assert!(conn
                .execute(
                    "INSERT INTO restore_tests (tenant, source, time, job_id, state, started, finished)
                     VALUES ('t', 'vm-100', 5, 1, 'passed', 6, 7)",
                    [],
                )
                .is_err());
            assert!(conn
                .execute("UPDATE restore_test_schedules SET every_days = 0", [])
                .is_err());
            conn.execute("DELETE FROM groups", []).unwrap();
            let n: i64 = conn
                .query_row("SELECT COUNT(*) FROM restore_test_schedules", [], |r| r.get(0))
                .unwrap();
            assert_eq!(n, 0);
        }
        drop(c);
        let old = Connection::open(&p).unwrap();
        old.execute(
            "INSERT INTO policies (id, name, schedule, gfs) VALUES (2, 'q', 'daily 22:00', '{}')",
            [],
        )
        .unwrap();
    }

    /// v31 (passkeys) on top of the previous catalog: the table starts empty,
    /// credentials go when their user goes; the previous release still signs in.
    #[test]
    fn migration_v31_passkeys() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("c.db");
        let before = MIGRATIONS.iter().position(|m| *m == SCHEMA_V31).unwrap();
        {
            let c = Connection::open(&p).unwrap();
            for (i, m) in MIGRATIONS[..before].iter().enumerate() {
                c.execute_batch(m).unwrap();
                c.pragma_update(None, "user_version", (i + 1) as i64).unwrap();
            }
            c.execute(
                "INSERT INTO users (name, password_hash, totp_secret, role, created) VALUES ('a', 'h', 's', 'admin', 1)",
                [],
            )
            .unwrap();
        }
        let c = Catalog::open(&p).unwrap();
        {
            let conn = c.conn();
            conn.execute(
                "INSERT INTO passkeys (user_id, cred_id, name, alg, public_key, rp_id, created) VALUES (1, 'x', 'k', -7, x'04', 'h', 1)",
                [],
            )
            .unwrap();
            assert!(conn
                .execute(
                    "INSERT INTO passkeys (user_id, cred_id, name, alg, public_key, rp_id, created) VALUES (1, 'y', 'k', -257, x'04', 'h', 1)",
                    [],
                )
                .is_err());
            conn.execute("DELETE FROM users", []).unwrap();
            let n: i64 = conn
                .query_row("SELECT COUNT(*) FROM passkeys", [], |r| r.get(0))
                .unwrap();
            assert_eq!(n, 0);
        }
        drop(c);
        let old = Connection::open(&p).unwrap();
        old.execute("UPDATE users SET last_login = 5", []).unwrap();
    }

    /// v26 (endpoint status) on top of the previous catalog: existing agents are
    /// unpolled with an empty policy; the previous release still updates agents.
    #[test]
    fn migration_v26_endpoint_status() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("c.db");
        let before = MIGRATIONS.iter().position(|m| *m == SCHEMA_V26).unwrap();
        {
            let c = Connection::open(&p).unwrap();
            for (i, m) in MIGRATIONS[..before].iter().enumerate() {
                c.execute_batch(m).unwrap();
                c.pragma_update(None, "user_version", (i + 1) as i64).unwrap();
            }
            c.execute_batch(
                "INSERT INTO tenants (name) VALUES ('t'); \
                 INSERT INTO agents (id, tenant, name, host, port) VALUES ('0123456789abcdef', 't', 'a', 'h', 7444);",
            )
            .unwrap();
        }
        let c = Catalog::open(&p).unwrap();
        {
            let conn = c.conn();
            let row: (Option<i64>, i64, String, String, i64) = conn
                .query_row(
                    "SELECT reachable, poll_failures, ui_policy, laptop, ui_policy_version FROM agents",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
                )
                .unwrap();
            assert_eq!(row, (None, 0, "{}".into(), "{}".into(), 0));
            conn.execute(
                "INSERT INTO agent_sessions (agent_id, job_id, tenant, summary, created) VALUES ('0123456789abcdef', 1, 't', '{}', 1)",
                [],
            )
            .unwrap();
        }
        drop(c);
        let old = Connection::open(&p).unwrap();
        old.execute("UPDATE agents SET last_seen = 5, version = '0.1'", [])
            .unwrap();
    }

    /// v24 (replication windows, close vault) on top of the previous catalog:
    /// existing sources sync always and are open; the previous release still
    /// inserts and updates sources.
    #[test]
    fn migration_v24_replication_windows() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("c.db");
        let before = MIGRATIONS.iter().position(|m| *m == SCHEMA_V24).unwrap();
        {
            let c = Connection::open(&p).unwrap();
            for (i, m) in MIGRATIONS[..before].iter().enumerate() {
                c.execute_batch(m).unwrap();
                c.pragma_update(None, "user_version", (i + 1) as i64).unwrap();
            }
            c.execute(
                "INSERT INTO replication_sources (name, url, peer_id, cert_pin, tenants, schedule, state, created) \
                 VALUES ('p', 'h:8443', 'x', 'pin', '[\"t\"]', 'daily 01:00', 'enrolled', 1)",
                [],
            )
            .unwrap();
        }
        let c = Catalog::open(&p).unwrap();
        {
            let conn = c.conn();
            let row: (String, String, String, Option<i64>) = conn
                .query_row(
                    "SELECT windows, sync_window, timezone, closed_until FROM replication_sources",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
                )
                .unwrap();
            assert_eq!(row, ("[]".into(), "[]".into(), "UTC".into(), None));
            conn.execute("UPDATE replication_sources SET closed_until = -1, closed_by = 'so'", [])
                .unwrap();
        }
        drop(c);
        let old = Connection::open(&p).unwrap();
        old.execute("UPDATE replication_sources SET schedule = 'daily 02:00'", [])
            .unwrap();
        old.execute(
            "INSERT INTO replication_sources (name, url, peer_id, cert_pin, tenants, schedule, state, created) \
             VALUES ('q', 'h:8443', 'y', 'pin', '[]', 'daily 01:00', 'enrolling', 1)",
            [],
        )
        .unwrap();
    }

    /// v19 (file index flag) on top of the previous catalog: existing groups do
    /// not index VM/CT disks; the previous release still inserts groups.
    #[test]
    fn migration_v19_index_files() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("c.db");
        let before = MIGRATIONS.iter().position(|m| *m == SCHEMA_V19).unwrap();
        {
            let c = Connection::open(&p).unwrap();
            for (i, m) in MIGRATIONS[..before].iter().enumerate() {
                c.execute_batch(m).unwrap();
                c.pragma_update(None, "user_version", (i + 1) as i64).unwrap();
            }
            c.execute_batch(
                "INSERT INTO tenants (name) VALUES ('acme');
                 INSERT INTO sources (id, tenant, name, kind, config) VALUES (1, 'acme', 'pve', 'pve', '{}');
                 INSERT INTO policies (id, name, schedule, gfs) VALUES (1, 'p', 'daily 01:00', '{}');
                 INSERT INTO groups (tenant, source_id, policy_id, name, guests) VALUES ('acme', 1, 1, 'g', '[100]');",
            )
            .unwrap();
        }
        let c = Catalog::open(&p).unwrap();
        {
            let conn = c.conn();
            let on: bool = conn
                .query_row("SELECT index_files FROM groups", [], |r| r.get(0))
                .unwrap();
            assert!(!on);
            conn.execute("UPDATE groups SET index_files = 1", []).unwrap();
        }
        drop(c);
        let old = Connection::open(&p).unwrap();
        old.execute(
            "INSERT INTO groups (tenant, source_id, policy_id, name, guests) VALUES ('acme', 1, 1, 'h', '[101]')",
            [],
        )
        .unwrap();
    }

    /// v11 (backup stats, tenant quotas) on top of the previous catalog: existing
    /// tenants have no quota, stats have one row per snapshot, and the previous
    /// release still reads and writes tenants afterwards.
    #[test]
    fn migration_v11_backup_stats_and_quota() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("c.db");
        let before = MIGRATIONS.iter().position(|m| *m == SCHEMA_V11).unwrap();
        {
            let c = Connection::open(&p).unwrap();
            c.pragma_update(None, "foreign_keys", "ON").unwrap();
            for (i, m) in MIGRATIONS[..before].iter().enumerate() {
                c.execute_batch(m).unwrap();
                c.pragma_update(None, "user_version", (i + 1) as i64).unwrap();
            }
            c.execute("INSERT INTO tenants (name) VALUES ('acme')", []).unwrap();
        }
        let c = Catalog::open(&p).unwrap();
        {
            let conn = c.conn();
            let v: i64 = conn.pragma_query_value(None, "user_version", |r| r.get(0)).unwrap();
            assert_eq!(v, MIGRATIONS.len() as i64);
            let q: Option<i64> = conn
                .query_row("SELECT quota_bytes FROM tenants WHERE name = 'acme'", [], |r| r.get(0))
                .unwrap();
            assert_eq!(q, None);
            conn.execute("UPDATE tenants SET quota_bytes = 1000 WHERE name = 'acme'", [])
                .unwrap();
            let ins =
                "INSERT INTO backup_stats (tenant, source, time, read, logical, new_chunks, new_plain, new_stored) \
                       VALUES ('acme', 'vm-100', 1, 10, 20, 1, 5, 3)";
            conn.execute(ins, []).unwrap();
            assert!(conn.execute(ins, []).is_err(), "one row per snapshot");
        }
        drop(c);
        let old = Connection::open(&p).unwrap();
        let v: i64 = old.pragma_query_value(None, "user_version", |r| r.get(0)).unwrap();
        assert_eq!(MIGRATIONS[..before].iter().skip(v as usize).count(), 0);
        old.execute("INSERT INTO tenants (name) VALUES ('beta')", []).unwrap();
    }

    /// v22 (tenant deactivation) on top of the previous catalog: every tenant is
    /// active; the flag accepts only 0/1; the previous release still creates
    /// and reads tenants afterwards.
    #[test]
    fn migration_v22_tenant_disabled() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("c.db");
        let before = MIGRATIONS.iter().position(|m| *m == SCHEMA_V22).unwrap();
        {
            let c = Connection::open(&p).unwrap();
            for (i, m) in MIGRATIONS[..before].iter().enumerate() {
                c.execute_batch(m).unwrap();
                c.pragma_update(None, "user_version", (i + 1) as i64).unwrap();
            }
            c.execute_batch("INSERT INTO tenants (name) VALUES ('acme');").unwrap();
        }
        let c = Catalog::open(&p).unwrap();
        {
            let conn = c.conn();
            let t: (i64, Option<i64>, Option<String>, Option<String>) = conn
                .query_row(
                    "SELECT disabled, disabled_at, disabled_by, disabled_reason FROM tenants WHERE name = 'acme'",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
                )
                .unwrap();
            assert_eq!(t, (0, None, None, None));
            assert!(!tenants::disabled(&conn, "acme").unwrap());
            assert!(conn.execute("UPDATE tenants SET disabled = 2", []).is_err());
            conn.execute("UPDATE tenants SET disabled = 1 WHERE name = 'acme'", [])
                .unwrap();
            assert!(tenants::disabled(&conn, "acme").unwrap());
            assert!(!tenants::disabled(&conn, "nope").unwrap());
            assert_eq!(tenants::all_disabled(&conn).unwrap().len(), 1);
        }
        drop(c);
        let old = Connection::open(&p).unwrap();
        let v: i64 = old.pragma_query_value(None, "user_version", |r| r.get(0)).unwrap();
        assert_eq!(MIGRATIONS[..before].iter().skip(v as usize).count(), 0);
        old.execute_batch(
            "INSERT INTO tenants (name, offsite) VALUES ('globex', '{}'); SELECT name, offsite FROM tenants;",
        )
        .unwrap();
    }

    /// v21 (disk/file selection, agents) on top of the previous catalog: groups
    /// exclude no disks and run one guest at a time, policies have no global file
    /// filters, agents have no limits and an unknown certificate validity. The
    /// previous release still reads and writes groups, policies and agents.
    #[test]
    fn migration_v23_snapshot_meta() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("c.db");
        let before = MIGRATIONS.iter().position(|m| *m == SCHEMA_V23).unwrap();
        {
            let c = Connection::open(&p).unwrap();
            for (i, m) in MIGRATIONS[..before].iter().enumerate() {
                c.execute_batch(m).unwrap();
                c.pragma_update(None, "user_version", (i + 1) as i64).unwrap();
            }
            c.execute_batch(
                "INSERT INTO snapshots (tenant, source, time, local, offsite) VALUES ('acme', 'plugin-postgresql-1', 5, 1, 0);",
            )
            .unwrap();
        }
        let c = Catalog::open(&p).unwrap();
        let conn = c.conn();
        let m: Option<String> = conn
            .query_row("SELECT meta FROM snapshots WHERE time = 5", [], |r| r.get(0))
            .unwrap();
        assert_eq!(m, None);
        conn.execute("UPDATE snapshots SET meta = '{\"a\":1}' WHERE time = 5", [])
            .unwrap();
    }

    #[test]
    fn migration_v21_selection_agents() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("c.db");
        let before = MIGRATIONS.iter().position(|m| *m == SCHEMA_V21).unwrap();
        {
            let c = Connection::open(&p).unwrap();
            for (i, m) in MIGRATIONS[..before].iter().enumerate() {
                c.execute_batch(m).unwrap();
                c.pragma_update(None, "user_version", (i + 1) as i64).unwrap();
            }
            c.execute_batch(
                "INSERT INTO tenants (name) VALUES ('acme');
                 INSERT INTO sources (id, tenant, kind, name, config) VALUES (1, 'acme', 'pve', 'pve', '{}');
                 INSERT INTO policies (id, name, schedule, gfs) VALUES (1, 'p', 'daily 01:00', '{}');
                 INSERT INTO groups (id, tenant, source_id, policy_id, name, guests) VALUES (1, 'acme', 1, 1, 'g', '[100]');
                 INSERT INTO agents (id, tenant, name, host, port, cert_sha256, enrolled_at)
                   VALUES ('0123456789abcdef', 'acme', 'web', 'h', 7444, 'ab', 5);",
            )
            .unwrap();
        }
        let c = Catalog::open(&p).unwrap();
        {
            let conn = c.conn();
            let g: (String, String, i64) = conn
                .query_row(
                    "SELECT exclude_disks, exclude_disks_mode, parallel_guests FROM groups WHERE id = 1",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
                .unwrap();
            assert_eq!(g, ("{}".into(), "placeholder".into(), 1));
            let f: String = conn
                .query_row("SELECT file_filters FROM policies WHERE id = 1", [], |r| r.get(0))
                .unwrap();
            assert_eq!(f, "{}");
            let a: (Option<i64>, Option<String>, String) = conn
                .query_row("SELECT cert_expires, cert_sha256_next, limits FROM agents", [], |r| {
                    Ok((r.get(0)?, r.get(1)?, r.get(2)?))
                })
                .unwrap();
            assert_eq!(a, (None, None, "{}".into()));
            assert!(conn.execute("UPDATE groups SET parallel_guests = 9", []).is_err());
            assert!(conn.execute("UPDATE groups SET exclude_disks_mode = 'x'", []).is_err());
        }
        drop(c);
        let old = Connection::open(&p).unwrap();
        let v: i64 = old.pragma_query_value(None, "user_version", |r| r.get(0)).unwrap();
        assert_eq!(MIGRATIONS[..before].iter().skip(v as usize).count(), 0);
        old.execute_batch(
            "INSERT INTO groups (tenant, source_id, policy_id, name, guests) VALUES ('acme', 1, 1, 'g2', '[]');
             UPDATE agents SET last_seen = 9;",
        )
        .unwrap();
    }

    /// v17 (access) on top of the previous catalog: users keep ids, roles and
    /// credentials, get `can_download` NULL (role default), no expiry and a
    /// `last_login` (activated accounts only); sessions survive with a numeric
    /// id; `viewer` is accepted, unknown roles still are not. The previous
    /// release still logs in (reads users, inserts sessions) afterwards.
    #[test]
    fn migration_v17_access() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("c.db");
        let before = MIGRATIONS.iter().position(|m| *m == SCHEMA_V17).unwrap();
        {
            let c = Connection::open(&p).unwrap();
            c.pragma_update(None, "foreign_keys", "ON").unwrap();
            for (i, m) in MIGRATIONS[..before].iter().enumerate() {
                c.execute_batch(m).unwrap();
                c.pragma_update(None, "user_version", (i + 1) as i64).unwrap();
            }
            c.execute_batch(
                "INSERT INTO users (id, name, password_hash, totp_secret, role, tenant, created, totp_last_step)
                   VALUES (7, 'alice', 'h', 's', 'admin', NULL, 1, 42);
                 INSERT INTO users (id, name, password_hash, totp_secret, role, tenant, created, activation_hash)
                   VALUES (8, 'pend', '!', '', 'tenant_user', 'acme', 2, 'abc');
                 INSERT INTO users (id, name, password_hash, totp_secret, role, created, auth, oidc_sub)
                   VALUES (9, 'sso', '!oidc', '', 'operator', 3, 'oidc', 'iss|1');
                 INSERT INTO sessions (id_hash, user_id, csrf, created, last_seen) VALUES ('h1', 7, 'c', 10, 11);
                 INSERT INTO api_tokens (user_id, name, prefix, hash, scope, expires, created)
                   VALUES (7, 'ci', 'abcd0123', 'h', 'read', 99, 1);",
            )
            .unwrap();
        }
        let c = Catalog::open(&p).unwrap();
        {
            let conn = c.conn();
            let v: i64 = conn.pragma_query_value(None, "user_version", |r| r.get(0)).unwrap();
            assert_eq!(v, MIGRATIONS.len() as i64);
            let (step, dl, exp, ll): (i64, Option<i64>, Option<i64>, Option<i64>) = conn
                .query_row(
                    "SELECT totp_last_step, can_download, expires, last_login FROM users WHERE id = 7",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
                )
                .unwrap();
            assert_eq!((step, dl, exp), (42, None, None));
            assert!(ll.is_some_and(|t| t > 1_700_000_000));
            // the v15 api_tokens foreign key still points at the rebuilt `users`
            let (tu, fk): (i64, i64) = conn
                .query_row(
                    "SELECT (SELECT user_id FROM api_tokens WHERE prefix = 'abcd0123'),
                            (SELECT COUNT(*) FROM pragma_foreign_key_check)",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .unwrap();
            assert_eq!((tu, fk), (7, 0), "api_tokens survive, foreign keys clean");
            let fk_sql: String = conn
                .query_row("SELECT sql FROM sqlite_master WHERE name = 'api_tokens'", [], |r| {
                    r.get(0)
                })
                .unwrap();
            assert!(fk_sql.contains("REFERENCES users(id)"), "{fk_sql}");
            assert!(
                conn.execute(
                    "INSERT INTO api_tokens (user_id, name, prefix, hash, scope, expires, created)
                     VALUES (999, 'x', 'ffff0000', 'h', 'read', 99, 1)",
                    []
                )
                .is_err(),
                "the token foreign key is enforced against the new users table"
            );
            let ll: Option<i64> = conn
                .query_row("SELECT last_login FROM users WHERE id = 8", [], |r| r.get(0))
                .unwrap();
            assert_eq!(ll, None, "pending accounts never logged in");
            let (sid, uid, ip): (i64, i64, String) = conn
                .query_row("SELECT id, user_id, ip FROM sessions WHERE id_hash = 'h1'", [], |r| {
                    Ok((r.get(0)?, r.get(1)?, r.get(2)?))
                })
                .unwrap();
            assert!(sid > 0 && uid == 7 && ip.is_empty());
            conn.execute(
                "INSERT INTO users (name, password_hash, totp_secret, role, created) VALUES ('vic', 'h', 's', 'viewer', 4)",
                [],
            )
            .unwrap();
            assert!(conn
                .execute(
                    "INSERT INTO users (name, password_hash, totp_secret, role, created) VALUES ('x', 'h', 's', 'root', 4)",
                    []
                )
                .is_err());
            assert!(
                conn.execute(
                    "INSERT INTO users (name, password_hash, totp_secret, role, created, oidc_sub) VALUES ('y', 'h', 's', 'viewer', 4, 'iss|1')",
                    []
                )
                .is_err(),
                "oidc_sub index rebuilt"
            );
            assert!(
                conn.execute(
                    "INSERT INTO sessions (id_hash, user_id, csrf, created, last_seen) VALUES ('h2', 99, 'c', 1, 1)",
                    []
                )
                .is_err(),
                "sessions still reference users"
            );
        }
        drop(c);
        let old = Connection::open(&p).unwrap();
        let v: i64 = old.pragma_query_value(None, "user_version", |r| r.get(0)).unwrap();
        assert_eq!(MIGRATIONS[..before].iter().skip(v as usize).count(), 0);
        old.execute(
            "INSERT INTO sessions (id_hash, user_id, csrf, created, last_seen) VALUES ('h3', 7, 'c', 1, 1)",
            [],
        )
        .unwrap();
        let n: i64 = old
            .query_row("SELECT COUNT(*) FROM users WHERE id IN (7, 8, 9)", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 3);
    }

    /// v14 (run control) on top of the previous catalog: existing policies get the
    /// default retry (3 x 5 min), no blackout and no SLA; groups run in UTC and
    /// are not paused; jobs are attempt 1. The previous release still reads and
    /// writes policies, groups and jobs afterwards.
    #[test]
    fn migration_v14_run_control() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("c.db");
        let before = MIGRATIONS.iter().position(|m| *m == SCHEMA_V14).unwrap();
        {
            let c = Connection::open(&p).unwrap();
            c.pragma_update(None, "foreign_keys", "ON").unwrap();
            for (i, m) in MIGRATIONS[..before].iter().enumerate() {
                c.execute_batch(m).unwrap();
                c.pragma_update(None, "user_version", (i + 1) as i64).unwrap();
            }
            c.execute_batch(
                r#"INSERT INTO tenants (name) VALUES ('acme');
                 INSERT INTO sources (id, tenant, kind, name, config) VALUES (7, 'acme', 'pve', 'cluster', '{}');
                 INSERT INTO policies (id, name, schedule, gfs) VALUES (1, 'p', 'daily 22:00', '{}');
                 INSERT INTO groups (id, tenant, source_id, policy_id, name, guests) VALUES (3, 'acme', 7, 1, 'g', '[100]');
                 INSERT INTO jobs (kind, tenant, params, state, requested_by, created) VALUES ('backup', 'acme', '{}', 'ok', 's', 1);"#,
            )
            .unwrap();
        }
        let c = Catalog::open(&p).unwrap();
        {
            let conn = c.conn();
            let v: i64 = conn.pragma_query_value(None, "user_version", |r| r.get(0)).unwrap();
            assert_eq!(v, MIGRATIONS.len() as i64);
            let pol: (String, String, Option<i64>) = conn
                .query_row("SELECT retry, blackout, sla_minutes FROM policies", [], |r| {
                    Ok((r.get(0)?, r.get(1)?, r.get(2)?))
                })
                .unwrap();
            assert_eq!(pol, (r#"{"count":3,"delay_min":5}"#.into(), "[]".into(), None));
            let g: (Option<i64>, String) = conn
                .query_row("SELECT paused_until, timezone FROM groups", [], |r| {
                    Ok((r.get(0)?, r.get(1)?))
                })
                .unwrap();
            assert_eq!(g, (None, "UTC".into()));
            let m: Option<i64> = conn
                .query_row("SELECT maintenance_until FROM sources", [], |r| r.get(0))
                .unwrap();
            assert_eq!(m, None);
            let j: (i64, Option<i64>, Option<i64>, Option<String>, i64) = conn
                .query_row(
                    "SELECT attempt, not_before, retry_of, cancel_by, sla_alerted FROM jobs",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
                )
                .unwrap();
            assert_eq!(j, (1, None, None, None, 0));
        }
        drop(c);
        let old = Connection::open(&p).unwrap();
        let v: i64 = old.pragma_query_value(None, "user_version", |r| r.get(0)).unwrap();
        assert_eq!(MIGRATIONS[..before].iter().skip(v as usize).count(), 0);
        old.execute_batch(
            "INSERT INTO policies (name, schedule, gfs, offsite) VALUES ('q', 'hourly 5', '{}', 0);
             INSERT INTO groups (tenant, source_id, policy_id, name, guests) VALUES ('acme', 7, 2, 'h', '[]');
             INSERT INTO jobs (kind, tenant, params, state, requested_by, created) VALUES ('backup', 'acme', '{}', 'queued', 's', 2);",
        )
        .unwrap();
    }

    /// v15 (API tokens) on top of the previous catalog: the table starts empty,
    /// the scope is checked and tokens follow their user (ON DELETE CASCADE).
    #[test]
    fn migration_v15_api_tokens() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("c.db");
        let before = MIGRATIONS.iter().position(|m| *m == SCHEMA_V15).unwrap();
        {
            let c = Connection::open(&p).unwrap();
            for (i, m) in MIGRATIONS[..before].iter().enumerate() {
                c.execute_batch(m).unwrap();
                c.pragma_update(None, "user_version", (i + 1) as i64).unwrap();
            }
            c.execute_batch(
                "INSERT INTO users (id, name, password_hash, totp_secret, role, created) VALUES (1, 'a', 'x', '', 'admin', 0);",
            )
            .unwrap();
        }
        let c = Catalog::open(&p).unwrap();
        let conn = c.conn();
        let v: i64 = conn.pragma_query_value(None, "user_version", |r| r.get(0)).unwrap();
        assert_eq!(v, MIGRATIONS.len() as i64);
        let n: i64 = conn
            .query_row("SELECT COUNT(*) FROM api_tokens", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 0);
        let ins = "INSERT INTO api_tokens (user_id, name, prefix, hash, scope, expires, created) VALUES (1, ?1, ?2, 'h', ?3, 10, 0)";
        conn.execute(ins, ["ci", "abcd1234", "read"]).unwrap();
        assert!(conn.execute(ins, ["x", "ffff0000", "admin"]).is_err(), "scope checked");
        conn.execute("DELETE FROM users WHERE id = 1", []).unwrap();
        let n: i64 = conn
            .query_row("SELECT COUNT(*) FROM api_tokens", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 0, "tokens follow their user");
    }

    /// v20 (consistency) on top of the previous catalog: existing snapshots have
    /// no level (NULL), policies require nothing; the level is checked; the
    /// previous release still writes both tables.
    #[test]
    fn migration_v20_consistency() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("c.db");
        let before = MIGRATIONS.iter().position(|m| *m == SCHEMA_V20).unwrap();
        {
            let c = Connection::open(&p).unwrap();
            for (i, m) in MIGRATIONS[..before].iter().enumerate() {
                c.execute_batch(m).unwrap();
                c.pragma_update(None, "user_version", (i + 1) as i64).unwrap();
            }
            c.execute_batch(
                "INSERT INTO policies (id, name, schedule, gfs) VALUES (1, 'p', 'daily 22:00', '{}');
                 INSERT INTO snapshots (tenant, source, time, local, offsite) VALUES ('t', 'vm-100', 1, 1, 0);",
            )
            .unwrap();
        }
        let c = Catalog::open(&p).unwrap();
        {
            let conn = c.conn();
            let v: i64 = conn.pragma_query_value(None, "user_version", |r| r.get(0)).unwrap();
            assert_eq!(v, MIGRATIONS.len() as i64);
            let lvl: Option<String> = conn
                .query_row("SELECT consistency FROM snapshots", [], |r| r.get(0))
                .unwrap();
            assert_eq!(lvl, None);
            let req: String = conn
                .query_row("SELECT require_consistency FROM policies", [], |r| r.get(0))
                .unwrap();
            assert_eq!(req, r#"{"mode":"off","level":"crash"}"#);
            conn.execute("UPDATE snapshots SET consistency = 'application'", [])
                .unwrap();
            assert!(conn.execute("UPDATE snapshots SET consistency = 'app'", []).is_err());
        }
        drop(c);
        let old = Connection::open(&p).unwrap();
        old.execute_batch(
            "INSERT INTO policies (name, schedule, gfs) VALUES ('q', 'hourly 5', '{}');
             INSERT INTO snapshots (tenant, source, time, local, offsite) VALUES ('t', 'vm-100', 2, 1, 0);",
        )
        .unwrap();
    }

    /// A fresh catalog runs every migration: all source kinds and the
    /// replication tables exist.
    #[test]
    fn fresh_catalog_has_all_migrations() {
        let d = tempfile::tempdir().unwrap();
        for c in [
            Catalog::open_memory().unwrap(),
            Catalog::open(&d.path().join("c.db")).unwrap(),
        ] {
            let conn = c.conn();
            conn.execute("INSERT INTO tenants (name) VALUES ('t')", []).unwrap();
            for k in ["pve", "linux", "truenas", "nfs", "smb", "plugin:files"] {
                conn.execute(
                    "INSERT INTO sources (tenant, kind, name, config) VALUES ('t', ?1, ?1, '{}')",
                    [k],
                )
                .unwrap();
            }
            for t in [
                "agents",
                "replication_peers",
                "replication_sources",
                "plugins",
                "plugin_keys",
            ] {
                let n: i64 = conn
                    .query_row(&format!("SELECT COUNT(*) FROM {t}"), [], |r| r.get(0))
                    .unwrap();
                assert_eq!(n, 0);
            }
            conn.query_row("SELECT origin FROM snapshots LIMIT 1", [], |_| Ok(()))
                .or_else(|e| match e {
                    rusqlite::Error::QueryReturnedNoRows => Ok(()),
                    e => Err(e),
                })
                .unwrap();
        }
    }

    #[test]
    fn audit_chain_detects_tampering() {
        let c = Catalog::open_memory().unwrap();
        for i in 0..5 {
            c.audit("alice", "policy.update", &format!("policy/{i}"), &json!({"daily": 14}))
                .unwrap();
        }
        assert_eq!(c.verify_audit().unwrap(), 5);
        // the append-only triggers block normal tampering …
        assert!(c
            .conn()
            .execute("UPDATE audit SET actor='mallory' WHERE seq=3", [])
            .is_err());
        assert!(c.conn().execute("DELETE FROM audit WHERE seq=5", []).is_err());
        // … and the chain catches anyone who drops the triggers
        c.conn()
            .execute_batch("DROP TRIGGER audit_no_update; UPDATE audit SET actor='mallory' WHERE seq=3;")
            .unwrap();
        assert!(c.verify_audit().unwrap_err().to_string().contains("seq 3"));
    }

    #[test]
    fn constraints_hold() {
        let c = Catalog::open_memory().unwrap();
        let bad = c.conn().execute(
            "INSERT INTO users (name, password_hash, totp_secret, role, created) VALUES ('x','h','s','root',0)",
            [],
        );
        assert!(bad.is_err(), "unknown role rejected");
        assert!(
            c.conn()
                .execute(
                    "INSERT INTO groups (tenant, source_id, policy_id, name, guests) VALUES ('t',1,1,'g','[]')",
                    []
                )
                .is_err(),
            "foreign keys enforced"
        );
    }

    /// v12 (alert lifecycle) on top of a v10 catalog: keys and last_ts are
    /// backfilled, acknowledged alerts count as resolved, everything as
    /// delivered, and the previous release still inserts and acknowledges.
    #[test]
    fn migration_v12_alert_lifecycle() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("c.db");
        let pos = MIGRATIONS.iter().position(|m| *m == SCHEMA_V12).unwrap();
        {
            let c = Connection::open(&p).unwrap();
            for (i, m) in MIGRATIONS[..pos].iter().enumerate() {
                c.execute_batch(m).unwrap();
                c.pragma_update(None, "user_version", (i + 1) as i64).unwrap();
            }
            c.execute_batch(
                "INSERT INTO alerts (id, ts, severity, kind, message, acked_by) VALUES
                   (1, 100, 'warning', 'capacity', 'store capacity above 75 % (now 80 %)', NULL),
                   (2, 200, 'warning', 'offsite_lag', 'offsite copy of tenant acme lags by 49 h (oldest …)', NULL),
                   (3, 300, 'warning', 'gc_quorum', 'GC for tenant initech needs approval by an admin', 'so'),
                   (4, 400, 'critical', 'job_failed', 'backup job 9 (acme) failed: x', NULL);",
            )
            .unwrap();
        }
        let c = Catalog::open(&p).unwrap();
        {
            let conn = c.conn();
            type Row = (String, i64, i64, Option<i64>, Option<String>, i64);
            let rows: Vec<Row> = conn
                .prepare("SELECT key, last_ts, count, resolved_at, resolved_by, notified_ts FROM alerts ORDER BY id")
                .unwrap()
                .query_map([], |r| {
                    Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?))
                })
                .unwrap()
                .collect::<Result<_, _>>()
                .unwrap();
            let keys: Vec<&str> = rows.iter().map(|r| r.0.as_str()).collect();
            assert_eq!(
                keys,
                [
                    "capacity",
                    "offsite_lag:acme",
                    "gc_quorum:initech",
                    "job_failed:backup job 9 (acme) failed: x"
                ]
            );
            assert_eq!((rows[1].1, rows[1].2), (200, 1));
            assert_eq!(
                (rows[2].3, rows[2].4.as_deref()),
                (Some(300), Some("so")),
                "ack = resolved"
            );
            assert_eq!(rows[0].3, None, "unacknowledged stays open");
            assert!(rows.iter().all(|r| r.5 > 0), "nothing redelivered");
        }
        drop(c);
        let old = Connection::open(&p).unwrap();
        let v: i64 = old.pragma_query_value(None, "user_version", |r| r.get(0)).unwrap();
        assert_eq!(MIGRATIONS[..pos].iter().skip(v as usize).count(), 0);
        old.execute_batch(
            "INSERT INTO alerts (ts, severity, kind, message) VALUES (500, 'info', 'x', 'y');
             UPDATE alerts SET acked_by = 'op' WHERE id = 1;",
        )
        .unwrap();
        let n: i64 = old
            .query_row("SELECT count FROM alerts WHERE id = 5", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 1);
    }

    /// v13 (inventory, group modes) on top of the previous schema: existing groups
    /// stay `explicit`, modes are checked, inventory rows go with their source, and
    /// the previous release still reads and writes groups afterwards.
    #[test]
    fn migration_v13_inventory_and_group_modes() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("c.db");
        let prev = MIGRATIONS.len() - 1;
        {
            let c = Connection::open(&p).unwrap();
            c.pragma_update(None, "foreign_keys", "ON").unwrap();
            for (i, m) in MIGRATIONS[..prev].iter().enumerate() {
                c.execute_batch(m).unwrap();
                c.pragma_update(None, "user_version", (i + 1) as i64).unwrap();
            }
            c.execute_batch(
                "INSERT INTO tenants (name) VALUES ('t');
                 INSERT INTO sources (id, tenant, kind, name, config) VALUES (1,'t','pve','p','{}'), (2,'t','truenas','n','{}');
                 INSERT INTO policies (id, name, schedule, gfs) VALUES (1,'p','daily 22:00','{}');
                 INSERT INTO groups (id, tenant, source_id, policy_id, name, guests) VALUES (1,'t',1,1,'g','[100]');",
            )
            .unwrap();
        }
        let c = Catalog::open(&p).unwrap();
        {
            let conn = c.conn();
            let v: i64 = conn.pragma_query_value(None, "user_version", |r| r.get(0)).unwrap();
            assert_eq!(v, MIGRATIONS.len() as i64);
            let (mode, sel, ex): (String, String, String) = conn
                .query_row("SELECT mode, selector, exclude FROM groups WHERE id = 1", [], |r| {
                    Ok((r.get(0)?, r.get(1)?, r.get(2)?))
                })
                .unwrap();
            assert_eq!((mode.as_str(), sel.as_str(), ex.as_str()), ("explicit", "[]", "[]"));
            let ok = |sql: &str| conn.execute(sql, []).is_ok();
            assert!(!ok("UPDATE groups SET mode = 'some' WHERE id = 1"));
            assert!(ok(
                "INSERT INTO groups (tenant, source_id, policy_id, name, guests, mode, selector) VALUES ('t',2,1,'n','[]','tags','[\"pool:tank\"]')"
            ));
            assert!(ok(
                "INSERT INTO inventory (source_id, guest, name, kind, tags, seen) VALUES (1,'100','web','qemu','[]',1)"
            ));
            assert!(!ok(
                "INSERT INTO inventory (source_id, guest, name, kind, tags, seen) VALUES (9,'100','web','qemu','[]',1)"
            ));
            conn.execute_batch("DELETE FROM groups WHERE source_id = 1; DELETE FROM sources WHERE id = 1;")
                .unwrap();
            let n: i64 = conn
                .query_row("SELECT COUNT(*) FROM inventory", [], |r| r.get(0))
                .unwrap();
            assert_eq!(n, 0, "inventory rows go with their source");
        }
        drop(c);
        // the previous release: nothing left to migrate, its group queries still work
        let old = Connection::open(&p).unwrap();
        let v: i64 = old.pragma_query_value(None, "user_version", |r| r.get(0)).unwrap();
        assert_eq!(MIGRATIONS[..prev].iter().skip(v as usize).count(), 0);
        old.execute(
            "INSERT INTO groups (tenant, source_id, policy_id, name, guests) VALUES ('t',2,1,'old','[\"tank\"]')",
            [],
        )
        .unwrap();
        let n: i64 = old.query_row("SELECT COUNT(*) FROM groups", [], |r| r.get(0)).unwrap();
        assert_eq!(n, 2);
    }

    /// v16 (forwarding outbox) on top of the previous catalog: the outbox and
    /// the delivery state start empty; alert raise / ack / resolve and job
    /// completion each add one event, in order; the previous release still
    /// writes alerts and jobs afterwards.
    #[test]
    fn migration_v16_forwarding_outbox() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("c.db");
        let before = MIGRATIONS.iter().position(|m| *m == SCHEMA_V16).unwrap();
        {
            let c = Connection::open(&p).unwrap();
            for (i, m) in MIGRATIONS[..before].iter().enumerate() {
                c.execute_batch(m).unwrap();
                c.pragma_update(None, "user_version", (i + 1) as i64).unwrap();
            }
            c.execute_batch(
                "INSERT INTO jobs (kind, tenant, params, state, requested_by, created) VALUES ('backup','t','{}','running','s',1);
                 INSERT INTO alerts (ts, severity, kind, message) VALUES (1, 'info', 'x', 'old');",
            )
            .unwrap();
        }
        let c = Catalog::open(&p).unwrap();
        {
            let conn = c.conn();
            let v: i64 = conn.pragma_query_value(None, "user_version", |r| r.get(0)).unwrap();
            assert_eq!(v, MIGRATIONS.len() as i64);
            let n = |sql: &str| conn.query_row(sql, [], |r| r.get::<_, i64>(0)).unwrap();
            assert_eq!(n("SELECT COUNT(*) FROM forward_events"), 0);
            assert_eq!(n("SELECT COUNT(*) FROM forward_state"), 0);
            conn.execute_batch(
                "INSERT INTO alerts (ts, last_ts, severity, kind, key, message) VALUES (5, 5, 'warning', 'k', 'k:1', 'm');
                 UPDATE alerts SET count = count + 1 WHERE key = 'k:1';
                 UPDATE alerts SET severity = 'critical' WHERE key = 'k:1';
                 UPDATE alerts SET acked_by = 'alice' WHERE key = 'k:1';
                 UPDATE alerts SET resolved_at = 9, resolved_by = 'alice' WHERE key = 'k:1';
                 UPDATE jobs SET log = 'x';
                 UPDATE jobs SET state = 'ok', finished = 7;
                 UPDATE jobs SET state = 'ok';",
            )
            .unwrap();
            let ev: Vec<(String, String)> = conn
                .prepare("SELECT type, payload FROM forward_events ORDER BY seq")
                .unwrap()
                .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
                .unwrap()
                .collect::<Result<_, _>>()
                .unwrap();
            let events: Vec<(String, String)> = ev
                .iter()
                .map(|(t, p)| {
                    let v: serde_json::Value = serde_json::from_str(p).unwrap();
                    let e = v["event"]
                        .as_str()
                        .map_or_else(|| v["state"].to_string(), str::to_owned);
                    (t.clone(), e)
                })
                .collect();
            let want = [
                ("alert", "raised"),
                ("alert", "escalated"),
                ("alert", "acknowledged"),
                ("alert", "resolved"),
                ("job", "\"ok\""),
            ];
            assert_eq!(events, want.map(|(a, b)| (a.to_owned(), b.to_owned())).to_vec());
            let job: serde_json::Value = serde_json::from_str(&ev[4].1).unwrap();
            assert_eq!(
                (job["finished"].as_i64(), job["kind"].as_str()),
                (Some(7), Some("backup"))
            );
        }
        drop(c);
        let old = Connection::open(&p).unwrap();
        let v: i64 = old.pragma_query_value(None, "user_version", |r| r.get(0)).unwrap();
        assert_eq!(MIGRATIONS[..before].iter().skip(v as usize).count(), 0);
        old.execute_batch(
            "INSERT INTO alerts (ts, severity, kind, message) VALUES (2, 'info', 'y', 'older release');
             INSERT INTO jobs (kind, tenant, params, state, requested_by, created) VALUES ('gc','t','{}','queued','s',2);",
        )
        .unwrap();
    }

    /// v18 (legal holds) on top of the previous catalog: no holds; one open
    /// hold per snapshot, history rows unlimited; the previous release still
    /// deletes snapshot rows afterwards (the holds table is not in its way).
    #[test]
    fn migration_v18_legal_holds() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("c.db");
        let before = MIGRATIONS.iter().position(|m| *m == SCHEMA_V18).unwrap();
        {
            let c = Connection::open(&p).unwrap();
            for (i, m) in MIGRATIONS[..before].iter().enumerate() {
                c.execute_batch(m).unwrap();
                c.pragma_update(None, "user_version", (i + 1) as i64).unwrap();
            }
            c.execute(
                "INSERT INTO snapshots (tenant, source, time, local, offsite) VALUES ('acme', 'vm-100', 5, 1, 0)",
                [],
            )
            .unwrap();
        }
        let c = Catalog::open(&p).unwrap();
        {
            let conn = c.conn();
            let v: i64 = conn.pragma_query_value(None, "user_version", |r| r.get(0)).unwrap();
            assert_eq!(v, MIGRATIONS.len() as i64);
            assert!(holds::held(&conn, "acme").unwrap().is_empty());
            let ins = "INSERT INTO legal_holds (tenant, source, time, state, reason, held_by, held_at) \
                       VALUES ('acme', 'vm-100', 5, ?1, 'case 1', 'sam', 1)";
            conn.execute(ins, ["active"]).unwrap();
            assert!(conn.execute(ins, ["advisory"]).is_err(), "one open hold per snapshot");
            assert!(conn.execute(ins, ["bogus"]).is_err());
            conn.execute("UPDATE legal_holds SET state = 'released'", []).unwrap();
            conn.execute(ins, ["active"]).unwrap();
            assert_eq!(
                holds::held(&conn, "acme").unwrap().into_iter().collect::<Vec<_>>(),
                vec![("vm-100".to_owned(), 5)]
            );
        }
        drop(c);
        let old = Connection::open(&p).unwrap();
        let v: i64 = old.pragma_query_value(None, "user_version", |r| r.get(0)).unwrap();
        assert_eq!(MIGRATIONS[..before].iter().skip(v as usize).count(), 0);
        old.execute("DELETE FROM snapshots WHERE tenant = 'acme'", []).unwrap();
    }

    /// v27 (fleet enrollment) on top of the previous catalog: existing agents keep
    /// working (no fleet), fleets and candidates can be stored, a candidate endpoint
    /// is unique per fleet, the state is checked.
    #[test]
    fn migration_v27_fleets() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("c.db");
        let before = MIGRATIONS.iter().position(|m| *m == SCHEMA_V27).unwrap();
        {
            let c = Connection::open(&p).unwrap();
            for (i, m) in MIGRATIONS[..before].iter().enumerate() {
                c.execute_batch(m).unwrap();
                c.pragma_update(None, "user_version", (i + 1) as i64).unwrap();
            }
            c.execute_batch(
                "INSERT INTO tenants (name) VALUES ('acme');
                 INSERT INTO agents (id, tenant, name, host, port) VALUES ('0123456789abcdef', 'acme', 'web', 'h', 7444);",
            )
            .unwrap();
        }
        let c = Catalog::open(&p).unwrap();
        let conn = c.conn();
        let f: Option<String> = conn.query_row("SELECT fleet_id FROM agents", [], |r| r.get(0)).unwrap();
        assert_eq!(f, None);
        conn.execute_batch(
            "INSERT INTO fleets (id, tenant, name, secret_hash, created, created_by, expires, port)
               VALUES ('00112233aabbccdd', 'acme', 'f', 'sealed', 1, 'alice', 2, 7444);
             INSERT INTO fleet_candidates (fleet_id, host, port, hostname, os, version, first_seen, last_seen)
               VALUES ('00112233aabbccdd', '10.0.0.5', 7444, 'web-1', 'Debian', '0.1', 1, 1);",
        )
        .unwrap();
        assert!(conn
            .execute(
                "INSERT INTO fleet_candidates (fleet_id, host, port, hostname, os, version, first_seen, last_seen)
                 VALUES ('00112233aabbccdd', '10.0.0.5', 7444, 'x', 'x', 'x', 2, 2)",
                [],
            )
            .is_err());
        assert!(conn.execute("UPDATE fleet_candidates SET state = 'maybe'", []).is_err());
    }

    /// v25 (tenant admins) on top of the previous catalog: existing tenants get
    /// distinct uids, new ones get one from the trigger; names and uids are
    /// immutable; old audit entries naming a tenant are indexed (chain intact);
    /// sessions, policies and the previous release keep working.
    #[test]
    fn migration_v25_tenancy() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("c.db");
        let before = MIGRATIONS.iter().position(|m| *m == SCHEMA_V25).unwrap();
        {
            let c = Connection::open(&p).unwrap();
            for (i, m) in MIGRATIONS[..before].iter().enumerate() {
                c.execute_batch(m).unwrap();
                c.pragma_update(None, "user_version", (i + 1) as i64).unwrap();
            }
            c.execute_batch("INSERT INTO tenants (name) VALUES ('acme'), ('globex');")
                .unwrap();
        }
        {
            // entries written by the previous release
            let old = Catalog {
                conn: Mutex::new(Connection::open(&p).unwrap()),
            };
            let raw = |a: &str, t: &str, d: &serde_json::Value| {
                let c = old.conn();
                let (seq, prev): (i64, String) = c
                    .query_row("SELECT seq, hash FROM audit ORDER BY seq DESC LIMIT 1", [], |r| {
                        Ok((r.get(0)?, r.get(1)?))
                    })
                    .optional()
                    .unwrap()
                    .unwrap_or((0, "0".repeat(64)));
                let h = chain_hash(&prev, seq + 1, 5, "alice", a, t, &d.to_string());
                c.execute(
                    "INSERT INTO audit (seq, ts, actor, action, target, details, prev_hash, hash) VALUES (?1,5,'alice',?2,?3,?4,?5,?6)",
                    params![seq + 1, a, t, d.to_string(), prev, h],
                )
                .unwrap();
            };
            raw("tenant.create", "tenant/acme", &json!({}));
            raw("job.create", "job/1", &json!({"tenant": "globex"}));
            raw("settings.x", "settings", &json!({}));
        }
        let c = Catalog::open(&p).unwrap();
        {
            let conn = c.conn();
            let v: i64 = conn.pragma_query_value(None, "user_version", |r| r.get(0)).unwrap();
            assert_eq!(v, MIGRATIONS.len() as i64);
            let uids: Vec<String> = conn
                .prepare("SELECT uid FROM tenants ORDER BY name")
                .unwrap()
                .query_map([], |r| r.get(0))
                .unwrap()
                .collect::<Result<_, _>>()
                .unwrap();
            assert_eq!(uids.len(), 2);
            assert!(uids[0] != uids[1] && uids.iter().all(|u| u.len() == 32));
            assert!(conn
                .execute("UPDATE tenants SET name = 'acme2' WHERE name = 'acme'", [])
                .is_err());
            let idx: Vec<(i64, String)> = conn
                .prepare("SELECT seq, tenant FROM audit_tenants ORDER BY seq")
                .unwrap()
                .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
                .unwrap()
                .collect::<Result<_, _>>()
                .unwrap();
            assert_eq!(idx, vec![(1, "acme".to_owned()), (2, "globex".to_owned())]);
            conn.execute_batch(
                "INSERT INTO policies (id, name, schedule, gfs) VALUES (4, 'p', 'daily 01:00', '{}');
                 INSERT INTO tenant_policies (tenant, policy_id) VALUES ('acme', 4);
                 UPDATE policies SET tier = 'gold';",
            )
            .unwrap();
            assert!(conn.execute("UPDATE policies SET tier = 'platinum'", []).is_err());
        }
        assert_eq!(c.verify_audit().unwrap(), 3);
        drop(c);
        let old = Connection::open(&p).unwrap();
        let v: i64 = old.pragma_query_value(None, "user_version", |r| r.get(0)).unwrap();
        assert_eq!(MIGRATIONS[..before].iter().skip(v as usize).count(), 0);
        old.execute("INSERT INTO tenants (name) VALUES ('initech')", [])
            .unwrap();
        let u: Option<String> = old
            .query_row("SELECT uid FROM tenants WHERE name = 'initech'", [], |r| r.get(0))
            .unwrap();
        assert!(u.is_some_and(|u| u.len() == 32));
    }

    /// v28 (anomaly flags, file change counts) on top of the previous catalog:
    /// existing snapshots are clean, existing stats have no counts; the previous
    /// release still upserts snapshots and stats.
    #[test]
    fn migration_v28_anomaly_flags() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("c.db");
        let before = MIGRATIONS.iter().position(|m| *m == SCHEMA_V28).unwrap();
        {
            let c = Connection::open(&p).unwrap();
            for (i, m) in MIGRATIONS[..before].iter().enumerate() {
                c.execute_batch(m).unwrap();
                c.pragma_update(None, "user_version", (i + 1) as i64).unwrap();
            }
            c.execute_batch(
                "INSERT INTO snapshots (tenant, source, time, local, offsite) VALUES ('t', 'host-a', 5, 1, 0);
                 INSERT INTO backup_stats (tenant, source, time, read, logical, new_chunks, new_plain, new_stored)
                   VALUES ('t', 'host-a', 5, 1, 1, 1, 1, 1);",
            )
            .unwrap();
        }
        let c = Catalog::open(&p).unwrap();
        {
            let conn = c.conn();
            let row: (Option<String>, Option<i64>) = conn
                .query_row(
                    "SELECT s.anomaly, b.files_added FROM snapshots s JOIN backup_stats b USING (tenant, source, time)",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .unwrap();
            assert_eq!(row, (None, None));
            conn.execute("UPDATE snapshots SET anomaly = 'x', anomaly_at = 6", [])
                .unwrap();
        }
        drop(c);
        let old = Connection::open(&p).unwrap();
        old.execute(
            "INSERT INTO snapshots (tenant, source, time, local, offsite) VALUES ('t', 'host-a', 5, 1, 0) \
             ON CONFLICT (tenant, source, time) DO UPDATE SET local = 1",
            [],
        )
        .unwrap();
        old.execute(
            "INSERT INTO backup_stats (tenant, source, time, read, logical, new_chunks, new_plain, new_stored) \
             VALUES ('t', 'host-a', 7, 1, 1, 1, 1, 1)",
            [],
        )
        .unwrap();
        let a: Option<String> = old
            .query_row("SELECT anomaly FROM snapshots WHERE time = 5", [], |r| r.get(0))
            .unwrap();
        assert_eq!(a.as_deref(), Some("x"), "the flag survives the refresh upsert");
    }

    /// v32 (damaged snapshots) on top of the previous catalog: existing
    /// snapshots are healthy; the flag survives the scheduler's refresh upsert.
    #[test]
    fn migration_v32_damaged_snapshots() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("c.db");
        let before = MIGRATIONS.iter().position(|m| *m == SCHEMA_V32).unwrap();
        {
            let c = Connection::open(&p).unwrap();
            for (i, m) in MIGRATIONS[..before].iter().enumerate() {
                c.execute_batch(m).unwrap();
                c.pragma_update(None, "user_version", (i + 1) as i64).unwrap();
            }
            c.execute_batch(
                "INSERT INTO snapshots (tenant, source, time, local, offsite) VALUES ('t', 'vm-1', 5, 1, 0);",
            )
            .unwrap();
        }
        let c = Catalog::open(&p).unwrap();
        let conn = c.conn();
        let d: Option<i64> = conn
            .query_row("SELECT damaged FROM snapshots", [], |r| r.get(0))
            .unwrap();
        assert_eq!(d, None);
        conn.execute("UPDATE snapshots SET damaged = 2, damaged_at = 6", [])
            .unwrap();
        conn.execute(
            "INSERT INTO snapshots (tenant, source, time, local, offsite) VALUES ('t', 'vm-1', 5, 1, 0) \
             ON CONFLICT (tenant, source, time) DO UPDATE SET local = 1",
            [],
        )
        .unwrap();
        let d: Option<i64> = conn
            .query_row("SELECT damaged FROM snapshots", [], |r| r.get(0))
            .unwrap();
        assert_eq!(d, Some(2));
    }

    /// v33 (YARA rules, scan results) on top of the previous catalog.
    #[test]
    fn migration_v33_snapshot_scans() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("c.db");
        let before = MIGRATIONS.iter().position(|m| *m == SCHEMA_V33).unwrap();
        {
            let c = Connection::open(&p).unwrap();
            for (i, m) in MIGRATIONS[..before].iter().enumerate() {
                c.execute_batch(m).unwrap();
                c.pragma_update(None, "user_version", (i + 1) as i64).unwrap();
            }
        }
        let c = Catalog::open(&p).unwrap();
        let conn = c.conn();
        conn.execute_batch(
            "INSERT INTO yara_rules VALUES ('r.yar', 'rule x { condition: true }', 'ab', 'alice', 1);
             INSERT INTO snapshot_scans (job_id, tenant, source, time, finished, rules, files, skipped, errors,
               complete, matches_total, matches)
             VALUES (7, 't', 'vm-100', 5, 9, 'ab', 10, 1, 0, 1, 1, '[{\"rule\":\"r.yar:x\",\"path\":\"/vda1/a\"}]');",
        )
        .unwrap();
        let n: i64 = conn
            .query_row(
                "SELECT matches_total FROM snapshot_scans WHERE tenant='t' AND source='vm-100' AND time=5",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(n, 1);
        assert!(conn
            .execute("INSERT INTO yara_rules VALUES ('r.yar', 'x', 'cd', 'bob', 2)", [])
            .is_err());
    }

    /// v37 (tenant IdPs, offsite capacity samples) on top of the previous catalog:
    /// old samples have no offsite figure; an IdP row needs an existing tenant.
    #[test]
    fn migration_v37_tenant_idps() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("c.db");
        let before = MIGRATIONS.iter().position(|m| *m == SCHEMA_V37).unwrap();
        {
            let c = Connection::open(&p).unwrap();
            for (i, m) in MIGRATIONS[..before].iter().enumerate() {
                c.execute_batch(m).unwrap();
                c.pragma_update(None, "user_version", (i + 1) as i64).unwrap();
            }
            c.execute_batch(
                "INSERT INTO tenants (name) VALUES ('acme');
                 INSERT INTO capacity_samples (day, tenant, used, logical) VALUES ('2026-10-11', 'acme', 1, 2);",
            )
            .unwrap();
        }
        let c = Catalog::open(&p).unwrap();
        let conn = c.conn();
        let o: Option<i64> = conn
            .query_row("SELECT offsite FROM capacity_samples", [], |r| r.get(0))
            .unwrap();
        assert_eq!(o, None);
        conn.execute("INSERT INTO tenant_idps (tenant, settings) VALUES ('acme', '{}')", [])
            .unwrap();
        let domains: String = conn
            .query_row("SELECT domains FROM tenant_idps", [], |r| r.get(0))
            .unwrap();
        assert_eq!(domains, "[]");
        assert!(conn
            .execute("INSERT INTO tenant_idps (tenant, settings) VALUES ('ghost', '{}')", [])
            .is_err());
    }

    /// v40 (live job progress) on top of the previous catalog: existing jobs
    /// have neither; a running job gets both, the old release's final write
    /// (`log = log || …`) still works.
    #[test]
    fn migration_v40_job_progress() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("c.db");
        let before = MIGRATIONS.iter().position(|m| *m == SCHEMA_V40).unwrap();
        {
            let c = Connection::open(&p).unwrap();
            for (i, m) in MIGRATIONS[..before].iter().enumerate() {
                c.execute_batch(m).unwrap();
                c.pragma_update(None, "user_version", (i + 1) as i64).unwrap();
            }
            c.execute_batch(
                "INSERT INTO jobs (kind, tenant, params, state, requested_by, created) VALUES ('backup','t','{}','running','s',1);",
            )
            .unwrap();
        }
        let c = Catalog::open(&p).unwrap();
        let conn = c.conn();
        let (l, pr): (Option<String>, Option<String>) = conn
            .query_row("SELECT live_log, progress FROM jobs", [], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .unwrap();
        assert_eq!((l, pr), (None, None));
        conn.execute_batch(
            r#"UPDATE jobs SET live_log = 'item 1/2: vm-100' || char(10), progress = '{"items":2}';
               UPDATE jobs SET state = 'ok', log = log || 'committed vm-100/5', live_log = NULL, progress = NULL;"#,
        )
        .unwrap();
        let log: String = conn.query_row("SELECT log FROM jobs", [], |r| r.get(0)).unwrap();
        assert_eq!(log, "committed vm-100/5");
    }

    /// v39 (edge proxies) on top of the previous catalog: agents keep working
    /// without an edge.
    #[test]
    fn migration_v39_edges() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("c.db");
        let before = MIGRATIONS.iter().position(|m| *m == SCHEMA_V39).unwrap();
        {
            let c = Connection::open(&p).unwrap();
            for (i, m) in MIGRATIONS[..before].iter().enumerate() {
                c.execute_batch(m).unwrap();
                c.pragma_update(None, "user_version", (i + 1) as i64).unwrap();
            }
            c.execute_batch(
                "INSERT INTO tenants (name) VALUES ('t'); \
                 INSERT INTO agents (id, tenant, name, host, port) VALUES ('0123456789abcdef', 't', 'lap', 'h', 7444);",
            )
            .unwrap();
        }
        let c = Catalog::open(&p).unwrap();
        let conn = c.conn();
        let e: Option<String> = conn.query_row("SELECT edge_id FROM agents", [], |r| r.get(0)).unwrap();
        assert_eq!(e, None);
        conn.execute_batch(
            "INSERT INTO edges (id, name, host, public_host, created, created_by) \
             VALUES ('e1', 'dmz', '10.0.0.5', 'edge.example.com', 1, 'alice');
             UPDATE agents SET edge_id = 'e1', via = 'edge';",
        )
        .unwrap();
        let ports: (i64, i64) = conn
            .query_row("SELECT port, public_port FROM edges", [], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .unwrap();
        assert_eq!(ports, (7445, 443));
        assert!(
            conn.execute(
                "INSERT INTO edges (id, name, host, public_host, created, created_by) VALUES ('e2', 'dmz', 'x', 'y', 1, 'a')",
                [],
            )
            .is_err(),
            "names are unique"
        );
    }

    /// v43 (Phase 28) on top of the previous catalog: a scanned snapshot gets
    /// its state from the newest scan, groups keep scanning and hashing off.
    #[test]
    fn migration_v43_threat_scans_hashes_lockdown_devices() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("c.db");
        let before = MIGRATIONS.iter().position(|m| *m == SCHEMA_V43).unwrap();
        {
            let c = Connection::open(&p).unwrap();
            for (i, m) in MIGRATIONS[..before].iter().enumerate() {
                c.execute_batch(m).unwrap();
                c.pragma_update(None, "user_version", (i + 1) as i64).unwrap();
            }
            c.execute_batch(
                "INSERT INTO tenants (name) VALUES ('t');
                 INSERT INTO snapshots (tenant, source, time, size, local, offsite, lock_until) VALUES
                   ('t','vm-1',1,0,1,0,0), ('t','vm-1',2,0,1,0,0), ('t','vm-1',3,0,1,0,0), ('t','vm-1',4,0,1,0,0);
                 INSERT INTO snapshot_scans (job_id, tenant, source, time, finished, rules, files, skipped, errors,
                   complete, matches_total) VALUES
                   (1,'t','vm-1',1,1,'r',5,0,0,1,0), (2,'t','vm-1',2,1,'r',5,0,0,1,3),
                   (3,'t','vm-1',3,1,'r',5,0,0,0,0), (4,'t','vm-1',1,1,'r',5,0,0,1,1);",
            )
            .unwrap();
        }
        let c = Catalog::open(&p).unwrap();
        let conn = c.conn();
        let states: Vec<Option<String>> = conn
            .prepare("SELECT scan_state FROM snapshots ORDER BY time")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        // snapshot 1: the newest scan (job 4) found a match
        assert_eq!(
            states,
            [Some("hit".into()), Some("hit".into()), Some("incomplete".into()), None]
        );
        conn.execute_batch(
            "INSERT INTO users (name, password_hash, totp_secret, role, created) VALUES ('ann','x','y','admin',1);
             INSERT INTO login_devices (user_id, fingerprint, family, prefix, first_seen, last_seen)
               VALUES (1, 'f', 'Firefox on Linux', '192.0.2.0/24', 1, 1);
             INSERT INTO tenant_lockdowns (tenant, active, state) VALUES ('t', 1, '{}');
             INSERT INTO hash_lists (name, hashes, count, sha256, uploaded_by, uploaded_at) VALUES ('l','',0,'x','ann',1);",
        )
        .unwrap();
        assert!(conn
            .execute(
                "INSERT INTO login_devices (user_id, fingerprint, family, prefix, first_seen, last_seen) VALUES (1,'f','a','b',1,1)",
                [],
            )
            .is_err());
        conn.execute("DELETE FROM users", []).unwrap();
        let n: i64 = conn
            .query_row("SELECT COUNT(*) FROM login_devices", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 0, "devices go with the account");
    }
}
