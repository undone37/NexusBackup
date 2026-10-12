//! Catalog (plan §11.3, docs/control-plane.md): SQLite in WAL mode shared by
//! web-api (intent) and scheduler (execution), plus the hash-chained audit log.

use anyhow::{bail, Result};
use rusqlite::{params, Connection, OptionalExtension};
use sha2::{Digest, Sha256};
use std::path::Path;
use std::sync::{Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

pub mod alerting;
pub mod auth;
pub mod inventory;
pub mod schedule;
pub mod secret;
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

const MIGRATIONS: &[&str] = &[
    SCHEMA_V1, SCHEMA_V2, SCHEMA_V3, SCHEMA_V4, SCHEMA_V5, SCHEMA_V6, SCHEMA_V7, SCHEMA_V8, SCHEMA_V9, SCHEMA_V10,
    SCHEMA_V11, SCHEMA_V12, SCHEMA_V13, SCHEMA_V14,
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

/// Users who could approve a quorum request: enabled, activated admins and
/// security officers.
pub fn possible_approvers(c: &Connection) -> rusqlite::Result<Vec<String>> {
    c.prepare(
        "SELECT name FROM users WHERE role IN ('admin','security_officer') AND disabled = 0
         AND activation_hash IS NULL ORDER BY name",
    )?
    .query_map([], |r| r.get(0))?
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
}
