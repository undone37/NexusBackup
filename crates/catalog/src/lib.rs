//! Catalog (plan §11.3, docs/control-plane.md): SQLite in WAL mode shared by
//! web-api (intent) and scheduler (execution), plus the hash-chained audit log.

use anyhow::{bail, Result};
use rusqlite::{params, Connection, OptionalExtension};
use sha2::{Digest, Sha256};
use std::path::Path;
use std::sync::{Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

pub mod auth;
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

const MIGRATIONS: &[&str] = &[SCHEMA_V1];

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
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.busy_timeout(std::time::Duration::from_secs(10))?;
        let version: i64 = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
        for (i, m) in MIGRATIONS.iter().enumerate().skip(version as usize) {
            let tx = conn.unchecked_transaction()?;
            tx.execute_batch(m)?;
            tx.pragma_update(None, "user_version", (i + 1) as i64)?;
            tx.commit()?;
        }
        Ok(Catalog { conn: Mutex::new(conn) })
    }

    pub fn open_memory() -> Result<Self> {
        let c = Catalog {
            conn: Mutex::new(Connection::open_in_memory()?),
        };
        c.conn().execute_batch(SCHEMA_V1)?;
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
        assert_eq!(v, 1);
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
}
