//! Optional per-tenant recovery key (Phase 17e, docs/control-plane.md
//! "Tenant recovery key"). The web-api generates the key when the approved
//! requester opens it (shown once, never stored) and keeps only its X25519
//! public key in the setting [`setting_key`]; the scheduler hands that to keyd,
//! which seals every DEK version of the tenant to it for the offsite copy.

use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// The quorum action (approval by a second person while approvals are enabled).
pub const ACTION: &str = "tenant.recovery_key";
/// An approved request must be opened within this time.
pub const SHOW_TTL_SECS: i64 = 24 * 3600;

/// What the catalog knows about a tenant's recovery key (no secret).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Status {
    /// X25519 public key, 64 hex digits
    pub public: String,
    /// first 16 hex digits of `public` (the escrow file names offsite carry it)
    pub kid: String,
    /// Phase 30: the ML-KEM-768 encapsulation key derived from the same secret
    /// (hex; keys set before have none and keep X25519-only escrow files)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_pq: Option<String>,
    pub set_at: i64,
    pub requested_by: String,
    pub approved_by: String,
    pub quorum: i64,
}

pub fn setting_key(tenant: &str) -> String {
    format!("tenant_recovery_key:{tenant}")
}

pub fn get(c: &Connection, tenant: &str) -> rusqlite::Result<Option<Status>> {
    Ok(crate::setting(c, &setting_key(tenant))?.and_then(|v| serde_json::from_str(&v).ok()))
}

pub fn put(c: &Connection, tenant: &str, s: &Status) -> rusqlite::Result<()> {
    crate::set_setting(
        c,
        &setting_key(tenant),
        &serde_json::to_string(s).expect("serializable"),
    )
}

pub fn remove(c: &Connection, tenant: &str) -> rusqlite::Result<()> {
    c.execute("DELETE FROM settings WHERE key = ?1", [setting_key(tenant)])?;
    Ok(())
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// The public key keyd seals the escrow to: X25519, followed by the ML-KEM-768
/// key when there is one (`keyd::hybrid`).
pub fn sealing_key(s: &Status) -> Option<Vec<u8>> {
    let mut out = parse_public(&s.public)?.to_vec();
    if let Some(pq) = &s.public_pq {
        if pq.len() % 2 != 0 {
            return None;
        }
        for i in (0..pq.len()).step_by(2) {
            out.push(u8::from_str_radix(pq.get(i..i + 2)?, 16).ok()?);
        }
    }
    Some(out)
}

/// Public key bytes of a [`Status::public`].
pub fn parse_public(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(s.get(2 * i..2 * i + 2)?, 16).ok()?;
    }
    Some(out)
}

/// The ML-KEM-768 seed context of `keyd::tenant_key::RECOVERY_CONTEXT` (the
/// scheduler's tests check both give the same key).
const RECOVERY_CONTEXT: &str = "NexusBackup 2026 tenant-recovery ml-kem-768 v1";

/// ML-KEM-768 encapsulation key (hex) of a tenant recovery secret: the seed is
/// BLAKE3's derive-key output over the secret (`keyd::hybrid::Secret::derive`).
pub fn pq_public(secret: &[u8; 32]) -> String {
    use ml_kem::kem::KeyExport;
    let mut seed = Zeroizing::new([0u8; 64]);
    blake3::Hasher::new_derive_key(RECOVERY_CONTEXT)
        .update(secret)
        .finalize_xof()
        .fill(&mut seed[..]);
    let dk = ml_kem::ml_kem_768::DecapsulationKey::from_seed(ml_kem::Seed::from(*seed));
    hex(&dk.encapsulation_key().to_bytes())
}

/// A new tenant recovery key: 256 random bits written like the appliance
/// recovery key (24 BIP39 words, `recovery_key::format`), its
/// X25519 public key (hex; the key itself is the X25519 secret key) and, since
/// Phase 30, the ML-KEM-768 public key derived from it (hex, [`pq_public`]).
pub fn generate() -> (Zeroizing<String>, String, String) {
    let k = Zeroizing::new(rand::random::<[u8; 32]>());
    let key = Zeroizing::new(recovery_key::format(&k));
    let public = crypto_box::SecretKey::from_bytes(*k).public_key();
    (key, hex(public.as_bytes()), pq_public(&k))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_format_and_public_key() {
        let (k, p, pq) = generate();
        assert_eq!(pq.len(), 2 * 1184);
        assert_eq!(k.split(' ').count(), 24);
        let sk = recovery_key::parse(&k).unwrap();
        let expect = crypto_box::SecretKey::from_bytes(*sk).public_key();
        assert_eq!(parse_public(&p).unwrap(), *expect.as_bytes());
        assert_ne!(generate().0, k, "random");
        assert!(parse_public("zz").is_none());
    }

    #[test]
    fn status_roundtrip() {
        let cat = crate::Catalog::open_memory().unwrap();
        let c = cat.conn();
        assert_eq!(get(&c, "acme").unwrap(), None);
        let s = Status {
            public: "ab".repeat(32),
            kid: "ab".repeat(8),
            public_pq: None,
            set_at: 5,
            requested_by: "alice".into(),
            approved_by: "bob".into(),
            quorum: 3,
        };
        put(&c, "acme", &s).unwrap();
        assert_eq!(get(&c, "acme").unwrap(), Some(s));
        remove(&c, "acme").unwrap();
        assert_eq!(get(&c, "acme").unwrap(), None);
    }
}
