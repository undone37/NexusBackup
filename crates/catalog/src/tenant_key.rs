//! Optional per-tenant recovery key (Phase 17e, docs/key-management.md
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

/// A new tenant recovery key: 256 random bits written like the appliance
/// recovery key (16 groups of 4 hex digits, `keyd::format_recovery_key`), and
/// its X25519 public key (hex). The key itself is the X25519 secret key.
pub fn generate() -> (Zeroizing<String>, String) {
    let k = Zeroizing::new(rand::random::<[u8; 32]>());
    let h = Zeroizing::new(hex(&k[..]));
    let key = Zeroizing::new((0..16).map(|i| &h[i * 4..i * 4 + 4]).collect::<Vec<_>>().join("-"));
    let public = crypto_box::SecretKey::from_bytes(*k).public_key();
    (key, hex(public.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_format_and_public_key() {
        let (k, p) = generate();
        let groups: Vec<&str> = k.split('-').collect();
        assert_eq!(groups.len(), 16);
        assert!(groups
            .iter()
            .all(|g| g.len() == 4 && g.bytes().all(|b| b.is_ascii_hexdigit())));
        let raw: String = groups.concat();
        let mut sk = [0u8; 32];
        for (i, b) in sk.iter_mut().enumerate() {
            *b = u8::from_str_radix(&raw[2 * i..2 * i + 2], 16).unwrap();
        }
        let expect = crypto_box::SecretKey::from_bytes(sk).public_key();
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
