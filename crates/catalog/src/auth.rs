//! Password hashing (argon2id) and TOTP (RFC 6238, SHA-1, 6 digits, 30 s),
//! shared by web-api (login) and nexus-setup (first admin).

use anyhow::{anyhow, Result};
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use totp_rs::{Algorithm, Secret, TOTP};

pub fn hash_password(pw: &str) -> Result<String> {
    if pw.chars().count() < 12 {
        return Err(anyhow!("password must have at least 12 characters"));
    }
    Ok(Argon2::default()
        .hash_password(
            pw.as_bytes(),
            &SaltString::encode_b64(&rand::random::<[u8; 16]>()).map_err(|e| anyhow!("{e}"))?,
        )
        .map_err(|e| anyhow!("{e}"))?
        .to_string())
}

pub fn verify_password(pw: &str, hash: &str) -> bool {
    PasswordHash::new(hash).is_ok_and(|h| Argon2::default().verify_password(pw.as_bytes(), &h).is_ok())
}

/// New random TOTP secret (base32, 160 bit).
pub fn new_totp_secret() -> String {
    Secret::generate_secret().to_encoded().to_string()
}

fn totp(secret_b32: &str, account: &str) -> Result<TOTP> {
    let raw = Secret::Encoded(secret_b32.to_owned())
        .to_bytes()
        .map_err(|e| anyhow!("totp secret: {e:?}"))?;
    TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        raw,
        Some("NexusBackup".into()),
        account.into(),
    )
    .map_err(|e| anyhow!("{e}"))
}

/// `otpauth://` URI for authenticator apps (QR code).
pub fn totp_uri(secret_b32: &str, account: &str) -> Result<String> {
    Ok(totp(secret_b32, account)?.get_url())
}

/// Accepts the current code and one step of clock skew either way.
pub fn totp_check(secret_b32: &str, code: &str) -> bool {
    totp(secret_b32, "x").is_ok_and(|t| t.check_current(code.trim()).unwrap_or(false))
}

/// Like `totp_check`, but returns the matched 30 s step so callers can refuse
/// replays (accept only steps greater than the last accepted one).
pub fn totp_step(secret_b32: &str, code: &str) -> Option<u64> {
    let t = totp(secret_b32, "x").ok()?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs()
        / 30;
    let code = code.trim();
    (now.saturating_sub(1)..=now + 1).find(|s| {
        let want = t.generate(s * 30);
        want.len() == code.len() && want.bytes().zip(code.bytes()).fold(0u8, |acc, (a, b)| acc | (a ^ b)) == 0
    })
}

pub fn totp_now(secret_b32: &str) -> Result<String> {
    totp(secret_b32, "x")?.generate_current().map_err(|e| anyhow!("{e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_and_totp() {
        assert!(hash_password("short").is_err());
        let h = hash_password("correct horse battery").unwrap();
        assert!(h.starts_with("$argon2id$"));
        assert!(verify_password("correct horse battery", &h) && !verify_password("wrong horse battery", &h));
        let s = new_totp_secret();
        assert!(totp_check(&s, &totp_now(&s).unwrap()));
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            / 30;
        assert!(totp_step(&s, &totp_now(&s).unwrap()).is_some_and(|st| st + 1 >= now && st <= now + 1));
        assert_eq!(totp_step(&s, "12345"), None);
        assert!(!totp_check(&s, "000000") || totp_now(&s).unwrap() == "000000");
        assert!(totp_uri(&s, "admin")
            .unwrap()
            .starts_with("otpauth://totp/NexusBackup:admin?"));
    }
}
