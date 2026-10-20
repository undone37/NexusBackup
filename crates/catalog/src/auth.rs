//! Password hashing (argon2id) and TOTP (RFC 6238, SHA-1, 6 digits, 30 s),
//! shared by web-api (login) and nexus-setup (first admin).

use anyhow::{anyhow, Result};
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use totp_rs::{Algorithm, Builder, Secret, Totp};

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

/// One-time code (agent enrollment tokens, activation codes): 128 bit from the
/// OS CSPRNG, base32 without padding (26 characters).
pub fn new_code() -> String {
    const A: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let b: [u8; 16] = rand::random();
    let mut out = String::new();
    let (mut acc, mut bits) = (0u32, 0);
    for x in b {
        acc = (acc << 8) | u32::from(x);
        bits += 8;
        while bits >= 5 {
            out.push(A[((acc >> (bits - 5)) & 31) as usize] as char);
            bits -= 5;
        }
    }
    if bits > 0 {
        out.push(A[((acc << (5 - bits)) & 31) as usize] as char);
    }
    out
}

/// New random TOTP secret (base32, 160 bit).
pub fn new_totp_secret() -> String {
    Secret::generate().to_base32()
}

fn totp(secret_b32: &str, account: &str) -> Result<Totp> {
    let secret = Secret::try_from_base32(secret_b32).map_err(|e| anyhow!("totp secret: {e}"))?;
    Builder::new()
        .with_algorithm(Algorithm::SHA1)
        .with_digits(6)
        .with_skew(1)
        .with_step_duration(30)
        .with_secret(secret)
        .with_issuer(Some("NexusBackup"))
        .with_account_name(account)
        .build()
        .map_err(|e| anyhow!("{e}"))
}

/// `otpauth://` URI for authenticator apps (QR code).
pub fn totp_uri(secret_b32: &str, account: &str) -> Result<String> {
    totp(secret_b32, account)?.to_url().map_err(|e| anyhow!("{e}"))
}

/// Accepts the current code and one step of clock skew either way.
pub fn totp_check(secret_b32: &str, code: &str) -> bool {
    totp_step(secret_b32, code).is_some()
}

/// Like `totp_check`, but returns the matched 30 s step so callers can refuse
/// replays (accept only steps greater than the last accepted one).
pub fn totp_step(secret_b32: &str, code: &str) -> Option<u64> {
    totp(secret_b32, "x").ok()?.check_current(code.trim())
}

pub fn totp_now(secret_b32: &str) -> Result<String> {
    Ok(totp(secret_b32, "x")?.generate_current().to_string())
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

    /// RFC 6238 appendix B (SHA-1 secret "12345678901234567890"): stored secrets keep their codes across
    /// totp-rs upgrades; 32 base32 characters as new_totp_secret writes them.
    #[test]
    fn totp_rfc6238_vectors() {
        let t = totp("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", "x").unwrap();
        for (time, code) in [
            (59, "287082"),
            (1111111109, "081804"),
            (1234567890, "005924"),
            (2000000000, "279037"),
        ] {
            assert_eq!(t.generate(time).to_string(), code);
            assert_eq!(t.check(code, time), Some(time / 30));
        }
        assert_eq!(new_totp_secret().len(), 32);
    }
}
