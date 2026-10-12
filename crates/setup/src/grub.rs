//! Boot menu password (Phase 18, docs/control-plane.md "Boot menu password").
//!
//! GRUB's menu entries boot unattended (the bootc/BLS entries are unrestricted),
//! but editing an entry or the GRUB command line needs the superuser `root` and
//! its password: without it a console user could add `init=/bin/sh` or `rd.break`
//! and bypass the console gate. The password is not a second secret: it is
//! derived from the recovery key (whoever holds the key can compute it, also on
//! another computer: manual chapter 14):
//!
//! ```text
//! d = HMAC-SHA256(key = the 32 bytes of the recovery key, "nexus-grub-password-v1")
//! n = first 16 bytes of d as a big-endian integer
//! password = 20 letters: ALPHABET[n % 20], then n //= 20, repeated
//! ```
//!
//! The alphabet avoids letters that sit elsewhere on German or French keyboards
//! (GRUB reads the keyboard as US layout). nexus-setup writes the PBKDF2 hash to
//! `/etc/nexus/grub-user.cfg` (`GRUB2_PASSWORD=grub.pbkdf2.sha512.…`); the root
//! oneshot nexus-grub-password installs it as `/boot/grub2/user.cfg`, which the
//! static GRUB configuration (bootupd's `01_users.cfg`) sources.

use anyhow::{Context, Result};
use ring::{hmac, pbkdf2};
use std::num::NonZeroU32;
use zeroize::Zeroizing;

/// No a, m, q, w, y, z: those move between US, QWERTZ and AZERTY layouts.
pub const ALPHABET: &[u8; 20] = b"bcdefghijklnoprstuvx";
pub const LEN: usize = 20;
const LABEL: &[u8] = b"nexus-grub-password-v1";
/// grub2-mkpasswd-pbkdf2's defaults
const ITERATIONS: u32 = 10_000;
const SALT_LEN: usize = 64;
const HASH_LEN: usize = 64;

/// The boot menu password of a recovery key (as printed: groups, any case).
pub fn password(recovery_key: &str) -> Result<Zeroizing<String>> {
    let rk = keyd::parse_recovery_key(recovery_key).context("recovery key")?;
    let tag = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, &rk[..]), LABEL);
    let mut n = u128::from_be_bytes(tag.as_ref()[..16].try_into().unwrap());
    let mut out = Zeroizing::new(String::with_capacity(LEN));
    for _ in 0..LEN {
        out.push(ALPHABET[(n % 20) as usize] as char);
        n /= 20;
    }
    Ok(out)
}

/// Shown in groups of five; typed without the spaces.
pub fn grouped(pw: &str) -> String {
    pw.as_bytes()
        .chunks(5)
        .map(|c| std::str::from_utf8(c).unwrap())
        .collect::<Vec<_>>()
        .join(" ")
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02X}")).collect()
}

/// `grub.pbkdf2.sha512.<iterations>.<SALT>.<HASH>` as grub2-mkpasswd-pbkdf2 prints it.
pub fn pbkdf2_hash(pw: &str, salt: &[u8]) -> String {
    let mut out = [0u8; HASH_LEN];
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA512,
        NonZeroU32::new(ITERATIONS).unwrap(),
        salt,
        pw.as_bytes(),
        &mut out,
    );
    format!("grub.pbkdf2.sha512.{ITERATIONS}.{}.{}", hex(salt), hex(&out))
}

/// Content of `user.cfg` (a fresh random salt).
pub fn user_cfg(pw: &str) -> String {
    let mut salt = [0u8; SALT_LEN];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut salt);
    format!("GRUB2_PASSWORD={}\n", pbkdf2_hash(pw, &salt))
}

#[cfg(test)]
mod tests {
    use super::*;

    const RK: &str = "abab-abab-abab-abab-abab-abab-abab-abab-abab-abab-abab-abab-abab-abab-abab-abab";

    /// Fixed vector: the manual's Python one-liner must print the same.
    #[test]
    fn derivation_is_stable() {
        let pw = password(RK).unwrap();
        assert_eq!(pw.len(), LEN);
        assert!(pw.bytes().all(|b| ALPHABET.contains(&b)));
        assert_eq!(
            *pw,
            *password(&RK.to_ascii_uppercase().replace('-', " ")).unwrap(),
            "format-insensitive"
        );
        assert_eq!(&*pw, "iohfkgkeirouljustevo", "also what the manual's Python prints");
        assert_ne!(*pw, *password(&"cd".repeat(32)).unwrap());
        assert!(password("nope").is_err());
        assert_eq!(grouped("abcdefghijklmnopqrst"), "abcde fghij klmno pqrst");
    }

    /// RFC 6070-style check of the PBKDF2-HMAC-SHA512 parameters, and GRUB's text format.
    #[test]
    fn grub_hash_format() {
        let h = pbkdf2_hash("password", b"salt");
        let parts: Vec<&str> = h.split('.').collect();
        assert_eq!(&parts[..4], ["grub", "pbkdf2", "sha512", "10000"]);
        assert_eq!(parts[4], "73616C74");
        assert_eq!(parts[5].len(), 128);
        // PBKDF2-HMAC-SHA512("password", "salt", 10000) as Python's hashlib computes it
        assert!(parts[5].starts_with("72629A41B076E588"), "{}", parts[5]);
        // what `grub2-mkpasswd-pbkdf2` (AlmaLinux 10, grub2 2.12) printed for "testpw"
        let grub = "grub.pbkdf2.sha512.10000.7837C7BCD73793EAC5F09450901F5D5647561F61CD85324872A491FC2AC7ED335070639B5BE51F98766E97ED400AEAE29D17128555CC091DBE337D2E425C1C00.089C813E3E04DEE9E935ADF9EA9E52B4E7921C61418F9B7750DD3AF479E58BD0638679083EA32F21148980013501531F6DD0CE82C17D80F9FD79DE1EBF5D67A4";
        let salt = grub.split('.').nth(4).unwrap();
        let salt: Vec<u8> = (0..salt.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&salt[i..i + 2], 16).unwrap())
            .collect();
        assert_eq!(pbkdf2_hash("testpw", &salt), grub);
        let cfg = user_cfg("x");
        assert!(cfg.starts_with("GRUB2_PASSWORD=grub.pbkdf2.sha512.10000.") && cfg.ends_with('\n'));
        assert_eq!(cfg.trim_end().rsplit('.').nth(1).unwrap().len(), 128, "64-byte salt");
    }
}
