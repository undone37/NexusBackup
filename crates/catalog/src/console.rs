//! Emergency console root access (Phase 14c, docs/control-plane.md "Console
//! root shell"): one-time unlock codes, shared by the web-api, which issues
//! them after an approved `console.unlock` request, and the console gate on
//! tty2 (`nexus-console-gate`, crates/setup), which accepts them.
//!
//! The web-api writes one file per code into [`UNLOCK_DIR`] (SELinux: only
//! nexus_webapi_t creates them, only the gate reads and deletes them). It holds
//! the SHA-256 of the code, never the code itself: 100 random bits make a slow
//! hash unnecessary, and the gate limits attempts anyway.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

/// The quorum action (approval by a second person while approvals are enabled).
pub const ACTION: &str = "console.unlock";
/// Longest root shell, for codes and for the recovery key alike.
pub const MAX_HOURS: u32 = 8;
/// A code must be fetched and used within this time after the approval.
pub const CODE_TTL_SECS: i64 = 24 * 3600;
pub const UNLOCK_DIR: &str = "/var/lib/nexus/console-unlock";
/// Setting written by the gate while a root shell runs (UI banner):
/// `{at, until, method, unlock, alert}`.
pub const SHELL_SETTING: &str = "console_shell_active";

/// One issued code (`<UNLOCK_DIR>/<id>.json`, `id` = the quorum request).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Unlock {
    pub id: i64,
    /// [`hash`] of the code
    pub hash: String,
    pub hours: u32,
    pub requested_by: String,
    pub approved_by: String,
    pub reason: String,
    pub issued: i64,
    /// approval + [`CODE_TTL_SECS`]
    pub expires: i64,
}

/// Crockford base32: no I, L, O, U (read aloud or typed from a phone).
const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const GROUPS: usize = 4;
const GROUP_LEN: usize = 5;

/// 4 groups of 5 characters (100 bits), e.g. `7K3QD-1M9ZX-...`.
pub fn new_code() -> String {
    let b: [u8; GROUPS * GROUP_LEN] = rand::random();
    let chars: Vec<char> = b.iter().map(|x| ALPHABET[usize::from(x & 31)] as char).collect();
    chars
        .chunks(GROUP_LEN)
        .map(|g| g.iter().collect::<String>())
        .collect::<Vec<_>>()
        .join("-")
}

/// Canonical form of typed input: case, spaces and dashes ignored, O/I/L read
/// as 0/1/1. `None` unless it has exactly the code's length and alphabet.
pub fn normalize(input: &str) -> Option<String> {
    let s: String = input
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .map(|c| match c.to_ascii_uppercase() {
            'O' => '0',
            'I' | 'L' => '1',
            c => c,
        })
        .collect();
    (s.len() == GROUPS * GROUP_LEN && s.bytes().all(|b| ALPHABET.contains(&b))).then_some(s)
}

/// SHA-256 (hex) of the normalized code; `None` if `code` is not one.
pub fn hash(code: &str) -> Option<String> {
    let n = normalize(code)?;
    Some(
        Sha256::digest(n.as_bytes())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect(),
    )
}

pub fn path(dir: &Path, id: i64) -> PathBuf {
    dir.join(format!("{id}.json"))
}

/// The unexpired unlock whose code is `input`, with its file. Unreadable or
/// foreign files are skipped.
pub fn find(dir: &Path, input: &str, now: i64) -> Option<(PathBuf, Unlock)> {
    let h = hash(input)?;
    std::fs::read_dir(dir)
        .ok()?
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .filter_map(|p| Some((serde_json::from_slice::<Unlock>(&std::fs::read(&p).ok()?).ok()?, p)))
        .find(|(u, _)| u.hash == h && u.expires > now && u.hours >= 1 && u.hours <= MAX_HOURS)
        .map(|(u, p)| (p, u))
}

/// Files of expired unlocks (the gate deletes them).
pub fn expired(dir: &Path, now: i64) -> Vec<PathBuf> {
    let Ok(rd) = std::fs::read_dir(dir) else { return vec![] };
    rd.flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .filter(|p| {
            std::fs::read(p)
                .ok()
                .and_then(|b| serde_json::from_slice::<Unlock>(&b).ok())
                .is_none_or(|u| u.expires <= now)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_normalize_and_hash() {
        let c = new_code();
        assert_eq!(c.len(), 23);
        assert_eq!(c.matches('-').count(), 3);
        assert_ne!(c, new_code());
        let n = normalize(&c).unwrap();
        assert_eq!(
            normalize(&format!("  {} ", c.to_lowercase().replace('-', " "))),
            Some(n.clone())
        );
        assert_eq!(hash(&c), hash(&n));
        assert_eq!(hash(&c).unwrap().len(), 64);
        // look-alikes typed by hand
        assert_eq!(normalize("oil00-11111-22222-33333").unwrap(), "01100111112222233333");
        for bad in [
            "",
            "ABCDE-FGHJK-MNPQR",
            "ABCDE-FGHJK-MNPQR-STVWXY",
            "ABCDE-FGHJK-MNPQR-STVWU",
            "1a2b-3c4d",
        ] {
            assert!(normalize(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn find_matches_only_unexpired_codes() {
        let d = tempfile::tempdir().unwrap();
        let code = new_code();
        let mut u = Unlock {
            id: 7,
            hash: hash(&code).unwrap(),
            hours: 2,
            requested_by: "alice".into(),
            approved_by: "sam".into(),
            reason: "r".into(),
            issued: 100,
            expires: 1000,
        };
        std::fs::write(path(d.path(), 7), serde_json::to_vec(&u).unwrap()).unwrap();
        std::fs::write(d.path().join("junk.json"), b"{").unwrap();
        assert_eq!(find(d.path(), &code, 999).unwrap().1, u);
        assert!(find(d.path(), &code, 1000).is_none(), "expired");
        assert!(find(d.path(), &new_code(), 999).is_none(), "other code");
        assert!(find(d.path(), "not a code", 999).is_none());
        u.hours = 9;
        std::fs::write(path(d.path(), 7), serde_json::to_vec(&u).unwrap()).unwrap();
        assert!(find(d.path(), &code, 999).is_none(), "longer than 8 h");
        let mut e = expired(d.path(), 1000);
        e.sort();
        assert_eq!(e, vec![path(d.path(), 7), d.path().join("junk.json")]);
        assert!(expired(d.path(), 999).iter().all(|p| p.ends_with("junk.json")));
    }
}
