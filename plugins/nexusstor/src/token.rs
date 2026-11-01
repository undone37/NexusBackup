//! The NexusStor pairing token (NexusStor `docs/nexusbackup-protocol.md` "Pairing"):
//! `nst1.<base64url(JSON)>` with `{"address", "fingerprint", "code", "expires"}`.
//! Pasted by an admin, so it is checked strictly before anything is connected to.
//! Used by the web-api (host, port and pin of a new source) and by the plugin
//! (the one-time code for `pair`).

use anyhow::{bail, Context, Result};
use base64::Engine;
use serde::Deserialize;

/// Token prefix (format version 1).
pub const PREFIX: &str = "nst1.";
/// Longest token accepted (the manifest's `maxLength`).
pub const MAX_TOKEN: usize = 2048;
/// NexusStor's management port when the address names none.
pub const DEFAULT_PORT: u16 = 8443;

/// A decoded pairing token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Token {
    /// Management address of the NexusStor (host name or IP address).
    pub host: String,
    /// Its port (8443 unless the token names another).
    pub port: u16,
    /// SHA-256 of NexusStor's TLS identity certificate, 64 lowercase hex digits.
    pub fingerprint: String,
    /// The one-time pairing code (26 characters base32, 128 bit).
    pub code: String,
    /// End of validity, Unix seconds.
    pub expires: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Raw {
    address: String,
    fingerprint: String,
    code: String,
    expires: u64,
}

/// Host names and IP addresses (the web-api's `hostname` format).
pub fn valid_host(s: &str) -> bool {
    if s.parse::<std::net::IpAddr>().is_ok() {
        return true;
    }
    (1..=253).contains(&s.len())
        && s.split('.').all(|l| {
            (1..=63).contains(&l.len())
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

/// 64 lowercase hex digits.
pub fn valid_fingerprint(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// `host`, `host:port`, `[v6]`, `[v6]:port` or a bare IPv6 address.
fn split_address(s: &str) -> Option<(String, u16)> {
    if s.parse::<std::net::Ipv6Addr>().is_ok() {
        return Some((s.to_owned(), DEFAULT_PORT));
    }
    let (host, port) = if let Some(rest) = s.strip_prefix('[') {
        let (h, after) = rest.split_once(']')?;
        h.parse::<std::net::Ipv6Addr>().ok()?;
        match after {
            "" => (h, None),
            p => (h, Some(p.strip_prefix(':')?)),
        }
    } else {
        match s.split_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (s, None),
        }
    };
    let port = match port {
        None => DEFAULT_PORT,
        Some(p) if !p.is_empty() && p.len() <= 5 && p.bytes().all(|b| b.is_ascii_digit()) => {
            p.parse::<u16>().ok().filter(|p| *p > 0)?
        }
        Some(_) => return None,
    };
    valid_host(host).then(|| (host.to_owned(), port))
}

impl Token {
    /// Decodes and checks a token (format only; expiry: [`Token::expired`]).
    pub fn parse(s: &str) -> Result<Token> {
        let s = s.trim();
        if s.len() > MAX_TOKEN {
            bail!("the pairing token is longer than {MAX_TOKEN} characters");
        }
        let body = s
            .strip_prefix(PREFIX)
            .context("not a NexusStor pairing token (it starts with nst1.)")?;
        let json = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(body.trim_end_matches('='))
            .context("pairing token: not base64url")?;
        let r: Raw = serde_json::from_slice(&json).context("pairing token: unexpected content")?;
        let (host, port) =
            split_address(&r.address).with_context(|| format!("pairing token: invalid address {:?}", r.address))?;
        if !valid_fingerprint(&r.fingerprint) {
            bail!("pairing token: the fingerprint is not 64 lowercase hex digits");
        }
        if r.code.len() != 26
            || !r
                .code
                .bytes()
                .all(|b| b.is_ascii_uppercase() || (b'2'..=b'7').contains(&b))
        {
            bail!("pairing token: the code is not 26 base32 characters");
        }
        Ok(Token {
            host,
            port,
            fingerprint: r.fingerprint,
            code: r.code,
            expires: r.expires,
        })
    }

    /// Whether the token is past its validity at `now` (Unix seconds).
    pub fn expired(&self, now: u64) -> bool {
        self.expires <= now
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn tok(v: serde_json::Value) -> String {
        format!(
            "{PREFIX}{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(v.to_string())
        )
    }

    fn good() -> serde_json::Value {
        json!({"address": "nas1.example.com", "fingerprint": "ab".repeat(32),
               "code": "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "expires": 2000})
    }

    #[test]
    fn decodes_valid_tokens() {
        let t = Token::parse(&tok(good())).unwrap();
        assert_eq!((t.host.as_str(), t.port, t.expires), ("nas1.example.com", 8443, 2000));
        assert!(!t.expired(1999) && t.expired(2000));
        for (addr, host, port) in [
            ("192.0.2.7:9443", "192.0.2.7", 9443),
            ("[2001:db8::1]:8444", "2001:db8::1", 8444),
            ("[2001:db8::1]", "2001:db8::1", 8443),
            ("2001:db8::1", "2001:db8::1", 8443),
        ] {
            let mut v = good();
            v["address"] = json!(addr);
            let t = Token::parse(&format!("  {}=\n", tok(v))).unwrap();
            assert_eq!((t.host.as_str(), t.port), (host, port), "{addr}");
        }
    }

    #[test]
    fn refuses_bad_tokens() {
        let bad = |k: &str, x: serde_json::Value| {
            let mut v = good();
            v[k] = x;
            tok(v)
        };
        let mut extra = good();
        extra["more"] = json!(1);
        for t in [
            "nst2.e30".to_owned(),
            "nst1.!!!".to_owned(),
            format!("nst1.{}", "A".repeat(MAX_TOKEN)),
            tok(json!({"address": "a"})),
            tok(extra),
            bad("address", json!("nas1 example")),
            bad("address", json!("nas1:0")),
            bad("address", json!("nas1:99999")),
            bad("address", json!("nas1:")),
            bad("address", json!("[::1]x")),
            bad("address", json!("-a.example")),
            bad("fingerprint", json!("AB".repeat(32))),
            bad("fingerprint", json!("ab".repeat(31))),
            bad("code", json!("abcdefghijklmnopqrstuvwxyz")),
            bad("code", json!("ABCDEFGHIJKLMNOPQRSTUVWXY1")),
            bad("code", json!("ABC")),
            bad("expires", json!(-1)),
        ] {
            assert!(Token::parse(&t).is_err(), "{t}");
        }
    }
}
