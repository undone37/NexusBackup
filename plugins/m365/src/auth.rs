//! Entra ID certificate credential: the app's RSA private key and the certificate
//! uploaded to the app registration. The token request is the OAuth 2.0 client
//! credentials grant with a signed client assertion (JWT, PS256, `x5t#S256` =
//! SHA-256 thumbprint of the certificate; `x5t` = SHA-1 for older endpoints) —
//! no client secret exists anywhere.

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use base64::Engine;
use ring::digest;
use ring::rand::{SecureRandom, SystemRandom};
use ring::signature::{RsaKeyPair, RSA_PSS_SHA256};
use serde_json::json;

pub struct Credential {
    key: RsaKeyPair,
    pub cert_der: Vec<u8>,
}

/// (config field, problem)
pub type Bad = (&'static str, String);

/// PEM text with its line structure restored: single-line form fields drop the
/// newlines of a pasted PEM (`-----BEGIN X----- MIIB… -----END X-----`).
pub fn normalize_pem(s: &str) -> String {
    let mut out = String::new();
    let mut rest = s;
    while let Some(b) = rest.find("-----BEGIN ") {
        let after = &rest[b + 11..];
        let Some(le) = after.find("-----") else { break };
        let label = &after[..le];
        let body_start = &after[le + 5..];
        let end_marker = format!("-----END {label}-----");
        let Some(e) = body_start.find(&end_marker) else { break };
        let body: String = body_start[..e].split_whitespace().collect();
        // headers of legacy encrypted keys (Proc-Type: …) are kept as a marker only
        out.push_str(&format!("-----BEGIN {label}-----\n"));
        for chunk in body.as_bytes().chunks(64) {
            out.push_str(&String::from_utf8_lossy(chunk));
            out.push('\n');
        }
        out.push_str(&format!("{end_marker}\n"));
        rest = &body_start[e + end_marker.len()..];
    }
    out
}

impl Credential {
    /// Certificate and key as PEM. Either field may hold both blocks (a combined PEM);
    /// the first certificate is the app's. PKCS#8 and PKCS#1 RSA keys, unencrypted.
    pub fn parse(cert_pem: &str, key_pem: &str) -> Result<Credential, Bad> {
        let blocks =
            |f: &'static str, s: &str| pem::parse_many(normalize_pem(s)).map_err(|e| (f, format!("not PEM: {e}")));
        let mut all = blocks("certificate", cert_pem)?;
        all.extend(blocks("private_key", key_pem)?);
        let cert_der = all
            .iter()
            .find(|p| p.tag() == "CERTIFICATE")
            .map(|p| p.contents().to_vec())
            .ok_or(("certificate", "no PEM certificate (-----BEGIN CERTIFICATE-----)".into()))?;
        if all.iter().any(|p| p.tag() == "ENCRYPTED PRIVATE KEY") || key_pem.contains("Proc-Type: 4,ENCRYPTED") {
            return Err((
                "private_key",
                "the key is passphrase-protected; export it unencrypted (it is sealed by the appliance)".into(),
            ));
        }
        let key = if let Some(p) = all.iter().find(|p| p.tag() == "PRIVATE KEY") {
            RsaKeyPair::from_pkcs8(p.contents())
        } else if let Some(p) = all.iter().find(|p| p.tag() == "RSA PRIVATE KEY") {
            RsaKeyPair::from_der(p.contents())
        } else {
            return Err((
                "private_key",
                "no PEM private key (PRIVATE KEY / RSA PRIVATE KEY)".into(),
            ));
        }
        .map_err(|e| ("private_key", format!("not a usable RSA key (2048 bits or more): {e}")))?;
        // the certificate's SubjectPublicKeyInfo holds the PKCS#1 RSAPublicKey verbatim
        let public = key.public().as_ref();
        if !cert_der.windows(public.len()).any(|w| w == public) {
            return Err((
                "private_key",
                "the private key does not belong to the certificate".into(),
            ));
        }
        Ok(Credential { key, cert_der })
    }

    /// SHA-1 thumbprint as Entra shows it (hex, upper case).
    pub fn thumbprint(&self) -> String {
        digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, &self.cert_der)
            .as_ref()
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect()
    }

    /// The signed client assertion for `aud` (= the token endpoint URL).
    pub fn assertion(&self, client_id: &str, aud: &str, now: u64) -> anyhow::Result<String> {
        let rng = SystemRandom::new();
        let mut jti = [0u8; 16];
        rng.fill(&mut jti).map_err(|_| anyhow::anyhow!("no randomness"))?;
        let header = json!({
            "alg": "PS256",
            "typ": "JWT",
            "x5t": B64URL.encode(digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, &self.cert_der)),
            "x5t#S256": B64URL.encode(digest::digest(&digest::SHA256, &self.cert_der)),
        });
        let claims = json!({
            "aud": aud,
            "iss": client_id,
            "sub": client_id,
            "jti": jti.iter().map(|b| format!("{b:02x}")).collect::<String>(),
            "nbf": now.saturating_sub(60),
            "iat": now,
            "exp": now + 600,
        });
        let input = format!(
            "{}.{}",
            B64URL.encode(header.to_string()),
            B64URL.encode(claims.to_string())
        );
        let mut sig = vec![0u8; self.key.public().modulus_len()];
        self.key
            .sign(&RSA_PSS_SHA256, &rng, input.as_bytes(), &mut sig)
            .map_err(|_| anyhow::anyhow!("signing the client assertion failed"))?;
        Ok(format!("{input}.{}", B64URL.encode(sig)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::signature::{UnparsedPublicKey, RSA_PSS_2048_8192_SHA256};

    const CERT: &str = include_str!("../tests/data/test-app.crt");
    const KEY: &str = include_str!("../tests/data/test-app.key");
    const KEY1: &str = include_str!("../tests/data/test-app.pkcs1.key");

    #[test]
    fn assertion_verifies() {
        let c = Credential::parse(CERT, KEY).unwrap();
        assert_eq!(c.thumbprint().len(), 40);
        let jwt = c
            .assertion("app-1", "https://login.test/t/oauth2/v2.0/token", 1_800_000_000)
            .unwrap();
        let parts: Vec<&str> = jwt.split('.').collect();
        assert_eq!(parts.len(), 3);
        let h: serde_json::Value = serde_json::from_slice(&B64URL.decode(parts[0]).unwrap()).unwrap();
        assert_eq!(h["alg"], "PS256");
        assert_eq!(
            h["x5t#S256"],
            B64URL.encode(digest::digest(&digest::SHA256, &c.cert_der))
        );
        let claims: serde_json::Value = serde_json::from_slice(&B64URL.decode(parts[1]).unwrap()).unwrap();
        assert_eq!(
            (claims["iss"].as_str(), claims["exp"].as_u64()),
            (Some("app-1"), Some(1_800_000_600))
        );
        let pk = UnparsedPublicKey::new(&RSA_PSS_2048_8192_SHA256, c.key.public().as_ref().to_vec());
        pk.verify(
            format!("{}.{}", parts[0], parts[1]).as_bytes(),
            &B64URL.decode(parts[2]).unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn formats_and_mismatches() {
        assert!(Credential::parse(CERT, KEY1).is_ok(), "PKCS#1");
        assert!(Credential::parse(&format!("{CERT}{KEY}"), "").is_ok(), "combined PEM");
        // pasted into a single-line field: newlines gone (or turned into spaces)
        assert!(Credential::parse(&CERT.replace('\n', ""), &KEY.replace('\n', " ")).is_ok());
        assert_eq!(Credential::parse("", KEY).err().unwrap().0, "certificate");
        assert_eq!(Credential::parse(CERT, "").err().unwrap().0, "private_key");
        let enc = "-----BEGIN ENCRYPTED PRIVATE KEY-----\nMA==\n-----END ENCRYPTED PRIVATE KEY-----\n";
        assert!(Credential::parse(CERT, enc).err().unwrap().1.contains("passphrase"));
        // a certificate of another key
        let other = rcgen::generate_simple_self_signed(vec!["x".into()]).unwrap().cert.pem();
        let e = Credential::parse(&other, KEY).err().unwrap();
        assert!(e.1.contains("does not belong"), "{e:?}");
    }
}
