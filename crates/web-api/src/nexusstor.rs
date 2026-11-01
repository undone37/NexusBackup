//! NexusStor sources (`plugin:nexusstor`, docs/nexusstor-design.md): the admin
//! pastes NexusStor's pairing token; this module decodes it into `host`, `port`
//! and the pinned `fingerprint` and gives the pairing its own client certificate
//! (`client_cert`, key `client_key` sealed like every plugin secret). The plugin's
//! `Validate` then pairs with the token's one-time code (the web-api cannot reach
//! NexusStor before the egress firewall opens the source's endpoint).
//! These fields are derived only: values a client sends for them are ignored.

use crate::{ApiError, ApiResult};
use nexusstor_plugin::token::Token;
use serde_json::{json, Value};

/// Source kind of NexusStor sources.
pub const KIND: &str = "plugin:nexusstor";

const DERIVED: &[&str] = &["host", "port", "fingerprint", "client_cert", "client_key"];

/// A new client identity: ECDSA P-256 key (PKCS#8 PEM) and a self-signed
/// certificate for TLS client authentication (NexusStor pins its SHA-256).
pub fn client_identity(appliance: &str, now: u64) -> ApiResult<(String, String)> {
    let key = rcgen::KeyPair::generate().map_err(anyhow::Error::from)?;
    let mut p = rcgen::CertificateParams::new(Vec::<String>::new()).map_err(anyhow::Error::from)?;
    p.distinguished_name
        .push(rcgen::DnType::CommonName, format!("NexusBackup {appliance}"));
    p.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
    let year = i32::try_from(1970 + now / 31_556_952).unwrap_or(2026);
    p.not_before = rcgen::date_time_ymd(year - 1, 1, 1);
    p.not_after = rcgen::date_time_ymd(year + 30, 1, 1);
    let cert = p.self_signed(&key).map_err(anyhow::Error::from)?;
    Ok((cert.pem(), key.serialize_pem()))
}

fn hostname() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .ok()
        .map(|h| {
            h.trim()
                .chars()
                .filter(|c| (' '..='~').contains(c))
                .take(64)
                .collect::<String>()
        })
        .filter(|h| !h.is_empty())
        .unwrap_or_else(|| "NexusBackup".into())
}

/// The config to store for a create (`old` = None) or update: derived fields from
/// the token (or kept from `old` when no new token is given), a client identity
/// (kept while host and port stay the same), and the name shown on NexusStor.
pub fn prepare(mut cfg: Value, old: Option<&Value>, now: u64) -> ApiResult<Value> {
    let o = cfg
        .as_object_mut()
        .ok_or_else(|| ApiError::bad("config: must be an object"))?;
    for k in DERIVED {
        o.remove(*k);
    }
    if o.get("appliance").and_then(Value::as_str).is_none_or(str::is_empty) {
        let a = old
            .and_then(|x| x["appliance"].as_str())
            .map_or_else(hostname, str::to_owned);
        o.insert("appliance".into(), json!(a));
    }
    let token = o
        .get("token")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_owned);
    match (token, old) {
        (Some(raw), _) => {
            let t = Token::parse(&raw).map_err(|e| ApiError::bad(format!("config.token: {e:#}")))?;
            if t.expired(now) {
                return Err(ApiError::bad(
                    "config.token: the pairing token has expired (valid 15 minutes); create a new one on NexusStor",
                ));
            }
            let same = old.is_some_and(|x| {
                x["host"] == t.host.as_str()
                    && x["port"] == t.port
                    && x["client_cert"].is_string()
                    && x["client_key"].is_string()
            });
            o.insert("token".into(), json!(raw.trim()));
            o.insert("host".into(), json!(t.host));
            o.insert("port".into(), json!(t.port));
            o.insert("fingerprint".into(), json!(t.fingerprint));
            if same {
                // the stored key stays (sealed_plugin_config keeps omitted secrets)
                o.insert("client_cert".into(), old.unwrap()["client_cert"].clone());
            } else {
                let name = o["appliance"].as_str().unwrap_or("NexusBackup").to_owned();
                let (cert, key) = client_identity(&name, now)?;
                o.insert("client_cert".into(), json!(cert));
                o.insert("client_key".into(), json!(key));
            }
        }
        (None, Some(old)) => {
            for k in ["host", "port", "fingerprint", "client_cert"] {
                if let Some(x) = old.get(k) {
                    o.insert(k.into(), x.clone());
                }
            }
        }
        (None, None) => {
            return Err(ApiError::bad(
                "config.token: paste the pairing token shown on NexusStor (Settings, NexusBackup, Pair)",
            ))
        }
    }
    Ok(cfg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    const NOW: u64 = 1_793_500_000;

    fn token(addr: &str, fp: &str) -> String {
        let j = json!({"address": addr, "fingerprint": fp, "code": "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "expires": NOW + 900});
        format!(
            "nst1.{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(j.to_string())
        )
    }

    #[test]
    fn create_derives_endpoint_pin_and_identity() {
        let fp = "ab".repeat(32);
        let cfg = json!({"token": token("nas1.example.com", &fp), "host": "evil.example.com",
                         "fingerprint": "00".repeat(32), "client_key": "mine", "appliance": "nb1"});
        let v = prepare(cfg, None, NOW).unwrap();
        assert_eq!(
            (v["host"].as_str(), v["port"].as_u64()),
            (Some("nas1.example.com"), Some(8443))
        );
        assert_eq!(v["fingerprint"], fp.as_str());
        assert!(v["client_cert"]
            .as_str()
            .unwrap()
            .starts_with("-----BEGIN CERTIFICATE-----"));
        assert!(v["client_key"].as_str().unwrap().contains("BEGIN PRIVATE KEY"));
        assert_eq!(v["appliance"], "nb1");
        // no token, a bad one, an expired one
        assert!(prepare(json!({}), None, NOW).is_err());
        assert!(prepare(json!({"token": "nst1.e30"}), None, NOW).is_err());
        assert!(prepare(json!({"token": token("nas1", &fp)}), None, NOW + 900).is_err());
    }

    #[test]
    fn update_keeps_or_renews_the_identity() {
        let fp = "ab".repeat(32);
        let old = json!({"token": "sealed:v1:x", "host": "nas1", "port": 8443, "fingerprint": fp,
                         "client_cert": "CERT", "client_key": "sealed:v1:y", "appliance": "nb1"});
        // no token: everything derived stays, client values are ignored
        let v = prepare(
            json!({"host": "other", "fingerprint": "00".repeat(32)}),
            Some(&old),
            NOW,
        )
        .unwrap();
        assert_eq!(
            (v["host"].as_str(), v["fingerprint"].as_str()),
            (Some("nas1"), Some(fp.as_str()))
        );
        assert_eq!(v["client_cert"], "CERT");
        assert!(v.get("client_key").is_none() && v.get("token").is_none()); // kept by the sealing step
        assert_eq!(v["appliance"], "nb1");
        // a new token for the same NexusStor (new certificate there): same identity, new pin
        let fp2 = "cd".repeat(32);
        let v = prepare(json!({"token": token("nas1", &fp2)}), Some(&old), NOW).unwrap();
        assert_eq!(
            (v["fingerprint"].as_str(), v["client_cert"].as_str()),
            (Some(fp2.as_str()), Some("CERT"))
        );
        assert!(v.get("client_key").is_none());
        // another NexusStor: a new identity
        let v = prepare(json!({"token": token("nas2:9443", &fp2)}), Some(&old), NOW).unwrap();
        assert_eq!((v["host"].as_str(), v["port"].as_u64()), (Some("nas2"), Some(9443)));
        assert_ne!(v["client_cert"], "CERT");
        assert!(v["client_key"].is_string());
    }
}
