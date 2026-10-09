//! Outbound allow-list for the appliance firewall (plan §12.1): every
//! destination the configuration makes the appliance connect to, resolved to
//! addresses and written to `Config::nft_allowed` for `nexus-nft-sync`
//! (crate `nftsync`), which loads it into the nftables sets.
//!
//! Destinations: per source the PVE API (`connect_addr`, else `host:port`,
//! default 8006) and the SSH endpoint of every node (default 22); per tenant
//! the SFTP box (default 23); the webhook URL and SMTP relay of alerts.json.
//! Names that do not resolve are skipped (and retried on the next tick).

use crate::alerts::{AlertsConfig, SmtpTls};
use nftsync::{Endpoint, Proto};
use serde_json::Value;
use std::net::ToSocketAddrs;

/// (host, port) pairs of one source config (`sources.config`, kind pve).
pub fn source_targets(src: &Value) -> Vec<(String, u16)> {
    let mut out = Vec::new();
    let api = if src["api"].is_object() { &src["api"] } else { src };
    let port = |v: &Value, def: u16| v["port"].as_u64().and_then(|p| u16::try_from(p).ok()).unwrap_or(def);
    if let Some((h, p)) = api["connect_addr"].as_str().and_then(split_host_port) {
        out.push((h, p));
    } else if let Some(h) = api["host"].as_str() {
        out.push((h.trim_matches(['[', ']']).to_owned(), port(api, 8006)));
    }
    let nodes: Vec<&Value> = match &src["nodes"] {
        Value::Object(m) => m.values().collect(),
        Value::Array(a) => a.iter().collect(),
        _ => Vec::new(),
    };
    for n in nodes {
        if let Some(h) = n["host"].as_str() {
            out.push((h.trim_matches(['[', ']']).to_owned(), port(n, 22)));
        }
    }
    out
}

/// (host, port) pairs of a TrueNAS source: the API (`connect_addr`, else
/// `host:port`, default 443) and SSH (`ssh.host:ssh.port`, default 22).
pub fn truenas_targets(src: &Value) -> Vec<(String, u16)> {
    let port = |v: &Value, def: u16| v["port"].as_u64().and_then(|p| u16::try_from(p).ok()).unwrap_or(def);
    let mut out = Vec::new();
    if let Some((h, p)) = src["connect_addr"].as_str().and_then(split_host_port) {
        out.push((h, p));
    } else if let Some(h) = src["host"].as_str() {
        out.push((h.trim_matches(['[', ']']).to_owned(), port(src, 443)));
    }
    if let Some(h) = src["ssh"]["host"].as_str() {
        out.push((h.trim_matches(['[', ']']).to_owned(), port(&src["ssh"], 22)));
    }
    out
}

/// (host, port) pairs of an NFS/SMB share source (docs/nas-connector.md). The
/// kernel client's connections leave from the appliance like any other, so the
/// allow-list covers them: NFS the NFS port (default 2049; v4.x needs nothing
/// else) and for v3 the mountd port (default 20048; the helper mounts with
/// `mountport=`, no portmapper/rpcbind 111 and `nolock`, no NLM/statd); SMB the
/// SMB port (default 445). SMB Kerberos also needs the KDC (88) — not derivable
/// from the source; it goes into `/etc/nexus/allowed-hosts`.
pub fn share_targets(kind: &str, src: &Value) -> Vec<(String, u16)> {
    let port = |k: &str, def: u16| src[k].as_u64().and_then(|p| u16::try_from(p).ok()).unwrap_or(def);
    let Some(h) = src["host"].as_str() else {
        return Vec::new();
    };
    let h = h.trim_matches(['[', ']']).to_owned();
    match kind {
        "nfs" => {
            let mut out = vec![(h.clone(), port("port", 2049))];
            if src["version"].as_str() == Some("3") {
                out.push((h, port("mount_port", 20048)));
            }
            out
        }
        "smb" => vec![(h, port("port", 445))],
        _ => Vec::new(),
    }
}

/// (host, port) of a tenant's offsite remote (`tenants.offsite`), SFTP only.
pub fn offsite_target(o: &Value) -> Option<(String, u16)> {
    let r = &o["remote"];
    if r["type"].as_str() != Some("sftp") {
        return None;
    }
    let port = r["port"].as_u64().and_then(|p| u16::try_from(p).ok()).unwrap_or(23);
    Some((r["host"].as_str()?.to_owned(), port))
}

/// (host, port) of the webhook and the SMTP relay.
pub fn alert_targets(a: &AlertsConfig) -> Vec<(String, u16)> {
    let mut out = Vec::new();
    if let Some(w) = &a.webhook {
        let (scheme, rest) = w.url.split_once("://").unwrap_or(("https", &w.url));
        let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
        let authority = authority.rsplit('@').next().unwrap_or_default();
        let def = if scheme.eq_ignore_ascii_case("http") { 80 } else { 443 };
        if let Some(hp) = split_host_port(authority) {
            out.push(hp);
        } else if !authority.is_empty() {
            out.push((authority.trim_matches(['[', ']']).to_owned(), def));
        }
    }
    if let Some(s) = &a.smtp {
        let def = match s.tls {
            SmtpTls::Starttls => 587,
            SmtpTls::Tls => 465,
            SmtpTls::None => 25,
        };
        out.push((s.host.clone(), s.port.unwrap_or(def)));
    }
    out
}

/// `host:port` / `[v6]:port` → (host, port); None without a valid port.
fn split_host_port(s: &str) -> Option<(String, u16)> {
    let (h, p) = s.rsplit_once(':')?;
    let p: u16 = p.parse().ok()?;
    let h = h.trim_matches(['[', ']']);
    (!h.is_empty() && (!h.contains(':') || s.starts_with('['))).then(|| (h.to_owned(), p))
}

/// Resolves (host, port) pairs to TCP endpoints; unresolvable names are skipped.
pub fn resolve(targets: &[(String, u16)]) -> Vec<Endpoint> {
    let mut out = Vec::new();
    for (h, p) in targets {
        if let Ok(it) = (h.as_str(), *p).to_socket_addrs() {
            out.extend(it.map(|a| Endpoint {
                addr: a.ip(),
                proto: Proto::Tcp,
                port: *p,
            }));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn targets() {
        let s = json!({"host": "pve1", "port": 18006, "connect_addr": "10.0.2.2:18006",
                       "nodes": {"pve1": {"host": "10.0.2.2", "port": 10022}, "pve2": {"host": "pve2"}}});
        assert_eq!(
            source_targets(&s),
            vec![
                ("10.0.2.2".into(), 18006),
                ("10.0.2.2".into(), 10022),
                ("pve2".into(), 22)
            ]
        );
        let s = json!({"api": {"host": "10.0.0.5"}, "nodes": [{"name": "n", "host": "[2001:db8::1]", "port": 22}]});
        assert_eq!(
            source_targets(&s),
            vec![("10.0.0.5".into(), 8006), ("2001:db8::1".into(), 22)]
        );
        assert_eq!(
            offsite_target(&json!({"remote": {"type": "sftp", "host": "u1.your-storagebox.de"}})),
            Some(("u1.your-storagebox.de".into(), 23))
        );
        assert_eq!(
            offsite_target(&json!({"remote": {"type": "local", "path": "/x"}})),
            None
        );
        let a: AlertsConfig = serde_json::from_str(
            r#"{"webhook":{"url":"https://user@hooks.example:8443/x?y"},"smtp":{"host":"mail","from":"a@b.c","to":[]}}"#,
        )
        .unwrap();
        assert_eq!(
            alert_targets(&a),
            vec![("hooks.example".into(), 8443), ("mail".into(), 587)]
        );
        let a: AlertsConfig = serde_json::from_str(r#"{"webhook":{"url":"http://[2001:db8::2]/h"}}"#).unwrap();
        assert_eq!(alert_targets(&a), vec![("2001:db8::2".into(), 80)]);
        assert_eq!(split_host_port("[2001:db8::1]:23"), Some(("2001:db8::1".into(), 23)));
        assert_eq!(split_host_port("2001:db8::1"), None);
    }

    #[test]
    fn resolves_literals() {
        let r = resolve(&[("10.0.2.2".into(), 22), ("2001:db8::1".into(), 23)]);
        assert_eq!(r.len(), 2);
        assert_eq!(r[1].port, 23);
    }
}
