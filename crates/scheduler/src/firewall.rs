//! Outbound allow-list for the appliance firewall (plan §12.1): every
//! destination the configuration makes the appliance connect to, resolved to
//! addresses and written to `Config::nft_allowed` for `nexus-nft-sync`
//! (crate `nftsync`), which loads it into the nftables sets.
//!
//! Destinations: per source the PVE API (`connect_addr`, else `host:port`,
//! default 8006) and the SSH endpoint of every node (default 22); per tenant
//! the SFTP box (default 23) or the S3 endpoint (default 443; with
//! virtual-hosted addressing `<bucket>.<host>`); the webhook URL of every
//! alert rule and the SMTP relay.
//! Names that do not resolve are skipped (and retried on the next tick).
//! Names are resolved here, at sync time: endpoints whose DNS answers rotate
//! through many addresses (AWS S3) can hand the job an address that is not
//! in the set yet (see docs/s3-offsite.md, "Firewall").

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

/// (host, port) of a tenant's offsite remote (`tenants.offsite`): the SFTP
/// box, or the S3 endpoint (the host the requests go to).
pub fn offsite_targets(o: &Value) -> Vec<(String, u16)> {
    let r = &o["remote"];
    match r["type"].as_str() {
        Some("sftp") => {
            let port = r["port"].as_u64().and_then(|p| u16::try_from(p).ok()).unwrap_or(23);
            r["host"].as_str().map(|h| (h.to_owned(), port)).into_iter().collect()
        }
        Some("s3") => {
            let Some(ep) = r["endpoint"].as_str().and_then(|e| e.strip_prefix("https://")) else {
                return vec![];
            };
            let ep = ep.trim_end_matches('/');
            let (host, port) = split_host_port(ep).unwrap_or_else(|| (ep.trim_matches(['[', ']']).to_owned(), 443));
            if host.is_empty() {
                return vec![];
            }
            let path_style = r["path_style"].as_bool().unwrap_or(false);
            match r["bucket"].as_str() {
                Some(b) if !path_style => vec![(format!("{b}.{host}"), port)],
                _ => vec![(host, port)],
            }
        }
        _ => vec![],
    }
}

/// (host, port) of every alert rule's webhook and of the SMTP relay.
pub fn alert_targets(a: &AlertsConfig) -> Vec<(String, u16)> {
    let mut out: Vec<(String, u16)> = Vec::new();
    for w in a.rules.iter().filter_map(|r| r.channels.webhook.as_ref()) {
        let (scheme, rest) = w.url.split_once("://").unwrap_or(("https", &w.url));
        let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
        let authority = authority.rsplit('@').next().unwrap_or_default();
        let def = if scheme.eq_ignore_ascii_case("http") { 80 } else { 443 };
        let t = match split_host_port(authority) {
            Some(hp) => hp,
            None if !authority.is_empty() => (authority.trim_matches(['[', ']']).to_owned(), def),
            None => continue,
        };
        if !out.contains(&t) {
            out.push(t);
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

/// (host, port) of an http(s) URL.
fn url_target(u: &str) -> Option<(String, u16)> {
    let url = reqwest::Url::parse(u).ok()?;
    matches!(url.scheme(), "https" | "http").then_some(())?;
    Some((
        url.host_str()?.trim_matches(['[', ']']).to_owned(),
        url.port_or_known_default()?,
    ))
}

/// OIDC (docs/phase12-contract.md §2): the issuer (discovery) and the token and
/// JWKS endpoints of the last discovery (`settings.oidc_endpoints`, recorded by
/// the web-api), while OIDC is configured. The browser reaches the authorization
/// endpoint itself.
/// Tenants' own IdPs (Phase 23a, `tenant_idps`) likewise, with their recorded endpoints.
pub fn oidc_targets(c: &catalog::rusqlite::Connection) -> anyhow::Result<Vec<(String, u16)>> {
    let mut idps: Vec<(Option<String>, Option<String>)> =
        vec![(catalog::setting(c, "oidc")?, catalog::setting(c, "oidc_endpoints")?)];
    let mut q = c.prepare("SELECT settings, endpoints FROM tenant_idps ORDER BY tenant")?;
    for r in q.query_map([], |r| Ok((Some(r.get(0)?), r.get(1)?)))? {
        idps.push(r?);
    }
    let mut out = Vec::new();
    let parse = |v: Option<String>| v.and_then(|v| serde_json::from_str::<Value>(&v).ok());
    for (s, e) in idps {
        let Some(s) = parse(s) else {
            continue;
        };
        let mut add = |t: Option<(String, u16)>| out.extend(t.filter(|t| !out.contains(t)));
        add(s["issuer"].as_str().and_then(url_target));
        if let Some(e) = parse(e) {
            for k in ["token_endpoint", "jwks_uri"] {
                add(e[k].as_str().and_then(url_target));
            }
        }
    }
    Ok(out)
}

/// Forwarding sinks (forward.rs), enabled or not ("Send test message" works
/// for a disabled one): the syslog server and the HTTPS endpoint.
pub fn forward_targets(f: &catalog::forwarding::Forwarding) -> Vec<(String, u16)> {
    let mut out = Vec::new();
    if let Some(s) = &f.syslog {
        out.push((s.host.trim_matches(['[', ']']).to_owned(), s.port));
    }
    out.extend(f.https.as_ref().and_then(|h| url_target(&h.url)));
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
            offsite_targets(&json!({"remote": {"type": "sftp", "host": "u1.your-storagebox.de"}})),
            vec![("u1.your-storagebox.de".into(), 23)]
        );
        assert_eq!(
            offsite_targets(&json!({"remote": {"type": "local", "path": "/x"}})),
            vec![]
        );
        assert_eq!(
            offsite_targets(
                &json!({"remote": {"type": "s3", "endpoint": "https://fsn1.your-objectstorage.com", "bucket": "nx"}})
            ),
            vec![("nx.fsn1.your-objectstorage.com".into(), 443)]
        );
        assert_eq!(
            offsite_targets(
                &json!({"remote": {"type": "s3", "endpoint": "https://minio.lan:9000/", "bucket": "nx", "path_style": true}})
            ),
            vec![("minio.lan".into(), 9000)]
        );
        assert_eq!(
            offsite_targets(
                &json!({"remote": {"type": "s3", "endpoint": "https://[2001:db8::5]:9000", "bucket": "nx", "path_style": true}})
            ),
            vec![("2001:db8::5".into(), 9000)]
        );
        assert_eq!(
            offsite_targets(&json!({"remote": {"type": "s3", "endpoint": "http://plain", "bucket": "nx"}})),
            vec![]
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
    fn oidc() {
        let c = catalog::Catalog::open_memory().unwrap();
        let conn = c.conn();
        assert!(oidc_targets(&conn).unwrap().is_empty());
        catalog::set_setting(&conn, "oidc", r#"{"issuer": "https://idp.example.com/realms/nexus"}"#).unwrap();
        assert_eq!(oidc_targets(&conn).unwrap(), vec![("idp.example.com".into(), 443)]);
        catalog::set_setting(
            &conn,
            "oidc_endpoints",
            r#"{"token_endpoint": "https://idp.example.com/t", "jwks_uri": "https://keys.example.com:8443/k"}"#,
        )
        .unwrap();
        assert_eq!(
            oidc_targets(&conn).unwrap(),
            vec![("idp.example.com".into(), 443), ("keys.example.com".into(), 8443)]
        );
        // a tenant's own IdP (Phase 23a)
        conn.execute_batch(
            r#"INSERT INTO tenants (name) VALUES ('acme');
               INSERT INTO tenant_idps (tenant, settings, endpoints) VALUES ('acme',
                 '{"issuer": "https://login.acme.example/x"}', '{"jwks_uri": "https://idp.example.com/k"}');"#,
        )
        .unwrap();
        assert_eq!(
            oidc_targets(&conn).unwrap(),
            vec![
                ("idp.example.com".into(), 443),
                ("keys.example.com".into(), 8443),
                ("login.acme.example".into(), 443)
            ]
        );
    }

    #[test]
    fn forwarding() {
        let f: catalog::forwarding::Forwarding = serde_json::from_value(json!({
            "syslog": {"host": "[2001:db8::7]", "enabled": false},
            "https": {"url": "https://siem.example:8443/in"}}))
        .unwrap();
        assert_eq!(
            forward_targets(&f),
            vec![("2001:db8::7".into(), 6514), ("siem.example".into(), 8443)]
        );
        assert!(forward_targets(&Default::default()).is_empty());
    }

    #[test]
    fn resolves_literals() {
        let r = resolve(&[("10.0.2.2".into(), 22), ("2001:db8::1".into(), 23)]);
        assert_eq!(r.len(), 2);
        assert_eq!(r[1].port, 23);
    }
}
