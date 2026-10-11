//! Alert delivery: webhook (JSON POST) and SMTP. Configured in the catalog
//! (setting `alerts`, written by `PUT /settings/alerts`, SMTP password sealed to
//! the scheduler; docs/phase12-contract.md §3) or, when that setting is absent,
//! in `/etc/nexus/alerts.json` (kept as fallback):
//!
//! ```json
//! { "webhook": { "url": "https://hooks.example/nexus", "headers": { "Authorization": "Bearer …" } },
//!   "smtp": { "host": "mail.example", "port": 587, "tls": "starttls", "from": "nexus@example",
//!             "to": ["ops@example"], "username": "nexus", "password_file": "/etc/nexus/smtp-password" } }
//! ```
//! Both parts are optional. `tls` is `starttls` (default), `tls` (implicit, port 465) or `none`
//! (local relay only). Delivery runs on its own thread with a few retries so a slow
//! endpoint never stalls the tick loop.

use anyhow::{Context, Result};
use catalog::secret::SchedulerKey;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{channel, Sender};
use std::time::Duration;

#[derive(Deserialize, Default, Clone)]
pub struct AlertsConfig {
    pub webhook: Option<Webhook>,
    pub smtp: Option<Smtp>,
    /// catalog setting only: alerts below this severity are not delivered
    #[serde(skip)]
    pub min_severity: Option<String>,
}

/// Owner of the sealed SMTP password in the catalog setting (as the web-api seals it).
pub const SETTING_OWNER: &str = "settings/alerts";
/// Catalog setting key.
pub const SETTING_KEY: &str = "alerts";

fn rank(severity: &str) -> u8 {
    match severity {
        "critical" => 2,
        "warning" => 1,
        _ => 0,
    }
}

#[derive(Deserialize, Clone)]
pub struct Webhook {
    pub url: String,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
}

#[derive(Deserialize, Clone)]
pub struct Smtp {
    pub host: String,
    pub port: Option<u16>,
    #[serde(default)]
    pub tls: SmtpTls,
    pub from: String,
    pub to: Vec<String>,
    pub username: Option<String>,
    pub password_file: Option<PathBuf>,
    /// catalog setting: the opened password (never serialized)
    #[serde(skip)]
    pub password: Option<String>,
}

#[derive(Deserialize, Clone, Copy, Default, PartialEq, Debug)]
#[serde(rename_all = "lowercase")]
pub enum SmtpTls {
    #[default]
    Starttls,
    Tls,
    None,
}

#[derive(Serialize, Clone, Debug)]
pub struct Alert {
    pub id: i64,
    pub ts: i64,
    pub severity: String,
    pub kind: String,
    pub message: String,
    pub host: String,
}

impl AlertsConfig {
    /// From the catalog setting `alerts` (`{webhook_url, smtp: {host, port,
    /// starttls, from, to, user, password (sealed)}, min_severity}`).
    pub fn from_setting(mut v: Value, key: &SchedulerKey) -> Result<Self> {
        key.open_all(SETTING_OWNER, &mut v)?;
        let webhook = v["webhook_url"].as_str().map(|u| Webhook {
            url: u.to_owned(),
            headers: BTreeMap::new(),
        });
        let s = &v["smtp"];
        let smtp = s["host"].as_str().map(|host| {
            let port = s["port"].as_u64().and_then(|p| u16::try_from(p).ok());
            Smtp {
                host: host.to_owned(),
                port,
                tls: match (s["starttls"].as_bool().unwrap_or(true), port) {
                    (true, _) => SmtpTls::Starttls,
                    (false, Some(465)) => SmtpTls::Tls,
                    (false, _) => SmtpTls::None,
                },
                from: s["from"].as_str().unwrap_or_default().to_owned(),
                to: s["to"]
                    .as_array()
                    .map(|a| a.iter().filter_map(Value::as_str).map(str::to_owned).collect())
                    .unwrap_or_default(),
                username: s["user"].as_str().map(str::to_owned),
                password_file: None,
                password: s["password"].as_str().map(str::to_owned),
            }
        });
        Ok(AlertsConfig {
            webhook,
            smtp,
            min_severity: v["min_severity"].as_str().map(str::to_owned),
        })
    }

    /// The catalog setting if present, else the file.
    pub fn current(db: &catalog::Catalog, key: &SchedulerKey, file: &Path) -> Result<Self> {
        let setting = catalog::setting(&db.conn(), SETTING_KEY)?;
        match setting {
            Some(raw) => Self::from_setting(serde_json::from_str(&raw)?, key),
            None => Self::load(file),
        }
    }

    /// Whether an alert of `severity` goes out (test alerts always do).
    pub fn wants(&self, a: &Alert) -> bool {
        a.kind == "test"
            || self
                .min_severity
                .as_deref()
                .is_none_or(|m| rank(&a.severity) >= rank(m))
    }

    /// Missing file = no delivery (alerts still land in the catalog).
    pub fn load(path: &Path) -> Result<Self> {
        match std::fs::read(path) {
            Ok(b) => serde_json::from_slice(&b).with_context(|| format!("{}", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e).with_context(|| format!("{}", path.display())),
        }
    }
}

pub fn send_webhook(w: &Webhook, a: &Alert) -> Result<()> {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()?;
    let mut req = client.post(&w.url).json(a);
    for (k, v) in &w.headers {
        req = req.header(k, v);
    }
    req.send()?.error_for_status()?;
    Ok(())
}

pub fn send_mail(s: &Smtp, a: &Alert) -> Result<()> {
    use lettre::transport::smtp::authentication::Credentials;
    use lettre::{Message, SmtpTransport, Transport};
    let mut b = Message::builder()
        .from(s.from.parse()?)
        .subject(format!("[NexusBackup {}] {}: {}", a.host, a.severity, a.kind));
    for to in &s.to {
        b = b.to(to.parse()?);
    }
    let msg = b.body(format!(
        "{}\n\nseverity: {}\nkind: {}\nalert id: {}\ntime (unix): {}\nappliance: {}\n",
        a.message, a.severity, a.kind, a.id, a.ts, a.host
    ))?;
    let mut t = match s.tls {
        SmtpTls::Starttls => SmtpTransport::starttls_relay(&s.host)?,
        SmtpTls::Tls => SmtpTransport::relay(&s.host)?,
        SmtpTls::None => SmtpTransport::builder_dangerous(&s.host),
    }
    .timeout(Some(Duration::from_secs(30)));
    if let Some(p) = s.port {
        t = t.port(p);
    }
    if let (Some(u), Some(pw)) = (&s.username, &s.password) {
        t = t.credentials(Credentials::new(u.clone(), pw.clone()));
    } else if let (Some(u), Some(pf)) = (&s.username, &s.password_file) {
        let pw = std::fs::read_to_string(pf).with_context(|| format!("{}", pf.display()))?;
        t = t.credentials(Credentials::new(u.clone(), pw.trim().to_owned()));
    }
    t.build().send(&msg)?;
    Ok(())
}

/// One `test` alert through each configured channel, no retries: one member
/// per configured channel (`webhook`, `smtp`), `"ok"` or `"error: …"`.
pub fn test(cfg: &AlertsConfig, host: &str) -> Value {
    let a = Alert {
        id: 0,
        ts: catalog::now(),
        severity: "info".into(),
        kind: "test".into(),
        message: "Test alert from the NexusBackup appliance (Settings → Alert delivery).".into(),
        host: host.to_owned(),
    };
    let res = |r: Result<()>| match r {
        Ok(()) => json!("ok"),
        Err(e) => json!(format!("error: {e:#}")),
    };
    let mut out = serde_json::Map::new();
    if let Some(w) = &cfg.webhook {
        out.insert("webhook".into(), res(send_webhook(w, &a)));
    }
    if let Some(s) = &cfg.smtp {
        out.insert("smtp".into(), res(send_mail(s, &a)));
    }
    Value::Object(out)
}

/// Background delivery with retries (0 s, 10 s, 60 s), each alert with the
/// configuration current when it was raised. Returns the sender.
pub fn spawn_delivery(backoff: [Duration; 2]) -> Sender<(AlertsConfig, Alert)> {
    let (tx, rx) = channel::<(AlertsConfig, Alert)>();
    std::thread::spawn(move || {
        for (cfg, a) in rx {
            if cfg.wants(&a) {
                deliver(&cfg, &a, backoff);
            }
        }
    });
    tx
}

fn deliver(cfg: &AlertsConfig, a: &Alert, backoff: [Duration; 2]) {
    let retry = |what: &str, f: &dyn Fn() -> Result<()>| {
        for (i, wait) in [Duration::ZERO, backoff[0], backoff[1]].into_iter().enumerate() {
            std::thread::sleep(wait);
            match f() {
                Ok(()) => return,
                Err(e) => eprintln!("<4>alert {} {what} delivery attempt {} failed: {e:#}", a.id, i + 1),
            }
        }
        eprintln!("<3>alert {} could not be delivered by {what}", a.id);
    };
    if let Some(w) = &cfg.webhook {
        retry("webhook", &|| send_webhook(w, a));
    }
    if let Some(s) = &cfg.smtp {
        retry("smtp", &|| send_mail(s, a));
    }
}

pub fn hostname() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .map(|s| s.trim().to_owned())
        .unwrap_or_else(|_| "nexus".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_parses() {
        let c: AlertsConfig = serde_json::from_str(
            r#"{"webhook":{"url":"http://x/y"},"smtp":{"host":"m","from":"a@b.c","to":["d@e.f"],"tls":"none"}}"#,
        )
        .unwrap();
        assert_eq!(c.smtp.unwrap().tls, SmtpTls::None);
        assert!(c.webhook.unwrap().headers.is_empty());
        assert!(AlertsConfig::load(Path::new("/nonexistent/alerts.json"))
            .unwrap()
            .webhook
            .is_none());
    }

    /// The catalog form (web-api `PUT /settings/alerts`): sealed password opened,
    /// TLS mode from `starttls` + port, severity filter.
    #[test]
    fn catalog_setting() {
        let k = SchedulerKey::generate();
        let mut v = json!({"webhook_url": "https://hooks.example/x", "min_severity": "warning",
                           "smtp": {"host": "mail.example", "port": 465, "starttls": false, "from": "a@b.example",
                                    "to": ["ops@b.example"], "user": "nexus", "password": "pw"}});
        k.public().seal_all(SETTING_OWNER, &mut v).unwrap();
        assert!(v["smtp"]["password"].as_str().unwrap().starts_with("sealed:v1:"));
        let c = AlertsConfig::from_setting(v.clone(), &k).unwrap();
        let s = c.smtp.as_ref().unwrap();
        assert_eq!(
            (s.tls, s.password.as_deref(), s.port),
            (SmtpTls::Tls, Some("pw"), Some(465))
        );
        assert_eq!(c.webhook.as_ref().unwrap().url, "https://hooks.example/x");
        let a = |sev: &str, kind: &str| Alert {
            id: 1,
            ts: 0,
            severity: sev.into(),
            kind: kind.into(),
            message: String::new(),
            host: String::new(),
        };
        assert!(!c.wants(&a("info", "x")) && c.wants(&a("warning", "x")) && c.wants(&a("critical", "x")));
        assert!(c.wants(&a("info", "test")));
        // a password moved to another host does not open
        v["smtp"]["host"] = json!("evil.example");
        assert!(AlertsConfig::from_setting(v, &k).is_err());
        let c = AlertsConfig::from_setting(json!({"smtp": {"host": "m", "from": "a@b.c", "to": []}}), &k).unwrap();
        assert_eq!(c.smtp.unwrap().tls, SmtpTls::Starttls);
    }
}
