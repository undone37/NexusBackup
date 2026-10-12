//! Alert delivery: notification rules (catalog setting `alert_rules`, written by
//! `PUT /settings/alerts`; `catalog::alerting`) route each alert by severity,
//! kind and tenant to e-mail recipients (through the one SMTP server of the
//! setting `alerts`, password sealed to the scheduler) and webhooks (JSON POST,
//! default payload or a `{{field}}` template; header values sealed). Without
//! catalog settings, `/etc/nexus/alerts.json` is used (one rule, every severity):
//!
//! ```json
//! { "webhook": { "url": "https://hooks.example/nexus", "headers": { "Authorization": "Bearer …" } },
//!   "smtp": { "host": "mail.example", "port": 587, "tls": "starttls", "from": "nexus@example",
//!             "to": ["ops@example"], "username": "nexus", "password_file": "/etc/nexus/smtp-password" } }
//! ```
//! Both parts are optional. `tls` is `starttls` (default), `tls` (implicit, port 465) or `none`
//! (local relay only). Delivery runs on its own thread with a few retries so a slow
//! endpoint never stalls the tick loop.

use anyhow::{bail, Context, Result};
use catalog::alerting::{self, Rule, Webhook};
use catalog::secret::SchedulerKey;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{channel, Sender};
use std::time::Duration;

/// The SMTP server (global) and the notification rules.
#[derive(Deserialize, Default, Clone)]
#[serde(from = "FileConfig")]
pub struct AlertsConfig {
    pub smtp: Option<Smtp>,
    pub rules: Vec<Rule>,
}

/// `/etc/nexus/alerts.json`.
#[derive(Deserialize)]
struct FileConfig {
    webhook: Option<FileWebhook>,
    smtp: Option<Smtp>,
}

#[derive(Deserialize)]
struct FileWebhook {
    url: String,
    #[serde(default)]
    headers: BTreeMap<String, String>,
}

impl From<FileConfig> for AlertsConfig {
    fn from(f: FileConfig) -> Self {
        let email = f.smtp.as_ref().map(|s| s.to.clone()).unwrap_or_default();
        let webhook = f.webhook.map(|w| Webhook {
            url: w.url,
            headers: w.headers,
            template: None,
        });
        let rules = if email.is_empty() && webhook.is_none() {
            Vec::new()
        } else {
            vec![Rule {
                name: "default".into(),
                min_severity: "info".into(),
                kinds: Vec::new(),
                tenants: Vec::new(),
                channels: alerting::Channels { email, webhook },
            }]
        };
        AlertsConfig { smtp: f.smtp, rules }
    }
}

/// Owner of the sealed SMTP password in the catalog setting (as the web-api seals it).
pub const SETTING_OWNER: &str = "settings/alerts";
/// Catalog setting key (SMTP server; before 13f also the single webhook / recipients).
pub const SETTING_KEY: &str = "alerts";

#[derive(Deserialize, Clone)]
pub struct Smtp {
    pub host: String,
    pub port: Option<u16>,
    #[serde(default)]
    pub tls: SmtpTls,
    pub from: String,
    /// alerts.json only (the catalog form has the recipients in the rules)
    #[serde(default)]
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

/// The delivered payload (also the fields of webhook templates).
#[derive(Serialize, Clone, Debug)]
pub struct Alert {
    pub id: i64,
    /// first seen (= `first_ts`, kept for receivers of the pre-13f payload)
    pub ts: i64,
    pub first_ts: i64,
    pub last_ts: i64,
    pub count: i64,
    pub severity: String,
    pub kind: String,
    pub message: String,
    pub hint: String,
    pub tenant: Option<String>,
    pub host: String,
    pub alert_url: String,
}

impl Alert {
    pub fn url(host: &str, id: i64) -> String {
        format!("https://{host}/#/alerts?id={id}")
    }
}

impl AlertsConfig {
    /// From the catalog: the SMTP server of the setting `alerts` (`{smtp: {host,
    /// port, starttls, from, user, password (sealed)}}`) and the rules (header
    /// values opened).
    pub fn from_setting(mut v: Value, rules: Vec<Rule>, key: &SchedulerKey) -> Result<Self> {
        key.open_all(SETTING_OWNER, &mut v)?;
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
                to: Vec::new(),
                username: s["user"].as_str().map(str::to_owned),
                password_file: None,
                password: s["password"].as_str().map(str::to_owned),
            }
        });
        let mut rules = rules;
        for r in &mut rules {
            if let Some(w) = &mut r.channels.webhook {
                for (h, val) in &mut w.headers {
                    if catalog::secret::is_sealed(val) {
                        *val = key
                            .open(&alerting::header_location(&r.name, h, &w.url), val)?
                            .to_string();
                    }
                }
            }
        }
        Ok(AlertsConfig { smtp, rules })
    }

    /// The catalog settings if present (rules, else the pre-13f single
    /// configuration as one rule), else the file.
    pub fn current(db: &catalog::Catalog, key: &SchedulerKey, file: &Path) -> Result<Self> {
        let (alerts, has_rules, rules) = {
            let c = db.conn();
            (
                catalog::setting(&c, SETTING_KEY)?,
                catalog::setting(&c, alerting::RULES_SETTING)?.is_some(),
                alerting::load_rules(&c)?,
            )
        };
        match alerts {
            Some(raw) => Self::from_setting(serde_json::from_str(&raw)?, rules, key),
            None if has_rules => Self::from_setting(Value::Null, rules, key),
            None => Self::load(file),
        }
    }

    /// Missing file = no delivery (alerts still land in the catalog).
    pub fn load(path: &Path) -> Result<Self> {
        match std::fs::read(path) {
            Ok(b) => serde_json::from_slice(&b).with_context(|| format!("{}", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e).with_context(|| format!("{}", path.display())),
        }
    }

    /// Rules that route `a` (test alerts: every rule).
    pub fn matching(&self, a: &Alert) -> Vec<&Rule> {
        self.rules
            .iter()
            .filter(|r| a.kind == "test" || r.matches(&a.severity, &a.kind, a.tenant.as_deref()))
            .collect()
    }
}

pub fn send_webhook(w: &Webhook, a: &Alert) -> Result<()> {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()?;
    let mut req = client.post(&w.url);
    req = match &w.template {
        Some(t) => {
            let body = alerting::render(t, &serde_json::to_value(a)?).map_err(anyhow::Error::msg)?;
            req.header("Content-Type", "application/json").body(body)
        }
        None => req.json(a),
    };
    for (k, v) in &w.headers {
        req = req.header(k, v);
    }
    req.send()?.error_for_status()?;
    Ok(())
}

pub fn send_mail(s: &Smtp, to: &BTreeSet<String>, a: &Alert) -> Result<()> {
    use lettre::Message;
    let mut b = Message::builder()
        .from(s.from.parse()?)
        .subject(format!("[NexusBackup {}] {}: {}", a.host, a.severity, a.kind));
    for to in to {
        b = b.to(to.parse()?);
    }
    let seen = if a.count > 1 {
        format!(
            "seen {} times, first (unix) {}, last {}\n",
            a.count, a.first_ts, a.last_ts
        )
    } else {
        String::new()
    };
    let msg = b.body(format!(
        "{}\n\nWhat to do: {}\n\nseverity: {}\nkind: {}\ntenant: {}\nalert id: {}\ntime (unix): {}\n{seen}appliance: {}\n{}\n",
        a.message,
        a.hint,
        a.severity,
        a.kind,
        a.tenant.as_deref().unwrap_or("-"),
        a.id,
        a.ts,
        a.host,
        a.alert_url
    ))?;
    send_message(s, &msg)
}

/// Sends a composed message through the SMTP server `s` (alerts, scheduled reports).
pub fn send_message(s: &Smtp, msg: &lettre::Message) -> Result<()> {
    use lettre::transport::smtp::authentication::Credentials;
    use lettre::{SmtpTransport, Transport};
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
    t.build().send(msg)?;
    Ok(())
}

fn mail(cfg: &AlertsConfig, to: &BTreeSet<String>, a: &Alert) -> Result<()> {
    match &cfg.smtp {
        Some(s) => send_mail(s, to, a),
        None => bail!("no SMTP server configured"),
    }
}

/// One `test` alert through the channels of rule `only` (every rule if None),
/// no retries: `"ok"` or `"error: …"` per channel (`webhook`, `email`); with
/// several rules the members are `<rule>/<channel>`.
pub fn test(cfg: &AlertsConfig, host: &str, only: Option<&str>) -> Value {
    let a = Alert {
        id: 0,
        ts: catalog::now(),
        first_ts: catalog::now(),
        last_ts: catalog::now(),
        count: 1,
        severity: "info".into(),
        kind: "test".into(),
        message: "Test alert from the NexusBackup appliance (Settings → Alert delivery).".into(),
        hint: alerting::hint("test").into(),
        tenant: None,
        host: host.to_owned(),
        alert_url: Alert::url(host, 0),
    };
    let res = |r: Result<()>| match r {
        Ok(()) => json!("ok"),
        Err(e) => json!(format!("error: {e:#}")),
    };
    let mut out = serde_json::Map::new();
    let rules: Vec<&Rule> = cfg.rules.iter().filter(|r| only.is_none_or(|n| r.name == n)).collect();
    if let (Some(n), true) = (only, rules.is_empty()) {
        out.insert("rule".into(), json!(format!("error: no rule named {n}")));
    }
    let name = |r: &Rule, ch: &str| {
        if only.is_some() {
            ch.to_owned()
        } else {
            format!("{}/{ch}", r.name)
        }
    };
    for r in rules {
        if let Some(w) = &r.channels.webhook {
            out.insert(name(r, "webhook"), res(send_webhook(w, &a)));
        }
        if !r.channels.email.is_empty() {
            let to = r.channels.email.iter().cloned().collect();
            out.insert(name(r, "email"), res(mail(cfg, &to, &a)));
        }
    }
    Value::Object(out)
}

/// Background delivery with retries (0 s, 10 s, 60 s), each alert with the
/// configuration current when it was due. Returns the sender.
pub fn spawn_delivery(backoff: [Duration; 2]) -> Sender<(AlertsConfig, Alert)> {
    let (tx, rx) = channel::<(AlertsConfig, Alert)>();
    std::thread::spawn(move || {
        for (cfg, a) in rx {
            deliver(&cfg, &a, backoff);
        }
    });
    tx
}

/// Every matching rule's webhook; one mail to the union of the matching rules' recipients.
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
    let rules = cfg.matching(a);
    for r in &rules {
        if let Some(w) = &r.channels.webhook {
            retry(&format!("webhook of rule {}", r.name), &|| send_webhook(w, a));
        }
    }
    let to: BTreeSet<String> = rules.iter().flat_map(|r| r.channels.email.iter().cloned()).collect();
    if !to.is_empty() {
        retry("e-mail", &|| mail(cfg, &to, a));
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
        assert_eq!(c.smtp.as_ref().unwrap().tls, SmtpTls::None);
        let r = &c.rules[0];
        assert_eq!((r.min_severity.as_str(), r.channels.email.len()), ("info", 1));
        assert!(r.channels.webhook.as_ref().unwrap().headers.is_empty());
        assert!(AlertsConfig::load(Path::new("/nonexistent/alerts.json"))
            .unwrap()
            .rules
            .is_empty());
    }

    fn alert(sev: &str, kind: &str, tenant: Option<&str>) -> Alert {
        Alert {
            id: 1,
            ts: 0,
            first_ts: 0,
            last_ts: 0,
            count: 1,
            severity: sev.into(),
            kind: kind.into(),
            message: String::new(),
            hint: String::new(),
            tenant: tenant.map(str::to_owned),
            host: String::new(),
            alert_url: String::new(),
        }
    }

    /// The catalog form (web-api `PUT /settings/alerts`): sealed SMTP password and
    /// header values opened, TLS mode from `starttls` + port, the pre-13f
    /// single configuration as one rule.
    #[test]
    fn catalog_setting() {
        let k = SchedulerKey::generate();
        let mut v = json!({"webhook_url": "https://hooks.example/x", "min_severity": "warning",
                           "smtp": {"host": "mail.example", "port": 465, "starttls": false, "from": "a@b.example",
                                    "to": ["ops@b.example"], "user": "nexus", "password": "pw"}});
        k.public().seal_all(SETTING_OWNER, &mut v).unwrap();
        assert!(v["smtp"]["password"].as_str().unwrap().starts_with("sealed:v1:"));
        let c = AlertsConfig::from_setting(v.clone(), alerting::legacy_rules(&v), &k).unwrap();
        let s = c.smtp.as_ref().unwrap();
        assert_eq!(
            (s.tls, s.password.as_deref(), s.port),
            (SmtpTls::Tls, Some("pw"), Some(465))
        );
        assert_eq!(
            c.rules[0].channels.webhook.as_ref().unwrap().url,
            "https://hooks.example/x"
        );
        assert_eq!(c.rules[0].channels.email, vec!["ops@b.example".to_owned()]);
        assert!(c.matching(&alert("info", "x", None)).is_empty());
        assert_eq!(c.matching(&alert("warning", "x", None)).len(), 1);
        assert_eq!(c.matching(&alert("info", "test", None)).len(), 1);
        // a password moved to another host does not open
        v["smtp"]["host"] = json!("evil.example");
        assert!(AlertsConfig::from_setting(v, vec![], &k).is_err());
        let c = AlertsConfig::from_setting(json!({"smtp": {"host": "m", "from": "a@b.c"}}), vec![], &k).unwrap();
        assert_eq!(c.smtp.unwrap().tls, SmtpTls::Starttls);
        // header values: opened at their location, refused at another URL
        let url = "https://hooks.example/y";
        let sealed = k
            .public()
            .seal(&alerting::header_location("ops", "Authorization", url), "Bearer t")
            .unwrap();
        let mut r: Rule = serde_json::from_value(json!({"name": "ops", "channels": {"webhook": {
            "url": url, "headers": {"Authorization": sealed}}}}))
        .unwrap();
        let c = AlertsConfig::from_setting(Value::Null, vec![r.clone()], &k).unwrap();
        assert_eq!(
            c.rules[0].channels.webhook.as_ref().unwrap().headers["Authorization"],
            "Bearer t"
        );
        r.channels.webhook.as_mut().unwrap().url = "https://evil.example/y".into();
        assert!(AlertsConfig::from_setting(Value::Null, vec![r], &k).is_err());
    }

    /// Rules route by severity, kind and tenant; recipients of several matching
    /// rules get one mail.
    #[test]
    fn routing() {
        let rules: Vec<Rule> = serde_json::from_value(json!([
            {"name": "all-critical", "min_severity": "critical", "channels": {"email": ["ops@x.example"]}},
            {"name": "acme", "min_severity": "info", "tenants": ["acme"], "kinds": ["job_failed"],
             "channels": {"email": ["ops@x.example", "acme@x.example"]}}
        ]))
        .unwrap();
        let c = AlertsConfig { smtp: None, rules };
        let names = |a: &Alert| c.matching(a).iter().map(|r| r.name.clone()).collect::<Vec<_>>();
        assert_eq!(
            names(&alert("critical", "job_failed", Some("acme"))),
            ["all-critical", "acme"]
        );
        assert_eq!(names(&alert("warning", "job_failed", Some("acme"))), ["acme"]);
        assert!(names(&alert("warning", "job_failed", Some("globex"))).is_empty());
        assert_eq!(names(&alert("critical", "capacity", None)), ["all-critical"]);
        // no SMTP server: the test reports it per rule
        let r = test(&c, "nexus", Some("acme"));
        assert_eq!(r["email"], "error: no SMTP server configured");
        assert!(test(&c, "nexus", Some("nope"))["rule"]
            .as_str()
            .unwrap()
            .contains("no rule"));
        assert!(test(&c, "nexus", None).get("all-critical/email").is_some());
    }
}
