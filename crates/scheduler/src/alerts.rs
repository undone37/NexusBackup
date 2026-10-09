//! Alert delivery: webhook (JSON POST) and SMTP, configured in
//! `/etc/nexus/alerts.json`:
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
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::time::Duration;

#[derive(Deserialize, Default, Clone)]
pub struct AlertsConfig {
    pub webhook: Option<Webhook>,
    pub smtp: Option<Smtp>,
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
    if let (Some(u), Some(pf)) = (&s.username, &s.password_file) {
        let pw = std::fs::read_to_string(pf).with_context(|| format!("{}", pf.display()))?;
        t = t.credentials(Credentials::new(u.clone(), pw.trim().to_owned()));
    }
    t.build().send(&msg)?;
    Ok(())
}

/// Background delivery with retries (0 s, 10 s, 60 s). Returns the sender.
pub fn spawn_delivery(cfg: AlertsConfig, backoff: [Duration; 2]) -> Sender<Alert> {
    let (tx, rx): (Sender<Alert>, Receiver<Alert>) = channel();
    std::thread::spawn(move || {
        for a in rx {
            deliver(&cfg, &a, backoff);
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
}
