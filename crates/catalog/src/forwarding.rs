//! Audit and alert forwarding (Phase 14a, docs/control-plane.md "Forwarding"):
//! the setting `forwarding` (written by the web-api, `PUT /settings/forwarding`)
//! shared with the scheduler's forwarder (`scheduler/src/forward.rs`), which
//! delivers the audit chain (by `seq`) and the alert / job events of the outbox
//! (`forward_events`, catalog v15) to a syslog server over TLS and / or an
//! HTTPS endpoint, keeping its cursors in `forward_state`.

use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const SETTING: &str = "forwarding";

/// Private Enterprise Number in the RFC 5424 SD-ID `nexus@<PEN>`. 32473 is the
/// example PEN reserved for documentation (RFC 5612); replace it with an
/// assigned PEN before receivers rely on the SD-ID.
pub const PEN: u32 = 32473;

/// Alert key of a failing sink (`forwarding:syslog`, `forwarding:https`).
pub fn alert_key(sink: &str) -> String {
    format!("forwarding:{sink}")
}

/// Both sinks may be configured and enabled at the same time.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug, Default)]
#[serde(deny_unknown_fields)]
pub struct Forwarding {
    #[serde(default)]
    pub syslog: Option<Syslog>,
    #[serde(default)]
    pub https: Option<Https>,
}

/// RFC 5424 messages, RFC 5425 framing over TLS. Trust: `ca_pem` (a CA, or the
/// server certificate itself), or `pin_sha256` (SHA-256 of the server
/// certificate, hex); neither = the public web PKI roots.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
#[serde(deny_unknown_fields)]
pub struct Syslog {
    #[serde(default = "yes")]
    pub enabled: bool,
    pub host: String,
    #[serde(default = "syslog_port")]
    pub port: u16,
    #[serde(default)]
    pub ca_pem: Option<String>,
    #[serde(default)]
    pub pin_sha256: Option<String>,
    #[serde(default = "app_name")]
    pub app_name: String,
    /// syslog facility code (0..=23); default 13 ("log audit")
    #[serde(default = "facility")]
    pub facility: u8,
}

/// Batched JSON POST (an array of `{type: audit|alert|job, …}`); header values
/// are sealed to the scheduler at [`header_location`] (write-only in the API).
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
#[serde(deny_unknown_fields)]
pub struct Https {
    #[serde(default = "yes")]
    pub enabled: bool,
    pub url: String,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    #[serde(default = "batch_max")]
    pub batch_max: u32,
    #[serde(default)]
    pub ca_pem: Option<String>,
    #[serde(default)]
    pub pin_sha256: Option<String>,
}

fn yes() -> bool {
    true
}
fn syslog_port() -> u16 {
    6514
}
fn app_name() -> String {
    "nexus".into()
}
fn facility() -> u8 {
    13
}
fn batch_max() -> u32 {
    100
}

/// Where a sealed header value of the HTTPS sink opens (bound to the URL).
pub fn header_location(header: &str, url: &str) -> String {
    format!("settings/forwarding/https/{header}@{url}")
}

impl Syslog {
    /// The destination (cursors restart at 0 when it changes).
    pub fn dest(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

impl Https {
    pub fn dest(&self) -> String {
        self.url.clone()
    }
}

impl Forwarding {
    /// The stored setting (missing or unreadable = nothing configured).
    pub fn load(c: &Connection) -> rusqlite::Result<Self> {
        Ok(crate::setting(c, SETTING)?
            .and_then(|v| serde_json::from_str(&v).ok())
            .unwrap_or_default())
    }

    /// Enabled sinks as (name, destination).
    pub fn enabled(&self) -> Vec<(&'static str, String)> {
        let mut out = Vec::new();
        if let Some(s) = self.syslog.as_ref().filter(|s| s.enabled) {
            out.push(("syslog", s.dest()));
        }
        if let Some(h) = self.https.as_ref().filter(|h| h.enabled) {
            out.push(("https", h.dest()));
        }
        out
    }

    /// Weakens what leaves the box (needs approval): an enabled sink disabled or
    /// removed, or its destination, trust (CA / pin) or headers changed.
    /// Adding or enabling a sink, and format options (app name, facility, batch
    /// size), apply at once.
    pub fn weaker_than(&self, old: &Forwarding) -> bool {
        let syslog = old.syslog.as_ref().filter(|o| o.enabled).is_some_and(|o| {
            !self.syslog.as_ref().is_some_and(|n| {
                n.enabled
                    && n.host == o.host
                    && n.port == o.port
                    && n.ca_pem == o.ca_pem
                    && n.pin_sha256 == o.pin_sha256
            })
        });
        let https = old.https.as_ref().filter(|o| o.enabled).is_some_and(|o| {
            !self.https.as_ref().is_some_and(|n| {
                n.enabled
                    && n.url == o.url
                    && n.ca_pem == o.ca_pem
                    && n.pin_sha256 == o.pin_sha256
                    && n.headers == o.headers
            })
        });
        syslog || https
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn weakening() {
        let on: Forwarding = serde_json::from_value(json!({
            "syslog": {"host": "log.example", "pin_sha256": "ab"},
            "https": {"url": "https://siem.example/in", "headers": {"Authorization": "sealed:v1:x"}}
        }))
        .unwrap();
        let s = on.syslog.as_ref().unwrap();
        assert_eq!(
            (s.port, s.facility, s.app_name.as_str(), s.enabled),
            (6514, 13, "nexus", true)
        );
        assert_eq!(on.enabled().len(), 2);
        let none = Forwarding::default();
        assert!(!on.weaker_than(&none), "adding sinks is never weaker");
        assert!(none.weaker_than(&on));
        assert!(!on.weaker_than(&on));
        let edit = |f: &dyn Fn(&mut Forwarding)| {
            let mut n = on.clone();
            f(&mut n);
            n.weaker_than(&on)
        };
        assert!(edit(&|n| n.syslog.as_mut().unwrap().enabled = false));
        assert!(edit(&|n| n.syslog.as_mut().unwrap().host = "elsewhere".into()));
        assert!(edit(&|n| n.syslog.as_mut().unwrap().pin_sha256 = None));
        assert!(edit(&|n| n.https = None));
        assert!(edit(&|n| {
            n.https.as_mut().unwrap().headers.clear();
        }));
        assert!(!edit(&|n| n.syslog.as_mut().unwrap().facility = 16));
        assert!(!edit(&|n| n.https.as_mut().unwrap().batch_max = 10));
        // a disabled sink may change freely
        let mut off = on.clone();
        off.syslog.as_mut().unwrap().enabled = false;
        let mut moved = off.clone();
        moved.syslog.as_mut().unwrap().host = "x".into();
        assert!(!moved.weaker_than(&off));
    }
}
