//! Inbound firewall policy (Phase 16c, docs/control-plane.md "Inbound
//! firewall"): per service of the appliance, which source addresses may open
//! connections. Setting `inbound` = `{services: {<id>: {allow: [CIDR],
//! enabled?}}}`; a service without an entry has its defaults (allow any,
//! enabled as in [`SERVICES`]). It generalises the Phase 14d management
//! allow-list: without an `inbound` setting, `mgmt_allow` is `web`'s list, and
//! every write mirrors `web` back into `mgmt_allow`.
//!
//! The web-api changes it (approval `firewall.inbound`), the scheduler writes
//! it into the firewall file (`nftsync::Allowed::inbound`), nexus-nft-sync
//! loads it into the `in_<id>_v4/v6` sets of os/nftables.conf, and
//! `nexus-setup reset-firewall` clears every list at the console.

use crate::access;
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const SETTING: &str = "inbound";
/// Most source entries per service (as the 14d allow-list).
pub const MAX_ALLOW: usize = access::MGMT_MAX;

/// A service the appliance listens on (or may in the future).
#[derive(Serialize, Clone, Copy, Debug)]
pub struct Service {
    pub id: &'static str,
    /// what the firewall rule matches (display)
    pub ports: &'static str,
    /// restricting it can lock the administrators out (lock-out guard)
    pub lockout: bool,
    /// something listens on it in this release (else shown, not configurable)
    pub available: bool,
    /// enabled when there is no entry
    pub default_enabled: bool,
    /// may be switched off entirely (else only restricted)
    pub can_disable: bool,
}

/// The fixed registry. `web` is the only TCP listener: the web UI, the REST
/// API, `/metrics` and replication (secondaries pull with their own ALPN) all
/// share 8443, and nftables cannot tell them apart inside TLS, so they are
/// restricted together. Backup agents and every other source are pulled
/// (outbound); DHCP replies, IPv6 neighbour discovery and replies to the
/// appliance's own connections are fixed rules, not services. `ssh` is
/// reserved: there is no SSH server on the appliance.
pub const SERVICES: &[Service] = &[
    Service {
        id: "web",
        ports: "8443/tcp",
        lockout: true,
        available: true,
        default_enabled: true,
        can_disable: false,
    },
    Service {
        id: "icmp",
        ports: "icmp, icmpv6 echo-request",
        lockout: false,
        available: true,
        default_enabled: false,
        can_disable: true,
    },
    Service {
        id: "ssh",
        ports: "22/tcp",
        lockout: true,
        available: false,
        default_enabled: false,
        can_disable: true,
    },
];

pub fn service(id: &str) -> Option<&'static Service> {
    SERVICES.iter().find(|s| s.id == id)
}

/// One service's sources: an empty `allow` means any address.
#[derive(Serialize, Deserialize, Clone, Default, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
}

#[derive(Serialize, Deserialize, Clone, Default, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Inbound {
    #[serde(default)]
    pub services: BTreeMap<String, Rule>,
}

/// Canonical CIDRs (`10.0.0.0/8`; a bare address is /32 or /128), duplicates
/// dropped; the error names the offending entry.
pub fn normalize(allow: &[String]) -> Result<Vec<String>, String> {
    if allow.len() > MAX_ALLOW {
        return Err(format!("allow: at most {MAX_ALLOW} entries"));
    }
    let mut out = Vec::new();
    for s in allow {
        let c = access::cidr_string(s).ok_or_else(|| format!("allow: {s:?} is not an address or CIDR (10.0.0.0/8)"))?;
        if !out.contains(&c) {
            out.push(c);
        }
    }
    Ok(out)
}

impl Inbound {
    /// The effective rule of a service (`enabled` always set).
    pub fn rule(&self, id: &str) -> Rule {
        let r = self.services.get(id).cloned().unwrap_or_default();
        let enabled = service(id).is_some_and(|d| !d.can_disable || r.enabled.unwrap_or(d.default_enabled));
        Rule {
            allow: r.allow,
            enabled: Some(enabled),
        }
    }

    /// `(id, enabled, allow)` of every service something listens on: what the
    /// firewall file carries.
    pub fn effective(&self) -> Vec<(&'static str, bool, Vec<String>)> {
        SERVICES
            .iter()
            .filter(|s| s.available)
            .map(|s| {
                let r = self.rule(s.id);
                (s.id, r.enabled == Some(true), r.allow)
            })
            .collect()
    }

    /// Unknown services and invalid entries dropped.
    fn cleaned(mut self) -> Inbound {
        self.services.retain(|id, _| service(id).is_some());
        for r in self.services.values_mut() {
            let mut v: Vec<String> = Vec::new();
            for c in r.allow.iter().filter_map(|s| access::cidr_string(s)) {
                if !v.contains(&c) && v.len() < MAX_ALLOW {
                    v.push(c);
                }
            }
            r.allow = v;
        }
        self
    }
}

/// The stored policy; without an `inbound` setting the 14d `mgmt_allow` list
/// becomes `web`'s (migration on read).
pub fn load(c: &Connection) -> rusqlite::Result<Inbound> {
    if let Some(v) = crate::setting(c, SETTING)? {
        return Ok(serde_json::from_str::<Inbound>(&v).unwrap_or_default().cleaned());
    }
    let mut i = Inbound::default();
    let legacy = access::legacy_mgmt_allow(c)?;
    if !legacy.is_empty() {
        i.services.insert(
            "web".into(),
            Rule {
                allow: legacy,
                enabled: None,
            },
        );
    }
    Ok(i)
}

/// Stores the policy and mirrors `web`'s list into `mgmt_allow`.
pub fn store(c: &Connection, i: &Inbound) -> rusqlite::Result<()> {
    crate::set_setting(c, SETTING, &serde_json::to_string(i).unwrap_or_default())?;
    crate::set_setting(
        c,
        access::MGMT_ALLOW,
        &serde_json::to_string(&i.rule("web").allow).unwrap_or_default(),
    )
}

/// Console reset: every list cleared (any address), the switches kept.
/// Returns the lists that were removed (service → CIDRs).
pub fn reset(c: &Connection) -> rusqlite::Result<BTreeMap<String, Vec<String>>> {
    let mut i = load(c)?;
    let mut old = BTreeMap::new();
    for (id, r) in i.services.iter_mut() {
        if !r.allow.is_empty() {
            old.insert(id.clone(), std::mem::take(&mut r.allow));
        }
    }
    store(c, &i)?;
    Ok(old)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn registry_defaults_and_validation() {
        let i = Inbound::default();
        assert_eq!(i.rule("web").enabled, Some(true));
        assert_eq!(i.rule("icmp").enabled, Some(false));
        assert_eq!(
            i.effective().iter().map(|e| e.0).collect::<Vec<_>>(),
            ["web", "icmp"],
            "ssh is reserved"
        );
        // web cannot be switched off, only restricted
        let mut j = Inbound::default();
        j.services.insert(
            "web".into(),
            Rule {
                allow: vec![],
                enabled: Some(false),
            },
        );
        assert_eq!(j.rule("web").enabled, Some(true));
        assert_eq!(
            normalize(&s(&["10.1.2.3/8", "10.0.0.0/8", "2001:db8::1"])).unwrap(),
            s(&["10.0.0.0/8", "2001:db8::1/128"])
        );
        assert!(normalize(&s(&["10.0.0.0/33"])).unwrap_err().contains("10.0.0.0/33"));
        assert!(normalize(&s(&["::/129"])).is_err());
        let many: Vec<String> = (0..=MAX_ALLOW).map(|n| format!("10.0.{n}.0/24")).collect();
        assert!(normalize(&many).is_err());
    }

    #[test]
    fn migration_store_and_reset() {
        let cat = crate::Catalog::open_memory().unwrap();
        let c = cat.conn();
        assert_eq!(load(&c).unwrap(), Inbound::default());
        // the 14d list is read as web's
        crate::set_setting(&c, access::MGMT_ALLOW, r#"["10.1.2.3/16","bad"]"#).unwrap();
        let mut i = load(&c).unwrap();
        assert_eq!(i.rule("web").allow, ["10.1.0.0/16"]);
        assert_eq!(access::mgmt_allow(&c).unwrap(), ["10.1.0.0/16"]);
        i.services.insert(
            "icmp".into(),
            Rule {
                allow: s(&["192.0.2.0/24"]),
                enabled: Some(true),
            },
        );
        i.services.get_mut("web").unwrap().allow = s(&["192.0.2.0/24"]);
        store(&c, &i).unwrap();
        assert_eq!(load(&c).unwrap(), i);
        // the old setting follows web
        assert_eq!(access::legacy_mgmt_allow(&c).unwrap(), ["192.0.2.0/24"]);
        // unknown services and invalid entries never come back from storage
        crate::set_setting(
            &c,
            SETTING,
            r#"{"services":{"web":{"allow":["x","10.0.0.0/8","10.0.0.0/8"]},"telnet":{"allow":[]}}}"#,
        )
        .unwrap();
        let l = load(&c).unwrap();
        assert_eq!(l.services.keys().collect::<Vec<_>>(), ["web"]);
        assert_eq!(l.rule("web").allow, ["10.0.0.0/8"]);
        store(&c, &i).unwrap();
        assert_eq!(reset(&c).unwrap().len(), 2);
        let r = load(&c).unwrap();
        assert!(r.rule("web").allow.is_empty() && r.rule("icmp").allow.is_empty());
        assert_eq!(r.rule("icmp").enabled, Some(true), "the reset keeps the switches");
        assert!(access::mgmt_allow(&c).unwrap().is_empty());
    }
}
