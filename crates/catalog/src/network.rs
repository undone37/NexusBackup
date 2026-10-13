//! Network interfaces (Phase 22a, docs/control-plane.md "Network interfaces"): extra NICs,
//! bonds, VLANs, MTU, static addresses and routes, and the role of each interface
//! (management, data, replication). The root helper `nexus-net`
//! (os/greenboot/usr/libexec/nexus/nexus-net) writes the NetworkManager keyfiles and
//! activates them; this module is what the web-api (validation before the approval,
//! Settings → Network) and the scheduler (interface-bound egress) share. The helper checks
//! everything again before it writes anything.
//!
//! Control dir [`DIR`] (2771 root:nexus-webapi): `req-<id>.json` and `confirm.json` (web-api),
//! `status.json` and `ops.json` (helper, 0644: devices, the applied configuration, a pending
//! management change, the path-MTU results).

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

pub const DIR: &str = "/var/lib/nexus/net";
/// A management change is rolled back unless confirmed within this many seconds.
pub const CONFIRM_SECS: i64 = 120;
pub const ROLES: &[&str] = &["management", "data", "replication"];
pub const KINDS: &[&str] = &["ethernet", "bond", "vlan"];
pub const BOND_MODES: &[&str] = &["active-backup", "802.3ad"];
pub const MAX_IFACES: usize = 16;
pub const MTU_MIN: u32 = 1280;
pub const MTU_MAX: u32 = 9216;

/// The configuration nexus-net applies. Every field is always serialized (the helper
/// compares the `old` of a request with its applied configuration as JSON).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub interfaces: Vec<Iface>,
    /// the role whose interface offsite traffic leaves through
    #[serde(default = "management")]
    pub offsite_role: String,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            interfaces: Vec::new(),
            offsite_role: management(),
        }
    }
}

fn management() -> String {
    "management".into()
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
#[serde(deny_unknown_fields)]
pub struct Iface {
    /// the kernel interface name: the NIC for `ethernet`, else the new device's name
    pub name: String,
    pub kind: String,
    /// bond: the member NICs
    #[serde(default)]
    pub ports: Vec<String>,
    /// bond: active-backup | 802.3ad
    #[serde(default)]
    pub mode: Option<String>,
    /// vlan: a NIC or a bond of this configuration
    #[serde(default)]
    pub parent: Option<String>,
    #[serde(default)]
    pub vlan_id: Option<u16>,
    #[serde(default)]
    pub role: Option<String>,
    #[serde(default)]
    pub mtu: Option<u32>,
    /// IPv4 by DHCP (never the default route unless management)
    #[serde(default)]
    pub dhcp: bool,
    /// static `address/prefix`, IPv4 or IPv6
    #[serde(default)]
    pub addresses: Vec<String>,
    /// management only: the default gateway
    #[serde(default)]
    pub gateway: Option<String>,
    #[serde(default)]
    pub dns: Vec<String>,
    #[serde(default)]
    pub routes: Vec<Route>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Route {
    /// network in CIDR form (host bits clear), never a default route
    pub to: String,
    /// next hop in one of the interface's subnets; none = on-link
    #[serde(default)]
    pub via: Option<String>,
}

/// What the helper reported about the host (`status.json`).
pub struct Host<'a> {
    /// physical NICs present
    pub nics: Vec<&'a str>,
    /// the console-configured management NIC (`nexus-mgmt` from nexus-setup) while the
    /// configuration has no management interface
    pub console_mgmt: Option<&'a str>,
    /// the applied configuration has a management interface (it cannot be removed again)
    pub had_mgmt: bool,
}

impl<'a> Host<'a> {
    pub fn from_status(s: &'a Value) -> Host<'a> {
        let nics = s["devices"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|d| d["kind"] == "nic")
            .filter_map(|d| d["name"].as_str())
            .collect();
        let had_mgmt = applied(s).interfaces.iter().any(|i| i.role.as_deref() == Some("management"));
        let console_mgmt = s["management"]["ifname"]
            .as_str()
            .filter(|_| s["management"]["source"] == "console");
        Host {
            nics,
            console_mgmt,
            had_mgmt,
        }
    }
}

/// The applied configuration in a helper status (default: none).
pub fn applied(status: &Value) -> Config {
    serde_json::from_value(status["config"].clone()).unwrap_or_default()
}

/// `addr/prefix` → (address, prefix).
pub fn parse_cidr(s: &str) -> Option<(IpAddr, u8)> {
    let (a, p) = s.split_once('/')?;
    let a: IpAddr = a.parse().ok()?;
    let p: u8 = (!p.is_empty() && p.len() <= 3 && p.bytes().all(|b| b.is_ascii_digit()))
        .then(|| p.parse().ok())??;
    (p <= if a.is_ipv4() { 32 } else { 128 }).then_some((a, p))
}

fn masked(a: IpAddr, p: u8) -> IpAddr {
    match a {
        IpAddr::V4(v) => IpAddr::V4((u32::from(v) & u32::MAX.checked_shl(32 - p as u32).unwrap_or(0)).into()),
        IpAddr::V6(v) => IpAddr::V6((u128::from(v) & u128::MAX.checked_shl(128 - p as u32).unwrap_or(0)).into()),
    }
}

fn in_subnet(ip: IpAddr, net: (IpAddr, u8)) -> bool {
    ip.is_ipv4() == net.0.is_ipv4() && masked(ip, net.1) == masked(net.0, net.1)
}

fn host_ok(a: &IpAddr) -> bool {
    !(a.is_unspecified() || a.is_loopback() || a.is_multicast() || matches!(a, IpAddr::V4(v) if v.is_broadcast()))
}

pub fn ifname_ok(n: &str) -> bool {
    let b = n.as_bytes();
    (1..=15).contains(&b.len())
        && b[0].is_ascii_alphanumeric()
        && b.iter().all(|c| c.is_ascii_alphanumeric() || b"_.-".contains(c))
        && n != "lo"
}

/// Checks a configuration against the host; the first problem as a message.
pub fn validate(c: &Config, host: &Host) -> Result<(), String> {
    if c.interfaces.len() > MAX_IFACES {
        return Err(format!("at most {MAX_IFACES} interfaces"));
    }
    if !ROLES.contains(&c.offsite_role.as_str()) {
        return Err("offsite_role must be management, data or replication".into());
    }
    let names: BTreeSet<&str> = c.interfaces.iter().map(|i| i.name.as_str()).collect();
    if names.len() != c.interfaces.len() {
        return Err("each interface name once".into());
    }
    // NIC → what uses it
    let mut nic_use: BTreeMap<String, String> = BTreeMap::new();
    let mut roles = BTreeSet::new();
    let mut addrs = BTreeSet::new();
    for i in &c.interfaces {
        let n = i.name.as_str();
        if !ifname_ok(n) {
            return Err(format!("{n:?}: an interface name has 1-15 letters, digits, '.', '_' or '-'"));
        }
        let mut uses = |nic: &str, what: String| -> Result<(), String> {
            if !host.nics.contains(&nic) {
                return Err(format!("{n}: there is no network card {nic:?}"));
            }
            if let Some(prev) = nic_use.insert(nic.to_owned(), what.clone()) {
                return Err(format!("{nic} is used twice ({prev} and {what})"));
            }
            Ok(())
        };
        match i.kind.as_str() {
            "ethernet" => {
                if !i.ports.is_empty() || i.mode.is_some() || i.parent.is_some() || i.vlan_id.is_some() {
                    return Err(format!("{n}: a network card has no ports, mode, parent or VLAN ID"));
                }
                uses(n, format!("interface {n}"))?;
            }
            "bond" => {
                if host.nics.contains(&n) {
                    return Err(format!("{n}: a bond needs a new name (e.g. bond0), not a network card's"));
                }
                if i.parent.is_some() || i.vlan_id.is_some() {
                    return Err(format!("{n}: a bond has no parent or VLAN ID"));
                }
                if !matches!(i.mode.as_deref(), Some(m) if BOND_MODES.contains(&m)) {
                    return Err(format!("{n}: bond mode must be active-backup or 802.3ad (LACP)"));
                }
                if i.ports.is_empty() || i.ports.len() > 8 {
                    return Err(format!("{n}: a bond has 1 to 8 ports"));
                }
                for p in &i.ports {
                    uses(p, format!("bond {n}"))?;
                }
            }
            "vlan" => {
                if host.nics.contains(&n) {
                    return Err(format!("{n}: a VLAN needs a new name (e.g. {}.{}), not a network card's",
                        i.parent.as_deref().unwrap_or("eth0"), i.vlan_id.unwrap_or(10)));
                }
                if !i.ports.is_empty() || i.mode.is_some() {
                    return Err(format!("{n}: a VLAN has no ports or mode"));
                }
                if !matches!(i.vlan_id, Some(1..=4094)) {
                    return Err(format!("{n}: VLAN ID must be 1 to 4094"));
                }
                let p = i.parent.as_deref().unwrap_or_default();
                match c.interfaces.iter().find(|x| x.name == p) {
                    Some(x) if x.kind == "vlan" => return Err(format!("{n}: a VLAN cannot sit on another VLAN")),
                    Some(x) => {
                        if let (Some(m), Some(pm)) = (i.mtu, x.mtu.or(Some(1500))) {
                            if m > pm {
                                return Err(format!("{n}: MTU {m} is larger than the MTU of {p} ({pm})"));
                            }
                        }
                    }
                    None if host.nics.contains(&p) => {}
                    None => return Err(format!("{n}: parent {p:?} is neither a network card nor an interface here")),
                }
                if c.interfaces.iter().any(|x| x.kind == "bond" && x.ports.iter().any(|q| q == p)) {
                    return Err(format!("{n}: {p} is a bond port; put the VLAN on the bond"));
                }
                if c.interfaces.iter().any(|x| x.kind == "vlan" && x.name != n && x.parent == i.parent && x.vlan_id == i.vlan_id) {
                    return Err(format!("{n}: VLAN {} on {p} twice", i.vlan_id.unwrap_or(0)));
                }
            }
            _ => return Err(format!("{n}: kind must be ethernet, bond or vlan")),
        }
        if let Some(r) = &i.role {
            if !ROLES.contains(&r.as_str()) {
                return Err(format!("{n}: role must be management, data or replication"));
            }
            if !roles.insert(r.as_str()) {
                return Err(format!("only one interface can have the role {r}"));
            }
        }
        let mgmt = i.role.as_deref() == Some("management");
        if let Some(m) = i.mtu {
            if !(MTU_MIN..=MTU_MAX).contains(&m) {
                return Err(format!("{n}: MTU must be {MTU_MIN} to {MTU_MAX}"));
            }
        }
        if i.addresses.len() > 8 || i.dns.len() > 4 || i.routes.len() > 32 {
            return Err(format!("{n}: at most 8 addresses, 4 DNS servers and 32 routes"));
        }
        let mut nets = Vec::new();
        for a in &i.addresses {
            let (ip, p) = parse_cidr(a).ok_or_else(|| format!("{n}: {a:?} is not address/prefix (192.0.2.10/24)"))?;
            if !host_ok(&ip) || p == 0 {
                return Err(format!("{n}: {a} is not a usable host address"));
            }
            if !addrs.insert(ip) {
                return Err(format!("{ip} is configured twice"));
            }
            nets.push((ip, p));
        }
        if mgmt && !i.dhcp && i.addresses.is_empty() {
            return Err(format!("{n}: the management interface needs DHCP or an address"));
        }
        if let Some(g) = &i.gateway {
            if !mgmt {
                return Err(format!(
                    "{n}: only the management interface has a default gateway; reach other networks with routes"
                ));
            }
            let g: IpAddr = g.parse().map_err(|_| format!("{n}: gateway {g:?} is not an address"))?;
            if i.dhcp && g.is_ipv4() {
                return Err(format!("{n}: with DHCP the gateway comes from the DHCP server"));
            }
            if !host_ok(&g) || nets.iter().any(|x| x.0 == g) || !nets.iter().any(|x| in_subnet(g, *x)) {
                return Err(format!("{n}: gateway {g} must be another host in one of its subnets"));
            }
        }
        for d in &i.dns {
            if !d.parse::<IpAddr>().is_ok_and(|a| host_ok(&a)) {
                return Err(format!("{n}: DNS server {d:?} is not an address"));
            }
        }
        for r in &i.routes {
            let (net, p) = parse_cidr(&r.to).ok_or_else(|| format!("{n}: route {:?} is not a network (10.30.0.0/16)", r.to))?;
            if p == 0 {
                return Err(format!("{n}: no default route here; the management interface's gateway is the default"));
            }
            if masked(net, p) != net {
                return Err(format!("{n}: route {} has host bits set (did you mean {}/{p}?)", r.to, masked(net, p)));
            }
            if let Some(v) = &r.via {
                let v: IpAddr = v.parse().map_err(|_| format!("{n}: next hop {v:?} is not an address"))?;
                if v.is_ipv4() != net.is_ipv4() || !host_ok(&v) {
                    return Err(format!("{n}: next hop {v} does not fit route {}", r.to));
                }
                if !(i.dhcp && v.is_ipv4()) && !nets.iter().any(|x| in_subnet(v, *x)) {
                    return Err(format!("{n}: next hop {v} is not in a subnet of {n}"));
                }
            }
        }
    }
    let has_mgmt = roles.contains("management");
    if host.had_mgmt && !has_mgmt {
        return Err("the management interface cannot be removed, only changed (or reset at the console)".into());
    }
    if let (false, Some(m)) = (has_mgmt, host.console_mgmt) {
        if let Some(what) = nic_use.get(m) {
            return Err(format!(
                "{m} is the management network card (set at the console); it cannot be used as {what}. \
                 Give an interface the management role to move the management network."
            ));
        }
    }
    Ok(())
}

/// The management interface and what it sits on (its parent, the bond's ports): what a
/// change of needs the 120-second confirmation.
pub fn management_chain(c: &Config) -> Vec<&Iface> {
    let mut out = Vec::new();
    if let Some(m) = c.interfaces.iter().find(|i| i.role.as_deref() == Some("management")) {
        out.push(m);
        if let Some(p) = m.parent.as_deref().and_then(|p| c.interfaces.iter().find(|x| x.name == p)) {
            out.push(p);
        }
    }
    out
}

/// Whether going from `old` to `new` touches the management interface.
pub fn management_changed(old: &Config, new: &Config) -> bool {
    management_chain(old) != management_chain(new)
}

/// role → interface name for interface-bound egress (`data`, `replication`, `offsite`): only
/// roles the applied configuration gives an interface; the rest leave through any interface.
pub fn egress(c: &Config) -> BTreeMap<&'static str, String> {
    let of = |role: &str| {
        c.interfaces
            .iter()
            .find(|i| i.role.as_deref() == Some(role))
            .map(|i| i.name.clone())
    };
    let mut out = BTreeMap::new();
    for (k, role) in [("data", "data"), ("replication", "replication"), ("offsite", c.offsite_role.as_str())] {
        if let Some(n) = of(role) {
            out.insert(k, n);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn cfg(v: Value) -> Config {
        serde_json::from_value(v).unwrap()
    }

    fn host() -> Host<'static> {
        Host {
            nics: vec!["ens3", "ens4", "ens5", "ens6"],
            console_mgmt: Some("ens3"),
            had_mgmt: false,
        }
    }

    #[test]
    fn valid_bond_vlan_data() {
        let c = cfg(json!({"interfaces": [
            {"name": "bond0", "kind": "bond", "ports": ["ens4", "ens5"], "mode": "802.3ad", "mtu": 9000},
            {"name": "bond0.20", "kind": "vlan", "parent": "bond0", "vlan_id": 20, "role": "data", "mtu": 9000,
             "addresses": ["10.0.20.5/24"], "routes": [{"to": "10.30.0.0/16", "via": "10.0.20.1"}]},
            {"name": "ens6", "kind": "ethernet", "role": "replication", "dhcp": true}
        ]}));
        validate(&c, &host()).unwrap();
        assert_eq!(c.offsite_role, "management");
        let e = egress(&c);
        assert_eq!(e.get("data").map(String::as_str), Some("bond0.20"));
        assert_eq!(e.get("replication").map(String::as_str), Some("ens6"));
        assert!(!e.contains_key("offsite"), "management not configured here: any interface");
        assert!(!management_changed(&Config::default(), &c));
        // every field serialized (the helper compares `old` as JSON)
        let v = serde_json::to_value(&c).unwrap();
        assert_eq!(v["interfaces"][2]["ports"], json!([]));
        assert!(v["interfaces"][2].as_object().unwrap().contains_key("gateway"));
    }

    #[test]
    fn refusals() {
        let bad = |v: Value, want: &str| {
            let e = validate(&cfg(json!({"interfaces": v})), &host()).unwrap_err();
            assert!(e.contains(want), "{e} / {want}");
        };
        bad(json!([{"name": "ens9", "kind": "ethernet"}]), "no network card");
        bad(json!([{"name": "bond0", "kind": "bond", "ports": ["ens4"], "mode": "balance-rr"}]), "active-backup");
        bad(json!([{"name": "bond0", "kind": "bond", "ports": ["ens4"], "mode": "802.3ad"},
                   {"name": "ens4", "kind": "ethernet"}]), "used twice");
        bad(json!([{"name": "bond0", "kind": "bond", "ports": ["ens3"], "mode": "802.3ad"}]), "management network card");
        bad(json!([{"name": "v", "kind": "vlan", "parent": "ens4", "vlan_id": 4095}]), "1 to 4094");
        bad(json!([{"name": "v", "kind": "vlan", "parent": "ens9", "vlan_id": 5}]), "neither");
        bad(json!([{"name": "bond0", "kind": "bond", "ports": ["ens4"], "mode": "802.3ad"},
                   {"name": "v", "kind": "vlan", "parent": "ens4", "vlan_id": 5}]), "bond port");
        bad(json!([{"name": "bond0", "kind": "bond", "ports": ["ens4"], "mode": "802.3ad", "mtu": 1500},
                   {"name": "v", "kind": "vlan", "parent": "bond0", "vlan_id": 5, "mtu": 9000}]), "larger than");
        bad(json!([{"name": "ens4", "kind": "ethernet", "role": "data"}, {"name": "ens5", "kind": "ethernet", "role": "data"}]), "only one");
        bad(json!([{"name": "ens4", "kind": "ethernet", "mtu": 100}]), "MTU");
        bad(json!([{"name": "ens4", "kind": "ethernet", "addresses": ["10.0.0.5"]}]), "address/prefix");
        bad(json!([{"name": "ens4", "kind": "ethernet", "addresses": ["10.0.0.5/24"], "gateway": "10.0.0.1"}]), "only the management");
        bad(json!([{"name": "ens4", "kind": "ethernet", "role": "management", "addresses": ["10.0.0.5/24"], "gateway": "10.1.0.1"}]), "subnets");
        bad(json!([{"name": "ens4", "kind": "ethernet", "role": "management"}]), "DHCP or an address");
        bad(json!([{"name": "ens4", "kind": "ethernet", "addresses": ["10.0.0.5/24"], "routes": [{"to": "0.0.0.0/0", "via": "10.0.0.1"}]}]), "default route");
        bad(json!([{"name": "ens4", "kind": "ethernet", "addresses": ["10.0.0.5/24"], "routes": [{"to": "10.30.1.0/16"}]}]), "host bits");
        bad(json!([{"name": "ens4", "kind": "ethernet", "addresses": ["10.0.0.5/24"], "routes": [{"to": "10.30.0.0/16", "via": "10.9.0.1"}]}]), "not in a subnet");
        bad(json!([{"name": "ens4", "kind": "ethernet", "addresses": ["10.0.0.5/24"]}, {"name": "ens5", "kind": "ethernet", "addresses": ["10.0.0.5/16"]}]), "twice");
        bad(json!([{"name": "x;rm", "kind": "bond", "ports": ["ens4"], "mode": "802.3ad"}]), "interface name");
        assert!(serde_json::from_value::<Config>(json!({"interfaces": [{"name": "a", "kind": "bond", "x": 1}]})).is_err());
    }

    #[test]
    fn management_moves() {
        let mut h = host();
        // the console NIC joins a bond together with the management role: allowed
        let c = cfg(json!({"interfaces": [
            {"name": "bond0", "kind": "bond", "ports": ["ens3", "ens4"], "mode": "active-backup", "role": "management",
             "addresses": ["192.0.2.10/24"], "gateway": "192.0.2.1", "dns": ["192.0.2.53"]}
        ], "offsite_role": "management"}));
        validate(&c, &h).unwrap();
        assert!(management_changed(&Config::default(), &c));
        assert_eq!(egress(&c).get("offsite").map(String::as_str), Some("bond0"));
        // once managed here, it cannot be dropped again
        h.had_mgmt = true;
        h.console_mgmt = None;
        let e = validate(&Config::default(), &h).unwrap_err();
        assert!(e.contains("cannot be removed"), "{e}");
        // a change elsewhere is not a management change
        let mut c2 = c.clone();
        c2.interfaces.push(cfg(json!({"interfaces": [{"name": "ens5", "kind": "ethernet", "role": "data", "dhcp": true}]})).interfaces.remove(0));
        assert!(!management_changed(&c, &c2));
        let st = json!({"config": c2, "devices": [{"name": "ens3", "kind": "nic"}, {"name": "bond0", "kind": "bond"}],
                        "management": {"ifname": "bond0", "source": "config"}});
        let h = Host::from_status(&st);
        assert_eq!(h.nics, vec!["ens3"]);
        assert!(h.had_mgmt && h.console_mgmt.is_none());
    }
}
