//! Outbound firewall allow-list sync (plan §12.1, os/nftables.conf).
//!
//! The scheduler knows every configured destination (PVE API + SSH of each
//! source, SFTP boxes, webhook/SMTP) and writes them, resolved to addresses,
//! to [`ALLOWED_FILE`] ([`write_allowed`], only when the content changes).
//! `nexus-nft-sync` (root oneshot, started by `nexus-nft-sync.path` on every
//! change and by a timer) validates that file and replaces the sets of
//! `table inet nexus` in one nft transaction:
//!
//! - `allowed_out_v4/v6` (addr . proto . port) from the file,
//! - `dns_servers_v4/v6` from the `nameserver` lines of /etc/resolv.conf
//!   (written by NetworkManager),
//! - `nts_servers_v4/v6` from the `server`/`pool` lines of /etc/chrony.conf and the files it
//!   includes (the time servers of Settings > Time, /etc/nexus/time/*.conf; NTS-KE 4460/tcp and
//!   NTP 123/udp, plain NTP servers only if an administrator allowed them there), resolved after
//!   the DNS sets are in place,
//! - `bound_out_v4/v6` (addr . proto . port . oifname, Phase 22a) from the file's `roles`:
//!   the destinations of a role (data: sources and agents; offsite; replication) that has an
//!   interface (Settings → Network) may only leave through it; a role without one goes
//!   into `allowed_out_*` like any destination. `probe_v4/v6`: every role destination's
//!   address, for the ICMP echo of nexus-net's path-MTU check,
//! - `in_<service>_v4/v6` (inbound, Phase 16c: who may open connections to a
//!   service of [`INBOUND_SERVICES`]) from the file's `inbound` rules (catalog
//!   setting `inbound`): enabled with an empty list = any address (`0.0.0.0/0`,
//!   `::/0`), enabled with a list = those CIDRs, disabled = nobody. A service
//!   missing from the file keeps its sets. Always flushed and refilled in the
//!   same transaction (interval sets: no partial state, no lockout window).
//!
//! `nexus-nft-sync --status` (and every sync) writes [`STATUS_FILE`] for the
//! web UI: the effective inbound and outbound sets and the recent blocked
//! inbound attempts, which the input chain records in the dynamic sets
//! `in_drops_v4/v6` (source . protocol . port, 24 h timeout, refreshed per
//! packet, with a packet counter).
//!
//! The root side never interprets anything but IP literals, protocol names,
//! port numbers and the fixed service ids from the unprivileged file; the nft
//! script is built from parsed values only, so no text from the file reaches nft.

#![warn(missing_docs)]

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::io::Write as _;
use std::net::{IpAddr, ToSocketAddrs};
use std::path::Path;
use std::process::{Command, Stdio};

pub mod status;
pub use status::STATUS_FILE;

/// Allow-list the scheduler writes (unprivileged) and nexus-nft-sync reads; JSON of [`Allowed`].
pub const ALLOWED_FILE: &str = "/run/nexus-nft/allowed.json";
/// nft family and name of the table whose sets this tool replaces (os/nftables.conf).
pub const TABLE: &str = "inet nexus";
/// Upper bound of endpoints accepted from the file.
pub const MAX_ENDPOINTS: usize = 4096;
const MAX_FILE: u64 = 1 << 20;

/// Transport protocol of an endpoint; lower case in JSON and in nft.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "lowercase")]
pub enum Proto {
    /// TCP
    Tcp,
    /// UDP
    Udp,
}

impl Proto {
    fn as_str(self) -> &'static str {
        match self {
            Proto::Tcp => "tcp",
            Proto::Udp => "udp",
        }
    }
}

/// One outbound destination: an element `addr . proto . port` of the allow sets.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(deny_unknown_fields)]
pub struct Endpoint {
    /// resolved address (no names: the root side resolves nothing); unspecified, multicast, loopback and broadcast are refused
    pub addr: IpAddr,
    /// transport protocol
    pub proto: Proto,
    /// destination port; 0 is refused
    pub port: u16,
}

/// Content of [`ALLOWED_FILE`]. Read with [`Allowed::parse`] / [`Allowed::load`], which validate it.
#[derive(Serialize, Deserialize, Default, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Allowed {
    /// destinations of no role (or of a role without an interface): `allowed_out_v4/v6`
    pub endpoints: Vec<Endpoint>,
    /// inbound rules per service id; `None` = not managed
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inbound: Option<BTreeMap<String, InboundRule>>,
    /// destinations per role ([`ROLES`]), bound to the role's interface when it has one
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub roles: BTreeMap<String, RoleTargets>,
}

/// Roles whose destinations can be bound to an interface (catalog::network egress).
pub const ROLES: &[&str] = &["data", "offsite", "replication"];

/// The destinations of one role ([`ROLES`]) and the interface they are bound to.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RoleTargets {
    /// the interface they must leave through; `None` = any (the role has no interface)
    #[serde(default)]
    pub iface: Option<String>,
    /// destinations of the role; at most [`MAX_ENDPOINTS`] over the whole file
    pub endpoints: Vec<Endpoint>,
}

/// A Linux interface name as nft gets it (quoted): 1-15 of `[A-Za-z0-9_.-]`.
pub fn ifname_ok(n: &str) -> bool {
    (1..=15).contains(&n.len())
        && n.bytes().all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
        && n.as_bytes()[0].is_ascii_alphanumeric()
}

/// Services with `in_<id>_v4/v6` sets in os/nftables.conf (catalog::firewall
/// registry, available services only).
pub const INBOUND_SERVICES: &[&str] = &["web", "icmp"];

/// Who may reach one service: `allow` empty = any address.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct InboundRule {
    /// `false` = nobody may connect (both sets empty)
    pub enabled: bool,
    /// CIDRs or bare addresses (see [`parse_cidr`]), at most [`MAX_ALLOW`]
    pub allow: Vec<String>,
}

/// The file's `inbound` map from `(service, enabled, allow)` (as
/// `catalog::firewall::Inbound::effective` yields them).
pub fn inbound_map<S: Into<String>>(
    rules: impl IntoIterator<Item = (S, bool, Vec<String>)>,
) -> BTreeMap<String, InboundRule> {
    rules
        .into_iter()
        .map(|(id, enabled, allow)| (id.into(), InboundRule { enabled, allow }))
        .collect()
}

/// Upper bound of CIDRs per service accepted from the file.
pub const MAX_ALLOW: usize = 64;

/// `addr/prefix` or a bare address, host bits cleared; `None` if invalid. The
/// result is formatted from the parsed value only (no text reaches nft).
pub fn parse_cidr(s: &str) -> Option<(IpAddr, u8)> {
    let (a, p) = s.split_once('/').map_or((s, None), |(a, p)| (a, Some(p)));
    let addr: IpAddr = a.parse().ok()?;
    let max = if addr.is_ipv4() { 32 } else { 128 };
    let prefix = match p {
        Some(p) if (1..=3).contains(&p.len()) && p.bytes().all(|b| b.is_ascii_digit()) => p.parse().ok()?,
        Some(_) => return None,
        None => max,
    };
    if prefix > max {
        return None;
    }
    let addr = match addr {
        IpAddr::V4(v) => IpAddr::V4((u32::from(v) & u32::MAX.checked_shl(32 - prefix as u32).unwrap_or(0)).into()),
        IpAddr::V6(v) => IpAddr::V6((u128::from(v) & u128::MAX.checked_shl(128 - prefix as u32).unwrap_or(0)).into()),
    };
    Some((addr, prefix))
}

/// The `in_<service>_v4/v6` sets of one service: enabled with no CIDRs = any
/// address, disabled = empty (nobody). `service` must be one of
/// [`INBOUND_SERVICES`] (the caller checks; the set names are fixed).
pub fn inbound_state(service: &str, enabled: bool, list: &[(IpAddr, u8)]) -> State {
    let mut v4: BTreeSet<String> = BTreeSet::new();
    let mut v6: BTreeSet<String> = BTreeSet::new();
    if enabled {
        for (a, p) in list {
            if a.is_ipv4() { &mut v4 } else { &mut v6 }.insert(format!("{a}/{p}"));
        }
        if list.is_empty() {
            v4.insert("0.0.0.0/0".into());
            v6.insert("::/0".into());
        }
    }
    State::from([(format!("in_{service}_v4"), v4), (format!("in_{service}_v6"), v6)])
}

/// The sets of every rule in `inbound` (validated: known services, CIDRs).
pub fn inbound_states(inbound: &BTreeMap<String, InboundRule>) -> State {
    let mut st = State::new();
    for (id, r) in inbound {
        if let Some(svc) = INBOUND_SERVICES.iter().find(|s| *s == id) {
            let nets: Vec<(IpAddr, u8)> = r.allow.iter().filter_map(|c| parse_cidr(c)).collect();
            st.extend(inbound_state(svc, r.enabled, &nets));
        }
    }
    st
}

/// Addresses that never belong into an outbound allow-list.
fn usable(a: &IpAddr) -> bool {
    !(a.is_unspecified() || a.is_multicast() || a.is_loopback() || matches!(a, IpAddr::V4(v) if v.is_broadcast()))
}

impl Allowed {
    /// Parses and validates `allowed.json`: endpoint count, known roles and inbound services, interface names,
    /// usable addresses, ports and CIDRs. Any violation fails the whole file (nothing is applied).
    pub fn parse(bytes: &[u8]) -> Result<Allowed> {
        let a: Allowed = serde_json::from_slice(bytes).context("allowed.json")?;
        let n = a.endpoints.len() + a.roles.values().map(|r| r.endpoints.len()).sum::<usize>();
        if n > MAX_ENDPOINTS {
            bail!("allowed.json: {n} endpoints (max {MAX_ENDPOINTS})");
        }
        for (role, r) in &a.roles {
            if !ROLES.contains(&role.as_str()) {
                bail!("allowed.json: unknown role {role:?}");
            }
            if let Some(i) = r.iface.as_deref().filter(|i| !ifname_ok(i)) {
                bail!("allowed.json: {role}: refused interface name {i:?}");
            }
        }
        for e in a.endpoints.iter().chain(a.roles.values().flat_map(|r| &r.endpoints)) {
            if e.port == 0 || !usable(&e.addr) {
                bail!(
                    "allowed.json: refused endpoint {} {} {}",
                    e.addr,
                    e.proto.as_str(),
                    e.port
                );
            }
        }
        for (id, r) in a.inbound.iter().flatten() {
            if !INBOUND_SERVICES.contains(&id.as_str()) {
                bail!("allowed.json: unknown inbound service {id:?}");
            }
            if r.allow.len() > MAX_ALLOW {
                bail!("allowed.json: {id}: {} CIDRs (max {MAX_ALLOW})", r.allow.len());
            }
            if let Some(bad) = r.allow.iter().find(|c| parse_cidr(c).is_none()) {
                bail!("allowed.json: {id}: refused CIDR {bad:?}");
            }
        }
        Ok(a)
    }

    /// Missing file = no endpoints (scheduler not running yet).
    pub fn load(path: &Path) -> Result<Allowed> {
        use std::io::Read;
        let f = match std::fs::File::open(path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Allowed::default()),
            Err(e) => return Err(e).with_context(|| path.display().to_string()),
        };
        let mut b = Vec::new();
        f.take(MAX_FILE + 1).read_to_end(&mut b)?;
        if b.len() as u64 > MAX_FILE {
            bail!("{} is larger than {MAX_FILE} bytes", path.display());
        }
        Allowed::parse(&b)
    }
}

/// Writes `allowed.json` atomically when its content differs (sorted, deduplicated).
/// Returns whether it was written. A missing parent directory means the
/// firewall sync is not installed (development): nothing is written.
/// `inbound`: the inbound rules (unknown services and invalid entries dropped).
/// `roles`: destinations per role (unknown roles and invalid interface names dropped).
pub fn write_allowed(
    path: &Path,
    endpoints: impl IntoIterator<Item = Endpoint>,
    inbound: Option<&BTreeMap<String, InboundRule>>,
    roles: &BTreeMap<String, RoleTargets>,
) -> Result<bool> {
    let ok = |e: &Endpoint| usable(&e.addr) && e.port != 0;
    let set: BTreeSet<Endpoint> = endpoints.into_iter().filter(ok).collect();
    let mut budget = MAX_ENDPOINTS.saturating_sub(set.len());
    let roles: BTreeMap<String, RoleTargets> = roles
        .iter()
        .filter(|(id, r)| ROLES.contains(&id.as_str()) && r.iface.as_deref().is_none_or(ifname_ok))
        .map(|(id, r)| {
            let eps: BTreeSet<Endpoint> = r.endpoints.iter().copied().filter(ok).collect();
            let eps: Vec<Endpoint> = eps.into_iter().take(budget).collect();
            budget -= eps.len();
            (
                id.clone(),
                RoleTargets {
                    iface: r.iface.clone(),
                    endpoints: eps,
                },
            )
        })
        .filter(|(_, r)| !r.endpoints.is_empty())
        .collect();
    let inbound = inbound.map(|m| {
        m.iter()
            .filter(|(id, _)| INBOUND_SERVICES.contains(&id.as_str()))
            .map(|(id, r)| {
                let nets: BTreeSet<String> = r
                    .allow
                    .iter()
                    .filter_map(|c| parse_cidr(c))
                    .map(|(a, p)| format!("{a}/{p}"))
                    .collect();
                let allow = nets.into_iter().take(MAX_ALLOW).collect();
                (
                    id.clone(),
                    InboundRule {
                        enabled: r.enabled,
                        allow,
                    },
                )
            })
            .collect()
    });
    let a = Allowed {
        endpoints: set.into_iter().take(MAX_ENDPOINTS).collect(),
        inbound,
        roles,
    };
    let mut data = serde_json::to_vec_pretty(&a)?;
    data.push(b'\n');
    let Some(dir) = path.parent().filter(|d| d.is_dir()) else {
        return Ok(false);
    };
    if std::fs::read(path).is_ok_and(|old| old == data) {
        return Ok(false);
    }
    let tmp = dir.join(".allowed.json.tmp");
    let _ = std::fs::remove_file(&tmp);
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o644)
            .open(&tmp)?;
        f.write_all(&data)?;
        // world-readable whatever the umask (the scheduler runs with 0077): the
        // root reader holds only CAP_NET_ADMIN, no DAC override
        use std::os::unix::fs::PermissionsExt;
        f.set_permissions(std::fs::Permissions::from_mode(0o644))?;
    }
    std::fs::rename(&tmp, path)?;
    Ok(true)
}

/// `nameserver` IP literals of a resolv.conf (scoped IPv6 and loopback skipped).
pub fn parse_resolv(text: &str) -> Vec<IpAddr> {
    let mut out = Vec::new();
    for l in text.lines() {
        let mut w = l.split_whitespace();
        if w.next() == Some("nameserver") {
            if let Some(a) = w.next().and_then(|a| a.parse::<IpAddr>().ok()) {
                if usable(&a) && !out.contains(&a) {
                    out.push(a);
                }
            }
        }
    }
    out
}

/// Host names (or IP literals) of the `server`/`pool` lines: NTS and, where an administrator
/// allowed them (Settings > Time), plain NTP servers (both need 123/udp; NTS also 4460/tcp).
pub fn parse_chrony(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for l in text.lines() {
        let l = l.split(['#', '!', ';']).next().unwrap_or_default();
        let w: Vec<&str> = l.split_whitespace().collect();
        if w.len() >= 2 && matches!(w[0], "server" | "pool") {
            let h = w[1].to_owned();
            let ok =
                !h.is_empty() && h.len() <= 253 && h.bytes().all(|b| b.is_ascii_alphanumeric() || b".-:".contains(&b));
            if ok && !out.contains(&h) {
                out.push(h);
            }
        }
    }
    out
}

/// The NTP endpoints nexus-time reports for chronyd's sources (`/run/nexus-time/addresses`, `<address>
/// <port>` per line): NTS key exchange may hand out NTP servers at other addresses and ports than the
/// server's own (nts.netnod.se: other addresses, port 4123), which chronyd learned over the authenticated
/// exchange. UDP only; lines that are not an address and a port 1-65535 are ignored; at most 64.
pub fn parse_time_endpoints(text: &str) -> Vec<Endpoint> {
    let mut out: Vec<Endpoint> = text
        .lines()
        .filter_map(|l| {
            let mut w = l.split_whitespace();
            let addr: IpAddr = w.next()?.parse().ok()?;
            let port: u16 = w.next()?.parse().ok()?;
            (w.next().is_none() && port != 0 && usable(&addr)).then_some(Endpoint {
                addr,
                proto: Proto::Udp,
                port,
            })
        })
        .collect();
    out.sort();
    out.dedup();
    out.truncate(64);
    out
}

/// The files named by `include` lines: a file, or `<dir>/*.conf` (every `.conf` file in the
/// directory, sorted, as chronyd's glob reads them).
pub fn chrony_includes(text: &str) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    for l in text.lines() {
        let w: Vec<&str> = l
            .split(['#', '!', ';'])
            .next()
            .unwrap_or_default()
            .split_whitespace()
            .collect();
        if w.len() != 2 || w[0] != "include" {
            continue;
        }
        match w[1].strip_suffix("/*.conf") {
            Some(dir) => {
                let mut files: Vec<_> = std::fs::read_dir(dir)
                    .map(|rd| {
                        rd.filter_map(Result::ok)
                            .map(|e| e.path())
                            .filter(|p| p.extension().is_some_and(|x| x == "conf"))
                            .collect()
                    })
                    .unwrap_or_default();
                files.sort();
                out.extend(files);
            }
            None => out.push(w[1].into()),
        }
    }
    out
}

/// Static destinations of the OS itself (e.g. the update registry), root-owned
/// `/etc/nexus/allowed-hosts`: `<host> <port> [tcp|udp]` per line, `#` comments.
pub fn parse_hosts(text: &str) -> Vec<(String, u16, Proto)> {
    let mut out = Vec::new();
    for l in text.lines() {
        let w: Vec<&str> = l.split('#').next().unwrap_or_default().split_whitespace().collect();
        let proto = match w.get(2).copied() {
            None | Some("tcp") => Proto::Tcp,
            Some("udp") => Proto::Udp,
            Some(p) => {
                eprintln!("<4>nexus-nft-sync: allowed-hosts: unknown protocol {p:?}");
                continue;
            }
        };
        match (w.first(), w.get(1).and_then(|p| p.parse::<u16>().ok())) {
            (Some(h), Some(p)) if p != 0 && w.len() <= 3 => out.push((h.to_string(), p, proto)),
            (None, _) => {}
            _ => eprintln!("<4>nexus-nft-sync: allowed-hosts: ignoring {l:?}"),
        }
    }
    out
}

/// Resolves `parse_hosts` entries; failures are reported, not fatal.
pub fn resolve_hosts(hosts: &[(String, u16, Proto)]) -> (Vec<Endpoint>, Vec<String>) {
    let mut out = Vec::new();
    let mut errors = Vec::new();
    for (h, port, proto) in hosts {
        match (h.as_str(), *port).to_socket_addrs() {
            Ok(it) => out.extend(it.map(|a| a.ip()).filter(usable).map(|addr| Endpoint {
                addr,
                proto: *proto,
                port: *port,
            })),
            Err(e) => errors.push(format!("{h}: {e}")),
        }
    }
    (out, errors)
}

/// Resolves NTS server names (NTS-KE port) to addresses; failures are reported, not fatal.
pub fn resolve(hosts: &[String]) -> (Vec<IpAddr>, Vec<String>) {
    let mut addrs = Vec::new();
    let mut errors = Vec::new();
    for h in hosts {
        match (h.as_str(), 4460).to_socket_addrs() {
            Ok(it) => {
                for a in it.map(|s| s.ip()) {
                    if usable(&a) && !addrs.contains(&a) {
                        addrs.push(a);
                    }
                }
            }
            Err(e) => errors.push(format!("{h}: {e}")),
        }
    }
    (addrs, errors)
}

/// Elements per set (set name -> nft element expressions) that this tool manages.
/// Only sets present in the map are touched.
pub type State = BTreeMap<String, BTreeSet<String>>;

fn split<T>(addrs: &[T], v4: impl Fn(&T) -> bool, fmt: impl Fn(&T) -> String) -> (BTreeSet<String>, BTreeSet<String>) {
    let (a, b): (Vec<&T>, Vec<&T>) = addrs.iter().partition(|x| v4(x));
    (a.into_iter().map(&fmt).collect(), b.into_iter().map(&fmt).collect())
}

/// The desired content of the given sets; `None` = leave those sets alone.
pub fn desired(dns: Option<&[IpAddr]>, nts: Option<&[IpAddr]>, allowed: Option<&Allowed>) -> State {
    let mut st = State::new();
    for (name, list) in [("dns_servers", dns), ("nts_servers", nts)] {
        if let Some(list) = list {
            let (v4, v6) = split(list, IpAddr::is_ipv4, IpAddr::to_string);
            st.insert(format!("{name}_v4"), v4);
            st.insert(format!("{name}_v6"), v6);
        }
    }
    if let Some(a) = allowed {
        // role destinations without an interface are plain destinations
        let mut plain = a.endpoints.clone();
        let mut bound: Vec<(Endpoint, &str)> = Vec::new();
        let mut probe: Vec<IpAddr> = Vec::new();
        for r in a.roles.values() {
            match r.iface.as_deref() {
                Some(i) => bound.extend(r.endpoints.iter().map(|e| (*e, i))),
                None => plain.extend(r.endpoints.iter().copied()),
            }
            probe.extend(r.endpoints.iter().map(|e| e.addr));
        }
        let (v4, v6) = split(
            &plain,
            |e| e.addr.is_ipv4(),
            |e| format!("{} . {} . {}", e.addr, e.proto.as_str(), e.port),
        );
        st.insert("allowed_out_v4".into(), v4);
        st.insert("allowed_out_v6".into(), v6);
        // the interface name was checked (ifname_ok): quoted as an nft string
        let (v4, v6) = split(
            &bound,
            |(e, _)| e.addr.is_ipv4(),
            |(e, i)| format!("{} . {} . {} . \"{i}\"", e.addr, e.proto.as_str(), e.port),
        );
        st.insert("bound_out_v4".into(), v4);
        st.insert("bound_out_v6".into(), v6);
        let (v4, v6) = split(&probe, IpAddr::is_ipv4, IpAddr::to_string);
        st.insert("probe_v4".into(), v4);
        st.insert("probe_v6".into(), v6);
        if let Some(m) = &a.inbound {
            st.extend(inbound_states(m));
        }
    }
    st
}

/// The nft script from the previously applied state to `want`. Without a
/// previous state (first run after boot) the sets are flushed and refilled.
/// With one, only elements this tool added before and no longer wants are
/// removed (`destroy`: no error if already gone, e.g. after an nftables
/// reload), so elements added by others (nexus-update opens 443/tcp to the
/// registry in `allowed_out_*` during a fetch) survive a sync.
pub fn script(prev: Option<&State>, want: &State) -> String {
    let mut out = String::new();
    for (set, elems) in want {
        // interval sets (auto-merge): elements cannot be removed one by one reliably
        let prev = prev.filter(|_| !set.starts_with("in_"));
        match prev {
            None => {
                let _ = writeln!(out, "flush set {TABLE} {set}");
            }
            Some(p) => {
                for gone in p.get(set).into_iter().flatten().filter(|e| !elems.contains(*e)) {
                    let _ = writeln!(out, "destroy element {TABLE} {set} {{ {gone} }}");
                }
            }
        }
        if !elems.is_empty() {
            let v: Vec<&str> = elems.iter().map(String::as_str).collect();
            let _ = writeln!(out, "add element {TABLE} {set} {{ {} }}", v.join(", "));
        }
    }
    out
}

/// Applies a script atomically (`nft -f -`: one transaction).
pub fn apply(nft: &Path, script: &str) -> Result<()> {
    let mut c = Command::new(nft)
        .args(["-f", "-"])
        .stdin(Stdio::piped())
        .spawn()
        .with_context(|| format!("spawn {}", nft.display()))?;
    c.stdin.take().unwrap().write_all(script.as_bytes())?;
    let st = c.wait()?;
    if !st.success() {
        bail!("nft -f - failed ({st})");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allowed_validation() {
        let a = Allowed::parse(
            br#"{"endpoints":[{"addr":"10.0.2.2","proto":"tcp","port":18006},{"addr":"2001:db8::1","proto":"udp","port":53}]}"#,
        )
        .unwrap();
        assert_eq!(a.endpoints.len(), 2);
        for bad in [
            r#"{"endpoints":[{"addr":"0.0.0.0","proto":"tcp","port":1}]}"#,
            r#"{"endpoints":[{"addr":"127.0.0.1","proto":"tcp","port":1}]}"#,
            r#"{"endpoints":[{"addr":"10.0.0.1","proto":"tcp","port":0}]}"#,
            r#"{"endpoints":[{"addr":"10.0.0.1","proto":"icmp","port":1}]}"#,
            r#"{"endpoints":[{"addr":"10.0.0.1 } ; flush ruleset","proto":"tcp","port":1}]}"#,
            r#"{"endpoints":[{"addr":"10.0.0.1","proto":"tcp","port":1,"why":"x"}]}"#,
            r#"{"endpoints":[{"addr":"10.0.0.1","proto":"tcp","port":70000}]}"#,
        ] {
            assert!(Allowed::parse(bad.as_bytes()).is_err(), "{bad}");
        }
    }

    #[test]
    fn resolv_and_chrony() {
        let r = "# NM\nsearch lab\nnameserver 10.0.2.3\nnameserver fe80::1%eth0\nnameserver 2001:db8::53\nnameserver 127.0.0.53\n";
        assert_eq!(
            parse_resolv(r),
            vec!["10.0.2.3".parse::<IpAddr>().unwrap(), "2001:db8::53".parse().unwrap()]
        );
        let c = "server time.cloudflare.com iburst nts\nserver ntp.internal iburst\n# server x nts\nserver ptbtime1.ptb.de nts iburst # c\nserver bad$(rm) nts\n";
        assert_eq!(
            parse_chrony(c),
            vec!["time.cloudflare.com", "ntp.internal", "ptbtime1.ptb.de"]
        );
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join("b.conf"), "server b.example iburst nts\n").unwrap();
        std::fs::write(d.path().join("a.conf"), "server a.example iburst\n").unwrap();
        std::fs::write(d.path().join("a.conf.tmp"), "server tmp.example\n").unwrap();
        let main = format!("include {}/*.conf\ninclude /etc/other.conf # c\n", d.path().display());
        let ep = |a: &str, port| Endpoint {
            addr: a.parse().unwrap(),
            proto: Proto::Udp,
            port,
        };
        assert_eq!(
            parse_time_endpoints(
                "194.58.203.197 4123\n162.159.200.1 123\nnot-an-ip 123\n10.0.0.1 0\n127.0.0.1 123\n2001:db8::7b 123\n194.58.203.197 4123\n10.0.0.2 123 x\n"
            ),
            vec![ep("162.159.200.1", 123), ep("194.58.203.197", 4123), ep("2001:db8::7b", 123)]
        );
        let inc = chrony_includes(&main);
        assert_eq!(
            inc,
            vec![
                d.path().join("a.conf"),
                d.path().join("b.conf"),
                "/etc/other.conf".into()
            ]
        );
    }

    #[test]
    fn static_hosts() {
        let h = parse_hosts("# update registry\nghcr.io 443\n192.0.2.7 514 udp # syslog\nbad\nx 1 icmp\n\n");
        assert_eq!(
            h,
            vec![
                ("ghcr.io".into(), 443, Proto::Tcp),
                ("192.0.2.7".into(), 514, Proto::Udp)
            ]
        );
        let (eps, errs) = resolve_hosts(&h[1..]);
        assert!(errs.is_empty());
        assert_eq!(
            eps,
            vec![Endpoint {
                addr: "192.0.2.7".parse().unwrap(),
                proto: Proto::Udp,
                port: 514
            }]
        );
    }

    #[test]
    fn script_shape() {
        let a = Allowed {
            endpoints: vec![
                Endpoint {
                    addr: "10.0.2.2".parse().unwrap(),
                    proto: Proto::Tcp,
                    port: 10022,
                },
                Endpoint {
                    addr: "10.0.2.2".parse().unwrap(),
                    proto: Proto::Tcp,
                    port: 10022,
                },
                Endpoint {
                    addr: "2001:db8::1".parse().unwrap(),
                    proto: Proto::Tcp,
                    port: 23,
                },
            ],
            inbound: None,
            roles: BTreeMap::new(),
        };
        let dns: Vec<IpAddr> = vec!["10.0.2.3".parse().unwrap()];
        let want = desired(Some(&dns), None, Some(&a));
        assert_eq!(
            script(None, &want),
            "flush set inet nexus allowed_out_v4\nadd element inet nexus allowed_out_v4 { 10.0.2.2 . tcp . 10022 }\n\
             flush set inet nexus allowed_out_v6\nadd element inet nexus allowed_out_v6 { 2001:db8::1 . tcp . 23 }\n\
             flush set inet nexus bound_out_v4\nflush set inet nexus bound_out_v6\n\
             flush set inet nexus dns_servers_v4\nadd element inet nexus dns_servers_v4 { 10.0.2.3 }\n\
             flush set inet nexus dns_servers_v6\n\
             flush set inet nexus probe_v4\nflush set inet nexus probe_v6\n"
        );
        assert!(!script(None, &want).contains("nts_servers"));
        // incremental: only our own stale elements go, nothing is flushed
        let a2 = Allowed {
            endpoints: vec![a.endpoints[2]],
            inbound: None,
            roles: BTreeMap::new(),
        };
        let s = script(Some(&want), &desired(Some(&dns), None, Some(&a2)));
        assert_eq!(
            s,
            "destroy element inet nexus allowed_out_v4 { 10.0.2.2 . tcp . 10022 }\n\
             add element inet nexus allowed_out_v6 { 2001:db8::1 . tcp . 23 }\n\
             add element inet nexus dns_servers_v4 { 10.0.2.3 }\n"
        );
    }

    #[test]
    fn management_allow_list() {
        assert_eq!(parse_cidr("10.1.2.3/8"), Some(("10.0.0.0".parse().unwrap(), 8)));
        assert_eq!(parse_cidr("2001:db8::1"), Some(("2001:db8::1".parse().unwrap(), 128)));
        assert_eq!(parse_cidr("0.0.0.0/0"), Some(("0.0.0.0".parse().unwrap(), 0)));
        for bad in [
            "10.0.0.0/33",
            "10.0.0.0/",
            "x",
            "10.0.0.0/8 }; flush ruleset",
            "::/1290",
        ] {
            assert_eq!(parse_cidr(bad), None, "{bad}");
        }
        for bad in [
            r#"{"endpoints":[],"inbound":{"web":{"enabled":true,"allow":["10.0.0.0/8 } ; flush ruleset"]}}}"#,
            r#"{"endpoints":[],"inbound":{"web } ; flush ruleset":{"enabled":true,"allow":[]}}}"#,
            r#"{"endpoints":[],"inbound":{"ssh":{"enabled":true,"allow":[]}}}"#,
            r#"{"endpoints":[],"inbound":{"web":{"enabled":true,"allow":[],"x":1}}}"#,
            r#"{"endpoints":[],"mgmt":[]}"#,
        ] {
            assert!(Allowed::parse(bad.as_bytes()).is_err(), "{bad}");
        }
        let many: Vec<String> = (0..=MAX_ALLOW).map(|n| format!("10.0.{n}.0/24")).collect();
        let j = serde_json::json!({"endpoints": [], "inbound": {"web": {"enabled": true, "allow": many}}});
        assert!(Allowed::parse(j.to_string().as_bytes()).is_err(), "too many");
        let a = Allowed::parse(
            br#"{"endpoints":[],"inbound":{"web":{"enabled":true,"allow":["192.0.2.0/24","2001:db8::/32"]},
                "icmp":{"enabled":false,"allow":["192.0.2.0/24"]}}}"#,
        )
        .unwrap();
        let want = desired(None, None, Some(&a));
        // the previous state does not matter: always flushed and refilled
        let s = script(Some(&want), &want);
        assert_eq!(
            s,
            "flush set inet nexus in_icmp_v4\nflush set inet nexus in_icmp_v6\n\
             flush set inet nexus in_web_v4\nadd element inet nexus in_web_v4 { 192.0.2.0/24 }\n\
             flush set inet nexus in_web_v6\nadd element inet nexus in_web_v6 { 2001:db8::/32 }\n"
        );
        // enabled + empty = any; a v4-only list closes v6; disabled = nobody
        let open = script(None, &inbound_state("web", true, &[]));
        assert!(open.contains("in_web_v4 { 0.0.0.0/0 }") && open.contains("in_web_v6 { ::/0 }"));
        let v4 = inbound_state("icmp", true, &[parse_cidr("10.0.0.0/8").unwrap()]);
        assert_eq!(v4["in_icmp_v4"].len(), 1);
        assert!(v4["in_icmp_v6"].is_empty());
        assert!(inbound_state("icmp", false, &[]).values().all(BTreeSet::is_empty));
        // without `inbound` the sets are not touched
        let a = Allowed::parse(br#"{"endpoints":[]}"#).unwrap();
        assert!(!script(None, &desired(None, None, Some(&a))).contains("in_"));
    }

    #[test]
    fn write_only_on_change() {
        let d = std::env::temp_dir().join(format!("nftsync-test-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let p = d.join("allowed.json");
        let e = Endpoint {
            addr: "192.0.2.1".parse().unwrap(),
            proto: Proto::Tcp,
            port: 22,
        };
        assert!(write_allowed(&p, [e, e], None, &BTreeMap::new()).unwrap());
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o644);
        assert!(!write_allowed(&p, [e], None, &BTreeMap::new()).unwrap());
        assert_eq!(Allowed::load(&p).unwrap().endpoints, vec![e]);
        assert!(!write_allowed(&d.join("missing/allowed.json"), [e], None, &BTreeMap::new()).unwrap());
        let rule = |allow: &[&str]| InboundRule {
            enabled: true,
            allow: allow.iter().map(std::string::ToString::to_string).collect(),
        };
        let m = BTreeMap::from([
            ("web".to_owned(), rule(&["10.1.2.3/16", "bad", "10.1.0.0/16"])),
            ("telnet".to_owned(), rule(&[])),
        ]);
        assert!(write_allowed(&p, [e], Some(&m), &BTreeMap::new()).unwrap());
        assert_eq!(
            Allowed::load(&p).unwrap().inbound,
            Some(BTreeMap::from([("web".to_owned(), rule(&["10.1.0.0/16"]))]))
        );
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn role_binding() {
        let ep = |a: &str, port: u16| Endpoint {
            addr: a.parse().unwrap(),
            proto: Proto::Tcp,
            port,
        };
        let a = Allowed::parse(
            br#"{"endpoints":[{"addr":"192.0.2.9","proto":"tcp","port":443}],"roles":{
                "data":{"iface":"bond0.20","endpoints":[{"addr":"10.0.20.7","proto":"tcp","port":8006},
                                                         {"addr":"2001:db8::7","proto":"tcp","port":22}]},
                "offsite":{"endpoints":[{"addr":"198.51.100.40","proto":"tcp","port":23}]}}}"#,
        )
        .unwrap();
        let want = desired(None, None, Some(&a));
        assert_eq!(
            want["bound_out_v4"],
            BTreeSet::from(["10.0.20.7 . tcp . 8006 . \"bond0.20\"".to_owned()])
        );
        assert_eq!(
            want["bound_out_v6"],
            BTreeSet::from(["2001:db8::7 . tcp . 22 . \"bond0.20\"".to_owned()])
        );
        // a role without an interface: any interface, like every other destination
        assert!(want["allowed_out_v4"].contains("198.51.100.40 . tcp . 23"));
        assert!(want["allowed_out_v4"].contains("192.0.2.9 . tcp . 443"));
        assert!(!want["allowed_out_v4"].contains("10.0.20.7 . tcp . 8006"));
        assert_eq!(
            want["probe_v4"],
            BTreeSet::from(["10.0.20.7".to_owned(), "198.51.100.40".to_owned()])
        );
        // without roles the bound sets are emptied (a role lost its interface)
        let s = script(None, &desired(None, None, Some(&Allowed::default())));
        assert!(s.contains("flush set inet nexus bound_out_v4\n") && s.contains("flush set inet nexus probe_v6\n"));
        for bad in [
            r#"{"endpoints":[],"roles":{"mgmt":{"endpoints":[]}}}"#,
            r#"{"endpoints":[],"roles":{"data":{"iface":"eth0\" } ; flush ruleset","endpoints":[]}}}"#,
            r#"{"endpoints":[],"roles":{"data":{"iface":"0123456789abcdef","endpoints":[]}}}"#,
            r#"{"endpoints":[],"roles":{"data":{"endpoints":[{"addr":"127.0.0.1","proto":"tcp","port":1}]}}}"#,
            r#"{"endpoints":[],"roles":{"data":{"endpoints":[],"x":1}}}"#,
        ] {
            assert!(Allowed::parse(bad.as_bytes()).is_err(), "{bad}");
        }
        // writing drops what the reader would refuse
        let d = std::env::temp_dir().join(format!("nftsync-roles-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let p = d.join("allowed.json");
        let roles = BTreeMap::from([
            (
                "data".to_owned(),
                RoleTargets {
                    iface: Some("bond0.20".into()),
                    endpoints: vec![ep("10.0.20.7", 8006), ep("127.0.0.1", 1)],
                },
            ),
            (
                "bogus".to_owned(),
                RoleTargets {
                    iface: None,
                    endpoints: vec![ep("10.0.0.1", 1)],
                },
            ),
            (
                "replication".to_owned(),
                RoleTargets {
                    iface: Some("bad name".into()),
                    endpoints: vec![ep("10.0.0.2", 8443)],
                },
            ),
        ]);
        assert!(write_allowed(&p, [], None, &roles).unwrap());
        let back = Allowed::load(&p).unwrap();
        assert_eq!(back.roles.len(), 1);
        assert_eq!(back.roles["data"].endpoints, vec![ep("10.0.20.7", 8006)]);
        std::fs::remove_dir_all(&d).unwrap();
    }
}
