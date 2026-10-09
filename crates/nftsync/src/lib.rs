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
//! - `nts_servers_v4/v6` from the `server`/`pool` lines with `nts` in
//!   /etc/chrony.conf, resolved after the DNS sets are in place.
//!
//! The root side never interprets anything but IP literals, protocol names and
//! port numbers from the unprivileged file; the nft script is built from parsed
//! values only, so no text from the file reaches nft.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::io::Write as _;
use std::net::{IpAddr, ToSocketAddrs};
use std::path::Path;
use std::process::{Command, Stdio};

pub const ALLOWED_FILE: &str = "/run/nexus-nft/allowed.json";
pub const TABLE: &str = "inet nexus";
/// Upper bound of endpoints accepted from the file.
pub const MAX_ENDPOINTS: usize = 4096;
const MAX_FILE: u64 = 1 << 20;

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "lowercase")]
pub enum Proto {
    Tcp,
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

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(deny_unknown_fields)]
pub struct Endpoint {
    pub addr: IpAddr,
    pub proto: Proto,
    pub port: u16,
}

#[derive(Serialize, Deserialize, Default, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Allowed {
    pub endpoints: Vec<Endpoint>,
}

/// Addresses that never belong into an outbound allow-list.
fn usable(a: &IpAddr) -> bool {
    !(a.is_unspecified() || a.is_multicast() || a.is_loopback() || matches!(a, IpAddr::V4(v) if v.is_broadcast()))
}

impl Allowed {
    pub fn parse(bytes: &[u8]) -> Result<Allowed> {
        let a: Allowed = serde_json::from_slice(bytes).context("allowed.json")?;
        if a.endpoints.len() > MAX_ENDPOINTS {
            bail!("allowed.json: {} endpoints (max {MAX_ENDPOINTS})", a.endpoints.len());
        }
        for e in &a.endpoints {
            if e.port == 0 || !usable(&e.addr) {
                bail!(
                    "allowed.json: refused endpoint {} {} {}",
                    e.addr,
                    e.proto.as_str(),
                    e.port
                );
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
pub fn write_allowed(path: &Path, endpoints: impl IntoIterator<Item = Endpoint>) -> Result<bool> {
    let set: BTreeSet<Endpoint> = endpoints
        .into_iter()
        .filter(|e| usable(&e.addr) && e.port != 0)
        .collect();
    let a = Allowed {
        endpoints: set.into_iter().take(MAX_ENDPOINTS).collect(),
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

/// Host names (or IP literals) of `server`/`pool` lines that use NTS.
pub fn parse_chrony(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for l in text.lines() {
        let l = l.split(['#', '!', ';']).next().unwrap_or_default();
        let w: Vec<&str> = l.split_whitespace().collect();
        if w.len() >= 2 && matches!(w[0], "server" | "pool") && w[2..].contains(&"nts") {
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
        let (v4, v6) = split(
            &a.endpoints,
            |e| e.addr.is_ipv4(),
            |e| format!("{} . {} . {}", e.addr, e.proto.as_str(), e.port),
        );
        st.insert("allowed_out_v4".into(), v4);
        st.insert("allowed_out_v6".into(), v6);
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
        let c = "server time.cloudflare.com iburst nts\npool pool.ntp.org iburst\n# server x nts\nserver ptbtime1.ptb.de nts iburst # c\nserver bad;rm nts\n";
        assert_eq!(parse_chrony(c), vec!["time.cloudflare.com", "ptbtime1.ptb.de"]);
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
        };
        let dns: Vec<IpAddr> = vec!["10.0.2.3".parse().unwrap()];
        let want = desired(Some(&dns), None, Some(&a));
        assert_eq!(
            script(None, &want),
            "flush set inet nexus allowed_out_v4\nadd element inet nexus allowed_out_v4 { 10.0.2.2 . tcp . 10022 }\n\
             flush set inet nexus allowed_out_v6\nadd element inet nexus allowed_out_v6 { 2001:db8::1 . tcp . 23 }\n\
             flush set inet nexus dns_servers_v4\nadd element inet nexus dns_servers_v4 { 10.0.2.3 }\n\
             flush set inet nexus dns_servers_v6\n"
        );
        assert!(!script(None, &want).contains("nts_servers"));
        // incremental: only our own stale elements go, nothing is flushed
        let a2 = Allowed {
            endpoints: vec![a.endpoints[2]],
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
    fn write_only_on_change() {
        let d = std::env::temp_dir().join(format!("nftsync-test-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let p = d.join("allowed.json");
        let e = Endpoint {
            addr: "192.0.2.1".parse().unwrap(),
            proto: Proto::Tcp,
            port: 22,
        };
        assert!(write_allowed(&p, [e, e]).unwrap());
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o644);
        assert!(!write_allowed(&p, [e]).unwrap());
        assert_eq!(Allowed::load(&p).unwrap().endpoints, vec![e]);
        assert!(!write_allowed(&d.join("missing/allowed.json"), [e]).unwrap());
        std::fs::remove_dir_all(&d).unwrap();
    }
}
