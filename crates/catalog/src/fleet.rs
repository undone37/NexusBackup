//! Fleet enrollment (docs/agent-protocol.md "Fleet enrollment", manual 04): an admin
//! creates a reusable, time-limited fleet secret (`nxf1.<id>.<secret>`, shown once;
//! `fleets.secret_hash` = its token digest sealed to the scheduler at
//! [`secret_location`]); agents pre-installed with it wait for the appliance's scan
//! of the fleet's address ranges (`fleet_scan` jobs, scheduler `fleet.rs`) and are
//! listed as candidates; accepting one ([`accept`], by an admin or automatically)
//! creates the agent, gives it a source and group copied from a template group and
//! queues the normal `agent_enroll` job with the fleet secret instead of a token.

use anyhow::{bail, Context, Result};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::net::IpAddr;

/// Longest validity of a fleet secret.
pub const MAX_DAYS: i64 = 30;
/// Range entries per fleet and addresses they may expand to.
pub const MAX_RANGES: usize = 32;
pub const MAX_ADDRESSES: usize = 4096;
/// Scan interval per fleet.
pub const SCAN_SECS: i64 = 15 * 60;

/// Where the fleet secret's digest is sealed (`fleets.secret_hash`).
pub fn secret_location(id: &str) -> String {
    format!("fleet/{id}")
}

/// Hostname pattern → template group (first match wins).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub pattern: String,
    pub group: String,
}

#[derive(Debug, Clone)]
pub struct Fleet {
    pub id: String,
    pub tenant: String,
    pub name: String,
    pub secret_hash: String,
    pub expires: i64,
    pub max_uses: Option<i64>,
    pub uses: i64,
    pub revoked: bool,
    pub auto_accept: bool,
    pub port: u16,
    pub ranges: Vec<String>,
    pub group: Option<String>,
    pub rules: Vec<Rule>,
    pub last_scan: Option<i64>,
}

pub const COLS: &str = "id, tenant, name, secret_hash, expires, max_uses, uses, revoked, auto_accept, port, ranges, \
                        default_group, group_rules, last_scan, created, created_by";

pub fn row(r: &rusqlite::Row) -> rusqlite::Result<Fleet> {
    Ok(Fleet {
        id: r.get(0)?,
        tenant: r.get(1)?,
        name: r.get(2)?,
        secret_hash: r.get(3)?,
        expires: r.get(4)?,
        max_uses: r.get(5)?,
        uses: r.get(6)?,
        revoked: r.get(7)?,
        auto_accept: r.get(8)?,
        port: r.get(9)?,
        ranges: serde_json::from_str(&r.get::<_, String>(10)?).unwrap_or_default(),
        group: r.get(11)?,
        rules: serde_json::from_str(&r.get::<_, String>(12)?).unwrap_or_default(),
        last_scan: r.get(13)?,
    })
}

pub fn load(c: &Connection, id: &str) -> Result<Option<Fleet>> {
    Ok(
        c.query_row(&format!("SELECT {COLS} FROM fleets WHERE id = ?1"), [id], row)
            .optional()?,
    )
}

impl Fleet {
    /// Why the secret cannot be used at all now (revoked, expired). Agents already
    /// accepted may still enroll with it otherwise.
    pub fn invalid(&self, now: i64) -> Option<&'static str> {
        if self.revoked {
            Some("the fleet secret was revoked")
        } else if self.expires <= now {
            Some("the fleet secret expired")
        } else {
            None
        }
    }

    /// Why no further agent can be accepted (None = it can): invalid or used up.
    pub fn unusable(&self, now: i64) -> Option<&'static str> {
        self.invalid(now).or_else(|| {
            self.max_uses
                .is_some_and(|m| self.uses >= m)
                .then_some("the fleet secret reached its maximum number of uses")
        })
    }

    /// Template group for a hostname: the first matching rule, else the default.
    pub fn group_for(&self, hostname: &str) -> Option<&str> {
        self.rules
            .iter()
            .find(|r| glob(&r.pattern, hostname))
            .map(|r| r.group.as_str())
            .or(self.group.as_deref())
    }
}

/// `*` / `?` glob, ASCII case-insensitive (hostname patterns).
pub fn glob(pattern: &str, name: &str) -> bool {
    let (p, n): (Vec<char>, Vec<char>) = (
        pattern.to_ascii_lowercase().chars().collect(),
        name.to_ascii_lowercase().chars().collect(),
    );
    // iterative matcher with backtracking to the last `*`
    let (mut i, mut j, mut star, mut mark) = (0, 0, None, 0);
    while j < n.len() {
        if i < p.len() && (p[i] == '?' || p[i] == n[j]) {
            i += 1;
            j += 1;
        } else if i < p.len() && p[i] == '*' {
            star = Some(i);
            mark = j;
            i += 1;
        } else if let Some(s) = star {
            i = s + 1;
            mark += 1;
            j = mark;
        } else {
            return false;
        }
    }
    p[i..].iter().all(|c| *c == '*')
}

/// Range entries → addresses / host names to probe: IPv4 CIDR /22../32 (without
/// network and broadcast address up to /30), IPv6 /118../128, single addresses and
/// host names. At most [`MAX_RANGES`] entries and [`MAX_ADDRESSES`] addresses.
pub fn expand(ranges: &[String]) -> Result<Vec<String>, String> {
    if ranges.len() > MAX_RANGES {
        return Err(format!("ranges: at most {MAX_RANGES} entries"));
    }
    let mut out: Vec<String> = Vec::new();
    for r in ranges {
        let r = r.trim();
        let bad = || {
            format!("ranges: {r:?} is no address, CIDR range (IPv4 /22 or smaller, IPv6 /118 or smaller) or host name")
        };
        if let Some((a, p)) = r.split_once('/') {
            let ip: IpAddr = a.parse().map_err(|_| bad())?;
            let p: u32 = p.parse().map_err(|_| bad())?;
            match ip {
                IpAddr::V4(v4) if (22..=32).contains(&p) => {
                    let base = u32::from(v4) & (u32::MAX << (32 - p));
                    let n = 1u32 << (32 - p);
                    let (first, last) = if p <= 30 { (1, n - 1) } else { (0, n) };
                    out.extend((first..last).map(|i| std::net::Ipv4Addr::from(base + i).to_string()));
                }
                IpAddr::V6(v6) if (118..=128).contains(&p) => {
                    let base = u128::from(v6) & (u128::MAX << (128 - p));
                    out.extend((0..1u128 << (128 - p)).map(|i| std::net::Ipv6Addr::from(base + i).to_string()));
                }
                _ => return Err(bad()),
            }
        } else if let Ok(ip) = r.parse::<IpAddr>() {
            out.push(ip.to_string());
        } else if (1..=253).contains(&r.len())
            && !r.starts_with(['-', '.'])
            && r.bytes().all(|b| b.is_ascii_alphanumeric() || b".-".contains(&b))
        {
            out.push(r.to_ascii_lowercase());
        } else {
            return Err(bad());
        }
        if out.len() > MAX_ADDRESSES {
            return Err(format!("ranges: more than {MAX_ADDRESSES} addresses in one fleet"));
        }
    }
    out.sort();
    out.dedup();
    Ok(out)
}

/// A name for the agent from its (untrusted) hostname: `[A-Za-z0-9._-]{1,64}`,
/// made unique in the tenant (agents, sources and groups share it).
fn agent_name(c: &Connection, tenant: &str, hostname: &str, host: &str, id: &str) -> Result<String> {
    let clean = |s: &str| -> String {
        s.chars()
            .filter(|c| c.is_ascii_alphanumeric() || "._-".contains(*c))
            .take(56)
            .collect::<String>()
            .trim_start_matches('.')
            .to_owned()
    };
    let mut name = clean(hostname.split('.').next().unwrap_or_default());
    if name.is_empty() {
        name = clean(&host.replace(':', "-"));
    }
    let taken = |n: &str| -> Result<bool> {
        Ok(c.query_row(
            "SELECT EXISTS (SELECT 1 FROM agents WHERE tenant = ?1 AND name = ?2)
                OR EXISTS (SELECT 1 FROM sources WHERE tenant = ?1 AND name = ?2)
                OR EXISTS (SELECT 1 FROM groups WHERE tenant = ?1 AND name = ?2)",
            params![tenant, n],
            |r| r.get(0),
        )?)
    };
    if taken(&name)? {
        name = format!("{name}-{}", &id[..6]);
    }
    if taken(&name)? {
        bail!("agent name {name} is taken in tenant {tenant}");
    }
    Ok(name)
}

/// Gives a new agent its own linux source and protection group, copied from the
/// template `group` (a group of a linux source in the same tenant): the source's
/// paths and filters, every group setting (policy, schedule fields, timezone, …).
/// Returns the new group's id, `None` if there is no such template.
pub fn assign_group(c: &Connection, tenant: &str, agent_id: &str, name: &str, group: &str) -> Result<Option<i64>> {
    let Some((gid, src_config)) = c
        .query_row(
            "SELECT g.id, s.config FROM groups g JOIN sources s ON s.id = g.source_id
             WHERE g.tenant = ?1 AND g.name = ?2 AND s.kind = 'linux'",
            params![tenant, group],
            |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)),
        )
        .optional()?
    else {
        return Ok(None);
    };
    let mut cfg: Value = serde_json::from_str(&src_config)?;
    cfg["agent_id"] = json!(agent_id);
    c.execute(
        "INSERT INTO sources (tenant, kind, name, config) VALUES (?1, 'linux', ?2, ?3)",
        params![tenant, name, cfg.to_string()],
    )?;
    let sid = c.last_insert_rowid();
    // every other column as the template has it (future columns included)
    let cols: Vec<String> = c
        .prepare("SELECT name FROM pragma_table_info('groups')")?
        .query_map([], |r| r.get(0))?
        .collect::<rusqlite::Result<_>>()?;
    let copied: Vec<&String> = cols
        .iter()
        .filter(|n| !["id", "source_id", "name", "guests", "paused_until"].contains(&n.as_str()))
        .collect();
    let list = copied.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ");
    c.execute(
        &format!(
            "INSERT INTO groups (source_id, name, guests, {list}) SELECT ?1, ?2, ?3, {list} FROM groups WHERE id = ?4"
        ),
        params![sid, name, json!([agent_id]).to_string(), gid],
    )?;
    Ok(Some(c.last_insert_rowid()))
}

/// What [`accept`] created.
#[derive(Debug, Serialize)]
pub struct Accepted {
    pub agent_id: String,
    pub name: String,
    pub tenant: String,
    pub group: Option<String>,
    pub group_id: Option<i64>,
    pub job: i64,
}

/// Accepts an awaiting candidate (one transaction): the agent (endpoint = the
/// scanned address and port), its source + group from the template group of its
/// hostname, an `agent_enroll` job with the fleet id, one use of the fleet.
/// The caller audits.
pub fn accept(c: &mut Connection, candidate: i64, actor: &str, now: i64) -> Result<Accepted> {
    let tx = c.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    let (fleet_id, host, port, hostname, state): (String, String, u16, String, String) = tx
        .query_row(
            "SELECT fleet_id, host, port, hostname, state FROM fleet_candidates WHERE id = ?1",
            [candidate],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        )
        .optional()?
        .context("no such candidate")?;
    if state != "awaiting" {
        bail!("the candidate was already {state}");
    }
    // vault mode: no new agents (the web-api refuses them too; this covers auto-accept)
    if crate::vault::enabled(&tx)? {
        bail!("vault mode is on: no new agents on this appliance");
    }
    let f = load(&tx, &fleet_id)?.context("fleet gone")?;
    if let Some(why) = f.unusable(now) {
        bail!("{why}");
    }
    let id: String = tx.query_row("SELECT lower(hex(randomblob(8)))", [], |r| r.get(0))?;
    let name = agent_name(&tx, &f.tenant, &hostname, &host, &id)?;
    tx.execute(
        "INSERT INTO agents (id, tenant, name, host, port, fleet_id) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![id, f.tenant, name, host, port, f.id],
    )?;
    let group = f.group_for(&hostname).map(str::to_owned);
    let group_id = match &group {
        Some(g) => assign_group(&tx, &f.tenant, &id, &name, g)?,
        None => None,
    };
    tx.execute(
        "INSERT INTO jobs (kind, tenant, params, state, requested_by, created) VALUES ('agent_enroll', ?1, ?2, 'queued', ?3, ?4)",
        params![f.tenant, json!({"agent_id": id, "fleet_id": f.id}).to_string(), actor, now],
    )?;
    let job = tx.last_insert_rowid();
    tx.execute(
        "UPDATE fleet_candidates SET state = 'accepted', agent_id = ?2, decided_by = ?3 WHERE id = ?1",
        params![candidate, id, actor],
    )?;
    tx.execute("UPDATE fleets SET uses = uses + 1 WHERE id = ?1", [&f.id])?;
    tx.commit()?;
    Ok(Accepted {
        agent_id: id,
        name,
        tenant: f.tenant,
        group: group.filter(|_| group_id.is_some()),
        group_id,
        job,
    })
}

/// Records one agent found by a scan (`fleet-agent {json}`). Returns the
/// candidate id if it is new or still awaiting acceptance. A known endpoint keeps
/// its decision (a rejected agent stays rejected); host info is refreshed.
pub fn record(c: &Connection, fleet_id: &str, v: &Value, now: i64) -> Result<Option<i64>> {
    let s = |k: &str| v[k].as_str().unwrap_or_default().chars().take(128).collect::<String>();
    let (host, port) = (s("host"), v["port"].as_u64().and_then(|p| u16::try_from(p).ok()));
    let Some(port) = port.filter(|_| !host.is_empty()) else {
        return Ok(None);
    };
    c.execute(
        "INSERT INTO fleet_candidates (fleet_id, host, port, hostname, os, version, first_seen, last_seen)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7)
         ON CONFLICT (fleet_id, host, port) DO UPDATE SET hostname = ?4, os = ?5, version = ?6, last_seen = ?7",
        params![fleet_id, host, port, s("hostname"), s("os"), s("version"), now],
    )?;
    Ok(c.query_row(
        "SELECT id FROM fleet_candidates WHERE fleet_id = ?1 AND host = ?2 AND port = ?3 AND state = 'awaiting'",
        params![fleet_id, host, port],
        |r| r.get(0),
    )
    .optional()?)
}

/// Before a tenant is deleted: its fleets and their candidates go too.
pub fn forget_tenant(c: &Connection, tenant: &str) -> Result<()> {
    c.execute(
        "DELETE FROM fleet_candidates WHERE fleet_id IN (SELECT id FROM fleets WHERE tenant = ?1)",
        [tenant],
    )?;
    c.execute("DELETE FROM fleets WHERE tenant = ?1", [tenant])?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn globs() {
        assert!(glob("web-*", "WEB-01"));
        assert!(glob("*db?", "pgdb1"));
        assert!(glob("*", ""));
        assert!(glob("a*b*c", "axxbyyc"));
        assert!(!glob("a*b*c", "axxbyy"));
        assert!(!glob("web-?", "web-10"));
    }

    #[test]
    fn ranges_expand_with_limits() {
        let v = |s: &[&str]| s.iter().map(std::string::ToString::to_string).collect::<Vec<_>>();
        let a = expand(&v(&["10.0.0.0/30", "10.0.0.2", "Host-1.example", "2001:db8::/127"])).unwrap();
        assert_eq!(
            a,
            vec!["10.0.0.1", "10.0.0.2", "2001:db8::", "2001:db8::1", "host-1.example"]
        );
        assert_eq!(expand(&v(&["192.168.0.0/22"])).unwrap().len(), 1022);
        assert_eq!(expand(&v(&["192.168.0.7/32"])).unwrap(), vec!["192.168.0.7"]);
        assert!(expand(&v(&["192.168.0.0/21"])).is_err());
        assert!(expand(&v(&["2001:db8::/117"])).is_err());
        assert!(expand(&v(&["10.0.0.0/22"; 5])).is_err(), "more than 4096 addresses");
        assert!(expand(&v(&["-x"])).is_err());
        assert!(expand(&v(&["a b"])).is_err());
        assert!(expand(&v(&["h"; 33])).is_err());
    }

    #[test]
    fn group_rules_first_match_then_default() {
        let f = Fleet {
            id: "0".repeat(16),
            tenant: "t".into(),
            name: "n".into(),
            secret_hash: String::new(),
            expires: 100,
            max_uses: Some(2),
            uses: 1,
            revoked: false,
            auto_accept: false,
            port: 7444,
            ranges: vec![],
            group: Some("default".into()),
            rules: vec![
                Rule {
                    pattern: "db-*".into(),
                    group: "databases".into(),
                },
                Rule {
                    pattern: "*".into(),
                    group: "all".into(),
                },
            ],
            last_scan: None,
        };
        assert_eq!(f.group_for("DB-1"), Some("databases"));
        assert_eq!(f.group_for("web"), Some("all"));
        assert_eq!(f.unusable(50), None);
        assert!(f.unusable(100).is_some());
        assert!(Fleet { uses: 2, ..f.clone() }.unusable(50).is_some());
        assert!(Fleet {
            revoked: true,
            ..f.clone()
        }
        .unusable(50)
        .is_some());
        assert_eq!(Fleet { rules: vec![], ..f }.group_for("web"), Some("default"));
    }
}
