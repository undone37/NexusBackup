//! The effective firewall state for the web UI (Phase 16c): `nexus-nft-sync
//! --status` (a timer, every minute) and every sync list `table inet nexus`
//! (`nft -j`) and write [`STATUS_FILE`] (0644, read by the web-api):
//!
//! - the elements of the sets this tool manages (inbound `in_*`, outbound
//!   `allowed_out_*`, `bound_out_*` and `probe_*` (Phase 22a), `dns_servers_*`, `nts_servers_*`),
//! - the recent blocked inbound attempts from the dynamic sets
//!   `in_drops_v4/v6` (source . protocol . port; each packet refreshes the
//!   element's 24 h timeout, so `timeout - expires` is the time since the last
//!   one), newest first.
//!
//! The web-api never talks to nft or reads the journal; this file is all it sees.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::io::Write as _;
use std::path::Path;
use std::process::{Command, Stdio};

pub const STATUS_FILE: &str = "/run/nexus-nft-status/status.json";
/// Most blocked attempts reported (the sets hold at most 256 each).
pub const MAX_DROPS: usize = 200;

#[derive(Serialize, Deserialize, Default, Debug, PartialEq)]
pub struct Status {
    /// when it was taken (unix seconds)
    pub ts: i64,
    /// set name → elements as nft prints them (`10.0.0.0/8`, `192.0.2.1 . tcp . 22`)
    pub sets: BTreeMap<String, Vec<String>>,
    pub drops: Vec<Drop>,
}

/// A blocked inbound attempt (per source, protocol and port).
#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct Drop {
    pub src: String,
    pub proto: String,
    pub port: u16,
    /// approximate (from the element's remaining timeout)
    pub last_seen: i64,
    pub packets: u64,
}

fn managed(set: &str) -> bool {
    (set.starts_with("in_") && !set.starts_with("in_drops_"))
        || ["allowed_out_", "bound_out_", "probe_", "dns_servers_", "nts_servers_"]
            .iter()
            .any(|p| set.starts_with(p))
}

/// One element as text; `None` for shapes this tool does not produce.
fn elem_text(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Object(o) => {
            if let Some(p) = o.get("prefix") {
                return Some(format!("{}/{}", p["addr"].as_str()?, p["len"].as_u64()?));
            }
            if let Some(r) = o.get("range") {
                return Some(format!("{}-{}", elem_text(&r[0])?, elem_text(&r[1])?));
            }
            if let Some(c) = o.get("concat") {
                let parts: Option<Vec<String>> = c.as_array()?.iter().map(elem_text).collect();
                return Some(parts?.join(" . "));
            }
            o.get("elem").and_then(|e| elem_text(&e["val"]))
        }
        _ => None,
    }
}

fn proto_name(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(
            match n.as_u64()? {
                6 => "tcp",
                17 => "udp",
                _ => return Some(n.to_string()),
            }
            .into(),
        ),
        _ => None,
    }
}

/// `set_timeout`: the set's; nft prints an element's own only when it differs.
fn drop_of(e: &Value, set_timeout: i64, now: i64) -> Option<Drop> {
    let e = e.get("elem")?;
    let c = e["val"]["concat"].as_array()?;
    let timeout = e["timeout"].as_i64().unwrap_or(set_timeout);
    let expires = e["expires"].as_i64().unwrap_or(timeout);
    Some(Drop {
        src: c.first()?.as_str()?.to_owned(),
        proto: proto_name(c.get(1)?)?,
        port: u16::try_from(c.get(2)?.as_u64()?).ok()?,
        last_seen: now - (timeout - expires).max(0),
        packets: e["counter"]["packets"].as_u64().unwrap_or(0),
    })
}

/// The status from `nft -j list table inet nexus` output.
pub fn parse(v: &Value, now: i64) -> Status {
    let mut st = Status {
        ts: now,
        ..Default::default()
    };
    for item in v["nftables"].as_array().into_iter().flatten() {
        let Some(set) = item.get("set") else { continue };
        let Some(name) = set["name"].as_str() else { continue };
        let elems = set["elem"].as_array().map(Vec::as_slice).unwrap_or_default();
        if name.starts_with("in_drops_") {
            let timeout = set["timeout"].as_i64().unwrap_or(0);
            st.drops.extend(elems.iter().filter_map(|e| drop_of(e, timeout, now)));
        } else if managed(name) {
            st.sets
                .insert(name.to_owned(), elems.iter().filter_map(elem_text).collect());
        }
    }
    st.drops
        .sort_by(|a, b| b.last_seen.cmp(&a.last_seen).then_with(|| a.src.cmp(&b.src)));
    st.drops.truncate(MAX_DROPS);
    st
}

/// `nft -j list table inet nexus`.
pub fn query(nft: &Path) -> Result<Value> {
    let out = Command::new(nft)
        .args(["-j", "list", "table", "inet", "nexus"])
        .stdin(Stdio::null())
        .stderr(Stdio::inherit())
        .output()
        .with_context(|| format!("spawn {}", nft.display()))?;
    if !out.status.success() {
        bail!("nft -j list table failed ({})", out.status);
    }
    serde_json::from_slice(&out.stdout).context("nft -j output")
}

/// Writes the status atomically, world-readable (the web-api reads it; the
/// unit's umask is 0077). A missing directory (development) writes nothing.
pub fn write(path: &Path, st: &Status) -> Result<()> {
    let Some(dir) = path.parent().filter(|d| d.is_dir()) else {
        return Ok(());
    };
    let tmp = dir.join(".status.json.tmp");
    let _ = std::fs::remove_file(&tmp);
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o644)
            .open(&tmp)?;
        f.write_all(&serde_json::to_vec(st)?)?;
        f.set_permissions(std::fs::Permissions::from_mode(0o644))?;
    }
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// Lists the table and writes the status file.
pub fn refresh(nft: &Path, path: &Path) -> Result<()> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64);
    write(path, &parse(&query(nft)?, now))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_nft_json() {
        let v = json!({"nftables": [
            {"metainfo": {"version": "1.1.5"}},
            {"table": {"family": "inet", "name": "nexus"}},
            {"set": {"name": "in_web_v4", "elem": [{"prefix": {"addr": "10.0.0.0", "len": 8}}, "192.0.2.7",
                {"range": ["10.1.0.1", "10.1.0.9"]}]}},
            {"set": {"name": "in_web_v6", "elem": [{"prefix": {"addr": "::", "len": 0}}]}},
            {"set": {"name": "in_icmp_v4"}},
            {"set": {"name": "allowed_out_v4", "elem": [{"concat": ["10.0.2.2", "tcp", 10022]}]}},
            {"set": {"name": "something_else", "elem": ["1.2.3.4"]}},
            {"set": {"name": "in_drops_v4", "timeout": 86400, "elem": [
                {"elem": {"val": {"concat": ["192.0.2.1", "tcp", 22]}, "expires": 86000,
                          "counter": {"packets": 3, "bytes": 180}}},
                {"elem": {"val": {"concat": ["192.0.2.9", 17, 161]}, "timeout": 86400, "expires": 86390}}]}},
            {"set": {"name": "in_drops_v6", "elem": [
                {"elem": {"val": {"concat": ["2001:db8::1", "tcp", 3389]}, "timeout": 86400, "expires": 1}}]}},
            {"chain": {"name": "input"}}
        ]});
        let s = parse(&v, 100_000);
        assert_eq!(s.sets["in_web_v4"], ["10.0.0.0/8", "192.0.2.7", "10.1.0.1-10.1.0.9"]);
        assert_eq!(s.sets["in_web_v6"], ["::/0"]);
        assert!(s.sets["in_icmp_v4"].is_empty());
        assert_eq!(s.sets["allowed_out_v4"], ["10.0.2.2 . tcp . 10022"]);
        assert!(!s.sets.contains_key("something_else") && !s.sets.contains_key("in_drops_v4"));
        assert_eq!(
            s.drops,
            [
                Drop {
                    src: "192.0.2.9".into(),
                    proto: "udp".into(),
                    port: 161,
                    last_seen: 99_990,
                    packets: 0
                },
                Drop {
                    src: "192.0.2.1".into(),
                    proto: "tcp".into(),
                    port: 22,
                    last_seen: 99_600,
                    packets: 3
                },
                Drop {
                    src: "2001:db8::1".into(),
                    proto: "tcp".into(),
                    port: 3389,
                    last_seen: 100_000 - 86_399,
                    packets: 0
                },
            ]
        );
    }

    #[test]
    fn writes_world_readable() {
        let d = std::env::temp_dir().join(format!("nftsync-status-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let p = d.join("status.json");
        let st = Status {
            ts: 5,
            ..Default::default()
        };
        write(&p, &st).unwrap();
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o644);
        let back: Status = serde_json::from_slice(&std::fs::read(&p).unwrap()).unwrap();
        assert_eq!(back, st);
        write(&d.join("missing/status.json"), &st).unwrap();
        std::fs::remove_dir_all(&d).unwrap();
    }
}
