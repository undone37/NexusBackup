//! High availability: the source may name several servers (`host` plus `hosts`, e.g.
//! a primary and its streaming replicas, or the members of a Patroni cluster).
//! Backups run against the primary (`pg_is_in_recovery()` = false); after a
//! failover the new primary is on a new timeline, so the next cluster backup is a
//! full one (physical.rs) and re-creates the replication slot there.

use anyhow::Result;

/// `host`/`port` first, then each `hosts` item (`host` or `host:port`, default `port`).
pub fn candidates(cfg: &serde_json::Value) -> Vec<(String, u16)> {
    let port = cfg["port"].as_u64().and_then(|p| u16::try_from(p).ok()).unwrap_or(5432);
    let mut out: Vec<(String, u16)> = Vec::new();
    let first = cfg["host"].as_str().map(|h| h.trim_matches(['[', ']'])).unwrap_or_default();
    if !first.is_empty() {
        out.push((first.to_owned(), port));
    }
    for h in cfg["hosts"].as_array().into_iter().flatten().filter_map(|v| v.as_str()) {
        if let Some(c) = plugin_sdk::proto::split_host_port(h, port) {
            if !out.contains(&c) {
                out.push(c);
            }
        }
    }
    out
}

pub fn show((h, p): &(String, u16)) -> String {
    if h.contains(':') {
        format!("[{h}]:{p}")
    } else {
        format!("{h}:{p}")
    }
}

/// The primary among `cands`: `probe` answers `pg_is_in_recovery()` per server.
/// Ok((index, report)); Err(report) when no server is a reachable primary. Two
/// primaries (split brain, or a failed-over old primary not yet demoted) take the
/// first in the configured order, with a warning in the report.
pub fn pick_primary(
    cands: &[(String, u16)],
    mut probe: impl FnMut(&(String, u16)) -> Result<bool>,
) -> std::result::Result<(usize, String), String> {
    let mut primaries = Vec::new();
    let mut lines = Vec::new();
    for (i, c) in cands.iter().enumerate() {
        match probe(c) {
            Ok(false) => {
                primaries.push(i);
                lines.push(format!("{} primary", show(c)));
            }
            Ok(true) => lines.push(format!("{} standby", show(c))),
            Err(e) => lines.push(format!("{} unreachable ({e:#})", show(c))),
        }
    }
    let report = lines.join(", ");
    match primaries.as_slice() {
        [] => Err(format!("no primary among the configured servers: {report}")),
        [one] => Ok((*one, report)),
        [first, ..] => Ok((
            *first,
            format!(
                "{report}; WARNING: more than one primary, using {} (demote or remove the others)",
                show(&cands[*first])
            ),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::anyhow;
    use serde_json::json;

    #[test]
    fn candidates_from_config() {
        let c = candidates(&json!({"host": "pg1", "port": 6432, "hosts": ["pg2", "pg3:5433", "pg1", "[fd00::5]"]}));
        assert_eq!(
            c,
            [
                ("pg1".to_owned(), 6432),
                ("pg2".into(), 6432),
                ("pg3".into(), 5433),
                ("fd00::5".into(), 6432)
            ]
        );
        assert_eq!(show(&c[3]), "[fd00::5]:6432");
        assert_eq!(candidates(&json!({"host": "db"})), [("db".to_owned(), 5432)]);
    }

    /// A fake cluster: which server answers what.
    type Probe<'a> = Box<dyn FnMut(&(String, u16)) -> Result<bool> + 'a>;

    fn cluster<'a>(state: &'a [(&'a str, Option<bool>)]) -> (Vec<(String, u16)>, Probe<'a>) {
        let cands = state.iter().map(|(h, _)| (h.to_string(), 5432)).collect();
        let probe = move |c: &(String, u16)| -> Result<bool> {
            let (_, s) = state.iter().find(|(h, _)| *h == c.0).unwrap();
            s.ok_or_else(|| anyhow!("connection refused"))
        };
        (cands, Box::new(probe))
    }

    #[test]
    fn primary_selection() {
        // the configured host is a standby: the primary is found further down
        let (c, p) = cluster(&[("pg1", Some(true)), ("pg2", None), ("pg3", Some(false))]);
        let (i, r) = pick_primary(&c, p).unwrap();
        assert_eq!(i, 2);
        assert_eq!(
            r,
            "pg1:5432 standby, pg2:5432 unreachable (connection refused), pg3:5432 primary"
        );
        // after a failover: the old primary is down, the promoted replica answers
        let (c, p) = cluster(&[("pg1", None), ("pg2", Some(false))]);
        assert_eq!(pick_primary(&c, p).unwrap().0, 1);
        // no primary
        let (c, p) = cluster(&[("pg1", Some(true)), ("pg2", None)]);
        assert!(pick_primary(&c, p).unwrap_err().starts_with("no primary"));
        // two primaries: the first wins, with a warning
        let (c, p) = cluster(&[("pg1", Some(false)), ("pg2", Some(false))]);
        let (i, r) = pick_primary(&c, p).unwrap();
        assert_eq!(i, 0);
        assert!(r.contains("more than one primary, using pg1:5432"), "{r}");
    }
}
