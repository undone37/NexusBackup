//! Storage accounting (Phase 13d/e, docs/storage-accounting.md): per tenant and
//! per group logical, data in, stored, ratios and growth (`GET /storage`, the
//! dashboard's capacity tile, the `storage` report).
//!
//! Figures come from `backup_stats` rows (the connectors' `nexus-stats` lines)
//! of snapshots that are still kept locally:
//! - Logical = sum of the snapshots' sizes (a full copy of each),
//! - Data in = plain bytes of the chunks each snapshot added to the store,
//! - Stored = their sealed size on disk, Saved = Logical − Stored;
//! - dedup = Logical / Data in, compression = Data in / Stored,
//!   reduction = Logical / Stored.
//!
//! Approximation: a chunk counts for the snapshot that wrote it first. Once
//! that snapshot is gone its bytes drop out although later snapshots may still
//! use them, so Stored is a lower bound and the ratios lean high; the store's
//! measured size (`used`, daily capacity sample) stays the authority.

use crate::rusqlite::{self, params, Connection};
use crate::{day, Cell, Kind, Table, DAY};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

/// Summed `backup_stats` of a set of snapshots.
#[derive(Default, Clone, Copy)]
struct Sum {
    snapshots: i64,
    logical: i64,
    data_in: i64,
    stored: i64,
}

impl Sum {
    fn add(&mut self, logical: i64, plain: i64, stored: i64) {
        self.snapshots += 1;
        self.logical += logical;
        self.data_in += plain;
        self.stored += stored;
    }

    fn json(&self) -> Value {
        let ratio = |a: i64, b: i64| (b > 0).then(|| a as f64 / b as f64);
        json!({
            "snapshots": self.snapshots, "logical": self.logical, "data_in": self.data_in,
            "stored": self.stored, "saved": (self.logical - self.stored).max(0),
            "dedup": ratio(self.logical, self.data_in), "compression": ratio(self.data_in, self.stored),
            "reduction": ratio(self.logical, self.stored),
        })
    }
}

/// (tenant, source, logical, new_plain, new_stored)
type Row = (String, String, i64, i64, i64);

/// `backup_stats` of locally kept snapshots.
fn rows(c: &Connection, scope: Option<&str>) -> rusqlite::Result<Vec<Row>> {
    c.prepare(
        "SELECT b.tenant, b.source, b.logical, b.new_plain, b.new_stored FROM backup_stats b
         JOIN snapshots s ON s.tenant = b.tenant AND s.source = b.source AND s.time = b.time AND s.local = 1
         WHERE ?1 IS NULL OR b.tenant = ?1",
    )?
    .query_map([scope], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)))?
    .collect()
}

/// (dedup, compression) over the scope, for the dashboard's capacity tile.
pub fn ratios(c: &Connection, scope: Option<&str>) -> rusqlite::Result<(Option<f64>, Option<f64>)> {
    let mut s = Sum::default();
    for (_, _, l, p, st) in rows(c, scope)? {
        s.add(l, p, st);
    }
    let v = s.json();
    Ok((v["dedup"].as_f64(), v["compression"].as_f64()))
}

/// Whether snapshot `source` belongs to a group of source `sid` / `kind` with `guests`
/// (the scheduler's `group_sources` / `group_prefixes`, empty lists = whole source).
fn in_group(kind: &str, sid: u64, guests: &[Value], source: &str) -> bool {
    let strs: Vec<&str> = guests.iter().filter_map(Value::as_str).collect();
    match kind {
        "pve" => guests
            .iter()
            .filter_map(Value::as_u64)
            .any(|v| source == format!("vm-{v}") || source == format!("ct-{v}")),
        "truenas" => truenas::parse_source_name(source).is_some_and(|(id, ds)| {
            id == sid && (strs.is_empty() || strs.iter().any(|d| ds == *d || ds.starts_with(&format!("{d}/"))))
        }),
        "nfs" | "smb" => nas::parse_source_name(source) == Some(sid),
        k if k.starts_with("plugin:") => plugin_proto::parse_source_name(source)
            .is_some_and(|(_, id, g)| id == sid && (strs.is_empty() || g.is_some_and(|g| strs.contains(&g.as_str())))),
        // agent sources: guests are agent ids
        _ => strs.iter().any(|a| source == format!("host-{a}")),
    }
}

/// Used bytes `days` ago vs. the latest sample (per tenant, or summed with `None`).
fn growth(c: &Connection, tenant: Option<&str>, scope: Option<&str>, now: i64) -> rusqlite::Result<Value> {
    let samples: Vec<(String, i64)> = c
        .prepare(
            "SELECT day, SUM(used) FROM capacity_samples WHERE (?1 IS NULL OR tenant = ?1) AND (?2 IS NULL OR tenant = ?2)
             AND day > ?3 GROUP BY day ORDER BY day",
        )?
        .query_map(params![tenant, scope, day(now - 120 * DAY)], |r| Ok((r.get(0)?, r.get(1)?)))?
        .collect::<Result<_, _>>()?;
    let Some((_, last)) = samples.last() else {
        return Ok(json!({"d7": null, "d30": null, "d90": null}));
    };
    let ago = |d: i64| {
        let cut = day(now - d * DAY);
        samples.iter().rev().find(|(day, _)| *day <= cut).map(|(_, u)| last - u)
    };
    Ok(json!({"d7": ago(7), "d30": ago(30), "d90": ago(90)}))
}

/// The `GET /storage` body.
#[allow(clippy::type_complexity)]
pub fn compute(c: &Connection, scope: Option<&str>, now: i64) -> rusqlite::Result<Value> {
    let tenants: Vec<(String, Option<i64>, Option<i64>)> = c
        .prepare(
            "SELECT t.name, t.quota_bytes, (SELECT used FROM capacity_samples s WHERE s.tenant = t.name
               ORDER BY day DESC LIMIT 1) FROM tenants t WHERE ?1 IS NULL OR t.name = ?1 ORDER BY t.name",
        )?
        .query_map([scope], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
        .collect::<Result<_, _>>()?;
    let groups: Vec<(i64, String, String, String, u64, Vec<Value>)> = c
        .prepare(
            "SELECT g.id, g.tenant, g.name, s.kind, g.source_id, g.guests FROM groups g
             JOIN sources s ON s.id = g.source_id WHERE ?1 IS NULL OR g.tenant = ?1 ORDER BY g.id",
        )?
        .query_map([scope], |r| {
            let guests: String = r.get(5)?;
            Ok((
                r.get(0)?,
                r.get(1)?,
                r.get(2)?,
                r.get(3)?,
                r.get::<_, i64>(4)? as u64,
                serde_json::from_str(&guests).unwrap_or_default(),
            ))
        })?
        .collect::<Result<_, _>>()?;
    let mut total = Sum::default();
    let mut per_tenant: BTreeMap<String, Sum> = BTreeMap::new();
    // (tenant, group id or None = ungrouped) → (sum, sources)
    let mut per_group: BTreeMap<(String, Option<i64>), (Sum, BTreeSet<String>)> = BTreeMap::new();
    for (tenant, source, l, p, st) in rows(c, scope)? {
        total.add(l, p, st);
        per_tenant.entry(tenant.clone()).or_default().add(l, p, st);
        // a source in several groups counts for the first one (lowest id)
        let g = groups
            .iter()
            .find(|g| g.1 == tenant && in_group(&g.3, g.4, &g.5, &source))
            .map(|g| g.0);
        let e = per_group.entry((tenant, g)).or_default();
        e.0.add(l, p, st);
        e.1.insert(source);
    }
    let names: BTreeMap<i64, &str> = groups.iter().map(|g| (g.0, g.2.as_str())).collect();
    let covered: i64 = c.query_row(
        "SELECT COUNT(*) FROM snapshots WHERE local = 1 AND (?1 IS NULL OR tenant = ?1)",
        [scope],
        |r| r.get(0),
    )?;
    let mut tenant_rows = Vec::new();
    for (t, quota, used) in &tenants {
        let mut v = per_tenant.get(t).copied().unwrap_or_default().json();
        v["tenant"] = json!(t);
        v["quota_bytes"] = json!(quota);
        v["used"] = json!(used);
        v["quota_used"] = json!(quota.filter(|q| *q > 0).map(|q| used.unwrap_or(0) as f64 / q as f64));
        v["growth"] = growth(c, Some(t), scope, now)?;
        tenant_rows.push(v);
    }
    let group_rows: Vec<Value> = per_group
        .into_iter()
        .map(|((t, g), (s, sources))| {
            let mut v = s.json();
            v["tenant"] = json!(t);
            v["group_id"] = json!(g);
            v["group"] = json!(g.and_then(|g| names.get(&g).copied()));
            v["sources"] = json!(sources.len());
            v
        })
        .collect();
    let per_day: Vec<Value> = c
        .prepare(
            "SELECT day, SUM(used), SUM(logical) FROM capacity_samples WHERE day > ?1 AND (?2 IS NULL OR tenant = ?2)
             GROUP BY day ORDER BY day",
        )?
        .query_map(params![day(now - 90 * DAY), scope], |r| {
            Ok(json!({"day": r.get::<_, String>(0)?, "used": r.get::<_, i64>(1)?, "logical": r.get::<_, i64>(2)?}))
        })?
        .collect::<Result<_, _>>()?;
    let mut totals = total.json();
    totals["snapshots_all"] = json!(covered);
    totals["used"] = json!(tenants.iter().filter_map(|t| t.2).sum::<i64>());
    totals["growth"] = growth(c, None, scope, now)?;
    Ok(json!({
        "generated": now, "totals": totals, "tenants": tenant_rows, "groups": group_rows, "per_day": per_day,
    }))
}

/// Inputs of the restore point simulator's size estimate (Phase 23a, web-api
/// `simulate.rs`), from the measured `backup_stats` of the sources the scope
/// covers (the groups of `policy_id`, else every source of the tenant scope):
/// `full` = a compressed full copy of each source (latest logical size ÷ the
/// measured compression), `delta` = one run's new stored data (per source the
/// median `new_stored` of its last 30 backups, the first backup excluded).
pub fn estimate(c: &Connection, policy_id: Option<i64>, scope: Option<&str>) -> rusqlite::Result<Option<Value>> {
    let groups: Vec<(String, String, u64, Vec<Value>)> = c
        .prepare(
            "SELECT g.tenant, s.kind, g.source_id, g.guests FROM groups g JOIN sources s ON s.id = g.source_id
             WHERE g.policy_id = ?1 AND (?2 IS NULL OR g.tenant = ?2)",
        )?
        .query_map(params![policy_id, scope], |r| {
            let guests: String = r.get(3)?;
            Ok((
                r.get(0)?,
                r.get(1)?,
                r.get::<_, i64>(2)? as u64,
                serde_json::from_str(&guests).unwrap_or_default(),
            ))
        })?
        .collect::<Result<_, _>>()?;
    // (tenant, source) -> rows newest first: (logical, new_plain, new_stored)
    type Hist = Vec<(i64, i64, i64)>;
    let mut per: BTreeMap<(String, String), Hist> = BTreeMap::new();
    let mut q = c.prepare(
        "SELECT tenant, source, logical, new_plain, new_stored FROM backup_stats WHERE ?1 IS NULL OR tenant = ?1
         ORDER BY time DESC",
    )?;
    let rows = q.query_map([scope], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get(2)?,
            r.get(3)?,
            r.get(4)?,
        ))
    })?;
    for row in rows {
        let (t, src, l, p, st) = row?;
        let covered = policy_id.is_none() || groups.iter().any(|g| g.0 == t && in_group(&g.1, g.2, &g.3, &src));
        if covered {
            per.entry((t, src)).or_default().push((l, p, st));
        }
    }
    if per.is_empty() {
        return Ok(None);
    }
    let (mut full, mut delta, mut samples, mut plain, mut stored) = (0f64, 0i64, 0usize, 0i64, 0i64);
    for v in per.values() {
        plain += v.iter().map(|r| r.1).sum::<i64>();
        stored += v.iter().map(|r| r.2).sum::<i64>();
        samples += v.len();
        // the oldest row is the first full backup when the history is complete
        if v.len() > 1 {
            let mut d: Vec<i64> = v[..(v.len() - 1).min(30)].iter().map(|r| r.2).collect();
            d.sort_unstable();
            delta += d[d.len() / 2];
        }
    }
    let compression = if stored > 0 {
        (plain as f64 / stored as f64).max(1.0)
    } else {
        1.0
    };
    for v in per.values() {
        full += v[0].0 as f64 / compression;
    }
    Ok(Some(json!({
        "sources": per.len(), "samples": samples, "compression": compression,
        "full": full.round() as i64, "delta": delta,
    })))
}

pub const STORAGE_COLUMNS: &[&str] = &[
    "level",
    "tenant",
    "group",
    "sources",
    "snapshots",
    "logical_bytes",
    "data_in_bytes",
    "stored_bytes",
    "saved_bytes",
    "dedup",
    "compression",
    "reduction",
    "used_bytes",
    "quota_bytes",
    "growth_7d_bytes",
    "growth_30d_bytes",
    "growth_90d_bytes",
];

/// One row per tenant, then one per group (`group` empty = snapshots of no group).
pub fn table(c: &Connection, scope: Option<&str>, now: i64) -> rusqlite::Result<Table> {
    let v = compute(c, scope, now)?;
    let int = |x: &Value| Cell::opt_int(x.as_i64());
    let sums = |x: &Value| {
        ["logical", "data_in", "stored", "saved"]
            .iter()
            .map(|k| int(&x[*k]))
            .chain(
                ["dedup", "compression", "reduction"]
                    .iter()
                    .map(|k| Cell::opt_ratio(x[*k].as_f64())),
            )
            .collect::<Vec<_>>()
    };
    let mut rows = Vec::new();
    for t in v["tenants"].as_array().into_iter().flatten() {
        let mut r = vec![
            Cell::text("tenant"),
            Cell::text(t["tenant"].as_str().unwrap_or_default()),
            Cell::Empty,
            Cell::Empty,
            int(&t["snapshots"]),
        ];
        r.extend(sums(t));
        r.extend([
            int(&t["used"]),
            int(&t["quota_bytes"]),
            int(&t["growth"]["d7"]),
            int(&t["growth"]["d30"]),
            int(&t["growth"]["d90"]),
        ]);
        rows.push(r);
    }
    for g in v["groups"].as_array().into_iter().flatten() {
        let mut r = vec![
            Cell::text("group"),
            Cell::text(g["tenant"].as_str().unwrap_or_default()),
            Cell::text(g["group"].as_str().unwrap_or_default()),
            int(&g["sources"]),
            int(&g["snapshots"]),
        ];
        r.extend(sums(g));
        r.extend([Cell::Empty, Cell::Empty, Cell::Empty, Cell::Empty, Cell::Empty]);
        rows.push(r);
    }
    Ok(Table {
        kind: Kind::Storage,
        columns: STORAGE_COLUMNS,
        rows,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn group_membership() {
        let g = |v: Value| v.as_array().unwrap().clone();
        assert!(in_group("pve", 1, &g(json!([100])), "ct-100"));
        assert!(!in_group("pve", 1, &g(json!([100])), "vm-1000"));
        assert!(in_group("linux", 1, &g(json!(["abc"])), "host-abc"));
        assert!(in_group("truenas", 3, &g(json!(["tank/a"])), "nas-3-tank.a.child"));
        assert!(!in_group("truenas", 3, &g(json!(["tank/a"])), "nas-3-tank.ab"));
        assert!(in_group("truenas", 3, &g(json!([])), "nas-3-tank.ab"));
        assert!(in_group("smb", 6, &g(json!([])), "share-6"));
        assert!(in_group("plugin:pgx", 9, &g(json!(["db1"])), "plugin-pgx-9-db1"));
        assert!(!in_group("plugin:pgx", 9, &g(json!(["db1"])), "plugin-pgx-9-db2"));
        assert!(in_group("plugin:pgx", 9, &g(json!([])), "plugin-pgx-9"));
    }
}
