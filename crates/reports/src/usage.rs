//! Per-tenant usage for billing (Phase 23a, docs/storage-accounting.md "Usage
//! export"): one row per tenant over a period (normally a calendar month).
//!
//! - objects: protected objects (snapshot sources) with at least one backup in
//!   the period (`backup_stats` ∪ `snapshots`, so pruned snapshots still count);
//! - logical average / peak: the daily `capacity_samples.logical` (sum of the
//!   sizes of the locally kept snapshots) over the sampled days of the period;
//! - stored average / peak: the daily measured store size (`capacity_samples.used`,
//!   a directory walk of the tenant's store: the billing authority);
//! - offsite average / peak: logical bytes of the snapshots with an offsite copy
//!   (`capacity_samples.offsite`, v37; the remote side is not measured).
//!
//! Days without a sample (appliance off, tenant created later) are left out of
//! the averages; `days_sampled` says how many there were.

use crate::rusqlite::{self, params, Connection};
use crate::{day, Cell, Kind, Table};
use serde_json::{json, Value};

pub const USAGE_COLUMNS: &[&str] = &[
    "period_start",
    "period_end",
    "tenant",
    "tenant_uid",
    "objects",
    "backups",
    "logical_avg_bytes",
    "logical_peak_bytes",
    "stored_avg_bytes",
    "stored_peak_bytes",
    "offsite_avg_bytes",
    "offsite_peak_bytes",
    "days_sampled",
    "quota_bytes",
];

/// `[from, to)` of the calendar month `YYYY-MM` (UTC), or `None` if malformed.
pub fn month_range(m: &str) -> Option<(i64, i64)> {
    let (y, mo) = m.split_once('-')?;
    let (y, mo): (i64, i64) = (y.parse().ok()?, mo.parse().ok()?);
    if m.len() != 7 || !(1970..=9999).contains(&y) || !(1..=12).contains(&mo) {
        return None;
    }
    let from = crate::parse_day(&format!("{y:04}-{mo:02}-01"))?;
    let (ny, nm) = if mo == 12 { (y + 1, 1) } else { (y, mo + 1) };
    let to = crate::parse_day(&format!("{ny:04}-{nm:02}-01"))?;
    Some((from * crate::DAY, to * crate::DAY))
}

/// The usage rows of `[from, to)` as JSON (`GET /usage`), one per tenant.
pub fn compute(c: &Connection, scope: Option<&str>, from: i64, to: i64) -> rusqlite::Result<Vec<Value>> {
    let (d0, d1) = (day(from), day(to - 1));
    c.prepare(
        "SELECT t.name, t.uid, t.quota_bytes,
           (SELECT COUNT(*) FROM (SELECT source FROM backup_stats WHERE tenant = t.name AND time >= ?2 AND time < ?3
              UNION SELECT source FROM snapshots WHERE tenant = t.name AND time >= ?2 AND time < ?3)),
           (SELECT COUNT(*) FROM (SELECT source, time FROM backup_stats WHERE tenant = t.name AND time >= ?2 AND time < ?3
              UNION SELECT source, time FROM snapshots WHERE tenant = t.name AND time >= ?2 AND time < ?3)),
           s.n, s.la, s.lp, s.ua, s.up, s.oa, s.op
         FROM tenants t LEFT JOIN (
           SELECT tenant, COUNT(*) AS n, AVG(logical) AS la, MAX(logical) AS lp, AVG(used) AS ua, MAX(used) AS up,
                  AVG(offsite) AS oa, MAX(offsite) AS op
           FROM capacity_samples WHERE day >= ?4 AND day <= ?5 GROUP BY tenant) s ON s.tenant = t.name
         WHERE ?1 IS NULL OR t.name = ?1 ORDER BY t.name",
    )?
    .query_map(params![scope, from, to, d0, d1], |r| {
        let avg = |i: usize| -> rusqlite::Result<Option<i64>> { Ok(r.get::<_, Option<f64>>(i)?.map(|f| f.round() as i64)) };
        Ok(json!({
            "tenant": r.get::<_, String>(0)?, "tenant_uid": r.get::<_, Option<String>>(1)?,
            "quota_bytes": r.get::<_, Option<i64>>(2)?, "objects": r.get::<_, i64>(3)?,
            "backups": r.get::<_, i64>(4)?, "days_sampled": r.get::<_, Option<i64>>(5)?.unwrap_or(0),
            "logical_avg": avg(6)?, "logical_peak": r.get::<_, Option<i64>>(7)?,
            "stored_avg": avg(8)?, "stored_peak": r.get::<_, Option<i64>>(9)?,
            "offsite_avg": avg(10)?, "offsite_peak": r.get::<_, Option<i64>>(11)?,
        }))
    })?
    .collect()
}

/// The `usage` report over `[from, to)`.
pub fn table(c: &Connection, scope: Option<&str>, from: i64, to: i64) -> rusqlite::Result<Table> {
    let int = |x: &Value| Cell::opt_int(x.as_i64());
    let rows = compute(c, scope, from, to)?
        .iter()
        .map(|u| {
            let mut r = vec![
                Cell::text(day(from)),
                Cell::text(day(to - 1)),
                Cell::text(u["tenant"].as_str().unwrap_or_default()),
                Cell::text(u["tenant_uid"].as_str().unwrap_or_default()),
            ];
            r.extend(
                [
                    "objects",
                    "backups",
                    "logical_avg",
                    "logical_peak",
                    "stored_avg",
                    "stored_peak",
                    "offsite_avg",
                    "offsite_peak",
                    "days_sampled",
                    "quota_bytes",
                ]
                .iter()
                .map(|k| int(&u[*k])),
            );
            r
        })
        .collect();
    Ok(Table {
        kind: Kind::Usage,
        columns: USAGE_COLUMNS,
        rows,
    })
}
