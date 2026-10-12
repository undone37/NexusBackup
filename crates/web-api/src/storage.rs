//! Storage accounting (Phase 13d/e, docs/storage-accounting.md):
//! `GET /storage` (per tenant and per group: logical, data in, stored, ratios,
//! growth), the soft tenant quota `PUT /tenants/{name}/quota` and the anomaly
//! thresholds `GET|PUT /settings/anomaly`.
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

use crate::auth::Ctx;
use crate::quorum::gate;
use crate::{ApiError, ApiResult, St, J};
use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use axum::Json;
use catalog::rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;

const ADMIN: &[&str] = &["admin"];
const SETTINGS_READ: &[&str] = &["admin", "security_officer"];
pub const ANOMALY_SETTING: &str = "anomaly";
const DAY: i64 = 86400;

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

/// `backup_stats` of locally kept snapshots: (tenant, source, logical, new_plain, new_stored).
fn rows(c: &Connection, scope: Option<&str>) -> ApiResult<Vec<(String, String, i64, i64, i64)>> {
    Ok(c.prepare(
        "SELECT b.tenant, b.source, b.logical, b.new_plain, b.new_stored FROM backup_stats b
         JOIN snapshots s ON s.tenant = b.tenant AND s.source = b.source AND s.time = b.time AND s.local = 1
         WHERE ?1 IS NULL OR b.tenant = ?1",
    )?
    .query_map([scope], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)))?
    .collect::<Result<_, _>>()?)
}

/// (dedup, compression) over the scope, for the dashboard's capacity tile.
pub fn ratios(c: &Connection, scope: Option<&str>) -> ApiResult<(Option<f64>, Option<f64>)> {
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
fn growth(c: &Connection, tenant: Option<&str>, scope: Option<&str>, now: i64) -> ApiResult<Value> {
    let samples: Vec<(String, i64)> = c
        .prepare(
            "SELECT day, SUM(used) FROM capacity_samples WHERE (?1 IS NULL OR tenant = ?1) AND (?2 IS NULL OR tenant = ?2)
             AND day > ?3 GROUP BY day ORDER BY day",
        )?
        .query_map(params![tenant, scope, crate::dashboard::day(now - 120 * DAY)], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })?
        .collect::<Result<_, _>>()?;
    let Some((_, last)) = samples.last() else {
        return Ok(json!({"d7": null, "d30": null, "d90": null}));
    };
    let ago = |d: i64| {
        let cut = crate::dashboard::day(now - d * DAY);
        samples.iter().rev().find(|(day, _)| *day <= cut).map(|(_, u)| last - u)
    };
    Ok(json!({"d7": ago(7), "d30": ago(30), "d90": ago(90)}))
}

#[allow(clippy::type_complexity)]
pub fn compute(c: &Connection, scope: Option<&str>, now: i64) -> ApiResult<Value> {
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
    let mut per_group: BTreeMap<(String, Option<i64>), (Sum, std::collections::BTreeSet<String>)> = BTreeMap::new();
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
        .query_map(params![crate::dashboard::day(now - 90 * DAY), scope], |r| {
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

pub async fn storage(State(st): State<St>, ctx: Ctx) -> ApiResult<Json<Value>> {
    Ok(Json(compute(&st.cat.conn(), ctx.scope(), catalog::now())?))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuotaReq {
    quota_bytes: Option<i64>,
}

/// Sets or clears a tenant's soft quota. Applies directly: it only raises
/// alerts (80 % warning, 100 % critical), backups are never blocked.
pub async fn put_quota(
    State(st): State<St>,
    ctx: Ctx,
    Path(name): Path<String>,
    J(r): J<QuotaReq>,
) -> ApiResult<Json<Value>> {
    ctx.require(ADMIN)?;
    if r.quota_bytes.is_some_and(|q| q <= 0) {
        return Err(ApiError::bad("quota_bytes: a positive number of bytes, or null"));
    }
    let n = st.cat.conn().execute(
        "UPDATE tenants SET quota_bytes = ?2 WHERE name = ?1",
        params![name, r.quota_bytes],
    )?;
    if n == 0 {
        return Err(ApiError::not_found());
    }
    let v = json!({"name": name, "quota_bytes": r.quota_bytes});
    st.audit(ctx.name(), "tenant.quota", &format!("tenant/{name}"), v.clone())?;
    Ok(Json(v))
}

/// Setting `anomaly` (scheduler `anomaly.rs` reads the same fields).
#[derive(Deserialize, Serialize, Clone, PartialEq, Debug)]
#[serde(deny_unknown_fields)]
pub struct Anomaly {
    pub enabled: bool,
    pub factor: f64,
    pub history: u64,
    pub floor_bytes: u64,
}

impl Default for Anomaly {
    fn default() -> Self {
        Anomaly {
            enabled: true,
            factor: 3.0,
            history: 14,
            floor_bytes: 1 << 30,
        }
    }
}

impl Anomaly {
    fn check(&self) -> ApiResult<()> {
        if !(1.5..=100.0).contains(&self.factor) {
            return Err(ApiError::bad("factor: 1.5..=100"));
        }
        if !(5..=100).contains(&self.history) {
            return Err(ApiError::bad("history: 5..=100 runs"));
        }
        if !(1 << 20..=1 << 50).contains(&self.floor_bytes) {
            return Err(ApiError::bad("floor_bytes: 1 MiB..=1 PiB"));
        }
        Ok(())
    }

    /// Detection gets less sensitive (switched off, higher factor or floor, …).
    fn weaker_than(&self, old: &Anomaly) -> bool {
        (old.enabled && !self.enabled) || self.factor > old.factor || self.floor_bytes > old.floor_bytes
    }
}

pub fn load_anomaly(c: &Connection) -> ApiResult<Anomaly> {
    Ok(catalog::setting(c, ANOMALY_SETTING)?
        .and_then(|v| serde_json::from_str(&v).ok())
        .unwrap_or_default())
}

pub async fn get_anomaly(State(st): State<St>, ctx: Ctx) -> ApiResult<Json<Value>> {
    ctx.require(SETTINGS_READ)?;
    Ok(Json(json!(load_anomaly(&st.cat.conn())?)))
}

/// Stricter thresholds apply at once; weakening the detection (a ransomware
/// signal) goes through approval (`settings.anomaly`).
pub async fn put_anomaly(State(st): State<St>, ctx: Ctx, J(new): J<Anomaly>) -> ApiResult<Response> {
    ctx.require(ADMIN)?;
    new.check()?;
    let old = load_anomaly(&st.cat.conn())?;
    if new.weaker_than(&old) {
        let p = json!({"anomaly": new, "old": old});
        return gate(&st, &ctx, "settings.anomaly", "settings/anomaly", p);
    }
    catalog::set_setting(&st.cat.conn(), ANOMALY_SETTING, &json!(new).to_string())?;
    st.audit(ctx.name(), "settings.anomaly", "settings/anomaly", json!(new))?;
    Ok(Json(json!(new)).into_response())
}

/// Current value for the quorum's "unchanged since the request" check.
pub fn anomaly_value(c: &Connection) -> ApiResult<Option<Value>> {
    Ok(Some(json!(load_anomaly(c)?)))
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

    #[test]
    fn anomaly_weakening() {
        let d = Anomaly::default();
        let off = Anomaly {
            enabled: false,
            ..d.clone()
        };
        assert!(off.weaker_than(&d));
        assert!(!d.weaker_than(&off));
        let strict = Anomaly {
            factor: 2.0,
            ..d.clone()
        };
        assert!(!strict.weaker_than(&d));
        assert!(d.weaker_than(&strict));
    }
}
