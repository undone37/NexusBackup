//! `GET /dashboard?days=7|30` (docs/phase12-contract.md §1): management KPIs
//! computed server-side from the catalog, cached for at most 60 s per
//! (tenant scope, days). Tenant users see their tenant only (no appliance-wide
//! capacity or replication figures).

use crate::auth::Ctx;
use crate::{ApiError, ApiResult, St, Q};
use axum::extract::State;
use axum::Json;
use catalog::rusqlite::{params, Connection, OptionalExtension};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::time::{Duration, Instant};

pub const CACHE_SECS: u64 = 60;
/// `worst` lists at most this many objects
const WORST: usize = 10;
/// `unprotected_list` lists at most this many objects
const UNPROTECTED_LIST: usize = 200;
/// minimum samples for a capacity forecast (contract: `null` below 7)
const MIN_SAMPLES: usize = 7;
const DAY: i64 = 86400;

/// Cached answers: (scope, days) → (computed at, body).
pub type Cache = std::sync::Mutex<HashMap<(Option<String>, i64), (Instant, Value)>>;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DashQuery {
    days: Option<i64>,
}

pub async fn dashboard(State(st): State<St>, ctx: Ctx, Q(q): Q<DashQuery>) -> ApiResult<Json<Value>> {
    let days = q.days.unwrap_or(30);
    if days != 7 && days != 30 {
        return Err(ApiError::bad("days: 7 or 30"));
    }
    let key = (ctx.scope().map(str::to_owned), days);
    let cached = st
        .dashboard
        .lock()
        .unwrap()
        .get(&key)
        .filter(|(at, _)| at.elapsed() < Duration::from_secs(CACHE_SECS))
        .map(|(_, v)| v.clone());
    let mut body = match cached {
        Some(v) => v,
        None => {
            let v = compute(&st.cat.conn(), ctx.scope(), days, catalog::now())?;
            let mut cache = st.dashboard.lock().unwrap();
            cache.retain(|_, (at, _)| at.elapsed() < Duration::from_secs(CACHE_SECS));
            cache.insert(key, (Instant::now(), v.clone()));
            v
        }
    };
    // not cached: an acknowledgement must hide the banner at once
    body["break_glass"] = break_glass(&st.cat.conn(), &ctx)?;
    body["console_shell"] = crate::console::shell_banner(&st.cat.conn(), &ctx)?;
    Ok(Json(body))
}

/// The pending break-glass notice (`settings.break_glass`, written by
/// `nexus-setup recover-admin`) while its alert is unacknowledged; only for
/// appliance-wide roles that can see alerts.
pub fn break_glass(c: &Connection, ctx: &Ctx) -> ApiResult<Value> {
    if ctx.scope().is_some() || ctx.user.role == "tenant_user" {
        return Ok(Value::Null);
    }
    let Some(raw) = catalog::setting(c, "break_glass")? else {
        return Ok(Value::Null);
    };
    let v: Value = serde_json::from_str(&raw).unwrap_or(Value::Null);
    let open = match v["alert"].as_i64() {
        Some(id) => c
            .query_row("SELECT 1 FROM alerts WHERE id = ?1 AND acked_by IS NULL", [id], |_| {
                Ok(())
            })
            .optional()?
            .is_some(),
        None => true,
    };
    Ok(if open { v } else { Value::Null })
}

pub use reports::day;

/// Least-squares slope (y per x) of the points; `None` for fewer than 2.
pub fn slope(points: &[(f64, f64)]) -> Option<f64> {
    let n = points.len() as f64;
    if points.len() < 2 {
        return None;
    }
    let (sx, sy) = points.iter().fold((0.0, 0.0), |(a, b), (x, y)| (a + x, b + y));
    let (mx, my) = (sx / n, sy / n);
    let (num, den) = points.iter().fold((0.0, 0.0), |(a, b), (x, y)| {
        (a + (x - mx) * (y - my), b + (x - mx) * (x - mx))
    });
    (den > 0.0).then(|| num / den)
}

/// Days until `free` bytes are used up at the trend of the daily samples
/// `(day index, used)`: `None` with fewer than 7 samples or no growth.
pub fn forecast_days(samples: &[(f64, f64)], free: Option<i64>) -> Option<i64> {
    if samples.len() < MIN_SAMPLES {
        return None;
    }
    let s = slope(samples).filter(|s| *s > 0.0)?;
    Some((free? as f64 / s).ceil() as i64)
}

fn protection(c: &Connection, scope: Option<&str>, now: i64) -> ApiResult<Value> {
    // the protected objects and their SLA state (shared with the protection / sla reports)
    let objs = reports::protection::assess(c, scope, now)?;
    let (mut ok, mut breach, mut never, mut paused) = (0, 0, 0, 0);
    let mut list: Vec<(u8, i64, Value)> = Vec::new();
    for s in &objs {
        match s.sla {
            "never" => never += 1,
            "paused" => paused += 1,
            "breach" => breach += 1,
            _ => ok += 1,
        }
        let rank = match s.sla {
            "never" => 0,
            "breach" => 1,
            _ => 2,
        };
        let (o, age) = (&s.obj, s.age);
        list.push((
            rank,
            -age.unwrap_or(i64::MAX),
            json!({"source": s.source, "name": o.name, "kind": o.kind, "tenant": o.tenant,
                   "last_ok": s.last_ok, "age_s": age, "rpo_s": o.rpo, "sla": s.sla}),
        ));
    }
    // breach before never would hide objects that never worked: the contract puts
    // both first; never (no backup at all) is the worse of the two
    list.sort_by_key(|(rank, age, _)| (*rank, *age));
    let worst: Vec<Value> = list.into_iter().take(WORST).map(|(_, _, v)| v).collect();

    // unprotected: enrolled agents no group backs up, share sources without a group,
    // inventory guests (PVE, TrueNAS, plugins) outside every group of their source
    let protected_hosts: HashSet<String> = objs.iter().flat_map(|s| s.obj.sources.clone()).collect();
    let mut open: Vec<Value> = Vec::new();
    let agents: Vec<(String, String, String)> = c
        .prepare("SELECT tenant, id, name FROM agents WHERE ?1 IS NULL OR tenant = ?1 ORDER BY tenant, name")?
        .query_map([scope], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
        .collect::<Result<_, _>>()?;
    for (tenant, id, name) in agents {
        if !protected_hosts.contains(&format!("host-{id}")) {
            open.push(
                json!({"tenant": tenant, "kind": "linux", "source_id": null, "source": name,
                             "guest": id, "name": name}),
            );
        }
    }
    let shares: Vec<(String, i64, String, String)> = c
        .prepare(
            "SELECT tenant, id, kind, name FROM sources WHERE kind IN ('nfs','smb') AND (?1 IS NULL OR tenant = ?1)
             AND id NOT IN (SELECT source_id FROM groups) ORDER BY tenant, name",
        )?
        .query_map([scope], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?
        .collect::<Result<_, _>>()?;
    for (tenant, sid, kind, name) in shares {
        open.push(
            json!({"tenant": tenant, "kind": kind, "source_id": sid, "source": name, "guest": null, "name": name}),
        );
    }
    let cover = crate::inventory::coverage(c, scope)?;
    let inv: Vec<(String, i64, String, String, String, String)> = c
        .prepare(
            "SELECT s.tenant, s.id, s.kind, s.name, i.guest, i.name FROM inventory i JOIN sources s ON s.id = i.source_id
             WHERE i.gone IS NULL AND (?1 IS NULL OR s.tenant = ?1) ORDER BY s.tenant, s.name, length(i.guest), i.guest",
        )?
        .query_map([scope], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?))
        })?
        .collect::<Result<_, _>>()?;
    for (tenant, sid, kind, sname, guest, name) in inv {
        let covered = cover
            .get(&sid)
            .is_some_and(|(whole, ids)| !whole.is_empty() || ids.contains_key(&guest));
        if !covered {
            open.push(
                json!({"tenant": tenant, "kind": kind, "source_id": sid, "source": sname,
                             "guest": guest, "name": name}),
            );
        }
    }
    let unprotected = open.len();
    open.truncate(UNPROTECTED_LIST);
    let protected = objs.len();
    Ok(json!({
        "objects": protected + unprotected, "protected": protected, "unprotected": unprotected,
        "unprotected_list": open,
        "sla_ok": ok, "sla_breach": breach, "sla_paused": paused, "never": never, "worst": worst,
    }))
}

/// Source kind of a backup job (via its group / source / agent / vmid).
fn job_source_kind(p: &Value, groups: &HashMap<i64, String>, sources: &HashMap<i64, String>) -> String {
    if let Some(k) = p["group_id"].as_i64().and_then(|g| groups.get(&g)) {
        return k.clone();
    }
    if let Some(k) = p["source_id"].as_i64().and_then(|s| sources.get(&s)) {
        return k.clone();
    }
    if p["agent_id"].is_string() {
        return "linux".into();
    }
    if p["vmid"].is_u64() {
        return "pve".into();
    }
    "other".into()
}

fn jobs(c: &Connection, scope: Option<&str>, days: i64, now: i64) -> ApiResult<Value> {
    let since = (now.div_euclid(DAY) - days + 1) * DAY;
    let groups: HashMap<i64, String> = c
        .prepare("SELECT g.id, s.kind FROM groups g JOIN sources s ON s.id = g.source_id")?
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
        .collect::<Result<_, _>>()?;
    let sources: HashMap<i64, String> = c
        .prepare("SELECT id, kind FROM sources")?
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
        .collect::<Result<_, _>>()?;
    let mut per_day: BTreeMap<String, [i64; 3]> = (0..days).map(|i| (day(since + i * DAY), [0; 3])).collect();
    let mut by_kind: BTreeMap<String, i64> = BTreeMap::new();
    let rows: Vec<(String, i64, String, Option<String>)> = c
        .prepare(
            "SELECT state, finished, params, result FROM jobs
             WHERE kind IN ('backup', 'plugin_backup') AND state IN ('ok', 'failed') AND finished >= ?1
             AND (?2 IS NULL OR tenant = ?2)",
        )?
        .query_map(params![since, scope], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
        })?
        .collect::<Result<_, _>>()?;
    let mut tot = [0i64; 3];
    for (state, finished, p, result) in rows {
        let result: Value = result
            .and_then(|r| serde_json::from_str(&r).ok())
            .unwrap_or(Value::Null);
        let i = match state.as_str() {
            "failed" => 2,
            _ if result["consistent"] == false => 1,
            _ => 0,
        };
        tot[i] += 1;
        if let Some(d) = per_day.get_mut(&day(finished)) {
            d[i] += 1;
        }
        if i == 2 {
            let p: Value = serde_json::from_str(&p).unwrap_or(Value::Null);
            *by_kind.entry(job_source_kind(&p, &groups, &sources)).or_default() += 1;
        }
    }
    let total: i64 = tot.iter().sum();
    let mut failed_by_kind: Vec<(String, i64)> = by_kind.into_iter().collect();
    failed_by_kind.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    Ok(json!({
        "success_rate": (total > 0).then(|| (tot[0] + tot[1]) as f64 / total as f64),
        "total": total, "ok": tot[0], "warning": tot[1], "failed": tot[2],
        "per_day": per_day.into_iter().map(|(d, [o, w, f])| json!({"day": d, "ok": o, "warning": w, "failed": f})).collect::<Vec<_>>(),
        "failed_by_kind": failed_by_kind.into_iter().map(|(k, n)| json!({"kind": k, "failed": n})).collect::<Vec<_>>(),
    }))
}

fn capacity(c: &Connection, scope: Option<&str>, days: i64, now: i64) -> ApiResult<Value> {
    // appliance file system (scheduler, settings `capacity`): not for tenant users
    let fs: Value = match scope {
        None => catalog::setting(c, "capacity")?
            .and_then(|v| serde_json::from_str(&v).ok())
            .unwrap_or(Value::Null),
        Some(_) => Value::Null,
    };
    let first = day(now - 30 * DAY);
    let samples: Vec<(String, i64, i64)> = c
        .prepare(
            "SELECT day, SUM(used), SUM(logical) FROM capacity_samples
             WHERE day > ?1 AND (?2 IS NULL OR tenant = ?2) GROUP BY day ORDER BY day",
        )?
        .query_map(params![first, scope], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
        .collect::<Result<_, _>>()?;
    let window = day(now - days * DAY);
    let (physical, logical) = samples.last().map(|s| (s.1, s.2)).unwrap_or((0, 0));
    let points: Vec<(f64, f64)> = samples
        .iter()
        .map(|(d, used, _)| (day_number(d) as f64, *used as f64))
        .collect();
    let free = fs["free"].as_i64();
    let (dedup, compression) = crate::storage::ratios(c, scope)?;
    Ok(json!({
        "total": fs["total"], "used": if scope.is_some() { json!(physical) } else { fs["used"].clone() },
        "free": fs["free"], "logical": logical, "physical": physical,
        // measured (daily capacity sample); before the first sample, the stats' dedup × compression
        "reduction": (physical > 0)
            .then(|| logical as f64 / physical as f64)
            .or(dedup.zip(compression).map(|(d, c)| d * c)),
        // from backup_stats (docs/storage-accounting.md); null before the first measured backup
        "dedup": dedup, "compression": compression,
        "per_day": samples.iter().filter(|s| s.0 > window)
            .map(|(d, u, l)| json!({"day": d, "used": u, "logical": l})).collect::<Vec<_>>(),
        "forecast_full_days": forecast_days(&points, free),
    }))
}

/// Days since 1970-01-01 of a `YYYY-MM-DD` string (inverse of [`day`]).
fn day_number(d: &str) -> i64 {
    let mut it = d.split('-').map(|x| x.parse::<i64>().unwrap_or(1));
    let (y, m, d) = (
        it.next().unwrap_or(1970),
        it.next().unwrap_or(1),
        it.next().unwrap_or(1),
    );
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn offsite(c: &Connection, scope: Option<&str>, days: i64, now: i64, lag_alert: i64) -> ApiResult<Value> {
    let tenants: Vec<(String, String)> = c
        .prepare("SELECT name, offsite FROM tenants WHERE ?1 IS NULL OR name = ?1")?
        .query_map([scope], |r| Ok((r.get(0)?, r.get(1)?)))?
        .collect::<Result<_, _>>()?;
    let with_remote: Vec<String> = tenants
        .into_iter()
        .filter(|(_, o)| serde_json::from_str::<Value>(o).is_ok_and(|v| v["remote"]["type"].is_string()))
        .map(|(t, _)| t)
        .collect();
    // offsite-protected sources: groups whose policy copies offsite
    let mut lag_max: Option<i64> = None;
    let mut lagging = 0;
    for t in &with_remote {
        let oldest: Option<i64> = c.query_row(
            "SELECT MIN(time) FROM snapshots WHERE tenant = ?1 AND local = 1 AND offsite = 0
             AND EXISTS (SELECT 1 FROM groups g JOIN policies p ON p.id = g.policy_id
                         WHERE g.tenant = ?1 AND p.offsite = 1)",
            [t],
            |r| r.get(0),
        )?;
        let lag = oldest.map(|o| (now - o).max(0)).unwrap_or(0);
        lag_max = Some(lag_max.unwrap_or(0).max(lag));
        if lag > lag_alert {
            lagging += 1;
        }
    }
    let (n, locked): (i64, i64) = c.query_row(
        "SELECT COUNT(*), COALESCE(SUM(lock_until > ?2), 0) FROM snapshots WHERE local = 1 AND (?1 IS NULL OR tenant = ?1)",
        params![scope, now],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    let replication_lag: Option<i64> = match scope {
        Some(_) => None,
        None => c.query_row(
            "SELECT MAX(?1 - COALESCE(last_sync, created)) FROM replication_sources WHERE state = 'enrolled'",
            [now],
            |r| r.get(0),
        )?,
    };
    let since = (now.div_euclid(DAY) - days + 1) * DAY;
    let (last_verify, verify_failed): (Option<i64>, i64) = c.query_row(
        "SELECT MAX(CASE WHEN state = 'ok' THEN finished END), COALESCE(SUM(state = 'failed' AND finished >= ?2), 0)
         FROM jobs WHERE kind = 'verify' AND (?1 IS NULL OR tenant = ?1)",
        params![scope, since],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    Ok(json!({
        "tenants": with_remote.len(), "lag_max_s": lag_max, "lagging": lagging,
        "lock_coverage": (n > 0).then(|| locked as f64 / n as f64),
        "replication_lag_max_s": replication_lag, "last_verify": last_verify, "verify_failed": verify_failed,
    }))
}

/// The whole dashboard body (without `break_glass`).
/// Consistency of each source's newest local snapshot (Phase 15d): count per level.
fn consistency(c: &Connection, scope: Option<&str>) -> ApiResult<Value> {
    let mut out = json!({"application": 0, "crash": 0, "inconsistent": 0, "unknown": 0});
    let rows: Vec<(String, i64)> = c
        .prepare(
            "SELECT COALESCE(s.consistency, 'unknown'), COUNT(*) FROM snapshots s
             WHERE s.local = 1 AND (?1 IS NULL OR s.tenant = ?1)
               AND s.time = (SELECT MAX(x.time) FROM snapshots x
                             WHERE x.tenant = s.tenant AND x.source = s.source AND x.local = 1)
             GROUP BY 1",
        )?
        .query_map([scope], |r| Ok((r.get(0)?, r.get(1)?)))?
        .collect::<Result<_, _>>()?;
    for (level, n) in rows {
        out[level] = json!(n);
    }
    Ok(out)
}

pub fn compute(c: &Connection, scope: Option<&str>, days: i64, now: i64) -> ApiResult<Value> {
    Ok(json!({
        "generated": now, "days": days,
        "protection": protection(c, scope, now)?,
        "consistency": consistency(c, scope)?,
        "jobs": jobs(c, scope, days, now)?,
        "capacity": capacity(c, scope, days, now)?,
        // same threshold as the scheduler's offsite_lag alert (48 h)
        "offsite": offsite(c, scope, days, now, 48 * 3600)?,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn days_roundtrip() {
        assert_eq!(day(0), "1970-01-01");
        assert_eq!(day(1_791_750_000), "2026-10-11");
        assert_eq!(day(951_782_400), "2000-02-29");
        for t in [0, 951_782_400, 1_791_750_000, 4_102_444_800] {
            assert_eq!(day_number(&day(t)), t.div_euclid(DAY));
        }
    }

    #[test]
    fn forecast_rules() {
        let grow: Vec<(f64, f64)> = (0..10).map(|d| (d as f64, 1000.0 + 100.0 * d as f64)).collect();
        assert_eq!(forecast_days(&grow, Some(1000)), Some(10));
        assert_eq!(forecast_days(&grow[..6], Some(1000)), None, "fewer than 7 samples");
        let flat: Vec<(f64, f64)> = (0..10).map(|d| (d as f64, 1000.0)).collect();
        assert_eq!(forecast_days(&flat, Some(1000)), None, "not growing");
        let shrink: Vec<(f64, f64)> = (0..10).map(|d| (d as f64, 1000.0 - d as f64)).collect();
        assert_eq!(forecast_days(&shrink, Some(1000)), None);
        assert_eq!(forecast_days(&grow, None), None, "free unknown");
        assert_eq!(slope(&[(1.0, 1.0)]), None);
    }
}
