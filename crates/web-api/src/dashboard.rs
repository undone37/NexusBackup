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
/// an object breaches its SLA when its last good backup is older than RPO × 1.5
const SLA_FACTOR: f64 = 1.5;
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

/// `YYYY-MM-DD` (UTC) of a unix time (civil-from-days, H. Hinnant).
pub fn day(ts: i64) -> String {
    let z = ts.div_euclid(DAY) + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02}")
}

/// RPO of a policy schedule: the (longest) schedule period.
fn rpo(schedule: &str) -> i64 {
    catalog::schedule::Schedule::parse(schedule).map_or(DAY, |s| s.period())
}

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

struct Obj {
    tenant: String,
    /// snapshot sources that count for this object (PVE: `vm-` and `ct-`)
    sources: Vec<String>,
    name: String,
    kind: String,
    rpo: i64,
    /// every group of the object is paused (or its source in maintenance, Phase 13b)
    paused: bool,
}

/// (tenant, source id, guests, schedule, source kind, source name, source config, paused)
type GroupRow = (String, i64, String, String, String, String, String, bool);

fn protection(c: &Connection, scope: Option<&str>, now: i64) -> ApiResult<Value> {
    let rows: Vec<GroupRow> = c
        .prepare(
            "SELECT g.tenant, g.source_id, g.guests, p.schedule, s.kind, s.name, s.config,
                    g.paused_until = -1 OR g.paused_until > ?2 OR s.maintenance_until = -1 OR s.maintenance_until > ?2
             FROM groups g JOIN policies p ON p.id = g.policy_id JOIN sources s ON s.id = g.source_id
             WHERE ?1 IS NULL OR g.tenant = ?1 ORDER BY g.id",
        )?
        .query_map(params![scope, now], |r| {
            Ok((
                r.get(0)?,
                r.get(1)?,
                r.get(2)?,
                r.get(3)?,
                r.get(4)?,
                r.get(5)?,
                r.get(6)?,
                r.get::<_, Option<bool>>(7)?.unwrap_or(false),
            ))
        })?
        .collect::<Result<_, _>>()?;
    // object key (tenant, first source) → object; one object in several groups counts once (shortest RPO)
    let mut objs: BTreeMap<(String, String), Obj> = BTreeMap::new();
    // plugin source id → whole source protected / protected guest ids
    let mut plugin_cover: HashMap<i64, (bool, HashSet<String>)> = HashMap::new();
    for (tenant, sid, guests, schedule, kind, sname, cfg, paused) in rows {
        let guests: Vec<Value> = serde_json::from_str(&guests).unwrap_or_default();
        let strs = || guests.iter().filter_map(Value::as_str).map(str::to_owned);
        let mut add: Vec<(Vec<String>, String)> = Vec::new();
        match kind.as_str() {
            "pve" => {
                for v in guests.iter().filter_map(Value::as_u64) {
                    add.push((vec![format!("vm-{v}"), format!("ct-{v}")], format!("{sname} guest {v}")));
                }
            }
            "linux" => {
                for a in strs() {
                    add.push((vec![format!("host-{a}")], format!("{sname} ({a})")));
                }
            }
            "truenas" => {
                let mut ds: Vec<String> = strs().collect();
                if ds.is_empty() {
                    let cfg: Value = serde_json::from_str(&cfg).unwrap_or(Value::Null);
                    ds = cfg["datasets"]
                        .as_array()
                        .map(|a| a.iter().filter_map(Value::as_str).map(str::to_owned).collect())
                        .unwrap_or_default();
                }
                for d in ds {
                    add.push((vec![truenas::source_name(sid as u64, &d)], format!("{sname} {d}")));
                }
            }
            "nfs" | "smb" => add.push((vec![nas::source_name(sid as u64)], sname.clone())),
            k => {
                let Some(pk) = k.strip_prefix("plugin:") else { continue };
                let Some(cur) = plugin_manager::current_for_kind(c, pk).ok().flatten() else {
                    continue;
                };
                let g: Vec<String> = strs().collect();
                let cover = plugin_cover.entry(sid).or_default();
                if g.is_empty() {
                    cover.0 = true;
                    add.push((
                        vec![plugin_proto::source_name(&cur.id, sid as u64, None)],
                        sname.clone(),
                    ));
                }
                for x in g {
                    cover.1.insert(x.clone());
                    add.push((
                        vec![plugin_proto::source_name(&cur.id, sid as u64, Some(&x))],
                        format!("{sname} {x}"),
                    ));
                }
            }
        }
        let r = rpo(&schedule);
        for (sources, name) in add {
            let o = objs.entry((tenant.clone(), sources[0].clone())).or_insert_with(|| Obj {
                tenant: tenant.clone(),
                sources,
                name,
                kind: kind.clone(),
                rpo: r,
                paused,
            });
            o.rpo = o.rpo.min(r);
            o.paused &= paused;
        }
    }
    let last: HashMap<(String, String), i64> = c
        .prepare(
            "SELECT tenant, source, MAX(time) FROM snapshots WHERE ?1 IS NULL OR tenant = ?1 GROUP BY tenant, source",
        )?
        .query_map([scope], |r| Ok(((r.get(0)?, r.get(1)?), r.get(2)?)))?
        .collect::<Result<_, _>>()?;
    let (mut ok, mut breach, mut never, mut paused) = (0, 0, 0, 0);
    let mut list: Vec<(u8, i64, Value)> = Vec::new();
    for o in objs.values() {
        let last_ok = o
            .sources
            .iter()
            .filter_map(|s| last.get(&(o.tenant.clone(), s.clone())))
            .max()
            .copied();
        let source = o
            .sources
            .iter()
            .find(|s| last.contains_key(&(o.tenant.clone(), (*s).clone())))
            .unwrap_or(&o.sources[0]);
        let age = last_ok.map(|t| (now - t).max(0));
        let (sla, rank) = match age {
            None => {
                never += 1;
                ("never", 0)
            }
            // paused on purpose: shown, but not a breach
            Some(a) if a as f64 > o.rpo as f64 * SLA_FACTOR && o.paused => {
                paused += 1;
                ("paused", 2)
            }
            Some(a) if a as f64 > o.rpo as f64 * SLA_FACTOR => {
                breach += 1;
                ("breach", 1)
            }
            Some(_) => {
                ok += 1;
                ("ok", 2)
            }
        };
        list.push((
            rank,
            -age.unwrap_or(i64::MAX),
            json!({"source": source, "name": o.name, "kind": o.kind, "tenant": o.tenant,
                   "last_ok": last_ok, "age_s": age, "rpo_s": o.rpo, "sla": sla}),
        ));
    }
    // breach before never would hide objects that never worked: the contract puts
    // both first; never (no backup at all) is the worse of the two
    list.sort_by_key(|(rank, age, _)| (*rank, *age));
    let worst: Vec<Value> = list.into_iter().take(WORST).map(|(_, _, v)| v).collect();

    // unprotected: enrolled agents no group backs up, plugin guests (last
    // `plugin_guests` listing per source) outside every group of their source
    let protected_hosts: HashSet<String> = objs.values().flat_map(|o| o.sources.clone()).collect();
    let agents: Vec<String> = c
        .prepare("SELECT id FROM agents WHERE ?1 IS NULL OR tenant = ?1")?
        .query_map([scope], |r| r.get(0))?
        .collect::<Result<_, _>>()?;
    let mut unprotected = agents
        .iter()
        .filter(|a| !protected_hosts.contains(&format!("host-{a}")))
        .count();
    let listings: Vec<(String, String)> = c
        .prepare(
            "SELECT params, result FROM jobs WHERE kind = 'plugin_guests' AND state = 'ok' AND result IS NOT NULL
             AND (?1 IS NULL OR tenant = ?1) ORDER BY id DESC LIMIT 500",
        )?
        .query_map([scope], |r| Ok((r.get(0)?, r.get(1)?)))?
        .collect::<Result<_, _>>()?;
    let mut seen = HashSet::new();
    let sources: HashSet<i64> = c
        .prepare("SELECT id FROM sources")?
        .query_map([], |r| r.get(0))?
        .collect::<Result<_, _>>()?;
    for (p, r) in listings {
        let p: Value = serde_json::from_str(&p).unwrap_or(Value::Null);
        let Some(sid) = p["source_id"].as_i64() else { continue };
        if !seen.insert(sid) || !sources.contains(&sid) {
            continue;
        }
        let (whole, guests) = plugin_cover.get(&sid).cloned().unwrap_or_default();
        if whole {
            continue;
        }
        let r: Value = serde_json::from_str(&r).unwrap_or(Value::Null);
        unprotected += r["guests"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|g| g["id"].as_str())
                    .filter(|id| !guests.contains(*id))
                    .count()
            })
            .unwrap_or(0);
    }
    let protected = objs.len();
    Ok(json!({
        "objects": protected + unprotected, "protected": protected, "unprotected": unprotected,
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
    Ok(json!({
        "total": fs["total"], "used": if scope.is_some() { json!(physical) } else { fs["used"].clone() },
        "free": fs["free"], "logical": logical, "physical": physical,
        "reduction": (physical > 0).then(|| logical as f64 / physical as f64),
        // not measured separately yet (the store keeps no uncompressed chunk sizes)
        "dedup": Value::Null, "compression": Value::Null,
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
pub fn compute(c: &Connection, scope: Option<&str>, days: i64, now: i64) -> ApiResult<Value> {
    Ok(json!({
        "generated": now, "days": days,
        "protection": protection(c, scope, now)?,
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
