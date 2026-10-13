//! Restore point simulator (Phase 23a, Veeam comparison row 9): `POST
//! /policies/simulate {schedule, gfs, timezone?, policy_id?, tenant?, days?}`.
//!
//! Runs the policy's schedule forward from now over `days` (default 400, at
//! most 1100, at most [`MAX_RUNS`] runs) and applies the store's own GFS rule
//! (`retention::keep`, the code retention runs) after every run:
//! the answer has the kept restore points over time (sampled), the classes at
//! the end of the horizon and the oldest restore point. The size estimate uses
//! the measured `backup_stats` of the sources the policy's groups cover (or the
//! tenant's / all sources for a new policy, `reports::storage::estimate`):
//! stored ≈ full + (points − 1) × one run's new data. An estimate, not a promise:
//! the change between weekly or monthly points is less than 7 or 30 daily runs
//! (overwritten blocks), dedup across sources is ignored.
//!
//! The policy dialog shows it while editing; the approvals page shows it for
//! `policy.update` requests (old and new values side by side).

use crate::auth::Ctx;
use crate::validate::Gfs;
use crate::{validate, ApiError, ApiResult, St, J};
use axum::extract::State;
use axum::Json;
use retention::Class;
use serde::Deserialize;
use serde_json::{json, Value};

/// Simulated runs at most (a 5-minute schedule covers about 70 days).
pub const MAX_RUNS: usize = 20_000;
const SAMPLES: usize = 60;
const READERS: &[&str] = &["admin", "security_officer", "operator", "tenant_admin", "viewer"];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SimReq {
    schedule: String,
    gfs: Gfs,
    #[serde(default)]
    timezone: Option<String>,
    /// size estimate from the stats of this policy's groups
    #[serde(default)]
    policy_id: Option<i64>,
    /// size estimate from this tenant's sources (tenant-scoped users: always theirs)
    #[serde(default)]
    tenant: Option<String>,
    #[serde(default)]
    days: Option<u32>,
}

/// The run times of `schedule` from `start` (exclusive) over `days`, at most [`MAX_RUNS`].
fn runs(s: catalog::schedule::Schedule, start: i64, days: u32) -> Vec<u64> {
    // `days` calendar days in the schedule's time zone, not days × 86400 s (DST)
    let end = catalog::schedule::add_local_days(s.tz, start, days);
    let mut out = Vec::new();
    let mut t = start;
    while out.len() < MAX_RUNS {
        match s.next_slot(t) {
            Some(n) if n <= end => {
                out.push(n as u64);
                t = n;
            }
            _ => break,
        }
    }
    out
}

/// Points over time and the final state for these run times.
pub fn simulate(times: &[u64], gfs: &Gfs) -> Value {
    let g = retention::Gfs {
        recent: gfs.recent,
        daily: gfs.daily,
        weekly: gfs.weekly,
        monthly: gfs.monthly,
        yearly: gfs.yearly,
    };
    let step = times.len().div_ceil(SAMPLES).max(1);
    let mut points = Vec::new();
    for i in (step - 1..times.len())
        .step_by(step)
        .chain([times.len().saturating_sub(1)])
    {
        if points.last().is_some_and(|p: &Value| p["run"] == i + 1) || times.is_empty() {
            continue;
        }
        let kept = retention::keep(&times[..=i], &g);
        points.push(json!({"run": i + 1, "t": times[i], "points": kept.len()}));
    }
    let kept = retention::keep(times, &g);
    let count = |c: Class| kept.values().filter(|v| v.contains(&c)).count();
    let peak = points.iter().filter_map(|p| p["points"].as_u64()).max().unwrap_or(0);
    json!({
        "runs": times.len(),
        "series": points,
        "final": {
            "points": kept.len(), "peak": peak,
            "recent": count(Class::Recent), "daily": count(Class::Daily), "weekly": count(Class::Weekly),
            "monthly": count(Class::Monthly), "yearly": count(Class::Yearly),
            "oldest": kept.keys().next(), "newest": times.last(),
        },
    })
}

pub async fn simulate_policy(State(st): State<St>, ctx: Ctx, J(r): J<SimReq>) -> ApiResult<Json<Value>> {
    ctx.require(READERS)?;
    validate::schedule(&r.schedule)?;
    r.gfs.check()?;
    let tz = r.timezone.as_deref().unwrap_or("UTC");
    let sched = catalog::schedule::Schedule::parse(&r.schedule)
        .and_then(|s| s.in_tz(tz))
        .map_err(|e| ApiError::bad(format!("{e:#}")))?;
    let days = r.days.unwrap_or(400);
    if !(1..=1100).contains(&days) {
        return Err(ApiError::bad("days: 1..=1100"));
    }
    let scope = match (ctx.scope(), r.tenant.as_deref().filter(|t| !t.is_empty())) {
        (Some(own), Some(t)) if t != own => return Err(ApiError::forbidden()),
        (Some(own), _) => Some(own.to_owned()),
        (None, t) => t.map(str::to_owned),
    };
    let now = catalog::now();
    let times = runs(sched, now, days);
    let mut out = simulate(&times, &r.gfs);
    out["days"] = json!(days);
    out["truncated"] = json!(times.len() >= MAX_RUNS);
    let est = reports::storage::estimate(&st.cat.conn(), r.policy_id, scope.as_deref())?;
    out["estimate"] = match est {
        Some(mut e) => {
            let n = out["final"]["points"].as_i64().unwrap_or(0);
            let peak = out["final"]["peak"].as_i64().unwrap_or(0);
            let (full, delta) = (e["full"].as_i64().unwrap_or(0), e["delta"].as_i64().unwrap_or(0));
            let size = |n: i64| full + (n - 1).max(0) * delta;
            e["stored"] = json!(if n > 0 { size(n) } else { 0 });
            e["stored_peak"] = json!(if peak > 0 { size(peak) } else { 0 });
            e
        }
        None => Value::Null,
    };
    Ok(Json(out))
}

#[cfg(test)]
mod tests {
    use super::*;

    const DAY: u64 = 86400;

    #[test]
    fn daily_runs_settle_at_the_gfs_sum() {
        // a daily run at 22:00 for 400 days from a Monday: 14 daily + 4 weekly +
        // 6 monthly + 2 yearly, overlapping classes counted once
        let s = catalog::schedule::Schedule::parse("daily 22:00").unwrap();
        let start = 1_791_763_200; // 2026-10-12 (Monday) 00:00 UTC
        let times = runs(s, start, 400);
        assert_eq!(times.len(), 400);
        assert_eq!(times[0], start as u64 + 22 * 3600);
        let gfs = Gfs {
            recent: 0,
            daily: 14,
            weekly: 4,
            monthly: 6,
            yearly: 2,
        };
        let v = simulate(&times, &gfs);
        let f = &v["final"];
        assert_eq!(f["daily"], 14);
        assert_eq!(f["weekly"], 4);
        assert_eq!(f["monthly"], 6);
        assert_eq!(f["yearly"], 2);
        let n = f["points"].as_u64().unwrap();
        assert!((14..=26).contains(&n), "{n}");
        // the series grows from 1 and never exceeds the final peak
        let series = v["series"].as_array().unwrap();
        assert_eq!(series.last().unwrap()["run"], 400);
        assert!(series.len() <= SAMPLES + 1);
        assert!(f["oldest"].as_u64().unwrap() < times[times.len() - 1] - 300 * DAY);
    }

    #[test]
    fn caps_runs() {
        let s = catalog::schedule::Schedule::parse("every 5m").unwrap();
        let times = runs(s, 1_791_763_200, 1100);
        assert_eq!(times.len(), MAX_RUNS);
        let gfs = Gfs {
            recent: 0,
            daily: 1,
            weekly: 0,
            monthly: 0,
            yearly: 0,
        };
        assert_eq!(simulate(&[], &gfs)["final"]["points"], 0);
    }
}
