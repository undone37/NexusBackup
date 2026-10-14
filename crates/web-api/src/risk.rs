//! Privileged-activity risk signals (Phase 29, docs/control-plane.md "Risk
//! signals and step-up"; NetBackup Tier 1 #5). Deterministic rules, no model:
//!
//! - **unusual sign-in hour** ([`sign_in`], every new session): an hour (UTC,
//!   plus or minus one) the account has not signed in at for 90 days, once it
//!   has at least 10 sign-ins of history (`login_hours`) -> warning;
//! - **weakening burst** ([`observe`], every audit record): 5 or more requests
//!   in one hour that weaken protection (approvals off, retention cuts, allow-
//!   list / firewall / forwarding / anomaly / session / passkey policy changes,
//!   offsite target removals, replication deletes, hold releases, keep limits,
//!   tenant deactivation) -> critical;
//! - **bulk deletes**: 10 or more delete requests in one hour (snapshots,
//!   sources, groups, policies, agents, tenants) -> critical;
//! - **download volume**: bytes downloaded in 24 h above 10 times the account's
//!   median daily volume of the last 30 days, and above 1 GiB -> warning.
//!
//! A signal raises `user_risk` and marks the account for 24 h
//! (`users.risk_since/risk_until/risk_reason`). While marked, the first changing
//! request of each session answers 428 until the session re-authenticates with
//! `POST /auth/step-up` (`sessions.step_up_at`, checked by the `Ctx`
//! extractor: [`check`]); API tokens of a marked account cannot change
//! anything. Requests are counted once: as `quorum.request`, or as the action
//! itself when approvals are disabled.

use crate::auth::{reauth, ClientIp, Ctx};
use crate::{ApiError, ApiResult, St, J};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use catalog::rusqlite::{params, Connection, OptionalExtension};
use serde::Deserialize;
use serde_json::{json, Value};

pub const ALERT_KIND: &str = "user_risk";
/// How long a signal marks the account.
pub const MARK_SECS: i64 = 24 * 3600;
pub const BASELINE_DAYS: i64 = 90;
pub const MIN_SIGN_INS: i64 = 10;
pub const WINDOW_SECS: i64 = 3600;
pub const WEAKENING_BURST: usize = 5;
pub const DELETE_BURST: usize = 10;
pub const DOWNLOAD_FACTOR: u64 = 10;
pub const DOWNLOAD_FLOOR: u64 = 1 << 30;
const MANAGERS: &[&str] = &["admin", "security_officer"];

pub fn routes() -> Router<St> {
    Router::new()
        .route("/auth/step-up", post(step_up))
        .route("/risk", get(list))
        .route("/users/{id}/risk/clear", post(clear))
}

/// What a request does, for the burst rules.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Kind {
    Weakening,
    Delete,
}

const WEAKENING: &[&str] = &[
    "approvals.disable",
    "security.mgmt_allow",
    "security.session",
    crate::passkeys::ACTION,
    crate::firewall::ACTION,
    "settings.forwarding",
    "settings.anomaly",
    "replication_peer.delete",
    "replication_source.delete",
    catalog::holds::RELEASE_ACTION,
    crate::keep::SETTING_ACTION,
    catalog::tenants::DISABLE_ACTION,
    catalog::vault::DISABLE,
    // gated only when it removes or loosens the offsite copy (resources::update_tenant)
    "tenant.update",
];

const DELETES: &[&str] = &[
    "snapshot.delete",
    "source.delete",
    "group.delete",
    "policy.delete",
    "agent.delete",
    "tenant.delete",
];

/// A GFS class of `new` below `old` (policy update that keeps less).
fn retention_cut(p: &Value) -> bool {
    ["recent", "daily", "weekly", "monthly", "yearly"].iter().any(|k| {
        match (p["old"]["gfs"][k].as_u64(), p["gfs"][k].as_u64()) {
            (Some(o), Some(n)) => n < o,
            _ => false,
        }
    })
}

/// The request an audit record stands for: `quorum.request` (approvals on), or
/// the action itself executed directly (approvals off); executions after an
/// approval are not counted again.
pub fn classify(action: &str, details: &Value) -> Option<Kind> {
    let (a, p) = if action == "quorum.request" {
        (details["action"].as_str()?, &details["params"])
    } else if details["approvals"] == "disabled" {
        (action, &details["params"])
    } else {
        return None;
    };
    if DELETES.contains(&a) {
        Some(Kind::Delete)
    } else if WEAKENING.contains(&a) || (a == "policy.update" && retention_cut(p)) {
        Some(Kind::Weakening)
    } else {
        None
    }
}

fn median(mut v: Vec<u64>) -> u64 {
    if v.is_empty() {
        return 0;
    }
    v.sort_unstable();
    v[v.len() / 2]
}

/// The download rule: `days` = bytes per earlier day with downloads (30 days).
pub fn download_over(last_24h: u64, days: Vec<u64>) -> bool {
    last_24h > DOWNLOAD_FLOOR && last_24h > DOWNLOAD_FACTOR.saturating_mul(median(days))
}

/// The unusual-hour rule over the account's recent sign-in hours (`hour -> count`).
pub fn unusual_hour(hour: i64, hours: &[(i64, i64)]) -> bool {
    let total: i64 = hours.iter().map(|(_, n)| n).sum();
    if total < MIN_SIGN_INS {
        return false;
    }
    let near = [(hour + 23) % 24, hour, (hour + 1) % 24];
    !hours.iter().any(|(h, _)| near.contains(h))
}

/// Marks the account and raises (or refreshes) its `user_risk` alert.
pub fn mark(c: &Connection, user_id: i64, rule: &str, severity: &str, why: &str) -> ApiResult<()> {
    let now = catalog::now();
    let Some((name, role, tenant)) = c
        .query_row("SELECT name, role, tenant FROM users WHERE id = ?1", [user_id], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, Option<String>>(2)?,
            ))
        })
        .optional()?
    else {
        return Ok(());
    };
    c.execute(
        "UPDATE users SET risk_since = ?2, risk_until = ?3, risk_reason = ?4 WHERE id = ?1",
        params![user_id, now, now + MARK_SECS, why],
    )?;
    let key = format!("{ALERT_KIND}:{user_id}:{rule}");
    let msg = format!(
        "account {name} ({role}): {why}; it must re-authenticate before its next change in each session for 24 hours"
    );
    let open = c.execute(
        "UPDATE alerts SET last_ts = ?2, message = ?3, severity = ?4 WHERE key = ?1 AND resolved_at IS NULL",
        params![key, now, msg, severity],
    )?;
    if open == 0 {
        c.execute(
            "INSERT INTO alerts (ts, last_ts, severity, kind, key, message, tenant) VALUES (?1, ?1, ?2, ?3, ?4, ?5, ?6)",
            params![now, severity, ALERT_KIND, key, msg, tenant],
        )?;
    }
    Ok(())
}

/// A new session of `user_id` (local, passkey or OIDC sign-in): the
/// unusual-hour rule, then the hour joins the baseline.
pub fn sign_in(c: &Connection, user_id: i64) -> ApiResult<()> {
    let now = catalog::now();
    let hour = (now.rem_euclid(86_400)) / 3600;
    let hours: Vec<(i64, i64)> = c
        .prepare("SELECT hour, count FROM login_hours WHERE user_id = ?1 AND last_seen >= ?2")?
        .query_map(params![user_id, now - BASELINE_DAYS * 86_400], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })?
        .collect::<Result<_, _>>()?;
    if unusual_hour(hour, &hours) {
        mark(
            c,
            user_id,
            "sign_in_hour",
            "warning",
            &format!("signed in at {hour:02}:xx UTC, an hour it has not used in {BASELINE_DAYS} days"),
        )?;
    }
    c.execute(
        "INSERT INTO login_hours (user_id, hour, count, last_seen) VALUES (?1, ?2, 1, ?3)
         ON CONFLICT (user_id, hour) DO UPDATE SET count = count + 1, last_seen = ?3",
        params![user_id, hour, now],
    )?;
    Ok(())
}

/// Every audit record (crate::AppState::audit): the burst and download rules
/// for the acting account.
pub fn observe(c: &Connection, actor: &str, action: &str, details: &Value) -> ApiResult<()> {
    let kind = classify(action, details);
    if kind.is_none() && action != "download.get" {
        return Ok(());
    }
    let Some(user_id) = c
        .query_row("SELECT id FROM users WHERE name = ?1", [actor], |r| r.get::<_, i64>(0))
        .optional()?
    else {
        return Ok(());
    };
    let now = catalog::now();
    // the audit actor may carry a suffix (impersonation, API token)
    let rows: Vec<(i64, String, String)> = c
        .prepare(
            "SELECT ts, action, details FROM audit WHERE ts >= ?2 AND (actor = ?1 OR actor LIKE ?1 || ' %')
             AND (action IN ('quorum.request', 'download.get') OR details LIKE '%\"approvals\":\"disabled\"%')
             ORDER BY seq DESC LIMIT 5000",
        )?
        .query_map(params![actor, now - 31 * 86_400], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?))
        })?
        .collect::<Result<_, _>>()?;
    if let Some(k) = kind {
        let n = rows
            .iter()
            .filter(|(ts, a, d)| {
                *ts >= now - WINDOW_SECS && serde_json::from_str::<Value>(d).is_ok_and(|d| classify(a, &d) == Some(k))
            })
            .count();
        match k {
            Kind::Weakening if n >= WEAKENING_BURST => mark(
                c,
                user_id,
                "weakening",
                "critical",
                &format!(
                    "{n} requests that weaken protection within an hour (last: {})",
                    details["action"].as_str().unwrap_or(action)
                ),
            )?,
            Kind::Delete if n >= DELETE_BURST => mark(
                c,
                user_id,
                "deletes",
                "critical",
                &format!("{n} delete requests within an hour"),
            )?,
            _ => {}
        }
        return Ok(());
    }
    // download.get: bytes in the last 24 h against the earlier days' median
    let mut last = 0u64;
    let mut days: std::collections::BTreeMap<i64, u64> = Default::default();
    for (ts, a, d) in rows.iter().filter(|(_, a, _)| a == "download.get") {
        let _ = a;
        let b = serde_json::from_str::<Value>(d)
            .ok()
            .and_then(|d| d["bytes"].as_u64())
            .unwrap_or(0);
        if *ts >= now - 86_400 {
            last += b;
        } else {
            *days.entry(ts.div_euclid(86_400)).or_default() += b;
        }
    }
    if download_over(last, days.into_values().collect()) {
        mark(
            c,
            user_id,
            "downloads",
            "warning",
            &format!("downloaded {} MiB within 24 hours, far more than usual", last >> 20),
        )?;
    }
    Ok(())
}

/// The risk mark of an account: `(since, until, reason)` while active.
pub fn active_mark(c: &Connection, user_id: i64) -> ApiResult<Option<(i64, i64, String)>> {
    Ok(c.query_row(
        "SELECT risk_since, risk_until, COALESCE(risk_reason, '') FROM users
             WHERE id = ?1 AND risk_until > ?2 AND risk_since IS NOT NULL",
        params![user_id, catalog::now()],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    )
    .optional()?)
}

/// Paths a marked session may still use without stepping up (sign-in,
/// step-up itself, the passkey challenge for it, sign-out).
fn exempt(path: &str) -> bool {
    let p = path.strip_prefix("/api/v1").unwrap_or(path);
    p.starts_with("/auth/")
}

/// The `Ctx` extractor's check for a changing request of a session (`sid`)
/// or an API token (`sid` empty) of `user_id`.
pub fn check(c: &Connection, user_id: i64, sid: &str, token: bool, path: &str) -> ApiResult<()> {
    if exempt(path) {
        return Ok(());
    }
    let Some((since, _, why)) = active_mark(c, user_id)? else {
        return Ok(());
    };
    if token {
        return Err(ApiError(
            StatusCode::FORBIDDEN,
            format!("API tokens of this account cannot change anything while it is marked by a risk signal ({why})"),
        ));
    }
    let done: Option<i64> = c
        .query_row("SELECT step_up_at FROM sessions WHERE id_hash = ?1", [sid], |r| {
            r.get(0)
        })
        .optional()?
        .flatten();
    if done.is_some_and(|d| d >= since) {
        return Ok(());
    }
    Err(ApiError(
        StatusCode::PRECONDITION_REQUIRED,
        format!("step-up required: re-enter your password and second factor ({why})"),
    ))
}

/// `/auth/me` field: `{since, until, reason, done}` while the account is marked.
pub fn me(c: &Connection, ctx: &Ctx) -> ApiResult<Value> {
    let Some((since, until, reason)) = active_mark(c, ctx.user.id)? else {
        return Ok(Value::Null);
    };
    let done: Option<i64> = c
        .query_row("SELECT step_up_at FROM sessions WHERE id_hash = ?1", [&ctx.sid], |r| {
            r.get(0)
        })
        .optional()?
        .flatten();
    Ok(json!({"since": since, "until": until, "reason": reason, "done": done.is_some_and(|d| d >= since)}))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StepUpReq {
    current_password: Option<String>,
    current_totp: Option<String>,
}

/// `POST /auth/step-up`: re-authentication of the session (password + TOTP or passkey).
pub async fn step_up(
    State(st): State<St>,
    ctx: Ctx,
    ClientIp(ip): ClientIp,
    J(r): J<StepUpReq>,
) -> ApiResult<Json<Value>> {
    if ctx.token.is_some() {
        return Err(ApiError::forbidden());
    }
    reauth(&st, &ctx, &ip, r.current_password, r.current_totp, "step up").await?;
    let now = catalog::now();
    st.cat.conn().execute(
        "UPDATE sessions SET step_up_at = ?2 WHERE id_hash = ?1",
        params![ctx.sid, now],
    )?;
    st.audit(
        ctx.name(),
        "auth.step_up",
        &format!("user/{}", ctx.name()),
        json!({"ip": ip}),
    )?;
    Ok(Json(json!({"step_up_at": now})))
}

/// `GET /risk`: accounts marked now.
pub async fn list(State(st): State<St>, ctx: Ctx) -> ApiResult<Json<Value>> {
    ctx.require(MANAGERS)?;
    if ctx.scope().is_some() {
        return Err(ApiError::forbidden());
    }
    let c = st.cat.conn();
    let rows: Vec<Value> = c
        .prepare(
            "SELECT id, name, role, tenant, risk_since, risk_until, risk_reason FROM users
             WHERE risk_until > ?1 AND risk_since IS NOT NULL ORDER BY risk_since DESC",
        )?
        .query_map([catalog::now()], |r| {
            Ok(json!({"user_id": r.get::<_, i64>(0)?, "user": r.get::<_, String>(1)?,
                      "role": r.get::<_, String>(2)?, "tenant": r.get::<_, Option<String>>(3)?,
                      "since": r.get::<_, i64>(4)?, "until": r.get::<_, i64>(5)?,
                      "reason": r.get::<_, Option<String>>(6)?}))
        })?
        .collect::<Result<_, _>>()?;
    Ok(Json(Value::Array(rows)))
}

/// `POST /users/{id}/risk/clear`: ends a mark early (not one's own).
pub async fn clear(State(st): State<St>, ctx: Ctx, Path(id): Path<i64>) -> ApiResult<Json<Value>> {
    ctx.require(MANAGERS)?;
    if ctx.scope().is_some() || ctx.token.is_some() {
        return Err(ApiError::forbidden());
    }
    if id == ctx.user.id {
        return Err(ApiError(
            StatusCode::FORBIDDEN,
            "a risk mark on your own account is cleared by someone else".into(),
        ));
    }
    let name: String = {
        let c = st.cat.conn();
        let name = c
            .query_row("SELECT name FROM users WHERE id = ?1", [id], |r| r.get(0))
            .optional()?
            .ok_or_else(ApiError::not_found)?;
        if active_mark(&c, id)?.is_none() {
            return Err(ApiError::conflict("the account is not marked"));
        }
        c.execute(
            "UPDATE users SET risk_until = ?2 WHERE id = ?1",
            params![id, catalog::now()],
        )?;
        name
    };
    st.audit(ctx.name(), "user.risk_clear", &format!("user/{name}"), json!({}))?;
    Ok(Json(json!({"cleared": true})))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rules() {
        assert!(!unusual_hour(3, &[(9, 5)]), "too little history");
        assert!(unusual_hour(3, &[(9, 6), (10, 6)]));
        assert!(!unusual_hour(3, &[(2, 6), (10, 6)]), "a neighbouring hour counts");
        assert!(!unusual_hour(0, &[(23, 12)]), "wraps around midnight");
        assert!(!download_over(2 << 30, vec![1 << 30]), "within 10 times the median");
        assert!(download_over(3 << 30, vec![100 << 20, 200 << 20, 300 << 20]));
        assert!(!download_over(900 << 20, vec![]), "below the floor");
        assert!(download_over(2 << 30, vec![]), "no history: the floor");
        let req = |a: &str, p: Value| json!({"action": a, "params": p});
        assert_eq!(
            classify("quorum.request", &req("approvals.disable", json!({}))),
            Some(Kind::Weakening)
        );
        assert_eq!(
            classify("quorum.request", &req("snapshot.delete", json!({}))),
            Some(Kind::Delete)
        );
        let cut = json!({"gfs": {"daily": 3}, "old": {"gfs": {"daily": 7}}});
        let up = json!({"gfs": {"daily": 9}, "old": {"gfs": {"daily": 7}}});
        assert_eq!(
            classify("quorum.request", &req("policy.update", cut.clone())),
            Some(Kind::Weakening)
        );
        assert_eq!(classify("quorum.request", &req("policy.update", up)), None);
        assert_eq!(
            classify("policy.update", &json!({"approvals": "disabled", "params": cut})),
            Some(Kind::Weakening)
        );
        assert_eq!(
            classify("source.delete", &json!({"approved_by": "bob"})),
            None,
            "the execution after an approval is not counted again"
        );
        assert_eq!(classify("group.update", &json!({})), None);
    }
}
