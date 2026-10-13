//! "Restore priority" switch (Phase 22b, `catalog::priority`, docs/control-plane.md
//! "Restore priority"): admins and operators turn it on for 1–24 hours during a
//! disaster recovery (renewing restarts the period), or off. No approval: it
//! only holds background work, always expires, is audited, and the scheduler
//! keeps a `restore_priority` warning open (delivered like every alert) while it
//! is on. Everyone signed in reads it (the web UI's banner).

use crate::auth::Ctx;
use crate::{validate, ApiError, ApiResult, St, J};
use axum::extract::State;
use axum::Json;
use catalog::priority::{self, Priority};
use serde::Deserialize;
use serde_json::{json, Value};

const OPS: &[&str] = &["admin", "operator"];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PriorityReq {
    hours: u32,
    #[serde(default)]
    reason: String,
}

fn value(p: Option<&Priority>) -> Value {
    match p {
        Some(p) => json!({"active": true, "until": p.until, "since": p.since, "by": p.by, "reason": p.reason,
                          "max_hours": priority::MAX_SECS / 3600}),
        None => json!({"active": false, "max_hours": priority::MAX_SECS / 3600}),
    }
}

pub async fn get(State(st): State<St>, _ctx: Ctx) -> ApiResult<Json<Value>> {
    let p = priority::active(&st.cat.conn(), catalog::now())?;
    Ok(Json(value(p.as_ref())))
}

pub async fn put(State(st): State<St>, ctx: Ctx, J(r): J<PriorityReq>) -> ApiResult<Json<Value>> {
    ctx.require(OPS)?;
    if !(1..=(priority::MAX_SECS / 3600) as u32).contains(&r.hours) {
        return Err(ApiError::bad("hours: 1..=24 (renew it if the recovery takes longer)"));
    }
    validate::text(&r.reason, "reason", 200)?;
    let now = catalog::now();
    let c = st.cat.conn();
    let old = priority::active(&c, now)?;
    let p = Priority {
        until: now + i64::from(r.hours) * 3600,
        since: old.as_ref().map_or(now, |o| o.since),
        by: ctx.name().to_owned(),
        reason: r.reason.trim().to_owned(),
    };
    priority::store(&c, &p)?;
    drop(c);
    st.audit(
        ctx.name(),
        "restore_priority.on",
        priority::SETTING,
        json!({"until": p.until, "hours": r.hours, "reason": p.reason, "renewed": old.is_some()}),
    )?;
    Ok(Json(value(Some(&p))))
}

pub async fn delete(State(st): State<St>, ctx: Ctx) -> ApiResult<Json<Value>> {
    ctx.require(OPS)?;
    let c = st.cat.conn();
    let old = priority::load(&c)?;
    if priority::clear(&c)? {
        drop(c);
        st.audit(
            ctx.name(),
            "restore_priority.off",
            priority::SETTING,
            json!({"since": old.as_ref().map(|o| o.since), "until": old.as_ref().map(|o| o.until)}),
        )?;
    }
    Ok(Json(value(None)))
}
