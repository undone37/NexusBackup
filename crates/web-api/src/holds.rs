//! Legal holds (Phase 15c, catalog v18, docs/control-plane.md "Legal hold").
//!
//! A security officer sets a hold on one snapshot or on every snapshot of a
//! tenant (optionally one source) in a time range; it takes effect at once
//! and is audited (`snapshot.hold`). Retention (local, orphan sweep, offsite,
//! replica), GC and `snapshot.delete` skip held snapshots (the scheduler reads
//! the holds when it plans a job). Releasing one is the approval action
//! `snapshot.hold_release`, requested by a security officer or an admin and
//! approved by another approver. On a replication secondary the primary's holds
//! arrive as `advisory` rows; setting a hold on such a snapshot applies it.

use crate::auth::Ctx;
use crate::{validate, ApiError, ApiResult, St, J, Q};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Response;
use axum::routing::{get, post};
use axum::{Json, Router};
use catalog::holds::{advisory_key, RELEASE_ACTION};
use catalog::rusqlite::{params, Connection, OptionalExtension};
use serde::Deserialize;
use serde_json::{json, Value};

/// Who sets holds (immediately).
const SETTERS: &[&str] = &["security_officer"];
/// Who may request a release (approved by another admin / security officer).
const RELEASERS: &[&str] = &["security_officer", "admin"];

pub fn routes() -> Router<St> {
    Router::new()
        .route("/holds", get(list).post(bulk))
        .route("/snapshots/{tenant}/{source}/{time}/hold", post(set).delete(release))
}

pub(crate) fn reason(r: &str) -> ApiResult<String> {
    let r = r.trim();
    if r.is_empty() || r.chars().count() > 500 || r.chars().any(char::is_control) {
        return Err(ApiError::bad("reason: 1 to 500 characters, one line"));
    }
    Ok(r.to_owned())
}

/// Holds one snapshot (inside the caller's transaction): applies an advisory
/// row, else inserts an active one. `None` if it is already held.
pub(crate) fn hold_one(
    c: &Connection,
    tenant: &str,
    source: &str,
    time: i64,
    reason: &str,
    by: &str,
) -> ApiResult<Option<Value>> {
    let open: Option<(i64, String, Option<String>, String)> = c
        .query_row(
            "SELECT id, state, origin, held_by FROM legal_holds WHERE tenant = ?1 AND source = ?2 AND time = ?3
             AND state IN ('active','advisory')",
            params![tenant, source, time],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .optional()?;
    let now = catalog::now();
    match open {
        Some((_, state, ..)) if state == "active" => Ok(None),
        Some((id, _, origin, primary_by)) => {
            c.execute(
                "UPDATE legal_holds SET state = 'active', reason = ?2, held_by = ?3, held_at = ?4 WHERE id = ?1",
                params![id, reason, by, now],
            )?;
            c.execute(
                "UPDATE alerts SET resolved_at = ?2, resolved_by = ?3, auto = 1 WHERE key = ?1 AND resolved_at IS NULL",
                params![advisory_key(tenant, source, time as u64), now, by],
            )?;
            Ok(Some(
                json!({"id": id, "advisory_from": origin, "primary_held_by": primary_by}),
            ))
        }
        None => {
            c.execute(
                "INSERT INTO legal_holds (tenant, source, time, state, reason, held_by, held_at)
                 VALUES (?1, ?2, ?3, 'active', ?4, ?5, ?6)",
                params![tenant, source, time, reason, by, now],
            )?;
            Ok(Some(json!({"id": c.last_insert_rowid()})))
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HoldReq {
    reason: String,
}

/// `POST /snapshots/{tenant}/{source}/{time}/hold {reason}`: security officer, immediate.
pub async fn set(
    State(st): State<St>,
    ctx: Ctx,
    Path((tenant, source, time)): Path<(String, String, i64)>,
    J(r): J<HoldReq>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    ctx.require(SETTERS)?;
    validate::name(&tenant, "tenant")?;
    validate::source_ref(&source)?;
    if !ctx.sees(&tenant) {
        return Err(ApiError::forbidden());
    }
    let reason = reason(&r.reason)?;
    let out = {
        let mut c = st.cat.conn();
        let tx = c.transaction()?;
        let exists: bool = tx.query_row(
            "SELECT EXISTS (SELECT 1 FROM snapshots WHERE tenant = ?1 AND source = ?2 AND time = ?3)",
            params![tenant, source, time],
            |r| r.get(0),
        )?;
        if !exists {
            return Err(ApiError(StatusCode::NOT_FOUND, "no such snapshot".into()));
        }
        let out = hold_one(&tx, &tenant, &source, time, &reason, ctx.name())?
            .ok_or_else(|| ApiError::conflict("snapshot is already under a legal hold"))?;
        tx.commit()?;
        out
    };
    let mut details = json!({"reason": reason});
    crate::quorum::merge(&mut details, &out);
    st.audit(
        ctx.name(),
        "snapshot.hold",
        &format!("snapshot/{tenant}/{source}/{time}"),
        details,
    )?;
    Ok((StatusCode::CREATED, Json(out)))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BulkReq {
    tenant: String,
    source: Option<String>,
    from: i64,
    to: i64,
    reason: String,
}

/// `POST /holds {tenant, source?, from, to, reason}`: holds every snapshot of
/// the tenant (or source) taken in `[from, to]` (incident response). One audit
/// entry lists them.
pub async fn bulk(State(st): State<St>, ctx: Ctx, J(r): J<BulkReq>) -> ApiResult<Json<Value>> {
    ctx.require(SETTERS)?;
    validate::name(&r.tenant, "tenant")?;
    if let Some(s) = &r.source {
        validate::source_ref(s)?;
    }
    if !ctx.sees(&r.tenant) {
        return Err(ApiError::forbidden());
    }
    if r.from > r.to {
        return Err(ApiError::bad("from must not be after to"));
    }
    let reason = reason(&r.reason)?;
    let held = {
        let mut c = st.cat.conn();
        let tx = c.transaction()?;
        let snaps: Vec<(String, i64)> = tx
            .prepare(
                "SELECT source, time FROM snapshots WHERE tenant = ?1 AND (?2 IS NULL OR source = ?2)
                 AND time BETWEEN ?3 AND ?4 ORDER BY source, time",
            )?
            .query_map(params![r.tenant, r.source, r.from, r.to], |x| {
                Ok((x.get(0)?, x.get(1)?))
            })?
            .collect::<Result<_, _>>()?;
        let mut held = Vec::new();
        for (source, time) in snaps {
            if hold_one(&tx, &r.tenant, &source, time, &reason, ctx.name())?.is_some() {
                held.push(format!("{source}/{time}"));
            }
        }
        tx.commit()?;
        held
    };
    if !held.is_empty() {
        st.audit(
            ctx.name(),
            "snapshot.hold",
            &format!("tenant/{}", r.tenant),
            json!({"reason": reason, "source": r.source, "from": r.from, "to": r.to, "snapshots": held}),
        )?;
    }
    Ok(Json(json!({"held": held.len(), "snapshots": held})))
}

/// `DELETE /snapshots/{tenant}/{source}/{time}/hold`: approval request
/// `snapshot.hold_release` (security officer or admin).
pub async fn release(
    State(st): State<St>,
    ctx: Ctx,
    Path((tenant, source, time)): Path<(String, String, i64)>,
) -> ApiResult<Response> {
    ctx.require(RELEASERS)?;
    validate::name(&tenant, "tenant")?;
    validate::source_ref(&source)?;
    if !ctx.sees(&tenant) {
        return Err(ApiError::forbidden());
    }
    let id = {
        let c = st.cat.conn();
        let id = catalog::holds::active(&c, &tenant, &source, time)?
            .ok_or_else(|| ApiError(StatusCode::NOT_FOUND, "snapshot is not under a legal hold".into()))?;
        let pending: bool = c.query_row(
            "SELECT EXISTS (SELECT 1 FROM quorum WHERE action = ?1 AND state IN ('pending','approved')
             AND json_extract(params, '$.hold_id') = ?2)",
            params![RELEASE_ACTION, id],
            |r| r.get(0),
        )?;
        if pending {
            return Err(ApiError::conflict("a release of this hold is already requested"));
        }
        id
    };
    let o = crate::quorum::request(
        &st,
        &ctx,
        RELEASE_ACTION,
        &format!("snapshot/{tenant}/{source}/{time}"),
        json!({"tenant": tenant, "source": source, "time": time, "hold_id": id}),
    )?;
    Ok(crate::quorum::accepted(o, json!({})))
}

/// Quorum execute arm of `snapshot.hold_release`.
pub fn execute(c: &Connection, p: &Value, approver: &str, requested_by: &str) -> ApiResult<()> {
    let id = p["hold_id"]
        .as_i64()
        .ok_or_else(|| ApiError::bad("quorum params: missing hold_id"))?;
    let n = c.execute(
        "UPDATE legal_holds SET state = 'released', released_by = ?2, approved_by = ?3, released_at = ?4
         WHERE id = ?1 AND state = 'active'",
        params![id, requested_by, approver, catalog::now()],
    )?;
    if n != 1 {
        return Err(ApiError::conflict("the hold is no longer active"));
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HoldFilter {
    tenant: Option<String>,
    /// `active`, `advisory`, `released`, `withdrawn`; default all (history)
    state: Option<String>,
}

pub fn row(r: &catalog::rusqlite::Row) -> catalog::rusqlite::Result<Value> {
    Ok(json!({
        "id": r.get::<_, i64>("id")?, "tenant": r.get::<_, String>("tenant")?,
        "source": r.get::<_, String>("source")?, "time": r.get::<_, i64>("time")?,
        "state": r.get::<_, String>("state")?, "reason": r.get::<_, String>("reason")?,
        "held_by": r.get::<_, String>("held_by")?, "held_at": r.get::<_, i64>("held_at")?,
        "origin": r.get::<_, Option<String>>("origin")?, "released_by": r.get::<_, Option<String>>("released_by")?,
        "approved_by": r.get::<_, Option<String>>("approved_by")?,
        "released_at": r.get::<_, Option<i64>>("released_at")?,
        "release_quorum": r.get::<_, Option<i64>>("release_quorum")?,
    }))
}

/// The hold columns plus the pending release request (`release_quorum`).
pub const COLUMNS: &str = "h.id, h.tenant, h.source, h.time, h.state, h.reason, h.held_by, h.held_at, h.origin,
    h.released_by, h.approved_by, h.released_at,
    (SELECT q.id FROM quorum q WHERE q.action = 'snapshot.hold_release' AND q.state IN ('pending','approved')
       AND json_extract(q.params, '$.hold_id') = h.id) AS release_quorum";

/// `GET /holds`: holds and their history, scoped like snapshots.
pub async fn list(State(st): State<St>, ctx: Ctx, Q(f): Q<HoldFilter>) -> ApiResult<Json<Value>> {
    let c = st.cat.conn();
    let rows = c
        .prepare(&format!(
            "SELECT {COLUMNS} FROM legal_holds h WHERE (?1 IS NULL OR h.tenant = ?1) AND (?2 IS NULL OR h.tenant = ?2)
             AND (?3 IS NULL OR h.state = ?3) ORDER BY h.id DESC LIMIT 5000"
        ))?
        .query_map(params![f.tenant, ctx.scope(), f.state], row)?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Json(Value::Array(rows)))
}

/// The tenant's active holds for a replication peer (advisory there).
pub fn active_infos(c: &Connection, tenant: &str) -> ApiResult<Vec<repl_proto::HoldInfo>> {
    Ok(c.prepare(
        "SELECT source, time, reason, held_by, held_at FROM legal_holds WHERE tenant = ?1 AND state = 'active'
         ORDER BY source, time",
    )?
    .query_map([tenant], |r| {
        Ok(repl_proto::HoldInfo {
            source: r.get(0)?,
            time: r.get::<_, i64>(1)? as u64,
            reason: r.get(2)?,
            held_by: r.get(3)?,
            held_at: r.get(4)?,
        })
    })?
    .collect::<Result<_, _>>()?)
}

/// The snapshot an alert offers to hold: the last one before an anomaly
/// ("hold last good snapshot") or the one of a legal-hold advisory.
pub fn alert_snapshot(kind: &str, key: Option<&str>, message: &str, tenant: Option<&str>) -> Value {
    let parse = |s: &str| -> Option<(String, i64)> {
        let (source, time) = s.rsplit_once('/')?;
        Some((source.to_owned(), time.parse().ok()?))
    };
    let found = match kind {
        "anomaly" => message
            .split("last snapshot before: ")
            .nth(1)
            .and_then(|s| parse(s.split_whitespace().next()?))
            .and_then(|(s, t)| Some((tenant?.to_owned(), s, t))),
        catalog::holds::ADVISORY_KIND => key
            .and_then(|k| k.strip_prefix(&format!("{}:", catalog::holds::ADVISORY_KIND)))
            .and_then(|k| {
                let (t, rest) = k.split_once('/')?;
                let (s, time) = parse(rest)?;
                Some((t.to_owned(), s, time))
            }),
        _ => None,
    };
    found.map_or(
        Value::Null,
        |(t, s, time)| json!({"tenant": t, "source": s, "time": time}),
    )
}
