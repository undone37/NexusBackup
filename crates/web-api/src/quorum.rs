//! Four-eyes approval. Gated requests are stored as `quorum` rows and answered
//! with 202 `{quorum_id}`; a *different* security_officer approves within 72 h.
//!
//! On approval the web-api itself executes the config actions listed in
//! [`WEB_ACTIONS`] (state → `executed`). Every other action (e.g. `gc`, raised
//! by the scheduler) is only marked `approved`; the scheduler picks it up and
//! sets `executed` when done.

use crate::auth::Ctx;
use crate::{ApiError, ApiResult, St, Q};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use catalog::rusqlite::{params, Connection, OptionalExtension};
use serde::Deserialize;
use serde_json::{json, Value};

pub const EXPIRY_SECS: i64 = 72 * 3600;

pub const WEB_ACTIONS: &[&str] = &[
    "tenant.delete",
    "tenant.update",
    "source.delete",
    "policy.delete",
    "policy.update",
    "group.delete",
    "group.update",
    "user.update",
    "agent.delete",
    "replication_peer.create",
    "replication_peer.delete",
    "replication_source.delete",
    "replication_source.update",
    "plugin.install",
    "plugin.disable",
    "plugin.activate",
    "plugin.remove",
    "plugin_key.add",
    "plugin_key.remove",
];

const SECRET_KEYS: &[&str] = &["password_hash", "totp_secret"];

/// Hides credentials in quorum params (shown in lists and the audit log):
/// password hashes, TOTP seeds and sealed secrets (e.g. an S3 `secret_key`
/// in a `tenant.update`), at any depth. The stored params keep them.
pub fn redact(mut v: Value) -> Value {
    fn walk(v: &mut Value) {
        match v {
            Value::Object(o) => {
                for (k, x) in o.iter_mut() {
                    if SECRET_KEYS.contains(&k.as_str()) || catalog::secret::SECRET_FIELDS.contains(&k.as_str()) {
                        *x = json!("<redacted>");
                    } else {
                        walk(x);
                    }
                }
            }
            Value::Array(a) => a.iter_mut().for_each(walk),
            _ => {}
        }
    }
    walk(&mut v);
    v
}

/// 202 `{quorum_id, ..extra}`.
pub fn accepted(id: i64, extra: Value) -> Response {
    let mut body = json!({"quorum_id": id});
    if let (Some(b), Some(e)) = (body.as_object_mut(), extra.as_object()) {
        b.extend(e.clone());
    }
    (StatusCode::ACCEPTED, Json(body)).into_response()
}

/// Creates a pending request (audited) and returns its id.
pub fn request(st: &St, ctx: &Ctx, action: &str, target: &str, params: Value) -> ApiResult<i64> {
    request_as(st, ctx.name(), action, target, params)
}

/// Like [`request`] on behalf of `by` (e.g. the replication key export that
/// enrollment requests for the peer's creator).
pub fn request_as(st: &St, by: &str, action: &str, target: &str, params: Value) -> ApiResult<i64> {
    let id = {
        let c = st.cat.conn();
        c.execute(
            "INSERT INTO quorum (action, params, requested_by, created, state) VALUES (?1, ?2, ?3, ?4, 'pending')",
            params![action, params.to_string(), by, catalog::now()],
        )?;
        c.last_insert_rowid()
    };
    st.audit(
        by,
        "quorum.request",
        &format!("quorum/{id}"),
        json!({"action": action, "target": target, "params": redact(params)}),
    )?;
    Ok(id)
}

/// Creates a pending request and answers 202 `{quorum_id}`.
pub fn gate(st: &St, ctx: &Ctx, action: &str, target: &str, params: Value) -> ApiResult<Response> {
    Ok(accepted(request(st, ctx, action, target, params)?, json!({})))
}

/// Marks pending requests older than 72 h as expired (audited).
pub fn expire(st: &St) -> ApiResult<()> {
    let ids: Vec<i64> = {
        let c = st.cat.conn();
        let cutoff = catalog::now() - EXPIRY_SECS;
        let ids = c
            .prepare("SELECT id FROM quorum WHERE state = 'pending' AND created <= ?1")?
            .query_map([cutoff], |r| r.get(0))?
            .collect::<Result<_, _>>()?;
        c.execute(
            "UPDATE quorum SET state = 'expired', decided_at = ?2 WHERE state = 'pending' AND created <= ?1",
            params![cutoff, catalog::now()],
        )?;
        ids
    };
    for id in ids {
        st.audit("web-api", "quorum.expire", &format!("quorum/{id}"), json!({}))?;
    }
    Ok(())
}

fn changed(n: usize) -> ApiResult<()> {
    if n == 1 {
        Ok(())
    } else {
        Err(ApiError::conflict("the object no longer exists"))
    }
}

fn int(p: &Value, k: &str) -> ApiResult<i64> {
    p[k].as_i64()
        .ok_or_else(|| ApiError::bad(format!("quorum params: missing {k}")))
}

/// Update requests carry the object as it was when the request was made
/// (`old`, shown to the approver as the diff). If it changed since, approving
/// would apply a different change than the one reviewed: refuse.
fn unchanged_since_request(c: &Connection, action: &str, p: &Value) -> ApiResult<()> {
    let current = match action {
        "policy.update" => crate::resources::policy_value(c, int(p, "id")?)?,
        "group.update" => crate::resources::group_value(c, int(p, "id")?)?,
        "tenant.update" => crate::resources::tenant_value(c, p["name"].as_str().unwrap_or_default())?,
        _ => return Ok(()),
    };
    if current.as_ref() != Some(&p["old"]) {
        return Err(ApiError::conflict(
            "the object changed since this request was made; reject it and request the change again",
        ));
    }
    Ok(())
}

/// Applies an approved action inside the caller's transaction.
/// Returns false for actions the scheduler executes.
fn execute(c: &Connection, action: &str, p: &Value, approver: &str, requested_by: &str) -> ApiResult<bool> {
    unchanged_since_request(c, action, p)?;
    match action {
        "tenant.update" => changed(c.execute(
            "UPDATE tenants SET offsite = ?2 WHERE name = ?1",
            params![p["name"].as_str(), p["offsite"].to_string()],
        )?)?,
        "tenant.delete" => {
            let name = p["name"].as_str().unwrap_or_default();
            crate::resources::tenant_deletable(c, name)?;
            changed(c.execute("DELETE FROM tenants WHERE name = ?1", [name])?)?;
        }
        "source.delete" => changed(c.execute("DELETE FROM sources WHERE id = ?1", [int(p, "id")?])?)?,
        "policy.delete" => changed(c.execute("DELETE FROM policies WHERE id = ?1", [int(p, "id")?])?)?,
        "group.delete" => changed(c.execute("DELETE FROM groups WHERE id = ?1", [int(p, "id")?])?)?,
        "policy.update" => changed(c.execute(
            "UPDATE policies SET name = ?2, schedule = ?3, gfs = ?4, offsite = ?5 WHERE id = ?1",
            params![
                int(p, "id")?,
                p["name"].as_str(),
                p["schedule"].as_str(),
                p["gfs"].to_string(),
                p["offsite"].as_bool().unwrap_or(true)
            ],
        )?)?,
        "group.update" => changed(c.execute(
            "UPDATE groups SET source_id = ?2, policy_id = ?3, name = ?4, guests = ?5 WHERE id = ?1",
            params![
                int(p, "id")?,
                int(p, "source_id")?,
                int(p, "policy_id")?,
                p["name"].as_str(),
                p["guests"].to_string()
            ],
        )?)?,
        "user.update" => crate::resources::apply_user_update(c, p)?,
        "agent.delete" => {
            let id = p["id"].as_str().unwrap_or_default();
            if crate::agents::agent_in_use(c, id)? {
                return Err(ApiError::conflict("agent is still used by a source"));
            }
            changed(c.execute("DELETE FROM agents WHERE id = ?1", [id])?)?
        }
        a if a.starts_with("replication_") => return crate::replication::execute(c, a, p),
        a if a.starts_with("plugin") => return crate::plugins::execute(c, a, p, approver, requested_by),
        _ => return Ok(false),
    }
    Ok(true)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuorumFilter {
    state: Option<String>,
}

/// Readable by admin, security_officer and operator (an admin needs to see
/// the state of their own requests); not by tenant users.
pub async fn list_quorum(State(st): State<St>, ctx: Ctx, Q(f): Q<QuorumFilter>) -> ApiResult<Json<Value>> {
    ctx.require(&["admin", "security_officer", "operator"])?;
    expire(&st)?;
    let c = st.cat.conn();
    let mut stmt = c.prepare(
        "SELECT id, action, params, requested_by, created, decided_by, decided_at, state FROM quorum
         WHERE ?1 IS NULL OR state = ?1 ORDER BY id DESC LIMIT 500",
    )?;
    let rows = stmt
        .query_map([&f.state], |r| {
            let p: String = r.get(2)?;
            let created: i64 = r.get(4)?;
            Ok(json!({
                "id": r.get::<_, i64>(0)?, "action": r.get::<_, String>(1)?,
                "params": redact(serde_json::from_str(&p).unwrap_or(Value::Null)),
                "requested_by": r.get::<_, String>(3)?, "created": created, "expires": created + EXPIRY_SECS,
                "decided_by": r.get::<_, Option<String>>(5)?, "decided_at": r.get::<_, Option<i64>>(6)?,
                "state": r.get::<_, String>(7)?,
            }))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Json(Value::Array(rows)))
}

fn load_pending(st: &St, id: i64) -> ApiResult<(String, Value, String)> {
    let (action, p, by, state): (String, String, String, String) = st
        .cat
        .conn()
        .query_row(
            "SELECT action, params, requested_by, state FROM quorum WHERE id = ?1",
            [id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .optional()?
        .ok_or_else(ApiError::not_found)?;
    if state != "pending" {
        return Err(ApiError::conflict(format!("request is {state}")));
    }
    Ok((action, serde_json::from_str(&p).unwrap_or(Value::Null), by))
}

pub async fn approve(State(st): State<St>, ctx: Ctx, Path(id): Path<i64>) -> ApiResult<Json<Value>> {
    ctx.require(&["security_officer"])?;
    expire(&st)?;
    let (action, p, requested_by) = load_pending(&st, id)?;
    if requested_by == ctx.name() {
        return Err(ApiError(
            StatusCode::FORBIDDEN,
            "the requester cannot approve their own request".into(),
        ));
    }
    let executed = {
        let mut c = st.cat.conn();
        let tx = c.transaction()?;
        let executed = execute(&tx, &action, &p, ctx.name(), &requested_by)?;
        let state = if executed { "executed" } else { "approved" };
        changed(tx.execute(
            "UPDATE quorum SET state = ?2, decided_by = ?3, decided_at = ?4 WHERE id = ?1 AND state = 'pending'",
            params![id, state, ctx.name(), catalog::now()],
        )?)?;
        tx.commit()?;
        executed
    };
    let state = if executed { "executed" } else { "approved" };
    st.audit(
        ctx.name(),
        "quorum.approve",
        &format!("quorum/{id}"),
        json!({"action": action, "requested_by": requested_by, "state": state}),
    )?;
    if executed {
        crate::plugins::after_approve(&st, &action);
        st.audit(
            &requested_by,
            &action,
            &format!("quorum/{id}"),
            json!({"approved_by": ctx.name(), "params": redact(p)}),
        )?;
    }
    Ok(Json(json!({"id": id, "state": state})))
}

pub async fn reject(State(st): State<St>, ctx: Ctx, Path(id): Path<i64>) -> ApiResult<Json<Value>> {
    ctx.require(&["security_officer"])?;
    expire(&st)?;
    let (action, p, requested_by) = load_pending(&st, id)?;
    crate::plugins::after_reject(&st, &action, &p);
    changed(st.cat.conn().execute(
        "UPDATE quorum SET state = 'rejected', decided_by = ?2, decided_at = ?3 WHERE id = ?1 AND state = 'pending'",
        params![id, ctx.name(), catalog::now()],
    )?)?;
    st.audit(
        ctx.name(),
        "quorum.reject",
        &format!("quorum/{id}"),
        json!({"action": action, "requested_by": requested_by}),
    )?;
    Ok(Json(json!({"id": id, "state": "rejected"})))
}
