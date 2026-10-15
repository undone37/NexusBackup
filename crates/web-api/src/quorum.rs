//! Four-eyes approval (optional, plan §2 "Approval system"). With approvals
//! enabled (setting `approvals_enabled`), gated requests are stored as `quorum`
//! rows and answered with 202 `{quorum_id}`; a *different* admin or
//! security_officer approves within 72 h. With approvals disabled the same
//! requests execute directly (audited with `"approvals": "disabled"`).
//!
//! On approval the web-api itself executes the config actions listed in
//! [`WEB_ACTIONS`] (state → `executed`). Every other action (e.g. `gc`, raised
//! by the scheduler) is only marked `approved`; the scheduler picks it up and
//! sets `executed` when done.
//!
//! Phase 33, tenant-side approvers (`catalog::approvers`): a request that
//! destroys or weakens the data of a tenant that opted in also needs one of that
//! tenant's eligible `tenant_admin` accounts (`quorum_tenants`, one row per such
//! tenant). The provider's approval is recorded (`quorum.approved_by`) while a
//! tenant decision is open; the request executes with the last missing decision.
//! A tenant approver's refusal is final. With approvals disabled such requests
//! still wait for the tenants (the requester's own decision stands for the
//! provider side). Impersonating sessions and API tokens never decide for a tenant.

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
    crate::replication::REOPEN,
    "plugin.install",
    "plugin.disable",
    "plugin.activate",
    "plugin.remove",
    "plugin_key.add",
    "plugin_key.remove",
    "approvals.disable",
    "oidc.update",
    "update.apply",
    "settings.anomaly",
    "settings.forwarding",
    "security.session",
    "security.mgmt_allow",
    crate::passkeys::ACTION,
    crate::firewall::ACTION,
    catalog::holds::RELEASE_ACTION,
    "disks.create_array",
    "disks.add_spare",
    "disks.replace",
    "disks.grow",
    crate::network::ACTION,
    catalog::vault::ENABLE,
    catalog::vault::RESTORE,
    catalog::tenants::DISABLE_ACTION,
    crate::impersonate::ACTION,
    crate::incident::LEAVE,
    catalog::tenants::LOCKDOWN_LIFT,
    catalog::incident::FREEZE_LIFT,
    crate::keep::ACTION,
    crate::keep::SETTING_ACTION,
    crate::tenant_idp::ACTION,
    catalog::agent_updates::ROLLBACK_ACTION,
    catalog::anomaly::LOWER_ACTION,
    catalog::elevation::ACTION,
    catalog::elevation::SETTING_ACTION,
    catalog::approvers::DISABLE_ACTION,
];

/// Who may approve or reject requests (never their own: see [`approve`]).
pub const APPROVERS: &[&str] = &["admin", "security_officer"];
/// Phase 33: tenant admins decide the tenant side of requests concerning their tenant.
const DECIDERS: &[&str] = &["admin", "security_officer", "tenant_admin"];

const SECRET_KEYS: &[&str] = &[
    "password_hash",
    "totp_secret",
    "activation_hash",
    "client_secret",
    "download_token",
];

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
            // e.g. the sealed header values of a `settings.forwarding` request
            Value::String(s) if catalog::secret::is_sealed(s) => *v = json!("<redacted>"),
            Value::Array(a) => a.iter_mut().for_each(walk),
            _ => {}
        }
    }
    walk(&mut v);
    v
}

/// What became of a gated request.
#[derive(Debug)]
pub enum Outcome {
    /// approvals enabled: a pending `quorum` row
    Pending(i64),
    /// approvals disabled: executed by the web-api (`quorum_id: None`) or, for
    /// actions the scheduler executes, recorded as an `approved` quorum row;
    /// `extra` is what an approver would have been shown
    Direct { quorum_id: Option<i64>, extra: Value },
}

pub(crate) fn merge(body: &mut Value, extra: &Value) {
    if let (Some(b), Some(e)) = (body.as_object_mut(), extra.as_object()) {
        b.extend(e.clone());
    }
}

/// Pending: 202 `{quorum_id, ..extra}`. Direct: 200 `{approvals: "disabled",
/// executed, ..extra}` (+ `quorum_id`, `state: "approved"` for scheduler actions).
pub fn accepted(o: Outcome, extra: Value) -> Response {
    match o {
        Outcome::Pending(id) => {
            let mut body = json!({"quorum_id": id});
            merge(&mut body, &extra);
            (StatusCode::ACCEPTED, Json(body)).into_response()
        }
        Outcome::Direct { quorum_id, extra: done } => {
            let mut body = json!({"approvals": "disabled", "executed": quorum_id.is_none()});
            if let Some(id) = quorum_id {
                body["quorum_id"] = json!(id);
                body["state"] = json!("approved");
            }
            merge(&mut body, &done);
            merge(&mut body, &extra);
            (StatusCode::OK, Json(body)).into_response()
        }
    }
}

/// Whether quorum approvals are on (appliance setting, catalog v9).
pub fn enabled(st: &St) -> ApiResult<bool> {
    Ok(catalog::approvals_enabled(&st.cat.conn())?)
}

/// Gates `action`: a pending request (audited) when approvals are enabled,
/// otherwise direct execution (see [`Outcome`]).
pub fn request(st: &St, ctx: &Ctx, action: &str, target: &str, params: Value) -> ApiResult<Outcome> {
    request_as(st, ctx.name(), action, target, params)
}

/// Like [`request`] on behalf of `by` (e.g. the replication key export that
/// enrollment requests for the peer's creator).
pub fn request_as(st: &St, by: &str, action: &str, target: &str, params: Value) -> ApiResult<Outcome> {
    if !enabled(st)? {
        // Phase 33: tenants with their own approvers are asked even with approvals disabled
        let waiting = {
            let c = st.cat.conn();
            let mut w = Vec::new();
            for t in catalog::approvers::gated(&c, action, &params)? {
                if !own_consent(&c, &t, by)? {
                    w.push(t);
                }
            }
            w
        };
        if waiting.is_empty() {
            return direct(st, by, action, target, params);
        }
        let id = pending(st, by, action, target, params)?;
        // the requester's own decision stands for the provider side (approvals are disabled)
        st.cat.conn().execute(
            "UPDATE quorum SET approved_by = ?2, approved_at = ?3 WHERE id = ?1",
            params![id, by, catalog::now()],
        )?;
        return Ok(Outcome::Pending(id));
    }
    Ok(Outcome::Pending(pending(st, by, action, target, params)?))
}

/// Phase 33: a request by an eligible tenant approver of `tenant` is that tenant's consent.
fn own_consent(c: &Connection, tenant: &str, by: &str) -> ApiResult<bool> {
    Ok(catalog::approvers::eligible_from(c, tenant, by)?.is_some_and(|t| t <= catalog::now()))
}

/// Phase 33: records the opted-in tenants a request concerns (also tenants that
/// opted in after it was made) and returns those still undecided.
fn tenant_gates(c: &Connection, id: i64, action: &str, p: &Value, by: &str) -> ApiResult<Vec<String>> {
    for t in catalog::approvers::gated(c, action, p)? {
        let own = own_consent(c, &t, by)?;
        c.execute(
            "INSERT OR IGNORE INTO quorum_tenants (quorum_id, tenant, decided_by, decided_at, decision)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                id,
                t,
                own.then_some(by),
                own.then(catalog::now),
                own.then_some("requested")
            ],
        )?;
    }
    waiting_for(c, id)
}

/// The tenants whose decision is still open.
fn waiting_for(c: &Connection, id: i64) -> ApiResult<Vec<String>> {
    Ok(
        c.prepare("SELECT tenant FROM quorum_tenants WHERE quorum_id = ?1 AND decision IS NULL ORDER BY tenant")?
            .query_map([id], |r| r.get(0))?
            .collect::<Result<_, _>>()?,
    )
}

/// A pending request regardless of the setting (`approvals.disable`).
pub fn pending(st: &St, by: &str, action: &str, target: &str, params: Value) -> ApiResult<i64> {
    let (id, tenants) = {
        let c = st.cat.conn();
        c.execute(
            "INSERT INTO quorum (action, params, requested_by, created, state) VALUES (?1, ?2, ?3, ?4, 'pending')",
            params![action, params.to_string(), by, catalog::now()],
        )?;
        let id = c.last_insert_rowid();
        (id, tenant_gates(&c, id, action, &params, by)?)
    };
    let mut details = json!({"action": action, "target": target, "params": redact(params)});
    if !tenants.is_empty() {
        details["tenant_approvers"] = json!(tenants);
    }
    st.audit(by, "quorum.request", &format!("quorum/{id}"), details)?;
    Ok(id)
}

/// Approvals disabled: executes `action` at once, still audited (actor = the
/// requester, details `"approvals": "disabled"`). Actions the scheduler
/// executes get an `approved` quorum row (decided by the requester) as their
/// work item.
fn direct(st: &St, by: &str, action: &str, target: &str, params: Value) -> ApiResult<Outcome> {
    let (quorum_id, extra) = {
        let mut c = st.cat.conn();
        let tx = c.transaction()?;
        let out = execute(&tx, action, &params, by, by)?;
        let quorum_id = match out {
            Some(_) => None,
            None => {
                let now = catalog::now();
                tx.execute(
                    "INSERT INTO quorum (action, params, requested_by, created, decided_by, decided_at, state)
                     VALUES (?1, ?2, ?3, ?4, ?3, ?4, 'approved')",
                    params![action, params.to_string(), by, now],
                )?;
                Some(tx.last_insert_rowid())
            }
        };
        tx.commit()?;
        (quorum_id, out.unwrap_or_else(|| json!({})))
    };
    let mut details = json!({"approvals": "disabled", "params": redact(params.clone())});
    if let Some(id) = quorum_id {
        details["quorum_id"] = json!(id);
    }
    st.audit(by, action, target, details)?;
    if quorum_id.is_none() {
        crate::plugins::after_approve(st, action);
        crate::settings::after_approve(st, action, by, &params);
        crate::hardware::after_approve(st, action, by, &params, None);
        crate::network::after_approve(st, action, by, &params, None);
    }
    Ok(Outcome::Direct { quorum_id, extra })
}

/// Gates `action` and answers accordingly (see [`accepted`]).
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
        "settings.anomaly" => crate::storage::anomaly_value(c)?,
        "settings.forwarding" => crate::forwarding::value(c)?,
        catalog::anomaly::LOWER_ACTION => crate::changes::sensitivity_value(c, p)?,
        catalog::elevation::SETTING_ACTION => crate::elevation::settings_value(c)?,
        _ => return Ok(()),
    };
    if current.as_ref() != Some(&p["old"]) {
        return Err(ApiError::conflict(
            "the object changed since this request was made; reject it and request the change again",
        ));
    }
    Ok(())
}

/// Applies an approved action inside the caller's transaction. Returns `None`
/// for actions the scheduler executes, else what the approver is shown (e.g.
/// the second half of an activation code).
fn execute(c: &Connection, action: &str, p: &Value, approver: &str, requested_by: &str) -> ApiResult<Option<Value>> {
    unchanged_since_request(c, action, p)?;
    match action {
        "tenant.update" => changed(c.execute(
            "UPDATE tenants SET offsite = ?2 WHERE name = ?1",
            params![p["name"].as_str(), p["offsite"].to_string()],
        )?)?,
        "tenant.delete" => {
            let name = p["name"].as_str().unwrap_or_default();
            crate::resources::tenant_deletable(c, name)?;
            catalog::tenancy::bury(c, name, requested_by)?;
            catalog::fleet::forget_tenant(c, name)?;
            c.execute("DELETE FROM tenant_idps WHERE tenant = ?1", [name])?;
            c.execute("DELETE FROM tenant_approvals WHERE tenant = ?1", [name])?;
            changed(c.execute("DELETE FROM tenants WHERE name = ?1", [name])?)?;
            catalog::tenant_key::remove(c, name)?;
        }
        "source.delete" => changed(c.execute("DELETE FROM sources WHERE id = ?1", [int(p, "id")?])?)?,
        "policy.delete" => changed(c.execute("DELETE FROM policies WHERE id = ?1", [int(p, "id")?])?)?,
        "group.delete" => changed(c.execute("DELETE FROM groups WHERE id = ?1", [int(p, "id")?])?)?,
        "policy.update" => {
            changed(c.execute(
                "UPDATE policies SET name = ?2, schedule = ?3, gfs = ?4, offsite = ?5, retry = ?6, blackout = ?7,
             sla_minutes = ?8, require_consistency = ?9 WHERE id = ?1",
                params![
                int(p, "id")?,
                p["name"].as_str(),
                p["schedule"].as_str(),
                p["gfs"].to_string(),
                p["offsite"].as_bool().unwrap_or(true),
                p.get("retry").map_or_else(|| json!(catalog::schedule::Retry::default()), Clone::clone).to_string(),
                p.get("blackout").map_or_else(|| json!([]), Clone::clone).to_string(),
                p["sla_minutes"].as_u64(),
                // requests made before v19 carry none: off
                p.get("require_consistency")
                    .map_or_else(|| r#"{"mode":"off","level":"crash"}"#.to_owned(), std::string::ToString::to_string)
            ],
            )?)?;
            c.execute(
                "UPDATE policies SET file_filters = ?2 WHERE id = ?1",
                params![int(p, "id")?, p.get("file_filters").unwrap_or(&json!({})).to_string()],
            )?;
            // Phase 19b (requests made before carry none: unchanged)
            if let Some(t) = p.get("tier") {
                c.execute(
                    "UPDATE policies SET tier = ?2 WHERE id = ?1",
                    params![int(p, "id")?, t.as_str()],
                )?;
            }
        }
        "group.update" => {
            crate::tenancy::check_requested_policy(c, p, requested_by)?;
            changed(c.execute(
                "UPDATE groups SET source_id = ?2, policy_id = ?3, name = ?4, guests = ?5, mode = ?6, selector = ?7, \
             exclude = ?8, timezone = ?9 WHERE id = ?1",
                params![
                    int(p, "id")?,
                    int(p, "source_id")?,
                    int(p, "policy_id")?,
                    p["name"].as_str(),
                    p["guests"].to_string(),
                    // requests made before v12 carry no mode: explicit
                    p["mode"].as_str().unwrap_or("explicit"),
                    p.get("selector").unwrap_or(&json!([])).to_string(),
                    p.get("exclude").unwrap_or(&json!([])).to_string(),
                    p["timezone"].as_str().unwrap_or("UTC")
                ],
            )?)?;
            // Phase 15e/f fields (requests made before carry none: defaults)
            c.execute(
                "UPDATE groups SET exclude_disks = ?2, exclude_disks_mode = ?3, parallel_guests = ?4 WHERE id = ?1",
                params![
                    int(p, "id")?,
                    p.get("exclude_disks").unwrap_or(&json!({})).to_string(),
                    p["exclude_disks_mode"].as_str().unwrap_or("placeholder"),
                    p["parallel_guests"].as_u64().unwrap_or(1)
                ],
            )?;
        }
        "user.update" => return crate::resources::apply_user_update(c, p).map(Some),
        "approvals.disable" => {
            if catalog::vault::enabled(c)? {
                return Err(ApiError::conflict("vault mode is on: approvals cannot be disabled"));
            }
            catalog::set_setting(c, "approvals_enabled", "false")?;
        }
        catalog::vault::ENABLE => crate::vault::execute_enable(c, requested_by)?,
        // carried out at the console with the recovery key (nexus-setup vault-disable)
        catalog::vault::DISABLE => return Ok(None),
        catalog::vault::RESTORE => return crate::vault::execute_restore(c, p, requested_by).map(Some),
        catalog::tenants::DISABLE_ACTION => crate::tenants::execute_disable(c, p, requested_by)?,
        crate::impersonate::ACTION => crate::impersonate::execute(c, p, requested_by)?,
        "oidc.update" => crate::oidc::execute(c, p)?,
        // the request file for nexus-update is written after the commit (settings::after_approve)
        "update.apply" => {}
        // the request for nexus-disks likewise (hardware::after_approve)
        a if a.starts_with("disks.") => {}
        // and for nexus-net (network::after_approve)
        crate::network::ACTION => {}
        "settings.anomaly" => catalog::set_setting(c, crate::storage::ANOMALY_SETTING, &p["anomaly"].to_string())?,
        "settings.forwarding" => catalog::set_setting(c, catalog::forwarding::SETTING, &p["forwarding"].to_string())?,
        a if a.starts_with("security.") => crate::access::execute(c, a, p)?,
        crate::firewall::ACTION => crate::firewall::execute(c, p)?,
        catalog::holds::RELEASE_ACTION => crate::holds::execute(c, p, approver, requested_by)?,
        crate::incident::LEAVE => crate::incident::execute(c, p, approver, requested_by)?,
        catalog::tenants::LOCKDOWN_LIFT => crate::lockdown::execute(c, p, approver, requested_by)?,
        catalog::incident::FREEZE_LIFT => crate::incident::execute_freeze_lift(c, p, approver)?,
        crate::keep::ACTION => return crate::keep::execute(c, p, requested_by).map(Some),
        crate::keep::SETTING_ACTION => crate::keep::execute_setting(c, p)?,
        crate::tenant_idp::ACTION => crate::tenant_idp::execute(c, p)?,
        catalog::approvers::DISABLE_ACTION => crate::approvers::execute_disable(c, p)?,
        catalog::agent_updates::ROLLBACK_ACTION => crate::agent_updates::execute_rollback(c, p)?,
        catalog::anomaly::LOWER_ACTION => crate::changes::execute_sensitivity(c, p, requested_by)?,
        catalog::elevation::ACTION => return crate::elevation::execute(c, p).map(Some),
        catalog::elevation::SETTING_ACTION => crate::elevation::execute_settings(c, p)?,
        "agent.delete" => {
            let id = p["id"].as_str().unwrap_or_default();
            if crate::agents::agent_in_use(c, id)? {
                return Err(ApiError::conflict("agent is still used by a source"));
            }
            changed(c.execute("DELETE FROM agents WHERE id = ?1", [id])?)?;
        }
        a if a.starts_with("replication_") || a == crate::replication::REOPEN => {
            return Ok(crate::replication::execute(c, a, p)?.then(|| json!({})));
        }
        a if a.starts_with("plugin") => {
            return Ok(crate::plugins::execute(c, a, p, approver, requested_by)?.then(|| json!({})));
        }
        _ => return Ok(None),
    }
    Ok(Some(json!({})))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuorumFilter {
    state: Option<String>,
}

/// Readable by admin, security_officer and operator (an admin needs to see
/// the state of their own requests); tenant admins see their own requests
/// only and (Phase 33) those their tenant must co-approve; not by tenant users.
/// Each row has the provider's recorded approval (`approved_by`, while tenant
/// decisions are open) and the tenants' decisions (`tenant_approvals`).
pub async fn list_quorum(State(st): State<St>, ctx: Ctx, Q(f): Q<QuorumFilter>) -> ApiResult<Json<Value>> {
    ctx.require(&["admin", "security_officer", "operator", "tenant_admin"])?;
    expire(&st)?;
    let own = ctx.is_tenant_admin().then(|| ctx.name().to_owned());
    let tenant = own.as_ref().and(ctx.scope());
    let c = st.cat.conn();
    let mut stmt = c.prepare(
        "SELECT id, action, params, requested_by, created, decided_by, decided_at, state, approved_by, approved_at,
           (SELECT json_group_array(json_object('tenant', t.tenant, 'decided_by', t.decided_by,
              'decided_at', t.decided_at, 'decision', t.decision)) FROM quorum_tenants t WHERE t.quorum_id = quorum.id)
         FROM quorum
         WHERE (?1 IS NULL OR state = ?1)
           AND (?2 IS NULL OR requested_by = ?2 OR id IN (SELECT quorum_id FROM quorum_tenants WHERE tenant = ?3))
         ORDER BY id DESC LIMIT 500",
    )?;
    let rows = stmt
        .query_map(params![f.state, own, tenant], |r| {
            let p: String = r.get(2)?;
            let created: i64 = r.get(4)?;
            let tenants: Value = r
                .get::<_, Option<String>>(10)?
                .and_then(|t| serde_json::from_str(&t).ok())
                .unwrap_or_else(|| json!([]));
            Ok(json!({
                "id": r.get::<_, i64>(0)?, "action": r.get::<_, String>(1)?,
                "params": redact(serde_json::from_str(&p).unwrap_or(Value::Null)),
                "requested_by": r.get::<_, String>(3)?, "created": created, "expires": created + EXPIRY_SECS,
                "decided_by": r.get::<_, Option<String>>(5)?, "decided_at": r.get::<_, Option<i64>>(6)?,
                "state": r.get::<_, String>(7)?,
                "approved_by": r.get::<_, Option<String>>(8)?, "approved_at": r.get::<_, Option<i64>>(9)?,
                "tenant_approvals": tenants,
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

/// Phase 33: an impersonating session or an API token acting as a tenant admin
/// never decides, nor does a tenant admin decide requests that do not concern its
/// tenant (403, as before tenant-side approvers; an unknown request stays 404).
fn refuse_borrowed(st: &St, ctx: &Ctx, id: i64) -> ApiResult<()> {
    if !ctx.is_tenant_admin() {
        return Ok(());
    }
    if ctx.impersonating.is_some() || ctx.token.is_some() {
        return Err(ApiError::forbidden());
    }
    let (exists, concerns): (bool, bool) = st.cat.conn().query_row(
        "SELECT EXISTS (SELECT 1 FROM quorum WHERE id = ?1),
                EXISTS (SELECT 1 FROM quorum_tenants WHERE quorum_id = ?1 AND tenant = ?2)",
        params![id, ctx.scope()],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    match (exists, concerns) {
        (false, _) => Err(ApiError::not_found()),
        (true, false) => Err(ApiError::forbidden()),
        (true, true) => Ok(()),
    }
}

/// Phase 33: the tenant a tenant admin decides for: its tenant must still be
/// open on the request and its wait over; never while impersonating or by token.
fn tenant_decider(st: &St, ctx: &Ctx, id: i64) -> ApiResult<String> {
    refuse_borrowed(st, ctx, id)?;
    let tenant = ctx.scope().ok_or_else(ApiError::forbidden)?.to_owned();
    let c = st.cat.conn();
    let open: bool = c.query_row(
        "SELECT EXISTS (SELECT 1 FROM quorum_tenants WHERE quorum_id = ?1 AND tenant = ?2 AND decision IS NULL)",
        params![id, tenant],
        |r| r.get(0),
    )?;
    if !open {
        return Err(ApiError(
            StatusCode::FORBIDDEN,
            "this request does not wait for your tenant's decision".into(),
        ));
    }
    match catalog::approvers::eligible_from(&c, &tenant, ctx.name())? {
        Some(t) if t <= catalog::now() => Ok(tenant),
        Some(t) => Err(ApiError(
            StatusCode::FORBIDDEN,
            format!("a new tenant approver may decide 24 hours after becoming one, from {t} (unix time)"),
        )),
        None => Err(ApiError::forbidden()),
    }
}

/// Approves a request. Provider side (admins, security officers): executes it,
/// or records the approval while tenants still have to decide. Tenant side
/// (Phase 33, a tenant admin of a tenant the request waits for): records the
/// tenant's approval; the last missing decision executes it.
pub async fn approve(State(st): State<St>, ctx: Ctx, Path(id): Path<i64>) -> ApiResult<Json<Value>> {
    ctx.require(DECIDERS)?;
    refuse_borrowed(&st, &ctx, id)?;
    expire(&st)?;
    let (action, p, requested_by) = load_pending(&st, id)?;
    if requested_by == ctx.name() {
        return Err(ApiError(
            StatusCode::FORBIDDEN,
            "the requester cannot approve their own request".into(),
        ));
    }
    // the provider's approver when a tenant decides last
    let mut recorded: Option<String> = None;
    if ctx.is_tenant_admin() {
        let tenant = tenant_decider(&st, &ctx, id)?;
        let (waiting, approved_by) = {
            let c = st.cat.conn();
            changed(c.execute(
                "UPDATE quorum_tenants SET decided_by = ?3, decided_at = ?4, decision = 'approved'
                 WHERE quorum_id = ?1 AND tenant = ?2 AND decision IS NULL",
                params![id, tenant, ctx.name(), catalog::now()],
            )?)?;
            let by: Option<String> = c.query_row("SELECT approved_by FROM quorum WHERE id = ?1", [id], |r| r.get(0))?;
            (tenant_gates(&c, id, &action, &p, &requested_by)?, by)
        };
        st.audit(
            ctx.name(),
            "quorum.approve",
            &format!("quorum/{id}"),
            json!({"action": action, "requested_by": requested_by, "side": "tenant", "tenant": tenant,
                   "waiting_for": waiting}),
        )?;
        match approved_by {
            Some(by) if waiting.is_empty() => recorded = Some(by),
            by => {
                return Ok(Json(json!({"id": id, "state": "pending", "waiting_for": waiting,
                                      "provider_approved": by.is_some()})))
            }
        }
    } else {
        let waiting = {
            let c = st.cat.conn();
            let waiting = tenant_gates(&c, id, &action, &p, &requested_by)?;
            if !waiting.is_empty() {
                let n = c.execute(
                    "UPDATE quorum SET approved_by = ?2, approved_at = ?3 WHERE id = ?1 AND approved_by IS NULL",
                    params![id, ctx.name(), catalog::now()],
                )?;
                if n != 1 {
                    return Err(ApiError::conflict(format!(
                        "already approved by the provider; waiting for the approvers of {}",
                        waiting.join(", ")
                    )));
                }
            }
            waiting
        };
        if !waiting.is_empty() {
            st.audit(
                ctx.name(),
                "quorum.approve",
                &format!("quorum/{id}"),
                json!({"action": action, "requested_by": requested_by, "state": "pending", "waiting_for": waiting}),
            )?;
            return Ok(Json(
                json!({"id": id, "state": "pending", "waiting_for": waiting, "provider_approved": true}),
            ));
        }
    }
    let approver = recorded.unwrap_or_else(|| ctx.name().to_owned());
    let out = {
        let mut c = st.cat.conn();
        let tx = c.transaction()?;
        let out = execute(&tx, &action, &p, &approver, &requested_by)?;
        let state = if out.is_some() { "executed" } else { "approved" };
        changed(tx.execute(
            "UPDATE quorum SET state = ?2, decided_by = ?3, decided_at = ?4 WHERE id = ?1 AND state = 'pending'",
            params![id, state, approver, catalog::now()],
        )?)?;
        tx.commit()?;
        out
    };
    let executed = out.is_some();
    let state = if executed { "executed" } else { "approved" };
    st.audit(
        ctx.name(),
        "quorum.approve",
        &format!("quorum/{id}"),
        json!({"action": action, "requested_by": requested_by, "state": state, "approved_by": approver}),
    )?;
    if executed {
        crate::plugins::after_approve(&st, &action);
        crate::settings::after_approve(&st, &action, &requested_by, &p);
        crate::hardware::after_approve(&st, &action, &requested_by, &p, Some(id));
        crate::network::after_approve(&st, &action, &requested_by, &p, Some(id));
        st.audit(
            &requested_by,
            &action,
            &format!("quorum/{id}"),
            json!({"approved_by": approver, "params": redact(p)}),
        )?;
    }
    let mut body = json!({"id": id, "state": state});
    merge(&mut body, &out.unwrap_or(Value::Null));
    Ok(Json(body))
}

/// Rejects a request (provider side or, Phase 33, a tenant approver whose
/// tenant the request waits for: final, the provider cannot override it).
pub async fn reject(State(st): State<St>, ctx: Ctx, Path(id): Path<i64>) -> ApiResult<Json<Value>> {
    ctx.require(DECIDERS)?;
    refuse_borrowed(&st, &ctx, id)?;
    expire(&st)?;
    let (action, p, requested_by) = load_pending(&st, id)?;
    let tenant = if ctx.is_tenant_admin() {
        Some(tenant_decider(&st, &ctx, id)?)
    } else {
        None
    };
    crate::plugins::after_reject(&st, &action, &p);
    {
        let mut c = st.cat.conn();
        let tx = c.transaction()?;
        changed(tx.execute(
            "UPDATE quorum SET state = 'rejected', decided_by = ?2, decided_at = ?3 WHERE id = ?1 AND state = 'pending'",
            params![id, ctx.name(), catalog::now()],
        )?)?;
        if let Some(t) = &tenant {
            tx.execute(
                "UPDATE quorum_tenants SET decided_by = ?3, decided_at = ?4, decision = 'rejected'
                 WHERE quorum_id = ?1 AND tenant = ?2",
                params![id, t, ctx.name(), catalog::now()],
            )?;
        }
        tx.commit()?;
    }
    let mut details = json!({"action": action, "requested_by": requested_by});
    if let Some(t) = tenant {
        details["side"] = json!("tenant");
        details["tenant"] = json!(t);
    }
    st.audit(ctx.name(), "quorum.reject", &format!("quorum/{id}"), details)?;
    Ok(Json(json!({"id": id, "state": "rejected"})))
}
