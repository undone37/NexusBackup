//! "View as tenant" (Phase 19b, docs/control-plane.md "Impersonation").
//!
//! An admin's session can act inside one tenant: as a `viewer` of it at once
//! (read-only), or as its `tenant_admin` after approval (`tenant.impersonate`,
//! applied to the requesting session). The role is the intersection: never more
//! than the admin has, never more than the chosen tenant role, no downloads.
//! Every audit entry written meanwhile names the real admin and the tenant
//! (`alice impersonating:acme`) and is indexed under that tenant, so the
//! tenant's own admins read it in their audit view. It ends with the session or
//! `POST /auth/impersonation/end`; demoting or disabling the admin ends it too.

use crate::auth::{Ctx, User};
use crate::quorum::{accepted, Outcome};
use crate::{validate, ApiError, ApiResult, St, J};
use axum::extract::{Path, Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use catalog::rusqlite::{params, Connection, OptionalExtension};
use catalog::tenancy::IMPERSONATING;
use serde::Deserialize;
use serde_json::{json, Value};
use std::borrow::Cow;
use std::cell::RefCell;

/// Approval action of the elevated mode (`act as tenant admin`).
pub const ACTION: &str = "tenant.impersonate";

tokio::task_local! {
    /// (admin name, tenant) once the request's session turned out to impersonate
    static IMP: RefCell<Option<(String, String)>>;
}

/// Middleware: room for the request's impersonation (filled by the `Ctx` extractor).
pub async fn layer(req: Request, next: Next) -> Response {
    IMP.scope(RefCell::new(None), next.run(req)).await
}

/// The audit actor: `alice impersonating:acme` for the impersonating admin.
pub fn audit_actor(actor: &str) -> Cow<'_, str> {
    IMP.try_with(|c| {
        c.borrow()
            .as_ref()
            .and_then(|(u, t)| (actor == u).then(|| format!("{u}{IMPERSONATING}{t}")))
    })
    .ok()
    .flatten()
    .map_or(Cow::Borrowed(actor), Cow::Owned)
}

/// Applies the session's impersonation (`imp` = its tenant and role) to `user`;
/// returns the tenant. A session whose user is no admin any more, or whose
/// tenant is gone, loses it.
pub fn apply(
    c: &Connection,
    sid: &str,
    user: &mut User,
    imp: (Option<String>, Option<String>),
) -> ApiResult<Option<String>> {
    let (Some(tenant), Some(role)) = imp else {
        return Ok(None);
    };
    let exists = c
        .query_row("SELECT 1 FROM tenants WHERE name = ?1", [&tenant], |_| Ok(()))
        .optional()?
        .is_some();
    if user.role != "admin" || !exists {
        c.execute(
            "UPDATE sessions SET impersonating = NULL, impersonating_role = NULL WHERE id_hash = ?1",
            [sid],
        )?;
        return Ok(None);
    }
    user.role = role;
    user.tenant = Some(tenant.clone());
    user.can_download = false;
    let _ = IMP.try_with(|c| *c.borrow_mut() = Some((user.name.clone(), tenant.clone())));
    Ok(Some(tenant))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StartReq {
    /// act as the tenant's admin (needs approval) instead of viewing it
    #[serde(default)]
    elevated: bool,
}

/// `POST /tenants/{name}/impersonate`: admins, in a browser session only.
pub async fn start(State(st): State<St>, ctx: Ctx, Path(name): Path<String>, J(r): J<StartReq>) -> ApiResult<Response> {
    ctx.require(&["admin"])?;
    if ctx.token.is_some() || ctx.impersonating.is_some() || ctx.scope().is_some() {
        return Err(ApiError::forbidden());
    }
    validate::name(&name, "tenant")?;
    let session: i64 = {
        let c = st.cat.conn();
        c.query_row("SELECT 1 FROM tenants WHERE name = ?1", [&name], |_| Ok(()))
            .optional()?
            .ok_or_else(ApiError::not_found)?;
        c.query_row("SELECT id FROM sessions WHERE id_hash = ?1", [&ctx.sid], |r| r.get(0))?
    };
    let target = format!("tenant/{name}");
    if r.elevated {
        let p = json!({"tenant": name, "user": ctx.name(), "session": session, "role": "tenant_admin"});
        let o = crate::quorum::request(&st, &ctx, ACTION, &target, p)?;
        let extra = match o {
            Outcome::Direct { .. } => json!({"impersonating": {"tenant": name, "role": "tenant_admin"}}),
            Outcome::Pending(_) => json!({}),
        };
        return Ok(accepted(o, extra));
    }
    st.cat.conn().execute(
        "UPDATE sessions SET impersonating = ?2, impersonating_role = 'viewer' WHERE id_hash = ?1",
        params![ctx.sid, name],
    )?;
    st.audit(
        ctx.name(),
        "tenant.impersonate",
        &target,
        json!({"tenant": name, "role": "viewer", "session": session}),
    )?;
    Ok(Json(json!({"impersonating": {"tenant": name, "role": "viewer"}})).into_response())
}

/// Approved (or approvals off): the requesting session, if it still exists and
/// belongs to the requester, acts as the tenant's admin.
pub fn execute(c: &Connection, p: &Value, requested_by: &str) -> ApiResult<()> {
    let n = c.execute(
        "UPDATE sessions SET impersonating = ?2, impersonating_role = 'tenant_admin'
         WHERE id = ?1 AND user_id = (SELECT id FROM users WHERE name = ?3 AND role = 'admin')
           AND EXISTS (SELECT 1 FROM tenants WHERE name = ?2)",
        params![p["session"].as_i64(), p["tenant"].as_str(), requested_by],
    )?;
    if n != 1 {
        return Err(ApiError::conflict(
            "the requesting session has ended (or the tenant is gone): reject this request and ask again",
        ));
    }
    Ok(())
}

/// `POST /auth/impersonation/end`: back to the admin's own role.
pub async fn end(State(st): State<St>, ctx: Ctx) -> ApiResult<Response> {
    let Some(tenant) = ctx.impersonating.clone() else {
        return Err(ApiError(StatusCode::CONFLICT, "not impersonating".into()));
    };
    st.cat.conn().execute(
        "UPDATE sessions SET impersonating = NULL, impersonating_role = NULL WHERE id_hash = ?1",
        [&ctx.sid],
    )?;
    st.audit(
        ctx.name(),
        "tenant.impersonate_end",
        &format!("tenant/{tenant}"),
        json!({"tenant": tenant, "role": ctx.user.role}),
    )?;
    Ok(Json(json!({"ok": true})).into_response())
}
