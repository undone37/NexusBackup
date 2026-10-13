//! A tenant's own OIDC identity provider (Phase 23a, catalog v37 `tenant_idps`,
//! docs/control-plane.md "Tenant identity providers").
//!
//! Same settings and login flow as the appliance's IdP (crate::oidc), with:
//! - mappings limited to the tenant roles (`tenant_admin`, `tenant_user`,
//!   `viewer`) of this tenant (an empty tenant list means this tenant);
//! - `domains`: e-mail domains of the tenant's users, unique across tenants. The
//!   login page asks "organisation or e-mail" and starts
//!   `/auth/oidc/start?org=<tenant | e-mail>`; tenant names are never listed to
//!   anonymous visitors (`GET /auth/oidc` says only whether any exists);
//! - accounts keyed by tenant + issuer + subject (crate::oidc::provision), so an
//!   account of a tenant IdP never becomes an appliance-wide one;
//! - a deactivated tenant's IdP refuses logins like its other accounts.
//!
//! `GET /tenants/{name}/oidc` (admin, security officer; the tenant's admins
//! read their own), `PUT` (admin, approval `tenant_oidc.update` like
//! `oidc.update`: it decides who can sign in), `POST …/oidc/test` (admin).
//! The scheduler adds the issuer and the recorded token / JWKS endpoints to the
//! egress allow-list (scheduler `firewall::oidc_targets`).

use crate::auth::Ctx;
use crate::oidc::{self, Settings, SettingsReq};
use crate::quorum::{accepted, request};
use crate::{validate, ApiError, ApiResult, St, J};
use axum::extract::{Path, State};
use axum::http::{HeaderMap, Uri};
use axum::response::Response;
use axum::routing::{get, post};
use axum::{Json, Router};
use catalog::rusqlite::{params, Connection, OptionalExtension};
use serde_json::{json, Value};

pub const ACTION: &str = "tenant_oidc.update";
const MAX_DOMAINS: usize = 32;

pub fn routes() -> Router<St> {
    Router::new()
        .route("/tenants/{name}/oidc", get(get_idp).put(put_idp))
        .route("/tenants/{name}/oidc/test", post(test_idp))
}

/// (settings, domains) of a tenant's IdP.
fn row(c: &Connection, tenant: &str) -> ApiResult<Option<(Settings, Vec<String>)>> {
    let r: Option<(String, String)> = c
        .query_row(
            "SELECT settings, domains FROM tenant_idps WHERE tenant = ?1",
            [tenant],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    Ok(r.and_then(|(s, d)| {
        let mut s: Settings = serde_json::from_str(&s).ok()?;
        s.tenant = Some(tenant.to_owned());
        Some((s, serde_json::from_str(&d).unwrap_or_default()))
    }))
}

pub fn load(c: &Connection, tenant: &str) -> ApiResult<Option<Settings>> {
    Ok(row(c, tenant)?.map(|r| r.0))
}

pub fn any_enabled(c: &Connection) -> ApiResult<bool> {
    Ok(c.query_row(
        "SELECT EXISTS (SELECT 1 FROM tenant_idps i JOIN tenants t ON t.name = i.tenant
           WHERE json_extract(i.settings, '$.enabled') = 1 AND t.disabled = 0)",
        [],
        |r| r.get(0),
    )?)
}

/// The IdP for what a visitor typed: an e-mail address (by its domain) or a
/// tenant name. `None` = no enabled IdP of an active tenant.
pub fn resolve(c: &Connection, org: &str) -> ApiResult<Option<Settings>> {
    let org = org.to_ascii_lowercase();
    let tenant: Option<String> = match org.rsplit_once('@') {
        Some((_, domain)) => c
            .query_row(
                "SELECT i.tenant FROM tenant_idps i, json_each(i.domains) d WHERE d.value = ?1",
                [domain],
                |r| r.get(0),
            )
            .optional()?,
        None => Some(org),
    };
    let Some(t) = tenant.filter(|t| validate::name(t, "org").is_ok()) else {
        return Ok(None);
    };
    if catalog::tenants::disabled(c, &t).unwrap_or(true) {
        return Ok(None);
    }
    Ok(load(c, &t)?.filter(|s| s.enabled))
}

/// `example.com`-like: lowercase labels of [a-z0-9-], at least one dot.
fn domain_ok(d: &str) -> bool {
    (3..=253).contains(&d.len())
        && d.contains('.')
        && d.split('.').all(|l| {
            (1..=63).contains(&l.len())
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}

fn require_tenant(c: &Connection, name: &str) -> ApiResult<()> {
    validate::name(name, "tenant")?;
    c.query_row("SELECT 1 FROM tenants WHERE name = ?1", [name], |_| Ok(()))
        .optional()?
        .ok_or_else(ApiError::not_found)
}

pub async fn get_idp(
    State(st): State<St>,
    ctx: Ctx,
    Path(name): Path<String>,
    uri: Uri,
    headers: HeaderMap,
) -> ApiResult<Json<Value>> {
    ctx.require(&["admin", "security_officer", "tenant_admin"])?;
    if !ctx.sees(&name) {
        return Err(ApiError::forbidden());
    }
    let c = st.cat.conn();
    require_tenant(&c, &name)?;
    let (s, domains) = row(&c, &name)?.unwrap_or_default();
    let mut v = oidc::public(&s, &oidc::redirect_uri(&uri, &headers));
    v["domains"] = json!(domains);
    v["tenant"] = json!(name);
    Ok(Json(v))
}

/// Tenant roles of this tenant only; an empty tenant list means this tenant.
fn check(c: &Connection, name: &str, s: &mut Settings, domains: &mut [String]) -> ApiResult<()> {
    for m in &mut s.mappings {
        if !crate::tenancy::TENANT_ROLES.contains(&m.role.as_str()) {
            return Err(ApiError::bad(
                "mappings: a tenant's IdP maps to tenant_admin, tenant_user or viewer only",
            ));
        }
        if m.tenants.is_empty() {
            m.tenants = vec![name.to_owned()];
        }
        if m.tenants != [name] {
            return Err(ApiError::bad(format!("mappings: only tenant {name}")));
        }
    }
    oidc::validate_settings(c, s)?;
    if domains.len() > MAX_DOMAINS {
        return Err(ApiError::bad(format!("domains: at most {MAX_DOMAINS}")));
    }
    for d in domains.iter_mut() {
        *d = d.trim().trim_start_matches('@').to_ascii_lowercase();
        if !domain_ok(d) {
            return Err(ApiError::bad(format!("domains: {d:?} is not a domain name")));
        }
        let other: Option<String> = c
            .query_row(
                "SELECT i.tenant FROM tenant_idps i, json_each(i.domains) d WHERE d.value = ?1 AND i.tenant != ?2",
                params![&*d, name],
                |r| r.get(0),
            )
            .optional()?;
        if let Some(o) = other {
            return Err(ApiError::conflict(format!("domains: {d} belongs to tenant {o}")));
        }
    }
    Ok(())
}

pub async fn put_idp(
    State(st): State<St>,
    ctx: Ctx,
    Path(name): Path<String>,
    J(mut r): J<SettingsReq>,
) -> ApiResult<Response> {
    ctx.require(&["admin"])?;
    if ctx.scope().is_some() {
        return Err(ApiError::forbidden());
    }
    require_tenant(&st.cat.conn(), &name)?;
    let mut domains = r.domains.take().unwrap_or_default();
    let old = row(&st.cat.conn(), &name)?;
    let mut new = oidc::from_req(&st, r, old.as_ref().map(|o| &o.0), Some(&name))?;
    check(&st.cat.conn(), &name, &mut new, &mut domains)?;
    let old = old.map(|(s, d)| json!({"settings": s, "domains": d}));
    let p = json!({"tenant": name, "settings": new, "domains": domains, "old": old});
    let o = request(&st, &ctx, ACTION, &format!("tenant/{name}"), p)?;
    Ok(accepted(o, json!({})))
}

/// Approved [`ACTION`] (refused when the IdP changed since the request).
pub fn execute(c: &Connection, p: &Value) -> ApiResult<()> {
    let name = p["tenant"].as_str().unwrap_or_default();
    let current = row(c, name)?.map(|(s, d)| json!({"settings": s, "domains": d}));
    if current.unwrap_or(Value::Null) != p["old"] {
        return Err(ApiError::conflict(
            "the tenant's IdP changed since this request was made; reject it and request the change again",
        ));
    }
    let s: Settings =
        serde_json::from_value(p["settings"].clone()).map_err(|_| ApiError::bad("quorum params: settings"))?;
    c.execute(
        "INSERT INTO tenant_idps (tenant, settings, domains) VALUES (?1, ?2, ?3)
         ON CONFLICT (tenant) DO UPDATE SET settings = excluded.settings, domains = excluded.domains",
        params![name, serde_json::to_string(&s)?, p["domains"].to_string()],
    )?;
    Ok(())
}

pub async fn test_idp(State(st): State<St>, ctx: Ctx, Path(name): Path<String>) -> ApiResult<Json<Value>> {
    ctx.require(&["admin"])?;
    if ctx.scope().is_some() {
        return Err(ApiError::forbidden());
    }
    require_tenant(&st.cat.conn(), &name)?;
    let s = load(&st.cat.conn(), &name)?.ok_or_else(|| ApiError::bad("no IdP configured for this tenant"))?;
    let out = oidc::test_idp(&st, &s).await?;
    st.audit(ctx.name(), "settings.oidc_test", &format!("tenant/{name}"), out.clone())?;
    Ok(Json(out))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domains() {
        assert!(domain_ok("example.com"));
        assert!(domain_ok("mail.acme-corp.de"));
        for bad in ["example", "Example.com", "-a.com", "a..com", "a b.com", "@x.com"] {
            assert!(!domain_ok(bad), "{bad}");
        }
    }
}
